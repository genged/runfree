
import net from "node:net";

import { type RuntimeNetwork } from "../network.ts";
import {
  parseHostServiceSetMembers,
  validateProxyNftablesTableJson,
  type ProxyNftablesProofInput,
} from "../proxy-nftables-proof.ts";
import { remedy } from "../remedies.ts";
import { PROXY_SERVER_UID } from "@runfree/proxy/firewall/nftables";
import { HOST_SERVICE_GATEWAY_STATUS_FILE } from "@runfree/runtime-contracts/host-services";
import {
  DEFAULT_PROXY_STATUS_DIR,
  hostServiceEntryKey,
  parseHostServiceGatewayStatus,
  type HostServiceSetEntry,
} from "@runfree/runtime-contracts/proxy-status";
import { runDockerExec, runDockerExecProxyServer, runDockerExecRoot } from "./attach.ts";
import {
  applyDenyProbeBatchResult,
  denyProbeBatchScript,
  judgeDroppedProbeExit,
  type DenyProbeSpec,
} from "./deny-probe-batch.ts";
import { AGENT_UID_GID } from "./constants.ts";
import { dockerClientEnvOptions, } from "./docker.ts";
import { createDockerClient } from "./docker-client.ts";
import type { CaptureResult, DockerNetworkInspect, RuntimeContext, RuntimeIO } from "./types.ts";

export type RuntimeProbeIssue = string;
export type RuntimeProbeProgressOptions = {
  onBoundaryViolation?(): void;
  onAttempt?(label: string, attempt: number, maxAttempts: number): void;
  onProbe?(label: string): void;
  /** proxy_egress address the default route must use; checked on the batched route section. */
  expectedEgressSource?: string;
};

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

// Hop 2 of the per-session MCP OAuth callback, run as the agent user inside
// the session container before the session is admitted. Argv: bind address,
// port, probe challenge, the one peer address allowed to connect (the
// callback forwarder's agent_internal address), and the session callback port
// file. It records the port for the session's `claude`/`codex` adapters before
// it listens — nothing else in the session runs before admission, so the file
// exists before any client starts — then relays only the forwarder's
// connections to the session's own loopback, answering the host probe's
// challenge with an echo. A peer session connecting to this address is closed
// without reaching the loopback callback listener.
export const MCP_CALLBACK_BRIDGE_SOURCE = [
  "/* runfree_mcp_callback_bridge */",
  "const fs = require('node:fs');",
  "const net = require('node:net');",
  "const host = process.argv[1];",
  "const port = Number(process.argv[2]);",
  "const probeToken = process.argv[3];",
  "const allowedPeer = process.argv[4];",
  "const portFile = process.argv[5];",
  "if (!probeToken || !allowedPeer || !portFile || !Number.isInteger(port)) process.exit(1);",
  "const temporary = `${portFile}.${process.pid}`;",
  "fs.writeFileSync(temporary, `${port}\\n`, { flag: 'wx', mode: 0o644 });",
  "fs.chmodSync(temporary, 0o644);",
  "fs.renameSync(temporary, portFile);",
  "const peerAddress = (address) => typeof address === 'string' && address.startsWith('::ffff:') ? address.slice(7) : address;",
  "const server = net.createServer((client) => {",
  "  if (peerAddress(client.remoteAddress) !== allowedPeer) {",
  "    client.destroy();",
  "    return;",
  "  }",
  "  let decided = false;",
  "  const closeClient = () => client.destroy();",
  "  const forward = (firstChunk) => {",
  "    if (decided) return;",
  "    decided = true;",
  "    const upstream = net.connect({ host: '127.0.0.1', port });",
  "    const closeBoth = () => { client.destroy(); upstream.destroy(); };",
  "    client.on('error', closeBoth);",
  "    upstream.on('error', closeBoth);",
  "    upstream.on('connect', () => { if (firstChunk) upstream.write(firstChunk); client.pipe(upstream); upstream.pipe(client); });",
  "  };",
  "  client.setTimeout(1000, () => forward());",
  "  client.once('data', (chunk) => {",
  "    if (chunk.toString('utf8').trim() === probeToken) {",
  "      decided = true;",
  "      client.end(probeToken + '\\n');",
  "      return;",
  "    }",
  "    forward(chunk);",
  "  });",
  "  client.once('error', closeClient);",
  "});",
  "server.on('error', (error) => {",
  "  console.error(error instanceof Error ? error.message : String(error));",
  "  process.exit(1);",
  "});",
  "server.listen({ host, port, exclusive: true });",
  "setInterval(() => {}, 60_000);",
].join("\n");

/** The session callback port file the bridge writes and the adapters read. */
export const SESSION_MCP_CALLBACK_PORT_FILE = "/tmp/runfree-mcp-oauth-callback-port";

function captureResult(status: number, stdout = "", stderr = ""): CaptureResult {
  return { status, stdout, stderr };
}

const MCP_CALLBACK_BRIDGE_PROBE_ATTEMPTS = 20;
const MCP_CALLBACK_BRIDGE_PROBE_DELAY_MS = 100;
const MCP_CALLBACK_BRIDGE_PROBE_TIMEOUT_MS = 500;
const MCP_CALLBACK_BRIDGE_PROBE_SLEEP_BUFFER = new Int32Array(new SharedArrayBuffer(4));

function sleepForMcpCallbackBridgeRetry(): void {
  Atomics.wait(MCP_CALLBACK_BRIDGE_PROBE_SLEEP_BUFFER, 0, 0, MCP_CALLBACK_BRIDGE_PROBE_DELAY_MS);
}

function probeMcpCallbackHostPath(
  port: number,
  challenge: string,
  timeoutMs = MCP_CALLBACK_BRIDGE_PROBE_TIMEOUT_MS,
): Promise<CaptureResult> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let data = "";
    let done = false;
    // A whole-try bound, not only an idle one: the far end is in the session
    // container, and a peer that trickles bytes must not keep a try open.
    const deadline = setTimeout(() => finish(captureResult(1, data, "callback host probe timed out")), timeoutMs);
    const finish = (result: CaptureResult) => {
      if (done) return;
      done = true;
      clearTimeout(deadline);
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs, () => finish(captureResult(1, data, "callback host probe timed out")));
    socket.once("connect", () => socket.write(`${challenge}\n`));
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.includes(challenge)) finish(captureResult(0));
    });
    socket.once("error", (error) => {
      const code = "code" in error && typeof error.code === "string" ? error.code : "callback host probe failed";
      finish(captureResult(1, "", code));
    });
    socket.once("close", () => {
      finish(captureResult(1, data, "callback host probe closed before echo"));
    });
  });
}

/**
 * Starts hop 2 of the per-session callback — a `docker exec -d` node process,
 * as the agent user, that records the session callback port and then relays
 * `bindIp:port` to the session's own `127.0.0.1:port`, accepting only
 * `allowedPeerIp` (the forwarder) and intercepting the probe challenge with an
 * echo. The session container is new, so no earlier bridge can hold the port.
 */
export function startMcpCallbackBridgeInContainer(
  context: RuntimeContext,
  io: RuntimeIO,
  params: Readonly<{ containerId: string; bindIp: string; port: number; challenge: string; allowedPeerIp: string }>,
): number {
  return createDockerClient(io, dockerClientEnvOptions(context)).terminal.exec(
    params.containerId,
    [
      "node",
      "-e",
      MCP_CALLBACK_BRIDGE_SOURCE,
      params.bindIp,
      String(params.port),
      params.challenge,
      params.allowedPeerIp,
      SESSION_MCP_CALLBACK_PORT_FILE,
    ],
    { detach: true, user: AGENT_UID_GID },
  );
}

/**
 * Probes the host callback path end to end (`127.0.0.1:port` → forwarder →
 * bridge echo), retrying while the sidecars come up. Used by the per-session
 * callback setup. There is no environment override: a route this host did not
 * prove never counts as set up.
 */
export async function probeMcpCallbackPathWithRetries(
  port: number,
  challenge: string,
  deadlineMs = Number.POSITIVE_INFINITY,
  nowMs: () => number = () => performance.now(),
): Promise<CaptureResult> {
  // Each try is cut off at the setup deadline too, and no try starts after it.
  const timeoutMs = (): number => Math.min(MCP_CALLBACK_BRIDGE_PROBE_TIMEOUT_MS, Math.floor(deadlineMs - nowMs()));
  if (timeoutMs() <= 0) return captureResult(1, "", "the callback setup budget ended before the host path was probed");
  let probe = await probeMcpCallbackHostPath(port, challenge, timeoutMs());
  for (let attempt = 2; probe.status !== 0 && attempt <= MCP_CALLBACK_BRIDGE_PROBE_ATTEMPTS; attempt += 1) {
    if (deadlineMs - nowMs() <= MCP_CALLBACK_BRIDGE_PROBE_DELAY_MS) break;
    sleepForMcpCallbackBridgeRetry();
    if (timeoutMs() <= 0) break;
    probe = await probeMcpCallbackHostPath(port, challenge, timeoutMs());
  }
  return probe;
}


const _PROXY_REACHABILITY_ATTEMPTS = 30;
const _PROXY_REACHABILITY_DELAY_MS = 500;
const _PROXY_REACHABILITY_TIMEOUT_SECONDS = 1;
export function expectProbeSuccess(issues: string[], label: string, result: CaptureResult): void {
  if (result.status !== 0) {
    const detail = compactDiagnostic(`${result.stderr}\n${result.stdout}`);
    issues.push(`${label} failed${detail ? `: ${detail}` : ""}`);
  }
}

// Bounded retry for a success-expected probe that traverses a real network
// path, where one lost packet would otherwise fail a valid runtime closed.
// Never use this for a failure-expected probe: retrying those could only
// mask an enforcement gap.
export function expectProbeSuccessWithRetry(
  issues: string[],
  label: string,
  run: () => CaptureResult,
  attempts: number,
): void {
  let result = run();
  for (let attempt = 2; result.status !== 0 && attempt <= attempts; attempt += 1) {
    result = run();
  }
  expectProbeSuccess(issues, label, result);
}

export function expectProbeFailure(issues: string[], label: string, result: CaptureResult): void {
  if (result.status === 0) {
    const detail = compactDiagnostic(result.stdout || result.stderr);
    issues.push(`${label} unexpectedly succeeded${detail ? `: ${detail}` : ""}`);
  }
}

export function expectProbeOutputContains(issues: string[], label: string, result: CaptureResult, expected: string): void {
  if (result.status !== 0) {
    const detail = compactDiagnostic(`${result.stderr}\n${result.stdout}`);
    issues.push(`${label} failed${detail ? `: ${detail}` : ""}`);
    return;
  }
  if (!result.stdout.includes(expected)) {
    const detail = compactDiagnostic(result.stdout || result.stderr);
    issues.push(`${label} did not return ${expected}${detail ? `: ${detail}` : ""}`);
  }
}

// Target for the raw non-443 CONNECT rejection probe. The proxy's CONNECT
// classifier checks the port before it checks the host allowlist and before any
// DNS lookup or upstream connection, so this probe proves port rejection
// without the hostname ever being resolved. The name is therefore fixed and
// policy-independent by construction: it must not vary with project policy
// content (a deny-all policy has no host to borrow), and runtime validation
// must never make a third-party service a hidden dependency or imply that any
// host is allowed. `.invalid` is reserved by RFC 2606 and never resolves.
export const NON_RESOLVING_CONNECT_PROBE_HOST = "deny-all.runfree.invalid";

export const LINUX_CAPABILITY_BITS = {
  NET_ADMIN: 12n,
  NET_RAW: 13n,
} as const;

const BRIDGE_INHIBIT_IPV4_OPTION = "com.docker.network.bridge.inhibit_ipv4";

export function dockerOptionIsTrue(value: unknown): boolean {
  return value === true || value === "true";
}

export function bridgeInhibitIpv4Option(): string {
  return BRIDGE_INHIBIT_IPV4_OPTION;
}

export function dockerNetworkGateways(network: DockerNetworkInspect | undefined): string[] {
  const gateways = network?.IPAM?.Config
    ?.map((config) => config.Gateway?.trim())
    .filter((gateway): gateway is string => Boolean(gateway)) ?? [];
  return Array.from(new Set(gateways));
}

function routeInterface(stdout: string): string | undefined {
  return /(?:^|\s)dev\s+([^\s]+)/.exec(stdout)?.[1];
}

/**
 * The evidence the firewall proof captured, surfaced so a caller can mint the
 * post-cutover deny-by-default observation from the SAME validated fetch
 * without issuing a second `nft list` docker exec. Populated only when the
 * route interfaces and the live nft table fetch both succeeded, i.e. when this
 * proof actually validated the ruleset.
 */
export type ProxyFirewallProof = {
  nftablesProofInput?: ProxyNftablesProofInput;
  /**
   * The pinned host-service gateway the proxy published, when the gateway
   * status file was valid, named the effective network policy generation,
   * and carried an address. Absent otherwise; the gateway port probes then
   * do not run (there is no address to probe).
   */
  hostServiceGatewayIp?: string;
};

/**
 * The effective policy's host services, read on the host: the network policy
 * generation they belong to and their ports. Startup reads them from the same
 * active effective policy generation the firewall readiness check waited for.
 */
export type EffectiveHostServices = Readonly<{
  policyGeneration: string;
  ports: readonly number[];
}>;

export const PROXY_HOST_SERVICE_GATEWAY_STATUS_PATH = `${DEFAULT_PROXY_STATUS_DIR}/${HOST_SERVICE_GATEWAY_STATUS_FILE}`;
export const PROXY_HOST_SERVICE_SET_COMMAND = "nft -j list set inet runfree_proxy host_service";
// `%u %f`: owner uid and the raw mode in hex (file type bits included), so a
// symlink or a non-regular file can never read as a regular one.
export const PROXY_ETC_HOSTS_STAT_COMMAND = "stat -c '%u %f' /etc/hosts";
export const PROXY_HOST_SERVICE_GATEWAY_COMMAND = `cat ${PROXY_HOST_SERVICE_GATEWAY_STATUS_PATH}`;

const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const GROUP_OR_OTHER_WRITE = 0o022;

/**
 * Root's stat of the proxy's `/etc/hosts`, which carries the daemon-written
 * gateway alias: uid 0, a regular file, and no group or other write bit.
 */
export function judgeProxyEtcHostsStat(issues: string[], section: FirewallSectionResult): void {
  if (section.exit !== 0) {
    issues.push(`proxy /etc/hosts inspection failed: ${compactDiagnostic(section.body) || `exit ${section.exit}`}`);
    return;
  }
  const match = /^(\d+) ([0-9a-f]{1,8})$/u.exec(section.body.trim());
  const uid = match ? Number(match[1]) : undefined;
  const mode = match ? Number.parseInt(match[2], 16) : undefined;
  if (uid !== 0 || mode === undefined || (mode & S_IFMT) !== S_IFREG || (mode & GROUP_OR_OTHER_WRITE) !== 0) {
    issues.push(`proxy /etc/hosts must be a root-owned regular file that is not group- or other-writable; got ${compactDiagnostic(section.body) || "<empty>"}; run \`${remedy.rebuild()}\` to recreate the proxy`);
  }
}

type HostServiceFirewallObservation = {
  elements?: HostServiceSetEntry[];
  expected?: HostServiceSetEntry[];
  gatewayIp?: string;
};

/**
 * Judges the `@host_service` member listing and the gateway status file
 * against the effective host services. Expected members are the effective
 * ports paired with the published gateway. When the status file carries
 * `unavailableReason` there is no gateway: the supervisor withholds it only
 * while `@host_service` is empty (never pinned, a suspect address, or a
 * failed write it tore down), so the expected members are none.
 */
function observeHostServiceFirewall(
  issues: string[],
  setSection: FirewallSectionResult,
  gatewaySection: FirewallSectionResult,
  effective: EffectiveHostServices | undefined,
): HostServiceFirewallObservation {
  const observation: HostServiceFirewallObservation = {};
  if (setSection.exit !== 0) {
    issues.push(`proxy nftables host_service set inspection failed: ${compactDiagnostic(setSection.body) || `exit ${setSection.exit}`}`);
  } else {
    observation.elements = parseHostServiceSetMembers(setSection.body);
    if (!observation.elements) issues.push("proxy nftables host_service set inspection did not return the owned host_service set as nft JSON");
  }
  if (gatewaySection.exit !== 0) {
    issues.push(`proxy host-service gateway status inspection failed: ${compactDiagnostic(gatewaySection.body) || `exit ${gatewaySection.exit}`}`);
    return observation;
  }
  let status: ReturnType<typeof parseHostServiceGatewayStatus>;
  try {
    status = parseHostServiceGatewayStatus(gatewaySection.body);
  } catch (error) {
    issues.push(`proxy host-service gateway status is malformed: ${error instanceof Error ? error.message : String(error)}`);
    return observation;
  }
  if (!effective) return observation;
  if (status.policyGeneration !== effective.policyGeneration) {
    issues.push(`proxy host-service gateway status names network policy generation ${status.policyGeneration}, not the effective network policy generation ${effective.policyGeneration}`);
    return observation;
  }
  const gatewayIp = status.gatewayIp;
  observation.gatewayIp = gatewayIp;
  observation.expected = gatewayIp === undefined ? [] : effective.ports.map((port) => ({ ip: gatewayIp, port }));
  return observation;
}

// The lowest port from 9 up that the effective policy does not approve: the
// uid-1001 probe target that must stay unreachable.
function unapprovedHostServicePort(approved: readonly number[]): number {
  const taken = new Set(approved);
  let port = 9;
  while (taken.has(port)) port += 1;
  return port;
}

/** The gateway TCP probe body; the address is a strict IPv4 literal. */
export function hostGatewayTcpProbeCommand(gatewayIp: string, port: number): string {
  return `timeout 3 bash -c '</dev/tcp/${gatewayIp}/${port}'`;
}

/**
 * Root-position gateway probes (design "Host-side proof"): the `@host_service`
 * accept is uid 1001 only, so root to each approved port must be dropped. The
 * uid-1001 unapproved-port probe rides the server-UID denial batch instead.
 * Run once each, never retried: a success is an enforcement gap, and only a
 * timeout proves the drop (see `judgeDroppedProbeExit`).
 */
function runRootGatewayProbes(
  issues: string[],
  context: RuntimeContext,
  io: RuntimeIO,
  proxyId: string,
  gatewayIp: string,
  ports: readonly number[],
  options: RuntimeProbeProgressOptions,
): void {
  if (ports.length === 0) return;
  const rootSpecs: DenyProbeSpec[] = ports.map((port) => ({
    label: `proxy-position root host gateway port ${port}`,
    command: hostGatewayTcpProbeCommand(gatewayIp, port),
  }));
  options.onProbe?.("proxy-position root host gateway denial probes");
  applyDenyProbeBatchResult(
    issues,
    rootSpecs,
    runDockerExecRoot(context, io, proxyId, ["bash", "-c", denyProbeBatchScript(rootSpecs)]),
    options.onBoundaryViolation,
    undefined,
    { requireTimeout: true },
  );
}

// L5b framing: firewall probes merge only within one exec identity group, and
// every merged exec frames its per-probe results with these host-declared,
// index-keyed markers. A missing, duplicated, reordered, or garbled section is
// a whole-validation failure, never success and never denial-proven.
const FIREWALL_SECTION_MARKER = "RUNFREE_FIREWALL_SECTION";
const FIREWALL_PROBE_MARKER = "RUNFREE_FIREWALL_PROBE";
const FIREWALL_BATCH_OUTPUT_MAX_BYTES = 256 * 1024;
const FIREWALL_SECTION_HEADER_PATTERN = /^RUNFREE_FIREWALL_SECTION (\d+) exit=(\d+)$/u;
const FIREWALL_PROBE_RECORD_PATTERN = /^RUNFREE_FIREWALL_PROBE (\d+) exit=(\d+)$/u;
const IPV4_LITERAL_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/u;

export type FirewallSectionResult = Readonly<{ exit: number; body: string }>;

/**
 * Builds one `sh` script that runs each command sequentially, capturing its
 * combined output and exit status, then prints every section framed in
 * host-declared order. The script itself exits 0 — per-section exit codes are
 * the host's to judge; a nonzero batch exit means the harness broke.
 */
export function firewallSectionBatchScript(commands: readonly string[]): string {
  const lines: string[] = ["set -u"];
  commands.forEach((command, index) => {
    lines.push(`runfree_out_${index}=$({ ${command}; } 2>&1); runfree_status_${index}=$?`);
  });
  commands.forEach((_, index) => {
    lines.push(`printf '${FIREWALL_SECTION_MARKER} %s exit=%s\\n' ${index} "$runfree_status_${index}"`);
    lines.push(`printf '%s\\n' "$runfree_out_${index}"`);
    lines.push(`printf '${FIREWALL_SECTION_MARKER}_END %s\\n' ${index}`);
  });
  lines.push("exit 0");
  return lines.join("\n");
}

/** Strict section parse; any deviation returns undefined (fail closed). */
export function parseFirewallSectionBatch(
  result: CaptureResult,
  expectedSections: number,
): FirewallSectionResult[] | undefined {
  if (result.status !== 0) return undefined;
  if (Buffer.byteLength(result.stdout) > FIREWALL_BATCH_OUTPUT_MAX_BYTES) return undefined;
  const lines = result.stdout.split(/\r?\n/u);
  const sections: FirewallSectionResult[] = [];
  let cursor = 0;
  for (let index = 0; index < expectedSections; index += 1) {
    const header = FIREWALL_SECTION_HEADER_PATTERN.exec(lines[cursor] ?? "");
    if (!header || Number(header[1]) !== index) return undefined;
    cursor += 1;
    const body: string[] = [];
    while (cursor < lines.length && lines[cursor] !== `${FIREWALL_SECTION_MARKER}_END ${index}`) {
      if (lines[cursor].startsWith(FIREWALL_SECTION_MARKER)) return undefined;
      body.push(lines[cursor]);
      cursor += 1;
    }
    if (cursor >= lines.length) return undefined;
    cursor += 1;
    sections.push(Object.freeze({ exit: Number(header[2]), body: body.join("\n") }));
  }
  for (; cursor < lines.length; cursor += 1) {
    if (lines[cursor].trim() !== "") return undefined;
  }
  return sections;
}

// The five failure-expected server-UID probes, batched into ONE exec under the
// exact server identity (`--user PROXY_SERVER_UID_GID`) — the identity is the
// subject of these denial proofs, so they must never merge across identity
// groups. Probes run concurrently (the two DNS probes each burn their in-probe
// timeout by design) and the batch exits 0 iff it launched every probe and
// printed every record; per-probe exit codes are judged host-side. The
// `command -v` preflight distinguishes could-not-run from denied: a missing
// binary aborts the batch instead of reading as five denials.
export const SERVER_UID_DENIAL_PROBE_LABELS = [
  "proxy server UID DNS to 1.1.1.1",
  "proxy server UID DNS to 127.0.0.11",
  "proxy server UID nftables ruleset inspection",
  "proxy server UID nftables set inspection",
  "proxy server UID route administration",
] as const;

/**
 * The uid-1001 host gateway probe that rides the server-UID denial batch as
 * one more concurrent record: uid 1001 to a port the effective policy does
 * not approve must be dropped, because the `@host_service` accept is
 * port-exact. The host chooses the gateway (from the status file) and port.
 */
export type ServerUidGatewayProbe = Readonly<{ gatewayIp: string; port: number }>;

export function serverUidGatewayProbeLabel(port: number): string {
  return `proxy-position server UID host gateway unapproved port ${port}`;
}

const STRICT_IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
const STRICT_IPV4_LITERAL = new RegExp(`^${STRICT_IPV4_OCTET}(?:\\.${STRICT_IPV4_OCTET}){3}$`, "u");

export function serverUidDenialBatchScript(gatewayProbe?: ServerUidGatewayProbe): string {
  if (gatewayProbe && (!STRICT_IPV4_LITERAL.test(gatewayProbe.gatewayIp)
    || !Number.isInteger(gatewayProbe.port) || gatewayProbe.port < 1 || gatewayProbe.port > 65535)) {
    // Both values are interpolated into the shell: refuse anything else.
    throw new Error("server UID gateway probe needs an IPv4 literal and a port from 1 to 65535");
  }
  const probes = [
    "( timeout 3 dig +time=2 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1 )",
    "( timeout 3 dig +time=2 +tries=1 @127.0.0.11 example.com >/dev/null 2>&1 )",
    "( nft list ruleset >/dev/null 2>&1 )",
    "( nft list set inet runfree_proxy allowed_ipv4 >/dev/null 2>&1 )",
    "( if ip route add blackhole 203.0.113.254/32 >/dev/null 2>&1; then ip route del blackhole 203.0.113.254/32 >/dev/null 2>&1 || true; exit 0; fi; exit 1 )",
    ...(gatewayProbe ? [`( ${hostGatewayTcpProbeCommand(gatewayProbe.gatewayIp, gatewayProbe.port)} >/dev/null 2>&1 )`] : []),
  ];
  return [
    "set -u",
    `for runfree_tool in dig ip nft timeout${gatewayProbe ? " bash" : ""}; do`,
    "  if ! command -v \"$runfree_tool\" >/dev/null 2>&1; then",
    "    printf 'missing probe binary: %s\\n' \"$runfree_tool\" >&2",
    "    exit 96",
    "  fi",
    "done",
    ...probes.map((probe, index) => `${probe} & runfree_pid_${index}=$!`),
    ...probes.map((_, index) => `wait "$runfree_pid_${index}"; runfree_status_${index}=$?`),
    ...probes.map((_, index) => `printf '${FIREWALL_PROBE_MARKER} ${index} exit=%s\\n' "$runfree_status_${index}"`),
    "exit 0",
  ].join("\n");
}

export const SERVER_UID_DENIAL_BATCH_SCRIPT = serverUidDenialBatchScript();

/**
 * Judges the batched server-UID denial records. No retry of failure-expected
 * probes; exit 0 is an enforcement gap, 126/127 is could-not-run (a validation
 * failure, not a denial — today's single-exec conflation, strengthened), and
 * any missing, duplicated, reordered, or extra record fails the validation.
 * With `gatewayProbe`, the sixth record is the uid-1001 gateway probe, which
 * only a timeout proves denied (`judgeDroppedProbeExit`).
 */
export function applyServerUidDenialBatch(
  issues: string[],
  result: CaptureResult,
  onBoundaryViolation?: () => void,
  gatewayProbe?: ServerUidGatewayProbe,
): void {
  const batchFailure = (detail: string): void => {
    issues.push(`proxy server UID nftables and route denial batch could not run${detail ? `: ${detail}` : ""}`);
    if (gatewayProbe) issues.push(`${serverUidGatewayProbeLabel(gatewayProbe.port)} denial probe did not run: the server UID batch failed`);
  };
  const expectedRecords = SERVER_UID_DENIAL_PROBE_LABELS.length + (gatewayProbe ? 1 : 0);
  if (result.status !== 0) {
    batchFailure(compactDiagnostic(`${result.stderr}\n${result.stdout}`));
    return;
  }
  if (Buffer.byteLength(result.stdout) > FIREWALL_BATCH_OUTPUT_MAX_BYTES) {
    batchFailure("probe records exceeded the bounded output size");
    return;
  }
  const records = result.stdout.split(/\r?\n/u).filter((line) => line.trim() !== "");
  if (records.length !== expectedRecords) {
    batchFailure(`expected ${expectedRecords} probe records, got ${records.length}`);
    return;
  }
  const outcomes: number[] = [];
  for (let index = 0; index < records.length; index += 1) {
    const match = FIREWALL_PROBE_RECORD_PATTERN.exec(records[index]);
    if (!match || Number(match[1]) !== index) {
      batchFailure(`probe record ${index} is missing or garbled`);
      return;
    }
    outcomes.push(Number(match[2]));
  }
  outcomes.forEach((exit, index) => {
    if (gatewayProbe && index === SERVER_UID_DENIAL_PROBE_LABELS.length) {
      judgeDroppedProbeExit(issues, serverUidGatewayProbeLabel(gatewayProbe.port), exit, onBoundaryViolation);
      return;
    }
    const label = SERVER_UID_DENIAL_PROBE_LABELS[index];
    if (exit === 0) {
      onBoundaryViolation?.();
      issues.push(`${label} unexpectedly succeeded`);
    } else if (exit === 126 || exit === 127) {
      issues.push(`${label} could not run inside the proxy (exit ${exit})`);
    }
  });
}

/**
 * Firewall evidence a warm launch already fetched in its one root batch
 * (sub-second launch plan Task 2). When given, `validateProxyFirewall` issues
 * no Docker call: it judges these exact outputs with the same checks as the
 * full path. Two probes do not run on a warm match — the root Docker DNS
 * liveness probe and the server-UID denial batch; their inputs (proxy
 * instance and image, network, ruleset shape) are bound by the warm proof.
 */
export type WarmFirewallEvidence = Readonly<{
  /** The two framed route sections, exactly as `firewallSectionBatchScript` frames them. */
  routes: readonly FirewallSectionResult[];
  /** The raw `nft -j list table inet runfree_proxy` output. */
  nftTable: FirewallSectionResult;
  /** `nft list set inet runfree_proxy allowed_ipv4`. */
  allowedSet: FirewallSectionResult;
  /** `PROXY_HOST_SERVICE_SET_COMMAND`. */
  hostServiceSet: FirewallSectionResult;
  /** `PROXY_HOST_SERVICE_GATEWAY_COMMAND`. */
  hostServiceGateway: FirewallSectionResult;
  /** `PROXY_ETC_HOSTS_STAT_COMMAND`. */
  etcHostsStat: FirewallSectionResult;
}>;

export function validateProxyFirewall(
  issues: string[],
  context: RuntimeContext,
  io: RuntimeIO,
  proxyId: string,
  runtimeNetwork: RuntimeNetwork,
  options: RuntimeProbeProgressOptions & {
    warm?: WarmFirewallEvidence;
    /**
     * When given, `@host_service` must hold exactly these ports at the
     * published gateway, and the gateway port probes run. Startup always
     * passes it.
     */
    effectiveHostServices?: EffectiveHostServices;
  } = {},
): ProxyFirewallProof {
  const warm = options.warm;
  // Exec 1 (default daemon user): both route inspections, one framed batch.
  options.onProbe?.("proxy internal and egress route inspections");
  let internalIface: string | undefined;
  let egressIface: string | undefined;
  if (!IPV4_LITERAL_PATTERN.test(runtimeNetwork.agentIp)) {
    issues.push(`proxy internal route inspection failed: agent address is not IPv4: ${runtimeNetwork.agentIp}`);
  } else {
    const routeBatch: CaptureResult = warm
      ? { status: 0, stdout: "", stderr: "" }
      : runDockerExec(context, io, proxyId, ["sh", "-c", firewallSectionBatchScript([
        `ip -o route get ${runtimeNetwork.agentIp}`,
        "ip -o route get 1.1.1.1",
      ])]);
    const routeSections = warm
      ? (warm.routes.length === 2 ? [...warm.routes] : undefined)
      : parseFirewallSectionBatch(routeBatch, 2);
    if (!routeSections) {
      const detail = compactDiagnostic(`${routeBatch.stderr}\n${routeBatch.stdout}`);
      issues.push(`proxy internal route inspection failed: route batch was missing or garbled${detail ? `: ${detail}` : ""}`);
      issues.push(`proxy egress route inspection failed: route batch was missing or garbled${detail ? `: ${detail}` : ""}`);
    } else {
      const [internalRoute, egressRoute] = routeSections;
      if (internalRoute.exit !== 0) {
        issues.push(`proxy internal route inspection failed: ${compactDiagnostic(internalRoute.body) || `exit ${internalRoute.exit}`}`);
      } else {
        internalIface = routeInterface(internalRoute.body);
      }
      if (egressRoute.exit !== 0) {
        issues.push(`proxy egress route inspection failed: ${compactDiagnostic(egressRoute.body) || `exit ${egressRoute.exit}`}`);
      } else {
        egressIface = routeInterface(egressRoute.body);
        if (options.expectedEgressSource && !egressRoute.body.includes(` src ${options.expectedEgressSource}`)) {
          issues.push(`proxy default egress route must use proxy_egress address ${options.expectedEgressSource}; got ${compactDiagnostic(egressRoute.body)}`);
        }
      }
    }
  }
  if (!internalIface) issues.push("proxy internal route must expose an interface for nftables proof");
  if (!egressIface) issues.push("proxy egress route must expose an interface for nftables proof");
  if (internalIface && egressIface && internalIface === egressIface) {
    issues.push(`proxy internal and egress routes must use different interfaces; both used ${internalIface}`);
  }

  // Exec 2 (root, deliberately dedicated): the raw `nft -j list table` fetch.
  // Its stdout is minted verbatim into ProxyNftablesProofInput and reused for
  // the deny-by-default observation, so it never shares a framed batch.
  options.onProbe?.("proxy nftables owned-table inspection");
  const proxyTable: CaptureResult = warm
    ? { status: warm.nftTable.exit, stdout: warm.nftTable.body, stderr: "" }
    : runDockerExecRoot(context, io, proxyId, ["nft", "-j", "list", "table", "inet", "runfree_proxy"]);
  expectProbeSuccess(issues, "proxy nftables owned-table inspection", proxyTable);
  if (proxyTable.status !== 0) return {};

  // Exec 3 (root batch, full path): allowlist-set inspection, root Docker DNS,
  // the `@host_service` members, the host-service gateway status, and the
  // `/etc/hosts` stat. A warm launch already fetched the same outputs (all
  // but root DNS) in its one root batch.
  const rootDnsCommand = "timeout 3 dig +time=2 +tries=1 @127.0.0.11 example.com";
  let allowedSet: FirewallSectionResult | undefined;
  let rootDns: FirewallSectionResult | undefined;
  let hostServiceSet: FirewallSectionResult | undefined;
  let hostServiceGateway: FirewallSectionResult | undefined;
  let etcHostsStat: FirewallSectionResult | undefined;
  if (warm) {
    ({ allowedSet, hostServiceSet, hostServiceGateway, etcHostsStat } = warm);
  } else {
    options.onProbe?.("proxy nftables allowlist set, root Docker DNS, and host-service gateway inspection");
    const rootBatch = runDockerExecRoot(context, io, proxyId, ["sh", "-lc", firewallSectionBatchScript([
      "nft list set inet runfree_proxy allowed_ipv4",
      rootDnsCommand,
      PROXY_HOST_SERVICE_SET_COMMAND,
      PROXY_HOST_SERVICE_GATEWAY_COMMAND,
      PROXY_ETC_HOSTS_STAT_COMMAND,
    ])]);
    const rootSections = parseFirewallSectionBatch(rootBatch, 5);
    if (!rootSections) {
      const detail = compactDiagnostic(`${rootBatch.stderr}\n${rootBatch.stdout}`);
      const garbled = `root batch was missing or garbled${detail ? `: ${detail}` : ""}`;
      issues.push(`proxy nftables allowlist set inspection failed: ${garbled}`);
      issues.push(`proxy root Docker DNS failed: ${garbled}`);
      issues.push(`proxy nftables host_service set inspection failed: ${garbled}`);
      issues.push(`proxy /etc/hosts inspection failed: ${garbled}`);
    } else {
      [allowedSet, rootDns, hostServiceSet, hostServiceGateway, etcHostsStat] = rootSections;
    }
  }

  if (allowedSet) {
    if (allowedSet.exit !== 0) {
      issues.push(`proxy nftables allowlist set inspection failed: ${compactDiagnostic(allowedSet.body) || `exit ${allowedSet.exit}`}`);
    } else if (!allowedSet.body.includes("set allowed_ipv4")) {
      issues.push("proxy firewall must expose the allowed_ipv4 nftables set for live inspection");
    }
  }
  if (rootDns && rootDns.exit !== 0) {
    // Only the root Docker DNS probe retries, and it retries SOLO (L5b): it
    // traverses a real network path where one lost packet would fail a valid
    // runtime closed, and re-running any other probe alongside it — above
    // all a failure-expected one — could only mask an enforcement gap. Two
    // solo attempts on top of the batch attempt keep today's three total.
    options.onProbe?.("proxy root Docker DNS retry");
    const attempts = [`attempt 1 exit=${rootDns.exit}: ${compactDiagnostic(rootDns.body) || "no output"}`];
    let succeeded = false;
    for (let attempt = 2; attempt <= 3; attempt += 1) {
      const result = runDockerExecRoot(context, io, proxyId, ["sh", "-lc", rootDnsCommand]);
      if (result.status === 0) {
        succeeded = true;
        break;
      }
      attempts.push(`attempt ${attempt} exit=${result.status}: ${compactDiagnostic(`${result.stdout}\n${result.stderr}`) || "no output"}`);
    }
    if (!succeeded) {
      issues.push(`proxy root Docker DNS failed: resolver=127.0.0.11 query=example.com; ${attempts.join("; ")}`);
    }
  }
  if (etcHostsStat) judgeProxyEtcHostsStat(issues, etcHostsStat);
  const hostServices: HostServiceFirewallObservation = hostServiceSet && hostServiceGateway
    ? observeHostServiceFirewall(issues, hostServiceSet, hostServiceGateway, options.effectiveHostServices)
    : {};

  let nftablesProofInput: ProxyNftablesProofInput | undefined;
  if (internalIface && egressIface) {
    nftablesProofInput = {
      rawJson: proxyTable.stdout,
      internalIface,
      egressIface,
      serverUid: PROXY_SERVER_UID,
      ...(hostServices.elements ? { hostServiceElements: hostServices.elements } : {}),
      ...(hostServices.expected ? { expectedHostServiceElements: hostServices.expected } : {}),
    };
    const proofIssues = validateProxyNftablesTableJson(nftablesProofInput);
    if (proofIssues.length) {
      // A kernel member the effective policy does not approve is a widening;
      // a missing one only refuses (the supervisor may be mid-write).
      const shapeIssues = validateProxyNftablesTableJson({
        ...nftablesProofInput,
        hostServiceElements: undefined,
        expectedHostServiceElements: undefined,
      });
      // A member at a different address than the status gateway is a re-pin
      // or publish-order race: it refuses (a retry recovers) but proves no
      // widening. Only a member at the status gateway on a port the
      // effective policy does not approve is a violation.
      const expectedKeys = new Set(hostServices.expected?.map(hostServiceEntryKey) ?? []);
      const unapprovedMember = hostServices.expected !== undefined && hostServices.gatewayIp !== undefined
        && (hostServices.elements ?? []).some((entry) => entry.ip === hostServices.gatewayIp
          && !expectedKeys.has(hostServiceEntryKey(entry)));
      try {
        const observed = JSON.parse(proxyTable.stdout) as { nftables?: unknown };
        if (Array.isArray(observed.nftables) && (shapeIssues.length > 0 || unapprovedMember)) options.onBoundaryViolation?.();
      } catch { /* Malformed evidence is not a proved violation. */ }
    }
    issues.push(...proofIssues);
  }
  const proof: ProxyFirewallProof = {
    nftablesProofInput,
    ...(hostServices.gatewayIp !== undefined ? { hostServiceGatewayIp: hostServices.gatewayIp } : {}),
  };

  // Warm match: the root DNS liveness probe, the server-UID denial batch and
  // the proxy-position gateway probes are not re-run.
  if (warm) return proof;

  // The proxy-position gateway probes need the pinned gateway; with none
  // published (`unavailableReason`) there is no address to probe and
  // `@host_service` was proved empty above instead.
  const gatewayIp = options.effectiveHostServices ? hostServices.gatewayIp : undefined;
  const approvedPorts = options.effectiveHostServices?.ports ?? [];
  const gatewayProbe: ServerUidGatewayProbe | undefined = gatewayIp !== undefined
    ? { gatewayIp, port: unapprovedHostServicePort(approvedPorts) }
    : undefined;

  // Exec 4 (server UID batch): the five failure-expected denial probes, plus
  // the uid-1001 unapproved-port gateway probe as one more concurrent record.
  options.onProbe?.("proxy server UID denial probes");
  applyServerUidDenialBatch(
    issues,
    runDockerExecProxyServer(context, io, proxyId, ["sh", "-lc", serverUidDenialBatchScript(gatewayProbe)]),
    options.onBoundaryViolation,
    gatewayProbe,
  );

  // Exec 5 (root): root to each approved gateway port.
  if (gatewayIp !== undefined) runRootGatewayProbes(issues, context, io, proxyId, gatewayIp, approvedPorts, options);
  return proof;
}

export function containerLogs(context: RuntimeContext, io: RuntimeIO, containerId: string): string {
  const logs = createDockerClient(io, dockerClientEnvOptions(context)).logs(containerId, { tail: 80 });
  return logs.status === 0 ? compactDiagnostic(`${logs.stdout}\n${logs.stderr}`) : "";
}
