
import net from "node:net";

import { type RuntimeNetwork } from "../network.ts";
import { validateProxyNftablesTableJson, type ProxyNftablesProofInput } from "../proxy-nftables-proof.ts";
import { warn } from "../warnings.ts";
import { PROXY_SERVER_UID } from "@runfree/proxy/firewall/nftables";
import { runDockerExec, runDockerExecAgent, runDockerExecProxyServer, runDockerExecRoot } from "./attach.ts";
import { AGENT_UID_GID } from "./constants.ts";
import { dockerClientEnvOptions, } from "./docker.ts";
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

const MCP_CALLBACK_BRIDGE_STOP_SOURCE = [
  "/* runfree_mcp_callback_bridge_stop */",
  "const fs = require('node:fs');",
  "const marker = 'runfree_mcp_callback_bridge';",
  "for (const entry of fs.readdirSync('/proc')) {",
  "  if (!/^\\d+$/.test(entry) || Number(entry) === process.pid) continue;",
  "  let cmdline = '';",
  "  try { cmdline = fs.readFileSync(`/proc/${entry}/cmdline`, 'utf8'); } catch { continue; }",
  "  if (!cmdline.includes(marker)) continue;",
  "  try { process.kill(Number(entry), 'SIGTERM'); } catch (error) {",
  "    if (!error || error.code !== 'ESRCH') throw error;",
  "  }",
  "}",
].join("\n");

const MCP_CALLBACK_BRIDGE_SOURCE = [
  "/* runfree_mcp_callback_bridge */",
  "const net = require('node:net');",
  "const host = process.argv[1];",
  "const port = Number(process.argv[2]);",
  "const probeToken = process.argv[3];",
  "if (!probeToken) process.exit(1);",
  "const server = net.createServer((client) => {",
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

function probeMcpCallbackHostPath(port: number, challenge: string): Promise<CaptureResult> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let data = "";
    let done = false;
    const finish = (result: CaptureResult) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(MCP_CALLBACK_BRIDGE_PROBE_TIMEOUT_MS, () => finish(captureResult(1, data, "callback host probe timed out")));
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
 * Starts the in-container callback bridge — a `docker exec -d` node process that
 * listens on `bindIp:port` and forwards to the container's own `127.0.0.1:port`,
 * intercepting the probe challenge with an echo. Shared by the legacy shared-agent
 * bridge (bound to the agent IP) and the per-session hop-2 bridge (bound to the
 * session IP). Stops any prior bridge first so a restart is clean.
 */
export function startMcpCallbackBridgeInContainer(
  context: RuntimeContext,
  io: RuntimeIO,
  params: Readonly<{ containerId: string; bindIp: string; port: number; challenge: string }>,
): number {
  const stop = runDockerExecAgent(context, io, params.containerId, ["node", "-e", MCP_CALLBACK_BRIDGE_STOP_SOURCE]);
  if (stop.status !== 0) {
    warn("MCP OAuth callback bridge failed to stop an existing bridge before validation");
    return stop.status;
  }
  return io.run("docker", [
    "exec",
    "-d",
    "--user",
    AGENT_UID_GID,
    params.containerId,
    "node",
    "-e",
    MCP_CALLBACK_BRIDGE_SOURCE,
    params.bindIp,
    String(params.port),
    params.challenge,
  ], dockerClientEnvOptions(context));
}

/**
 * Probes the host callback path end to end (`127.0.0.1:port` → forwarder →
 * bridge echo), honoring the test override and retrying while the sidecars come
 * up. Used by the per-session callback setup.
 */
export async function probeMcpCallbackPathWithRetries(
  context: RuntimeContext,
  port: number,
  challenge: string,
): Promise<CaptureResult> {
  if (context.env?.RUNFREE_TEST_MCP_CALLBACK_HOST_PROBE === "success") return captureResult(0);
  if (context.env?.RUNFREE_TEST_MCP_CALLBACK_HOST_PROBE === "fail") return captureResult(1, "", "forced");
  let probe = await probeMcpCallbackHostPath(port, challenge);
  for (let attempt = 2; probe.status !== 0 && attempt <= MCP_CALLBACK_BRIDGE_PROBE_ATTEMPTS; attempt += 1) {
    sleepForMcpCallbackBridgeRetry();
    probe = await probeMcpCallbackHostPath(port, challenge);
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
};

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

export const SERVER_UID_DENIAL_BATCH_SCRIPT = [
  "set -u",
  "for runfree_tool in dig ip nft timeout; do",
  "  if ! command -v \"$runfree_tool\" >/dev/null 2>&1; then",
  "    printf 'missing probe binary: %s\\n' \"$runfree_tool\" >&2",
  "    exit 96",
  "  fi",
  "done",
  "( timeout 3 dig +time=2 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1 ) & runfree_pid_0=$!",
  "( timeout 3 dig +time=2 +tries=1 @127.0.0.11 example.com >/dev/null 2>&1 ) & runfree_pid_1=$!",
  "( nft list ruleset >/dev/null 2>&1 ) & runfree_pid_2=$!",
  "( nft list set inet runfree_proxy allowed_ipv4 >/dev/null 2>&1 ) & runfree_pid_3=$!",
  "( if ip route add blackhole 203.0.113.254/32 >/dev/null 2>&1; then ip route del blackhole 203.0.113.254/32 >/dev/null 2>&1 || true; exit 0; fi; exit 1 ) & runfree_pid_4=$!",
  "wait \"$runfree_pid_0\"; runfree_status_0=$?",
  "wait \"$runfree_pid_1\"; runfree_status_1=$?",
  "wait \"$runfree_pid_2\"; runfree_status_2=$?",
  "wait \"$runfree_pid_3\"; runfree_status_3=$?",
  "wait \"$runfree_pid_4\"; runfree_status_4=$?",
  `printf '${FIREWALL_PROBE_MARKER} 0 exit=%s\\n' "$runfree_status_0"`,
  `printf '${FIREWALL_PROBE_MARKER} 1 exit=%s\\n' "$runfree_status_1"`,
  `printf '${FIREWALL_PROBE_MARKER} 2 exit=%s\\n' "$runfree_status_2"`,
  `printf '${FIREWALL_PROBE_MARKER} 3 exit=%s\\n' "$runfree_status_3"`,
  `printf '${FIREWALL_PROBE_MARKER} 4 exit=%s\\n' "$runfree_status_4"`,
  "exit 0",
].join("\n");

/**
 * Judges the batched server-UID denial records. No retry of failure-expected
 * probes; exit 0 is an enforcement gap, 126/127 is could-not-run (a validation
 * failure, not a denial — today's single-exec conflation, strengthened), and
 * any missing, duplicated, reordered, or extra record fails the validation.
 */
export function applyServerUidDenialBatch(issues: string[], result: CaptureResult, onBoundaryViolation?: () => void): void {
  const batchFailure = (detail: string): void => {
    issues.push(`proxy server UID nftables and route denial batch could not run${detail ? `: ${detail}` : ""}`);
  };
  if (result.status !== 0) {
    batchFailure(compactDiagnostic(`${result.stderr}\n${result.stdout}`));
    return;
  }
  if (Buffer.byteLength(result.stdout) > FIREWALL_BATCH_OUTPUT_MAX_BYTES) {
    batchFailure("probe records exceeded the bounded output size");
    return;
  }
  const records = result.stdout.split(/\r?\n/u).filter((line) => line.trim() !== "");
  if (records.length !== SERVER_UID_DENIAL_PROBE_LABELS.length) {
    batchFailure(`expected ${SERVER_UID_DENIAL_PROBE_LABELS.length} probe records, got ${records.length}`);
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
    const label = SERVER_UID_DENIAL_PROBE_LABELS[index];
    if (exit === 0) {
      onBoundaryViolation?.();
      issues.push(`${label} unexpectedly succeeded`);
    } else if (exit === 126 || exit === 127) {
      issues.push(`${label} could not run inside the proxy (exit ${exit})`);
    }
  });
}

export function validateProxyFirewall(
  issues: string[],
  context: RuntimeContext,
  io: RuntimeIO,
  proxyId: string,
  runtimeNetwork: RuntimeNetwork,
  options: RuntimeProbeProgressOptions = {},
): ProxyFirewallProof {
  // Exec 1 (default daemon user): both route inspections, one framed batch.
  options.onProbe?.("proxy internal and egress route inspections");
  let internalIface: string | undefined;
  let egressIface: string | undefined;
  if (!IPV4_LITERAL_PATTERN.test(runtimeNetwork.agentIp)) {
    issues.push(`proxy internal route inspection failed: agent address is not IPv4: ${runtimeNetwork.agentIp}`);
  } else {
    const routeBatch = runDockerExec(context, io, proxyId, ["sh", "-c", firewallSectionBatchScript([
      `ip -o route get ${runtimeNetwork.agentIp}`,
      "ip -o route get 1.1.1.1",
    ])]);
    const routeSections = parseFirewallSectionBatch(routeBatch, 2);
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
  const proxyTable = runDockerExecRoot(context, io, proxyId, ["nft", "-j", "list", "table", "inet", "runfree_proxy"]);
  expectProbeSuccess(issues, "proxy nftables owned-table inspection", proxyTable);
  if (proxyTable.status !== 0) return {};
  let nftablesProofInput: ProxyNftablesProofInput | undefined;
  if (internalIface && egressIface) {
    nftablesProofInput = {
      rawJson: proxyTable.stdout,
      internalIface,
      egressIface,
      serverUid: PROXY_SERVER_UID,
    };
    const shapeIssues = validateProxyNftablesTableJson(nftablesProofInput);
    if (shapeIssues.length) {
      try {
        const observed = JSON.parse(proxyTable.stdout) as { nftables?: unknown };
        if (Array.isArray(observed.nftables)) options.onBoundaryViolation?.();
      } catch { /* Malformed evidence is not a proved violation. */ }
    }
    issues.push(...shapeIssues);
  }

  // Exec 3 (root batch): allowlist-set inspection plus root Docker DNS.
  options.onProbe?.("proxy nftables allowlist set inspection and root Docker DNS");
  const rootDnsCommand = "timeout 3 dig +time=2 +tries=1 @127.0.0.11 example.com";
  const rootBatch = runDockerExecRoot(context, io, proxyId, ["sh", "-lc", firewallSectionBatchScript([
    "nft list set inet runfree_proxy allowed_ipv4",
    rootDnsCommand,
  ])]);
  const rootSections = parseFirewallSectionBatch(rootBatch, 2);
  if (!rootSections) {
    const detail = compactDiagnostic(`${rootBatch.stderr}\n${rootBatch.stdout}`);
    issues.push(`proxy nftables allowlist set inspection failed: root batch was missing or garbled${detail ? `: ${detail}` : ""}`);
    issues.push(`proxy root Docker DNS failed: root batch was missing or garbled${detail ? `: ${detail}` : ""}`);
  } else {
    const [allowedSet, rootDns] = rootSections;
    if (allowedSet.exit !== 0) {
      issues.push(`proxy nftables allowlist set inspection failed: ${compactDiagnostic(allowedSet.body) || `exit ${allowedSet.exit}`}`);
    } else if (!allowedSet.body.includes("set allowed_ipv4")) {
      issues.push("proxy firewall must expose the allowed_ipv4 nftables set for live inspection");
    }
    if (rootDns.exit !== 0) {
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
  }

  // Exec 4 (server UID batch): the five failure-expected denial probes.
  options.onProbe?.("proxy server UID denial probes");
  applyServerUidDenialBatch(
    issues,
    runDockerExecProxyServer(context, io, proxyId, ["sh", "-lc", SERVER_UID_DENIAL_BATCH_SCRIPT]),
    options.onBoundaryViolation,
  );
  return { nftablesProofInput };
}

export function containerLogs(context: RuntimeContext, io: RuntimeIO, containerId: string): string {
  const logs = io.capture("docker", ["logs", "--tail", "80", containerId], dockerClientEnvOptions(context));
  return logs.status === 0 ? compactDiagnostic(`${logs.stdout}\n${logs.stderr}`) : "";
}
