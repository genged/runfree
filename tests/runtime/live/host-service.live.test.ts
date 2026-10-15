// Host-service live tranche (core tier): an approved service on the host's
// loopback, reached by the agent through its loopback relay and the proxy's
// opaque splice to the pinned Docker Desktop host gateway, and nothing else.
//
// Setup: a TCP echo server on host 127.0.0.1 (an approved port P and an
// unapproved port Q, both OS-chosen), the seeded sandbox project, `runfree
// host-service add echo --port P` converged live, `runfree up` to select the
// session agent that renders it (the startup a production launch runs), then
// a standing session.
//
// The echo server runs in a child process, not in this test process: every
// Docker and CLI call here is `spawnSync`, which blocks this process's event
// loop, so an in-process server could never answer a connection the agent
// makes during one of those calls. The child records every connection, byte
// and close to a log file, which is the host's own view of the splice.
//
// What each case proves, and what is a recorded proof gap rather than a proof:
//
//   1. reachable: an in-session client on 127.0.0.1:P gets its nonce back, and
//      the host log shows that nonce arriving on P.
//   2. unapproved pairs (wrong port, wrong name, the suffix on 443) get a raw
//      403 from the proxy and the host sees no connection at all.
//   2b. loopback MCP grants no reach (T1, S5): a project `.mcp.json` entry
//      `http://127.0.0.1:<Q>/mcp` on the unapproved port, enabled without a
//      terminal, lands in a new session's generated Claude config, leaves its
//      `RUNFREE_HOST_SERVICES` unchanged, and gets no in-session listener on Q
//      (while the relay's row on P shows the read works). An in-session dial
//      to the URL's host and port is refused (ECONNREFUSED), the host listener
//      on Q records zero accepts (and then one, for a direct host connection:
//      the positive control), and the proxy logs nothing naming Q.
//   3. no direct path: the session cannot connect to <gateway>:P; root in the
//      proxy times out on it (a dropped SYN), while uid 1001 in the proxy
//      connects (the positive control that makes root's timeout meaningful).
//   4. set members: `@host_service` is exactly `<gateway> . P`.
//   5. no cross-session reach: a second session cannot connect to the first
//      session's relay port, while it can reach a 0.0.0.0 listener in the
//      first session (the positive control).
//   6. admission and registry: static refusals, no listener, a Docker
//      Desktop-owned port; `forward` and `vnc` in another project refuse the
//      approved port and name this project; a corrupt registry refuses and
//      `host-service list --repair` recovers it.
//   7. revocation: `host-service remove` closes an open relay connection on
//      both sides. The request-proxy cut is proven alone: a root nft rule
//      accepts exactly this pair above the `@host_service_draining` drop for
//      the whole removal, so the firewall cut cannot act, and the host still
//      sees the connection close (the proxy's own FIN).
//   7b. firewall-only cut (R19): a root flow in the proxy, opened through a
//      one-shot root rule, is one the request proxy does not track. After
//      `host-service remove` and past the drain window, new bytes on it never
//      reach the host: the pinned-gateway drop above the established accept
//      holds the cut with no time limit.
//   8. session stop: the host sees the splice close when its session ends.
//      The session's processes die with the container, so this does not
//      separate the proxy's revoke-driven socket cut from an ordinary client
//      close; it proves only that no splice outlives its session.
//   8b. loopback MCP reaches an approved host service (T8, Claude): a host
//      MCP stub on port P', approved as host service `mcpstub`, and a project
//      loopback entry for it. After the session's relay listens on P', the
//      pinned Claude lists its MCP servers with the session's own proxy
//      environment; the stub logs `initialize` and `tools/list`, and the proxy
//      logs no request to 127.0.0.1. The probe command is UNVERIFIED (see the
//      case). Codex is a skipped case: no probe is known (spec Q2).
//   9. gateway change and reclaim (HS8): a rewritten `/etc/hosts` alias makes
//      host services refuse with `gateway address changed`; the firewall
//      drains the pinned pair, and the request proxy's gateway watch cuts the
//      already-open splice (the client sees the close, the proxy logs
//      `host-service splices cut` naming the withdrawn gateway). Past the
//      drain window, when the established accept would pass the flow again,
//      no established proxy socket to the old pair remains and the host saw
//      no new bytes on it. `runfree rebuild` re-pins and the echo works again.
//
// Recorded proof gaps (not staged here, never faked):
//
//   - The firewall cut of a request-proxy splice, on `host-service remove`
//     or on a gateway change: the request proxy cuts a removed pair's
//     splices on reload and cuts every splice on a withdrawn or changed
//     gateway, with no switch to disable either. Case 7b stages the firewall
//     cut alone on a root flow the request proxy does not track, which is
//     the same kernel path (the drops are not uid-scoped); the rule order is
//     covered by the ruleset proof and the supervisor unit tests.
//   - A changed proxy `HostConfig.ExtraHosts` failing the topology proof with
//     `proxy-extra-hosts-exact`: a running container's ExtraHosts cannot be
//     changed without recreating it from a different Compose template. The
//     unit inspect test covers it; case 3 reads back the exact shipped entry.
//   - A missing relay binary not changing the entry's exit code: that needs a
//     project image without the relay; `scripts/session-entry.test.ts` covers
//     it against the real entry script.
//   - F29 (startup top-ten): the launch-time warning loop now answers every
//     approved host service from one bounded `lsof -iTCP -sTCP:LISTEN -Fpcn`
//     observation of every TCP listener on the host instead of one
//     `lsof -iTCP:<port>` call per service (host-listener-snapshot.ts). The
//     `up` assertion in `beforeAll` proves visibility and owner accuracy for
//     this fixture's one real listener on a real macOS/Docker Desktop host,
//     but a Docker sandbox has no way to stage "0 real listeners", "1 real
//     listener", "10 real listeners", or a high ambient host-process count
//     without faking the host's own process table -- the controller ruling
//     for this task is explicit that the 0/1/10 real-listener measurements
//     and this production-context visibility proof are OWED to the
//     maintainer's macOS host, not simulated here. The parser's own fixture
//     coverage (multi-owner, multi-address, malformed/truncated/timeout
//     output, the ordered-warning-line equivalence with the per-port probe)
//     is unit-level: host-listener-snapshot.test.ts.
//   - T8 for Codex (spec Q2): no command is known that makes the pinned
//     codex-cli connect to its MCP servers without a model login, so case 8b
//     has no Codex half. The Claude half's probe command is the plan's
//     candidate and must be confirmed on a Docker host.


import childProcess from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { runfreeStateRoot } from "../../../packages/cli/src/paths.ts";
import { refusedHostServicePortReason } from "../../../packages/runtime-contracts/src/host-services.ts";
import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow, waitUntil } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  forceCleanSessions,
  provisionSandboxFixture,
  releaseStandingSessions,
  startStandingSession,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  type StandingSessionHandle,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;
const REBUILD_TEST_TIMEOUT_MS = 40 * 60_000;
const SERVICE_NAME = "echo";
const GATEWAY_ALIAS = "gateway.runfree.internal";
const GATEWAY_STATUS_PATH = "/run/runfree-proxy-status/host-service-gateway.json";
const NFT_TABLE = "runfree_proxy";
/** The proxy's host-service drain window (PROXY_HOST_SERVICE_DRAIN_SECONDS default). */
const DRAIN_WINDOW_MS = 30_000;
/** Firewall maintenance runs every 2 s; this allows several ticks. */
const MAINTENANCE_WAIT_MS = 30_000;
const BYPASS_COMMENT = "runfree-livetest-drain-bypass";
const ROOT_OPENER_COMMENT = "runfree-livetest-root-opener";
/** A public address: the gateway validator requires RFC 1918. */
const TAMPERED_GATEWAY = "1.1.1.1";

const PROXY_ENV_UNSET = [
  "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
  "-u", "ALL_PROXY", "-u", "all_proxy", "-u", "NO_PROXY", "-u", "no_proxy",
] as const;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the host-service tranche");
  }
  return backend;
}

function nonce(label: string): string {
  return `${label}-${randomBytes(8).toString("hex")}`;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollUntil(predicate: () => boolean, options: { timeoutMs: number; intervalMs?: number; label: string }): Promise<void> {
  const deadline = Date.now() + options.timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() >= deadline) throw new Error(`timed out after ${options.timeoutMs}ms waiting for ${options.label}`);
    await sleep(options.intervalMs ?? 250);
  }
}

// ---------------------------------------------------------------------------
// The host echo server (a child process; see the header).
// ---------------------------------------------------------------------------

const ECHO_SERVER_PROGRAM = `
const net = require("node:net");
const fs = require("node:fs");
const log = process.argv[1];
let next = 0;
const record = (event) => fs.appendFileSync(log, JSON.stringify(event) + "\\n");
const serve = (label) => new Promise((resolve, reject) => {
  const server = net.createServer((socket) => {
    const id = ++next;
    record({ event: "open", label, id });
    socket.on("data", (chunk) => { record({ event: "data", label, id, text: chunk.toString("utf8") }); socket.write(chunk); });
    socket.on("error", (error) => record({ event: "error", label, id, code: error.code || String(error) }));
    socket.on("close", () => record({ event: "close", label, id }));
  });
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => resolve(server.address().port));
});
Promise.all([serve("approved"), serve("unapproved")]).then(([approved, unapproved]) => {
  process.stdout.write(JSON.stringify({ approved, unapproved }) + "\\n");
}, (error) => { process.stderr.write(String(error) + "\\n"); process.exit(1); });
`;

type EchoEvent = Readonly<{ event: "open" | "data" | "error" | "close"; label: "approved" | "unapproved"; id: number; text?: string }>;

type EchoServer = Readonly<{
  approvedPort: number;
  unapprovedPort: number;
  events(): readonly EchoEvent[];
  stop(): void;
}>;

async function startEchoServer(): Promise<EchoServer> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-host-service-echo."));
  const logPath = path.join(dir, "events.jsonl");
  fs.writeFileSync(logPath, "");
  const child = childProcess.spawn(process.execPath, ["-e", ECHO_SERVER_PROGRAM, logPath], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += String(chunk); });
  child.stderr.on("data", (chunk) => { stderr = (stderr + String(chunk)).slice(-4096); });
  const deadline = Date.now() + 10_000;
  while (!stdout.includes("\n")) {
    if (child.exitCode !== null || Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`the host echo server did not start: ${describeOutput(stderr)}`);
    }
    await sleep(50);
  }
  const ports = JSON.parse(stdout.split("\n")[0]) as { approved: number; unapproved: number };
  return Object.freeze({
    approvedPort: ports.approved,
    unapprovedPort: ports.unapproved,
    events: () => fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as EchoEvent),
    stop: () => {
      child.kill("SIGKILL");
      fs.rmSync(dir, { recursive: true, force: true });
    },
  });
}

/** The host-side connection id that carried `text`, if any did. */
function hostConnectionCarrying(echo: EchoServer, text: string): number | undefined {
  return echo.events().find((event) => event.event === "data" && event.text?.includes(text))?.id;
}

function hostConnectionClosed(echo: EchoServer, id: number): boolean {
  return echo.events().some((event) => event.event === "close" && event.id === id);
}

function hostOpenCount(echo: EchoServer, label: EchoEvent["label"]): number {
  return echo.events().filter((event) => event.event === "open" && event.label === label).length;
}

/** A host port nothing listens on: bound by the OS, then released. */
async function freeHostPort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

// ---------------------------------------------------------------------------
// In-session probes. Every program is passed as argv, never shell-quoted.
// ---------------------------------------------------------------------------

/** One exchange: connect, send a nonce line, report how the connection ended. */
const EXCHANGE_PROGRAM = `
const net = require("node:net");
const host = process.argv[1];
const port = Number(process.argv[2]);
const text = process.argv[3];
let data = "";
let settled = false;
const socket = net.connect({ host, port });
const finish = (outcome, detail) => {
  if (settled) return;
  settled = true;
  clearTimeout(timer);
  socket.destroy();
  process.stdout.write(JSON.stringify({ outcome, data, detail: detail || null }) + "\\n");
  process.exit(0);
};
const timer = setTimeout(() => finish("timeout"), Number(process.argv[4] || 8000));
socket.on("connect", () => socket.write(text + "\\n"));
socket.on("data", (chunk) => { data += chunk.toString("utf8"); if (data.includes(text)) finish("echoed"); });
socket.on("close", () => finish(data ? "closed-with-data" : "closed-without-data"));
socket.on("error", (error) => finish("error", error.code || error.message));
`;

type ExchangeOutcome = Readonly<{ outcome: "echoed" | "closed-with-data" | "closed-without-data" | "error" | "timeout"; data: string; detail: string | null }>;

function sessionExchange(sessionId: string, host: string, port: number, text: string, timeoutMs = 8000): ExchangeOutcome {
  const result = docker(["exec", sessionId, "env", ...PROXY_ENV_UNSET, "node", "-e", EXCHANGE_PROGRAM, host, String(port), text, String(timeoutMs)]);
  const line = result.stdout.trim().split("\n").at(-1) ?? "";
  try {
    return JSON.parse(line) as ExchangeOutcome;
  } catch {
    throw new Error(`the in-session exchange probe did not run: ${describeOutput(result.output)}`);
  }
}

/** A raw CONNECT straight to the proxy, as an agent that skips the relay would send it. */
const RAW_CONNECT_PROGRAM = `
const net = require("node:net");
const proxyHost = process.argv[1];
const authority = process.argv[2];
let response = "";
let settled = false;
const socket = net.connect({ host: proxyHost, port: 8080 });
const finish = (tag) => {
  if (settled) return;
  settled = true;
  clearTimeout(timer);
  socket.destroy();
  process.stdout.write(JSON.stringify({ tag, response }) + "\\n");
  process.exit(0);
};
const timer = setTimeout(() => finish("timeout"), 10000);
socket.on("connect", () => socket.write("CONNECT " + authority + " HTTP/1.1\\r\\nHost: " + authority + "\\r\\n\\r\\n"));
socket.on("data", (chunk) => { response += chunk.toString("latin1"); if (response.length > 16384) finish("overflow"); });
socket.on("close", () => finish("closed"));
socket.on("error", (error) => { response += "\\nsocket-error " + (error.code || error.message); });
`;

function sessionRawConnect(sessionId: string, proxyIp: string, authority: string): string {
  const result = docker(["exec", sessionId, "env", ...PROXY_ENV_UNSET, "node", "-e", RAW_CONNECT_PROGRAM, proxyIp, authority]);
  const line = result.stdout.trim().split("\n").at(-1) ?? "";
  try {
    return (JSON.parse(line) as { response: string }).response;
  } catch {
    throw new Error(`the raw CONNECT probe did not run: ${describeOutput(result.output)}`);
  }
}

/**
 * A long-lived relay client driven over stdin: one line out per line in.
 * argv[3] is a kill marker: never read, present only so this exact process
 * can be found and killed by its argv (see \`killMarkedProcess\`) — a bare
 * \`child.kill()\` on the host-side \`docker exec\` CLI leaves this process,
 * and its open socket, running inside the container.
 */
const LONG_LIVED_CLIENT_PROGRAM = `
const net = require("node:net");
const port = Number(process.argv[1]);
const socket = net.connect({ host: process.argv[2], port });
let incoming = "";
let outgoing = "";
socket.on("connect", () => console.log("connected"));
socket.on("data", (chunk) => {
  incoming += chunk.toString("utf8");
  let index;
  while ((index = incoming.indexOf("\\n")) >= 0) { console.log("echo " + incoming.slice(0, index)); incoming = incoming.slice(index + 1); }
});
socket.on("error", (error) => console.log("error " + (error.code || error.message)));
socket.on("close", () => { console.log("closed"); process.exit(0); });
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  outgoing += chunk;
  let index;
  while ((index = outgoing.indexOf("\\n")) >= 0) { socket.write(outgoing.slice(0, index) + "\\n"); outgoing = outgoing.slice(index + 1); }
});
`;

type LongLivedClient = Readonly<{
  send(text: string): void;
  lines(): readonly string[];
  waitForLine(line: string, timeoutMs: number): Promise<void>;
  stop(): void;
}>;

/** Every long-lived client this tranche has opened, for the afterAll sweep. */
type MarkedClient = Readonly<{ containerId: string; marker: string; asRoot: boolean }>;
const markedClients: MarkedClient[] = [];

function openLongLivedClient(sessionId: string, port: number): LongLivedClient {
  const marker = nonce("runfree-livetest-client");
  return spawnLongLivedClient(
    ["exec", "-i", sessionId, "env", ...PROXY_ENV_UNSET, "node", "-e", LONG_LIVED_CLIENT_PROGRAM, String(port), "127.0.0.1", marker],
    { containerId: sessionId, marker, asRoot: false },
  );
}

/**
 * A root-owned client inside the proxy container, connected straight to
 * `gateway:port`. The request proxy never sees it, so no request-proxy cut
 * can close it: only the firewall can stop its bytes.
 */
function openRootProxyClient(proxyId: string, gateway: string, port: number): LongLivedClient {
  const marker = nonce("runfree-livetest-client");
  return spawnLongLivedClient(
    ["exec", "-i", "--user", "0:0", proxyId, "node", "-e", LONG_LIVED_CLIENT_PROGRAM, String(port), gateway, marker],
    { containerId: proxyId, marker, asRoot: true },
  );
}

function spawnLongLivedClient(dockerArgs: readonly string[], marked: MarkedClient): LongLivedClient {
  // Asynchronous on purpose: this client must stay open across the CLI and
  // Docker calls the case makes while it is connected.
  const child = childProcess.spawn("docker", [...dockerArgs], { stdio: ["pipe", "pipe", "pipe"] });
  markedClients.push(marked);
  const received: string[] = [];
  let partial = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    partial += String(chunk);
    for (let index = partial.indexOf("\n"); index >= 0; index = partial.indexOf("\n")) {
      received.push(partial.slice(0, index));
      partial = partial.slice(index + 1);
    }
  });
  child.stderr.on("data", (chunk) => { stderr = (stderr + String(chunk)).slice(-4096); });
  let stopped = false;
  return Object.freeze({
    send: (text: string) => { child.stdin.write(`${text}\n`); },
    lines: () => [...received],
    waitForLine: async (line: string, timeoutMs: number) => {
      await pollUntil(() => received.includes(line), { timeoutMs, label: `the relay client to print ${JSON.stringify(line)}` })
        .catch((error: unknown) => {
          throw new Error(`${String(error)}; client output: ${describeOutput(received.join(" | "))}; stderr: ${describeOutput(stderr)}`);
        });
    },
    // Killing only the host-side `docker exec` CLI leaves the in-container
    // process (and its open socket) running: that is the leak this closes.
    // Idempotent, and never throws — a cleanup failure here must not replace
    // a case's own assertion failure; the afterAll sweep is the backstop.
    stop: () => {
      if (stopped) return;
      stopped = true;
      try {
        killMarkedProcess(marked.containerId, marked.marker, marked.asRoot);
      } catch (error) {
        console.warn(`could not confirm the marked client ${marked.marker} exited: ${String(error)}`);
      }
      child.kill("SIGKILL");
    },
  });
}

/**
 * Kills, inside its container, every process whose argv contains `marker` —
 * read directly from `/proc/<pid>/cmdline`, since neither the proxy nor the
 * agent image is guaranteed to carry procps (`pkill`/`pgrep`). A container or
 * exec target that is already gone counts as "already killed": cleanup must
 * never be what fails a run. Bounded: polls until no matching process remains.
 */
function killMarkedProcess(containerId: string, marker: string, asRoot: boolean): void {
  const user = asRoot ? ["--user", "0:0"] : [];
  const run = (program: string): CaptureResult => docker(["exec", ...user, containerId, "node", "-e", program, marker]);
  const killed = run(KILL_MARKED_PROCESS_PROGRAM);
  if (killed.status !== 0) return; // the container (or its exec target) is already gone.
  waitUntil(() => {
    const counted = run(COUNT_MARKED_PROCESS_PROGRAM);
    return counted.status !== 0 || counted.stdout.trim() === "0";
  }, { timeoutMs: 5_000, intervalMs: 100, label: `the marked client ${marker} in ${containerId.slice(0, 12)} to exit` });
}

const KILL_MARKED_PROCESS_PROGRAM = `
const fs = require("node:fs");
const marker = process.argv[1];
for (const entry of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(entry) || Number(entry) === process.pid) continue;
  let cmdline;
  try { cmdline = fs.readFileSync("/proc/" + entry + "/cmdline", "utf8"); } catch { continue; }
  if (!cmdline.includes(marker)) continue;
  try { process.kill(Number(entry), "SIGKILL"); } catch {}
}
`;

const COUNT_MARKED_PROCESS_PROGRAM = `
const fs = require("node:fs");
const marker = process.argv[1];
let count = 0;
for (const entry of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(entry)) continue;
  let cmdline;
  try { cmdline = fs.readFileSync("/proc/" + entry + "/cmdline", "utf8"); } catch { continue; }
  if (cmdline.includes(marker)) count++;
}
process.stdout.write(String(count) + "\\n");
`;

// ---------------------------------------------------------------------------
// Proxy-side reads. Each is a direct daemon or kernel read, not a product
// derivation.
// ---------------------------------------------------------------------------

type GatewayStatus = Readonly<{ policyGeneration?: string; gatewayIp?: string; unavailableReason?: string }>;

function readGatewayStatus(proxyId: string): GatewayStatus {
  const text = dockerOrThrow("host-service gateway status", ["exec", "--user", "0:0", proxyId, "cat", GATEWAY_STATUS_PATH]);
  return JSON.parse(text) as GatewayStatus;
}

function pinnedGateway(proxyId: string): string {
  const status = readGatewayStatus(proxyId);
  if (!status.gatewayIp || !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(status.gatewayIp)) {
    throw new Error(`the proxy published no host-service gateway: ${JSON.stringify(status)}`);
  }
  return status.gatewayIp;
}

/** The `ip . port` members of one proxy-owned host-service set, or throws. */
function hostServiceSetMembers(proxyId: string, setName: "host_service" | "host_service_draining"): readonly string[] {
  const json = dockerOrThrow(`${setName} set`, ["exec", "--user", "0:0", proxyId, "nft", "-j", "list", "set", "inet", NFT_TABLE, setName]);
  const parsed = JSON.parse(json) as { nftables?: { set?: { elem?: unknown[] } }[] };
  const set = (parsed.nftables ?? []).map((statement) => statement.set).find(Boolean);
  if (!set) throw new Error(`nft printed no ${setName} set: ${describeOutput(json)}`);
  const members: string[] = [];
  for (const element of set.elem ?? []) {
    const value = element && typeof element === "object" && "elem" in element
      ? (element as { elem?: { val?: unknown } }).elem?.val
      : element;
    const concat = value && typeof value === "object" ? (value as { concat?: unknown }).concat : undefined;
    if (!Array.isArray(concat) || concat.length !== 2) throw new Error(`unexpected ${setName} element: ${JSON.stringify(element)}`);
    members.push(`${String(concat[0])} . ${String(concat[1])}`);
  }
  return members.sort();
}

function outputChainWithHandles(proxyId: string): string {
  return dockerOrThrow("output chain", ["exec", "--user", "0:0", proxyId, "nft", "-a", "list", "chain", "inet", NFT_TABLE, "output"]);
}

/**
 * Disables only the firewall's cut for one pair: a root rule accepting the
 * established flows of exactly `gateway:port`, placed immediately above the
 * `@host_service_draining` drop. It admits no new connection.
 * Removed by `removeDrainBypass`; a leftover rule fails the next launch's
 * ruleset proof, so it can never pass silently.
 */
function installDrainBypass(proxyId: string, gateway: string, port: number): void {
  const chain = outputChainWithHandles(proxyId);
  const match = /@host_service_draining drop # handle (\d+)/u.exec(chain);
  if (!match) throw new Error(`the output chain has no host_service_draining drop: ${describeOutput(chain)}`);
  dockerOrThrow("install drain bypass", [
    "exec", "--user", "0:0", proxyId, "nft", "insert", "rule", "inet", NFT_TABLE, "output", "position", match[1],
    "ip", "daddr", gateway, "tcp", "dport", String(port), "ct", "state", "established,related",
    "accept", "comment", `"${BYPASS_COMMENT}"`,
  ]);
  if (!drainBypassPresent(proxyId)) throw new Error("the drain bypass rule did not land in the output chain");
}

function drainBypassPresent(proxyId: string): boolean {
  return outputChainWithHandles(proxyId).includes(BYPASS_COMMENT);
}

function removeDrainBypass(proxyId: string): void {
  removeCommentedRules(proxyId, BYPASS_COMMENT);
}

function removeCommentedRules(proxyId: string, comment: string): void {
  for (const line of outputChainWithHandles(proxyId).split("\n")) {
    const match = line.includes(comment) ? /# handle (\d+)/u.exec(line) : null;
    if (match) dockerOrThrow(`remove ${comment}`, ["exec", "--user", "0:0", proxyId, "nft", "delete", "rule", "inet", NFT_TABLE, "output", "handle", match[1]]);
  }
  if (outputChainWithHandles(proxyId).includes(comment)) throw new Error(`the ${comment} rule is still in the output chain`);
}

/**
 * Lets root open one NEW flow to exactly `gateway:port`: a rule at the top
 * of the output chain. Root has no host-service accept of its own (uid 1001
 * only), so this is the only way to stage a flow the request proxy does not
 * track. Removed by `removeCommentedRules` right after the connect; a
 * leftover rule fails the next launch's ruleset proof.
 */
function installRootOpener(proxyId: string, gateway: string, port: number): void {
  dockerOrThrow("install root opener", [
    "exec", "--user", "0:0", proxyId, "nft", "insert", "rule", "inet", NFT_TABLE, "output",
    "meta", "skuid", "0", "ip", "daddr", gateway, "tcp", "dport", String(port), "ct", "state", "new",
    "accept", "comment", `"${ROOT_OPENER_COMMENT}"`,
  ]);
  if (!outputChainWithHandles(proxyId).includes(ROOT_OPENER_COMMENT)) throw new Error("the root opener rule did not land in the output chain");
}

function proxyLogsSince(proxyId: string, sinceIso: string): string {
  return dockerOrThrow("proxy logs", ["logs", "--since", sinceIso, proxyId]);
}

/**
 * The proxy's ESTABLISHED TCP sockets to exactly `ip:port`, each identified
 * by its own local port, read by root from the proxy network namespace's
 * `/proc/net/tcp` (state 01). A direct kernel read: an open splice's upstream
 * leg is one such socket, and its local port is what makes one flow (and its
 * disappearance) distinguishable from any other that happens to share the
 * remote pair.
 */
const ESTABLISHED_FLOWS_PROGRAM = `
const [ip, port] = process.argv.slice(1);
const hex = (value, width) => value.toString(16).toUpperCase().padStart(width, "0");
const remote = ip.split(".").reverse().map((octet) => hex(Number(octet), 2)).join("") + ":" + hex(Number(port), 4);
const rows = require("node:fs").readFileSync("/proc/net/tcp", "utf8").split("\\n").slice(1).filter(Boolean);
const localPorts = rows
  .map((row) => row.trim().split(/\\s+/))
  .filter((fields) => fields[2] === remote && fields[3] === "01")
  .map((fields) => parseInt(fields[1].split(":")[1], 16));
process.stdout.write(JSON.stringify(localPorts) + "\\n");
`;

/** The local ports of the proxy's ESTABLISHED sockets to exactly `ip:port`. */
function establishedProxyLocalPorts(proxyId: string, ip: string, port: number): readonly number[] {
  const text = dockerOrThrow("proxy established flows", ["exec", "--user", "0:0", proxyId, "node", "-e", ESTABLISHED_FLOWS_PROGRAM, ip, String(port)]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.trim());
  } catch {
    throw new Error(`the established-flow probe printed ${describeOutput(text)}`);
  }
  if (!Array.isArray(parsed) || !parsed.every((value) => Number.isInteger(value))) {
    throw new Error(`the established-flow probe printed ${describeOutput(text)}`);
  }
  return parsed as number[];
}

function hostDataEvents(echo: EchoServer, id: number): number {
  return echo.events().filter((event) => event.event === "data" && event.id === id).length;
}

// ---------------------------------------------------------------------------
// Loopback MCP (T1, T8): the host MCP stub, the in-session listener read, and
// the generated config read.
// ---------------------------------------------------------------------------

/** The project `.mcp.json` entry T1 points at the unapproved port Q. */
const LOOPBACK_PROBE_SERVER = "qprobe";
/** The T8 MCP server name and the host service that backs its port. */
const STUB_SERVER = "mcpstub";
const STUB_SERVICE_NAME = "mcpstub";
const SESSION_CLAUDE_MCP_CONFIG = "/runfree/mcp/claude.json";
/**
 * The pinned Claude binary in the sandbox project image. The fixture's image
 * moves the real `claude-real` here and puts a recorder stand-in in its place
 * (fixture.ts, MANAGED_IMAGE_DOCKERFILE_STANZA), so `claude` in the session is
 * not the real agent. Calling this path directly skips the `claude` launcher,
 * so the probe passes the two flags the launcher would prepend itself.
 */
const PINNED_CLAUDE = "/usr/local/libexec/runfree/claude-real-pinned";

/**
 * A minimal Streamable-HTTP MCP server for the host, run as a child process
 * for the same reason as the echo server. It answers `initialize`,
 * `notifications/initialized` (202, no body), `tools/list` (one tool, `ping`),
 * and `ping`; GET on the endpoint gets 405 (no server-sent event stream), and
 * any other path 404. Every request is logged before it is answered, with the
 * JSON-RPC method names it carried: the log is the host's own view of which
 * MCP calls arrived.
 */
const MCP_STUB_PROGRAM = `
const http = require("node:http");
const fs = require("node:fs");
const log = process.argv[1];
const record = (event) => fs.appendFileSync(log, JSON.stringify(event) + "\\n");
const server = http.createServer((req, res) => {
  let body = "";
  req.setEncoding("utf8");
  req.on("data", (chunk) => { body += chunk; if (body.length > 1048576) req.destroy(); });
  req.on("end", () => {
    let parsed;
    try { parsed = body ? JSON.parse(body) : undefined; } catch { parsed = undefined; }
    const batch = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
    const pathname = new URL(req.url || "/", "http://stub").pathname;
    record({
      httpMethod: req.method,
      path: pathname,
      rpc: batch.map((message) => message && typeof message.method === "string" ? message.method : null),
      userAgent: req.headers["user-agent"] || null,
    });
    if (pathname !== "/mcp") { res.writeHead(404); res.end(); return; }
    if (req.method !== "POST") { res.writeHead(405, { allow: "POST" }); res.end(); return; }
    const answers = [];
    for (const message of batch) {
      if (!message || message.id === undefined || message.id === null) continue;
      const reply = (result) => answers.push({ jsonrpc: "2.0", id: message.id, result });
      if (message.method === "initialize") {
        reply({
          protocolVersion: (message.params && message.params.protocolVersion) || "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "runfree-livetest-mcp-stub", version: "0.0.0" },
        });
      } else if (message.method === "tools/list") {
        reply({ tools: [{ name: "ping", description: "Runfree live-test stub tool", inputSchema: { type: "object", properties: {} } }] });
      } else if (message.method === "ping") {
        reply({});
      } else {
        answers.push({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "method not found" } });
      }
    }
    if (answers.length === 0) { res.writeHead(202); res.end(); return; }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(Array.isArray(parsed) ? answers : answers[0]));
  });
});
server.once("error", (error) => { process.stderr.write(String(error) + "\\n"); process.exit(1); });
server.listen(0, "127.0.0.1", () => process.stdout.write(JSON.stringify({ port: server.address().port }) + "\\n"));
`;

type McpStubRequest = Readonly<{ httpMethod: string; path: string; rpc: readonly (string | null)[]; userAgent: string | null }>;

type McpStub = Readonly<{
  port: number;
  requests(): readonly McpStubRequest[];
  stop(): void;
}>;

async function startMcpStub(): Promise<McpStub> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-host-service-mcp-stub."));
  const logPath = path.join(dir, "requests.jsonl");
  fs.writeFileSync(logPath, "");
  const child = childProcess.spawn(process.execPath, ["-e", MCP_STUB_PROGRAM, logPath], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += String(chunk); });
  child.stderr.on("data", (chunk) => { stderr = (stderr + String(chunk)).slice(-4096); });
  const deadline = Date.now() + 10_000;
  while (!stdout.includes("\n")) {
    if (child.exitCode !== null || Date.now() >= deadline) {
      child.kill("SIGKILL");
      fs.rmSync(dir, { recursive: true, force: true });
      throw new Error(`the host MCP stub did not start: ${describeOutput(stderr)}`);
    }
    await sleep(50);
  }
  const { port: stubPort } = JSON.parse(stdout.split("\n")[0]) as { port: number };
  return Object.freeze({
    port: stubPort,
    requests: () => fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as McpStubRequest),
    stop: () => {
      child.kill("SIGKILL");
      fs.rmSync(dir, { recursive: true, force: true });
    },
  });
}

/**
 * One exchange from this test process straight to host `127.0.0.1:<port>`:
 * the positive control that a host listener is live and that its log records
 * the accept. Asynchronous is safe here: the listener is a child process.
 */
async function hostDirectEcho(hostPort: number, text: string): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    let data = "";
    const socket = net.connect({ host: "127.0.0.1", port: hostPort });
    const finish = (echoed: boolean): void => {
      clearTimeout(timer);
      socket.destroy();
      resolve(echoed);
    };
    const timer = setTimeout(() => finish(false), 5_000);
    socket.on("connect", () => socket.write(`${text}\n`));
    socket.on("data", (chunk) => { data += chunk.toString("utf8"); if (data.includes(text)) finish(true); });
    socket.on("error", () => finish(false));
    socket.on("close", () => finish(data.includes(text)));
  });
}

/**
 * The session's TCP listeners (state 0A), read from its own network
 * namespace's `/proc/net/tcp` and, when present, `/proc/net/tcp6`: a direct
 * kernel read, the same pattern as ESTABLISHED_FLOWS_PROGRAM. `address` is the
 * kernel's hex form (`0100007F` is 127.0.0.1).
 */
const LISTENERS_PROGRAM = `
const fs = require("node:fs");
const listeners = [];
for (const [family, file] of [["tcp", "/proc/net/tcp"], ["tcp6", "/proc/net/tcp6"]]) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch (error) { if (family === "tcp6") continue; throw error; }
  for (const row of text.split("\\n").slice(1).filter(Boolean)) {
    const fields = row.trim().split(/\\s+/);
    if (fields[3] !== "0A") continue;
    const [address, port] = fields[1].split(":");
    listeners.push({ family, address, port: parseInt(port, 16) });
  }
}
process.stdout.write(JSON.stringify(listeners) + "\\n");
`;

type SessionListener = Readonly<{ family: "tcp" | "tcp6"; address: string; port: number }>;

function sessionListeners(sessionId: string): readonly SessionListener[] {
  const text = dockerOrThrow("session listeners", ["exec", sessionId, "node", "-e", LISTENERS_PROGRAM]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.trim());
  } catch {
    throw new Error(`the session listener probe printed ${describeOutput(text)}`);
  }
  if (!Array.isArray(parsed)) throw new Error(`the session listener probe printed ${describeOutput(text)}`);
  return parsed as SessionListener[];
}

const IPV4_LOOPBACK_HEX = "0100007F";

/** True once the session's relay listens on 127.0.0.1:<port>. */
function relayListening(sessionId: string, relayPort: number): boolean {
  return sessionListeners(sessionId).some((listener) =>
    listener.family === "tcp" && listener.address === IPV4_LOOPBACK_HEX && listener.port === relayPort);
}

function sessionEnvValue(sessionId: string, name: string): string | undefined {
  const env = JSON.parse(dockerOrThrow("session env", ["inspect", "-f", "{{json .Config.Env}}", sessionId])) as string[];
  const entry = env.find((line) => line.startsWith(`${name}=`));
  return entry === undefined ? undefined : entry.slice(name.length + 1);
}

/** The generated Claude MCP config exactly as the session sees it. */
function sessionClaudeMcpServers(sessionId: string): Record<string, unknown> {
  const text = dockerOrThrow("session Claude MCP config", ["exec", sessionId, "cat", SESSION_CLAUDE_MCP_CONFIG]);
  const parsed = JSON.parse(text) as { mcpServers?: Record<string, unknown> };
  if (!parsed.mcpServers || typeof parsed.mcpServers !== "object") {
    throw new Error(`${SESSION_CLAUDE_MCP_CONFIG} has no mcpServers: ${describeOutput(text)}`);
  }
  return parsed.mcpServers;
}

/** The proxy's structured log events (`proxy-request:` and `proxy-denial:` lines). */
function proxyEvents(logs: string): readonly Readonly<{ line: string; fields: Record<string, unknown> }>[] {
  const events: { line: string; fields: Record<string, unknown> }[] = [];
  for (const line of logs.split("\n")) {
    const match = /(?:proxy-request|proxy-denial): (\{.*\})\s*$/u.exec(line);
    if (!match) continue;
    try {
      events.push({ line, fields: JSON.parse(match[1]) as Record<string, unknown> });
    } catch {
      // A truncated line is not evidence either way; the raw-text checks still see it.
    }
  }
  return events;
}

function projectMcpJsonPath(projectRoot: string): string {
  return path.join(projectRoot, ".mcp.json");
}

/** Adds one server to the project `.mcp.json`; returns the original bytes to restore. */
function addProjectMcpServer(projectRoot: string, name: string, config: Record<string, unknown>): string {
  const mcpPath = projectMcpJsonPath(projectRoot);
  const original = fs.readFileSync(mcpPath, "utf8");
  const current = JSON.parse(original) as { mcpServers?: Record<string, unknown> };
  current.mcpServers = { ...(current.mcpServers ?? {}), [name]: config };
  fs.writeFileSync(mcpPath, `${JSON.stringify(current)}\n`);
  return original;
}

// ---------------------------------------------------------------------------
// The tranche.
// ---------------------------------------------------------------------------

describe("approved host services", () => {
  let echo: EchoServer;
  let fixture: LiveFixture;
  let proxyId: string;
  let proxyIp: string;
  let port: number;
  /** Every standing session still running, oldest first. */
  const sessions: StandingSessionHandle[] = [];

  const resolveProxy = (): void => {
    const project = composeProjectName(fixture);
    proxyId = composeServiceContainerId(project, "proxy");
    proxyIp = dockerOrThrow("proxy internal address", [
      "inspect", "-f", `{{with index .NetworkSettings.Networks "${project}_agent_internal"}}{{.IPAddress}}{{end}}`, proxyId,
    ]);
  };

  const startSession = async (allowExistingSessions = false): Promise<StandingSessionHandle> => {
    const handle = await startStandingSession(fixture, { allowExistingSessions });
    sessions.push(handle);
    return handle;
  };

  const stopSession = async (handle: StandingSessionHandle): Promise<void> => {
    sessions.splice(sessions.indexOf(handle), 1);
    await handle.stop();
  };

  const runConverged = (args: readonly string[]): CaptureResult => {
    const result = fixture.runfree(args);
    expect(result.status, `runfree ${args.join(" ")} failed: ${describeOutput(result.output)}`).toBe(0);
    expect(result.stdout, `runfree ${args.join(" ")} did not converge live`)
      .toMatch(/effective policy: live now \(effective policy generation sha256:/u);
    return result;
  };

  /** The relay round trip from one session, retried while its relay binds. */
  const assertEchoThroughRelay = async (sessionId: string, label: string): Promise<void> => {
    const text = nonce(label);
    let last: ExchangeOutcome | undefined;
    await pollUntil(() => {
      last = sessionExchange(sessionId, "127.0.0.1", port, text);
      return last.outcome === "echoed";
    }, { timeoutMs: 20_000, intervalMs: 1000, label: `${label}: the nonce to come back through the relay` })
      .catch((error: unknown) => { throw new Error(`${String(error)}; last outcome: ${JSON.stringify(last)}`); });
    expect(hostConnectionCarrying(echo, text), `${label}: the host never received the nonce on the approved port`).toBeDefined();
  };

  beforeAll(async () => {
    requiredBackend();
    echo = await startEchoServer();
    port = echo.approvedPort;
    for (const candidate of [echo.approvedPort, echo.unapprovedPort]) {
      expect(refusedHostServicePortReason(candidate), `the OS chose a statically refused port ${candidate}`).toBeUndefined();
    }
    fixture = provisionSandboxFixture(REPO_ROOT);
    resolveProxy();
    const added = runConverged(["host-service", "add", SERVICE_NAME, "--port", String(port)]);
    expect(added.stdout, "add did not name the admitted listener").toMatch(
      new RegExp(`approved host service ${SERVICE_NAME}: 127\\.0\\.0\\.1:${port} \\([^,()]+, pid [1-9][0-9]*\\)`, "u"),
    );
    // The activation selected a new effective policy generation only. The
    // session template renders the approved host services, so the session
    // agent that carries this service is selected by the next startup. A
    // production `runfree claude` runs that startup itself; the standing
    // session's crash-runner launch does not, so `up` stands in for it. Later
    // remove/add cycles restore this same policy content and session agent.
    const up = fixture.runfree(["up"]);
    expect(up.status, `runfree up did not select the host-service session agent: ${describeOutput(up.output)}`).toBe(0);
    // F29 (startup top-ten): this launch's warning loop answers the owner
    // check from one bounded `lsof` observation of every host listener
    // (host-listener-snapshot.ts), not one `lsof -iTCP:<port>` call per
    // approved service as before. `add` just recorded the echo server as
    // this port's owner (the assertion above); a healthy launch immediately
    // after must see that exact same owner from the batched snapshot and
    // print no drift/visibility warning for it. Any regression in the batched
    // parse -- a missed listener, a wrong address, an unavailable snapshot --
    // would surface here as a "host service" warning line (see
    // hostServiceWarningLines), so silence is the positive proof, not an
    // absence of one.
    expect(up.output, `a real host listener was not visible through the batched snapshot: ${describeOutput(up.output)}`)
      .not.toMatch(/runfree warning:.*host service \S+ \(127\.0\.0\.1:\d+\):/u);
    await startSession();
  }, PROVISION_TIMEOUT_MS);

  afterAll(async () => {
    // Safety net: a case that forgot to stop a client, or whose own stop()
    // only partly succeeded, must not leave an in-container process (and its
    // open socket) running past this tranche. Each marker is killed
    // best-effort, before tearing anything else down, while its container is
    // still most likely to be alive.
    for (const client of markedClients.splice(0)) {
      try {
        killMarkedProcess(client.containerId, client.marker, client.asRoot);
      } catch (error) {
        console.warn(`afterAll: could not confirm the marked client ${client.marker} exited: ${String(error)}`);
      }
    }
    try {
      if (fixture) {
        try {
          if (proxyId && docker(["container", "inspect", proxyId]).status === 0) {
            if (drainBypassPresent(proxyId)) removeDrainBypass(proxyId);
            if (outputChainWithHandles(proxyId).includes(ROOT_OPENER_COMMENT)) removeCommentedRules(proxyId, ROOT_OPENER_COMMENT);
          }
        } finally {
          try {
            await releaseStandingSessions(sessions.splice(0), () => forceCleanSessions(fixture));
          } finally {
            destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
          }
        }
      }
    } finally {
      echo?.stop();
    }
  }, PROVISION_TIMEOUT_MS);

  test("an approved host service is reachable at 127.0.0.1:<port> through the session's relay", async () => {
    const session = sessions[0].session;
    const env = JSON.parse(dockerOrThrow("session env", ["inspect", "-f", "{{json .Config.Env}}", session.containerId])) as string[];
    expect(env, "the session template did not render the host-owned service list").toContain(`RUNFREE_HOST_SERVICES=${SERVICE_NAME}:${port}`);
    await assertEchoThroughRelay(session.containerId, "reachable");
  }, TEST_TIMEOUT_MS);

  test("unapproved pairs are refused at the proxy with a raw 403 and no dial", () => {
    const sessionId = sessions[0].session.containerId;
    const approvedOpensBefore = hostOpenCount(echo, "approved");
    const cases = [
      { authority: `${SERVICE_NAME}.runfree.internal:${echo.unapprovedPort}`, label: "the approved name on an unapproved port" },
      { authority: `other.runfree.internal:${port}`, label: "an unapproved name on the approved port" },
      { authority: `${SERVICE_NAME}.runfree.internal:443`, label: "the reserved suffix on 443" },
    ];
    for (const { authority, label } of cases) {
      const response = sessionRawConnect(sessionId, proxyIp, authority);
      expect(response.startsWith("HTTP/1.1 403"), `${label} was not refused with a raw 403: ${describeOutput(response)}`).toBe(true);
      expect(response, `${label}: the refusal does not name its reason`).toContain("host-service-not-configured");
    }
    expect(hostOpenCount(echo, "unapproved"), "the proxy dialled the unapproved host port").toBe(0);
    expect(hostOpenCount(echo, "approved"), "a refused CONNECT reached the approved host port").toBe(approvedOpensBefore);
  }, TEST_TIMEOUT_MS);

  test("a loopback MCP entry on an unapproved port grants no host reach (T1, S5)", async () => {
    const unapprovedPort = echo.unapprovedPort;
    const url = `http://127.0.0.1:${unapprovedPort}/mcp`;
    const hostServicesBefore = sessionEnvValue(sessions[0].session.containerId, "RUNFREE_HOST_SERVICES");
    expect(hostServicesBefore, "the standing session does not carry exactly the approved host service").toBe(`${SERVICE_NAME}:${port}`);
    const originalMcpJson = addProjectMcpServer(fixture.projectRoot, LOOPBACK_PROBE_SERVER, { type: "http", url });
    let probe: StandingSessionHandle | undefined;
    let revoked = true;
    try {
      // No terminal (the fixture's stdin is not a TTY) and no --no-discover:
      // a loopback entry makes no discovery call and needs no review prompt.
      const enabled = fixture.runfree(["mcp", "enable", "claude", LOOPBACK_PROBE_SERVER, "--source", "project"]);
      revoked = enabled.status !== 0;
      expect(enabled.status, `mcp enable of a loopback entry failed without a terminal: ${describeOutput(enabled.output)}`).toBe(0);
      expect(enabled.stdout).toContain(`Enable MCP server: claude ${LOOPBACK_PROBE_SERVER} (project, http-loopback/none)`);
      expect(enabled.stdout, "enable did not show that the port has no host service")
        .toContain(`reach=container-local 127.0.0.1:${unapprovedPort}:`);
      expect(enabled.stdout).toContain(`enabled MCP server: claude ${LOOPBACK_PROBE_SERVER}`);
      expect(enabled.output, "enable ran OAuth discovery for a loopback entry").not.toMatch(/Discovering OAuth hosts|discovers OAuth hosts only on a terminal/u);

      probe = await startSession(true);
      const sessionId = probe.session.containerId;
      // The descriptor reached the session's generated config, as the
      // normalized href...
      const servers = sessionClaudeMcpServers(sessionId);
      expect(servers[LOOPBACK_PROBE_SERVER], "the generated config does not carry the loopback entry").toEqual({ type: "http", url });
      // ...and changed nothing about which host services the relay serves.
      expect(sessionEnvValue(sessionId, "RUNFREE_HOST_SERVICES"), "mcp enable changed the session's host services")
        .toBe(hostServicesBefore);

      // Positive control for the listener read: the relay listens on the
      // approved port P in this same session, so the reader sees relay rows.
      await pollUntil(() => relayListening(sessionId, port), { timeoutMs: 20_000, label: `the relay to listen on 127.0.0.1:${port}` });
      const onUnapproved = sessionListeners(sessionId).filter((listener) => listener.port === unapprovedPort);
      expect(onUnapproved, `something in the session listens on the unapproved port ${unapprovedPort}`).toEqual([]);

      // Use the entry the way a client would: dial the host and port the
      // generated config names, from inside the session.
      const target = new URL(String((servers[LOOPBACK_PROBE_SERVER] as { url?: unknown }).url));
      expect(Number(target.port), "the generated URL does not name the unapproved port").toBe(unapprovedPort);
      const opensBefore = hostOpenCount(echo, "unapproved");
      const since = new Date().toISOString();
      const attempt = sessionExchange(sessionId, target.hostname, Number(target.port), nonce("loopback-mcp"));
      // ECONNREFUSED proves the dial was made and nothing in the session
      // accepted it; a timeout or any data would not.
      expect(attempt, `the in-session dial to 127.0.0.1:${unapprovedPort} was not refused locally`)
        .toMatchObject({ outcome: "error", detail: "ECONNREFUSED" });
      await sleep(2_000);
      expect(hostOpenCount(echo, "unapproved"), "the host listener on the unapproved port accepted a connection").toBe(opensBefore);

      const logs = proxyLogsSince(proxyId, since);
      expect(logs, "the proxy logged a CONNECT for the unapproved port").not.toMatch(new RegExp(`runfree\\.internal:${unapprovedPort}\\b`, "u"));
      const naming = proxyEvents(logs).filter(({ fields }) => fields.port === unapprovedPort);
      expect(naming.map(({ line }) => line), "the proxy logged an event naming the unapproved port").toEqual([]);

      // Positive control for the zero: the host listener on Q is live, and
      // its log records an accept when one happens.
      expect(await hostDirectEcho(unapprovedPort, nonce("host-control")), "the host listener on the unapproved port is not live").toBe(true);
      await pollUntil(() => hostOpenCount(echo, "unapproved") === opensBefore + 1, {
        timeoutMs: 5_000,
        label: "the host log to record the control connection",
      });

      await stopSession(probe);
      probe = undefined;
      const revoke = fixture.runfree(["mcp", "revoke", "claude", LOOPBACK_PROBE_SERVER, "--source", "project"]);
      revoked = revoke.status === 0;
      expect(revoke.status, `mcp revoke failed: ${describeOutput(revoke.output)}`).toBe(0);
      expect(revoke.stdout).toContain(`revoked project MCP server: claude ${LOOPBACK_PROBE_SERVER}`);
    } finally {
      // Best effort: a cleanup failure must not replace the case's own failure.
      if (probe && sessions.includes(probe)) await stopSession(probe).catch((error: unknown) => console.warn(`T1 cleanup: ${String(error)}`));
      if (!revoked) fixture.runfree(["mcp", "revoke", "claude", LOOPBACK_PROBE_SERVER, "--source", "project"]);
      fs.writeFileSync(projectMcpJsonPath(fixture.projectRoot), originalMcpJson);
    }
  }, TEST_TIMEOUT_MS);

  test("the gateway is reachable only by the request proxy user, and never from the session", () => {
    const extraHosts = JSON.parse(dockerOrThrow("proxy ExtraHosts", ["inspect", "-f", "{{json .HostConfig.ExtraHosts}}", proxyId])) as unknown;
    expect(extraHosts, "the proxy's ExtraHosts is not exactly the gateway alias").toEqual([`${GATEWAY_ALIAS}:host-gateway`]);
    const gateway = pinnedGateway(proxyId);
    const hosts = dockerOrThrow("proxy /etc/hosts", ["exec", "--user", "0:0", proxyId, "cat", "/etc/hosts"]);
    expect(
      hosts.split("\n").some((line) => line.split(/\s+/u)[0] === gateway && line.split(/\s+/u).includes(GATEWAY_ALIAS)),
      `the pinned gateway ${gateway} is not the daemon's alias entry: ${describeOutput(hosts)}`,
    ).toBe(true);

    const fromSession = sessionExchange(sessions[0].session.containerId, gateway, port, nonce("direct"), 5000);
    expect(["error", "timeout"], `the session reached the gateway directly: ${JSON.stringify(fromSession)}`).toContain(fromSession.outcome);

    const probe = `timeout 3 bash -c '</dev/tcp/${gateway}/${port}'`;
    const asServer = docker(["exec", "--user", "1001:1001", proxyId, "sh", "-c", probe]);
    expect(asServer.status, `uid 1001 could not reach the approved pair (positive control): ${describeOutput(asServer.output)}`).toBe(0);
    const asRoot = docker(["exec", "--user", "0:0", proxyId, "sh", "-c", probe]);
    expect(asRoot.status, `root in the proxy was not dropped on the approved pair (124 is a dropped-SYN timeout): ${describeOutput(asRoot.output)}`).toBe(124);
  }, TEST_TIMEOUT_MS);

  test("the kernel host_service set holds exactly the gateway and the approved port", () => {
    const gateway = pinnedGateway(proxyId);
    expect(hostServiceSetMembers(proxyId, "host_service")).toEqual([`${gateway} . ${port}`]);
  }, TEST_TIMEOUT_MS);

  test("a second session cannot reach the first session's relay", async () => {
    const first = sessions[0].session;
    const second = await startSession(true);
    try {
      expect(second.session.sourceIp, "the two sessions share a source IP").not.toBe(first.sourceIp);
      // Positive control: peers can reach a 0.0.0.0 listener in the first session.
      const portFile = "/tmp/runfree-livetest-peer-port";
      dockerOrThrow("start peer listener", ["exec", "-d", first.containerId, "node", "-e",
        `const net=require("node:net");const fs=require("node:fs");const s=net.createServer((c)=>c.pipe(c));s.listen(0,"0.0.0.0",()=>fs.writeFileSync(${JSON.stringify(portFile)},String(s.address().port)));`]);
      let peerPort = "";
      await pollUntil(() => {
        peerPort = docker(["exec", first.containerId, "cat", portFile]).stdout.trim();
        return /^[1-9][0-9]*$/u.test(peerPort);
      }, { timeoutMs: 10_000, label: "the peer listener to bind" });
      const control = sessionExchange(second.session.containerId, first.sourceIp, Number(peerPort), nonce("peer"));
      expect(control.outcome, `the second session cannot reach the first at all, so the relay check proves nothing: ${JSON.stringify(control)}`)
        .toBe("echoed");

      const relay = sessionExchange(second.session.containerId, first.sourceIp, port, nonce("cross"));
      expect(relay.outcome, `the first session's relay answered a peer: ${JSON.stringify(relay)}`).toBe("error");
    } finally {
      await stopSession(second);
    }
  }, TEST_TIMEOUT_MS);

  test("add refuses unsafe ports before any policy write, and other projects' publications refuse the approved port", async () => {
    const policyPath = path.join(fixture.projectRoot, ".runfree", "network-policy.json");
    const policyBefore = fs.readFileSync(policyPath, "utf8");
    const refusedAdd = (name: string, servicePort: number, expected: string): void => {
      const result = fixture.runfree(["host-service", "add", name, "--port", String(servicePort)]);
      expect(result.status, `add ${name} --port ${servicePort} was not refused: ${describeOutput(result.output)}`).not.toBe(0);
      expect(result.output, `add ${name} --port ${servicePort} refused for another reason`).toContain(expected);
      expect(fs.readFileSync(policyPath, "utf8"), `a refused add of ${name} changed the project policy`).toBe(policyBefore);
    };
    refusedAdd("bad", 2375, "port 2375 is refused");
    refusedAdd("callback", 47100, "runfree's own MCP callback block");
    const unused = await freeHostPort();
    refusedAdd("nothing", unused, `no process listens on 127.0.0.1:${unused}`);

    // A Docker Desktop-owned port: this project's own forward publishes one.
    const published = await freeHostPort();
    const forward = fixture.runfree(["forward", String(published)]);
    expect(forward.status, `could not open a forward to stage a Docker-owned port: ${describeOutput(forward.output)}`).toBe(0);
    try {
      refusedAdd("published", published, "owned by Docker Desktop");
    } finally {
      const closed = fixture.runfree(["forward", String(published), "stop"]);
      expect(closed.status, `could not close the staging forward: ${describeOutput(closed.output)}`).toBe(0);
    }

    // Another project on this host, never started, sharing the host state.
    const other = path.join(fixture.ownerRoot, "other-project");
    fs.mkdirSync(other);
    fs.writeFileSync(path.join(other, "package.json"), `${JSON.stringify({ name: "runfree-host-service-other", private: true })}\n`);
    const runfreeOther = (args: readonly string[]): CaptureResult => {
      const result = childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", other, ...args], {
        cwd: REPO_ROOT,
        encoding: "utf8",
        env: { ...fixture.env, RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT },
        maxBuffer: 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
      if (result.error) throw result.error;
      return Object.freeze({ status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr, output: `${result.stdout}${result.stderr}` });
    };
    const initialized = runfreeOther(["init"]);
    expect(initialized.status, `could not initialize the other project: ${describeOutput(initialized.output)}`).toBe(0);
    const ownedElsewhere = `already approved as a host service for the project at ${fixture.projectRoot}`;
    for (const args of [["forward", String(port), "start"], ["vnc", "--host-port", String(port)]]) {
      const refused = runfreeOther(args);
      expect(refused.status, `runfree ${args.join(" ")} in another project was not refused: ${describeOutput(refused.output)}`).not.toBe(0);
      expect(refused.output, `runfree ${args.join(" ")} did not name the owning project`).toContain(ownedElsewhere);
    }

    // A corrupt registry fails closed, and the named repair reclaims it.
    const registry = path.join(runfreeStateRoot(fixture.env), "host-service-ports.json");
    expect(fs.existsSync(registry), `the host-service port registry is not at ${registry}`).toBe(true);
    fs.writeFileSync(registry, "{");
    const corrupt = runfreeOther(["forward", String(port), "start"]);
    expect(corrupt.status, `forward did not refuse on a corrupt registry: ${describeOutput(corrupt.output)}`).not.toBe(0);
    expect(corrupt.output, "the corrupt-registry refusal does not name its cause").toContain("the host-service port registry could not be read");
    expect(corrupt.output, "the corrupt-registry refusal does not name its remedy").toContain("runfree host-service list --repair");
    const repaired = fixture.runfree(["host-service", "list", "--repair"]);
    expect(repaired.status, `repair failed: ${describeOutput(repaired.output)}`).toBe(0);
    expect(repaired.stdout).toMatch(/host-service port registry rebuilt: 1 port\(s\) from [1-9][0-9]* project\(s\)/u);
    const afterRepair = runfreeOther(["forward", String(port), "start"]);
    expect(afterRepair.status, `forward was not refused after the repair: ${describeOutput(afterRepair.output)}`).not.toBe(0);
    expect(afterRepair.output, "the repaired registry lost the approved port").toContain(ownedElsewhere);
  }, TEST_TIMEOUT_MS);

  test("remove cuts an open relay connection, and the request-proxy cut alone closes it", async () => {
    const sessionId = sessions[0].session.containerId;
    const gateway = pinnedGateway(proxyId);
    const client = openLongLivedClient(sessionId, port);
    try {
      const opened = nonce("revoke");
      client.send(opened);
      await client.waitForLine(`echo ${opened}`, 20_000);
      const hostId = hostConnectionCarrying(echo, opened);
      expect(hostId, "the host never saw the long-lived connection").toBeDefined();

      const since = new Date().toISOString();
      installDrainBypass(proxyId, gateway, port);
      try {
        const removed = runConverged(["host-service", "remove", SERVICE_NAME]);
        expect(removed.stdout, "remove did not report the removal").toContain(`host service ${SERVICE_NAME} removed`);
        // The firewall cut was armed (the pair is draining) but bypassed.
        expect(hostServiceSetMembers(proxyId, "host_service"), "the removed pair is still accepted").toEqual([]);
        expect(hostServiceSetMembers(proxyId, "host_service_draining"), "the firewall did not drain the removed pair")
          .toContain(`${gateway} . ${port}`);

        await client.waitForLine("closed", DRAIN_WINDOW_MS);
        // The host saw the proxy's own FIN: only the request proxy closing its
        // upstream leg sends one, and the bypass let it through.
        await pollUntil(() => hostConnectionClosed(echo, hostId as number), {
          timeoutMs: DRAIN_WINDOW_MS,
          label: "the host to see the revoked splice close",
        });
        expect(drainBypassPresent(proxyId), "the bypass was gone before the cut was observed").toBe(true);
        expect(proxyLogsSince(proxyId, since), "the request proxy did not log cutting the splice").toContain("proxy: host-service splices cut: 1");
      } finally {
        removeDrainBypass(proxyId);
      }

      const afterRemove = sessionExchange(sessionId, "127.0.0.1", port, nonce("removed"));
      expect(afterRemove.outcome, `the relay still reached a removed service: ${JSON.stringify(afterRemove)}`).toBe("closed-without-data");
    } finally {
      client.stop();
    }

    // Restore the approval for the remaining cases.
    runConverged(["host-service", "add", SERVICE_NAME, "--port", String(port)]);
    await assertEchoThroughRelay(sessionId, "re-added");
  }, TEST_TIMEOUT_MS);

  test("the firewall alone keeps a removed pair cut past the drain window (R19)", async () => {
    // A flow the request proxy does not track: root in the proxy, opened
    // through a one-shot root rule while the pair is approved. No request-
    // proxy cut can close it, so only the firewall stops its bytes.
    const gateway = pinnedGateway(proxyId);
    const pair = `${gateway} . ${port}`;
    installRootOpener(proxyId, gateway, port);
    let client: LongLivedClient | undefined;
    try {
      client = openRootProxyClient(proxyId, gateway, port);
      const opened = nonce("untracked");
      client.send(opened);
      await client.waitForLine(`echo ${opened}`, 20_000);
    } finally {
      removeCommentedRules(proxyId, ROOT_OPENER_COMMENT);
    }
    try {
      // Positive control: with the opener gone, the established flow still
      // carries bytes while the pair is approved.
      const control = nonce("untracked-control");
      client.send(control);
      await client.waitForLine(`echo ${control}`, 20_000);
      const hostId = hostConnectionCarrying(echo, control);
      expect(hostId, "the host never saw the root flow").toBeDefined();

      runConverged(["host-service", "remove", SERVICE_NAME]);
      await pollUntil(() => hostServiceSetMembers(proxyId, "host_service_draining").includes(pair), {
        timeoutMs: MAINTENANCE_WAIT_MS,
        label: "the firewall to drain the removed pair",
      });
      const drainObservedAt = Date.now();
      await pollUntil(() => !hostServiceSetMembers(proxyId, "host_service_draining").includes(pair), {
        timeoutMs: DRAIN_WINDOW_MS + MAINTENANCE_WAIT_MS,
        label: "the drain window to close",
      });
      const windowLeft = DRAIN_WINDOW_MS - (Date.now() - drainObservedAt);
      if (windowLeft > 0) await sleep(windowLeft);
      expect(hostServiceSetMembers(proxyId, "host_service"), "the removed pair is still accepted").toEqual([]);

      // Past the drain window the established accept would pass this flow
      // again; the pinned-gateway cut must still drop it.
      const hostDataBefore = hostDataEvents(echo, hostId as number);
      const late = nonce("untracked-late");
      client.send(late);
      await sleep(5_000);
      expect(hostConnectionCarrying(echo, late), "bytes reached the host on a removed pair after the drain window").toBeUndefined();
      expect(hostDataEvents(echo, hostId as number), "the host saw new data on the removed pair").toBe(hostDataBefore);
      expect(client.lines(), "the root client got an echo after the drain window").not.toContain(`echo ${late}`);
    } finally {
      client.stop();
    }

    // Restore the approval for the remaining cases.
    runConverged(["host-service", "add", SERVICE_NAME, "--port", String(port)]);
    await assertEchoThroughRelay(sessions[0].session.containerId, "re-added after the firewall-only cut");
  }, TEST_TIMEOUT_MS);

  test("no splice outlives its session", async () => {
    const handle = sessions[0];
    const client = openLongLivedClient(handle.session.containerId, port);
    let hostId: number | undefined;
    try {
      const opened = nonce("session-stop");
      client.send(opened);
      await client.waitForLine(`echo ${opened}`, 20_000);
      hostId = hostConnectionCarrying(echo, opened);
      expect(hostId, "the host never saw the connection").toBeDefined();
      await stopSession(handle);
    } finally {
      client.stop();
    }
    await pollUntil(() => hostConnectionClosed(echo, hostId as number), {
      timeoutMs: DRAIN_WINDOW_MS,
      label: "the host to see the splice close after its session ended",
    });
  }, TEST_TIMEOUT_MS);

  // T8, Claude. UNVERIFIED PROBE COMMAND: `claude --mcp-config <file>
  // --strict-mcp-config mcp list` is the plan's candidate for making the
  // pinned Claude connect to its configured MCP servers without a model
  // login. It has not been run against the pinned Claude (no Docker host was
  // available when this case was written). Confirm on a Docker host that it
  // (a) accepts the two flags before the `mcp list` subcommand, (b) connects
  // to the servers in that file rather than only the user/project scopes, and
  // (c) sends `tools/list` as well as `initialize`. If it does not, replace
  // the command; never relax the stub assertions to fit it.
  test("a loopback MCP entry reaches an approved host service through the relay: Claude (T8)", async () => {
    const stub = await startMcpStub();
    const stubPort = stub.port;
    const url = `http://127.0.0.1:${stubPort}/mcp`;
    let originalMcpJson: string | undefined;
    let session: StandingSessionHandle | undefined;
    let serviceAdded = false;
    let enabled = false;
    try {
      expect(refusedHostServicePortReason(stubPort), `the OS chose a statically refused port ${stubPort}`).toBeUndefined();
      runConverged(["host-service", "add", STUB_SERVICE_NAME, "--port", String(stubPort)]);
      serviceAdded = true;
      originalMcpJson = addProjectMcpServer(fixture.projectRoot, STUB_SERVER, { type: "http", url });
      const enable = fixture.runfree(["mcp", "enable", "claude", STUB_SERVER, "--source", "project"]);
      enabled = enable.status === 0;
      expect(enable.status, `mcp enable failed: ${describeOutput(enable.output)}`).toBe(0);
      expect(enable.stdout, "enable did not show the host-service reach").toContain(`reach=host-service ${STUB_SERVICE_NAME}:${stubPort}`);
      // As in beforeAll: the session template renders host services, so the
      // startup a production launch runs selects the agent that carries it.
      const up = fixture.runfree(["up"]);
      expect(up.status, `runfree up did not select the session agent: ${describeOutput(up.output)}`).toBe(0);

      session = await startSession();
      const sessionId = session.session.containerId;
      expect(sessionEnvValue(sessionId, "RUNFREE_HOST_SERVICES"), "the session does not carry the stub's host service")
        .toBe([`${SERVICE_NAME}:${port}`, `${STUB_SERVICE_NAME}:${stubPort}`].sort().join(","));
      expect(sessionClaudeMcpServers(sessionId)[STUB_SERVER], "the generated config does not carry the stub entry").toEqual({ type: "http", url });
      // Wait for the relay to bind before probing: a probe that runs first
      // fails with a refused connection that proves nothing about the agent.
      await pollUntil(() => relayListening(sessionId, stubPort), {
        timeoutMs: 20_000,
        label: `the relay to listen on 127.0.0.1:${stubPort}`,
      });

      const requestsBefore = stub.requests().length;
      const since = new Date().toISOString();
      // The session's own environment, proxy variables included: the threat
      // (T8) is a client that ignores NO_PROXY and sends plain HTTP to the
      // proxy, so the proxy variables must stay set for this probe.
      const probe = docker([
        "exec", sessionId, "timeout", "120",
        PINNED_CLAUDE, "--mcp-config", SESSION_CLAUDE_MCP_CONFIG, "--strict-mcp-config", "mcp", "list",
      ]);
      const requests = stub.requests().slice(requestsBefore);
      const calls = requests.flatMap((request) => request.rpc);
      const context = `probe exit ${probe.status}, output: ${describeOutput(probe.output)}; stub saw: ${JSON.stringify(requests)}`;
      expect(calls, `the stub never saw initialize from Claude; ${context}`).toContain("initialize");
      expect(calls, `the stub never saw tools/list from Claude; ${context}`).toContain("tools/list");

      const logs = proxyLogsSince(proxyId, since);
      const plain = proxyEvents(logs).filter(({ fields }) => fields.host === "127.0.0.1");
      expect(plain.map(({ line }) => line), "the proxy logged a request to 127.0.0.1 (a client ignored NO_PROXY)").toEqual([]);
      expect(logs, "the proxy logged a plain-HTTP URL to 127.0.0.1").not.toContain(`http://127.0.0.1:${stubPort}`);

      // Restore the tranche's state for the next case: no session, no stub
      // entry, and only the echo service in the policy and the template.
      await stopSession(session);
      session = undefined;
      const revoke = fixture.runfree(["mcp", "revoke", "claude", STUB_SERVER, "--source", "project"]);
      enabled = revoke.status !== 0;
      expect(revoke.status, `mcp revoke failed: ${describeOutput(revoke.output)}`).toBe(0);
      runConverged(["host-service", "remove", STUB_SERVICE_NAME]);
      serviceAdded = false;
      const restored = fixture.runfree(["up"]);
      expect(restored.status, `runfree up did not restore the session agent: ${describeOutput(restored.output)}`).toBe(0);
    } finally {
      // Best effort: a cleanup failure must not replace the case's own failure.
      if (session && sessions.includes(session)) await stopSession(session).catch((error: unknown) => console.warn(`T8 cleanup: ${String(error)}`));
      if (enabled) fixture.runfree(["mcp", "revoke", "claude", STUB_SERVER, "--source", "project"]);
      if (originalMcpJson !== undefined) fs.writeFileSync(projectMcpJsonPath(fixture.projectRoot), originalMcpJson);
      if (serviceAdded) {
        fixture.runfree(["host-service", "remove", STUB_SERVICE_NAME]);
        fixture.runfree(["up"]);
      }
      stub.stop();
    }
  }, TEST_TIMEOUT_MS);

  // T8, Codex: no known probe. Spec open question Q2: the live per-agent
  // probe needs a command that makes the agent connect to its configured MCP
  // servers without a model login, and none is known for the pinned
  // codex-cli 0.156.1 (to check on a Docker host: `codex mcp --help`). Until
  // one is found this case stays skipped and T8 is unproven for Codex; the
  // maintainer decides between shipping Claude-only (refusing Codex loopback
  // entries with a named reason) and shipping both with this recorded gap.
  // The body fails rather than passes if someone un-skips it without a probe.
  test.skip("a loopback MCP entry reaches an approved host service through the relay: Codex (T8, spec Q2)", () => {
    throw new Error("no Codex probe command is known (spec Q2); write one before enabling this case");
  });

  test("a changed gateway refuses with a named cause, the request proxy cuts an open splice, and rebuild re-pins", async () => {
    const before = await startSession();
    const client = openLongLivedClient(before.session.containerId, port);
    try {
      const opened = nonce("pre-change");
      client.send(opened);
      await client.waitForLine(`echo ${opened}`, 20_000);
      const pinned = pinnedGateway(proxyId);
      const hostId = hostConnectionCarrying(echo, opened);
      expect(hostId, "the host never saw the long-lived connection").toBeDefined();
      // Positive control for the flow probe below: the open splice's upstream
      // leg is exactly one established proxy socket to the pinned pair. (Not
      // just "at least one": a prior case's leaked client would also show up
      // here, making the later zero-count check pass without proving anything.)
      const openPortsBeforeChange = establishedProxyLocalPorts(proxyId, pinned, port);
      expect(openPortsBeforeChange.length, "the flow probe does not see exactly the open splice").toBe(1);
      const splicePort = openPortsBeforeChange[0];

      const since = new Date().toISOString();
      // Rewrite only the IPv4 alias line, in place (a bind-mounted file cannot
      // be renamed over), keeping its owner and mode.
      const rewrite = [
        "set -eu",
        `rewritten="$(sed -E 's/^[0-9.]+([[:space:]]+(.*[[:space:]])?${GATEWAY_ALIAS.replaceAll(".", "\\.")}([[:space:]]|$))/${TAMPERED_GATEWAY}\\1/' /etc/hosts)"`,
        "printf '%s\\n' \"$rewritten\" > /etc/hosts",
      ].join("\n");
      dockerOrThrow("rewrite the gateway alias", ["exec", "--user", "0:0", proxyId, "sh", "-c", rewrite]);
      const hosts = dockerOrThrow("proxy /etc/hosts", ["exec", "--user", "0:0", proxyId, "cat", "/etc/hosts"]);
      expect(hosts, "the alias line was not rewritten").toMatch(new RegExp(`^${TAMPERED_GATEWAY.replaceAll(".", "\\.")}\\s.*${GATEWAY_ALIAS.replaceAll(".", "\\.")}`, "mu"));

      let status: GatewayStatus = {};
      await pollUntil(() => {
        status = readGatewayStatus(proxyId);
        return status.unavailableReason?.includes("gateway address changed") === true;
      }, { timeoutMs: MAINTENANCE_WAIT_MS, label: "the gateway status to report the changed address" });
      expect(status.gatewayIp, "a changed gateway is still offered to the request proxy").toBeUndefined();
      expect(status.unavailableReason, "the refusal does not name its reclaim").toContain("runfree rebuild");
      const drainingPair = `${pinned} . ${port}`;
      await pollUntil(() => hostServiceSetMembers(proxyId, "host_service_draining").includes(drainingPair), {
        timeoutMs: MAINTENANCE_WAIT_MS,
        label: "the firewall to drain the pinned pair",
      });
      const drainObservedAt = Date.now();
      expect(hostServiceSetMembers(proxyId, "host_service"), "the firewall still accepts the old pair").toEqual([]);

      // The request-proxy cut: a gateway change changes no policy, so this is
      // the proxy's own gateway watch, not a reload's `cutRemoved`.
      await client.waitForLine("closed", MAINTENANCE_WAIT_MS);
      let logs = "";
      await pollUntil(() => {
        logs = proxyLogsSince(proxyId, since);
        return logs.includes("host-service splices cut");
      }, { timeoutMs: MAINTENANCE_WAIT_MS, label: "the request proxy to log the gateway cut" });
      expect(logs, "the cut does not name the withdrawn gateway as its reason")
        .toMatch(/proxy: host-service splices cut: [1-9][0-9]*; reason: the host-service gateway is unavailable: [^\n]*gateway address changed/u);
      const hostDataAtCut = hostDataEvents(echo, hostId as number);

      // Past the drain window the firewall flushes the draining set, and the
      // established accept would pass a still-open flow again. The cut left
      // none: no established proxy socket to the old pair, and no new bytes
      // at the host on that connection.
      await pollUntil(() => !hostServiceSetMembers(proxyId, "host_service_draining").includes(drainingPair), {
        timeoutMs: DRAIN_WINDOW_MS + MAINTENANCE_WAIT_MS,
        label: "the drain window to close",
      });
      const windowLeft = DRAIN_WINDOW_MS - (Date.now() - drainObservedAt);
      if (windowLeft > 0) await sleep(windowLeft);
      await sleep(5_000);
      expect(hostServiceSetMembers(proxyId, "host_service"), "the sticky refusal re-admitted the old pair").toEqual([]);
      const openPortsAfterWindow = establishedProxyLocalPorts(proxyId, pinned, port);
      expect(openPortsAfterWindow, "the cut splice's own flow is still established after the drain window").not.toContain(splicePort);
      expect(openPortsAfterWindow.length, "a cut splice's flow is still established after the drain window").toBe(0);
      expect(hostDataEvents(echo, hostId as number), "bytes reached the host on the cut flow after the drain window").toBe(hostDataAtCut);

      // New connections refuse with the named cause.
      const response = sessionRawConnect(before.session.containerId, proxyIp, `${SERVICE_NAME}.runfree.internal:${port}`);
      expect(response.startsWith("HTTP/1.1 403"), `a changed gateway did not refuse: ${describeOutput(response)}`).toBe(true);
      expect(response, "the refusal does not name the changed gateway").toContain("gateway address changed");
      const viaRelay = sessionExchange(before.session.containerId, "127.0.0.1", port, nonce("refused"));
      expect(viaRelay.outcome, `the relay reached the service past a changed gateway: ${JSON.stringify(viaRelay)}`).toBe("closed-without-data");
    } finally {
      client.stop();
    }
    await stopSession(before);

    // The named reclaim: rebuild recreates the proxy, which re-pins.
    const rebuilt = fixture.runfree(["rebuild", "--yes"]);
    expect(rebuilt.status, `runfree rebuild failed: ${describeOutput(rebuilt.output, 4000)}`).toBe(0);
    resolveProxy();
    const repinned = pinnedGateway(proxyId);
    expect(hostServiceSetMembers(proxyId, "host_service")).toEqual([`${repinned} . ${port}`]);
    const after = await startSession();
    await assertEchoThroughRelay(after.session.containerId, "after-rebuild");
  }, REBUILD_TEST_TIMEOUT_MS);
});
