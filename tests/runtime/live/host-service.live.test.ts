// Host-service live tranche (core tier): an approved service on the host's
// loopback, reached by the agent through its loopback relay and the proxy's
// opaque splice to the pinned Docker Desktop host gateway, and nothing else.
//
// Setup: a TCP echo server on host 127.0.0.1 (an approved port P and an
// unapproved port Q, both OS-chosen), the seeded sandbox project, `runfree
// host-service add echo --port P` converged live, then a standing session.
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
//   8. session stop: the host sees the splice close when its session ends.
//      The session's processes die with the container, so this does not
//      separate the proxy's revoke-driven socket cut from an ordinary client
//      close; it proves only that no splice outlives its session.
//   9. gateway change and reclaim (HS8): a rewritten `/etc/hosts` alias makes
//      host services refuse with `gateway address changed`, and the firewall
//      drain alone stops bytes on an already-open splice (a gateway change
//      changes no policy, so the request proxy cuts nothing; the proxy log is
//      checked for that). `runfree rebuild` re-pins and the echo works again.
//
// Recorded proof gaps (not staged here, never faked):
//
//   - The firewall drain alone on `host-service remove`: the request proxy
//     always cuts a removed pair's splices on reload and has no switch to
//     disable that. Case 9 proves the same `@host_service_draining` drop alone,
//     triggered by a gateway change instead of a removal.
//   - A changed proxy `HostConfig.ExtraHosts` failing the topology proof with
//     `proxy-extra-hosts-exact`: a running container's ExtraHosts cannot be
//     changed without recreating it from a different Compose template. The
//     unit inspect test covers it; case 3 reads back the exact shipped entry.
//   - A missing relay binary not changing the entry's exit code: that needs a
//     project image without the relay; `scripts/session-entry.test.ts` covers
//     it against the real entry script.

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
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
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

/** A long-lived relay client driven over stdin: one line out per line in. */
const LONG_LIVED_CLIENT_PROGRAM = `
const net = require("node:net");
const port = Number(process.argv[1]);
const socket = net.connect({ host: "127.0.0.1", port });
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

function openLongLivedClient(sessionId: string, port: number): LongLivedClient {
  // Asynchronous on purpose: this client must stay open across the CLI and
  // Docker calls the case makes while it is connected.
  const child = childProcess.spawn(
    "docker",
    ["exec", "-i", sessionId, "env", ...PROXY_ENV_UNSET, "node", "-e", LONG_LIVED_CLIENT_PROGRAM, String(port)],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
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
  return Object.freeze({
    send: (text: string) => { child.stdin.write(`${text}\n`); },
    lines: () => [...received],
    waitForLine: async (line: string, timeoutMs: number) => {
      await pollUntil(() => received.includes(line), { timeoutMs, label: `the relay client to print ${JSON.stringify(line)}` })
        .catch((error: unknown) => {
          throw new Error(`${String(error)}; client output: ${describeOutput(received.join(" | "))}; stderr: ${describeOutput(stderr)}`);
        });
    },
    stop: () => { child.kill("SIGKILL"); },
  });
}

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
  for (const line of outputChainWithHandles(proxyId).split("\n")) {
    const match = line.includes(BYPASS_COMMENT) ? /# handle (\d+)/u.exec(line) : null;
    if (match) dockerOrThrow("remove drain bypass", ["exec", "--user", "0:0", proxyId, "nft", "delete", "rule", "inet", NFT_TABLE, "output", "handle", match[1]]);
  }
  if (drainBypassPresent(proxyId)) throw new Error("the drain bypass rule is still in the output chain");
}

function proxyLogsSince(proxyId: string, sinceIso: string): string {
  return dockerOrThrow("proxy logs", ["logs", "--since", sinceIso, proxyId]);
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
    await startSession();
  }, PROVISION_TIMEOUT_MS);

  afterAll(async () => {
    try {
      if (fixture) {
        try {
          if (proxyId && docker(["container", "inspect", proxyId]).status === 0 && drainBypassPresent(proxyId)) removeDrainBypass(proxyId);
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

  test("a changed gateway refuses with a named cause, the drain alone stops an open splice, and rebuild re-pins", async () => {
    const before = await startSession();
    const client = openLongLivedClient(before.session.containerId, port);
    try {
      const opened = nonce("pre-change");
      client.send(opened);
      await client.waitForLine(`echo ${opened}`, 20_000);
      const pinned = pinnedGateway(proxyId);

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
      await pollUntil(() => hostServiceSetMembers(proxyId, "host_service_draining").includes(`${pinned} . ${port}`), {
        timeoutMs: MAINTENANCE_WAIT_MS,
        label: "the firewall to drain the pinned pair",
      });
      expect(hostServiceSetMembers(proxyId, "host_service"), "the firewall still accepts the old pair").toEqual([]);

      // The firewall drain alone: no policy changed, so the request proxy
      // keeps the splice; bytes on it must still stop at the drop.
      const stranded = nonce("after-change");
      client.send(stranded);
      await sleep(8_000);
      expect(client.lines(), "bytes crossed a drained splice").not.toContain(`echo ${stranded}`);
      expect(hostConnectionCarrying(echo, stranded), "the host received bytes on a drained splice").toBeUndefined();
      expect(client.lines(), "the splice was closed, so the drop was not the only cut").not.toContain("closed");
      expect(proxyLogsSince(proxyId, since), "the request proxy cut splices, so the drain was not alone").not.toContain("host-service splices cut");

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
