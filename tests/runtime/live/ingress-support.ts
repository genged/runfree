// Host support for the ingress-forwarder live tranche.
//
// Everything asserted through this module is read back from the daemon or
// from inside the session container: `docker inspect` of the forwarder, the
// ingress host network's own labels, `/proc` inside the session, and real TCP
// and HTTP round trips from the host. Nothing reads Runfree's render or its
// in-memory plan, so a forwarder that the product *meant* to publish on
// loopback but did not still fails here (the taxonomy's declarative-config
// lesson).
//
// Launches go through the public CLI (`runfree claude`, `runfree shell`,
// `runfree mcp auth`), not the crash harness's `--launch`: the harness drives
// the admission driver directly and never runs the public launch frame the
// per-session MCP OAuth callback hangs off.

import childProcess from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";

import { CONTAINER_ROLE_LABEL, INGRESS_PURPOSE_LABEL } from "../../../packages/cli/src/runtime/container-inventory.ts";
import { AGENT_UID_GID, PROJECT_ID_LABEL } from "../../../packages/cli/src/runtime/constants.ts";
import { peekSessionContainerRecordsV2, SESSION_CONTAINER_LABELS } from "../../../packages/cli/src/runtime/session-containers.ts";
import { runfreeStateRoot } from "../../../packages/cli/src/paths.ts";
import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import { stageLongLivedAgentBinary } from "./agent-stub.ts";
import { ATTACHED_WAIT_TIMEOUT_MS, REPO_ROOT, SESSION_TEARDOWN_TIMEOUT_MS, awaitAgentStarted } from "./attached-support.ts";
import { containerAddressOnNetwork, docker, dockerOrThrow, internalNetworkId } from "./docker.ts";
import { describeOutput, sessionAgentContainerIds, type LiveFixture } from "./fixture.ts";

const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

/** The project MCP server the tranche makes OAuth-capable. Reserved, never resolves. */
export const MCP_FIXTURE_SERVER = "fixture";
export const MCP_FIXTURE_JSON = `${JSON.stringify({
  mcpServers: { [MCP_FIXTURE_SERVER]: { type: "http", url: "https://mcp.example.invalid/mcp" } },
})}\n`;

/**
 * Where the session learns its callback port.
 *
 * Contract: session MCP OAuth callback decisions 2026-09-30.
 */
export const CALLBACK_PORT_FILE = "/tmp/runfree-mcp-oauth-callback-port";
/** The in-session bridge's cmdline marker (`packages/cli/src/runtime/probes.ts`). */
export const CALLBACK_BRIDGE_MARKER = "runfree_mcp_callback_bridge";
/** The OAuth-shaped path the host-side "browser" requests; echoed back byte for byte. */
export const CALLBACK_REQUEST_PATH = "/callback/abc?code=synthetic&state=x";

/** Bound for a launch's callback forwarder to appear once its agent is up. */
export const CALLBACK_FORWARDER_TIMEOUT_MS = 60_000;
/** Bound for a host round trip through a forwarder to succeed once it exists. */
export const HOST_REACH_TIMEOUT_MS = 30_000;
/** Bound for an in-session listener this module starts to accept connections. */
const LISTENER_READY_TIMEOUT_MS = 20_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function runOrThrow(fixture: LiveFixture, args: readonly string[]): string {
  const result = fixture.runfree(args);
  if (result.status !== 0) throw new Error(`runfree ${args.join(" ")} failed: ${describeOutput(result.output, 4000)}`);
  return result.output;
}

function git(projectRoot: string, args: readonly string[]): void {
  const result = childProcess.spawnSync("git", ["-C", projectRoot, ...args], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${describeOutput(`${result.stdout ?? ""}${result.stderr ?? ""}`)}`);
  }
}

/**
 * The tranche's project: an agent that stays up, the Claude operational
 * service a public `runfree claude` refuses to launch without, and a committed
 * project `.mcp.json` naming one public HTTP server.
 *
 * The MCP server is deliberately left unapproved here. An unapproved project
 * entry is not imported into the runtime OAuth policy, so the project starts
 * out with no OAuth-capable server — the negative case's precondition — and
 * `ensureMcpOAuthEligible` makes it eligible the way a user would.
 */
export function configureIngressProject(fixture: LiveFixture): void {
  stageLongLivedAgentBinary(fixture);
  runOrThrow(fixture, ["service", "enable", "agent-claude", "--no-reload"]);
  fs.writeFileSync(path.join(fixture.projectRoot, ".mcp.json"), MCP_FIXTURE_JSON);
  git(fixture.projectRoot, ["add", ".mcp.json"]);
  git(fixture.projectRoot, ["commit", "-m", "add project MCP server"]);
}

const CONTROL_APPROVAL_PATTERN = /^runfree control approve ([a-z-]+) --subject-digest (sha256:[a-f0-9]{64})$/u;

/**
 * `runfree up`, approving exactly the control subjects startup names.
 *
 * A changed MCP approval can change desired controls; a user answers that
 * refusal with the printed `control approve` commands, so this does the same,
 * parsed from anchored lines and never evaluated as shell. Any other refusal
 * fails the case with the product's own output.
 */
export function upWithExactApprovals(fixture: LiveFixture): void {
  const first = fixture.runfree(["up"]);
  if (first.status === 0) return;
  if (!first.output.includes("desired controls require exact approval before startup")) {
    throw new Error(`runfree up failed: ${describeOutput(first.output, 4000)}`);
  }
  const approvals = first.output.split("\n")
    .map((line) => CONTROL_APPROVAL_PATTERN.exec(line.trim()))
    .filter((match): match is RegExpExecArray => match !== null);
  if (approvals.length === 0) throw new Error(`startup named no exact control approval: ${describeOutput(first.output, 4000)}`);
  for (const [, subject, digest] of approvals) {
    runOrThrow(fixture, ["control", "approve", subject, "--subject-digest", digest]);
  }
  runOrThrow(fixture, ["up"]);
}

/** A loopback port nothing on this host is bound to right now. */
export async function freeLoopbackPort(): Promise<string> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => resolve());
  });
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!address || typeof address === "string") throw new Error("could not allocate a free loopback port");
  return String(address.port);
}

// ---------------------------------------------------------------------------
// Docker readback
// ---------------------------------------------------------------------------

type PortBinding = Readonly<{ HostIp?: string; HostPort?: string }>;
type PortMap = Readonly<Record<string, readonly PortBinding[] | null>> | null | undefined;

export type ContainerInspect = Readonly<{
  Id: string;
  Name?: string;
  Image?: string;
  State?: Readonly<{ Running?: boolean; Status?: string }>;
  Config?: Readonly<{ User?: string; Env?: readonly string[] | null; Labels?: Readonly<Record<string, string>> | null }>;
  HostConfig?: Readonly<{
    AutoRemove?: boolean;
    Binds?: readonly string[] | null;
    CapAdd?: readonly string[] | null;
    CapDrop?: readonly string[] | null;
    NetworkMode?: string;
    PidsLimit?: number | null;
    PortBindings?: PortMap;
    Privileged?: boolean;
    ReadonlyRootfs?: boolean;
    SecurityOpt?: readonly string[] | null;
  }>;
  Mounts?: readonly unknown[] | null;
  NetworkSettings?: Readonly<{
    Networks?: Readonly<Record<string, Readonly<{ NetworkID?: string; IPAddress?: string }>>> | null;
    Ports?: PortMap;
  }>;
}>;

/**
 * `docker container inspect`, or undefined when Docker definitively says the
 * container does not exist. Any other failure throws: an unreachable daemon is
 * not evidence that a forwarder is gone.
 */
export function inspectContainer(nameOrId: string): ContainerInspect | undefined {
  const result = docker(["container", "inspect", nameOrId]);
  if (result.status !== 0) {
    if (/No such (?:container|object)/iu.test(result.stderr)) return undefined;
    throw new Error(`docker inspect ${nameOrId} failed: ${describeOutput(result.output)}`);
  }
  const parsed = JSON.parse(result.stdout) as ContainerInspect[];
  if (parsed.length !== 1) throw new Error(`docker inspect ${nameOrId} returned ${parsed.length} containers`);
  return parsed[0];
}

export function containerEnv(inspect: ContainerInspect): Readonly<Record<string, string>> {
  const env: Record<string, string> = {};
  for (const entry of inspect.Config?.Env ?? []) {
    const separator = entry.indexOf("=");
    if (separator > 0) env[entry.slice(0, separator)] = entry.slice(separator + 1);
  }
  return env;
}

export function containerName(inspect: ContainerInspect): string {
  return (inspect.Name ?? "").replace(/^\//u, "");
}

/** Only the entries that actually publish, as plain `{HostIp, HostPort}` pairs. */
export function publishedBindings(map: PortMap): Record<string, PortBinding[]> {
  const out: Record<string, PortBinding[]> = {};
  for (const [containerPort, bindings] of Object.entries(map ?? {})) {
    if (!Array.isArray(bindings) || bindings.length === 0) continue;
    out[containerPort] = bindings.map((binding) => ({ HostIp: binding.HostIp, HostPort: binding.HostPort }));
  }
  return out;
}

/** What loopback-only publication of one port reads as, in both inspect maps. */
export function loopbackOnlyPublication(port: string): Record<string, PortBinding[]> {
  return { [`${port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: port }] };
}

export type ForwarderRef = Readonly<{ id: string; name: string }>;

/** This project's ingress forwarders by label, running or not. */
export function projectIngressForwarders(projectId: string, purpose?: string): readonly ForwarderRef[] {
  return dockerOrThrow("ingress forwarder inventory", [
    "ps", "-a", "--no-trunc",
    "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`,
    "--filter", `label=${CONTAINER_ROLE_LABEL}=ingress-forwarder`,
    ...(purpose ? ["--filter", `label=${INGRESS_PURPOSE_LABEL}=${purpose}`] : []),
    "--format", "{{.ID}}\t{{.Names}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const [id, name] = line.split("\t");
    return Object.freeze({ id, name });
  });
}

/** Removes every ingress forwarder of this project, whatever state it is in. Cleanup only. */
export function forceRemoveProjectForwarders(projectId: string): readonly string[] {
  const forwarders = projectIngressForwarders(projectId);
  for (const forwarder of forwarders) docker(["rm", "-f", forwarder.id]);
  return forwarders.map((forwarder) => forwarder.name);
}

/** The project's ingress host networks, found by the labels the facility mints. */
export function projectIngressHostNetworks(projectId: string): readonly string[] {
  return dockerOrThrow("ingress host network inventory", [
    "network", "ls", "--no-trunc",
    "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`,
    "--filter", "label=io.runfree.network-role=ingress-host",
    "--format", "{{.Name}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
}

export type CallbackForwarder = Readonly<{ id: string; name: string; port: string; env: Readonly<Record<string, string>> }>;

/** The mcp-callback forwarders whose minted identity names this session. */
export function callbackForwardersForSession(projectId: string, sessionId: string): readonly CallbackForwarder[] {
  const found: CallbackForwarder[] = [];
  for (const ref of projectIngressForwarders(projectId, "mcp-callback")) {
    const inspect = inspectContainer(ref.id);
    if (!inspect) continue;
    const env = containerEnv(inspect);
    // Contract: session MCP OAuth callback decisions 2026-09-30.
    if (env.RUNFREE_CALLBACK_SESSION_ID !== sessionId) continue;
    found.push(Object.freeze({ id: inspect.Id, name: containerName(inspect), port: env.INGRESS_HOST_PORT ?? "", env }));
  }
  return found;
}

/** Every mcp-callback forwarder of the project with its inspected env. */
export function allCallbackForwarders(projectId: string): readonly CallbackForwarder[] {
  const found: CallbackForwarder[] = [];
  for (const ref of projectIngressForwarders(projectId, "mcp-callback")) {
    const inspect = inspectContainer(ref.id);
    if (!inspect) continue;
    const env = containerEnv(inspect);
    found.push(Object.freeze({ id: inspect.Id, name: containerName(inspect), port: env.INGRESS_HOST_PORT ?? "", env }));
  }
  return found;
}

// ---------------------------------------------------------------------------
// Public CLI launches
// ---------------------------------------------------------------------------

export type LaunchedSession = Readonly<{ containerId: string; sessionId: string; ip: string }>;

export type CliLaunch = Readonly<{
  label: string;
  session: LaunchedSession;
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  output: () => string;
  /** Whether the owning CLI has exited, by any path. */
  exited: () => boolean;
  /**
   * Ends the session the ordinary way — its agent dies — and waits for the
   * owning CLI to run its teardown and exit.
   */
  end: () => Promise<Readonly<{ status: number | null; output: string }>>;
  /**
   * SIGKILLs only the owning CLI. The `docker start --attach` child and the
   * session container survive, which is the residue a closed terminal leaves.
   */
  killOwner: () => Promise<void>;
}>;

/**
 * Starts a public CLI launch and waits for its session's agent to be running
 * and its lifecycle record to be attached.
 *
 * The new session is the one session-agent container that was not running
 * before the spawn, so launches must be started one at a time. Stdin is a
 * pipe held open for the whole launch: a login shell attached to a closed
 * stdin exits at once, and the agent stub ignores it.
 */
export async function startCliSession(
  fixture: LiveFixture,
  project: string,
  args: readonly string[],
  options: Readonly<{ label: string; extraEnv?: NodeJS.ProcessEnv }>,
): Promise<CliLaunch> {
  const before = new Set(sessionAgentContainerIds(project));
  const child = childProcess.spawn(
    process.execPath,
    [...cliEntryArgv(), "--workspace", fixture.projectRoot, ...args],
    {
      cwd: REPO_ROOT,
      env: { ...fixture.env, RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT, ...options.extraEnv },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  let output = "";
  const collect = (chunk: Buffer | string): void => {
    output = (output + String(chunk)).slice(-CAPTURE_MAX_BYTES);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  child.stdin?.on("error", () => undefined);
  let exited: Readonly<{ status: number | null; output: string }> | undefined;
  const completion = new Promise<Readonly<{ status: number | null; output: string }>>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status) => {
      exited = Object.freeze({ status, output });
      resolve(exited);
    });
  });

  let containerId: string | undefined;
  const deadline = Date.now() + ATTACHED_WAIT_TIMEOUT_MS;
  while (!containerId) {
    const fresh = sessionAgentContainerIds(project).filter((id) => !before.has(id));
    if (fresh.length > 1) {
      child.kill("SIGKILL");
      throw new Error(`${options.label}: ${fresh.length} new session containers appeared for one launch`);
    }
    if (fresh.length === 1) {
      containerId = fresh[0];
      break;
    }
    if (exited) {
      throw new Error(`${options.label}: runfree ${args.join(" ")} exited before its session ran: ${describeOutput(exited.output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`${options.label}: no session container appeared: ${describeOutput(output, 4000)}`);
    }
    await sleep(250);
  }
  if (!/^[a-f0-9]{64}$/u.test(containerId)) throw new Error(`${options.label}: session container id is not exact: ${containerId}`);
  await awaitAgentStarted(containerId, options.label);
  const inspect = inspectContainer(containerId);
  const sessionId = inspect?.Config?.Labels?.[SESSION_CONTAINER_LABELS.sessionId];
  if (!sessionId) throw new Error(`${options.label}: the session container carries no session id label`);
  // The agent runs before its record says so: the launch reports `attached`
  // only once its own handoff poll sees the entry exec the agent. Consumers
  // that resolve "the" session (`runfree forward`, `vnc`) accept only an
  // attached record, so the launch is not usable until then.
  const projectId = project.replace(/^runfree-/u, "");
  const stateDir = path.join(runfreeStateRoot(fixture.env), "projects", projectId);
  for (;;) {
    const record = peekSessionContainerRecordsV2(stateDir, { projectId, composeProject: project }).records
      .find((candidate) => candidate.sessionId === sessionId);
    if (record?.state === "attached") break;
    if (exited) {
      throw new Error(`${options.label}: runfree ${args.join(" ")} exited before its session was attached: ${describeOutput(exited.output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`${options.label}: session ${sessionId} never reached attached (record state ${record?.state ?? "absent"}): ${describeOutput(output, 4000)}`);
    }
    await sleep(100);
  }
  const ip = containerAddressOnNetwork(containerId, internalNetworkId(project));
  const session: LaunchedSession = Object.freeze({ containerId, sessionId, ip });

  const bounded = async (): Promise<Readonly<{ status: number | null; output: string }>> => {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`${options.label}: the owning CLI did not exit after its session ended: ${describeOutput(output, 4000)}`));
      }, SESSION_TEARDOWN_TIMEOUT_MS);
    });
    try {
      return await Promise.race([completion, timeout]);
    } finally {
      clearTimeout(timer);
    }
  };
  const end = async (): Promise<Readonly<{ status: number | null; output: string }>> => {
    if (exited) return exited;
    docker(["kill", containerId]);
    return await bounded();
  };
  const killOwner = async (): Promise<void> => {
    child.kill("SIGKILL");
    // Release this end of the pipes: the surviving `docker start --attach`
    // inherited them, so `close` would otherwise wait on the very process the
    // crash deliberately leaves running.
    await sleep(250);
    child.stdin?.destroy();
    child.stdout?.destroy();
    child.stderr?.destroy();
    await completion.catch(() => undefined);
  };
  return Object.freeze({
    label: options.label,
    session,
    completion,
    output: () => output,
    exited: () => exited !== undefined,
    end,
    killOwner,
  });
}

// ---------------------------------------------------------------------------
// In-session programs (run as the agent user through `docker exec`)
// ---------------------------------------------------------------------------

/**
 * An HTTP server standing in for the agent's own listener: a dev server for
 * `runfree forward`, the CLI's loopback OAuth callback server for the MCP
 * callback. It answers every request with `<marker>\n<request url>` and appends
 * each request url to a log, so a test can prove both what reached it and what
 * did not.
 */
const LISTENER_SOURCE = [
  "/* runfree-livetest-ingress-listener */",
  "const http = require('node:http');",
  "const fs = require('node:fs');",
  "const [host, port, marker, log] = process.argv.slice(1);",
  "http.createServer((req, res) => {",
  "  try { fs.appendFileSync(log, req.url + '\\n'); } catch {}",
  "  res.writeHead(200, { 'content-type': 'text/plain', connection: 'close' });",
  "  res.end(marker + '\\n' + req.url);",
  "}).listen({ host, port: Number(port) });",
].join("\n");

/** One TCP attempt: connect, send one HTTP/1.0 request, report what came back. */
const TCP_PROBE_SOURCE = [
  "const net = require('node:net');",
  "const [host, port, requestPath, timeoutMs] = process.argv.slice(1);",
  "let connected = false; let data = ''; let finished = false;",
  "const done = (error) => {",
  "  if (finished) return; finished = true;",
  "  process.stdout.write(JSON.stringify({ connected, data, error }));",
  "  process.exit(0);",
  "};",
  "const socket = net.connect({ host, port: Number(port) });",
  "socket.setTimeout(Number(timeoutMs), () => { socket.destroy(); done('timeout'); });",
  "socket.on('connect', () => { connected = true; socket.write('GET ' + requestPath + ' HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n'); });",
  "socket.on('data', (chunk) => { data += chunk.toString('utf8'); });",
  "socket.on('error', (error) => done(error.code || String(error)));",
  "socket.on('close', () => done(null));",
].join("\n");

/**
 * Who holds a LISTEN socket on one exact `ip:port`, from `/proc`: whether the
 * socket exists, the pids whose argv carries the marker, and whether one of
 * those pids owns the socket (null when their fds were unreadable).
 */
const LISTENER_OWNER_SOURCE = [
  "const fs = require('node:fs');",
  "const [ip, port, marker] = process.argv.slice(1);",
  "const address = ip.split('.').reverse().map((octet) => Number(octet).toString(16).padStart(2, '0')).join('').toUpperCase()",
  "  + ':' + Number(port).toString(16).toUpperCase().padStart(4, '0');",
  "const inodes = fs.readFileSync('/proc/net/tcp', 'utf8').split('\\n').slice(1)",
  "  .map((line) => line.trim().split(/\\s+/)).filter((cols) => cols[1] === address && cols[3] === '0A').map((cols) => cols[9]);",
  "const pids = []; let readable = false; let owned = false;",
  "for (const entry of fs.readdirSync('/proc')) {",
  "  if (!/^\\d+$/.test(entry) || Number(entry) === process.pid) continue;",
  "  let cmdline = '';",
  "  try { cmdline = fs.readFileSync('/proc/' + entry + '/cmdline', 'utf8'); } catch { continue; }",
  "  if (!cmdline.includes(marker)) continue;",
  "  pids.push(Number(entry));",
  "  let fds = [];",
  "  try { fds = fs.readdirSync('/proc/' + entry + '/fd'); readable = true; } catch { continue; }",
  "  for (const fd of fds) {",
  "    let link = '';",
  "    try { link = fs.readlinkSync('/proc/' + entry + '/fd/' + fd); } catch { continue; }",
  "    const match = /^socket:\\[(\\d+)\\]$/.exec(link);",
  "    if (match && inodes.includes(match[1])) owned = true;",
  "  }",
  "}",
  "process.stdout.write(JSON.stringify({ listening: inodes.length > 0, pids, owned: readable ? owned : null }));",
].join("\n");

/** Every process whose argv carries `needle`, as argv arrays. */
const PROCESS_ARGV_SOURCE = [
  "const fs = require('node:fs');",
  "const [needle] = process.argv.slice(1);",
  "const found = [];",
  "for (const entry of fs.readdirSync('/proc')) {",
  "  if (!/^\\d+$/.test(entry) || Number(entry) === process.pid) continue;",
  "  let cmdline = '';",
  "  try { cmdline = fs.readFileSync('/proc/' + entry + '/cmdline', 'utf8'); } catch { continue; }",
  "  if (cmdline.includes(needle)) found.push(cmdline.split('\\0').filter(Boolean));",
  "}",
  "process.stdout.write(JSON.stringify(found));",
].join("\n");

function sessionNode(containerId: string, source: string, args: readonly string[]): string {
  return dockerOrThrow("in-session node program", ["exec", "--user", AGENT_UID_GID, containerId, "node", "-e", source, ...args]);
}

export type TcpProbeResult = Readonly<{ connected: boolean; data: string; error: string | null }>;

/** One connection attempt from inside a session container to `host:port`. */
export function sessionTcpProbe(containerId: string, host: string, port: string, requestPath: string, timeoutMs = 4000): TcpProbeResult {
  return JSON.parse(sessionNode(containerId, TCP_PROBE_SOURCE, [host, port, requestPath, String(timeoutMs)])) as TcpProbeResult;
}

export type ListenerOwner = Readonly<{ listening: boolean; pids: readonly number[]; owned: boolean | null }>;

export function sessionListenerOwner(containerId: string, ip: string, port: string, marker: string): ListenerOwner {
  return JSON.parse(sessionNode(containerId, LISTENER_OWNER_SOURCE, [ip, port, marker])) as ListenerOwner;
}

export function sessionProcessArgv(containerId: string, needle: string): readonly (readonly string[])[] {
  return JSON.parse(sessionNode(containerId, PROCESS_ARGV_SOURCE, [needle])) as string[][];
}

/** Reads a file inside the session, or undefined when it does not exist. */
export function sessionFile(containerId: string, file: string): string | undefined {
  const result = docker(["exec", "--user", AGENT_UID_GID, containerId, "sh", "-c", 'test -e "$1" || exit 3; cat "$1"', "sh", file]);
  if (result.status === 3) return undefined;
  if (result.status !== 0) throw new Error(`could not read ${file} in the session: ${describeOutput(result.output)}`);
  return result.stdout;
}

export type SessionListener = Readonly<{ host: string; port: string; marker: string; log: string }>;

/**
 * Starts the stand-in listener inside the session and waits until it accepts.
 * `host` is its bind address: `0.0.0.0` for a dev server a forward can reach,
 * `127.0.0.1` for the CLI callback server only the bridge may reach.
 */
export async function startSessionListener(containerId: string, host: string, port: string, tag: string): Promise<SessionListener> {
  const marker = `runfree-livetest-${tag}-${Math.random().toString(36).slice(2, 10)}`;
  const log = `/tmp/runfree-livetest-${tag}-${port}.log`;
  dockerOrThrow(`start the ${tag} listener`, [
    "exec", "-d", "--user", AGENT_UID_GID, containerId, "node", "-e", LISTENER_SOURCE, host, port, marker, log,
  ]);
  const probeHost = host === "0.0.0.0" ? "127.0.0.1" : host;
  const deadline = Date.now() + LISTENER_READY_TIMEOUT_MS;
  for (;;) {
    const probe = sessionTcpProbe(containerId, probeHost, port, "/__runfree_livetest_ready", 2000);
    if (probe.data.includes(marker)) break;
    if (Date.now() >= deadline) throw new Error(`the ${tag} listener never answered on ${probeHost}:${port}: ${JSON.stringify(probe)}`);
    await sleep(250);
  }
  return Object.freeze({ host, port, marker, log });
}

/** The request urls the listener has seen. */
export function listenerLog(containerId: string, listener: SessionListener): readonly string[] {
  return (sessionFile(containerId, listener.log) ?? "").split("\n").filter(Boolean);
}

// ---------------------------------------------------------------------------
// Host side
// ---------------------------------------------------------------------------

export type HostHttpResult = Readonly<{ status: number; body: string }>;

/** One GET from the host to `127.0.0.1:port`; rejects on a transport failure. */
export function hostHttpGet(port: string, requestPath: string, timeoutMs = 5000): Promise<HostHttpResult> {
  return new Promise((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port: Number(port), path: requestPath, agent: false, timeout: timeoutMs }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => { body += chunk; });
      response.on("end", () => resolve(Object.freeze({ status: response.statusCode ?? 0, body })));
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error("host request timed out")));
    request.on("error", reject);
  });
}

/**
 * Retries a host GET until the listener's answer comes back, then returns it.
 * A forwarder can exist a moment before its splice is ready; the bound is the
 * claim that it becomes ready, not that it is ready on the first packet.
 */
export async function awaitHostReach(port: string, requestPath: string, listener: SessionListener, label: string): Promise<HostHttpResult> {
  const deadline = Date.now() + HOST_REACH_TIMEOUT_MS;
  let last = "<no attempt>";
  for (;;) {
    try {
      const result = await hostHttpGet(port, requestPath);
      if (result.body.startsWith(`${listener.marker}\n`)) return result;
      last = `status ${result.status}, body ${describeOutput(result.body, 400)}`;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    if (Date.now() >= deadline) throw new Error(`${label}: 127.0.0.1:${port} never reached the in-session listener (${last})`);
    await sleep(500);
  }
}

/** The first bytes a TCP server sends on connect, from the host. */
export function hostTcpBanner(port: string, bytes: number, timeoutMs = 5000): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port: Number(port) });
    let data = "";
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`no ${bytes}-byte banner within ${timeoutMs}ms (got ${JSON.stringify(data)})`));
    });
    socket.on("data", (chunk) => {
      data += chunk.toString("latin1");
      if (data.length >= bytes) {
        socket.destroy();
        resolve(data.slice(0, bytes));
      }
    });
    socket.on("error", reject);
    socket.on("close", () => reject(new Error(`connection closed before a ${bytes}-byte banner (got ${JSON.stringify(data)})`)));
  });
}
