import * as childProcess from "node:child_process";

import { type DockerEndpoint, type DockerEndpointFs, nodeDockerEndpointFs, resolveDockerEndpoint } from "../docker-endpoint.ts";
import type { CaptureResult } from "../types.ts";
import { bindDaemon, type BindingOutcome, type CliRunner, type DaemonBinding, socketIdentity } from "./binding.ts";
import { createNativeDockerCliProbe, type DockerCliProbe } from "./cli-identity.ts";
import { demuxDockerStream, formatRawInspect, truncateId } from "./format.ts";
import { type DockerApiRoute, matchDockerApiRoute } from "./routes.ts";
import { type BridgeReply, type BridgeRequest, createSyncBridge, type SyncBridge } from "./sync-bridge.ts";

/**
 * Opt-in until the live equivalence proof and Gate C pass on a Docker host:
 * only `api` enables the transport; unset, empty, `cli`, or anything else
 * keeps every call on the Docker CLI.
 */
export const DOCKER_TRANSPORT_ENV = "RUNFREE_DOCKER_TRANSPORT";

// spawnSync's default maxBuffer.
const DEFAULT_MAX_BUFFER = 1024 * 1024;
// A routed call the caller gave no timeout still ends here. The CLI path
// would wait without limit; a bounded wait fails closed with 124 instead.
// It is also how long Ctrl-C can wait: the calling thread cannot run a
// signal handler while it sleeps in Atomics.wait.
export const UNBUDGETED_ROUTED_CALL_MS = 60_000;
// Exec inspect polls after the stream ends, until the daemon records the exit
// or the call's deadline passes.
const EXEC_EXIT_FIRST_POLL_MS = 5;
const EXEC_EXIT_MAX_POLL_MS = 100;
const ALLOWED_OPTION_KEYS = new Set(["env", "timeout", "maxBuffer", "input", "encoding"]);

export type DockerApiCaptureOutcome =
  | { routed: true; result: CaptureResult }
  /** Stay on the CLI. `timeout` is the budget left for it when the transport spent some. */
  | { routed: false; timeout?: number };

export type DockerApiCapture = (command: string, args: readonly string[], options?: childProcess.SpawnSyncOptions) => DockerApiCaptureOutcome;

export type DockerApiCaptureDeps = {
  /** The runfree process environment: the kill switch is read here, never from a call's env. */
  controlEnv?: NodeJS.ProcessEnv;
  bridge?: SyncBridge;
  endpointFs?: DockerEndpointFs;
  resolveEndpoint?: (env: NodeJS.ProcessEnv) => DockerEndpoint;
  dockerCliProbe?: DockerCliProbe;
  /** Runs the Docker CLI for the one-time daemon binding (`docker version`). */
  runCli?: CliRunner;
  /** The socket's identity (real path, device, inode); undefined when it is not a socket. */
  socketIdentity?: (socketPath: string) => string | undefined;
  now?: () => number;
};

const spawnDockerCli: CliRunner = (args, env, timeoutMs) => {
  const result = childProcess.spawnSync("docker", [...args], { encoding: "utf8", env, timeout: timeoutMs, maxBuffer: 1024 * 1024 });
  const timedOut = (result.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
  const status = timedOut ? 124 : result.error || result.signal ? 125 : result.status ?? 125;
  return { status, stdout: typeof result.stdout === "string" ? result.stdout : "" };
};

class StayOnCli {
  constructor(readonly reason: string) {}
}

type RouteRun = CaptureResult | StayOnCli;

function statusOnly(status: number, stderr: string, extra: Partial<CaptureResult> = {}): CaptureResult {
  return { status, stdout: "", stderr, ...extra };
}

const TIMED_OUT: CaptureResult = { status: 124, stdout: "", stderr: "", timedOut: true };

function transportFailure(detail: string): CaptureResult {
  return statusOnly(125, `runfree: Docker Engine API call failed: ${detail}\n`);
}

function isAllowedOptions(options: childProcess.SpawnSyncOptions): boolean {
  for (const key of Object.keys(options)) {
    if (!ALLOWED_OPTION_KEYS.has(key)) return false;
  }
  const { encoding, timeout, maxBuffer, input } = options as childProcess.SpawnSyncOptionsWithStringEncoding;
  if (encoding !== undefined && encoding !== "utf8" && encoding !== "utf-8") return false;
  if (timeout !== undefined && !(typeof timeout === "number" && Number.isFinite(timeout) && timeout > 0)) return false;
  if (maxBuffer !== undefined && !(typeof maxBuffer === "number" && maxBuffer > 0)) return false;
  if (input !== undefined && typeof input !== "string" && !(input instanceof Uint8Array)) return false;
  return true;
}

function parseJson(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function daemonMessage(body: Buffer): string {
  const parsed = parseJson(body);
  return isRecord(parsed) && typeof parsed.message === "string" ? parsed.message : body.toString("utf8").trim();
}

function objectPath(route: Extract<DockerApiRoute, { kind: "inspect" }>, ref: string, version: string): string {
  switch (route.object) {
    case "container":
      return `/v${version}/containers/${ref}/json`;
    case "image":
      return `/v${version}/images/${ref}/json`;
    case "network":
      return `/v${version}/networks/${ref}`;
    case "volume":
      return `/v${version}/volumes/${ref}`;
  }
}

/**
 * The argv-compatible Engine API transport behind `capture("docker", …)`.
 *
 * Answers a routed argv with the status, stdout, and stderr the Docker CLI
 * would give, or tells the caller to use the CLI. It never answers a call it
 * cannot answer exactly; every doubt — the kill switch, an unexpected option,
 * an unrouted argv, a non-native `docker` on PATH, a non-Unix or unreadable
 * endpoint, a daemon that is not Docker, a refused connection, or any
 * non-success reply before a non-idempotent step — goes to the CLI. After a
 * non-idempotent step (an exec start) it never re-runs the command: an
 * unclear outcome fails closed with 125, a missed budget with 124.
 */
export function createDockerApiCapture(deps: DockerApiCaptureDeps = {}): DockerApiCapture {
  const controlEnv = deps.controlEnv ?? process.env;
  const bridge = deps.bridge ?? createSyncBridge();
  const endpointFs = deps.endpointFs ?? nodeDockerEndpointFs;
  const resolveEndpoint = deps.resolveEndpoint ?? ((env: NodeJS.ProcessEnv) => resolveDockerEndpoint(env, endpointFs));
  const dockerCliProbe = deps.dockerCliProbe ?? createNativeDockerCliProbe();
  const runCli = deps.runCli ?? spawnDockerCli;
  const identifySocket = deps.socketIdentity ?? socketIdentity;
  const now = deps.now ?? (() => performance.now());
  const bindings = new Map<string, Extract<BindingOutcome, { kind: "bound" | "cli" }>>();
  // The binding the current call runs under; calls are synchronous, so there
  // is at most one.
  let active: { key: string; binding: DaemonBinding } | undefined;

  const exchange = (req: Omit<BridgeRequest, "headers"> & { headers?: Record<string, string> }, deadline: number): BridgeReply => {
    const headers: Record<string, string> = { "User-Agent": "runfree-docker-transport", ...(req.headers ?? {}) };
    if (req.body) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(req.body.byteLength);
    }
    const reply = bridge.request({ ...req, headers }, deadline);
    // Every Docker reply names its engine (`Server`, `Api-Version`). A reply
    // from another engine than the one bound — a backend restarted or swapped
    // behind the same socket file — drops the binding and is treated like a
    // refused connection: a read or an unstarted exec goes to the CLI, and a
    // started exec fails closed.
    if (active && reply.kind === "response" && !sameEngine(reply.headers, active.binding)) {
      bindings.delete(active.key);
      active = undefined;
      return { kind: "error", code: "EDAEMONCHANGED", phase: "connect" };
    }
    return reply;
  };

  const runInspect = (
    route: Extract<DockerApiRoute, { kind: "inspect" }>,
    socketPath: string,
    version: string,
    maxBuffer: number,
    deadline: number,
  ): RouteRun => {
    const bodies: Buffer[] = [];
    for (const ref of route.refs) {
      const reply = exchange({ socketPath, method: "GET", path: objectPath(route, ref, version), maxBytes: maxBuffer }, deadline);
      const failure = readFailure(reply);
      if (failure) return failure;
      if (reply.kind !== "response") return transportFailure("unexpected reply");
      // Any miss or error: the CLI prints it (and, for type-less inspect,
      // searches the other object types). A read is safe to repeat.
      if (reply.status !== 200) return new StayOnCli(`inspect answered ${reply.status}`);
      const parsed = parseJson(reply.body);
      if (!isRecord(parsed)) return new StayOnCli("inspect body is not a JSON object");
      bodies.push(reply.body);
      if (route.template === "id" && typeof parsed.Id !== "string") return new StayOnCli("inspect body has no Id");
      if (route.template === "state-running" && !(isRecord(parsed.State) && typeof parsed.State.Running === "boolean")) {
        return new StayOnCli("inspect body has no State.Running");
      }
    }
    let stdout: Buffer;
    if (route.template === "raw") {
      stdout = formatRawInspect(bodies);
    } else {
      const lines = bodies.map((body) => {
        const parsed = parseJson(body) as Record<string, unknown>;
        return route.template === "id" ? String(parsed.Id) : String((parsed.State as Record<string, unknown>).Running);
      });
      stdout = Buffer.from(lines.map((line) => `${line}\n`).join(""));
    }
    if (stdout.byteLength > maxBuffer) return transportFailure("output exceeds maxBuffer");
    return { status: 0, stdout: stdout.toString("utf8"), stderr: "" };
  };

  const runPs = (
    route: Extract<DockerApiRoute, { kind: "ps" }>,
    socketPath: string,
    version: string,
    maxBuffer: number,
    deadline: number,
  ): RouteRun => {
    const query = new URLSearchParams();
    if (route.all) query.set("all", "1");
    const filterKeys = Object.keys(route.filters).sort();
    if (filterKeys.length > 0) {
      const encoded: Record<string, Record<string, boolean>> = {};
      for (const key of filterKeys) {
        encoded[key] = {};
        for (const value of route.filters[key]) encoded[key][value] = true;
      }
      query.set("filters", JSON.stringify(encoded));
    }
    const search = query.toString();
    const reply = exchange({ socketPath, method: "GET", path: `/v${version}/containers/json${search ? `?${search}` : ""}`, maxBytes: Math.max(maxBuffer, 16 * 1024 * 1024) }, deadline);
    const failure = readFailure(reply);
    if (failure) return failure;
    if (reply.kind !== "response") return transportFailure("unexpected reply");
    if (reply.status !== 200) return new StayOnCli(`container list answered ${reply.status}`);
    const parsed = parseJson(reply.body);
    if (!Array.isArray(parsed)) return new StayOnCli("container list is not an array");
    const ids: string[] = [];
    for (const entry of parsed) {
      if (!isRecord(entry) || typeof entry.Id !== "string" || entry.Id === "" || /\s/u.test(entry.Id)) return new StayOnCli("container list entry has no Id");
      ids.push(route.noTrunc ? entry.Id : truncateId(entry.Id));
    }
    const stdout = ids.map((id) => `${id}\n`).join("");
    if (Buffer.byteLength(stdout) > maxBuffer) return transportFailure("output exceeds maxBuffer");
    return { status: 0, stdout, stderr: "" };
  };

  const runExec = (
    route: Extract<DockerApiRoute, { kind: "exec" }>,
    socketPath: string,
    version: string,
    maxBuffer: number,
    input: Uint8Array | undefined,
    deadline: number,
  ): RouteRun => {
    const createBody = Buffer.from(JSON.stringify({
      ...(route.user !== undefined ? { User: route.user } : {}),
      AttachStdin: route.interactive,
      AttachStdout: true,
      AttachStderr: true,
      Tty: false,
      Cmd: route.cmd,
    }));
    const created = exchange({ socketPath, method: "POST", path: `/v${version}/containers/${route.containerId}/exec`, body: createBody, maxBytes: 64 * 1024 }, deadline);
    // Nothing has run yet: a refused connection or any daemon refusal (no such
    // container, not running) is the CLI's to report, with its exact text.
    const createFailure = readFailure(created);
    if (createFailure) return createFailure;
    if (created.kind !== "response") return transportFailure("unexpected exec create reply");
    if (created.status !== 201) return new StayOnCli(`exec create answered ${created.status}`);
    const createdBody = parseJson(created.body);
    const execId = isRecord(createdBody) ? createdBody.Id : undefined;
    if (typeof execId !== "string" || !/^[a-f0-9]{64}$/.test(execId)) return new StayOnCli("exec create returned no exec id");

    // From here on the command may run: never hand it to the CLI again.
    const started = exchange({
      socketPath,
      method: "POST",
      path: `/v${version}/exec/${execId}/start`,
      headers: { Connection: "Upgrade", Upgrade: "tcp" },
      body: Buffer.from(JSON.stringify({ Detach: false, Tty: false })),
      upgrade: { ...(route.interactive && input && input.byteLength > 0 ? { stdin: input } : {}) },
      // stdout and stderr each may reach maxBuffer, plus frame headers.
      maxBytes: maxBuffer * 2 + 64 * 1024,
    }, deadline);
    const startFailure = readFailure(started);
    if (startFailure) return startFailure;
    // A refused start never ran the command (the daemon hijacks the
    // connection before it starts the process); the CLI reports it as its
    // generic daemon error with status 1.
    if (started.kind === "response") {
      return statusOnly(1, `Error response from daemon: ${daemonMessage(started.body)}\n`);
    }
    if (started.kind !== "upgraded" || started.status !== 101) return transportFailure("exec start was not upgraded");
    const streams = demuxDockerStream(started.body);
    if (!streams.ok) return transportFailure(streams.reason);
    if (streams.stdout.byteLength > maxBuffer || streams.stderr.byteLength > maxBuffer) return transportFailure("output exceeds maxBuffer");

    for (let pause = EXEC_EXIT_FIRST_POLL_MS; ; pause = Math.min(pause * 2, EXEC_EXIT_MAX_POLL_MS)) {
      const inspected = exchange({ socketPath, method: "GET", path: `/v${version}/exec/${execId}/json`, maxBytes: 256 * 1024 }, deadline);
      const inspectFailure = readFailure(inspected, true);
      if (inspectFailure) return inspectFailure;
      if (inspected.kind !== "response" || inspected.status !== 200) return transportFailure("exec inspect failed");
      const state = parseJson(inspected.body);
      if (!isRecord(state)) return transportFailure("exec inspect body is not a JSON object");
      const exitCode = state.ExitCode;
      if (state.Running === false && typeof exitCode === "number" && Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255) {
        return { status: exitCode, stdout: streams.stdout.toString("utf8"), stderr: streams.stderr.toString("utf8") };
      }
      if (state.Running === false) return transportFailure("exec exit code unavailable");
      // The stream can end a moment before the daemon records the exit; keep
      // asking until the call's own deadline, never past it.
      const wait = Math.min(pause, deadline - now());
      if (wait <= 0) return TIMED_OUT;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, wait);
    }
  };

  return (command, args, options = {}) => {
    if (command !== "docker") return { routed: false };
    const mode = controlEnv[DOCKER_TRANSPORT_ENV];
    if (mode !== "api") return { routed: false };
    const envGiven = options.env !== undefined;
    const env = options.env ?? process.env;
    if (controlEnv.RUNFREE_TEST_FAKE_DOCKER === "1" || env.RUNFREE_TEST_FAKE_DOCKER === "1") return { routed: false };
    if (!isAllowedOptions(options)) return { routed: false };
    const input = typeof options.input === "string" ? Buffer.from(options.input) : options.input as Uint8Array | undefined;
    const route = matchDockerApiRoute(args, { hasInput: input !== undefined });
    if (!route) return { routed: false };
    if (bridge.isDead()) return { routed: false };
    const cliIdentity = dockerCliProbe(env, envGiven);
    if (cliIdentity === undefined) return { routed: false };
    const endpoint = resolveEndpoint(env);
    if (endpoint.kind !== "unix") return { routed: false };
    const socket = identifySocket(endpoint.socketPath);
    if (socket === undefined) return { routed: false };

    const started = now();
    const budget = options.timeout ?? UNBUDGETED_ROUTED_CALL_MS;
    const deadline = started + budget;
    const maxBuffer = options.maxBuffer ?? DEFAULT_MAX_BUFFER;
    const remaining = (): number | undefined => {
      if (options.timeout === undefined) return undefined;
      return Math.max(1, Math.floor(deadline - now()));
    };

    const bindingKey = `${cliIdentity}\u0000${socket}\u0000${endpoint.context}`;
    let bound = bindings.get(bindingKey);
    if (!bound) {
      const outcome = bindDaemon({
        exchange: (req, until) => exchange({ ...req, socketPath: endpoint.socketPath }, until),
        runCli,
        env,
        context: endpoint.context,
        deadline,
        now,
      });
      if (outcome.kind === "reply") {
        // A binding step that timed out or lost its socket mid-request is as
        // unclear as any other: 124 or 125, never a guess.
        const failure = readFailure(outcome.reply);
        if (failure instanceof StayOnCli || failure === undefined) return { routed: false, timeout: remaining() };
        return { routed: true, result: failure };
      }
      if (outcome.kind === "cli" && !outcome.cache) return { routed: false, timeout: remaining() };
      bound = outcome;
      bindings.set(bindingKey, bound);
    }
    if (bound.kind !== "bound") {
      if (options.timeout !== undefined && deadline - now() <= 0) return { routed: true, result: TIMED_OUT };
      return { routed: false, timeout: remaining() };
    }
    const binding: DaemonBinding = bound.binding;
    active = { key: bindingKey, binding };
    if (route.kind === "inspect" && route.typeless && !binding.swarmInactive) return { routed: false, timeout: remaining() };

    let run: RouteRun;
    try {
      switch (route.kind) {
      case "inspect":
        run = runInspect(route, endpoint.socketPath, binding.apiVersion, maxBuffer, deadline);
        break;
      case "ps":
        run = runPs(route, endpoint.socketPath, binding.apiVersion, maxBuffer, deadline);
        break;
      case "exec":
        run = runExec(route, endpoint.socketPath, binding.apiVersion, maxBuffer, input, deadline);
        break;
      }
    } finally {
      active = undefined;
    }
    if (run instanceof StayOnCli) {
      if (options.timeout !== undefined && deadline - now() <= 0) return { routed: true, result: TIMED_OUT };
      return { routed: false, timeout: remaining() };
    }
    return { routed: true, result: run };
  };
}

function sameEngine(headers: Record<string, string>, binding: DaemonBinding): boolean {
  const server = headers.server;
  const apiVersion = headers["api-version"];
  return (server === undefined || server === binding.server) && (apiVersion === undefined || apiVersion === binding.daemonApiVersion);
}

/**
 * A timeout, a dead worker, a mid-request socket error, or an overrun as the
 * CLI-shaped failure it maps to (see failClosedSpawnStatus); undefined for a
 * reply the route must read itself. A connect-phase error on a read is safe to
 * hand to the CLI (nothing reached the daemon), except once an exec may have
 * run: then every failure is final, so the command never runs twice.
 */
function readFailure(reply: BridgeReply, commandMayHaveRun = false): CaptureResult | StayOnCli | undefined {
  switch (reply.kind) {
    case "timeout":
      return TIMED_OUT;
    case "dead":
      return transportFailure("the Engine API worker stopped");
    case "overflow":
      return transportFailure("output exceeds maxBuffer");
    case "error":
      if (reply.phase === "connect" && !commandMayHaveRun) return new StayOnCli(`connect failed (${reply.code})`);
      return transportFailure(`socket error (${reply.code})`);
    default:
      return undefined;
  }
}
