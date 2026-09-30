import type * as childProcess from "node:child_process";

import { type DockerEndpoint, type DockerEndpointFs, nodeDockerEndpointFs, resolveDockerEndpoint } from "../docker-endpoint.ts";
import type { CaptureResult } from "../types.ts";
import { createNativeDockerCliProbe, type DockerCliProbe } from "./cli-identity.ts";
import { demuxDockerStream, formatRawInspect, truncateId } from "./format.ts";
import { type DockerApiRoute, matchDockerApiRoute } from "./routes.ts";
import { type BridgeReply, type BridgeRequest, createSyncBridge, type SyncBridge } from "./sync-bridge.ts";

/** `cli` forces every call onto the Docker CLI; unset or `api` allows the transport. */
export const DOCKER_TRANSPORT_ENV = "RUNFREE_DOCKER_TRANSPORT";

// spawnSync's default maxBuffer.
const DEFAULT_MAX_BUFFER = 1024 * 1024;
// A routed call the caller gave no timeout still ends here. The CLI path
// would wait without limit; a bounded wait fails closed with 124 instead.
// Longer than the 90 s lifecycle operation budget, so a budgeted caller
// always hits its own budget first.
export const UNBUDGETED_ROUTED_CALL_MS = 120_000;
// The oldest Engine API whose exec hijack and inspect bodies the routes rely on
// (Docker 20.10).
const MIN_API_MINOR = 41;
const EXEC_EXIT_POLLS = 20;
const EXEC_EXIT_POLL_MS = 10;
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
  now?: () => number;
};

type Ping = { ok: true; apiVersion: string } | { ok: false };

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
  const now = deps.now ?? (() => performance.now());
  const pings = new Map<string, Ping>();

  const exchange = (req: Omit<BridgeRequest, "headers"> & { headers?: Record<string, string> }, deadline: number): BridgeReply => {
    const headers: Record<string, string> = { "User-Agent": "runfree-docker-transport", ...(req.headers ?? {}) };
    if (req.body) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(req.body.byteLength);
    }
    return bridge.request({ ...req, headers }, deadline);
  };

  const ping = (socketPath: string, deadline: number): Ping | BridgeReply => {
    const cached = pings.get(socketPath);
    if (cached) return cached;
    const reply = exchange({ socketPath, method: "GET", path: "/_ping", maxBytes: 4096 }, deadline);
    if (reply.kind === "timeout" || reply.kind === "dead") return reply;
    if (reply.kind === "error") return reply;
    let result: Ping = { ok: false };
    if (reply.kind === "response" && reply.status === 200) {
      const version = reply.headers["api-version"] ?? "";
      const server = reply.headers.server ?? "";
      const match = /^1\.([0-9]{1,3})$/.exec(version);
      const isDocker = server.startsWith("Docker/") && reply.headers["libpod-api-version"] === undefined;
      if (match && Number(match[1]) >= MIN_API_MINOR && isDocker) result = { ok: true, apiVersion: version };
    }
    pings.set(socketPath, result);
    return result;
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
    if (started.kind === "response") {
      return statusOnly(125, `Error response from daemon: ${daemonMessage(started.body)}\n`);
    }
    if (started.kind !== "upgraded" || started.status !== 101) return transportFailure("exec start was not upgraded");
    const streams = demuxDockerStream(started.body);
    if (!streams.ok) return transportFailure(streams.reason);
    if (streams.stdout.byteLength > maxBuffer || streams.stderr.byteLength > maxBuffer) return transportFailure("output exceeds maxBuffer");

    for (let poll = 0; poll < EXEC_EXIT_POLLS; poll += 1) {
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
      // The stream can end a moment before the daemon records the exit.
      const pause = Math.min(EXEC_EXIT_POLL_MS, deadline - now());
      if (pause <= 0) return TIMED_OUT;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, pause);
    }
    return transportFailure("exec exit code unavailable");
  };

  return (command, args, options = {}) => {
    if (command !== "docker") return { routed: false };
    const mode = controlEnv[DOCKER_TRANSPORT_ENV];
    if (mode !== undefined && mode !== "" && mode !== "api") return { routed: false };
    const envGiven = options.env !== undefined;
    const env = options.env ?? process.env;
    if (controlEnv.RUNFREE_TEST_FAKE_DOCKER === "1" || env.RUNFREE_TEST_FAKE_DOCKER === "1") return { routed: false };
    if (!isAllowedOptions(options)) return { routed: false };
    const input = typeof options.input === "string" ? Buffer.from(options.input) : options.input as Uint8Array | undefined;
    const route = matchDockerApiRoute(args, { hasInput: input !== undefined });
    if (!route) return { routed: false };
    if (bridge.isDead()) return { routed: false };
    if (!dockerCliProbe(env, envGiven)) return { routed: false };
    const endpoint = resolveEndpoint(env);
    if (endpoint.kind !== "unix") return { routed: false };

    const started = now();
    const budget = options.timeout ?? UNBUDGETED_ROUTED_CALL_MS;
    const deadline = started + budget;
    const maxBuffer = options.maxBuffer ?? DEFAULT_MAX_BUFFER;
    const remaining = (): number | undefined => {
      if (options.timeout === undefined) return undefined;
      return Math.max(1, Math.floor(deadline - now()));
    };

    const pinged = ping(endpoint.socketPath, deadline);
    if ("kind" in pinged) {
      // A daemon that cannot be reached is the CLI's to report; a ping that
      // failed after connecting is as unclear as any other socket error.
      const failure = readFailure(pinged);
      if (failure instanceof StayOnCli) return { routed: false, timeout: remaining() };
      return { routed: true, result: failure ?? transportFailure("unexpected ping reply") };
    }
    if (!pinged.ok) return { routed: false, timeout: remaining() };

    let run: RouteRun;
    switch (route.kind) {
      case "inspect":
        run = runInspect(route, endpoint.socketPath, pinged.apiVersion, maxBuffer, deadline);
        break;
      case "ps":
        run = runPs(route, endpoint.socketPath, pinged.apiVersion, maxBuffer, deadline);
        break;
      case "exec":
        run = runExec(route, endpoint.socketPath, pinged.apiVersion, maxBuffer, input, deadline);
        break;
    }
    if (run instanceof StayOnCli) {
      if (options.timeout !== undefined && deadline - now() <= 0) return { routed: true, result: TIMED_OUT };
      return { routed: false, timeout: remaining() };
    }
    return { routed: true, result: run };
  };
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
