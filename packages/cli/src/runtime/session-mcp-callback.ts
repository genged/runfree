// The per-session MCP OAuth callback, as a session-owned two-hop ingress path.
//
// An MCP OAuth login ends with the provider redirecting the operator's browser
// to a loopback port, where the agent CLI's callback server listens inside the
// session (Claude and Codex bind the session's own 127.0.0.1). Every eligible
// session — `runfree claude|codex|pi|shell`, a resume, `mcp auth` — owns its
// own port and path:
//
//   host 127.0.0.1:P
//     ── hop 1: mcp-callback ingress forwarder, bound to this session ──▶ session-IP:P
//         ── hop 2: in-session bridge (forwarder peer only) ──▶ session 127.0.0.1:P
//
// Ownership (session MCP OAuth callback decisions, 2026-09-30). The forwarder
// is created in one `docker run` that also mints its owner binding — the
// session id and the exact session container id in its environment — so no
// forwarder ever exists without it, and crash recovery finds it by listing.
// The session's lifecycle record keeps reserving the target address; the
// shared ordered teardown removes the forwarder before that record, and the
// orphan sweeps remove it before a container no record claims, so an address
// is never released while a route to it survives.
//
// The port is a routing value, not an authority. The client keeps OAuth
// state, PKCE, and issuer validation; the proxy keeps egress and tokens. A
// session that damages its own bridge or port file only breaks its own login.

import type * as childProcess from "node:child_process";
import crypto from "node:crypto";
import net from "node:net";

import { CliError } from "../errors.ts";
import { readHostServicePortRegistry } from "../host-service-registry.ts";
import { createDockerClient } from "./docker-client.ts";
import { dockerClientEnvOptions, parseDockerJson } from "./docker.ts";
import { projectHash } from "./env.ts";
import { connectIngressForwarderAsync, ingressForwarderName, startIngressForwarderAsync } from "./ingress-forwarder.ts";
import {
  SESSION_CALLBACK_COMPLETE_BUDGET_MS,
  SESSION_CALLBACK_RESERVE_BUDGET_MS,
  SESSION_CALLBACK_SETUP_BUDGET_MS,
} from "./launch-lock-hold.ts";
import { removeValidatedIngressForwarders } from "./ingress-forwarder-ownership.ts";
import { mcpOAuthCallbackPort, runtimeMcpOAuthPolicyHasServers } from "./mcp.ts";
import { probeMcpCallbackPathWithRetries, startMcpCallbackBridgeInContainer } from "./probes.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeContext, RuntimeIO } from "./types.ts";
import {
  forwarderHostPort,
  inspectCallbackForwardersAsync,
  MCP_CALLBACK_PURPOSE,
  removeSessionMcpCallbackIngress,
  SESSION_CALLBACK_CONTAINER_ENV,
  SESSION_CALLBACK_SESSION_ID_ENV,
} from "./session-callback-ingress.ts";


/** Ports tried per session: the legacy project port, then up to 31 alternatives. */
export const SESSION_CALLBACK_PORT_ATTEMPTS = 32;
// Same range as the legacy project port (mcp.ts), so every Runfree callback
// port stays in one recognizable unprivileged block.
const CALLBACK_PORT_BASE = 47100;
const CALLBACK_PORT_SPAN = 1000;

const SESSION_ID_PATTERN = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/;
const FULL_DOCKER_ID_PATTERN = /^[a-f0-9]{64}$/;
const IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
// Docker Engine: "Bind for 127.0.0.1:P failed: port is already allocated";
// Docker Desktop: "Ports are not available: ... bind: address already in use".
const PUBLICATION_CONFLICT_PATTERN = /port is already allocated|address already in use|ports are not available/i;

export type SessionCallbackOwner = Readonly<{
  sessionId: string;
  /** The exact 64-hex session container id. */
  containerId: string;
  /** The session's agent_internal IPv4 address. */
  sourceIp: string;
  /** The exact runtime name of the project's agent_internal network. */
  internalNetwork: string;
}>;

export type SessionCallbackEndpoint = Readonly<{
  port: number;
  forwarderName: string;
}>;

/** A published, LISTENing forwarder bound to its session, not yet attached to `agent_internal`. */
export type SessionCallbackReservation = Readonly<{
  port: number;
  forwarderName: string;
  /** The forwarder's exact 64-hex container id. */
  forwarderId: string;
}>;

/**
 * What the admission driver needs, in two phases. Teardown is shared.
 *
 * `reserve` may overlap the session container's start and running proof: it
 * touches only the forwarder and the host-facing network. `complete` runs
 * after the running proof and before the session file is written: attaching
 * `agent_internal` (a dynamic address) waits until the session's static
 * address is bound, and the bridge announces the port before any client runs.
 */
export type SessionIngressLifecycle = Readonly<{
  /** Steps 1-5: list forwarders, host port check, name check, host network, `docker run -p` (the reservation), readiness. */
  reserve(owner: SessionCallbackOwner): Promise<SessionCallbackReservation>;
  /** Step 6 onward: connect agent_internal, internal address, bridge (port file), probe. Removes the ingress on failure. */
  complete(owner: SessionCallbackOwner, reservation: SessionCallbackReservation): Promise<SessionCallbackEndpoint>;
}>;

function assertOwner(owner: SessionCallbackOwner): void {
  if (!SESSION_ID_PATTERN.test(owner.sessionId)) throw new Error("session callback owner has an invalid session id");
  if (!FULL_DOCKER_ID_PATTERN.test(owner.containerId)) {
    throw new Error("session callback owner requires an exact session container id");
  }
  if (!IPV4_PATTERN.test(owner.sourceIp)) throw new Error("session callback owner requires an exact IPv4 address");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/u.test(owner.internalNetwork)) {
    throw new Error("session callback owner requires an exact internal network name");
  }
}

/** Whether this project's sessions need a callback path at all. */
export function sessionMcpCallbackRequired(context: RuntimeContext): boolean {
  return runtimeMcpOAuthPolicyHasServers(context.project);
}

/**
 * The ordered port candidates for one session: the project's legacy port
 * first (a single-session project keeps the port it always had), then
 * pseudo-random alternatives seeded by the session id, skipping `excluded`.
 */
export function sessionCallbackPortCandidates(
  projectRoot: string,
  sessionId: string,
  excluded: ReadonlySet<number> = new Set(),
): number[] {
  const candidates: number[] = [];
  const seen = new Set<number>(excluded);
  const add = (port: number) => {
    if (seen.has(port) || candidates.length >= SESSION_CALLBACK_PORT_ATTEMPTS) return;
    seen.add(port);
    candidates.push(port);
  };
  add(mcpOAuthCallbackPort(projectRoot));
  for (let index = 0; candidates.length < SESSION_CALLBACK_PORT_ATTEMPTS && index < CALLBACK_PORT_SPAN * 4; index += 1) {
    const digest = crypto.createHash("sha256").update(`${sessionId}:${index}`).digest();
    add(CALLBACK_PORT_BASE + (digest.readUInt32BE(0) % CALLBACK_PORT_SPAN));
  }
  return candidates;
}

function hostCanBind(host: string, port: number): Promise<"free" | "busy" | "unavailable"> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", (error: NodeJS.ErrnoException) => {
      resolve(error.code === "EADDRNOTAVAIL" || error.code === "EAFNOSUPPORT" ? "unavailable" : "busy");
    });
    server.listen({ host, port, exclusive: true }, () => {
      server.close(() => resolve("free"));
    });
  });
}

/**
 * Advisory: whether the host's loopback port is unclaimed right now, on both
 * address families. Docker publishes only 127.0.0.1, but Claude advertises
 * `localhost`, which a browser may try as `[::1]` first — so a host process on
 * `[::1]:port` would receive the callback. A host without IPv6 loopback counts
 * as free there. Docker's publication, not this check, is the reservation.
 */
export async function hostLoopbackPortFree(port: number): Promise<boolean> {
  if (await hostCanBind("127.0.0.1", port) !== "free") return false;
  return await hostCanBind("::1", port) !== "busy";
}

function sessionCallbackRetry(detail: string): CliError {
  return new CliError(
    `the MCP OAuth callback for this session could not be set up: ${detail}. `
      + "Nothing was left running for this session; retry the command",
  );
}

type PrepareDependencies = Readonly<{
  hostPortFree?: (port: number) => Promise<boolean>;
  probe?: (port: number, challenge: string, deadlineMs: number, nowMs: () => number) => Promise<CaptureResult>;
  /** Monotonic clock for the setup budget; defaults to `performance.now`. */
  nowMs?: () => number;
  /**
   * The phase's budget. Defaults: `SESSION_CALLBACK_RESERVE_BUDGET_MS` for a
   * reserve, `SESSION_CALLBACK_COMPLETE_BUDGET_MS` for a complete, and
   * `SESSION_CALLBACK_SETUP_BUDGET_MS` for the whole of a prepare, whose two
   * phases share one deadline.
   */
  budgetMs?: number;
  /** The ordered port candidates, given the excluded ports; defaults to `sessionCallbackPortCandidates`. */
  candidates?: (excluded: ReadonlySet<number>) => readonly number[];
  /**
   * Ports any project has approved as a host service (HS7): never a callback
   * candidate, in any project. Defaults to one bounded read of the host-global
   * registry — never lsof, never the registry's own write lock — and reads
   * as empty rather than throwing, since the callback's own fixed port block
   * (47100-48099) is a host-service port no project can ever register, so an
   * unreadable registry does not weaken it.
   */
  registeredHostPorts?: () => ReadonlySet<number>;
}>;

/**
 * The setup's Docker calls, each cut off (SIGKILL) at the time left in the
 * setup budget, and refused once it is spent, so the setup never stretches a
 * launch's hold of the lifecycle lock (`launch-lock-hold.ts`). Only the setup
 * steps use it: removing what the setup created runs on the caller's io, so a
 * spent budget never leaves a forwarder behind for want of time to remove it.
 */
export function withSetupDeadline(io: RuntimeIO, remainingMs: () => number, budgetMs: number): RuntimeIO {
  const bounded = (options: childProcess.SpawnSyncOptions | undefined): childProcess.SpawnSyncOptions => {
    const left = Math.floor(remainingMs());
    if (left <= 0) throw new Error(`the callback setup used its whole ${budgetMs} ms budget`);
    return { ...(options ?? {}), timeout: Math.min(options?.timeout ?? left, left), killSignal: "SIGKILL" };
  };
  // A killed call leaves stderr empty, so callers' `stderr || "failed to …"`
  // messages would hide that the cut, not Docker, ended it.
  const named = (command: string, args: string[], bound: childProcess.SpawnSyncOptions, result: CaptureResult): CaptureResult => {
    if (!result.timedOut) return result;
    const note = `${[command, args[0]].filter(Boolean).join(" ")} timed out after ${bound.timeout} ms (MCP OAuth callback setup budget ${budgetMs} ms)`;
    return { ...result, stderr: result.stderr.trim() ? `${result.stderr.trimEnd()}\n${note}` : note };
  };
  const { captureAsync } = io;
  return {
    ...io,
    capture: (command, args, options) => {
      const bound = bounded(options);
      return named(command, args, bound, io.capture(command, args, bound));
    },
    run: (command, args, options) => io.run(command, args, bounded(options)),
    ...(captureAsync ? {
      captureAsync: async (command: string, args: string[], options?: childProcess.SpawnSyncOptions) => {
        const bound = bounded(options);
        return named(command, args, bound, await captureAsync.call(io, command, args, bound));
      },
    } : {}),
  };
}

function removeCreatedResidue(context: RuntimeContext, io: RuntimeIO, projectId: string, name: string): void {
  // A publication conflict can leave the created, never-started container
  // behind under this name; remove it by exact validated identity.
  removeValidatedIngressForwarders(context, io, projectId, [name]);
}

function forwarderInternalAddress(
  context: RuntimeContext,
  io: RuntimeIO,
  name: string,
  internalNetwork: string,
): string {
  const inspected = createDockerClient(io, dockerClientEnvOptions(context)).inspect([name], { type: "container" });
  const parsed = inspected.status === 0
    ? parseDockerJson<DockerContainerInspect[]>(inspected, "docker inspect MCP OAuth callback forwarder")
    : undefined;
  const address = parsed?.length === 1 ? parsed[0]?.NetworkSettings?.Networks?.[internalNetwork]?.IPAddress : undefined;
  if (!address || !IPV4_PATTERN.test(address)) {
    throw new Error(`MCP OAuth callback forwarder ${name} has no exact ${internalNetwork} address`);
  }
  return address;
}

type PhaseDeadline = Readonly<{ deadlineMs: number; budgetMs: number }>;

function phaseDeadline(deps: PrepareDependencies, defaultBudgetMs: number): PhaseDeadline {
  const budgetMs = deps.budgetMs ?? defaultBudgetMs;
  return Object.freeze({ deadlineMs: (deps.nowMs ?? (() => performance.now()))() + budgetMs, budgetMs });
}

function failureMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Removes every forwarder routed to this session, on the caller's io (never
 * cut off by a spent budget), then throws the retry error for `message`.
 */
function failAfterRemovingSessionIngress(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  message: string,
): never {
  try {
    removeSessionMcpCallbackIngress({
      io,
      dockerOptions: dockerClientEnvOptions(context),
      projectId: projectHash(context.projectRoot),
      sessionId: owner.sessionId,
      sourceIp: owner.sourceIp,
    });
  } catch (cleanup) {
    throw sessionCallbackRetry(`${message}; and cleanup failed: ${failureMessage(cleanup)}`);
  }
  throw sessionCallbackRetry(message);
}

async function reserveWithin(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  deps: PrepareDependencies,
  phase: PhaseDeadline,
): Promise<SessionCallbackReservation> {
  assertOwner(owner);
  const projectId = projectHash(context.projectRoot);
  const { internalNetwork } = owner;
  const hostPortFree = deps.hostPortFree ?? hostLoopbackPortFree;
  const nowMs = deps.nowMs ?? (() => performance.now());
  const { deadlineMs, budgetMs } = phase;
  // Every reservation step runs on the asynchronous client, so it can overlap
  // the session container's start, and each is cut off at the time left.
  // Cleanup (removing what this call created) uses the caller's io.
  const setupIo = withSetupDeadline(io, () => deadlineMs - nowMs(), budgetMs);

  // Ports this project's forwarders already publish are never candidates;
  // Docker's publication conflict covers every other process on the host,
  // including another project's concurrent reservation.
  const held = new Set((await inspectCallbackForwardersAsync({
    io: setupIo,
    dockerOptions: dockerClientEnvOptions(context),
    projectId,
  })).forwarders
    .map(forwarderHostPort)
    .filter((port): port is number => port !== undefined));
  const registeredHostPorts = deps.registeredHostPorts ?? (() => {
    const read = readHostServicePortRegistry(context.env ?? process.env);
    return read.ok ? new Set(read.owners.keys()) : new Set<number>();
  });
  for (const port of registeredHostPorts()) held.add(port);
  const candidates = (deps.candidates ?? ((excluded) => sessionCallbackPortCandidates(context.projectRoot, owner.sessionId, excluded)))(held)
    .filter((port) => !held.has(port));

  let lastConflict = "";
  for (const port of candidates) {
    if (nowMs() >= deadlineMs) {
      throw sessionCallbackRetry(`the callback setup used its whole ${budgetMs} ms budget before a port was reserved`);
    }
    if (!(await hostPortFree(port))) continue;
    const name = ingressForwarderName(projectId, MCP_CALLBACK_PURPOSE, String(port));
    try {
      const started = await startIngressForwarderAsync(context, setupIo, {
        purpose: MCP_CALLBACK_PURPOSE,
        projectId,
        hostPort: String(port),
        target: owner.sourceIp,
        targetPort: String(port),
        internalNetwork,
        extraEnv: {
          [SESSION_CALLBACK_SESSION_ID_ENV]: owner.sessionId,
          [SESSION_CALLBACK_CONTAINER_ENV]: owner.containerId,
        },
      });
      if (started.name !== name || !FULL_DOCKER_ID_PATTERN.test(started.containerId)) {
        throw new Error(`MCP OAuth callback forwarder ${started.name} started without its exact identity`);
      }
      return Object.freeze({ port, forwarderName: name, forwarderId: started.containerId });
    } catch (error) {
      const message = failureMessage(error);
      if (!PUBLICATION_CONFLICT_PATTERN.test(message)) failAfterRemovingSessionIngress(context, io, owner, message);
      lastConflict = message;
      try {
        removeCreatedResidue(context, io, projectId, name);
      } catch (cleanup) {
        throw sessionCallbackRetry(`${message}; and cleanup failed: ${failureMessage(cleanup)}`);
      }
    }
  }
  throw sessionCallbackRetry(
    `no free loopback port among ${candidates.length} candidates${lastConflict ? ` (last conflict: ${lastConflict})` : ""}`,
  );
}

async function completeWithin(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  reservation: SessionCallbackReservation,
  deps: PrepareDependencies,
  phase: PhaseDeadline,
): Promise<SessionCallbackEndpoint> {
  assertOwner(owner);
  const nowMs = deps.nowMs ?? (() => performance.now());
  const { deadlineMs, budgetMs } = phase;
  const setupIo = withSetupDeadline(io, () => deadlineMs - nowMs(), budgetMs);
  try {
    const projectId = projectHash(context.projectRoot);
    if (!Number.isInteger(reservation.port)
      || reservation.forwarderName !== ingressForwarderName(projectId, MCP_CALLBACK_PURPOSE, String(reservation.port))
      || !FULL_DOCKER_ID_PATTERN.test(reservation.forwarderId)) {
      throw new Error("the callback reservation is not this project's forwarder for its port");
    }
    // Attached only now: the forwarder's `agent_internal` address is dynamic,
    // and the session's static address is bound only once it has started.
    await connectIngressForwarderAsync(
      context,
      setupIo,
      { name: reservation.forwarderName, containerId: reservation.forwarderId },
      owner.internalNetwork,
    );
    const allowedPeerIp = forwarderInternalAddress(context, setupIo, reservation.forwarderName, owner.internalNetwork);
    const challenge = crypto.randomBytes(24).toString("base64url");
    const bridge = startMcpCallbackBridgeInContainer(context, setupIo, {
      containerId: owner.containerId,
      bindIp: owner.sourceIp,
      port: reservation.port,
      challenge,
      allowedPeerIp,
    });
    if (bridge !== 0) throw new Error(`the in-session callback bridge did not start (exit ${bridge})`);
    const probe = await (deps.probe ?? probeMcpCallbackPathWithRetries)(reservation.port, challenge, deadlineMs, nowMs);
    if (probe.status !== 0) {
      throw new Error(`http://127.0.0.1:${reservation.port} did not reach the session (${probe.stderr || "no echo"})`);
    }
  } catch (error) {
    failAfterRemovingSessionIngress(context, io, owner, failureMessage(error));
  }
  return Object.freeze({ port: reservation.port, forwarderName: reservation.forwarderName });
}

/**
 * Reserves this session's callback port: creates its bound forwarder on the
 * host-facing network and waits until it LISTENs there. Every Docker call is
 * asynchronous, so a launch runs this beside the session container's start.
 * The forwarder is not attached to `agent_internal`. Any failure removes what
 * this call created and throws, failing the launch.
 */
export async function reserveSessionMcpCallback(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  deps: PrepareDependencies = {},
): Promise<SessionCallbackReservation> {
  return reserveWithin(context, io, owner, deps, phaseDeadline(deps, SESSION_CALLBACK_RESERVE_BUDGET_MS));
}

/**
 * Completes a reserved callback after the session's running proof: attaches
 * the forwarder to `agent_internal`, starts the peer-only bridge (which writes
 * the port file), and proves the host path. Runs before activation, while the
 * session's entry is still waiting. Any failure removes every forwarder routed
 * to this session and throws, failing the launch.
 */
export async function completeSessionMcpCallback(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  reservation: SessionCallbackReservation,
  deps: PrepareDependencies = {},
): Promise<SessionCallbackEndpoint> {
  return completeWithin(context, io, owner, reservation, deps, phaseDeadline(deps, SESSION_CALLBACK_COMPLETE_BUDGET_MS));
}

/**
 * Sets up this session's callback in one call: reserve, then complete, under
 * one deadline for the whole setup. For a caller with nothing to overlap.
 */
export async function prepareSessionMcpCallback(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  deps: PrepareDependencies = {},
): Promise<SessionCallbackEndpoint> {
  const phase = phaseDeadline(deps, SESSION_CALLBACK_SETUP_BUDGET_MS);
  const reservation = await reserveWithin(context, io, owner, deps, phase);
  return completeWithin(context, io, owner, reservation, deps, phase);
}

/** The lifecycle the admission driver runs for an eligible launch; undefined when none is needed. */
export function sessionMcpCallbackLifecycle(context: RuntimeContext, io: RuntimeIO): SessionIngressLifecycle | undefined {
  if (!sessionMcpCallbackRequired(context)) return undefined;
  return Object.freeze({
    reserve: (owner: SessionCallbackOwner) => reserveSessionMcpCallback(context, io, owner),
    complete: (owner: SessionCallbackOwner, reservation: SessionCallbackReservation) =>
      completeSessionMcpCallback(context, io, owner, reservation),
  });
}
