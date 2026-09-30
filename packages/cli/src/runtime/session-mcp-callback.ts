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
// shared ordered teardown removes the forwarder before that record, so an
// address is never released while a route to it survives.
//
// The port is a routing value, not an authority. The client keeps OAuth
// state, PKCE, and issuer validation; the proxy keeps egress and tokens. A
// session that damages its own bridge or port file only breaks its own login.

import crypto from "node:crypto";
import net from "node:net";

import { CliError } from "../errors.ts";
import { dockerClientEnvOptions, parseDockerJson } from "./docker.ts";
import { projectHash } from "./env.ts";
import { ingressForwarderName, startIngressForwarder } from "./ingress-forwarder.ts";
import { removeValidatedIngressForwarders } from "./ingress-forwarder-ownership.ts";
import { mcpOAuthCallbackPort, runtimeMcpOAuthPolicyHasServers } from "./mcp.ts";
import { probeMcpCallbackPathWithRetries, startMcpCallbackBridgeInContainer } from "./probes.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeContext, RuntimeIO } from "./types.ts";
import {
  forwarderHostPort,
  inspectCallbackForwarders,
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

/** What the admission driver needs: set up before activation. Teardown is shared. */
export type SessionIngressLifecycle = Readonly<{
  prepare(owner: SessionCallbackOwner): Promise<SessionCallbackEndpoint | undefined>;
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
  probe?: (port: number, challenge: string) => Promise<CaptureResult>;
}>;

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
  const inspected = io.capture("docker", ["container", "inspect", name], dockerClientEnvOptions(context));
  const parsed = inspected.status === 0
    ? parseDockerJson<DockerContainerInspect[]>(inspected, "docker inspect MCP OAuth callback forwarder")
    : undefined;
  const address = parsed?.length === 1 ? parsed[0]?.NetworkSettings?.Networks?.[internalNetwork]?.IPAddress : undefined;
  if (!address || !IPV4_PATTERN.test(address)) {
    throw new Error(`MCP OAuth callback forwarder ${name} has no exact ${internalNetwork} address`);
  }
  return address;
}

/**
 * Sets up this session's callback: reserves a port by creating its bound
 * forwarder, starts the in-session bridge, and proves the host path. Runs
 * before activation, while the session's entry is still waiting. Any failure
 * removes what this call created and throws, failing the launch.
 */
export async function prepareSessionMcpCallback(
  context: RuntimeContext,
  io: RuntimeIO,
  owner: SessionCallbackOwner,
  deps: PrepareDependencies = {},
): Promise<SessionCallbackEndpoint> {
  assertOwner(owner);
  const projectId = projectHash(context.projectRoot);
  const { internalNetwork } = owner;
  const dockerInput = { io, dockerOptions: dockerClientEnvOptions(context), projectId } as const;
  const hostPortFree = deps.hostPortFree ?? hostLoopbackPortFree;

  // Ports this project's forwarders already publish are never candidates;
  // Docker's publication conflict covers every other process on the host.
  const held = new Set(inspectCallbackForwarders(dockerInput).forwarders
    .map(forwarderHostPort)
    .filter((port): port is number => port !== undefined));
  const candidates = sessionCallbackPortCandidates(context.projectRoot, owner.sessionId, held);

  let endpoint: SessionCallbackEndpoint | undefined;
  let lastConflict = "";
  for (const port of candidates) {
    if (!(await hostPortFree(port))) continue;
    const name = ingressForwarderName(projectId, MCP_CALLBACK_PURPOSE, String(port));
    try {
      startIngressForwarder(context, io, {
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
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!PUBLICATION_CONFLICT_PATTERN.test(message)) {
        try {
          removeSessionMcpCallbackIngress({ ...dockerInput, sessionId: owner.sessionId, sourceIp: owner.sourceIp });
        } catch (cleanup) {
          throw sessionCallbackRetry(`${message}; and cleanup failed: ${cleanup instanceof Error ? cleanup.message : String(cleanup)}`);
        }
        throw sessionCallbackRetry(message);
      }
      lastConflict = message;
      try {
        removeCreatedResidue(context, io, projectId, name);
      } catch (cleanup) {
        throw sessionCallbackRetry(`${message}; and cleanup failed: ${cleanup instanceof Error ? cleanup.message : String(cleanup)}`);
      }
      continue;
    }
    endpoint = Object.freeze({ port, forwarderName: name });
    break;
  }
  if (!endpoint) {
    throw sessionCallbackRetry(
      `no free loopback port among ${candidates.length} candidates${lastConflict ? ` (last conflict: ${lastConflict})` : ""}`,
    );
  }

  try {
    const allowedPeerIp = forwarderInternalAddress(context, io, endpoint.forwarderName, internalNetwork);
    const challenge = crypto.randomBytes(24).toString("base64url");
    const bridge = startMcpCallbackBridgeInContainer(context, io, {
      containerId: owner.containerId,
      bindIp: owner.sourceIp,
      port: endpoint.port,
      challenge,
      allowedPeerIp,
    });
    if (bridge !== 0) throw new Error(`the in-session callback bridge did not start (exit ${bridge})`);
    const probe = await (deps.probe ?? probeMcpCallbackPathWithRetries)(endpoint.port, challenge);
    if (probe.status !== 0) {
      throw new Error(`http://127.0.0.1:${endpoint.port} did not reach the session (${probe.stderr || "no echo"})`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    try {
      removeSessionMcpCallbackIngress({ ...dockerInput, sessionId: owner.sessionId, sourceIp: owner.sourceIp });
    } catch (cleanup) {
      throw sessionCallbackRetry(`${message}; and cleanup failed: ${cleanup instanceof Error ? cleanup.message : String(cleanup)}`);
    }
    throw sessionCallbackRetry(message);
  }
  return endpoint;
}

/** The lifecycle the admission driver runs for an eligible launch; undefined when none is needed. */
export function sessionMcpCallbackLifecycle(context: RuntimeContext, io: RuntimeIO): SessionIngressLifecycle | undefined {
  if (!sessionMcpCallbackRequired(context)) return undefined;
  return Object.freeze({
    prepare: (owner: SessionCallbackOwner) => prepareSessionMcpCallback(context, io, owner),
  });
}
