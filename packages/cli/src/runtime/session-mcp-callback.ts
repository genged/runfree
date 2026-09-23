// The per-session MCP OAuth callback, as a two-hop ingress path.
//
// The OAuth provider redirects the operator's browser to a fixed host port, and
// the agent CLI's callback server binds the session's own loopback (Claude and
// Codex choose 127.0.0.1; Runfree does not control that bind). Reaching it from
// the host is two hops:
//
//   host 127.0.0.1:PORT
//     ── hop 1: mcp-callback ingress forwarder ──▶ session-IP:PORT
//         ── hop 2: in-session bridge ──▶ session 127.0.0.1:PORT (the callback server)
//
// Hop 1 is a hardened ingress forwarder created here, targeting the live
// session's exact internal IP — never the legacy relay's hardwired agent IP,
// which is the bug this replaces. Hop 2 is the same in-container bridge the
// legacy shared-agent path ran (probes.ts), moved into the session and bound to
// its network interface: the untrusted session never publishes a host port,
// only the trusted forwarder does. Both are created when `runfree mcp auth`
// launches the session and are scoped to that session's life — hop 2 dies with
// the session container, hop 1 is removed when the session ends.

import crypto from "node:crypto";

import { warn } from "../warnings.ts";
import { composeProjectName, projectHash } from "./env.ts";
import {
  ingressForwarderName,
} from "./ingress-forwarder.ts";
import {
  removeValidatedIngressForwarders,
  replaceValidatedIngressForwarder,
} from "./ingress-forwarder-ownership.ts";
import { mcpOAuthCallbackPort, runtimeMcpOAuthPolicyHasServers } from "./mcp.ts";
import { probeMcpCallbackPathWithRetries, startMcpCallbackBridgeInContainer } from "./probes.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const MCP_CALLBACK_PURPOSE = "mcp-callback" as const;

export type SessionCallbackTarget = Readonly<{ containerId: string; sourceIp: string }>;

/**
 * Stands up the two-hop callback for a live session and validates it end to end.
 *
 * No-op (returns 0) when the project's OAuth policy has no servers that need a
 * browser callback. Otherwise creates hop 1 (the ingress forwarder) and hop 2
 * (the in-session bridge), then probes the host path. A hop-1 failure is warned
 * and reported rather than thrown, so the caller can still launch the session
 * and let the operator retry.
 */
export async function startSessionMcpCallback(
  context: RuntimeContext,
  io: RuntimeIO,
  session: SessionCallbackTarget,
): Promise<number> {
  if (!runtimeMcpOAuthPolicyHasServers(context.project)) return 0;
  const projectId = projectHash(context.projectRoot);
  const project = composeProjectName(context.projectRoot);
  const port = mcpOAuthCallbackPort(context.projectRoot);
  const internalNetwork = `${project}_agent_internal`;
  const challenge = crypto.randomBytes(24).toString("base64url");

  // hop 1: host loopback -> the live session's internal IP.
  try {
    replaceValidatedIngressForwarder(context, io, projectId, {
      purpose: MCP_CALLBACK_PURPOSE,
      projectId,
      hostPort: String(port),
      target: session.sourceIp,
      targetPort: String(port),
      internalNetwork,
    });
  } catch (error) {
    warn(`MCP OAuth callback forwarder failed to start: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  // hop 2: the session's network interface -> its own loopback callback server.
  const bridge = startMcpCallbackBridgeInContainer(context, io, {
    containerId: session.containerId,
    bindIp: session.sourceIp,
    port,
    challenge,
  });
  if (bridge !== 0) {
    warn(`MCP OAuth callback bridge failed to start in session ${session.containerId}`);
    return bridge;
  }

  const probe = await probeMcpCallbackPathWithRetries(context, port, challenge);
  if (probe.status !== 0) warn(`MCP OAuth callback path did not answer on http://localhost:${port}/callback`);
  return probe.status;
}

/**
 * Removes this project's mcp-callback forwarder (hop 1) when the session ends.
 * Hop 2 is a process inside the session container and dies with it, so no
 * separate teardown is needed for it.
 */
export function stopSessionMcpCallback(context: RuntimeContext, io: RuntimeIO): void {
  const projectId = projectHash(context.projectRoot);
  const port = mcpOAuthCallbackPort(context.projectRoot);
  removeValidatedIngressForwarders(context, io, projectId, [
    ingressForwarderName(projectId, MCP_CALLBACK_PURPOSE, String(port)),
  ]);
}
