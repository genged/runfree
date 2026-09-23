// Which container a consumer means when it says "the agent".
//
// Post-cutover, "the agent" means one exact attached session container. A
// consumer that cannot name exactly one live registry record must not fall back
// to a pre-cutover Compose agent or choose between concurrent sessions.

import type { RuntimeDocker } from "./docker.ts";
import { peekSessionContainerRecordsV2 } from "./session-containers.ts";

export type AgentExecTarget = Readonly<{
  kind: "session";
  containerId: string;
  sessionId: string;
      /**
       * The session's fixed internal-network address. Consumers that forward
       * traffic (VNC) target this rather than a container name: sessions are
       * admitted by source IP, so the address is the identity the rest of the
       * machinery already binds.
       */
  sourceIp: string;
  running: true;
}>;

export type ResolveAgentExecTargetOptions = Readonly<{
  /**
   * Consult the per-session lifecycle registry.
   *
   * Post-cutover there is no shared agent service, and "the agent" means the
   * foreground session container. Only an `attached` record
   * whose container the daemon confirms running qualifies; a partially
   * legible registry or more than one live session refuses loudly rather
   * than picking — a consumer acting on "the" session must not guess.
   */
  sessionRegistry?: Readonly<{ stateDir: string; projectId: string }>;
}>;

/**
 * Resolves the container a consumer should act on, or `undefined` when none
 * exists in the requested state.
 */
export function resolveAgentExecTarget(
  project: string,
  docker: RuntimeDocker,
  options: ResolveAgentExecTargetOptions = {},
): AgentExecTarget | undefined {
  if (options.sessionRegistry) {
    const session = resolveSessionTarget(project, docker, options.sessionRegistry);
    if (session) return session;
  }
  return undefined;
}

function resolveSessionTarget(
  project: string,
  docker: RuntimeDocker,
  registry: Readonly<{ stateDir: string; projectId: string }>,
): AgentExecTarget | undefined {
  const peek = peekSessionContainerRecordsV2(registry.stateDir, {
    projectId: registry.projectId,
    composeProject: project,
  });
  if (peek.unreadable > 0) {
    // A partial view cannot prove which session is "the" one. Acting on the
    // readable subset could exec into the wrong session while the unreadable
    // record names the right one.
    throw new Error(
      `cannot resolve the agent container: ${peek.unreadable} session lifecycle record(s) are unreadable; `
      + `\`runfree destroy --force\` recovers an illegible registry`,
    );
  }
  const live = peek.records
    .filter((record) => record.state === "attached" && typeof record.containerId === "string")
    .filter((record) => docker.containerRunning(record.containerId as string));
  if (live.length === 0) return undefined;
  if (live.length > 1) {
    // "The agent" is ill-defined with concurrent sessions; a consumer that
    // needs one must be told to address it exactly rather than being handed
    // an arbitrary winner.
    throw new Error(
      `cannot resolve the agent container: ${live.length} sessions are live `
      + `(${live.map((record) => record.sessionId).join(", ")}); this operation needs exactly one`,
    );
  }
  const record = live[0];
  return Object.freeze({
    kind: "session" as const,
    containerId: record.containerId as string,
    sessionId: record.sessionId,
    sourceIp: record.sourceIp,
    running: true as const,
  });
}
