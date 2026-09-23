import { composeProjectName } from "./env.ts";
import { createRuntimeDocker } from "./docker.ts";
import {
  buildResumeLaunchPlan,
  classifyRecoveryItemLive,
  liveClaudeSessionBlocksPicker,
  runWithRecoveryClaim,
  sessionContainerRecoveryLiveInputs,
  type RecoveryItem,
  type RecoveryLiveInputs,
} from "./recovery.ts";
import {
  createInternalSessionAdmissionDriver,
  type SessionAdmissionLaunchOptions,
} from "./session-admission-driver.ts";
import { BUILTIN_SESSION_ADMISSION_PROBE_AGENTS, type SessionAdmissionProbeAgent } from "./session-admission-probe.ts";
import type { SessionContainerForegroundSpawner } from "./session-container-start.ts";
import {
  preparedRuntimeContext,
  StalePreparedRuntimeError,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import {
  createSessionLockManager,
  projectLifecycleLockPath,
  tryAcquireProjectLifecycleLockWithRetry,
} from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

export type SessionAdmissionResumeResult = Readonly<{
  /** Exit status of the resumed agent process; a signal death maps to 1. */
  status: number;
  /** Whether the claimed recovery evidence was consumed (status 0 and fingerprint still matching). */
  consumed: boolean;
}>;

export type SessionAdmissionResumeInput = Readonly<{
  preparedRuntime: PreparedRuntime;
  io: RuntimeIO;
  item: RecoveryItem;
  foregroundSpawner?: SessionContainerForegroundSpawner;
  reprepare?: () => Promise<PreparedRuntime>;
}>;

function builtinProbeAgent(agent: string): SessionAdmissionProbeAgent {
  const match = BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.find((candidate) => candidate === agent);
  if (!match) throw new Error(`per-session resume supports only built-in agents, not ${agent || "<empty>"}`);
  return match;
}

/**
 * Resumes one interrupted conversation as a new validated lifecycle session
 * through the internal admission path.
 *
 * The old container is never a party to this: recovery evidence and persisted
 * Claude/Codex state select *what* to resume, and admission creates a fresh
 * session container whose exact typed launch argv is the recovery spec's
 * resume argv. Liveness is revalidated against the lifecycle registry and any
 * explicit pre-cutover recovery evidence before the claim. The claim serializes every
 * representation of the same project-agent scope, and evidence is consumed
 * only after a status-0 completion with a matching fingerprint. A failed
 * attempt leaves the original evidence retryable; the launch's own transient
 * session evidence is removed rather than minted into a second item.
 *
 * Public `runfree resume` reaches this after the per-session cutover. The
 * launch remains a fresh validated container and retains the source-IP and
 * session-keyed authorization contract.
 */
export async function resumeInterruptedSessionThroughAdmission(
  input: SessionAdmissionResumeInput,
): Promise<SessionAdmissionResumeResult> {
  const { io, item } = input;
  const agent = builtinProbeAgent(item.agent);
  let preparedRuntime = input.preparedRuntime;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const context = preparedRuntimeContext(preparedRuntime);
    const classified = validateResumeTarget(context, io, item, { ignoreClaim: false });
    try {
      const result = await runWithRecoveryClaim(context, classified, async () => {
        // Match fresh public launches: an attached session can hold this lock
        // for one brief renewal section, which must not make resume fail.
        const initialLifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(context);
        if (!initialLifecycleLock) {
          throw new Error(`per-session resume deferred because a runtime lifecycle change is in progress (lock: ${projectLifecycleLockPath(context)})`);
        }
        const sessionLockManager = createSessionLockManager(context, initialLifecycleLock);
        try {
          // Revalidate under both the claim and lifecycle lock. Admission uses
          // this lock too, so a concurrent fresh or resumed session cannot pass
          // between this check and container creation.
          const current = validateResumeTarget(context, io, classified, { ignoreClaim: true });
          const driver = createInternalSessionAdmissionDriver({
            preparedRuntime,
            sessionLockManager,
            io,
            ...(input.foregroundSpawner ? { foregroundSpawner: input.foregroundSpawner } : {}),
          });
          const outcome = await driver.launchBuiltin(agent, current.resume);
          return typeof outcome.status === "number" ? outcome.status : 1;
        } finally {
          sessionLockManager.close();
        }
      });
      if (!result) {
        throw new Error(`recovery item ${classified.id} changed or is already claimed`);
      }
      return Object.freeze({ status: result.status, consumed: result.consumed });
    } catch (error) {
      if (!(error instanceof StalePreparedRuntimeError)) throw error;
      if (attempt !== 0 || !input.reprepare) {
        throw new Error(
          "per-session resume could not converge because runtime lifecycle state changed repeatedly; retry the command",
        );
      }
    }
    preparedRuntime = await input.reprepare();
  }
  throw new Error("per-session resume preparation retry bound was exceeded");
}

/**
 * Classifies the item with fresh live inputs and refuses everything the
 * per-session resume path must not launch: an item that is not provably
 * interrupted, a custom shell resume command, and an imprecise Claude picker
 * while another Claude session may be live. Returns the re-read item together
 * with the typed resume request derived from it.
 */
function validateResumeTarget(
  context: RuntimeContext,
  io: RuntimeIO,
  item: RecoveryItem,
  options: Readonly<{ ignoreClaim: boolean }>,
): RecoveryItem & Readonly<{ resume: SessionAdmissionLaunchOptions }> {
  const docker = createRuntimeDocker(context, io);
  const project = composeProjectName(context.projectRoot);
  const live: RecoveryLiveInputs = {
    activeSessions: docker.activeAgentSessions(project),
    agentContainerId: docker.runningServiceContainerId(project, "agent"),
    sessionContainers: sessionContainerRecoveryLiveInputs(context),
  };
  const classified = classifyRecoveryItemLive(item, context, io, live, { ignoreClaim: options.ignoreClaim });
  if (classified.state !== "interrupted") {
    throw new Error(options.ignoreClaim
      ? `recovery item ${classified.id} became ${classified.state} before the resume launch`
      : `recovery item ${classified.id} is ${classified.state}; per-session resume requires proven interruption`);
  }
  const plan = buildResumeLaunchPlan(context, classified);
  if (!plan) {
    throw new Error(`resume is not supported for ${classified.agent} with this project's configured command`);
  }
  if (plan.shellCommand !== undefined) {
    // A project resumeCommand is shell syntax. It stays on the shell-evaluated
    // legacy path and must never be split into direct-launch authority.
    throw new Error(`per-session resume supports only the built-in ${classified.agent} resume argv, not a custom resume command`);
  }
  // Stale records do not block here: this launch runs the driver preflight
  // under the same lifecycle lock, which reclaims that residue — container
  // included — before the picker's claude ever starts.
  if (classified.agent === "claude" && plan.precision === "picker"
    && liveClaudeSessionBlocksPicker(context, live, { staleRecordsReclaimedBeforeLaunch: true })) {
    throw new Error("cannot open the Claude resume picker while another Claude session may be active in this project");
  }
  return Object.freeze({
    ...classified,
    resume: {
      resume: {
        ...(plan.precision === "exact" && classified.conversationId !== undefined
          ? { conversationId: classified.conversationId }
          : {}),
      },
    },
  });
}
