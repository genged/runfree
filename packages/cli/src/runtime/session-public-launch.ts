// The public foreground launch, expressed as a per-session admission.
//
// This is the composition `runfree claude|codex|pi` selects post-cutover: it
// replaced the legacy `docker exec zsh -c "$RUNFREE_AGENT_COMMAND"` into the
// shared Compose agent, which the D23 cutover removed, and it is now the launch
// path for every public command (alongside `launchBuiltin` and the resume
// orchestrator). It was internal until the cutover — exposing it earlier would
// have activated sessions while the proxy still keyed approvals to the whole
// runtime, giving several containers one approval subject — which per-session
// source-IP identity now resolves.
//
// The composition is deliberately thin. Everything security-relevant lives in
// the driver: preflight threads the project's *real* configured command, so a
// customized command is refused with exact guidance before any Docker effect
// (cutover decision D-3), and recorded legacy defaults launch normally because
// the config layer normalizes them (D-1). What this module owns is only the
// public-facing frame: builtin-name validation, the lifecycle lock with a
// bounded retry, and the outcome-to-exit-status mapping.

import { CliError } from "../errors.ts";
import {
  createInternalSessionAdmissionDriver,
  type SessionRunningHook,
} from "./session-admission-driver.ts";
import {
  preparedRuntimeContext,
  StalePreparedRuntimeError,
  type PreparedRuntime,
} from "./prepared-runtime.ts";
import {
  BUILTIN_SESSION_ADMISSION_PROBE_AGENTS,
  type SessionAdmissionProbeAgent,
} from "./session-admission-probe.ts";
import type { SessionContainerForegroundSpawner } from "./session-container-start.ts";
import {
  createSessionLockManager,
  projectLifecycleLockPath,
  tryAcquireProjectLifecycleLockWithRetry,
} from "./sessions.ts";
import type { RuntimeIO } from "./types.ts";

export type SessionPublicLaunchInput = Readonly<{
  preparedRuntime: PreparedRuntime;
  io: RuntimeIO;
  /** The agent name the command line resolved; must be a built-in. */
  agentName: string;
  foregroundSpawner?: SessionContainerForegroundSpawner;
  /** Fired once the session is running; `mcp auth` uses it for callback setup. */
  onSessionRunning?: SessionRunningHook;
  /** Trusted startup finalizer retry used only for valid concurrent drift. */
  reprepare?: () => Promise<PreparedRuntime>;
}>;

/**
 * Refuses an agent name that is not a launchable built-in.
 *
 * Exported so the public launch path can refuse *before* it starts a runtime.
 * The name is fully resolved from project config, and this is a membership test
 * against a frozen three-element list — it depends on nothing Docker produces.
 * Until 2026-09-21 the only call was the one below, inside the launch, which
 * runs after `startRuntime`: `runfree <custom-agent>` stood up the entire
 * runtime and only then reported that custom agents are unsupported. The live
 * suite measured that refusal at 5.5 s idle and 18.1 s under load.
 *
 * The call below stays. This is a gate moved earlier, not moved: the launch
 * entry must still refuse on its own, so no future caller can reach
 * `launchBuiltin` with an unchecked name.
 */
export function assertBuiltinLaunchAgent(agentName: string): SessionAdmissionProbeAgent {
  const match = BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.find((candidate) => candidate === agentName);
  if (!match) {
    // Cutover decision D-3 (2026-08-17): custom agents end as managed
    // launches; there is no fallback container to run them in. The refusal
    // names the way out rather than only the rule.
    throw new CliError(
      `per-session launch supports only the built-in agents `
      + `(${BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.join(", ")}), not ${agentName || "<empty>"}. `
      + `\`runfree shell\` remains available for custom tools.`,
    );
  }
  return match;
}

/**
 * Launches one built-in agent as a new validated lifecycle session and holds
 * it in the foreground until the agent process ends.
 *
 * The driver owns the whole admission sequence — stopped create, proof,
 * paired provisioning, direct launch, running proof, activation, lease
 * renewal, and revocation on every exit path — plus the outcome-aware host
 * session evidence that makes a killed client recoverable. A non-numeric exit
 * (signal death) maps to 1, matching the resume orchestrator.
 */
export async function launchConfiguredAgentThroughAdmission(
  input: SessionPublicLaunchInput,
): Promise<number> {
  const agent = assertBuiltinLaunchAgent(input.agentName);
  return await withOutcomeLine(
    `${input.agentName} did not start`,
    () => withSessionLaunchFrame(input, (driver) => driver.launchBuiltin(agent)),
  );
}

// Outcome-first failure text (contract D5): a refusal anywhere in the launch
// ladder ends with what did not happen in the user's nouns. Only refusals are
// annotated; unexpected errors keep their own rendering.
async function withOutcomeLine(outcome: string, launch: () => Promise<number>): Promise<number> {
  try {
    return await launch();
  } catch (error) {
    if (error instanceof CliError && !error.message.endsWith(outcome)) {
      throw Object.assign(new CliError(`${error.message}\n${outcome}`, error.status), { cause: error });
    }
    throw error;
  }
}

export type SessionPublicShellInput = Readonly<{
  preparedRuntime: PreparedRuntime;
  io: RuntimeIO;
  foregroundSpawner?: SessionContainerForegroundSpawner;
  onSessionRunning?: SessionRunningHook;
  reprepare?: () => Promise<PreparedRuntime>;
}>;

/**
 * Launches the agent image's interactive login shell as a session.
 *
 * The composition `runfree shell` selects at the cutover: same frame as an
 * agent launch, with the driver's shell kind as the first process. No agent
 * name and no configured command are involved — the shell is the escape hatch
 * the custom-command refusal points at, so nothing project-configurable may
 * gate it.
 */
export async function launchShellThroughAdmission(input: SessionPublicShellInput): Promise<number> {
  return await withOutcomeLine(
    "the shell session did not start",
    () => withSessionLaunchFrame(input, (driver) => driver.launchShell()),
  );
}

type SessionLaunchDriver = ReturnType<typeof createInternalSessionAdmissionDriver>;

async function withSessionLaunchFrame(
  input: SessionPublicShellInput,
  launch: (driver: SessionLaunchDriver) => Promise<Readonly<{ status: number | null }>>,
): Promise<number> {
  let preparedRuntime = input.preparedRuntime;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const context = preparedRuntimeContext(preparedRuntime);
    // Bounded lock acquisition avoids random refusal behind another process's
    // short critical section. A lock held for the complete window is a real
    // lifecycle operation, so this launch defers.
    const initialLifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(context);
    if (!initialLifecycleLock) {
      throw new CliError(
        `per-session launch deferred because a runtime lifecycle change is in progress (lock: ${projectLifecycleLockPath(context)})`,
      );
    }
    const sessionLockManager = createSessionLockManager(context, initialLifecycleLock);
    try {
      const driver = createInternalSessionAdmissionDriver({
        preparedRuntime,
        sessionLockManager,
        io: input.io,
        ...(input.foregroundSpawner ? { foregroundSpawner: input.foregroundSpawner } : {}),
        ...(input.onSessionRunning ? { onSessionRunning: input.onSessionRunning } : {}),
      });
      const outcome = await launch(driver);
      return typeof outcome.status === "number" ? outcome.status : 1;
    } catch (error) {
      if (!(error instanceof StalePreparedRuntimeError)) throw error;
      if (attempt !== 0 || !input.reprepare) {
        throw new CliError(
          "per-session launch could not converge because runtime lifecycle state changed repeatedly; retry the command",
        );
      }
    } finally {
      sessionLockManager.close();
    }
    preparedRuntime = await input.reprepare();
  }
  throw new Error("per-session launch preparation retry bound was exceeded");
}
