import { CliError } from "../errors.ts";
import { projectHash } from "../project-identity.ts";
import { composeProjectName } from "../runtime/env.ts";
import { readSessionHostStatus } from "../runtime/session-host-status.ts";
import { classifySessionRecordLiveness } from "../runtime/session-record-liveness.ts";
import { peekSessionContainerRecordsV2 } from "../runtime/session-containers.ts";
import {
  sessionWarningLine,
  tryAcquireProjectLifecycleLockWithRetry,
} from "../runtime/sessions.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { migrateControlApprovalRecord } from "./approval-migration.ts";

// A quiesce refusal names a domain condition (another lifecycle or control
// change is in progress, live sessions are running) with the operator's next
// step, so it is a CliError: rendered as a refusal, never as a stack trace.
export class ProjectQuiesceError extends CliError {
  constructor(message: string, options?: ErrorOptions) {
    super(message);
    if (options?.cause !== undefined) this.cause = options.cause;
    this.name = "ProjectQuiesceError";
  }
}

function refuseLivePerSessionAgents(context: RuntimeContext, allowLiveSessions: boolean): void {
  const projectId = projectHash(context.projectRoot);
  const peek = peekSessionContainerRecordsV2(context.project.paths.stateDir, {
    projectId,
    composeProject: composeProjectName(context.projectRoot),
  });
  // Unreadable lifecycle state is refused before any trusted project read even
  // for the live-capable mutations: an opt-in widens which sessions may run
  // beside the transaction, not what corrupt state the transaction tolerates.
  if (peek.unreadable > 0) {
    throw new ProjectQuiesceError("control change deferred because session-container lifecycle state is unreadable");
  }
  if (allowLiveSessions) return;
  const live = peek.records.filter((record) => record.state !== "revoking"
    && classifySessionRecordLiveness(record, {
      nowEpochMs: Date.now(),
      env: context.env,
      stamp: readSessionHostStatus(context.project.paths.stateDir, record.sessionId),
    }).kind === "live");
  if (live.length > 0) {
    const details = live.map((record) => `${sessionWarningLine({
      command: record.command,
      containerTty: "<session-container>",
      name: record.displayName,
      processCount: 1,
      sessionId: record.sessionId,
    })}, host pid ${record.hostPid}`);
    throw new ProjectQuiesceError(
      `control change deferred because ${live.length} active per-session agent${live.length === 1 ? " is" : "s are"} running:\n${
        details.map((detail) => `  ${detail}`).join("\n")
      }\nstop the named session${live.length === 1 ? "" : "s"}, then retry the control change`,
    );
  }
}

/**
 * Serializes a control transaction against runtime lifecycle work under the
 * project lifecycle lock. Session containers are never paused, inspected for
 * pause state, or resumed (A2 decision, 2026-09-01): the typed desired-policy
 * mutations carry their own agent-drift guarantee through the capture →
 * approved-base → atomic-write → re-read → content-addressed-approve chain,
 * so they may opt in to running beside live sessions. Every other caller —
 * lifecycle rebuild/destroy and the startup capture — keeps the default
 * refusal of live per-session agents.
 */
export async function withQuiescedProject<T>(
  context: RuntimeContext,
  _io: RuntimeIO,
  action: () => T | Promise<T>,
  options: {
    allowLiveSessions?: boolean;
    lifecycleLockRetry?: { attempts?: number; delayMs?: number };
  } = {},
): Promise<T> {
  const lock = await tryAcquireProjectLifecycleLockWithRetry(context, options.lifecycleLockRetry);
  if (!lock) throw new ProjectQuiesceError("another Runfree runtime lifecycle or control change is in progress");
  try {
    refuseLivePerSessionAgents(context, options.allowLiveSessions === true);
    // The one funnel every approvals writer crosses. Migration needs the
    // lifecycle lock and must not be a side effect of reading, so this prelude
    // is where it belongs: reaching any writer beyond this point implies the
    // record is already on the current schema.
    migrateControlApprovalRecord(context.projectRoot, context.project);
    return await action();
  } finally {
    lock.release();
  }
}
