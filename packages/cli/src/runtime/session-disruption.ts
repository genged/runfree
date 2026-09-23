import { listSessionContainerRecordsV2, type SessionContainerProjectIdentity } from "./session-containers.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { readSessionHostStatus } from "./session-host-status.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";

/** Explicit operations only. Candidate containment and replacement use their own ownership. */
export function assertSessionDisruptionAuthorized(input: {
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  lifecycleLock: ProjectLifecycleLock;
  operation: "stop" | "runtime reload-policy";
  force?: boolean;
  env?: NodeJS.ProcessEnv;
}): void {
  input.lifecycleLock.assertHeld();
  const records = listSessionContainerRecordsV2(input.stateDir, input.expectedProject);
  // Nothing writes an admission journal. What says "a session lifecycle
  // transaction is in flight" is the host status stamp its owner wrote: a
  // record stamped terminal is mid-teardown, and stopping the runtime
  // underneath that teardown is exactly the interruption this gate refuses —
  // whether or not its owner still answers.
  const revoking = records.filter((record) =>
    readSessionHostStatus(input.stateDir, record.sessionId)?.terminal === "revoking");
  const rebind = readControlPlaneRebindTransaction(input.stateDir, input.expectedProject);
  const participants = [...records, ...(rebind?.oldRecords ?? [])];
  const live = [...new Set([
    ...participants.filter((record) => sessionRecordOwnerLiveness(record, input.env) !== "dead").map((record) => record.sessionId),
    ...revoking.map((record) => record.sessionId),
  ])];
  input.lifecycleLock.assertHeld();
  if (!input.force && (live.length || rebind)) {
    throw new Error(`runfree ${input.operation} refuses disruption while sessions or a lifecycle transaction remain: `
      + `${live.join(", ") || "pending transaction"}; inspect with \`runfree sessions\`; wait for completion, `
      + `or run runfree ${input.operation} --force to authorize interrupted network access`);
  }
}
