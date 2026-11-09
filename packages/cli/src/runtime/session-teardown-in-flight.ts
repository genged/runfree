// The one answer to "is this record terminal cleanup rather than a session?"
//
// Two writers mark a record terminal, and they mark it in two places:
//
//   - `destroy`, `rebuild`, and the control-plane rebind coordinator transition
//     the durable record itself to `state: "revoking"` before any Docker
//     effect, so an interrupted teardown is inert from its first step;
//   - the per-session teardown (`session-file-teardown.ts`), the reconcile, and
//     the pending-admission reclaim leave the record exactly as it was and
//     write the `terminal: "revoking"` host status stamp beside it instead.
//
// Either mark alone means the same thing: the session has ended, its address
// is still reserved, and some later pass must finish the teardown. A consumer
// that reads only one of them splits that fact in two — `runfree up` refused
// over a record that `runfree sessions` did not list, with a remedy that could
// not work — so every consumer reads both through this predicate.

import type { SessionContainerRecordV2 } from "./session-containers.ts";
import type { SessionHostStatusV1 } from "./session-host-status.ts";

/**
 * Whether a session's teardown has begun and not finished.
 *
 * True for a record in `revoking` state, for a record whose host status stamp
 * is terminal, and for both at once. Pure: the caller reads the stamp
 * (`readSessionHostStatus` never throws; an unreadable stamp is absent).
 */
export function sessionTeardownInFlight(
  record: Pick<SessionContainerRecordV2, "state">,
  stamp: Pick<SessionHostStatusV1, "terminal"> | undefined,
): boolean {
  return record.state === "revoking" || stamp?.terminal === "revoking";
}
