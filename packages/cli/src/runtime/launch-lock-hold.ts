// How long one launch may hold the project lifecycle lock in one continuous
// span, and how that span is split between startup and admission.
//
// Another command waits `PROJECT_LIFECYCLE_LOCK_RETRY_WINDOW_MS` (60 s) for the
// lock before it gives up. A launch holds the lock from the moment it is taken
// (by startup, when startup hands it to admission; otherwise by the launch
// frame) until the session entry has handed off to the agent. That one span is
// planned against `LAUNCH_LOCK_HOLD_BUDGET_MS`:
//
//   startup span (handoff only)  <= LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS
//   running proof                <= RUNNING_PROOF_TIMEOUT_MS
//   callback setup               <= SESSION_CALLBACK_SETUP_BUDGET_MS
//   entry-handoff wait           ends at the hold deadline at the latest
//
// The remaining 10 s of the 60 s window is the allowance for the short daemon
// round-trips between those steps (inspect, create, start, the session-file
// write), which carry no timeout of their own. The whole-chain arithmetic is
// pinned by a unit test in `sessions.test.ts`. This module imports nothing, so
// startup, the launch frame, the driver, and the callback setup can all read it.

/** The planned bound on one continuous launch hold of the lifecycle lock. */
export const LAUNCH_LOCK_HOLD_BUDGET_MS = 50_000;

/**
 * The longest admission waits for a started session container to be proved
 * running (see the driver's running proof).
 */
export const RUNNING_PROOF_TIMEOUT_MS = 30_000;

/**
 * The whole per-session MCP OAuth callback setup: the forwarder port search,
 * the in-session bridge, and the host path probe. Every Docker call in it is
 * cut off at the time left, and the probe stops retrying at the deadline.
 */
export const SESSION_CALLBACK_SETUP_BUDGET_MS = 12_000;

/**
 * The longest startup may already have held the lock when it hands the lock
 * to admission (sub-second launch plan Task 3). Past it, startup releases the
 * lock and admission takes its own, so admission's own bounded steps still
 * fit the budget.
 */
export const LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS =
  LAUNCH_LOCK_HOLD_BUDGET_MS - RUNNING_PROOF_TIMEOUT_MS - SESSION_CALLBACK_SETUP_BUDGET_MS;

/**
 * How long a launch that has just released a long-held lock waits before it
 * takes the lock again. A waiting command retries every 200 ms
 * (`PROJECT_LIFECYCLE_LOCK_RETRY_DELAY_MS`), so this gap gives every waiter at
 * least one try; without it the releasing launch, which retries at once, wins
 * the lock back and the waiter's one-minute clock keeps running.
 */
export const LIFECYCLE_LOCK_WAITER_YIELD_MS = 450;

/** Whether a lock taken at `acquiredAtMs` may still be handed to admission at `nowMs`. */
export function launchHandoffSpanFits(acquiredAtMs: number, nowMs: number): boolean {
  const elapsed = nowMs - acquiredAtMs;
  return Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= LAUNCH_HANDOFF_STARTUP_SPAN_MAX_MS;
}

/** The monotonic time by which a hold that started at `acquiredAtMs` must end. */
export function launchLockHoldDeadline(acquiredAtMs: number): number {
  return acquiredAtMs + LAUNCH_LOCK_HOLD_BUDGET_MS;
}
