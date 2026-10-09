/**
 * A scope that always lets every started branch settle before its caller
 * moves on — safe to call from more than one concurrent caller, and
 * reusable across more than one settlement.
 *
 * Session admission runs sibling Docker calls that must not outlive cleanup
 * or the lifecycle lock: if one branch fails while another is still creating
 * a container, releasing the lock or tearing down before that sibling
 * finishes would let it keep creating resources with no lock held and no one
 * watching. A scope makes that impossible structurally — `settleAll` only
 * returns once nothing started through the scope is still in flight,
 * including branches started while it was already waiting. Waiting is
 * driven by an in-flight count rather than by draining a list, so more than
 * one concurrent `settleAll` call observes the same zero: neither can
 * return while the other still has branches outstanding.
 *
 * The scope has no timer of its own and never gives up waiting on a branch.
 * Each branch is responsible for its own bound (a per-call timeout); the
 * scope only guarantees that whatever that branch does, every waiting
 * `settleAll` call learns about it before any of them returns.
 *
 * The scope stays open across a clean settlement: `start` keeps working
 * afterward, and the next `settleAll` still waits for whatever is started
 * after it. Only a throw from `assertHeld` closes it — once the caller's
 * authority is gone, starting another branch under it would be meaningless,
 * so `start` refuses from then on.
 */
export type ScopedTask<T> = Readonly<{
  label: string;
  /** Resolves or rejects exactly as the started branch does. */
  result(): Promise<T>;
}>;

export type TaskScope = Readonly<{
  /** Starts `run` synchronously and tracks it for every pending `settleAll`. */
  start<T>(label: string, run: () => Promise<T>): ScopedTask<T>;
  /**
   * Waits until nothing started through the scope is in flight, including
   * branches started while this call was already waiting. Never rejects for
   * a branch's own failure. Once nothing is in flight, asserts the caller
   * still holds the authority it started under; a throw from that assertion
   * propagates and permanently refuses further `start` calls. Safe to call
   * concurrently — every caller waits for the same zero.
   */
  settleAll(): Promise<void>;
  /** How many started branches are currently in flight. */
  pending(): number;
}>;

export function createTaskScope(input: Readonly<{ assertHeld: () => void }>): TaskScope {
  const { assertHeld } = input;
  let inFlight = 0;
  let refused = false;
  let waiters: Array<() => void> = [];

  function wakeWaiters(): void {
    const toWake = waiters;
    waiters = [];
    for (const wake of toWake) wake();
  }

  function absorb(): void {
    inFlight -= 1;
    wakeWaiters();
  }

  function start<T>(label: string, run: () => Promise<T>): ScopedTask<T> {
    if (refused) {
      throw new Error(`task scope refused: cannot start "${label}" after assertHeld failed`);
    }
    let promise: Promise<T>;
    try {
      promise = run();
    } catch (error) {
      promise = Promise.reject(error);
    }
    inFlight += 1;
    // Attaching a rejection handler here, even though it only does
    // bookkeeping, is also what keeps an unread rejected `result()` from
    // ever surfacing as an unhandled rejection.
    promise.then(absorb, absorb);
    return Object.freeze({ label, result: () => promise });
  }

  async function settleAll(): Promise<void> {
    while (inFlight > 0) {
      await new Promise<void>((resolve) => {
        waiters.push(resolve);
      });
    }
    try {
      assertHeld();
    } catch (error) {
      refused = true;
      throw error;
    }
  }

  function pending(): number {
    return inFlight;
  }

  return Object.freeze({ start, settleAll, pending });
}
