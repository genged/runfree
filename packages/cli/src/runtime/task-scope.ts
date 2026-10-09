/**
 * A scope that always lets every started branch settle before its caller
 * moves on.
 *
 * Session admission runs sibling Docker calls that must not outlive cleanup
 * or the lifecycle lock: if one branch fails while another is still creating
 * a container, releasing the lock or tearing down before that sibling
 * finishes would let it keep creating resources with no lock held and no one
 * watching. A scope makes that impossible structurally — `settleAll` only
 * returns once every branch it has started, including branches started while
 * it was already settling, has finished one way or the other.
 *
 * The scope has no timer of its own and never gives up waiting on a branch.
 * Each branch is responsible for its own bound (a per-call timeout); the
 * scope only guarantees that whatever that branch does, the caller learns
 * about it before `settleAll` returns.
 */
export type ScopedTask<T> = Readonly<{
  label: string;
  /** Resolves or rejects exactly as the started branch does. */
  result(): Promise<T>;
}>;

export type TaskScope = Readonly<{
  /** Starts `run` synchronously and tracks it for the next `settleAll`. */
  start<T>(label: string, run: () => Promise<T>): ScopedTask<T>;
  /**
   * Awaits every started branch, including ones started during this call,
   * until none remain. Never rejects for a branch's own failure. Once
   * settled, asserts the caller still holds the authority it started under;
   * a throw from that assertion propagates.
   */
  settleAll(): Promise<void>;
  /** The number of branches started since the last full settlement. */
  pending(): number;
}>;

export function createTaskScope(input: Readonly<{ assertHeld: () => void }>): TaskScope {
  const { assertHeld } = input;
  const settling: Array<Promise<void>> = [];
  let settled = false;

  function start<T>(label: string, run: () => Promise<T>): ScopedTask<T> {
    if (settled) {
      throw new Error(`task scope already settled: refusing to start "${label}"`);
    }
    let promise: Promise<T>;
    try {
      promise = run();
    } catch (error) {
      promise = Promise.reject(error);
    }
    // Swallow the branch's own outcome here so a caller who never reads
    // `result()` can never produce an unhandled rejection; `result()` still
    // observes the branch's real outcome from `promise` itself.
    settling.push(promise.then(() => undefined, () => undefined));
    return Object.freeze({ label, result: () => promise });
  }

  async function settleAll(): Promise<void> {
    while (settling.length > 0) {
      await Promise.all(settling.splice(0));
    }
    settled = true;
    assertHeld();
  }

  function pending(): number {
    return settling.length;
  }

  return Object.freeze({ start, settleAll, pending });
}
