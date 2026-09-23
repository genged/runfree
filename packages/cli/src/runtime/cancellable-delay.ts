/**
 * A delay that can be woken early.
 *
 * `setTimeout` cannot be observed while it is pending, so a loop sleeping on one
 * cannot notice that it should stop until the timer expires. Where something
 * waits on that loop to finish, the wait inherits the full remaining delay.
 *
 * That is not merely slow in the session lease-renewal loop: revocation waits
 * for the loop, so an uncancellable sleep leaves a session holding proxy
 * authority for up to a full renewal interval after its attached process has
 * exited.
 */
export type CancellableDelay = Readonly<{
  /** Resolves when the delay expires or `cancel` is called, whichever is first. */
  elapsed: Promise<void>;
  /** Wakes the delay immediately. Safe to call repeatedly, and after expiry. */
  cancel: () => void;
}>;

export function cancellableDelay(milliseconds: number): CancellableDelay {
  let cancel = (): void => {};
  const elapsed = new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    cancel = () => {
      clearTimeout(timer);
      resolve();
    };
  });
  return Object.freeze({ elapsed, cancel: () => cancel() });
}
