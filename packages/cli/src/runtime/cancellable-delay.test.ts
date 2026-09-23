import { describe, expect, test } from "vitest";

import { cancellableDelay } from "./cancellable-delay.ts";

describe("cancellable delay", () => {
  test("wakes immediately when cancelled, instead of serving out the delay", async () => {
    // The property the session lease-renewal loop depends on. A bare
    // `setTimeout` here left a session holding proxy authority for up to a full
    // renewal interval after its attached process had exited, because
    // revocation waits on that loop.
    const delay = cancellableDelay(60_000);
    const startedAt = Date.now();
    delay.cancel();
    await delay.elapsed;
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  test("expires on its own when nobody cancels", async () => {
    const delay = cancellableDelay(1);
    await expect(delay.elapsed).resolves.toBeUndefined();
  });

  test("tolerates cancelling more than once, and after it has expired", async () => {
    // The caller cancels from a `finally` that also runs on the path where the
    // delay already elapsed, so a second cancel must be harmless.
    const delay = cancellableDelay(1);
    await delay.elapsed;
    expect(() => {
      delay.cancel();
      delay.cancel();
    }).not.toThrow();
  });
});
