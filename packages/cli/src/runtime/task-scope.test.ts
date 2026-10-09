import { describe, expect, test } from "vitest";

import { createTaskScope } from "./task-scope.ts";

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function tick(milliseconds: number): Promise<"tick"> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds)).then(() => "tick");
}

describe("task scope", () => {
  test("settleAll does not resolve while a slow task is pending, even when a sibling already rejected", async () => {
    const scope = createTaskScope({ assertHeld: () => {} });
    const slow = deferred<void>();
    scope.start("slow", () => slow.promise);
    const fast = scope.start("fast", () => Promise.reject(new Error("boom")));

    const settling = scope.settleAll();
    const raced = await Promise.race([settling.then(() => "settled" as const), tick(20)]);
    expect(raced).toBe("tick");

    slow.resolve();
    await settling;
    await expect(fast.result()).rejects.toThrow("boom");
  });

  test("result() rejects with the task's own error", async () => {
    const scope = createTaskScope({ assertHeld: () => {} });
    const error = new Error("boom");
    const task = scope.start("x", () => Promise.reject(error));
    await expect(task.result()).rejects.toBe(error);
    await scope.settleAll();
  });

  test("a rejected task whose result() is never read produces no unhandledRejection", async () => {
    const seen: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => {
      seen.push(reason);
    };
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      const scope = createTaskScope({ assertHeld: () => {} });
      scope.start("x", () => Promise.reject(new Error("boom")));
      await scope.settleAll();
      // Give the microtask/event-loop queue a chance to surface any
      // unhandled rejection before asserting none occurred.
      await new Promise((resolve) => setImmediate(resolve));
      expect(seen).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
    }
  });

  test("assertHeld runs after settlement, and a throw from it propagates", async () => {
    const calls: string[] = [];
    const scope = createTaskScope({
      assertHeld: () => {
        calls.push("assertHeld");
        throw new Error("lock lost");
      },
    });
    scope.start("x", async () => {
      calls.push("task");
    });
    await expect(scope.settleAll()).rejects.toThrow("lock lost");
    expect(calls).toEqual(["task", "assertHeld"]);
  });

  test("start calls run synchronously, so an effect is never deferred past the caller's intent flag", async () => {
    const scope = createTaskScope({ assertHeld: () => {} });
    let calledSynchronously = false;
    const task = scope.start("x", async () => {
      calledSynchronously = true;
      return 1;
    });
    expect(calledSynchronously).toBe(true);
    await expect(task.result()).resolves.toBe(1);
    await scope.settleAll();
  });

  test("start after assertHeld has thrown is refused", async () => {
    const scope = createTaskScope({
      assertHeld: () => {
        throw new Error("lock lost");
      },
    });
    await expect(scope.settleAll()).rejects.toThrow("lock lost");
    expect(() => scope.start("late", async () => undefined)).toThrow();
  });

  test("pending() counts", async () => {
    const scope = createTaskScope({ assertHeld: () => {} });
    expect(scope.pending()).toBe(0);

    const first = deferred<void>();
    scope.start("a", () => first.promise);
    expect(scope.pending()).toBe(1);

    const second = deferred<void>();
    scope.start("b", () => second.promise);
    expect(scope.pending()).toBe(2);

    first.resolve();
    second.resolve();
    await scope.settleAll();
    expect(scope.pending()).toBe(0);
  });
});
