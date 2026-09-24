import { expect, test, vi } from "vitest";
import { withRebindBudgetIO } from "./control-plane-rebind-budget.ts";
import { wasRefusedBeforeSpawn } from "./io-refusal.ts";
import type { RuntimeIO } from "./types.ts";

const state = vi.hoisted(() => ({ transaction: undefined as unknown }));
vi.mock("./control-plane-rebind.ts", () => ({ readControlPlaneRebindTransaction: () => state.transaction }));

test("explicit retry can observe an exhausted transaction but cannot mutate before its new allowance is durable", () => {
  const allowance = { number: 0, exhausted: true, deadlineAt: new Date(Date.now() - 1).toISOString(), lastObservedAt: new Date().toISOString() };
  state.transaction = { transactionId: "a".repeat(64), phase: "prepared", recovery: { allowance } };
  const capture = vi.fn(() => ({ status: 0, stdout: "[]", stderr: "" }));
  const run = vi.fn(() => 0);
  const io = withRebindBudgetIO({ capture, run } as unknown as RuntimeIO, "/state",
    { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" }, () => {}, true);
  expect(io.capture("docker", ["container", "inspect", "exact"]).status).toBe(0);
  expect(() => io.run("docker", ["compose", "up"])).toThrow("allowance to be durable");
  expect(() => io.capture("docker", ["create", "image"])).toThrow("allowance to be durable");
  expect(run).not.toHaveBeenCalled();
  expect(capture).toHaveBeenCalledOnce();
  allowance.number = 1; allowance.exhausted = false; allowance.deadlineAt = new Date(Date.now() + 120_000).toISOString();
  expect(io.run("docker", ["compose", "up"])).toBe(0);
  expect(run).toHaveBeenCalledOnce();
});

// A Docker call that *finishes* after the allowance expires was never
// authorized: the wrapper re-reads the persisted allowance after the call
// returns, so an operation that outlived its budget cannot report success to
// the caller that would act on it.
test("no docker call outlives the allowance, and one that finishes after it expires is refused", () => {
  const allowance = { number: 0, exhausted: false, deadlineAt: new Date(Date.now() + 5_000).toISOString(), lastObservedAt: new Date().toISOString(), startedAt: new Date().toISOString(), creations: 0 };
  state.transaction = { transactionId: "b".repeat(64), phase: "control-selected", recovery: { allowance } };
  const observed: Array<number | undefined> = [];
  const expire = (_c: string, _a: string[], options: { timeout?: number } = {}) => {
    observed.push(options.timeout);
    // The call itself runs past the deadline it was clamped to.
    allowance.deadlineAt = new Date(Date.now() - 1).toISOString();
    return { status: 0, stdout: "", stderr: "" };
  };
  const io = withRebindBudgetIO({ capture: expire, run: expire } as unknown as RuntimeIO, "/state",
    { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" }, () => {});

  expect(() => io.capture("docker", ["container", "inspect", "exact"], { timeout: 600_000 })).toThrow(/allowance ended/);
  allowance.deadlineAt = new Date(Date.now() + 5_000).toISOString();
  expect(() => io.run("docker", ["compose", "up"], { timeout: 600_000 })).toThrow(/allowance ended/);

  // The clamp is an inequality, not a restatement of the Math.min: each call
  // was given less than it asked for, and no more than the allowance left.
  expect(observed).toHaveLength(2);
  for (const timeout of observed) {
    expect(timeout).toBeLessThan(600_000);
    expect(timeout).toBeLessThanOrEqual(5_000);
  }
});

test("a rebind refusal before delegating is marked as never spawned; one after the call is not", () => {
  const allowance = { number: 0, exhausted: false, deadlineAt: new Date(Date.now() + 5_000).toISOString(), lastObservedAt: new Date().toISOString() };
  state.transaction = { transactionId: "c".repeat(64), phase: "prepared", recovery: { allowance } };
  let authorized = false;
  const capture = vi.fn(() => { allowance.deadlineAt = new Date(Date.now() - 1).toISOString(); return { status: 0, stdout: "", stderr: "" }; });
  const io = withRebindBudgetIO({ capture, run: vi.fn(() => 0) } as unknown as RuntimeIO, "/state",
    { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" }, () => { if (!authorized) throw new Error("lock lost"); });
  const refusal = (call: () => unknown): unknown => { try { call(); } catch (error) { return error; } throw new Error("expected a refusal"); };
  expect(wasRefusedBeforeSpawn(refusal(() => io.capture("docker", ["run", "image"])))).toBe(true);
  expect(wasRefusedBeforeSpawn(refusal(() => io.run("docker", ["compose", "up"])))).toBe(true);
  expect(capture).not.toHaveBeenCalled();
  authorized = true;
  expect(wasRefusedBeforeSpawn(refusal(() => io.capture("docker", ["run", "image"])))).toBe(false);
  expect(capture).toHaveBeenCalledOnce();
});
