// Review C4, admin half: `runtime reload-policy --force` restores admission
// with no validation to reuse, so the restore runs the ephemeral helpers. It
// must hand them the unbudgeted base IO as their containment IO, and do the
// restore's own work on the budgeted IO. The runtime half (that this fence
// reaches the helpers inside the restore) is proven end to end in
// runtime.test.ts ("the reload-policy restore runs its helpers under the fence").

import { expect, test, vi } from "vitest";

import type { ActiveRuntimePlan } from "../runtime/plan.ts";
import type { ProjectLifecycleLock } from "../runtime/sessions.ts";
import type { RuntimeIO } from "../runtime/types.ts";

const restore = vi.hoisted(() => ({ calls: [] as Record<string, unknown>[] }));
vi.mock("../runtime/startup.ts", () => ({
  restoreSameProxySessionAdmission: vi.fn(async (input: Record<string, unknown>) => { restore.calls.push(input); }),
}));

const { restoreAdmissionAfterProxyRestart } = await import("./admin-core.ts");

test("the reload-policy restore gets the budgeted IO for its work and the base IO for helper containment", async () => {
  const capture = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));
  const baseIO = { capture, run: vi.fn(() => 0) } as unknown as RuntimeIO;
  const plan = { projectId: "0123456789ab" } as unknown as ActiveRuntimePlan;
  const lifecycleLock = { ownerToken: "t", assertHeld: vi.fn(), release: vi.fn() } as ProjectLifecycleLock;
  let deadline = performance.now() + 60_000;

  await restoreAdmissionAfterProxyRestart({ plan, lifecycleLock, proxyId: "p".repeat(64), deadline, baseIO });

  expect(restore.calls).toHaveLength(1);
  const input = restore.calls[0] as { io: RuntimeIO; containmentIO: RuntimeIO; plan: unknown; lifecycleLock: unknown; proxyId: string };
  expect(input.containmentIO).toBe(baseIO);
  expect(input.plan).toBe(plan);
  expect(input.lifecycleLock).toBe(lifecycleLock);
  expect(input.proxyId).toBe("p".repeat(64));
  // The work IO is the budgeted wrapper over the same base: it delegates while
  // the budget lasts, and refuses once it is spent. The containment IO does not.
  expect(input.io).not.toBe(baseIO);
  input.io.capture("docker", ["ps"], { timeout: 120_000 });
  expect((capture.mock.calls[0] as unknown[])[2]).toMatchObject({ timeout: expect.any(Number) });
  expect(((capture.mock.calls[0] as unknown[])[2] as { timeout: number }).timeout).toBeLessThanOrEqual(60_000);

  deadline = performance.now() - 1;
  await restoreAdmissionAfterProxyRestart({ plan, lifecycleLock, proxyId: "p".repeat(64), deadline, baseIO });
  const spent = restore.calls[1] as { io: RuntimeIO; containmentIO: RuntimeIO };
  expect(() => spent.io.capture("docker", ["ps"])).toThrow("budget ended");
  expect(spent.containmentIO.capture("docker", ["ps"]).status).toBe(0);
});
