// A warm launch validates the runtime topology before admission runs. A dead
// session's MCP OAuth callback forwarder (its launcher killed, its container
// since stopped) fails that validation on every later launch, so startup
// reclaims dead callback routes under the held lock and proves the topology
// once more — the refusal and its reclamation, both here.

import { beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  validate: vi.fn(),
  reclaim: vi.fn(),
  assertHeld: vi.fn(),
}));

vi.mock("./topology.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./topology.ts")>()),
  validateRuntimeTopologyWithProof: mocks.validate,
}));
vi.mock("./session-callback-ingress.ts", () => ({
  reclaimStaleSessionMcpCallbackForwarders: mocks.reclaim,
}));

import { validateRuntimeTopologyOrRemoveInvalid } from "./startup.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const plan = { projectId: "0123456789ab", composeProjectName: "runfree-0123456789ab" } as unknown as ActiveRuntimePlan;
const context = { projectRoot: "/workspace/project", env: {} } as unknown as RuntimeContext;
const io = {} as RuntimeIO;
const docker = {} as never;
const lifecycleLock = { assertHeld: mocks.assertHeld } as unknown as ProjectLifecycleLock;
const effectiveHostServices = { policyGeneration: `sha256:${"a".repeat(64)}`, ports: [5432] };
const staleIssue = {
  code: "utility-ingress-forwarder-shape",
  message: "mcp-callback forwarder x must target its own live session's internal IP",
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("startup topology validation and dead callback routes", () => {
  test("reclaims dead callback routes under the lock and passes on the second proof", () => {
    mocks.validate
      .mockReturnValueOnce({ issues: [staleIssue] })
      .mockReturnValueOnce({ issues: [] });
    mocks.reclaim.mockReturnValue(1);

    const result = validateRuntimeTopologyOrRemoveInvalid(plan, context, io, docker, { lifecycleLock, effectiveHostServices });

    expect(result.status).toBe(0);
    expect(mocks.assertHeld).toHaveBeenCalled();
    expect(mocks.reclaim).toHaveBeenCalledWith(expect.objectContaining({
      projectId: "0123456789ab",
      internalNetwork: "runfree-0123456789ab_agent_internal",
    }));
    expect(mocks.validate).toHaveBeenCalledTimes(2);
    // Both proofs judge @host_service against the same effective host services.
    for (const call of mocks.validate.mock.calls) {
      expect(call[2]).toEqual(expect.objectContaining({ effectiveHostServices }));
    }
  });

  test("keeps the refusal when nothing was reclaimable", () => {
    mocks.validate.mockReturnValue({ issues: [staleIssue] });
    mocks.reclaim.mockReturnValue(0);

    expect(validateRuntimeTopologyOrRemoveInvalid(plan, context, io, docker, { lifecycleLock, effectiveHostServices }).status).toBe(1);
    expect(mocks.validate).toHaveBeenCalledTimes(1);
  });

  test("keeps the refusal when what is stale cannot be proved", () => {
    mocks.validate.mockReturnValue({ issues: [staleIssue] });
    mocks.reclaim.mockImplementation(() => { throw new Error("Cannot connect to the Docker daemon"); });

    expect(validateRuntimeTopologyOrRemoveInvalid(plan, context, io, docker, { lifecycleLock, effectiveHostServices }).status).toBe(1);
    expect(mocks.validate).toHaveBeenCalledTimes(1);
  });

  test("never mutates without the lifecycle lock or in a read-only validation", () => {
    mocks.validate.mockReturnValue({ issues: [staleIssue] });

    expect(validateRuntimeTopologyOrRemoveInvalid(plan, context, io, docker, { effectiveHostServices }).status).toBe(1);
    expect(validateRuntimeTopologyOrRemoveInvalid(plan, context, io, docker, { lifecycleLock, readOnly: true, effectiveHostServices }).status).toBe(1);
    expect(mocks.reclaim).not.toHaveBeenCalled();
  });

  test("a healthy topology spends nothing on reclaim", () => {
    mocks.validate.mockReturnValue({ issues: [] });

    expect(validateRuntimeTopologyOrRemoveInvalid(plan, context, io, docker, { lifecycleLock, effectiveHostServices }).status).toBe(0);
    expect(mocks.reclaim).not.toHaveBeenCalled();
  });
});
