import { beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  peek: vi.fn(),
}));

vi.mock("./session-containers.ts", () => ({
  peekSessionContainerRecordsV2: mocks.peek,
}));

import { resolveAgentExecTarget } from "./agent-exec-target.ts";
import type { RuntimeDocker } from "./docker.ts";

const CONTAINER_ID = "a".repeat(64);
const OTHER_CONTAINER_ID = "b".repeat(64);
const REGISTRY = { stateDir: "/state", projectId: "0123456789ab" } as const;

function fakeDocker(overrides: Partial<RuntimeDocker> = {}): RuntimeDocker {
  return {
    runningServiceContainerId: vi.fn(() => undefined),
    serviceContainerId: vi.fn(() => undefined),
    containerRunning: vi.fn(() => true),
    ...overrides,
  } as unknown as RuntimeDocker;
}

function attachedRecord(overrides: Record<string, unknown> = {}) {
  return {
    state: "attached",
    containerId: CONTAINER_ID,
    sessionId: "rf-20260817-abcdef",
    sourceIp: "172.30.0.21",
    ...overrides,
  };
}

function peekReturns(records: readonly unknown[], unreadable = 0): void {
  mocks.peek.mockReturnValue({ records, unreadable });
}

describe("resolveAgentExecTarget", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("ignores leftover Compose-agent evidence and resolves only the lifecycle registry", () => {
    peekReturns([attachedRecord()]);
    const docker = fakeDocker({ runningServiceContainerId: vi.fn(() => CONTAINER_ID) });

    const target = resolveAgentExecTarget("runfree-p", docker, { sessionRegistry: REGISTRY });

    expect(target).toMatchObject({ kind: "session", containerId: CONTAINER_ID });
    expect(mocks.peek).toHaveBeenCalledOnce();
  });

  test("resolves the one live attached session when no shared agent exists", () => {
    peekReturns([attachedRecord()]);

    const target = resolveAgentExecTarget("runfree-p", fakeDocker(), { sessionRegistry: REGISTRY });

    expect(target).toEqual({
      kind: "session",
      containerId: CONTAINER_ID,
      sessionId: "rf-20260817-abcdef",
      sourceIp: "172.30.0.21",
      running: true,
    });
    expect(mocks.peek).toHaveBeenCalledWith("/state", { projectId: "0123456789ab", composeProject: "runfree-p" });
  });

  test("an attached record whose container is no longer running is not a target", () => {
    peekReturns([attachedRecord()]);
    const docker = fakeDocker({ containerRunning: vi.fn(() => false) });

    expect(resolveAgentExecTarget("runfree-p", docker, { sessionRegistry: REGISTRY })).toBeUndefined();
  });

  test("non-attached records never become targets", () => {
    peekReturns([
      attachedRecord({ state: "provisioning-running" }),
      attachedRecord({ state: "revoking", containerId: OTHER_CONTAINER_ID }),
    ]);

    expect(resolveAgentExecTarget("runfree-p", fakeDocker(), { sessionRegistry: REGISTRY })).toBeUndefined();
  });

  test("refuses a partially legible registry rather than guessing from the readable subset", () => {
    peekReturns([attachedRecord()], 1);

    expect(() => resolveAgentExecTarget("runfree-p", fakeDocker(), { sessionRegistry: REGISTRY }))
      .toThrow(/1 session lifecycle record\(s\) are unreadable.*destroy --force/su);
  });

  test("refuses to pick between concurrent live sessions, naming them", () => {
    peekReturns([
      attachedRecord(),
      attachedRecord({ containerId: OTHER_CONTAINER_ID, sessionId: "rf-20260817-fedcba" }),
    ]);

    expect(() => resolveAgentExecTarget("runfree-p", fakeDocker(), { sessionRegistry: REGISTRY }))
      .toThrow(/2 sessions are live \(rf-20260817-abcdef, rf-20260817-fedcba\)/u);
  });

  test("without the registry option, no singleton agent target exists", () => {
    const docker = fakeDocker();

    expect(resolveAgentExecTarget("runfree-p", docker)).toBeUndefined();
    expect(mocks.peek).not.toHaveBeenCalled();
  });
});
