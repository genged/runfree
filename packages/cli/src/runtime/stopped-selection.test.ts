import { describe, expect, test, vi } from "vitest";

import type { ControlPlaneEffectiveSelectionV2 } from "./component-state-v2.ts";
import { clearStoppedControlPlaneSelection, type StoppedSelectionDeps } from "./stopped-selection.ts";
import type { CaptureResult } from "./types.ts";

const PROJECT = { projectId: "abcdef123456", composeProject: "runfree-abcdef123456" };
const PROXY_ID = "a".repeat(64);
const INTERNAL_ID = "b".repeat(64);
const EGRESS_ID = "c".repeat(64);

const SELECTION = {
  ...PROJECT,
  proxyContainerId: PROXY_ID,
  networkIds: { agentInternal: INTERNAL_ID, proxyEgress: EGRESS_ID },
} as unknown as ControlPlaneEffectiveSelectionV2;

const clean: CaptureResult = { status: 0, stdout: "", stderr: "" };

function harness(overrides: Partial<StoppedSelectionDeps> = {}) {
  const calls: string[][] = [];
  const clearSelection = vi.fn();
  const deps = {
    readSelection: () => SELECTION,
    peekRecords: () => ({ records: [], unreadable: 0 }),
    readRebind: () => undefined,
    clearSelection,
    docker: (args: readonly string[]) => {
      calls.push([...args]);
      return clean;
    },
    assertAuthority: () => {},
    ...overrides,
  } as unknown as StoppedSelectionDeps;
  return { deps, calls, clearSelection };
}

describe("clearStoppedControlPlaneSelection", () => {
  test("clears the selection when Docker proves its proxy and both networks are gone", () => {
    const { deps, calls, clearSelection } = harness();
    expect(clearStoppedControlPlaneSelection("/state", PROJECT, deps)).toBe("cleared");
    expect(clearSelection).toHaveBeenCalledExactlyOnceWith("/state");
    expect(calls).toEqual([
      ["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${PROXY_ID}`],
      ["network", "ls", "--quiet", "--no-trunc", "--filter", `id=${INTERNAL_ID}`],
      ["network", "ls", "--quiet", "--no-trunc", "--filter", `id=${EGRESS_ID}`],
    ]);
  });

  test("reports absent and touches nothing when there is no selection", () => {
    const { deps, calls, clearSelection } = harness({ readSelection: () => undefined });
    expect(clearStoppedControlPlaneSelection("/state", PROJECT, deps)).toBe("absent");
    expect(calls).toEqual([]);
    expect(clearSelection).not.toHaveBeenCalled();
  });

  test.each([
    ["a lifecycle record (a forced stop left sessions on the networks)", "retained", { peekRecords: () => ({ records: [{}], unreadable: 0 }) }],
    ["a pending rebind journal", "retained", { readRebind: () => ({}) }],
    ["a selection for another project", "unverified", { readSelection: () => ({ ...SELECTION, projectId: "ffffffffffff" }) }],
    ["an unreadable selection", "unverified", { readSelection: () => { throw new Error("malformed selection"); } }],
    ["an unreadable lifecycle record", "unverified", { peekRecords: () => ({ records: [], unreadable: 1 }) }],
    ["an unreadable registry", "unverified", { peekRecords: () => { throw new Error("unsafe registry directory"); } }],
    ["an unreadable rebind journal", "unverified", { readRebind: () => { throw new Error("invalid journal"); } }],
  ])("keeps the selection, before any Docker read, on %s", (_label, outcome, override) => {
    const { deps, calls, clearSelection } = harness(override as Partial<StoppedSelectionDeps>);
    expect(clearStoppedControlPlaneSelection("/state", PROJECT, deps)).toBe(outcome);
    expect(calls).toEqual([]);
    expect(clearSelection).not.toHaveBeenCalled();
  });

  test.each([
    ["the proxy container survives", "retained", 0, { ...clean, stdout: `${PROXY_ID}\n` }],
    ["the internal network survives", "retained", 1, { ...clean, stdout: `${INTERNAL_ID}\n` }],
    ["the egress network survives", "retained", 2, { ...clean, stdout: `${EGRESS_ID}\n` }],
    ["a listing fails", "unverified", 1, { ...clean, status: 1 }],
    ["a listing writes to stderr", "unverified", 2, { ...clean, stderr: "error during connect" }],
  ])("keeps the selection when %s", (_label, outcome, failingCall, answer) => {
    let call = 0;
    const { deps, clearSelection } = harness({
      docker: () => (call++ === failingCall ? answer : clean),
    });
    expect(clearStoppedControlPlaneSelection("/state", PROJECT, deps)).toBe(outcome);
    expect(clearSelection).not.toHaveBeenCalled();
  });

  test("a lost lifecycle lock stops the clear", () => {
    let checks = 0;
    const { deps, clearSelection } = harness({
      assertAuthority: () => {
        checks += 1;
        if (checks === 2) throw new Error("lifecycle lock lost");
      },
    });
    expect(() => clearStoppedControlPlaneSelection("/state", PROJECT, deps)).toThrow("lifecycle lock lost");
    expect(clearSelection).not.toHaveBeenCalled();
  });
});
