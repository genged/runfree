// The difference between the two checkout observations, encoded deliberately.
//
// `checkoutBinding` is the persistent one: it is compared across launches, and
// the device number is recorded but never compared, because a reboot that
// renumbers the volume must keep every approval. `checkoutFingerprint` is the
// operation-local one: it covers path, device, AND inode, and it is compared
// only against itself inside a single capture/commit, where a change means the
// ground moved under an operation already in flight.
//
// One observation drives both — `checkoutFingerprint` derives from
// `observeCheckoutBinding` — so this file moves that single observation and
// asserts the two opposite outcomes. The mock is the seam because the real
// window between a capture and its commit is a few microseconds of synchronous
// code with no hook in it; what is under test is the guard's presence and
// polarity, not the width of that window.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  approveNetworkCandidate,
  readApprovedNetworkPolicy,
  readControlApprovalRecord,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { captureQuiescedDesiredPolicyCandidate } from "./workflow.ts";

const seam = vi.hoisted(() => ({
  afterCapture: [] as (undefined | (() => void))[],
  /** Appended to one observed field, keeping both fields decimal strings. */
  moved: undefined as undefined | "rootDevice" | "rootInode",
}));

vi.mock("./checkout-binding.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./checkout-binding.ts")>();
  return {
    ...actual,
    observeCheckoutBinding: (projectRoot: string) => {
      const binding = actual.observeCheckoutBinding(projectRoot);
      return seam.moved ? { ...binding, [seam.moved]: `${binding[seam.moved]}9` } : binding;
    },
  };
});

vi.mock("./candidates.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./candidates.ts")>();
  return {
    ...actual,
    captureDesiredPolicyCandidate: (...args: Parameters<typeof actual.captureDesiredPolicyCandidate>) => {
      const candidate = actual.captureDesiredPolicyCandidate(...args);
      seam.afterCapture.shift()?.();
      return candidate;
    },
  };
});

describe("operation-local checkout identity", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;

  const io: RuntimeIO = {
    capture: () => ({ status: 0, stdout: "", stderr: "" }),
    run: () => 0,
    commandExists: () => true,
    confirm: () => false,
    admin: async () => 0,
  };

  beforeEach(() => {
    seam.afterCapture = [];
    seam.moved = undefined;
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-operation-local-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-operation-local-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
    const env = {
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env } as RuntimeContext;
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  // The reported incident, from the persistent side: between launches, a
  // renumbered volume changes nothing at all.
  test("a device number that changed between launches keeps every approval", () => {
    seam.moved = "rootDevice";

    expect(readControlApprovalRecord(root, context.project).kind).toBe("valid");
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")?.hosts).toEqual(["example.com"]);
  });

  test("an inode that changed between launches is a mismatch, and names that field", () => {
    seam.moved = "rootInode";

    expect(readControlApprovalRecord(root, context.project))
      .toMatchObject({ kind: "mismatch", reason: "root-inode" });
  });

  // The same two observations, moved during one capture/commit instead of
  // between launches. Here the device is not exempt: the operation-local check
  // is about the ground moving mid-operation, not about durable identity.
  for (const field of ["rootDevice", "rootInode"] as const) {
    test(`a ${field} change between a capture and its commit refuses the capture`, async () => {
      seam.afterCapture = [() => { seam.moved = field; }];

      await expect(captureQuiescedDesiredPolicyCandidate(context, io))
        .rejects.toThrow("project checkout identity changed after candidate capture; rerun control review");
    });
  }

  // The control for the two refusals above: the same fixture, unarmed, commits
  // the bytes it captured.
  test("an unmoved checkout commits its capture", async () => {
    const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);

    expect(candidate.project.hosts).toEqual(["example.com"]);
  });
});
