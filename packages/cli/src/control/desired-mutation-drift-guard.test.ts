// The A2 invariant (2026-09-01 evolution-strategy decision, option b): a live
// desired-policy mutation approves only the exact in-memory candidate it
// re-read and verified under the lifecycle lock, never a fresh read of the
// worktree file. With no pause freezing the agent, this window guard is
// what carries the "agent cannot usefully write during the transaction"
// guarantee: an agent edit in any window is refused or left as inert
// unapproved drift, and the approved snapshot always equals a clean candidate.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  approveNetworkCandidate,
  readApprovedNetworkPolicy,
  readControlApprovalSelection,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { mutateDesiredHost, readDesiredHostRules } from "./local-host-mutation.ts";

// The transaction body is synchronous, so the agent-write injections need
// seams at the exact windows: one before each candidate capture (the first
// capture is T1, the re-read is T4) and one immediately before the atomic
// replace (inside T1..T3). The wrappers below pass through to the real
// modules; a queued hook runs first when a test arms it.
const seams = vi.hoisted(() => ({
  beforeCapture: [] as (undefined | (() => void))[],
  beforeReplace: undefined as (() => void) | undefined,
  beforeApprove: undefined as (() => void) | undefined,
}));

vi.mock("./candidates.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./candidates.ts")>();
  return {
    ...actual,
    captureDesiredPolicyCandidate: (
      ...args: Parameters<typeof actual.captureDesiredPolicyCandidate>
    ) => {
      seams.beforeCapture.shift()?.();
      return actual.captureDesiredPolicyCandidate(...args);
    },
  };
});

vi.mock("./approvals.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./approvals.ts")>();
  return {
    ...actual,
    approveNetworkCandidate: (
      ...args: Parameters<typeof actual.approveNetworkCandidate>
    ) => {
      seams.beforeApprove?.();
      seams.beforeApprove = undefined;
      return actual.approveNetworkCandidate(...args);
    },
  };
});

vi.mock("../safe-fs.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../safe-fs.ts")>();
  return {
    ...actual,
    safeReplaceProjectFile: (
      ...args: Parameters<typeof actual.safeReplaceProjectFile>
    ) => {
      seams.beforeReplace?.();
      seams.beforeReplace = undefined;
      return actual.safeReplaceProjectFile(...args);
    },
  };
});

const AGENT_DRIFT = '{"version":2,"hosts":["agent-drift.example.com"]}\n';

describe("desired-mutation agent-drift window guard", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  let projectPolicyPath: string;

  beforeEach(() => {
    seams.beforeCapture = [];
    seams.beforeReplace = undefined;
    seams.beforeApprove = undefined;
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-drift-guard-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-drift-guard-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    projectPolicyPath = path.join(root, ".runfree", "network-policy.json");
    fs.writeFileSync(projectPolicyPath, '{"version":2,"hosts":["project.example.com"]}\n');
    const env = {
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env };
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive", new Date("2026-09-01T00:00:00.000Z"));
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive", new Date("2026-09-01T00:00:00.000Z"));
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  function io(): RuntimeIO {
    return {
      capture: (commandName, args): CaptureResult => {
        if (commandName !== "docker") throw new Error(`unexpected command: ${commandName}`);
        if (args[0] === "ps") return { status: 0, stdout: "", stderr: "" };
        return { status: 1, stdout: "", stderr: "unexpected Docker call" };
      },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    };
  }

  function approvedProjectDigest(): string | undefined {
    return readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest;
  }

  function writeAgentDrift(): void {
    fs.writeFileSync(projectPolicyPath, AGENT_DRIFT);
  }

  test("window 1 - an edit before capture is refused against the approved base", async () => {
    const approvedBefore = approvedProjectDigest();
    writeAgentDrift();

    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "new.example.com" }))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");

    expect(approvedProjectDigest()).toBe(approvedBefore);
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).toEqual({
      version: 2,
      hosts: ["project.example.com"],
    });
    // The drift stays on disk as inert unapproved input, never adopted.
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(AGENT_DRIFT);
  });

  test("window 2 - an edit between capture and the atomic write is destroyed by the rename", async () => {
    seams.beforeReplace = writeAgentDrift;

    const result = await mutateDesiredHost(context, io(), "project", { kind: "add", host: "new.example.com" });

    expect(result.changed).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(projectPolicyPath, "utf8")) as { hosts: string[] };
    expect(onDisk.hosts).toEqual(["new.example.com", "project.example.com"]);
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).toEqual({
      version: 2,
      hosts: ["new.example.com", "project.example.com"],
    });
  });

  test("window 3 - an edit between the write and the re-read fails the exact-match check unapproved", async () => {
    const approvedBefore = approvedProjectDigest();
    // First capture (T1) runs clean; the re-read capture (T4) sees the drift.
    seams.beforeCapture = [undefined, writeAgentDrift];

    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "new.example.com" }))
      .rejects.toThrow("project policy write did not produce the exact planned candidate");

    expect(approvedProjectDigest()).toBe(approvedBefore);
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).toEqual({
      version: 2,
      hosts: ["project.example.com"],
    });
    // The drift the agent landed is inert: the next typed transaction refuses it.
    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "other.example.com" }))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");
  });

  test("window 4 - an edit after the re-read cannot reach the approval, which uses the in-memory candidate", async () => {
    // THE window the A2 invariant exists for. The spec's counterweight is a
    // future mutation written the natural way -- approve whatever the file says
    // now -- which would be exploitable here. Approval must consume the exact
    // candidate already re-read and verified under the lock, so an agent edit
    // landing in this window changes nothing that gets approved.
    seams.beforeApprove = writeAgentDrift;

    const result = await mutateDesiredHost(context, io(), "project", { kind: "add", host: "new.example.com" });

    expect(result.changed).toBe(true);
    // The approved snapshot is the clean planned candidate, not the drift.
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).toEqual({
      version: 2,
      hosts: ["new.example.com", "project.example.com"],
    });
    // The agent's bytes are still on disk, inert and unapproved: the next
    // typed transaction refuses them against the approved base.
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(AGENT_DRIFT);
    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "other.example.com" }))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");
  });

  test("the read-only rules query refuses agent drift instead of printing it as policy", async () => {
    // These reads run beside live sessions, so an unguarded read would hand the
    // operator agent-authored bytes as "the host's rules" at exactly the moment
    // they are deciding whether to intervene.
    await mutateDesiredHost(context, io(), "project", { kind: "add", host: "api.example.com" });
    fs.writeFileSync(projectPolicyPath, JSON.stringify({
      version: 2,
      hosts: ["api.example.com", "project.example.com"],
      requests: { "api.example.com": { methods: ["GET"], writeAction: "allow" } },
    }));

    await expect(readDesiredHostRules(context, io(), "project", "api.example.com"))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");
  });

  test("window 5 - an edit after approval cannot reach the content-addressed snapshot", async () => {
    const result = await mutateDesiredHost(context, io(), "project", { kind: "add", host: "new.example.com" });
    expect(result.changed).toBe(true);

    writeAgentDrift();

    // Publication consumes the digest-keyed snapshot store, not the worktree.
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).toEqual({
      version: 2,
      hosts: ["new.example.com", "project.example.com"],
    });
    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "other.example.com" }))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");
  });
});
