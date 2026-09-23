import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
  readControlApprovalSelection,
  type ControlApprovalSelection,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { checkoutFingerprint } from "./subjects.ts";
import { requireUsableApprovalSelection } from "./workflow.ts";

let root: string;
let stateHome: string;
let context: RuntimeContext;
let lines: string[];
let logSpy: ReturnType<typeof vi.spyOn>;

const baseIo: RuntimeIO = {
  capture: (_command, args) => args[0] === "ps"
    ? { status: 0, stdout: "", stderr: "" }
    : { status: 1, stdout: "", stderr: "unexpected" },
  run: () => 0,
  commandExists: () => true,
  confirm: () => false,
  admin: async () => 0,
};

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approval-recovery-"));
  stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approval-recovery-state-"));
  fs.mkdirSync(path.join(root, ".runfree"));
  fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
  const env = {
    XDG_STATE_HOME: stateHome,
    XDG_CONFIG_HOME: path.join(stateHome, "config"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
    RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
  };
  context = {
    projectRoot: root,
    project: projectInfo(root, env),
    runtimeRoot: path.join(root, "runtime"),
    env,
  } as RuntimeContext;
  lines = [];
  logSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  });
});

afterEach(() => {
  logSpy.mockRestore();
  fs.rmSync(root, { recursive: true });
  fs.rmSync(stateHome, { recursive: true });
});

function io(overrides: Partial<RuntimeIO>): RuntimeIO {
  return { ...baseIo, ...overrides } as RuntimeIO;
}

/** An approved project whose record was then bound to a different checkout. */
function mismatched(field: "resolvedRoot" | "rootInode" = "rootInode"): string {
  const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
  approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
  approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(root, context.project, "interactive");
  const approvalsPath = context.project.paths.controlApprovalsPath;
  const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: Record<string, string> };
  stored.checkoutBinding[field] = field === "rootInode" ? "999999999" : "/elsewhere";
  const record = `${JSON.stringify(stored, null, 2)}\n`;
  fs.writeFileSync(approvalsPath, record);
  return record;
}

/**
 * Rewrite the approved record as the v1 schema it would have had before the
 * binding change. `fingerprint` defaults to the one this checkout observes, so
 * the record still describes it; pass a different value for the group that
 * rebooted before the fix shipped.
 */
function legacy(options: { fingerprint?: string; withImageSubject?: boolean } = {}): string {
  const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
  approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
  approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(root, context.project, "interactive");
  const approvalsPath = context.project.paths.controlApprovalsPath;
  const current = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as ControlApprovalSelection;
  const subjects: Record<string, unknown> = { ...current.subjects };
  if (options.withImageSubject) {
    // An image subject whose snapshot was never published: it cannot be carried
    // forward, and it must not be dropped while reporting migration success.
    subjects["image-build"] = {
      approvedAt: "2026-09-01T00:00:00.000Z",
      digest: `sha256:${"e".repeat(64)}`,
      mechanism: "typed-host-command",
    };
  }
  const record = `${JSON.stringify({
    schemaVersion: 1,
    projectId: current.projectId,
    checkoutFingerprint: options.fingerprint ?? checkoutFingerprint(root),
    configVersion: current.configVersion,
    subjects,
  }, null, 2)}\n`;
  fs.writeFileSync(approvalsPath, record);
  return record;
}

test("a valid record passes the gate without printing or prompting", async () => {
  const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
  approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");

  const read = await requireUsableApprovalSelection(context, io({
    confirm: () => { throw new Error("a valid record must not prompt"); },
  }));

  expect(read.kind).toBe("valid");
  expect(lines).toEqual([]);
});

test("a missing record passes the gate: first approval is not a recovery", async () => {
  const read = await requireUsableApprovalSelection(context, io({
    confirm: () => { throw new Error("a missing record must not prompt here"); },
  }));

  expect(read.kind).toBe("missing");
  expect(lines).toEqual([]);
});

test("a mismatch renders the canonical desired policy body, not only digests", async () => {
  mismatched();

  await requireUsableApprovalSelection(context, io({ confirm: () => true, isInteractive: () => true }));

  const output = lines.join("\n");
  expect(output).toContain("Runfree needs to review this checkout's saved approvals.");
  expect(output).toContain("The directory at this path was replaced.");
  expect(output).toContain("canonical desired policy:");
  expect(output).toContain("example.com");
  expect(output).toContain("runtime-isolation subject digest: sha256:");
});

// A retargeted project-root symlink reaches the same review with its own
// reason. `control/approvals.test.ts` retargets a real symlink; this covers what
// the operator is shown when it happens.
test("a resolved-root mismatch names the path, not the directory", async () => {
  mismatched("resolvedRoot");

  await requireUsableApprovalSelection(context, io({ confirm: () => true, isInteractive: () => true }));

  const output = lines.join("\n");
  expect(output).toContain("This path now resolves somewhere else.");
  expect(output).not.toContain("The directory at this path was replaced.");
  expect(output).toContain("canonical desired policy:");
});

test("a declined review leaves the previous selector byte-identical and starts nothing", async () => {
  const before = mismatched();

  await expect(requireUsableApprovalSelection(context, io({ confirm: () => false, isInteractive: () => true })))
    .rejects.toThrow("declined");

  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

test("an accepted mismatch carries only the newly approved subjects, and the copy exists", async () => {
  const superseded = mismatched();
  // An image-build approval from the previous binding must not survive: it was
  // granted against a checkout that is no longer the one at this path.
  const stored = JSON.parse(superseded) as { subjects: Record<string, unknown> };
  expect(stored.subjects["runtime-isolation"]).toBeDefined();

  await requireUsableApprovalSelection(context, io({ confirm: () => true, isInteractive: () => true }));

  const after = readControlApprovalSelection(root, context.project);
  expect(Object.keys(after?.subjects ?? {}).sort())
    .toEqual(["network-local", "network-project", "runtime-isolation"]);
  for (const record of Object.values(after?.subjects ?? {})) {
    expect(record?.mechanism).toBe("interactive");
  }
  const copies = fs.readdirSync(context.project.paths.controlDir)
    .filter((name) => name.startsWith("approvals.json.superseded-"));
  expect(copies).toHaveLength(1);
  expect(fs.readFileSync(path.join(context.project.paths.controlDir, copies[0]), "utf8")).toBe(superseded);
});

test("non-interactive recovery prints the review and the exact digest commands", async () => {
  const before = mismatched();

  await expect(requireUsableApprovalSelection(context, io({
    isInteractive: () => false,
    confirm: () => { throw new Error("a non-TTY must not be asked to confirm"); },
  }))).rejects.toThrow("require exact approval before startup");

  const output = lines.join("\n");
  expect(output).toContain("canonical desired policy:");
  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

// T4, first half. The launch path reaches this gate before any lifecycle-locked
// funnel, so if the gate could not migrate, a v1 project could never start.
test("a v1 record that still describes this checkout migrates at the gate, silently", async () => {
  legacy();
  const before = JSON.parse(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")) as {
    subjects: Record<string, { digest: string }>;
  };

  const read = await requireUsableApprovalSelection(context, io({
    confirm: () => { throw new Error("a record that proves its own continuity must not prompt"); },
  }));

  expect(read.kind).toBe("valid");
  expect(lines).toEqual([]);
  const after = readControlApprovalSelection(root, context.project);
  expect(after?.schemaVersion).toBe(2);
  // The same consent, re-expressed: digests, mechanisms, and timestamps all
  // survive the schema change.
  expect(after?.subjects).toEqual(before.subjects);
});

// T4, second half, and the wedge this gate was missing: `policy review` renders
// but writes nothing, so before this branch existed the refusal named a command
// that could not clear the state, forever.
test("a v1 record that no longer describes this checkout renders the review and recovers", async () => {
  const superseded = legacy({ fingerprint: `sha256:${"e".repeat(64)}` });

  await requireUsableApprovalSelection(context, io({ confirm: () => true, isInteractive: () => true }));

  const output = lines.join("\n");
  expect(output).toContain("Runfree needs to review this checkout's saved approvals.");
  expect(output).toContain("predate this version of runfree and no longer describe this checkout");
  expect(output).toContain("canonical desired policy:");
  expect(output).toContain("example.com");
  // A hash cannot say which field moved, so the review must not claim one.
  expect(output).not.toContain("The directory at this path was replaced.");

  const after = readControlApprovalSelection(root, context.project);
  expect(after?.schemaVersion).toBe(2);
  expect(Object.keys(after?.subjects ?? {}).sort())
    .toEqual(["network-local", "network-project", "runtime-isolation"]);
  for (const record of Object.values(after?.subjects ?? {})) expect(record?.mechanism).toBe("interactive");
  const copies = fs.readdirSync(context.project.paths.controlDir)
    .filter((name) => name.startsWith("approvals.json.superseded-"));
  expect(copies).toHaveLength(1);
  expect(fs.readFileSync(path.join(context.project.paths.controlDir, copies[0]), "utf8")).toBe(superseded);
});

test("a declined v1 review leaves the previous record byte-identical and starts nothing", async () => {
  const before = legacy({ fingerprint: `sha256:${"e".repeat(64)}` });

  await expect(requireUsableApprovalSelection(context, io({ confirm: () => false, isInteractive: () => true })))
    .rejects.toThrow("declined");

  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

// A v1 record whose own identity holds but whose approved snapshots do not.
// Nothing here can repair it, so it refuses — but the refusal names the path
// that clears it, which is the rule the first version of this gate broke.
test("a v1 record whose approved snapshots no longer verify refuses with a usable reclamation", async () => {
  const before = legacy({ withImageSubject: true });

  const gate = requireUsableApprovalSelection(context, io({
    isInteractive: () => true,
    confirm: () => { throw new Error("an unverifiable snapshot is not a consent problem"); },
  }));

  await expect(gate).rejects.toThrow("their approved snapshots no longer verify");
  const message = await gate.then(() => "", (error: Error) => error.message);
  expect(message).toContain("runfree policy status");
  expect(message).toContain("runfree up");
  // Never `policy review`: it renders the policy and writes nothing.
  expect(message).not.toContain("policy review");
  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

// T5's reclamation half for `legacy`. The writer refusal stays — a writer
// reached without crossing the gate or the funnel must not overwrite a record
// whose approvals are still carryable — and the command it names has to work.
test("the writer refuses a v1 record, and the reclamation it names clears the state", async () => {
  legacy();

  expect(() => approveRuntimeIsolationControl(root, context.project, "interactive"))
    .toThrow("migrate them with: runfree up");

  // What `runfree up` does first.
  await requireUsableApprovalSelection(context, io({
    confirm: () => { throw new Error("migration must not prompt") },
  }));

  expect(readControlApprovalSelection(root, context.project)?.schemaVersion).toBe(2);
  expect(() => approveRuntimeIsolationControl(root, context.project, "interactive")).not.toThrow();
});

test("a corrupt record refuses with its own reclamation path and never prompts", async () => {
  mismatched();
  const garbage = `{"schemaVersion":1,"subjects":\n`;
  fs.writeFileSync(context.project.paths.controlApprovalsPath, garbage);

  await expect(requireUsableApprovalSelection(context, io({
    isInteractive: () => true,
    confirm: () => { throw new Error("a corrupt record is not a consent problem"); },
  }))).rejects.toThrow("could not be read");

  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(garbage);
});
