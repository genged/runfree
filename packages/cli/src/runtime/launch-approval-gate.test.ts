// T10: every public launch entry meets the recovery gate.
//
// The entries share one funnel — `startRuntime` runs
// `prepareEffectiveControlsForStartup` before Docker planning, image
// materialization, credential resolution, or attach — so the proof has two
// halves. The first is that the funnel itself refuses a record carrying no
// authority before any of that, and renders the review rather than a bare
// error. The second is that each entry reaches the funnel, and that the two
// entries which read approved authority on their own (`runfree <agent>` and
// `runfree resume`) cross the gate before they do.
//
// The consent cases live in `control/approval-recovery.test.ts`; this file is
// about reachability and refusal.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { resumeRecoveryRuntime, shellRuntime } from "../runtime.ts";
import { mcpAuthRuntime } from "./mcp-auth.ts";
import { startRuntime, up } from "./startup.ts";
import { flushWarnings, pendingWarningsForTest } from "../warnings.ts";
import { mcpApprovalPath, mcpInventory, saveMcpApproval } from "./mcp.ts";
import type { RecoveryItem } from "./recovery.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

let root: string;
let stateHome: string;
let context: RuntimeContext;
let printed: string[];
let logSpy: ReturnType<typeof vi.spyOn>;
let errorSpy: ReturnType<typeof vi.spyOn>;

function io(overrides: Partial<RuntimeIO> = {}): RuntimeIO {
  return {
    capture: (_command: string, args: string[]) => args[0] === "ps"
      ? { status: 0, stdout: "", stderr: "" }
      : { status: 1, stdout: "", stderr: "unexpected" },
    run: () => 0,
    commandExists: () => true,
    confirm: () => { throw new Error("a non-interactive entry must not be asked to confirm"); },
    isInteractive: () => false,
    admin: async () => 0,
    ...overrides,
  } as RuntimeIO;
}

/** An approved project whose record was then bound to a different checkout. */
function mismatched(): string {
  const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
  approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
  approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(root, context.project, "interactive");
  const approvalsPath = context.project.paths.controlApprovalsPath;
  const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
  stored.checkoutBinding.rootInode = "999999999";
  const record = `${JSON.stringify(stored, null, 2)}\n`;
  fs.writeFileSync(approvalsPath, record);
  return record;
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-launch-gate-"));
  stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-launch-gate-state-"));
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
  printed = [];
  flushWarnings();
  logSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    printed.push(args.map(String).join(" "));
  });
  errorSpy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    printed.push(args.map(String).join(" "));
  });
});

afterEach(() => {
  logSpy.mockRestore();
  errorSpy.mockRestore();
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(stateHome, { recursive: true, force: true });
});

test("the start funnel renders the review and refuses before Docker planning", async () => {
  const before = mismatched();

  const result = await startRuntime(context, io(), false, {});

  expect(result.kind).toBe("failed");
  expect(result.status).toBe(1);
  expect(printed.join("\n")).toContain("Runfree needs to review this checkout's saved approvals.");
  // Full digests, copyable as the exact-approval commands non-interactive
  // recovery requires. The start path reports the refusal as a warning, which
  // the CLI entrypoint flushes on exit.
  const reported = pendingWarningsForTest().map((event) => event.message).join("\n");
  expect(reported).toMatch(/runfree control approve network-project --subject-digest sha256:[a-f0-9]{64}/);
  expect(reported).toMatch(/runfree control approve network-local --subject-digest sha256:[a-f0-9]{64}/);
  expect(reported).toMatch(/runfree control approve runtime-isolation --subject-digest sha256:[a-f0-9]{64}/);
  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

/**
 * The refusal actually reached was the approval gate's.
 *
 * Asserting the rendered review and a non-zero status alone is not enough: the
 * start path reports any thrown error as status 1, so a regression that asked
 * this file's non-interactive `io` to confirm would fail inside `confirm` and
 * still look like a clean refusal. The reported text is what distinguishes
 * them.
 */
function expectApprovalRefusal(): void {
  expect(printed.join("\n")).toContain("Runfree needs to review this checkout's saved approvals.");
  expect(pendingWarningsForTest().map((event) => event.message).join("\n"))
    .toContain("desired controls require exact approval before startup");
}

// `--yes` selects unattended operation for a destructive default; it is not
// consent to approve controls, and no flag on any launch entry is.
test("--yes cannot approve", async () => {
  const before = mismatched();

  const result = await startRuntime(context, io(), false, { assumeYes: true });

  expect(result.status).toBe(1);
  expectApprovalRefusal();
  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

test("up reaches the gate", async () => {
  mismatched();

  expect(await up(context, io())).toBe(1);
  expectApprovalRefusal();
});

test("shell reaches the gate", async () => {
  mismatched();

  expect(await shellRuntime(context, io(), { verbose: false })).toBe(1);
  expectApprovalRefusal();
});

// Resume reads approved authority in its operational-service review before
// `startRuntime` runs, so it carries the gate itself. Without it the record
// surfaced as an unreadable-approval error out of that review, with no review
// rendered and nothing to repair it.
test("resume crosses the gate before its operational-service review", async () => {
  mismatched();
  const item = { id: "rf-20260916-resume01", agent: "claude" } as unknown as RecoveryItem;

  await expect(resumeRecoveryRuntime(context, io({
    capture: () => { throw new Error("resume must refuse before probing Docker"); },
  }), item)).rejects.toThrow("require exact approval before startup");

  expect(printed.join("\n")).toContain("Runfree needs to review this checkout's saved approvals.");
});

// MCP auth resolves which server to authenticate and then hands off to the same
// funnel, before any session launch. Driven through the real `startRuntime`:
// injecting a fake one would prove only that this test can inject a fake one.
test("mcp auth reaches the gate before launching a session", async () => {
  const before = mismatched();
  const launch = vi.fn(async () => 0);
  fs.mkdirSync(path.join(root, ".codex"), { recursive: true });
  fs.writeFileSync(
    path.join(root, ".codex", "config.toml"),
    '[mcp_servers.repo_tools]\nurl = "https://repo-tools.example.com/mcp"\n',
  );
  const approvalPath = mcpApprovalPath(context.project.paths.stateDir);
  const entry = mcpInventory({ approvalPath, env: context.env ?? process.env, projectRoot: root }).entries
    .find((candidate) => candidate.agent === "codex" && candidate.source === "project" && candidate.name === "repo_tools");
  if (!entry) throw new Error("missing project MCP server fixture");
  saveMcpApproval(root, approvalPath, entry);

  const status = await mcpAuthRuntime(
    { agent: "codex", server: "repo_tools", source: "project" },
    context,
    io(),
    { launch },
  );

  expect(status).toBe(1);
  expectApprovalRefusal();
  expect(launch).not.toHaveBeenCalled();
  expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(before);
});
