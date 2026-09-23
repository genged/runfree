// The wizard-facing approval gate: a migrated (or drifted) desired project
// policy must pass the exact-review approval before typed wizard mutations,
// and a failing wizard intent must surface as a failed plan item, not a crash.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { createAdminState } from "../admin/context.ts";
import { runAdminAction, sourceAddCommandIntent } from "../admin/options.ts";
import { projectInfo } from "../config.ts";
import {
  approveNetworkCandidate,
  readApprovedNetworkPolicy,
  readControlApprovalSelection,
} from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  ensureWizardApprovedBase,
  projectPolicyNeedsExactApproval,
  runWizardAdminIntent,
} from "./init.ts";

describe("init wizard approved-base gate", () => {
  let root: string;
  let stateHome: string;
  let env: NodeJS.ProcessEnv;
  let context: RuntimeContext;

  const wizardIO = (confirm: () => boolean): RuntimeIO => ({
    capture: (_command, args) => {
      if (args[0] === "ps") return { status: 0, stdout: "", stderr: "" };
      throw new Error(`unexpected Docker call: ${args.join(" ")}`);
    },
    run: () => 0,
    commandExists: () => true,
    confirm,
    admin: async () => 0,
  });

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-init-gate-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-init-gate-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    env = {
      // The source-add case below resolves `node` on the sanitized host PATH.
      PATH: process.env.PATH,
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env };
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  function writeMigratedPolicy(): void {
    fs.writeFileSync(
      path.join(root, ".runfree", "network-policy.json"),
      `{"version":2,"hosts":["migrated.example.com"]}`,
    );
  }

  function adminState() {
    return createAdminState({
      projectRoot: root,
      policyPath: context.project.paths.policyPath,
      policyAccess: "effective-read-only",
      effectiveControlSelected: false,
      stateDir: context.project.paths.stateDir,
      tokenConfigPath: context.project.paths.tokenConfigPath,
      env,
    });
  }

  test("the authority-free scaffold needs no review", async () => {
    const confirm = vi.fn(() => true);
    expect(projectPolicyNeedsExactApproval(context)).toBe(false);
    await expect(ensureWizardApprovedBase(context, wizardIO(confirm))).resolves.toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  test("a matching approved base needs no review", async () => {
    writeMigratedPolicy();
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    const confirm = vi.fn(() => true);
    expect(projectPolicyNeedsExactApproval(context)).toBe(false);
    await expect(ensureWizardApprovedBase(context, wizardIO(confirm))).resolves.toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  test("a migrated policy without an approved base passes the exact review, then typed mutations work", async () => {
    writeMigratedPolicy();
    expect(projectPolicyNeedsExactApproval(context)).toBe(true);

    const io = wizardIO(() => true);
    await expect(ensureWizardApprovedBase(context, io)).resolves.toBe(true);
    const selection = readControlApprovalSelection(root, context.project);
    expect(selection?.subjects["network-project"]?.mechanism).toBe("interactive");
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")?.hosts)
      .toEqual(["migrated.example.com"]);

    const status = await runWizardAdminIntent(
      adminState(),
      { kind: "allow-host", host: "extra.example.com" },
      context,
      io,
    );
    expect(status).toBe(0);
    expect(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8"))
      .toContain("extra.example.com");
  });

  test("declining the review skips the wizard and approves nothing", async () => {
    writeMigratedPolicy();
    await expect(ensureWizardApprovedBase(context, wizardIO(() => false))).resolves.toBe(false);
    expect(fs.existsSync(context.project.paths.controlApprovalsPath)).toBe(false);
  });

  // The todo item's transcript: github already bound to 1Password, the wizard
  // asks for github-cli with replaceSource:false. The planner no longer plans
  // this intent, but the enforcement stays the backstop: it refuses before the
  // token save and before the desired-policy mutation, and the wizard reports a
  // failed item (exit 1 from init) rather than "Done.".
  test("a wizard bind against a differing credential binding is refused before any policy or token write", async () => {
    const tokenConfigPath = context.project.paths.tokenConfigPath;
    fs.mkdirSync(path.dirname(tokenConfigPath), { recursive: true });
    const tokensBefore = JSON.stringify({ github: { source: "1password", ref: "op://vault/github/token" } });
    fs.writeFileSync(tokenConfigPath, tokensBefore);
    const policyBefore = fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8");
    const added = await runAdminAction(adminState(), () => sourceAddCommandIntent({
      name: "github-cli",
      replaceSource: false,
      command: ["node", "-e", "process.stdout.write('tok')"],
    }));
    expect(added, vi.mocked(console.error).mock.calls.flat().join("\n")).toBe(0);

    const status = await runWizardAdminIntent(
      adminState(),
      { kind: "service-enable", id: "github", fromSource: "github-cli" },
      context,
      wizardIO(() => true),
    );

    expect(status).toBe(1);
    const stderr = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(stderr).toContain("github credential source is already 1password");
    expect(stderr).toContain("--replace-source");
    expect(fs.readFileSync(tokenConfigPath, "utf8")).toBe(tokensBefore);
    expect(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8")).toBe(policyBefore);
    expect(fs.existsSync(context.project.paths.controlApprovalsPath)).toBe(false);
  });

  test("wizard service binding refuses an unapproved base before writing a credential source", async () => {
    writeMigratedPolicy();
    expect(await runAdminAction(adminState(), () => sourceAddCommandIntent({
      name: "github-cli", replaceSource: false,
      command: ["node", "-e", "process.stdout.write('tok')"],
    }))).toBe(0);
    const before = fs.existsSync(context.project.paths.tokenConfigPath)
      ? fs.readFileSync(context.project.paths.tokenConfigPath, "utf8") : undefined;
    const status = await runWizardAdminIntent(adminState(),
      { kind: "service-enable", id: "github", fromSource: "github-cli" }, context, wizardIO(() => false));
    expect(status).toBe(1);
    expect(fs.existsSync(context.project.paths.tokenConfigPath)
      ? fs.readFileSync(context.project.paths.tokenConfigPath, "utf8") : undefined).toBe(before);
  });

  test("a wizard intent that hits an unapproved base fails its plan item instead of crashing", async () => {
    writeMigratedPolicy();
    const status = await runWizardAdminIntent(
      adminState(),
      { kind: "allow-host", host: "extra.example.com" },
      context,
      wizardIO(() => false),
    );
    expect(status).toBe(1);
    expect(vi.mocked(console.error).mock.calls.flat().join("\n")).toContain("no approved base");
    expect(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8"))
      .not.toContain("extra.example.com");
  });
});
