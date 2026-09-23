import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo } from "../config.ts";
import { writeLiveAttachedSessionContainerRecordFixture } from "../runtime/session-container.test-harness.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { approveNetworkCandidate, readControlApprovalSelection } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { LOCAL_POLICY_EXCLUDE_PATTERN } from "./git-exclude.ts";
import { mutateDesiredHost, readDesiredHostRules } from "./local-host-mutation.ts";

function command(commandName: string, args: string[]): CaptureResult {
  const result = childProcess.spawnSync(commandName, args, { encoding: "utf8" });
  return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

describe("checkout-local host mutations", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  let projectPolicyPath: string;
  let localPolicyPath: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-local-host-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-local-host-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    projectPolicyPath = path.join(root, ".runfree", "network-policy.json");
    localPolicyPath = path.join(root, ".runfree", "network-policy.local.json");
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
    approveDesiredBases();
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  function approveDesiredBases(): void {
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive", new Date("2026-08-05T00:00:00.000Z"));
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive", new Date("2026-08-05T00:00:00.000Z"));
  }

  // The typed transaction never touches a container (A2 decision): the fake
  // fails any Docker call so a reintroduced pause or inspect cannot pass.
  function io(): RuntimeIO {
    return {
      capture: (commandName, args) => {
        if (commandName === "git") return command(commandName, args);
        throw new Error(`unexpected command: ${commandName} ${args.join(" ")}`);
      },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    };
  }

  function localPolicy(): Record<string, unknown> {
    return JSON.parse(fs.readFileSync(localPolicyPath, "utf8")) as Record<string, unknown>;
  }

  test("adds, changes rules, and removes only the checkout-local host", async () => {
    const originalProject = fs.readFileSync(projectPolicyPath, "utf8");
    const added = await mutateDesiredHost(context, io(), "local", {
      kind: "add",
      host: "LOCAL.EXAMPLE.COM",
      requestRule: { readOnly: true, methods: [], pathPrefixes: [], denyGitPush: false },
    });

    expect(added).toMatchObject({ changed: true, host: "local.example.com" });
    expect(localPolicy()).toMatchObject({
      version: 2,
      hosts: ["local.example.com"],
      requests: { "local.example.com": { methods: ["GET", "HEAD", "OPTIONS"] } },
    });
    expect(added.selection.subjects["network-local"]?.mechanism).toBe("typed-host-command");

    const ruled = await mutateDesiredHost(context, io(), "local", {
      kind: "rules",
      host: "local.example.com",
      clear: false,
      write: "deny",
    });
    expect(ruled.changed).toBe(true);
    expect(localPolicy()).toMatchObject({
      requests: { "local.example.com": { methods: ["GET", "HEAD", "OPTIONS"], writeAction: "deny" } },
    });
    await expect(readDesiredHostRules(context, io(), "local", "LOCAL.EXAMPLE.COM")).resolves.toMatchObject({
      host: "local.example.com",
      rule: { methods: ["GET", "HEAD", "OPTIONS"], writeAction: "deny" },
      scope: "local",
    });

    const removed = await mutateDesiredHost(context, io(), "local", { kind: "remove", host: "local.example.com" });
    expect(removed.changed).toBe(true);
    expect(localPolicy()).toEqual({ version: 2, hosts: [] });
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(originalProject);
  });

  test("applies the same exact typed transaction to the project desired layer", async () => {
    const added = await mutateDesiredHost(context, io(), "project", {
      kind: "add",
      host: "typed.example.com",
      requestRule: { readOnly: false, methods: ["POST"], pathPrefixes: ["/v1/"], denyGitPush: true },
    });

    expect(added).toMatchObject({ changed: true, host: "typed.example.com", scope: "project" });
    expect(added.selection.subjects["network-project"]?.mechanism).toBe("typed-host-command");
    expect(JSON.parse(fs.readFileSync(projectPolicyPath, "utf8"))).toMatchObject({
      version: 2,
      hosts: ["project.example.com", "typed.example.com"],
      requests: { "typed.example.com": { methods: ["POST"], pathPrefixes: ["/v1/"], gitPush: "deny" } },
    });
    expect(fs.existsSync(localPolicyPath)).toBe(false);

    await mutateDesiredHost(context, io(), "project", {
      kind: "rules",
      host: "typed.example.com",
      clear: false,
      write: "ask",
    });
    await expect(readDesiredHostRules(context, io(), "project", "typed.example.com")).resolves.toMatchObject({
      rule: { methods: ["POST"], pathPrefixes: ["/v1/"], gitPush: "deny", writeAction: "ask" },
    });

    await mutateDesiredHost(context, io(), "project", { kind: "remove", host: "typed.example.com" });
    expect(JSON.parse(fs.readFileSync(projectPolicyPath, "utf8"))).toEqual({
      version: 2,
      hosts: ["project.example.com"],
    });
  });

  test("rejects out-of-transaction local drift without overwriting or approving it", async () => {
    fs.writeFileSync(localPolicyPath, '{"version":2,"hosts":["drift.example.com"]}\n');
    const before = fs.readFileSync(localPolicyPath, "utf8");
    const approvedBefore = readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest;

    await expect(mutateDesiredHost(context, io(), "local", { kind: "add", host: "new.example.com" }))
      .rejects.toThrow("local desired policy changed outside a trusted Runfree transaction");

    expect(fs.readFileSync(localPolicyPath, "utf8")).toBe(before);
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest).toBe(approvedBefore);
  });

  test("rejects out-of-transaction project drift without approving the typed delta", async () => {
    fs.writeFileSync(projectPolicyPath, '{"version":2,"hosts":["drift.example.com"]}\n');
    const before = fs.readFileSync(projectPolicyPath, "utf8");
    const approvedBefore = readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest;

    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "new.example.com" }))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");

    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(before);
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-project"]?.digest).toBe(approvedBefore);
  });

  test("does not remove or change a host supplied only by the project layer", async () => {
    const approvedBefore = readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest;

    await expect(mutateDesiredHost(context, io(), "local", { kind: "remove", host: "project.example.com" }))
      .rejects.toThrow("not allowlisted in checkout-local policy");
    await expect(mutateDesiredHost(context, io(), "local", {
      kind: "rules",
      host: "project.example.com",
      clear: false,
      write: "deny",
    })).rejects.toThrow("not allowlisted in checkout-local policy");

    expect(fs.existsSync(localPolicyPath)).toBe(false);
    expect(readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest).toBe(approvedBefore);
  });

  test("says a removed host is still allowlisted by the service that also provides it", async () => {
    // Direct authority is one of several owners. Removing the direct entry for
    // a service-provided host changes nothing the proxy enforces, so reporting
    // only "updated" would read as a revocation that did not happen.
    fs.writeFileSync(projectPolicyPath, JSON.stringify({
      version: 2,
      hosts: ["api.example.com", "project.example.com"],
      services: {
        api: {
          revision: 1,
          definitionDigest: `sha256:${"b".repeat(64)}`,
          resolved: { hosts: ["api.example.com"], requests: { "api.example.com": { writeAction: "deny", gitPush: "write" } } },
        },
      },
    }));
    approveDesiredBases();

    const result = await mutateDesiredHost(context, io(), "project", { kind: "remove", host: "api.example.com" });

    expect(result.changed).toBe(true);
    expect(result.warnings.join("\n")).toMatch(/still allowlisted by service:api/);
    expect(result.warnings.join("\n")).toMatch(/runfree service disable api/);
  });

  test("says a direct request rule replaced the whole rule a service owned", async () => {
    fs.writeFileSync(projectPolicyPath, JSON.stringify({
      version: 2,
      hosts: ["api.example.com"],
      services: {
        api: {
          revision: 1,
          definitionDigest: `sha256:${"b".repeat(64)}`,
          resolved: { hosts: ["api.example.com"], requests: { "api.example.com": { writeAction: "deny", gitPush: "write" } } },
        },
      },
    }));
    approveDesiredBases();

    const result = await mutateDesiredHost(context, io(), "project", {
      kind: "rules",
      host: "api.example.com",
      clear: false,
      write: "allow",
    });

    // The service's gitPush classification is gone, not merged with the new rule.
    expect(result.warnings.join("\n")).toMatch(/replaces the whole request rule service:api/);
    expect(result.warnings.join("\n")).toMatch(/gitPush/);
  });

  test("refuses a tracked local policy before changing either policy or exclude", async () => {
    expect(command("git", ["init", "-q", root]).status).toBe(0);
    fs.writeFileSync(localPolicyPath, '{"version":2,"hosts":[]}\n');
    expect(command("git", ["-C", root, "add", "-f", ".runfree/network-policy.local.json"]).status).toBe(0);
    const excludePath = path.join(root, ".git", "info", "exclude");
    const excludeBefore = fs.readFileSync(excludePath, "utf8");
    const policyBefore = fs.readFileSync(localPolicyPath, "utf8");

    await expect(mutateDesiredHost(context, io(), "local", { kind: "add", host: "new.example.com" }))
      .rejects.toThrow("checkout-local policy must remain untracked");

    expect(fs.readFileSync(localPolicyPath, "utf8")).toBe(policyBefore);
    expect(fs.readFileSync(excludePath, "utf8")).toBe(excludeBefore);
  });

  test("writes the anchored Git exclude before the first local policy mutation", async () => {
    expect(command("git", ["init", "-q", root]).status).toBe(0);
    await mutateDesiredHost(context, io(), "local", { kind: "add", host: "new.example.com" });

    const exclude = fs.readFileSync(path.join(root, ".git", "info", "exclude"), "utf8");
    expect(exclude.split(/\r?\n/)).toContain(LOCAL_POLICY_EXCLUDE_PATTERN);
    expect(localPolicy()).toMatchObject({ hosts: ["new.example.com"] });
  });

  test("the rules query never creates an approval as a side effect of a failed lookup", async () => {
    // A show-only command must not change durable authority. The mutation
    // paths may auto-approve an authority-free scaffold; a read may not.
    fs.rmSync(context.project.paths.controlApprovalsPath, { force: true });
    fs.writeFileSync(projectPolicyPath, '{"version":2,"hosts":[]}\n');

    await expect(readDesiredHostRules(context, io(), "project", "absent.example.com"))
      .rejects.toThrow("has no approved base");

    expect(fs.existsSync(context.project.paths.controlApprovalsPath)).toBe(false);
  });

  test("mutates and approves while a per-session agent is live, touching no container", async () => {
    writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: root,
      env: context.env,
    });

    const added = await mutateDesiredHost(context, io(), "project", { kind: "add", host: "live.example.com" });

    expect(added).toMatchObject({ changed: true, host: "live.example.com", scope: "project" });
    expect(added.selection.subjects["network-project"]?.mechanism).toBe("typed-host-command");
    await expect(readDesiredHostRules(context, io(), "project", "live.example.com")).resolves.toMatchObject({
      host: "live.example.com",
    });
  });
});
