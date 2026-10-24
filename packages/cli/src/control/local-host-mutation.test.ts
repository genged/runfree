import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  withRequiredDesiredNetworkPolicyVersion,
  type DesiredNetworkPolicyJson,
  type DesiredServiceEntry,
} from "@runfree/runtime-contracts/desired-network-policy";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { service as registryService } from "../../../../scripts/services.ts";
import { desiredServiceEntry } from "../admin/service-policy.ts";
import { projectInfo } from "../config.ts";
import { writeLiveAttachedSessionContainerRecordFixture } from "../runtime/session-container.test-harness.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { approveNetworkCandidate, readControlApprovalSelection } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import { LOCAL_POLICY_EXCLUDE_PATTERN } from "./git-exclude.ts";
import { mutateDesiredHost, readDesiredHostRules } from "./local-host-mutation.ts";

type RequestRuleFlags = { readOnly: boolean; methods: string[]; pathPrefixes: string[]; denyGitPush: boolean };

const DIGEST = `sha256:${"b".repeat(64)}`;

function registryEntry(id: string, selection: { skippedHosts?: string[]; writeMode?: "allow-write" | "read-only" } = {}): DesiredServiceEntry {
  const svc = registryService(id);
  if (!svc) throw new Error(`no registry service ${id}`);
  return desiredServiceEntry(svc, selection);
}

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

  function projectPolicy(): Record<string, unknown> {
    return JSON.parse(fs.readFileSync(projectPolicyPath, "utf8")) as Record<string, unknown>;
  }

  function readLayer(file: string): DesiredNetworkPolicyJson {
    return fs.existsSync(file)
      ? JSON.parse(fs.readFileSync(file, "utf8")) as DesiredNetworkPolicyJson
      : { version: 2, hosts: [] };
  }

  // Writes and approves both layers, as a typed command would have left them.
  function useLayers(project: Omit<DesiredNetworkPolicyJson, "version">, local?: Omit<DesiredNetworkPolicyJson, "version">): void {
    fs.writeFileSync(projectPolicyPath, `${JSON.stringify(withRequiredDesiredNetworkPolicyVersion(project))}\n`);
    if (local) fs.writeFileSync(localPolicyPath, `${JSON.stringify(withRequiredDesiredNetworkPolicyVersion(local))}\n`);
    approveDesiredBases();
  }

  function compiledRule(host: string) {
    return compileDesiredPolicies({ project: readLayer(projectPolicyPath), local: readLayer(localPolicyPath) }).policy.requests?.[host];
  }

  function hostRulesOf(file: string, id: string): unknown {
    return readLayer(file).services?.[id]?.selection?.hostRules;
  }

  // Both files' bytes and both approval digests: a refusal must change none.
  function state(): string {
    const selection = readControlApprovalSelection(root, context.project);
    return JSON.stringify({
      project: fs.readFileSync(projectPolicyPath, "utf8"),
      local: fs.existsSync(localPolicyPath) ? fs.readFileSync(localPolicyPath, "utf8") : null,
      approvedProject: selection?.subjects["network-project"]?.digest,
      approvedLocal: selection?.subjects["network-local"]?.digest,
    });
  }

  async function refusesUnchanged(run: () => Promise<unknown>, message: string | RegExp): Promise<void> {
    const before = state();
    await expect(run()).rejects.toThrow(message);
    expect(state()).toBe(before);
  }

  function rules(host: string, flags: Partial<RequestRuleFlags> & { write?: "allow" | "ask" | "deny"; service?: string } = {}) {
    const { write, service, ...rule } = flags;
    const requestRule = { readOnly: false, methods: [], pathPrefixes: [], denyGitPush: false, ...rule };
    const hasRule = requestRule.readOnly || requestRule.methods.length > 0 || requestRule.pathPrefixes.length > 0 || requestRule.denyGitPush;
    return {
      kind: "rules" as const,
      host,
      clear: false,
      ...(hasRule ? { requestRule } : {}),
      ...(write ? { write } : {}),
      ...(service ? { service } : {}),
    };
  }

  function clear(host: string, service?: string) {
    return { kind: "rules" as const, host, clear: true, ...(service ? { service } : {}) };
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
      enforced: { methods: ["GET", "HEAD", "OPTIONS"], writeAction: "deny" },
      owner: "direct",
      ownerLayer: "local",
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
      enforced: { methods: ["POST"], pathPrefixes: ["/v1/"], gitPush: "deny", writeAction: "ask" },
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

  test("refuses to add a host using the reserved runfree.internal suffix before any file write (SR4/A1)", async () => {
    const beforeProject = fs.readFileSync(projectPolicyPath, "utf8");
    expect(fs.existsSync(localPolicyPath)).toBe(false);

    await expect(mutateDesiredHost(context, io(), "project", { kind: "add", host: "x.runfree.internal" }))
      .rejects.toThrow("reserved runfree.internal suffix");

    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(beforeProject);
    expect(fs.existsSync(localPolicyPath)).toBe(false);
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

  test("a rule set on a host a service provides goes to the service, not over it", async () => {
    // The host also has a direct hosts entry, but no direct rule: the service
    // owns the rule (spec §4.4), so the setting is laid over its gitPush
    // classification instead of replacing it.
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

    expect(result).toMatchObject({
      changed: true,
      owner: "service:api",
      ownerLayer: "project",
      before: { writeAction: "deny", gitPush: "write" },
      after: { writeAction: "allow", gitPush: "write" },
      warnings: [],
    });
    const written = projectPolicy();
    expect(written.version).toBe(4);
    expect(written.requests).toBeUndefined();
    expect(written.services).toMatchObject({ api: { selection: { hostRules: { "api.example.com": { writeAction: "allow" } } } } });
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

  // Spec 2026-10-23 service host rules §6. The numbers name the spec's items.
  describe("request rules on service hosts", () => {
    test("1: --deny-git-push on a service-only host writes the service's hostRules at version 4 (G5)", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });
      const resolvedBefore = readLayer(projectPolicyPath).services?.github?.resolved;

      const result = await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));

      expect(result).toMatchObject({
        changed: true,
        owner: "service:github",
        ownerLayer: "project",
        before: { gitPush: "write" },
        after: { gitPush: "deny" },
        warnings: [],
      });
      const written = readLayer(projectPolicyPath);
      expect(written.version).toBe(4);
      expect(written.hosts).toEqual([]);
      expect(written.requests).toBeUndefined();
      expect(written.services?.github?.selection).toEqual({ hostRules: { "github.com": { gitPush: "deny" } } });
      expect(written.services?.github?.resolved).toEqual(resolvedBefore);
      expect(compiledRule("github.com")).toEqual({ gitPush: "deny" });
      await expect(readDesiredHostRules(context, io(), "project", "github.com")).resolves.toEqual({
        host: "github.com",
        scope: "project",
        owner: "service:github",
        ownerLayer: "project",
        enforced: { gitPush: "deny" },
        serviceRule: { gitPush: "write" },
        userSetting: { gitPush: "deny" },
      });
    });

    test("2: every permission flag and --write patch a gitlab-shaped host and keep its graphql classification", async () => {
      useLayers({ hosts: [], services: { gitlab: registryEntry("gitlab") } });
      const serviceRule = readLayer(projectPolicyPath).services?.gitlab?.resolved.requests?.["gitlab.com"];
      expect(serviceRule?.graphql).toBeDefined();

      await mutateDesiredHost(context, io(), "project", rules("gitlab.com", { methods: ["get", "POST"] }));
      await mutateDesiredHost(context, io(), "project", rules("gitlab.com", { pathPrefixes: ["/api/"] }));
      await mutateDesiredHost(context, io(), "project", rules("gitlab.com", { denyGitPush: true }));
      await mutateDesiredHost(context, io(), "project", rules("gitlab.com", { write: "deny" }));
      expect(hostRulesOf(projectPolicyPath, "gitlab")).toEqual({
        "gitlab.com": { gitPush: "deny", methods: ["GET", "POST"], pathPrefixes: ["/api/"], writeAction: "deny" },
      });
      await mutateDesiredHost(context, io(), "project", rules("gitlab.com", { readOnly: true }));

      expect(compiledRule("gitlab.com")).toEqual({
        ...serviceRule,
        gitPush: "deny",
        methods: ["GET", "HEAD", "OPTIONS"],
        pathPrefixes: ["/api/"],
        writeAction: "deny",
      });
      expect(compiledRule("gitlab.com")?.graphql).toEqual(serviceRule?.graphql);
    });

    test("3: --clear removes the setting, restores the service rule, and lowers the version", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });
      const versionBefore = readLayer(projectPolicyPath).version;
      await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));
      expect(readLayer(projectPolicyPath).version).toBe(4);

      const cleared = await mutateDesiredHost(context, io(), "project", clear("github.com"));

      expect(cleared).toMatchObject({ changed: true, owner: "service:github", before: { gitPush: "deny" }, after: { gitPush: "write" } });
      const written = readLayer(projectPolicyPath);
      expect(written.version).toBe(versionBefore);
      expect(written.services?.github?.selection).toBeUndefined();
      expect(compiledRule("github.com")).toEqual({ gitPush: "write" });
      // Nothing left to clear: unchanged, not a refusal.
      await expect(mutateDesiredHost(context, io(), "project", clear("github.com"))).resolves.toMatchObject({ changed: false });
    });

    test("3: --clear keeps the service's other settings", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github", { writeMode: "read-only" }) } });
      await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));
      await mutateDesiredHost(context, io(), "project", rules("api.github.com", { write: "ask" }));

      await mutateDesiredHost(context, io(), "project", clear("github.com"));

      expect(readLayer(projectPolicyPath).services?.github?.selection).toEqual({
        hostRules: { "api.github.com": { writeAction: "ask" } },
        writeMode: "read-only",
      });
    });

    test("4: a legacy direct rule refuses a set with no change; --clear removes it, then the set succeeds", async () => {
      useLayers({
        hosts: ["github.com"],
        requests: { "github.com": { writeAction: "allow" } },
        services: { github: registryEntry("github") },
      });

      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true })),
        "github.com has a direct rule that replaces the rule from service github; remove it with: runfree host rules github.com --clear",
      );

      const cleared = await mutateDesiredHost(context, io(), "project", clear("github.com"));
      expect(cleared).toMatchObject({ changed: true, before: { writeAction: "allow" }, after: { gitPush: "write" }, owner: "service:github" });
      expect(readLayer(projectPolicyPath)).toMatchObject({ hosts: ["github.com"] });
      expect(readLayer(projectPolicyPath).requests).toBeUndefined();

      await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));
      expect(hostRulesOf(projectPolicyPath, "github")).toEqual({ "github.com": { gitPush: "deny" } });
      expect(compiledRule("github.com")).toEqual({ gitPush: "deny" });
    });

    test("4: a legacy direct rule in the other layer is named by its own --clear, which reclaims it", async () => {
      useLayers(
        { hosts: [], services: { github: registryEntry("github") } },
        { hosts: ["github.com"], requests: { "github.com": { writeAction: "allow" } } },
      );
      const legacy = "github.com has a direct rule that replaces the rule from service github; remove it with: runfree host rules github.com --clear --local";

      await refusesUnchanged(() => mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true })), legacy);
      await refusesUnchanged(() => mutateDesiredHost(context, io(), "project", clear("github.com")), legacy);

      await mutateDesiredHost(context, io(), "local", clear("github.com"));
      expect(readLayer(localPolicyPath).requests).toBeUndefined();
      await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));
      expect(compiledRule("github.com")).toEqual({ gitPush: "deny" });
    });

    test("8: on an OAuth token host a narrower setting is accepted and a broader one refused before any write", async () => {
      useLayers({ hosts: [], services: { "google-ads": registryEntry("google-ads") } });
      expect(compiledRule("oauth2.googleapis.com")).toEqual({ methods: ["POST"], pathPrefixes: ["/token"] });

      await mutateDesiredHost(context, io(), "project", rules("oauth2.googleapis.com", { methods: ["POST"], pathPrefixes: ["/token/v2"] }));
      expect(compiledRule("oauth2.googleapis.com")).toEqual({ methods: ["POST"], pathPrefixes: ["/token/v2"] });

      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("oauth2.googleapis.com", { methods: ["GET"] })),
        "service google-ads sets the methods or path prefixes for oauth2.googleapis.com, and a host rule there can only narrow them: methods includes GET, which the service rule does not allow (service methods: POST)",
      );
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("oauth2.googleapis.com", { readOnly: true })),
        /can only narrow them: methods includes GET/,
      );
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("oauth2.googleapis.com", { pathPrefixes: ["/other"] })),
        /pathPrefixes includes \/other, which is not under a service path prefix \(service pathPrefixes: \/token\)/,
      );
      // A writeAction only is not a method or path widening.
      await mutateDesiredHost(context, io(), "project", rules("oauth2.googleapis.com", { write: "ask" }));
      expect(compiledRule("oauth2.googleapis.com")).toEqual({ methods: ["POST"], pathPrefixes: ["/token/v2"], writeAction: "ask" });
    });

    test("9: two services on one host refuse without --service and accept the service that owns the rule", async () => {
      const shared = (requests?: DesiredServiceEntry["resolved"]["requests"]): DesiredServiceEntry => ({
        revision: 1,
        definitionDigest: DIGEST,
        resolved: { hosts: ["shared.example.com"], ...(requests ? { requests } : {}) },
      });
      useLayers({ hosts: [], services: { alpha: shared({ "shared.example.com": { gitPush: "write" } }), beta: shared() } });

      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("shared.example.com", { denyGitPush: true })),
        /provided by 2 services \(alpha, beta\)[\s\S]*runfree host rules shared\.example\.com --deny-git-push --service alpha[\s\S]*runfree host rules shared\.example\.com --deny-git-push --service beta/,
      );
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("shared.example.com", { denyGitPush: true, service: "beta" })),
        /already has a request rule from service alpha/,
      );
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("shared.example.com", { denyGitPush: true, service: "gamma" })),
        "service gamma does not provide shared.example.com; services that provide it: alpha, beta",
      );

      const result = await mutateDesiredHost(context, io(), "project", rules("shared.example.com", { denyGitPush: true, service: "alpha" }));
      expect(result).toMatchObject({ changed: true, owner: "service:alpha" });
      expect(hostRulesOf(projectPolicyPath, "alpha")).toEqual({ "shared.example.com": { gitPush: "deny" } });
      expect(hostRulesOf(projectPolicyPath, "beta")).toBeUndefined();
      expect(compiledRule("shared.example.com")).toEqual({ gitPush: "deny" });
    });

    test("9: with no service rule on the host, --service picks the owner", async () => {
      const shared: DesiredServiceEntry = { revision: 1, definitionDigest: DIGEST, resolved: { hosts: ["shared.example.com"] } };
      useLayers({ hosts: [], services: { alpha: shared, beta: shared } });

      await mutateDesiredHost(context, io(), "project", rules("shared.example.com", { write: "deny", service: "beta" }));

      expect(hostRulesOf(projectPolicyPath, "beta")).toEqual({ "shared.example.com": { writeAction: "deny" } });
      expect(compiledRule("shared.example.com")).toEqual({ writeAction: "deny" });
      await mutateDesiredHost(context, io(), "project", clear("shared.example.com"));
      expect(hostRulesOf(projectPolicyPath, "beta")).toBeUndefined();
    });

    test("10: --local against a project service refuses, and a project write against a local service refuses", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "local", rules("github.com", { denyGitPush: true })),
        "github.com gets its request rules from service github, which is enabled in the project desired policy; run the command without --local: runfree host rules github.com --deny-git-push --service github",
      );
      expect(fs.existsSync(localPolicyPath)).toBe(false);

      useLayers({ hosts: [] }, { hosts: [], services: { github: registryEntry("github") } });
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true })),
        "github.com gets its request rules from service github, which is enabled in the checkout-local desired policy; run the command with --local: runfree host rules github.com --deny-git-push --service github --local",
      );
      await mutateDesiredHost(context, io(), "local", rules("github.com", { denyGitPush: true }));
      expect(hostRulesOf(localPolicyPath, "github")).toEqual({ "github.com": { gitPush: "deny" } });
      await expect(readDesiredHostRules(context, io(), "project", "github.com")).resolves.toMatchObject({
        owner: "service:github",
        ownerLayer: "local",
        enforced: { gitPush: "deny" },
      });
    });

    test("12: host remove on a service-only host refuses with the remedy; an unskippable host gets no --skip-host", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github", { skippedHosts: ["codeload.github.com"], writeMode: "read-only" }) } });

      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", { kind: "remove", host: "avatars.githubusercontent.com" }),
        [
          "avatars.githubusercontent.com is allowlisted by service github, not by a host entry in project policy",
          "remove the service with: runfree service disable github",
          "or keep the service without this host: runfree service enable github --skip-host avatars.githubusercontent.com --skip-host codeload.github.com --read-only",
        ].join("\n"),
      );
      const before = state();
      const refusal = await mutateDesiredHost(context, io(), "project", { kind: "remove", host: "github.com" }).catch((error: Error) => error);
      expect(state()).toBe(before);
      expect(refusal).toBeInstanceOf(Error);
      expect((refusal as Error).message).toBe([
        "github.com is allowlisted by service github, not by a host entry in project policy",
        "remove the service with: runfree service disable github",
        "service github cannot skip github.com: it receives the github credential",
      ].join("\n"));
    });

    test("12: a local service names the --local forms", async () => {
      useLayers({ hosts: [] }, { hosts: [], services: { github: registryEntry("github") } });
      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "local", { kind: "remove", host: "avatars.githubusercontent.com" }),
        /runfree service disable github --local\nor keep the service without this host: runfree service enable github --skip-host avatars\.githubusercontent\.com --local$/,
      );
    });

    test("14: on a direct host, set flags patch their own fields and --clear removes the whole rule", async () => {
      useLayers({ hosts: ["a.example.com"] });

      await mutateDesiredHost(context, io(), "project", rules("a.example.com", { denyGitPush: true }));
      const patched = await mutateDesiredHost(context, io(), "project", rules("a.example.com", { methods: ["GET"] }));
      expect(patched).toMatchObject({ owner: "direct", ownerLayer: "project", before: { gitPush: "deny" }, after: { gitPush: "deny", methods: ["GET"] } });
      await mutateDesiredHost(context, io(), "project", rules("a.example.com", { methods: ["POST", "PUT"] }));
      expect(projectPolicy().requests).toEqual({ "a.example.com": { gitPush: "deny", methods: ["POST", "PUT"] } });

      await mutateDesiredHost(context, io(), "project", clear("a.example.com"));
      expect(projectPolicy()).toEqual({ version: 2, hosts: ["a.example.com"] });
    });

    test("14: on a service host, set flags patch the setting and --clear removes it", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });

      await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));
      await mutateDesiredHost(context, io(), "project", rules("github.com", { methods: ["GET"] }));
      expect(hostRulesOf(projectPolicyPath, "github")).toEqual({ "github.com": { gitPush: "deny", methods: ["GET"] } });
      await mutateDesiredHost(context, io(), "project", rules("github.com", { methods: ["GET", "POST"] }));
      expect(compiledRule("github.com")).toEqual({ gitPush: "deny", methods: ["GET", "POST"] });

      await mutateDesiredHost(context, io(), "project", clear("github.com"));
      expect(compiledRule("github.com")).toEqual({ gitPush: "write" });
    });

    test("14: host add with rule flags patches a direct rule, and refuses on a service host", async () => {
      useLayers({ hosts: ["a.example.com"], requests: { "a.example.com": { gitPush: "deny" } }, services: { github: registryEntry("github") } });

      await mutateDesiredHost(context, io(), "project", {
        kind: "add",
        host: "a.example.com",
        requestRule: { readOnly: true, methods: [], pathPrefixes: [], denyGitPush: false },
      });
      expect(projectPolicy().requests).toEqual({ "a.example.com": { gitPush: "deny", methods: ["GET", "HEAD", "OPTIONS"] } });

      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", {
          kind: "add",
          host: "github.com",
          requestRule: { readOnly: false, methods: [], pathPrefixes: [], denyGitPush: true },
        }),
        "github.com gets its request rules from service github; add it without rule flags and set them with: runfree host rules github.com --deny-git-push --service github",
      );
      // Without rule flags, add still writes only the direct hosts entry.
      await mutateDesiredHost(context, io(), "project", { kind: "add", host: "github.com" });
      expect(projectPolicy()).toMatchObject({ hosts: ["a.example.com", "github.com"] });
      expect(compiledRule("github.com")).toEqual({ gitPush: "write" });
    });

    test("show reads any host the layer pair allows, from the other layer's approved policy", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } }, { hosts: ["local.example.com"] });

      await expect(readDesiredHostRules(context, io(), "local", "github.com")).resolves.toMatchObject({
        owner: "service:github",
        ownerLayer: "project",
        enforced: { gitPush: "write" },
        serviceRule: { gitPush: "write" },
      });
      await expect(readDesiredHostRules(context, io(), "project", "local.example.com")).resolves.toEqual({
        host: "local.example.com",
        owner: "none",
        scope: "project",
      });
      await expect(readDesiredHostRules(context, io(), "project", "absent.example.com"))
        .rejects.toThrow("absent.example.com is not allowlisted in project or checkout-local policy");
    });

    test("14: host add with rule flags on a service host the service sets no rule for patches the direct rule (C4, R3)", async () => {
      const plain: DesiredServiceEntry = { revision: 1, definitionDigest: DIGEST, resolved: { hosts: ["plain.example.com"] } };
      useLayers({ hosts: ["plain.example.com"], requests: { "plain.example.com": { writeAction: "ask" } }, services: { plain } });

      const result = await mutateDesiredHost(context, io(), "project", {
        kind: "add",
        host: "plain.example.com",
        requestRule: { readOnly: false, methods: [], pathPrefixes: [], denyGitPush: true },
      });

      expect(result).toMatchObject({ changed: true, owner: "direct", after: { gitPush: "deny", writeAction: "ask" } });
      expect(projectPolicy().requests).toEqual({ "plain.example.com": { gitPush: "deny", writeAction: "ask" } });
      expect(hostRulesOf(projectPolicyPath, "plain")).toBeUndefined();
    });

    test("--deny-git-push on a service host without git handling refuses before any write; its remedy succeeds (S3)", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });
      expect(compiledRule("avatars.githubusercontent.com")?.gitPush).toBeUndefined();
      const remedy = "runfree host rules avatars.githubusercontent.com --write deny --service github";

      await refusesUnchanged(
        () => mutateDesiredHost(context, io(), "project", rules("avatars.githubusercontent.com", { denyGitPush: true })),
        `service github has no git handling for avatars.githubusercontent.com, so --deny-git-push cannot be set there; restrict it with --method or --write deny instead, e.g.: ${remedy}`,
      );

      await mutateDesiredHost(context, io(), "project", rules("avatars.githubusercontent.com", { write: "deny", service: "github" }));
      expect(hostRulesOf(projectPolicyPath, "github")).toEqual({ "avatars.githubusercontent.com": { writeAction: "deny" } });
      expect(compiledRule("avatars.githubusercontent.com")).toEqual({ writeAction: "deny" });
    });

    test("show with --service refuses a service that does not provide the host and shows for one that does (C2)", async () => {
      useLayers({ hosts: ["a.example.com"], services: { github: registryEntry("github") } });

      await expect(readDesiredHostRules(context, io(), "project", "github.com", "gitlab"))
        .rejects.toThrow("service gitlab does not provide github.com; services that provide it: github");
      await expect(readDesiredHostRules(context, io(), "project", "a.example.com", "github"))
        .rejects.toThrow("service github does not provide a.example.com; no enabled service provides it");
      await expect(readDesiredHostRules(context, io(), "project", "github.com", "GitHub")).resolves.toMatchObject({
        owner: "service:github",
        enforced: { gitPush: "write" },
      });
    });

    test("--clear --service naming a service with no setting for the host says so and changes nothing (C5)", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });
      const before = state();

      const result = await mutateDesiredHost(context, io(), "project", clear("github.com", "github"));

      expect(result).toMatchObject({ changed: false, notices: ["service github has no host rule setting for github.com"] });
      expect(state()).toBe(before);
      // Without --service, nothing to clear stays silent.
      await expect(mutateDesiredHost(context, io(), "project", clear("github.com"))).resolves.toMatchObject({ changed: false, notices: [] });
    });

    test("--clear reaches a project setting that a same-id local service entry replaces", async () => {
      // The local entry shadows the project entry in the compiled policy, but
      // a project-layer `service diff --apply` still checks the project
      // setting and names this command as the way out, so it must work.
      const ruled = { ...registryEntry("github"), selection: { hostRules: { "github.com": { gitPush: "deny" as const } } } };
      useLayers({ hosts: [], services: { github: ruled } }, { hosts: [], services: { github: registryEntry("github") } });

      const cleared = await mutateDesiredHost(context, io(), "project", clear("github.com", "github"));

      expect(cleared).toMatchObject({ changed: true });
      expect(readLayer(projectPolicyPath).services?.github?.selection).toBeUndefined();
      expect(readLayer(localPolicyPath).services?.github).toEqual(registryEntry("github"));
    });

    test("the owner and rules a set prints read the other layer's approved policy, not its unapproved file (R1, S5)", async () => {
      useLayers({ hosts: [], services: { github: registryEntry("github") } });
      // Unapproved local drift: a local github entry would replace the
      // project entry, so a display read from it would print a local owner
      // and the service's unrestricted rule.
      const drift = `${JSON.stringify(withRequiredDesiredNetworkPolicyVersion({
        hosts: [],
        services: { github: registryEntry("github") },
      }))}\n`;
      fs.writeFileSync(localPolicyPath, drift);

      const result = await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));

      expect(result).toMatchObject({
        owner: "service:github",
        ownerLayer: "project",
        before: { gitPush: "write" },
        after: { gitPush: "deny" },
        warnings: [],
      });
      expect(hostRulesOf(projectPolicyPath, "github")).toEqual({ "github.com": { gitPush: "deny" } });
      expect(fs.readFileSync(localPolicyPath, "utf8")).toBe(drift);
    });

    test("owner resolution reads the other layer's approved policy, not its unapproved file (R1)", async () => {
      useLayers({ hosts: ["github.com"] });
      // Unapproved local drift that would make github.com a local service host.
      const drift = `${JSON.stringify(withRequiredDesiredNetworkPolicyVersion({
        hosts: [],
        services: { github: registryEntry("github") },
      }))}\n`;
      fs.writeFileSync(localPolicyPath, drift);
      const approvedLocal = readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest;

      const result = await mutateDesiredHost(context, io(), "project", rules("github.com", { denyGitPush: true }));

      // The approved local layer has no service, so the host is direct.
      expect(result.owner).toBe("direct");
      expect(projectPolicy().requests).toEqual({ "github.com": { gitPush: "deny" } });
      expect(fs.readFileSync(localPolicyPath, "utf8")).toBe(drift);
      expect(readControlApprovalSelection(root, context.project)?.subjects["network-local"]?.digest).toBe(approvedLocal);
    });
  });
});
