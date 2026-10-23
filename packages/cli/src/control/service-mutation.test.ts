import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  type DesiredServiceEntry,
  withRequiredDesiredNetworkPolicyVersion,
} from "@runfree/runtime-contracts/desired-network-policy";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { SERVICES } from "../../../../scripts/services.ts";
import { desiredServiceEntry } from "../admin/service-policy.ts";
import { projectInfo } from "../config.ts";
import { writeLiveAttachedSessionContainerRecordFixture } from "../runtime/session-container.test-harness.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { approveNetworkCandidate, readControlApprovalSelection } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import { mutateDesiredService, reconcileDesiredService } from "./service-mutation.ts";

const digest = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;
const entry = (host: string, marker = "a"): DesiredServiceEntry => ({
  revision: 1,
  definitionDigest: digest(marker),
  resolved: {
    hosts: [host],
    requests: { [host]: { methods: ["GET"] } },
  },
});
const hostOnlyEntry = (host: string, marker = "a"): DesiredServiceEntry => ({
  revision: 1,
  definitionDigest: digest(marker),
  resolved: { hosts: [host] },
});

describe("desired service reconciliation", () => {
  test("replaces the complete entry instead of retaining stale resolved fields", () => {
    const current = {
      version: 2 as const,
      hosts: [],
      services: { api: entry("old.example.com") },
    };
    const result = reconcileDesiredService(current, {
      kind: "enable",
      id: "API",
      entry: entry("new.example.com", "b"),
    });

    expect(result.policy.services?.api).toEqual(entry("new.example.com", "b"));
    expect(JSON.stringify(result.policy)).not.toContain("old.example.com");
  });

  test("transfers an identical direct token to the enabling service so the pair compiles", () => {
    const token = {
      description: "GitHub API token",
      allowAnonymous: true,
      credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" as const }],
    };
    // The shape legacy migration produces: the service is recorded, but the
    // token it owns is still held directly because migration could not prove
    // which enable created it.
    const current = {
      version: 2 as const,
      hosts: ["api.github.com"],
      tokens: { github: token },
    };
    const result = reconcileDesiredService(current, {
      kind: "enable",
      id: "github",
      entry: {
        revision: 2,
        definitionDigest: digest("c"),
        resolved: { hosts: ["api.github.com"], tokens: { github: token } },
      },
    });

    expect(result.policy.tokens).toBeUndefined();
    expect(result.policy.services?.github.resolved.tokens?.github).toEqual(token);
    const compiled = compileDesiredPolicies({ project: result.policy, local: { version: 2, hosts: [] } });
    expect(compiled.policy.tokens?.github).toEqual(token);
    expect(compiled.provenance.tokens.github).toBe("service:github");
  });

  test("refuses to take over a direct token whose credential destination differs", () => {
    const current = {
      version: 2 as const,
      hosts: ["api.github.com", "uploads.github.com"],
      tokens: {
        github: {
          description: "GitHub API token",
          credentials: [{ host: "uploads.github.com", header: "Authorization", scheme: "bearer" as const }],
        },
      },
    };
    expect(() => reconcileDesiredService(current, {
      kind: "enable",
      id: "github",
      entry: {
        revision: 2,
        definitionDigest: digest("c"),
        resolved: {
          hosts: ["api.github.com"],
          tokens: {
            github: {
              description: "GitHub API token",
              credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" as const }],
            },
          },
        },
      },
    })).toThrow(/different credential destination/);
    // The direct destination the user configured survives an attempted takeover.
    expect(current.tokens.github.credentials[0].host).toBe("uploads.github.com");
  });

  test("local service provenance replaces project semantics and removal reveals project", () => {
    const project = { version: 2 as const, hosts: [], services: { api: entry("project.example.com") } };
    const localEnabled = reconcileDesiredService({ version: 2, hosts: [] }, {
      kind: "enable",
      id: "api",
      entry: entry("local.example.com", "b"),
    }).policy;
    const selected = compileDesiredPolicies({ project, local: localEnabled });
    expect(selected.policy.hosts).toEqual(["local.example.com"]);
    expect(selected.provenance.hosts["local.example.com"]).toEqual(["service:api"]);
    expect(selected.provenance.requests["local.example.com"]).toBe("service:api");
    expect(selected.selectedServices.api.definitionDigest).toBe(digest("b"));

    const localDisabled = reconcileDesiredService(localEnabled, { kind: "disable", id: "api" }).policy;
    const revealed = compileDesiredPolicies({ project, local: localDisabled });
    expect(revealed.policy.hosts).toEqual(["project.example.com"]);
    expect(revealed.selectedServices.api.definitionDigest).toBe(digest("a"));
  });

  test("disable removes only selected service ownership and preserves direct hosts, request rules, and a shared service", () => {
    const current = {
      version: 2 as const,
      hosts: ["registry.npmjs.org", "user-added.example.com"],
      requests: { "registry.npmjs.org": { methods: ["GET" as const] } },
      services: {
        node: desiredServiceEntry(SERVICES.node),
        mirror: hostOnlyEntry("registry.yarnpkg.com", "e"),
      },
    };
    const before = compileDesiredPolicies({ project: current, local: { version: 2, hosts: [] } });
    expect(before.provenance.hosts["registry.npmjs.org"]).toEqual(["direct", "service:node"]);
    expect(before.provenance.hosts["registry.yarnpkg.com"]).toEqual(["service:mirror", "service:node"]);

    const disabled = reconcileDesiredService(current, { kind: "disable", id: "node" }).policy;
    const after = compileDesiredPolicies({ project: disabled, local: { version: 2, hosts: [] } });

    expect(after.policy.hosts).toEqual([
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "user-added.example.com",
    ]);
    expect(after.policy.requests).toEqual({ "registry.npmjs.org": { methods: ["GET"] } });
    expect(after.provenance.hosts["registry.npmjs.org"]).toEqual(["direct"]);
    expect(after.provenance.hosts["registry.yarnpkg.com"]).toEqual(["service:mirror"]);
    expect(after.selectedServices).toEqual({ mirror: current.services.mirror });
  });

  test("disable is record-driven for an unavailable definition and refuses an absent record without mutation", () => {
    const unavailable = hostOnlyEntry("retired.example.com", "f");
    const current = {
      version: 2 as const,
      hosts: ["kept.example.com"],
      services: { retired: unavailable },
    };

    const disabled = reconcileDesiredService(current, { kind: "disable", id: "RETIRED" }).policy;
    expect(disabled).toEqual({ version: 2, hosts: ["kept.example.com"] });
    expect(compileDesiredPolicies({ project: disabled, local: { version: 2, hosts: [] } }).policy.hosts)
      .toEqual(["kept.example.com"]);

    const before = structuredClone(disabled);
    expect(() => reconcileDesiredService(disabled, { kind: "disable", id: "missing" }))
      .toThrow("missing service is not enabled in the selected desired policy layer");
    expect(disabled).toEqual(before);
  });

  test.each([
    ["github", SERVICES.github],
    ["appstore-connect", SERVICES["appstore-connect"]],
  ])("disable removes %s static credential links and placeholder declarations", (id, definition) => {
    // github's git-http Basic mapping needs desired version 3; the enable path
    // derives the version the same way.
    const current = withRequiredDesiredNetworkPolicyVersion({
      hosts: [],
      services: { [id]: desiredServiceEntry(definition) },
    });
    const before = compileDesiredPolicies({ project: current, local: { version: 2, hosts: [] } });
    expect(Object.keys(before.policy.tokens ?? {})).not.toHaveLength(0);
    expect(before.agentEnv).not.toHaveLength(0);

    const disabled = reconcileDesiredService(current, { kind: "disable", id }).policy;
    const after = compileDesiredPolicies({ project: disabled, local: { version: 2, hosts: [] } });
    expect(after.policy.hosts).toEqual([]);
    expect(Object.keys(after.policy.tokens ?? {})).toHaveLength(0);
    expect(after.policy.requests).toBeUndefined();
    expect(after.agentEnv).toEqual([]);
    expect(after.selectedServices).toEqual({});
  });

  test.each([
    ["google-ads", SERVICES["google-ads"]],
    ["apple-ads", SERVICES["apple-ads"]],
  ])("disable removes %s OAuth policy, seed credentials, endpoint rules, and agent env declarations", (id, definition) => {
    const current = {
      version: 2 as const,
      hosts: [],
      services: { [id]: desiredServiceEntry(definition) },
    };
    const before = compileDesiredPolicies({ project: current, local: { version: 2, hosts: [] } });
    expect(Object.keys(before.oauth)).not.toHaveLength(0);
    expect(Object.keys(before.policy.tokens ?? {})).not.toHaveLength(0);
    expect(Object.keys(before.policy.requests ?? {})).not.toHaveLength(0);
    expect(before.agentEnv).not.toHaveLength(0);

    const disabled = reconcileDesiredService(current, { kind: "disable", id }).policy;
    const after = compileDesiredPolicies({ project: disabled, local: { version: 2, hosts: [] } });
    expect(after.policy.hosts).toEqual([]);
    expect(Object.keys(after.policy.tokens ?? {})).toHaveLength(0);
    expect(after.policy.requests).toBeUndefined();
    expect(after.oauth).toEqual({});
    expect(after.agentEnv).toEqual([]);
  });

  test("disable removes the complete service-owned read-only request profile", () => {
    const current = {
      version: 3 as const,
      hosts: [],
      services: {
        github: desiredServiceEntry(SERVICES.github, { writeMode: "read-only" }),
      },
    };
    const before = compileDesiredPolicies({ project: current, local: { version: 2, hosts: [] } });
    expect(before.policy.requests?.["github.com"]).toEqual({ gitPush: "write", writeAction: "deny" });
    expect(before.policy.requests?.["api.github.com"]).toEqual({
      graphql: { endpoints: ["/graphql"], writeOps: "mutation" },
      writeAction: "deny",
    });

    const disabled = reconcileDesiredService(current, { kind: "disable", id: "github" }).policy;
    const after = compileDesiredPolicies({ project: disabled, local: { version: 2, hosts: [] } }).policy;
    expect(after.hosts).toEqual([]);
    expect(after.requests).toBeUndefined();
  });
});

describe("service host rules through the service lifecycle", () => {
  const ruled = (overrides: Partial<DesiredServiceEntry> = {}): DesiredServiceEntry => ({
    revision: 1,
    definitionDigest: digest("a"),
    selection: { hostRules: { "b.example.com": { gitPush: "deny" } } },
    resolved: {
      hosts: ["a.example.com", "b.example.com"],
      requests: { "b.example.com": { gitPush: "write" } },
    },
    ...overrides,
  });
  const rebuilt = (overrides: Partial<DesiredServiceEntry> = {}): DesiredServiceEntry => {
    const value = ruled(overrides);
    if (!overrides.selection) delete value.selection;
    return value;
  };
  const enabled = (policy: Record<string, unknown> = {}) => withRequiredDesiredNetworkPolicyVersion({
    version: 2 as const,
    hosts: [] as string[],
    services: { git: ruled() },
    ...policy,
  });

  test("a re-enable keeps the saved hostRules and the policy compiles with them", () => {
    const result = reconcileDesiredService(enabled(), { kind: "enable", id: "git", entry: rebuilt() });
    expect(result.policy.services?.git.selection?.hostRules).toEqual({ "b.example.com": { gitPush: "deny" } });
    expect(result.policy.version).toBe(4);
    expect(result.changed).toBe(false);
    const compiled = compileDesiredPolicies({ project: result.policy, local: { version: 2, hosts: [] } });
    expect(compiled.policy.requests?.["b.example.com"]).toEqual({ gitPush: "deny" });
  });

  test("a re-enable that skips a host with a setting refuses and names the clear", () => {
    expect(() => reconcileDesiredService(enabled(), {
      kind: "enable",
      id: "git",
      entry: rebuilt({
        selection: { skippedHosts: ["b.example.com"] },
        resolved: { hosts: ["a.example.com"] },
      }),
    })).toThrow(
      "--skip-host b.example.com cannot skip b.example.com in service git: it has a host rule setting; remove it first with: runfree host rules b.example.com --clear --service git",
    );
  });

  test("a new revision that removes a host with a setting refuses", () => {
    expect(() => reconcileDesiredService(enabled(), {
      kind: "enable",
      id: "git",
      entry: rebuilt({ revision: 2, resolved: { hosts: ["a.example.com"] } }),
    }, { layer: "local" })).toThrow(
      "service git revision 2 no longer allows b.example.com, which has a host rule setting; remove it first with: runfree host rules b.example.com --clear --service git --local",
    );
  });

  test("a setting broader than the new revision's OAuth rule refuses", () => {
    const current = withRequiredDesiredNetworkPolicyVersion({
      version: 2 as const,
      hosts: [] as string[],
      services: {
        oauth: {
          revision: 1,
          definitionDigest: digest("a"),
          selection: { hostRules: { "auth.example.com": { pathPrefixes: ["/oauth/token/v1"] } } },
          resolved: {
            hosts: ["auth.example.com"],
            requests: { "auth.example.com": { methods: ["POST" as const], pathPrefixes: ["/oauth/token"] } },
          },
        },
      },
    });
    expect(() => reconcileDesiredService(current, {
      kind: "enable",
      id: "oauth",
      entry: {
        revision: 2,
        definitionDigest: digest("b"),
        resolved: {
          hosts: ["auth.example.com"],
          requests: { "auth.example.com": { methods: ["POST"], pathPrefixes: ["/oauth/v2/token"] } },
        },
      },
    })).toThrow(
      /^the host rule setting for auth\.example\.com is broader than service oauth revision 2 allows \(pathPrefixes includes \/oauth\/token\/v1, .*\); remove it with: runfree host rules auth\.example\.com --clear --service oauth$/,
    );
  });

  test("disable removes the setting with the entry and the layer validates", () => {
    const result = reconcileDesiredService(enabled({ hosts: ["a.example.com"] }), { kind: "disable", id: "git" });
    expect(result.policy).toEqual({ version: 2, hosts: ["a.example.com"] });
    expect(JSON.stringify(result.policy)).not.toContain("hostRules");
  });

  test("an identical direct rule is taken over by the service; its hosts entry stays", () => {
    const result = reconcileDesiredService(withRequiredDesiredNetworkPolicyVersion({
      version: 2 as const,
      hosts: ["b.example.com"],
      requests: { "b.example.com": { gitPush: "deny" as const } },
      services: { git: ruled() },
    }), { kind: "enable", id: "git", entry: rebuilt() });
    expect(result.policy.requests).toBeUndefined();
    expect(result.policy.hosts).toEqual(["b.example.com"]);
    expect(result.warnings).toEqual([]);
    expect(result.notices).toEqual([
      "b.example.com: the direct rule matched service git's rule and now belongs to the service; service disable removes it",
    ]);
    const compiled = compileDesiredPolicies({ project: result.policy, local: { version: 2, hosts: [] } });
    expect(compiled.provenance.requests["b.example.com"]).toBe("service:git");
  });

  test("a different direct rule is kept with a warning naming the clear", () => {
    const current = {
      version: 2 as const,
      hosts: ["b.example.com"],
      requests: { "b.example.com": { writeAction: "allow" as const } },
    };
    const result = reconcileDesiredService(current, { kind: "enable", id: "git", entry: rebuilt() }, { layer: "local" });
    expect(result.policy.requests).toEqual({ "b.example.com": { writeAction: "allow" } });
    expect(result.notices).toEqual([]);
    expect(result.warnings).toEqual([
      "b.example.com has a direct rule that replaces the rule from service git; remove it with: runfree host rules b.example.com --clear --local",
    ]);
  });

  test("a direct rule on a service host without a service rule is not legacy", () => {
    const result = reconcileDesiredService({
      version: 2,
      hosts: ["a.example.com"],
      requests: { "a.example.com": { methods: ["GET"] } },
    }, { kind: "enable", id: "git", entry: rebuilt() });
    expect(result.warnings).toEqual([]);
    expect(result.notices).toEqual([]);
    expect(result.policy.requests).toEqual({ "a.example.com": { methods: ["GET"] } });
  });
});

describe("typed desired service mutation", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  const io: RuntimeIO = {
    capture: (_command, args) => {
      if (args[0] === "ps") return { status: 0, stdout: "", stderr: "" };
      throw new Error(`unexpected Docker call: ${args.join(" ")}`);
    },
    run: () => 0,
    commandExists: () => true,
    confirm: () => false,
    admin: async () => 0,
  };

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-service-mutation-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-service-mutation-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
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
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  test("writes and approves only the selected layer", async () => {
    const before = readControlApprovalSelection(root, context.project);
    const result = await mutateDesiredService(context, io, "local", {
      kind: "enable",
      id: "api",
      entry: entry("local.example.com"),
    });
    const written = JSON.parse(fs.readFileSync(path.join(root, ".runfree", "network-policy.local.json"), "utf8"));
    const after = readControlApprovalSelection(root, context.project);

    expect(written.services.api).toEqual(entry("local.example.com"));
    expect(result.selection.subjects["network-local"]?.digest).toBe(result.layerDigest);
    expect(after?.subjects["network-project"]?.digest).toBe(before?.subjects["network-project"]?.digest);
  });

  test("mutates the desired service while a per-session agent is live", async () => {
    writeLiveAttachedSessionContainerRecordFixture({
      stateDir: context.project.paths.stateDir,
      projectRoot: root,
      env: context.env,
    });

    const result = await mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    });

    expect(result.changed).toBe(true);
    expect(result.selection.subjects["network-project"]?.mechanism).toBe("typed-host-command");
  });

  test("leaves approval state unchanged when the selected service already matches", async () => {
    const mutation = {
      kind: "enable" as const,
      id: "api",
      entry: entry("api.example.com"),
    };
    await mutateDesiredService(context, io, "project", mutation);
    const before = fs.readFileSync(context.project.paths.controlApprovalsPath);

    const result = await mutateDesiredService(context, io, "project", mutation);

    expect(result.changed).toBe(false);
    expect(fs.readFileSync(context.project.paths.controlApprovalsPath)).toEqual(before);
  });

  test("refuses a non-empty layer with no approved base before any write", async () => {
    // The state a v3->v4 migration without a legacy enforced proof leaves
    // behind: desired authority exists, but nothing approved it.
    fs.rmSync(context.project.paths.controlApprovalsPath);
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["migrated.example.com"]}`);

    await expect(mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    })).rejects.toThrow("approve it with: runfree policy approve --project");
    expect(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8")).not.toContain("api.example.com");
    expect(fs.existsSync(context.project.paths.controlApprovalsPath)).toBe(false);
  });

  test("accepts the authority-free scaffold as the initial typed mutation base", async () => {
    fs.rmSync(context.project.paths.controlApprovalsPath);

    const result = await mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    });

    expect(result.changed).toBe(true);
    expect(result.selection.subjects["network-project"]?.mechanism).toBe("typed-host-command");
  });

  test("refuses to persist a layer pair the compiler rejects", async () => {
    const token = {
      description: "API token",
      credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer" as const }],
    };
    // The direct token sits in the project layer while the service is enabled
    // in local, so only a cross-layer compile can see the ownership clash.
    fs.writeFileSync(
      path.join(root, ".runfree", "network-policy.json"),
      JSON.stringify({ version: 2, hosts: ["api.example.com"], tokens: { api: token } }),
    );
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");

    await expect(mutateDesiredService(context, io, "local", {
      kind: "enable",
      id: "api",
      entry: {
        revision: 1,
        definitionDigest: digest("d"),
        resolved: { hosts: ["api.example.com"], tokens: { api: token } },
      },
    })).rejects.toThrow(/token api conflicts/);
    expect(fs.existsSync(path.join(root, ".runfree", "network-policy.local.json"))).toBe(false);
  });

  test("rejects unrelated drift before changing the selected layer", async () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["drift.example.com"]}`);
    await expect(mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    })).rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");
    expect(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8")).not.toContain("api.example.com");
  });

  test("refuses a tampered service record before it can steer disable cleanup", async () => {
    await mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("service.example.com"),
    });
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    const tampered = JSON.parse(fs.readFileSync(policyPath, "utf8")) as {
      services: Record<string, DesiredServiceEntry>;
    };
    tampered.services.api = {
      revision: 1,
      definitionDigest: digest("e"),
      selection: { writeMode: "read-only" },
      resolved: {
        hosts: ["unrelated.example.com"],
        requests: { "unrelated.example.com": { writeAction: "deny" } },
      },
    };
    fs.writeFileSync(policyPath, `${JSON.stringify(tampered, null, 2)}\n`);
    const before = fs.readFileSync(policyPath, "utf8");

    await expect(mutateDesiredService(context, io, "project", {
      kind: "disable",
      id: "api",
    })).rejects.toThrow(/project desired policy changed outside a trusted Runfree transaction/);
    expect(fs.readFileSync(policyPath, "utf8")).toBe(before);
  });

  test("a mismatched approval record refuses instead of planning against an empty baseline", async () => {
    const approvalsPath = context.project.paths.controlApprovalsPath;
    const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
    stored.checkoutBinding.rootInode = "999999999";
    const mismatched = `${JSON.stringify(stored, null, 2)}\n`;
    fs.writeFileSync(approvalsPath, mismatched);
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    const policyBefore = fs.readFileSync(policyPath, "utf8");

    await expect(mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    })).rejects.toThrow("the directory at this path was replaced");

    // Refusal before the sensitive side effect: neither the desired policy nor
    // the approvals record moved.
    expect(fs.readFileSync(policyPath, "utf8")).toBe(policyBefore);
    expect(fs.readFileSync(approvalsPath, "utf8")).toBe(mismatched);
  });

  test("a mismatched record is not silently auto-approved through the authority-free base", async () => {
    // The local layer is authority-free here, which is the shape
    // readOrApproveAuthorityFreeNetworkBase auto-approves. Under a mismatch it
    // must refuse before that write, not mint a fresh record.
    const approvalsPath = context.project.paths.controlApprovalsPath;
    const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as {
      checkoutBinding: { rootInode: string };
      subjects: Record<string, unknown>;
    };
    delete stored.subjects["network-local"];
    stored.checkoutBinding.rootInode = "999999999";
    const mismatched = `${JSON.stringify(stored, null, 2)}\n`;
    fs.writeFileSync(approvalsPath, mismatched);

    await expect(mutateDesiredService(context, io, "local", {
      kind: "enable",
      id: "api",
      entry: entry("local.example.com"),
    })).rejects.toThrow("the directory at this path was replaced");
    expect(fs.readFileSync(approvalsPath, "utf8")).toBe(mismatched);
  });
  test("a re-enable that skips a ruled host refuses before any write or host-state bind", async () => {
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    const ruledEntry: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest("a"),
      selection: { hostRules: { "b.example.com": { writeAction: "deny" } } },
      resolved: { hosts: ["a.example.com", "b.example.com"] },
    };
    fs.writeFileSync(policyPath, JSON.stringify({ version: 4, hosts: [], services: { git: ruledEntry } }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    const before = fs.readFileSync(policyPath, "utf8");
    const approvalsBefore = fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8");
    let bound = false;

    await expect(mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "git",
      entry: {
        revision: 1,
        definitionDigest: digest("a"),
        selection: { skippedHosts: ["b.example.com"] },
        resolved: { hosts: ["a.example.com"] },
      },
    }, {
      beforeWrite: () => {
        bound = true;
        return undefined;
      },
    })).rejects.toThrow("--skip-host b.example.com cannot skip b.example.com in service git: it has a host rule setting");
    expect(bound).toBe(false);
    expect(fs.readFileSync(policyPath, "utf8")).toBe(before);
    expect(fs.readFileSync(context.project.paths.controlApprovalsPath, "utf8")).toBe(approvalsBefore);
  });

  test("warns about a direct rule in the other layer that replaces the service rule", async () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.local.json"), JSON.stringify({
      version: 2,
      hosts: ["api.example.com"],
      requests: { "api.example.com": { writeAction: "allow" } },
    }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");

    const result = await mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    });

    expect(result.warnings).toEqual([
      "api.example.com has a direct rule that replaces the rule from service api; remove it with: runfree host rules api.example.com --clear --local",
    ]);
    expect(result.notices).toEqual([]);
  });

  test("takes over an identical same-layer direct rule and reports it", async () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      version: 2,
      hosts: ["api.example.com"],
      requests: { "api.example.com": { methods: ["GET"] } },
    }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");

    const result = await mutateDesiredService(context, io, "project", {
      kind: "enable",
      id: "api",
      entry: entry("api.example.com"),
    });

    const written = JSON.parse(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8"));
    expect(written.requests).toBeUndefined();
    expect(written.hosts).toEqual(["api.example.com"]);
    expect(result.warnings).toEqual([]);
    expect(result.notices).toEqual([
      "api.example.com: the direct rule matched service api's rule and now belongs to the service; service disable removes it",
    ]);
  });
});
