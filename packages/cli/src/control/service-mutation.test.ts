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
    })).toThrow(/service github would send it to different destinations:/);
    // The direct destination the user configured survives an attempted takeover.
    expect(current.tokens.github.credentials[0].host).toBe("uploads.github.com");
  });

  test("takes over a direct token whose destinations match and only the description differs", () => {
    const credentials = [{ host: "api.github.com", header: "Authorization", scheme: "bearer" as const }];
    const current = {
      version: 2 as const,
      hosts: ["api.github.com"],
      tokens: { github: { description: "my hand-written GitHub token", allowAnonymous: true, credentials } },
    };
    const serviceToken = { description: "GitHub API token", allowAnonymous: true, credentials };
    const result = reconcileDesiredService(current, {
      kind: "enable",
      id: "github",
      entry: {
        revision: 2,
        definitionDigest: digest("c"),
        resolved: { hosts: ["api.github.com"], tokens: { github: serviceToken } },
      },
    });

    expect(result.policy.tokens).toBeUndefined();
    expect(result.policy.services?.github.resolved.tokens?.github).toEqual(serviceToken);
    expect(result.notices).toEqual([
      'token github: the direct token had the same destinations as service github and now belongs to the service; its description changes to "GitHub API token"; service disable removes it',
    ]);
  });

  test("refuses a takeover that would change whether requests without a stored token go out", () => {
    const credentials = [{ host: "api.github.com", header: "Authorization", scheme: "bearer" as const }];
    const current = {
      version: 2 as const,
      hosts: ["api.github.com"],
      tokens: { github: { description: "GitHub API token", credentials } },
    };
    let message = "";
    try {
      reconcileDesiredService(current, {
        kind: "enable",
        id: "github",
        entry: {
          revision: 2,
          definitionDigest: digest("c"),
          resolved: { hosts: ["api.github.com"], tokens: { github: { description: "GitHub API token", allowAnonymous: true, credentials } } },
        },
      });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("and service github sends it differently:");
    expect(message).toMatch(/requests with no token stored\s+refused\s+sent anonymously/);
    expect(current.tokens.github).toEqual({ description: "GitHub API token", credentials });
  });

  test("the conflict refusal shows both destination sets, the layer and file, and every reclaim path", () => {
    const current = {
      version: 2 as const,
      hosts: ["api.github.com", "raw.githubusercontent.com"],
      tokens: {
        github: {
          description: "Read-only GitHub API token",
          allowAnonymous: true,
          credentials: [
            { host: "api.github.com", header: "Authorization", scheme: "bearer" as const },
            { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" as const },
          ],
        },
      },
    };
    const entry = desiredServiceEntry(SERVICES.github, { skippedHosts: ["avatars.githubusercontent.com"] });
    const refuse = (layer: "project" | "local") => {
      try {
        reconcileDesiredService(current, { kind: "enable", id: "github", entry, sourceArgs: "--from-source github-cli" }, { layer });
      } catch (error) {
        return (error as Error).message;
      }
      throw new Error("expected a refusal");
    };

    expect(refuse("project")).toBe([
      "token github conflicts with service github",
      "  the project layer (.runfree/network-policy.json) already defines token github directly,",
      "  and service github would send it to different destinations:",
      "",
      "    destination                                                             direct   service github",
      "    api.github.com -> Authorization (bearer)                                yes      yes",
      "    github.com -> Authorization (basic:x-access-token, protocol=git-http)   -        yes",
      "    github.com -> Authorization (basic:x-access-token, protocol=git-lfs)    -        yes",
      "    raw.githubusercontent.com -> Authorization (bearer)                     yes      yes",
      "",
      '  direct token description: "Read-only GitHub API token"',
      "",
      "  choose one:",
      "    keep the direct token and leave service github off:",
      "      nothing to do; allow other hosts with: runfree host add <host>",
      "    let service github own the token:",
      "      runfree credential remove github",
      "      runfree service enable github --skip-host avatars.githubusercontent.com --from-source github-cli",
      "    the same, with writes refused:",
      "      runfree credential remove github",
      "      runfree service enable github --skip-host avatars.githubusercontent.com --read-only --from-source github-cli",
      "",
      "  full service definition: runfree service explain github",
    ].join("\n"));

    const local = refuse("local");
    expect(local).toContain("  the checkout-local layer (.runfree/network-policy.local.json) already defines token github directly,");
    expect(local).toContain("      remove tokens.github from .runfree/network-policy.local.json");
    expect(local).toContain("      runfree service enable github --skip-host avatars.githubusercontent.com --from-source github-cli --local");
    expect(local).not.toContain("runfree credential remove");
  });

  test("the conflict refusal offers no second read-only path when the enable is already read-only", () => {
    const current = {
      version: 2 as const,
      hosts: ["api.github.com"],
      tokens: { github: { description: "x", credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" as const }] } },
    };
    const entry = desiredServiceEntry(SERVICES.github, { writeMode: "read-only" });
    expect(() => reconcileDesiredService(current, { kind: "enable", id: "github", entry }))
      .toThrow(/let service github own the token:\n {6}runfree credential remove github\n {6}runfree service enable github --read-only\n\n/);
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
    ["google-search-console", SERVICES["google-search-console"]],
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

  test("the settings come from the policy read under the lock, not from a planned entry", () => {
    // `service diff --apply` plans its entries before it takes the lock; a
    // setting approved in between must survive the apply.
    const planned = ruled({ selection: { hostRules: { "b.example.com": { writeAction: "ask" } } } });
    const current = enabled({ services: { git: ruled({ selection: { hostRules: { "b.example.com": { writeAction: "deny" } } } }) } });
    const kept = reconcileDesiredService(current, { kind: "enable", id: "git", entry: planned });
    expect(kept.policy.services?.git.selection?.hostRules).toEqual({ "b.example.com": { writeAction: "deny" } });
    // A setting cleared in between is not brought back by the planned copy.
    const cleared = reconcileDesiredService(enabled({ services: { git: rebuilt() } }), { kind: "enable", id: "git", entry: planned });
    expect(cleared.policy.services?.git.selection).toBeUndefined();
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

  test("an identical classification-only direct rule is taken over by the service; its hosts entry stays", () => {
    const result = reconcileDesiredService({
      version: 2 as const,
      hosts: ["b.example.com"],
      requests: { "b.example.com": { gitPush: "write" as const } },
    }, { kind: "enable", id: "git", entry: rebuilt() });
    expect(result.policy.requests).toBeUndefined();
    expect(result.policy.hosts).toEqual(["b.example.com"]);
    expect(result.warnings).toEqual([]);
    expect(result.notices).toEqual([
      "b.example.com: the direct rule matched service git's rule and now belongs to the service; service disable removes it",
    ]);
    const compiled = compileDesiredPolicies({ project: result.policy, local: { version: 2, hosts: [] } });
    expect(compiled.provenance.requests["b.example.com"]).toBe("service:git");
  });

  test("an identical direct rule with a permission field stays direct, warns, and survives disable (S1)", () => {
    // The service rule with the saved setting laid over it is
    // { gitPush: "deny" }: the same as the direct rule, but that rule is the
    // user's restriction, and a takeover would let disable drop it.
    const result = reconcileDesiredService(withRequiredDesiredNetworkPolicyVersion({
      version: 2 as const,
      hosts: ["b.example.com"],
      requests: { "b.example.com": { gitPush: "deny" as const } },
      services: { git: ruled() },
    }), { kind: "enable", id: "git", entry: rebuilt() });
    expect(result.policy.requests).toEqual({ "b.example.com": { gitPush: "deny" } });
    expect(result.notices).toEqual([]);
    expect(result.warnings).toEqual([
      "b.example.com has a direct rule that replaces the rule from service git; remove it with: runfree host rules b.example.com --clear",
    ]);

    const disabled = reconcileDesiredService(result.policy, { kind: "disable", id: "git" }).policy;
    const compiled = compileDesiredPolicies({ project: disabled, local: { version: 2, hosts: [] } });
    expect(compiled.policy.hosts).toEqual(["b.example.com"]);
    expect(compiled.policy.requests?.["b.example.com"]).toEqual({ gitPush: "deny" });
  });

  test.each([
    ["methods", { methods: ["POST" as const] }],
    ["pathPrefixes", { pathPrefixes: ["/oauth/token"] }],
    ["writeAction", { writeAction: "deny" as const }],
  ])("an identical direct rule with %s stays direct", (_field, rule) => {
    const entry: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest("a"),
      resolved: { hosts: ["b.example.com"], requests: { "b.example.com": rule } },
    };
    const result = reconcileDesiredService({ version: 2, hosts: ["b.example.com"], requests: { "b.example.com": rule } }, {
      kind: "enable",
      id: "svc",
      entry,
    });
    expect(result.policy.requests).toEqual({ "b.example.com": rule });
    expect(result.notices).toEqual([]);
    expect(result.warnings).toHaveLength(1);
  });

  test("a classification-only takeover leaves the host allowed by its hosts entry after disable", () => {
    const taken = reconcileDesiredService({
      version: 2 as const,
      hosts: ["b.example.com"],
      requests: { "b.example.com": { gitPush: "write" as const } },
    }, { kind: "enable", id: "git", entry: rebuilt() }).policy;
    const disabled = reconcileDesiredService(taken, { kind: "disable", id: "git" }).policy;
    expect(disabled).toEqual({ version: 2, hosts: ["b.example.com"] });
  });

  test("a carried write setting weaker than the new write mode warns and names the clear (S2)", () => {
    const current = withRequiredDesiredNetworkPolicyVersion({
      version: 2 as const,
      hosts: [] as string[],
      services: {
        git: {
          ...ruled(),
          selection: { hostRules: { "a.example.com": { writeAction: "allow" as const }, "b.example.com": { writeAction: "deny" as const } } },
        },
      },
    });
    const readOnly = (requests: DesiredServiceEntry["resolved"]["requests"]): DesiredServiceEntry => rebuilt({
      selection: { writeMode: "read-only" },
      resolved: { hosts: ["a.example.com", "b.example.com"], requests },
    });
    const result = reconcileDesiredService(current, {
      kind: "enable",
      id: "git",
      entry: readOnly({ "a.example.com": { writeAction: "deny" }, "b.example.com": { gitPush: "write", writeAction: "deny" } }),
    }, { layer: "local" });
    expect(result.warnings).toEqual([
      "a.example.com keeps its own write setting (allow) from host rules, which is weaker than service git's read-only write mode; remove it with: runfree host rules a.example.com --clear --service git --local",
    ]);
    // The setting still wins: a per-host setting outranks the write mode.
    const compiled = compileDesiredPolicies({ project: { version: 2, hosts: [] }, local: result.policy });
    expect(compiled.policy.requests?.["a.example.com"]).toEqual({ writeAction: "allow" });

    // allow-write stamps allow: nothing is weaker, so no warning.
    const allowWrite = reconcileDesiredService(current, {
      kind: "enable",
      id: "git",
      entry: rebuilt({
        selection: { writeMode: "allow-write" },
        resolved: {
          hosts: ["a.example.com", "b.example.com"],
          requests: { "a.example.com": { writeAction: "allow" }, "b.example.com": { gitPush: "write", writeAction: "allow" } },
        },
      }),
    });
    expect(allowWrite.warnings).toEqual([]);
  });

  test("a new revision that drops the git handling of a host with a --deny-git-push setting refuses (S3)", () => {
    expect(() => reconcileDesiredService(enabled(), {
      kind: "enable",
      id: "git",
      entry: rebuilt({ revision: 2, resolved: { hosts: ["a.example.com", "b.example.com"] } }),
    })).toThrow(
      "service git revision 2 has no git handling for b.example.com, which has a --deny-git-push setting; remove it with: runfree host rules b.example.com --clear --service git",
    );
    // The reclaim: with the setting cleared, the same revision applies.
    const cleared = withRequiredDesiredNetworkPolicyVersion({ version: 2 as const, hosts: [] as string[], services: { git: rebuilt() } });
    expect(reconcileDesiredService(cleared, {
      kind: "enable",
      id: "git",
      entry: rebuilt({ revision: 2, resolved: { hosts: ["a.example.com", "b.example.com"] } }),
    }).policy.services?.git.revision).toBe(2);
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

  test("takes over an identical classification-only same-layer direct rule and reports it", async () => {
    const classifying: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest("a"),
      resolved: { hosts: ["api.example.com"], requests: { "api.example.com": { readPathPrefixes: ["/search"] } } },
    };
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), JSON.stringify({
      version: 2,
      hosts: ["api.example.com"],
      requests: { "api.example.com": { readPathPrefixes: ["/search"] } },
    }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");

    const result = await mutateDesiredService(context, io, "project", { kind: "enable", id: "api", entry: classifying });

    const written = JSON.parse(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8"));
    expect(written.requests).toBeUndefined();
    expect(written.hosts).toEqual(["api.example.com"]);
    expect(result.warnings).toEqual([]);
    expect(result.notices).toEqual([
      "api.example.com: the direct rule matched service api's rule and now belongs to the service; service disable removes it",
    ]);
  });

  test("keeps a matching project direct rule when a same-id local entry shadows the project entry", async () => {
    // The compiler picks the local entry, so the project entry matching the
    // direct rule proves nothing: deleting the direct rule would expose the
    // local entry's writeAction: allow on a host that now asks.
    const classifying: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest("a"),
      resolved: { hosts: ["api.example.com"], requests: { "api.example.com": { readPathPrefixes: ["/search"] } } },
    };
    const projectPath = path.join(root, ".runfree", "network-policy.json");
    const directRule = { readPathPrefixes: ["/search"] };
    fs.writeFileSync(projectPath, JSON.stringify({ version: 2, hosts: ["api.example.com"], requests: { "api.example.com": directRule } }));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.local.json"), JSON.stringify({
      version: 2,
      hosts: [],
      services: { api: { ...classifying, resolved: { ...classifying.resolved, requests: { "api.example.com": { ...directRule, writeAction: "allow" } } } } },
    }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");

    const result = await mutateDesiredService(context, io, "project", { kind: "enable", id: "api", entry: classifying });

    const written = JSON.parse(fs.readFileSync(projectPath, "utf8"));
    expect(written.requests).toEqual({ "api.example.com": directRule });
    expect(result.notices).toEqual([]);
    expect(result.warnings).toContain(
      "api.example.com has a direct rule that replaces the rule from service api; remove it with: runfree host rules api.example.com --clear",
    );
    const compiled = compileDesiredPolicies({
      project: written,
      local: JSON.parse(fs.readFileSync(path.join(root, ".runfree", "network-policy.local.json"), "utf8")),
    });
    expect(compiled.policy.requests?.["api.example.com"]).toEqual(directRule);
  });

  test("keeps a matching local direct rule that overrides a different project direct rule", async () => {
    // Deleting the local rule would let the project rule (writeAction: allow)
    // override the service rule, so writes that asked would be allowed.
    const classifying: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest("a"),
      resolved: { hosts: ["api.example.com"], requests: { "api.example.com": { readPathPrefixes: ["/search"] } } },
    };
    const localPath = path.join(root, ".runfree", "network-policy.local.json");
    const projectPath = path.join(root, ".runfree", "network-policy.json");
    const localRule = { readPathPrefixes: ["/search"] };
    fs.writeFileSync(projectPath, JSON.stringify({
      version: 2,
      hosts: ["api.example.com"],
      requests: { "api.example.com": { writeAction: "allow" } },
    }));
    fs.writeFileSync(localPath, JSON.stringify({ version: 2, hosts: ["api.example.com"], requests: { "api.example.com": localRule } }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, context.project, candidate, "network-local", "interactive");

    const result = await mutateDesiredService(context, io, "local", { kind: "enable", id: "api", entry: classifying });

    const written = JSON.parse(fs.readFileSync(localPath, "utf8"));
    expect(written.requests).toEqual({ "api.example.com": localRule });
    expect(result.notices).toEqual([]);
    const compiled = compileDesiredPolicies({ project: JSON.parse(fs.readFileSync(projectPath, "utf8")), local: written });
    expect(compiled.policy.requests?.["api.example.com"]).toEqual(localRule);
  });

  test("keeps an identical direct rule that restricts, so service disable leaves the restriction (S1)", async () => {
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    fs.writeFileSync(policyPath, JSON.stringify({
      version: 2,
      hosts: ["api.example.com"],
      requests: { "api.example.com": { methods: ["GET"] } },
    }));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");

    const enabled = await mutateDesiredService(context, io, "project", { kind: "enable", id: "api", entry: entry("api.example.com") });
    expect(enabled.notices).toEqual([]);
    expect(enabled.warnings).toEqual([
      "api.example.com has a direct rule that replaces the rule from service api; remove it with: runfree host rules api.example.com --clear",
    ]);
    await mutateDesiredService(context, io, "project", { kind: "disable", id: "api" });

    const written = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    expect(written.services).toBeUndefined();
    const compiled = compileDesiredPolicies({ project: written, local: { version: 2, hosts: [] } });
    expect(compiled.policy.hosts).toEqual(["api.example.com"]);
    expect(compiled.policy.requests?.["api.example.com"]).toEqual({ methods: ["GET"] });
  });

  test("a local enable that shadows a project entry with host rule settings warns, naming the hosts (S4)", async () => {
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    const ruled: DesiredServiceEntry = {
      ...entry("api.example.com"),
      selection: { hostRules: { "api.example.com": { writeAction: "deny" } } },
    };
    fs.writeFileSync(policyPath, JSON.stringify(withRequiredDesiredNetworkPolicyVersion({ hosts: [], services: { api: ruled } })));
    const candidate = captureDesiredPolicyCandidate(root, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, context.project, candidate, "network-project", "interactive");

    const shadowing = await mutateDesiredService(context, io, "local", { kind: "enable", id: "api", entry: entry("api.example.com") });
    expect(shadowing.warnings).toEqual([
      "service api in the checkout-local desired policy replaces the project entry, so its host rule settings for api.example.com no longer apply; remove the local entry with: runfree service disable api --local",
    ]);
    // A project-layer enable, or a local service the project does not rule, does not warn.
    const other = await mutateDesiredService(context, io, "local", { kind: "enable", id: "other", entry: entry("other.example.com") });
    expect(other.warnings).toEqual([]);
    // The reclaim the warning names: the project entry and its settings apply again.
    await mutateDesiredService(context, io, "local", { kind: "disable", id: "api" });
    const compiled = compileDesiredPolicies({
      project: JSON.parse(fs.readFileSync(policyPath, "utf8")),
      local: JSON.parse(fs.readFileSync(path.join(root, ".runfree", "network-policy.local.json"), "utf8")),
    });
    expect(compiled.policy.requests?.["api.example.com"]).toEqual({ methods: ["GET"], writeAction: "deny" });
  });
});
