import { describe, expect, test } from "vitest";

import { compileDesiredPolicies } from "./compiler.ts";
import type { DesiredNetworkPolicyJson, DesiredServiceEntry, DesiredServiceHostRule } from "@runfree/runtime-contracts/desired-network-policy";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import { service as registryService } from "../../../../scripts/services.ts";
import { desiredServiceEntry } from "../admin/service-policy.ts";

const digest = `sha256:${"a".repeat(64)}`;

function service(host: string, readPrefix: string) {
  return {
    revision: 1,
    definitionDigest: digest,
    resolved: {
      hosts: [host],
      requests: { [host]: { readPathPrefixes: [readPrefix], writeAction: "ask" as const } },
    },
  };
}

describe("desired policy compiler", () => {
  test("overlays whole service entries before the single expansion pass", () => {
    const project: DesiredNetworkPolicyJson = {
      version: 2,
      hosts: ["direct.example.com"],
      services: { registry: service("old.example.com", "/old") },
    };
    const local: DesiredNetworkPolicyJson = {
      version: 2,
      hosts: [],
      services: { registry: service("new.example.com", "/new") },
    };
    const compiled = compileDesiredPolicies({ project, local });
    expect(compiled.policy.hosts).toEqual(["direct.example.com", "new.example.com"]);
    expect(compiled.policy.hosts).not.toContain("old.example.com");
    expect(compiled.policy.requests).toEqual({
      "new.example.com": { readPathPrefixes: ["/new"], writeAction: "ask" },
    });
  });

  test("local direct rules replace project rules completely and override service rules", () => {
    const compiled = compileDesiredPolicies({
      project: {
        version: 2,
        hosts: ["api.example.com"],
        services: { api: service("api.example.com", "/service") },
        requests: { "api.example.com": { methods: ["GET"], pathPrefixes: ["/project"] } },
      },
      local: {
        version: 2,
        hosts: ["api.example.com"],
        requests: { "api.example.com": { methods: ["GET", "HEAD"] } },
      },
    });
    expect(compiled.policy.requests).toEqual({ "api.example.com": { methods: ["GET", "HEAD"] } });
    expect(compiled.provenance.requests["api.example.com"]).toBe("direct");
    expect(compiled.provenance.sources.hosts["api.example.com"]).toEqual([
      "local:direct",
      "project:direct",
      "project:service:api",
    ]);
    expect(compiled.provenance.sources.requests["api.example.com"]).toBe("local:direct");
    expect(compiled.provenance.sources.services.api).toBe("project");
  });

  test("rejects duplicate service credential ownership", () => {
    const token = {
      description: "API token",
      credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer" as const }],
    };
    const entry = {
      revision: 1,
      definitionDigest: digest,
      resolved: { hosts: ["api.example.com"], tokens: { api: token } },
    };
    expect(() => compileDesiredPolicies({
      project: { version: 2, hosts: [], services: { one: entry, two: entry } },
      local: { version: 2, hosts: [] },
    })).toThrow("duplicate owners");
  });

  test("rejects credentials with distinct names that own the same destination header", () => {
    const credential = { host: "api.example.com", header: "Authorization", scheme: "bearer" as const };
    expect(() => compileDesiredPolicies({
      project: {
        version: 2,
        hosts: [],
        services: {
          one: {
            revision: 1,
            definitionDigest: digest,
            resolved: {
              hosts: ["api.example.com"],
              tokens: { first: { description: "First", credentials: [credential] } },
            },
          },
          two: {
            revision: 1,
            definitionDigest: digest,
            resolved: {
              hosts: ["api.example.com"],
              tokens: { second: { description: "Second", credentials: [credential] } },
            },
          },
        },
      },
      local: { version: 2, hosts: [] },
    })).toThrow("conflicts with first.api.example.com.Authorization");
  });

  test("a host-service name defined in both layers is an ownership conflict (SR9), even when identical", () => {
    const project: DesiredNetworkPolicyJson = { version: 2, hosts: [], hostServices: { idb: { target: "host-loopback", port: 10882 } } };
    const differentPort: DesiredNetworkPolicyJson = { version: 2, hosts: [], hostServices: { idb: { target: "host-loopback", port: 10883 } } };
    expect(() => compileDesiredPolicies({ project, local: differentPort }))
      .toThrow("host service idb is defined in both the project and checkout-local desired policy");
    expect(() => compileDesiredPolicies({ project, local: structuredClone(project) }))
      .toThrow("host service idb is defined in both the project and checkout-local desired policy");
  });

  test("host services from both layers merge, and a port claimed by two names is refused", () => {
    const project: DesiredNetworkPolicyJson = { version: 2, hosts: [], hostServices: { idb: { target: "host-loopback", port: 10882 } } };
    const local: DesiredNetworkPolicyJson = { version: 2, hosts: [], hostServices: { sim: { target: "host-loopback", port: 10883 } } };
    expect(compileDesiredPolicies({ project, local }).policy.hostServices).toEqual({
      idb: { target: "host-loopback", port: 10882 },
      sim: { target: "host-loopback", port: 10883 },
    });
    const clash: DesiredNetworkPolicyJson = { version: 2, hosts: [], hostServices: { other: { target: "host-loopback", port: 10882 } } };
    expect(() => compileDesiredPolicies({ project, local: clash })).toThrow("duplicate port");
  });
});

// Spec 2026-10-23 service host rules §4.3: a service's selection.hostRules is
// laid over its stored resolved rule; the service stays the only owner.
function registryEntry(
  id: string,
  selection: { writeMode?: "allow-write" | "read-only" } = {},
  hostRules?: Record<string, DesiredServiceHostRule>,
): DesiredServiceEntry {
  const svc = registryService(id);
  if (!svc) throw new Error(`no registry service ${id}`);
  const entry = desiredServiceEntry(svc, selection);
  return hostRules ? { ...entry, selection: { ...entry.selection, hostRules } } : entry;
}

function compileProject(services: Record<string, DesiredServiceEntry>, extra: Partial<DesiredNetworkPolicyJson> = {}) {
  return compileDesiredPolicies({
    project: { version: 4, hosts: [], services, ...extra },
    local: { version: 2, hosts: [] },
  });
}

describe("desired policy compiler: service hostRules overlay", () => {
  test("gitPush deny replaces the service's gitPush write and keeps the service as owner", () => {
    const github = registryEntry("github", { writeMode: "allow-write" }, { "github.com": { gitPush: "deny" } });
    expect(github.resolved.requests?.["github.com"]?.gitPush).toBe("write");
    const compiled = compileProject({ github });
    expect(compiled.policy.requests?.["github.com"]).toEqual({ ...github.resolved.requests?.["github.com"], gitPush: "deny" });
    expect(compiled.provenance.requests["github.com"]).toBe("service:github");
    expect(compiled.provenance.sources.requests["github.com"]).toBe("project:service:github");
    // Every other host keeps the stored service rule.
    expect(compiled.policy.requests?.["api.github.com"]).toEqual(github.resolved.requests?.["api.github.com"]);
  });

  test("gitlab's classification fields survive a user methods and writeAction setting", () => {
    const gitlab = registryEntry("gitlab", {}, { "gitlab.com": { methods: ["GET", "POST"], writeAction: "deny" } });
    const resolved = gitlab.resolved.requests?.["gitlab.com"];
    expect(resolved?.graphql).toBeDefined();
    const compiled = compileProject({ gitlab });
    expect(compiled.policy.requests?.["gitlab.com"]).toEqual({ ...resolved, methods: ["GET", "POST"], writeAction: "deny" });
    expect(compiled.policy.requests?.["gitlab.com"]?.graphql).toEqual(resolved?.graphql);
    expect(compiled.policy.requests?.["gitlab.com"]?.gitPush).toBe("write");
  });

  test("a per-host writeAction replaces the one the service's writeMode set", () => {
    const github = registryEntry("github", { writeMode: "read-only" }, { "github.com": { writeAction: "ask" } });
    expect(github.resolved.requests?.["github.com"]?.writeAction).toBe("deny");
    const compiled = compileProject({ github });
    expect(compiled.policy.requests?.["github.com"]?.writeAction).toBe("ask");
    expect(compiled.policy.requests?.["api.github.com"]?.writeAction).toBe("deny");
  });

  test("a setting on a service host without a resolved rule creates a service-owned rule", () => {
    const entry: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest,
      selection: { hostRules: { "api.example.com": { methods: ["GET"] } } },
      resolved: { hosts: ["api.example.com"] },
    };
    const compiled = compileProject({ api: entry });
    expect(compiled.policy.requests).toEqual({ "api.example.com": { methods: ["GET"] } });
    expect(compiled.provenance.requests["api.example.com"]).toBe("service:api");
  });

  test("a second service's setting on a host the first service rules is an ownership conflict", () => {
    const first: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest,
      resolved: { hosts: ["git.example.com"], requests: { "git.example.com": { gitPush: "write" } } },
    };
    const second: DesiredServiceEntry = {
      revision: 1,
      definitionDigest: digest,
      selection: { hostRules: { "git.example.com": { gitPush: "deny" } } },
      resolved: { hosts: ["git.example.com"] },
    };
    expect(() => compileProject({ first, second }))
      .toThrow("request rule git.example.com conflicts between service:first and service:second");
    // An identical overlaid rule from a second service is still two owners.
    const denying = { ...first, resolved: { ...first.resolved, requests: { "git.example.com": { gitPush: "deny" as const } } } };
    expect(() => compileProject({ first: denying, second }))
      .toThrow("request rule git.example.com has duplicate owners service:first and service:second");
  });

  test("a direct rule still replaces the overlaid service rule (legacy precedence)", () => {
    const github = registryEntry("github", {}, { "github.com": { gitPush: "deny" } });
    const compiled = compileProject({ github }, { hosts: ["github.com"], requests: { "github.com": { writeAction: "allow" } } });
    expect(compiled.policy.requests?.["github.com"]).toEqual({ writeAction: "allow" });
    expect(compiled.provenance.requests["github.com"]).toBe("direct");
  });

  test("a local service entry replaces the project entry together with its hostRules", () => {
    const projectGithub = registryEntry("github", {}, { "github.com": { gitPush: "deny" } });
    const localGithub = registryEntry("github");
    const compiled = compileDesiredPolicies({
      project: { version: 4, hosts: [], services: { github: projectGithub } },
      local: { version: 3, hosts: [], services: { github: localGithub } },
    });
    expect(compiled.policy.requests?.["github.com"]?.gitPush).toBe("write");
    expect(compiled.provenance.sources.requests["github.com"]).toBe("local:service:github");

    const withLocalSetting = compileDesiredPolicies({
      project: { version: 3, hosts: [], services: { github: localGithub } },
      local: { version: 4, hosts: [], services: { github: projectGithub } },
    });
    expect(withLocalSetting.policy.requests?.["github.com"]?.gitPush).toBe("deny");
  });

  test("the compiled policy is a valid effective policy that round-trips", () => {
    const compiled = compileProject({
      github: registryEntry("github", {}, { "github.com": { gitPush: "deny", methods: ["GET", "POST"], writeAction: "deny" } }),
      gitlab: registryEntry("gitlab", {}, { "gitlab.com": { pathPrefixes: ["/group/"] } }),
    });
    const reloaded = validateNetworkPolicy(JSON.parse(JSON.stringify(compiled.policy)));
    expect(reloaded.raw).toEqual(compiled.policy);
    expect(reloaded.requests["github.com"]).toMatchObject({ gitPush: "deny", methods: ["GET", "POST"], writeAction: "deny" });
  });
});
