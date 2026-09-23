import { describe, expect, test } from "vitest";

import { compileDesiredPolicies } from "./compiler.ts";
import type { DesiredNetworkPolicyJson } from "@runfree/runtime-contracts/desired-network-policy";

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
});
