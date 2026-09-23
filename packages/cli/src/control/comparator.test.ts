import { describe, expect, test } from "vitest";

import type { CompiledDesiredPolicy } from "./compiler.ts";
import {
  compareCompiledAuthority,
  compareRuntimeIsolationAuthority,
} from "./comparator.ts";

function compiled(policy: CompiledDesiredPolicy["policy"], extras: Partial<CompiledDesiredPolicy> = {}): CompiledDesiredPolicy {
  return {
    policy,
    agentEnv: [],
    oauth: {},
    provenance: {
      hosts: {},
      oauth: {},
      requests: {},
      tokens: {},
      sources: { agentEnv: {}, hosts: {}, oauth: {}, requests: {}, services: {}, tokens: {} },
    },
    selectedServices: {},
    ...extras,
  };
}

describe("compareCompiledAuthority", () => {
  test("proves host removal and request/write tightening", () => {
    const previous = compiled({
      hosts: ["api.example.com", "removed.example.com"],
      writeApproval: "allow",
      requests: {
        "api.example.com": {
          methods: ["GET", "POST"],
          pathPrefixes: ["/v1"],
          readPathPrefixes: ["/v1/search"],
          writePathPrefixes: ["/v1/admin"],
          gitPush: "write",
          writeAction: "ask",
        },
      },
    });
    const next = compiled({
      hosts: ["api.example.com"],
      writeApproval: "deny",
      requests: {
        "api.example.com": {
          methods: ["GET"],
          pathPrefixes: ["/v1/items"],
          writePathPrefixes: ["/v1"],
          gitPush: "deny",
          writeAction: "deny",
        },
      },
    });
    expect(compareCompiledAuthority(previous, next)).toEqual({ provenReduction: true, reasons: [] });
  });

  test("rejects new hosts and widened method, path, read, write, and GraphQL classifiers", () => {
    const previous = compiled({
      hosts: ["api.example.com"],
      requests: {
        "api.example.com": {
          methods: ["GET"],
          pathPrefixes: ["/v1/items"],
          readPathPrefixes: ["/v1/search/exact"],
          writePathPrefixes: ["/v1/admin"],
          graphql: { endpoints: ["/graphql"], writeOps: "mutation" },
          writeAction: "deny",
        },
      },
    });
    const next = compiled({
      hosts: ["api.example.com", "new.example.com"],
      requests: {
        "api.example.com": {
          methods: ["GET", "POST"],
          pathPrefixes: ["/v1"],
          readPathPrefixes: ["/v1/search"],
          writeAction: "ask",
        },
      },
    });
    const comparison = compareCompiledAuthority(previous, next);
    expect(comparison.provenReduction).toBe(false);
    expect(comparison.reasons).toEqual(expect.arrayContaining([
      "new.example.com: host added",
      "api.example.com: request methods widened",
      "api.example.com: request paths widened",
      "api.example.com: read classifier widened",
      "api.example.com: write classifier weakened",
      "api.example.com: GraphQL classification changed",
      "api.example.com: write action weakened",
    ]));
  });

  test("allows credential removal/path narrowing but rejects mapping, anonymity, OAuth, and env additions", () => {
    const previous = compiled({
      hosts: ["api.example.com"],
      tokens: {
        api: {
          description: "old description",
          credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer" }],
        },
      },
    });
    const narrowed = compiled({
      hosts: ["api.example.com"],
      tokens: {
        api: {
          description: "new description",
          credentials: [{ host: "api.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/v1" }],
        },
      },
    });
    expect(compareCompiledAuthority(previous, narrowed)).toEqual({ provenReduction: true, reasons: [] });

    const widened = compiled({
      hosts: ["api.example.com"],
      tokens: {
        api: {
          description: "api",
          allowAnonymous: true,
          credentials: [{ host: "api.example.com", header: "X-Token", scheme: "raw" }],
        },
      },
    }, {
      agentEnv: ["API_CLIENT_ID"],
      oauth: {
        api: { resourceHost: "api.example.com", tokenEndpoints: [{ host: "api.example.com", path: "/token" }] },
      },
    });
    const comparison = compareCompiledAuthority(previous, widened);
    expect(comparison.provenReduction).toBe(false);
    expect(comparison.reasons).toEqual(expect.arrayContaining([
      "api.example.com: credential mapping added or widened for api",
      "api: anonymous credential fallback enabled",
      "api: OAuth authority added or changed",
      "API_CLIENT_ID: agent-visible service environment added",
    ]));
  });

  test("treats Git and GraphQL changes as incomparable unless Git becomes deny", () => {
    const base = compiled({ hosts: ["git.example.com"], requests: { "git.example.com": { gitPush: "write" } } });
    expect(compareCompiledAuthority(base, compiled({ hosts: ["git.example.com"], requests: { "git.example.com": { gitPush: "deny" } } })).provenReduction)
      .toBe(true);
    expect(compareCompiledAuthority(base, compiled({ hosts: ["git.example.com"] })).provenReduction).toBe(false);
  });
});

describe("compareRuntimeIsolationAuthority", () => {
  test("only off to auto is an automatic isolation reduction", () => {
    expect(compareRuntimeIsolationAuthority({ dependencyOverlays: "off" }, { dependencyOverlays: "auto" }).provenReduction).toBe(true);
    expect(compareRuntimeIsolationAuthority({ dependencyOverlays: "auto" }, { dependencyOverlays: "off" }).provenReduction).toBe(false);
    expect(compareRuntimeIsolationAuthority({ dependencyOverlays: "auto" }, { dependencyOverlays: "auto" }).provenReduction).toBe(true);
  });
});
