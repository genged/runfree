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

  test("a protocol scope narrows a mapping; removing or changing it, or the username, widens", () => {
    const withCredential = (credential: Record<string, string>) => compiled({
      hosts: ["gitlab.com"],
      tokens: {
        gitlab: {
          description: "GitLab token",
          credentials: [{ host: "gitlab.com", header: "Authorization", ...credential } as never],
        },
      },
    });
    const unscopedBasic = withCredential({ scheme: "basic", username: "oauth2" });
    const scopedBasic = withCredential({ scheme: "basic", username: "oauth2", protocol: "git-http" });
    const scopedPrefixedBasic = withCredential({ scheme: "basic", username: "oauth2", pathPrefix: "/group/", protocol: "git-http" });
    const otherUser = withCredential({ scheme: "basic", username: "x-access-token", protocol: "git-http" });
    const scopedBearer = withCredential({ scheme: "bearer", protocol: "git-http" });

    expect(compareCompiledAuthority(unscopedBasic, scopedBasic)).toEqual({ provenReduction: true, reasons: [] });
    expect(compareCompiledAuthority(scopedBasic, scopedBasic)).toEqual({ provenReduction: true, reasons: [] });
    expect(compareCompiledAuthority(scopedBasic, scopedPrefixedBasic)).toEqual({ provenReduction: true, reasons: [] });
    expect(compareCompiledAuthority(unscopedBasic, scopedPrefixedBasic)).toEqual({ provenReduction: true, reasons: [] });

    const widening = ["gitlab.com: credential mapping added or widened for gitlab"];
    expect(compareCompiledAuthority(scopedBasic, unscopedBasic)).toEqual({ provenReduction: false, reasons: widening });
    expect(compareCompiledAuthority(scopedPrefixedBasic, scopedBasic)).toEqual({ provenReduction: false, reasons: widening });
    expect(compareCompiledAuthority(scopedBasic, otherUser)).toEqual({ provenReduction: false, reasons: widening });
    expect(compareCompiledAuthority(scopedBasic, scopedBearer)).toEqual({ provenReduction: false, reasons: widening });
  });

  // Credential selection is host-wide (protocol tier, then longest
  // pathPrefix), so on a host with several mappings a change to one mapping
  // can make the proxy pick another token's mapping for a request that used
  // to get the changed one. Per-mapping containment cannot see that.
  describe("hosts with more than one credential mapping", () => {
    type Credential = Record<string, string>;
    const policyWith = (mappings: Record<string, Credential[]>) => compiled({
      hosts: ["github.com"],
      tokens: Object.fromEntries(Object.entries(mappings).map(([name, credentials]) => [name, {
        description: name,
        credentials: credentials.map((credential) => ({ host: "github.com", header: "Authorization", scheme: "raw", ...credential }) as never),
      }])),
    });
    const changed = ["github.com: credential mapping changed on a host with more than one mapping"];

    test("adding a protocol to the narrow mapping is not a reduction (it exposes the broad mapping)", () => {
      const previous = policyWith({ narrow: [{ pathPrefix: "/org/" }], broad: [{}] });
      const next = policyWith({ narrow: [{ pathPrefix: "/org/", protocol: "git-http" }], broad: [{}] });
      expect(compareCompiledAuthority(previous, next)).toEqual({ provenReduction: false, reasons: changed });
    });

    test("narrowing the narrow mapping's prefix is not a reduction", () => {
      const previous = policyWith({ narrow: [{ pathPrefix: "/org/" }], broad: [{}] });
      const next = policyWith({ narrow: [{ pathPrefix: "/org/repo/" }], broad: [{}] });
      expect(compareCompiledAuthority(previous, next)).toEqual({ provenReduction: false, reasons: changed });
    });

    test("removing a mapping that hides another one is not a reduction", () => {
      const previous = policyWith({ git: [{ protocol: "git-http" }], broad: [{}] });
      const next = policyWith({ broad: [{}] });
      expect(compareCompiledAuthority(previous, next)).toEqual({ provenReduction: false, reasons: changed });
      const hidingByPrefix = policyWith({ narrow: [{ pathPrefix: "/org/" }], broad: [{}] });
      expect(compareCompiledAuthority(hidingByPrefix, next)).toEqual({ provenReduction: false, reasons: changed });
    });

    test("a mapping on another header still counts: selection is host-wide", () => {
      const previous = policyWith({ git: [{ protocol: "git-http" }], api: [{ header: "X-Api-Key" }] });
      const next = policyWith({ api: [{ header: "X-Api-Key" }] });
      expect(compareCompiledAuthority(previous, next).provenReduction).toBe(false);
    });

    test("an unchanged mapping set, or removing every mapping of the host, is still a reduction", () => {
      const both = policyWith({ narrow: [{ pathPrefix: "/org/" }], broad: [{}] });
      expect(compareCompiledAuthority(both, both)).toEqual({ provenReduction: true, reasons: [] });
      expect(compareCompiledAuthority(both, policyWith({}))).toEqual({ provenReduction: true, reasons: [] });
    });

    test("a single-mapping narrowing stays a reduction", () => {
      const previous = policyWith({ only: [{ pathPrefix: "/org/" }] });
      const next = policyWith({ only: [{ pathPrefix: "/org/repo/", protocol: "git-http" }] });
      expect(compareCompiledAuthority(previous, next)).toEqual({ provenReduction: true, reasons: [] });
    });
  });

  test("treats Git and GraphQL changes as incomparable unless Git becomes deny", () => {
    const base = compiled({ hosts: ["git.example.com"], requests: { "git.example.com": { gitPush: "write" } } });
    expect(compareCompiledAuthority(base, compiled({ hosts: ["git.example.com"], requests: { "git.example.com": { gitPush: "deny" } } })).provenReduction)
      .toBe(true);
    expect(compareCompiledAuthority(base, compiled({ hosts: ["git.example.com"] })).provenReduction).toBe(false);
  });

  test("adding or re-porting a host service is widening; removing one is a reduction", () => {
    const none = compiled({ hosts: [], tokens: {} });
    const idb = compiled({ hosts: [], tokens: {}, hostServices: { idb: { target: "host-loopback", port: 10882 } } });
    const moved = compiled({ hosts: [], tokens: {}, hostServices: { idb: { target: "host-loopback", port: 10883 } } });
    expect(compareCompiledAuthority(none, idb)).toEqual({ provenReduction: false, reasons: ["idb: host service added"] });
    expect(compareCompiledAuthority(idb, moved)).toEqual({ provenReduction: false, reasons: ["idb: host service changed"] });
    expect(compareCompiledAuthority(idb, none).provenReduction).toBe(true);
  });
});

describe("compareRuntimeIsolationAuthority", () => {
  test("only off to auto is an automatic isolation reduction", () => {
    expect(compareRuntimeIsolationAuthority({ dependencyOverlays: "off" }, { dependencyOverlays: "auto" }).provenReduction).toBe(true);
    expect(compareRuntimeIsolationAuthority({ dependencyOverlays: "auto" }, { dependencyOverlays: "off" }).provenReduction).toBe(false);
    expect(compareRuntimeIsolationAuthority({ dependencyOverlays: "auto" }, { dependencyOverlays: "auto" }).provenReduction).toBe(true);
  });
});
