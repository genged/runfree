import { describe, expect, test } from "vitest";

import {
  canonicalDesiredNetworkPolicy,
  desiredNetworkPolicyDigest,
  desiredPolicyDirectProjection,
  validateDesiredNetworkPolicy,
} from "./desired-network-policy.ts";

const digest = `sha256:${"a".repeat(64)}`;

describe("desired network policy v2", () => {
  test("refuses IP-literal hosts, which would skip the resolver snapshot (R20)", () => {
    for (const host of ["192.168.65.254", "127.0.0.1", "1.2.3.0x7f", "foo.123"]) {
      expect(() => validateDesiredNetworkPolicy({ version: 2, hosts: [host] }), host)
        .toThrow(`${host} is an IP address; policy hosts must be hostnames`);
    }
    expect(validateDesiredNetworkPolicy({ version: 2, hosts: ["x1.example.com"] }).hosts).toEqual(["x1.example.com"]);
  });

  test("canonicalizes direct policy and self-contained service semantics", () => {
    const first = validateDesiredNetworkPolicy({
      version: 2,
      hosts: ["standards.example.org"],
      services: {
        github: {
          revision: 3,
          definitionDigest: digest,
          selection: { writeMode: "read-only", skippedHosts: ["uploads.github.com"] },
          resolved: {
            hosts: ["api.github.com"],
            requests: { "api.github.com": { methods: ["GET", "HEAD", "OPTIONS"] } },
            tokens: {
              github: {
                description: "GitHub token",
                allowAnonymous: true,
                credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
              },
            },
            agentEnv: ["GITHUB_TOKEN"],
          },
        },
      },
    });
    const reordered = {
      services: first.services,
      hosts: ["standards.example.org"],
      version: 2,
    };
    expect(canonicalDesiredNetworkPolicy(first)).toBe(canonicalDesiredNetworkPolicy(reordered as never));
    expect(desiredNetworkPolicyDigest(first)).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  test("rejects unknown fields and invalid resolved service policy", () => {
    expect(() => validateDesiredNetworkPolicy({ version: 2, hosts: [], surprise: true })).toThrow("surprise is not a known field");
    expect(() => validateDesiredNetworkPolicy({
      version: 2,
      hosts: [],
      services: {
        github: {
          revision: 1,
          definitionDigest: digest,
          resolved: {
            hosts: [],
            tokens: {
              github: {
                description: "GitHub token",
                credentials: [{ host: "api.github.com", header: "Authorization", scheme: "bearer" }],
              },
            },
          },
        },
      },
    })).toThrow("credentialed but not allowlisted");
  });

  test("carries declared service parameters and still accepts legacy OAuth passthrough", () => {
    const entry = (resolved: Record<string, unknown>) => ({
      version: 2,
      hosts: [],
      services: { "apple-ads": { revision: 2, definitionDigest: digest, resolved: { hosts: ["api.searchads.apple.com"], ...resolved } } },
    });
    const parameters = [{ key: "client-id", envVar: "APPLE_ADS_CLIENT_ID", description: "Apple Ads OAuth client id", oauthField: "client_id" }];
    const validated = validateDesiredNetworkPolicy(entry({ agentEnv: ["APPLE_ADS_CLIENT_ID"], parameters }));
    expect(validated.services?.["apple-ads"]?.resolved.parameters).toEqual(parameters);
    // Sorted by key on the way in.
    const two = validateDesiredNetworkPolicy(entry({
      agentEnv: ["A_REGION", "A_TEAM"],
      parameters: [
        { key: "team", envVar: "A_TEAM", description: "team" },
        { key: "region", envVar: "A_REGION", description: "region" },
      ],
    }));
    expect(two.services?.["apple-ads"]?.resolved.parameters?.map((parameter) => parameter.key)).toEqual(["region", "team"]);
    expect(() => validateDesiredNetworkPolicy(entry({ parameters })))
      .toThrow("parameters[0] env APPLE_ADS_CLIENT_ID must also be listed in resolved.agentEnv");
    expect(() => validateDesiredNetworkPolicy(entry({ agentEnv: ["APPLE_ADS_CLIENT_ID"], parameters: [...parameters, ...parameters] })))
      .toThrow("parameters[1] duplicates parameter key client-id");
    expect(() => validateDesiredNetworkPolicy(entry({ agentEnv: ["A"], parameters: [{ key: "Bad", envVar: "A", description: "d" }] })))
      .toThrow("parameters[0] is malformed");
    expect(() => validateDesiredNetworkPolicy(entry({ agentEnv: ["A"], parameters: [{ key: "a", envVar: "A", description: "d", pattern: "^x$" }] })))
      .toThrow("pattern is not a known field");
    const legacy = validateDesiredNetworkPolicy(entry({
      agentEnv: ["APPLE_ADS_CLIENT_ID"],
      oauth: {
        "service:apple-ads": {
          resourceHost: "api.searchads.apple.com",
          tokenEndpoints: [{ host: "appleid.apple.com", path: "/auth/oauth2/token" }],
          passthrough: [{ envVar: "APPLE_ADS_CLIENT_ID", field: "client_id" }],
        },
      },
    }));
    expect(legacy.services?.["apple-ads"]?.resolved.oauth?.["service:apple-ads"]?.passthrough)
      .toEqual([{ envVar: "APPLE_ADS_CLIENT_ID", field: "client_id" }]);
  });

  test("write posture changes the canonical digest", () => {
    const ask = validateDesiredNetworkPolicy({ version: 2, hosts: [], writeApproval: "ask" });
    const deny = validateDesiredNetworkPolicy({ version: 2, hosts: [], writeApproval: "deny" });
    expect(desiredNetworkPolicyDigest(ask)).not.toBe(desiredNetworkPolicyDigest(deny));
  });

  test("hostServices is a known desired field and changes the digest", () => {
    const a = validateDesiredNetworkPolicy({ version: 2, hosts: [] });
    const b = validateDesiredNetworkPolicy({ version: 2, hosts: [], hostServices: { idb: { target: "host-loopback", port: 10882 } } });
    expect(b.hostServices).toEqual({ idb: { target: "host-loopback", port: 10882 } });
    expect(desiredNetworkPolicyDigest(a)).not.toBe(desiredNetworkPolicyDigest(b));
    expect(desiredPolicyDirectProjection(b).hostServices).toEqual(b.hostServices);
  });

  test("desired hostServices refuse the address target", () => {
    expect(() => validateDesiredNetworkPolicy({ version: 2, hosts: [], hostServices: { x: { target: "address", host: "h", port: 1 } } })).toThrow("not supported yet");
  });
});
