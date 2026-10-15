import { describe, expect, test } from "vitest";

import {
  canonicalDesiredNetworkPolicy,
  desiredNetworkPolicyDigest,
  desiredNetworkPolicyV3Features,
  desiredPolicyDirectProjection,
  requiredDesiredNetworkPolicyVersion,
  validateDesiredNetworkPolicy,
  withRequiredDesiredNetworkPolicyVersion,
  type DesiredNetworkPolicyJson,
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

const GITLAB_API_BEARER = { host: "gitlab.com", header: "Authorization", scheme: "bearer", pathPrefix: "/api/" };
const GITLAB_GIT_BASIC = { host: "gitlab.com", header: "Authorization", scheme: "basic", username: "oauth2", protocol: "git-http" };

function gitlabService(credentials: unknown[]): Record<string, unknown> {
  return {
    revision: 2,
    definitionDigest: digest,
    resolved: {
      hosts: ["gitlab.com"],
      tokens: { gitlab: { description: "GitLab token", allowAnonymous: true, credentials } },
    },
  };
}

function desiredIssues(raw: unknown): string {
  try {
    validateDesiredNetworkPolicy(raw);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return "";
}

describe("desired network policy version on need (v3)", () => {
  test("a policy without v3 features is written as version 2 and keeps its digest when declared 3", () => {
    const v2: DesiredNetworkPolicyJson = { version: 2, hosts: ["api.example.com"] };
    expect(validateDesiredNetworkPolicy(v2).version).toBe(2);
    expect(validateDesiredNetworkPolicy({ ...v2, version: 3 }).version).toBe(2);
    expect(desiredNetworkPolicyDigest({ ...v2, version: 3 })).toBe(desiredNetworkPolicyDigest(v2));
  });

  test("refuses unsupported version values", () => {
    for (const version of [1, 4, "3", undefined, 2.5]) {
      expect(desiredIssues({ version, hosts: [] }), String(version)).toContain("version must be one of: 2, 3");
    }
  });

  test.each([
    ["direct basic + username", { hosts: ["gitlab.com"], tokens: { gitlab: { description: "d", credentials: [{ ...GITLAB_GIT_BASIC, protocol: undefined }] } } },
      ["tokens.gitlab.credentials[0].scheme basic", "tokens.gitlab.credentials[0].username"]],
    ["direct protocol on bearer", { hosts: ["gitlab.com"], tokens: { gitlab: { description: "d", credentials: [{ host: "gitlab.com", header: "Authorization", scheme: "bearer", protocol: "git-http" }] } } },
      ["tokens.gitlab.credentials[0].protocol"]],
    ["service-resolved basic", { hosts: [], services: { gitlab: gitlabService([GITLAB_GIT_BASIC]) } },
      ["services.gitlab.resolved.tokens.gitlab.credentials[0].scheme basic"]],
    ["two direct mappings on one host and header", {
      hosts: ["gitlab.com"],
      tokens: {
        a: { description: "a", credentials: [GITLAB_API_BEARER] },
        b: { description: "b", credentials: [{ host: "gitlab.com", header: "authorization", scheme: "bearer", pathPrefix: "/v5/" }] },
      },
    }, ["tokens.b.credentials[0] shares (gitlab.com, authorization) with tokens.a.credentials[0]"]],
  ])("a declared v2 file using %s is refused naming the fields; v3 accepts and emits 3", (_name, body, fields) => {
    const message = desiredIssues({ version: 2, ...body });
    expect(message).toContain("version 2 cannot use these fields; declare version 3");
    for (const field of fields) expect(message).toContain(field);
    expect(validateDesiredNetworkPolicy({ version: 3, ...body }).version).toBe(3);
  });

  test("the gitlab shape (/api/ Bearer + git-http Basic) validates in v3 and canonicalizes with its fields (T12)", () => {
    const policy = validateDesiredNetworkPolicy({
      version: 3,
      hosts: [],
      services: { gitlab: gitlabService([GITLAB_API_BEARER, GITLAB_GIT_BASIC]) },
    });
    expect(policy.version).toBe(3);
    expect(policy.services?.gitlab.resolved.tokens?.gitlab.credentials).toEqual([GITLAB_API_BEARER, GITLAB_GIT_BASIC]);
    expect(canonicalDesiredNetworkPolicy(policy)).toContain("\"protocol\":\"git-http\"");
  });

  test("a tie and two protocol-scoped mappings are refused in v3 too", () => {
    expect(desiredIssues({
      version: 3,
      hosts: [],
      services: { gitlab: gitlabService([GITLAB_API_BEARER, { ...GITLAB_API_BEARER, scheme: "raw" }]) },
    })).toContain("conflicts with gitlab.gitlab.com.Authorization");
    expect(desiredIssues({
      version: 3,
      hosts: [],
      services: { gitlab: gitlabService([GITLAB_GIT_BASIC, { ...GITLAB_GIT_BASIC, pathPrefix: "/group/" }]) },
    })).toContain("second protocol-scoped mapping");
  });

  test("uniqueness is per validation scope: a direct and a service mapping on one host and header need no v3", () => {
    const body = {
      hosts: ["gitlab.com"],
      tokens: { direct: { description: "d", credentials: [{ host: "gitlab.com", header: "Authorization", scheme: "bearer", pathPrefix: "/v5/" }] } },
      services: { gitlab: gitlabService([GITLAB_API_BEARER]) },
    };
    expect(desiredNetworkPolicyV3Features(body)).toEqual([]);
    expect(requiredDesiredNetworkPolicyVersion(body)).toBe(2);
  });

  test("in-memory writers declare the version the content needs", () => {
    const withBasic = withRequiredDesiredNetworkPolicyVersion({
      hosts: [],
      services: { gitlab: gitlabService([GITLAB_GIT_BASIC]) },
    });
    expect(withBasic.version).toBe(3);
    expect(withRequiredDesiredNetworkPolicyVersion({ version: 3, hosts: [] }).version).toBe(2);
  });
});
