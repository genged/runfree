import { describe, expect, test } from "vitest";

import {
  canonicalDesiredNetworkPolicy,
  desiredNetworkPolicyDigest,
  desiredNetworkPolicyV3Features,
  desiredNetworkPolicyV4Features,
  desiredPolicyDirectProjection,
  overlayServiceHostRule,
  requiredDesiredNetworkPolicyVersion,
  SERVICE_HOST_RULE_FIELDS,
  serviceHostRuleNarrowingIssues,
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
    for (const version of [1, 5, "3", undefined, 2.5]) {
      expect(desiredIssues({ version, hosts: [] }), String(version)).toContain("version must be one of: 2, 3, 4");
    }
  });

  test.each([
    ["direct basic + username", { hosts: ["gitlab.com"], tokens: { gitlab: { description: "d", credentials: [{ ...GITLAB_GIT_BASIC, protocol: undefined }] } } },
      ["tokens.gitlab.credentials[0].scheme basic", "tokens.gitlab.credentials[0].username"]],
    ["direct protocol on bearer", { hosts: ["gitlab.com"], tokens: { gitlab: { description: "d", credentials: [{ host: "gitlab.com", header: "Authorization", scheme: "bearer", protocol: "git-http" }] } } },
      ["tokens.gitlab.credentials[0].protocol"]],
    ["direct git-lfs protocol", { hosts: ["gitlab.com"], tokens: { gitlab: { description: "d", credentials: [{ host: "gitlab.com", header: "Authorization", scheme: "bearer", protocol: "git-lfs" }] } } },
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
    })).toContain("second git-http mapping");
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

// Spec 2026-10-23 service host rules §4.2, §4.5, §4.9: a user setting stored
// with the service it restricts. Only permission fields, only on the service's
// own hosts, and never broader than a service-set method or path.
const GITLAB_RULE = {
  gitPush: "write",
  readPathPrefixes: ["/api/v4/search"],
  graphql: { endpoints: ["/api/graphql"], writeOps: "mutation" },
};
const OAUTH_RULE = { methods: ["POST"], pathPrefixes: ["/oauth/token"] };

function serviceWithHostRules(hostRules: unknown, selection: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 4,
    hosts: [],
    services: {
      gitlab: {
        revision: 2,
        definitionDigest: digest,
        selection: { ...selection, hostRules },
        resolved: {
          hosts: ["gitlab.com", "auth.example.com"],
          requests: { "gitlab.com": GITLAB_RULE, "auth.example.com": OAUTH_RULE },
        },
      },
    },
  };
}

describe("desired network policy v4: service hostRules", () => {
  test("exports the permission fields a user can set", () => {
    expect(SERVICE_HOST_RULE_FIELDS).toEqual(["gitPush", "methods", "pathPrefixes", "writeAction"]);
  });

  test("accepts permission fields on a service host and canonicalizes them byte-stably", () => {
    const raw = serviceWithHostRules({ "gitlab.com": { gitPush: "deny", methods: ["GET", "POST"], writeAction: "deny" } });
    const policy = validateDesiredNetworkPolicy(raw);
    expect(policy.version).toBe(4);
    expect(policy.services?.gitlab.selection).toEqual({
      hostRules: { "gitlab.com": { gitPush: "deny", methods: ["GET", "POST"], writeAction: "deny" } },
    });
    expect(policy.services?.gitlab.resolved.requests?.["gitlab.com"]).toEqual(GITLAB_RULE);
    const again = validateDesiredNetworkPolicy(JSON.parse(JSON.stringify(policy)));
    expect(canonicalDesiredNetworkPolicy(again)).toBe(canonicalDesiredNetworkPolicy(policy));
    expect(JSON.stringify(again)).toBe(JSON.stringify(policy));
  });

  test("keeps other selection fields beside hostRules", () => {
    const policy = validateDesiredNetworkPolicy(serviceWithHostRules(
      { "gitlab.com": { writeAction: "allow" } },
      { writeMode: "read-only", skippedHosts: ["uploads.gitlab.com"] },
    ));
    expect(policy.services?.gitlab.selection).toEqual({
      writeMode: "read-only",
      skippedHosts: ["uploads.gitlab.com"],
      hostRules: { "gitlab.com": { writeAction: "allow" } },
    });
  });

  test.each([
    ["an unknown field", { "gitlab.com": { methodz: ["GET"] } },
      "services.gitlab.selection.hostRules.gitlab.com.methodz is not a known field (known: gitPush, methods, pathPrefixes, writeAction)"],
    ["a host the service does not allow", { "example.org": { gitPush: "deny" } },
      "services.gitlab.selection.hostRules.example.org is not a host of this service"],
    ["a non-normalized host", { "GitLab.com": { gitPush: "deny" } },
      "services.gitlab.selection.hostRules.GitLab.com must be stored as gitlab.com"],
    ["__proto__ as a host", JSON.parse('{"__proto__": {"gitPush": "deny"}}'),
      "services.gitlab.selection.hostRules.__proto__"],
    ["readPathPrefixes", { "gitlab.com": { readPathPrefixes: ["/x"] } },
      "services.gitlab.selection.hostRules.gitlab.com.readPathPrefixes is set by the service and cannot be set in hostRules"],
    ["writePathPrefixes", { "gitlab.com": { writePathPrefixes: ["/x"] } },
      "services.gitlab.selection.hostRules.gitlab.com.writePathPrefixes is set by the service and cannot be set in hostRules"],
    ["graphql", { "gitlab.com": { graphql: { endpoints: ["/g"], writeOps: "mutation" } } },
      "services.gitlab.selection.hostRules.gitlab.com.graphql is set by the service and cannot be set in hostRules"],
    ["gitPush write", { "gitlab.com": { gitPush: "write" } },
      "services.gitlab.selection.hostRules.gitlab.com.gitPush must be \"deny\""],
    ["an empty hostRules", {}, "services.gitlab.selection.hostRules must not be empty"],
    ["a non-object hostRules", ["gitlab.com"], "services.gitlab.selection.hostRules must be an object"],
    ["an empty rule", { "gitlab.com": {} },
      "services.gitlab.selection.hostRules.gitlab.com must set at least one of: gitPush, methods, pathPrefixes, writeAction"],
    ["a non-object rule", { "gitlab.com": "deny" }, "services.gitlab.selection.hostRules.gitlab.com must be an object"],
    ["empty methods", { "gitlab.com": { methods: [] } }, "services.gitlab.selection.hostRules.gitlab.com.methods must be non-empty"],
    ["an unknown method", { "gitlab.com": { methods: ["BREW"] } }, "services.gitlab.selection.hostRules.gitlab.com.methods[0] must be one of"],
    ["a non-normalized path prefix", { "gitlab.com": { pathPrefixes: [" /api/"] } },
      "services.gitlab.selection.hostRules.gitlab.com.pathPrefixes[0] must be stored as exact normalized path prefix /api/"],
    ["an unknown writeAction", { "gitlab.com": { writeAction: "maybe" } },
      "services.gitlab.selection.hostRules.gitlab.com.writeAction must be one of: allow, ask, deny"],
    ["a broader method on an OAuth token host", { "auth.example.com": { methods: ["POST", "PUT"] } },
      "services.gitlab.selection.hostRules.auth.example.com.methods includes PUT, which the service rule does not allow (service methods: POST)"],
    ["a broader path on an OAuth token host", { "auth.example.com": { pathPrefixes: ["/"] } },
      "services.gitlab.selection.hostRules.auth.example.com.pathPrefixes includes /, which is not under a service path prefix (service pathPrefixes: /oauth/token)"],
    ["a sibling path on an OAuth token host", { "auth.example.com": { pathPrefixes: ["/oauth/tokenx"] } },
      "pathPrefixes includes /oauth/tokenx, which is not under a service path prefix"],
  ])("refuses %s", (_name, hostRules, message) => {
    expect(desiredIssues(serviceWithHostRules(hostRules))).toContain(message);
  });

  test("refuses a rule on a host the selection skipped", () => {
    // A skipped host is not in resolved.hosts, so a rule on it would restrict
    // nothing and must not survive as a stale entry.
    expect(desiredIssues(serviceWithHostRules({ "uploads.gitlab.com": { gitPush: "deny" } }, { skippedHosts: ["uploads.gitlab.com"] })))
      .toContain("services.gitlab.selection.hostRules.uploads.gitlab.com is not a host of this service");
  });

  test("accepts a narrower method and path on an OAuth token host", () => {
    const policy = validateDesiredNetworkPolicy(serviceWithHostRules({
      "auth.example.com": { methods: ["POST"], pathPrefixes: ["/oauth/token/refresh"], writeAction: "deny" },
    }));
    expect(policy.services?.gitlab.selection?.hostRules?.["auth.example.com"])
      .toEqual({ methods: ["POST"], pathPrefixes: ["/oauth/token/refresh"], writeAction: "deny" });
  });

  test("v4 is derived from the presence of hostRules, even when empty", () => {
    expect(desiredNetworkPolicyV4Features(serviceWithHostRules({}))).toEqual(["services.gitlab.selection.hostRules"]);
    expect(requiredDesiredNetworkPolicyVersion(serviceWithHostRules({ "gitlab.com": { gitPush: "deny" } }))).toBe(4);
    expect(requiredDesiredNetworkPolicyVersion({ hosts: [], services: { gitlab: gitlabService([GITLAB_GIT_BASIC]) } })).toBe(3);
    expect(withRequiredDesiredNetworkPolicyVersion({ ...serviceWithHostRules({ "gitlab.com": { gitPush: "deny" } }), version: 2 }).version).toBe(4);
  });

  test.each([2, 3])("a declared v%s file with hostRules is refused naming the field", (version) => {
    const message = desiredIssues({ ...serviceWithHostRules({ "gitlab.com": { gitPush: "deny" } }), version });
    expect(message).toContain(`version ${version} cannot use these fields; declare version 4: services.gitlab.selection.hostRules`);
  });

  test("a declared v2 file with v3 and v4 features names both; a declared v3 file names only the v4 one", () => {
    const body = serviceWithHostRules({ "gitlab.com": { gitPush: "deny" } });
    const gitlab = (body.services as Record<string, Record<string, unknown>>).gitlab;
    const withBasic = {
      ...body,
      services: { gitlab: { ...gitlab, resolved: { ...(gitlab.resolved as object), tokens: { gitlab: { description: "d", credentials: [GITLAB_GIT_BASIC] } } } } },
    };
    expect(desiredIssues({ ...withBasic, version: 2 })).toContain(
      "version 2 cannot use these fields; declare version 4: services.gitlab.resolved.tokens.gitlab.credentials[0].scheme basic; "
        + "services.gitlab.resolved.tokens.gitlab.credentials[0].username; services.gitlab.resolved.tokens.gitlab.credentials[0].protocol; "
        + "services.gitlab.selection.hostRules",
    );
    expect(desiredIssues({ ...withBasic, version: 3 })).toContain(
      "version 3 cannot use these fields; declare version 4: services.gitlab.selection.hostRules",
    );
    expect(validateDesiredNetworkPolicy({ ...withBasic, version: 4 }).version).toBe(4);
  });

  test("a policy without hostRules declared 4 is written as version 2 and keeps its digest", () => {
    const v2: DesiredNetworkPolicyJson = { version: 2, hosts: ["api.example.com"] };
    expect(validateDesiredNetworkPolicy({ ...v2, version: 4 })).toEqual(validateDesiredNetworkPolicy(v2));
    expect(desiredNetworkPolicyDigest({ ...v2, version: 4 })).toBe(desiredNetworkPolicyDigest(v2));
  });

  test("overlayServiceHostRule lays the user setting over the service rule field by field", () => {
    expect(overlayServiceHostRule(undefined, undefined)).toBeUndefined();
    expect(overlayServiceHostRule({ gitPush: "write" }, undefined)).toEqual({ gitPush: "write" });
    expect(overlayServiceHostRule(undefined, { gitPush: "deny" })).toEqual({ gitPush: "deny" });
    expect(overlayServiceHostRule(
      { gitPush: "write", readPathPrefixes: ["/api/v4/search"], writeAction: "ask" },
      { gitPush: "deny", writeAction: "deny" },
    )).toEqual({ gitPush: "deny", readPathPrefixes: ["/api/v4/search"], writeAction: "deny" });
  });

  test("serviceHostRuleNarrowingIssues checks only the fields the service set", () => {
    expect(serviceHostRuleNarrowingIssues(undefined, { methods: ["DELETE"], pathPrefixes: ["/"] })).toEqual([]);
    expect(serviceHostRuleNarrowingIssues({ gitPush: "write" }, { methods: ["DELETE"] })).toEqual([]);
    expect(serviceHostRuleNarrowingIssues({ methods: ["POST"], pathPrefixes: ["/oauth/token"] }, { pathPrefixes: ["/oauth/token"] })).toEqual([]);
    expect(serviceHostRuleNarrowingIssues({ methods: ["POST"], pathPrefixes: ["/oauth/token"] }, { methods: ["GET", "POST"], pathPrefixes: ["/a", "/oauth/token/x"] }))
      .toEqual([
        "methods includes GET, which the service rule does not allow (service methods: POST)",
        "pathPrefixes includes /a, which is not under a service path prefix (service pathPrefixes: /oauth/token)",
      ]);
  });
});
