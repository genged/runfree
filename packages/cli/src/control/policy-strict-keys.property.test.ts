import fc from "fast-check";
import { describe, expect, test } from "vitest";

import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { validateNetworkPolicy, type CredentialPolicyJson } from "@runfree/runtime-contracts/network-policy";

import { propertyParameters } from "../../../../tests/support/property.ts";
import { validateProxyPolicy } from "../../../proxy/src/policy.ts";
import { compileDesiredPolicies } from "./compiler.ts";

// T14 (spec §4.6 rule 1): every policy object refuses unknown keys, in desired
// and effective policy, in the CLI and in the proxy. Only maps whose keys are
// names by design (hosts, token names, service ids, provider ids, host-service
// names) are exempt: a new key there is a new entry, not an unknown field.

const digest = `sha256:${"a".repeat(64)}`;

const GITLAB_API_BEARER: CredentialPolicyJson = { host: "gitlab.com", header: "Authorization", scheme: "bearer", pathPrefix: "/api/" };
const GITLAB_GIT_BASIC: CredentialPolicyJson = {
  host: "gitlab.com",
  header: "Authorization",
  scheme: "basic",
  username: "oauth2",
  protocol: "git-http",
};

const FULL_REQUEST_RULE = {
  methods: ["GET", "POST"],
  pathPrefixes: ["/api/", "/group/"],
  gitPush: "write",
  writeAction: "ask",
  readPathPrefixes: ["/api/v4/search"],
  writePathPrefixes: ["/api/v4/admin"],
  graphql: { endpoints: ["/api/graphql"], writeOps: "mutation" },
};

function effectiveSample(): Record<string, unknown> {
  return {
    hosts: ["api.example.com", "gitlab.com"],
    tokens: {
      gitlab: { description: "GitLab token", allowAnonymous: true, credentials: [GITLAB_API_BEARER, GITLAB_GIT_BASIC] },
      example: { description: "Example token", credentials: [{ host: "api.example.com", header: "x-api-key", scheme: "raw" }] },
    },
    requests: { "gitlab.com": FULL_REQUEST_RULE },
    writeApproval: "ask",
    hostServices: { db: { target: "host-loopback", port: 15432 } },
  };
}

function desiredSample(): Record<string, unknown> {
  return {
    version: 3,
    hosts: ["api.example.com"],
    tokens: {
      example: { description: "Example token", credentials: [{ host: "api.example.com", header: "x-api-key", scheme: "raw" }] },
    },
    requests: { "api.example.com": { methods: ["GET"] } },
    writeApproval: "ask",
    hostServices: { db: { target: "host-loopback", port: 15432 } },
    services: {
      gitlab: {
        revision: 2,
        definitionDigest: digest,
        selection: { skippedHosts: ["uploads.gitlab.com"], writeMode: "read-only" },
        resolved: {
          hosts: ["gitlab.com"],
          requests: { "gitlab.com": FULL_REQUEST_RULE },
          tokens: {
            gitlab: { description: "GitLab token", allowAnonymous: true, credentials: [GITLAB_API_BEARER, GITLAB_GIT_BASIC] },
          },
          agentEnv: ["GITLAB_CLIENT_ID", "GITLAB_TOKEN"],
          parameters: [{ description: "Client id", envVar: "GITLAB_CLIENT_ID", key: "client-id", oauthField: "client_id" }],
          oauth: {
            gitlab: {
              resourceHost: "gitlab.com",
              resourcePathPrefix: "/api/",
              tokenEndpoints: [{ host: "gitlab.com", path: "/oauth/token" }],
              registrationEndpoints: [{ host: "gitlab.com", path: "/oauth/register" }],
              seeds: [{ description: "Refresh token", envVar: "GITLAB_REFRESH", field: "refresh_token", tokenName: "gitlab-refresh" }],
              passthrough: [{ envVar: "GITLAB_CLIENT_ID", field: "client_id" }],
            },
          },
        },
      },
    },
  };
}

// Paths (dot-joined, "*" for any map key or array index) whose object is a
// name-keyed map rather than a record with a fixed field set.
const EFFECTIVE_MAPS = new Set(["tokens", "requests", "hostServices"]);
const DESIRED_MAPS = new Set([
  "tokens",
  "requests",
  "hostServices",
  "services",
  "services.*.resolved.tokens",
  "services.*.resolved.requests",
  "services.*.resolved.oauth",
]);

// Distinct from every known field, including near misses an older or newer
// writer could produce, and keys with prototype significance.
const UNKNOWN_KEYS = ["zzUnknownField", "Protocol", "pathprefix", "user_name", "constructor", "__proto__"];

type ObjectPath = Array<string | number>;

function recordPaths(value: unknown, maps: Set<string>, at: ObjectPath = []): ObjectPath[] {
  if (Array.isArray(value)) return value.flatMap((entry, index) => recordPaths(entry, maps, [...at, index]));
  if (value === null || typeof value !== "object") return [];
  const pattern = at.map((segment, index) => {
    const parentPattern = at.slice(0, index).map((s) => (typeof s === "number" ? "*" : s)).join(".");
    return typeof segment === "number" || maps.has(parentPattern) ? "*" : segment;
  }).join(".");
  const own = maps.has(pattern) ? [] : [at];
  return [...own, ...Object.entries(value).flatMap(([key, entry]) => recordPaths(entry, maps, [...at, key]))];
}

function withUnknownKey(sample: Record<string, unknown>, at: ObjectPath, key: string): unknown {
  const copy = structuredClone(sample);
  let target: Record<string | number, unknown> = copy;
  for (const segment of at) target = target[segment] as Record<string | number, unknown>;
  // defineProperty, not assignment: `__proto__` must become an own key the way
  // JSON.parse makes it, not a prototype change.
  Object.defineProperty(target, key, { value: "x", enumerable: true, configurable: true, writable: true });
  return copy;
}

describe("strict keys at every object path (T14)", () => {
  test("the samples themselves validate, and cover every record path", () => {
    expect(() => validateNetworkPolicy(effectiveSample())).not.toThrow();
    expect(() => validateDesiredNetworkPolicy(desiredSample())).not.toThrow();
    const effectivePaths = recordPaths(effectiveSample(), EFFECTIVE_MAPS).map((p) => p.join("."));
    const desiredPaths = recordPaths(desiredSample(), DESIRED_MAPS).map((p) => p.join("."));
    expect(effectivePaths).toEqual(expect.arrayContaining([
      "",
      "tokens.gitlab",
      "tokens.gitlab.credentials.1",
      "requests.gitlab.com",
      "requests.gitlab.com.graphql",
      "hostServices.db",
    ]));
    expect(desiredPaths).toEqual(expect.arrayContaining([
      "",
      "services.gitlab",
      "services.gitlab.selection",
      "services.gitlab.resolved",
      "services.gitlab.resolved.tokens.gitlab.credentials.1",
      "services.gitlab.resolved.requests.gitlab.com.graphql",
      "services.gitlab.resolved.parameters.0",
      "services.gitlab.resolved.oauth.gitlab",
      "services.gitlab.resolved.oauth.gitlab.tokenEndpoints.0",
      "services.gitlab.resolved.oauth.gitlab.registrationEndpoints.0",
      "services.gitlab.resolved.oauth.gitlab.seeds.0",
      "services.gitlab.resolved.oauth.gitlab.passthrough.0",
    ]));
    expect(effectivePaths).toHaveLength(9);
    expect(desiredPaths).toHaveLength(19);
  });

  test("the proxy validates with the same contract function", () => {
    // The proxy's policy loader and its effective-control loader both call this
    // function, so the effective cases below cover the proxy too.
    expect(validateProxyPolicy).toBe(validateNetworkPolicy);
  });

  test("effective policy: an unknown key at any record path is refused", () => {
    const sample = effectiveSample();
    for (const at of recordPaths(sample, EFFECTIVE_MAPS)) {
      for (const key of UNKNOWN_KEYS) {
        expect(() => validateNetworkPolicy(withUnknownKey(sample, at, key)), `${at.join(".")} + ${key}`)
          .toThrow(`${key} is not a known`);
      }
    }
  });

  test("desired policy: an unknown key at any record path is refused", () => {
    const sample = desiredSample();
    for (const at of recordPaths(sample, DESIRED_MAPS)) {
      for (const key of UNKNOWN_KEYS) {
        expect(() => validateDesiredNetworkPolicy(withUnknownKey(sample, at, key)), `${at.join(".")} + ${key}`)
          .toThrow(`${key} is not a known`);
      }
    }
  });
});

const usernameArbitrary = fc.string({
  unit: fc.constantFrom(..."!\"#$%&'()*+,-./0123456789;<=>?@ABCXYZ[\\]^_`abcxyz{|}~"),
  minLength: 1,
  maxLength: 64,
});

const credentialArbitrary: fc.Arbitrary<CredentialPolicyJson> = fc.record({
  scheme: fc.constantFrom("bearer", "raw", "basic") as fc.Arbitrary<CredentialPolicyJson["scheme"]>,
  username: usernameArbitrary,
  pathPrefix: fc.option(fc.constantFrom("/", "/api/", "/group/repo.git"), { nil: undefined }),
  protocol: fc.option(fc.constantFrom("git-http", "git-lfs") as fc.Arbitrary<NonNullable<CredentialPolicyJson["protocol"]>>, { nil: undefined }),
}).map(({ scheme, username, pathPrefix, protocol }) => ({
  host: "gitlab.com",
  header: "Authorization",
  scheme,
  ...(scheme === "basic" ? { username } : {}),
  ...(pathPrefix !== undefined ? { pathPrefix } : {}),
  ...(protocol !== undefined ? { protocol } : {}),
}));

describe("new credential fields survive validate, compile and canonicalize (T14)", () => {
  test("scheme, username and protocol round-trip unchanged into the effective policy", () => {
    fc.assert(fc.property(credentialArbitrary, fc.boolean(), (credential, viaService) => {
      const token = { description: "GitLab token", credentials: [credential] };
      const desired = viaService
        ? {
          version: 3,
          hosts: [],
          services: {
            gitlab: { revision: 1, definitionDigest: digest, resolved: { hosts: ["gitlab.com"], tokens: { gitlab: token } } },
          },
        }
        : { version: 3, hosts: ["gitlab.com"], tokens: { gitlab: token } };
      const validated = validateDesiredNetworkPolicy(desired);
      const stored = viaService ? validated.services?.gitlab.resolved.tokens?.gitlab : validated.tokens?.gitlab;
      expect(stored?.credentials).toEqual([credential]);

      // Canonical form is a fixpoint, through a JSON round trip as on disk.
      const canonical = canonicalDesiredNetworkPolicy(validated);
      expect(canonicalDesiredNetworkPolicy(JSON.parse(canonical) as DesiredNetworkPolicyJson)).toBe(canonical);

      const compiled = compileDesiredPolicies({ project: validated, local: { version: 2, hosts: [] } });
      expect(compiled.policy.tokens?.gitlab.credentials).toEqual([credential]);
      const reloaded = validateNetworkPolicy(JSON.parse(JSON.stringify(compiled.policy)));
      expect(reloaded.raw).toEqual(compiled.policy);
      expect(reloaded.credentialMappings[0]).toMatchObject(credential);
    }), propertyParameters({ numRuns: 100 }));
  });
});
