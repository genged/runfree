import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import { afterEach, beforeEach, describe, expect, test, } from "vitest";

import {
  normalizeHostname,
  normalizePathPrefix,
  validateNetworkPolicy,
  type PolicyJson,
  type RequestPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import {
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
  type DesiredServiceEntry,
} from "@runfree/runtime-contracts/desired-network-policy";

import {
  SERVICES,
  type Service,
  serviceParameters,
  broadHostWarningLines,
  isUserServiceId,
  service,
  serviceBroadHosts,
  serviceHostNames,
  serviceNames,
  serviceSuggestionLines,
  suggestableServicesForHost,
  validateServiceDefinition,
} from "./services.ts";
import {
  desiredServiceEntry,
  desiredServicePolicy,
  doctorIntent,
  parseServiceRecords,
  runAdminAction,
  serviceConfigureIntent,
  serviceHostKeepReason,
  type ServiceRecords,
} from "../packages/cli/src/admin/options.ts";
import { createAdminState } from "../packages/cli/src/admin/context.ts";
import { projectInfo } from "../packages/cli/src/config.ts";
import { approveNetworkCandidate } from "../packages/cli/src/control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../packages/cli/src/control/candidates.ts";
import { compileDesiredPolicies } from "../packages/cli/src/control/compiler.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { RUNFREE_RUNTIME_DIGEST } from "../packages/cli/src/embedded-assets.generated.ts";
import { loadUserServiceCatalog, validateUserServiceDefinitionObject } from "../packages/cli/src/user-services.ts";
import { flushWarnings } from "../packages/cli/src/warnings.ts";
import { classifyWrite } from "../packages/proxy/src/policy.ts";
import { cliEntryArgv } from "../tests/support/prebuilt-entry.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

// Registry snapshot for the revision guard below. When a service's hosts (or
// removedHosts) change, the change MUST bump that service's revision and then
// update this snapshot in the same commit; the guard fails on unbumped edits.
const REVISION_SNAPSHOT: Record<string, { revision: number; hosts: string[]; removedHosts: string[] }> = {
  "agent-claude": {
    revision: 1,
    hosts: ["api.anthropic.com", "platform.claude.com"],
    removedHosts: [],
  },
  "agent-codex": {
    revision: 1,
    hosts: ["api.openai.com", "auth.openai.com", "chatgpt.com"],
    removedHosts: [],
  },
  node: {
    revision: 2,
    hosts: ["registry.npmjs.org", "registry.yarnpkg.com"],
    removedHosts: [],
  },
  python: {
    revision: 1,
    hosts: ["pypi.org", "files.pythonhosted.org"],
    removedHosts: [],
  },
  rust: {
    revision: 1,
    hosts: ["crates.io", "static.crates.io", "index.crates.io", "static.rust-lang.org"],
    removedHosts: [],
  },
  go: {
    revision: 1,
    hosts: ["proxy.golang.org", "sum.golang.org", "storage.googleapis.com"],
    removedHosts: [],
  },
  github: {
    revision: 2,
    hosts: [
      "github.com",
      "api.github.com",
      "codeload.github.com",
      "raw.githubusercontent.com",
      "objects.githubusercontent.com",
      "avatars.githubusercontent.com",
    ],
    removedHosts: [],
  },
  "docker-registry": {
    revision: 1,
    hosts: ["registry-1.docker.io", "auth.docker.io", "index.docker.io", "production.cloudflare.docker.com"],
    removedHosts: [],
  },
  "ubuntu-apt": {
    revision: 1,
    hosts: ["archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"],
    removedHosts: [],
  },
  anthropic: {
    revision: 1,
    hosts: ["api.anthropic.com"],
    removedHosts: [],
  },
  "apple-ads": {
    revision: 2,
    hosts: ["api.searchads.apple.com", "appleid.apple.com"],
    removedHosts: [],
  },
  "appstore-connect": {
    revision: 1,
    hosts: ["api.appstoreconnect.apple.com"],
    removedHosts: [],
  },
  gemini: {
    revision: 1,
    hosts: ["generativelanguage.googleapis.com"],
    removedHosts: [],
  },
  openai: {
    revision: 1,
    hosts: ["api.openai.com"],
    removedHosts: [],
  },
  "google-ads": {
    revision: 2,
    hosts: ["googleads.googleapis.com", "oauth2.googleapis.com"],
    removedHosts: [],
  },
  ruby: { revision: 1, hosts: ["rubygems.org", "index.rubygems.org"], removedHosts: [] },
  java: {
    revision: 1,
    hosts: ["repo1.maven.org", "repo.maven.apache.org", "plugins.gradle.org", "plugins-artifacts.gradle.org", "services.gradle.org"],
    removedHosts: [],
  },
  dotnet: { revision: 1, hosts: ["api.nuget.org", "www.nuget.org"], removedHosts: [] },
  php: { revision: 1, hosts: ["packagist.org", "repo.packagist.org"], removedHosts: [] },
  dart: { revision: 1, hosts: ["pub.dev", "storage.googleapis.com"], removedHosts: [] },
  conda: { revision: 1, hosts: ["conda.anaconda.org", "repo.anaconda.com"], removedHosts: [] },
  terraform: { revision: 1, hosts: ["registry.terraform.io", "releases.hashicorp.com"], removedHosts: [] },
  homebrew: { revision: 1, hosts: ["formulae.brew.sh", "ghcr.io"], removedHosts: [] },
  "debian-apt": { revision: 1, hosts: ["deb.debian.org", "security.debian.org"], removedHosts: [] },
  "alpine-apk": { revision: 1, hosts: ["dl-cdn.alpinelinux.org"], removedHosts: [] },
  gitlab: { revision: 1, hosts: ["gitlab.com"], removedHosts: [] },
  bitbucket: { revision: 1, hosts: ["bitbucket.org", "api.bitbucket.org"], removedHosts: [] },
  mistral: { revision: 1, hosts: ["api.mistral.ai"], removedHosts: [] },
  groq: { revision: 1, hosts: ["api.groq.com"], removedHosts: [] },
  deepseek: { revision: 1, hosts: ["api.deepseek.com"], removedHosts: [] },
  xai: { revision: 1, hosts: ["api.x.ai"], removedHosts: [] },
  openrouter: { revision: 1, hosts: ["openrouter.ai"], removedHosts: [] },
  perplexity: { revision: 1, hosts: ["api.perplexity.ai"], removedHosts: [] },
  elevenlabs: { revision: 1, hosts: ["api.elevenlabs.io"], removedHosts: [] },
};

const ALL_SERVICE_IDS = [
  "agent-claude",
  "agent-codex",
  "alpine-apk",
  "anthropic",
  "apple-ads",
  "appstore-connect",
  "bitbucket",
  "conda",
  "dart",
  "debian-apt",
  "deepseek",
  "docker-registry",
  "dotnet",
  "elevenlabs",
  "gemini",
  "github",
  "gitlab",
  "go",
  "google-ads",
  "groq",
  "homebrew",
  "java",
  "mistral",
  "node",
  "openai",
  "openrouter",
  "perplexity",
  "php",
  "python",
  "ruby",
  "rust",
  "terraform",
  "ubuntu-apt",
  "xai",
];

describe("service registry invariants", () => {
  test("ships the spec'd ecosystem and provider services", () => {
    expect(serviceNames()).toEqual(ALL_SERVICE_IDS);
  });

  test("shared service-definition validator accepts curated registry and reserves user namespace", () => {
    for (const svc of Object.values(SERVICES)) {
      expect(validateServiceDefinition(svc, { origin: "registry" }), svc.id).toEqual([]);
      expect(isUserServiceId(svc.id), `${svc.id} must not use reserved user namespace`).toBe(false);
      expect(svc.credential?.tokenName.startsWith("user-") ?? false, `${svc.id} token name must not use reserved user namespace`).toBe(false);
      expect(svc.oauthCredential?.seeds.some((seed) => seed.tokenName.startsWith("user-")) ?? false, `${svc.id} OAuth seed token must not use reserved user namespace`).toBe(false);
    }
  });

  test("agent operational services are credentialless, exact, and allow-write by default", () => {
    expect(serviceHostNames(SERVICES["agent-codex"])).toEqual(["api.openai.com", "auth.openai.com", "chatgpt.com"]);
    expect(serviceHostNames(SERVICES["agent-claude"])).toEqual(["api.anthropic.com", "platform.claude.com"]);
    for (const id of ["agent-codex", "agent-claude"] as const) {
      expect(SERVICES[id].credential).toBeUndefined();
      expect(SERVICES[id].oauthCredential).toBeUndefined();
      expect(SERVICES[id].defaultWriteMode).toBe("allow-write");
      expect(SERVICES[id].neverAutoSuggest).toBe(true);
      expect(SERVICES[id].label).not.toMatch(/Claude Code|Codex/);
      expect(SERVICES[id].explanations.join(" ")).not.toMatch(/Claude Code|Codex/);
    }
  });

  test("new-project templates authorize no hosts or pre-recorded services", () => {
    const policy = JSON.parse(fs.readFileSync(path.join(repoRoot, "packages/cli/templates/network-policy.json"), "utf8")) as PolicyJson;
    const config = JSON.parse(fs.readFileSync(path.join(repoRoot, "packages/cli/templates/runfree.json"), "utf8")) as {
      services?: Record<string, { revision: number; writeMode: string }>;
    };
    expect(policy).toEqual({ version: 2, hosts: [] });
    expect(config.services).toBeUndefined();
  });

  test("every host is exact, normalized, and unique within its service", () => {
    for (const svc of Object.values(SERVICES)) {
      const hosts = serviceHostNames(svc);
      expect(new Set(hosts).size, `${svc.id} has duplicate hosts`).toBe(hosts.length);
      for (const host of [...hosts, ...(svc.removedHosts ?? [])]) {
        expect(normalizeHostname(host), `${svc.id} host ${host} must equal its normalized form`).toBe(host);
        expect(host.includes("*"), `${svc.id} host ${host} must not be a wildcard`).toBe(false);
      }
      expect(svc.id).toBe(svc.id.toLowerCase());
      expect(Number.isInteger(svc.revision) && svc.revision >= 1).toBe(true);
      expect(svc.explanations.length).toBeGreaterThan(0);
    }
  });

  test("every credential targets only hosts the service allowlists", () => {
    for (const svc of Object.values(SERVICES)) {
      if (!svc.credential) continue;
      const hosts = new Set(serviceHostNames(svc));
      for (const credential of svc.credential.credentials) {
        expect(hosts.has(credential.host), `${svc.id} credential host ${credential.host} must be a service host`).toBe(true);
      }
      expect(svc.credential.agentEnv.length).toBeGreaterThan(0);
    }
    // The credentialed services and their token names.
    expect(Object.values(SERVICES).filter((svc) => svc.credential).map((svc) => svc.id).sort())
      .toEqual([
        "anthropic",
        "appstore-connect",
        "bitbucket",
        "deepseek",
        "elevenlabs",
        "gemini",
        "github",
        "gitlab",
        "google-ads",
        "groq",
        "mistral",
        "openai",
        "openrouter",
        "perplexity",
        "xai",
      ]);
  });

  test("oauth credentials stay curated to service hosts and narrow fields", () => {
    const oauthServices = Object.values(SERVICES).filter((svc) => svc.oauthCredential).map((svc) => svc.id).sort();
    expect(oauthServices).toEqual(["apple-ads", "google-ads"]);
    // Every OAuth service's resource host and token endpoint host must be hosts
    // the service itself allowlists (no off-list egress), over HTTPS.
    for (const id of oauthServices) {
      const oauthSvc = SERVICES[id];
      const oauthHosts = new Set(serviceHostNames(oauthSvc));
      expect(oauthHosts.has(oauthSvc.oauthCredential?.resourceHost ?? "")).toBe(true);
      const oauthEndpoint = new URL(oauthSvc.oauthCredential?.tokenEndpoint ?? "");
      expect(oauthEndpoint.protocol).toBe("https:");
      expect(oauthHosts.has(oauthEndpoint.hostname)).toBe(true);
    }
    const svc = SERVICES["google-ads"];
    expect(svc.oauthCredential?.resourceHost).toBe("googleads.googleapis.com");
    expect(svc.oauthCredential?.seeds.map((seed) => seed.field).sort()).toEqual(["client_secret", "refresh_token"]);
    expect(svc.parameters).toEqual([{
      key: "client-id",
      envVar: "GOOGLE_ADS_CLIENT_ID",
      oauthField: "client_id",
      description: "Google Ads OAuth client id",
      example: "1234567890-abc.apps.googleusercontent.com",
    }]);
    // Apple Ads is OAuth-only (no static credential): the lone seed is the
    // client-secret JWT exchanged at appleid.apple.com for access tokens.
    const apple = SERVICES["apple-ads"];
    expect(apple.credential).toBeUndefined();
    expect(apple.oauthCredential?.resourceHost).toBe("api.searchads.apple.com");
    expect(apple.oauthCredential?.tokenEndpoint).toBe("https://appleid.apple.com/auth/oauth2/token");
    expect(apple.oauthCredential?.seeds.map((seed) => seed.field)).toEqual(["client_secret"]);
    expect(apple.parameters).toEqual([{
      key: "client-id",
      envVar: "APPLE_ADS_CLIENT_ID",
      oauthField: "client_id",
      description: "Apple Ads OAuth client id (SEARCHADS.<uuid>)",
      example: "SEARCHADS.12345678-1234-1234-1234-123456789012",
      pattern: "^SEARCHADS\\.[0-9a-fA-F-]{36}$",
    }]);
  });

  test("service parameters are non-secret, unique, and disjoint from credential env", () => {
    const owners = new Map<string, string>();
    for (const svc of Object.values(SERVICES)) {
      const parameters = serviceParameters(svc);
      const keys = parameters.map((parameter) => parameter.key);
      expect(new Set(keys).size).toBe(keys.length);
      for (const parameter of parameters) {
        expect(parameter.key).toMatch(/^[a-z][a-z0-9-]{0,31}$/);
        expect(parameter.envVar).toMatch(/^[A-Za-z_][A-Za-z0-9_]*$/);
        expect(parameter.description.trim()).not.toBe("");
        if (parameter.oauthField !== undefined) expect(svc.oauthCredential).toBeDefined();
        if (parameter.pattern !== undefined) expect(() => new RegExp(parameter.pattern ?? "")).not.toThrow();
        if (parameter.pattern !== undefined && parameter.example !== undefined) {
          expect(parameter.example).toMatch(new RegExp(parameter.pattern));
        }
        expect(svc.credential?.agentEnv ?? []).not.toContain(parameter.envVar);
        expect((svc.oauthCredential?.seeds ?? []).map((seed) => seed.envVar)).not.toContain(parameter.envVar);
        const owner = owners.get(parameter.envVar);
        expect(owner === undefined || owner === svc.id).toBe(true);
        owners.set(parameter.envVar, svc.id);
      }
    }
    expect(validateServiceDefinition(SERVICES["apple-ads"], { origin: "registry" })).toEqual([]);
  });

  test("validateServiceDefinition rejects malformed parameters", () => {
    const base = SERVICES.github;
    const issues = (parameters: unknown) =>
      validateServiceDefinition({ ...base, parameters } as Service, { origin: "registry" });
    expect(issues([{ key: "Bad Key", envVar: "X", description: "d" }])).toContainEqual(expect.stringContaining("parameter key"));
    expect(issues([{ key: "a", envVar: "GH_TOKEN", description: "d" }])).toContainEqual(expect.stringContaining("collides"));
    expect(issues([{ key: "a", envVar: "A", description: "d" }, { key: "a", envVar: "B", description: "d" }]))
      .toContainEqual(expect.stringContaining("duplicate parameter key"));
    expect(issues([{ key: "a", envVar: "A", description: "d", oauthField: "client_id" }]))
      .toContainEqual(expect.stringContaining("oauthField"));
    expect(issues([{ key: "a", envVar: "A", description: "d", pattern: "(" }]))
      .toContainEqual(expect.stringContaining("pattern"));
    expect(issues([{ key: "a", envVar: "A", description: " " }])).toContainEqual(expect.stringContaining("description"));
    expect(issues([{ key: "a", envVar: "A", description: "d", pattern: "x+" }]))
      .toContainEqual(expect.stringContaining("pattern must be anchored"));
    expect(issues([{ key: "a", envVar: "A", description: "d", pattern: "^x+$" }])).toEqual([]);
    expect(issues([{ key: "a", envVar: "A", description: "d" }])).toEqual([]);
  });

  test("read-only profiles target only service hosts with normalized paths", () => {
    for (const svc of Object.values(SERVICES)) {
      if (!svc.readOnly) continue;
      const hosts = new Set(serviceHostNames(svc));
      for (const [host, profile] of Object.entries(svc.readOnly)) {
        expect(hosts.has(host), `${svc.id} readOnly host ${host} must be a service host`).toBe(true);
        for (const prefix of [...(profile.readPathPrefixes ?? []), ...(profile.writePathPrefixes ?? [])]) {
          expect(normalizePathPrefix(prefix), `${svc.id} readOnly ${host} prefix ${prefix} must be normalized`).toBe(prefix);
        }
        for (const endpoint of profile.graphql?.endpoints ?? []) {
          expect(normalizePathPrefix(endpoint), `${svc.id} readOnly ${host} graphql endpoint ${endpoint} must be normalized`).toBe(endpoint);
          expect(endpoint.includes("*"), `${svc.id} readOnly ${host} graphql endpoint ${endpoint} must be exact`).toBe(false);
        }
        if (profile.gitPush !== undefined) expect(profile.gitPush).toBe("write");
      }
    }
    // The services carrying a read-only profile: git hosts (fetch stays a
    // read, push classifies write), GraphQL endpoints, and the POST-read
    // model providers (MED-6).
    expect(Object.values(SERVICES).filter((svc) => svc.readOnly).map((svc) => svc.id).sort())
      .toEqual([
        "anthropic",
        "bitbucket",
        "deepseek",
        "gemini",
        "github",
        "gitlab",
        "groq",
        "mistral",
        "node",
        "openai",
        "openrouter",
        "perplexity",
        "xai",
      ]);
  });

  test("every broad annotation carries an explanation string", () => {
    const broadHosts = Object.values(SERVICES).flatMap((svc) => serviceBroadHosts(svc));
    expect(broadHosts.map((host) => host.host).sort()).toEqual([
      "conda.anaconda.org",
      "ghcr.io",
      "objects.githubusercontent.com",
      "production.cloudflare.docker.com",
      "storage.googleapis.com",
      "storage.googleapis.com",
    ]);
    for (const host of broadHosts) {
      expect(typeof host.explanation, `${host.host} broad annotation needs an explanation`).toBe("string");
      expect((host.explanation ?? "").length).toBeGreaterThan(20);
    }
  });

  test("revision guard: host changes without a revision bump fail", () => {
    for (const svc of Object.values(SERVICES)) {
      const snapshot = REVISION_SNAPSHOT[svc.id];
      expect(snapshot, `add ${svc.id} to REVISION_SNAPSHOT`).toBeDefined();
      const hostsChanged = JSON.stringify(serviceHostNames(svc)) !== JSON.stringify(snapshot.hosts)
        || JSON.stringify(svc.removedHosts ?? []) !== JSON.stringify(snapshot.removedHosts);
      if (hostsChanged) {
        expect(
          svc.revision,
          `${svc.id} hosts changed: bump revision above ${snapshot.revision} and update REVISION_SNAPSHOT`,
        ).toBeGreaterThan(snapshot.revision);
      } else {
        expect(svc.revision, `${svc.id} revision changed without a host change`).toBe(snapshot.revision);
      }
    }
    expect(Object.keys(REVISION_SNAPSHOT).sort()).toEqual(serviceNames());
  });

  test("ubuntu-apt is never auto-suggested", () => {
    expect(SERVICES["ubuntu-apt"].neverAutoSuggest).toBe(true);
    expect(SERVICES["ubuntu-apt"].detect).toEqual([]);
    expect(suggestableServicesForHost("archive.ubuntu.com")).toEqual([]);
    expect(serviceSuggestionLines("archive.ubuntu.com")).toEqual([]);
  });

  test("python is a credential-less service that owns the PyPI hosts", () => {
    expect(SERVICES.python.credential).toBeUndefined();
    expect(serviceHostNames(SERVICES.python)).toEqual(["pypi.org", "files.pythonhosted.org"]);
  });

  test("github merges the full ecosystem with an optional credential on api/raw", () => {
    expect(serviceHostNames(SERVICES.github)).toEqual([
      "github.com",
      "api.github.com",
      "codeload.github.com",
      "raw.githubusercontent.com",
      "objects.githubusercontent.com",
      "avatars.githubusercontent.com",
    ]);
    expect(SERVICES.github.credential?.tokenName).toBe("github");
    expect(SERVICES.github.revision).toBe(2);
    expect(SERVICES.github.credential?.allowAnonymous).toBe(true);
    expect(SERVICES.github.credential?.agentEnv).toEqual(["GH_TOKEN", "GITHUB_TOKEN"]);
    expect(SERVICES.github.credential?.credentials.map((c) => c.host)).toEqual([
      "api.github.com",
      "raw.githubusercontent.com",
    ]);
  });

  test("node owns only the npm bulk advisory read exemption and its exact adoption migration", () => {
    expect(SERVICES.node.revision).toBe(2);
    expect(SERVICES.node.readOnly).toEqual({
      "registry.npmjs.org": {
        readPathPrefixes: ["/-/npm/v1/security/advisories/bulk"],
      },
    });
    expect(SERVICES.node.migrations).toEqual([
      {
        fromRevision: 1,
        toRevision: 2,
        requestRuleReplacements: [
          {
            host: "registry.npmjs.org",
            field: "readPathPrefixes",
            from: ["/-/npm/v1/security/"],
            to: ["/-/npm/v1/security/advisories/bulk"],
          },
        ],
      },
    ]);
  });

  test("node's maintained profile exempts only the npm bulk advisory POST", () => {
    const profile = SERVICES.node.readOnly?.["registry.npmjs.org"];
    const rule: RequestPolicyJson = {
      ...(profile?.readPathPrefixes ? { readPathPrefixes: profile.readPathPrefixes } : {}),
    };
    const classify = (
      requestPath: string,
      options: { headers?: Record<string, string>; method?: string } = {},
    ) => classifyWrite({
      method: options.method ?? "POST",
      url: new URL(`https://registry.npmjs.org${requestPath}`),
      rule,
      headers: options.headers,
    });

    expect(classify("/-/npm/v1/security/advisories/bulk")).toEqual({ write: false });
    expect(classify("/-/npm/v1/security/advisories/bulk?packages=one")).toEqual({ write: false });
    expect(classify("/-/npm/v1/security/audits/quick").write).toBe(true);
    expect(classify("/-/npm/v1/security/other").write).toBe(true);
    expect(classify("/-/package/example/dist-tags/latest").write).toBe(true);
    expect(classify("/-/npm/v1/security/advisories/bulk%2fescape").write).toBe(true);
    expect(classify("/-/npm/v1/security/advisories/bulk//escape").write).toBe(true);
    expect(classify("/-/npm/v1/security/advisories/bulk", {
      method: "GET",
      headers: { "x-http-method-override": "POST" },
    }).write).toBe(true);
  });

  test("rejects malformed anonymous fallback and migration metadata", () => {
    const invalidAnonymous = {
      ...SERVICES.github,
      credential: { ...SERVICES.github.credential, allowAnonymous: "yes" },
    } as unknown as Service;
    expect(validateServiceDefinition(invalidAnonymous, { origin: "registry" }))
      .toContain("github: credential.allowAnonymous must be a boolean when present");

    const invalidMigration = {
      ...SERVICES.node,
      migrations: [{
        fromRevision: 1,
        toRevision: 3,
        requestRuleReplacements: [{
          host: "registry.npmjs.org",
          field: "readPathPrefixes",
          from: ["/-/npm/v1/security/?query"],
          to: ["/-/npm/v1/security/"],
        }],
      }],
    } as Service;
    const issues = validateServiceDefinition(invalidMigration, { origin: "registry" });
    expect(issues).toContain("node: migrations[0] must cover adjacent revisions");
    expect(issues).toContain("node: migrations[0].toRevision must not exceed service revision 2");
    expect(issues.some((issue) => issue.includes("pathPrefix must not contain query or fragment"))).toBe(true);
    expect(issues).toContain("node: migrations[0].requestRuleReplacements[0].to must equal the current service profile");
  });

  test("service lookups are case-insensitive and unknown ids return undefined", () => {
    expect(service("NODE")?.id).toBe("node");
    expect(service("nope")).toBeUndefined();
  });
});

describe("service suggestion lines (denial/audit secondary feedback)", () => {
  test("name the owning service with host and broad counts, plus a credential follow-up", () => {
    const lines = serviceSuggestionLines("api.github.com");
    expect(lines[0]).toBe('api.github.com is part of service "github" (6 hosts, 1 broad).');
    expect(lines[1]).toContain("runfree service enable github");
    expect(lines[1]).toContain("never applied automatically");
    expect(lines[2]).toBe("runfree service enable github --from-env GH_TOKEN   # also inject the github credential");
    expect(lines.join("\n")).toContain("note: objects.githubusercontent.com");
  });

  test("credential-less services without broad hosts get exactly two lines", () => {
    const lines = serviceSuggestionLines("registry.npmjs.org");
    expect(lines).toEqual([
      'registry.npmjs.org is part of service "node" (2 hosts).',
      "runfree service enable node   # allow the whole ecosystem (never applied automatically)",
    ]);
  });

  test("provider API hosts now surface their credentialed service", () => {
    const lines = serviceSuggestionLines("api.openai.com");
    expect(lines[0]).toBe('api.openai.com is part of service "openai" (1 hosts).');
    expect(lines[2]).toBe("runfree service enable openai --from-env OPENAI_API_KEY   # also inject the openai credential");
  });

  test("hosts outside every service produce no lines", () => {
    expect(serviceSuggestionLines("api.example.com")).toEqual([]);
  });

  test("broad warning lines cover exactly the broad hosts", () => {
    expect(broadHostWarningLines(SERVICES.go.hosts)).toHaveLength(1);
    expect(broadHostWarningLines(SERVICES.node.hosts)).toEqual([]);
  });
});

describe("service record parsing (hostile project config)", () => {
  test("reads records from the `services` key, ignoring malformed entries", () => {
    expect(parseServiceRecords({})).toEqual({});
    expect(parseServiceRecords({ services: "nope" })).toEqual({});
    expect(parseServiceRecords({
      services: {
        node: { revision: 2 },
        bad1: { revision: 0 },
        bad2: { revision: "x" },
        bad3: null,
        github: { revision: 1, skippedHosts: ["objects.githubusercontent.com"] },
        bad4: { revision: 1, skippedHosts: [42] },
      },
    })).toEqual({
      node: { revision: 2 },
      github: { revision: 1, skippedHosts: ["objects.githubusercontent.com"] },
      bad4: { revision: 1 },
    });
  });
});

describe("serviceHostKeepReason (conservative disable computation)", () => {
  const registry: Record<string, Service> = {
    alpha: {
      id: "alpha",
      label: "Alpha",
      revision: 2,
      hosts: [{ host: "shared.example.com" }, { host: "alpha-only.example.com" }],
      detect: [],
      explanations: ["alpha"],
    },
    beta: {
      id: "beta",
      label: "Beta",
      revision: 1,
      hosts: [{ host: "shared.example.com" }],
      detect: [],
      explanations: ["beta"],
    },
  };

  test("keeps hosts that still carry a requests rule and flags the rule", () => {
    const policy: PolicyJson = {
      hosts: ["shared.example.com"],
      tokens: {},
      requests: { "shared.example.com": { gitPush: "deny" } },
    };
    expect(serviceHostKeepReason(policy, { alpha: { revision: 2 } }, "alpha", "shared.example.com", registry))
      .toEqual({ reason: "still has request rules", requestRule: true });
  });

  test("keeps hosts required by a token credential mapping (also covers services enabled by an older CLI)", () => {
    const policy: PolicyJson = {
      hosts: ["alpha-only.example.com"],
      tokens: {
        mytoken: {
          description: "token",
          credentials: [{ host: "alpha-only.example.com", header: "Authorization", scheme: "bearer" }],
        },
      },
    };
    expect(serviceHostKeepReason(policy, { alpha: { revision: 2 } }, "alpha", "alpha-only.example.com", registry))
      .toEqual({ reason: "required by token credential mapping: mytoken" });
  });

  test("keeps hosts required by another enabled service, unless that service skipped them", () => {
    const policy: PolicyJson = { hosts: ["shared.example.com"], tokens: {} };
    const records: ServiceRecords = { alpha: { revision: 2 }, beta: { revision: 1 } };
    expect(serviceHostKeepReason(policy, records, "alpha", "shared.example.com", registry))
      .toEqual({ reason: "required by enabled service beta" });
    const skippedRecords: ServiceRecords = {
      alpha: { revision: 2 },
      beta: { revision: 1, skippedHosts: ["shared.example.com"] },
    };
    expect(serviceHostKeepReason(policy, skippedRecords, "alpha", "shared.example.com", registry)).toBeUndefined();
  });

  test("unknown recorded service ids never keep a host", () => {
    const policy: PolicyJson = { hosts: ["shared.example.com"], tokens: {} };
    expect(serviceHostKeepReason(policy, { mystery: { revision: 9 } }, "alpha", "shared.example.com", registry))
      .toBeUndefined();
  });
});

describe("desiredServicePolicy", () => {
  test("projects hosts, classifiers, credentials, and placeholders deterministically", () => {
    expect(desiredServicePolicy(SERVICES.github, {
      skippedHosts: ["objects.githubusercontent.com"],
      writeMode: "read-only",
    })).toEqual({
      hosts: [
        "api.github.com",
        "avatars.githubusercontent.com",
        "codeload.github.com",
        "github.com",
        "raw.githubusercontent.com",
      ],
      requestRules: {
        "api.github.com": {
          writeAction: "deny",
          graphql: { endpoints: ["/graphql"], writeOps: "mutation" },
        },
        "avatars.githubusercontent.com": { writeAction: "deny" },
        "codeload.github.com": { writeAction: "deny" },
        "github.com": { writeAction: "deny", gitPush: "write" },
        "raw.githubusercontent.com": { writeAction: "deny" },
      },
      credential: {
        tokenName: "github",
        description: "GitHub API token for API and raw content requests",
        allowAnonymous: true,
        links: [
          { host: "api.github.com", header: "Authorization", scheme: "bearer" },
          { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" },
        ],
        agentEnv: ["GH_TOKEN", "GITHUB_TOKEN"],
      },
    });
  });

  test("projects the exact OAuth token endpoint rule", () => {
    const projected = desiredServicePolicy(SERVICES["google-ads"]);
    expect(projected.requestRules["oauth2.googleapis.com"]).toEqual({
      methods: ["POST"],
      pathPrefixes: ["/token"],
    });
  });
});

// --- CLI-level semantics through the spawned admin entrypoint ---------------

let tmpBase: string;
let tmp: string;
let home: string;

type AdminRunResult = {
  status: number;
  stderr: string;
  stdout: string;
};

function writeFixtureRepo(policy: unknown, config?: unknown): void {
  fs.mkdirSync(path.join(tmp, ".runfree"), { recursive: true });
  const nodeModulesLink = path.join(tmp, "node_modules");
  if (!fs.existsSync(nodeModulesLink)) fs.symlinkSync(path.join(repoRoot, "node_modules"), nodeModulesLink, "dir");
  fs.writeFileSync(path.join(tmp, ".runfree/network-policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
  if (config !== undefined) {
    fs.writeFileSync(path.join(tmp, ".runfree/runfree.json"), `${JSON.stringify(config, null, 2)}\n`);
  }
}

function writeApprovedDesiredFixture(policy: DesiredNetworkPolicyJson): void {
  writeFixtureRepo(policy, {
    version: 4,
    agents: { default: "claude" },
    runtime: {},
  });
  const env = adminTestEnv();
  const project = projectInfo(tmp, env);
  const candidate = captureDesiredPolicyCandidate(tmp, project.paths.controlCandidatesDir);
  approveNetworkCandidate(tmp, project, candidate, "network-project", "interactive");
  approveNetworkCandidate(tmp, project, candidate, "network-local", "interactive");
}

function userServicesDir(): string {
  return path.join(home, ".config", "runfree", "services");
}

function installEmptyRuntimeDockerFake(): string {
  const fakeBin = path.join(tmpBase, "fake-docker-bin");
  fs.mkdirSync(fakeBin, { recursive: true });
  const dockerPath = path.join(fakeBin, "docker");
  if (!fs.existsSync(dockerPath)) {
    fs.writeFileSync(dockerPath, `#!/bin/sh
if [ "$1" = "ps" ]; then
  exit 0
fi
printf 'unexpected docker invocation: %s\\n' "$*" >&2
exit 97
`, { mode: 0o755 });
  }
  return fakeBin;
}

function writeUserServiceFile(id: string, definition: Record<string, unknown>): void {
  fs.mkdirSync(userServicesDir(), { recursive: true });
  fs.writeFileSync(path.join(userServicesDir(), `${id}.json`), `${JSON.stringify(definition, null, 2)}\n`);
}

function userAcmeDefinition(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    id: "user-acme",
    label: "Acme internal API",
    revision: 1,
    hosts: [
      { host: "api.acme.example" },
      { host: "cdn.acme.example", broad: true, explanation: "Shared Acme CDN host that can serve arbitrary tenant content." },
    ],
    explanations: ["Acme REST API: api.acme.example"],
    detect: [{ kind: "file", path: ".acme.toml" }],
    credential: {
      tokenDescription: "Acme API token",
      agentEnv: ["ACME_TOKEN"],
      credentials: [
        { host: "api.acme.example", header: "Authorization", scheme: "bearer" },
      ],
    },
    ...overrides,
  };
}

function staleNodeDesiredEntry(): DesiredServiceEntry {
  return {
    definitionDigest: `sha256:${"a".repeat(64)}`,
    revision: 1,
    resolved: {
      hosts: ["registry.npmjs.org"],
      requests: {
        "registry.npmjs.org": { readPathPrefixes: ["/-/npm/v1/security/"] },
      },
    },
  };
}

function adminTestEnv(extraEnv: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const fakeBin = installEmptyRuntimeDockerFake();
  return {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local/share"),
    XDG_STATE_HOME: path.join(home, ".local/state"),
    RUNFREE_PACKAGE_ROOT: tmp,
    RUNFREE_PROJECT_ID: projectHash(tmp),
    RUNFREE_RUNTIME_DIGEST,
    RUNFREE_TEST_FAKE_DOCKER: "1",
    PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    ...extraEnv,
  };
}

// Run a command through the typed runfree CLI subprocess. Used for tests that
// need real stdin (interactive confirm prompts, --from-stdin secrets).
function runAdminCli(
  args: string[],
  options: { input?: string; extraEnv?: NodeJS.ProcessEnv } = {},
): AdminRunResult {
  fs.mkdirSync(home, { recursive: true });
  const env = adminTestEnv(options.extraEnv);
  const result = childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", tmp, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    input: options.input,
    env,
  });
  return {
    status: result.status ?? 1,
    stderr: result.stderr,
    stdout: result.stdout,
  };
}

// Run typed admin enforcement in-process within a fresh admin state.
async function runAdmin(
  action: () => void | Promise<void>,
  options: { extraEnv?: NodeJS.ProcessEnv } = {},
): Promise<AdminRunResult> {
  fs.mkdirSync(home, { recursive: true });
  const env = adminTestEnv(options.extraEnv);

  let stderr = "";
  let stdout = "";
  const originalConsoleError = console.error;
  const originalConsoleLog = console.log;
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  const capture = (append: (text: string) => void) =>
    (chunk: string | Uint8Array, encoding?: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void): boolean => {
      append(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
      const cb = typeof encoding === "function" ? encoding : callback;
      if (cb) queueMicrotask(() => cb(null));
      return true;
    };
  process.stdout.write = capture((text) => { stdout += text; }) as typeof process.stdout.write;
  process.stderr.write = capture((text) => { stderr += text; }) as typeof process.stderr.write;
  console.log = (...values: unknown[]) => {
    stdout += `${util.format(...values)}\n`;
  };
  console.error = (...values: unknown[]) => {
    stderr += `${util.format(...values)}\n`;
  };
  try {
    let status: number;
    try {
      status = await runAdminAction(createAdminState({
        env,
        packageRoot: tmp,
        projectRoot: tmp,
        stateDir: path.join(home, ".local/state/runfree"),
      }), action);
    } catch (error) {
      status = typeof (error as { status?: unknown }).status === "number"
        ? (error as { status: number }).status
        : 1;
      console.error(error instanceof Error ? error.message : String(error));
    }
    flushWarnings();
    return { status, stderr, stdout };
  } finally {
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    process.stdout.write = originalStdoutWrite as typeof process.stdout.write;
    process.stderr.write = originalStderrWrite as typeof process.stderr.write;
  }
}

function readDesiredPolicy(): DesiredNetworkPolicyJson {
  return validateDesiredNetworkPolicy(
    JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8")),
  );
}

function readRawConfig(): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/runfree.json"), "utf8")) as Record<string, unknown>;
}

function readTokenConfig(): Record<string, unknown> {
  const file = path.join(home, ".config", "runfree", "projects", projectHash(tmp), "tokens.json");
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown> : {};
}

beforeEach(() => {
  tmpBase = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-services-")));
  tmp = path.join(tmpBase, "repo");
  home = path.join(tmpBase, "home");
  fs.mkdirSync(tmp, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

describe("runfree service CLI: user-defined services", () => {

  test("user-defined services may declare non-secret parameters but never OAuth fields", () => {
    const withParameters = validateUserServiceDefinitionObject(userAcmeDefinition({
      parameters: [{ key: "region", envVar: "ACME_REGION", description: "Acme region", example: "eu-1", pattern: "^[a-z]{2}-[0-9]$" }],
    }));
    expect(withParameters.svc.parameters).toEqual([
      { key: "region", envVar: "ACME_REGION", description: "Acme region", example: "eu-1", pattern: "^[a-z]{2}-[0-9]$" },
    ]);
    expect(desiredServiceEntry(withParameters.svc, {}, withParameters.digest).resolved).toMatchObject({
      agentEnv: ["ACME_REGION", "ACME_TOKEN"],
      parameters: [{ key: "region", envVar: "ACME_REGION", description: "Acme region" }],
    });
    expect(() => validateUserServiceDefinitionObject(userAcmeDefinition({
      parameters: [{ key: "region", envVar: "ACME_REGION", description: "Acme region", oauthField: "client_id" }],
    }))).toThrow("parameters[0]: unknown key oauthField");
    expect(() => validateUserServiceDefinitionObject(userAcmeDefinition({
      parameters: [{ key: "token", envVar: "ACME_TOKEN", description: "collides with the credential env" }],
    }))).toThrow("collides");
    expect(() => validateUserServiceDefinitionObject(userAcmeDefinition({
      parameters: [{ key: "Region", envVar: "ACME_REGION", description: "bad key" }],
    }))).toThrow("parameter key");
    expect(() => validateUserServiceDefinitionObject(userAcmeDefinition({ parameters: "nope" }))).toThrow("parameters must be an array");
    expect(() => validateUserServiceDefinitionObject(userAcmeDefinition({
      parameters: [{ key: "proxy", envVar: "HTTPS_PROXY", description: "runtime-owned name" }],
    }))).toThrow("parameters[0].envVar HTTPS_PROXY is runtime-owned");
  });

  test("user-service parameter env names must not collide with curated or other user services", () => {
    writeUserServiceFile("user-acme", userAcmeDefinition({
      parameters: [{ key: "region", envVar: "ACME_REGION", description: "Acme region" }],
    }));
    writeUserServiceFile("user-beta", userAcmeDefinition({
      id: "user-beta",
      hosts: [{ host: "api.beta.example" }],
      explanations: ["Beta API: api.beta.example"],
      detect: undefined,
      credential: undefined,
      parameters: [{ key: "region", envVar: "ACME_REGION", description: "same env as user-acme" }],
    }));
    writeUserServiceFile("user-gamma", userAcmeDefinition({
      id: "user-gamma",
      hosts: [{ host: "api.gamma.example" }],
      explanations: ["Gamma API: api.gamma.example"],
      detect: undefined,
      credential: undefined,
      parameters: [{ key: "client-id", envVar: "APPLE_ADS_CLIENT_ID", description: "curated apple-ads parameter env" }],
    }));
    const catalog = loadUserServiceCatalog(tmp, adminTestEnv());
    expect(Object.keys(catalog.services)).toEqual([]);
    expect(catalog.invalid.map((entry) => `${entry.id}: ${entry.reason}`).sort()).toEqual([
      "user-acme: agent env ACME_REGION collides with another user-defined service",
      "user-beta: agent env ACME_REGION collides with another user-defined service",
      "user-gamma: agent env APPLE_ADS_CLIENT_ID collides with a curated service",
    ]);
  });

  test("service diff replaces stale self-contained user-service semantics", () => {
    writeUserServiceFile("user-acme", userAcmeDefinition({
      hosts: [
        { host: "api.acme.example" },
        { host: "old.acme.example" },
      ],
      credential: {
        tokenDescription: "Old Acme token",
        agentEnv: ["ACME_TOKEN"],
        credentials: [
          { host: "api.acme.example", header: "Authorization", scheme: "bearer" },
          { host: "old.acme.example", header: "Authorization", scheme: "bearer" },
        ],
      },
    }));
    const oldDefinition = loadUserServiceCatalog(tmp, adminTestEnv()).services["user-acme"];
    writeApprovedDesiredFixture({
      version: 2,
      hosts: [],
      services: {
        "user-acme": desiredServiceEntry(oldDefinition.svc, {}, oldDefinition.digest),
      },
    });
    writeUserServiceFile("user-acme", userAcmeDefinition({
      revision: 2,
      hosts: [{ host: "api.acme.example" }],
      credential: {
        tokenDescription: "Acme API token",
        agentEnv: ["ACME_TOKEN"],
        credentials: [{ host: "api.acme.example", header: "Authorization", scheme: "bearer" }],
      },
    }));

    const result = runAdminCli(["service", "diff", "--apply", "--no-reload"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("user-acme (project): revision 1 -> 2");
    expect(result.stdout).toContain("old.acme.example");
    const entry = readDesiredPolicy().services?.["user-acme"];
    expect(entry?.revision).toBe(2);
    expect(entry?.resolved.hosts).toEqual(["api.acme.example"]);
    expect(entry?.resolved.tokens?.["user-acme"]?.credentials).toEqual([
      { host: "api.acme.example", header: "Authorization", scheme: "bearer" },
    ]);
    expect(readRawConfig().services).toBeUndefined();
  });

  test("configure on a non-TTY exits before reading or writing project policy", async () => {
    const result = await runAdmin(() => serviceConfigureIntent(
      { id: "node", reloadProxy: false },
      { apply: async () => {} },
    ));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("service configure requires an interactive TTY");
    expect(fs.existsSync(path.join(tmp, ".runfree/network-policy.json"))).toBe(false);
  });

  test("custom add --from-file requires review unless --yes, then imports to the id-derived XDG path", () => {
    writeFixtureRepo({ hosts: [], tokens: {} });
    const source = path.join(tmpBase, "downloaded-definition.json");
    fs.writeFileSync(source, JSON.stringify(userAcmeDefinition(), null, 2));

    const rejected = runAdminCli(["service", "custom", "add", "user-acme", "--from-file", source]);
    expect(rejected.status).toBe(1);
    expect(fs.existsSync(path.join(userServicesDir(), "user-acme.json"))).toBe(false);

    const imported = runAdminCli(["service", "custom", "add", "user-acme", "--from-file", source, "--yes"]);
    expect(imported.status, imported.stderr).toBe(0);
    expect(imported.stdout).toContain("definition contents:");
    expect(imported.stdout).toContain("api.acme.example");
    expect(fs.existsSync(path.join(userServicesDir(), "user-acme.json"))).toBe(true);
    expect(fs.existsSync(path.join(userServicesDir(), ".metadata", "user-acme.json"))).toBe(true);
  });
});

describe("runfree service CLI: desired disable", () => {
  test("disable removes compiled credential exposure, keeps the host-owned source, and refuses a null repeat", () => {
    writeApprovedDesiredFixture({ version: 2, hosts: [] });

    const enabled = runAdminCli(
      ["service", "enable", "github", "--from-env", "MY_GH_TOKEN", "--no-reload"],
      { extraEnv: { MY_GH_TOKEN: "host-secret" } },
    );
    expect(enabled.status, enabled.stderr).toBe(0);
    expect(enabled.stdout).toContain("host-owned credential sources: github bound");
    const compiledEnabled = compileDesiredPolicies({
      project: readDesiredPolicy(),
      local: { version: 2, hosts: [] },
    });
    expect(compiledEnabled.policy.tokens?.github).toBeDefined();
    expect(compiledEnabled.agentEnv).toEqual(["GH_TOKEN", "GITHUB_TOKEN"]);
    expect(readTokenConfig().github).toEqual({ source: "env", env: "MY_GH_TOKEN" });

    const disabled = runAdminCli(["service", "disable", "github", "--no-reload"]);
    expect(disabled.status, disabled.stderr).toBe(0);
    expect(disabled.stdout).toContain("service github: disabled in project desired policy");
    expect(disabled.stdout).toContain("host-owned credential sources: unchanged");
    const compiledDisabled = compileDesiredPolicies({
      project: readDesiredPolicy(),
      local: { version: 2, hosts: [] },
    });
    expect(compiledDisabled.policy.hosts).toEqual([]);
    expect(Object.keys(compiledDisabled.policy.tokens ?? {})).toHaveLength(0);
    expect(compiledDisabled.agentEnv).toEqual([]);
    expect(readTokenConfig().github).toEqual({ source: "env", env: "MY_GH_TOKEN" });

    const policyBeforeRepeat = fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8");
    const sourcesBeforeRepeat = JSON.stringify(readTokenConfig());
    const repeated = runAdminCli(["service", "disable", "github", "--no-reload"]);
    expect(repeated.status).toBe(1);
    expect(repeated.stderr).toContain("github service is not enabled in the selected desired policy layer");
    expect(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8")).toBe(policyBeforeRepeat);
    expect(JSON.stringify(readTokenConfig())).toBe(sourcesBeforeRepeat);
  });
});

describe("runfree service CLI: list, explain, diff", () => {

  test("diff reports approved service drift, retains unavailable definitions, and applies exact replacements", () => {
    const unavailable: DesiredServiceEntry = {
      definitionDigest: `sha256:${"b".repeat(64)}`,
      revision: 2,
      resolved: { hosts: ["mystery.example"] },
    };
    writeApprovedDesiredFixture({
      version: 2,
      hosts: [],
      services: {
        node: staleNodeDesiredEntry(),
        mystery: unavailable,
      },
    });
    const before = readDesiredPolicy();

    const diff = runAdminCli(["service", "diff", "--no-reload"]);
    expect(diff.status, diff.stderr).toBe(0);
    expect(diff.stdout).toContain("mystery (project): definition unavailable; approved semantics retained");
    expect(diff.stdout).toContain("node (project): revision 1 -> 2");
    expect(diff.stdout).toContain("registry.yarnpkg.com");
    expect(diff.stdout).toContain("apply with: runfree service diff --apply");
    expect(readDesiredPolicy()).toEqual(before);

    const applied = runAdminCli(["service", "diff", "--apply", "--no-reload"]);
    expect(applied.status, applied.stderr).toBe(0);
    expect(applied.stdout).toContain("effective policy: unchanged (--no-reload)");
    const policy = readDesiredPolicy();
    expect(policy.services?.node).toEqual(desiredServiceEntry(SERVICES.node));
    expect(policy.services?.mystery).toEqual(unavailable);
    expect(readRawConfig().services).toBeUndefined();
  });

  test("diff rejects unapproved desired-policy drift before applying a replacement", () => {
    writeApprovedDesiredFixture({
      version: 2,
      hosts: [],
      services: { node: staleNodeDesiredEntry() },
    });
    const drifted: DesiredNetworkPolicyJson = {
      ...readDesiredPolicy(),
      hosts: ["drift.example"],
    };
    fs.writeFileSync(
      path.join(tmp, ".runfree/network-policy.json"),
      `${JSON.stringify(drifted, null, 2)}\n`,
    );

    const result = runAdminCli(["service", "diff", "--apply", "--no-reload"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("project desired policy changed outside a trusted Runfree transaction");
    expect(readDesiredPolicy()).toEqual(drifted);
  });

  test("diff replaces the stale Node service classifier with the exact curated rule", () => {
    writeApprovedDesiredFixture({
      version: 2,
      hosts: [],
      services: { node: staleNodeDesiredEntry() },
    });

    const diff = runAdminCli(["service", "diff", "--no-reload"]);
    expect(diff.status, diff.stderr).toBe(0);
    expect(diff.stdout).toContain('"readPathPrefixes":["/-/npm/v1/security/"]');
    expect(diff.stdout).toContain('"readPathPrefixes":["/-/npm/v1/security/advisories/bulk"]');

    const applied = runAdminCli(["service", "diff", "--apply", "--no-reload"]);
    expect(applied.status, applied.stderr).toBe(0);
    expect(readDesiredPolicy().services?.node?.resolved.requests?.["registry.npmjs.org"]?.readPathPrefixes)
      .toEqual(["/-/npm/v1/security/advisories/bulk"]);
  });

  test("diff preserves an unrelated direct classifier while replacing service-owned semantics", () => {
    const nearMatch = ["/-/npm/v1/security/", "/custom"];
    writeApprovedDesiredFixture({
      version: 2,
      hosts: ["registry.npmjs.org"],
      requests: { "registry.npmjs.org": { readPathPrefixes: nearMatch } },
      services: { node: staleNodeDesiredEntry() },
    });

    const result = runAdminCli(["service", "diff", "--apply", "--no-reload"]);
    expect(result.status, result.stderr).toBe(0);
    const desired = readDesiredPolicy();
    expect(desired.requests?.["registry.npmjs.org"]?.readPathPrefixes).toEqual(nearMatch);
    expect(desired.services?.node).toEqual(desiredServiceEntry(SERVICES.node));
  });

  test("doctor names the owning service as a secondary option for blocked members", async () => {
    writeFixtureRepo({ hosts: [], tokens: {} });
    const fakeBin = path.join(tmp, "fake-bin");
    fs.mkdirSync(fakeBin, { recursive: true });
    const denial = JSON.stringify({ v: 1, reason: "host-not-allowlisted", host: "api.github.com" });
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
case "$*" in
  info) exit 0 ;;
  *logs*) printf 'proxy-denial: %s\\n' '${denial}' ;;
  *com.docker.compose.service=proxy*) echo proxy-id ;;
  *com.docker.compose.project*) echo agent-id ;;
  *inspect*) echo fake-project ;;
esac
exit 0
`, { mode: 0o755 });

    const result = await runAdmin(() => doctorIntent({ postFailure: false }), {
      extraEnv: { PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}` },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("suggested fix: runfree host add api.github.com");
    expect(result.stdout).toContain('api.github.com is part of service "github" (6 hosts, 1 broad).');
    expect(result.stdout).toContain("runfree service enable github");
    expect(result.stdout).toContain("note: objects.githubusercontent.com");
  });

  test("doctor reports a customized Claude command without the inbox grant", async () => {
    writeFixtureRepo({ hosts: [], tokens: {} }, {
      version: 3,
      agents: {
        default: "claude",
        claude: { command: "claude --model opus --dangerously-skip-permissions" },
      },
      runtime: {},
    });
    const emptyBin = path.join(tmp, "empty-bin");
    fs.mkdirSync(emptyBin);

    const result = await runAdmin(() => doctorIntent({ postFailure: false }), {
      extraEnv: { PATH: emptyBin },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(
      "doctor: agents.claude.command does not grant the Runfree inbox; add --add-dir /runfree/inbox",
    );
  });
});

describe("CLI smoke: init --yes + service enable node", () => {
  test("produces desired service policy that compiles to valid effective policy", () => {
    const project = path.join(tmpBase, "smoke-project");
    fs.mkdirSync(project, { recursive: true });
    const env = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: path.join(tmpBase, "xdg-config"),
      XDG_DATA_HOME: path.join(tmpBase, "xdg-data"),
      XDG_STATE_HOME: path.join(tmpBase, "xdg-state"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      PATH: `${installEmptyRuntimeDockerFake()}${path.delimiter}${process.env.PATH ?? ""}`,
    };

    const init = childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", project, "init", "--yes"], {
      cwd: repoRoot,
      encoding: "utf8",
      env,
    });
    expect(init.status, init.stderr).toBe(0);
    expect(init.stdout).toContain("network policy:");

    const enable = childProcess.spawnSync(
      process.execPath,
      [...cliEntryArgv(), "--workspace", project, "service", "enable", "node", "--no-reload"],
      { cwd: repoRoot, encoding: "utf8", env },
    );
    expect(enable.status, enable.stderr).toBe(0);
    expect(enable.stdout).toContain("service node: updated in project desired policy");

    const policy = validateDesiredNetworkPolicy(
      JSON.parse(fs.readFileSync(path.join(project, ".runfree/network-policy.json"), "utf8")),
    );
    expect(policy.version).toBe(2);
    expect(policy.services?.node?.revision).toBe(2);
    const effective = compileDesiredPolicies({
      project: policy,
      local: { version: 2, hosts: [] },
    }).policy;
    const loaded = validateNetworkPolicy(effective, "smoke effective");
    expect(loaded.allowedHostSet.has("registry.npmjs.org")).toBe(true);
    expect(loaded.allowedHostSet.has("registry.yarnpkg.com")).toBe(true);
    const rawConfig = JSON.parse(fs.readFileSync(path.join(project, ".runfree/runfree.json"), "utf8")) as Record<string, unknown>;
    expect(rawConfig.services).toBeUndefined();
    expect(rawConfig.version).toBe(4);
  });
});
