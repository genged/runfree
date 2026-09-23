import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { validateDesiredNetworkPolicy } from "@runfree/runtime-contracts/desired-network-policy";
import { describe, expect, test } from "vitest";

import { RUNFREE_PLACEHOLDER_VALUE, service, type Service } from "../../../../scripts/services.ts";
import { createAdminState } from "./context.ts";
import { runAdminAction } from "./admin-core.ts";
import {
  bindDesiredServiceCredentialSources,
  desiredServiceEntry,
  parseParamFlags,
  planDesiredServiceEnable,
  promptForMissingServiceParameters,
  recordedAgentEnvNamesForServiceEntry,
  resolveServiceParameters,
  serviceParameterStatus,
  serviceParameterRefusal,
} from "./service-policy.ts";
import { setAgentEnvValues, loadTokenConfig, readAgentEnv, readOAuthSeedHandleStore, saveTokenConfig } from "./admin-core.ts";
import { serviceHostState } from "./service-policy.ts";

describe("desired service entries", () => {
  test("captures a complete static-credential service without source metadata", () => {
    const svc = service("github");
    if (!svc) throw new Error("github service missing");

    const entry = desiredServiceEntry(svc, {
      skippedHosts: ["objects.githubusercontent.com"],
      writeMode: "read-only",
    });
    const policy = validateDesiredNetworkPolicy({
      version: 2,
      hosts: [],
      services: { github: entry },
    });

    expect(policy.services?.github).toEqual(entry);
    expect(entry.resolved.hosts).not.toContain("objects.githubusercontent.com");
    expect(entry.resolved.tokens?.github).toMatchObject({
      description: "GitHub API token for API and raw content requests",
    });
    expect(entry.resolved.agentEnv).toEqual(["GH_TOKEN", "GITHUB_TOKEN"]);
    expect(JSON.stringify(entry)).not.toMatch(/from-env|from-source|op:\/\/|sourceCommand|secretRef/);
  });

  test("captures OAuth destinations and declarations without minting handles", () => {
    const svc = service("apple-ads");
    if (!svc) throw new Error("apple-ads service missing");

    const entry = desiredServiceEntry(svc);

    expect(entry.resolved.requests?.["appleid.apple.com"]).toEqual({
      methods: ["POST"],
      pathPrefixes: ["/auth/oauth2/token"],
    });
    expect(entry.resolved.tokens?.["oauth-apple-ads-client-secret"]).toEqual({
      description: "Apple Ads OAuth client-secret JWT seed",
      credentials: [],
    });
    expect(entry.resolved.oauth?.["service:apple-ads"]).toMatchObject({
      resourceHost: "api.searchads.apple.com",
      tokenEndpoints: [{ host: "appleid.apple.com", path: "/auth/oauth2/token" }],
      seeds: [{
        description: "Apple Ads OAuth client-secret JWT seed",
        envVar: "APPLE_ADS_CLIENT_SECRET",
        field: "client_secret",
        tokenName: "oauth-apple-ads-client-secret",
      }],
    });
    expect(entry.resolved.oauth?.["service:apple-ads"]).not.toHaveProperty("passthrough");
    expect(entry.resolved.parameters).toEqual([{
      key: "client-id",
      envVar: "APPLE_ADS_CLIENT_ID",
      description: "Apple Ads OAuth client id (SEARCHADS.<uuid>)",
      oauthField: "client_id",
    }]);
    expect(entry.resolved.agentEnv).toEqual(["APPLE_ADS_CLIENT_ID", "APPLE_ADS_CLIENT_SECRET"]);
    expect(JSON.stringify(entry)).not.toMatch(/runfree_oauth_(?:refresh|secret)_/);
    expect(JSON.stringify(entry)).not.toMatch(/pattern|example/);
  });

  test("definition provenance changes when trusted semantics change", () => {
    const svc = service("node");
    if (!svc) throw new Error("node service missing");

    const first = desiredServiceEntry(svc);
    const changed = desiredServiceEntry({
      ...svc,
      hosts: [...svc.hosts, { host: "mirror.example.com" }],
    });

    expect(changed.definitionDigest).not.toBe(first.definitionDigest);
  });

  test("refuses to skip a host the service's credential wiring names", async () => {
    // Skipping such a host drops it from the allowlist while the credential
    // link or OAuth endpoint keeps pointing at it, which is an entry that
    // cannot compile. Refuse where the flag can still be named.
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-skip-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-skip-config-"));
    try {
      const status = await runAdminAction(createAdminState({
        projectRoot: root,
        packageRoot: "/workspace",
        tokenConfigPath: path.join(configRoot, "tokens.json"),
        env: { RUNFREE_TEST_FAKE_DOCKER: "1" },
      }), () => {
        const refused: Array<[string, string, RegExp]> = [
          ["github", "api.github.com", /receives the github credential/],
          ["gitlab", "gitlab.com", /receives the gitlab credential/],
          ["apple-ads", "api.searchads.apple.com", /OAuth resource host/],
          ["apple-ads", "appleid.apple.com", /OAuth token endpoint/],
          ["google-ads", "oauth2.googleapis.com", /OAuth token endpoint/],
        ];
        for (const [id, host, reason] of refused) {
          expect(() => planDesiredServiceEnable({
            id,
            skipHosts: [host],
            tokenSource: { kind: "none" },
            replaceSource: false,
            skipBroad: false,
            reloadProxy: false,
          }), `${id} --skip-host ${host}`).toThrow(reason);
        }
        // A broad host with no credential wiring stays skippable.
        const plan = planDesiredServiceEnable({
          id: "github",
          skipHosts: ["objects.githubusercontent.com"],
          tokenSource: { kind: "none" },
          replaceSource: false,
          skipBroad: false,
          reloadProxy: false,
        });
        expect(plan.skippedHosts).toEqual(["objects.githubusercontent.com"]);
        expect(plan.entry.resolved.hosts).not.toContain("objects.githubusercontent.com");
      });
      expect(status).toBe(0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });

  test("binds source metadata outside the project without adding it to desired state", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-service-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-service-config-"));
    const tokenConfigPath = path.join(configRoot, "tokens.json");
    try {
      let desired = "";
      const status = await runAdminAction(createAdminState({
        projectRoot: root,
        packageRoot: "/workspace",
        tokenConfigPath,
        env: { GITHUB_TEST_TOKEN: "host-secret", RUNFREE_TEST_FAKE_DOCKER: "1" },
      }), () => {
        const plan = planDesiredServiceEnable({
          id: "github",
          tokenSource: { kind: "env", env: "GITHUB_TEST_TOKEN" },
          replaceSource: false,
          skipBroad: false,
          reloadProxy: false,
        });
        expect(bindDesiredServiceCredentialSources(plan, false)).toEqual(["github"]);
        desired = JSON.stringify(plan.entry);
      });

      expect(status).toBe(0);
      expect(fs.realpathSync(tokenConfigPath).startsWith(fs.realpathSync(root))).toBe(false);
      expect(JSON.parse(fs.readFileSync(tokenConfigPath, "utf8"))).toEqual({
        github: { source: "env", env: "GITHUB_TEST_TOKEN" },
      });
      expect(desired).not.toContain("GITHUB_TEST_TOKEN");
      expect(desired).not.toContain("host-secret");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });

  test("re-enabling a user-defined service with its existing source is not a change", async () => {
    // The plan's refusal check has to predict the bind's write exactly. It did
    // not: it looked under `credential.tokenName` with the caller's source
    // while the bind wrote under `svc.id` with the owner marker, so a second
    // enable with the same source compared as a change and was refused --
    // naming the very source the caller had asked for.
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-user-service-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-user-service-config-"));
    const servicesDir = path.join(configRoot, "services");
    const tokenConfigPath = path.join(configRoot, "tokens.json");
    try {
      fs.mkdirSync(servicesDir, { recursive: true });
      fs.writeFileSync(path.join(servicesDir, "user-acme.json"), JSON.stringify({
        schemaVersion: 1,
        id: "user-acme",
        label: "Acme",
        revision: 1,
        hosts: [{ host: "api.acme.test" }],
        explanations: ["user-defined test service"],
        credential: {
          tokenDescription: "Acme API token",
          agentEnv: ["ACME_TOKEN"],
          credentials: [{ host: "api.acme.test", header: "Authorization", scheme: "bearer" }],
        },
      }));
      const adminState = () => createAdminState({
        projectRoot: root,
        packageRoot: "/workspace",
        tokenConfigPath,
        env: {
          ACME_TEST_TOKEN: "host-secret",
          RUNFREE_TEST_FAKE_DOCKER: "1",
          RUNFREE_USER_SERVICES_DIR: servicesDir,
        },
      });
      const enable = () => planDesiredServiceEnable({
        id: "user-acme",
        tokenSource: { kind: "env", env: "ACME_TEST_TOKEN" },
        replaceSource: false,
        skipBroad: false,
        reloadProxy: false,
      });

      const first = await runAdminAction(adminState(), () => {
        bindDesiredServiceCredentialSources(enable(), false);
      });
      expect(first).toBe(0);
      // The bind stores under the service id, carrying the ownership marker.
      expect(JSON.parse(fs.readFileSync(tokenConfigPath, "utf8"))["user-acme"]).toEqual({
        source: "env",
        env: "ACME_TEST_TOKEN",
        runfreeUserServiceOwner: "user-acme",
      });

      // The same enable again must plan and bind without demanding
      // --replace-source, and must leave the stored entry untouched.
      const before = fs.readFileSync(tokenConfigPath, "utf8");
      const second = await runAdminAction(adminState(), () => {
        expect(bindDesiredServiceCredentialSources(enable(), false)).toEqual([]);
      });
      expect(second).toBe(0);
      expect(fs.readFileSync(tokenConfigPath, "utf8")).toBe(before);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });

  test("refuses to replace a differing binding before any token write unless --replace-source", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-service-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-service-config-"));
    const tokenConfigPath = path.join(configRoot, "tokens.json");
    try {
      const before = `${JSON.stringify({ github: { source: "1password", ref: "op://vault/github/token" } }, null, 2)}\n`;
      fs.writeFileSync(tokenConfigPath, before);
      const adminState = () => createAdminState({
        projectRoot: root,
        packageRoot: "/workspace",
        tokenConfigPath,
        env: { GITHUB_TEST_TOKEN: "host-secret", RUNFREE_TEST_FAKE_DOCKER: "1" },
      });
      const plan = (replaceSource = false) => planDesiredServiceEnable({
        id: "github",
        tokenSource: { kind: "env", env: "GITHUB_TEST_TOKEN" },
        replaceSource,
        skipBroad: false,
        reloadProxy: false,
      });

      let refusal = "";
      const refused = await runAdminAction(adminState(), () => {
        try {
          bindDesiredServiceCredentialSources(plan(), false);
        } catch (error) {
          refusal = error instanceof Error ? error.message : String(error);
          throw error;
        }
      });
      expect(refused).not.toBe(0);
      expect(refusal).toBe("github credential source is already 1password; pass --replace-source to change it");
      // The refusal fires before the save: the binding file is byte-identical.
      expect(fs.readFileSync(tokenConfigPath, "utf8")).toBe(before);

      const replaced = await runAdminAction(adminState(), () => {
        expect(bindDesiredServiceCredentialSources(plan(true), true)).toEqual(["github"]);
      });
      expect(replaced).toBe(0);
      expect(JSON.parse(fs.readFileSync(tokenConfigPath, "utf8"))).toEqual({
        github: { source: "env", env: "GITHUB_TEST_TOKEN" },
      });
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });

  test("binds OAuth handles and host-env parameter values only into host-owned state", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-oauth-service-"));
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-oauth-state-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-oauth-config-"));
    const agentEnvPath = path.join(stateDir, "control", "inputs", "agent.env");
    try {
      const status = await runAdminAction(createAdminState({
        agentEnvPath,
        projectRoot: root,
        packageRoot: "/workspace",
        stateDir,
        tokenConfigPath: path.join(configRoot, "tokens.json"),
        env: {
          APPLE_ADS_CLIENT_ID: "SEARCHADS.12345678-1234-1234-1234-123456789012",
          APPLE_ADS_SECRET_SOURCE: "host-secret",
          RUNFREE_TEST_FAKE_DOCKER: "1",
        },
      }), () => {
        const plan = planDesiredServiceEnable({
          id: "apple-ads",
          tokenSource: { kind: "env", env: "APPLE_ADS_SECRET_SOURCE" },
          replaceSource: false,
          skipBroad: false,
          reloadProxy: false,
        });
        expect(bindDesiredServiceCredentialSources(plan, false)).toEqual(["oauth-apple-ads-client-secret"]);
      });

      expect(status).toBe(0);
      const env = fs.readFileSync(agentEnvPath, "utf8");
      expect(env).toContain("APPLE_ADS_CLIENT_ID=SEARCHADS.12345678-1234-1234-1234-123456789012");
      expect(env).toMatch(/APPLE_ADS_CLIENT_SECRET=runfree_oauth_secret_[A-Za-z0-9_-]{32,}/);
      expect(env).not.toContain("host-secret");
      expect(JSON.parse(fs.readFileSync(path.join(stateDir, "oauth-handles.json"), "utf8")))
        .toMatchObject({
          schemaVersion: 1,
          providers: { "service:apple-ads": { client_secret: expect.stringMatching(/^runfree_oauth_secret_/) } },
        });
      expect(fs.existsSync(path.join(root, ".runfree", "config", "agent.env"))).toBe(false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });
});

const CLIENT_ID = "SEARCHADS.12345678-1234-1234-1234-123456789012";
const OTHER_CLIENT_ID = "SEARCHADS.abcdefab-abcd-abcd-abcd-abcdefabcdef";

function appleAds(): Service {
  const svc = service("apple-ads");
  if (!svc) throw new Error("apple-ads service missing");
  return svc;
}

describe("service parameters", () => {
  test("offers one command containing every missing parameter", () => {
    const svc = { ...appleAds(), parameters: [
      { key: "client-id", envVar: "CLIENT_ID", description: "Client identifier" },
      { key: "account", envVar: "ACCOUNT", description: "Account identifier" },
    ] };
    const resolution = resolveServiceParameters(svc, { hostEnv: {}, existing: {} });
    const message = serviceParameterRefusal(svc, resolution, {
      id: svc.id, tokenSource: { kind: "named", name: "saved-source" },
      replaceSource: false, skipBroad: false, reloadProxy: false,
    });
    const command = message.split("\n").find((line) => line.includes("--param client-id="));
    expect(command).toContain("--from-source saved-source");
    expect(command).toContain("--param account=<value>");
  });

  test("retry instructions retain parameters supplied only by flags", () => {
    const svc = { ...appleAds(), parameters: [
      { key: "client-id", envVar: "CLIENT_ID", description: "Client identifier" },
      { key: "account", envVar: "ACCOUNT", description: "Account identifier" },
    ] };
    const resolution = resolveServiceParameters(svc, { flags: { "client-id": "valid" }, hostEnv: {}, existing: {} });
    const message = serviceParameterRefusal(svc, resolution, {
      id: svc.id, tokenSource: { kind: "named", name: "saved-source" },
      parameters: ["client-id=valid"], replaceSource: false, skipBroad: false, reloadProxy: false,
    });
    const command = message.split("\n").find((line) => line.includes("--param account="));
    expect(command).toContain("--param client-id=<value>");
  });

  test("resolves by precedence: flag, item field, host env, recorded value", () => {
    const svc = appleAds();
    const all = resolveServiceParameters(svc, {
      flags: { "client-id": CLIENT_ID },
      itemValues: { APPLE_ADS_CLIENT_ID: OTHER_CLIENT_ID },
      hostEnv: { APPLE_ADS_CLIENT_ID: "SEARCHADS.00000000-0000-0000-0000-000000000000" },
      existing: { APPLE_ADS_CLIENT_ID: "SEARCHADS.11111111-1111-1111-1111-111111111111" },
    });
    expect(all.values).toEqual({ APPLE_ADS_CLIENT_ID: CLIENT_ID });
    expect(all.sources).toEqual({ APPLE_ADS_CLIENT_ID: "flag" });
    expect(all.missing).toEqual([]);
    expect(all.invalid).toEqual([]);

    // The resolver is key-only; parseParamFlags canonicalizes env-name spellings.
    expect(resolveServiceParameters(svc, {
      flags: parseParamFlags(svc, [`APPLE_ADS_CLIENT_ID=${CLIENT_ID}`]),
      hostEnv: {},
      existing: {},
    }).sources).toEqual({ APPLE_ADS_CLIENT_ID: "flag" });
    expect(resolveServiceParameters(svc, {
      flags: { APPLE_ADS_CLIENT_ID: CLIENT_ID },
      hostEnv: {},
      existing: {},
    }).missing.map((parameter) => parameter.key)).toEqual(["client-id"]);
    expect(resolveServiceParameters(svc, {
      itemValues: { APPLE_ADS_CLIENT_ID: OTHER_CLIENT_ID },
      hostEnv: { APPLE_ADS_CLIENT_ID: CLIENT_ID },
      existing: {},
    })).toMatchObject({ values: { APPLE_ADS_CLIENT_ID: OTHER_CLIENT_ID }, sources: { APPLE_ADS_CLIENT_ID: "1password-item" } });
    expect(resolveServiceParameters(svc, {
      hostEnv: { APPLE_ADS_CLIENT_ID: CLIENT_ID },
      existing: { APPLE_ADS_CLIENT_ID: OTHER_CLIENT_ID },
    })).toMatchObject({ values: { APPLE_ADS_CLIENT_ID: CLIENT_ID }, sources: { APPLE_ADS_CLIENT_ID: "host-env" } });
    expect(resolveServiceParameters(svc, {
      hostEnv: {},
      existing: { APPLE_ADS_CLIENT_ID: OTHER_CLIENT_ID },
    })).toMatchObject({ values: { APPLE_ADS_CLIENT_ID: OTHER_CLIENT_ID }, sources: { APPLE_ADS_CLIENT_ID: "existing" } });
    const placeholderOnly = resolveServiceParameters(svc, {
      hostEnv: { APPLE_ADS_CLIENT_ID: "" },
      existing: { APPLE_ADS_CLIENT_ID: RUNFREE_PLACEHOLDER_VALUE },
    });
    expect(placeholderOnly.values).toEqual({});
    expect(placeholderOnly.missing.map((parameter) => parameter.key)).toEqual(["client-id"]);
  });

  test("reports an invalid value with its source and does not fall through", () => {
    const svc = appleAds();
    const invalid = resolveServiceParameters(svc, {
      hostEnv: { APPLE_ADS_CLIENT_ID: "not-a-client-id" },
      existing: { APPLE_ADS_CLIENT_ID: CLIENT_ID },
    });
    expect(invalid.values).toEqual({});
    expect(invalid.missing).toEqual([]);
    expect(invalid.invalid).toEqual([{
      parameter: expect.objectContaining({ key: "client-id" }),
      source: "host-env",
      reason: expect.stringContaining("SEARCHADS"),
    }]);
    const newline = resolveServiceParameters(svc, {
      flags: { "client-id": `${CLIENT_ID}\nX=1` },
      hostEnv: {},
      existing: {},
    });
    expect(newline.invalid).toEqual([expect.objectContaining({ source: "flag", reason: expect.stringContaining("control") })]);
    // U+2028/U+2029 are not matched by `.` in the line parsers; google-ads has
    // no pattern, so only this check keeps them out of the host-owned file.
    const googleAds = service("google-ads");
    if (!googleAds) throw new Error("google-ads service missing");
    for (const separator of ["\u2028", "\u2029", "\u0085"]) {
      const split = resolveServiceParameters(googleAds, {
        flags: { "client-id": `abc${separator}def` },
        hostEnv: {},
        existing: {},
      });
      expect(split.values).toEqual({});
      expect(split.invalid).toEqual([expect.objectContaining({ source: "flag", reason: expect.stringContaining("line-separator") })]);
    }
  });

  test("the host-owned agent env writer refuses a value its own reader could not parse back", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-agent-env-guard-"));
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-agent-env-guard-state-"));
    const agentEnvPath = path.join(stateDir, "control", "inputs", "agent.env");
    try {
      const status = await runAdminAction(createAdminState({
        agentEnvPath,
        projectRoot: root,
        packageRoot: "/workspace",
        stateDir,
        tokenConfigPath: path.join(stateDir, "tokens.json"),
        env: { RUNFREE_TEST_FAKE_DOCKER: "1" },
      }), () => {
        setAgentEnvValues({ SAFE: "value" });
        expect(() => setAgentEnvValues({ BROKEN: "a\u2028b" })).toThrow("agent env BROKEN cannot be written as a single line");
        expect(() => setAgentEnvValues({ BROKEN: "a\nb" })).toThrow("agent env BROKEN cannot be written as a single line");
      });
      expect(status).toBe(0);
      expect(fs.readFileSync(agentEnvPath, "utf8")).toBe("SAFE=value\n");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  test("lists the agent env names a service entry recorded, including legacy passthrough", () => {
    const entry = desiredServiceEntry(appleAds());
    expect(recordedAgentEnvNamesForServiceEntry(entry)).toEqual(["APPLE_ADS_CLIENT_ID", "APPLE_ADS_CLIENT_SECRET"]);
    const github = service("github");
    if (!github) throw new Error("github service missing");
    expect(recordedAgentEnvNamesForServiceEntry(desiredServiceEntry(github))).toEqual([]);
    const legacy = structuredClone(entry);
    const { parameters: _dropped, ...resolved } = legacy.resolved;
    const provider = resolved.oauth?.["service:apple-ads"];
    if (!provider) throw new Error("provider missing");
    provider.passthrough = [{ envVar: "APPLE_ADS_CLIENT_ID", field: "client_id" }];
    expect(recordedAgentEnvNamesForServiceEntry({ ...legacy, resolved })).toEqual(["APPLE_ADS_CLIENT_ID", "APPLE_ADS_CLIENT_SECRET"]);
  });

  test("reports set/unset per declared parameter without exposing other agent env", () => {
    const parameters = desiredServiceEntry(appleAds()).resolved.parameters ?? [];
    expect(serviceParameterStatus(parameters, { APPLE_ADS_CLIENT_ID: CLIENT_ID, GITHUB_TOKEN: "raw" })).toEqual({ "client-id": "set" });
    expect(serviceParameterStatus(parameters, { APPLE_ADS_CLIENT_ID: RUNFREE_PLACEHOLDER_VALUE })).toEqual({ "client-id": "unset" });
    expect(serviceParameterStatus(parameters, {})).toEqual({ "client-id": "unset" });
    expect(serviceParameterStatus([], { APPLE_ADS_CLIENT_ID: CLIENT_ID })).toEqual({});
  });

  test("parses --param key=value by key or env name and rejects bad shapes", () => {
    const svc = appleAds();
    expect(parseParamFlags(svc, [`client-id=${CLIENT_ID}`])).toEqual({ "client-id": CLIENT_ID });
    expect(parseParamFlags(svc, [`APPLE_ADS_CLIENT_ID=${CLIENT_ID}`])).toEqual({ "client-id": CLIENT_ID });
    expect(parseParamFlags(svc, ["client-id=a=b"])).toEqual({ "client-id": "a=b" });
    expect(() => parseParamFlags(svc, ["client-id"])).toThrow("--param arguments must be <key>=<value> (known keys: client-id)");
    // A swapped argument never echoes what came after the separator.
    expect(() => parseParamFlags(svc, ["=SEARCHADS.secret-looking"])).toThrow(/^(?!.*secret-looking)--param arguments must be/);
    expect(() => parseParamFlags(svc, ["client-id="])).toThrow("--param client-id needs a value");
    expect(() => parseParamFlags(svc, ["nope=1"])).toThrow("apple-ads has no parameter nope (known: client-id)");
    expect(() => parseParamFlags(svc, [`client-id=${CLIENT_ID}`, `APPLE_ADS_CLIENT_ID=${OTHER_CLIENT_ID}`]))
      .toThrow("--param client-id given more than once");
    const node = service("node");
    if (!node) throw new Error("node service missing");
    expect(() => parseParamFlags(node, ["x=1"])).toThrow("node service declares no parameters");
  });

  test("prompts only on a TTY, only for what is missing, and re-asks until the value is valid", async () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-prompt-state-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-prompt-config-"));
    const agentEnvPath = path.join(stateDir, "control", "inputs", "agent.env");
    const input = {
      id: "apple-ads",
      tokenSource: { kind: "named" as const, name: "apple" },
      replaceSource: false,
      skipBroad: false,
      reloadProxy: false,
    };
    const adminState = (env: Record<string, string> = {}) => createAdminState({
      agentEnvPath,
      projectRoot: stateDir,
      packageRoot: "/workspace",
      stateDir,
      tokenConfigPath: path.join(configRoot, "tokens.json"),
      env: { RUNFREE_TEST_FAKE_DOCKER: "1", ...env },
    });
    try {
      await runAdminAction(adminState(), async () => {
        // Non-interactive: untouched, so the plan refuses with the remedy text.
        expect(await promptForMissingServiceParameters(input, { interactive: false })).toBe(input);
        // A 1Password item enable is never prompted.
        const item = { ...input, fromOnePasswordItem: "op://vault/item" };
        expect(await promptForMissingServiceParameters(item, { interactive: true, ask: async () => "unused" })).toBe(item);
        // A service without parameters is never prompted.
        const node = { ...input, id: "node" };
        expect(await promptForMissingServiceParameters(node, { interactive: true, ask: async () => "unused" })).toBe(node);

        const answers = ["not-valid", "", CLIENT_ID];
        const asked: Array<string | undefined> = [];
        const prepared = await promptForMissingServiceParameters(input, {
          interactive: true,
          ask: async (parameter, retryReason) => {
            expect(parameter.key).toBe("client-id");
            asked.push(retryReason);
            return answers.shift() ?? "";
          },
        });
        expect(prepared.parameters).toEqual([`client-id=${CLIENT_ID}`]);
        expect(asked).toEqual([undefined, expect.stringContaining("SEARCHADS"), "a value is required"]);
        // The answers feed the plan like --param flags.
        expect(planDesiredServiceEnable({ ...prepared, tokenSource: { kind: "none" } }).parameterValues)
          .toEqual({ APPLE_ADS_CLIENT_ID: CLIENT_ID });
      });
      await runAdminAction(adminState({ APPLE_ADS_CLIENT_ID: CLIENT_ID }), async () => {
        // Host env supplies the value: nothing to ask.
        expect(await promptForMissingServiceParameters(input, {
          interactive: true,
          ask: async () => { throw new Error("must not ask"); },
        })).toBe(input);
      });
      await runAdminAction(adminState({ APPLE_ADS_CLIENT_ID: "garbage" }), async () => {
        // An invalid host env value is re-asked with the reason attached.
        const prepared = await promptForMissingServiceParameters(input, {
          interactive: true,
          ask: async (_parameter, retryReason) => {
            expect(retryReason).toContain("host env APPLE_ADS_CLIENT_ID");
            return CLIENT_ID;
          },
        });
        expect(prepared.parameters).toEqual([`client-id=${CLIENT_ID}`]);
      });
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });

  test("refuses a missing parameter before any policy, token, or agent env write", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-refuse-"));
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-refuse-state-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-refuse-config-"));
    const agentEnvPath = path.join(stateDir, "control", "inputs", "agent.env");
    const tokenConfigPath = path.join(configRoot, "tokens.json");
    try {
      const status = await runAdminAction(createAdminState({
        agentEnvPath,
        projectRoot: root,
        packageRoot: "/workspace",
        stateDir,
        tokenConfigPath,
        env: { APPLE_ADS_SECRET_SOURCE: "host-secret", RUNFREE_TEST_FAKE_DOCKER: "1" },
      }), () => {
        expect(() => planDesiredServiceEnable({
          id: "apple-ads",
          tokenSource: { kind: "env", env: "APPLE_ADS_SECRET_SOURCE" },
          replaceSource: false,
          skipBroad: false,
          reloadProxy: false,
        })).toThrow(/apple-ads needs 1 parameter[\s\S]*client-id[\s\S]*APPLE_ADS_CLIENT_ID/);
      });
      expect(status).toBe(0);
      expect(fs.existsSync(tokenConfigPath)).toBe(false);
      expect(fs.existsSync(agentEnvPath)).toBe(false);
      expect(fs.existsSync(path.join(stateDir, "oauth-handles.json"))).toBe(false);
      expect(fs.existsSync(path.join(root, ".runfree"))).toBe(false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });

  test("finishes external item reads during planning before the locked binding", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-item-preflight-"));
    const projectRoot = path.join(root, "project");
    const stateDir = path.join(root, "state");
    const binDir = path.join(root, "bin");
    for (const directory of [projectRoot, stateDir, binDir]) fs.mkdirSync(directory);
    const op = path.join(binDir, "op");
    fs.writeFileSync(op, "#!/bin/sh\nprintf 'test-secret\\n'\n", { mode: 0o700 });
    try {
      expect(await runAdminAction(createAdminState({
        projectRoot, packageRoot: "/workspace", stateDir,
        agentEnvPath: path.join(stateDir, "agent.env"),
        tokenConfigPath: path.join(stateDir, "tokens.json"),
        env: { PATH: binDir, RUNFREE_TEST_FAKE_DOCKER: "1" },
      }), () => {
        const input = {
          id: "apple-ads", tokenSource: { kind: "none" as const },
          fromOnePasswordItem: "op://vault/apple", parameters: [`client-id=${CLIENT_ID}`],
          replaceSource: false, skipBroad: false, reloadProxy: false,
        };
        const plan = planDesiredServiceEnable(input);
        expect(loadTokenConfig()).toEqual({});
        // The external helper becomes unavailable before entering the write lock.
        fs.writeFileSync(op, "#!/bin/sh\nexit 1\n");
        expect(() => planDesiredServiceEnable(input)).toThrow();
        const state = serviceHostState(plan.id, () => { bindDesiredServiceCredentialSources(plan, false); });
        const before = { project: { version: 2 as const, hosts: [] }, local: { version: 2 as const, hosts: [] } };
        const next = { ...before, project: { ...before.project, services: { [plan.id]: plan.entry } } };
        state.withWriteLock(() => state.beforeWrite(before, next));
        expect(loadTokenConfig()["oauth-apple-ads-client-secret"]).toEqual({
          source: "1password", ref: "op://vault/apple/APPLE_ADS_CLIENT_SECRET",
        });
        expect(readAgentEnv().APPLE_ADS_CLIENT_ID).toBe(CLIENT_ID);
      })).toBe(0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test.each([false, true])("restores all service host stores after failure (during bind: %s)", async (duringBind) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-bind-rollback-"));
    const stateDir = path.join(root, "state");
    fs.mkdirSync(stateDir);
    const projectRoot = path.join(root, "project");
    fs.mkdirSync(projectRoot);
    const adminState = createAdminState({
      projectRoot, packageRoot: "/workspace", stateDir,
      agentEnvPath: path.join(stateDir, "agent.env"),
      tokenConfigPath: path.join(stateDir, "tokens.json"),
      env: { APPLE_ADS_SECRET_SOURCE: "test-secret", RUNFREE_TEST_FAKE_DOCKER: "1" },
    });
    try {
      expect(await runAdminAction(adminState, () => {
        const sources = { preserved: { source: "env" as const, env: "PRESERVED" } };
        saveTokenConfig(sources);
        setAgentEnvValues({ PRESERVED_PARAMETER: "old" });
        const plan = planDesiredServiceEnable({
          id: "apple-ads", tokenSource: { kind: "env", env: "APPLE_ADS_SECRET_SOURCE" },
          parameters: [`client-id=${CLIENT_ID}`], replaceSource: true, skipBroad: false, reloadProxy: false,
        });
        const state = serviceHostState(plan.id, () => {
          bindDesiredServiceCredentialSources(plan, true);
          expect(readOAuthSeedHandleStore().providers).not.toEqual({});
          if (duringBind) throw new Error("late binding failure");
        });
        const before = { project: { version: 2 as const, hosts: [] }, local: { version: 2 as const, hosts: [] } };
        const next = { ...before, project: { ...before.project, services: { [plan.id]: plan.entry } } };
        const lockPath = path.join(stateDir, `token-store-sync-${adminState.projectId}.lock`);
        fs.mkdirSync(lockPath);
        fs.writeFileSync(path.join(lockPath, "pid"), String(process.ppid));
        expect(() => state.withWriteLock(() => state.beforeWrite(before, next))).toThrow("token store lock");
        expect(loadTokenConfig()).toEqual(sources);
        fs.rmSync(lockPath, { recursive: true });
        state.withWriteLock(() => {
          if (duringBind) expect(() => state.beforeWrite(before, next)).toThrow("late binding failure");
          else state.beforeWrite(before, next)();
        });
        expect(loadTokenConfig()).toEqual(sources);
        expect(readOAuthSeedHandleStore()).toEqual({ schemaVersion: 1, providers: {} });
        expect(readAgentEnv()).toEqual({ PRESERVED_PARAMETER: "old" });
      })).toBe(0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("binds a --param value and reuses the recorded value on re-enable", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-bind-"));
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-bind-state-"));
    const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-param-bind-config-"));
    const agentEnvPath = path.join(stateDir, "control", "inputs", "agent.env");
    const adminState = () => createAdminState({
      agentEnvPath,
      projectRoot: root,
      packageRoot: "/workspace",
      stateDir,
      tokenConfigPath: path.join(configRoot, "tokens.json"),
      env: { APPLE_ADS_SECRET_SOURCE: "host-secret", RUNFREE_TEST_FAKE_DOCKER: "1" },
    });
    const enable = (parameters?: string[]) => planDesiredServiceEnable({
      id: "apple-ads",
      tokenSource: { kind: "env", env: "APPLE_ADS_SECRET_SOURCE" },
      ...(parameters ? { parameters } : {}),
      replaceSource: true,
      skipBroad: false,
      reloadProxy: false,
    });
    try {
      expect(await runAdminAction(adminState(), () => {
        const plan = enable([`client-id=${CLIENT_ID}`]);
        expect(plan.parameterValues).toEqual({ APPLE_ADS_CLIENT_ID: CLIENT_ID });
        bindDesiredServiceCredentialSources(plan, false);
      })).toBe(0);
      expect(fs.readFileSync(agentEnvPath, "utf8")).toContain(`APPLE_ADS_CLIENT_ID=${CLIENT_ID}`);

      // No flag, no host env: the recorded value carries over.
      expect(await runAdminAction(adminState(), () => {
        const plan = enable();
        expect(plan.parameterValues).toEqual({ APPLE_ADS_CLIENT_ID: CLIENT_ID });
        bindDesiredServiceCredentialSources(plan, true);
      })).toBe(0);
      expect(fs.readFileSync(agentEnvPath, "utf8")).toContain(`APPLE_ADS_CLIENT_ID=${CLIENT_ID}`);

      // A new flag value replaces the recorded one.
      expect(await runAdminAction(adminState(), () => {
        bindDesiredServiceCredentialSources(enable([`client-id=${OTHER_CLIENT_ID}`]), true);
      })).toBe(0);
      const env = fs.readFileSync(agentEnvPath, "utf8");
      expect(env).toContain(`APPLE_ADS_CLIENT_ID=${OTHER_CLIENT_ID}`);
      expect(env).not.toContain(CLIENT_ID);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(stateDir, { recursive: true, force: true });
      fs.rmSync(configRoot, { recursive: true, force: true });
    }
  });
});
