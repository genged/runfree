import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  validateDesiredNetworkPolicy,
  withRequiredDesiredNetworkPolicyVersion,
} from "@runfree/runtime-contracts/desired-network-policy";

import { desiredServiceEntry } from "./admin/service-policy.ts";
import {
  readAndValidateUserServiceFile,
  userServiceDigest,
  validateUserServiceDefinitionObject,
} from "./user-services.ts";

function writeDefinition(dir: string, id: string, definition: Record<string, unknown>): string {
  const filePath = path.join(dir, `${id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(definition));
  return filePath;
}

describe("user service definitions (SR4/A1 reserved suffix)", () => {
  let dir: string;

  function makeDir(): string {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-user-service-def-"));
    return dir;
  }

  function cleanup(): void {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  test("refuses a host using the reserved runfree.internal suffix", () => {
    makeDir();
    try {
      const filePath = writeDefinition(dir, "user-acme", {
        schemaVersion: 1,
        id: "user-acme",
        label: "Acme",
        revision: 1,
        hosts: [{ host: "x.runfree.internal" }],
        explanations: ["user-defined test service"],
      });
      expect(() => readAndValidateUserServiceFile(filePath)).toThrow("reserved runfree.internal suffix");
    } finally {
      cleanup();
    }
  });

  test("refuses a credential destination using the reserved runfree.internal suffix", () => {
    makeDir();
    try {
      const filePath = writeDefinition(dir, "user-acme", {
        schemaVersion: 1,
        id: "user-acme",
        label: "Acme",
        revision: 1,
        hosts: [{ host: "api.acme.test" }],
        explanations: ["user-defined test service"],
        credential: {
          tokenDescription: "Acme API token",
          agentEnv: ["ACME_TOKEN"],
          credentials: [{ host: "x.runfree.internal", header: "Authorization", scheme: "bearer" }],
        },
      });
      expect(() => readAndValidateUserServiceFile(filePath)).toThrow("reserved runfree.internal suffix");
    } finally {
      cleanup();
    }
  });
});

describe("user service definitions: basic scheme, username, and git-http/git-lfs protocols (O-8)", () => {
  function definition(credentials: unknown[]): Record<string, unknown> {
    return {
      schemaVersion: 1,
      id: "user-forge",
      label: "Self-hosted forge",
      revision: 1,
      hosts: [{ host: "git.forge.example" }],
      explanations: ["git over HTTPS: git.forge.example"],
      credential: {
        tokenDescription: "Forge token",
        agentEnv: ["FORGE_TOKEN"],
        credentials,
      },
    };
  }
  const basicGit = {
    host: "git.forge.example",
    header: "Authorization",
    scheme: "basic",
    username: "oauth2",
    protocol: "git-http",
  };

  test("accepts, canonicalizes, and pins basic + username + protocol beside an API bearer mapping", () => {
    // Keys out of canonical order on input; the stored definition is canonical.
    const loaded = validateUserServiceDefinitionObject(definition([
      { protocol: "git-http", username: "oauth2", scheme: "basic", header: "Authorization", host: "git.forge.example" },
      { host: "git.forge.example", header: "Authorization", scheme: "bearer", pathPrefix: "/api/" },
    ]));
    expect(loaded.svc.credential?.credentials).toEqual([
      basicGit,
      { host: "git.forge.example", header: "Authorization", scheme: "bearer", pathPrefix: "/api/" },
    ]);
    expect(Object.keys(loaded.svc.credential?.credentials[0] ?? {}))
      .toEqual(["host", "header", "scheme", "username", "protocol"]);
    expect(loaded.definition.schemaVersion).toBe(1);
    expect(loaded.digest).toBe(userServiceDigest(loaded.definition));
    // The digest is a function of the definition: a different username pins differently.
    const other = validateUserServiceDefinitionObject(definition([{ ...basicGit, username: "x-access-token" }]));
    expect(other.digest).not.toBe(loaded.digest);

    const entry = desiredServiceEntry(loaded.svc, {}, loaded.digest);
    expect(entry.resolved.tokens?.["user-forge"]?.credentials).toContainEqual(basicGit);
    const project = withRequiredDesiredNetworkPolicyVersion({ hosts: [], services: { "user-forge": entry } });
    expect(project.version).toBe(3);
    expect(validateDesiredNetworkPolicy(project).services?.["user-forge"]).toEqual(entry);
  });

  test("a user definition with only bearer mappings still pins to desired v2", () => {
    const loaded = validateUserServiceDefinitionObject(definition([
      { host: "git.forge.example", header: "Authorization", scheme: "bearer" },
    ]));
    const entry = desiredServiceEntry(loaded.svc, {}, loaded.digest);
    expect(withRequiredDesiredNetworkPolicyVersion({ hosts: [], services: { "user-forge": entry } }).version).toBe(2);
  });

  test.each([
    ["username with a colon", { ...basicGit, username: "a:b" }, "credentials[0].username must not contain ':'"],
    ["username with a space", { ...basicGit, username: "a b" }, "credentials[0].username must contain only printable ASCII"],
    ["username with a control character", { ...basicGit, username: "a\u0007b" }, "credentials[0].username must contain only printable ASCII"],
    ["username with a non-ASCII character", { ...basicGit, username: "ü" }, "credentials[0].username must contain only printable ASCII"],
    ["username longer than 64 bytes", { ...basicGit, username: "a".repeat(65) }, "credentials[0].username must be at most 64 bytes"],
    ["empty username", { ...basicGit, username: "" }, "credentials[0].username must be non-empty"],
    ["non-string username", { ...basicGit, username: 7 }, "credentials[0].username must be a string"],
    ["basic without a username", { host: "git.forge.example", header: "Authorization", scheme: "basic" }, "credentials[0].username is required with scheme basic"],
    ["username with bearer", { host: "git.forge.example", header: "Authorization", scheme: "bearer", username: "oauth2" }, "credentials[0].username is valid only with scheme basic"],
    ["username with raw", { host: "git.forge.example", header: "X-Token", scheme: "raw", username: "oauth2" }, "credentials[0].username is valid only with scheme basic"],
    ["unknown protocol", { ...basicGit, protocol: "git-ssh" }, "credentials[0].protocol must be one of: git-http, git-lfs"],
    ["non-string protocol", { ...basicGit, protocol: ["git-http"] }, "credentials[0].protocol must be one of: git-http, git-lfs"],
    ["unknown scheme", { ...basicGit, scheme: "digest" }, "credentials[0].scheme must be one of: bearer, raw, basic"],
    ["unknown credential key", { ...basicGit, password: "x" }, "unknown key password"],
  ])("refuses %s", (_name, credential, message) => {
    expect(() => validateUserServiceDefinitionObject(definition([credential]))).toThrow(message);
  });

  test("accepts one git-http and one git-lfs mapping on one host and header", () => {
    const loaded = validateUserServiceDefinitionObject(definition([basicGit, { ...basicGit, protocol: "git-lfs" }]));
    expect(loaded.svc.credential?.credentials.map((credential) => credential.protocol)).toEqual(["git-http", "git-lfs"]);
  });

  test("refuses two mappings with one protocol for one host and header through the shared validator", () => {
    expect(() => validateUserServiceDefinitionObject(definition([
      basicGit,
      { ...basicGit, username: "other" },
    ]))).toThrow("conflicts with user-forge.git.forge.example.Authorization");
    expect(() => validateUserServiceDefinitionObject(definition([
      basicGit,
      { ...basicGit, username: "other", pathPrefix: "/scoped/" },
    ]))).toThrow("second git-http mapping");
  });

  test("a 64-byte username is accepted", () => {
    const loaded = validateUserServiceDefinitionObject(definition([{ ...basicGit, username: "a".repeat(64) }]));
    expect(loaded.svc.credential?.credentials[0]?.username).toBe("a".repeat(64));
  });
});
