import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateNetworkPolicy } from "./network-policy.ts";
import {
  EFFECTIVE_CONTROL_COMPILER_VERSION,
  loadEffectiveProxyControl,
} from "./effective-control.ts";

function digest(source: string): string {
  return `sha256:${crypto.createHash("sha256").update(source).digest("hex")}`;
}

describe("effective proxy control loading", () => {
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-effective-proxy-"));
  });

  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  function publish(input: { hosts?: string[]; oauthProviders?: Record<string, unknown> } = {}) {
    const networkSource = `${JSON.stringify({ hosts: input.hosts ?? ["api.example.com"] }, null, 2)}\n`;
    const oauthSource = `${JSON.stringify({ providers: input.oauthProviders ?? {} }, null, 2)}\n`;
    const policyGeneration = validateNetworkPolicy(JSON.parse(networkSource)).generation;
    const controlGeneration = `sha256:${"a".repeat(64)}`;
    const generationDir = path.join(root, "generations", controlGeneration.slice("sha256:".length));
    fs.mkdirSync(generationDir, { recursive: true });
    fs.writeFileSync(path.join(generationDir, "network-policy.json"), networkSource);
    fs.writeFileSync(path.join(generationDir, "oauth-mediation-policy.json"), oauthSource);
    const manifestSource = `${JSON.stringify({
      schemaVersion: 1,
      compilerVersion: EFFECTIVE_CONTROL_COMPILER_VERSION,
      controlGeneration,
      policyGeneration,
      files: {
        "network-policy.json": digest(networkSource),
        "oauth-mediation-policy.json": digest(oauthSource),
      },
    }, null, 2)}\n`;
    fs.writeFileSync(path.join(generationDir, "manifest.json"), manifestSource);
    const active = {
      schemaVersion: 1,
      controlGeneration,
      proxyManifestDigest: digest(manifestSource),
      hostManifestDigest: `sha256:${"b".repeat(64)}`,
    };
    fs.writeFileSync(path.join(root, "active.json"), `${JSON.stringify(active, null, 2)}\n`);
    return { active, generationDir, manifestSource, networkSource, oauthSource };
  }

  test("loads network and OAuth policy from one manifest-selected generation", () => {
    const fixture = publish({
      oauthProviders: {
        example: {
          resourceHost: "api.example.com",
          tokenEndpoints: [{ host: "api.example.com", path: "/oauth/token" }],
        },
      },
    });
    const loaded = loadEffectiveProxyControl(root);

    expect(loaded.active).toEqual(fixture.active);
    expect(loaded.networkPolicy.allowedHosts).toEqual(["api.example.com"]);
    expect(loaded.oauthPolicy.providers.map((provider: { providerId: string }) => provider.providerId)).toEqual(["example"]);
    expect(loaded.manifest.controlGeneration).toBe(fixture.active.controlGeneration);
  });

  test("rejects a substituted OAuth payload before returning any new policy", () => {
    const { generationDir } = publish();
    fs.writeFileSync(path.join(generationDir, "oauth-mediation-policy.json"), `{"providers":{"attacker":{}}}\n`);

    expect(() => loadEffectiveProxyControl(root)).toThrow("payload digest");
  });

  test("rejects a manifest from another selection before loading its payloads", () => {
    const { generationDir } = publish();
    const manifestPath = path.join(generationDir, "manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.controlGeneration = `sha256:${"c".repeat(64)}`;
    const manifestSource = `${JSON.stringify(manifest, null, 2)}\n`;
    fs.writeFileSync(manifestPath, manifestSource);
    const activePath = path.join(root, "active.json");
    const active = JSON.parse(fs.readFileSync(activePath, "utf8")) as Record<string, unknown>;
    active.proxyManifestDigest = digest(manifestSource);
    fs.writeFileSync(activePath, `${JSON.stringify(active, null, 2)}\n`);

    expect(() => loadEffectiveProxyControl(root)).toThrow("different control generation");
  });

  test("rejects duplicate pointer keys and linked generation files", () => {
    const { generationDir } = publish();
    fs.writeFileSync(
      path.join(root, "active.json"),
      `{"schemaVersion":1,"schemaVersion":1,"controlGeneration":"sha256:${"a".repeat(64)}","proxyManifestDigest":"sha256:${"b".repeat(64)}","hostManifestDigest":"sha256:${"c".repeat(64)}"}`,
    );
    expect(() => loadEffectiveProxyControl(root)).toThrow("duplicate object key");

    publish();
    fs.linkSync(path.join(generationDir, "network-policy.json"), path.join(root, "linked-policy.json"));
    expect(() => loadEffectiveProxyControl(root)).toThrow("regular single-link");
  });

  test("does not infer a generation when active selection is missing", () => {
    publish();
    fs.rmSync(path.join(root, "active.json"));

    expect(() => loadEffectiveProxyControl(root)).toThrow();
  });
});
