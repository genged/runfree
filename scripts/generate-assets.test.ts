import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  RUNTIME_INPUT_BUILD_ARGUMENTS,
  runtimeInputBuildArgumentDescriptors,
  runtimeInputBuildEnvironmentForComponent,
} from "../packages/cli/src/runtime-inputs.ts";
import { RUNTIME_ASSET_DESCRIPTORS, RUNTIME_ASSET_EXECUTABLE_MODE } from "./build-runtime.ts";
import {
  computeRuntimeComponentDigests,
  generateEmbeddedAssetsSource,
  type RuntimeAssetContent,
} from "./generate-assets.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const baseBuildArguments = {
  "agent-image": [
    ["RUNFREE_AGENT_BASE_IMAGE", "agent-base"],
    ["RUNFREE_APT_PACKAGE_NODEJS", "node-shared"],
  ],
  "proxy-image": [
    ["RUNFREE_PROXY_BASE_IMAGE", "proxy-base"],
    ["RUNFREE_APT_PACKAGE_NODEJS", "node-shared"],
  ],
} as const;

function assets(): RuntimeAssetContent[] {
  return RUNTIME_ASSET_DESCRIPTORS.map(({ path: assetPath }) => ({
    path: assetPath,
    content: Buffer.from(`content:${assetPath}`),
  }));
}

function mutateAsset(runtimeAssets: RuntimeAssetContent[], assetPath: string): RuntimeAssetContent[] {
  return runtimeAssets.map((asset) => asset.path === assetPath
    ? { ...asset, content: Buffer.from(`${asset.content.toString("utf8")}:changed`) }
    : asset);
}

describe("runtime component digests", () => {
  test.each([
    ["agent/Dockerfile", "agentImageInputDigest"],
    ["proxy/server.js", "proxyImageInputDigest"],
    ["agent/compose.yaml", "composeTemplateDigest"],
    ["agent/inspect-active-sessions.sh", "hostHelperDigest"],
  ] as const)("changing %s changes only %s", (assetPath, changedKey) => {
    const baseline = computeRuntimeComponentDigests(assets(), baseBuildArguments);
    const changed = computeRuntimeComponentDigests(mutateAsset(assets(), assetPath), baseBuildArguments);
    for (const key of [
      "agentImageInputDigest",
      "proxyImageInputDigest",
      "composeTemplateDigest",
      "hostHelperDigest",
    ] as const) {
      expect(changed[key] === baseline[key], key).toBe(key !== changedKey);
    }
  });

  test("project templates and package version do not affect component digests", () => {
    const baselineAssets = assets();
    const changedAssets = mutateAsset(baselineAssets, "templates/runfree.json");
    expect(computeRuntimeComponentDigests(changedAssets, baseBuildArguments))
      .toEqual(computeRuntimeComponentDigests(baselineAssets, baseBuildArguments));

    const first = generateEmbeddedAssetsSource({ version: "1.0.0", runtimeAssets: baselineAssets, buildArguments: baseBuildArguments });
    const second = generateEmbeddedAssetsSource({ version: "2.0.0", runtimeAssets: baselineAssets, buildArguments: baseBuildArguments });
    const componentLine = /export const RUNFREE_RUNTIME_COMPONENTS = (\{[\s\S]*?\}) as const;/;
    expect(first.match(componentLine)?.[1]).toBe(second.match(componentLine)?.[1]);
    expect(first).toContain("export const RUNFREE_RUNTIME_COMPONENTS");
    expect(first).toContain("export const EMBEDDED_MANIFEST");
  });

  test("embeds binary assets losslessly and takes modes from the declaration", () => {
    const binaryPath = "agent/inspect-active-sessions.sh";
    const binaryAssets = assets().map((asset) => asset.path === binaryPath
      ? { ...asset, content: Buffer.from([0, 255, 1, 2]) }
      : asset);
    const baseline = computeRuntimeComponentDigests(assets(), baseBuildArguments);
    const changed = computeRuntimeComponentDigests(binaryAssets, baseBuildArguments);
    const source = generateEmbeddedAssetsSource({
      version: "1.0.0",
      runtimeAssets: binaryAssets,
      buildArguments: baseBuildArguments,
    });

    expect(source).toContain('"base64": "AP8BAg=="');
    expect(changed.hostHelperDigest).not.toBe(baseline.hostHelperDigest);
    expect(changed.agentImageInputDigest).toBe(baseline.agentImageInputDigest);

    // The manifest lists exactly the declared executables; every other asset is
    // the 0644 default and is omitted. Contents cannot influence either.
    const modes = JSON.parse(/"modes": (\{[\s\S]*?\})\n\}/.exec(source)?.[1] ?? "null") as Record<string, number>;
    expect(modes).toEqual(Object.fromEntries(RUNTIME_ASSET_DESCRIPTORS
      .filter(({ executable }) => executable === true)
      .map(({ path: assetPath }) => [`runtime/${assetPath}`, RUNTIME_ASSET_EXECUTABLE_MODE])));
    expect(modes).toEqual({ "runtime/agent/inspect-active-sessions.sh": RUNTIME_ASSET_EXECUTABLE_MODE });
  });

  test("refuses to embed an asset that the declaration does not cover", () => {
    expect(() => generateEmbeddedAssetsSource({
      version: "1.0.0",
      runtimeAssets: [...assets(), { path: "proxy/smuggled.js", content: Buffer.from("payload") }],
      buildArguments: baseBuildArguments,
    })).toThrow("undeclared runtime asset: proxy/smuggled.js");
  });

  test("shared and component-owned build arguments invalidate only their consumers", () => {
    const baseline = computeRuntimeComponentDigests(assets(), baseBuildArguments);
    const shared = {
      "agent-image": baseBuildArguments["agent-image"].map(([name, value]) => [name, name.includes("NODEJS") ? "node-next" : value] as const),
      "proxy-image": baseBuildArguments["proxy-image"].map(([name, value]) => [name, name.includes("NODEJS") ? "node-next" : value] as const),
    };
    const agentOnly = {
      ...baseBuildArguments,
      "agent-image": baseBuildArguments["agent-image"].map(([name, value]) => [name, name.includes("AGENT_BASE") ? "agent-next" : value] as const),
    };
    const proxyOnly = {
      ...baseBuildArguments,
      "proxy-image": baseBuildArguments["proxy-image"].map(([name, value]) => [name, name.includes("PROXY_BASE") ? "proxy-next" : value] as const),
    };
    const sharedDigests = computeRuntimeComponentDigests(assets(), shared);
    const agentDigests = computeRuntimeComponentDigests(assets(), agentOnly);
    const proxyDigests = computeRuntimeComponentDigests(assets(), proxyOnly);

    expect(sharedDigests.agentImageInputDigest).not.toBe(baseline.agentImageInputDigest);
    expect(sharedDigests.proxyImageInputDigest).not.toBe(baseline.proxyImageInputDigest);
    expect(agentDigests.agentImageInputDigest).not.toBe(baseline.agentImageInputDigest);
    expect(agentDigests.proxyImageInputDigest).toBe(baseline.proxyImageInputDigest);
    expect(proxyDigests.agentImageInputDigest).toBe(baseline.agentImageInputDigest);
    expect(proxyDigests.proxyImageInputDigest).not.toBe(baseline.proxyImageInputDigest);
  });
});

describe("runtime input ownership", () => {
  let temporaryRuntimeRoot: string;

  beforeEach(() => {
    temporaryRuntimeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-runtime-input-projection-"));
    fs.copyFileSync(
      path.join(repoRoot, "packages/agent-runtime/runtime-inputs.lock.json"),
      path.join(temporaryRuntimeRoot, "runtime-inputs.lock.json"),
    );
    for (const [source, destination] of [
      ["packages/agent-runtime/agent/agent-tools/package-lock.json", "agent/agent-tools/package-lock.json"],
      ["packages/proxy/package-lock.json", "proxy/package-lock.json"],
    ]) {
      const destinationPath = path.join(temporaryRuntimeRoot, destination);
      fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
      fs.copyFileSync(path.join(repoRoot, source), destinationPath);
    }
  });

  afterEach(() => {
    fs.rmSync(temporaryRuntimeRoot, { recursive: true, force: true });
  });

  test("projects the canonical validated environment by declared owner", () => {
    const names = RUNTIME_INPUT_BUILD_ARGUMENTS.map(({ name }) => name);
    expect(new Set(names).size).toBe(names.length);
    expect(RUNTIME_INPUT_BUILD_ARGUMENTS.every(({ lockPaths }) => lockPaths.length > 0)).toBe(true);

    const agent = runtimeInputBuildEnvironmentForComponent(temporaryRuntimeRoot, "agent-image");
    const proxy = runtimeInputBuildEnvironmentForComponent(temporaryRuntimeRoot, "proxy-image");
    expect(agent.RUNFREE_AGENT_BASE_IMAGE).toBeDefined();
    expect(agent.RUNFREE_PROXY_BASE_IMAGE).toBeUndefined();
    expect(agent.RUNFREE_APT_PACKAGE_GIT).toBeDefined();
    expect(agent.RUNFREE_APT_PACKAGE_DUMB_INIT).toBeUndefined();
    expect(proxy.RUNFREE_AGENT_BASE_IMAGE).toBeUndefined();
    expect(proxy.RUNFREE_PROXY_BASE_IMAGE).toBeDefined();
    expect(proxy.RUNFREE_APT_PACKAGE_GIT).toBeUndefined();
    expect(proxy.RUNFREE_APT_PACKAGE_DUMB_INIT).toBeDefined();
    expect(agent.RUNFREE_APT_PACKAGE_NODEJS).toBe(proxy.RUNFREE_APT_PACKAGE_NODEJS);
    expect(Object.keys(agent).sort()).toEqual(runtimeInputBuildArgumentDescriptors("agent-image").map(({ name }) => name).sort());
    expect(Object.keys(proxy).sort()).toEqual(runtimeInputBuildArgumentDescriptors("proxy-image").map(({ name }) => name).sort());
  });
});
