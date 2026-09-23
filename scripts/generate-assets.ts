import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  runtimeInputBuildEnvironmentForComponent,
  type RuntimeImageComponent,
} from "../packages/cli/src/runtime-inputs.ts";
import {
  assertGeneratedRuntimeManifest,
  isDirectEntrypoint,
  RUNTIME_ASSET_DESCRIPTORS,
  RUNTIME_ASSET_REGULAR_MODE,
  type RuntimeAssetRole,
  runtimeAssetMode,
} from "./build-runtime.ts";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const runtimeRoot = path.join(repoRoot, "dist", "runtime");
const outputPath = path.join(repoRoot, "packages", "cli", "src", "embedded-assets.generated.ts");

// Deliberately carries no mode: the mode is a property of the declared asset,
// looked up by path, so there is no second copy of it that could disagree.
export type RuntimeAssetContent = Readonly<{
  path: string;
  content: Buffer;
}>;

export type RuntimeComponentDigests = Readonly<{
  schemaVersion: 1;
  agentImageInputDigest: string;
  proxyImageInputDigest: string;
  composeTemplateDigest: string;
  hostHelperDigest: string;
}>;

function listFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory() && entry.name === "node_modules") continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function sha256(value: string | Buffer): string {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function utf8AssetContent(content: Buffer): string | undefined {
  if (content.includes(0)) return undefined;
  const source = content.toString("utf8");
  return Buffer.from(source, "utf8").equals(content) ? source : undefined;
}

export function stableJson(value: unknown): string {
  const normalized = (entry: unknown): unknown => {
    if (Array.isArray(entry)) return entry.map(normalized);
    if (typeof entry !== "object" || entry === null) return entry;
    return Object.fromEntries(Object.entries(entry)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, normalized(child)]));
  };
  return JSON.stringify(normalized(value));
}

function componentDigest(
  role: RuntimeAssetRole,
  assets: readonly RuntimeAssetContent[],
  buildArguments: readonly (readonly [string, string])[] = [],
): string {
  const rolePaths = new Set(RUNTIME_ASSET_DESCRIPTORS
    .filter(({ roles }) => roles.includes(role))
    .map(({ path: assetPath }) => assetPath));
  const files = assets
    .filter(({ path: assetPath }) => rolePaths.has(assetPath))
    .map(({ path: assetPath, content }) => {
      const declaredMode = runtimeAssetMode(assetPath);
      return declaredMode === RUNTIME_ASSET_REGULAR_MODE
        ? [assetPath, sha256(content)] as const
        : [assetPath, sha256(content), declaredMode] as const;
    })
    .sort(([left], [right]) => left.localeCompare(right));
  const sortedBuildArguments = [...buildArguments].sort(([left], [right]) => left.localeCompare(right));
  return sha256(stableJson({ schemaVersion: 1, files, buildArguments: sortedBuildArguments }));
}

export function computeRuntimeComponentDigests(
  assets: readonly RuntimeAssetContent[],
  buildArguments: Readonly<Record<RuntimeImageComponent, readonly (readonly [string, string])[]>>,
): RuntimeComponentDigests {
  return {
    schemaVersion: 1,
    agentImageInputDigest: componentDigest("agent-image", assets, buildArguments["agent-image"]),
    proxyImageInputDigest: componentDigest("proxy-image", assets, buildArguments["proxy-image"]),
    composeTemplateDigest: componentDigest("compose-template", assets),
    hostHelperDigest: componentDigest("host-helper", assets),
  };
}

function componentBuildArguments(
  sourceRuntimeRoot: string,
  component: RuntimeImageComponent,
): readonly (readonly [string, string])[] {
  return Object.entries(runtimeInputBuildEnvironmentForComponent(sourceRuntimeRoot, component))
    .map(([name, value]) => {
      if (value === undefined) throw new Error(`runtime input build argument missing: ${name}`);
      return [name, value] as const;
    })
    .sort(([left], [right]) => left.localeCompare(right));
}

export function generateEmbeddedAssetsSource(options: {
  version: string;
  runtimeAssets: readonly RuntimeAssetContent[];
  buildArguments: Readonly<Record<RuntimeImageComponent, readonly (readonly [string, string])[]>>;
}): string {
  const assets = options.runtimeAssets
    .map(({ path: runtimePath, content }) => {
      const textContent = utf8AssetContent(content);
      return {
        path: `runtime/${runtimePath}`,
        ...(textContent === undefined
          ? { base64: content.toString("base64") }
          : { content: textContent }),
        sha256: sha256(content),
        mode: runtimeAssetMode(runtimePath),
      };
    })
    .sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    version: options.version,
    files: Object.fromEntries(assets.map((asset) => [asset.path, asset.sha256])),
    modes: Object.fromEntries(assets
      .filter((asset) => asset.mode !== RUNTIME_ASSET_REGULAR_MODE)
      .map((asset) => [asset.path, asset.mode])),
  };
  const runtimeDigest = sha256(JSON.stringify(assets
    .filter((asset) => !asset.path.startsWith("runtime/templates/"))
    .map((asset) => [asset.path, asset.sha256])));
  const components = computeRuntimeComponentDigests(options.runtimeAssets, options.buildArguments);

  return `// Generated by scripts/generate-assets.ts. Do not edit by hand.

export const RUNFREE_VERSION = ${JSON.stringify(options.version)} as const;

/** @deprecated Use RUNFREE_RUNTIME_COMPONENTS for component identity. */
export const RUNFREE_RUNTIME_DIGEST = ${JSON.stringify(runtimeDigest)} as const;

export const RUNFREE_RUNTIME_COMPONENTS = ${JSON.stringify(components, null, 2)} as const;

export const EMBEDDED_ASSETS = ${JSON.stringify(assets.map((asset) => ({
    path: asset.path,
    ...("base64" in asset ? { base64: asset.base64 } : { content: asset.content }),
    ...(asset.mode !== RUNTIME_ASSET_REGULAR_MODE ? { mode: asset.mode } : {}),
  })), null, 2)} as const;

export const EMBEDDED_MANIFEST = ${JSON.stringify(manifest, null, 2)} as const;
`;
}

export function generateEmbeddedAssets(options: {
  repoRoot?: string;
  runtimeRoot?: string;
  outputPath?: string;
  version?: string;
} = {}): void {
  const sourceRepoRoot = options.repoRoot ?? repoRoot;
  const sourceRuntimeRoot = options.runtimeRoot ?? runtimeRoot;
  const destination = options.outputPath ?? outputPath;
  const version = options.version ?? (JSON.parse(
    fs.readFileSync(path.join(sourceRepoRoot, "package.json"), "utf8"),
  ) as { version: string }).version;
  assertGeneratedRuntimeManifest(sourceRuntimeRoot);
  const runtimeAssets = listFiles(sourceRuntimeRoot)
    .map((filePath) => ({
      path: path.relative(sourceRuntimeRoot, filePath).split(path.sep).join("/"),
      content: fs.readFileSync(filePath),
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const source = generateEmbeddedAssetsSource({
    version,
    runtimeAssets,
    buildArguments: {
      "agent-image": componentBuildArguments(sourceRuntimeRoot, "agent-image"),
      "proxy-image": componentBuildArguments(sourceRuntimeRoot, "proxy-image"),
    },
  });
  fs.writeFileSync(destination, source);
}

if (isDirectEntrypoint(import.meta.url, process.argv[1])) {
  generateEmbeddedAssets();
}
