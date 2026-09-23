import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { RUNFREE_VERSION, EMBEDDED_ASSETS, EMBEDDED_MANIFEST } from "./embedded-assets.generated.ts";
import { runfreeDataRoot } from "./paths.ts";

export type AssetManifest = {
  version: string;
  files: Record<string, string>;
  modes: Record<string, number>;
};

export type MaterializedAssets = {
  version: string;
  dataDir: string;
  versionDir: string;
  currentDir: string;
  runtimeDir: string;
  manifest: AssetManifest;
};

function fileSha256(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function listFiles(dir: string, prefix = ""): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = prefix ? path.posix.join(prefix, entry.name) : entry.name;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return listFiles(fullPath, relativePath);
    return entry.isFile() ? [relativePath] : [];
  });
}

function validExistingVersion(versionDir: string, manifest: AssetManifest): boolean {
  const manifestPath = path.join(versionDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) return false;
  try {
    const installed = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as AssetManifest;
    if (installed.version !== manifest.version) return false;
    const expectedFiles = ["manifest.json", ...Object.keys(manifest.files)].sort((left, right) => left.localeCompare(right));
    const actualFiles = listFiles(versionDir).sort((left, right) => left.localeCompare(right));
    if (actualFiles.join("\0") !== expectedFiles.join("\0")) return false;
    for (const [relativePath, expected] of Object.entries(manifest.files)) {
      const filePath = path.join(versionDir, relativePath);
      const stat = fs.lstatSync(filePath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) return false;
      if (`sha256:${fileSha256(filePath)}` !== expected) return false;
      if ((stat.mode & 0o777) !== (manifest.modes[relativePath] ?? 0o644)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

type EmbeddedAsset = (typeof EMBEDDED_ASSETS)[number];

function embeddedAssetBytes(asset: EmbeddedAsset): Buffer {
  const base64 = Reflect.get(asset, "base64");
  if (typeof base64 === "string") return Buffer.from(base64, "base64");
  const content = Reflect.get(asset, "content");
  if (typeof content !== "string") throw new Error(`embedded asset has no decodable content: ${asset.path}`);
  return Buffer.from(content, "utf8");
}

function embeddedAssetMode(asset: EmbeddedAsset): number {
  return "mode" in asset ? asset.mode : 0o644;
}

function replaceCurrentLink(currentPath: string, versionDir: string): void {
  try {
    const current = fs.lstatSync(currentPath);
    if (current.isSymbolicLink()) {
      if (fs.readlinkSync(currentPath) === versionDir) return;
      fs.unlinkSync(currentPath);
    } else {
      fs.rmSync(currentPath, { recursive: true, force: true });
    }
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
      throw error;
    }
  }
  try {
    fs.symlinkSync(versionDir, currentPath, "dir");
  } catch {
    fs.cpSync(versionDir, currentPath, { recursive: true });
  }
}

export function materializeAssets(env: NodeJS.ProcessEnv = process.env): MaterializedAssets {
  const dataDir = runfreeDataRoot(env);
  const versionsDir = path.join(dataDir, "versions");
  const version = RUNFREE_VERSION;
  const versionDir = path.join(versionsDir, version);
  const currentDir = path.join(dataDir, "current");
  const manifest = EMBEDDED_MANIFEST as AssetManifest;

  fs.mkdirSync(versionsDir, { recursive: true, mode: 0o755 });

  if (!validExistingVersion(versionDir, manifest)) {
    const tmpDir = path.join(versionsDir, `${version}.${process.pid}.tmp`);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    for (const asset of EMBEDDED_ASSETS) {
      const destination = path.join(tmpDir, asset.path);
      fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
      const mode = embeddedAssetMode(asset);
      fs.writeFileSync(destination, embeddedAssetBytes(asset), { mode });
      fs.chmodSync(destination, mode);
    }
    fs.writeFileSync(path.join(tmpDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    fs.rmSync(versionDir, { recursive: true, force: true });
    fs.renameSync(tmpDir, versionDir);
  }

  replaceCurrentLink(currentDir, versionDir);

  return {
    version,
    dataDir,
    versionDir,
    currentDir,
    runtimeDir: path.join(currentDir, "runtime"),
    manifest,
  };
}

export function cleanOldAssetVersions(env: NodeJS.ProcessEnv = process.env): string[] {
  const dataDir = runfreeDataRoot(env);
  const versionsDir = path.join(dataDir, "versions");
  const removed: string[] = [];
  if (!fs.existsSync(versionsDir)) return removed;

  for (const entry of fs.readdirSync(versionsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === RUNFREE_VERSION) continue;
    fs.rmSync(path.join(versionsDir, entry.name), { recursive: true, force: true });
    removed.push(entry.name);
  }
  return removed;
}
