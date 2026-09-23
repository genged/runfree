import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { cleanOldAssetVersions, materializeAssets } from "./assets.ts";
import { RUNFREE_RUNTIME_DIGEST, EMBEDDED_ASSETS, EMBEDDED_MANIFEST } from "./embedded-assets.generated.ts";
import { runtimeInputBuildEnvironment } from "./runtime-inputs.ts";

let tmp: string;

function sha256(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function digestManifestEntries(paths: string[]): string {
  const files: Record<string, string> = EMBEDDED_MANIFEST.files;
  const entries = paths
    .slice()
    .sort((left, right) => left.localeCompare(right))
    .map((relativePath) => [relativePath, files[relativePath]]);
  return `sha256:${crypto.createHash("sha256").update(JSON.stringify(entries)).digest("hex")}`;
}

function embeddedAssetContent(relativePath: string): string {
  const asset = EMBEDDED_ASSETS.find((entry) => entry.path === relativePath);
  if (!asset) throw new Error(`missing embedded asset: ${relativePath}`);
  const base64 = Reflect.get(asset, "base64");
  if (typeof base64 === "string") return Buffer.from(base64, "base64").toString("utf8");
  const content = Reflect.get(asset, "content");
  if (typeof content !== "string") throw new Error(`embedded asset has no decodable content: ${relativePath}`);
  return content;
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-assets-tests-")));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("runtime asset materialization", () => {
  test("runtime digest covers container assets without forcing rebuilds for templates", () => {
    const allPaths = Object.keys(EMBEDDED_MANIFEST.files);
    const containerPaths = allPaths.filter((relativePath) => !relativePath.startsWith("runtime/templates/"));

    expect(RUNFREE_RUNTIME_DIGEST).toBe(digestManifestEntries(containerPaths));
    expect(RUNFREE_RUNTIME_DIGEST).not.toBe(digestManifestEntries(allPaths));
    expect(containerPaths).toContain("runtime/runtime-inputs.lock.json");
    expect(containerPaths).toContain("runtime/agent/agent-tools/package-lock.json");
    expect(containerPaths).toContain("runtime/agent/claude-runfree.sh");
    expect(containerPaths).toContain("runtime/agent/session-entry.sh");
    expect(containerPaths).toContain("runtime/agent/session-ready-probe.cjs");
    expect(containerPaths).toContain("runtime/proxy/package-lock.json");
    expect(containerPaths).toContain("runtime/proxy/server.js");
    expect(containerPaths).toContain("runtime/proxy/contracts/network-policy.js");
    expect(RUNFREE_RUNTIME_DIGEST).toBe(digestManifestEntries(containerPaths));
    expect(RUNFREE_RUNTIME_DIGEST).not.toBe(digestManifestEntries(containerPaths
      .filter((relativePath) => relativePath !== "runtime/runtime-inputs.lock.json")));
    expect(RUNFREE_RUNTIME_DIGEST).not.toBe(digestManifestEntries(containerPaths
      .filter((relativePath) => relativePath !== "runtime/agent/agent-tools/package-lock.json")));
    expect(RUNFREE_RUNTIME_DIGEST).not.toBe(digestManifestEntries(containerPaths
      .filter((relativePath) => relativePath !== "runtime/proxy/package-lock.json")));
    expect(RUNFREE_RUNTIME_DIGEST).not.toBe(digestManifestEntries(containerPaths
      .filter((relativePath) => relativePath !== "runtime/proxy/contracts/network-policy.js")));
  });

  test("runtime input lock and package locks declare the agent tools shipped in the image", () => {
    const lock = JSON.parse(embeddedAssetContent("runtime/runtime-inputs.lock.json")) as {
      apt?: {
        family?: string;
        sources?: Record<string, {
          url?: string;
          suites?: string[];
          components?: string[];
          signedBy?: string;
        }>;
      };
      npm?: Record<string, string>;
    };
    const agentToolsPackage = JSON.parse(embeddedAssetContent("runtime/agent/agent-tools/package.json")) as {
      dependencies?: Record<string, string>;
    };
    const agentToolsLock = JSON.parse(embeddedAssetContent("runtime/agent/agent-tools/package-lock.json")) as {
      lockfileVersion?: number;
      packages?: Record<string, unknown>;
    };
    const proxyLock = JSON.parse(embeddedAssetContent("runtime/proxy/package-lock.json")) as {
      lockfileVersion?: number;
      packages?: Record<string, unknown>;
    };

    expect(lock.apt?.family).toBe("ubuntu");
    expect(lock.apt?.sources).toMatchObject({
      ubuntu: {
        url: "http://archive.ubuntu.com/ubuntu",
        suites: ["resolute", "resolute-updates"],
        components: ["main", "universe"],
        signedBy: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
      },
      ubuntuSecurity: {
        url: "http://security.ubuntu.com/ubuntu",
        suites: ["resolute-security"],
        components: ["main", "universe"],
        signedBy: "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
      },
    });
    expect(lock.npm?.agentToolsPackageLock).toBe("agent/agent-tools/package-lock.json");
    expect(lock.npm?.proxyPackageLock).toBe("proxy/package-lock.json");

    expect(agentToolsPackage.dependencies).toMatchObject({
      "@openai/codex": expect.any(String),
      "@earendil-works/pi-coding-agent": expect.any(String),
      pnpm: expect.any(String),
    });
    expect(agentToolsLock.lockfileVersion).toBe(3);
    expect(agentToolsLock.packages).toHaveProperty("node_modules/@earendil-works/pi-coding-agent");
    expect(agentToolsLock.packages).toHaveProperty("node_modules/pnpm");
    expect(proxyLock.lockfileVersion).toBe(3);
  });

  test("runtime APT pins use Ubuntu packages with relative-worktree Git and Node 22", () => {
    const installed = materializeAssets({ XDG_DATA_HOME: path.join(tmp, "xdg-data") });
    const lockEnv = runtimeInputBuildEnvironment(installed.runtimeDir);

    expect(lockEnv.RUNFREE_AGENT_BASE_IMAGE).toMatch(/^ubuntu:26\.04@sha256:[a-f0-9]{64}$/);
    expect(lockEnv.RUNFREE_PROXY_BASE_IMAGE).toBe(lockEnv.RUNFREE_AGENT_BASE_IMAGE);
    expect(lockEnv.RUNFREE_APT_SOURCE_UBUNTU_URL).toBe("http://archive.ubuntu.com/ubuntu");
    expect(lockEnv.RUNFREE_APT_SOURCE_UBUNTU_SECURITY_URL).toBe("http://security.ubuntu.com/ubuntu");
    expect(lockEnv.RUNFREE_APT_PACKAGE_GIT).toBe("1:2.53.0-1ubuntu1");
    expect(lockEnv.RUNFREE_APT_PACKAGE_NODEJS).toBe("22.22.1+dfsg+~cs22.19.15-1ubuntu1");
    expect(lockEnv.RUNFREE_APT_PACKAGE_NPM).toBe("9.2.0~ds3-1");
  });

  test("rewrites a corrupted installed asset before exposing the current runtime", () => {
    const env = { XDG_DATA_HOME: path.join(tmp, "xdg-data") };
    const first = materializeAssets(env);
    const dockerfile = path.join(first.versionDir, "runtime", "agent", "Dockerfile");
    const expectedDigest = first.manifest.files["runtime/agent/Dockerfile"];

    expect(fs.existsSync(dockerfile)).toBe(true);
    expect(`sha256:${sha256(dockerfile)}`).toBe(expectedDigest);

    fs.writeFileSync(dockerfile, "corrupt runtime asset\n");

    const second = materializeAssets(env);

    expect(second.versionDir).toBe(first.versionDir);
    expect(`sha256:${sha256(dockerfile)}`).toBe(expectedDigest);
    expect(fs.existsSync(path.join(second.runtimeDir, "agent", "Dockerfile"))).toBe(true);
  });

  test("restores the exact embedded executable mode before exposing an asset", () => {
    const env = { XDG_DATA_HOME: path.join(tmp, "xdg-data") };
    const first = materializeAssets(env);
    const helper = path.join(first.versionDir, "runtime", "agent", "inspect-active-sessions.sh");
    const expectedMode = EMBEDDED_MANIFEST.modes["runtime/agent/inspect-active-sessions.sh"];

    expect(expectedMode).toBe(0o755);
    expect(fs.statSync(helper).mode & 0o777).toBe(expectedMode);
    fs.chmodSync(helper, 0o644);

    materializeAssets(env);

    expect(fs.statSync(helper).mode & 0o777).toBe(expectedMode);
  });

  test("repairs a bad current runtime pointer and removes stale version files", () => {
    const env = { XDG_DATA_HOME: path.join(tmp, "xdg-data") };
    const installed = materializeAssets(env);
    const versionSentinel = path.join(installed.versionDir, "locally-created-marker");
    fs.writeFileSync(versionSentinel, "kept when the version remains valid");
    fs.rmSync(installed.currentDir, { recursive: true, force: true });
    fs.mkdirSync(installed.currentDir, { recursive: true });
    fs.writeFileSync(path.join(installed.currentDir, "wrong-runtime"), "not the installed runtime");

    const repaired = materializeAssets(env);

    expect(fs.existsSync(versionSentinel)).toBe(false);
    expect(fs.existsSync(path.join(repaired.currentDir, "wrong-runtime"))).toBe(false);
    expect(sha256(path.join(repaired.runtimeDir, "agent", "Dockerfile")))
      .toBe(sha256(path.join(installed.versionDir, "runtime", "agent", "Dockerfile")));
  });

  test("exposes the current runtime by copying when symlinks are unavailable", () => {
    const env = { XDG_DATA_HOME: path.join(tmp, "xdg-data") };
    vi.spyOn(fs, "symlinkSync").mockImplementationOnce(() => {
      throw new Error("symlinks disabled");
    });

    const installed = materializeAssets(env);

    expect(fs.lstatSync(installed.currentDir).isSymbolicLink()).toBe(false);
    expect(sha256(path.join(installed.runtimeDir, "agent", "Dockerfile")))
      .toBe(sha256(path.join(installed.versionDir, "runtime", "agent", "Dockerfile")));
  });

  test("cleans old asset versions without removing the installed current version", () => {
    const env = { XDG_DATA_HOME: path.join(tmp, "xdg-data") };
    const installed = materializeAssets(env);
    const oldVersionDir = path.join(installed.dataDir, "versions", "0.0.0-old");
    const strayFile = path.join(installed.dataDir, "versions", "README.txt");
    fs.mkdirSync(oldVersionDir, { recursive: true });
    fs.writeFileSync(path.join(oldVersionDir, "marker.txt"), "old");
    fs.writeFileSync(strayFile, "not a version directory");

    const removed = cleanOldAssetVersions(env);

    expect(removed).toEqual(["0.0.0-old"]);
    expect(fs.existsSync(oldVersionDir)).toBe(false);
    expect(fs.existsSync(installed.versionDir)).toBe(true);
    expect(fs.existsSync(strayFile)).toBe(true);
  });
});
