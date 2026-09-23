import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const runtimeRoot = path.join(repoRoot, "dist", "runtime");
const lockPath = path.join(repoRoot, "packages", "agent-runtime", "runtime-inputs.lock.json");
const embeddedAssetsPath = path.join(repoRoot, "packages", "cli", "src", "embedded-assets.generated.ts");

let tmp: string;
let originalLock: string;
let originalEmbeddedAssets: string;

function runUpdateRuntimeInputs(mockFetchPath: string): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync(process.execPath, [
    "--import",
    mockFetchPath,
    "--import",
    "tsx",
    path.join(repoRoot, "scripts", "update-runtime-input-lock.ts"),
  ], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      CI: "1",
    },
  });
}

function writeMockFetch(): string {
  const lock = JSON.parse(originalLock) as {
    images: Record<string, { ref: string }>;
    releaseArtifacts: {
      githubCli: {
        version: string;
        linuxAmd64Deb: { sha256: string };
        linuxArm64Deb: { sha256: string };
      };
    };
  };
  const manifestDigests = new Map<string, string>();
  for (const image of Object.values(lock.images)) {
    const [nameAndTag, digest] = image.ref.split("@");
    const tagIndex = nameAndTag.lastIndexOf(":");
    const tag = nameAndTag.slice(tagIndex + 1);
    const imageName = nameAndTag.slice(0, tagIndex);
    let repository = imageName;
    let registry = "registry-1.docker.io";
    if (imageName.includes("/")) {
      const [first, ...rest] = imageName.split("/");
      if (first.includes(".") || first.includes(":") || first === "localhost") {
        registry = first;
        repository = rest.join("/");
      } else {
        repository = imageName;
      }
    } else {
      repository = `library/${imageName}`;
    }
    manifestDigests.set(`https://${registry}/v2/${repository}/manifests/${tag}`, digest);
  }

  const checksums = [
    `${lock.releaseArtifacts.githubCli.linuxAmd64Deb.sha256}  gh_${lock.releaseArtifacts.githubCli.version}_linux_amd64.deb`,
    `${lock.releaseArtifacts.githubCli.linuxArm64Deb.sha256}  gh_${lock.releaseArtifacts.githubCli.version}_linux_arm64.deb`,
  ].join("\n");
  const mockPath = path.join(tmp, "mock-fetch.mjs");
  fs.writeFileSync(mockPath, `
const manifestDigests = new Map(${JSON.stringify([...manifestDigests])});
const checksums = ${JSON.stringify(checksums)};

globalThis.fetch = async (input, init = {}) => {
  const url = String(input);
  if (init.method === "HEAD" && manifestDigests.has(url)) {
    return new Response("", {
      status: 200,
      headers: { "docker-content-digest": manifestDigests.get(url) },
    });
  }
  if (url.endsWith("_checksums.txt")) {
    return new Response(checksums, { status: 200 });
  }
  throw new Error("unexpected fetch " + url);
};
`);
  return mockPath;
}

function cleanRuntimeRootForTest(dir: string): void {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name === "node_modules") continue;
    if (entry.isDirectory()) {
      cleanRuntimeRootForTest(entryPath);
      continue;
    }
    fs.rmSync(entryPath, { force: true });
  }
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-update-runtime-inputs-")));
  originalLock = fs.readFileSync(lockPath, "utf8");
  originalEmbeddedAssets = fs.readFileSync(embeddedAssetsPath, "utf8");
});

afterEach(() => {
  fs.writeFileSync(lockPath, originalLock);
  fs.writeFileSync(embeddedAssetsPath, originalEmbeddedAssets);
  cleanRuntimeRootForTest(runtimeRoot);
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("runtime input lock updater", () => {
  test("rebuilds runtime bundle before regenerating embedded assets", () => {
    cleanRuntimeRootForTest(runtimeRoot);
    const mockFetchPath = writeMockFetch();

    const result = runUpdateRuntimeInputs(mockFetchPath);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(fs.existsSync(path.join(runtimeRoot, "runtime-inputs.lock.json"))).toBe(true);
    expect(fs.readFileSync(path.join(runtimeRoot, "runtime-inputs.lock.json"), "utf8")).toBe(fs.readFileSync(lockPath, "utf8"));
    expect(fs.readFileSync(embeddedAssetsPath, "utf8")).toContain(
      `"content": ${JSON.stringify(fs.readFileSync(lockPath, "utf8"))}`,
    );
  });
});
