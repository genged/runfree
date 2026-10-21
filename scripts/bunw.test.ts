// `./bunw`: every Bun call in this repo runs the version in `.bun-version`.
//
// Each case runs the real launcher from a temporary repo root (so it reads a
// test `.bun-version`), with its cache in a temporary directory and its
// registry pointed at a local server that serves a version document and a
// tarball holding a fake `bun`.

import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const DECLARED = "7.7.7";
const BUNW_SOURCE = fs.readFileSync(path.join(repoRoot, "bunw"), "utf8");
// The line a mutant replaces to prove the integrity case catches a broken
// comparison.
const HASH_COMPARISON = 'if [ "${actual}" != "${integrity}" ]; then';

let tmp: string;
let repo: string;
let cache: string;
let registry: Registry;

type Registry = {
  url: string;
  requests: string[];
  tarball: Buffer;
  integrity: string;
  documentStatus: number;
  close(): Promise<void>;
};

type Run = { status: number | null; stdout: string; stderr: string };

function fakeBunScript(version: string): string {
  return `#!/bin/sh
case "\${1:-}" in
  --version) echo ${version} ;;
  --revision) echo ${version}+fake ;;
  *) printf 'fake-bun args=%s\\n' "$*"; printf 'PATH=%s\\n' "$PATH" ;;
esac
`;
}

function makeTarball(version: string): Buffer {
  const staging = fs.mkdtempSync(path.join(tmp, "tarball-"));
  const bin = path.join(staging, "package", "bin");
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, "bun"), fakeBunScript(version), { mode: 0o644 });
  fs.writeFileSync(path.join(staging, "package", "package.json"), "{}\n");
  const out = path.join(staging, "bun.tgz");
  childProcess.execFileSync("tar", ["-czf", out, "-C", staging, "package"]);
  return fs.readFileSync(out);
}

function sha512(bytes: Buffer): string {
  return `sha512-${crypto.createHash("sha512").update(bytes).digest("base64")}`;
}

async function startRegistry(tarball: Buffer): Promise<Registry> {
  const requests: string[] = [];
  const state = { tarball, integrity: sha512(tarball), documentStatus: 200 };
  const server = http.createServer((req, res) => {
    const url = req.url ?? "";
    requests.push(url);
    if (url === "/bun.tgz") {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(registry.tarball);
      return;
    }
    if (/^\/@oven\/bun-[a-z0-9-]+\/[^/]+$/.test(url) && registry.documentStatus === 200) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          name: url.split("/")[2],
          version: DECLARED,
          dist: { integrity: registry.integrity, tarball: `${registry.url}/bun.tgz` },
        }),
      );
      return;
    }
    res.writeHead(registry.documentStatus === 200 ? 404 : registry.documentStatus);
    res.end("not found");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    ...state,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function writeRepo(bunwSource: string = BUNW_SOURCE, version: string | null = `${DECLARED}\n`): void {
  fs.writeFileSync(path.join(repo, "bunw"), bunwSource, { mode: 0o755 });
  if (version === null) fs.rmSync(path.join(repo, ".bun-version"), { force: true });
  else fs.writeFileSync(path.join(repo, ".bun-version"), version);
}

/** PATH without proxies; the registry server is local and plain HTTP. */
function baseEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!/_proxy$/i.test(key)) env[key] = value;
  }
  return { ...env, RUNFREE_BUN_CACHE: cache, RUNFREE_BUN_REGISTRY: registry.url, ...extra };
}

function runBunw(args: string[], env: NodeJS.ProcessEnv = baseEnv()): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(path.join(repo, "bunw"), args, { cwd: tmp, env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function installedFiles(): string[] {
  const found: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else found.push(path.relative(cache, full));
    }
  };
  if (fs.existsSync(cache)) walk(cache);
  return found;
}

beforeEach(async () => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-bunw-")));
  repo = path.join(tmp, "repo");
  cache = path.join(tmp, "cache");
  fs.mkdirSync(repo);
  writeRepo();
  registry = await startRegistry(makeTarball(DECLARED));
});

afterEach(async () => {
  await registry.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("bunw", () => {
  test("installs the declared Bun on a cache miss and runs it first on PATH", async () => {
    const result = await runBunw(["build", "x.ts"]);

    expect(result.status, result.stderr).toBe(0);
    const files = installedFiles();
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(new RegExp(`^${DECLARED.replaceAll(".", "\\.")}/[a-z0-9-]+/bin/bun$`));
    const binDir = path.dirname(path.join(cache, files[0] ?? ""));
    expect(result.stdout).toContain("fake-bun args=build x.ts");
    expect(result.stdout).toContain(`PATH=${binDir}:`);
    expect(result.stderr).toContain("bunw: sha512 matches the registry integrity value");
    expect(result.stderr).toContain(`bunw: installed Bun ${DECLARED} (revision ${DECLARED}+fake)`);
  });

  test("a second run uses the cache, sends no request, and prints nothing", async () => {
    expect((await runBunw(["--version"])).status).toBe(0);
    const before = registry.requests.length;

    const second = await runBunw(["--version"]);

    expect(second.status, second.stderr).toBe(0);
    expect(second.stdout.trim()).toBe(DECLARED);
    expect(second.stderr).toBe("");
    expect(registry.requests.length).toBe(before);
  });

  test("refuses a tarball whose sha512 differs from the registry value", async () => {
    registry.integrity = sha512(Buffer.from("something else"));

    const result = await runBunw(["--version"]);

    expect(result.status).toBe(1);
    expect(installedFiles()).toEqual([]);
    expect(result.stderr).toContain(`registry: ${registry.integrity}`);
    expect(result.stderr).toContain(`download: ${sha512(registry.tarball)}`);
    expect(result.stdout).toBe("");
  });

  test("fault injection: a launcher with a broken hash comparison passes the bad tarball", async () => {
    // Proves the integrity case above detects a broken comparison: the same
    // input gets through once the comparison is gone.
    expect(BUNW_SOURCE).toContain(HASH_COMPARISON);
    writeRepo(BUNW_SOURCE.replace(HASH_COMPARISON, "if false; then"));
    registry.integrity = sha512(Buffer.from("something else"));

    const result = await runBunw(["--version"]);

    expect(result.status).toBe(0);
    expect(installedFiles()).toHaveLength(1);
  });

  test("refuses a downloaded binary that reports another version", async () => {
    registry.tarball = makeTarball("7.7.8");
    registry.integrity = sha512(registry.tarball);

    const result = await runBunw(["--version"]);

    expect(result.status).toBe(1);
    expect(installedFiles()).toEqual([]);
    expect(result.stderr).toContain("reports version '7.7.8'");
  });

  test("a registry 404 names the platform package and the version", async () => {
    registry.documentStatus = 404;

    const result = await runBunw(["--version"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(new RegExp(`cannot read .*/@oven/bun-[a-z0-9-]+/${DECLARED}: curl exit 22`));
    expect(result.stderr).toContain("bunw: no Bun was run.");
    expect(installedFiles()).toEqual([]);
  });

  test.each([
    ["missing", null],
    ["empty", ""],
    ["a range", "^7.7.7\n"],
    ["two components", "7.7\n"],
    ["four components", "7.7.7.7\n"],
    ["a v prefix", "v7.7.7\n"],
    ["two lines", "7.7.7\n7.7.8\n"],
  ])("refuses a .bun-version that is %s before any request", async (_name, content) => {
    writeRepo(BUNW_SOURCE, content);

    const result = await runBunw(["--version"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/^bunw: .*\.bun-version/);
    expect(registry.requests).toEqual([]);
  });

  test("uses a PATH Bun that already reports the declared version", async () => {
    const pathBin = path.join(tmp, "path-bin");
    fs.mkdirSync(pathBin);
    fs.writeFileSync(path.join(pathBin, "bun"), fakeBunScript(DECLARED), { mode: 0o755 });

    const result = await runBunw(["build"], baseEnv({ PATH: `${pathBin}:${process.env.PATH ?? ""}` }));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("fake-bun args=build");
    expect(registry.requests).toEqual([]);
    expect(installedFiles()).toEqual([]);
  });

  test("ignores a PATH Bun that reports another version", async () => {
    const pathBin = path.join(tmp, "path-bin");
    fs.mkdirSync(pathBin);
    fs.writeFileSync(path.join(pathBin, "bun"), fakeBunScript("7.7.8"), { mode: 0o755 });

    const result = await runBunw(["--version"], baseEnv({ PATH: `${pathBin}:${process.env.PATH ?? ""}` }));

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(DECLARED);
    expect(installedFiles()).toHaveLength(1);
  });

  test("--print-bin-dir prints one directory and runs nothing", async () => {
    const result = await runBunw(["--print-bin-dir"]);

    expect(result.status, result.stderr).toBe(0);
    const lines = result.stdout.split("\n").filter((line) => line !== "");
    expect(lines).toHaveLength(1);
    expect(fs.existsSync(path.join(lines[0] ?? "", "bun"))).toBe(true);
    expect(result.stdout).not.toContain("fake-bun");
  });

  test("two runs on a cache miss both succeed and leave one binary", async () => {
    const [first, second] = await Promise.all([runBunw(["--version"]), runBunw(["--version"])]);

    expect(first.status, first.stderr).toBe(0);
    expect(second.status, second.stderr).toBe(0);
    expect(installedFiles()).toHaveLength(1);
  });
});
