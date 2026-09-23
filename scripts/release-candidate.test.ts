// Candidate acceptance runs against the archive that will ship, so these tests
// build real tarballs with real checksums and then damage them one property at a
// time. A source build that passes proves the tree is good; it says nothing
// about whether the bytes in the release archive are the bytes that were built.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const VERSION = "0.5.0";
const TARGET = "darwin-arm64";
const ARCHIVE = `runfree-${VERSION}-${TARGET}.tar.gz`;

let tmp: string;
let artifactDir: string;
let buildDir: string;

function sh(command: string, args: string[], cwd: string): void {
  const result = childProcess.spawnSync(command, args, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr}`);
  }
}

function sha256(filePath: string): string {
  const tool = fs.existsSync("/usr/bin/shasum") ? ["shasum", "-a", "256"] : ["sha256sum"];
  const result = childProcess.spawnSync(tool[0], [...tool.slice(1), path.basename(filePath)], {
    cwd: path.dirname(filePath),
    encoding: "utf8",
  });
  if (result.status !== 0) throw new Error(`checksum failed: ${result.stderr}`);
  return result.stdout.trim().split(/\s+/)[0];
}

function buildArchive(options: { version?: string; members?: string[] } = {}): void {
  const reported = options.version ?? VERSION;
  const members = options.members ?? ["runfree", "LICENSE", "NOTICE"];
  fs.rmSync(buildDir, { recursive: true, force: true });
  fs.mkdirSync(buildDir, { recursive: true });

  fs.writeFileSync(
    path.join(buildDir, "runfree"),
    `#!/usr/bin/env bash\nif [ "\${1:-}" = "version" ]; then printf '%s\\n' "${reported}"; exit 0; fi\nexit 0\n`,
  );
  fs.chmodSync(path.join(buildDir, "runfree"), 0o755);
  fs.writeFileSync(path.join(buildDir, "LICENSE"), "MIT License\n");
  fs.writeFileSync(path.join(buildDir, "NOTICE"), "Third-party notices\n");

  sh("tar", ["-C", buildDir, "-czf", path.join(artifactDir, ARCHIVE), ...members], repoRoot);
}

function recordChecksum(): void {
  const archive = path.join(artifactDir, ARCHIVE);
  fs.writeFileSync(`${archive}.sha256`, `${sha256(archive)}  ${ARCHIVE}\n`);
}

function runVerify(args: string[] = [VERSION, TARGET]): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("bash", [path.join(repoRoot, "scripts", "verify-release-candidate.sh"), ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      RUNFREE_ARTIFACT_DIR: artifactDir,
      RUNFREE_CANDIDATE_DIR: path.join(tmp, "candidate"),
    },
  });
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-release-candidate-")));
  artifactDir = path.join(tmp, "artifacts");
  buildDir = path.join(tmp, "build");
  fs.mkdirSync(artifactDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("scripts/verify-release-candidate.sh", () => {
  test("accepts an intact candidate and reports the extracted executable", () => {
    buildArchive();
    recordChecksum();

    const result = runVerify();

    expect(result.status, result.stderr).toBe(0);
    const binary = result.stdout.trim().split("\n").at(-1) ?? "";
    expect(binary).toBe(path.join(tmp, "candidate", "runfree"));
    expect(fs.existsSync(binary)).toBe(true);
    expect(result.stderr).toContain("candidate reports version 0.5.0");
  });

  test("refuses a candidate whose bytes changed after the signing job hashed it", () => {
    buildArchive();
    recordChecksum();
    fs.appendFileSync(path.join(artifactDir, ARCHIVE), "tampered");

    const result = runVerify();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("checksum mismatch");
    expect(fs.existsSync(path.join(tmp, "candidate", "runfree"))).toBe(false);
  });

  test("refuses a candidate with no recorded checksum from the signing job", () => {
    buildArchive();

    const result = runVerify();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing candidate checksum");
  });

  test("refuses an archive that omits a required redistribution file", () => {
    buildArchive({ members: ["runfree", "LICENSE"] });
    recordChecksum();

    const result = runVerify();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("is missing NOTICE");
  });

  test("refuses a candidate binary built from a different version of the tree", () => {
    buildArchive({ version: "0.4.0" });
    recordChecksum();

    const result = runVerify();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("candidate reports version 0.4.0, release is 0.5.0");
  });

  test("refuses a target the release does not build", () => {
    buildArchive();
    recordChecksum();

    const result = runVerify([VERSION, "darwin-x64"]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("unknown release target: darwin-x64");
  });
});
