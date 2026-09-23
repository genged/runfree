// Publication is the one step in the release that cannot be undone, so its
// refusals are tested as behavior: the script runs against a fake `gh` and real
// artifact files, and the assertions are about which gh commands it did and did
// not reach.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const VERSION = "0.5.0";
const TAG = "v0.5.0";
const SHA = "c".repeat(40);

let tmp: string;
let fakeBin: string;
let artifactDir: string;
let notesDir: string;
let notesFile: string;
let ghLog: string;
let releaseJson: string;
let existingManifest: string;

function writeExecutable(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content);
  fs.chmodSync(filePath, 0o755);
}

function installFakeGh(): void {
  writeExecutable(
    path.join(fakeBin, "gh"),
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$RUNFREE_FAKE_GH_LOG"
if [ "\${1:-}" = "release" ] && [ "\${2:-}" = "view" ]; then
  if [ -f "$RUNFREE_FAKE_RELEASE_JSON" ]; then
    cat "$RUNFREE_FAKE_RELEASE_JSON"
    exit 0
  fi
  printf 'release not found\\n' >&2
  exit 1
fi
if [ "\${1:-}" = "release" ] && [ "\${2:-}" = "download" ]; then
  if [ ! -f "\${RUNFREE_FAKE_EXISTING_MANIFEST:-}" ]; then
    printf 'no assets\\n' >&2
    exit 1
  fi
  dir=""
  pattern=""
  while [ "$#" -gt 0 ]; do
    case "\${1:-}" in
      --dir) dir="\${2:-}"; shift 2 ;;
      --pattern) pattern="\${2:-}"; shift 2 ;;
      *) shift ;;
    esac
  done
  mkdir -p "$dir"
  cp "$RUNFREE_FAKE_EXISTING_MANIFEST" "$dir/$pattern"
  exit 0
fi
exit 0
`,
  );
}

function writeCandidate(target: string, contents = "signed archive bytes"): void {
  fs.writeFileSync(path.join(artifactDir, `runfree-${VERSION}-${target}.tar.gz`), contents);
}

function writeManifest(filePath: string, hash = "0123456789abcdef"): void {
  fs.writeFileSync(filePath, `${hash}  runfree-${VERSION}-darwin-arm64.tar.gz\n`);
}

function runPublish(env: NodeJS.ProcessEnv = {}): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("bash", [path.join(repoRoot, "scripts", "publish-release-assets.sh")], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      TAG,
      VERSION,
      SHA,
      RUNFREE_ARTIFACT_DIR: artifactDir,
      RUNFREE_RELEASE_NOTES_FILE: notesFile,
      RUNFREE_FAKE_GH_LOG: ghLog,
      RUNFREE_FAKE_RELEASE_JSON: releaseJson,
      ...env,
    },
  });
}

function ghCommands(): string {
  return fs.existsSync(ghLog) ? fs.readFileSync(ghLog, "utf8") : "";
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-release-publish-")));
  fakeBin = path.join(tmp, "bin");
  artifactDir = path.join(tmp, "artifacts");
  notesDir = path.join(tmp, "notes");
  notesFile = path.join(notesDir, `${VERSION}.md`);
  ghLog = path.join(tmp, "gh.log");
  releaseJson = path.join(tmp, "release.json");
  existingManifest = path.join(tmp, "existing.sha256");
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.mkdirSync(artifactDir, { recursive: true });
  fs.mkdirSync(notesDir, { recursive: true });
  installFakeGh();

  fs.writeFileSync(notesFile, "# Runfree 0.5.0\n\nFirst public beta.\n");
  writeCandidate("darwin-arm64");
  writeManifest(path.join(artifactDir, `runfree-${VERSION}.sha256`));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("scripts/publish-release-assets.sh", () => {
  test("creates the release from the exact archives and the written release body", () => {
    const result = runPublish();

    expect(result.status, result.stderr).toBe(0);
    const log = ghCommands();
    expect(log).toContain("release create v0.5.0");
    expect(log).toContain(`runfree-${VERSION}-darwin-arm64.tar.gz`);
    expect(log).toContain(`runfree-${VERSION}.sha256`);
    expect(log).toContain("--verify-tag");
    expect(log).toContain(`--target ${SHA}`);
    expect(log).toContain(`--notes-file ${notesFile}`);
    expect(log).not.toContain("--generate-notes");
  });

  test("refuses to publish without a written release body", () => {
    fs.rmSync(notesFile);

    const result = runPublish();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing release notes");
    expect(ghCommands()).toBe("");
  });

  test("refuses to publish a partial set when an advertised target is missing", () => {
    fs.rmSync(path.join(artifactDir, `runfree-${VERSION}-darwin-arm64.tar.gz`));

    const result = runPublish();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing release archive for advertised target darwin-arm64");
    expect(ghCommands()).toBe("");
  });

  test("refuses to publish without the checksum manifest the installer verifies against", () => {
    fs.rmSync(path.join(artifactDir, `runfree-${VERSION}.sha256`));

    const result = runPublish();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing checksum manifest");
    expect(ghCommands()).toBe("");
  });

  test("never replaces the assets of an already published release, even with replace_assets", () => {
    fs.writeFileSync(releaseJson, JSON.stringify({ isDraft: false, targetCommitish: SHA }));

    const result = runPublish({ REPLACE_ASSETS: "true" });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("already published");
    expect(result.stderr).toContain("new patch tag");
    expect(ghCommands()).not.toContain("release upload");
    expect(ghCommands()).not.toContain("release create");
  });

  test("leaves an existing draft alone unless recovery was explicitly requested", () => {
    fs.writeFileSync(releaseJson, JSON.stringify({ isDraft: true, targetCommitish: SHA }));

    const result = runPublish();

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("draft release already exists");
    expect(ghCommands()).not.toContain("release upload");
  });

  test("finishes a draft left by an interrupted run for the same commit and candidate", () => {
    fs.writeFileSync(releaseJson, JSON.stringify({ isDraft: true, targetCommitish: SHA }));
    writeManifest(existingManifest);

    const result = runPublish({
      REPLACE_ASSETS: "true",
      RUNFREE_FAKE_EXISTING_MANIFEST: existingManifest,
    });

    expect(result.status, result.stderr).toBe(0);
    const log = ghCommands();
    expect(log).toContain("release upload v0.5.0");
    expect(log).toContain("--clobber");
    expect(log).toContain("release edit v0.5.0 --draft=false");
  });

  test("stops draft recovery when the draft belongs to a different source commit", () => {
    fs.writeFileSync(releaseJson, JSON.stringify({ isDraft: true, targetCommitish: "d".repeat(40) }));

    const result = runPublish({ REPLACE_ASSETS: "true" });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("was created for");
    expect(result.stderr).toContain("Recovery does not move a draft to different source");
    expect(ghCommands()).not.toContain("release upload");
  });

  test("stops draft recovery when the rebuilt candidate hashes differ from the draft's", () => {
    fs.writeFileSync(releaseJson, JSON.stringify({ isDraft: true, targetCommitish: SHA }));
    writeManifest(existingManifest, "ffffffffffffffff");

    const result = runPublish({
      REPLACE_ASSETS: "true",
      RUNFREE_FAKE_EXISTING_MANIFEST: existingManifest,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("not the same candidate bytes");
    expect(ghCommands()).not.toContain("release upload");
  });

  test("rejects a malformed source SHA before reaching GitHub", () => {
    const result = runPublish({ SHA: "HEAD" });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("SHA must be a full commit SHA");
    expect(ghCommands()).toBe("");
  });
});
