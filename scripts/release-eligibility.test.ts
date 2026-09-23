// The gates that decide which commit a release is allowed to build from.
//
// These run the scripts, against a real temporary Git repository, rather than asserting that release.yml contains certain strings. The
// assessment that produced this work found 24 release tests passing while the
// macOS jobs were missing their dependency setup entirely: shape assertions
// over YAML cannot fail for a gate that does not run.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

let tmp: string;
let originDir: string;
let workDir: string;
let outputFile: string;

function git(cwd: string, ...args: string[]): string {
  const result = childProcess.spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Release Test",
      GIT_AUTHOR_EMAIL: "release@example.invalid",
      GIT_COMMITTER_NAME: "Release Test",
      GIT_COMMITTER_EMAIL: "release@example.invalid",
    },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function runScript(
  script: string,
  options: { cwd?: string; env?: NodeJS.ProcessEnv; args?: string[] } = {},
): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("bash", [path.join(repoRoot, "scripts", script), ...(options.args ?? [])], {
    cwd: options.cwd ?? workDir,
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_OUTPUT: outputFile,
      ...options.env,
    },
  });
}

function stepOutputs(): Record<string, string> {
  if (!fs.existsSync(outputFile)) return {};
  const entries: Record<string, string> = {};
  for (const line of fs.readFileSync(outputFile, "utf8").split("\n")) {
    const index = line.indexOf("=");
    if (index > 0) entries[line.slice(0, index)] = line.slice(index + 1);
  }
  return entries;
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-release-eligibility-")));
  originDir = path.join(tmp, "origin.git");
  workDir = path.join(tmp, "work");
  outputFile = path.join(tmp, "github-output.txt");

  git(tmp, "init", "--bare", "--initial-branch=main", originDir);
  git(tmp, "clone", originDir, workDir);
  fs.writeFileSync(path.join(workDir, "README.md"), "release fixture\n");
  git(workDir, "add", "README.md");
  git(workDir, "commit", "-m", "initial");
  git(workDir, "push", "origin", "main");
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("scripts/resolve-release-tag.sh", () => {
  test("resolves a well-formed tag on the default branch to one SHA and the target matrix", () => {
    const sha = git(workDir, "rev-parse", "HEAD");
    git(workDir, "tag", "v0.5.0");

    const result = runScript("resolve-release-tag.sh", { env: { TAG: "v0.5.0", DEFAULT_BRANCH: "main" } });

    expect(result.status, result.stderr).toBe(0);
    const outputs = stepOutputs();
    expect(outputs.tag).toBe("v0.5.0");
    expect(outputs.version).toBe("0.5.0");
    expect(outputs.sha).toBe(sha);
    expect(outputs.replace_assets).toBe("false");
    expect(JSON.parse(outputs.targets)).toEqual([{ target: "darwin-arm64", runner: "macos-15" }]);
  });

  test.each([
    ["v1.2", "an incomplete version"],
    ["1.2.3", "a missing v prefix"],
    ["vX.Y.Z", "non-numeric components"],
    ["v0.5.0; touch /tmp/runfree-release-injection", "a shell metacharacter"],
    ["v0.5.0 --allow-anything", "an embedded flag"],
    ["v.0.5.0", "an empty component"],
  ])("refuses %s (%s) before touching git", (tag) => {
    const result = runScript("resolve-release-tag.sh", { env: { TAG: tag, DEFAULT_BRANCH: "main" } });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("tag must look like");
    expect(fs.existsSync("/tmp/runfree-release-injection")).toBe(false);
    expect(stepOutputs()).toEqual({});
  });

  test("refuses a tag that does not exist in the checkout", () => {
    const result = runScript("resolve-release-tag.sh", { env: { TAG: "v9.9.9", DEFAULT_BRANCH: "main" } });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("tag not found in this checkout: v9.9.9");
    expect(stepOutputs()).toEqual({});
  });

  test("refuses a tag moved between discovery and lane resolution", () => {
    git(workDir, "tag", "v0.5.0");
    const result = runScript("resolve-release-tag.sh", {
      env: { TAG: "v0.5.0", DEFAULT_BRANCH: "main", EXPECTED_SHA: "b".repeat(40) },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("moved since release discovery");
    expect(stepOutputs()).toEqual({});
  });

  test("refuses a tag whose commit is not reachable from the default branch", () => {
    git(workDir, "checkout", "-b", "side");
    fs.writeFileSync(path.join(workDir, "side.txt"), "not on main\n");
    git(workDir, "add", "side.txt");
    git(workDir, "commit", "-m", "side commit");
    git(workDir, "tag", "v0.5.0");

    const result = runScript("resolve-release-tag.sh", { env: { TAG: "v0.5.0", DEFAULT_BRANCH: "main" } });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("must point to a commit reachable from main");
    expect(stepOutputs()).toEqual({});
  });

  test("refuses a replace_assets value that is neither true nor false", () => {
    git(workDir, "tag", "v0.5.0");

    const result = runScript("resolve-release-tag.sh", {
      env: { TAG: "v0.5.0", DEFAULT_BRANCH: "main", REPLACE_ASSETS: "yes" },
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("REPLACE_ASSETS must be true or false");
  });
});

describe("scripts/require-unmoved-tag.sh", () => {
  test("passes while the remote tag still names the resolved commit", () => {
    const sha = git(workDir, "rev-parse", "HEAD");
    git(workDir, "tag", "v0.5.0");
    git(workDir, "push", "origin", "v0.5.0");

    const result = runScript("require-unmoved-tag.sh", { env: { TAG: "v0.5.0", EXPECTED_SHA: sha } });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`tag v0.5.0 still names ${sha}`);
  });

  test("stops publication when the tag moved to a different commit mid-release", () => {
    const originalSha = git(workDir, "rev-parse", "HEAD");
    git(workDir, "tag", "v0.5.0");
    git(workDir, "push", "origin", "v0.5.0");

    fs.writeFileSync(path.join(workDir, "README.md"), "moved after the release started\n");
    git(workDir, "add", "README.md");
    git(workDir, "commit", "-m", "second");
    git(workDir, "push", "origin", "main");
    git(workDir, "tag", "-f", "v0.5.0");
    git(workDir, "push", "--force", "origin", "v0.5.0");
    const movedSha = git(workDir, "rev-parse", "HEAD");

    const result = runScript("require-unmoved-tag.sh", { env: { TAG: "v0.5.0", EXPECTED_SHA: originalSha } });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("moved during this release");
    expect(result.stderr).toContain(movedSha);
    expect(result.stderr).toContain("Nothing was published");
  });

  test("follows an annotated tag to the commit it points at", () => {
    const sha = git(workDir, "rev-parse", "HEAD");
    git(workDir, "tag", "-a", "v0.5.0", "-m", "annotated release");
    git(workDir, "push", "origin", "v0.5.0");

    const result = runScript("require-unmoved-tag.sh", { env: { TAG: "v0.5.0", EXPECTED_SHA: sha } });

    expect(result.status, result.stderr).toBe(0);
  });

  test("refuses a tag that no longer exists on the remote", () => {
    const sha = git(workDir, "rev-parse", "HEAD");

    const result = runScript("require-unmoved-tag.sh", { env: { TAG: "v0.5.0", EXPECTED_SHA: sha } });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("no longer exists on origin");
  });
});
