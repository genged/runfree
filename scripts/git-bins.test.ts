import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  assetUrl,
  compareGitVersions,
  ensurePinnedGit,
  type GitBinsLock,
  gitCacheRoot,
  gitPlatform,
  parseGitBinsLock,
  prependPath,
  readGitBinsLock,
  selectedGitVersion,
} from "./git-bins.ts";

const DIGEST = "a".repeat(64);

function lock(assets: GitBinsLock["versions"][string]["assets"] = {}): GitBinsLock {
  return {
    release: { repository: "genged/runfree", tag: "git-test-bin-1" },
    default: "2.48.0",
    versions: { "2.48.0": { sourceSha256: DIGEST, assets } },
  };
}

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-git-bins-"));
});

afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

/** A tarball whose bin/git prints `git version <reported>`, and its digest. */
function fakeAsset(reported: string): { archive: string; digest: string } {
  const tree = path.join(tmp, `tree-${reported}`);
  fs.mkdirSync(path.join(tree, "bin"), { recursive: true });
  fs.writeFileSync(path.join(tree, "bin", "git"), `#!/bin/sh\necho "git version ${reported}"\n`, { mode: 0o755 });
  const archive = path.join(tmp, `asset-${reported}.tar.gz`);
  expect(childProcess.spawnSync("tar", ["-czf", archive, "-C", tree, "."]).status).toBe(0);
  return { archive, digest: crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex") };
}

describe("lock file", () => {
  test("the checked-in lock parses and its default is a locked version", () => {
    const checkedIn = readGitBinsLock();
    expect(Object.keys(checkedIn.versions)).toContain(checkedIn.default);
  });

  test("rejects a malformed digest, platform, tag or default", () => {
    const valid = lock();
    const parse = (value: unknown) => () => parseGitBinsLock(JSON.stringify(value));
    expect(parse(valid)).not.toThrow();
    expect(parse({ ...valid, versions: { "2.48.0": { sourceSha256: "abc", assets: {} } } })).toThrow(/sourceSha256/);
    expect(parse({ ...valid, versions: { "2.48.0": { sourceSha256: DIGEST, assets: { "windows-x64": DIGEST } } } })).toThrow(/unknown platform/);
    expect(parse({ ...valid, release: { ...valid.release, tag: "v1.0.0" } })).toThrow(/git-test-bin/);
    expect(parse({ ...valid, default: "2.99.0" })).toThrow(/default/);
  });

  test("refuses a release from any repository but genged/runfree, before anything is downloaded", () => {
    const valid = lock();
    for (const repository of ["genged-agent/runfree", "attacker/runfree", "genged/runfree-fork", "genged/runfree/../x"]) {
      const lockPath = path.join(tmp, "git-bins.lock.json");
      fs.writeFileSync(lockPath, JSON.stringify({ ...valid, release: { ...valid.release, repository } }));
      expect(() => readGitBinsLock(lockPath)).toThrow(/release\.repository must be genged\/runfree/);
    }
  });

  test("a run selects the lock default, or a locked version by name, and refuses others", () => {
    expect(selectedGitVersion(lock(), {})).toBe("2.48.0");
    expect(selectedGitVersion(lock(), { RUNFREE_TEST_GIT_VERSION: "2.48.0" })).toBe("2.48.0");
    expect(() => selectedGitVersion(lock(), { RUNFREE_TEST_GIT_VERSION: "2.43.0" })).toThrow(/not in git-bins.lock.json/);
  });
});

test("platform keys cover the four supported targets and refuse others", () => {
  expect(gitPlatform("linux", "x64")).toBe("linux-x64");
  expect(gitPlatform("darwin", "arm64")).toBe("darwin-arm64");
  expect(() => gitPlatform("win32", "x64")).toThrow(/no binaries for win32-x64/);
});

test("compares versions numerically, not as strings", () => {
  expect(compareGitVersions("2.9.0", "2.48")).toBe(-1);
  expect(compareGitVersions("2.48.0", "2.48")).toBe(0);
  expect(compareGitVersions("2.56.0", "2.48")).toBe(1);
});

test("the cache lives outside the repo, under XDG_CACHE_HOME when it is absolute", () => {
  expect(gitCacheRoot({ XDG_CACHE_HOME: "/x/cache" })).toBe("/x/cache/runfree-dev/git");
  expect(gitCacheRoot({ XDG_CACHE_HOME: "relative" })).toBe(path.join(os.homedir(), ".cache", "runfree-dev", "git"));
});

test("prepending the pinned bin directory is idempotent", () => {
  const once = prependPath("/pinned/bin", ["/usr/bin", "/pinned/bin", "/bin"].join(path.delimiter));
  expect(once).toBe(["/pinned/bin", "/usr/bin", "/bin"].join(path.delimiter));
  expect(prependPath("/pinned/bin", once)).toBe(once);
});

describe("ensurePinnedGit", () => {
  test("downloads the release asset once, verifies it, and reuses the cache", () => {
    const { archive, digest } = fakeAsset("2.48.0");
    const pinned = lock({ "linux-x64": digest });
    const cacheRoot = path.join(tmp, "cache");
    const urls: string[] = [];
    const fetchAsset = (url: string, destination: string) => {
      urls.push(url);
      fs.copyFileSync(archive, destination);
    };

    const first = ensurePinnedGit({ lock: pinned, version: "2.48.0", platform: "linux-x64", cacheRoot, fetchAsset });
    const second = ensurePinnedGit({ lock: pinned, version: "2.48.0", platform: "linux-x64", cacheRoot, fetchAsset });

    expect(first).toEqual({ version: "2.48.0", binDir: path.join(cacheRoot, "2.48.0", "bin") });
    expect(second).toEqual(first);
    expect(urls).toEqual([assetUrl(pinned, "2.48.0", "linux-x64")]);
    expect(urls[0]).toBe("https://github.com/genged/runfree/releases/download/git-test-bin-1/git-2.48.0-linux-x64.tar.gz");
  });

  test("refuses an asset whose digest differs before unpacking it", () => {
    const { archive } = fakeAsset("2.48.0");
    const cacheRoot = path.join(tmp, "cache");
    const run = () => ensurePinnedGit({
      lock: lock({ "linux-x64": DIGEST }),
      version: "2.48.0",
      platform: "linux-x64",
      cacheRoot,
      fetchAsset: (_url, destination) => fs.copyFileSync(archive, destination),
    });

    expect(run).toThrow(/SHA-256 mismatch .*refusing to unpack/);
    // Nothing was unpacked: no version directory and no leftover work tree.
    expect(fs.readdirSync(cacheRoot)).toEqual([]);
  });

  test("refuses a binary that reports another version", () => {
    const { archive, digest } = fakeAsset("2.47.3");
    const run = () => ensurePinnedGit({
      lock: lock({ "linux-x64": digest }),
      version: "2.48.0",
      platform: "linux-x64",
      cacheRoot: path.join(tmp, "cache"),
      fetchAsset: (_url, destination) => fs.copyFileSync(archive, destination),
    });

    expect(run).toThrow(/reports "git version 2.47.3"/);
  });

  test("a platform with no locked asset fails with the local build command, without downloading", () => {
    let fetched = false;
    const run = () => ensurePinnedGit({
      lock: lock(),
      version: "2.48.0",
      platform: "linux-x64",
      cacheRoot: path.join(tmp, "cache"),
      fetchAsset: () => {
        fetched = true;
      },
    });

    expect(run).toThrow(/no linux-x64 binary; build it locally with: make test-git-build GIT=2.48.0/);
    expect(fetched).toBe(false);
  });

  test("a failed download names the local build command", () => {
    const run = () => ensurePinnedGit({
      lock: lock({ "linux-x64": DIGEST }),
      version: "2.48.0",
      platform: "linux-x64",
      cacheRoot: path.join(tmp, "cache"),
      fetchAsset: () => {
        throw new Error("offline");
      },
    });

    expect(run).toThrow(/could not download .*offline.*make test-git-build GIT=2.48.0/);
  });
});
