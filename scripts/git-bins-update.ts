#!/usr/bin/env node

// Keeps tests/git-matrix/git-bins.lock.json current. See CONTRIBUTING.md
// "Pinned Git".
//
//   tsx scripts/git-bins-update.ts add <version> [--replace <old-version>]
//   tsx scripts/git-bins-update.ts pin
//   tsx scripts/git-bins-update.ts latest
//
// add     downloads the kernel.org tarball, checks Junio Hamano's signature on
//         it against tests/git-matrix/git-signing-key.asc, and locks its
//         SHA-256. If the lock's release is already published, it moves to the
//         next git-test-bin-<n> tag and clears every asset digest, because the
//         new release rebuilds every version. `default` becomes the newest
//         locked version. Needs curl, gpg, gpgv and xz.
// pin     reads the published release's SHA256SUMS and records every asset
//         digest. Refuses unless every locked version has all four platforms.
// latest  prints `newest=<v>` (the newest stable Git on kernel.org),
//         `current=<v>` (the lock's default), and `newer=yes|no`. The
//         listing is only a hint for a to-do issue; nothing from it is
//         trusted or locked.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  assetName,
  compareGitVersions,
  GIT_BINS_LOCK_PATH,
  GIT_PLATFORMS,
  type GitBinsLock,
  parseGitBinsLock,
  readGitBinsLock,
  sha256File,
  sourceUrl,
  verifySourceSignature,
} from "./git-bins.ts";

const KERNEL_ORG_SUMS_URL = "https://mirrors.edge.kernel.org/pub/software/scm/git/sha256sums.asc";
const STABLE_TARBALL = /^git-(\d+\.\d+\.\d+)\.tar\.xz$/u;

/** `<sha256>  <file>` lines, as written by sha256sum. Other lines are ignored. */
export function parseSha256Sums(text: string): Map<string, string> {
  const sums = new Map<string, string>();
  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64}) [ *]?(\S+)$/u.exec(line.trim());
    if (match) sums.set(match[2], match[1]);
  }
  return sums;
}

/** The newest x.y.z tarball in a kernel.org listing; release candidates are skipped. */
export function newestStableGit(listing: string): string {
  let newest: string | undefined;
  for (const file of parseSha256Sums(listing).keys()) {
    const version = STABLE_TARBALL.exec(file)?.[1];
    if (version && (newest === undefined || compareGitVersions(version, newest) > 0)) newest = version;
  }
  if (newest === undefined) throw new Error("no git-<x.y.z>.tar.xz in the kernel.org listing");
  return newest;
}

function nextTag(tag: string): string {
  const number = Number(/^git-test-bin-(\d+)$/u.exec(tag)?.[1]);
  return `git-test-bin-${number + 1}`;
}

function newestLocked(versions: GitBinsLock["versions"]): string {
  return Object.keys(versions).sort(compareGitVersions).at(-1) as string;
}

export type AddOptions = {
  version: string;
  sourceSha256: string;
  replace?: string;
  /** The lock's current release tag is already published. */
  releasePublished: boolean;
};

/** The lock after adding one version. Pure; the caller verifies the digest. */
export function addVersion(lock: GitBinsLock, options: AddOptions): GitBinsLock {
  const { version, replace } = options;
  if (version in lock.versions) throw new Error(`Git ${version} is already locked`);
  if (replace !== undefined && !(replace in lock.versions)) {
    throw new Error(`--replace ${replace}: not locked; locked: ${Object.keys(lock.versions).join(", ")}`);
  }
  const published = options.releasePublished || Object.values(lock.versions).some((entry) => Object.keys(entry.assets).length > 0);
  const versions: GitBinsLock["versions"] = {};
  for (const [locked, entry] of Object.entries(lock.versions)) {
    if (locked !== replace) versions[locked] = { sourceSha256: entry.sourceSha256, assets: published ? {} : { ...entry.assets } };
  }
  versions[version] = { sourceSha256: options.sourceSha256, assets: {} };
  const sorted = Object.fromEntries(Object.keys(versions).sort(compareGitVersions).map((key) => [key, versions[key]]));
  return parseGitBinsLock(
    JSON.stringify({
      release: { ...lock.release, tag: published ? nextTag(lock.release.tag) : lock.release.tag },
      default: newestLocked(sorted),
      versions: sorted,
    }),
  );
}

/** The lock with every asset digest taken from the release's SHA256SUMS. */
export function pinAssets(lock: GitBinsLock, sha256sums: string): GitBinsLock {
  const sums = parseSha256Sums(sha256sums);
  const missing: string[] = [];
  const versions: GitBinsLock["versions"] = {};
  for (const [version, entry] of Object.entries(lock.versions)) {
    const assets: GitBinsLock["versions"][string]["assets"] = {};
    for (const platform of GIT_PLATFORMS) {
      const digest = sums.get(assetName(version, platform));
      if (digest === undefined) missing.push(assetName(version, platform));
      else assets[platform] = digest;
    }
    versions[version] = { sourceSha256: entry.sourceSha256, assets };
  }
  if (missing.length > 0) {
    throw new Error(`${lock.release.tag} SHA256SUMS lacks ${missing.join(", ")}; is the release built from this lock file?`);
  }
  return parseGitBinsLock(JSON.stringify({ ...lock, versions }));
}

function curl(args: readonly string[]): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("curl", ["--silent", "--show-error", "--location", "--retry", "3", ...args], {
    encoding: "utf8",
    maxBuffer: 64 << 20,
  });
}

function fetchText(url: string): string {
  const result = curl(["--fail", url]);
  if (result.error || result.status !== 0) {
    throw new Error(`could not download ${url}: ${result.error?.message ?? result.stderr.trim()}`);
  }
  return result.stdout;
}

/** Whether the release exists. Anything but a clean 200 or 404 is an error, never a guess. */
function releasePublished(lock: GitBinsLock): boolean {
  const url = `https://api.github.com/repos/${lock.release.repository}/releases/tags/${lock.release.tag}`;
  const result = curl(["--output", "/dev/null", "--write-out", "%{http_code}", url]);
  const status = result.stdout.trim();
  if (status === "200") return true;
  if (status === "404") return false;
  throw new Error(`could not tell whether ${lock.release.tag} is published (${url}: HTTP ${status || result.stderr.trim()})`);
}

function writeLock(lock: GitBinsLock): void {
  fs.writeFileSync(GIT_BINS_LOCK_PATH, `${JSON.stringify(lock, null, 2)}\n`);
}

function verifiedSourceSha256(version: string): string {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-git-add-"));
  try {
    const tarball = path.join(work, `git-${version}.tar.xz`);
    const result = curl(["--fail", "--output", tarball, sourceUrl(version)]);
    if (result.error || result.status !== 0) {
      throw new Error(`could not download ${sourceUrl(version)}: ${result.error?.message ?? result.stderr.trim()}`);
    }
    verifySourceSignature(work, version, tarball);
    return sha256File(tarball);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

function usage(): never {
  console.error(
    "usage: tsx scripts/git-bins-update.ts add <version> [--replace <old-version>] | pin | latest",
  );
  process.exit(2);
}

function main(argv: string[]): void {
  const [command, ...rest] = argv;
  const lock = readGitBinsLock();
  if (command === "add") {
    const version = rest[0];
    const replaceIndex = rest.indexOf("--replace");
    const replace = replaceIndex >= 0 ? rest[replaceIndex + 1] : undefined;
    const expected = replaceIndex >= 0 ? 3 : 1;
    if (!version || !/^\d+\.\d+\.\d+$/u.test(version) || rest.length !== expected || (replaceIndex >= 0 && !replace)) usage();
    // Check what the lock allows before the download.
    const published = releasePublished(lock);
    addVersion(lock, { version, sourceSha256: "0".repeat(64), replace, releasePublished: published });
    const sourceSha256 = verifiedSourceSha256(version);
    const updated = addVersion(lock, { version, sourceSha256, replace, releasePublished: published });
    writeLock(updated);
    console.log(`locked Git ${version} (source ${sourceSha256}, signature checked)`);
    if (replace) console.log(`removed Git ${replace}`);
    console.log(`release tag: ${updated.release.tag}; default: ${updated.default}`);
    console.log(`next: make test-git-build GIT=${version} && make test-git GIT=${version}, then open the pull request`);
  } else if (command === "pin") {
    if (rest.length !== 0) usage();
    const url = `https://github.com/${lock.release.repository}/releases/download/${lock.release.tag}/SHA256SUMS`;
    writeLock(pinAssets(lock, fetchText(url)));
    console.log(`pinned every asset digest from ${url}`);
  } else if (command === "latest") {
    if (rest.length !== 0) usage();
    const newest = newestStableGit(fetchText(KERNEL_ORG_SUMS_URL));
    console.log(`newest=${newest}`);
    console.log(`current=${lock.default}`);
    console.log(`newer=${compareGitVersions(newest, lock.default) > 0 ? "yes" : "no"}`);
  } else {
    usage();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`git-bins-update: ${(error as Error).message}`);
    process.exit(1);
  }
}
