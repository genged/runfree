// git-bins.ts — pinned Git binaries for the test suite.
//
// Tests that spawn the real `git` would otherwise depend on whatever Git the
// host ships. The suite instead runs on an exact Git version: a prebuilt,
// minimal Git published as an asset on this repo's `git-test-bin-<n>` GitHub
// release, or built locally from the same pinned kernel.org tarball.
//
// tests/git-matrix/git-bins.lock.json pins two digests per version: the
// kernel.org source tarball, and each prebuilt asset per platform. A download
// is checked against its digest before it is unpacked.
//
// Binaries live outside the repo, in ~/.cache/runfree-dev/git/<version>/:
// Runfree never runs executables from inside a project checkout
// (packages/cli/src/host-path.ts), and tests run product code against this
// checkout. They are for tests only and are never shipped to users.

import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const GIT_BINS_LOCK_PATH = path.join(repoRoot, "tests", "git-matrix", "git-bins.lock.json");
export const GIT_SIGNING_KEY_PATH = path.join(repoRoot, "tests", "git-matrix", "git-signing-key.asc");
export const GIT_MATRIX_FILES_PATH = path.join(repoRoot, "tests", "git-matrix", "files.txt");

/** Selects one locked version for a test run instead of the lock file's default. */
export const GIT_VERSION_ENV = "RUNFREE_TEST_GIT_VERSION";

/**
 * Title suffix of a test that declared a minimum Git (`needsGit` in
 * tests/support/git-version.ts); `make test-git` accepts only these skips.
 */
export const NEEDS_GIT_TITLE = /\[needs Git (\d+\.\d+(?:\.\d+)?)\]$/u;

export function compareGitVersions(left: string, right: string): number {
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

export const GIT_PLATFORMS = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"] as const;
export type GitPlatform = (typeof GIT_PLATFORMS)[number];

const SHA256 = /^[0-9a-f]{64}$/u;
const VERSION = /^\d+\.\d+\.\d+$/u;
const MARKER = ".runfree-git.json";

export type GitBinsLock = {
  release: { repository: string; tag: string };
  default: string;
  versions: Record<string, { sourceSha256: string; assets: Partial<Record<GitPlatform, string>> }>;
};

type Marker = {
  version: string;
  platform: GitPlatform;
  origin: "release" | "source";
  sha256: string;
};

/**
 * The make flags for every pinned build, release and local alike. Perl and
 * Python commands, translations and the GUI are left out; RUNTIME_PREFIX makes
 * the unpacked tree work from any directory. libcurl stays in: the submodule
 * test in state.test.ts needs `git-remote-https`, which links the host's
 * libcurl (stock on macOS and Ubuntu; building needs its dev files).
 */
export const GIT_MAKE_FLAGS = [
  "prefix=/",
  "RUNTIME_PREFIX=YesPlease",
  "NO_OPENSSL=YesPlease",
  "NO_PERL=YesPlease",
  "NO_PYTHON=YesPlease",
  "NO_TCLTK=YesPlease",
  "NO_GETTEXT=YesPlease",
  "NO_EXPAT=YesPlease",
  // Rust is optional until Git 3.0 and would need cargo on every builder;
  // older versions ignore the flag.
  "NO_RUST=YesPlease",
  "NO_INSTALL_HARDLINKS=YesPlease",
  "INSTALL_SYMLINKS=YesPlease",
  "SKIP_DASHED_BUILT_INS=YesPlease",
  "CFLAGS=-O2",
] as const;

export function gitPlatform(platform: NodeJS.Platform = process.platform, arch: string = process.arch): GitPlatform {
  const key = `${platform}-${arch}`;
  if ((GIT_PLATFORMS as readonly string[]).includes(key)) return key as GitPlatform;
  throw new Error(`pinned Git: no binaries for ${key}; supported: ${GIT_PLATFORMS.join(", ")}`);
}

export function parseGitBinsLock(text: string): GitBinsLock {
  const raw = JSON.parse(text) as GitBinsLock;
  const fail = (why: string): never => {
    throw new Error(`git-bins.lock.json: ${why}`);
  };
  if (typeof raw?.release?.repository !== "string" || !/^[\w.-]+\/[\w.-]+$/u.test(raw.release.repository)) {
    fail("release.repository must be owner/name");
  }
  if (typeof raw.release.tag !== "string" || !/^git-test-bin-\d+$/u.test(raw.release.tag)) {
    fail("release.tag must look like git-test-bin-<n>");
  }
  if (typeof raw.versions !== "object" || raw.versions === null) fail("versions must be an object");
  for (const [version, entry] of Object.entries(raw.versions)) {
    if (!VERSION.test(version)) fail(`version ${JSON.stringify(version)} must be x.y.z`);
    if (!SHA256.test(entry?.sourceSha256 ?? "")) fail(`${version}: sourceSha256 must be a SHA-256 hex digest`);
    if (typeof entry.assets !== "object" || entry.assets === null) fail(`${version}: assets must be an object`);
    for (const [platform, digest] of Object.entries(entry.assets)) {
      if (!(GIT_PLATFORMS as readonly string[]).includes(platform)) fail(`${version}: unknown platform ${platform}`);
      if (!SHA256.test(digest ?? "")) fail(`${version}/${platform}: asset digest must be a SHA-256 hex digest`);
    }
  }
  if (!(raw.default in raw.versions)) fail(`default ${JSON.stringify(raw.default)} is not a locked version`);
  return raw;
}

export function readGitBinsLock(lockPath = GIT_BINS_LOCK_PATH): GitBinsLock {
  return parseGitBinsLock(fs.readFileSync(lockPath, "utf8"));
}

/** The version a run uses: RUNFREE_TEST_GIT_VERSION when set, else the lock's default. */
export function selectedGitVersion(lock: GitBinsLock, env: NodeJS.ProcessEnv = process.env): string {
  const requested = env[GIT_VERSION_ENV];
  if (requested === undefined || requested === "") return lock.default;
  if (!(requested in lock.versions)) {
    throw new Error(`${GIT_VERSION_ENV}=${requested} is not in git-bins.lock.json; locked: ${Object.keys(lock.versions).join(", ")}`);
  }
  return requested;
}

export function gitCacheRoot(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.XDG_CACHE_HOME && path.isAbsolute(env.XDG_CACHE_HOME)
    ? env.XDG_CACHE_HOME
    : path.join(os.homedir(), ".cache");
  return path.join(base, "runfree-dev", "git");
}

export function assetName(version: string, platform: GitPlatform): string {
  return `git-${version}-${platform}.tar.gz`;
}

export function assetUrl(lock: GitBinsLock, version: string, platform: GitPlatform): string {
  return `https://github.com/${lock.release.repository}/releases/download/${lock.release.tag}/${assetName(version, platform)}`;
}

export function sourceUrl(version: string): string {
  return `https://mirrors.edge.kernel.org/pub/software/scm/git/git-${version}.tar.xz`;
}

export function sha256File(filePath: string): string {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(1 << 20);
    for (;;) {
      const read = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      hash.update(buffer.subarray(0, read));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

/** Refuses a file whose digest differs from the pinned one. Call before unpacking. */
export function assertSha256(filePath: string, expected: string, label: string): void {
  const actual = sha256File(filePath);
  if (actual !== expected) {
    throw new Error(`${label}: SHA-256 mismatch (expected ${expected}, got ${actual}); refusing to unpack`);
  }
}

function run(command: string, args: readonly string[], options: childProcess.SpawnSyncOptions = {}): void {
  const result = childProcess.spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error) throw new Error(`${command} ${args.join(" ")}: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} exited with ${result.status ?? result.signal}`);
}

/**
 * Downloads with the system curl, which honours HTTPS_PROXY (Node's fetch does
 * not on Node 22), so it also works inside a Runfree sandbox.
 */
export function download(url: string, destination: string): void {
  run("curl", ["--fail", "--silent", "--show-error", "--location", "--retry", "3", "--output", destination, url], {
    stdio: ["ignore", "inherit", "inherit"],
  });
}

/** Exactly `git version <version>`, run with a clean exec path. */
export function gitBinaryVersion(binDir: string): string {
  const env = { ...process.env };
  delete env.GIT_EXEC_PATH;
  const result = childProcess.spawnSync(path.join(binDir, "git"), ["--version"], { encoding: "utf8", env });
  if (result.error || result.status !== 0) {
    throw new Error(`${binDir}/git --version failed: ${result.error?.message ?? result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

function readMarker(dir: string): Marker | undefined {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, MARKER), "utf8")) as Marker;
  } catch {
    return undefined;
  }
}

function markerMatches(marker: Marker | undefined, lock: GitBinsLock, version: string, platform: GitPlatform): boolean {
  if (marker?.version !== version || marker.platform !== platform) return false;
  const entry = lock.versions[version];
  if (marker.origin === "release") return marker.sha256 === entry.assets[platform];
  if (marker.origin === "source") return marker.sha256 === entry.sourceSha256;
  return false;
}

/**
 * Moves a fully prepared tree into place. A concurrent run may have won the
 * race; its tree is as good as ours.
 */
function installTree(staged: string, target: string, marker: Marker): void {
  fs.writeFileSync(path.join(staged, MARKER), `${JSON.stringify(marker, null, 2)}\n`);
  fs.rmSync(target, { recursive: true, force: true });
  try {
    fs.renameSync(staged, target);
  } catch (error) {
    if (!fs.existsSync(path.join(target, MARKER))) throw error;
    fs.rmSync(staged, { recursive: true, force: true });
  }
}

export type EnsureOptions = {
  lock?: GitBinsLock;
  version?: string;
  platform?: GitPlatform;
  cacheRoot?: string;
  /** Fetches an asset; tests replace it. */
  fetchAsset?: (url: string, destination: string) => void;
};

/**
 * Returns the `bin` directory of the pinned Git, downloading and verifying it
 * once. Never falls back to the host Git: a run that cannot get the pinned
 * version fails with the command that fixes it.
 */
export function ensurePinnedGit(options: EnsureOptions = {}): { version: string; binDir: string } {
  const lock = options.lock ?? readGitBinsLock();
  const version = options.version ?? selectedGitVersion(lock);
  const platform = options.platform ?? gitPlatform();
  const cacheRoot = options.cacheRoot ?? gitCacheRoot();
  const target = path.join(cacheRoot, version);
  const binDir = path.join(target, "bin");
  const fix = `build it locally with: make test-git-build GIT=${version}`;

  if (!markerMatches(readMarker(target), lock, version, platform)) {
    const digest = lock.versions[version]?.assets[platform];
    if (!digest) {
      throw new Error(`pinned Git ${version}: git-bins.lock.json has no ${platform} binary; ${fix}`);
    }
    fs.mkdirSync(cacheRoot, { recursive: true });
    const work = fs.mkdtempSync(path.join(cacheRoot, `.tmp-${version}-`));
    try {
      const archive = path.join(work, assetName(version, platform));
      const url = assetUrl(lock, version, platform);
      try {
        (options.fetchAsset ?? download)(url, archive);
      } catch (error) {
        throw new Error(`pinned Git ${version}: could not download ${url} (${(error as Error).message}); check the network, or ${fix}`);
      }
      assertSha256(archive, digest, assetName(version, platform));
      const staged = path.join(work, "tree");
      fs.mkdirSync(staged);
      run("tar", ["-xzf", archive, "-C", staged]);
      installTree(staged, target, { version, platform, origin: "release", sha256: digest });
    } finally {
      fs.rmSync(work, { recursive: true, force: true });
    }
  }

  const reported = gitBinaryVersion(binDir);
  if (reported !== `git version ${version}`) {
    throw new Error(`pinned Git ${version}: ${binDir}/git reports "${reported}"; delete ${target} and rerun`);
  }
  return { version, binDir };
}

/** Puts the pinned Git first on PATH. Idempotent. */
export function prependPath(binDir: string, currentPath: string | undefined): string {
  const rest = (currentPath ?? "").split(path.delimiter).filter((entry) => entry !== "" && entry !== binDir);
  return [binDir, ...rest].join(path.delimiter);
}

function staticZlibDir(work: string): string | undefined {
  if (process.platform !== "linux") return undefined;
  const result = childProcess.spawnSync("cc", ["-print-file-name=libz.a"], { encoding: "utf8" });
  const libz = result.stdout?.trim();
  if (!libz || !path.isAbsolute(libz) || !fs.existsSync(libz)) {
    throw new Error("static zlib (libz.a) not found; install zlib development files (Debian/Ubuntu: zlib1g-dev)");
  }
  // A directory holding only libz.a: the linker searches it first and finds no
  // libz.so there, so the build links zlib statically.
  const dir = path.join(work, "zlib");
  fs.mkdirSync(path.join(dir, "lib"), { recursive: true });
  fs.symlinkSync(libz, path.join(dir, "lib", "libz.a"));
  return dir;
}

export type BuildOptions = {
  lock?: GitBinsLock;
  version: string;
  /** Write a release asset here. */
  outputArchive?: string;
  /** Install the build into the cache for this machine's test runs. */
  installToCache?: boolean;
  cacheRoot?: string;
  /** Also check kernel.org's signature (needs gpg and xz). */
  verifySignature?: boolean;
  jobs?: number;
};

/** Builds one pinned version from its verified kernel.org tarball. */
export function buildPinnedGit(options: BuildOptions): void {
  const lock = options.lock ?? readGitBinsLock();
  const { version } = options;
  const entry = lock.versions[version];
  if (!entry) throw new Error(`Git ${version} is not in git-bins.lock.json; locked: ${Object.keys(lock.versions).join(", ")}`);
  const platform = gitPlatform();
  const cacheRoot = options.cacheRoot ?? gitCacheRoot();
  fs.mkdirSync(cacheRoot, { recursive: true });
  const work = fs.mkdtempSync(path.join(cacheRoot, `.build-${version}-`));
  try {
    const tarball = path.join(work, `git-${version}.tar.xz`);
    console.log(`downloading ${sourceUrl(version)}`);
    download(sourceUrl(version), tarball);
    assertSha256(tarball, entry.sourceSha256, `git-${version}.tar.xz`);
    if (options.verifySignature) verifySourceSignature(work, version, tarball);

    run("tar", ["-xJf", tarball, "-C", work]);
    const source = path.join(work, `git-${version}`);
    const zlib = staticZlibDir(work);
    const flags = [...GIT_MAKE_FLAGS, ...(zlib ? [`ZLIB_PATH=${zlib}`] : [])];
    const jobs = String(options.jobs ?? os.availableParallelism());
    const stage = path.join(work, "stage");
    console.log(`building Git ${version} for ${platform}`);
    run("make", ["-C", source, `-j${jobs}`, ...flags, "all", "strip"], { stdio: ["ignore", "ignore", "inherit"] });
    run("make", ["-C", source, ...flags, `DESTDIR=${stage}`, "install"], { stdio: ["ignore", "ignore", "inherit"] });
    // Not used by the tests, and gitweb is a Perl CGI the build cannot run.
    fs.rmSync(path.join(stage, "share", "gitweb"), { recursive: true, force: true });

    const reported = gitBinaryVersion(path.join(stage, "bin"));
    if (reported !== `git version ${version}`) throw new Error(`built Git reports "${reported}", expected ${version}`);

    if (options.outputArchive) {
      fs.mkdirSync(path.dirname(path.resolve(options.outputArchive)), { recursive: true });
      run("tar", ["-czf", path.resolve(options.outputArchive), "-C", stage, "."]);
      console.log(`${options.outputArchive}  sha256 ${sha256File(options.outputArchive)}`);
    }
    if (options.installToCache) {
      installTree(stage, path.join(cacheRoot, version), { version, platform, origin: "source", sha256: entry.sourceSha256 });
      console.log(`installed Git ${version} to ${path.join(cacheRoot, version)}`);
    }
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

/** kernel.org signs the uncompressed tar with Junio Hamano's release key, pinned in the repo. */
function verifySourceSignature(work: string, version: string, tarball: string): void {
  const signature = path.join(work, `git-${version}.tar.sign`);
  download(sourceUrl(version).replace(/\.tar\.xz$/u, ".tar.sign"), signature);
  const keyring = path.join(work, "git-signing-key.gpg");
  run("gpg", ["--batch", "--yes", "--dearmor", "--output", keyring, GIT_SIGNING_KEY_PATH]);
  const tar = path.join(work, `git-${version}.tar`);
  fs.writeFileSync(tar, childProcess.execFileSync("xz", ["-dc", tarball], { maxBuffer: 1 << 30 }));
  run("gpgv", ["--keyring", keyring, signature, tar]);
  fs.rmSync(tar);
}
