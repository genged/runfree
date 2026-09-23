import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

// Read from the helper rather than restated here: a test that repeated the
// literal would keep passing after the helper's value drifted.
const expectedIdentifier = childProcess
  .execFileSync(path.join(repoRoot, "scripts", "macos-code-signing.sh"), ["identifier"], { encoding: "utf8" })
  .trim();

let tmp: string;
let fakeBin: string;
let artifactDir: string;
let fakeLog: string;

function writeExecutable(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content);
  fs.chmodSync(filePath, 0o755);
}

function installFakeBuildTools(): void {
  writeExecutable(path.join(fakeBin, "node"), `#!/usr/bin/env bash
printf '0.1.0'
`);

  writeExecutable(path.join(fakeBin, "bun"), `#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "--version" ]; then
  printf '%s\\n' "\${RUNFREE_FAKE_BUN_VERSION:-\${RUNFREE_BUN_VERSION:-1.3.14}}"
  exit 0
fi
printf '%s\\n' "$*" >> "$RUNFREE_FAKE_LOG"
if [ "\${1:-}" = "build" ]; then
  outfile=""
  while [ "$#" -gt 0 ]; do
    if [ "\${1:-}" = "--outfile" ]; then
      outfile="\${2:-}"
      break
    fi
    shift
  done
  if [ -z "$outfile" ]; then
    printf 'missing fake outfile\\n' >&2
    exit 1
  fi
  mkdir -p "$(dirname "$outfile")"
  printf '#!/usr/bin/env bash\\ncase "\${1:-}" in help) exit 0 ;; *) exit 0 ;; esac\\n' > "$outfile"
  chmod +x "$outfile"
fi
`);

  writeExecutable(path.join(fakeBin, "tar"), `#!/usr/bin/env bash
set -euo pipefail
printf 'tar %s\\n' "$*" >> "$RUNFREE_FAKE_LOG"
archive=""
extract_dir=""
mode="create"
while [ "$#" -gt 0 ]; do
  if [ "\${1:-}" = "-czf" ]; then
    archive="\${2:-}"
    mode="create"
    break
  fi
  if [ "\${1:-}" = "-xzf" ]; then
    archive="\${2:-}"
    mode="extract"
    shift 2
    continue
  fi
  if [ "\${1:-}" = "-C" ]; then
    extract_dir="\${2:-}"
    shift 2
    continue
  fi
  shift
done
if [ -z "$archive" ]; then
  printf 'missing fake archive path\\n' >&2
  exit 1
fi
if [ "$mode" = "extract" ]; then
  mkdir -p "$extract_dir"
  printf '#!/usr/bin/env bash\\ncase "\${1:-}" in help) exit 0 ;; *) exit 0 ;; esac\\n' > "$extract_dir/runfree"
  chmod +x "$extract_dir/runfree"
  exit 0
fi
mkdir -p "$(dirname "$archive")"
printf 'fake archive\\n' > "$archive"
`);

  writeExecutable(path.join(fakeBin, "shasum"), `#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "-a" ]; then
  shift 2
fi
for file in "$@"; do
  printf 'fakehash  %s\\n' "$file"
done
`);
}

function installFakeMacSigningTools(): void {
  writeExecutable(path.join(fakeBin, "codesign"), `#!/usr/bin/env bash
printf 'codesign %s\\n' "$*" >> "$RUNFREE_FAKE_LOG"
if [ "\${1:-}" = "--display" ]; then
  # Real codesign writes its display output to stderr, and the identifier it
  # reports is what the packaging assertion reads.
  printf 'Identifier=%s\\n' "\${RUNFREE_FAKE_CODESIGN_IDENTIFIER:-dev.runfree.cli}" >&2
fi
`);

  // Both exist on any macOS host, so a test that only checked "the script did
  // not call spctl" would prove nothing about what the script is capable of
  // reaching. These log every invocation, which makes their absence from the
  // log evidence rather than an assumption.
  writeExecutable(path.join(fakeBin, "spctl"), `#!/usr/bin/env bash
printf 'spctl %s\\n' "$*" >> "$RUNFREE_FAKE_LOG"
`);

  writeExecutable(path.join(fakeBin, "xcrun"), `#!/usr/bin/env bash
printf 'xcrun %s\\n' "$*" >> "$RUNFREE_FAKE_LOG"
`);
}

function runScript(scriptPath: string, args: string[] = [], env: NodeJS.ProcessEnv = {}): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("bash", [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_ARTIFACT_DIR: artifactDir,
      RUNFREE_FAKE_LOG: fakeLog,
      ...env,
    },
  });
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-release-scripts-")));
  fakeBin = path.join(tmp, "bin");
  artifactDir = path.join(tmp, "artifacts");
  fakeLog = path.join(tmp, "fake-tools.log");
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.mkdirSync(artifactDir, { recursive: true });
  installFakeBuildTools();
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("release packaging scripts", () => {
  test("install:bin refreshes workspace dependencies before building", () => {
    const packageJson = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    const installBin = packageJson.scripts?.["install:bin"] ?? "";

    expect(installBin).toContain("pnpm install --frozen-lockfile");
    expect(installBin.indexOf("pnpm install --frozen-lockfile")).toBeLessThan(installBin.indexOf("pnpm run build:bin"));
  });

  test("package script accepts explicit target arguments and skips checksums for CI fan-out", () => {
    const result = runScript("scripts/package-homebrew-artifacts.sh", ["darwin-arm64"], {
      RUNFREE_SKIP_CHECKSUM: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz"))).toBe(true);
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0.sha256"))).toBe(false);

    const log = fs.readFileSync(fakeLog, "utf8");
    expect(log).toContain("--target bun-darwin-arm64");
  });

  test("package script accepts RUNFREE_ARTIFACT_TARGETS", () => {
    const result = runScript("scripts/package-homebrew-artifacts.sh", [], {
      RUNFREE_ARTIFACT_TARGETS: "darwin-arm64",
      RUNFREE_SKIP_CHECKSUM: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz"))).toBe(true);
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0-linux-x64.tar.gz"))).toBe(false);
  });

  test.each(["linux-x64", "darwin-x64"])(
    "package script rejects %s, which this release does not build, before building anything",
    (unknownTarget) => {
      const result = runScript("scripts/package-homebrew-artifacts.sh", ["darwin-arm64", unknownTarget], {
        RUNFREE_SKIP_CHECKSUM: "1",
      });

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(`unknown release target: ${unknownTarget}`);
      expect(fs.existsSync(fakeLog)).toBe(false);
    },
  );

  test("package script puts the license and third-party notices in the archive", () => {
    const result = runScript("scripts/package-homebrew-artifacts.sh", ["darwin-arm64"], {
      RUNFREE_SKIP_CHECKSUM: "1",
    });

    expect(result.status, result.stderr).toBe(0);
    const buildDir = path.join(artifactDir, "build/darwin-arm64");
    expect(fs.existsSync(path.join(buildDir, "LICENSE"))).toBe(true);
    expect(fs.existsSync(path.join(buildDir, "NOTICE"))).toBe(true);
    const log = fs.readFileSync(fakeLog, "utf8");
    expect(log).toMatch(/-czf .*runfree-0\.1\.0-darwin-arm64\.tar\.gz runfree LICENSE NOTICE/);
  });

  test("package script verifies pinned Bun version when release CI sets one", () => {
    const result = runScript("scripts/package-homebrew-artifacts.sh", ["darwin-arm64"], {
      RUNFREE_FAKE_BUN_VERSION: "1.3.14",
      RUNFREE_BUN_VERSION: "1.3.15",
      RUNFREE_SKIP_CHECKSUM: "1",
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("bun version mismatch: expected 1.3.15, got 1.3.14");
  });

  test("checksum script hashes only the advertised release tarballs", () => {
    fs.writeFileSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz"), "darwin-arm64");
    fs.writeFileSync(path.join(artifactDir, "runfree-0.1.0-darwin-x64.tar.gz"), "stale-intel");
    fs.writeFileSync(path.join(artifactDir, "runfree-0.1.0-linux-x64.tar.gz"), "stale-linux");
    fs.mkdirSync(path.join(artifactDir, "notary"), { recursive: true });
    fs.writeFileSync(path.join(artifactDir, "notary/runfree-0.1.0-darwin-arm64.zip"), "notary");

    const result = runScript("scripts/checksum-release-artifacts.sh", ["0.1.0"]);

    expect(result.status, result.stderr).toBe(0);
    const checksum = fs.readFileSync(path.join(artifactDir, "runfree-0.1.0.sha256"), "utf8");
    expect(checksum).toContain("runfree-0.1.0-darwin-arm64.tar.gz");
    expect(checksum).not.toContain("darwin-x64");
    expect(checksum).not.toContain("linux");
    expect(checksum).not.toContain(".zip");
  });

  test("checksum script refuses a manifest when an advertised target is missing", () => {
    const result = runScript("scripts/checksum-release-artifacts.sh", ["0.1.0"]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing release tarball");
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0.sha256"))).toBe(false);
  });

  test("checksum script records a per-target hash for one signed candidate", () => {
    fs.writeFileSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz"), "darwin-arm64");

    const result = runScript("scripts/checksum-release-artifacts.sh", ["0.1.0", "darwin-arm64"]);

    expect(result.status, result.stderr).toBe(0);
    const recorded = fs.readFileSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz.sha256"), "utf8");
    expect(recorded).toContain("runfree-0.1.0-darwin-arm64.tar.gz");
    // Per-target mode writes only the candidate record, never the manifest the
    // installer verifies against.
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0.sha256"))).toBe(false);
  });

  test("checksum script stops publication when an archive no longer matches its build-job hash", () => {
    fs.writeFileSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz"), "darwin-arm64");
    fs.writeFileSync(
      path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz.sha256"),
      "adifferenthash  runfree-0.1.0-darwin-arm64.tar.gz\n",
    );

    const result = runScript("scripts/checksum-release-artifacts.sh", ["0.1.0"]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("candidate checksum mismatch");
    expect(result.stderr).toContain("Nothing was published");
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0.sha256"))).toBe(false);
  });

  test("ad-hoc signing script signs, repacks, and checks the bytes that ship, without claiming an assessment", () => {
    installFakeMacSigningTools();
    const buildDir = path.join(artifactDir, "build/darwin-arm64");
    fs.mkdirSync(buildDir, { recursive: true });
    const binary = path.join(buildDir, "runfree");
    fs.writeFileSync(binary, "#!/usr/bin/env bash\ncase \"${1:-}\" in help) exit 0 ;; *) exit 0 ;; esac\n");
    fs.chmodSync(binary, 0o755);

    const result = runScript("scripts/sign-adhoc-macos-target.sh", ["darwin-arm64"], {
      RUNFREE_RELEASE_VERSION: "0.1.0",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz"))).toBe(true);
    const log = fs.readFileSync(fakeLog, "utf8");
    expect(log).toContain(`--identifier ${expectedIdentifier}`);
    expect(log).toContain("--sign -");
    // An ad-hoc binary cannot pass Gatekeeper assessment and carries no ticket.
    // Running either tool here would fail every release, or worse, appear to
    // prove something it does not.
    expect(log).not.toContain("spctl");
    expect(log).not.toContain("xcrun");
    // The repacked archive has to match the shape the unsigned packaging path
    // produced, and the identifier is checked again on what comes back out.
    expect(log).toMatch(/tar -C .*build\/darwin-arm64 -czf .*runfree-0\.1\.0-darwin-arm64\.tar\.gz runfree LICENSE NOTICE/);
    const displays = log.split("\n").filter((line) => line.startsWith("codesign --display"));
    expect(displays).toHaveLength(2);
    expect(displays[1]).toContain("final-artifact/runfree");
    // With no notarization ticket, the checksum is the release's only
    // integrity evidence, so it has to exist.
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz.sha256"))).toBe(true);
  });

  test("ad-hoc signing script stops a candidate whose shipped bytes lost the identifier", () => {
    installFakeMacSigningTools();
    const buildDir = path.join(artifactDir, "build/darwin-arm64");
    fs.mkdirSync(buildDir, { recursive: true });
    const binary = path.join(buildDir, "runfree");
    fs.writeFileSync(binary, "#!/usr/bin/env bash\nexit 0\n");
    fs.chmodSync(binary, 0o755);

    const result = runScript("scripts/sign-adhoc-macos-target.sh", ["darwin-arm64"], {
      RUNFREE_RELEASE_VERSION: "0.1.0",
      RUNFREE_FAKE_CODESIGN_IDENTIFIER: "a.out",
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("generic linker identifier a.out");
    expect(fs.existsSync(path.join(artifactDir, "runfree-0.1.0-darwin-arm64.tar.gz.sha256"))).toBe(false);
  });

  test("ad-hoc signing script refuses a target this release does not build", () => {
    installFakeMacSigningTools();

    const result = runScript("scripts/sign-adhoc-macos-target.sh", ["darwin-x64"]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("usage:");
    expect(result.stderr).toContain("darwin-arm64");
  });

  test("ad-hoc signing script refuses to sign a candidate that was never built", () => {
    installFakeMacSigningTools();

    const result = runScript("scripts/sign-adhoc-macos-target.sh", ["darwin-arm64"], {
      RUNFREE_RELEASE_VERSION: "0.1.0",
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing release binary");
    expect(fs.existsSync(fakeLog)).toBe(false);
  });

});

describe("macOS code-signing identifier", () => {
  function runIdentityScript(args: string[], env: NodeJS.ProcessEnv = {}): childProcess.SpawnSyncReturns<string> {
    return runScript("scripts/macos-code-signing.sh", args, env);
  }

  test("names one Runfree-specific identifier instead of the linker default", () => {
    const result = runIdentityScript(["identifier"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(expectedIdentifier);
    expect(expectedIdentifier).not.toBe("a.out");
    // Reverse-DNS, tool-scoped, and without a version: the identifier names
    // the program across every release, because macOS keys the user's
    // protected-folder and Gatekeeper decisions off it.
    expect(expectedIdentifier).toMatch(/^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/);
    expect(expectedIdentifier).not.toMatch(/\d+\.\d+\.\d+/);
  });

  test("the identifier lives in one place, so local and release binaries cannot drift apart", () => {
    const tracked = childProcess
      .execFileSync("git", ["ls-files", "scripts", ".github", "docs"], { cwd: repoRoot, encoding: "utf8" })
      .split("\n")
      .filter((file) => file.length > 0 && !file.endsWith(".test.ts"));

    const hardcoded = tracked.filter((file) => {
      if (file === "scripts/macos-code-signing.sh") return false;
      const contents = fs.readFileSync(path.join(repoRoot, file), "utf8");
      // Documentation may name the identifier; source that signs or checks it
      // may not.
      return contents.includes(expectedIdentifier) && !file.startsWith("docs/");
    });

    expect(hardcoded).toEqual([]);
  });

  test("accepts a binary that reports the expected identifier", () => {
    installFakeMacSigningTools();
    const binary = path.join(tmp, "runfree");
    fs.writeFileSync(binary, "binary");

    const result = runIdentityScript(["assert", binary]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`code-signing identifier verified for ${binary}: ${expectedIdentifier}`);
  });

  test("refuses a binary signed under someone else's identifier", () => {
    installFakeMacSigningTools();
    const binary = path.join(tmp, "runfree");
    fs.writeFileSync(binary, "binary");

    const result = runIdentityScript(["assert", binary], { RUNFREE_FAKE_CODESIGN_IDENTIFIER: "com.example.other" });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`reports code-signing identifier com.example.other, expected ${expectedIdentifier}`);
  });

  test("local signing applies the identifier and the entitlements the release path uses", () => {
    installFakeMacSigningTools();
    const binary = path.join(tmp, "runfree");
    fs.writeFileSync(binary, "binary");

    const result = runIdentityScript(["sign-local", binary]);

    expect(result.status, result.stderr).toBe(0);
    const log = fs.readFileSync(fakeLog, "utf8");
    expect(log).toContain(`--identifier ${expectedIdentifier}`);
    expect(log).toContain("scripts/macos-entitlements.plist");
    // Ad-hoc: a local build is not notarized, and pretending otherwise would
    // produce a signature that fails assessment rather than a usable binary.
    expect(log).toContain("--sign -");
  });

  test("refuses a binary path that does not exist rather than reporting success", () => {
    installFakeMacSigningTools();

    const result = runIdentityScript(["assert", path.join(tmp, "absent")]);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("missing binary");
  });
});
