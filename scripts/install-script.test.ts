import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

let tmp: string;
let fakeBin: string;
let fakeLog: string;
let fakeManifest: string;

function writeExecutable(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content);
  fs.chmodSync(filePath, 0o755);
}

function installFakeTools(): void {
  writeExecutable(path.join(fakeBin, "uname"), `#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  -s) printf '%s\n' "\${RUNFREE_FAKE_UNAME_S:-Darwin}" ;;
  -m) printf '%s\n' "\${RUNFREE_FAKE_UNAME_M:-arm64}" ;;
  *) exit 1 ;;
esac
`);

  writeExecutable(path.join(fakeBin, "curl"), `#!/usr/bin/env bash
set -euo pipefail
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "\${1:-}" in
    -o)
      out="\${2:-}"
      shift 2
      ;;
    -* )
      shift
      ;;
    *)
      url="\${1:-}"
      shift
      ;;
  esac
done
[ -n "$out" ] || { printf 'fake curl missing -o\n' >&2; exit 1; }
[ -n "$url" ] || { printf 'fake curl missing url\n' >&2; exit 1; }
printf '%s\n' "$url" >> "$RUNFREE_FAKE_LOG"
case "$url" in
  *api.github.com*)
    printf '{"tag_name":"v0.2.0"}\n' > "$out"
    ;;
  *.sha256)
    cp "$RUNFREE_FAKE_MANIFEST" "$out"
    ;;
  *.tar.gz)
    printf 'fake archive for %s\n' "$url" > "$out"
    ;;
  *)
    printf 'unexpected fake curl url: %s\n' "$url" >&2
    exit 1
    ;;
esac
`);

  writeExecutable(path.join(fakeBin, "tar"), `#!/usr/bin/env bash
set -euo pipefail
extract_dir=""
while [ "$#" -gt 0 ]; do
  if [ "\${1:-}" = "-C" ]; then
    extract_dir="\${2:-}"
    shift 2
    continue
  fi
  shift
done
[ -n "$extract_dir" ] || { printf 'fake tar missing -C\n' >&2; exit 1; }
mkdir -p "$extract_dir"
printf '#!/usr/bin/env bash\nprintf "runfree fake\\n"\n' > "$extract_dir/runfree"
chmod +x "$extract_dir/runfree"
`);

  const checksumTool = `#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "-a" ]; then
  shift 2
fi
for file in "$@"; do
  printf '%s  %s\n' "\${RUNFREE_FAKE_SHA:-fakehash}" "$file"
done
`;
  writeExecutable(path.join(fakeBin, "shasum"), checksumTool);
  writeExecutable(path.join(fakeBin, "sha256sum"), checksumTool);
}

function writeManifest(hash = "fakehash"): void {
  fs.writeFileSync(
    fakeManifest,
    [
      `${hash}  runfree-0.2.0-darwin-arm64.tar.gz`,
      `${hash}  runfree-0.2.0-darwin-x64.tar.gz`,
      "",
    ].join("\n"),
  );
}

function runInstall(env: NodeJS.ProcessEnv = {}): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync("bash", ["scripts/install.sh"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      RUNFREE_FAKE_LOG: fakeLog,
      RUNFREE_FAKE_MANIFEST: fakeManifest,
      RUNFREE_VERSION: "0.2.0",
      ...env,
    },
  });
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-install-test-")));
  fakeBin = path.join(tmp, "bin");
  fakeLog = path.join(tmp, "curl.log");
  fakeManifest = path.join(tmp, "runfree.sha256");
  fs.mkdirSync(fakeBin, { recursive: true });
  installFakeTools();
  writeManifest();
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("scripts/install.sh", () => {
  test("prints help without downloading release assets", () => {
    const result = childProcess.spawnSync("bash", ["scripts/install.sh", "--help"], {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
        RUNFREE_FAKE_LOG: fakeLog,
        RUNFREE_FAKE_MANIFEST: fakeManifest,
      },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Usage: scripts/install.sh");
    expect(fs.existsSync(fakeLog)).toBe(false);
  });

  test.each([["Darwin", "arm64", "darwin-arm64"]])("maps %s %s to %s", (osName, archName, target) => {
    const installDir = path.join(tmp, "install", target);
    const result = runInstall({
      RUNFREE_FAKE_UNAME_S: osName,
      RUNFREE_FAKE_UNAME_M: archName,
      RUNFREE_INSTALL_DIR: installDir,
    });

    expect(result.status, result.stderr).toBe(0);
    const log = fs.readFileSync(fakeLog, "utf8");
    expect(log).toContain(`runfree-0.2.0-${target}.tar.gz`);
  });

  test("offers exactly the targets the release builds", () => {
    // The installer is fetched standalone, so it carries its own copy of the
    // platform map. An installer that offers a target the release does not
    // publish sends the user to a download URL that 404s.
    const script = fs.readFileSync(path.join(repoRoot, "scripts/install.sh"), "utf8");
    const offered = [...script.matchAll(/^\s*\w+:\S+\)\s*target="([^"]+)"/gm)].map((match) => match[1]);

    const released = fs
      .readFileSync(path.join(repoRoot, "scripts/release-targets.txt"), "utf8")
      .split("\n")
      .map((line) => line.replace(/#.*$/, "").trim())
      .filter((line) => line.length > 0)
      .map((line) => line.split(/\s+/)[0]);

    expect(offered.length).toBeGreaterThan(0);
    expect(offered.sort()).toEqual(released.sort());
  });

  test("does not install on Intel macOS, which this release does not publish", () => {
    const installDir = path.join(tmp, "install", "darwin-x64");
    const result = runInstall({
      RUNFREE_FAKE_UNAME_S: "Darwin",
      RUNFREE_FAKE_UNAME_M: "x86_64",
      RUNFREE_INSTALL_DIR: installDir,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Intel macOS release binaries are not published");
    expect(result.stderr).toContain("Apple Silicon");
    expect(fs.existsSync(path.join(installDir, "runfree"))).toBe(false);
    expect(fs.existsSync(fakeLog)).toBe(false);
  });

  test("uses an explicit RUNFREE_VERSION without resolving latest", () => {
    const installDir = path.join(tmp, "install", "explicit-version");
    const result = runInstall({ RUNFREE_INSTALL_DIR: installDir });

    expect(result.status, result.stderr).toBe(0);
    const log = fs.readFileSync(fakeLog, "utf8");
    expect(log).toContain("https://github.com/genged/runfree/releases/download/v0.2.0/runfree-0.2.0-darwin-arm64.tar.gz");
    expect(log).not.toContain("api.github.com");
  });

  test("does not install on Linux while no Linux release artifacts are published", () => {
    const installDir = path.join(tmp, "install", "linux");
    const result = runInstall({
      RUNFREE_FAKE_UNAME_S: "Linux",
      RUNFREE_FAKE_UNAME_M: "x86_64",
      RUNFREE_INSTALL_DIR: installDir,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Linux release binaries are not published yet");
    expect(fs.existsSync(path.join(installDir, "runfree"))).toBe(false);
    expect(fs.existsSync(fakeLog)).toBe(false);
  });

  test("fails checksum mismatch before installing", () => {
    writeManifest("expectedhash");
    const installDir = path.join(tmp, "install", "mismatch");
    const result = runInstall({
      RUNFREE_FAKE_SHA: "actualhash",
      RUNFREE_INSTALL_DIR: installDir,
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("checksum mismatch");
    expect(fs.existsSync(path.join(installDir, "runfree"))).toBe(false);
  });

  test("creates the install directory and installs the binary with safe permissions", () => {
    const installDir = path.join(tmp, "nested", "bin");
    const result = runInstall({ RUNFREE_INSTALL_DIR: installDir });

    expect(result.status, result.stderr).toBe(0);
    expect(fs.statSync(installDir).mode & 0o777).toBe(0o755);
    expect(fs.statSync(path.join(installDir, "runfree")).mode & 0o777).toBe(0o755);
    expect(result.stdout).toContain(`installed runfree to ${path.join(installDir, "runfree")}`);
  });

  test("warns when the install directory is not on PATH", () => {
    const installDir = path.join(tmp, "not-on-path");
    const result = runInstall({ RUNFREE_INSTALL_DIR: installDir });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain(`warning: ${installDir} is not on PATH`);
  });
});
