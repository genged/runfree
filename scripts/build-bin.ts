import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const binary = path.join(repoRoot, "dist", "runfree");
const signingScript = path.join(repoRoot, "scripts", "macos-code-signing.sh");

function run(command: string, args: string[], options: childProcess.SpawnSyncOptions = {}): number {
  const result = childProcess.spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

function build(): number {
  const buildCwd = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-bun-build-"));
  try {
    fs.mkdirSync(path.join(repoRoot, "dist"), { recursive: true });
    const status = run(
      "bun",
      ["build", path.join(repoRoot, "packages", "cli", "src", "cli.ts"), "--compile", "--outfile", binary],
      { cwd: buildCwd },
    );
    if (status !== 0) return status;
  } finally {
    fs.rmSync(buildCwd, { recursive: true, force: true });
  }

  // A locally built binary carries the same code-signing identifier as the
  // release binary. Without it Bun's compiled output advertises the generic
  // linker identifier `a.out`, which every other generically signed tool on
  // the machine also advertises, so macOS records its decisions about Runfree
  // under a name that identifies nothing.
  if (process.platform !== "darwin") return 0;
  const signed = run(signingScript, ["sign-local", binary]);
  if (signed !== 0) return signed;
  return run(signingScript, ["assert", binary]);
}

process.exitCode = build();
