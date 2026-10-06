import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  agentToolPackageSpecs,
  assertAgentToolsPackageLockConsistency,
  defaultSessionIdContractGate,
  main,
  parseAgentToolUpdateArgs,
  usage,
  type AgentToolUpdateDeps,
} from "./update-agent-tools.ts";

const OK_CONTRACT_STDOUT =
  "claude-transcript=ok\nclaude-resume-refused=ok\npi-session-id=ok\npi-resume-refused=ok\n";

/** A minimal spawnSync stand-in: fixed return shape, overridable per test. */
function spawnSyncResult(overrides: Partial<childProcess.SpawnSyncReturns<string>>): childProcess.SpawnSyncReturns<string> {
  return { status: 0, stdout: "", stderr: "", pid: 1, output: [], signal: null, ...overrides };
}

describe("agent tools updater", () => {
  test("defaults to updating all bundled agent tools and rebuilding assets", () => {
    const options = parseAgentToolUpdateArgs([]);

    expect(options).toEqual({
      dryRun: false,
      rebuildAssets: true,
      requests: ["all"],
      showHelp: false,
      skipContract: false,
    });
    expect(agentToolPackageSpecs(options.requests).map((spec) => spec.npmSpec)).toEqual([
      "@anthropic-ai/claude-code@latest",
      "@openai/codex@latest",
      "@earendil-works/pi-coding-agent@latest",
    ]);
  });

  test("accepts aliases, exact pins, package names, npm separators, and asset-skip options", () => {
    const options = parseAgentToolUpdateArgs([
      "--",
      "--dry-run",
      "--no-assets",
      "pi@0.78.0",
      "@openai/codex@0.139.0",
      "claude",
    ]);

    expect(options).toMatchObject({ dryRun: true, rebuildAssets: false, skipContract: false });
    expect(agentToolPackageSpecs(options.requests).map((spec) => spec.npmSpec)).toEqual([
      "@anthropic-ai/claude-code@latest",
      "@openai/codex@0.139.0",
      "@earendil-works/pi-coding-agent@0.78.0",
    ]);
  });

  test("--no-contract skips the pinned --session-id contract gate", () => {
    const options = parseAgentToolUpdateArgs(["--no-contract"]);
    expect(options).toMatchObject({ skipContract: true });
  });

  test("usage documents --no-contract", () => {
    expect(usage()).toContain("--no-contract");
  });

  test("all can be combined with an exact override", () => {
    expect(agentToolPackageSpecs(["all", "codex@0.139.0"]).map((spec) => spec.npmSpec)).toEqual([
      "@anthropic-ai/claude-code@latest",
      "@openai/codex@0.139.0",
      "@earendil-works/pi-coding-agent@latest",
    ]);
  });

  test("rejects unknown tools and unknown options", () => {
    expect(() => parseAgentToolUpdateArgs(["--bogus"])).toThrow("unknown option: --bogus");
    expect(() => agentToolPackageSpecs(["gemini"])).toThrow("unknown agent tool: gemini");
  });

  test("verifies exact package pins and matching package-lock entries", () => {
    const packageJson = {
      dependencies: {
        "@anthropic-ai/claude-code": "2.1.170",
        "@openai/codex": "0.138.0",
        "@earendil-works/pi-coding-agent": "0.77.0",
      },
    };
    const packageLock = {
      packages: {
        "": { dependencies: packageJson.dependencies },
        "node_modules/@anthropic-ai/claude-code": { version: "2.1.170" },
        "node_modules/@openai/codex": { version: "0.138.0" },
        "node_modules/@earendil-works/pi-coding-agent": { version: "0.77.0" },
      },
    };

    expect(() => assertAgentToolsPackageLockConsistency(packageJson, packageLock)).not.toThrow();
    expect(() =>
      assertAgentToolsPackageLockConsistency(
        { dependencies: { ...packageJson.dependencies, "@openai/codex": "^0.138.0" } },
        packageLock,
      ),
    ).toThrow("must be an exact resolved version");
    expect(() =>
      assertAgentToolsPackageLockConsistency(packageJson, {
        packages: {
          ...packageLock.packages,
          "node_modules/@openai/codex": { version: "0.137.0" },
        },
      }),
    ).toThrow("must lock 0.138.0");
  });
});

// ---------------------------------------------------------------------------
// defaultSessionIdContractGate: review finding 1. The host `npm ci` step
// must target the probe container's platform (Linux, Docker's own server
// arch), not the host's — resolved by spying on `childProcess.spawnSync`
// directly, since `spawnDocker` and `run()` both call it under the hood and
// this is the only seam that reaches every step (docker version, npm ci, and
// the final `docker run` probe) without adding a second injectable `deps`
// layer just for this one function.
// ---------------------------------------------------------------------------

describe("defaultSessionIdContractGate: host npm targets the container platform", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("the host npm ci argv carries --os/--cpu/--libc with the Docker server's mapped arch", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-contract-gate-test-"));
    const packageJsonPath = path.join(dir, "package.json");
    const packageLockPath = path.join(dir, "package-lock.json");
    fs.writeFileSync(packageJsonPath, "{}");
    fs.writeFileSync(packageLockPath, "{}");

    const spy = vi.spyOn(childProcess, "spawnSync").mockImplementation((command, args) => {
      const argv = (args ?? []) as string[];
      if (command === "docker" && argv[0] === "version") {
        return spawnSyncResult({ stdout: "x86_64\n" });
      }
      if (command === "npm" && argv[0] === "ci") {
        return spawnSyncResult({});
      }
      if (command === "docker" && argv[0] === "run") {
        return spawnSyncResult({ stdout: OK_CONTRACT_STDOUT });
      }
      throw new Error(`unexpected spawnSync(${command}, ${JSON.stringify(argv)})`);
    });

    expect(() => defaultSessionIdContractGate({ packageJsonPath, packageLockPath })).not.toThrow();

    const npmCall = spy.mock.calls.find(([command]) => command === "npm");
    expect(npmCall).toBeDefined();
    const npmArgs = npmCall?.[1] as string[];
    expect(npmArgs).toEqual(expect.arrayContaining(["--os=linux", "--cpu=x64", "--libc=glibc"]));

    fs.rmSync(dir, { recursive: true, force: true });
  });

  test("an architecture Docker reports that npm's --cpu does not recognize is refused before any npm call", () => {
    const spy = vi.spyOn(childProcess, "spawnSync").mockReturnValue(spawnSyncResult({ stdout: "riscv64\n" }));

    expect(() =>
      defaultSessionIdContractGate({
        packageJsonPath: "/nonexistent/package.json",
        packageLockPath: "/nonexistent/package-lock.json",
      }),
    ).toThrow(/unsupported Docker server architecture/);

    // Resolved before the temp dir exists, so neither file was even read —
    // and only the one `docker version` call happened, never `npm`.
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls.every(([command]) => command === "docker")).toBe(true);
  });

  test("a failing `docker version` (daemon unreachable) fails before any npm download, and main() restores the snapshot", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-contract-gate-restore-test-"));
    const packageJsonPath = path.join(dir, "package.json");
    const packageLockPath = path.join(dir, "package-lock.json");
    fs.writeFileSync(packageJsonPath, JSON.stringify(fixturePackageJson(BEFORE_VERSIONS)));
    fs.writeFileSync(packageLockPath, JSON.stringify(fixturePackageLock(BEFORE_VERSIONS)));
    const originalJson = fs.readFileSync(packageJsonPath);
    const originalLock = fs.readFileSync(packageLockPath);

    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    const spawnSpy = vi
      .spyOn(childProcess, "spawnSync")
      .mockReturnValue(spawnSyncResult({ status: 1, stderr: "Cannot connect to the Docker daemon\n" }));

    const deps: AgentToolUpdateDeps = {
      packageJsonPath,
      packageLockPath,
      runNpmUpdate: () => {
        fs.writeFileSync(packageJsonPath, JSON.stringify(fixturePackageJson(AFTER_VERSIONS)));
        fs.writeFileSync(packageLockPath, JSON.stringify(fixturePackageLock(AFTER_VERSIONS)));
      },
      runSessionIdContractGate: () => defaultSessionIdContractGate({ packageJsonPath, packageLockPath }),
      rebuildRuntimeAssets: vi.fn(),
    };

    await expect(main(["claude@2.1.171", "--no-assets"], deps)).rejects.toThrow(
      "agent tools left unchanged: --session-id contract failed",
    );

    // Exactly the "docker version" probe ran — no npm ci, no docker run.
    expect(spawnSpy.mock.calls.every(([command]) => command === "docker")).toBe(true);
    expect(fs.readFileSync(packageJsonPath)).toEqual(originalJson);
    expect(fs.readFileSync(packageLockPath)).toEqual(originalLock);

    fs.rmSync(dir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// main(): the npm step and the --session-id contract gate are injected as
// fakes (review F7's seam), so these never run real npm or Docker and never
// touch the real packages/agent-runtime/agent/agent-tools files — only a temp
// pair this block creates and removes itself.
// ---------------------------------------------------------------------------

type ToolVersions = { claude: string; codex: string; pi: string };

function fixturePackageJson(versions: ToolVersions) {
  return {
    dependencies: {
      "@anthropic-ai/claude-code": versions.claude,
      "@openai/codex": versions.codex,
      "@earendil-works/pi-coding-agent": versions.pi,
    },
  };
}

function fixturePackageLock(versions: ToolVersions) {
  const dependencies = fixturePackageJson(versions).dependencies;
  return {
    packages: {
      "": { dependencies },
      "node_modules/@anthropic-ai/claude-code": { version: versions.claude },
      "node_modules/@openai/codex": { version: versions.codex },
      "node_modules/@earendil-works/pi-coding-agent": { version: versions.pi },
    },
  };
}

const BEFORE_VERSIONS: ToolVersions = { claude: "2.1.170", codex: "0.138.0", pi: "0.77.0" };
const AFTER_VERSIONS: ToolVersions = { claude: "2.1.171", codex: "0.138.0", pi: "0.77.0" };

type MainFixture = {
  dir: string;
  packageJsonPath: string;
  packageLockPath: string;
  originalJson: Buffer;
  originalLock: Buffer;
};

function createMainFixture(): MainFixture {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-update-agent-tools-test-"));
  const packageJsonPath = path.join(dir, "package.json");
  const packageLockPath = path.join(dir, "package-lock.json");
  fs.writeFileSync(packageJsonPath, JSON.stringify(fixturePackageJson(BEFORE_VERSIONS)));
  fs.writeFileSync(packageLockPath, JSON.stringify(fixturePackageLock(BEFORE_VERSIONS)));
  return {
    dir,
    packageJsonPath,
    packageLockPath,
    originalJson: fs.readFileSync(packageJsonPath),
    originalLock: fs.readFileSync(packageLockPath),
  };
}

/** The fake npm step: writes the "after" pins, the way a real npm install would. */
function fakeRunNpmUpdate(fixture: MainFixture) {
  return () => {
    fs.writeFileSync(fixture.packageJsonPath, JSON.stringify(fixturePackageJson(AFTER_VERSIONS)));
    fs.writeFileSync(fixture.packageLockPath, JSON.stringify(fixturePackageLock(AFTER_VERSIONS)));
  };
}

describe("main(): --session-id contract gate wiring", () => {
  let fixture: MainFixture;

  afterEach(() => {
    vi.restoreAllMocks();
    if (fixture) fs.rmSync(fixture.dir, { recursive: true, force: true });
  });

  // Cheap minor fix: the restore now covers the npm step and the lockfile
  // check too, not only the contract gate — a throw from either also
  // restores the snapshot, named by the phase that actually failed.

  test("a failing npm step restores both agent-tools files exactly", async () => {
    fixture = createMainFixture();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const gate = vi.fn();
    const deps: AgentToolUpdateDeps = {
      packageJsonPath: fixture.packageJsonPath,
      packageLockPath: fixture.packageLockPath,
      runNpmUpdate: () => {
        throw new Error("npm install failed: network error");
      },
      runSessionIdContractGate: gate,
      rebuildRuntimeAssets: vi.fn(),
    };

    await expect(main(["claude@2.1.171", "--no-assets"], deps)).rejects.toThrow(
      "agent tools left unchanged: npm update failed",
    );

    expect(fs.readFileSync(fixture.packageJsonPath)).toEqual(fixture.originalJson);
    expect(fs.readFileSync(fixture.packageLockPath)).toEqual(fixture.originalLock);
    expect(gate).not.toHaveBeenCalled();
  });

  test("an inconsistent lockfile left by the npm step restores both agent-tools files exactly", async () => {
    fixture = createMainFixture();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const gate = vi.fn();
    const deps: AgentToolUpdateDeps = {
      packageJsonPath: fixture.packageJsonPath,
      packageLockPath: fixture.packageLockPath,
      runNpmUpdate: () => {
        // package.json claims a new pin; package-lock.json was left stale —
        // the real assertAgentToolsPackageLockConsistency must catch this.
        fs.writeFileSync(fixture.packageJsonPath, JSON.stringify(fixturePackageJson(AFTER_VERSIONS)));
        fs.writeFileSync(fixture.packageLockPath, JSON.stringify(fixturePackageLock(BEFORE_VERSIONS)));
      },
      runSessionIdContractGate: gate,
      rebuildRuntimeAssets: vi.fn(),
    };

    await expect(main(["claude@2.1.171", "--no-assets"], deps)).rejects.toThrow(
      "agent tools left unchanged: lockfile verification failed",
    );

    expect(fs.readFileSync(fixture.packageJsonPath)).toEqual(fixture.originalJson);
    expect(fs.readFileSync(fixture.packageLockPath)).toEqual(fixture.originalLock);
    expect(gate).not.toHaveBeenCalled();
  });

  test("a failing contract gate restores both agent-tools files exactly", async () => {
    fixture = createMainFixture();
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    const rebuildRuntimeAssets = vi.fn();
    const deps: AgentToolUpdateDeps = {
      packageJsonPath: fixture.packageJsonPath,
      packageLockPath: fixture.packageLockPath,
      runNpmUpdate: fakeRunNpmUpdate(fixture),
      runSessionIdContractGate: () => {
        throw new Error("--session-id contract failed (missing claude-transcript=ok)");
      },
      rebuildRuntimeAssets,
    };

    await expect(main(["claude@2.1.171", "--no-assets"], deps)).rejects.toThrow(
      "agent tools left unchanged: --session-id contract failed",
    );

    expect(fs.readFileSync(fixture.packageJsonPath)).toEqual(fixture.originalJson);
    expect(fs.readFileSync(fixture.packageLockPath)).toEqual(fixture.originalLock);
    expect(rebuildRuntimeAssets).not.toHaveBeenCalled();
  });

  test("a passing contract gate keeps the new pins", async () => {
    fixture = createMainFixture();
    vi.spyOn(console, "log").mockImplementation(() => {});
    const gate = vi.fn();
    const rebuildRuntimeAssets = vi.fn();
    const deps: AgentToolUpdateDeps = {
      packageJsonPath: fixture.packageJsonPath,
      packageLockPath: fixture.packageLockPath,
      runNpmUpdate: fakeRunNpmUpdate(fixture),
      runSessionIdContractGate: gate,
      rebuildRuntimeAssets,
    };

    await main(["claude@2.1.171", "--no-assets"], deps);

    expect(gate).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fs.readFileSync(fixture.packageJsonPath, "utf8"))).toEqual(fixturePackageJson(AFTER_VERSIONS));
    expect(JSON.parse(fs.readFileSync(fixture.packageLockPath, "utf8"))).toEqual(fixturePackageLock(AFTER_VERSIONS));
    // --no-assets was passed, independent of the contract gate.
    expect(rebuildRuntimeAssets).not.toHaveBeenCalled();
  });

  test("--no-contract skips the gate entirely and reports the skip", async () => {
    fixture = createMainFixture();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const gate = vi.fn();
    const deps: AgentToolUpdateDeps = {
      packageJsonPath: fixture.packageJsonPath,
      packageLockPath: fixture.packageLockPath,
      runNpmUpdate: fakeRunNpmUpdate(fixture),
      runSessionIdContractGate: gate,
      rebuildRuntimeAssets: vi.fn(),
    };

    await main(["claude@2.1.171", "--no-assets", "--no-contract"], deps);

    expect(gate).not.toHaveBeenCalled();
    expect(logSpy.mock.calls.map((call) => call[0])).toContain("session-id contract: skipped (--no-contract)");
    expect(JSON.parse(fs.readFileSync(fixture.packageJsonPath, "utf8"))).toEqual(fixturePackageJson(AFTER_VERSIONS));
  });
});
