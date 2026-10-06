import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  agentToolPackageSpecs,
  assertAgentToolsPackageLockConsistency,
  main,
  parseAgentToolUpdateArgs,
  usage,
  type AgentToolUpdateDeps,
} from "./update-agent-tools.ts";

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
