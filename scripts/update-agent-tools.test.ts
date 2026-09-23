import { describe, expect, test } from "vitest";

import {
  agentToolPackageSpecs,
  assertAgentToolsPackageLockConsistency,
  parseAgentToolUpdateArgs,
} from "./update-agent-tools.ts";

describe("agent tools updater", () => {
  test("defaults to updating all bundled agent tools and rebuilding assets", () => {
    const options = parseAgentToolUpdateArgs([]);

    expect(options).toEqual({
      dryRun: false,
      rebuildAssets: true,
      requests: ["all"],
      showHelp: false,
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

    expect(options).toMatchObject({ dryRun: true, rebuildAssets: false });
    expect(agentToolPackageSpecs(options.requests).map((spec) => spec.npmSpec)).toEqual([
      "@anthropic-ai/claude-code@latest",
      "@openai/codex@0.139.0",
      "@earendil-works/pi-coding-agent@0.78.0",
    ]);
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
