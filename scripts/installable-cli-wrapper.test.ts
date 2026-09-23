import { describe, expect, test } from "vitest";

import { RUNFREE_VERSION } from "../packages/cli/src/embedded-assets.generated.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { tmp, runBinWrapperCli } from "./installable-cli.test-harness.ts";

// The one file that spawns the real `bin/runfree.js` wrapper (which re-spawns
// the CLI through tsx). Every other installable-cli file spawns the prebuilt
// CLI bundle for speed, so the wrapper's own wiring — argv passthrough,
// RUNFREE_INVOCATION_CWD/RUNFREE_PROJECT_ROOT from the invocation directory,
// and exit-status propagation — is proven here and only here.
describe("installable runfree CLI: bin wrapper", () => {
  test("passes argv through and propagates a success status", () => {
    const result = runBinWrapperCli(["version"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(RUNFREE_VERSION);
  });

  test("derives the project root from the invocation directory", () => {
    // No --workspace: the wrapper must carry its cwd into the CLI's project
    // resolution via the env contract.
    const result = runBinWrapperCli(["project-id"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(projectHash(tmp));
  });

  test("keeps a leading --workspace working through the wrapper", () => {
    const result = runBinWrapperCli(["--workspace", ".", "project-id"]);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe(projectHash(tmp));
  });

  test("propagates a failure status and stderr", () => {
    const result = runBinWrapperCli(["definitely-not-a-command"]);

    expect(result.status).toBe(1);
    expect(result.stderr).not.toBe("");
  });
});
