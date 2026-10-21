// The shared verification lane, and the per-commit workflow that calls it.
//
// This asserts what the verification lane actually runs. The release lane calls
// it too, at the release SHA (see scripts/release-workflow.test.ts).

import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

describe("test workflow", () => {
  test("cancels superseded PR runs but preserves every main commit's verdict", () => {
    const workflow = readRepoFile(".github/workflows/test.yml");

    expect(workflow).toMatch(/permissions:\n\s+contents: read/);
    expect(workflow).toContain("group: test-${{ github.event_name == 'pull_request' && github.ref || github.sha }}");
    expect(workflow).toContain("cancel-in-progress: ${{ github.event_name == 'pull_request' }}");
  });

  test("runs on every push to the default branch and on pull requests", () => {
    const workflow = readRepoFile(".github/workflows/test.yml");

    expect(workflow).toMatch(/push:\n\s+branches:\n\s+- main/);
    expect(workflow).toContain("pull_request:");
  });

  test("delegates to the shared verification lane rather than restating it", () => {
    const workflow = readRepoFile(".github/workflows/test.yml");

    expect(workflow).toContain("uses: ./.github/workflows/verify.yml");
    expect(workflow).not.toContain("make test-unit");
  });
});

describe("verification lane", () => {
  const workflow = readRepoFile(".github/workflows/verify.yml");

  test("is callable by other workflows at a chosen commit", () => {
    expect(workflow).toMatch(/on:\n\s+workflow_call:/);
    expect(workflow).toMatch(/inputs:\n\s+ref:/);
    expect(workflow).toContain("ref: ${{ inputs.ref }}");
  });

  test("runs static, unit, template, asset, binary, smoke, and packaged CLI gates", () => {
    for (const command of [
      "make test-static",
      "make test-unit",
      "make test-templates",
      "pnpm run generate:assets",
      "git diff --exit-code -- packages/cli/src/embedded-assets.generated.ts",
      "pnpm run build:bin",
      "pnpm run smoke:bin",
      "scripts/run-cli-e2e.sh --no-build",
    ]) {
      expect(workflow).toContain(command);
    }
  });

  test("installs pnpm, Node, and Bun before the build", () => {
    const pnpmIndex = workflow.indexOf("uses: pnpm/action-setup@");
    const bunSetupIndex = workflow.indexOf("uses: oven-sh/setup-bun@");
    const installIndex = workflow.indexOf("run: pnpm install --frozen-lockfile");
    const buildIndex = workflow.indexOf("run: pnpm run build:bin");

    expect(pnpmIndex).toBeGreaterThanOrEqual(0);
    expect(bunSetupIndex).toBeGreaterThan(pnpmIndex);
    expect(installIndex).toBeGreaterThan(bunSetupIndex);
    expect(buildIndex).toBeGreaterThan(installIndex);
    expect(workflow).toContain("RUNFREE_PNPM_VERSION: 10.28.0");
  });

  // `.bun-version` is the one declaration of the Bun that builds the binaries;
  // `./bunw` reads the same file locally, so CI and local builds cannot drift.
  test.each([".github/workflows/verify.yml", ".github/workflows/release-lane.yml"])(
    "%s reads Bun from .bun-version and prints its revision",
    (workflowPath) => {
      const lane = readRepoFile(workflowPath);
      const setupIndex = lane.indexOf("uses: oven-sh/setup-bun@");

      expect(lane).toContain("bun-version-file: .bun-version");
      expect(lane).not.toContain("bun-version:");
      expect(lane).not.toContain("RUNFREE_BUN_VERSION");
      expect(setupIndex).toBeGreaterThanOrEqual(0);
      expect(lane.indexOf("run: bun --revision")).toBeGreaterThan(setupIndex);
    },
  );

  test(".bun-version holds one X.Y.Z version", () => {
    expect(readRepoFile(".bun-version")).toMatch(/^\d+\.\d+\.\d+\n$/);
  });

  test("stays unprivileged, because it runs on pull requests from forks", () => {
    expect(workflow).toMatch(/permissions:\n\s+contents: read/);
    expect(workflow).not.toContain("contents: write");
    expect(workflow).not.toContain("secrets.");
    expect(workflow).not.toContain("environment: release");
  });
});
