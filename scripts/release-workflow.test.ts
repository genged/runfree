// Structure of the release workflow itself: the job graph, what each job checks
// out, where privileged inputs are allowed, and that every action is pinned.
//
// The behavior of each gate is tested by running its script
// (release-eligibility, release-coordination, release-publication,
// release-scripts). What is left here is what only the workflow file can say,
// and these assertions are scoped to one job at a time: the previous version of
// this file used `/build-macos:[\s\S]*target: darwin-arm64/`, which is satisfied
// by text belonging to any later job.

import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

/** Splits a workflow's `jobs:` mapping into one text block per job id. */
function jobs(workflow: string): Record<string, string> {
  const lines = workflow.split("\n");
  const start = lines.findIndex((line) => line === "jobs:");
  if (start < 0) throw new Error("workflow has no jobs: block");

  const blocks: Record<string, string> = {};
  let current: string | null = null;
  for (const line of lines.slice(start + 1)) {
    const header = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (header) {
      current = header[1];
      blocks[current] = "";
      continue;
    }
    if (/^\S/.test(line) && line.trim() !== "") break;
    if (current) blocks[current] += `${line}\n`;
  }
  return blocks;
}

const releaseWorkflow = readRepoFile(".github/workflows/release-lane.yml");
const releaseRouter = readRepoFile(".github/workflows/release.yml");
const releaseJobs = jobs(releaseWorkflow);

describe("release workflow", () => {
  test("resolves the tag once and binds every later job to that SHA", () => {
    expect(releaseJobs.resolve).toContain("run: scripts/resolve-release-tag.sh");
    expect(releaseJobs.resolve).toContain("sha: ${{ steps.release.outputs.sha }}");

    for (const jobId of ["prepare", "unit-tests", "build-macos", "publish"]) {
      expect(releaseJobs[jobId], `${jobId} must check out the resolved SHA`).toContain(
        "ref: ${{ needs.resolve.outputs.sha }}",
      );
      // Checking out the tag again in a later job re-resolves a mutable pointer.
      expect(releaseJobs[jobId], `${jobId} must not re-resolve the tag`).not.toContain(
        "ref: ${{ needs.resolve.outputs.tag }}",
      );
    }
  });

  test("orders the gates so nothing is built before unit tests pass", () => {
    expect(releaseJobs.prepare).toContain("needs: resolve");
    expect(releaseJobs.prepare).toContain("run: bash scripts/prepare-release.sh");
    expect(releaseJobs["unit-tests"]).toContain("needs: [resolve, prepare]");
    expect(releaseJobs["unit-tests"]).toContain("if: needs.prepare.outputs.ready == 'true'");
    expect(releaseJobs.resolve).toContain("EXPECTED_SHA: ${{ inputs.sha }}");

    expect(releaseJobs["build-macos"]).toContain("needs: [resolve, prepare, unit-tests]");
    expect(releaseJobs.publish).toContain("needs: [resolve, prepare, unit-tests, build-macos]");
  });

  test("runs only the unit tests before release", () => {
    const unitTests = releaseJobs["unit-tests"];
    expect(unitTests.indexOf("run: pnpm run build:runtime")).toBeGreaterThanOrEqual(0);
    expect(unitTests.indexOf("run: make test-unit")).toBeGreaterThan(unitTests.indexOf("run: pnpm run build:runtime"));
    expect(releaseWorkflow).not.toContain("uses: ./.github/workflows/verify.yml");
    expect(releaseWorkflow).not.toContain("scripts/run-cli-e2e.sh");
    expect(releaseWorkflow).not.toContain("make test-static");
  });

  test("takes the build matrix from the central release target list", () => {
    expect(releaseJobs["build-macos"]).toContain("include: ${{ fromJSON(needs.resolve.outputs.targets) }}");
    // No target is spelled out in the workflow, so the list cannot disagree with
    // what packaging, signing, checksums, and the installer use.
    expect(releaseWorkflow).not.toContain("target: darwin-arm64");
    expect(releaseWorkflow).not.toContain("darwin-x64");
    expect(releaseWorkflow).not.toContain("runs-on: macos-latest");
  });

  test("installs pnpm and workspace dependencies in every job that builds or tests", () => {
    for (const jobId of ["unit-tests", "build-macos"]) {
      expect(releaseJobs[jobId], `${jobId} needs pnpm`).toContain("uses: pnpm/action-setup@");
      expect(releaseJobs[jobId], `${jobId} needs its own dependencies`).toContain(
        "run: pnpm install --frozen-lockfile",
      );
    }
    // Packaging shells out to pnpm; Node and Bun from another job do not supply
    // the workspace.
    expect(releaseJobs["build-macos"].indexOf("pnpm install --frozen-lockfile")).toBeLessThan(
      releaseJobs["build-macos"].indexOf("scripts/package-homebrew-artifacts.sh"),
    );
  });

  test("publishes the downloaded archives after re-checking the tag, and never rebuilds them", () => {
    const publish = releaseJobs.publish;
    const unmovedIndex = publish.indexOf("scripts/require-unmoved-tag.sh");
    const downloadIndex = publish.indexOf("uses: actions/download-artifact@");
    const publishIndex = publish.indexOf("scripts/publish-release-assets.sh");

    expect(unmovedIndex).toBeGreaterThanOrEqual(0);
    expect(downloadIndex).toBeGreaterThan(unmovedIndex);
    expect(publishIndex).toBeGreaterThan(downloadIndex);
    expect(publish).toContain("scripts/checksum-release-artifacts.sh");
    expect(publish).not.toContain("package-homebrew-artifacts.sh");
    expect(publish).not.toContain("sign-adhoc-macos-target.sh");
    expect(publish).toMatch(/permissions:\n\s+contents: write/);
  });

  test("serializes by resolved tag so two runs cannot publish the same tag at once", () => {
    expect(releaseRouter).toMatch(/concurrency:\n\s+group: release-\$\{\{ matrix.tag \}\}\n\s+cancel-in-progress: false/);
    expect(releaseRouter).toContain("queue: max");
    expect(releaseRouter).toContain("uses: ./.github/workflows/release-lane.yml");
    expect(releaseRouter).toContain("sha: ${{ matrix.sha }}");
    expect(releaseRouter).toContain("if: needs.discover.outputs.targets != '[]'");
    expect(releaseRouter).toContain("github.event_name == 'workflow_dispatch' && inputs.replace_assets || false");
  });

  test("isolates uploads and downloads per tag", () => {
    const candidateName = "name: release_${{ needs.resolve.outputs.tag }}_${{ matrix.target }}";
    expect(releaseJobs["build-macos"]).toContain(candidateName);
    expect(releaseJobs.publish).toContain("pattern: release_${{ needs.resolve.outputs.tag }}_*");
  });

  test("starts only from tag pushes and manual dispatch", () => {
    expect(releaseRouter).not.toContain("workflow_run:");
    expect(releaseRouter).toMatch(/push:\n\s+tags:/);
    expect(releaseRouter).toContain("workflow_dispatch:");
  });

  test("signs the candidate ad-hoc, with no Apple credentials anywhere in the release", () => {
    expect(shellBodies(releaseWorkflow).filter((body) => body.includes("sign-adhoc-macos-target.sh"))).toHaveLength(1);
    // An ad-hoc binary has no publisher identity and no notarization ticket, so
    // the release needs no signing credentials and no privileged environment,
    // and nothing may claim an assessment such a binary cannot pass.
    expect(releaseWorkflow).not.toContain("secrets.APPLE_");
    expect(releaseWorkflow).not.toContain("environment: release");
    expect(releaseWorkflow).not.toContain("notarytool");
    expect(releaseWorkflow).not.toContain("spctl");
  });

  test("starts from least privilege at the workflow level", () => {
    expect(releaseWorkflow).toMatch(/^permissions:\n {2}contents: read$/m);
  });

  test("passes tag and target inputs through the environment, never spliced into a shell command", () => {
    // `run: scripts/release.sh "${{ inputs.tag }}"` is command injection through
    // a tag name, and a tag is attacker-influenced input in a repository that
    // accepts contributions. Workflow expressions belong in `env:` and `with:`,
    // where the value is passed rather than pasted.
    const offenders = [...shellBodies(releaseWorkflow), ...shellBodies(releaseRouter)].filter((body) => body.includes("${{"));
    expect(offenders).toEqual([]);
  });
});

/** Returns the shell text of every `run:` step, inline scalars and block scalars alike. */
function shellBodies(workflow: string): string[] {
  const lines = workflow.split("\n");
  const bodies: string[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)run:\s*(.*)$/.exec(lines[index]);
    if (!match) continue;
    const [, indent, inline] = match;
    if (inline !== "|" && inline !== ">" && inline !== "|-" && inline !== ">-") {
      bodies.push(inline);
      continue;
    }
    const block: string[] = [];
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor];
      if (line.trim() !== "" && !line.startsWith(`${indent} `)) break;
      block.push(line);
    }
    bodies.push(block.join("\n"));
  }

  return bodies;
}

describe("release workflow action pinning", () => {
  const workflowDir = path.join(repoRoot, ".github/workflows");
  const workflowFiles = fs.readdirSync(workflowDir).filter((name) => name.endsWith(".yml"));

  test("every workflow file is covered by this check", () => {
    expect(workflowFiles.sort()).toEqual(["release-lane.yml", "release.yml", "test.yml", "verify.yml"]);
  });

  test.each(workflowFiles)("%s pins every third-party action to a commit SHA", (name) => {
    const workflow = fs.readFileSync(path.join(workflowDir, name), "utf8");
    const uses = [...workflow.matchAll(/uses:\s*(\S+)/g)].map((match) => match[1]);

    expect(uses.length).toBeGreaterThan(0);
    for (const reference of uses) {
      if (reference.startsWith("./")) continue; // a workflow in this repository
      expect(reference, `${reference} must be pinned to a 40-character commit SHA`).toMatch(
        /^[^@]+@[0-9a-f]{40}$/,
      );
    }
  });
});
