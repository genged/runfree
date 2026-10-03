// Empty-project admission tranche: a project with no dependencies launches.
//
// Every other live fixture commits a pnpm `package.json`, so its session plan
// always mounts dependency-overlay named volumes. Once the command-history
// volume was dropped, those overlays became the only named volumes a session
// mounts, and a project with no dependencies planned none at all. Admission
// then refused every launch with "session container plan has no named-volume
// mounts to prove" — the state `runfree init` leaves a new directory in, and
// one no tranche reached.
//
// The precondition is load-bearing: the case first proves the runtime holds no
// dependency volume for this project, so a fixture that quietly regained a
// package manifest cannot pass while proving nothing.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { composeProjectName, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";
import { runNominalAdmissionSlice } from "./session-admission-slice.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
const PROBE_AGENT = "claude" as const;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the empty-project admission tranche");
  }
  return backend;
}

function git(projectRoot: string, args: readonly string[]): void {
  const result = childProcess.spawnSync("git", ["-C", projectRoot, ...args], { encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${describeOutput(`${result.stdout}${result.stderr}`)}`);
  }
}

/**
 * Removes the fixture's package manifest before the first startup, leaving a
 * repository whose one commit has an empty tree: nothing for the dependency
 * overlay planner to detect.
 */
function removePackageManifest(fixture: LiveFixture): void {
  git(fixture.projectRoot, ["rm", "--quiet", "package.json"]);
  git(fixture.projectRoot, ["commit", "--quiet", "-m", "remove the package manifest"]);
  expect(fs.existsSync(path.join(fixture.projectRoot, "package.json"))).toBe(false);
}

describe("a project with no dependencies is admitted", () => {
  const backend = requiredBackend();
  let fixture: LiveFixture;
  let project: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: removePackageManifest });
    project = composeProjectName(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  });

  test("a session whose plan mounts no named volumes is admitted, proved, and revoked", () => {
    const volumes = dockerOrThrow("list project volumes", [
      "volume",
      "ls",
      "--quiet",
      "--filter",
      `label=com.docker.compose.project=${project}`,
    ]).split("\n").map((name) => name.trim()).filter(Boolean);
    expect(
      volumes.filter((name) => name.includes("runfree-deps-")),
      "the empty project planned dependency volumes, so this case would not reach the empty named-volume set",
    ).toEqual([]);

    runNominalAdmissionSlice({ fixture, backend, agent: PROBE_AGENT, expect: "success" });
  }, TEST_TIMEOUT_MS);
});
