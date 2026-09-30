// Live proof for the sub-second launch plan, Phase B (Tasks 2–6, 8).
//
// Each case launches the recording Claude stand-in one-shot (its hold marker
// absent, so it records its argv and exits 0) with `RUNFREE_TIMINGS=1`, and
// reads the timing lines the CLI prints. The assertions are about which path a
// launch took, never about a time budget, except the optional latency gate:
//
//   - a warm launch after a full validation matches its warm proof, skips the
//     full runtime validation, the image cleanup inventory, and the separate
//     IP-assignment read, and is admitted under the lock startup handed off;
//   - `runfree up` always validates fully and rewrites the warm proof;
//   - an in-place `docker restart` of the proxy is a warm-proof mismatch, and
//     the launch still succeeds on the full path;
//   - a firewall changed inside the running proxy (same container, same
//     start time) is a warm-proof mismatch, and removing the change reclaims
//     the warm path;
//   - a normal numeric exit takes the short teardown (spec open decision 3:
//     the exited container's inspection proves it stopped before removal),
//     and the session container is gone afterwards.
//
// The latency gate runs `LAUNCH_LATENCY_RUNS` (default 5) warm launches and
// writes their timings to `LAUNCH_LATENCY_REPORT` when set. With
// `LAUNCH_LATENCY_P95_MS` set it also asserts the nearest-rank p95 of the
// in-CLI `startup-total` plus admission phases; the plan's gates (Gate B:
// p50 about 1.8–2.0 s through the dev wrapper; Gate E/F: p95 <= 1.0 s) are
// recorded by the benchmark script, not hard-coded here.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  MANAGED_HOLD_RELATIVE_PATH,
  provisionSandboxFixture,
} from "./fixture.ts";
import { liveTierSelected } from "./tiers.ts";

// The fast paths are part of the trust boundary's proof (a warm launch must
// never skip what a changed runtime needs), so those cases are core; the
// latency gate is a measurement and is extended.
const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RUNFREE_BIN = path.join(REPO_ROOT, "bin", "runfree.js");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the launch latency tranche");
  }
  return backend;
}

function runfreeTimed(fixture: LiveFixture, args: readonly string[]): CaptureResult {
  const result = childProcess.spawnSync(process.execPath, [RUNFREE_BIN, "--workspace", fixture.projectRoot, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...fixture.env, RUNFREE_TIMINGS: "1" },
    maxBuffer: CAPTURE_MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const stderr = typeof result.stderr === "string" ? result.stderr : "";
  return Object.freeze({ status: result.status ?? 1, stdout, stderr, output: `${stdout}${stderr}` });
}

/** Every `timing: <phase> <detail>` line, as [phase, detail] pairs. */
function timingLines(output: string): Array<readonly [string, string]> {
  return output.split("\n").flatMap((line) => {
    const match = /timing: (\S+) (.*)$/.exec(line.trimEnd());
    return match ? [[match[1] as string, match[2] as string] as const] : [];
  });
}

function timing(output: string, phase: string): string[] {
  return timingLines(output).filter(([name]) => name === phase).map(([, detail]) => detail);
}

function milliseconds(output: string, phase: string): number | undefined {
  const detail = timing(output, phase).at(-1);
  const match = detail ? /^([\d.]+)ms$/.exec(detail) : undefined;
  return match ? Number(match[1]) : undefined;
}

function launchClaude(fixture: LiveFixture): CaptureResult {
  const launched = runfreeTimed(fixture, ["claude"]);
  expect(launched.status, describeOutput(launched.output)).toBe(0);
  return launched;
}

function sessionContainers(fixture: LiveFixture): string[] {
  const project = composeProjectName(fixture);
  const listed = docker(["ps", "-aq", "--no-trunc", "--filter", `name=^runfree-${project.replace(/^runfree-/, "")}-session-`]);
  return listed.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
}

function nearestRankP95(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(0.95 * sorted.length) - 1)] as number;
}

describe("launch latency: sub-second launch plan Phase B", () => {
  let fixture: LiveFixture;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    fs.rmSync(path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH), { force: true });
    // Two launches: the first may still build or select, the second leaves a
    // full validation's warm proof and a completed cleanup stamp behind.
    launchClaude(fixture);
    launchClaude(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  coreTest("a warm launch takes the warm proof, the held-lock handoff, and the short exit", () => {
    const warm = launchClaude(fixture);
    const output = warm.output;
    expect(timing(output, "validation:warm-proof"), describeOutput(output)).toContain("match");
    // The full validation's phases did not run.
    expect(milliseconds(output, "runtime-validation")).toBeUndefined();
    expect(milliseconds(output, "validation:topology")).toBeUndefined();
    expect(timing(output, "image-cleanup")).toContain("skipped inputs-unchanged");
    expect(timing(output, "launch-handoff")).toContain("minted");
    // Admission's Docker work before the agent is fully categorized.
    const before = timing(output, "session-admission")
      .map((detail) => /^docker-operations-before-agent=(\d+)$/.exec(detail)?.[1])
      .find((value) => value !== undefined);
    const categorized = timing(output, "admission-ops")
      .reduce((sum, detail) => sum + Number(/ count=(\d+) /.exec(detail)?.[1] ?? Number.NaN), 0);
    expect(Number(before)).toBe(categorized);
    // Spec open decision 3: the exited container's inspection proved it
    // stopped, so the teardown skipped the disconnect and the stop.
    expect(timing(output, "teardown-path")).toContain("exited");
    expect(sessionContainers(fixture)).toEqual([]);
  }, TEST_TIMEOUT_MS);

  coreTest("runfree up always validates fully, and the next launch is warm again", () => {
    const up = runfreeTimed(fixture, ["up"]);
    expect(up.status, describeOutput(up.output)).toBe(0);
    expect(milliseconds(up.output, "validation:topology"), describeOutput(up.output)).toBeGreaterThan(0);
    expect(timing(up.output, "validation:warm-proof")).toContain("recorded");
    const warm = launchClaude(fixture);
    expect(timing(warm.output, "validation:warm-proof"), describeOutput(warm.output)).toContain("match");
  }, TEST_TIMEOUT_MS);

  coreTest("an in-place proxy restart is a warm-proof mismatch, and the launch validates fully", () => {
    const project = composeProjectName(fixture);
    const proxyId = composeServiceContainerId(project, "proxy");
    dockerOrThrow("restart the proxy in place", ["restart", proxyId]);
    const restarted = launchClaude(fixture);
    const verdicts = timing(restarted.output, "validation:warm-proof");
    expect(verdicts.some((verdict) => verdict.startsWith("mismatch:")), describeOutput(restarted.output)).toBe(true);
    expect(milliseconds(restarted.output, "validation:topology")).toBeGreaterThan(0);
    // And the one after it is warm on the new incarnation.
    const warm = launchClaude(fixture);
    expect(timing(warm.output, "validation:warm-proof"), describeOutput(warm.output)).toContain("match");
  }, TEST_TIMEOUT_MS);

  coreTest("a firewall changed inside the running proxy is never a warm launch, and undoing it reclaims the warm path", () => {
    const project = composeProjectName(fixture);
    const proxyId = composeServiceContainerId(project, "proxy");
    const nft = (verb: "add" | "delete") =>
      ["exec", "--privileged", "--user", "0:0", proxyId, "nft", verb, "chain", "inet", "runfree_proxy", "runfree_warm_drift"];
    // Same proxy container and start time: only the in-proxy ruleset moved.
    dockerOrThrow("add a chain to the proxy's table", nft("add"));
    try {
      const drifted = runfreeTimed(fixture, ["claude"]);
      const verdicts = timing(drifted.output, "validation:warm-proof");
      expect(verdicts, describeOutput(drifted.output)).not.toContain("match");
      expect(verdicts.some((verdict) => verdict.startsWith("mismatch:")), describeOutput(drifted.output)).toBe(true);
    } finally {
      dockerOrThrow("remove the added chain", nft("delete"));
    }
    // Reclaim: the next launch validates fully, and the one after is warm.
    launchClaude(fixture);
    const warm = launchClaude(fixture);
    expect(timing(warm.output, "validation:warm-proof"), describeOutput(warm.output)).toContain("match");
  }, TEST_TIMEOUT_MS);

  extendedTest("latency gate: warm launches, measured in the CLI", () => {
    const runs = Number(process.env.LAUNCH_LATENCY_RUNS ?? "5");
    expect(Number.isSafeInteger(runs) && runs > 0).toBe(true);
    const samples: Array<Record<string, number | string | undefined>> = [];
    for (let index = 0; index < runs; index += 1) {
      const startedAt = performance.now();
      const launched = launchClaude(fixture);
      const wallMs = performance.now() - startedAt;
      const admission = ["admission:preflight", "admission:allocate", "admission:create-started", "admission:prove-running", "admission:activate", "admission:await-handoff"]
        .reduce((sum, phase) => sum + (milliseconds(launched.output, phase) ?? 0), 0);
      samples.push({
        wallMs,
        startupTotalMs: milliseconds(launched.output, "startup-total"),
        admissionMs: admission,
        warmProof: timing(launched.output, "validation:warm-proof").at(-1),
        handoff: timing(launched.output, "launch-handoff").at(-1),
        teardownPath: timing(launched.output, "teardown-path").at(-1),
      });
    }
    const report = process.env.LAUNCH_LATENCY_REPORT;
    if (report) fs.writeFileSync(report, `${JSON.stringify({ runs, samples }, null, 2)}\n`);
    for (const sample of samples) {
      expect(sample.warmProof).toBe("match");
      expect(sample.handoff).toBe("minted");
    }
    const bound = process.env.LAUNCH_LATENCY_P95_MS;
    if (bound !== undefined) {
      const overhead = samples.map((sample) => Number(sample.startupTotalMs ?? Number.NaN) + Number(sample.admissionMs));
      expect(nearestRankP95(overhead)).toBeLessThanOrEqual(Number(bound));
    }
  }, TEST_TIMEOUT_MS);
});
