// Shared `RUNFREE_TIMINGS=1` launch driver for live tranches that read
// startup's own phase instrumentation.
//
// Pulled out once three files needed the identical pair of "spawn `runfree`
// with timings on, then grep its `timing: <phase> <detail>` lines" — the
// latency tranche itself, plus the warm-empty-skip fallback cases in the
// negative and crash tranches (session-admission-negative.live.test.ts,
// session-admission-crash.live.test.ts). Three independent copies of the
// same parser and spawn options is exactly the kind of duplication that lets
// one of them silently drift (a dropped `timeout`, a different `maxBuffer`),
// so this is the one place that can drift.

import childProcess from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect } from "vitest";

import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import { composeProjectName, docker } from "./docker.ts";
import { describeOutput, type CaptureResult, type LiveFixture } from "./fixture.ts";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;
/**
 * One launch of the one-shot stand-in or one `up` on a provisioned runtime.
 * `spawnSync` blocks the worker, so the case timeout cannot fire; a hung
 * launch fails here with its partial output instead.
 */
export const LAUNCH_TIMEOUT_MS = 5 * 60_000;

/** Every `timing: <phase> <detail>` line, as [phase, detail] pairs. */
function timingLines(output: string): Array<readonly [string, string]> {
  return output.split("\n").flatMap((line) => {
    const match = /timing: (\S+) (.*)$/.exec(line.trimEnd());
    return match ? [[match[1] as string, match[2] as string] as const] : [];
  });
}

export function timing(output: string, phase: string): string[] {
  return timingLines(output).filter(([name]) => name === phase).map(([, detail]) => detail);
}

export function milliseconds(output: string, phase: string): number | undefined {
  const detail = timing(output, phase).at(-1);
  const match = detail ? /^([\d.]+)ms$/.exec(detail) : undefined;
  return match ? Number(match[1]) : undefined;
}

/** A real launch with `RUNFREE_TIMINGS=1`, so its stdout/stderr carries the startup phase lines. */
export function runfreeTimed(target: LiveFixture, args: readonly string[]): CaptureResult {
  const result = childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", target.projectRoot, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...target.env, RUNFREE_TIMINGS: "1", RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT },
    maxBuffer: CAPTURE_MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: LAUNCH_TIMEOUT_MS,
  });
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const stderr = typeof result.stderr === "string" ? result.stderr : "";
  if (result.error) {
    throw new Error(`runfree ${args.join(" ")} did not finish: ${result.error.message}: ${describeOutput(`${stdout}${stderr}`)}`);
  }
  return Object.freeze({ status: result.status ?? 1, stdout, stderr, output: `${stdout}${stderr}` });
}

/** A timed `claude` launch expected to succeed; fails loudly (with the non-timing output) otherwise. */
export function launchClaudeTimed(target: LiveFixture): CaptureResult {
  const launched = runfreeTimed(target, ["claude"]);
  // Timing lines fill the tail describeOutput keeps; a failure needs the errors.
  // The admission phases stay: they show which step of a failed launch overran.
  const withoutTimings = launched.output.split("\n")
    .filter((line) => !line.includes(" timing: ") || line.includes(" timing: admission:")).join("\n");
  expect(launched.status, describeOutput(withoutTimings, 4000)).toBe(0);
  return launched;
}

/** This project's session containers, from the daemon rather than the registry. */
export function sessionContainers(target: LiveFixture): string[] {
  const project = composeProjectName(target);
  const listed = docker(["ps", "-aq", "--no-trunc", "--filter", `name=^runfree-${project.replace(/^runfree-/, "")}-session-`]);
  return listed.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
}
