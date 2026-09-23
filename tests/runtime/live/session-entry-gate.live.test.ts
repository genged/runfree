// Live negative proof for the session entry activation gate (design T6).
//
// The session entry in the base agent image is cooperation, not enforcement:
// it moves the agent's first request past activation, and a project image may
// replace it. What a replaced entry loses is only that ordering, never
// authority. This file proves the second half of that sentence against the
// running proxy: a project image whose entry sends an ordinary CONNECT the
// moment the container starts is answered exactly the guard's provisioning
// refusal — a raw 403 naming the provisioning peer — while the session is
// registered and proven but not yet active. Nothing else about admission
// changes: the running proof still holds the replaced entry to the same
// `Path`, and revocation still reclaims the session.
//
// The lifecycle is parked between its running proof and activation with the
// crash runner's `--hold-at`, which drives the internal probe and never
// activates, so the window under test is the one the entry exists for. The
// stub's recorded answer is read from the workspace bind mount, not through
// `docker exec` into the untrusted container.
//
// An unadmitted session is one the proxy has never heard of, so its packets are
// dropped rather than refused in-band, and the grant that ends the window is
// one sealed file write.
//
// The load-bearing half follows the negative tranche's rule: the same runtime
// must still serve the session once its file exists, which the case below
// asserts as an established CONNECT after release.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import {
  CRASH_LAUNCH_PREFIX,
  CRASH_PRECONDITION_EXIT,
  HELD_STATE_FILE,
  HOLD_RELEASE_FILE,
  type CrashLaunchReport,
  type HeldSessionState,
} from "../session-admission-crash.ts";
import { EARLY_ENTRY_RESPONSE_RELATIVE_PATH, stageEarlySendingSessionEntry } from "./agent-stub.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  assertFilesPathExercised,
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";
import { sessionAdmissionCrashEntryArgv } from "../../support/prebuilt-entry.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
/**
 * How long the stub may take to be answered once the lifecycle is held. The
 * hold lands after registration and the running proof, so the session's
 * packets already reach the proxy; the margin is for the stub's own retry
 * cadence and a slow daemon.
 */
const EARLY_ANSWER_WAIT_TIMEOUT_MS = 60_000;
const PROBE_AGENT = "claude" as const;

/*
 * The window this file is about: a session whose file does not exist yet is a
 * session the proxy has never heard of, so the firewall drops its packets and
 * the readiness probe's verdict is `EXIT_UNREACHABLE` (exit 4) until the file
 * is written, and 200 from then on. There is no in-band refusal to observe,
 * because there is nothing registered to refuse.
 */
/** How long the held window is sampled for an answer that must not arrive. */
const DROPPED_WINDOW_SAMPLE_MS = 5_000;
/** How long a launch may take to reach its pre-authority hold. */
const HELD_LAUNCH_WAIT_TIMEOUT_MS = 180_000;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the session entry gate tranche");
  }
  return backend;
}

type HeldLaunchRun = Readonly<{
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  state: HeldSessionState;
  /** Everything the launch has written so far, for a failure that is waiting on it. */
  output: () => string;
  release(): void;
}>;

/**
 * Starts a production launch and waits until it pauses just before it would be
 * granted any authority.
 *
 * The probe above never activates, so it can only ever show the pre-authority
 * window. This one shows both sides of it: held, the container is running with
 * no session file; released, the same launch writes the file and the session is
 * served. Only the production launch does the second half.
 */
async function holdLaunchBeforeAuthority(fixture: LiveFixture): Promise<HeldLaunchRun> {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-entry-gate-launch."));
  const child = childProcess.spawn(
    process.execPath,
    [
      ...sessionAdmissionCrashEntryArgv(),
      "--workspace",
      fixture.projectRoot,
      "--agent",
      PROBE_AGENT,
      "--launch",
      "--hold-dir",
      holdDir,
      "--launch-hold-at",
      "before-session-file-write",
    ],
    { cwd: REPO_ROOT, env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  const collect = (chunk: Buffer | string): void => {
    output += String(chunk);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);

  let exited: Readonly<{ status: number | null; output: string }> | undefined;
  const completion = new Promise<Readonly<{ status: number | null; output: string }>>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status) => {
      exited = Object.freeze({ status, output });
      resolve(exited);
    });
  });

  const statePath = path.join(holdDir, HELD_STATE_FILE);
  const deadline = Date.now() + HELD_LAUNCH_WAIT_TIMEOUT_MS;
  while (!fs.existsSync(statePath)) {
    if (exited) {
      const detail = exited.status === CRASH_PRECONDITION_EXIT
        ? "the project was not clean before the launch, so an earlier case failed to converge"
        : "the launch ended before reaching its pre-authority hold";
      throw new Error(`${detail}: ${describeOutput(exited.output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`the launch never reached before-session-file-write: ${describeOutput(output, 4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const state = JSON.parse(fs.readFileSync(statePath, "utf8")) as HeldSessionState;
  if (!state.reason.startsWith("before-session-file-write")) {
    throw new Error(`the launch published ${state.reason} rather than its pre-authority hold`);
  }
  return Object.freeze({
    completion,
    state,
    output: () => output,
    release: () => fs.writeFileSync(path.join(holdDir, HOLD_RELEASE_FILE), ""),
  });
}

function parseLaunchReport(run: Readonly<{ status: number | null; output: string }>): CrashLaunchReport {
  const line = run.output.split("\n").find((candidate) => candidate.startsWith(CRASH_LAUNCH_PREFIX));
  if (!line) {
    throw new Error(`the launch runner emitted no labelled report: ${describeOutput(run.output, 4000)}`);
  }
  return JSON.parse(line) as CrashLaunchReport;
}

/** Whether the early-sending entry has recorded any answer at all yet. */
function earlyAnswerRecorded(fixture: LiveFixture): boolean {
  return fs.existsSync(path.join(fixture.projectRoot, EARLY_ENTRY_RESPONSE_RELATIVE_PATH));
}

/**
 * Waits for the early-sending stub's recorded raw proxy answer.
 *
 * The released launch is the one writing the session file the answer depends
 * on, so its own output is the account of a stub that was never answered — a
 * bare "never recorded an answer" says only that this side of the runtime saw
 * nothing.
 */
async function earlyAnswer(fixture: LiveFixture, launch: HeldLaunchRun): Promise<string> {
  const responsePath = path.join(fixture.projectRoot, EARLY_ENTRY_RESPONSE_RELATIVE_PATH);
  const deadline = Date.now() + EARLY_ANSWER_WAIT_TIMEOUT_MS;
  while (!fs.existsSync(responsePath)) {
    if (Date.now() >= deadline) {
      throw new Error(
        "the early-sending entry never recorded an answer from the proxy;"
          + ` the released launch reported: ${describeOutput(launch.output(), 4000)}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return fs.readFileSync(responsePath, "latin1");
}

function clearEarlyAnswer(fixture: LiveFixture): void {
  fs.rmSync(path.join(fixture.projectRoot, path.dirname(EARLY_ENTRY_RESPONSE_RELATIVE_PATH)), {
    recursive: true,
    force: true,
  });
}

/** Removes leftover state through the runner's harness-only reset. */
async function forceClean(fixture: LiveFixture): Promise<void> {
  await new Promise<void>((resolve) => {
    const child = childProcess.spawn(
      process.execPath,
      [...sessionAdmissionCrashEntryArgv(), "--workspace", fixture.projectRoot, "--agent", PROBE_AGENT, "--force-clean"],
      { cwd: REPO_ROOT, env: fixture.env, stdio: ["ignore", "ignore", "ignore"] },
    );
    child.once("close", () => resolve());
    child.once("error", () => resolve());
  });
}

describe("a project image that replaces the session entry loses only the start ordering", () => {
  // Called for its validation: the tranche refuses to run without a named backend.
  requiredBackend();
  let fixture: LiveFixture;
  let project: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: stageEarlySendingSessionEntry });
    project = composeProjectName(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  afterEach(async () => {
    if (!fixture) return;
    await forceClean(fixture);
    clearEarlyAnswer(fixture);
  });

  test("an entry that sends at once is dropped before its session file exists and answered after it", async () => {
    // The file source's answer to the same question. A launch is parked after
    // its running proof and before the sealed inspect-and-write, so the
    // container is running with no session file: the proxy has never heard of
    // this address and the firewall drops its packets, which is what the base
    // image's readiness probe reports as `EXIT_UNREACHABLE` (exit 4). The stub
    // is louder than the probe — it re-sends every half second and records the
    // first answer it ever gets — so "dropped" is proven by there being no
    // recorded answer at all across the held window, and the grant is proven by
    // the same request being answered 200 once the file is written.
    // F10: the proxy is on the files path and this project starts empty, so
    // the drop below is the absence of a session file rather than a leftover
    // state from an earlier case.
    assertFilesPathExercised(fixture, composeServiceContainerId(project, "proxy"), [], "before the held launch");

    const launch = await holdLaunchBeforeAuthority(fixture);
    let containerId: string | undefined;
    let released = false;
    try {
      const [record] = launch.state.records;
      expect(record, `the held launch observed no record: ${JSON.stringify(launch.state)}`).toBeDefined();
      expect(record.state, "the session held authority before its file existed").not.toMatch(/^attached$/u);
      expect(record.containerId, "the held record names no container").toBeTruthy();
      containerId = String(record.containerId);

      // The running proof held the replaced entry to the planned Path here too.
      expect(dockerOrThrow("session container Path", [
        "container",
        "inspect",
        "--format",
        "{{.Path}}",
        containerId,
      ]).trim()).toBe("/usr/local/libexec/runfree/session-entry");

      const droppedUntil = Date.now() + DROPPED_WINDOW_SAMPLE_MS;
      while (Date.now() < droppedUntil) {
        expect(
          earlyAnswerRecorded(fixture),
          "the proxy answered a session that holds no session file, instead of its packets being dropped",
        ).toBe(false);
        await new Promise((resolve) => setTimeout(resolve, 250));
      }

      launch.release();
      released = true;
      // The same request, once the sealed write has published the file: the
      // session is served, so the CONNECT is established rather than dropped.
      const answer = await earlyAnswer(fixture, launch);
      expect(answer, `the served session's CONNECT was not established: ${describeOutput(answer)}`)
        .toMatch(/^HTTP\/1\.1 200 /u);
    } finally {
      if (!released) launch.release();
      if (containerId) docker(["kill", containerId]);
    }

    const report = parseLaunchReport(await launch.completion);
    expect(report.failure, `the launch failed rather than completing: ${report.failure}`).toBeUndefined();
    expect(report.after.lifecycleRegistryEmpty, "the served session left a lifecycle record").toBe(true);
    expect(report.after.residualContainers, "the served session left a session container").toBe(0);
    const residual = docker([
      "ps",
      "--all",
      "--quiet",
      "--filter",
      `label=com.docker.compose.project=${project}`,
      "--filter",
      "label=io.runfree.container-role=session-agent",
    ]);
    expect(residual.stdout.trim(), "the served session left a session container").toBe("");
  }, TEST_TIMEOUT_MS);
});
