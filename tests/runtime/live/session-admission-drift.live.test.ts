// Live tranche for what changes underneath a session mid-lifecycle.
//
// The nominal tranche proves the sequence completes; the crash tranche proves
// what survives when the process dies. This one proves what happens when the
// process stays alive and the *world* changes: a competitor takes the address
// before the container starts, or a second network is attached after it does.
//
// Both need the lifecycle paused at an exact transition, which the crash
// runner's `--hold-at` provides through the same command-stream seam the kill
// uses. Racing a probe that completes in seconds is not an option — it would be
// nondeterministic, and a drift test that sometimes acts too late is a test
// that sometimes proves nothing.
//
// Not covered here: session grant separation, which the attached tranche
// proves. Drift detected *after*
// a container has been proven IS covered — by the attached tranche, which
// drives the production launch path and proves lease renewal refuses
// post-proof drift against a fresh exact Docker inspection.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import {
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";
import {
  composeProjectName,
  projectAgentImageId,
  docker,
  forceRemoveContainer,
  internalNetworkId,
  LIVE_TEST_LABEL,
} from "./docker.ts";
import {
  CRASH_HOLD_TIMEOUT_EXIT,
  CRASH_PRECONDITION_EXIT,
  CRASH_RECOVERY_PREFIX,
  CRASH_REPORT_PREFIX,
  HELD_STATE_FILE,
  HOLD_RELEASE_FILE,
  type CrashPoint,
  type CrashRecoveryReport,
  type CrashReport,
  type HeldSessionState,
} from "../session-admission-crash.ts";
import { sessionAdmissionCrashEntryArgv } from "../../support/prebuilt-entry.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
const HELD_WAIT_TIMEOUT_MS = 90_000;
const PROBE_AGENT = "claude" as const;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the drift admission tranche");
  }
  return backend;
}

type HeldRun = Readonly<{
  /** Resolves when the held lifecycle process exits. */
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  state: HeldSessionState;
  release(): void;
}>;

/**
 * Starts a lifecycle, waits until it pauses at `point`, and hands back its
 * observed state plus a release trigger.
 *
 * The caller acts on the live world while the lifecycle is stopped, then
 * releases it and asserts on how it finished.
 */
async function holdAt(
  fixture: LiveFixture,
  point: CrashPoint,
  occurrence?: number,
): Promise<HeldRun> {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-hold."));
  const child = childProcess.spawn(
    process.execPath,
    [
      ...sessionAdmissionCrashEntryArgv(),
      "--workspace",
      fixture.projectRoot,
      "--agent",
      PROBE_AGENT,
      "--hold-at",
      point,
      ...(occurrence ? ["--occurrence", String(occurrence)] : []),
      "--hold-dir",
      holdDir,
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
  const deadline = Date.now() + HELD_WAIT_TIMEOUT_MS;
  while (!fs.existsSync(statePath)) {
    if (exited) {
      // Exited before holding. Distinguish a dirty project from a genuine
      // lifecycle failure, because they need different responses.
      const detail = exited.status === CRASH_PRECONDITION_EXIT
        ? "the project was not clean before the hold, so an earlier case failed to converge"
        : "the lifecycle exited before reaching the hold point";
      throw new Error(`${detail}: ${describeOutput(exited.output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`the lifecycle never reached ${point}: ${describeOutput(output, 4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const state = JSON.parse(fs.readFileSync(statePath, "utf8")) as HeldSessionState;
  return Object.freeze({
    completion,
    state,
    release: () => fs.writeFileSync(path.join(holdDir, HOLD_RELEASE_FILE), ""),
  });
}

/**
 * Runs `body` against a held lifecycle and always lets that lifecycle go.
 *
 * Without this, an assertion that throws before the release leaves the child
 * blocked for the full hold timeout while it still owns the project lifecycle
 * lock — so the failure that mattered is followed by a cascade of unrelated
 * lock and residue failures in every later case.
 */
async function withHeldLifecycle<T>(
  fixture: LiveFixture,
  point: CrashPoint,
  body: (held: HeldRun) => Promise<T>,
): Promise<T> {
  const held = await holdAt(fixture, point);
  try {
    return await body(held);
  } finally {
    held.release();
    // Awaited so the lifecycle lock is demonstrably free before the next case
    // starts, rather than racing it.
    await held.completion.catch(() => undefined);
  }
}

/** Runs the crash runner in a given mode and resolves with its full output. */
async function crashRunner(fixture: LiveFixture, args: readonly string[]): Promise<string> {
  return await new Promise<string>((resolve) => {
    let output = "";
    const child = childProcess.spawn(
      process.execPath,
      [...sessionAdmissionCrashEntryArgv(), "--workspace", fixture.projectRoot, "--agent", PROBE_AGENT, ...args],
      { cwd: REPO_ROOT, env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
    );
    child.stdout?.on("data", (chunk: Buffer) => (output += String(chunk)));
    child.stderr?.on("data", (chunk: Buffer) => (output += String(chunk)));
    child.once("close", () => resolve(output));
    child.once("error", () => resolve(output));
  });
}

function parseLabelledLine<T>(output: string, prefix: string, label: string): T {
  const line = output.split("\n").find((candidate) => candidate.startsWith(prefix));
  if (!line) throw new Error(`${label}: the runner emitted no labelled result: ${describeOutput(output, 2000)}`);
  return JSON.parse(line) as T;
}

/** The registry and container inventory as they stand, with no side effect. */
async function readCrashReport(fixture: LiveFixture, label: string): Promise<CrashReport> {
  return parseLabelledLine<CrashReport>(await crashRunner(fixture, ["--report"]), CRASH_REPORT_PREFIX, label);
}

/** Runs the product's own recovery and returns both sides of it. */
async function recoverProject(fixture: LiveFixture, label: string): Promise<CrashRecoveryReport> {
  return parseLabelledLine<CrashRecoveryReport>(
    await crashRunner(fixture, ["--recover"]),
    CRASH_RECOVERY_PREFIX,
    label,
  );
}

/**
 * Asserts the product left nothing behind — before any harness cleanup runs.
 *
 * Order matters and is the whole point: `--force-clean` removes lifecycle
 * records and containers directly, so calling it first would make a leaked
 * container or record indistinguishable from a clean teardown.
 */
async function assertProjectClean(fixture: LiveFixture, label: string): Promise<void> {
  const report = await readCrashReport(fixture, label);
  expect(report.lifecycleRegistryEmpty, `${label} left a lifecycle record behind`).toBe(true);
  expect(report.residualContainers, `${label} left a session container behind`).toBe(0);
}

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

describe("per-session admission under drift", () => {
  void requiredBackend();
  let fixture: LiveFixture;
  let project: string;
  let networkId: string;
  let agentImage: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT });
    project = composeProjectName(fixture);
    networkId = internalNetworkId(project);
    // The image the runtime already built, so the competitor needs no pull and
    // the tranche has no network dependency of its own. Resolved by daemon
    // labels: the cutover removed the shared `agent` Compose service, so there
    // is no running container to read it from.
    agentImage = projectAgentImageId(project);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  afterEach(async () => {
    if (!fixture) return;
    await forceClean(fixture);
  });

  test("a competitor holding the session address makes the launch fail closed", async () => {
    // Start failure, caused the way it would really happen: something else owns
    // the address by the time the container tries to start. The session's
    // address is not predictable from outside, so the lifecycle is paused after
    // create to read it, then the competitor takes it before the start.
    const competitor = "runfree-drift-address-competitor";
    forceRemoveContainer(competitor);
    try {
      await withHeldLifecycle(fixture, "after-create", async (held) => {
        const [record] = held.state.records;
        expect(record, `the hold reported no lifecycle record: ${JSON.stringify(held.state)}`).toBeDefined();
        expect(record.sourceIp).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/u);

        const started = docker([
          "run",
          "-d",
          "--name",
          competitor,
          "--label",
          `${LIVE_TEST_LABEL}=drift`,
          "--network",
          networkId,
          "--ip",
          record.sourceIp,
          agentImage,
          "sleep",
          "600",
        ]);
        // If the competitor cannot start, the premise is gone and the result
        // below would be meaningless.
        expect(started.status, `could not occupy ${record.sourceIp}: ${describeOutput(started.output)}`).toBe(0);

        held.release();
        const finished = await held.completion;
        expect(finished.status, "the lifecycle completed even though its address was taken").not.toBe(0);
        expect(finished.status, "the hold was never released").not.toBe(CRASH_HOLD_TIMEOUT_EXIT);
      });

      // Asserted, not performed — and scoped to what the product can prove
      // while the competitor still squats the session's address. Registry-first
      // revocation and Docker teardown ran, so no session container and no
      // authority-bearing record may survive. The lifecycle record itself is
      // allowed to: `proveSessionContainerAbsent` refuses to declare an address
      // absent while *any* container holds it — removing the record would free
      // the IP for reallocation underneath the squatter — so a surviving record
      // in the non-authority `revoking` state is the fail-closed outcome, not a
      // leak. This assertion's first live contact (2026-08-17) demanded an
      // empty registry at this point, which demanded the product declare a
      // squatted address abandoned; that was this test's defect, not the
      // product's.
      // `residualContainers` counts reconciliation *classifications*, not
      // containers, and the squatter itself is one: it runs the project's
      // agent image and holds the record's source IP, so the surviving record
      // and the competitor classify together as a mismatch. Asserting zero
      // here asserts the harness's own container (second live lesson from this
      // case, 2026-08-17). The no-container/no-record completeness claim lives
      // in the recovery step below, where the world is sane again; the claim
      // that belongs to this moment is only that nothing carries authority.
      // Several fail-closed exits can leave the record, and which one fires
      // depends on where the lost address race surfaces — the same
      // layer-independence the negative tranche's unknown-participant case
      // records. If the failed `docker start` is noticed inside create-start,
      // the unadmitted cleanup runs and the record survives as `allocated` or
      // `provisioning-running` (the durable transition lands before the spawn,
      // and the absence proof rightly refuses to clear a record while the
      // squatter holds its address); if the exited foreground is noticed at
      // registration or the running proof, paired revocation runs and it
      // survives as `revoking`. All are authority-free — a provisioning-running
      // record the proxy never learned of, or learned of only as provisioning,
      // grants no ordinary traffic — and pinning one of them asserts
      // scheduling, not security.
      const report = await readCrashReport(fixture, "after the taken-address failure");
      for (const record of report.records) {
        expect(
          ["allocated", "provisioning-running", "revoking"],
          `a launch that failed on a taken address left session ${record.sessionId} in state ${record.state}, which can carry authority`,
        ).toContain(record.state);
      }

      // Once the squatter is gone, the product's own recovery must finish what
      // the absence proof correctly refused: prove the address absent and clear
      // the record, converging the project to empty with no harness reset.
      forceRemoveContainer(competitor);
      const recovery = await recoverProject(fixture, "recovery after the taken-address failure");
      expect(recovery.recovered, `recovery did not converge after the squatter left: ${recovery.failure ?? ""}`).toBe(true);
      expect(recovery.after.lifecycleRegistryEmpty, "recovery left a lifecycle record behind").toBe(true);
      expect(recovery.after.residualContainers, "recovery left a session container behind").toBe(0);
    } finally {
      forceRemoveContainer(competitor);
    }
  }, TEST_TIMEOUT_MS);

  test("a second network attached before the running proof is rejected", async () => {
    // The single-inspection ladder's required drift negative: `after-start`
    // fires when `docker container start --attach` is *issued* — before
    // registration and the one post-start inspection. The extra network is in
    // place by the time that single proof runs, and the proof refuses a
    // container attached to two networks before activation ever spends it, so
    // the session never gains proxy authority.
    //
    // Post-proof drift cannot be reached from this seam at all: the probe
    // revokes immediately after the running proof and never renews, and drift
    // after the proof is caught by lease renewal, which only runs in the launch
    // path. Recorded as owed rather than approximated here — a test whose
    // stated goal exceeds what it checks is the failure mode this suite exists
    // to catch.
    const extra = "runfree-drift-extra-network";
    docker(["network", "rm", extra]);
    try {
      await withHeldLifecycle(fixture, "after-start", async (held) => {
        const [record] = held.state.records;
        expect(record, `the hold reported no lifecycle record: ${JSON.stringify(held.state)}`).toBeDefined();
        expect(record.containerId, "the held record has no container id to drift").toBeTruthy();

        const created = docker(["network", "create", "--label", `${LIVE_TEST_LABEL}=drift`, extra]);
        expect(created.status, `could not create the drift network: ${describeOutput(created.output)}`).toBe(0);

        const connected = docker(["network", "connect", extra, String(record.containerId)]);
        expect(
          connected.status,
          `could not attach a second network to the session container: ${describeOutput(connected.output)}`,
        ).toBe(0);

        held.release();
        const finished = await held.completion;
        expect(
          finished.status,
          "the running proof accepted a session container attached to a second network",
        ).not.toBe(0);
        expect(finished.status, "the hold was never released").not.toBe(CRASH_HOLD_TIMEOUT_EXIT);
      });

      await assertProjectClean(fixture, "a launch that failed on an extra network");
    } finally {
      await forceClean(fixture);
      docker(["network", "rm", extra]);
    }
  }, TEST_TIMEOUT_MS);

  test("a reused source address gets a fresh session incarnation", async () => {
    // The recycling invariant, at the identity layer: when an address is freed
    // and handed to the next session, that session must be a new principal
    // rather than a continuation of the last one.
    //
    // The grant half — that session B inherits none of A's approvals — needs the
    // proxy keyed to source-IP identity, which only exists after the Phase B
    // cutover. What is provable now is that the identity bound to the address is
    // fresh, which is the precondition for that grant separation.
    const firstRecord = await withHeldLifecycle(fixture, "after-create", async (held) => {
      const [record] = held.state.records;
      expect(record).toBeDefined();
      return record;
    });
    await forceClean(fixture);

    const secondRecord = await withHeldLifecycle(fixture, "after-create", async (held) => {
      const [record] = held.state.records;
      expect(record).toBeDefined();
      return record;
    });

    expect(
      secondRecord.sourceIp,
      "the second session did not reuse the freed address, so this proves nothing about reuse",
    ).toBe(firstRecord.sourceIp);
    expect(secondRecord.sessionIncarnation).not.toBe(firstRecord.sessionIncarnation);
    expect(secondRecord.sessionId).not.toBe(firstRecord.sessionId);
  }, TEST_TIMEOUT_MS);
});
