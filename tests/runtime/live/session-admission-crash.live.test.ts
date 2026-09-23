// Crash live tranche for per-session admission.
//
// Granting a session its authority touches two places — the request-proxy
// registry and the firewall — so there is always a window in which only one has
// been updated. The design answers that with registry-first revocation: kill the
// identity before the packet filter, so whatever a crash leaves behind is inert
// rather than dangerous.
//
// This file kills the lifecycle at every exact transition its admission source
// has and asks the same two questions each time:
//
//   1. did the crash leave any record holding active authority?
//   2. does recovery reconcile the project back to empty?
//
// The kill is a real SIGKILL to the running lifecycle process, injected by
// watching the driver's own Docker command stream (see
// `../session-admission-crash.ts`). It is uncatchable, so no `finally` runs and
// no record is tidied on the way out — the state a host crash actually leaves.
//
// Each crash point is a separate `test`, so one surviving defect does not hide
// the others.
//
// Those transitions are the sealed session-file write and the ordered
// file-first teardown. The runner's own table selects them, and they are
// reached by parking a launch and killing its owner rather than by a
// command-stream kill, because the internal probe never activates.
//
// Crash points are named by the Docker command that completes the transition,
// never by a pre-measured command index. An absolute index was tried and is
// unreliable: the probe's command count varies between an untouched project and
// one that has already been crashed and reset (46 on a fresh run, 39 later), so
// a measured index selects a different moment on every run — or, as observed, a
// moment that never arrives. The two revocation points below give the same
// late-lifecycle coverage while remaining self-identifying.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import { startLivePhase } from "./timing.ts";
import { runfreeStateRoot } from "../../../packages/cli/src/paths.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  sessionContainerRecordsRoot,
} from "../../../packages/cli/src/runtime/session-containers.ts";
import { RESUME_STUB_DIRECTORY, stageLongLivedAgentBinary } from "./agent-stub.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  assertFilesPathExercised,
  forceCleanSessions,
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  readSessionFileEvidence,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";
import { runNominalAdmissionSlice } from "./session-admission-slice.ts";
import {
  CRASH_INJECTION_MARKER,
  CRASH_PRECONDITION_EXIT,
  CRASH_RECOVERY_PREFIX,
  CRASH_RESUME_PREFIX,
  HELD_STATE_FILE,
  launchCrashPoints,
  probeCrashPoints,
  type CrashPoint,
  type CrashRecoveryReport,
  type CrashResumeReport,
  type HeldSessionState,
} from "../session-admission-crash.ts";
import { sessionAdmissionCrashEntryArgv } from "../../support/prebuilt-entry.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;
/**
 * Grace period between the runner exiting and this harness stopping reading.
 *
 * Only covers bytes already written and not yet delivered. It is not a wait for
 * anything to finish: the runner is dead by then, and the only writer that could
 * still appear is an orphan whose output is not evidence about the crash.
 */
const ORPHAN_DRAIN_MS = 250;
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
const PROBE_AGENT = "claude" as const;

/** How long a launch may take to reach a held transition, cold daemon included. */
const HELD_LAUNCH_WAIT_TIMEOUT_MS = 180_000;

// States that mean the session may use the ordinary proxy path. A crash must
// never leave one behind, at any transition: the whole point of registry-first
// revocation is that leftover state cannot carry authority.
const AUTHORITY_BEARING_STATES = ["active", "attached"];

/**
 * The longest authority a crashed-away session can still hold.
 *
 * Mirrors `INTERNAL_PROBE_LEASE_DURATION_MS` in `session-admission-driver.ts`,
 * which is not exported. Duplicated rather than relaxed on purpose: if that
 * lease grows, this assertion should fail and be considered again rather than
 * quietly permit a longer window of unsupervised authority.
 */
const AUTHORITY_LEASE_MAX_MS = 5 * 60_000;

// `after-start` was skipped here behind TEST_RUNTIME_WHOLE_REGISTRY_RECOVERY=1
// while `recoverPending` refused any surviving lifecycle record: that crash
// leaves a leased provisioning-running record, which the drain path had no
// rule for. Preflight now reclaims records whose owning host process is gone,
// and the point passes on Docker Desktop, so the skip is gone rather than left
// switched off — the gate it protected no longer exists.

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the crash admission tranche");
  }
  return backend;
}

type CrashRun = Readonly<{ status: number | null; signal: NodeJS.Signals | null; output: string }>;

/**
 * Runs the crash runner and awaits its exit.
 *
 * Asynchronous `spawn` rather than `spawnSync`, deliberately. Each invocation
 * takes seconds, and `spawnSync` blocks the Vitest worker's event loop for that
 * whole time — long enough that the worker cannot service its RPC to the main
 * process. Vitest then reports `Error: [vitest-worker]: Timeout calling
 * "onTaskUpdate"` and abandons the run, which cost two other live files in the
 * same run. Reducing the number of blocking calls did not help and could not:
 * the starvation is per-call, not cumulative.
 *
 * Sequencing is unchanged — callers await each run in order — but the event
 * loop stays free between reads, so the worker keeps answering.
 */
async function runCrashScript(fixture: LiveFixture, args: readonly string[]): Promise<CrashRun> {
  return await new Promise<CrashRun>((resolve, reject) => {
    const child = childProcess.spawn(
      process.execPath,
      [...sessionAdmissionCrashEntryArgv(), "--workspace", fixture.projectRoot, "--agent", PROBE_AGENT, ...args],
      // Its own process group, so the orphans below can be reaped as a unit.
      { cwd: REPO_ROOT, detached: true, env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
    );
    let output = "";
    let truncated = false;
    const collect = (chunk: Buffer | string): void => {
      if (output.length >= CAPTURE_MAX_BYTES) {
        truncated = true;
        return;
      }
      output += String(chunk);
    };
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);
    child.once("error", reject);
    // Resolved on `exit` rather than `close`, and the difference is the whole
    // point: `close` waits for every inherited stdio pipe to be released, and
    // `docker container start --attach` is a separate process that survives the
    // runner's uncatchable SIGKILL. It held that pipe for as long as the session
    // container kept running, which was invisible while the launched agent
    // exited on its own and became a hang the moment one stayed up.
    //
    // The kill cannot be made tidy at the source — a crash that cleaned up after
    // itself would not be the state under test — so the tidying belongs here.
    child.once("exit", (status, signal) => {
      // A brief drain for output already in flight, then stop reading pipes an
      // orphan may still hold, and reap the group so nothing lingers into the
      // next case. Killing the attach client does not stop its container: that
      // container is the residue recovery is about to be asked to clear.
      setTimeout(() => {
        child.stdout?.destroy();
        child.stderr?.destroy();
        if (child.pid !== undefined) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            // The group is already gone, which is the ordinary case for every
            // selector that exits under its own control.
          }
        }
        resolve(Object.freeze({
          status,
          signal,
          output: truncated ? `${output}\n<output truncated at ${CAPTURE_MAX_BYTES} bytes>` : output,
        }));
      }, ORPHAN_DRAIN_MS);
    });
  });
}

type HeldOwner = Readonly<{
  /** Resolves when the held state file names a reason starting with `prefix`. */
  awaitReason(prefix: string, timeoutMs: number): Promise<HeldSessionState>;
  /**
   * SIGKILLs the owning host process group, leaving whatever the held
   * transition had reached.
   *
   * Uncatchable, so no `finally` runs: this is the crash, applied to a
   * transition that a hold has parked the lifecycle in. The group kill also
   * takes the `docker start --attach` client, which does not stop the container
   * it was showing — that container is part of the residue.
   */
  killOwner(): Promise<void>;
  discard(): void;
}>;

/**
 * Starts a production launch that parks at `point`, so the test can kill its
 * owner exactly there.
 *
 * The file-source points name transitions the internal probe never reaches (it
 * never activates, so it never writes a file) and that a command-stream kill
 * cannot select on its own (the launch is idle while its agent runs, issuing
 * nothing). Holding first and killing from outside gives the same state a real
 * crash leaves, at a transition this harness can actually name.
 */
function startHeldLaunchOwner(fixture: LiveFixture, args: readonly string[]): HeldOwner {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-crash-held-launch."));
  const child = childProcess.spawn(
    process.execPath,
    [
      ...sessionAdmissionCrashEntryArgv(),
      "--workspace", fixture.projectRoot,
      "--agent", PROBE_AGENT,
      "--launch", "--hold-dir", holdDir,
      ...args,
    ],
    // Its own process group, so the kill below reaps the attach client with it.
    { cwd: REPO_ROOT, detached: true, env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  const collect = (chunk: Buffer | string): void => {
    output += String(chunk);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  let exited = false;
  child.once("close", () => { exited = true; });
  child.once("error", () => { exited = true; });

  const statePath = path.join(holdDir, HELD_STATE_FILE);
  const readState = (): HeldSessionState | undefined => {
    try {
      return JSON.parse(fs.readFileSync(statePath, "utf8")) as HeldSessionState;
    } catch {
      // Absent, or caught mid-write; the next poll reads it.
      return undefined;
    }
  };
  const discard = (): void => {
    child.stdout?.destroy();
    child.stderr?.destroy();
    fs.rmSync(holdDir, { recursive: true, force: true });
  };
  return Object.freeze({
    async awaitReason(prefix: string, timeoutMs: number): Promise<HeldSessionState> {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const state = readState();
        if (state?.reason.startsWith(prefix)) return state;
        if (exited) {
          throw new Error(`the launch ended before reaching ${prefix}: ${describeOutput(output, 4000)}`);
        }
        if (Date.now() >= deadline) {
          if (child.pid !== undefined) {
            try { process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }
          }
          throw new Error(`the launch never reached ${prefix}: ${describeOutput(output, 4000)}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    },
    async killOwner(): Promise<void> {
      if (child.pid !== undefined) {
        try { process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }
      }
      await new Promise((resolve) => setTimeout(resolve, ORPHAN_DRAIN_MS));
    },
    discard,
  });
}

function parseCrashRecovery(run: CrashRun, label: string): CrashRecoveryReport {

  const line = run.output.split("\n").find((candidate) => candidate.startsWith(CRASH_RECOVERY_PREFIX));
  if (!line) {
    throw new Error(`${label} emitted no labelled recovery report: ${describeOutput(run.output, 4000)}`);
  }
  return JSON.parse(line) as CrashRecoveryReport;
}

function parseCrashResume(run: CrashRun, label: string): CrashResumeReport {
  const line = run.output.split("\n").find((candidate) => candidate.startsWith(CRASH_RESUME_PREFIX));
  if (!line) {
    throw new Error(`${label} emitted no labelled resume report: ${describeOutput(run.output, 4000)}`);
  }
  return JSON.parse(line) as CrashResumeReport;
}

describe("per-session admission survives a crash at every transition", () => {
  const backend = requiredBackend();
  let fixture: LiveFixture;
  let runtimeDestroyed = false;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: stageLongLivedAgentBinary });
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  /**
   * What a crash may leave behind: records, but none carrying authority —
   * except an attached record whose authority is provably bounded by one lease.
   */
  function assertCrashAuthorityBounded(
    records: CrashRecoveryReport["before"]["records"],
    label: string,
    attachedAuthorityExpected: boolean,
  ): void {
    // No record may carry authority — except where the crash happened *in* the
    // authority-bearing state, which
    // no amount of correctness can undo: the host that would have revoked the
    // record is the process that just died, and its session container is still
    // running. Demanding no attached record there would be demanding that a
    // SIGKILL run cleanup code.
    //
    // The property that survives is that the authority is bounded rather than
    // indefinite. Only a live host renews a lease and the proxy rejects an
    // expired one, so a record whose owner is gone stops being honoured on its
    // own, and recovery clears it. Asserting the bound is what keeps this
    // an invariant instead of an exemption.
    let attachedAuthority = 0;
    for (const record of records) {
      if (attachedAuthorityExpected && record.state === "attached") {
        attachedAuthority += 1;
        const expiresAtMs = record.leaseExpiresAt === null ? Number.NaN : Date.parse(record.leaseExpiresAt);
        expect(
          Number.isFinite(expiresAtMs),
          `a crash ${label} left session ${record.sessionId} attached with no readable lease expiry`
            + ` (${record.leaseExpiresAt}), so its authority has no proven end`,
        ).toBe(true);
        expect(
          expiresAtMs,
          `a crash ${label} left session ${record.sessionId} attached with authority reaching past one lease`,
        ).toBeLessThanOrEqual(Date.now() + AUTHORITY_LEASE_MAX_MS);
        continue;
      }
      expect(
        AUTHORITY_BEARING_STATES,
        `a crash ${label} left session ${record.sessionId} in the authority-bearing state ${record.state}`,
      ).not.toContain(record.state);
    }
    if (attachedAuthorityExpected) {
      // Without this the case passes when the crash lands anywhere else, which
      // is exactly how a selector that stopped matching would look.
      expect(
        attachedAuthority,
        `a crash ${label} was meant to happen with a session attached, but no attached record survived it`,
      ).toBeGreaterThan(0);
    }
  }

  /** Crashes with the given selector, then asserts the two invariants. */
  async function assertCrashLeavesNoAuthorityAndRecovers(
    selector: readonly string[],
    label: string,
  ): Promise<void> {
    const crashed = await runCrashScript(fixture, selector);

    // Exit 4: an earlier case failed to converge and left residue, so this one
    // would be testing that residue rather than its own crash. The earlier
    // failure is the one to read.
    if (crashed.status === CRASH_PRECONDITION_EXIT) {
      throw new Error(
        `the project was not clean before crashing at ${label}, so nothing was tested; an earlier case failed to converge: ${describeOutput(crashed.output, 2000)}`,
      );
    }
    // Exit 3: the runner's own "the transition never happened" signal. A kill
    // point that silently stopped matching would otherwise present as a clean
    // run and prove nothing.
    if (crashed.status === 3) {
      throw new Error(
        `crash point ${label} never occurred, so nothing was tested; the observed Docker command stream follows: ${describeOutput(crashed.output, 4000)}`,
      );
    }
    // Checked through the runner's own marker rather than the exit signal: the
    // marker names the transition the kill landed in, while a SIGKILL alone
    // would look the same from any point. SIGKILL is uncatchable, so this line
    // followed by no completion is proof the crash landed where it says.
    expect(
      crashed.output,
      `the lifecycle process did not report a crash at ${label}: ${describeOutput(crashed.output, 4000)}`,
    ).toContain(CRASH_INJECTION_MARKER);
    expect(crashed.status, `the crashed lifecycle process at ${label} exited cleanly`).not.toBe(0);

    // One invocation reports both sides of recovery. Recovery is the product's
    // own reconciliation, not a cleanup this test performs.
    const recovery = parseCrashRecovery(await runCrashScript(fixture, ["--recover"]), `recovery after ${label}`);

    // What the crash left behind. Records are expected — the crash happened
    // mid-lifecycle — but none may carry authority. Requiring at least one is
    // the vacuity guard: a named kill point fires only after allocation has
    // durably written a record, so an empty registry here means the kill
    // landed somewhere other than the transition it names.
    expect(
      recovery.before.records.length,
      `a crash ${label} left no lifecycle record at all, so the kill did not land inside the admission it names;`
        + ` the crashed run's output follows: ${describeOutput(crashed.output, 4000)}`,
    ).toBeGreaterThan(0);
    assertCrashAuthorityBounded(recovery.before.records, label, false);

    // The failure message carries the field-level diagnosis, because "record
    // and live container identity differ" names the conclusion and not the
    // cause, and finding the cause any other way costs a full live cycle.
    const diagnosis = (recovery.diagnosis ?? []).map((entry) => {
      const fields = entry.differences
        .map((difference) => `      ${difference.field}: record=${difference.record} container=${difference.container}`)
        .join("\n");
      const endpoint = entry.rawContainerShape === undefined
        ? ""
        : `\n      raw container shape from the daemon: ${JSON.stringify(entry.rawContainerShape)}`;
      return `    session ${entry.sessionId} record.state=${entry.recordState} container=${entry.containerId.slice(0, 12)}`
        + ` running=${entry.containerRunning} malformedMetadata=${entry.malformedInventoryMetadata}\n${fields}${endpoint}`;
    }).join("\n");
    expect(
      recovery.recovered,
      `recovery after a crash ${label} failed: ${describeOutput(recovery.failure ?? "<no failure reported>", 2000)}`
        + (diagnosis ? `\n  record/container differences:\n${diagnosis}` : ""),
    ).toBe(true);
    expect(recovery.after.lifecycleRegistryEmpty, `recovery after ${label} left lifecycle records behind`).toBe(true);
    expect(recovery.after.residualContainers, `recovery after ${label} left session containers behind`).toBe(0);
  }

  // Harness reset between cases, not an assertion. When the product's recovery
  // cannot converge, the residue makes every later case fail for an inherited
  // reason and only the first crash point gets tested. Clearing it costs the
  // cascade but buys coverage of the remaining points in the same run — and any
  // case that needed it has already failed its own recovery assertion.
  afterEach(async () => {
    if (!fixture || runtimeDestroyed) return;
    await forceCleanSessions(fixture);
  });

  // No occurrence overrides. `after-running-inspect` shares its subcommand
  // with preflight's whole-inventory reconciliation, whose batch count varies
  // with how many containers the whole daemon holds (observed live,
  // 2026-08-31: two 60-id inventory chunks fired before allocation, so both
  // occurrence 1 and 2 selected a pre-allocation moment and the vacuity guard
  // above refused the run — exactly the silent-vacuity failure it exists for).
  // The runner therefore arms that point by order instead: the first
  // `container inspect` after the foreground `container start` is, by the
  // ladder's own definition, the single post-start inspection.
  //
  // The point list is the runner's own: the internal probe never activates, so
  // it never writes a session file, and asking for a file transition would fail
  // as "never occurred" rather than prove anything.
  for (const point of probeCrashPoints()) {
    test(`a crash ${point} leaves no authority and recovers to empty`, async () => {
      await assertCrashLeavesNoAuthorityAndRecovers(["--kill-at", point], point);
    }, TEST_TIMEOUT_MS);
  }

  // The case every named point above misses, and the one that matters most.
  //
  // All six kill inside a discrete operation, where a transaction journal
  // exists on disk and recovery has something to reconcile against. A real
  // session spends almost none of its life there: it spends it attached, with
  // no operation running, no journal written, and no Docker command to name a
  // moment by. That is the state an ordinary kill lands in — a closed terminal,
  // a sleeping laptop, the OOM killer — and until preflight learned to reclaim
  // records whose owner is gone, reaching it meant the project could admit no
  // further session at all.
  //
  // It is also the first live exercise of `launchBuiltin` anywhere: every other
  // tranche drives the probe, which proves the session and tears it down
  // without ever activating.
  //
  // Ordering item 2, recovery integration: after the ordinary kill — a closed
  // terminal, a dead laptop — the interrupted conversation must come back as a
  // *new* validated lifecycle session created through the admission path. The
  // crashed container is residue to reclaim, never a resume target, and the
  // typed resume argv must be what actually launches in the new container.
  test("a crashed attached session resumes into a new lifecycle session, never the old container", async () => {
    const crashed = await runCrashScript(fixture, ["--kill-when-attached"]);
    expect(
      crashed.output,
      `no attached crash landed, so there was nothing to resume: ${describeOutput(crashed.output, 4000)}`,
    ).toContain(CRASH_INJECTION_MARKER);

    const composeProject = composeProjectName(fixture);
    const projectId = composeProject.replace(/^runfree-/u, "");
    const stateDir = path.join(runfreeStateRoot(fixture.env), "projects", projectId);
    const identity = { projectId, composeProject };
    const oldIds = new Set(listSessionContainerRecordsV2(stateDir, identity).map((record) => record.sessionId));
    const stubDir = path.join(fixture.projectRoot, RESUME_STUB_DIRECTORY);
    fs.rmSync(stubDir, { recursive: true, force: true });
    const finishResume = startLivePhase("crash: resume through fresh admission");
    let completed = false;
    const resumed = runCrashScript(fixture, ["--resume"]).then((result) => { completed = true; return result; });
    try {
      const deadline = Date.now() + HELD_LAUNCH_WAIT_TIMEOUT_MS;
      for (;;) {
        const attached = listSessionContainerRecordsV2(stateDir, identity)
          .find((record) => record.state === "attached" && !oldIds.has(record.sessionId));
        if (attached && fs.existsSync(path.join(stubDir, "ready"))) {
          assertFilesPathExercised(fixture, composeServiceContainerId(composeProject, "proxy"), [attached.sourceIp], "resumed session before normal exit");
          break;
        }
        if (completed) throw new Error(`resume ended before fresh attachment: ${(await resumed).output}`);
        if (Date.now() > deadline) throw new Error("resumed agent never reached its ready/attached handshake");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    } finally {
      fs.mkdirSync(stubDir, { recursive: true });
      fs.writeFileSync(path.join(stubDir, "release"), "");
      await resumed;
      finishResume();
    }
    const resume = parseCrashResume(await resumed, "resume after an attached crash");

    // Vacuity guard: the crash must have left the record the resume is about.
    const crashedSessions = resume.before.records.map((record) => record.sessionId);
    expect(crashedSessions.length, "the crash left no lifecycle record to resume past").toBeGreaterThan(0);
    // What the crash left carried authority bounded by one lease, and it was
    // attached — not a crash that landed somewhere else.
    assertCrashAuthorityBounded(resume.before.records, "an attached session", true);

    expect(
      resume.failure,
      `resume through admission failed: ${describeOutput(resume.failure ?? "", 4000)}`,
    ).toBeUndefined();
    // The stub agent exits 0 only when launched with the resume argv, so this
    // status is itself proof the typed argv reached the new container. Evidence
    // consumption requires the fingerprint to still match after completion.
    expect(resume.outcome).toEqual({ status: 0, consumed: true });

    // The new session container was created with the typed resume argv and a
    // new session identity — never the crashed session's name or container.
    const createCommand = resume.observedCommands.find((command) => command.startsWith("container create"));
    expect(createCommand, "no session container create was observed during resume").toBeDefined();
    expect(createCommand).toContain("--resume");
    for (const sessionId of crashedSessions) {
      expect(
        createCommand,
        `resume reused the crashed session identity ${sessionId}`,
      ).not.toContain(sessionId);
    }

    // The resumed session completed and revoked itself, and the crashed
    // residue was reclaimed on the way in: nothing survives on either side.
    expect(resume.after.lifecycleRegistryEmpty, "resume left lifecycle records behind").toBe(true);
    expect(resume.after.residualContainers, "resume left session containers behind").toBe(0);
  }, TEST_TIMEOUT_MS);

  // -------------------------------------------------------------------------
  // Per-session file source: the three transitions the probe cannot reach.
  //
  // The points above are all inside the internal probe, which never activates —
  // so under this source it never writes a session file, and the file-first
  // teardown it does run has nothing to take away. The interesting states are
  // an admission that has just granted authority, and a teardown that has (or
  // has not) managed to withdraw it. Both are reached by parking a production
  // launch there and killing its owner from outside, which leaves exactly what
  // a real crash leaves and names the transition it landed in.
  //
  // The question is the same one the whole file asks: does the next launch's
  // reconcile — `recoverPending`, which is the preflight every launch runs
  // before it allocates — bring the project back to empty?
  // -------------------------------------------------------------------------

  /**
   * Parks a launch at `point`, kills its owner there, and asserts the next
   * launch's reconcile converges the project to empty.
   *
   * `endSessionFirst` drives the teardown points: teardown only starts when the
   * agent ends, and the long-lived stub never does on its own.
   */
  async function assertHeldOwnerCrashRecovers(
    point: CrashPoint,
    options: Readonly<{ endSessionFirst: boolean; extraArgs?: readonly string[] }>,
  ): Promise<void> {
    const proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");
    // F10: this project starts empty — without that, the convergence asserted
    // below could be describing an earlier case's residue.
    assertFilesPathExercised(fixture, proxyId, [], `before crashing at ${point}`);
    const owner = startHeldLaunchOwner(fixture, ["--launch-hold-at", point, ...(options.extraArgs ?? [])]);
    let killed = false;
    try {
      if (options.endSessionFirst) {
        const attached = await owner.awaitReason("attached", HELD_LAUNCH_WAIT_TIMEOUT_MS);
        const [record] = attached.records;
        expect(record, `the launch observed no attached record: ${JSON.stringify(attached)}`).toBeDefined();
        expect(record.containerId, "the attached record names no container to end").toBeTruthy();
        // The session file is the authority; it must exist before a teardown
        // point can prove anything about withdrawing it.
        expect(
          readSessionFileEvidence(proxyId).files.length,
          "the attached session holds no session file, so the teardown point below would prove nothing",
        ).toBe(1);
        docker(["kill", String(record.containerId)]);
      }
      const held = await owner.awaitReason(point, HELD_LAUNCH_WAIT_TIMEOUT_MS);
      expect(
        held.records.length,
        `a launch held at ${point} shows no lifecycle record, so the hold did not land inside the admission it names`,
      ).toBeGreaterThan(0);
      const filesAtHold = readSessionFileEvidence(proxyId).files.length;
      if (point === "after-file-deleted-before-stop") {
        expect(filesAtHold, "the delete did not take the session file away before the hold").toBe(0);
      } else {
        expect(filesAtHold, `a launch held at ${point} holds no session file`).toBe(1);
      }
      await owner.killOwner();
      killed = true;
    } finally {
      if (!killed) await owner.killOwner();
      owner.discard();
    }

    // The next launch's reconcile, run on its own: the same preflight every
    // launch performs before it allocates.
    const recovery = parseCrashRecovery(await runCrashScript(fixture, ["--recover"]), `recovery after ${point}`);
    expect(
      recovery.before.records.length,
      `a crash at ${point} left no lifecycle record at all, so the kill did not land inside the admission it names`,
    ).toBeGreaterThan(0);
    expect(
      recovery.recovered,
      `recovery after a crash at ${point} failed: ${describeOutput(recovery.failure ?? "<no failure reported>", 2000)}`,
    ).toBe(true);
    expect(recovery.after.lifecycleRegistryEmpty, `recovery after ${point} left lifecycle records behind`).toBe(true);
    expect(recovery.after.residualContainers, `recovery after ${point} left session containers behind`).toBe(0);
    expect(
      readSessionFileEvidence(proxyId).files,
      `recovery after ${point} left a session file published, so the proxy would still serve a dead session`,
    ).toEqual([]);
  }

  for (const point of launchCrashPoints()) {
    test(`a crash ${point} leaves no served session and recovers to empty`, async () => {
      await assertHeldOwnerCrashRecovers(point, {
        // Only the admission point happens on the way in; the other two are
        // teardown steps, which need the agent to have ended.
        endSessionFirst: point !== "after-session-file-write",
        // The refused delete is refused because the harness refuses it; the
        // runner pairs the two so neither can be asked for alone.
        ...(point === "after-failed-file-delete" ? { extraArgs: ["--fail-session-file-delete"] } : {}),
      });
    }, TEST_TIMEOUT_MS);
  }

  test("the runtime still admits a session after every crash and recovery", () => {
    // The load-bearing close: six crashes and six recoveries must leave a
    // runtime that still works. A recovery that reconciled records while
    // quietly breaking admission would pass every assertion above.
    runNominalAdmissionSlice({ fixture, backend, agent: PROBE_AGENT, expect: "success" });
  }, TEST_TIMEOUT_MS);

  // Last on purpose: it ends the runtime. This is the assertion that would
  // have caught the taxonomy design's defect 1 — session containers are not
  // Compose resources, so the old one-Compose-call destroy left them running
  // and their records behind. Everything is read back from the daemon and the
  // state directory, never from destroy's own output.
  test("one plain destroy clears an attached-crash residue: no session container, no Compose container, empty registry", async () => {
    const crashed = await runCrashScript(fixture, ["--kill-when-attached"]);
    expect(
      crashed.output,
      `no attached crash landed, so destroy had no residue to clear: ${describeOutput(crashed.output, 4000)}`,
    ).toContain(CRASH_INJECTION_MARKER);

    // Vacuity guards: the sweep key is the daemon's own project-id label, read
    // off a live container rather than recomputed from the workspace path, and
    // both container kinds must actually exist before destroy runs.
    const composeProject = composeProjectName(fixture);
    const composeIds = dockerOrThrow("pre-destroy Compose containers", [
      "ps", "-aq", "--no-trunc", "--filter", `label=com.docker.compose.project=${composeProject}`,
    ]).trim().split(/\s+/).filter(Boolean);
    expect(composeIds.length, "no Compose containers existed before destroy").toBeGreaterThan(0);
    const projectId = dockerOrThrow("project-id label", [
      "container", "inspect", "--format", '{{ index .Config.Labels "io.runfree.project-id" }}', composeIds[0] ?? "",
    ]).trim();
    expect(projectId).toMatch(/^[0-9a-f]{12}$/);
    const sessionIds = dockerOrThrow("pre-destroy session containers", [
      "ps", "-aq", "--no-trunc",
      "--filter", `label=io.runfree.project-id=${projectId}`,
      "--filter", "label=io.runfree.container-role=session-agent",
    ]).trim().split(/\s+/).filter(Boolean);
    expect(sessionIds.length, "the crash left no session container behind").toBeGreaterThan(0);

    // Plain destroy, not --force: the crashed client is provably dead, so its
    // record is stale rather than live, and the ordinary remedy must suffice.
    const destroyed = fixture.runfree(["destroy"]);
    expect(destroyed.status, `destroy failed: ${describeOutput(destroyed.output, 4000)}`).toBe(0);

    const remaining = dockerOrThrow("post-destroy project scan", [
      "ps", "-aq", "--no-trunc", "--filter", `label=io.runfree.project-id=${projectId}`,
    ]).trim();
    expect(remaining, `containers carrying ${projectId} survived destroy: ${remaining}`).toBe("");

    const stateDir = path.join(runfreeStateRoot(fixture.env), "projects", projectId);
    expect(
      fs.existsSync(sessionContainerRecordsRoot(stateDir)),
      "lifecycle records survived destroy",
    ).toBe(false);
    expect(listQuarantinedSessionContainerRecordNamesV2(stateDir)).toEqual([]);
    runtimeDestroyed = true;
  }, TEST_TIMEOUT_MS);
});
