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
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import { startLivePhase } from "./timing.ts";
import { runfreeStateRoot } from "../../../packages/cli/src/paths.ts";
import { scanRecoveryInventory } from "../../../packages/cli/src/runtime/recovery.ts";
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
  CRASH_REPORT_PREFIX,
  CRASH_RESUME_PREFIX,
  HELD_STATE_FILE,
  launchCrashPoints,
  probeCrashPoints,
  type CrashPoint,
  type CrashRecoveryReport,
  type CrashReport,
  type CrashResumeReport,
  type HeldSessionState,
} from "../session-admission-crash.ts";
import { sessionAdmissionCrashEntryArgv } from "../../support/prebuilt-entry.ts";
import { liveTierSelected } from "./tiers.ts";

// This file holds cases of both live tiers (see `tiers.ts`): per-conversation
// concurrent resume is the trust-boundary property (exact ids keep two
// resumes from colliding) and is core; the single-crash-point sweep and
// recovery-lifecycle cases below it are availability/recovery proofs and stay
// extended.
const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

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
 * Mirrors `DEFAULT_INTERNAL_PROBE_LEASE_DURATION_MS` in
 * `session-admission-driver.ts` (the shared contract's
 * `SESSION_ADMISSION_LEASE_MAX_DURATION_MS`). Duplicated rather than imported
 * on purpose: if that lease grows, this assertion should fail and be
 * considered again rather than quietly permit a longer window of unsupervised
 * authority.
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
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the crash admission tranche");
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
 *
 * `options.env`, when given, replaces `fixture.env` for this one invocation —
 * the second-Docker-stop case (review F3, Task 7) needs a terminal identity
 * (`TERM_PROGRAM`/`ITERM_SESSION_ID`) in the runner's own environment so the
 * host evidence it writes for the resumed session names a terminal.
 */
async function runCrashScript(
  fixture: LiveFixture,
  args: readonly string[],
  options: Readonly<{ env?: NodeJS.ProcessEnv }> = {},
): Promise<CrashRun> {
  return await new Promise<CrashRun>((resolve, reject) => {
    const child = childProcess.spawn(
      process.execPath,
      [...sessionAdmissionCrashEntryArgv(), "--workspace", fixture.projectRoot, "--agent", PROBE_AGENT, ...args],
      // Its own process group, so the orphans below can be reaped as a unit.
      { cwd: REPO_ROOT, detached: true, env: options.env ?? fixture.env, stdio: ["ignore", "pipe", "pipe"] },
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

function parseCrashReport(run: CrashRun, label: string): CrashReport {
  const line = run.output.split("\n").find((candidate) => candidate.startsWith(CRASH_REPORT_PREFIX));
  if (!line) {
    throw new Error(`${label} emitted no labelled report: ${describeOutput(run.output, 4000)}`);
  }
  return JSON.parse(line) as CrashReport;
}

/**
 * Terminal-multiplexer/session env vars `captureTerminalIdentity`
 * (`terminal-identity.ts`) reads, beyond `TERM_PROGRAM` and
 * `ITERM_SESSION_ID` themselves — which every caller below overwrites
 * unconditionally, so they need no scrub of their own. Removed from the
 * runner's spawn env before stamping an exact terminal identity onto it:
 * `fixture.env` inherits this Vitest worker's own environment, and a
 * maintainer running the suite inside tmux, WezTerm, kitty, or Windows
 * Terminal would otherwise add ids the live assertion never asked for,
 * making the asserted `terminal.ids` depend on who runs it.
 */
const TERMINAL_IDENTITY_ENV_KEYS = [
  "TMUX",
  "TMUX_PANE",
  "WEZTERM_PANE",
  "WEZTERM_UNIX_SOCKET",
  "KITTY_WINDOW_ID",
  "KITTY_PID",
  "KITTY_LISTEN_ON",
  "WT_SESSION",
  "TERM_SESSION_ID",
  "ITERM_SESSION_ID",
] as const;

/** `base` with every other terminal identity env scrubbed, then the exact iTerm identity stamped on. */
function iTermOnlyEnv(base: NodeJS.ProcessEnv, itermSessionId: string): NodeJS.ProcessEnv {
  const scrubbed = { ...base };
  for (const key of TERMINAL_IDENTITY_ENV_KEYS) delete scrubbed[key];
  return { ...scrubbed, TERM_PROGRAM: "iTerm.app", ITERM_SESSION_ID: itermSessionId };
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
    extendedTest(`a crash ${point} leaves no authority and recovers to empty`, async () => {
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
  extendedTest("a crashed attached session resumes into a new lifecycle session, never the old container", async () => {
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

  // Task 12 (same-terminal resume plan): two tabs resume at the same time.
  //
  // Per-conversation claims (Task 6) are the property under test: a claim
  // scopes to one conversation, so two interrupted conversations in the same
  // project can resume concurrently rather than queueing behind one
  // whole-agent claim. `--resume-id` (this task) is what lets a caller name
  // one exact conversation to resume instead of accepting whichever host
  // evidence happens to be newest — without it, two concurrent crashes could
  // never be told apart by anything this runner exposes.
  coreTest("two interrupted Claude sessions resume at the same time, each with its own exact id", async () => {
    const composeProject = composeProjectName(fixture);
    const projectId = composeProject.replace(/^runfree-/u, "");
    const stateDir = path.join(runfreeStateRoot(fixture.env), "projects", projectId);
    const identity = { projectId, composeProject };
    const claimsDir = path.join(stateDir, "sessions", "recovery-claims");
    const stubDir = path.join(fixture.projectRoot, RESUME_STUB_DIRECTORY);
    const claimFiles = (): string[] => (fs.existsSync(claimsDir) ? fs.readdirSync(claimsDir) : []);

    const conversationA = crypto.randomUUID();
    const conversationB = crypto.randomUUID();

    // Step 1: two crashed fresh launches, one after the other, each carrying
    // its own host-chosen conversation id.
    //
    // The product's recovery (`--recover`) runs between them: the *second*
    // crash's own precondition refuses a dirty project (any surviving
    // lifecycle record or container), and the first crash's attached session
    // is exactly that — its owning host client is dead, but its session
    // container keeps running, matching a record, until something reclaims
    // it. That reclaim never touches the first crash's host evidence crash
    // manifest, which lives under a completely separate tree
    // (`sessions/<id>.json`, read by `scanRecoveryInventory`) from the
    // lifecycle record (`runtime/v2/session-containers/<id>.json`) the clean
    // removes — so neither conversation's recoverability is lost.
    // Session ids the two crashes leave, so the "attached" waits below can
    // exclude them explicitly rather than trust that recovery always finishes
    // before either wait starts polling.
    const crashedSessionIds = new Set<string>();
    for (const conversationId of [conversationA, conversationB]) {
      const crashed = await runCrashScript(fixture, ["--kill-when-attached", "--launch-conversation-id", conversationId]);
      expect(
        crashed.output,
        `no attached crash landed for conversation ${conversationId}: ${describeOutput(crashed.output, 4000)}`,
      ).toContain(CRASH_INJECTION_MARKER);
      for (const record of listSessionContainerRecordsV2(stateDir, identity)) crashedSessionIds.add(record.sessionId);
      // The product's own reconciliation clears the crash residue, as every
      // other crash case here does. `forceCleanSessions` is the harness's
      // last-resort repair and reports any repair as a failure, so using it
      // for expected residue failed this case live (2026-10-07).
      const recovery = parseCrashRecovery(
        await runCrashScript(fixture, ["--recover"]),
        `recovery after the crash of conversation ${conversationId}`,
      );
      expect(
        recovery.recovered,
        `recovery after the crash of conversation ${conversationId} failed: ${describeOutput(recovery.failure ?? "<no failure reported>", 2000)}`,
      ).toBe(true);
      expect(
        recovery.after.lifecycleRegistryEmpty && recovery.after.residualContainers === 0,
        `recovery after the crash of conversation ${conversationId} left session residue: ${JSON.stringify(recovery.after)}`,
      ).toBe(true);
    }

    // Step 2: the host-side inventory names both conversations exactly, each
    // its own host-chosen item.
    const crashedItems = scanRecoveryInventory({ projectRoot: fixture.projectRoot, env: fixture.env }).items;
    const itemA = crashedItems.find((candidate) => candidate.conversationId === conversationA);
    const itemB = crashedItems.find((candidate) => candidate.conversationId === conversationB);
    expect(itemA, `no recovery item names conversation A: ${JSON.stringify(crashedItems.map((item) => item.id))}`).toBeDefined();
    expect(itemB, `no recovery item names conversation B: ${JSON.stringify(crashedItems.map((item) => item.id))}`).toBeDefined();
    expect(itemA?.conversationSource, "conversation A was not host-chosen").toBe("host-chosen");
    expect(itemB?.conversationSource, "conversation B was not host-chosen").toBe("host-chosen");
    expect(itemA?.id, "the two crashed conversations share one recovery id").not.toBe(itemB?.id);

    // Vacuity guard: no per-conversation claim exists before either resume
    // starts, so the count asserted below while both are attached is this
    // case's own claims and not residue from an earlier one.
    expect(claimFiles(), "a per-conversation claim exists before either resume started").toEqual([]);

    // Step 3: both resumes run concurrently, each naming its own exact item.
    fs.rmSync(stubDir, { recursive: true, force: true });
    let completedA = false;
    let completedB = false;
    const resumedA = runCrashScript(fixture, ["--resume", "--resume-id", String(itemA?.id)])
      .then((result) => { completedA = true; return result; });
    const resumedB = runCrashScript(fixture, ["--resume", "--resume-id", String(itemB?.id)])
      .then((result) => { completedB = true; return result; });
    const finishConcurrent = startLivePhase("crash: two conversations resumed concurrently");
    try {
      const deadline = Date.now() + HELD_LAUNCH_WAIT_TIMEOUT_MS;
      for (;;) {
        // Excludes the two crashed sessions by id: both are reclaimed by now
        // (the loop above cleaned after each crash), but naming them
        // explicitly means this wait can never be satisfied by stale residue
        // instead of the two sessions this resume actually just admitted.
        const attached = listSessionContainerRecordsV2(stateDir, identity)
          .filter((record) => record.state === "attached" && !crashedSessionIds.has(record.sessionId));
        const readyA = fs.existsSync(path.join(stubDir, `ready-${conversationA}`));
        const readyB = fs.existsSync(path.join(stubDir, `ready-${conversationB}`));
        if (attached.length === 2 && readyA && readyB) break;
        if (completedA || completedB) {
          throw new Error(`a resume ended before both reached attached (A completed=${completedA}, B completed=${completedB})`);
        }
        if (Date.now() > deadline) throw new Error("both resumed agents never reached their ready/attached handshake");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      // Vacuity guard (step 3.5): the claim directory holds exactly two
      // claims while both resumes are attached, and both are
      // per-conversation — the proof that per-conversation claims, not one
      // shared whole-agent claim (nor some unrelated third claim), are what
      // let both run.
      const claimsWhileAttached = claimFiles();
      expect(
        claimsWhileAttached,
        `the claim directory does not hold exactly two claims while both resumes are attached: ${JSON.stringify(claimsWhileAttached)}`,
      ).toHaveLength(2);
      expect(
        claimsWhileAttached.every((name) => /^conv-[0-9a-f]{24}-[0-9a-f]{24}\.json$/u.test(name)),
        `an unexpected claim file name: ${JSON.stringify(claimsWhileAttached)}`,
      ).toBe(true);
    } finally {
      fs.mkdirSync(stubDir, { recursive: true });
      fs.writeFileSync(path.join(stubDir, `release-${conversationA}`), "");
      fs.writeFileSync(path.join(stubDir, `release-${conversationB}`), "");
      await Promise.allSettled([resumedA, resumedB]);
      finishConcurrent();
    }

    // Step 4: both resumes completed through admission with their own exact
    // id, never the other's and never a fresh-launch flag.
    const resultA = parseCrashResume(await resumedA, "resume A");
    const resultB = parseCrashResume(await resumedB, "resume B");
    for (const [label, result, conversationId] of [
      ["A", resultA, conversationA],
      ["B", resultB, conversationB],
    ] as const) {
      expect(result.failure, `resume ${label} failed: ${describeOutput(result.failure ?? "", 4000)}`).toBeUndefined();
      expect(result.outcome, `resume ${label} reported no outcome`).toEqual({ status: 0, consumed: true });
      const createCommand = result.observedCommands.find((command) => command.startsWith("container create"));
      expect(createCommand, `no session container create was observed during resume ${label}`).toBeDefined();
      expect(createCommand).toContain(`--resume ${conversationId}`);
      expect(createCommand, `resume ${label} carried a fresh-launch flag instead of resuming`).not.toContain("--session-id");
    }

    const after = parseCrashReport(await runCrashScript(fixture, ["--report"]), "report after both concurrent resumes");
    expect(after.lifecycleRegistryEmpty, "the concurrent resumes left a lifecycle record").toBe(true);
    expect(after.residualContainers, "the concurrent resumes left a session container").toBe(0);

    // Step 6 (review F3, Task 7): a second Docker stop. Crash A once more,
    // resume it with an iTerm terminal identity in the runner's own
    // environment, and end the resumed session's container directly — not
    // through the stub's ready/release handshake — while it is attached. A
    // resumed session that reaches attached and then ends non-zero keeps its
    // own record rather than the claimed original's, so the inventory holds
    // exactly one item afterwards: the resumed session's own, naming the
    // terminal it was resumed in.
    const crashedAgain = await runCrashScript(fixture, ["--kill-when-attached", "--launch-conversation-id", conversationA]);
    expect(
      crashedAgain.output,
      `no attached crash landed for the second-stop case: ${describeOutput(crashedAgain.output, 4000)}`,
    ).toContain(CRASH_INJECTION_MARKER);
    // Deliberately no `forceCleanSessions` here: this crashed record and
    // container are the residue the resume below is about, and the next
    // wait must not mistake them for the resumed session's own.
    const crashedAgainSessionIds = new Set(listSessionContainerRecordsV2(stateDir, identity).map((record) => record.sessionId));

    const itemAAgain = scanRecoveryInventory({ projectRoot: fixture.projectRoot, env: fixture.env }).items
      .find((candidate) => candidate.conversationId === conversationA);
    expect(itemAAgain, "no recovery item names conversation A after the second crash").toBeDefined();
    const originalEvidencePath = itemAAgain?.evidencePath;

    fs.rmSync(stubDir, { recursive: true, force: true });
    const iTermEnv = iTermOnlyEnv(fixture.env, "tab2");
    let secondResumeCompleted = false;
    const secondResume = runCrashScript(fixture, ["--resume", "--resume-id", String(itemAAgain?.id)], { env: iTermEnv })
      .then((result) => { secondResumeCompleted = true; return result; });
    let secondContainerId: string | undefined;
    try {
      const deadline = Date.now() + HELD_LAUNCH_WAIT_TIMEOUT_MS;
      for (;;) {
        // Excludes the just-crashed session by id: that record is still
        // attached (nothing has reclaimed it yet), and without this
        // exclusion the wait could read it as the resumed session's own and
        // `docker kill` the wrong, already-dead-owner container.
        const attached = listSessionContainerRecordsV2(stateDir, identity)
          .find((record) => record.state === "attached" && !crashedAgainSessionIds.has(record.sessionId));
        if (attached?.containerId && fs.existsSync(path.join(stubDir, `ready-${conversationA}`))) {
          secondContainerId = attached.containerId;
          break;
        }
        if (secondResumeCompleted) throw new Error(`the second-stop resume ended before reaching attached: ${(await secondResume).output}`);
        if (Date.now() > deadline) throw new Error("the second-stop resume never reached its ready/attached handshake");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    } finally {
      if (secondContainerId) {
        // The container is ended by an external stop, never by its own
        // release: writing the release file here too would race the kill,
        // and an exit the stub chose for itself is not the state this case
        // is about.
        docker(["kill", secondContainerId]);
      } else {
        // No container was ever found to kill (the wait above threw before
        // one was): release the stub anyway, so a session that is still
        // running does not sit waiting out its own 180s fallback, and
        // `afterEach`'s `forceCleanSessions` can reclaim a stopped container
        // instead of force-removing one still attached.
        fs.mkdirSync(stubDir, { recursive: true });
        fs.writeFileSync(path.join(stubDir, `release-${conversationA}`), "");
      }
    }
    const secondResult = parseCrashResume(await secondResume, "resume with a second Docker stop");
    expect(secondResult.failure, `the second-stop resume failed: ${describeOutput(secondResult.failure ?? "", 4000)}`).toBeUndefined();
    expect(secondResult.outcome, "the second-stop resume reported no outcome").toBeDefined();
    expect(secondResult.outcome?.status, "ending the container read as a clean resume exit").not.toBe(0);
    expect(secondResult.outcome?.consumed, "the second-stop resume did not consume the claimed original").toBe(true);

    // The claimed original's own evidence file must be gone: `consumed:
    // true` alone does not prove this, because `joinHostItemsBySameConversation`
    // merges every host record naming the same conversation into one
    // inventory item — "exactly one item for A" below would hold even if the
    // original were still sitting there, merely hidden as `linkedHost`
    // rather than actually unlinked.
    expect(
      originalEvidencePath !== undefined && fs.existsSync(originalEvidencePath),
      "the second-stop resume did not consume the original crashed evidence file",
    ).toBe(false);

    const finalItems = scanRecoveryInventory({ projectRoot: fixture.projectRoot, env: fixture.env }).items;
    const matchingA = finalItems.filter((candidate) => candidate.conversationId === conversationA);
    expect(
      matchingA,
      `expected exactly one recovery item for conversation A after the second stop: ${JSON.stringify(finalItems.map((item) => item.id))}`,
    ).toHaveLength(1);
    expect(matchingA[0]?.terminal?.ids).toEqual({ iterm: "tab2" });
    // The join above would otherwise hide a still-linked original behind
    // this one surviving item; no `linkedHost` is what proves there is
    // nothing left to hide.
    expect(
      matchingA[0]?.linkedHost ?? [],
      "the remaining item still links to another host record, so the original was not truly consumed",
    ).toEqual([]);

    // Harness cleanup: the kept record's own host evidence (and any linked
    // host evidence it names) does not live under the lifecycle-record tree
    // `afterEach`'s `forceCleanSessions` sweeps, so it would otherwise leak
    // into a later case in this file.
    for (const linked of matchingA[0]?.linkedHost ?? []) fs.rmSync(linked.evidencePath, { force: true });
    if (matchingA[0]) fs.rmSync(matchingA[0].evidencePath, { force: true });
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
    extendedTest(`a crash ${point} leaves no served session and recovers to empty`, async () => {
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

  // -------------------------------------------------------------------------
  // A Docker daemon that dies under a live session (todo 67, 2026-09-29).
  //
  // The owner stamps its record terminal, cannot delete the session file
  // because the daemon is gone, keeps the record, and exits. When the daemon
  // comes back, Docker has stopped both the session container and the proxy
  // (neither has a restart policy). The next start used to refuse that
  // pending record with `runfree rebuild` as the only remedy.
  //
  // The daemon itself is not restarted here: Docker Desktop cannot be restarted
  // reliably from a test. Its whole effect on this
  // project is reproduced instead, from the same parts a real death leaves —
  // a launch parked at its refused session-file delete (the stamp written, the
  // record kept), the session container and the proxy killed the way a daemon
  // stop kills them, and the owner SIGKILLed. A plain `runfree up` must then
  // finish the teardown on Docker's proof and start, with no `rebuild`.
  // -------------------------------------------------------------------------

  /**
   * Leaves the residue a daemon death leaves: a launch parked at its refused
   * session-file delete (stamp written, record kept), the session container
   * killed, optionally the proxy killed, and the owner SIGKILLed.
   */
  async function leaveInterruptedTeardown(options: Readonly<{ stopProxy: boolean }>): Promise<Readonly<{
    sessionId: string;
    containerId: string;
    proxyId: string;
    stateDir: string;
    identity: Readonly<{ projectId: string; composeProject: string }>;
  }>> {
    const composeProject = composeProjectName(fixture);
    const projectId = composeProject.replace(/^runfree-/u, "");
    const stateDir = path.join(runfreeStateRoot(fixture.env), "projects", projectId);
    const identity = { projectId, composeProject };
    const proxyId = composeServiceContainerId(composeProject, "proxy");
    assertFilesPathExercised(fixture, proxyId, [], "before the interrupted teardown");

    const point = "after-failed-file-delete" as const;
    const owner = startHeldLaunchOwner(fixture, ["--launch-hold-at", point, "--fail-session-file-delete"]);
    let killed = false;
    let sessionId = "";
    let containerId = "";
    try {
      const attached = await owner.awaitReason("attached", HELD_LAUNCH_WAIT_TIMEOUT_MS);
      const [record] = attached.records;
      expect(record?.containerId, "the attached record names no container").toBeTruthy();
      sessionId = String(record?.sessionId);
      containerId = String(record?.containerId);
      // The agent ends, so the owner starts its teardown; the refused delete
      // parks it with the stamp written and the record kept.
      docker(["kill", containerId]);
      await owner.awaitReason(point, HELD_LAUNCH_WAIT_TIMEOUT_MS);
      expect(readSessionFileEvidence(proxyId).files.length, "the refused delete left no session file").toBe(1);
      // What the daemon's death does to this project: its containers stop.
      if (options.stopProxy) docker(["kill", proxyId]);
      await owner.killOwner();
      killed = true;
    } finally {
      if (!killed) await owner.killOwner();
      owner.discard();
    }

    // Vacuity guard: the pending record the start used to refuse is there.
    expect(
      listSessionContainerRecordsV2(stateDir, identity).map((record) => record.sessionId),
      "the interrupted teardown left no record",
    ).toContain(sessionId);
    if (options.stopProxy) {
      expect(
        docker(["container", "inspect", "--format", "{{.State.Running}}", proxyId]).stdout.trim(),
        "the proxy was meant to be stopped, as a daemon restart leaves it",
      ).toBe("false");
    }
    return Object.freeze({ sessionId, containerId, proxyId, stateDir, identity });
  }

  async function assertInterruptedTeardownReclaimedByStart(options: Readonly<{ stopProxy: boolean }>): Promise<void> {
    const { sessionId, stateDir, identity } = await leaveInterruptedTeardown(options);
    const { composeProject, projectId } = identity;

    const started = fixture.runfree(["up"]);
    expect(started.status, `the start after an interrupted teardown failed: ${describeOutput(started.output, 4000)}`)
      .toBe(0);
    expect(started.output).not.toContain("requires recovery");
    expect(started.output).toContain(`finished the interrupted teardown of session ${sessionId}`);

    expect(listSessionContainerRecordsV2(stateDir, identity), "the start left the pending record behind").toEqual([]);
    const sessionContainers = dockerOrThrow("post-start session containers", [
      "ps", "-aq", "--no-trunc",
      "--filter", `label=io.runfree.project-id=${projectId}`,
      "--filter", "label=io.runfree.container-role=session-agent",
    ]);
    expect(sessionContainers, "the start left the interrupted session's container behind").toBe("");
    expect(
      readSessionFileEvidence(composeServiceContainerId(composeProject, "proxy")).files,
      "the started proxy serves a session file for a session that no longer exists",
    ).toEqual([]);
  }

  extendedTest("a start after the daemon stopped the proxy and session finishes the interrupted teardown without rebuild", async () => {
    await assertInterruptedTeardownReclaimedByStart({ stopProxy: true });
  }, TEST_TIMEOUT_MS);

  extendedTest("a start with the proxy still running finishes an interrupted teardown through the ordinary delete", async () => {
    await assertInterruptedTeardownReclaimedByStart({ stopProxy: false });
  }, TEST_TIMEOUT_MS);

  // The negative: Docker proves the session container is running again, so
  // the start must keep the record — the address reservation — and refuse
  // with the reason, not reclaim. The harness reset between cases clears it.
  extendedTest("a start refuses an interrupted teardown whose session container runs again, and keeps its record", async () => {
    const { sessionId, containerId, stateDir, identity } = await leaveInterruptedTeardown({ stopProxy: false });
    dockerOrThrow("restart the interrupted session container", ["start", containerId]);

    const started = fixture.runfree(["up"]);
    expect(started.status, `the start reclaimed a running session: ${describeOutput(started.output, 4000)}`).not.toBe(0);
    expect(started.output).toContain(`session ${sessionId}`);
    expect(started.output).toContain("is still running");
    expect(
      listSessionContainerRecordsV2(stateDir, identity).map((record) => record.sessionId),
      "the start dropped the record of a session whose container runs",
    ).toContain(sessionId);
    expect(started.output, "the refusal names its remedy").toContain("runfree rebuild");

    // The named remedy reclaims it: the record and the container are gone.
    const rebuilt = fixture.runfree(["rebuild"]);
    expect(rebuilt.status, `the named remedy failed: ${describeOutput(rebuilt.output, 4000)}`).toBe(0);
    expect(listSessionContainerRecordsV2(stateDir, identity).map((record) => record.sessionId)).not.toContain(sessionId);
    expect(docker(["container", "inspect", containerId]).status, "rebuild left the session container").not.toBe(0);
  }, TEST_TIMEOUT_MS);

  extendedTest("the runtime still admits a session after every crash and recovery", () => {
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
  extendedTest("one plain destroy clears an attached-crash residue: no session container, no Compose container, empty registry", async () => {
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
