// Crash-injection runner for the per-session admission lifecycle.
//
// The nominal matrix proves the sequence completes and cleans up. This runner
// proves what survives when the host dies partway through it, which is the
// failure mode the registry-first revocation ordering exists for.
//
// How the crash is injected, and why this way:
//
// The driver receives its Docker execution seam as `RuntimeIO`. Every Docker
// command it issues passes through `io.run`/`io.capture`, so a wrapper here can
// watch the real command stream and kill the process at an exact transition —
// deterministically, with no fault-injection hook in production code. That
// matters: this repository's own history is that a test escape hatch in
// production (`RUNFREE_TEST_MCP_CALLBACK_PORT_AVAILABLE`) hid a real defect for
// months by disabling the check it was supposed to prove.
//
// The kill is `SIGKILL` to this process's own PID. It is uncatchable, runs no
// exit handler, and unwinds no `finally` — which is exactly what a host crash
// looks like to durable lifecycle state. A thrown error would instead exercise
// the ordinary fail-closed path, which the nominal tranche already covers.
//
// If a requested kill point never matches, the runner exits non-zero rather
// than completing normally: a crash test whose crash never happened must not
// read as a pass.

import * as childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { createCommandContext } from "../../packages/cli/src/commands/context.ts";
import { createRuntimeSecurityContract } from "../../packages/cli/src/runtime/security-contract.ts";
import { readEffectiveControlPlaneV2 } from "../../packages/cli/src/runtime/component-state-v2.ts";
import { removeSessionHostStatus } from "../../packages/cli/src/runtime/session-host-status.ts";
import {
  servedSetReadCommand,
  sessionAdmissionFirewallSetReadCommand,
  sessionFileDeleteCommand,
} from "../../packages/cli/src/runtime/session-file-publisher.ts";
import { createInternalSessionAdmissionDriver } from "../../packages/cli/src/runtime/session-admission-driver.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
} from "../../packages/cli/src/runtime/session-container-reconciliation.ts";
import {
  listSessionContainerRecordsV2,
  sessionContainerRecordPath,
  sessionContainerRecordsRoot,
} from "../../packages/cli/src/runtime/session-containers.ts";
import {
  BUILTIN_SESSION_ADMISSION_PROBE_AGENTS,
  type SessionAdmissionLaunchOutcome,
  type SessionAdmissionProbeAgent,
} from "../../packages/cli/src/runtime/session-admission-probe.ts";
import { scanRecoveryInventory } from "../../packages/cli/src/runtime/recovery.ts";
import { resumeInterruptedSessionThroughAdmission } from "../../packages/cli/src/runtime/session-admission-resume.ts";
import { generatedRuntimeContextIfAvailable } from "../../packages/cli/src/runtime/images.ts";
import { mintPreparedRuntime } from "../../packages/cli/src/runtime/prepared-runtime.ts";
import {
  activeRuntimePlanFromContext,
  runtimeContextFromActivePlan,
} from "../../packages/cli/src/runtime/plan.ts";
import type { SessionContainerForegroundSpawner } from "../../packages/cli/src/runtime/session-container-start.ts";
import {
  createSessionLockManager,
  tryAcquireProjectLifecycleLock,
  tryAcquireProjectLifecycleLockWithRetry,
} from "../../packages/cli/src/runtime/sessions.ts";
import { runtimeValidationMarkerStatus } from "../../packages/cli/src/runtime/state.ts";
import { createMatrixRuntimeIO } from "./session-admission-matrix-io.ts";
import { renderFailure } from "./session-admission-failure.ts";
import { SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";

const CAPTURE_MAX_BYTES = 32 * 1024 * 1024;
/** Mirrors `CONTROL_CHARACTER_PATTERN` in `session-container-reconciliation.ts`. */
const LABEL_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;
export const CRASH_REPORT_PREFIX = '{"v":1,"kind":"runfree-session-admission-crash-report"';

/**
 * Printed immediately before the process kills itself.
 *
 * This is what a caller checks, rather than the exit signal. A parent that
 * spawns this runner directly sees `signal: "SIGKILL"`, but one that spawned it
 * through a wrapper (as `pnpm exec tsx` once did) saw the wrapper's ordinary
 * exit status and `signal: null`. The marker is spawn-shape independent and,
 * unlike the signal, names the transition the kill landed in.
 *
 * SIGKILL is uncatchable, so nothing after the write can execute: seeing this
 * line and no completion is proof the crash happened where it says.
 */
export const CRASH_INJECTION_MARKER = "crash-injection: killing after";

/**
 * Prefix for one observed Docker command in `--list-commands` output.
 *
 * The runner's `RuntimeIO.run` inherits stdio, so a Docker subcommand's own
 * output interleaves with this listing on the same stream. Counting raw lines
 * therefore counted that output too — a listing of 45 commands read as 727,
 * and the late-crash selector asked for a command index that could never
 * arrive. Each command now carries this prefix so a caller counts commands
 * rather than lines.
 */
export const CRASH_COMMAND_MARKER = "crash-command:";

/**
 * Named transitions, each identified by the exact Docker subcommand that
 * completes it.
 *
 * These are matched against the argv the driver actually issues rather than
 * against an internal phase name, so a rename inside the driver cannot silently
 * stop a kill point from firing — the command stream is the contract. The
 * `--list-commands` mode prints that stream so a mismatch is diagnosable in one
 * run instead of by guesswork.
 *
 * Verified against the argv `session-container-docker.ts` actually builds, not
 * against an assumed lifecycle. The driver attaches the network at create time
 * with `--network`, so there is no `network connect` command to crash after —
 * a point named for one would never have fired, and this tranche would have
 * reported a crash it never performed.
 */
export const CRASH_POINTS = {
  /**
   * After the session container exists but has never run — before its id is
   * durably bound to the allocated record.
   */
  "after-create": ["container", "create"],
  /**
   * At the launch of the first project-controlled process, before registration.
   *
   * `docker container start --attach` does not return while the container runs,
   * and the gateway spawns it asynchronously — the handle comes back at once.
   * So this fires just after the start is *issued*, with the container coming
   * up. Start precedes registration in the single-inspection ladder, so this is
   * the kill-before-registration window: the durable record already says
   * provisioning-running, but no proxy consumer has ever seen the session.
   */
  "after-start": ["container", "start"],
  /**
   * After the single post-start inspection, before activation spends it.
   *
   * The session is registered (provisioning at the proxy, journal completed)
   * and its one shape proof has been minted, but activation never ran, so the
   * request proxy still refuses everything except the readiness probe.
   *
   * Armed only after a `container start` has been observed — see
   * `crashPointArmed`. On a busy daemon, preflight's whole-inventory
   * reconciliation issues batched `container inspect` commands before any
   * session exists, and how many depends on how many containers the machine
   * happens to hold, so neither the first match nor any fixed `--occurrence`
   * names this transition. The one inspect this point is named for is, by the
   * ladder's own definition, the first `container inspect` after the
   * foreground start.
   */
  "after-running-inspect": ["container", "inspect"],
  /** Mid-revocation: the endpoint is gone but the container still exists. */
  "after-network-disconnect": ["network", "disconnect"],
  /** Late revocation: stopped, not yet removed. */
  "after-container-stop": ["container", "stop"],
  /**
   * Admission: the sealed inspect-and-write has just written this session's
   * file, so the proxy is already serving the address, but the durable record
   * has not yet followed the file to `attached`.
   *
   * Reachable only through the production launch: the internal probe never
   * activates, so it never writes a file at all.
   */
  "after-session-file-write": ["exec"],
  /**
   * Teardown step 1 (review fix F9): the session file is gone —
   * the authority is withdrawn — but the endpoint, the container, and above all
   * the record that reserves the session's address are all still there.
   */
  "after-file-deleted-before-stop": ["exec"],
  /**
   * Teardown step 1 refused (review fix F9): the delete could not
   * be performed, so the file may still be published. Nothing below it may run,
   * and the record must survive: releasing the address of a session that may
   * still be served is how two containers end up sharing one identity.
   *
   * Only armed with `--fail-session-file-delete`, which is what makes the delete
   * fail; the argv is otherwise identical to a successful one.
   */
  "after-failed-file-delete": ["exec"],
} as const;

export type CrashPoint = keyof typeof CRASH_POINTS;

/** How a point is reached: the internal probe, or the production launch. */
export type CrashPointDrive = "probe" | "launch";

/**
 * What drives each point.
 *
 * `drive: "launch"` marks the points that only the production launch reaches.
 * The internal probe issues teardown's session-file delete too (idempotently,
 * against a session that never had a file), so a probe-driven kill there would
 * fire and prove nothing — the state those points exist for is a session that
 * really was being served.
 */
export const CRASH_POINT_REACHABILITY = {
  "after-create": { drive: "probe" },
  "after-start": { drive: "probe" },
  "after-running-inspect": { drive: "probe" },
  "after-network-disconnect": { drive: "probe" },
  "after-container-stop": { drive: "probe" },
  "after-session-file-write": { drive: "launch" },
  "after-file-deleted-before-stop": { drive: "launch" },
  "after-failed-file-delete": { drive: "launch" },
} as const satisfies Record<CrashPoint, Readonly<{ drive: CrashPointDrive }>>;

function crashPoints(drive: CrashPointDrive): readonly CrashPoint[] {
  return Object.freeze((Object.keys(CRASH_POINTS) as CrashPoint[])
    .filter((point) => CRASH_POINT_REACHABILITY[point].drive === drive));
}

/** The points a `--kill-at` probe run can reach. */
export function probeCrashPoints(): readonly CrashPoint[] {
  return crashPoints("probe");
}

/** The points only a production launch reaches. */
export function launchCrashPoints(): readonly CrashPoint[] {
  return crashPoints("launch");
}

/**
 * Hold points for the production launch (`--launch-hold-at`).
 *
 * The crash points name Docker commands, and none of them falls between the
 * running proof and activation: the proof's last `container inspect` is
 * inside a time-bounded loop that also requires a live foreground, so a hold
 * there fails the proof rather than parking the launch.
 *
 * `before-session-file-write` is the one launch-only point: armed by the
 * post-start inspect that reports the container running (the running proof's
 * own last observation), it holds at that observation — after the proof has
 * been made and before the sealed inspect-and-write that grants authority. A
 * launch parked there has a running container, a durable provisioning record,
 * and no session file, so the proxy drops its packets. The activation-gate
 * tranche parks a launch there for longer than the session entry's wait bound.
 */
export type LaunchHoldPoint = CrashPoint | "before-session-file-write";

const LAUNCH_ONLY_HOLD_POINTS = ["before-session-file-write"] as const;

export function isLaunchHoldPoint(value: string): value is LaunchHoldPoint {
  return (LAUNCH_ONLY_HOLD_POINTS as readonly string[]).includes(value) || isCrashPoint(value);
}

export function isCrashPoint(value: string): value is CrashPoint {
  return Object.hasOwn(CRASH_POINTS, value);
}

/**
 * Matches a Docker argv against a crash point's leading subcommand path.
 *
 * The path must be the argv's *first* non-option tokens, in order. Searching for
 * it anywhere would also match an option's value — `docker run --name container
 * create` reads as `container create` once options are stripped — and would
 * crash the wrong transition while looking correct.
 *
 * This assumes the driver emits no Docker global options before the subcommand,
 * which is true of every command in `session-container-docker.ts`: each `args`
 * array starts with its noun. A global option that took a value would shift the
 * path and stop matching, which fails closed (the runner exits non-zero saying
 * the point never occurred) rather than crashing somewhere unintended.
 */
/**
 * Whether a crash point may fire yet, given what the command stream has shown.
 *
 * `after-running-inspect` shares its subcommand with preflight's
 * whole-inventory reconciliation, whose batch count varies with the daemon's
 * total container population (observed live, 2026-08-31: two 60-id inventory
 * chunks fired before allocation, so both occurrence 1 and occurrence 2
 * selected a pre-allocation moment and the empty-registry vacuity guard
 * refused the run). Order is the machine-independent discriminator: the single
 * post-start inspection is the first `container inspect` after the foreground
 * `container start` is issued.
 */
export function crashPointArmed(point: CrashPoint, sessionStartObserved: boolean): boolean {
  return point !== "after-running-inspect" || sessionStartObserved;
}

/** Whether a `container inspect` result reports its one container running. */
export function inspectReportsRunning(stdout: string | undefined): boolean {
  if (stdout === undefined) return false;
  try {
    const parsed: unknown = JSON.parse(stdout);
    if (!Array.isArray(parsed) || parsed.length !== 1) return false;
    const state = (parsed[0] as { State?: { Running?: unknown; Status?: unknown } }).State;
    return state?.Running === true && state?.Status === "running";
  } catch {
    return false;
  }
}

/**
 * Which per-session file command a Docker argv is, if it is one at all.
 *
 * Both commands are the same sealed `docker exec ... node -e <script>` shape
 * (`session-file-publisher.ts`), so the subcommand cannot tell them apart. What
 * can is the trailing argv the publisher pins: a write ends with the sha256 of
 * the exact stdin bytes, a delete ends with the file it removes. The sessions
 * directory also appears *inside* both scripts, so the test is anchored to the
 * start of an argument rather than searched anywhere in it — the same rule
 * `matchesCrashPoint` applies to subcommand paths, for the same reason.
 *
 * The eligibility publish shares the write script but names
 * `eligibility.json`, which is not under the sessions directory, so it is
 * correctly neither.
 */
export function sessionFileCommandEffect(argv: readonly string[]): "write" | "delete" | undefined {
  if (argv[0] !== "exec") return undefined;
  const sessionFilePrefix = `${SESSION_FILES_DIR}/`;
  if (!argv.some((argument) => argument.startsWith(sessionFilePrefix))) return undefined;
  const trailing = argv[argv.length - 1] ?? "";
  if (/^sha256:[a-f0-9]{64}$/u.test(trailing)) return "write";
  return trailing.startsWith(sessionFilePrefix) ? "delete" : undefined;
}

export function matchesCrashPoint(argv: readonly string[], point: CrashPoint): boolean {
  const tokens = CRASH_POINTS[point];
  const words = argv.filter((argument) => !argument.startsWith("-"));
  const prefixMatches = tokens.every((token, offset) => words[offset] === token);
  if (!prefixMatches) return false;
  if (point === "after-session-file-write") return sessionFileCommandEffect(argv) === "write";
  if (point === "after-file-deleted-before-stop" || point === "after-failed-file-delete") {
    return sessionFileCommandEffect(argv) === "delete";
  }
  return true;
}

type CrashOptions = Readonly<{
  workspace: string;
  agent: SessionAdmissionProbeAgent;
  mode: "crash" | "hold" | "launch" | "report" | "recover" | "resume" | "list-commands" | "force-clean";
  /** Directory used to publish held state and await release, for --hold-at. */
  holdDir?: string;
  /** Launch-harness only: admit beside already attached sessions. */
  allowExistingSessions?: boolean;
  /**
   * Launch-harness only: refuse every per-session file delete (review fix F9).
   *
   * The delete is the one teardown step whose failure must stop the sequence,
   * because a delete this host could not perform is not proof the file is gone.
   * Reproducing that live otherwise means breaking the proxy, which breaks
   * everything else with it; the injection returns the failure the sealed
   * command would have returned, without running it, so the file is genuinely
   * left published and the ordered teardown meets exactly the state it refuses
   * to continue past.
   */
  failSessionFileDelete?: boolean;
  /**
   * Launch-harness only: pause the production launch at a transition, the way
   * `--hold-at` pauses the internal probe, then run it to completion once
   * released. The activation-gate tranche uses it to leave a session parked
   * between its running proof and activation for longer than the session
   * entry's wait bound, so the entry's own timeout — not a kill from outside —
   * is what ends the container before activation spends the proof.
   */
  launchHoldPoint?: LaunchHoldPoint;
  crashPoint?: CrashPoint;
  /**
   * Kills after the Nth Docker command overall, regardless of which one it is.
   *
   * This exists because the named points can only cover transitions this runner
   * can recognise from the outside. The latest interesting crash — after the
   * running proof, just before revocation would have run — has no distinctive
   * command of its own, and guessing which `container inspect` it is would be a
   * model of the driver's internals rather than an observation. The caller
   * discovers the real stream length with `--list-commands` and picks from it.
   */
  killAfterCommand?: number;
  /**
   * Kills once the registry shows an attached session, and launches instead of
   * probing so that state can be reached at all.
   *
   * Every other selector names a Docker command, which is why every other case
   * crashes inside a discrete operation. The state that matters most is the one
   * with no commands in it: a session that is up and running issues nothing, so
   * there is no stream position to name, and no transaction journal on disk
   * either — which is exactly why recovery could not reason about it.
   *
   * `probeBuiltin` cannot reach it. The probe is a dress rehearsal that proves
   * every property and tears the session down without ever activating, so its
   * latest possible crash still lands inside provisioning. Only `launchBuiltin`
   * activates, and until this mode existed nothing in the repository called it.
   *
   * The trigger is the record's own state rather than a command count, because
   * a count means whatever the driver happens to issue today: add one inspect
   * and the case silently kills somewhere else while still passing.
   */
  killWhenAttached?: boolean;
  /** Which matching command to kill after; 1 is the first. */
  occurrence: number;
}>;

function usage(message: string): never {
  process.stderr.write(`${message}\n`);
  process.stderr.write(
    "usage: session-admission-crash.ts --workspace <dir> --agent <claude|codex|pi>"
      + " (--kill-at <point> [--occurrence <n>] | --kill-after-command <n> | --kill-when-attached"
      + " | --launch --hold-dir <dir> [--allow-existing-sessions]"
      + " [--fail-session-file-delete] [--launch-hold-at <point>]"
      + " | --report | --recover | --resume | --list-commands | --force-clean)\n",
  );
  process.stderr.write(`kill points: ${Object.keys(CRASH_POINTS).join(", ")}\n`);
  // Named apart because `--kill-at` drives the internal probe, which never
  // activates: these transitions exist only inside a production launch, so they
  // are reachable through `--launch-hold-at` and never through `--kill-at`.
  process.stderr.write(
    `launch-hold-only points: ${[...launchCrashPoints(), ...LAUNCH_ONLY_HOLD_POINTS].join(", ")}\n`,
  );
  process.exit(2);
}

function parseArguments(argv: readonly string[]): CrashOptions {
  let workspace: string | undefined;
  let agent: SessionAdmissionProbeAgent | undefined;
  let mode: CrashOptions["mode"] | undefined;
  let crashPoint: CrashPoint | undefined;
  let killAfterCommand: number | undefined;
  let killWhenAttached = false;
  let holdDir: string | undefined;
  let allowExistingSessions = false;
  let failSessionFileDelete = false;
  let launchHoldPoint: LaunchHoldPoint | undefined;
  let occurrence = 1;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    switch (argument) {
      case "--workspace":
        if (!value) usage("--workspace requires a directory");
        workspace = path.resolve(value);
        index += 1;
        break;
      case "--agent":
        if (!value || !BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.includes(value as SessionAdmissionProbeAgent)) {
          usage(`--agent must be one of ${BUILTIN_SESSION_ADMISSION_PROBE_AGENTS.join(", ")}`);
        }
        agent = value as SessionAdmissionProbeAgent;
        index += 1;
        break;
      case "--hold-at":
        if (!value || !isCrashPoint(value)) usage(`--hold-at must be one of ${Object.keys(CRASH_POINTS).join(", ")}`);
        crashPoint = value;
        mode = "hold";
        index += 1;
        break;
      case "--hold-dir":
        if (!value) usage("--hold-dir requires a directory");
        holdDir = path.resolve(value);
        index += 1;
        break;
      case "--launch-hold-at":
        if (!value || !isLaunchHoldPoint(value)) {
          usage(`--launch-hold-at must be one of ${[...Object.keys(CRASH_POINTS), ...LAUNCH_ONLY_HOLD_POINTS].join(", ")}`);
        }
        launchHoldPoint = value;
        index += 1;
        break;
      case "--kill-at":
        if (!value || !isCrashPoint(value)) usage(`--kill-at must be one of ${Object.keys(CRASH_POINTS).join(", ")}`);
        crashPoint = value;
        mode = "crash";
        index += 1;
        break;
      case "--occurrence":
        if (!value || !/^[1-9][0-9]*$/u.test(value)) usage("--occurrence must be a positive integer");
        occurrence = Number(value);
        index += 1;
        break;
      case "--kill-after-command":
        if (!value || !/^[1-9][0-9]*$/u.test(value)) usage("--kill-after-command must be a positive integer");
        killAfterCommand = Number(value);
        mode = "crash";
        index += 1;
        break;
      case "--kill-when-attached":
        killWhenAttached = true;
        mode = "crash";
        break;
      case "--launch":
        mode = "launch";
        break;
      case "--allow-existing-sessions":
        allowExistingSessions = true;
        break;
      case "--fail-session-file-delete":
        failSessionFileDelete = true;
        break;
      case "--report":
        mode = "report";
        break;
      case "--recover":
        mode = "recover";
        break;
      case "--resume":
        mode = "resume";
        break;
      case "--force-clean":
        mode = "force-clean";
        break;
      case "--list-commands":
        mode = "list-commands";
        break;
      default:
        usage(`unknown argument: ${argument}`);
    }
  }

  if (!workspace) usage("--workspace is required");
  if (!agent) usage("--agent is required");
  if (!mode) {
    usage(
      "one of --kill-at, --kill-after-command, --kill-when-attached, --launch, --report, --recover, --resume, or --list-commands is required",
    );
  }
  if ([crashPoint !== undefined, killAfterCommand !== undefined, killWhenAttached].filter(Boolean).length > 1) {
    usage("--kill-at, --kill-after-command, and --kill-when-attached select different crashes; pass exactly one");
  }
  if (killWhenAttached && holdDir !== undefined) {
    // A hold pauses the host mid-transition; this selector needs the host to
    // run all the way to an attached session. Accepting both would silently
    // test the hold.
    usage("--kill-when-attached cannot be combined with --hold-dir");
  }
  if (mode === "launch") {
    // The launch mode's whole value to a caller is the published attached
    // state: without it the test cannot learn the session's address or
    // container, so accepting the flag alone would run a launch nothing can
    // act on.
    if (holdDir === undefined) usage("--launch requires --hold-dir");
    if (crashPoint !== undefined || killAfterCommand !== undefined || killWhenAttached) {
      usage("--launch runs the lifecycle to completion; it cannot be combined with a crash selector");
    }
  } else if (allowExistingSessions) {
    usage("--allow-existing-sessions requires --launch");
  }
  if (launchHoldPoint !== undefined && mode !== "launch") {
    usage("--launch-hold-at requires --launch");
  }
  if (failSessionFileDelete && mode !== "launch") {
    usage("--fail-session-file-delete requires --launch");
  }
  // The refused-delete point's argv is identical to a successful delete's, so
  // the injection is what distinguishes them. Pairing them at parse time means
  // neither can be asked for without the other and be silently answered by the
  // wrong state.
  if (failSessionFileDelete !== (launchHoldPoint === "after-failed-file-delete")) {
    usage("--fail-session-file-delete and --launch-hold-at after-failed-file-delete must be passed together");
  }
  return Object.freeze({
    workspace,
    agent,
    mode,
    occurrence,
    ...(crashPoint ? { crashPoint } : {}),
    ...(killAfterCommand !== undefined ? { killAfterCommand } : {}),
    ...(killWhenAttached ? { killWhenAttached } : {}),
    ...(holdDir === undefined ? {} : { holdDir }),
    ...(allowExistingSessions ? { allowExistingSessions } : {}),
    ...(failSessionFileDelete ? { failSessionFileDelete } : {}),
    ...(launchHoldPoint ? { launchHoldPoint } : {}),
  });
}

function resolveProject(workspace: string) {
  const io = createMatrixRuntimeIO();
  const commandContext = createCommandContext({
    projectRoot: workspace,
    invocationCwd: process.cwd(),
    commandName: "internal-session-admission-crash",
    env: process.env,
  });
  const generatedContext = generatedRuntimeContextIfAvailable(commandContext.runtimeContext());
  const activePlan = activeRuntimePlanFromContext(generatedContext);
  const activeContext = runtimeContextFromActivePlan(activePlan);
  const contract = createRuntimeSecurityContract(activePlan);
  const validation = runtimeValidationMarkerStatus(activeContext, io, { contractHash: contract.contractHash });
  if (!validation.proof || validation.issue) {
    throw new Error(`runtime lacks an exact current validation proof: ${validation.issue ?? "missing proof"}`);
  }
  const context = Object.freeze({ ...activeContext, validatedRuntime: validation.proof });
  const preparedRuntime = mintPreparedRuntime({ plan: activePlan, validationProof: validation.proof });
  const expectedProject = Object.freeze({
    projectId: activePlan.projectId,
    composeProject: activePlan.composeProjectName,
  });
  return { io, activePlan, context, expectedProject, preparedRuntime };
}

export type CrashReport = Readonly<{
  v: 1;
  kind: "runfree-session-admission-crash-report";
  records: readonly Readonly<{
    state: string;
    sessionId: string;
    /**
     * When this record's authority lapses, or null if it holds none yet.
     *
     * Reported because a crash in the attached state necessarily leaves an
     * authority-bearing record — the host that would have revoked it is gone —
     * so the property a caller can still check is that the authority is
     * bounded. Only a live host renews a lease, and the proxy rejects an
     * expired one, so this is what makes leftover authority temporary rather
     * than indefinite.
     */
    leaseExpiresAt: string | null;
  }>[];
  residualContainers: number;
  lifecycleRegistryEmpty: boolean;
  /** Harness repair ran; callers must not count this as product convergence. */
  harnessReset?: boolean;
}>;

export const CRASH_RECOVERY_PREFIX = '{"v":1,"kind":"runfree-session-admission-crash-recovery"';

/**
 * Both sides of one recovery, from a single invocation.
 *
 * The caller needs the post-crash state (to assert nothing holds authority) and
 * the post-recovery state (to assert convergence). Reporting both here rather
 * than making the caller invoke twice halves the subprocess count of each crash
 * case — and each of those calls is a synchronous `spawnSync` that blocks the
 * Vitest worker's event loop. At five per case the worker missed its RPC
 * heartbeat, Vitest reported `Timeout calling "onTaskUpdate"`, and two other
 * live files in the same run never executed.
 */
export type CrashRecoveryReport = Readonly<{
  v: 1;
  kind: "runfree-session-admission-crash-recovery";
  before: CrashReport;
  after: CrashReport;
  recovered: boolean;
  failure?: string;
  /** Present when recovery failed: why each residual record and container disagree. */
  diagnosis?: readonly CrashMismatchDiagnosis[];
}>;

export const CRASH_LAUNCH_PREFIX = '{"v":1,"kind":"runfree-session-admission-crash-launch"';

/**
 * Both sides of one full launch through the production admission path.
 *
 * The attached tranche uses this to hold a session open while it reads the
 * paired consumers, then ends the session and asserts convergence. `attached`
 * is the registry as first observed in the attached state — published to
 * `--hold-dir` the moment it is seen, so the caller can act on the live session
 * — and `after` is the project once the launch has completed and revoked.
 * A launch that never reached attached reports `attached: null`, which a caller
 * must treat as "nothing was proven about the attached state" rather than as a
 * pass.
 */
export type CrashLaunchReport = Readonly<{
  v: 1;
  kind: "runfree-session-admission-crash-launch";
  attached: HeldSessionState | null;
  /** Present when the launch completed; the attached process's exit. */
  outcome?: Readonly<{ status: number | null; signal: string | null }>;
  after: CrashReport;
  failure?: string;
  diagnosis?: readonly CrashMismatchDiagnosis[];
}>;

export const CRASH_RESUME_PREFIX = '{"v":1,"kind":"runfree-session-admission-crash-resume"';

/**
 * Both sides of one resume-through-admission, from a single invocation.
 *
 * The interesting claims are structural and host-side: which recovery item was
 * selected, whether the launch completed and consumed the evidence, and what
 * the registry and container inventory look like afterwards. The observed
 * Docker command stream is included so a caller can assert the create carried
 * the typed resume argv and a *new* session identity — after a successful
 * resume the record and container are gone, so the stream is the only place
 * that identity remains observable.
 */
export type CrashResumeReport = Readonly<{
  v: 1;
  kind: "runfree-session-admission-crash-resume";
  before: CrashReport;
  after: CrashReport;
  item?: Readonly<{ id: string; sessionId: string; state: string; evidenceKind: string }>;
  outcome?: Readonly<{ status: number; consumed: boolean }>;
  observedCommands: readonly string[];
  failure?: string;
  diagnosis?: readonly CrashMismatchDiagnosis[];
}>;

export type CrashMismatchDiagnosis = Readonly<{
  sessionId: string;
  recordState: string;
  containerId: string;
  containerRunning: boolean;
  /** Field-by-field differences, in the order reconciliation checks them. */
  differences: readonly Readonly<{ field: string; record: string; container: string }>[];
  /**
   * The raw `NetworkSettings.Networks[<internal>]` object, exactly as the
   * daemon reported it.
   *
   * Included because this tranche has now twice been wrong about the shape
   * Docker produces for a created-but-unstarted container, and each wrong guess
   * cost a full live cycle. Reporting the daemon's own bytes ends the guessing:
   * the next failure says what the endpoint actually looks like rather than
   * what the reader assumed.
   */
  rawContainerShape?: unknown;
  /** Whether reconciliation considered the inspected metadata malformed. */
  malformedInventoryMetadata: boolean;
}>;

/**
 * Explains a `mismatch` classification in terms of the exact fields that differ.
 *
 * `record and live container identity differ` names the conclusion, not the
 * cause, and the two predicates behind it
 * (`recordMatchesContainer`, `unboundAllocatedRecordMatchesCreatedContainer` in
 * `session-container-reconciliation.ts`) compare a dozen fields each. Without
 * this, deciding where to fix the defect means guessing which comparison failed
 * — and each guess costs a full live cycle.
 *
 * Deliberately re-derived here rather than exported from the product: this is a
 * diagnostic view of the same inputs, and a test that imported the predicate
 * would report "they differ because they differ".
 */
function diagnoseMismatch(
  record: Record<string, unknown>,
  container: Record<string, unknown>,
): readonly Readonly<{ field: string; record: string; container: string }>[] {
  const show = (value: unknown): string => (value === undefined ? "<unset>" : JSON.stringify(value));
  const pairs: readonly (readonly [string, unknown, unknown])[] = [
    ["containerId", record.containerId, container.containerId],
    ["containerName", record.containerName, container.containerName],
    ["selectedAgentImageId", record.selectedAgentImageId, container.imageId],
    ["sourceIp", record.sourceIp, container.sourceIp],
    ["state/running", record.state, container.running],
    ["admittedAt", record.admittedAt, undefined],
    ["leaseGeneration", record.leaseGeneration, undefined],
    ["leaseExpiresAt", record.leaseExpiresAt, undefined],
  ];
  const labels = container.labels as Record<string, string> | undefined;
  const labelled: readonly (readonly [string, unknown, unknown])[] = [
    ["sessionId", record.sessionId, labels?.["io.runfree.session-id"]],
    ["sessionIncarnation", record.sessionIncarnation, labels?.["io.runfree.session-incarnation"]],
    ["selectedAgentImageInputDigest", record.selectedAgentImageInputDigest,
      labels?.["io.runfree.selected-agent-image-input-digest"]],
    ["sessionAgentMaterializationDigest", record.sessionAgentMaterializationDigest,
      labels?.["io.runfree.session-agent-materialization-digest"]],
    ["sessionAgentGenerationDigest", record.sessionAgentGenerationDigest,
      labels?.["io.runfree.session-agent-generation-digest"]],
    ["sessionTemplateDigest", record.sessionTemplateDigest, labels?.["io.runfree.session-template-digest"]],
    ["admissionContractEpoch", record.admissionContractEpoch, labels?.["io.runfree.admission-contract-epoch"]],
  ];
  return Object.freeze([...pairs, ...labelled]
    .filter(([field, left, right]) => {
      // `state/running` and the lease fields are reported unconditionally: they
      // are the ones whose *presence* decides which predicate applies, so their
      // values matter even when nothing "differs".
      if (field === "state/running" || field.startsWith("lease") || field === "admittedAt") return true;
      return String(left ?? "") !== String(right ?? "");
    })
    .map(([field, left, right]) => Object.freeze({ field, record: show(left), container: show(right) })));
}

/** Exit code for "the project was already dirty", distinct from a crash failure. */
export const CRASH_PRECONDITION_EXIT = 4;

/** Exit code for "nobody released the hold", distinct from a lifecycle failure. */
export const CRASH_HOLD_TIMEOUT_EXIT = 5;

export const HELD_STATE_FILE = "held.json";
export const HOLD_RELEASE_FILE = "release";
const HOLD_POLL_INTERVAL_MS = 100;
const HOLD_TIMEOUT_MS = 120_000;
/**
 * How often `--kill-when-attached` re-reads the registry, and how long it waits.
 *
 * Deliberately faster than the hold poll: the attached window is bounded by how
 * long the launched agent process happens to live, and a slow poll would turn a
 * short-lived agent into a flaky miss reported as an unrelated failure. Reading
 * the registry is a directory scan of small JSON files, so the cost of polling
 * this often is not the concern; missing the window is.
 */
const ATTACHED_POLL_INTERVAL_MS = 25;
const ATTACHED_WAIT_TIMEOUT_MS = 120_000;

export type HeldSessionState = Readonly<{
  reason: string;
  records: readonly Readonly<{
    sessionId: string;
    state: string;
    sourceIp: string;
    sessionIncarnation: string;
    containerId: string | null;
  }>[];
}>;

/**
 * Pauses the lifecycle at a transition so a caller can act on live state.
 *
 * The crash mode proves what survives when the process dies. Several remaining
 * proofs need the opposite: the process stays alive while the *world* changes
 * underneath it — a competing container takes the session's address before it
 * starts, or a second network is attached after it starts. Both are
 * observations about a running lifecycle, and neither is reachable by racing a
 * probe that completes in seconds.
 *
 * The same command-stream seam does it: at the chosen transition, write what
 * the registry currently holds and wait for a release file. Bounded, and a hold
 * nobody releases exits with its own code so it cannot be mistaken for a
 * lifecycle failure.
 */
/**
 * Publishes held state atomically: temp file, then rename. The live tests poll
 * for the file's existence and parse it at once, so a plain write can be
 * observed while still empty ("Unexpected end of JSON input"), which ends the
 * case before its cleanup registers the session and poisons every later case.
 */
function publishHeldState(directory: string, state: HeldSessionState): void {
  fs.mkdirSync(directory, { recursive: true });
  const target = path.join(directory, HELD_STATE_FILE);
  const temp = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(state)}\n`);
  fs.renameSync(temp, target);
}

function holdAtTransition(options: CrashOptions, reason: string, workspace: string): void {
  const directory = options.holdDir;
  if (!directory) throw new Error("--hold-at requires --hold-dir");
  const observed = report(workspace);
  const detailed = detailedRecords(workspace);
  const state: HeldSessionState = Object.freeze({ reason, records: detailed });
  publishHeldState(directory, state);
  process.stderr.write(`crash-injection: holding at ${reason}; ${observed.records.length} record(s)\n`);

  const release = path.join(directory, HOLD_RELEASE_FILE);
  const deadline = Date.now() + HOLD_TIMEOUT_MS;
  while (!fs.existsSync(release)) {
    if (Date.now() >= deadline) {
      process.stderr.write(`crash-injection: hold at ${reason} was never released\n`);
      process.exit(CRASH_HOLD_TIMEOUT_EXIT);
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, HOLD_POLL_INTERVAL_MS);
  }
  process.stderr.write(`crash-injection: released from ${reason}\n`);
}

/** The registry as it stands, with the fields a live proof needs to act on. */
function detailedRecords(workspace: string): HeldSessionState["records"] {
  const { activePlan, expectedProject } = resolveProject(workspace);
  return Object.freeze(listSessionContainerRecordsV2(activePlan.paths.stateDir, expectedProject)
    .map((record) => {
      const value = record as unknown as Record<string, unknown>;
      return Object.freeze({
        sessionId: String(value.sessionId ?? ""),
        state: String(value.state ?? ""),
        sourceIp: String(value.sourceIp ?? ""),
        sessionIncarnation: String(value.sessionIncarnation ?? ""),
        containerId: typeof value.containerId === "string" ? value.containerId : null,
      });
    }));
}

function report(workspace: string): CrashReport {
  const { io, activePlan, expectedProject } = resolveProject(workspace);
  const records = listSessionContainerRecordsV2(activePlan.paths.stateDir, expectedProject);
  const containers = inspectSessionContainerInventory(
    (executable, args, dockerOptions) => io.capture(executable, [...args], dockerOptions),
    expectedProject,
    { env: activePlan.execution.dockerClientEnv, maxBuffer: CAPTURE_MAX_BYTES, shell: false },
  );
  const residual = classifySessionContainerReconciliation({ expectedProject, records, containers });
  return Object.freeze({
    v: 1 as const,
    kind: "runfree-session-admission-crash-report" as const,
    // Only the state and identity are reported. A crash report that echoed the
    // whole record would make this runner a second, weaker reader of a format
    // the product already owns.
    records: Object.freeze(records.map((record) => {
      const value = record as unknown as Record<string, unknown>;
      return Object.freeze({
        state: String(value.state ?? "unknown"),
        sessionId: String(value.sessionId ?? "unknown"),
        leaseExpiresAt: typeof value.leaseExpiresAt === "string" ? value.leaseExpiresAt : null,
      });
    })),
    residualContainers: residual.length,
    lifecycleRegistryEmpty: records.length === 0,
  });
}

/**
 * Harness-only reset. **Not** part of any assertion.
 *
 * When the product's own recovery cannot converge, every later crash case
 * inherits that state and fails for an inherited reason, so exactly one crash
 * point per run gets tested. This removes the residue directly — the session
 * containers and their lifecycle record files — so the remaining points are
 * still exercised. It runs only after a case has finished asserting, and a case
 * that needed it has already failed on the recovery assertion.
 *
 * It touches only containers this project's reconciliation classifies as its
 * own session containers, and only record files under this project's session
 * record root.
 */
function forceClean(workspace: string): CrashReport {
  const { io, activePlan, expectedProject } = resolveProject(workspace);
  const records = listSessionContainerRecordsV2(activePlan.paths.stateDir, expectedProject);
  const containers = inspectSessionContainerInventory(
    (executable, args, dockerOptions) => io.capture(executable, [...args], dockerOptions),
    expectedProject,
    { env: activePlan.execution.dockerClientEnv, maxBuffer: CAPTURE_MAX_BYTES, shell: false },
  );
  const residual = classifySessionContainerReconciliation({ expectedProject, records, containers });
  // File first, container next, record last — the order the product's own
  // teardown uses, because a reset that released an address while the proxy
  // still held a file for it would be modelling the bug rather than clearing
  // it. Under the per-session file source the proxy holds the authority, so a
  // reset that removed only records and containers would leave files the proxy
  // still serves, and the next case would fail on the previous case's residue
  // — exactly the cascade this function exists to break. Harness-only, like
  // everything else here, and it reaches only this project's own proxy through
  // the product's sealed session-file commands.
  const effective = readEffectiveControlPlaneV2(activePlan.paths.stateDir);
  if (effective) {
    const proxyId = effective.selection.proxyContainerId;
    const dockerOptions = { env: activePlan.execution.dockerClientEnv, maxBuffer: CAPTURE_MAX_BYTES, shell: false };
    const served = io.capture("docker", [...servedSetReadCommand(proxyId).args], dockerOptions);
    if (served.status === 0) {
      let entries: readonly Readonly<{ sessionKey?: unknown }>[] = [];
      try {
        const parsed: unknown = JSON.parse(served.stdout);
        if (!Array.isArray(parsed)) throw new Error("invalid served-set response");
        entries = parsed as typeof entries;
      } catch (error) {
        throw new Error("cleanup could not read the served set", { cause: error });
      }
      if (records.length === 0 && residual.length === 0 && entries.length === 0) {
        // records is the same lifecycle-registry read used by report(); the
        // guarded empty result needs no second container inventory.
        const kernel = io.capture("docker", [...sessionAdmissionFirewallSetReadCommand(proxyId).args], dockerOptions);
        if (kernel.status !== 0) throw new Error(`cleanup could not inspect the kernel session set: ${kernel.stderr}`);
        const sets = JSON.parse(kernel.stdout).nftables.filter((entry: { set?: unknown }) => entry.set);
        if (sets.length !== 1 || sets[0].set.name !== "session_ipv4") {
          throw new Error("cleanup could not identify the kernel session set");
        }
        const harnessReset = (sets[0].set.elem ?? []).length !== 0;
        if (harnessReset) {
          // No owner, container, record, or file remains. Clear the orphaned
          // authority for the next case, but report that repair as a failure.
          const flushed = io.capture("docker", ["exec", "--user", "0:0", proxyId, "nft", "flush", "set", "inet", "runfree_proxy", "session_ipv4"], dockerOptions);
          if (flushed.status !== 0) throw new Error(`cleanup could not clear orphaned kernel authority: ${flushed.stderr}`);
        }
        return { v: 1, kind: "runfree-session-admission-crash-report", records: [], residualContainers: 0, lifecycleRegistryEmpty: true, harnessReset };
      }
      for (const entry of entries) {
        const sessionKey = typeof entry.sessionKey === "string" ? entry.sessionKey : undefined;
        if (sessionKey === undefined || !/^[a-f0-9]{64}$/u.test(sessionKey)) continue;
        io.capture("docker", [...sessionFileDeleteCommand(proxyId, sessionKey).args], dockerOptions);
      }
    }
  }
  for (const classification of classifySessionContainerReconciliation({ expectedProject, records, containers })) {
    const containerIds = "container" in classification
      ? [classification.container.containerId]
      : "containers" in classification
        ? classification.containers.map((candidate) => candidate.containerId)
        : [];
    for (const containerId of containerIds) {
      io.capture("docker", ["container", "rm", "--force", containerId], {
        env: activePlan.execution.dockerClientEnv,
        maxBuffer: CAPTURE_MAX_BYTES,
        shell: false,
      });
    }
  }
  const root = sessionContainerRecordsRoot(activePlan.paths.stateDir);
  for (const record of records) {
    const sessionId = String((record as unknown as { sessionId?: unknown }).sessionId ?? "");
    // Refuses anything that is not a plain file name under this project's own
    // record root, so a malformed record can never direct a delete elsewhere.
    if (!/^[A-Za-z0-9._-]+$/u.test(sessionId)) continue;
    const recordPath = sessionContainerRecordPath(activePlan.paths.stateDir, sessionId);
    if (!recordPath.startsWith(`${root}${path.sep}`)) continue;
    fs.rmSync(recordPath, { force: true });
    removeSessionHostStatus(activePlan.paths.stateDir, sessionId);
  }
  return { ...report(workspace), harnessReset: true };
}

/**
 * Resumes the newest interrupted host recovery item for the agent through the
 * internal admission path, observing the Docker command stream.
 *
 * A failure is captured rather than thrown, matching `recover`: the caller
 * needs the observed state on both sides either way, and that state is the
 * evidence for the finding.
 */
async function resumeCrashed(workspace: string, agent: SessionAdmissionProbeAgent): Promise<CrashResumeReport> {
  const before = report(workspace);
  const observed: string[] = [];
  let itemSummary: CrashResumeReport["item"];
  let outcome: CrashResumeReport["outcome"];
  let failure: string | undefined;
  try {
    const { io, context, preparedRuntime } = resolveProject(workspace);
    const watchingIo = Object.freeze({
      ...io,
      run(command: string, args: string[], runOptions?: Parameters<typeof io.run>[2]) {
        const status = io.run(command, args, runOptions);
        observed.push(args.join(" "));
        return status;
      },
      capture(command: string, args: string[], captureOptions?: Parameters<typeof io.capture>[2]) {
        const result = io.capture(command, args, captureOptions);
        observed.push(args.join(" "));
        return result;
      },
    });
    const foregroundSpawner: SessionContainerForegroundSpawner = (executable, args, spawnOptions) => {
      observed.push(args.join(" "));
      return childProcess.spawn(executable, [...args], spawnOptions) as ReturnType<SessionContainerForegroundSpawner>;
    };
    const inventory = scanRecoveryInventory({ env: context.env ?? process.env, projectRoot: context.projectRoot });
    const item = inventory.items
      .filter((candidate) => candidate.agent === agent && candidate.evidenceKind === "host")
      .sort((left, right) => (right.startedAt ?? "").localeCompare(left.startedAt ?? ""))[0];
    if (!item) throw new Error(`no host recovery evidence exists for ${agent}`);
    itemSummary = Object.freeze({
      id: item.id,
      sessionId: item.sourceId,
      state: item.state,
      evidenceKind: item.evidenceKind,
    });
    outcome = await resumeInterruptedSessionThroughAdmission({
      preparedRuntime,
      io: watchingIo,
      item,
      foregroundSpawner,
    });
  } catch (error) {
    failure = renderFailure(error);
  }
  return Object.freeze({
    v: 1 as const,
    kind: "runfree-session-admission-crash-resume" as const,
    before,
    after: report(workspace),
    ...(itemSummary === undefined ? {} : { item: itemSummary }),
    ...(outcome === undefined ? {} : { outcome }),
    observedCommands: Object.freeze(observed),
    ...(failure === undefined ? {} : { failure, diagnosis: diagnose(workspace) }),
  });
}

/**
 * How often the launch mode re-reads the registry while waiting for attached.
 *
 * Slower than the kill selector's poll on purpose: the launched stand-in agent
 * sleeps for an hour, so the attached window here is not fleeting, and each
 * poll is a synchronous registry read on the same event loop that runs the
 * driver's lease renewal.
 */
const LAUNCH_OBSERVER_POLL_INTERVAL_MS = 100;

/**
 * Runs the production launch path to completion, publishing the attached state.
 *
 * The launch is not crashed and not held: it ends when the attached process
 * ends, which the caller controls from outside (stopping the container, or
 * introducing drift that lease renewal must refuse). The registry watcher
 * publishes the first attached observation to `--hold-dir` so the caller can
 * act on the live session; the labelled report then carries the launch outcome
 * and the converged project state.
 *
 * A failure is captured rather than thrown, matching `recover` and `resume`:
 * for the drift case the failure *is* the expected result, and the caller needs
 * the converged state either way.
 */
async function launchAndReport(options: CrashOptions): Promise<CrashLaunchReport> {
  const directory = options.holdDir;
  if (!directory) throw new Error("--launch requires --hold-dir");
  // Wait in this process instead of redoing Docker inventory on every lock
  // miss. Recapture the plan and the starting registry only after acquisition.
  const initial = resolveProject(options.workspace);
  const lock = await tryAcquireProjectLifecycleLockWithRetry(initial.context, { attempts: 1501, delayMs: 200 });
  if (!lock) throw new Error("project lifecycle lock remained held for 300 seconds");
  const sessionLockManager = createSessionLockManager(initial.context, lock);
  try {
    // Concurrent launches need only the starting IDs for their observer. The
    // driver's preflight still performs the real container inventory; a second
    // inventory here would have no precondition to check in this mode.
    const starting = options.allowExistingSessions ? undefined : report(options.workspace);
    if (starting && (!starting.lifecycleRegistryEmpty || starting.residualContainers !== 0)) {
      process.stderr.write(
        `launch-observer: refusing to launch into a dirty project: ${starting.records.length} record(s) and ${starting.residualContainers} residual container(s) remain from an earlier case\n`,
      );
      sessionLockManager.close();
      process.exit(CRASH_PRECONDITION_EXIT);
    }
    const startingSessionIds = new Set((starting?.records ?? detailedRecords(options.workspace)).map((record) => record.sessionId));

    let attached: HeldSessionState | null = null;
    let outcome: SessionAdmissionLaunchOutcome | undefined;
    let failure: string | undefined;
    let observer: NodeJS.Timeout | undefined;
    try {
      const { io, preparedRuntime } = resolveProject(options.workspace);
      // `--fail-session-file-delete`: the sealed delete is refused exactly the
      // way the real command refuses, and never reaches Docker, so the file it
      // would have removed is genuinely still published when the ordered teardown
      // stops.
      const injectedIo = options.failSessionFileDelete
        ? Object.freeze({
            ...io,
            capture(
              command: string,
              args: string[],
              captureOptions?: Parameters<typeof io.capture>[2],
            ): ReturnType<typeof io.capture> {
              if (command === "docker" && sessionFileCommandEffect(args) === "delete") {
                return { status: 1, stdout: "", stderr: "injected session-file delete failure" };
              }
              return io.capture(command, args, captureOptions);
            },
          })
        : io;
      // `--launch-hold-at`: the same command-stream seam the crash and hold
      // modes use, applied to the production launch. The first armed match
      // pauses the host until the hold directory's release file appears; the
      // launch then continues to completion and reports as usual. Held state is
      // published to the same directory the attached observer uses, under the
      // transition's reason rather than "attached".
      let sessionStartObserved = false;
      let held = false;
      const watchForHold = (args: readonly string[], stdout?: string): void => {
        const point = options.launchHoldPoint;
        if (point === undefined || held) return;
        if (point === "before-session-file-write") {
          // Armed by the proof's own observation: the first post-start inspect
          // that reports the session container running is the last thing that
          // happens before the sealed inspect-and-write, so holding at that
          // observation parks the launch with a running container and no session
          // file.
          if (!sessionStartObserved) {
            if (matchesCrashPoint(args, "after-start")) sessionStartObserved = true;
            return;
          }
          if (!matchesCrashPoint(args, "after-running-inspect") || !inspectReportsRunning(stdout)) return;
          held = true;
          holdAtTransition(options, `${point} #1`, options.workspace);
          return;
        }
        const armed = crashPointArmed(point, sessionStartObserved);
        if (matchesCrashPoint(args, "after-start")) sessionStartObserved = true;
        if (!armed || !matchesCrashPoint(args, point)) return;
        held = true;
        holdAtTransition(options, `${point} #1`, options.workspace);
      };
      const heldIo = options.launchHoldPoint === undefined
        ? injectedIo
        : Object.freeze({
            ...injectedIo,
            run(command: string, args: string[], runOptions?: Parameters<typeof io.run>[2]) {
              const status = injectedIo.run(command, args, runOptions);
              watchForHold(args);
              return status;
            },
            capture(command: string, args: string[], captureOptions?: Parameters<typeof io.capture>[2]) {
              const result = injectedIo.capture(command, args, captureOptions);
              watchForHold(args, result.stdout);
              return result;
            },
          });
      const foregroundSpawner: SessionContainerForegroundSpawner = (executable, args, spawnOptions) => {
        const child = childProcess.spawn(executable, [...args], spawnOptions) as ReturnType<SessionContainerForegroundSpawner>;
        watchForHold(args);
        return child;
      };
      const driver = createInternalSessionAdmissionDriver({
        preparedRuntime,
        sessionLockManager,
        io: heldIo,
        foregroundSpawner,
      });

      fs.mkdirSync(directory, { recursive: true });
      observer = setInterval(() => {
        if (attached) return;
        let records: HeldSessionState["records"];
        try {
          records = detailedRecords(options.workspace).filter((record) => (
            record.state === "attached" && !startingSessionIds.has(record.sessionId)
          ));
        } catch {
          // The registry is mid-write during transitions; the next poll reads it.
          return;
        }
        if (records.length === 0) return;
        attached = Object.freeze({ reason: "attached", records });
        publishHeldState(directory, attached);
        process.stderr.write(
          `launch-observer: observed attached session ${records.map((record) => record.sessionId).join(", ")}\n`,
        );
      }, LAUNCH_OBSERVER_POLL_INTERVAL_MS);
      observer.unref?.();

      outcome = await driver.launchBuiltin(options.agent);
    } catch (error) {
      failure = renderFailure(error);
    } finally {
      if (observer) clearInterval(observer);
    }
    return Object.freeze({
      v: 1 as const,
      kind: "runfree-session-admission-crash-launch" as const,
      attached,
      ...(outcome === undefined
        ? {}
        : { outcome: Object.freeze({ status: outcome.status, signal: outcome.signal }) }),
      after: report(options.workspace),
      ...(failure === undefined ? {} : { failure, diagnosis: diagnose(options.workspace) }),
    });
  } finally {
    sessionLockManager.close();
  }
}

async function recover(workspace: string, agent: SessionAdmissionProbeAgent): Promise<CrashRecoveryReport> {
  const before = report(workspace);
  let failure: string | undefined;
  try {
    const { io, context, preparedRuntime } = resolveProject(workspace);
    const lock = tryAcquireProjectLifecycleLock(context);
    if (!lock) throw new Error("project lifecycle lock is held by another runtime operation");
    const sessionLockManager = createSessionLockManager(context, lock);
    try {
      const driver = createInternalSessionAdmissionDriver({ preparedRuntime, sessionLockManager, io });
      await driver.recoverPending(agent);
    } finally {
      sessionLockManager.close();
    }
  } catch (error) {
    // Captured rather than thrown: the caller needs the observed state on both
    // sides of a failed recovery, which is the evidence for the finding, and a
    // thrown error would take the report with it.
    failure = renderFailure(error);
  }
  return Object.freeze({
    v: 1 as const,
    kind: "runfree-session-admission-crash-recovery" as const,
    before,
    after: report(workspace),
    recovered: failure === undefined,
    ...(failure === undefined ? {} : { failure, diagnosis: diagnose(workspace) }),
  });
}

/**
 * Reads the daemon's own view of a container, unnormalized.
 *
 * A second `docker container inspect` rather than values carried out of the
 * snapshot, because the snapshot is the *parsed* view and the parse is exactly
 * what keeps being wrong.
 *
 * Reports every input to `malformedInventoryMetadata` in
 * `session-container-reconciliation.ts` — name, image, state, config, network
 * settings, and the internal endpoint — because knowing only that the metadata
 * was rejected does not say which of the six rejected it, and each guess about
 * that costs a full live cycle. Raw values, not re-derived verdicts: a
 * diagnostic that re-implemented the predicate could be wrong in the same way.
 */
function rawContainerShape(
  io: ReturnType<typeof createMatrixRuntimeIO>,
  activePlan: { execution: { dockerClientEnv?: NodeJS.ProcessEnv } },
  expectedProject: { composeProject: string },
  containerId: string,
): unknown {
  if (!/^[a-f0-9]{64}$/u.test(containerId)) return undefined;
  const result = io.capture(
    "docker",
    ["container", "inspect", containerId],
    { env: activePlan.execution.dockerClientEnv, maxBuffer: CAPTURE_MAX_BYTES, shell: false },
  );
  if (result.status !== 0) return undefined;
  try {
    const [inspected] = JSON.parse(result.stdout) as Record<string, unknown>[];
    if (!inspected) return undefined;
    const config = inspected.Config as Record<string, unknown> | undefined;
    const state = inspected.State as Record<string, unknown> | undefined;
    const networkSettings = inspected.NetworkSettings as Record<string, unknown> | undefined;
    const networks = networkSettings?.Networks as Record<string, unknown> | undefined;
    const labels = config?.Labels as Record<string, string> | undefined;
    return {
      Name: inspected.Name,
      Image: inspected.Image,
      "typeof Image": typeof inspected.Image,
      "State.Running": state?.Running,
      "typeof State.Running": typeof state?.Running,
      hasConfig: config !== undefined,
      labelCount: labels === undefined ? null : Object.keys(labels).length,
      runfreeLabelKeys: labels === undefined
        ? null
        : Object.keys(labels).filter((key) => key.startsWith("io.runfree.")).sort(),
      // `tolerantDockerLabels` marks the *entire* label set malformed if any
      // single value carries a control character or exceeds 4KB — and Docker
      // merges the image's labels into `Config.Labels`, so an upstream base
      // image's multi-line description would condemn every session container.
      // Reported per offending key, since the set-level verdict does not say
      // which entry caused it.
      offendingLabels: labels === undefined ? null : Object.entries(labels)
        .filter(([name, value]) => name.length === 0
          || name.length > 255
          || typeof value !== "string"
          || Buffer.byteLength(value) > 4 * 1024
          || LABEL_CONTROL_CHARACTERS.test(name)
          || LABEL_CONTROL_CHARACTERS.test(value))
        .map(([name, value]) => ({
          name,
          bytes: typeof value === "string" ? Buffer.byteLength(value) : null,
          preview: typeof value === "string" ? JSON.stringify(value.slice(0, 120)) : String(value),
        })),
      networkKeys: networks === undefined ? null : Object.keys(networks),
      expectedNetworkKey: `${expectedProject.composeProject}_agent_internal`,
      internalEndpoint: networks?.[`${expectedProject.composeProject}_agent_internal`],
    };
  } catch {
    return undefined;
  }
}

/** Field-level explanation of every residual mismatch, for a failed recovery. */
function diagnose(workspace: string): readonly CrashMismatchDiagnosis[] {
  try {
    const { io, activePlan, expectedProject } = resolveProject(workspace);
    const records = listSessionContainerRecordsV2(activePlan.paths.stateDir, expectedProject);
    const containers = inspectSessionContainerInventory(
      (executable, args, dockerOptions) => io.capture(executable, [...args], dockerOptions),
      expectedProject,
      { env: activePlan.execution.dockerClientEnv, maxBuffer: CAPTURE_MAX_BYTES, shell: false },
    );
    const found: CrashMismatchDiagnosis[] = [];
    for (const classification of classifySessionContainerReconciliation({ expectedProject, records, containers })) {
      if (classification.kind !== "mismatch") continue;
      const record = classification.record as unknown as Record<string, unknown>;
      for (const container of classification.containers) {
        const snapshot = container as unknown as Record<string, unknown>;
        const containerId = String(snapshot.containerId ?? "unknown");
        const endpoint = rawContainerShape(io, activePlan, expectedProject, containerId);
        found.push(Object.freeze({
          sessionId: String(record.sessionId ?? "unknown"),
          recordState: String(record.state ?? "unknown"),
          containerId,
          containerRunning: snapshot.running === true,
          differences: diagnoseMismatch(record, snapshot),
          malformedInventoryMetadata: snapshot.malformedInventoryMetadata === true,
          ...(endpoint === undefined ? {} : { rawContainerShape: endpoint }),
        }));
      }
    }
    return Object.freeze(found);
  } catch {
    // Diagnosis must never replace the failure it is explaining.
    return Object.freeze([]);
  }
}

async function crash(options: CrashOptions): Promise<never> {
  // Checked here rather than by a separate caller invocation, to keep each
  // crash case to as few blocking subprocess calls as possible. A dirty project
  // means an earlier case failed to converge and this one would test its
  // residue instead of its own crash.
  if (options.mode === "crash" || options.mode === "hold") {
    const starting = report(options.workspace);
    if (!starting.lifecycleRegistryEmpty || starting.residualContainers !== 0) {
      process.stderr.write(
        `crash-injection: refusing to crash a dirty project: ${starting.records.length} record(s) and ${starting.residualContainers} residual container(s) remain from an earlier case\n`,
      );
      process.exit(CRASH_PRECONDITION_EXIT);
    }
  }

  const { io, context, preparedRuntime } = resolveProject(options.workspace);
  const observed: string[] = [];
  let matches = 0;
  let sessionStartObserved = false;
  let heldAtTransition = false;

  const watch = (args: readonly string[]): void => {
    observed.push(args.join(" "));
    // Evaluated before this argv updates the stream state, so the start
    // command itself still satisfies `after-start`, while an order-gated point
    // arms only for commands that come after it.
    const armed = options.crashPoint === undefined
      || crashPointArmed(options.crashPoint, sessionStartObserved);
    if (matchesCrashPoint(args, "after-start")) sessionStartObserved = true;
    if (options.mode === "list-commands") return;
    let reason: string | undefined;
    if (options.killAfterCommand !== undefined) {
      if (observed.length !== options.killAfterCommand) return;
      reason = `command #${observed.length}`;
    } else {
      if (!options.crashPoint || !armed || !matchesCrashPoint(args, options.crashPoint)) return;
      matches += 1;
      if (matches < options.occurrence) return;
      reason = `${options.crashPoint} #${matches}`;
    }
    if (options.mode === "hold") {
      heldAtTransition = true;
      holdAtTransition(options, reason, options.workspace);
      return;
    }
    process.stderr.write(`${CRASH_INJECTION_MARKER} ${reason}: ${args.join(" ")}\n`);
    // Uncatchable, by design. No finally block runs and no lifecycle record is
    // tidied. If this transition still holds the lifecycle lock, its directory
    // also remains for stale-owner recovery.
    process.kill(process.pid, "SIGKILL");
  };

  const watchingIo = Object.freeze({
    ...io,
    run(command: string, args: string[], runOptions?: Parameters<typeof io.run>[2]) {
      const status = io.run(command, args, runOptions);
      watch(args);
      return status;
    },
    capture(command: string, args: string[], captureOptions?: Parameters<typeof io.capture>[2]) {
      const result = io.capture(command, args, captureOptions);
      watch(args);
      return result;
    },
  });

  // The foreground launch does NOT pass through `RuntimeIO`. The gateway spawns
  // `docker container start --attach` through a separate `foregroundSpawner`
  // (`session-admission-docker-gateway.ts`), so an io-only watcher never sees
  // the one command that starts project-controlled code — `after-start` silently
  // never fired and the probe ran to completion looking like a clean pass.
  const foregroundSpawner: SessionContainerForegroundSpawner = (executable, args, spawnOptions) => {
    const child = childProcess.spawn(executable, [...args], spawnOptions) as ReturnType<
      SessionContainerForegroundSpawner
    >;
    watch(args);
    return child;
  };

  const lock = tryAcquireProjectLifecycleLock(context);
  if (!lock) throw new Error("project lifecycle lock is held by another runtime operation");
  const sessionLockManager = createSessionLockManager(context, lock);
  const driver = createInternalSessionAdmissionDriver({
    preparedRuntime,
    sessionLockManager,
    io: watchingIo,
    foregroundSpawner,
  });
  // Watches the registry rather than the command stream, because the state this
  // selector targets issues no commands. Stopped on every exit path so a run
  // that failed for an unrelated reason cannot be killed by a stale timer and
  // reported as a successful crash.
  let attachedWatch: NodeJS.Timeout | undefined;
  const watchForAttachedSession = (): void => {
    const deadline = Date.now() + ATTACHED_WAIT_TIMEOUT_MS;
    attachedWatch = setInterval(() => {
      const attached = detailedRecords(options.workspace).filter((record) => record.state === "attached");
      if (attached.length === 0) {
        if (Date.now() < deadline) return;
        clearInterval(attachedWatch);
        process.stderr.write("crash-injection: no session reached attached before the wait expired\n");
        process.exit(3);
      }
      process.stderr.write(
        `${CRASH_INJECTION_MARKER} attached session ${attached.map((record) => record.sessionId).join(", ")}\n`,
      );
      // Same uncatchable kill as the command-triggered path: no finally runs and
      // no record is tidied. The attached wait has already yielded the lifecycle
      // lock, while the agent keeps running inside its container. That is the
      // residue a killed client leaves and the case recovery has to answer.
      process.kill(process.pid, "SIGKILL");
    }, ATTACHED_POLL_INTERVAL_MS);
    attachedWatch.unref?.();
  };

  try {
    if (options.killWhenAttached) {
      watchForAttachedSession();
      // The only caller of the production launch path anywhere in the repo.
      // Everything else drives `probeBuiltin`, which never activates.
      await driver.launchBuiltin(options.agent);
    } else {
      await driver.probeBuiltin(options.agent);
    }
  } finally {
    if (attachedWatch) clearInterval(attachedWatch);
    sessionLockManager.close();
    // The command stream is the diagnostic for every outcome of this mode,
    // including a probe that failed for an unrelated reason.
    if (options.mode === "list-commands") {
      for (const command of observed) process.stdout.write(`${CRASH_COMMAND_MARKER} ${command}\n`);
    }
  }

  if (options.mode === "list-commands") process.exit(0);
  // A hold that occurred and was released ran the lifecycle to completion;
  // that is the hold mode's success, distinct from the "never occurred"
  // failure below (which formerly swallowed it under exit 3).
  if (options.mode === "hold" && heldAtTransition) process.exit(0);
  // Reached only when the requested transition never occurred. Completing the
  // probe here would look identical to a successful crash test from the
  // outside, so it fails loudly and prints the stream that was actually seen.
  //
  // For an attached selector this means the launched agent exited before the
  // session was ever observed attached, so there was no window to crash in.
  const requested = options.killWhenAttached
    ? "an attached session"
    : options.killAfterCommand !== undefined
      ? `command #${options.killAfterCommand}`
      : `${options.crashPoint} #${options.occurrence}`;
  process.stderr.write(
    `crash-injection: ${requested} never occurred; observed ${observed.length} Docker commands:\n`,
  );
  process.stderr.write(`${observed.join("\n")}\n`);
  process.exit(3);
}

async function main(): Promise<number> {
  const options = parseArguments(process.argv.slice(2));
  if (options.mode === "report") {
    process.stdout.write(`${JSON.stringify(report(options.workspace))}\n`);
    return 0;
  }
  if (options.mode === "recover") {
    process.stdout.write(`${JSON.stringify(await recover(options.workspace, options.agent))}\n`);
    return 0;
  }
  if (options.mode === "resume") {
    process.stdout.write(`${JSON.stringify(await resumeCrashed(options.workspace, options.agent))}\n`);
    return 0;
  }
  if (options.mode === "launch") {
    process.stdout.write(`${JSON.stringify(await launchAndReport(options))}\n`);
    return 0;
  }
  if (options.mode === "force-clean") {
    process.stdout.write(`${JSON.stringify(forceClean(options.workspace))}\n`);
    return 0;
  }
  await crash(options);
  return 0;
}

function isMainModule(): boolean {
  const entrypoint = process.argv[1];
  return Boolean(entrypoint) && pathToFileURL(path.resolve(entrypoint)).href === import.meta.url;
}

// Guarded exactly as the matrix runner is. Without it, importing this module —
// which the unit tests and the live tranche both do, for `CRASH_POINTS` and the
// report type — parses the test runner's own argv and exits the process.
if (isMainModule()) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`${renderFailure(error)}\n`);
      process.exitCode = 1;
    },
  );
}
