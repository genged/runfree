// Shared host support for the three attached-session live tranches.
//
// Split out when the tranche itself was split into three files. It was one
// file of 2,536 lines holding three independent describes, each provisioning
// its own fixture; measured on Docker Desktop it ran 604.6 s of a 606.0 s
// wall clock, so the whole live suite waited on it while other workers idled.
// Three files run on three workers; one did not.
//
// Nothing here is a tranche. This module owns the launch drivers, the consumer
// readbacks and the project configuration the three share — the pieces whose
// duplication across files would let two tranches disagree about what
// "attached" or "served" means.
//
// Consumer state is read back from the proxy container itself, not from the
// host modules that wrote it: `cat` of the selection pointers and the selected
// immutable bindings, and `nft` for the enforced set. The taxonomy's
// declarative-config lesson applies — the daemon and the ruleset are the
// evidence, the renderer is not.
//
// The launched "agent" is the first-request stub (`agent-stub.ts`): a
// long-lived stand-in that sends one real request to an allowlisted host the
// moment it starts and records the answer. That first request is the
// activation-gate design's positive live proof (T5): behind the session entry
// it lands after activation and succeeds, where the real CLI used to be
// answered 403 and exit.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runfreeStateRoot } from "../../../packages/cli/src/paths.ts";
import { listSessionContainerRecordsV2 } from "../../../packages/cli/src/runtime/session-containers.ts";
import {
  sessionAdmissionFirewallSetReadCommand,
  servedSetReadCommand,
} from "../../../packages/cli/src/runtime/session-file-publisher.ts";
import {
  CRASH_LAUNCH_PREFIX,
  CRASH_PRECONDITION_EXIT,
  HELD_STATE_FILE,
  HOLD_RELEASE_FILE,
  type CrashLaunchReport,
  type HeldSessionState,
  type LaunchHoldPoint,
} from "../session-admission-crash.ts";
import {
  FIRST_REQUEST_HOST,
  FIRST_REQUEST_RESULT_RELATIVE_PATH,
  stageFirstRequestAgentBinary,
} from "./agent-stub.ts";
import { docker, dockerOrThrow } from "./docker.ts";
import { describeOutput, type LiveFixture, type LiveRuntimeBackend } from "./fixture.ts";
import { cliEntryArgv, sessionAdmissionCrashEntryArgv } from "../../support/prebuilt-entry.ts";
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const PROVISION_TIMEOUT_MS = 30 * 60_000;
export const TEST_TIMEOUT_MS = 15 * 60_000;
/** Admission to attached is seconds on a healthy daemon; the bound is for a cold one. */
export const ATTACHED_WAIT_TIMEOUT_MS = 360_000;
export const PROBE_AGENT = "claude" as const;

/**
 * Which admission source this run drives, decided once.
 *
 * The two sources answer "who is admitted" through different mechanisms, so a
 * handful of cases below exist for one of them only: the peer-lock lapse (L1)
 * is a property of a heartbeat that takes the lifecycle lock, and the file
 * cases are properties of a heartbeat that does not. Each is declared with the
 * matching helper so the other run records it skipped by name rather than
 * silently not existing.
 */

/**
 * A shortened heartbeat cadence for the file-source cases, clamped by the
 * driver to `[1s, 30s]`. Renewal timing is what several of these cases wait on,
 * and at the half-minute default each wait would be minutes of live time for a
 * property that is decided in one beat.
 */
export const FAST_HEARTBEAT_ENV = { RUNFREE_SESSION_HEARTBEAT_CADENCE_MS: "2000" } as const;
/** Bound for one session's ordered teardown to take its file away. */
export const SESSION_TEARDOWN_TIMEOUT_MS = 60_000;
/**
 * How long the held-lock case samples A's authority. Deliberately longer than
 * the shortened lease it runs under, so a heartbeat that the peer's lock really
 * did starve would lapse inside the window rather than after it.
 */
export const PEER_LOCK_HEARTBEAT_WINDOW_MS = 35_000;
/** Bound for a forced policy reload to republish the eligibility file. */
export const ELIGIBILITY_REPUBLISH_TIMEOUT_MS = 30_000;
/** The plan's own bound for sessions to be served again after a proxy restart. */
export const SESSION_REFILL_TIMEOUT_MS = 30_000;
/** The loopback port the ingress-forwarder case opens; nothing listens on it. */
export const FORWARD_PROBE_PORT = 3000;
/** Bound for a write to reach the pending-approval channel and be decided. */
export const HELD_WRITE_TIMEOUT_MS = 60_000;
/**
 * Bound for the file source's consumers to converge on a changed session set.
 *
 * The generation path waits for both consumer acknowledgements before the host
 * call returns, so a completed teardown there has already converged. The file
 * source publishes no acknowledgement: the firewall's own 100 ms
 * level-triggered loop is what adds and drops addresses, so a read taken the
 * instant a sealed write or delete returned can legitimately be one loop
 * behind. The bound is the claim — convergence is prompt, not eventual — and it
 * is deliberately far below any lease, so a set that stayed wrong because a
 * heartbeat lapsed still fails.
 */
export const CONSUMER_CONVERGENCE_TIMEOUT_MS = 15_000;

export function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the attached admission tranche");
  }
  return backend;
}

export type LaunchRun = Readonly<{
  /** Resolves when the launch runner exits, with its full output. */
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  /** The registry as first observed attached. */
  attached: HeldSessionState;
  /** The runner's output collected so far, for a poll that times out beside it. */
  output: () => string;
  /**
   * SIGKILLs the owning host process and settles, leaving its session behind.
   *
   * Uncatchable, so no teardown runs: the session file stays published, the
   * record stays in place, and the container keeps running under the
   * `docker start --attach` child that survives its parent. That is the residue
   * a closed terminal leaves, and what the next launch's reconcile must clear.
   */
  killOwner: () => Promise<void>;
}>;

/**
 * Starts a full production launch and waits until a session is attached.
 *
 * The runner publishes the first attached observation to the hold directory
 * and then runs to completion on its own; the session ends when this test ends
 * it from outside. The completion carries the runner's labelled report.
 */
export async function startAttachedLaunch(
  fixture: LiveFixture,
  options: Readonly<{ allowExistingSessions?: boolean; extraEnv?: NodeJS.ProcessEnv }> = {},
): Promise<LaunchRun> {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-launch."));
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
      ...(options.allowExistingSessions ? ["--allow-existing-sessions"] : []),
    ],
    { cwd: REPO_ROOT, env: { ...fixture.env, ...options.extraEnv }, stdio: ["ignore", "pipe", "pipe"] },
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
  const deadline = Date.now() + ATTACHED_WAIT_TIMEOUT_MS;
  while (!fs.existsSync(statePath)) {
    if (exited) {
      const detail = exited.status === CRASH_PRECONDITION_EXIT
        ? "the project was not clean before the launch, so an earlier case failed to converge"
        : "the launch ended before any session was observed attached";
      throw new Error(`${detail}: ${describeOutput(exited.output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`no session reached attached: ${describeOutput(output, 4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const attached = JSON.parse(fs.readFileSync(statePath, "utf8")) as HeldSessionState;
  const killOwner = async (): Promise<void> => {
    child.kill("SIGKILL");
    // A brief drain for output already in flight, then release this end of the
    // stdio pipes. The surviving `docker start --attach` client inherited them,
    // so `close` would otherwise wait for the very process this crash
    // deliberately leaves running — the hang the crash tranche already paid for
    // once.
    await new Promise((resolve) => setTimeout(resolve, 250));
    child.stdout?.destroy();
    child.stderr?.destroy();
    await completion.catch(() => undefined);
  };
  return Object.freeze({ completion, attached, output: () => output, killOwner });
}

export function parseLaunchReport(run: Readonly<{ status: number | null; output: string }>): CrashLaunchReport {
  const line = run.output.split("\n").find((candidate) => candidate.startsWith(CRASH_LAUNCH_PREFIX));
  if (!line) {
    throw new Error(`the launch runner emitted no labelled report: ${describeOutput(run.output, 4000)}`);
  }
  return JSON.parse(line) as CrashLaunchReport;
}

/**
 * How long the attached case waits for the stub's first request to be
 * answered and recorded. The request itself is bounded by the stub's own
 * `--max-time 30`; the margin is for a cold upstream connection.
 */
export const FIRST_REQUEST_WAIT_TIMEOUT_MS = 60_000;

/** Waits for the first-request stub's recorded answer and returns the HTTP code it saw. */
export async function firstRequestResult(fixture: LiveFixture): Promise<string> {
  const resultPath = path.join(fixture.projectRoot, FIRST_REQUEST_RESULT_RELATIVE_PATH);
  const deadline = Date.now() + FIRST_REQUEST_WAIT_TIMEOUT_MS;
  while (!fs.existsSync(resultPath)) {
    if (Date.now() >= deadline) {
      const stderrPath = path.join(path.dirname(resultPath), "stderr");
      const detail = fs.existsSync(stderrPath) ? describeOutput(fs.readFileSync(stderrPath, "utf8")) : "<no stderr>";
      throw new Error(`the launched stub never recorded its first request's answer: ${detail}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return fs.readFileSync(resultPath, "utf8").trim();
}

/** Removes a previous case's recorded first request so each launch is judged on its own. */
export function clearFirstRequestResult(fixture: LiveFixture): void {
  fs.rmSync(path.join(fixture.projectRoot, path.dirname(FIRST_REQUEST_RESULT_RELATIVE_PATH)), {
    recursive: true,
    force: true,
  });
}

/** How long a launch may take to reach the held transition. */
export const HELD_WAIT_TIMEOUT_MS = 90_000;

export type HeldLaunch = Readonly<{
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  held: HeldSessionState;
  /** Everything the launch has written so far, for a failure that is waiting on it. */
  output: () => string;
  release(): void;
}>;

/**
 * Starts a production launch that pauses at `point` before continuing to
 * completion once released (`--launch-hold-at`). The held state names the
 * session's container so the caller can act on and observe it.
 */
export async function startHeldLaunch(
  fixture: LiveFixture,
  point: LaunchHoldPoint,
  options: Readonly<{ allowExistingSessions?: boolean; extraEnv?: NodeJS.ProcessEnv }> = {},
): Promise<HeldLaunch> {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-held-launch."));
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
      point,
      ...(options.allowExistingSessions ? ["--allow-existing-sessions"] : []),
    ],
    { cwd: REPO_ROOT, env: { ...fixture.env, ...options.extraEnv }, stdio: ["ignore", "pipe", "pipe"] },
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
      const detail = exited.status === CRASH_PRECONDITION_EXIT
        ? "the project was not clean before the launch, so an earlier case failed to converge"
        : "the launch ended before reaching the hold point";
      throw new Error(`${detail}: ${describeOutput(exited.output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`the launch never reached ${point}: ${describeOutput(output, 4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const held = JSON.parse(fs.readFileSync(statePath, "utf8")) as HeldSessionState;
  if (!held.reason.startsWith(point)) {
    throw new Error(`the launch published ${held.reason} rather than the ${point} hold`);
  }
  return Object.freeze({
    completion,
    held,
    output: () => output,
    release: () => fs.writeFileSync(path.join(holdDir, HOLD_RELEASE_FILE), ""),
  });
}

/** Docker's own view of whether a container is still running and how it exited. */
export function containerExitState(containerId: string): Readonly<{ running: boolean; exitCode: number }> {
  const inspected = dockerOrThrow(`inspect of ${containerId}`, [
    "container",
    "inspect",
    "--format",
    "{{.State.Running}} {{.State.ExitCode}}",
    containerId,
  ]).trim();
  const [running, exitCode] = inspected.split(" ");
  return Object.freeze({ running: running === "true", exitCode: Number(exitCode) });
}

/**
 * The IPv4 elements the firewall is actually enforcing for sessions.
 *
 * `nft -j` of the live ruleset, not the renderer's input: a selection the
 * firewall consumer failed to apply would still show in the pointer file, and
 * only the kernel's own set says what packets are admitted.
 */
export function enforcedSessionSetIps(proxyId: string): readonly string[] {
  return nftSessionSetIps(dockerOrThrow("proxy session nftables set", [
    "exec",
    "--user",
    "0:0",
    proxyId,
    "nft",
    "-j",
    "list",
    "set",
    "inet",
    "runfree_proxy",
    "session_ipv4",
  ]));
}

export function nftSessionSetIps(json: string): readonly string[] {
  const parsed = JSON.parse(json) as { nftables?: readonly Record<string, unknown>[] };
  const ips: string[] = [];
  for (const entry of parsed.nftables ?? []) {
    const set = entry.set as { elem?: readonly unknown[] } | undefined;
    if (!set) continue;
    for (const element of set.elem ?? []) {
      const value = typeof element === "string"
        ? element
        : (element as { elem?: unknown })?.elem;
      if (typeof value === "string") ips.push(value);
    }
  }
  return ips.sort();
}

/**
 * The same set, read through the exact command the product itself uses.
 *
 * `enforcedSessionSetIps` above builds its own `nft` argv, which is the right
 * shape for a test that wants to see the kernel independently. This one runs
 * the sealed `sessionAdmissionFirewallSetReadCommand` argv instead, so the
 * file-source cases assert against what the host's own convergence proof reads
 * rather than against a lookalike of it.
 */
export function firewallSetIpsThroughProductCommand(proxyId: string): readonly string[] {
  const command = sessionAdmissionFirewallSetReadCommand(proxyId);
  const result = docker([...command.args]);
  if (result.status !== 0) {
    throw new Error(`the product's firewall set read failed: ${describeOutput(result.output)}`);
  }
  return nftSessionSetIps(result.stdout);
}

export type ServedSessionFile = Readonly<{
  sessionKey?: string;
  name?: string;
  sourceIp?: string;
  aliveUntil?: string;
  nonce?: string;
  eligible?: boolean;
  wallActive?: boolean;
  malformed?: boolean;
}>;

/**
 * What the proxy currently holds in its sessions directory, read through the
 * product's own sealed served-set command.
 *
 * This is the file source's counterpart to the request proxy's selected
 * bindings: the files are what the proxy serves from, and `eligible` /
 * `wallActive` are the two rules it applies to them.
 */
export function servedSessionFiles(proxyId: string): readonly ServedSessionFile[] {
  const command = servedSetReadCommand(proxyId);
  const result = docker([...command.args]);
  if (result.status !== 0) {
    throw new Error(`the product's served-set read failed: ${describeOutput(result.output)}`);
  }
  return JSON.parse(result.stdout) as readonly ServedSessionFile[];
}

/** The addresses the proxy currently holds a session file for. */
export function servedSourceIps(proxyId: string): readonly string[] {
  return servedSessionFiles(proxyId).map((entry) => String(entry.sourceIp)).sort();
}

/**
 * The key of the file the proxy currently holds for one address, or throws.
 *
 * Addresses are reused: the allocator hands out the lowest free host, so the
 * session that arrives after another leaves legitimately receives the address
 * the leaving one had. A case that has to follow one particular session's file
 * across such a handover reads its key here, while that session is
 * unambiguously the only one served at the address, and keys on the key
 * afterwards.
 */
export function servedSessionKey(proxyId: string, sourceIp: string): string {
  const entry = servedSessionFiles(proxyId).find((candidate) => candidate.sourceIp === sourceIp);
  if (!entry || typeof entry.sessionKey !== "string") {
    throw new Error(`the proxy holds no keyed session file for ${sourceIp}`);
  }
  return entry.sessionKey;
}

/** The lease window the proxy's file for one address currently grants, or throws. */
export function servedAliveUntil(proxyId: string, sourceIp: string): string {
  const entry = servedSessionFiles(proxyId).find((candidate) => candidate.sourceIp === sourceIp);
  if (!entry || typeof entry.aliveUntil !== "string") {
    throw new Error(`the proxy holds no session file for ${sourceIp}`);
  }
  return entry.aliveUntil;
}

/**
 * Stages the first-request stub and allowlists the host it sends to, before
 * the first `up`, so the stub's first request has an upstream the proxy may
 * forward it to. Nothing else about the policy changes; the tranche's
 * consumer assertions are about admitted source IPs, not hosts.
 */
export function configureAttachedProject(fixture: LiveFixture): void {
  stageFirstRequestAgentBinary(fixture);
  const added = fixture.runfree(["host", "add", FIRST_REQUEST_HOST, "--no-reload"]);
  if (added.status !== 0) {
    throw new Error(`runfree host add ${FIRST_REQUEST_HOST} failed: ${describeOutput(added.output)}`);
  }
}

/**
 * A short internally minted lease so the peer-isolation case can drive lease
 * expiry in seconds. The driver clamps this env to `(0, MAX]`, so it only ever
 * shortens the lease. It must stay well above the time a launch spends reaching
 * attached — the lease is not renewed before then — while being small enough
 * that a blocked renewal lapses inside the test's window. The 30s lease leaves
 * admission slack; its margin on a loaded Docker host needs live validation.
 */
export const PEER_LOCK_LEASE_MS = 30_000;
export const PEER_LOCK_LEASE_ENV = { RUNFREE_SESSION_INTERNAL_LEASE_DURATION_MS: String(PEER_LOCK_LEASE_MS) } as const;
/** Bound for A's own renewal to restore authority after the lock is released. */
export const RENEWAL_RESTORE_TIMEOUT_MS = 90_000;

/**
 * Starts a detached write from inside one session container.
 *
 * `exec -d` so the request is left held at the proxy while the test reads the
 * pending-approval channel; the recorded code is written into the container's
 * own /tmp, which nothing here reads back — what this case is about is which
 * session the proxy attributes the hold to, not what the answer eventually is.
 */
export function startHeldWrite(containerId: string, tag: string): void {
  dockerOrThrow(`start the held write from session ${tag}`, [
    "exec",
    "-d",
    containerId,
    "zsh",
    "-lc",
    `curl -sS --max-time 120 -o /dev/null -w '%{http_code}' -X POST https://${FIRST_REQUEST_HOST}/rate_limit`
      + ` > /tmp/runfree-grant-${tag}.code 2>&1`,
  ]);
}

/**
 * A launch running beside a poll, so the poll can say what that launch did.
 *
 * When the thing being polled for is something a *second* launch has to
 * produce, the poll's own label is the least useful half of the failure: the
 * launch's output is the diagnosis. This carries both halves — the completion,
 * so a launch that has already ended takes the wait down with it instead of
 * letting it run out its clock in silence, and the output collected so far,
 * for a launch that is still running at the deadline.
 */
export type LaunchWitness = Readonly<{
  label: string;
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  output: () => string;
}>;

/**
 * Polls a predicate until true or the deadline, then throws with the label.
 *
 * Every witness is a launch the awaited state depends on: the first to exit
 * ends the wait with its output, and a deadline reports what each one has
 * printed so far.
 */
export async function pollUntil(
  predicate: () => boolean,
  timeoutMs: number,
  label: string,
  witness?: LaunchWitness | readonly LaunchWitness[],
): Promise<void> {
  const witnesses: readonly LaunchWitness[] = witness === undefined ? [] : Array.isArray(witness) ? witness : [witness];
  const ended = new Map<LaunchWitness, Readonly<{ status: number | null; output: string }>>();
  for (const candidate of witnesses) {
    void candidate.completion.then((result) => {
      ended.set(candidate, result);
    }, () => undefined);
  }
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    const [exited] = ended;
    if (exited) {
      const [candidate, result] = exited;
      throw new Error(
        `${candidate.label} exited with status ${result.status ?? "<none>"} while waiting for ${label}:`
          + ` ${describeOutput(result.output, 4000)}`,
      );
    }
    if (Date.now() >= deadline) {
      const detail = witnesses
        .map((candidate) => `; ${candidate.label} is still running: ${describeOutput(candidate.output(), 4000)}`)
        .join("");
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${label}${detail}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

export function readDurableSessionRecord(
  fixture: LiveFixture,
  project: string,
  sessionId: string,
): { state: string; leaseGeneration?: string; sessionIncarnation: string; containerId?: string } | undefined {
  const projectId = project.replace(/^runfree-/, "");
  const stateDir = path.join(runfreeStateRoot(fixture.env), "projects", projectId);
  const records = listSessionContainerRecordsV2(stateDir, { projectId, composeProject: project });
  return records.find((record) => record.sessionId === sessionId);
}

/**
 * A hang backstop for a detached CLI, not a budget. The tranches bound their
 * own live work; this only kills a spawn that has already lost its way, so it
 * sits far above the slowest legitimate `up` (a forced image build behind a
 * held barrier, measured at ~70 s).
 */
const ASYNC_CLI_HANG_BACKSTOP_MS = 8 * 60_000;

export type AsyncCliRun = Readonly<{ completion: Promise<Readonly<{ status: number | null; output: string }>>; cancel(): void }>;

/** The fixture's CLI, spawned without blocking so the test can sample while it runs. */
export function startRunfree(fixture: LiveFixture, args: readonly string[], extraEnv: NodeJS.ProcessEnv = {}): AsyncCliRun {
  const child = childProcess.spawn(
    process.execPath,
    [...cliEntryArgv(), "--workspace", fixture.projectRoot, ...args],
    {
      cwd: REPO_ROOT,
      detached: true,
      env: { ...fixture.env, RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT, ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  const collect = (chunk: Buffer | string): void => {
    output = (output + String(chunk)).slice(-8 * 1024 * 1024);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  const completion = new Promise<Readonly<{ status: number | null; output: string }>>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status) => resolve(Object.freeze({ status, output })));
  });
  const cancel = (): void => {
    if (child.pid !== undefined) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* already exited */ }
    }
  };
  const timeout = setTimeout(cancel, ASYNC_CLI_HANG_BACKSTOP_MS);
  void completion.then(() => clearTimeout(timeout), () => clearTimeout(timeout));
  return Object.freeze({ completion, cancel });
}
