// Live tranche: bounded ephemeral-helper runs, the label sweep, and the pinned
// helper address.
//
// Startup runs the deny-by-default probes in one short-lived helper container
// on the untrusted project agent image, in the agent position on
// `agent_internal`. The unit suites prove the argv, the marker, and the
// residue sweep against a fake Docker. This file proves the same claims
// against a real daemon, and it turns every daemon behaviour the design
// assumes into an explicit assertion, so a wrong assumption fails here with a
// message that names it:
//
//   - D1: a helper run by the bound image id stores `sha256:<id>` as
//     `Config.Image`, and `--pull never` runs the local image;
//   - H3: `--rm` is daemon-side (`HostConfig.AutoRemove`);
//   - H5: `HostConfig.NetworkMode` stores the network id;
//   - S1: the sweep's label filter selects helpers only: a container from the
//     project image inherits the image's project-id LABEL but no helper role,
//     and the sweep never touches it;
//   - R2: an address-in-use start refusal is the Docker CLI's status 125 with
//     the daemon's own framing on stderr.
//
// How the helper is steered without touching the product: the project image
// installs `/etc/profile.d/zz-runfree-live-helper.sh`. Every deny probe runs as
// `bash -lc`, so the probe shells source it. It acts only in a container whose
// address is in the reserved helper block `.13`-`.19`; sessions (`.20`+) and
// the network-less helpers are never affected. Its mode is swapped by
// re-approving the image context:
//
//   - `slow`: sleep a few seconds, then run the probe. The batch still ends
//     well inside its 30 s bound, and the helper lives long enough to inspect.
//   - `hang`: ignore SIGTERM and SIGINT and sleep for an hour. Only the SIGKILL
//     bound and the sweep can end it.
//
// Every refusal below is paired with the removal of its cause and a success,
// the shape the negative admission tranche uses: a refusal for an unrelated
// reason must not read as a pass.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { PROJECT_ID_LABEL } from "../../../packages/cli/src/runtime/constants.ts";
import {
  CONTAINER_LABEL_SCHEMA_LABEL,
  CONTAINER_LABEL_SCHEMA_VERSION,
  CONTAINER_ROLE_LABEL,
  EPHEMERAL_HELPER_PURPOSE_LABEL,
  LIFECYCLE_OWNER_LABEL,
  MANAGED_CONTAINER_LABEL,
} from "../../../packages/cli/src/runtime/container-inventory.ts";
import { applyDenyProbeBatchResult } from "../../../packages/cli/src/runtime/deny-probe-batch.ts";
import {
  EPHEMERAL_HELPER_TIMEOUT_OVERRIDE_ENV,
  ephemeralHelperRunArguments,
} from "../../../packages/cli/src/runtime/ephemeral-helper.ts";
import {
  PENDING_CREATE_GRACE_MS,
  readHelperMarker,
  sweepProjectHelpers,
  type EphemeralHelperFence,
} from "../../../packages/cli/src/runtime/ephemeral-helper-residue.ts";
import { EPHEMERAL_HELPER_HOSTS } from "../../../packages/cli/src/runtime/session-container-reconciliation.ts";
import { failClosedSpawnStatus } from "../../../packages/cli/src/runtime/spawn-status.ts";
import type { CaptureResult as RuntimeCaptureResult } from "../../../packages/cli/src/runtime/types.ts";
import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import {
  composeProjectName,
  docker,
  dockerOrThrow,
  forceRemoveContainer,
  internalNetworkId,
  LIVE_TEST_LABEL,
} from "./docker.ts";
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
const TEST_TIMEOUT_MS = 20 * 60_000;
const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

/** How long an `up` may take to show its deny-probe helper (a rebuild included). */
const HELPER_APPEAR_TIMEOUT_MS = 10 * 60_000;
/**
 * The test-shortened helper bound (ruling D3: digits only, clamped to
 * [1000, 30000], may only shorten). 12 s rather than lower so a loaded Docker
 * Desktop host (the CA-bundle and dependency helpers share the override) does
 * not produce a false timeout.
 */
const SHORTENED_HELPER_TIMEOUT_MS = 12_000;
/**
 * The sweep's own fixed bound: listing, rm, and the bounded absence poll
 * (about 15 s). Never shortened.
 */
const SWEEP_BOUND_MS = 15_000;
/** Spawn, Compose, and CLI exit slack on a loaded Docker Desktop host. */
const EXIT_SLACK_MS = 30_000;
/** The `slow` profile's sleep: long enough to inspect, far below the 30 s bound. */
const SLOW_PROFILE_SECONDS = 6;
/** Bound for the live event stream to show a helper's kill+destroy after `up` returns. */
const HELPER_EVENT_WAIT_TIMEOUT_MS = 5_000;

const SQUATTER_LABEL_VALUE = "ephemeral-helper-reclaim";
const HELPER_PROFILE_FILENAME = "runfree-live-helper-profile.sh";
const HELPER_PROFILE_TARGET = "/etc/profile.d/zz-runfree-live-helper.sh";
const LOCK_CONTENTION_TEXT = "waiting for the project lifecycle lock";
const TIMED_OUT_BATCH_TEXT = "deny probe batch did not finish (timed out)";
const HEX64 = /^[a-f0-9]{64}$/u;
const SHA256_ID = /^sha256:[a-f0-9]{64}$/u;

type ProfileMode = "slow" | "hang";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the ephemeral-helper reclaim tranche");
  }
  return backend;
}

// ---------------------------------------------------------------------------
// The project-image stand-in that steers the helper.
// ---------------------------------------------------------------------------

function helperProfile(mode: ProfileMode): string {
  const body = mode === "slow"
    ? `  sleep ${SLOW_PROFILE_SECONDS}`
    : "  trap '' TERM INT\n  sleep 3600";
  const hosts = [...EPHEMERAL_HELPER_HOSTS].sort((left, right) => left - right).join("|");
  return [
    "# Live-test stand-in from tests/runtime/live/ephemeral-helper-reclaim.live.test.ts.",
    "# Acts only in a container holding an address in the reserved helper block.",
    "runfree_live_in_block=",
    "for runfree_live_address in $(PATH=\"$PATH:/usr/sbin:/sbin\"; ip -4 -o addr show 2>/dev/null | sed -n 's/.* inet \\([0-9.]*\\)\\/.*/\\1/p'); do",
    `  case "\${runfree_live_address##*.}" in ${hosts}) runfree_live_in_block=1 ;; esac`,
    "done",
    "if [ -n \"$runfree_live_in_block\" ]; then",
    body,
    "fi",
    "unset runfree_live_address runfree_live_in_block",
    "",
  ].join("\n");
}

const HELPER_PROFILE_DOCKERFILE_STANZA = [
  "",
  "USER root",
  `COPY ${HELPER_PROFILE_FILENAME} ${HELPER_PROFILE_TARGET}`,
  `RUN chmod 0644 ${HELPER_PROFILE_TARGET}`,
  "USER agent",
  "",
].join("\n");

function writeHelperProfile(fixture: LiveFixture, mode: ProfileMode): void {
  fs.writeFileSync(path.join(fixture.projectRoot, ".runfree", "image", HELPER_PROFILE_FILENAME), helperProfile(mode));
}

/** Runs before the fixture's first `up`, so its own approvals cover the stanza. */
function configureHelperProfileProject(fixture: LiveFixture): void {
  writeHelperProfile(fixture, "slow");
  fs.appendFileSync(path.join(fixture.projectRoot, ".runfree", "image", "Dockerfile"), HELPER_PROFILE_DOCKERFILE_STANZA);
}

/** Swaps the profile mode; the next `up` builds and selects the new image. */
function restageHelperProfile(fixture: LiveFixture, mode: ProfileMode): void {
  writeHelperProfile(fixture, mode);
  const approved = fixture.runfree(["image", "approve-context"]);
  if (approved.status !== 0) {
    throw new Error(`could not approve the ${mode} helper profile: ${describeOutput(approved.output)}`);
  }
}

// ---------------------------------------------------------------------------
// Asynchronous CLI runs, so a helper can be observed while `up` is running.
// ---------------------------------------------------------------------------

type RunfreeExit = Readonly<{ status: number | null; signal: NodeJS.Signals | null; output: string; endedAt: number }>;

type RunningRunfree = Readonly<{
  child: childProcess.ChildProcess;
  completion: Promise<RunfreeExit>;
  exited(): boolean;
  output(): string;
}>;

/**
 * Starts the CLI in its own process group, with the same invocation env the
 * fixture's synchronous runner uses plus `extraEnv`. Asynchronous so the event
 * loop keeps draining a long build log while the test polls Docker.
 */
function spawnRunfree(fixture: LiveFixture, args: readonly string[], extraEnv: NodeJS.ProcessEnv = {}): RunningRunfree {
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
  let exited = false;
  const collect = (chunk: Buffer | string): void => {
    if (output.length < CAPTURE_MAX_BYTES) output += String(chunk);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  const completion = new Promise<RunfreeExit>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status, signal) => {
      exited = true;
      resolve({ status, signal, output, endedAt: Date.now() });
    });
  });
  return Object.freeze({ child, completion, exited: () => exited, output: () => output });
}

async function runfreeAsync(fixture: LiveFixture, args: readonly string[], extraEnv: NodeJS.ProcessEnv = {}): Promise<RunfreeExit> {
  return await spawnRunfree(fixture, args, extraEnv).completion;
}

function killProcessGroup(run: RunningRunfree): void {
  if (run.child.pid === undefined) return;
  try { process.kill(-run.child.pid, "SIGKILL"); } catch { /* already gone */ }
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * Polls until `probe` returns a value. Fails at once, with the CLI's own
 * output, if the watched run exits first: a helper that never appeared is a
 * different failure from one that appeared and misbehaved.
 */
async function pollDuring<T>(
  run: RunningRunfree | undefined,
  label: string,
  timeoutMs: number,
  probe: () => T | undefined,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = probe();
    if (value !== undefined) return value;
    if (run?.exited()) {
      throw new Error(`runfree exited before ${label}: ${describeOutput(run.output(), 4000)}`);
    }
    if (Date.now() >= deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${label}${run ? `: ${describeOutput(run.output(), 4000)}` : ""}`);
    }
    await sleep(200);
  }
}

// ---------------------------------------------------------------------------
// Docker observations.
// ---------------------------------------------------------------------------

type HelperInspect = Readonly<{
  Id: string;
  Image: string;
  Created: string;
  State: Readonly<{ Status: string; Running: boolean }>;
  Config: Readonly<{ Image: string; Labels: Record<string, string> | null }>;
  HostConfig: Readonly<{
    AutoRemove?: boolean;
    NetworkMode?: string;
    ReadonlyRootfs?: boolean;
    CapDrop?: readonly string[] | null;
  }>;
  NetworkSettings: Readonly<{
    Networks: Record<string, Readonly<{
      NetworkID?: string;
      IPAddress?: string;
      IPAMConfig?: Readonly<{ IPv4Address?: string }> | null;
    }> | null>;
  }>;
}>;

function inspectContainer(id: string): HelperInspect | undefined {
  const result = docker(["container", "inspect", id]);
  if (result.status !== 0) return undefined;
  const parsed = JSON.parse(result.stdout) as HelperInspect[];
  if (parsed.length !== 1) throw new Error(`docker inspect ${id} returned ${parsed.length} containers`);
  return parsed[0];
}

function containerExists(id: string): boolean {
  return dockerOrThrow("exact-id listing", ["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${id}`]) !== "";
}

/** This project's deny-probe helpers, by the minted labels (hand-written, not the product's filter). */
function denyProbeHelperIds(projectId: string, options: { all: boolean }): readonly string[] {
  return dockerOrThrow("deny-probe helper listing", [
    "ps",
    ...(options.all ? ["--all"] : []),
    "--no-trunc",
    "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`,
    "--filter", `label=${CONTAINER_ROLE_LABEL}=ephemeral-helper`,
    "--filter", `label=${EPHEMERAL_HELPER_PURPOSE_LABEL}=deny-probe`,
    "--format", "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
}

function projectHelperIds(projectId: string): readonly string[] {
  return dockerOrThrow("helper listing", [
    "ps", "--all", "--no-trunc",
    "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`,
    "--filter", `label=${CONTAINER_ROLE_LABEL}=ephemeral-helper`,
    "--format", "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
}

/**
 * A live `docker events` subscription for this project's ephemeral helpers.
 *
 * The daemon replays past events only from a bounded in-memory buffer, not
 * from disk. An `up` under test issues many `docker exec` calls for the deny
 * probes (each an exec_create/exec_start/exec_die event), and those — plus
 * unrelated host activity — can evict a helper's own kill/destroy from that
 * buffer before a query made *after* `up` returns ever asks for them; a
 * standalone reproduction showed a removed container's events gone after
 * about 450 later events. Subscribing before `up` starts and reading the
 * stream as events arrive (no `--until`) sidesteps the replay buffer
 * entirely: `--since` only back-fills what happened between spawn and
 * subscription, and everything after is delivered live.
 */
type HelperEventStream = Readonly<{
  actionsFor(id: string): readonly string[];
  /** False once the child has exited or failed to spawn — it should not, before `stop()`. */
  isRunning(): boolean;
  /** Spawn error, exit code/signal, and any stderr, for a failure message. */
  diagnostics(): string;
  stop(): void;
}>;

function startHelperEventStream(fixture: LiveFixture, identity: ProjectIdentity, sinceSeconds: number): HelperEventStream {
  const child = childProcess.spawn(
    "docker",
    [
      "events",
      "--since", String(sinceSeconds),
      "--filter", "type=container",
      "--filter", `label=${PROJECT_ID_LABEL}=${identity.projectId}`,
      "--filter", `label=${CONTAINER_ROLE_LABEL}=ephemeral-helper`,
      // Actor.ID, not the top-level (deprecated) id field, is the stable
      // full 64-hex container id.
      "--format", "{{.Actor.ID}} {{.Action}}",
    ],
    { env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
  );
  const actions = new Map<string, string[]>();
  let buffer = "";
  let stderr = "";
  let spawnError: Error | undefined;
  let exit: { code: number | null; signal: NodeJS.Signals | null } | undefined;
  const consume = (chunk: Buffer | string): void => {
    buffer += String(chunk);
    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      newlineIndex = buffer.indexOf("\n");
      const spaceIndex = line.indexOf(" ");
      if (spaceIndex !== -1) {
        const id = line.slice(0, spaceIndex);
        const action = line.slice(spaceIndex + 1);
        const existing = actions.get(id);
        if (existing) existing.push(action); else actions.set(id, [action]);
      }
    }
  };
  child.stdout?.on("data", consume);
  child.stderr?.on("data", (chunk: Buffer | string) => { stderr += String(chunk); });
  child.on("error", (error) => { spawnError = error; });
  child.on("close", (code, signal) => { exit = { code, signal }; });
  let stopped = false;
  return Object.freeze({
    actionsFor: (id: string) => actions.get(id) ?? [],
    isRunning: () => spawnError === undefined && exit === undefined,
    diagnostics: () => {
      const parts: string[] = [];
      if (spawnError) parts.push(`spawn error: ${spawnError.message}`);
      if (exit) parts.push(`exited: code=${exit.code} signal=${exit.signal}`);
      if (stderr.trim()) parts.push(`stderr: ${stderr.trim()}`);
      return parts.length > 0 ? parts.join("; ") : "the docker events process is still running with no reported failure";
    },
    stop: () => {
      if (stopped) return;
      stopped = true;
      child.kill("SIGKILL");
    },
  });
}

/** Polls the live stream, bounded, until `id` has shown every action in `expected`. */
async function waitForHelperEvents(
  stream: HelperEventStream,
  id: string,
  expected: readonly string[],
  timeoutMs: number,
): Promise<readonly string[]> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const actions = stream.actionsFor(id);
    if (expected.every((action) => actions.includes(action))) return actions;
    if (Date.now() >= deadline) return actions;
    await sleep(100);
  }
}

function agentInternalEndpoint(inspect: HelperInspect, networkId: string) {
  const entries = Object.values(inspect.NetworkSettings.Networks ?? {});
  expect(entries, "the helper must have exactly one network attachment").toHaveLength(1);
  const entry = entries[0];
  if (!entry) throw new Error("the helper's only network attachment is null");
  // A created-never-started container may report an empty NetworkID; a
  // running helper must name the exact network.
  if (inspect.State.Status !== "created") {
    expect(entry.NetworkID, "the running helper's endpoint must be on agent_internal").toBe(networkId);
  }
  return entry;
}

function internalSubnetPrefix(networkId: string): string {
  const subnet = dockerOrThrow("agent_internal subnet", [
    "network", "inspect", "-f", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", networkId,
  ]).split(/\s+/u).find((entry) => /^\d+\.\d+\.\d+\.0\/24$/u.test(entry));
  if (!subnet) throw new Error("agent_internal has no exact /24 IPv4 subnet");
  return subnet.slice(0, subnet.lastIndexOf("."));
}

function hostOf(address: string): number {
  return Number(address.slice(address.lastIndexOf(".") + 1));
}

// ---------------------------------------------------------------------------
// The host marker.
// ---------------------------------------------------------------------------

/**
 * A marker whose late-create window is still open is expected after a killed
 * client or a killed CLI (see `ephemeral-helper-residue.ts`); anything else is
 * residue.
 */
function markerIsResidue(stateDir: string): boolean {
  const marker = readHelperMarker(stateDir);
  if (!marker) return false;
  const until = Math.max(
    marker.lateCreateUntil === undefined ? Number.NEGATIVE_INFINITY : Date.parse(marker.lateCreateUntil),
    marker.writtenAt === undefined ? Number.NEGATIVE_INFINITY : Date.parse(marker.writtenAt) + PENDING_CREATE_GRACE_MS,
  );
  return !(until > Date.now());
}

// ---------------------------------------------------------------------------
// The shared observation of one deny-probe helper and its host record.
// ---------------------------------------------------------------------------

type ObservedHelper = Readonly<{ id: string; address: string; firstSeenAt: number }>;

type ProjectIdentity = Readonly<{
  projectId: string;
  stateDir: string;
  networkId: string;
  prefix: string;
}>;

/**
 * Waits for the running `up` to show a running deny-probe helper, then
 * asserts every helper fact the design depends on.
 */
async function observeRunningHelper(
  identity: ProjectIdentity,
  run: RunningRunfree,
  known: ReadonlySet<string> = new Set(),
): Promise<ObservedHelper> {
  const found = await pollDuring(run, "a running deny-probe helper", HELPER_APPEAR_TIMEOUT_MS, () => {
    const id = denyProbeHelperIds(identity.projectId, { all: false }).find((candidate) => !known.has(candidate));
    return id;
  });
  const firstSeenAt = Date.now();
  expect(found, "the helper listing must print the exact 64-hex id").toMatch(HEX64);
  const inspect = inspectContainer(found);
  if (!inspect) throw new Error(`the deny-probe helper ${found} vanished before it could be inspected`);

  // Labels: all six minted helper labels, bound to this project.
  const labels = inspect.Config.Labels ?? {};
  expect(labels[MANAGED_CONTAINER_LABEL], "managed label").toBe("true");
  expect(labels[CONTAINER_ROLE_LABEL], "role label").toBe("ephemeral-helper");
  expect(labels[LIFECYCLE_OWNER_LABEL], "lifecycle-owner label").toBe("utility");
  expect(labels[CONTAINER_LABEL_SCHEMA_LABEL], "label-schema label").toBe(CONTAINER_LABEL_SCHEMA_VERSION);
  expect(labels[PROJECT_ID_LABEL], "project-id label").toBe(identity.projectId);
  expect(labels[EPHEMERAL_HELPER_PURPOSE_LABEL], "purpose label").toBe("deny-probe");

  // D1: run by the bound image id, so the stored reference is the id itself.
  expect(inspect.Config.Image, "D1: the deny-probe helper must be run by the bound sha256 image id, not a tag")
    .toMatch(SHA256_ID);
  expect(inspect.Image, "D1: Config.Image (the reference run) must equal the immutable Image id").toBe(inspect.Config.Image);
  const imageLabels = JSON.parse(dockerOrThrow("helper image labels", [
    "image", "inspect", "-f", "{{json .Config.Labels}}", inspect.Image,
  ])) as Record<string, string> | null;
  expect(imageLabels?.[PROJECT_ID_LABEL], "the helper image must be this project's agent image").toBe(identity.projectId);

  // H3 and H5, and the hardening the argv asks for.
  expect(inspect.HostConfig.AutoRemove, "H3: --rm must be daemon-side (HostConfig.AutoRemove)").toBe(true);
  expect(inspect.HostConfig.NetworkMode, "H5: HostConfig.NetworkMode must store the exact network id").toBe(identity.networkId);
  expect(inspect.HostConfig.ReadonlyRootfs, "the helper root filesystem must be read-only").toBe(true);
  expect(inspect.HostConfig.CapDrop ?? [], "the helper must drop every capability").toContain("ALL");

  // The pinned address: in the reserved block, outside the session pool.
  const endpoint = agentInternalEndpoint(inspect, identity.networkId);
  const address = endpoint.IPAddress ?? "";
  expect(address.startsWith(`${identity.prefix}.`), `the helper address ${address} must be on agent_internal`).toBe(true);
  expect(
    (EPHEMERAL_HELPER_HOSTS as readonly number[]).includes(hostOf(address)),
    `the helper address ${address} must be in the reserved block .13-.19`,
  ).toBe(true);
  expect(hostOf(address) >= 20, `the helper address ${address} must not be a session-pool address`).toBe(false);
  expect(endpoint.IPAMConfig?.IPv4Address, "C9: the pinned address must be recorded as IPAMConfig.IPv4Address")
    .toBe(address);

  // The host marker is on disk while the helper runs, so a CLI that dies now
  // leaves the next lock holder a reason to sweep.
  expect(readHelperMarker(identity.stateDir), "the helper marker must exist while a helper runs").toBeDefined();

  return Object.freeze({ id: found, address, firstSeenAt });
}

function assertNoHelperResidue(identity: ProjectIdentity, when: string): void {
  expect(projectHelperIds(identity.projectId), `no ephemeral-helper container may remain ${when}`).toEqual([]);
  expect(markerIsResidue(identity.stateDir), `no settled helper marker may remain ${when}`).toBe(false);
}

// ---------------------------------------------------------------------------
// Squatters: unlabeled-by-Runfree containers pinned to helper-block addresses.
// ---------------------------------------------------------------------------

function squatterName(address: string): string {
  return `runfree-helper-reclaim-squatter-${hostOf(address)}`;
}

function startSquatter(image: string, networkId: string, address: string): string {
  const name = squatterName(address);
  forceRemoveContainer(name);
  return dockerOrThrow(`start squatter on ${address}`, [
    "run", "-d",
    "--name", name,
    "--label", `${LIVE_TEST_LABEL}=${SQUATTER_LABEL_VALUE}`,
    "--network", networkId,
    "--ip", address,
    image,
    "sleep", "3600",
  ]);
}

function containerRunning(id: string): boolean {
  return dockerOrThrow("container state", ["inspect", "-f", "{{.State.Running}}", id]) === "true";
}

function selectedAgentImageId(stateDir: string): string {
  const desiredPath = path.join(stateDir, "runtime", "v2", "session-agent", "desired.json");
  const desired = JSON.parse(fs.readFileSync(desiredPath, "utf8")) as { selectedAgentImageId?: unknown };
  if (typeof desired.selectedAgentImageId !== "string" || !SHA256_ID.test(desired.selectedAgentImageId)) {
    throw new Error(`the desired session agent names no exact image id: ${desiredPath}`);
  }
  return desired.selectedAgentImageId;
}

/** A capture with the product's fail-closed status mapping, for the direct sweep proof. */
function liveCapture(command: string, args: string[], options: childProcess.SpawnSyncOptions = {}): RuntimeCaptureResult {
  const result = childProcess.spawnSync(command, args, {
    ...options,
    encoding: "utf8",
    maxBuffer: CAPTURE_MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    ...failClosedSpawnStatus(result),
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

// ---------------------------------------------------------------------------

describe("ephemeral helpers are bounded, swept by label under the lock, and pinned outside the session pool", () => {
  const backend = requiredBackend();
  let fixture: LiveFixture;
  let identity: ProjectIdentity;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: configureHelperProfileProject });
    const project = composeProjectName(fixture);
    const projectIdResult = fixture.runfree(["project-id"]);
    const projectId = projectIdResult.stdout.trim();
    if (projectIdResult.status !== 0 || !/^[a-f0-9]{12}$/u.test(projectId)) {
      throw new Error(`could not read the project id: ${describeOutput(projectIdResult.output)}`);
    }
    const networkId = internalNetworkId(project);
    identity = Object.freeze({
      projectId,
      stateDir: path.join(fixture.env.XDG_STATE_HOME as string, "runfree", "projects", projectId),
      networkId,
      prefix: internalSubnetPrefix(networkId),
    });
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    // Best-effort sweep: a failing Docker listing here must never skip the
    // fixture teardown below.
    try {
      for (const host of EPHEMERAL_HELPER_HOSTS) forceRemoveContainer(squatterName(`${identity?.prefix ?? "0.0.0"}.${host}`));
      // A helper this file created directly, or one a failed assertion left.
      if (identity) for (const id of projectHelperIds(identity.projectId)) forceRemoveContainer(id);
    } catch (error) {
      process.stderr.write(`ephemeral-helper-reclaim: helper sweep failed before teardown: ${error instanceof Error ? error.message : String(error)}\n`);
    }
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  });

  test("L1: a normal up runs the deny-probe helper pinned in .13-.19 and leaves no helper or record", async () => {
    assertNoHelperResidue(identity, "before the nominal up");
    const up = spawnRunfree(fixture, ["up"]);
    try {
      const helper = await observeRunningHelper(identity, up);
      // Default layout: nothing else holds a block address, so the highest
      // host is chosen (EPHEMERAL_HELPER_HOSTS is ordered highest first).
      expect(helper.address, "with a free block the helper must take the highest block host").toBe(
        `${identity.prefix}.${EPHEMERAL_HELPER_HOSTS[0]}`,
      );
      const exit = await up.completion;
      expect(exit.status, `the nominal up failed: ${describeOutput(exit.output, 4000)}`).toBe(0);
      expect(containerExists(helper.id), "H3: the cleanly exited helper must have been removed by --rm").toBe(false);
    } finally {
      killProcessGroup(up);
    }
    assertNoHelperResidue(identity, "after a nominal up");
  }, TEST_TIMEOUT_MS);

  test("the helper argv holds against the real daemon: create-only shape, address-in-use refusal, and a selective sweep", () => {
    // Drives the product's own argv builder and sweep against the daemon
    // directly, outside `up`, so each daemon assumption is observed on its
    // own. No `up` runs meanwhile, so the lifecycle fence is a stub; the
    // marker lives in a scratch state root the project never reads.
    const image = selectedAgentImageId(identity.stateDir);
    const scratchState = fs.mkdtempSync(path.join(fixture.ownerRoot, "helper-proof-state-"));
    const fence: EphemeralHelperFence = {
      lifecycleLock: { assertHeld() {} },
      containmentIO: { capture: liveCapture },
      stateDir: scratchState,
      dockerEnv: fixture.env,
    };
    const argvFor = (ip: string): string[] => ephemeralHelperRunArguments({
      purpose: "deny-probe",
      projectId: identity.projectId,
      image,
      user: "1000:1000",
      networkId: identity.networkId,
      ip,
      command: ["true"],
    });
    const createdIds: string[] = [];
    const occupied = `${identity.prefix}.${EPHEMERAL_HELPER_HOSTS[0]}`;
    const free = `${identity.prefix}.${EPHEMERAL_HELPER_HOSTS[1]}`;
    try {
      // 1. Created, never started: the shape a start refusal or a crash
      //    between create and start leaves behind.
      const runArgv = argvFor(free);
      expect(runArgv[0], "the product argv must be a docker run").toBe("run");
      const created = liveCapture("docker", ["create", ...runArgv.slice(1)], { env: fixture.env, timeout: 60_000 });
      expect(created.status, `--pull never must create from the local image by id: ${describeOutput(`${created.stdout}${created.stderr}`)}`).toBe(0);
      const createdId = created.stdout.trim();
      expect(createdId, "docker create must print the exact id").toMatch(HEX64);
      createdIds.push(createdId);
      const createdInspect = inspectContainer(createdId);
      if (!createdInspect) throw new Error("the created helper is not inspectable");
      expect(createdInspect.State.Status, "the create-only helper must be in state created").toBe("created");
      expect(createdInspect.Config.Image, "D1: Config.Image must equal the sha256 reference the helper was run by").toBe(image);
      expect(createdInspect.Image, "D1: Image must equal the bound id").toBe(image);
      expect(createdInspect.HostConfig.NetworkMode, "H5: NetworkMode must store the exact network id").toBe(identity.networkId);
      expect(createdInspect.HostConfig.AutoRemove, "H3: --rm must be daemon-side").toBe(true);

      // 2. Address in use at start: a container Runfree does not own holds
      //    the pinned address. It runs the project image, so it inherits the
      //    image's project-id LABEL but carries no helper role (S1).
      const squatter = startSquatter(image, identity.networkId, occupied);
      const squatterLabels = inspectContainer(squatter)?.Config.Labels ?? {};
      expect(squatterLabels[PROJECT_ID_LABEL], "S1: the squatter must inherit the project-id image LABEL").toBe(identity.projectId);
      expect(squatterLabels[CONTAINER_ROLE_LABEL], "S1: the squatter must carry no container role").toBeUndefined();
      const refused = liveCapture("docker", argvFor(occupied), { env: fixture.env, timeout: 60_000 });
      expect(
        refused.status,
        `R2: an address-in-use start refusal must be the Docker CLI's own status 125: ${describeOutput(`${refused.stdout}${refused.stderr}`)}`,
      ).toBe(125);
      const issues: string[] = [];
      applyDenyProbeBatchResult(issues, [{ label: "agent-position direct TCP egress", command: "true" }], refused, undefined, occupied);
      expect(
        issues.join("\n"),
        `R2: the product must recognize the daemon's address-in-use text on stderr: ${describeOutput(refused.stderr)}`,
      ).toContain(`ephemeral-helper address ${occupied} on agent_internal is already in use`);
      for (const id of projectHelperIds(identity.projectId)) if (!createdIds.includes(id)) createdIds.push(id);

      // 3. The sweep removes every helper, created or refused, and never the
      //    squatter.
      expect(sweepProjectHelpers(fence, identity.projectId), "the sweep must find the created helper at least").toBeGreaterThanOrEqual(1);
      expect(projectHelperIds(identity.projectId), "no helper may remain after the sweep").toEqual([]);
      expect(containerRunning(squatter), "S1: the sweep must never touch the foreign container holding the address").toBe(true);
    } finally {
      for (const id of createdIds) forceRemoveContainer(id);
      forceRemoveContainer(squatterName(occupied));
      fs.rmSync(scratchState, { recursive: true, force: true });
    }
  }, TEST_TIMEOUT_MS);

  test("L2: a helper past its bound is SIGKILLed and swept; up fails closed and the next up succeeds", async () => {
    restageHelperProfile(fixture, "hang");
    const startedSeconds = Math.floor(Date.now() / 1000) - 1;
    // Subscribe live before `up` starts; see the stream's own doc comment for
    // why a post-hoc `docker events` query cannot be trusted here.
    const events = startHelperEventStream(fixture, identity, startedSeconds);
    try {
      const up = spawnRunfree(fixture, ["up"], { [EPHEMERAL_HELPER_TIMEOUT_OVERRIDE_ENV]: String(SHORTENED_HELPER_TIMEOUT_MS) });
      let helper: ObservedHelper;
      let exit: RunfreeExit;
      try {
        helper = await observeRunningHelper(identity, up);
        exit = await up.completion;
      } finally {
        killProcessGroup(up);
      }
      const output = describeOutput(exit.output, 4000);
      expect(exit.status, `up must fail closed when the deny probes did not finish: ${output}`).not.toBe(0);
      expect(exit.output, "the refusal must name the unfinished deny-probe batch").toContain(TIMED_OUT_BATCH_TEXT);
      expect(exit.output, "the refusal must be the agent-position deny probes").toMatch(/agent-position .* denial probe did not run/u);
      expect(exit.output, `the sweep must not be left unconfirmed: ${output}`).not.toMatch(/could not be confirmed removed/u);
      const boundMs = SHORTENED_HELPER_TIMEOUT_MS + SWEEP_BOUND_MS + EXIT_SLACK_MS;
      const elapsedMs = exit.endedAt - helper.firstSeenAt;
      process.stderr.write(
        `ephemeral-helper-reclaim: I1 observed: up returned ${elapsedMs} ms after the hung helper appeared (bound ${boundMs} ms, helper timeout ${SHORTENED_HELPER_TIMEOUT_MS} ms)\n`,
      );
      expect(
        elapsedMs,
        `I1: up must return within the shortened helper bound plus the sweep bound (${boundMs} ms) after the hung helper appeared`,
      ).toBeLessThan(boundMs);

      expect(containerExists(helper.id), "the hung helper must be removed").toBe(false);
      expect(
        events.isRunning(),
        `the docker events stream must still be running when up finished, not have exited early: ${events.diagnostics()}`,
      ).toBe(true);
      const actions = await waitForHelperEvents(events, helper.id, ["kill", "destroy"], HELPER_EVENT_WAIT_TIMEOUT_MS);
      expect(
        actions,
        `the hung helper must have been force-removed (kill then destroy), not exited on its own: ${actions.join(",")} (event stream: ${events.diagnostics()})`,
      ).toEqual(expect.arrayContaining(["kill", "destroy"]));
      expect(readHelperMarker(identity.stateDir)?.lateCreateUntil, "a killed client must leave a late-create window open").toBeDefined();
      assertNoHelperResidue(identity, "after a timed-out helper");
    } finally {
      events.stop();
    }

    // Load-bearing half: remove the hang, and the next up succeeds without
    // meeting a held lifecycle lock.
    restageHelperProfile(fixture, "slow");
    const next = await runfreeAsync(fixture, ["up"]);
    expect(next.status, `the up after the hang was removed must succeed: ${describeOutput(next.output, 4000)}`).toBe(0);
    // Weak by design: a stale lock from a dead owner is reclaimed anyway, so
    // this only catches a live holder; the I1 timing above carries the proof.
    expect(next.output, "the failed up must have released the lifecycle lock").not.toContain(LOCK_CONTENTION_TEXT);
    assertNoHelperResidue(identity, "after the recovering up");
  }, TEST_TIMEOUT_MS);

  test("L2 crash: a CLI killed mid-helper leaves residue the next lock holder sweeps first", async () => {
    restageHelperProfile(fixture, "hang");
    const crashed = spawnRunfree(fixture, ["up"]);
    let orphan: ObservedHelper;
    try {
      orphan = await observeRunningHelper(identity, crashed);
    } finally {
      // The whole process group: the CLI and its Docker client die together,
      // as on a host crash. The container itself keeps running.
      killProcessGroup(crashed);
    }
    await crashed.completion;
    await sleep(1_000);
    expect(containerRunning(orphan.id), "the orphaned helper must outlive the killed CLI").toBe(true);
    expect(readHelperMarker(identity.stateDir), "the killed run's marker must remain").toBeDefined();

    // The next lock holder sweeps the orphan before anything else. The new
    // run's own helper still hangs (the profile is unchanged), so this up fails
    // on it, bounded; what matters is that the orphan went first.
    const reclaiming = spawnRunfree(fixture, ["up"], { [EPHEMERAL_HELPER_TIMEOUT_OVERRIDE_ENV]: String(SHORTENED_HELPER_TIMEOUT_MS) });
    let replacement: ObservedHelper;
    let exit: RunfreeExit;
    try {
      replacement = await observeRunningHelper(identity, reclaiming, new Set([orphan.id]));
      expect(containerExists(orphan.id), "the orphan must be removed before the next helper runs").toBe(false);
      exit = await reclaiming.completion;
    } finally {
      killProcessGroup(reclaiming);
    }
    const output = describeOutput(exit.output, 4000);
    expect(exit.output, `the residue sweep must not refuse: ${output}`).not.toMatch(/could not be confirmed removed/u);
    expect(exit.output, `the orphan must not surface as an unknown participant: ${output}`).not.toMatch(/unknown participant|untrusted-container/u);
    expect(exit.status, `the reclaiming up still fails on its own hung helper: ${output}`).not.toBe(0);
    expect(exit.output).toContain(TIMED_OUT_BATCH_TEXT);
    expect(containerExists(replacement.id), "the reclaiming up's own hung helper must be removed too").toBe(false);
    assertNoHelperResidue(identity, "after the reclaiming up");

    // Load-bearing half: the hang removed, up succeeds and a session is
    // admitted. The admission slice would refuse on any lingering helper.
    restageHelperProfile(fixture, "slow");
    const recovered = await runfreeAsync(fixture, ["up"]);
    expect(recovered.status, `the up after the crash residue was swept must succeed: ${describeOutput(recovered.output, 4000)}`).toBe(0);
    assertNoHelperResidue(identity, "after the recovered up");
    runNominalAdmissionSlice({ fixture, backend, agent: "claude", expect: "success" });
  }, TEST_TIMEOUT_MS);

  test("L3: an exhausted helper block refuses with its remedies, never removes a squatter, and clears once freed", async () => {
    const image = selectedAgentImageId(identity.stateDir);
    const addresses = EPHEMERAL_HELPER_HOSTS.map((host) => `${identity.prefix}.${host}`);
    const squatters = new Map<string, string>();
    const freed = `${identity.prefix}.16`;
    try {
      for (const address of addresses) squatters.set(address, startSquatter(image, identity.networkId, address));

      const refused = await runfreeAsync(fixture, ["up"]);
      const refusedOutput = describeOutput(refused.output, 4000);
      expect(refused.status, `up must refuse with the helper block exhausted: ${refusedOutput}`).not.toBe(0);
      expect(refused.output, `the refusal must name the exhausted block: ${refusedOutput}`)
        .toContain(`no free ephemeral-helper address in ${identity.prefix}.13-.19 on agent_internal`);
      expect(refused.output, "the refusal must name runfree forward stop").toContain("runfree forward stop");
      expect(refused.output, "the refusal must name runfree destroy --force").toContain("runfree destroy --force");
      for (const [address, id] of squatters) {
        expect(containerRunning(id), `the squatter on ${address} must never be removed or stopped`).toBe(true);
      }
      assertNoHelperResidue(identity, "when no helper address was free (no helper may be created)");

      // Free one address. Live, a foreign container on agent_internal is also
      // an unapproved participant, so up still refuses while the other six
      // remain; what changes is that the helper now runs, on exactly the
      // freed address, and the exhaustion refusal is gone.
      forceRemoveContainer(squatters.get(freed) as string);
      squatters.delete(freed);
      const partial = spawnRunfree(fixture, ["up"]);
      let helper: ObservedHelper;
      let partialExit: RunfreeExit;
      try {
        helper = await observeRunningHelper(identity, partial);
        partialExit = await partial.completion;
      } finally {
        killProcessGroup(partial);
      }
      expect(helper.address, "the helper must take the one freed block address").toBe(freed);
      expect(partialExit.output, "with one address free the block is no longer exhausted").not.toContain("no free ephemeral-helper address");
      expect(partialExit.output, "the remaining squatters are still refused as unapproved participants")
        .toContain("agent_internal contains unapproved container");
      expect(partialExit.status).not.toBe(0);
      for (const [address, id] of squatters) {
        expect(containerRunning(id), `the squatter on ${address} must still be running`).toBe(true);
      }
      assertNoHelperResidue(identity, "after the helper ran on the freed address");
    } finally {
      for (const address of addresses) forceRemoveContainer(squatterName(address));
    }

    // Load-bearing half: the block free again, up succeeds.
    const recovered = await runfreeAsync(fixture, ["up"]);
    expect(recovered.status, `up must succeed once the squatters are gone: ${describeOutput(recovered.output, 4000)}`).toBe(0);
    assertNoHelperResidue(identity, "after the squatters were removed");
  }, TEST_TIMEOUT_MS);
});
