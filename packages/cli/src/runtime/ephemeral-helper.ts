// Short-lived hardened helper containers (cutover decisions D-2 and D-5).
//
// Three consumers lose their exec target when the shared Compose agent is
// removed by the per-session cutover: the deny-by-default egress proof, the
// MCP callback bridge probe, and dependency-volume preparation. Each becomes
// one run of this shape instead — a `--rm` container on the selected agent
// image, hardened the way the ingress-forwarder contract hardens its sidecar,
// carrying the taxonomy's `ephemeral-helper` role with a diagnostic purpose.
//
// The shape is deliberately one function, not a per-consumer builder: like the
// ingress forwarder, there genuinely is one shape (cap-drop ALL,
// no-new-privileges, read-only rootfs, bounded pids, no mounts beyond the
// declared volumes, no network unless the probe position requires one), and
// what a given run is *for* is a label, never a branch.
//
// Helpers hold no session authority. A helper placed on `agent_internal` sits
// in the untrusted agent position on purpose — deny-by-default applies to it,
// which is exactly what makes the deny proof honest — and the proxy rejects
// its traffic like any unadmitted source.

import type { SpawnSyncOptions } from "node:child_process";

import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";

import {
  ephemeralHelperLabelArguments,
  type EphemeralHelperPurpose,
} from "./container-inventory.ts";
import { dockerClientEnvOptions } from "./docker.ts";
import {
  EphemeralHelperUnconfirmedError,
  markHelperRunPending,
  readHelperMarker,
  reclaimHelperResidue,
  settleHelperRun,
  type EphemeralHelperFence,
} from "./ephemeral-helper-residue.ts";
import { wasRefusedBeforeSpawn } from "./io-refusal.ts";

export type { EphemeralHelperFence } from "./ephemeral-helper-residue.ts";
import { EPHEMERAL_HELPER_HOSTS } from "./session-container-reconciliation.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const VOLUME_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
const DEFAULT_TIMEOUT_MS = 120_000;
const DENY_PROBE_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BUFFER = 4 * 1024 * 1024;

/**
 * The only capabilities a helper may add back after `--cap-drop ALL`.
 *
 * CHOWN exists for dependency-volume preparation, whose entire job is giving
 * fresh root-owned volumes to the agent user. Nothing network- or
 * ptrace-flavored is representable here on purpose.
 */
export const EPHEMERAL_HELPER_CAPABILITIES = ["CHOWN"] as const;
export type EphemeralHelperCapability = typeof EPHEMERAL_HELPER_CAPABILITIES[number];

/** What a caller asks for; `runEphemeralHelper` adds the run's own identity. */
export type EphemeralHelperRequest = Readonly<{
  purpose: EphemeralHelperPurpose;
  projectId: string;
  /** The exact image to run — normally the selected agent image. */
  image: string;
  user: "0:0" | "1000:1000";
  /**
   * Exact network id to attach, for probes that must sit in the agent
   * position. Omitted means `--network none`: a helper gets no network unless
   * its purpose is the network.
   */
  networkId?: string;
  /**
   * Static IPv4 on the attached network; requires `networkId`. Only a host of
   * the reserved ephemeral-helper block is accepted, so a helper can never be
   * pinned to a session-pool address, a fixed role, or the gateway.
   */
  ip?: string;
  /** Named volumes to mount read-write — dependency preparation's targets. */
  volumes?: readonly Readonly<{ name: string; target: string }>[];
  /** Capabilities added back after the blanket drop; see the closed set above. */
  capabilities?: readonly EphemeralHelperCapability[];
  command: readonly string[];
  /** Piped to the helper's stdin (`-i`), for script-over-stdin consumers. */
  stdin?: string;
  timeoutMs?: number;
}>;

/**
 * The exact `docker run` argv for one helper, pure and testable.
 *
 * Every hardening flag is load-bearing: the helper runs the project's selected
 * agent image, which is untrusted, so the run must grant nothing the session
 * create plan would not.
 */
export function ephemeralHelperRunArguments(input: EphemeralHelperRequest): string[] {
  if (!input.image || /\s/u.test(input.image)) {
    throw new Error(`ephemeral helper requires an exact image reference, not ${input.image || "<empty>"}`);
  }
  if (input.networkId !== undefined && !DOCKER_OBJECT_ID_PATTERN.test(input.networkId)) {
    throw new Error("ephemeral helper network must be an exact 64-hex network id");
  }
  if (input.networkId !== undefined && input.ip === undefined) {
    throw new Error("ephemeral helper on a network requires a pinned address in the reserved ephemeral-helper block");
  }
  if (input.ip !== undefined) {
    if (input.networkId === undefined) throw new Error("ephemeral helper static address requires a network");
    if (!isExactSessionSourceIpv4(input.ip)) throw new Error(`ephemeral helper address is not IPv4: ${input.ip}`);
    const host = Number(input.ip.slice(input.ip.lastIndexOf(".") + 1));
    if (!(EPHEMERAL_HELPER_HOSTS as readonly number[]).includes(host)) {
      throw new Error(`ephemeral helper address is outside the reserved ephemeral-helper block: ${input.ip}`);
    }
  }
  for (const volume of input.volumes ?? []) {
    if (!VOLUME_NAME_PATTERN.test(volume.name)) {
      throw new Error(`ephemeral helper volume name is invalid: ${volume.name || "<empty>"}`);
    }
    if (!volume.target.startsWith("/") || volume.target.includes(":")) {
      throw new Error(`ephemeral helper volume target is invalid: ${volume.target}`);
    }
  }
  if (input.command.length === 0) throw new Error("ephemeral helper requires a command");
  for (const capability of input.capabilities ?? []) {
    if (!EPHEMERAL_HELPER_CAPABILITIES.includes(capability)) {
      throw new Error(`ephemeral helper capability is not in the closed set: ${String(capability)}`);
    }
  }
  return [
    "run",
    "--rm",
    // A helper runs only an image that is already local: never a registry
    // fetch under the lifecycle lock, and never a different image by the
    // same reference.
    "--pull",
    "never",
    ...(input.stdin !== undefined ? ["-i"] : []),
    ...ephemeralHelperLabelArguments(input.projectId, input.purpose),
    "--user",
    input.user,
    "--cap-drop",
    "ALL",
    ...(input.capabilities ?? []).flatMap((capability) => ["--cap-add", capability]),
    "--security-opt",
    "no-new-privileges:true",
    "--read-only",
    "--pids-limit",
    "64",
    "--network",
    input.networkId ?? "none",
    ...(input.ip !== undefined ? ["--ip", input.ip] : []),
    ...(input.volumes ?? []).flatMap((volume) => ["-v", `${volume.name}:${volume.target}`]),
    input.image,
    ...input.command,
  ];
}

/** Test-only shortening of every helper's wall-time bound (ruling D3). */
export const EPHEMERAL_HELPER_TIMEOUT_OVERRIDE_ENV = "RUNFREE_TEST_EPHEMERAL_HELPER_TIMEOUT_MS";
const MINIMUM_OVERRIDE_TIMEOUT_MS = 1_000;

/**
 * The wall-time bound for one helper `docker run` client, before the lifecycle
 * budget clamps it further. Deny probes bound themselves at about 3 s, so 30 s
 * (ruling D4); the other purposes keep 120 s. The test override may only
 * shorten it: digits only, clamped to [1 s, default]. It never touches the
 * sweep timeouts.
 */
export function ephemeralHelperTimeoutMs(
  purpose: EphemeralHelperPurpose,
  env: NodeJS.ProcessEnv,
  requestedMs?: number,
): number {
  const base = requestedMs ?? (purpose === "deny-probe" ? DENY_PROBE_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  const override = env[EPHEMERAL_HELPER_TIMEOUT_OVERRIDE_ENV];
  if (override === undefined || !/^[0-9]{1,9}$/u.test(override)) return base;
  return Math.min(base, Math.max(MINIMUM_OVERRIDE_TIMEOUT_MS, Number(override)));
}

function isCleanHelperExit(result: CaptureResult): boolean {
  return result.status === 0 && result.timedOut !== true && result.signal === undefined;
}

export const EPHEMERAL_HELPER_FENCE_REQUIRED =
  "an ephemeral helper runs the untrusted agent image and requires the lifecycle fence (held lock, containment IO, state dir)";

/**
 * Runs one helper under the lifecycle fence, bounded and reclaimable.
 *
 * - A marker already present is swept first, whichever lock span left it.
 * - The host marker is written before the spawn, so a CLI that dies mid-run
 *   leaves the next lock holder a reason to sweep.
 * - The client is SIGKILLed at its bound: `spawnSync` sends one signal and then
 *   waits, so a SIGTERM the client forwards into the untrusted container would
 *   leave the lock held without limit (design D-A). SIGKILL is used for helper
 *   runs only, never as a global default.
 * - A clean exit (status 0, no timeout, no signal) means `--rm` already removed
 *   the container, so the marker is cleared with no Docker call.
 * - Anything else sweeps this project's helpers through the fence's unbudgeted
 *   containment IO, even when the budgeted call itself threw after the spawn;
 *   the original error is rethrown after the sweep. A sweep that cannot be
 *   confirmed throws `EphemeralHelperUnconfirmedError` and keeps the marker.
 */
export function runEphemeralHelper(
  context: RuntimeContext,
  io: RuntimeIO,
  request: EphemeralHelperRequest,
  fence: EphemeralHelperFence | undefined,
): CaptureResult {
  if (!fence) throw new Error(EPHEMERAL_HELPER_FENCE_REQUIRED);
  fence.lifecycleLock.assertHeld();
  // Argument validation refuses before the marker or the spawn.
  const args = ephemeralHelperRunArguments(request);
  const dockerOptions = dockerClientEnvOptions(context);
  // A marker here was left by another lock span (a crashed CLI, or one that
  // held the lock while this process released it). Sweep it first: this run's
  // clean exit would otherwise clear a marker whose helper was never swept.
  if (readHelperMarker(fence.stateDir)) {
    reclaimHelperResidue({ ...fence, dockerEnv: fence.dockerEnv ?? dockerOptions.env }, request.projectId);
  }
  markHelperRunPending(fence.stateDir);
  let spawned = false;
  let outcome: { ok: true; result: CaptureResult } | { ok: false; error: unknown };
  try {
    const options: SpawnSyncOptions = {
      ...dockerOptions,
      timeout: ephemeralHelperTimeoutMs(request.purpose, context.env ?? {}, request.timeoutMs),
      killSignal: "SIGKILL",
      maxBuffer: DEFAULT_MAX_BUFFER,
      ...(request.stdin !== undefined ? { input: request.stdin } : {}),
    };
    spawned = true;
    outcome = { ok: true, result: io.capture("docker", args, options) };
  } catch (error) {
    if (wasRefusedBeforeSpawn(error)) spawned = false;
    outcome = { ok: false, error };
  }
  const clean = !spawned || outcome.ok && isCleanHelperExit(outcome.result);
  // A client that exited on its own finished its create request; one that
  // timed out, was signalled, or whose call threw may not have.
  const clientKilled = spawned && (!outcome.ok || outcome.result.timedOut === true || outcome.result.signal !== undefined);
  try {
    settleHelperRun(
      { ...fence, dockerEnv: fence.dockerEnv ?? dockerOptions.env },
      request.projectId,
      { clean, clientKilled },
    );
  } catch (error) {
    // Keep the run's own failure (a spent budget, a lost rebind allowance)
    // as the cause, so its failure kind survives the sweep refusal.
    if (!outcome.ok && error instanceof EphemeralHelperUnconfirmedError) throw error.withRunFailure(outcome.error);
    throw error;
  }
  if (!outcome.ok) throw outcome.error;
  return outcome.result;
}
