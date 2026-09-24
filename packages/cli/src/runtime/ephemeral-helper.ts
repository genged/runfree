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
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";

import {
  ephemeralHelperLabelArguments,
  type EphemeralHelperPurpose,
} from "./container-inventory.ts";
import { dockerClientEnvOptions } from "./docker.ts";
import { EPHEMERAL_HELPER_HOSTS } from "./session-container-reconciliation.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const VOLUME_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
const DEFAULT_TIMEOUT_MS = 120_000;
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

export type EphemeralHelperInput = EphemeralHelperRequest & Readonly<{
  /**
   * `<stateDir>/helper-runs/run-XXXXXX/cid`: the Docker CLI writes the created
   * container's exact id here, which is what lets a timed-out or crashed run be
   * removed by id rather than by name or label.
   */
  cidFile: string;
  /** The run's random nonce, stamped as `io.runfree.helper-run`. */
  runNonce: string;
}>;

const HELPER_RUN_DIRECTORY_PATTERN = /^run-[A-Za-z0-9]{6}$/u;

function assertHelperRunCidFile(cidFile: string): void {
  const valid = path.isAbsolute(cidFile)
    && path.resolve(cidFile) === cidFile
    && path.basename(cidFile) === "cid"
    && HELPER_RUN_DIRECTORY_PATTERN.test(path.basename(path.dirname(cidFile)))
    && path.basename(path.dirname(path.dirname(cidFile))) === "helper-runs";
  if (!valid) {
    throw new Error(`ephemeral helper cidfile must be <state>/helper-runs/run-XXXXXX/cid, not ${cidFile || "<empty>"}`);
  }
}

/**
 * The exact `docker run` argv for one helper, pure and testable.
 *
 * Every hardening flag is load-bearing: the helper runs the project's selected
 * agent image, which is untrusted, so the run must grant nothing the session
 * create plan would not.
 */
export function ephemeralHelperRunArguments(input: EphemeralHelperInput): string[] {
  if (!input.image || /\s/u.test(input.image)) {
    throw new Error(`ephemeral helper requires an exact image reference, not ${input.image || "<empty>"}`);
  }
  if (input.networkId !== undefined && !DOCKER_OBJECT_ID_PATTERN.test(input.networkId)) {
    throw new Error("ephemeral helper network must be an exact 64-hex network id");
  }
  assertHelperRunCidFile(input.cidFile);
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
    "--cidfile",
    input.cidFile,
    ...(input.stdin !== undefined ? ["-i"] : []),
    ...ephemeralHelperLabelArguments(input.projectId, input.purpose, input.runNonce),
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

export function runEphemeralHelper(
  context: RuntimeContext,
  io: RuntimeIO,
  request: EphemeralHelperRequest,
): CaptureResult {
  // Each run gets its own host-owned directory for the Docker CLI's cidfile.
  const root = path.join(context.project.paths.stateDir, "helper-runs");
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const directory = fs.mkdtempSync(path.join(root, "run-"));
  try {
    const options: SpawnSyncOptions = {
      ...dockerClientEnvOptions(context),
      timeout: request.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxBuffer: DEFAULT_MAX_BUFFER,
      ...(request.stdin !== undefined ? { input: request.stdin } : {}),
    };
    return io.capture("docker", ephemeralHelperRunArguments({
      ...request,
      cidFile: path.join(directory, "cid"),
      runNonce: randomBytes(16).toString("hex"),
    }), options);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
