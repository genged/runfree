// Host-owned helper-run records and exact-id helper reclaim (todo 73).
//
// An ephemeral helper runs the project's untrusted agent image under the
// lifecycle lock. A helper whose `docker run` client timed out, was killed, or
// whose CLI crashed can outlive the call, and a lingering helper blocks every
// later admission as an unclaimed project container. This module is the one
// path that removes such a helper, and it removes only what it can prove:
//
// - Every run first records its intent (project, purpose, image, network,
//   pinned address, a random nonce) in a fresh 0700 directory under the
//   project's host-owned XDG state dir, before the helper is spawned. The
//   Docker CLI writes the created container's exact id beside it (`--cidfile`).
// - `docker rm -f` is only ever given a 64-hex id that came from that cidfile
//   or from a listing scoped to the run's nonce, and whose live inspection
//   matches the intent: the id, every minted helper label including the nonce,
//   the image, the network mode, and the single attachment with its pinned
//   address. The lifecycle lock is asserted around every Docker call.
// - Anything else is "unconfirmed": nothing is removed, the directory is kept
//   for the next `runfree up`, and the operator is told the remedy.
//
// Labels select; the host-owned intent and the inspection authorize. No
// Compose-label check is made: image LABELs are inherited into
// `Config.Labels`, so a project image could otherwise make every helper
// unremovable (security review C5). The run nonce is the binding.
//
// Accepted residual (security review F6): `docker rm -f <64-hex>` falls back to
// a container *name* match if the proven container vanished between the
// inspection and the rm. Only a Docker-socket holder can arrange that.

import fs from "node:fs";
import path from "node:path";

import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";

import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import {
  CONTAINER_LABEL_SCHEMA_LABEL,
  CONTAINER_LABEL_SCHEMA_VERSION,
  CONTAINER_ROLE_LABEL,
  EPHEMERAL_HELPER_PURPOSE_LABEL,
  EPHEMERAL_HELPER_PURPOSES,
  EPHEMERAL_HELPER_RUN_LABEL,
  EPHEMERAL_HELPER_RUN_NONCE_PATTERN,
  LIFECYCLE_OWNER_LABEL,
  MANAGED_CONTAINER_LABEL,
  ephemeralHelperRunFilters,
  type EphemeralHelperPurpose,
} from "./container-inventory.ts";
import { PROJECT_ID_LABEL } from "./constants.ts";
import { RuntimeObservationError, type RuntimeFailureKind } from "./observation-failure.ts";
import { EPHEMERAL_HELPER_HOSTS } from "./session-container-reconciliation.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

export const HELPER_RUNS_DIRECTORY = "helper-runs";
const RUN_DIRECTORY_PATTERN = /^run-[A-Za-z0-9]{6}$/u;
const INTENT_FILE = "intent.json";
const INTENT_TEMP_FILE = "intent.json.tmp";
const CID_FILE = "cid";
const MAX_INTENT_BYTES = 4096;
// 64 hex characters plus an optional newline (docker/cli writes none).
const MAX_CID_BYTES = 65;
const CID_PATTERN = /^([a-f0-9]{64})\n?$/u;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/u;
const NETWORK_ID_PATTERN = /^[a-f0-9]{64}$/u;
const IMAGE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const PROJECT_ID_PATTERN = /^[0-9a-f]{12}$/u;

// Fixed per-call bounds for the reclaim (security invariant I1's R). They are
// never shortened by the helper timeout override and never budgeted: removal
// must be able to run after the lifecycle budget is spent.
const OBSERVE_TIMEOUT_MS = 2_000;
const INSPECT_TIMEOUT_MS = 2_000;
const IMAGE_INSPECT_TIMEOUT_MS = 2_000;
const REMOVE_TIMEOUT_MS = 10_000;
const DEFAULT_POLL_DEADLINE_MS = 3_000;
const POLL_INTERVAL_MS = 200;
const MAX_BUFFER = 1024 * 1024;
// How long after a run's createdAt a killed client's in-flight create is still
// taken to be possible: the longest helper bound (120 s) plus a margin. Until
// then an empty nonce listing does not settle a run that has no container id.
export const PENDING_CREATE_GRACE_MS = 180_000;

/**
 * What a helper run needs from its caller: the held lifecycle lock, the
 * unbudgeted IO used for removal, and the host-owned state dir the run
 * directory lives under.
 */
export type EphemeralHelperFence = Readonly<{
  lifecycleLock: Pick<ProjectLifecycleLock, "assertHeld">;
  containmentIO: Pick<RuntimeIO, "capture">;
  stateDir: string;
  /** Docker client environment for the reclaim calls. */
  dockerEnv?: NodeJS.ProcessEnv;
}>;

export type HelperRunIntent = Readonly<{
  v: 1;
  projectId: string;
  purpose: EphemeralHelperPurpose;
  /** The exact image reference given to `docker run`: a tag or a `sha256:` id. */
  image: string;
  /** The exact 64-hex network id, or `none`. */
  network: string;
  /** The pinned address; present exactly when `network` is not `none`. */
  ip?: string;
  nonce: string;
  createdAt: string;
}>;

export type HelperRun = Readonly<{
  directory: string;
  cidFile: string;
  intent: HelperRunIntent;
}>;

export type HelperReclaimMode = "same-process" | "crash";

export type HelperReclaimOptions = Readonly<{
  /** How long the post-rm absence re-check may poll. */
  pollDeadlineMs?: number;
  sleep?: (milliseconds: number) => void;
  now?: () => number;
  /** The uid a cidfile and run directory must belong to; defaults to this process. */
  expectedUid?: number;
  /**
   * Whether the helper's `docker run` client may have died mid-request
   * (timed out, signalled, or the CLI itself crashed). Defaults to true, the
   * conservative answer; only a client that exited on its own is false.
   */
  clientKilled?: boolean;
  /** Wall clock for the pending-create grace; defaults to `Date.now`. */
  wallClockMs?: () => number;
}>;

export type HelperReclaimOutcome = "removed" | "absent" | "pending";

/** Removal of a helper could not be proven; the directory was kept for the next `up`. */
export class EphemeralHelperUnconfirmedError extends CliError {
  /** The failure kind of the helper run's own error, when it was an observation failure. */
  readonly failureKind?: RuntimeFailureKind;

  constructor(message: string, options: { cause?: unknown } = {}) {
    super(message);
    this.name = "EphemeralHelperUnconfirmedError";
    if (options.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    if (options.cause instanceof RuntimeObservationError) this.failureKind = options.cause.evidence.kind;
  }

  /**
   * The same refusal, caused by the helper run's own failure (for example a
   * spent lifecycle budget) rather than by the reclaim step, so the original
   * error and its failure kind reach the caller.
   */
  withRunFailure(runFailure: unknown): EphemeralHelperUnconfirmedError {
    const detail = runFailure instanceof Error ? runFailure.message : String(runFailure);
    return new EphemeralHelperUnconfirmedError(`${this.message}; the helper run itself failed: ${detail}`, { cause: runFailure });
  }
}

function unconfirmed(purpose: string, id: string | undefined, reason: string, cause?: unknown): EphemeralHelperUnconfirmedError {
  return new EphemeralHelperUnconfirmedError(
    `ephemeral helper ${purpose} ${id ?? "unknown"} could not be confirmed removed (${reason}); `
      + `run \`${remedy.up()}\` to retry, or \`${remedy.destroyForce()}\` to reset the project`,
    { cause },
  );
}

function untrusted(name: string, reason: string): EphemeralHelperUnconfirmedError {
  return new EphemeralHelperUnconfirmedError(
    `ephemeral helper run record ${name} cannot be trusted (${reason}); `
      + `run \`${remedy.destroyForce()}\` to reset the project`,
  );
}

function currentUid(options: HelperReclaimOptions): number | undefined {
  return options.expectedUid ?? process.getuid?.();
}

export function helperRunsRoot(stateDir: string): string {
  return path.join(stateDir, HELPER_RUNS_DIRECTORY);
}

function assertOwnedDirectory(target: string, uid: number | undefined): void {
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${target} must be a real directory, not a symlink or file`);
  }
  if (uid !== undefined && stat.uid !== uid) throw new Error(`${target} is owned by another user`);
}

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

/**
 * Creates `<stateDir>/helper-runs/run-XXXXXX` (0700) and writes the intent
 * there exclusively (0600, no symlink follow) before any helper exists. A
 * failure removes the new directory and throws: the helper is refused before
 * it is spawned.
 */
export function createHelperRun(stateDir: string, intent: HelperRunIntent): HelperRun {
  const serialized = `${JSON.stringify(serializableIntent(intent))}\n`;
  // Round-trip through the strict parser so a record this process cannot read
  // back is never written.
  parseHelperIntent(serialized);
  const root = helperRunsRoot(stateDir);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  assertOwnedDirectory(root, process.getuid?.());
  const directory = fs.mkdtempSync(path.join(root, "run-"));
  try {
    // Temp name, fsync, rename: a crash leaves either no intent (only the
    // temp file, which the residue reclaim clears) or the whole intent, so a
    // short or empty intent.json can only mean tampering. The fresh mkdtemp
    // directory gives the rename its exclusivity.
    const temporary = path.join(directory, INTENT_TEMP_FILE);
    const descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      fs.writeSync(descriptor, serialized);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    fs.renameSync(temporary, path.join(directory, INTENT_FILE));
    const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY);
    try {
      fs.fsyncSync(directoryDescriptor);
    } finally {
      fs.closeSync(directoryDescriptor);
    }
  } catch (error) {
    fs.rmSync(directory, { recursive: true, force: true });
    throw error;
  }
  return Object.freeze({ directory, cidFile: path.join(directory, CID_FILE), intent });
}

function serializableIntent(intent: HelperRunIntent): Record<string, unknown> {
  return {
    v: intent.v,
    projectId: intent.projectId,
    purpose: intent.purpose,
    image: intent.image,
    network: intent.network,
    ...(intent.ip !== undefined ? { ip: intent.ip } : {}),
    nonce: intent.nonce,
    createdAt: intent.createdAt,
  };
}

function isHelperBlockAddress(value: unknown): value is string {
  if (typeof value !== "string" || !isExactSessionSourceIpv4(value)) return false;
  const host = Number(value.slice(value.lastIndexOf(".") + 1));
  return (EPHEMERAL_HELPER_HOSTS as readonly number[]).includes(host);
}

/** A strict parser: any unknown, missing, or out-of-shape field refuses the record. */
export function parseHelperIntent(text: string): HelperRunIntent {
  const parsed = JSON.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("helper intent is not an object");
  const record = parsed as Record<string, unknown>;
  const allowed = new Set(["v", "projectId", "purpose", "image", "network", "ip", "nonce", "createdAt"]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`helper intent has an unknown field ${key}`);
  }
  if (record.v !== 1) throw new Error("helper intent version is not 1");
  if (typeof record.projectId !== "string" || !PROJECT_ID_PATTERN.test(record.projectId)) {
    throw new Error("helper intent project id is invalid");
  }
  if (typeof record.purpose !== "string" || !(EPHEMERAL_HELPER_PURPOSES as readonly string[]).includes(record.purpose)) {
    throw new Error("helper intent purpose is invalid");
  }
  if (typeof record.image !== "string" || record.image === "" || record.image.length > 512 || /\s/u.test(record.image)) {
    throw new Error("helper intent image is invalid");
  }
  if (typeof record.network !== "string" || (record.network !== "none" && !NETWORK_ID_PATTERN.test(record.network))) {
    throw new Error("helper intent network is invalid");
  }
  if (record.network === "none") {
    if (record.ip !== undefined) throw new Error("a network-less helper intent must not name an address");
  } else if (!isHelperBlockAddress(record.ip)) {
    throw new Error("a networked helper intent must name an address in the reserved helper block");
  }
  if (typeof record.nonce !== "string" || !EPHEMERAL_HELPER_RUN_NONCE_PATTERN.test(record.nonce)) {
    throw new Error("helper intent nonce is invalid");
  }
  if (typeof record.createdAt !== "string" || Number.isNaN(Date.parse(record.createdAt))) {
    throw new Error("helper intent createdAt is invalid");
  }
  return Object.freeze({
    v: 1,
    projectId: record.projectId,
    purpose: record.purpose as EphemeralHelperPurpose,
    image: record.image,
    network: record.network,
    ...(record.ip !== undefined ? { ip: record.ip as string } : {}),
    nonce: record.nonce,
    createdAt: record.createdAt,
  });
}

export type HelperCid =
  | { kind: "absent" }
  | { kind: "empty" }
  | { kind: "id"; id: string }
  | { kind: "tampered"; reason: string };

/**
 * Reads the Docker CLI's cidfile. Absent and empty (the normal state when the
 * CLI died between create and the write, security review C2) both mean "no
 * id". A symlink, a non-regular file, another owner, an oversized or malformed
 * file means the directory was tampered with.
 */
export function readHelperCid(directory: string, options: HelperReclaimOptions = {}): HelperCid {
  const cidPath = path.join(directory, CID_FILE);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(cidPath);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return { kind: "absent" };
    return { kind: "tampered", reason: `cidfile is unreadable: ${errorCode(error) ?? "error"}` };
  }
  if (stat.isSymbolicLink()) return { kind: "tampered", reason: "cidfile is a symlink" };
  if (!stat.isFile()) return { kind: "tampered", reason: "cidfile is not a regular file" };
  const uid = currentUid(options);
  if (uid !== undefined && stat.uid !== uid) return { kind: "tampered", reason: "cidfile is owned by another user" };
  if (stat.size > MAX_CID_BYTES) return { kind: "tampered", reason: "cidfile is oversized" };
  if (stat.size === 0) return { kind: "empty" };
  let content: string;
  // O_NONBLOCK: a FIFO swapped in after the lstat must not block the read.
  // The fstat recheck binds the read to the file the lstat judged.
  const descriptor = fs.openSync(cidPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.ino !== stat.ino || opened.dev !== stat.dev) {
      return { kind: "tampered", reason: "cidfile changed while it was read" };
    }
    const buffer = Buffer.alloc(MAX_CID_BYTES + 1);
    const length = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    content = buffer.subarray(0, length).toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
  if (content === "") return { kind: "empty" };
  const match = CID_PATTERN.exec(content);
  if (!match) return { kind: "tampered", reason: "cidfile does not hold one exact container id" };
  return { kind: "id", id: match[1] };
}

type HelperInspectNetwork = {
  NetworkID?: unknown;
  IPAddress?: unknown;
  IPAMConfig?: { IPv4Address?: unknown } | null;
};

type HelperInspect = {
  Id?: unknown;
  Image?: unknown;
  Config?: { Image?: unknown; Labels?: Record<string, unknown> | null } | null;
  HostConfig?: { NetworkMode?: unknown } | null;
  State?: { Status?: unknown } | null;
  NetworkSettings?: { Networks?: Record<string, HelperInspectNetwork | null> | null } | null;
};

/**
 * The pure removal proof (security invariant I2, checks 3, 4, 6, 7). Returns
 * the first reason the inspected container is not provably this run's helper,
 * or undefined when every check passes.
 *
 * `expected.imageId` is the resolved id of a tag intent on the same-process
 * path. An intent that is itself a `sha256:` id is compared to the container's
 * immutable image on both paths; a tag intent on the crash path is authorized
 * by the reference string and the nonce alone (ruling D1).
 */
export function validateEphemeralHelperRemovalCandidate(
  candidate: unknown,
  intent: HelperRunIntent,
  expected: Readonly<{ id: string; imageId?: string }>,
): string | undefined {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return "inspection is not one container";
  const inspect = candidate as HelperInspect;
  if (!CONTAINER_ID_PATTERN.test(expected.id) || inspect.Id !== expected.id) return "inspection names another container";
  const labels = inspect.Config?.Labels ?? {};
  const required: Record<string, string> = {
    [MANAGED_CONTAINER_LABEL]: "true",
    [CONTAINER_ROLE_LABEL]: "ephemeral-helper",
    [LIFECYCLE_OWNER_LABEL]: "utility",
    [CONTAINER_LABEL_SCHEMA_LABEL]: CONTAINER_LABEL_SCHEMA_VERSION,
    [PROJECT_ID_LABEL]: intent.projectId,
    [EPHEMERAL_HELPER_PURPOSE_LABEL]: intent.purpose,
    [EPHEMERAL_HELPER_RUN_LABEL]: intent.nonce,
  };
  for (const [key, value] of Object.entries(required)) {
    if (labels[key] !== value) return `label ${key} does not match this run`;
  }
  if (inspect.Config?.Image !== intent.image) return "image reference does not match this run";
  if (IMAGE_ID_PATTERN.test(intent.image)) {
    if (inspect.Image !== intent.image) return "image id does not match this run";
  } else if (expected.imageId !== undefined) {
    if (!IMAGE_ID_PATTERN.test(expected.imageId) || inspect.Image !== expected.imageId) {
      return "image id does not match the resolved image";
    }
  }
  if (inspect.HostConfig?.NetworkMode !== intent.network) return "network mode does not match this run";
  const networks = Object.entries(inspect.NetworkSettings?.Networks ?? {});
  if (networks.length !== 1) return "container does not have exactly one network attachment";
  const [name, endpoint] = networks[0];
  const address = typeof endpoint?.IPAddress === "string" ? endpoint.IPAddress : "";
  if (intent.network === "none") {
    if (name !== "none" || address !== "") return "network-less helper is attached to a network";
    return undefined;
  }
  const networkId = typeof endpoint?.NetworkID === "string" ? endpoint.NetworkID : "";
  if (networkId !== intent.network && !(networkId === "" && inspect.State?.Status === "created")) {
    return "network attachment does not match this run";
  }
  if (intent.ip === undefined) return "networked helper run has no pinned address";
  if (endpoint?.IPAMConfig?.IPv4Address !== intent.ip) return "pinned address does not match this run";
  if (address !== "" && address !== intent.ip) return "live address does not match this run";
  return undefined;
}

type DockerStep = (args: string[], timeout: number) => CaptureResult;

function reclaimContext(fence: EphemeralHelperFence): DockerStep {
  return (args, timeout) => {
    fence.lifecycleLock.assertHeld();
    const result = fence.containmentIO.capture("docker", args, {
      env: fence.dockerEnv,
      timeout,
      killSignal: "SIGKILL",
      maxBuffer: MAX_BUFFER,
    });
    fence.lifecycleLock.assertHeld();
    return result;
  };
}

type Observation = "absent" | "present";

class ReclaimRefusal extends Error {}

const INVENTORY_UNAVAILABLE = "the exact-id inventory is unavailable";

class InventoryUnavailable extends ReclaimRefusal {}

function observeExactId(docker: DockerStep, id: string, timeout = OBSERVE_TIMEOUT_MS): Observation {
  const inventory = docker(["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${id}`], timeout);
  if (inventory.status !== 0 || inventory.stderr.trim()) throw new InventoryUnavailable(INVENTORY_UNAVAILABLE);
  const ids = inventory.stdout.split(/\s+/u).filter(Boolean);
  if (ids.length === 0) return "absent";
  if (ids.length !== 1 || ids[0] !== id) throw new ReclaimRefusal("the exact-id inventory returned another identity");
  return "present";
}

function inspectExactId(docker: DockerStep, id: string): unknown {
  const inspected = docker(["container", "inspect", id], INSPECT_TIMEOUT_MS);
  if (inspected.status !== 0 || inspected.stderr.trim()) throw new ReclaimRefusal("the container inspection is unavailable");
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspected.stdout);
  } catch {
    throw new ReclaimRefusal("the container inspection is malformed");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) throw new ReclaimRefusal("the container inspection is not one container");
  return parsed[0];
}

function resolveImageId(docker: DockerStep, image: string): string {
  const inspected = docker(["image", "inspect", "--format", "{{.Id}}", image], IMAGE_INSPECT_TIMEOUT_MS);
  const imageId = inspected.stdout.trim();
  if (inspected.status !== 0 || inspected.stderr.trim() || !IMAGE_ID_PATTERN.test(imageId)) {
    throw new ReclaimRefusal("the helper image cannot be resolved to an exact id");
  }
  return imageId;
}

function removeProvenHelper(
  docker: DockerStep,
  run: HelperRun,
  id: string,
  mode: HelperReclaimMode,
  options: HelperReclaimOptions,
): "removed" | "absent" {
  if (observeExactId(docker, id) === "absent") return "absent";
  const inspected = inspectExactId(docker, id);
  const imageId = mode === "same-process" && !IMAGE_ID_PATTERN.test(run.intent.image)
    ? resolveImageId(docker, run.intent.image)
    : undefined;
  const issue = validateEphemeralHelperRemovalCandidate(inspected, run.intent, { id, ...(imageId ? { imageId } : {}) });
  if (issue) throw new ReclaimRefusal(issue);
  docker(["rm", "-f", id], REMOVE_TIMEOUT_MS);
  // Whatever rm reported, only an observed absence is success. Docker's own
  // `--rm` can race ours, so absence is polled (bounded) before the removal is
  // called unconfirmed (security review C6).
  const now = options.now ?? (() => performance.now());
  const sleep = options.sleep ?? sleepSync;
  const deadline = now() + (options.pollDeadlineMs ?? DEFAULT_POLL_DEADLINE_MS);
  for (;;) {
    const remaining = deadline - now();
    // A failed look is not an answer: it counts as "still present" until the
    // deadline, and only the final outcome decides. A contradiction (another
    // identity) still refuses at once.
    let observation: Observation | "unavailable";
    try {
      observation = observeExactId(docker, id, Math.min(OBSERVE_TIMEOUT_MS, Math.max(250, remaining)));
    } catch (error) {
      if (!(error instanceof InventoryUnavailable)) throw error;
      observation = "unavailable";
    }
    if (observation === "absent") return "removed";
    if (now() >= deadline) {
      throw new ReclaimRefusal(observation === "unavailable" ? INVENTORY_UNAVAILABLE : "the container is still present after rm");
    }
    sleep(Math.min(POLL_INTERVAL_MS, Math.max(1, deadline - now())));
  }
}

function sleepSync(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

/** Deletes a run directory this module created or validated. */
export function removeHelperRunDirectory(directory: string): void {
  fs.rmSync(directory, { recursive: true, force: true });
}

/**
 * Removes one run's helper, if any, by exact id, then its directory. Returns
 * whether a helper was removed or proven absent, or `pending` (directory kept)
 * when a killed client left no id and the create may still land; throws
 * `EphemeralHelperUnconfirmedError` (directory kept) otherwise. Every failure,
 * a lost lock included, is unconfirmed: nothing is removed after it.
 */
export function reclaimHelperRun(
  run: HelperRun,
  fence: EphemeralHelperFence,
  mode: HelperReclaimMode,
  options: HelperReclaimOptions = {},
): HelperReclaimOutcome {
  const purpose = run.intent.purpose;
  let id: string | undefined;
  try {
    fence.lifecycleLock.assertHeld();
    const cid = readHelperCid(run.directory, options);
    if (cid.kind === "tampered") throw untrusted(path.basename(run.directory), cid.reason);
    const docker = reclaimContext(fence);
    let outcome: "removed" | "absent" = "absent";
    if (cid.kind === "id") {
      id = cid.id;
      outcome = removeProvenHelper(docker, run, cid.id, mode, options);
    } else {
      // No id: the CLI died between create and the cidfile write, or before
      // create. List only this run's helpers (project, role, purpose, nonce).
      const listing = docker(
        ["ps", "--all", "--quiet", "--no-trunc", ...ephemeralHelperRunFilters(run.intent.projectId, purpose, run.intent.nonce)],
        OBSERVE_TIMEOUT_MS,
      );
      if (listing.status !== 0 || listing.stderr.trim()) throw new ReclaimRefusal("the helper-run listing is unavailable");
      const candidates = listing.stdout.split(/\s+/u).filter(Boolean);
      if (candidates.some((candidate) => !CONTAINER_ID_PATTERN.test(candidate))) {
        throw new ReclaimRefusal("the helper-run listing returned a non-id line");
      }
      for (const candidate of new Set(candidates)) {
        id = candidate;
        if (removeProvenHelper(docker, run, candidate, mode, options) === "removed") outcome = "removed";
      }
      // A client killed with its create request in flight leaves no id, and
      // the daemon can still finish that create after this listing. Keep the
      // record until the grace has passed, so the next lock holder re-lists
      // by nonce and removes a late container. A future createdAt (clock
      // skew) stays pending: it never settles early.
      if (candidates.length === 0 && options.clientKilled !== false) {
        const age = (options.wallClockMs ?? Date.now)() - Date.parse(run.intent.createdAt);
        if (!(age > PENDING_CREATE_GRACE_MS)) {
          fence.lifecycleLock.assertHeld();
          return "pending";
        }
      }
    }
    fence.lifecycleLock.assertHeld();
    removeHelperRunDirectory(run.directory);
    return outcome;
  } catch (error) {
    if (error instanceof EphemeralHelperUnconfirmedError) throw error;
    const reason = error instanceof ReclaimRefusal ? error.message : `reclaim stopped: ${error instanceof Error ? error.message : String(error)}`;
    throw unconfirmed(purpose, id, reason, error);
  }
}

/**
 * Reclaims every helper-run directory a previous lock holder left behind
 * (security invariant I5: any run directory present when the lock is newly
 * acquired is residue). Every record's directory and intent (name, owner,
 * no symlink, strict parse, this project) are checked before the first Docker
 * call, so an untrusted directory or intent refuses with none. Each record's
 * cidfile is read only when that record is reclaimed, so a tampered cidfile in
 * a later record is refused after earlier records' Docker calls (still before
 * any Docker call for itself). Costs one `lstat` and no Docker call when there
 * is no residue.
 *
 * Returns how many run records were reclaimed, and how many stay pending: a
 * killed run with no container id whose nonce listing is empty but that is
 * younger than the pending-create grace. A pending record does not refuse the
 * launch: it holds no authority, and a container created late carries its
 * nonce, so a later reclaim removes it.
 */
export function reclaimHelperRunResidue(
  fence: EphemeralHelperFence,
  expectedProjectId: string,
  options: HelperReclaimOptions = {},
): { reclaimed: number; pending: number } {
  const root = helperRunsRoot(fence.stateDir);
  try {
    fs.lstatSync(root);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return { reclaimed: 0, pending: 0 };
    throw untrusted(HELPER_RUNS_DIRECTORY, `unreadable: ${errorCode(error) ?? "error"}`);
  }
  const uid = currentUid(options);
  try {
    assertOwnedDirectory(root, uid);
  } catch (error) {
    throw untrusted(HELPER_RUNS_DIRECTORY, error instanceof Error ? error.message : String(error));
  }
  const names = fs.readdirSync(root).sort();
  if (names.length === 0) return { reclaimed: 0, pending: 0 };
  fence.lifecycleLock.assertHeld();

  const runs: HelperRun[] = [];
  const emptyDirectories: string[] = [];
  for (const name of names) {
    if (!RUN_DIRECTORY_PATTERN.test(name)) throw untrusted(name, "unexpected entry in helper-runs");
    const directory = path.join(root, name);
    try {
      assertOwnedDirectory(directory, uid);
    } catch (error) {
      throw untrusted(name, error instanceof Error ? error.message : String(error));
    }
    const intentPath = path.join(directory, INTENT_FILE);
    let intentStat: fs.Stats;
    try {
      intentStat = fs.lstatSync(intentPath);
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw untrusted(name, `intent is unreadable: ${errorCode(error) ?? "error"}`);
      // The run died between mkdtemp and the intent rename. The helper is
      // spawned only after the rename, so a directory holding nothing, or only
      // the torn temp intent, has no helper.
      const entries = fs.readdirSync(directory);
      if (entries.some((entry) => entry !== INTENT_TEMP_FILE)) throw untrusted(name, "run directory has no intent");
      emptyDirectories.push(directory);
      continue;
    }
    if (intentStat.isSymbolicLink() || !intentStat.isFile()) throw untrusted(name, "intent is not a regular file");
    if (uid !== undefined && intentStat.uid !== uid) throw untrusted(name, "intent is owned by another user");
    if (intentStat.size > MAX_INTENT_BYTES) throw untrusted(name, "intent is oversized");
    let intent: HelperRunIntent;
    try {
      const descriptor = fs.openSync(intentPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      let text: string;
      try {
        const opened = fs.fstatSync(descriptor);
        if (!opened.isFile() || opened.ino !== intentStat.ino || opened.dev !== intentStat.dev) {
          throw new Error("intent changed while it was read");
        }
        text = fs.readFileSync(descriptor, "utf8");
      } finally {
        fs.closeSync(descriptor);
      }
      intent = parseHelperIntent(text);
    } catch (error) {
      throw untrusted(name, `intent is unparsable: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (intent.projectId !== expectedProjectId) throw untrusted(name, "intent belongs to another project");
    runs.push(Object.freeze({ directory, cidFile: path.join(directory, CID_FILE), intent }));
  }

  for (const directory of emptyDirectories) removeHelperRunDirectory(directory);
  const failures: EphemeralHelperUnconfirmedError[] = [];
  let pending = 0;
  for (const run of runs) {
    try {
      if (reclaimHelperRun(run, fence, "crash", { ...options, clientKilled: true }) === "pending") pending += 1;
    } catch (error) {
      if (!(error instanceof EphemeralHelperUnconfirmedError)) throw error;
      failures.push(error);
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new EphemeralHelperUnconfirmedError(failures.map((failure) => failure.message).join("\n"), { cause: failures[0] });
  }
  return { reclaimed: runs.length - pending, pending };
}
