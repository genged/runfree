import type * as childProcess from "node:child_process";

import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";

import { parseStrictJson } from "../control/strict-json.ts";
import {
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  SELECTED_AGENT_IMAGE_LABEL_NAMES,
} from "./constants.ts";
import {
  assertSessionContainerRecordProject,
  SESSION_CONTAINER_LABELS,
  sessionContainerName,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { CaptureResult } from "./types.ts";
import { isRecord } from "../strict-primitives.ts";

export const SESSION_SOURCE_IP_FIRST_HOST = 20;
export const SESSION_CONTAINER_CONCURRENCY_CAP = 64;

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SESSION_ID_PATTERN = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/;
const OPAQUE_SESSION_IDENTITY_PATTERN = /^[a-f0-9]{64}$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const MAX_SESSION_CONTAINER_INVENTORY_IDS = 1_024;
const MAX_SESSION_CONTAINER_INVENTORY_LIST_BYTES = 128 * 1_024;
const MAX_SESSION_CONTAINER_INVENTORY_INSPECT_BYTES = 8 * 1_024 * 1_024;
const MAX_SESSION_CONTAINER_INVENTORY_INSPECT_IDS = 64;
const MAX_SESSION_CONTAINER_INVENTORY_REPAIR_PASSES = 4;

export type SessionNetworkAttachment = {
  networkId: string;
  networkName: string;
  containerId: string;
  containerName: string;
  sourceIp: string;
};

export type SessionContainerSnapshot = {
  containerId: string;
  containerName: string;
  imageId: string;
  labels: Record<string, string>;
  sourceIp?: string;
  internalNetworkId?: string;
  running: boolean;
  /** Present only when host-wide Docker metadata was not exact enough to trust. */
  malformedInventoryMetadata?: true;
  /** Preserves a Runfree ownership hint even when the hinted metadata is malformed. */
  managedInventoryHint?: true;
  /** Preserves the expected project's direct-session name hint after sanitizing metadata. */
  sessionInventoryHint?: true;
};

export type SessionContainerInventoryExecutor = (
  executable: "docker",
  args: readonly string[],
  options?: childProcess.SpawnSyncOptions,
) => CaptureResult;

export type VerifiedSessionContainerIdentity = {
  projectId: string;
  composeProject: string;
  sessionId: string;
  sessionIncarnation: string;
  selectedAgentImageInputDigest: string;
  selectedAgentImageId: string;
  sessionAgentMaterializationDigest: string;
  sessionAgentGenerationDigest: string;
  sessionTemplateDigest: string;
  admissionContractEpoch: number;
  runfreeVersion: string;
};

export type SessionReconciliationClassification =
  | {
      kind: "matching";
      record: SessionContainerRecordV2;
      container: SessionContainerSnapshot;
    }
  | {
      kind: "unbound-created";
      record: SessionContainerRecordV2;
      container: SessionContainerSnapshot;
      identity: VerifiedSessionContainerIdentity;
    }
  | {
      kind: "record-only";
      record: SessionContainerRecordV2;
    }
  | {
      kind: "container-only";
      container: SessionContainerSnapshot;
      identity: VerifiedSessionContainerIdentity;
    }
  | {
      kind: "mismatch";
      record: SessionContainerRecordV2;
      containers: SessionContainerSnapshot[];
      reason: string;
    }
  | {
      kind: "untrusted-container";
      container: SessionContainerSnapshot;
      reason: string;
    };

export type SessionAgentImageReference = {
  imageId: string;
  references: string[];
};

export type SessionAgentImageReferenceAccounting = {
  images: SessionAgentImageReference[];
  materializations: Array<{
    materializationDigest: string;
    references: string[];
  }>;
  uncertainContainerIds: string[];
};

type ContainerOnlySessionClassification = Extract<
  SessionReconciliationClassification,
  { kind: "container-only" }
>;

type UnboundCreatedSessionClassification = Extract<
  SessionReconciliationClassification,
  { kind: "unbound-created" }
>;

const containerOnlyClassificationBindings = new WeakMap<object, Readonly<{
  project: Readonly<SessionContainerProjectIdentity>;
  inventory: ExactDockerInventoryBinding;
}>>();
const unboundCreatedClassificationProjects = new WeakMap<object, Readonly<SessionContainerProjectIdentity>>();
type ExactDockerInventoryBinding = Readonly<{
  project: Readonly<SessionContainerProjectIdentity>;
  containers: readonly SessionContainerSnapshot[];
}>;

type SessionContainerInventoryInspection = Readonly<{
  snapshots: readonly SessionContainerSnapshot[];
  /** Members of chunks Docker refused; empty when every chunk inspected. */
  failedIds: readonly string[];
  /** Ids the daemon itself reported absent — the only evidence that one is gone. */
  goneIds: ReadonlySet<string>;
  /** Why Docker refused, bounded, so a refusal can name its own cause. */
  failureReason: string;
}>;

const exactDockerInventorySnapshots = new WeakMap<object, ExactDockerInventoryBinding>();


function assertExactSessionProjectIdentity(expected: SessionContainerProjectIdentity): void {
  if (!/^[a-f0-9]{12}$/.test(expected.projectId)
    || expected.composeProject !== `runfree-${expected.projectId}`) {
    throw new Error("session-container inventory project identity is invalid");
  }
}

function parseSessionContainerInventoryIds(source: string): readonly string[] {
  if (Buffer.byteLength(source) > MAX_SESSION_CONTAINER_INVENTORY_LIST_BYTES) {
    throw new Error("Docker session-container inventory list exceeds the size limit");
  }
  if (source === "") return Object.freeze([]);
  if (!source.endsWith("\n")) throw new Error("Docker session-container inventory list is malformed");
  const ids = source.slice(0, -1).split("\n");
  if (ids.length > MAX_SESSION_CONTAINER_INVENTORY_IDS) {
    throw new Error("Docker session-container inventory exceeds the container limit");
  }
  const unique = new Set<string>();
  for (const id of ids) {
    dockerObjectId(id, "session-container inventory id");
    if (unique.has(id)) throw new Error(`duplicate Docker session-container inventory id: ${id}`);
    unique.add(id);
  }
  return Object.freeze(ids);
}

function emptyEndpointField(value: unknown): boolean {
  return value === undefined || value === "";
}

/**
 * True when Docker reports network membership but has assigned no address.
 *
 * Keyed on `IPAddress` alone, which is the narrowest change that fixes the
 * defect:
 *
 * - `NetworkID` is not consulted, because it names *which* network the
 *   container was created against and the daemon knows that at create time,
 *   before any endpoint exists. Requiring it to be empty too is what made the
 *   first attempt at this fix ineffective against a real daemon.
 * - `EndpointID` is not consulted either. The original code never looked at it,
 *   and making it load-bearing reclassified every container whose inspection
 *   omits it — turning exact orphans into untrusted containers across fifteen
 *   existing tests. It buys no safety here: authority requires an exact source
 *   IP match, which an addressless container can never satisfy.
 *
 * An address that is present but invalid, or present alongside an invalid
 * network id, is still malformed — that validation is unchanged.
 */
function unassignedNetworkAddress(endpoint: Record<string, unknown>): boolean {
  return emptyEndpointField(endpoint.IPAddress);
}

function tolerantDockerLabels(value: unknown): Readonly<{
  labels: Record<string, string>;
  malformed: boolean;
  managedHint: boolean;
}> {
  if (value === null || value === undefined) {
    return { labels: {}, malformed: false, managedHint: false };
  }
  if (!isRecord(value)) {
    return { labels: {}, malformed: true, managedHint: false };
  }
  const labels: Record<string, string> = {};
  let malformed = false;
  let managedHint = false;
  for (const [name, label] of Object.entries(value)) {
    const managed = name.startsWith(RUNFREE_LABEL_NAMESPACE);
    if (managed) managedHint = true;
    if (!wellFormedDockerLabel(name, label)) {
      // Only Runfree's own namespace condemns the container.
      //
      // Docker merges the *image's* labels into `Config.Labels`, and a base
      // image may legitimately declare anything. Runfree's agent image descends
      // from Ubuntu, which ships a multi-line
      // `org.opencontainers.image.description`; its newlines are control
      // characters, so condemning the whole set for one bad value marked every
      // session container's metadata malformed. That is the first check in
      // `verifiedSessionContainerIdentity`, so no session container could be
      // reconciled at all — a crash mid-lifecycle left state that recovery
      // refused, and the project could not admit another session.
      //
      // A malformed label Runfree owns still condemns, because that is state
      // Runfree wrote and cannot explain. A malformed foreign label is dropped
      // from the map and otherwise ignored: it is not evidence about the
      // container's identity, which is carried entirely by the
      // `io.runfree.*` keys.
      if (managed) malformed = true;
      continue;
    }
    labels[name] = label;
  }
  return { labels, malformed, managedHint };
}

const RUNFREE_LABEL_NAMESPACE = "io.runfree.";

function wellFormedDockerLabel(name: string, label: unknown): label is string {
  return name.length > 0
    && name.length <= 255
    && !CONTROL_CHARACTER_PATTERN.test(name)
    && typeof label === "string"
    && Buffer.byteLength(label) <= 4 * 1_024
    && !CONTROL_CHARACTER_PATTERN.test(label);
}

function sessionContainerNameHint(value: unknown, expectedProject: SessionContainerProjectIdentity): boolean {
  return typeof value === "string"
    && value.startsWith(`/runfree-${expectedProject.projectId}-session-`);
}

function parseSessionContainerInventoryInspect(
  source: string,
  ids: readonly string[],
  expectedProject: SessionContainerProjectIdentity,
): readonly SessionContainerSnapshot[] {
  if (Buffer.byteLength(source) > MAX_SESSION_CONTAINER_INVENTORY_INSPECT_BYTES) {
    throw new Error("Docker session-container inventory inspection exceeds the size limit");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error("Docker returned malformed session-container inventory inspection JSON");
  }
  if (!Array.isArray(parsed) || parsed.length !== ids.length) {
    throw new Error("Docker did not return the exact session-container inventory");
  }
  const expectedIds = new Set(ids);
  const observedIds = new Set<string>();
  const internalNetworkName = `${expectedProject.composeProject}_agent_internal`;
  const snapshots = parsed.map((value): SessionContainerSnapshot => {
    if (!isRecord(value)) throw new Error("Docker session-container inventory item is malformed");
    const containerId = dockerObjectId(value.Id, "session-container inventory inspect id");
    if (!expectedIds.has(containerId) || observedIds.has(containerId)) {
      throw new Error("Docker session-container inventory inspection returned an unexpected container id");
    }
    observedIds.add(containerId);
    const rawName = value.Name;
    const managedNameHint = sessionContainerNameHint(rawName, expectedProject);
    const exactName = typeof rawName === "string"
      && rawName.startsWith("/")
      && rawName.length >= 2
      && rawName.length <= 256
      && !rawName.slice(1).includes("/")
      && !CONTROL_CHARACTER_PATTERN.test(rawName);
    const rawImage = value.Image;
    const exactImage = typeof rawImage === "string" && SHA256_PATTERN.test(rawImage);
    const config = isRecord(value.Config) ? value.Config : undefined;
    const parsedLabels = tolerantDockerLabels(config?.Labels);
    const state = isRecord(value.State) ? value.State : undefined;
    const rawRunning = state?.Running;
    const exactState = typeof rawRunning === "boolean";
    const networkSettings = isRecord(value.NetworkSettings) ? value.NetworkSettings : undefined;
    const networks = isRecord(networkSettings?.Networks) ? networkSettings.Networks : undefined;
    const exactNetworkSettings = networks !== undefined;
    const internalEndpoint = networks?.[internalNetworkName];
    let sourceIp: string | undefined;
    let internalNetworkId: string | undefined;
    let malformedInternalEndpoint = false;
    if (internalEndpoint !== undefined) {
      if (!isRecord(internalEndpoint)) {
        malformedInternalEndpoint = true;
      } else if (unassignedNetworkAddress(internalEndpoint)) {
        // Docker attaches a network endpoint at start, not at create. A
        // container that has never run therefore carries only its requested
        // address in `IPAMConfig`, with `IPAddress`, `NetworkID`, and
        // `EndpointID` empty — and a stopped container looks the same once its
        // endpoint is released. That is "no endpoint yet", not a malformed one.
        //
        // Treating it as malformed made `verifiedSessionContainerIdentity`
        // refuse at its first check, so a crash between `docker create` and the
        // record capturing the container id produced an unreconcilable
        // `mismatch` and stranded the project. `session-container-proof.ts`
        // already models this correctly (a created container is "not running
        // yet", not a violated contract); this module was the site that did
        // not.
        //
        // A *running* container in this shape is still malformed: it should
        // have an endpoint, and the authority-bearing match in
        // `recordMatchesContainer` requires an exact source IP, so nothing here
        // widens what may hold authority.
        malformedInternalEndpoint = rawRunning === true;
      } else if (typeof internalEndpoint.IPAddress !== "string"
        || !isExactSessionSourceIpv4(internalEndpoint.IPAddress)
        || typeof internalEndpoint.NetworkID !== "string"
        || !DOCKER_OBJECT_ID_PATTERN.test(internalEndpoint.NetworkID)) {
        malformedInternalEndpoint = true;
      } else {
        sourceIp = internalEndpoint.IPAddress;
        internalNetworkId = internalEndpoint.NetworkID;
      }
    }
    const malformedInventoryMetadata = !exactName
      || !exactImage
      || config === undefined
      || parsedLabels.malformed
      || !exactState
      || !exactNetworkSettings
      || malformedInternalEndpoint;
    const managedInventoryHint = parsedLabels.managedHint
      || malformedInternalEndpoint;
    const snapshot = Object.freeze({
      containerId,
      containerName: exactName ? rawName.slice(1) : `foreign-${containerId.slice(0, 12)}`,
      imageId: exactImage ? rawImage : `sha256:${"0".repeat(64)}`,
      labels: Object.freeze(parsedLabels.labels),
      ...(sourceIp === undefined ? {} : { sourceIp, internalNetworkId }),
      running: exactState ? rawRunning : false,
      ...(malformedInventoryMetadata ? { malformedInventoryMetadata: true as const } : {}),
      ...(managedInventoryHint ? { managedInventoryHint: true as const } : {}),
      ...(managedNameHint ? { sessionInventoryHint: true as const } : {}),
    });
    return snapshot;
  });
  return Object.freeze(snapshots);
}

function sealExactDockerInventory(
  snapshots: readonly SessionContainerSnapshot[],
  expectedIds: readonly string[],
  expectedProject: SessionContainerProjectIdentity,
): readonly SessionContainerSnapshot[] {
  if (snapshots.length !== expectedIds.length) {
    throw new Error("Docker did not return the exact session-container inventory");
  }
  const expected = new Set(expectedIds);
  const observed = new Set<string>();
  for (const snapshot of snapshots) {
    if (!expected.has(snapshot.containerId) || observed.has(snapshot.containerId)) {
      throw new Error("Docker session-container inventory inspection returned an unexpected container id");
    }
    observed.add(snapshot.containerId);
  }
  const containers = Object.freeze([...snapshots].sort((left, right) => left.containerId.localeCompare(right.containerId)));
  const binding = Object.freeze({
    project: Object.freeze({ ...expectedProject }),
    containers,
  });
  for (const snapshot of containers) exactDockerInventorySnapshots.set(snapshot, binding);
  return containers;
}

function listSessionContainerInventoryIds(
  executor: SessionContainerInventoryExecutor,
  options: childProcess.SpawnSyncOptions,
): readonly string[] {
  const listResult = executor("docker", [
    "container",
    "ls",
    "--all",
    "--no-trunc",
    "--format",
    "{{.ID}}",
  ], options);
  if (listResult.status !== 0) throw new Error("Docker could not list the exact session-container inventory");
  return parseSessionContainerInventoryIds(listResult.stdout);
}

function inspectSessionContainerInventoryIds(
  executor: SessionContainerInventoryExecutor,
  ids: readonly string[],
  expectedProject: SessionContainerProjectIdentity,
  options: childProcess.SpawnSyncOptions,
): SessionContainerInventoryInspection {
  const snapshots: SessionContainerSnapshot[] = [];
  const failedIds: string[] = [];
  const goneIds = new Set<string>();
  const failureReasons: string[] = [];
  let inspectedBytes = 0;
  for (let offset = 0; offset < ids.length; offset += MAX_SESSION_CONTAINER_INVENTORY_INSPECT_IDS) {
    const chunk = ids.slice(offset, offset + MAX_SESSION_CONTAINER_INVENTORY_INSPECT_IDS);
    const inspectResult = executor("docker", ["container", "inspect", ...chunk], options);
    if (inspectResult.status !== 0) {
      // Docker fails the whole chunk when any one member is gone and does not
      // say which. Keep the chunk for repair and inspect the rest: abandoning
      // the pass here only forces a re-inspection of chunks that already
      // succeeded, which re-opens their window for nothing.
      failedIds.push(...chunk);
      // The daemon names every id it could not find, one per line. That is the
      // only sound evidence that a container is gone: a fresh `container ls`
      // has been observed to still list an id that `container inspect` reports
      // as absent, so the list cannot settle existence.
      for (const id of goneIdsFromFailure(inspectResult, chunk)) goneIds.add(id);
      // Carry the reason: a vanished container, an unreachable daemon, and a
      // client-side buffer overrun all arrive here as a non-zero status, and a
      // refusal that cannot name which one is not diagnosable from a log.
      failureReasons.push(inspectFailureReason(inspectResult));
      continue;
    }
    inspectedBytes += Buffer.byteLength(inspectResult.stdout);
    if (inspectedBytes > MAX_SESSION_CONTAINER_INVENTORY_INSPECT_BYTES) {
      throw new Error("Docker session-container inventory inspection exceeds the cumulative size limit");
    }
    snapshots.push(...parseSessionContainerInventoryInspect(inspectResult.stdout, chunk, expectedProject));
  }
  return Object.freeze({
    snapshots: Object.freeze(snapshots),
    failedIds: Object.freeze(failedIds),
    goneIds,
    failureReason: failureReasons.join("; "),
  });
}

/**
 * Matches the daemon's "missing" replies, one line per absent id.
 *
 * `container inspect` says "No such container"; the generic `inspect` says
 * "No such object". Accept both so the classification does not hinge on which
 * verb a Docker version happens to use.
 */
const NO_SUCH_CONTAINER_PATTERN = /No such (?:container|object):\s*([0-9a-f]{6,64})/gi;

/**
 * Ids from this chunk that the daemon explicitly reported absent.
 *
 * Empty means the refusal was not about a missing container — an unreachable
 * daemon, a timeout, a buffer overrun — and the caller must fail closed rather
 * than treat the chunk as churn.
 */
function goneIdsFromFailure(result: CaptureResult, chunk: readonly string[]): readonly string[] {
  const named = new Set<string>();
  for (const match of `${result.stderr ?? ""}`.matchAll(NO_SUCH_CONTAINER_PATTERN)) {
    named.add(match[1].toLowerCase());
  }
  // Only ids this call actually asked about; the daemon should never name
  // another, and a reply that does is not evidence about our chunk.
  return chunk.filter((id) => named.has(id));
}

const MAX_INVENTORY_FAILURE_REASON_CHARS = 300;

/** Docker's own words for a refused chunk, bounded and single-line. */
function inspectFailureReason(result: CaptureResult): string {
  const detail = `${result.stderr ?? ""}`.replace(/\s+/g, " ").trim()
    || `exit status ${result.status === null ? "unknown" : result.status}`;
  return detail.length > MAX_INVENTORY_FAILURE_REASON_CHARS
    ? `${detail.slice(0, MAX_INVENTORY_FAILURE_REASON_CHARS)}…`
    : detail;
}

/**
 * Takes one bounded all-container ID snapshot, then inspects exactly that set.
 *
 * Docker refuses a whole `container inspect` chunk when any one member has
 * disappeared, so a failed chunk means either churn or a daemon failure. One
 * fresh all-container snapshot separates them and is the only authority for
 * "gone": an id that snapshot no longer reports does not exist, therefore holds
 * no address and belongs in no inventory. Every id it still reports must
 * inspect cleanly or the call fails closed.
 *
 * The repair re-inspects only what pass one did not already prove: refused ids
 * that survived, plus ids the fresh list newly reports, so a container racing
 * in to squat a session name is still seen. It never re-inspects a chunk that
 * already succeeded — doing that re-opens the chunk's window, and is what let a
 * second churn event anywhere on the host refuse a launch. Bounded at two lists
 * and two inspect passes; there is no unbounded retry.
 *
 * The returned objects carry process-local provenance used by destructive
 * orphan cleanup; caller-constructed lookalikes do not.
 */
export function inspectSessionContainerInventory(
  executor: SessionContainerInventoryExecutor,
  expectedProject: SessionContainerProjectIdentity,
  options: childProcess.SpawnSyncOptions = {},
): readonly SessionContainerSnapshot[] {
  assertExactSessionProjectIdentity(expectedProject);
  // Node's default synchronous-process buffer is smaller than the inventory
  // parser's explicit bounded contract on ordinary multi-project Docker
  // hosts. Give Docker enough room to return one accepted inventory while the
  // byte checks below remain the actual memory and trust boundary.
  const captureOptions: childProcess.SpawnSyncOptions = {
    ...options,
    maxBuffer: Math.max(options.maxBuffer ?? 0, MAX_SESSION_CONTAINER_INVENTORY_INSPECT_BYTES),
  };
  const ids = listSessionContainerInventoryIds(executor, captureOptions);
  if (ids.length === 0) return Object.freeze([]);
  const first = inspectSessionContainerInventoryIds(executor, ids, expectedProject, captureOptions);
  if (first.failedIds.length === 0) {
    return sealExactDockerInventory(first.snapshots, ids, expectedProject);
  }
  if (first.goneIds.size === 0) {
    throw new Error(
      `Docker could not inspect the exact session-container inventory: ${first.failureReason}`,
    );
  }

  // Something churned. Refresh once so a container that raced in after the
  // first snapshot -- one squatting a session name, say -- is still seen, then
  // inspect only what is still outstanding. Chunks that already succeeded are
  // never re-inspected: re-running them reopens their window for nothing.
  const refreshedIds = listSessionContainerInventoryIds(executor, captureOptions);
  const listed = new Set(refreshedIds);
  const gone = new Set(first.goneIds);
  // Keep only what pass one proved *and* the refresh still reports. A
  // container that left between the two is simply not in this inventory, and
  // carrying its snapshot would leave the seal counting a member the id set
  // no longer has.
  const snapshots = first.snapshots.filter((snapshot) => listed.has(snapshot.containerId));
  const inspected = new Set(snapshots.map((snapshot) => snapshot.containerId));

  // Each pass either finishes or removes at least one id the daemon named as
  // absent, so this converges; the cap only bounds a pathological daemon.
  for (let attempt = 0; attempt < MAX_SESSION_CONTAINER_INVENTORY_REPAIR_PASSES; attempt += 1) {
    const outstanding = refreshedIds.filter((id) => !inspected.has(id) && !gone.has(id));
    if (outstanding.length === 0) {
      return sealExactDockerInventory(
        snapshots.filter((snapshot) => !gone.has(snapshot.containerId)),
        refreshedIds.filter((id) => !gone.has(id)),
        expectedProject,
      );
    }
    const pass = inspectSessionContainerInventoryIds(executor, outstanding, expectedProject, captureOptions);
    for (const snapshot of pass.snapshots) {
      snapshots.push(snapshot);
      inspected.add(snapshot.containerId);
    }
    if (pass.failedIds.length === 0) continue;
    if (pass.goneIds.size === 0) {
      throw new Error(
        `Docker could not inspect the exact session-container inventory: ${pass.failureReason}`,
      );
    }
    for (const id of pass.goneIds) gone.add(id);
  }
  throw new Error("Docker could not inspect a settled exact session-container inventory");
}

function dockerObjectId(value: unknown, label: string): string {
  if (typeof value !== "string" || !DOCKER_OBJECT_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be an exact Docker object id`);
  }
  return value;
}

function sha256(value: string, label: string): string {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} must be a full sha256 digest`);
  return value;
}

function exactIpv4Cidr(value: unknown): { address: string; prefix: number } {
  if (typeof value !== "string") throw new Error("Docker network attachment has no exact IPv4 address");
  const [address, prefixRaw, extra] = value.split("/");
  const prefix = Number(prefixRaw);
  if (extra !== undefined
    || !address
    || !isExactSessionSourceIpv4(address)
    || !Number.isInteger(prefix)
    || prefix < 1
    || prefix > 32
    || `${address}/${prefix}` !== value) {
    throw new Error("Docker network attachment has an invalid IPv4 CIDR");
  }
  return { address, prefix };
}

function subnet24Prefix(subnet: string): string {
  const parsed = exactIpv4Cidr(subnet);
  if (parsed.prefix !== 24 || !parsed.address.endsWith(".0")) {
    throw new Error("session address pool requires an exact IPv4 /24 subnet ending in .0");
  }
  return parsed.address.slice(0, -2);
}

function hostNumber(ip: string, prefix: string): number | undefined {
  if (!ip.startsWith(`${prefix}.`)) return undefined;
  const host = Number(ip.slice(prefix.length + 1));
  return Number.isInteger(host) && host >= 0 && host <= 255 ? host : undefined;
}

export function parseSessionNetworkAttachments(
  source: string,
  expected: { networkId: string; networkName: string; subnet: string },
): SessionNetworkAttachment[] {
  dockerObjectId(expected.networkId, "expected session network id");
  const expectedPrefix = subnet24Prefix(expected.subnet);
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch {
    throw new Error("Docker returned malformed session network inspection JSON");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new Error("Docker did not return exactly one session network inspection");
  }
  const network = parsed[0];
  if (network.Id !== expected.networkId || network.Name !== expected.networkName) {
    throw new Error("Docker session network inspection names a different network");
  }
  if (network.Containers === undefined || network.Containers === null) return [];
  if (!isRecord(network.Containers)) throw new Error("Docker session network attachments are malformed");
  return Object.entries(network.Containers).map(([containerId, value]) => {
    dockerObjectId(containerId, "session network attachment container id");
    if (!isRecord(value)
      || typeof value.Name !== "string"
      || value.Name.length === 0
      || value.Name.length > 255
      || CONTROL_CHARACTER_PATTERN.test(value.Name)) {
      throw new Error("Docker session network attachment is malformed");
    }
    const address = exactIpv4Cidr(value.IPv4Address).address;
    if (hostNumber(address, expectedPrefix) === undefined) {
      throw new Error("Docker session network attachment is outside the selected subnet");
    }
    return {
      networkId: expected.networkId,
      networkName: expected.networkName,
      containerId,
      containerName: value.Name,
      sourceIp: address,
    };
  }).sort((left, right) => left.containerId.localeCompare(right.containerId));
}

function assertUniqueRecordClaims(records: readonly SessionContainerRecordV2[]): void {
  for (const [label, select] of [
    ["session id", (record: SessionContainerRecordV2) => record.sessionId],
    ["session incarnation", (record: SessionContainerRecordV2) => record.sessionIncarnation],
    ["session principal", (record: SessionContainerRecordV2) => record.sessionPrincipal],
    ["source IP", (record: SessionContainerRecordV2) => record.sourceIp],
  ] as const) {
    const values = new Set<string>();
    for (const record of records) {
      const value = select(record);
      if (values.has(value)) throw new Error(`duplicate session-container ${label} claim: ${value}`);
      values.add(value);
    }
  }
  const containerIds = new Set<string>();
  for (const record of records) {
    if (!record.containerId) continue;
    if (containerIds.has(record.containerId)) throw new Error(`duplicate session-container container id claim: ${record.containerId}`);
    containerIds.add(record.containerId);
  }
}

function assertUniqueAttachments(attachments: readonly SessionNetworkAttachment[]): void {
  const ids = new Set<string>();
  const ips = new Set<string>();
  for (const attachment of attachments) {
    dockerObjectId(attachment.networkId, "session network id");
    dockerObjectId(attachment.containerId, "session network attachment container id");
    if (!isExactSessionSourceIpv4(attachment.sourceIp)) throw new Error("session network attachment has an invalid source IP");
    if (ids.has(attachment.containerId)) throw new Error(`duplicate Docker network attachment for container ${attachment.containerId}`);
    if (ips.has(attachment.sourceIp)) throw new Error(`duplicate Docker network source IP ${attachment.sourceIp}`);
    ids.add(attachment.containerId);
    ips.add(attachment.sourceIp);
  }
}

export function allocateSessionSourceIp(input: {
  expectedProject: SessionContainerProjectIdentity;
  networkId: string;
  networkName: string;
  subnet: string;
  reservedIps: readonly string[];
  records: readonly SessionContainerRecordV2[];
  attachments: readonly SessionNetworkAttachment[];
  cap?: number;
}): string {
  const prefix = subnet24Prefix(input.subnet);
  dockerObjectId(input.networkId, "session network id");
  if (input.networkName.length === 0 || input.networkName.length > 255 || CONTROL_CHARACTER_PATTERN.test(input.networkName)) {
    throw new Error("session network name is invalid");
  }
  const cap = input.cap ?? SESSION_CONTAINER_CONCURRENCY_CAP;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > SESSION_CONTAINER_CONCURRENCY_CAP) {
    throw new Error(`session-container cap must be between 1 and ${SESSION_CONTAINER_CONCURRENCY_CAP}`);
  }
  if (SESSION_SOURCE_IP_FIRST_HOST + cap - 1 >= 255) throw new Error("session address pool exceeds the selected subnet");
  for (const record of input.records) assertSessionContainerRecordProject(record, input.expectedProject);
  assertUniqueRecordClaims(input.records);
  assertUniqueAttachments(input.attachments);
  if (input.attachments.some((attachment) => (
    attachment.networkId !== input.networkId || attachment.networkName !== input.networkName
  ))) {
    throw new Error("Docker attachment belongs to a different session network");
  }
  if (input.records.length >= cap) throw new Error(`session-container concurrency cap reached (${cap})`);

  const reserved = new Set<string>();
  for (const ip of input.reservedIps) {
    if (!isExactSessionSourceIpv4(ip) || hostNumber(ip, prefix) === undefined) {
      throw new Error(`reserved session-network address is invalid or outside ${input.subnet}: ${ip}`);
    }
    reserved.add(ip);
  }

  const poolStart = SESSION_SOURCE_IP_FIRST_HOST;
  const poolEnd = poolStart + cap - 1;
  const recordsByIp = new Map(input.records.map((record) => [record.sourceIp, record]));
  const attachmentsByContainer = new Map(input.attachments.map((attachment) => [attachment.containerId, attachment]));
  for (const record of input.records) {
    const recordHost = hostNumber(record.sourceIp, prefix);
    if (recordHost === undefined || recordHost < poolStart || recordHost > poolEnd) {
      throw new Error(`session-container record source IP is outside the reserved pool: ${record.sourceIp}`);
    }
    const attachment = record.containerId ? attachmentsByContainer.get(record.containerId) : undefined;
    const mustHaveLiveEndpoint = record.state === "provisioning-running" || record.state === "attached";
    if (mustHaveLiveEndpoint && (!attachment || attachment.sourceIp !== record.sourceIp)) {
      throw new Error(`session-container ${record.sessionId} network attachment disagrees with its lifecycle record`);
    }
    if (attachment && attachment.sourceIp !== record.sourceIp) {
      throw new Error(`session-container ${record.sessionId} has a contradictory Docker source IP`);
    }
  }

  for (const attachment of input.attachments) {
    const attachmentHost = hostNumber(attachment.sourceIp, prefix);
    if (attachmentHost === undefined) throw new Error("Docker network attachment is outside the selected subnet");
    const record = recordsByIp.get(attachment.sourceIp);
    if (record) {
      if (record.containerId !== attachment.containerId) {
        throw new Error(`Docker source IP ${attachment.sourceIp} belongs to a different session container`);
      }
      continue;
    }
    if (!reserved.has(attachment.sourceIp)) {
      throw new Error(`unknown Docker participant owns unreserved session-network IP ${attachment.sourceIp}`);
    }
  }

  const used = new Set([
    ...reserved,
    ...input.records.map((record) => record.sourceIp),
    ...input.attachments.map((attachment) => attachment.sourceIp),
  ]);
  for (let host = poolStart; host <= poolEnd; host += 1) {
    const candidate = `${prefix}.${host}`;
    if (!used.has(candidate)) return candidate;
  }
  throw new Error("session-container source IP pool is exhausted");
}

function boundedLabel(value: string | undefined, maximum: number): value is string {
  return value !== undefined
    && value === value.trim()
    && value.length > 0
    && value.length <= maximum
    && !CONTROL_CHARACTER_PATTERN.test(value);
}

function hasComposeOwnershipLabel(labels: Record<string, string>): boolean {
  return Object.keys(labels).some((name) => name.startsWith("com.docker.compose."));
}

function hasUnknownRunfreeLabel(labels: Record<string, string>): boolean {
  const allowed = new Set<string>([
    ...SELECTED_AGENT_IMAGE_LABEL_NAMES,
    ...Object.values(SESSION_CONTAINER_LABELS),
  ]);
  return Object.keys(labels).some((name) => name.startsWith("io.runfree.") && !allowed.has(name));
}

export function verifiedSessionContainerIdentity(
  container: SessionContainerSnapshot,
  expected: SessionContainerProjectIdentity,
): VerifiedSessionContainerIdentity | undefined {
  if (container.malformedInventoryMetadata
    || !DOCKER_OBJECT_ID_PATTERN.test(container.containerId)
    || !SHA256_PATTERN.test(container.imageId)
    || hasComposeOwnershipLabel(container.labels)
    || hasUnknownRunfreeLabel(container.labels)) return undefined;
  const labels = container.labels;
  const sessionId = labels[SESSION_CONTAINER_LABELS.sessionId];
  const incarnation = labels[SESSION_CONTAINER_LABELS.sessionIncarnation];
  const inputDigest = labels[SESSION_CONTAINER_LABELS.selectedAgentImageInputDigest];
  const selectedAgentImageId = labels[SESSION_CONTAINER_LABELS.selectedAgentImageId];
  const sessionAgentMaterializationDigest = labels[SESSION_CONTAINER_LABELS.sessionAgentMaterializationDigest];
  const sessionAgentGenerationDigest = labels[SESSION_CONTAINER_LABELS.sessionAgentGenerationDigest];
  const templateDigest = labels[SESSION_CONTAINER_LABELS.sessionTemplateDigest];
  const epochRaw = labels[SESSION_CONTAINER_LABELS.admissionContractEpoch];
  const version = labels[SESSION_CONTAINER_LABELS.version];
  const epoch = Number(epochRaw);
  if (labels[SESSION_CONTAINER_LABELS.managed] !== "true"
    || labels[SESSION_CONTAINER_LABELS.role] !== "session-agent"
    || labels[SESSION_CONTAINER_LABELS.projectId] !== expected.projectId
    || labels[SESSION_CONTAINER_LABELS.composeProject] !== expected.composeProject
    || typeof sessionId !== "string"
    || !SESSION_ID_PATTERN.test(sessionId)
    || typeof incarnation !== "string"
    || !OPAQUE_SESSION_IDENTITY_PATTERN.test(incarnation)
    || typeof inputDigest !== "string"
    || !SHA256_PATTERN.test(inputDigest)
    || typeof selectedAgentImageId !== "string"
    || !SHA256_PATTERN.test(selectedAgentImageId)
    || (labels[RUNFREE_IMAGE_ROLE_LABEL] !== AGENT_RUNTIME_IMAGE_ROLE
      && labels[RUNFREE_IMAGE_ROLE_LABEL] !== AGENT_PROJECT_IMAGE_ROLE)
    || labels[RUNFREE_DIGEST_SCHEMA_LABEL] !== RUNFREE_DIGEST_SCHEMA_VERSION
    || labels[RUNFREE_IMAGE_INPUT_DIGEST_LABEL] !== inputDigest
    || selectedAgentImageId !== container.imageId
    || typeof sessionAgentMaterializationDigest !== "string"
    || !SHA256_PATTERN.test(sessionAgentMaterializationDigest)
    || typeof sessionAgentGenerationDigest !== "string"
    || !SHA256_PATTERN.test(sessionAgentGenerationDigest)
    || typeof templateDigest !== "string"
    || !SHA256_PATTERN.test(templateDigest)
    || !Number.isSafeInteger(epoch)
    || epoch < 1
    || !boundedLabel(version, 64)
    || container.containerName !== sessionContainerName(expected.projectId, sessionId)
    || (container.sourceIp !== undefined && !isExactSessionSourceIpv4(container.sourceIp))) return undefined;
  return {
    projectId: expected.projectId,
    composeProject: expected.composeProject,
    sessionId,
    sessionIncarnation: incarnation,
    selectedAgentImageInputDigest: inputDigest,
    selectedAgentImageId,
    sessionAgentMaterializationDigest,
    sessionAgentGenerationDigest,
    sessionTemplateDigest: templateDigest,
    admissionContractEpoch: epoch,
    runfreeVersion: version,
  };
}

function recordMatchesContainer(
  record: SessionContainerRecordV2,
  container: SessionContainerSnapshot,
  expected: SessionContainerProjectIdentity,
): boolean {
  const identity = verifiedSessionContainerIdentity(container, expected);
  if (!identity || !record.containerId) return false;
  if (record.containerId !== container.containerId
    || record.containerName !== container.containerName
    || record.selectedAgentImageId !== container.imageId
    || record.sessionId !== identity.sessionId
    || record.sessionIncarnation !== identity.sessionIncarnation
    || record.selectedAgentImageInputDigest !== identity.selectedAgentImageInputDigest
    || record.selectedAgentImageId !== identity.selectedAgentImageId
    || record.sessionAgentMaterializationDigest !== identity.sessionAgentMaterializationDigest
    || record.sessionAgentGenerationDigest !== identity.sessionAgentGenerationDigest
    || record.sessionTemplateDigest !== identity.sessionTemplateDigest
    || record.admissionContractEpoch !== identity.admissionContractEpoch) return false;
  if (record.state === "allocated") {
    return !container.running && (container.sourceIp === undefined || container.sourceIp === record.sourceIp);
  }
  if (record.state === "provisioning-running" || record.state === "attached") {
    return container.running && container.sourceIp === record.sourceIp;
  }
  if (record.state === "revoking") return container.sourceIp === undefined || container.sourceIp === record.sourceIp;
  return false;
}

function unboundAllocatedRecordMatchesCreatedContainer(
  record: SessionContainerRecordV2,
  container: SessionContainerSnapshot,
  expected: SessionContainerProjectIdentity,
): VerifiedSessionContainerIdentity | undefined {
  const identity = verifiedSessionContainerIdentity(container, expected);
  if (!identity
    || record.state !== "allocated"
    || record.containerId !== undefined
    || record.admittedAt !== undefined
    || record.leaseGeneration !== undefined
    || record.leaseExpiresAt !== undefined
    || container.running
    || record.containerName !== container.containerName
    || record.selectedAgentImageId !== container.imageId
    || record.sessionId !== identity.sessionId
    || record.sessionIncarnation !== identity.sessionIncarnation
    || record.selectedAgentImageInputDigest !== identity.selectedAgentImageInputDigest
    || record.selectedAgentImageId !== identity.selectedAgentImageId
    || record.sessionAgentMaterializationDigest !== identity.sessionAgentMaterializationDigest
    || record.sessionAgentGenerationDigest !== identity.sessionAgentGenerationDigest
    || record.sessionTemplateDigest !== identity.sessionTemplateDigest
    || record.admissionContractEpoch !== identity.admissionContractEpoch
    || (container.sourceIp !== undefined && container.sourceIp !== record.sourceIp)) return undefined;
  return identity;
}

function managedSessionHint(container: SessionContainerSnapshot, expected: SessionContainerProjectIdentity): boolean {
  if (container.sessionInventoryHint === true
    || container.containerName.startsWith(`runfree-${expected.projectId}-session-`)
  ) return true;
  const projectScoped = container.labels[SESSION_CONTAINER_LABELS.projectId] === expected.projectId
    || container.labels[SESSION_CONTAINER_LABELS.composeProject] === expected.composeProject;
  const sessionSpecificHint = container.labels[SESSION_CONTAINER_LABELS.role] === "session-agent"
    || [
      SESSION_CONTAINER_LABELS.sessionId,
      SESSION_CONTAINER_LABELS.sessionIncarnation,
      SESSION_CONTAINER_LABELS.selectedAgentImageInputDigest,
      SESSION_CONTAINER_LABELS.selectedAgentImageId,
      SESSION_CONTAINER_LABELS.sessionAgentMaterializationDigest,
      SESSION_CONTAINER_LABELS.sessionAgentGenerationDigest,
      SESSION_CONTAINER_LABELS.sessionTemplateDigest,
      SESSION_CONTAINER_LABELS.admissionContractEpoch,
    ].some((label) => Object.hasOwn(container.labels, label));
  if (projectScoped && sessionSpecificHint) return true;
  if (hasComposeOwnershipLabel(container.labels)) return false;
  return projectScoped && (container.managedInventoryHint === true
    || container.labels[SESSION_CONTAINER_LABELS.managed] === "true"
    || container.labels[SESSION_CONTAINER_LABELS.role] === "session-agent");
}

function sealContainerOnlyClassification(
  container: SessionContainerSnapshot,
  identity: VerifiedSessionContainerIdentity,
  expectedProject: SessionContainerProjectIdentity,
): ContainerOnlySessionClassification {
  const sealedContainer = Object.freeze({
    ...container,
    labels: Object.freeze({ ...container.labels }),
  });
  const classification = Object.freeze({
    kind: "container-only" as const,
    container: sealedContainer,
    identity: Object.freeze({ ...identity }),
  });
  const inventory = exactDockerInventorySnapshots.get(container);
  if (inventory?.project.projectId === expectedProject.projectId
    && inventory.project.composeProject === expectedProject.composeProject) {
    containerOnlyClassificationBindings.set(classification, Object.freeze({
      project: Object.freeze({ ...expectedProject }),
      inventory,
    }));
  }
  return classification;
}

function sealUnboundCreatedClassification(
  record: SessionContainerRecordV2,
  container: SessionContainerSnapshot,
  identity: VerifiedSessionContainerIdentity,
  expectedProject: SessionContainerProjectIdentity,
): UnboundCreatedSessionClassification {
  const sealedRecord = Object.freeze({
    ...record,
    launchArgs: Object.freeze([...record.launchArgs]),
  });
  const sealedContainer = Object.freeze({
    ...container,
    labels: Object.freeze({ ...container.labels }),
  });
  const classification = Object.freeze({
    kind: "unbound-created" as const,
    record: sealedRecord,
    container: sealedContainer,
    identity: Object.freeze({ ...identity }),
  });
  const inventory = exactDockerInventorySnapshots.get(container);
  if (inventory?.project.projectId === expectedProject.projectId
    && inventory.project.composeProject === expectedProject.composeProject) {
    unboundCreatedClassificationProjects.set(classification, Object.freeze({ ...expectedProject }));
  }
  return classification;
}

/**
 * Proves that a container-only result came from this process's exact Docker
 * reconciliation pass. A structurally identical object is not cleanup
 * authority: callers must re-inspect and reclassify after a process restart.
 */
export function assertExactContainerOnlySessionClassification(
  classification: SessionReconciliationClassification,
  expectedProject: SessionContainerProjectIdentity,
): asserts classification is ContainerOnlySessionClassification {
  const binding = containerOnlyClassificationBindings.get(classification);
  if (!binding || classification.kind !== "container-only") {
    throw new Error("session-container orphan classification was not minted from exact reconciliation");
  }
  if (binding.project.projectId !== expectedProject.projectId
    || binding.project.composeProject !== expectedProject.composeProject
    || classification.identity.projectId !== binding.project.projectId
    || classification.identity.composeProject !== binding.project.composeProject) {
    throw new Error("session-container orphan classification belongs to another project");
  }
}

/**
 * Reclassifies the exact all-container Docker snapshot against the caller's
 * full lifecycle registry view. A container recorded by that view can never
 * remain container-only cleanup authority.
 */
export function reclassifyExactContainerOnlySessionClassification(
  classification: SessionReconciliationClassification,
  records: readonly SessionContainerRecordV2[],
  expectedProject: SessionContainerProjectIdentity,
): ContainerOnlySessionClassification {
  assertExactContainerOnlySessionClassification(classification, expectedProject);
  const binding = containerOnlyClassificationBindings.get(classification);
  if (!binding) throw new Error("session-container orphan classification has no exact inventory provenance");
  const reconciled = classifySessionContainerReconciliation({
    expectedProject,
    records,
    containers: binding.inventory.containers,
  });
  const exact = reconciled.find((entry): entry is ContainerOnlySessionClassification => (
    entry.kind === "container-only"
    && entry.container.containerId === classification.container.containerId
  ));
  if (!exact) {
    throw new Error("session-container orphan cleanup target is present in the full lifecycle registry");
  }
  return exact;
}

/**
 * Proves that a stopped container was matched to its exact unbound allocation
 * by a fresh all-container Docker inventory. This authority exists only to
 * discard the non-authorizing allocation record before orphan cleanup.
 */
export function assertExactUnboundCreatedSessionClassification(
  classification: SessionReconciliationClassification,
  expectedProject: SessionContainerProjectIdentity,
): asserts classification is UnboundCreatedSessionClassification {
  const project = unboundCreatedClassificationProjects.get(classification);
  if (!project || classification.kind !== "unbound-created") {
    throw new Error("session-container create-output recovery classification was not minted from exact reconciliation");
  }
  if (project.projectId !== expectedProject.projectId
    || project.composeProject !== expectedProject.composeProject
    || classification.identity.projectId !== project.projectId
    || classification.identity.composeProject !== project.composeProject
    || !unboundAllocatedRecordMatchesCreatedContainer(
      classification.record,
      classification.container,
      expectedProject,
    )) {
    throw new Error("session-container create-output recovery classification belongs to another identity");
  }
}

export function classifySessionContainerReconciliation(input: {
  expectedProject: SessionContainerProjectIdentity;
  records: readonly SessionContainerRecordV2[];
  containers: readonly SessionContainerSnapshot[];
}): SessionReconciliationClassification[] {
  for (const record of input.records) assertSessionContainerRecordProject(record, input.expectedProject);
  assertUniqueRecordClaims(input.records);
  const containerIds = new Set<string>();
  for (const container of input.containers) {
    dockerObjectId(container.containerId, "session container snapshot id");
    if (containerIds.has(container.containerId)) throw new Error(`duplicate session container snapshot: ${container.containerId}`);
    containerIds.add(container.containerId);
  }

  const identities = new Map(input.containers.map((container) => [
    container.containerId,
    verifiedSessionContainerIdentity(container, input.expectedProject),
  ]));
  const consumed = new Set<string>();
  const result: SessionReconciliationClassification[] = [];
  for (const record of input.records) {
    const candidates = input.containers.filter((container) => container.containerId === record.containerId
      || container.containerName === record.containerName
      || container.sourceIp === record.sourceIp
      || identities.get(container.containerId)?.sessionId === record.sessionId
      || identities.get(container.containerId)?.sessionIncarnation === record.sessionIncarnation);
    for (const candidate of candidates) consumed.add(candidate.containerId);
    if (candidates.length === 0) {
      result.push({ kind: "record-only", record });
    } else if (candidates.length === 1 && recordMatchesContainer(record, candidates[0], input.expectedProject)) {
      result.push({ kind: "matching", record, container: candidates[0] });
    } else if (candidates.length === 1) {
      const identity = unboundAllocatedRecordMatchesCreatedContainer(
        record,
        candidates[0],
        input.expectedProject,
      );
      if (identity) {
        result.push(sealUnboundCreatedClassification(
          record,
          candidates[0],
          identity,
          input.expectedProject,
        ));
      } else {
        result.push({
          kind: "mismatch",
          record,
          containers: candidates,
          reason: "record and live container identity differ",
        });
      }
    } else {
      result.push({
        kind: "mismatch",
        record,
        containers: candidates,
        reason: candidates.length > 1 ? "multiple containers claim one session" : "record and live container identity differ",
      });
    }
  }
  for (const container of input.containers) {
    if (consumed.has(container.containerId)) continue;
    const identity = identities.get(container.containerId);
    if (identity) {
      result.push(sealContainerOnlyClassification(container, identity, input.expectedProject));
    } else if (managedSessionHint(container, input.expectedProject)) {
      result.push({ kind: "untrusted-container", container, reason: "container lacks exact Runfree session identity proof" });
    }
  }
  return result;
}

export function exactSessionContainerCleanupTarget(
  classification: SessionReconciliationClassification,
): string | undefined {
  if (classification.kind === "container-only") return classification.container.containerId;
  if (classification.kind === "matching" && classification.record.state === "revoking") {
    return classification.container.containerId;
  }
  return undefined;
}

export function accountSessionAgentImageReferences(input: {
  expectedProject: SessionContainerProjectIdentity;
  records: readonly SessionContainerRecordV2[];
  containers: readonly SessionContainerSnapshot[];
  desiredSelectedAgentImageId?: string;
  desiredSessionAgentMaterializationDigest?: string;
  inProgressImageIds?: readonly string[];
  inProgressSessionAgentMaterializationDigests?: readonly string[];
}): SessionAgentImageReferenceAccounting {
  const references = new Map<string, Set<string>>();
  const materializationReferences = new Map<string, Set<string>>();
  const uncertainContainerIds = new Set<string>();
  const add = (imageId: string, reference: string): void => {
    sha256(imageId, "session agent image id");
    const current = references.get(imageId) ?? new Set<string>();
    current.add(reference);
    references.set(imageId, current);
  };
  const addMaterialization = (materializationDigest: string, reference: string): void => {
    sha256(materializationDigest, "session agent materialization digest");
    const current = materializationReferences.get(materializationDigest) ?? new Set<string>();
    current.add(reference);
    materializationReferences.set(materializationDigest, current);
  };
  for (const record of input.records) {
    assertSessionContainerRecordProject(record, input.expectedProject);
    add(record.selectedAgentImageId, `record-selected:${record.sessionId}:${record.sessionIncarnation}`);
    addMaterialization(
      record.sessionAgentMaterializationDigest,
      `record-selected:${record.sessionId}:${record.sessionIncarnation}`,
    );
  }
  for (const container of input.containers) {
    const identity = verifiedSessionContainerIdentity(container, input.expectedProject);
    if (identity) {
      add(identity.selectedAgentImageId, `container-selected:${container.containerId}`);
      addMaterialization(identity.sessionAgentMaterializationDigest, `container-selected:${container.containerId}`);
    } else if (managedSessionHint(container, input.expectedProject)) {
      uncertainContainerIds.add(container.containerId);
      // A malformed managed-looking participant blocks image GC. If Docker
      // still reports an exact image ID, retain that concrete image too.
      if (SHA256_PATTERN.test(container.imageId)) add(container.imageId, `uncertain-container:${container.containerId}`);
    }
  }
  if (input.desiredSelectedAgentImageId) add(input.desiredSelectedAgentImageId, "desired-selected-session-generation");
  if (input.desiredSessionAgentMaterializationDigest) {
    addMaterialization(input.desiredSessionAgentMaterializationDigest, "desired-selected-session-generation");
  }
  for (const [index, imageId] of (input.inProgressImageIds ?? []).entries()) add(imageId, `in-progress:${index}`);
  for (const [index, materializationDigest] of (
    input.inProgressSessionAgentMaterializationDigests ?? []
  ).entries()) {
    addMaterialization(materializationDigest, `in-progress:${index}`);
  }
  return {
    images: [...references.entries()]
      .map(([imageId, imageReferences]) => ({ imageId, references: [...imageReferences].sort() }))
      .sort((left, right) => left.imageId.localeCompare(right.imageId)),
    materializations: [...materializationReferences.entries()]
      .map(([materializationDigest, materializationReferenceSet]) => ({
        materializationDigest,
        references: [...materializationReferenceSet].sort(),
      }))
      .sort((left, right) => left.materializationDigest.localeCompare(right.materializationDigest)),
    uncertainContainerIds: [...uncertainContainerIds].sort(),
  };
}

export function unreferencedSessionAgentImageIds(
  candidateImageIds: readonly string[],
  accounting: SessionAgentImageReferenceAccounting,
): string[] {
  if (accounting.uncertainContainerIds.length > 0) return [];
  const referenced = new Set(accounting.images.map((entry) => entry.imageId));
  const candidates = new Set<string>();
  for (const imageId of candidateImageIds) candidates.add(sha256(imageId, "candidate session agent image id"));
  return [...candidates].filter((imageId) => !referenced.has(imageId)).sort();
}

export function unreferencedSessionAgentMaterializationDigests(
  candidateMaterializationDigests: readonly string[],
  accounting: SessionAgentImageReferenceAccounting,
): string[] {
  if (accounting.uncertainContainerIds.length > 0) return [];
  const referenced = new Set(accounting.materializations.map((entry) => entry.materializationDigest));
  const candidates = new Set<string>();
  for (const digest of candidateMaterializationDigests) {
    candidates.add(sha256(digest, "candidate session agent materialization digest"));
  }
  return [...candidates].filter((digest) => !referenced.has(digest)).sort();
}
