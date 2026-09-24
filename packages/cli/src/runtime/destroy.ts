// Fenced project destroy.
//
// `runfree destroy` used to be one Compose invocation, and session containers
// are not Compose resources: `docker compose down --remove-orphans` only covers
// containers labelled for this Compose project, a session container carries no
// Compose label at all, and the lifecycle registry lives under the project's
// XDG state dir which Compose never touches. A destroy that stops at Compose
// therefore leaves session containers running and their records behind — the
// wedge the container-label-taxonomy design's Phase 1 exists to remove.
//
// The sequence here is fenced and ordered; every step exists because the naive
// version has a specific failure:
//
//   1. hold the project lifecycle lock, so no session is admitted or renewed
//      between enumeration and removal
//   2. revoke recorded session authority registry-first, then take the
//      request-proxy and firewall consumers down (the proxy container) before
//      any session container is removed, so an interrupted destroy can never
//      leave live proxy authority over a freed address
//   3. remove session containers by exact record-bound container id — never by
//      the result of a label scan
//   4. Compose teardown of the Compose-owned resources
//   5. scan `io.runfree.project-id` for residue; report unverified candidates,
//      remove them only under --force
//   6. remove the project's lifecycle records only after 2-4 succeeded, so a
//      failed destroy never strands containers with no record to find them by
//
// Steps 3-6 are individually idempotent; a crashed destroy is re-runnable.

import fs from "node:fs";
import path from "node:path";

import { composeProjectName, projectHash } from "../project-identity.ts";
import { warn } from "../warnings.ts";
import { clearEffectiveControlPlaneV2, readEffectiveControlPlaneSelectionV2 } from "./component-state-v2.ts";
import { PROJECT_ID_LABEL } from "./constants.ts";
import {
  controlPlaneRebindTransactionPath,
  discardControlPlaneRebindTransaction,
  readControlPlaneRebindTransaction,
  type ControlPlaneRebindTransaction,
} from "./control-plane-rebind.ts";
import {
  composeProjectContainerFilters,
  wholeProjectContainerFilters,
} from "./container-inventory.ts";
import { dockerClientEnvOptions, type RuntimeDocker } from "./docker.ts";
import {
  enumerateSessionContainerRecordsV2,
  listIllegibleSessionContainerRegistryAsidesV2,
  listQuarantinedSessionContainerRecordNamesV2,
  quarantineIllegibleSessionContainerRegistryV2,
  removeIllegibleSessionContainerRegistryAsidesV2,
  removeExactSessionContainerRecordV2,
  replaceExactSessionContainerRecordV2,
  sessionContainerQuarantineRoot,
  sessionContainerRecordsRoot,
  transitionSessionContainerToRevokingV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordEnumerationV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readProxySessionFiles, type ProxySessionFile } from "./session-reconcile.ts";
import {
  executeSessionFileCommand,
  sessionFileDeleteCommand,
} from "./session-file-publisher.ts";
import { readSessionHostStatus, removeSessionHostStatus } from "./session-host-status.ts";
import { classifySessionRecordLiveness } from "./session-record-liveness.ts";
import { activeOrStartingAgentSessions, sessionWarningLine, type ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { remedy } from "../remedies.ts";

const SESSION_CONTAINER_STOP_SECONDS = 10;
// Bounds a single `docker container stop` argv the same way
// session-container-reconciliation.ts bounds `container inspect` chunks.
const STOP_ID_CHUNK_SIZE = 64;

export type FencedProjectDestroyInput = Readonly<{
  context: RuntimeContext;
  io: RuntimeIO;
  docker: RuntimeDocker;
  lifecycleLock: ProjectLifecycleLock;
  force: boolean;
  operation?: "destroy" | "rebuild";
  /** Runs after the live-session refusal gate and before any teardown effect. */
  beforeTeardown?: () => void;
  /** Read-only ownership proof; removal is deferred until every refusal passes. */
  prepareUtilities?: () => Readonly<{
    claimedContainerIds: readonly string[];
    remove: () => void;
  }>;
  /** Exact empty-network cleanup after the forced container residue sweep. */
  afterForcedResidueTeardown?: () => void;
  nowEpochMs?: () => number;
}>;

export type FencedProjectRebuildTeardownInput = Readonly<Omit<
  FencedProjectDestroyInput,
  "afterForcedResidueTeardown" | "beforeTeardown" | "force" | "operation" | "prepareUtilities"
> & {
  prepareUtilities?: () => Readonly<{
    claimedContainerIds: readonly string[];
    remove: () => void;
  }>;
}>;

type ResidueCandidate = Readonly<{ id: string; description: string }>;

const CONTAINER_NOT_FOUND_PATTERN = /no such (container|object)/i;

function operationName(input: FencedProjectDestroyInput): "destroy" | "rebuild" {
  return input.operation ?? "destroy";
}

/**
 * True only when Docker definitively reports the container gone. Any other
 * inspection failure throws: a daemon hiccup must not read as absence, or the
 * proxy-stop fence and record-bound removal would fail open — removing session
 * containers under a proxy that still holds authority, or discarding a record
 * whose container still exists.
 */
function containerProvenAbsent(input: FencedProjectDestroyInput, containerId: string): boolean {
  const inspected = input.io.capture(
    "docker",
    ["container", "inspect", "--format", "{{.Id}}", containerId],
    dockerClientEnvOptions(input.context),
  );
  if (inspected.status === 0) return false;
  if (CONTAINER_NOT_FOUND_PATTERN.test(inspected.stderr)) return true;
  const detail = inspected.stderr.trim().slice(0, 512) || `exit ${inspected.status}`;
  throw new Error(`Docker could not prove container ${containerId} absent: ${detail}`);
}

/**
 * Removes one exact record-bound session container. Idempotent: a container
 * that is already gone is success, and a failed removal is a failure only
 * while the container still exists.
 */
function removeRecordBoundSessionContainer(input: FencedProjectDestroyInput, containerId: string): void {
  const removed = input.io.capture(
    "docker",
    ["container", "rm", "--force", containerId],
    dockerClientEnvOptions(input.context),
  );
  if (removed.status === 0) return;
  if (containerProvenAbsent(input, containerId)) return;
  const detail = removed.stderr.trim().slice(0, 512) || `exit ${removed.status}`;
  throw new Error(`Docker failed to remove session container ${containerId}: ${detail}`);
}

/**
 * Stops every container that can hold request-proxy/firewall consumer
 * authority before any session container is removed.
 *
 * Candidates come from two independent sources on purpose. Compose-set
 * discovery covers the ordinary runtime, but it rides on `docker ps` and
 * returns nothing on a transient daemon failure — which must not silently
 * skip the fence. The durable effective control plane is host-owned state
 * naming the exact proxy container that session admission converged against,
 * so it survives daemon hiccups and lost Compose metadata; a corrupt durable
 * selection fails the destroy closed rather than proceeding unfenced.
 *
 * Only the selection is read, never the materialization it names: the proxy
 * container id lives in the selection, and a manifest this CLI cannot parse —
 * a control plane materialized before the current admission contract — must
 * not take the fence's durable evidence away with it, or the one command that
 * clears that state could never run.
 */
function resolveProxyConsumerIds(
  input: FencedProjectDestroyInput,
  project: string | undefined,
): readonly string[] {
  const candidates = new Set<string>();
  if (project) {
    const composeProxyId = input.docker.serviceContainerId(project, "proxy");
    if (composeProxyId) candidates.add(composeProxyId);
  }
  let durable: ReturnType<typeof readEffectiveControlPlaneSelectionV2>;
  try {
    durable = readEffectiveControlPlaneSelectionV2(input.context.project.paths.stateDir);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `${operationName(input)} refused to remove session containers while the durable control plane cannot name its proxy consumer: ${detail}`,
    );
  }
  if (durable) candidates.add(durable.proxyContainerId);
  return Object.freeze([...candidates]);
}

function stopProxyConsumers(input: FencedProjectDestroyInput, proxyConsumerIds: readonly string[]): void {
  for (const proxyId of proxyConsumerIds) {
    const stopped = input.io.capture(
      "docker",
      ["container", "stop", "--time", String(SESSION_CONTAINER_STOP_SECONDS), proxyId],
      dockerClientEnvOptions(input.context),
    );
    if (stopped.status === 0) continue;
    if (containerProvenAbsent(input, proxyId)) continue;
    const detail = stopped.stderr.trim().slice(0, 512) || `exit ${stopped.status}`;
    throw new Error(
      `${operationName(input)} refused to remove session containers while the proxy could not be stopped (${proxyId}): ${detail}`,
    );
  }
}

/**
 * Whether any Compose-owned resource still exists for the project. Container
 * discovery alone can be empty while networks, volumes, or stopped remnants
 * survive, and a destroy that skipped Compose teardown on that basis would
 * report success while retaining the project's persistent data. A listing
 * failure throws rather than reading as "nothing left".
 */
function composeResourcesPresent(input: FencedProjectDestroyInput, composeProject: string): boolean {
  const filters = composeProjectContainerFilters(composeProject);
  const listings: ReadonlyArray<readonly string[]> = [
    ["ps", "-aq", ...filters],
    ["network", "ls", "-q", ...filters],
    ["volume", "ls", "-q", ...filters],
    // Compose labels the images it builds; `down --rmi local` is the only
    // remover for those, so image-only residue still needs the teardown.
    ["image", "ls", "-q", ...filters],
  ];
  for (const args of listings) {
    const listed = input.io.capture("docker", [...args], dockerClientEnvOptions(input.context));
    if (listed.status !== 0) {
      const detail = listed.stderr.trim().slice(0, 512) || `exit ${listed.status}`;
      throw new Error(`destroy could not determine whether Compose resources remain: ${detail}`);
    }
    if (listed.stdout.trim() !== "") return true;
  }
  return false;
}

const COMPOSE_PROJECT_LABEL = "com.docker.compose.project";

/**
 * Running containers that carry this project's label but that neither a
 * lifecycle record nor Compose claims. Their liveness is unknowable — a crash
 * can orphan a live session's container — so plain destroy refuses before any
 * teardown effect rather than stopping them; only --force proceeds through
 * the stop-and-sweep path. The one bounded retry covers a container that
 * exits between the listing and its inspection.
 */
function unclaimedProjectContainers(
  input: FencedProjectDestroyInput,
  recordContainerIds: ReadonlySet<string>,
  composeProjects: ReadonlySet<string>,
  includeStopped: boolean,
): string[] {
  const projectId = projectHash(input.context.projectRoot);
  let lastDetail = "";
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const listed = input.io.capture(
      "docker",
      ["ps", includeStopped ? "-aq" : "-q", "--no-trunc", ...wholeProjectContainerFilters(projectId)],
      dockerClientEnvOptions(input.context),
    );
    if (listed.status !== 0) {
      const detail = listed.stderr.trim().slice(0, 512) || `exit ${listed.status}`;
      throw new Error(`${operationName(input)} could not list project containers: ${detail}`);
    }
    const ids = listed.stdout.trim().split(/\s+/).filter(Boolean)
      .filter((id) => !recordContainerIds.has(id));
    if (ids.length === 0) return [];
    const inspected = input.io.capture(
      "docker",
      ["container", "inspect", "--format", `{{.Id}}\t{{ index .Config.Labels "${COMPOSE_PROJECT_LABEL}" }}`, ...ids],
      dockerClientEnvOptions(input.context),
    );
    if (inspected.status !== 0) {
      lastDetail = inspected.stderr.trim().slice(0, 512) || `exit ${inspected.status}`;
      if (CONTAINER_NOT_FOUND_PATTERN.test(inspected.stderr)) continue;
      throw new Error(`${operationName(input)} could not classify project containers: ${lastDetail}`);
    }
    const unclaimed: string[] = [];
    for (const line of inspected.stdout.trim().split(/\n+/).filter(Boolean)) {
      const [id, composeLabel = ""] = line.split("\t");
      if (id === undefined || id === "") continue;
      const value = composeLabel.trim();
      if (value === "" || value === "<no value>" || !composeProjects.has(value)) unclaimed.push(id);
    }
    return unclaimed;
  }
  throw new Error(`${operationName(input)} could not classify project containers: ${lastDetail}`);
}

function runningUnclaimedProjectContainers(
  input: FencedProjectDestroyInput,
  recordContainerIds: ReadonlySet<string>,
  composeProjects: ReadonlySet<string>,
): string[] {
  return unclaimedProjectContainers(input, recordContainerIds, composeProjects, false);
}

/**
 * Stops every container still carrying this project's label before any
 * address-freeing removal. The Compose-set and durable-plane fences cover the
 * proxies destroy can name, but a stale project container from an earlier
 * generation is in neither set and may still hold consumer authority.
 * Stopping is deliberately the only action taken from this label scan: a
 * label never authorizes removal (that stays record-bound, or behind the
 * explicit --force residue pass), but a stopped container holds no live
 * authority while addresses are freed. Plain destroy only reaches this after
 * refusing on running unclaimed containers, so without --force this stops
 * nothing that a record or Compose does not claim.
 */
function stopProjectLabeledContainers(input: FencedProjectDestroyInput): void {
  const projectId = projectHash(input.context.projectRoot);
  const listed = input.io.capture(
    "docker",
    ["ps", "-q", "--no-trunc", ...wholeProjectContainerFilters(projectId)],
    dockerClientEnvOptions(input.context),
  );
  if (listed.status !== 0) {
    const detail = listed.stderr.trim().slice(0, 512) || `exit ${listed.status}`;
    throw new Error(`${operationName(input)} could not list running project containers before session removal: ${detail}`);
  }
  const running = listed.stdout.trim().split(/\s+/).filter(Boolean);
  if (running.length === 0) return;
  // Chunked batches: within a chunk, the Docker CLI issues the per-id stops
  // concurrently, so N live sessions share one grace period instead of
  // paying for N sequential ones. Chunking bounds a single call's argv the
  // same way container-inspect chunking does. On a chunk failure, fall back
  // to exact per-container stops for that chunk's ids so each failure is
  // attributed and proven exactly as before.
  for (let offset = 0; offset < running.length; offset += STOP_ID_CHUNK_SIZE) {
    const chunk = running.slice(offset, offset + STOP_ID_CHUNK_SIZE);
    const batch = input.io.capture(
      "docker",
      ["container", "stop", "--time", String(SESSION_CONTAINER_STOP_SECONDS), ...chunk],
      dockerClientEnvOptions(input.context),
    );
    if (batch.status === 0) continue;
    for (const containerId of chunk) {
      const stopped = input.io.capture(
        "docker",
        ["container", "stop", "--time", String(SESSION_CONTAINER_STOP_SECONDS), containerId],
        dockerClientEnvOptions(input.context),
      );
      if (stopped.status === 0) continue;
      if (containerProvenAbsent(input, containerId)) continue;
      const detail = stopped.stderr.trim().slice(0, 512) || `exit ${stopped.status}`;
      throw new Error(
        `${operationName(input)} refused to remove session containers while a project container could not be stopped (${containerId}): ${detail}`,
      );
    }
  }
}

function projectResidueCandidates(input: FencedProjectDestroyInput): ResidueCandidate[] {
  const projectId = projectHash(input.context.projectRoot);
  const listed = input.io.capture(
    "docker",
    ["ps", "-aq", "--no-trunc", ...wholeProjectContainerFilters(projectId)],
    dockerClientEnvOptions(input.context),
  );
  if (listed.status !== 0) {
    const detail = listed.stderr.trim().slice(0, 512) || `exit ${listed.status}`;
    throw new Error(`destroy could not scan for project residue: ${detail}`);
  }
  const ids = listed.stdout.trim().split(/\s+/).filter(Boolean);
  return ids.map((id) => {
    const inspected = input.io.capture(
      "docker",
      ["container", "inspect", "--format", "{{.Name}}\t{{.Config.Image}}\t{{.State.Status}}", id],
      dockerClientEnvOptions(input.context),
    );
    const description = inspected.status === 0
      ? inspected.stdout.trim().split("\t").filter(Boolean).join(" ")
      : "inspection failed";
    return Object.freeze({ id, description });
  });
}

function refuseLiveWork(
  input: FencedProjectDestroyInput,
  liveRecords: readonly SessionContainerRecordV2[],
): number | undefined {
  // Never gated on Compose discovery: the inventory derives its Compose name
  // deterministically from the project root, and its starting-session half
  // reads host metadata plus host process liveness with no Docker involved,
  // so a flaky daemon cannot silently empty the live-session gate.
  const agentSessions = activeOrStartingAgentSessions(input.context, input.docker);
  if (input.force || (liveRecords.length === 0 && agentSessions.length === 0)) return undefined;
  const lifecycleSessionIds = new Set(liveRecords.map((record) => record.sessionId));
  console.error("destroy refused: it would end live sessions:");
  for (const record of liveRecords) {
    console.error(
      `  session ${record.sessionId} (${record.displayName}): ${record.command}, state ${record.state}, host pid ${record.hostPid}`,
    );
  }
  for (const session of agentSessions) {
    if (session.sessionId === undefined || !lifecycleSessionIds.has(session.sessionId)) {
      console.error(`  ${sessionWarningLine(session)}`);
    }
  }
  console.error(`re-run \`${remedy.destroyForce()}\` to end them`);
  return 1;
}

function reportResidue(residue: readonly ResidueCandidate[], force: boolean): void {
  console.error(`destroy left ${residue.length} container(s) carrying this project's ${PROJECT_ID_LABEL} label that no record claims:`);
  for (const candidate of residue) console.error(`  ${candidate.id.slice(0, 12)} ${candidate.description}`);
  console.error(force
    ? "removal failed; inspect and remove them manually"
    : `re-run \`${remedy.destroyForce()}\` to remove them`);
}

type ValidatedLifecycleJournals = Readonly<{
  rebind?: ControlPlaneRebindTransaction;
}>;

function lifecycleJournalRecords(journals: ValidatedLifecycleJournals): readonly SessionContainerRecordV2[] {
  return Object.freeze([
    ...(journals.rebind ? [
      ...journals.rebind.oldRecords,
      ...journals.rebind.replacementRecords,
    ] : []),
  ]);
}

function lifecycleJournalContainerIds(journals: ValidatedLifecycleJournals): readonly string[] {
  return Object.freeze([
    ...new Set(lifecycleJournalRecords(journals).flatMap((record) => record.containerId ? [record.containerId] : [])),
  ]);
}

function readValidatedLifecycleJournals(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
): ValidatedLifecycleJournals {
  const rebind = readControlPlaneRebindTransaction(stateDir, expectedProject);
  return Object.freeze({
    ...(rebind === undefined ? {} : { rebind }),
  });
}

/** The proxy the durable selection names, or nothing when it cannot be read. */
function durableProxyId(input: FencedProjectDestroyInput): string | undefined {
  try {
    return readEffectiveControlPlaneSelectionV2(input.context.project.paths.stateDir)?.proxyContainerId;
  } catch {
    // Unreadable durable state names no proxy; `resolveProxyConsumerIds` is
    // where that refuses the teardown, and it has already run.
    return undefined;
  }
}

/**
 * Deletes this project's session files from the proxy, while it is still
 * running to answer.
 *
 * Invariant 3: a file is the whole of a session's authority under this source,
 * so it goes before the record that reserves its address — a record removed
 * first would free an address the proxy is still serving. Runs after the
 * registry is durably revoking and before the proxy is stopped, so an
 * interrupted destroy never leaves a file authorizing egress for a record that
 * no longer authorizes anything.
 *
 * Best effort by construction. A proxy that cannot answer at all holds no
 * files: the session directory is a tmpfs that dies with the container, so a
 * stopped or already-removed proxy has nothing to delete and the pass moves on
 * silently. A proxy that listed its files and then refused to delete one is a
 * different thing and is named, because the next step removes the container it
 * lives in and no later pass can report it.
 */
function removeProjectSessionFiles(input: FencedProjectDestroyInput, proxyId: string | undefined): void {
  if (proxyId === undefined) return;
  const dockerOptions = dockerClientEnvOptions(input.context);
  input.lifecycleLock.assertHeld();
  let files: readonly ProxySessionFile[];
  try {
    files = readProxySessionFiles({ io: input.io, proxyId, dockerOptions });
  } catch {
    return;
  }
  for (const file of files) {
    // A `.json` whose stem is not a session key cannot be named by the pinned
    // command's basename rule; the proxy's own scanner drops it, and the
    // container is removed moments from now.
    if (file.sessionKey === undefined) continue;
    input.lifecycleLock.assertHeld();
    try {
      executeSessionFileCommand(input.io, sessionFileDeleteCommand(proxyId, file.sessionKey), dockerOptions);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      warn(`the proxy refused to remove session file ${file.name} before teardown: ${detail}`);
    }
  }
}

function removeValidatedLifecycleState(
  input: FencedProjectDestroyInput,
  expectedProject: SessionContainerProjectIdentity,
  records: readonly SessionContainerRecordV2[],
  journals: ValidatedLifecycleJournals,
): void {
  const stateDir = input.context.project.paths.stateDir;
  input.lifecycleLock.assertHeld();
  // Docker and Compose teardown proved that the selected live control plane no
  // longer exists. Remove that stale authority first. The journal remains as an
  // explicit recovery blocker until the selection removal is durable, and the
  // revoking records remain as exact container evidence until it is gone. A
  // crash after any step can therefore retry rebuild without making normal
  // startup treat partial cleanup as current state.
  clearEffectiveControlPlaneV2(stateDir);
  input.lifecycleLock.assertHeld();
  if (journals.rebind) {
    discardControlPlaneRebindTransaction(stateDir, journals.rebind);
  } else if (readControlPlaneRebindTransaction(stateDir, expectedProject) !== undefined) {
    throw new Error("control-plane rebind transaction appeared during rebuild teardown");
  }
  fsyncExistingLifecycleJournalParent(stateDir, controlPlaneRebindTransactionPath(stateDir));
  // Stamps before records, for the same reason files come before both: a stamp
  // that outlived its record would make the next launch's liveness read answer
  // about a session that no longer exists.
  for (const record of records) removeSessionHostStatus(stateDir, record.sessionId);
  for (const record of records) {
    input.lifecycleLock.assertHeld();
    removeExactSessionContainerRecordV2(stateDir, expectedProject, record);
  }
  removeSessionContainerRecordsRootDurably(stateDir);
}

function removeSessionContainerRecordsRootDurably(stateDir: string): void {
  const recordsRoot = sessionContainerRecordsRoot(stateDir);
  fs.rmSync(recordsRoot, { recursive: true, force: true });
  fsyncExistingLifecycleJournalParent(stateDir, recordsRoot);
}

function assertLifecycleJournalParentSafe(stateDir: string, journalPath: string): void {
  const resolvedStateDir = path.resolve(stateDir);
  const resolvedJournalPath = path.resolve(journalPath);
  const relative = path.relative(resolvedStateDir, resolvedJournalPath);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("lifecycle journal path escapes the project state directory");
  }
  let current = resolvedStateDir;
  for (const segment of ["", ...relative.split(path.sep).slice(0, -1)]) {
    if (segment !== "") current = path.join(current, segment);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
      throw error;
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`lifecycle journal parent is not a safe directory: ${current}`);
    }
  }
}

function fsyncExistingLifecycleJournalParent(stateDir: string, journalPath: string): void {
  const resolvedJournalPath = path.resolve(journalPath);
  assertLifecycleJournalParentSafe(stateDir, resolvedJournalPath);
  const parent = path.dirname(resolvedJournalPath);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(parent);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`lifecycle journal parent is not a safe directory: ${parent}`);
  }
  const descriptor = fs.openSync(parent, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function forceRemoveLifecycleJournalPath(stateDir: string, journalPath: string): void {
  const resolvedJournalPath = path.resolve(journalPath);
  assertLifecycleJournalParentSafe(stateDir, resolvedJournalPath);
  fs.rmSync(resolvedJournalPath, { recursive: true, force: true });
  fsyncExistingLifecycleJournalParent(stateDir, resolvedJournalPath);
}

function assertForcedLifecycleJournalCleanupSafe(stateDir: string): void {
  assertLifecycleJournalParentSafe(stateDir, controlPlaneRebindTransactionPath(stateDir));
}

function removeForcedLifecycleState(
  input: FencedProjectDestroyInput,
  expectedProject: SessionContainerProjectIdentity,
  records: readonly SessionContainerRecordV2[],
): void {
  const stateDir = input.context.project.paths.stateDir;
  input.lifecycleLock.assertHeld();
  clearEffectiveControlPlaneV2(stateDir);
  forceRemoveLifecycleJournalPath(stateDir, controlPlaneRebindTransactionPath(stateDir));
  for (const record of records) removeSessionHostStatus(stateDir, record.sessionId);
  for (const record of records) {
    input.lifecycleLock.assertHeld();
    removeExactSessionContainerRecordV2(stateDir, expectedProject, record);
  }
  removeSessionContainerRecordsRootDurably(stateDir);
}

/**
 * Drains direct session containers during an operator-approved rebuild.
 *
 * Session containers are not Compose resources, and their durable admission
 * transaction prevents a newly recreated deny-all proxy from becoming the
 * selected control plane. Rebuild therefore performs the same security
 * ordering as destroy while preserving Compose volumes and local images:
 * records become revoking, every possible proxy consumer stops, exact
 * record-bound containers are removed, Compose goes down, and only then are
 * lifecycle records and the admission journal removed.
 *
 * The caller owns rebuild confirmation and must hold the project lifecycle
 * lock. Unreadable or unclaimed state is never forced through this path;
 * `destroy --force` remains the explicit remedy for evidence Runfree cannot
 * bind to an exact record.
 */
export function runFencedProjectRebuildTeardown(input: FencedProjectRebuildTeardownInput): number {
  const teardownInput: FencedProjectDestroyInput = Object.freeze({
    ...input,
    force: false,
    operation: "rebuild",
  });
  const { context, docker, lifecycleLock } = teardownInput;
  lifecycleLock.assertHeld();
  const stateDir = context.project.paths.stateDir;
  const expectedProject: SessionContainerProjectIdentity = {
    projectId: projectHash(context.projectRoot),
    composeProject: composeProjectName(context.projectRoot),
  };

  let enumeration: SessionContainerRecordEnumerationV2;
  try {
    enumeration = enumerateSessionContainerRecordsV2(stateDir, expectedProject);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`rebuild refused: the session lifecycle registry cannot be enumerated: ${detail}`);
    console.error(`run \`${remedy.destroyForce()}\` to clear unreadable lifecycle evidence`);
    return 1;
  }
  for (const entry of enumeration.quarantined) {
    warn(`quarantined unreadable session lifecycle record ${entry.fileName}: ${entry.reason}`);
  }
  let quarantined: string[];
  try {
    quarantined = [...new Set([
      ...enumeration.quarantined.map((entry) => entry.fileName),
      ...listQuarantinedSessionContainerRecordNamesV2(stateDir),
      ...listIllegibleSessionContainerRegistryAsidesV2(stateDir),
    ])].sort();
  } catch {
    console.error("rebuild refused: the session lifecycle quarantine is unreadable");
    console.error(`run \`${remedy.destroyForce()}\` to clear unreadable lifecycle evidence`);
    return 1;
  }
  if (quarantined.length > 0) {
    console.error(`rebuild refused: ${quarantined.length} unreadable session lifecycle item(s) require explicit removal:`);
    for (const name of quarantined) console.error(`  ${name}`);
    console.error(`run \`${remedy.destroyForce()}\` to clear unreadable lifecycle evidence`);
    return 1;
  }

  let journals: ValidatedLifecycleJournals;
  try {
    journals = readValidatedLifecycleJournals(stateDir, expectedProject);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`rebuild refused: pending lifecycle journal evidence is unreadable: ${detail}`);
    console.error(`run \`${remedy.destroyForce()}\` to clear unreadable lifecycle evidence`);
    return 1;
  }

  // Runtime-owned utilities are neither Compose services nor direct session
  // containers. Prove their exact identities without effects, then count only
  // those IDs as claimed during the refusal gate. Removal starts only after
  // every refusal has passed, so a refused rebuild leaves the runtime intact.
  const utilities = input.prepareUtilities?.() ?? Object.freeze({
    claimedContainerIds: Object.freeze([]),
    remove: () => {},
  });

  const project = docker.projectForWorkspace();
  const journalContainerIds = lifecycleJournalContainerIds(journals);
  const recordContainerIds = new Set(
    [
      ...enumeration.records.map((record) => record.containerId).filter((id): id is string => id !== undefined),
      ...journalContainerIds,
      ...utilities.claimedContainerIds,
    ],
  );
  const unclaimed = unclaimedProjectContainers(
    teardownInput,
    recordContainerIds,
    new Set([expectedProject.composeProject, ...(project === undefined ? [] : [project])]),
    true,
  );
  if (unclaimed.length > 0) {
    console.error(`rebuild refused: ${unclaimed.length} project container(s) have no lifecycle or Compose owner:`);
    for (const id of unclaimed) console.error(`  ${id.slice(0, 12)}`);
    console.error(`run \`${remedy.destroyForce()}\` to inspect and remove unclaimed project residue`);
    return 1;
  }

  // Resolve every proxy consumer while this is still a read-only preflight.
  // An unsafe durable selection must refuse before utilities or lifecycle
  // records are changed.
  const proxyConsumerIds = resolveProxyConsumerIds(teardownInput, project);

  utilities.remove();

  const revoking: SessionContainerRecordV2[] = [];
  for (const record of enumeration.records) {
    if (record.state === "revoking") {
      revoking.push(record);
      continue;
    }
    const next = transitionSessionContainerToRevokingV2(record);
    lifecycleLock.assertHeld();
    replaceExactSessionContainerRecordV2(stateDir, expectedProject, record, next);
    revoking.push(next);
  }

  removeProjectSessionFiles(teardownInput, durableProxyId(teardownInput));
  stopProxyConsumers(teardownInput, proxyConsumerIds);
  stopProjectLabeledContainers(teardownInput);

  const removalFailures: unknown[] = [];
  const exactSessionContainerIds = new Set([
    ...revoking.flatMap((record) => record.containerId ? [record.containerId] : []),
    ...journalContainerIds,
  ]);
  for (const containerId of exactSessionContainerIds) {
    try {
      removeRecordBoundSessionContainer(teardownInput, containerId);
    } catch (error) {
      removalFailures.push(error);
    }
  }
  if (removalFailures.length > 0) {
    for (const failure of removalFailures) {
      console.error(`  ${failure instanceof Error ? failure.message : String(failure)}`);
    }
    console.error("rebuild did not remove every recorded or journal-held session container; lifecycle evidence was kept");
    return 1;
  }

  const composeStatus = docker.composeDown(project ?? expectedProject.composeProject);
  if (composeStatus !== 0) {
    console.error("rebuild did not complete the Compose teardown; lifecycle records were kept");
    return composeStatus;
  }

  removeValidatedLifecycleState(teardownInput, expectedProject, revoking, journals);
  return 0;
}

export function runFencedProjectDestroy(input: FencedProjectDestroyInput): number {
  const { context, docker, lifecycleLock } = input;
  lifecycleLock.assertHeld();
  const stateDir = context.project.paths.stateDir;
  const expectedProject: SessionContainerProjectIdentity = {
    projectId: projectHash(context.projectRoot),
    composeProject: composeProjectName(context.projectRoot),
  };
  // `--force` may remove an unreadable exact journal path after teardown. Prove
  // now that its parent tree is safe, before registry quarantine or any Docker
  // effect. Revalidate at removal to close a later replacement race.
  if (input.force) {
    try {
      assertForcedLifecycleJournalCleanupSafe(stateDir);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.error(`destroy refused before teardown: forced lifecycle journal cleanup is unsafe: ${detail}`);
      return 1;
    }
  }

  // Enumeration is total: an unreadable record is quarantined and named, and
  // never blocks the readable rest from being destroyed. The scan itself can
  // still fail structurally (an over-limit registry, an unsafe records root),
  // and destroy is the remedy for exactly that state — so a failed scan
  // refuses plain destroy but must not wedge --force, which proceeds with an
  // empty readable registry and relies on the project-label sweep.
  let enumeration: SessionContainerRecordEnumerationV2;
  try {
    enumeration = enumerateSessionContainerRecordsV2(stateDir, expectedProject);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (!input.force) {
      console.error(`destroy refused: the session lifecycle registry cannot be enumerated: ${detail}`);
      console.error(`re-run \`${remedy.destroyForce()}\` to proceed`);
      return 1;
    }
    // A transient host error (a coded errno) describes the machine, not the
    // registry: retrying is the remedy, and moving the registry aside for it
    // would discard valid records. Only this module's own scan failures — an
    // over-limit registry — reach the recovery below.
    if (error instanceof Error && "code" in error) throw error;
    // Registry-first even when illegible: records that cannot be enumerated
    // cannot be marked revoking one by one, so the whole records root is
    // moved aside atomically before any Docker effect. No reader treats the
    // moved directory as the registry, so an interrupted destroy leaves no
    // durable authorizing record behind, and the bytes survive as evidence.
    // The move re-validates the tree, so a structural safe-path failure stays
    // fatal even under --force, and the aside is rediscovered by name pattern
    // so an interruption after the rename stays recoverable.
    quarantineIllegibleSessionContainerRegistryV2(stateDir);
    warn(`session lifecycle registry cannot be enumerated (${detail}); moved it aside and proceeding with the project-label sweep`);
    enumeration = Object.freeze({ records: Object.freeze([]), quarantined: Object.freeze([]) });
  }
  for (const entry of enumeration.quarantined) {
    warn(`quarantined unreadable session lifecycle record ${entry.fileName}: ${entry.reason}`);
  }

  // A quarantined record's liveness is unknowable — it may represent a live
  // session, which is exactly what plain destroy refuses to end. Fail closed
  // before any teardown effect unless --force was given. Destroy is the
  // documented remedy for quarantine state, so an unreadable quarantine path
  // (for example, an obstructing regular file) must not wedge it: plain
  // destroy refuses on it, and --force clears it with the rest.
  let quarantineListing: string[] | undefined;
  try {
    quarantineListing = listQuarantinedSessionContainerRecordNamesV2(stateDir);
  } catch {
    quarantineListing = undefined;
  }
  const registryAsides = listIllegibleSessionContainerRegistryAsidesV2(stateDir);
  const quarantinedNames = [...new Set([
    ...enumeration.quarantined.map((entry) => entry.fileName),
    ...(quarantineListing ?? []),
    ...registryAsides,
  ])].sort();
  if (!input.force && (quarantinedNames.length > 0 || quarantineListing === undefined)) {
    console.error(
      quarantineListing === undefined && quarantinedNames.length === 0
        ? "destroy refused: the session-record quarantine path is unreadable and may hide records of live sessions"
        : `destroy refused: ${quarantinedNames.length} quarantined unreadable lifecycle record(s) may represent live sessions:`,
    );
    for (const name of quarantinedNames) console.error(`  ${name}`);
    console.error(`re-run \`${remedy.destroyForce()}\` to proceed`);
    return 1;
  }

  let journals: ValidatedLifecycleJournals | undefined;
  let forceUnreadableJournals = false;
  try {
    journals = readValidatedLifecycleJournals(stateDir, expectedProject);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (!input.force) {
      console.error(`destroy refused: pending lifecycle journal evidence is unreadable: ${detail}`);
      console.error(`re-run \`${remedy.destroyForce()}\` to proceed`);
      return 1;
    }
    warn(`pending lifecycle journal evidence is unreadable (${detail}); --force will remove the exact journal paths after teardown`);
    forceUnreadableJournals = true;
  }

  const utilities = input.force
    ? Object.freeze({ claimedContainerIds: Object.freeze([]), remove: () => {} })
    : input.prepareUtilities?.() ?? Object.freeze({
      claimedContainerIds: Object.freeze([]),
      remove: () => {},
    });
  const nowEpochMs = (input.nowEpochMs ?? Date.now)();
  const liveRecords = [...new Map(
    [
      ...enumeration.records,
      ...(journals ? lifecycleJournalRecords(journals) : []),
    ]
      .filter((record) => {
        if (record.state === "revoking") return false;
        const stamp = readSessionHostStatus(stateDir, record.sessionId);
        // A session teardown never transitions the record —
        // `session-file-teardown.ts` leaves it exactly as it was and marks it
        // with this stamp instead. This exclusion narrows only destroy's
        // record gate. The independent session-listing gate still protects
        // alive or unknown owners. A terminal stamp is not death evidence;
        // explicit --force can reclaim uncertain teardown residue.
        if (stamp?.terminal === "revoking") return false;
        return classifySessionRecordLiveness(record, {
          nowEpochMs,
          env: context.env,
          stamp,
        }).kind === "live";
      })
      .map((record) => [record.sessionId, record] as const),
  ).values()];
  const project = docker.projectForWorkspace();
  const journalContainerIds = journals ? lifecycleJournalContainerIds(journals) : Object.freeze([]);
  if (!input.force) {
    // A running container that neither a record nor Compose claims may be a
    // live session whose record was lost. Plain destroy promises to only
    // report such residue, so it must refuse here — before any effect, not
    // after having stopped it.
    const unclaimed = runningUnclaimedProjectContainers(
      input,
      new Set([
        ...enumeration.records.map((record) => record.containerId).filter((id): id is string => id !== undefined),
        ...journalContainerIds,
        ...utilities.claimedContainerIds,
      ]),
      new Set([expectedProject.composeProject, ...(project === undefined ? [] : [project])]),
    );
    if (unclaimed.length > 0) {
      console.error(`destroy refused: ${unclaimed.length} running container(s) carry this project's label but no record or Compose claim:`);
      for (const id of unclaimed) console.error(`  ${id.slice(0, 12)}`);
      console.error(`re-run \`${remedy.destroyForce()}\` to stop and remove them`);
      return 1;
    }
  }
  const refusal = refuseLiveWork(input, liveRecords);
  if (refusal !== undefined) return refusal;

  // Keep malformed or unsafe durable control-plane evidence on the read-only
  // side of the teardown boundary. The lifecycle lock makes this exact proof
  // stable for the consumer-stop step below.
  const proxyConsumerIds = resolveProxyConsumerIds(input, project);

  input.beforeTeardown?.();
  utilities.remove();

  // Registry first: every record becomes durably non-authorizing before any
  // Docker effect, so a destroy interrupted at any later point is inert.
  const revoking: SessionContainerRecordV2[] = [];
  for (const record of enumeration.records) {
    if (record.state === "revoking") {
      revoking.push(record);
      continue;
    }
    const next = transitionSessionContainerToRevokingV2(record);
    lifecycleLock.assertHeld();
    replaceExactSessionContainerRecordV2(stateDir, expectedProject, record, next);
    revoking.push(next);
  }

  // Session files next, while the proxy is still running to answer: they are
  // the authority the records above just stopped carrying, and they must be
  // gone before any record is removed.
  removeProjectSessionFiles(input, durableProxyId(input));

  // Consumers second: the request-proxy and firewall consumers live in the
  // proxy container, so it stops before any session container is removed —
  // and so does every other container still claiming this project's label,
  // in case a stale generation left a consumer that neither Compose-set nor
  // durable-plane discovery can name.
  stopProxyConsumers(input, proxyConsumerIds);
  stopProjectLabeledContainers(input);

  // Session containers by exact registry- or journal-bound id (never from a
  // label scan). A transaction can durably own a candidate before the
  // registry replacement, so its validated ID remains removal authority.
  const removalFailures: unknown[] = [];
  const exactSessionContainerIds = new Set([
    ...revoking.flatMap((record) => record.containerId ? [record.containerId] : []),
    ...journalContainerIds,
  ]);
  for (const containerId of exactSessionContainerIds) {
    try {
      removeRecordBoundSessionContainer(input, containerId);
    } catch (error) {
      removalFailures.push(error);
    }
  }
  if (removalFailures.length > 0) {
    for (const failure of removalFailures) {
      console.error(`  ${failure instanceof Error ? failure.message : String(failure)}`);
    }
    console.error(`destroy did not remove every recorded or journal-held session container; lifecycle evidence was kept - re-run \`${remedy.destroy()}\``);
    return 1;
  }

  // Compose-owned teardown, unchanged in meaning: containers, networks,
  // volumes, and local images that Compose created. It is not gated on
  // container discovery alone — networks and volumes can outlive every
  // container, so the deterministic Compose identity decides when discovery
  // finds nothing. A failure here does not return yet: an unclaimed container
  // still attached to the internal network makes network removal fail, and
  // only the --force residue pass below can clear it — so the Compose
  // teardown gets one retry after that pass.
  const composeProject = project ?? expectedProject.composeProject;
  const composeTeardownNeeded = project !== undefined || composeResourcesPresent(input, composeProject);
  let composeStatus = 0;
  if (composeTeardownNeeded) composeStatus = docker.destroyProject(composeProject);

  // Residue: whatever still carries this project's id is claimed by no record
  // and was created by no path destroy recognises. Report it; remove it only
  // under --force, naming exactly what is removed.
  let residue = projectResidueCandidates(input);
  if (residue.length > 0 && input.force) {
    for (const candidate of residue) {
      console.log(`removing unverified project residue ${candidate.id.slice(0, 12)} (${candidate.description})`);
      const removed = input.io.capture(
        "docker",
        ["container", "rm", "--force", candidate.id],
        dockerClientEnvOptions(context),
      );
      if (removed.status !== 0) {
        let absent = false;
        try {
          absent = containerProvenAbsent(input, candidate.id);
        } catch {
          // An unprovable state is reported as a failed removal below.
        }
        if (!absent) {
          console.error(`  failed: ${removed.stderr.trim().slice(0, 512) || `exit ${removed.status}`}`);
        }
      }
    }
    residue = projectResidueCandidates(input);
  }
  if (input.force) input.afterForcedResidueTeardown?.();

  if (composeStatus !== 0 && input.force) {
    composeStatus = docker.destroyProject(composeProject);
  }
  if (composeStatus !== 0) {
    console.error(`destroy did not complete the Compose teardown; lifecycle records were kept - re-run \`${remedy.destroy()}\``);
    if (residue.length > 0) reportResidue(residue, input.force);
    return composeStatus;
  }

  // Records last, only after revocation, session removal, and Compose teardown
  // all succeeded. Residue never blocks this: the records claim none of it,
  // and deleting the registry before the effects it authorizes is the one
  // ordering this sequence exists to forbid.
  if (forceUnreadableJournals) {
    removeForcedLifecycleState(input, expectedProject, revoking);
  } else {
    removeValidatedLifecycleState(input, expectedProject, revoking, journals ?? Object.freeze({}));
  }

  if (residue.length > 0) {
    reportResidue(residue, input.force);
    return 1;
  }

  // Plain destroy refused above whenever quarantine was non-empty, so only
  // --force reaches this point with quarantined evidence to clear.
  if (input.force) {
    fs.rmSync(sessionContainerQuarantineRoot(stateDir), { recursive: true, force: true });
    // Swept by pattern rather than by this invocation's memory, so asides
    // left by an interrupted earlier destroy are cleared too.
    removeIllegibleSessionContainerRegistryAsidesV2(stateDir);
  }

  console.log("destroyed");
  return 0;
}
