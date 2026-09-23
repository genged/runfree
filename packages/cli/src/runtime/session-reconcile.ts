// Making the three lists agree, before an address is handed out.
//
// A project's session state lives in three places that can disagree after a
// crash: the proxy's session files (the only
// thing that grants a session anything), the host's lifecycle records (the only
// thing that reserves a session's address), and Docker's session containers
// (the only thing that can still send packets). Every launch, and every
// `runfree up`, reconciles them in one pass while the project lifecycle lock is
// held, and only then may an address be allocated.
//
// The order is the whole design:
//
//   1. Files with no record are deleted. A file is authority, and authority no
//      record accounts for is authority nothing will ever take away. The one
//      exception is a partially legible registry: while a quarantined record
//      exists, "no record accounts for it" cannot be decided, so unclaimed
//      files are kept and reported instead.
//   2. Records whose owning host process is gone are torn down through the
//      shared ordered teardown — file first, record last.
//   3. Containers with no record are stopped and removed. By now every record
//      that should have gone is gone, so what is left claims nothing.
//   4. Records whose owner cannot be proved either way are reported and left
//      exactly as they are. An unprovable owner may be a running session, and
//      destroying one is far worse than carrying residue to the next launch.
//   5. Eligibility is recomputed from the records that survived and published
//      when it changed — the narrowing half of invariant 9, and the widening
//      half for a launch whose agent generation is newer than the last one.
//
// Two properties matter more than the steps themselves.
//
// **The read is the only view.** `servedSetReadCommand` is how this module
// learns what the proxy holds, so a read it could not make is not "no files":
// it is no observation at all, and the launch refuses before allocating rather
// than allocating over files it cannot see. The refusal is reclaimed by
// retrying once the proxy answers.
//
// **Every address a file named is reserved**, whether or not this pass managed
// to delete the file. That turns "the delete probably landed" into an ordering
// proof: even a file this host failed to remove cannot have its address handed
// to a new session, because the allocator was told about it. The caller passes
// `reservedSourceIps` straight into allocation.
//
// `report` mode is the same observation with none of the repair: no writes, no
// Docker effects, and no lock. It exists so `runfree sessions` can describe a
// half-torn-down project without changing it, which means it must tolerate
// exactly the states repair fixes — a record with no file, a file with no
// record — and name them instead of acting on them.

import type * as childProcess from "node:child_process";

import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import { warn } from "../warnings.ts";
import {
  readEffectiveControlPlaneV2,
  readRetainedDesiredSessionAgentV2,
} from "./component-state-v2.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import {
  ensureSessionEligibilityPublished,
  observeProxyStartedAt,
} from "./session-eligibility-publication.ts";
import {
  authorizeSessionContainerOrphanCleanup,
  executeSessionContainerCleanupCommand,
  orphanSessionContainerRemoveCommand,
  orphanSessionContainerStopCommand,
  proveSessionContainerOrphanAbsent,
  type SessionContainerNetworkIdentity,
} from "./session-container-cleanup.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
} from "./session-container-reconciliation.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  peekSessionContainerRecordsV2,
  removeExactSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import {
  executeSessionFileCommand,
  servedSetReadCommand,
  sessionFileDeleteCommand,
  type SessionAdmissionDockerExecutor,
} from "./session-file-publisher.ts";
import { teardownSessionRecord } from "./session-file-teardown.ts";
import { removeSessionHostStatus, writeSessionHostStatus } from "./session-host-status.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult } from "./types.ts";

const SESSION_KEY_PATTERN = /^[a-f0-9]{64}$/;

export type SessionReconcileMode = "repair" | "report";

export type SessionReconcileInput = Readonly<{
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  io: SessionAdmissionDockerExecutor;
  /** The proxy whose session directory holds this project's files. */
  proxyId: string;
  /**
   * The project's exact agent-internal network. Required by `repair`, which
   * removes containers attached to it; `report` performs no Docker effect and
   * does not need it.
   */
  network?: SessionContainerNetworkIdentity;
  env?: NodeJS.ProcessEnv;
  /**
   * The project lifecycle lock, asserted before every `repair` effect so the
   * whole pass is one critical section with the allocation that follows it.
   * `report` never asserts it.
   */
  lifecycleLock: ProjectLifecycleLock;
  mode: SessionReconcileMode;
  dockerOptions?: childProcess.SpawnSyncOptions;
}>;

export type SessionReconcileResult = Readonly<{
  /** Session keys whose file this pass deleted. */
  orphanFilesDeleted: readonly string[];
  /** Session ids whose dead owner's session this pass ended. */
  deadOwnersRevoked: readonly string[];
  /** Container ids this pass removed because no record claimed them. */
  orphanContainersRemoved: readonly string[];
  /** Session ids whose owning host process could be proved neither way. */
  unknownOwners: readonly string[];
  /**
   * Every address a well-formed proxy session file named, deleted or not.
   * The caller passes these to the allocator as additional reserved addresses.
   */
  reservedSourceIps: readonly string[];
  /**
   * Files that named no record when the pass began: the session key, or the
   * file's name when its name is not a session key.
   */
  orphanFiles: readonly string[];
  /** Session ids whose record had no file when the pass began. */
  recordsWithoutFiles: readonly string[];
  /**
   * Unclaimed files this pass refused to delete because the registry holds a
   * quarantined record. Reported, never acted on; `repair` only.
   */
  quarantinedFiles: readonly string[];
}>;

/**
 * One entry of the proxy's session-file listing.
 *
 * `aliveUntil`, `eligible`, and `wallActive` are the proxy's own eligibility
 * verdict for a well-formed file (`malformed: false`); a malformed entry
 * carries none of them, since the script that produced it never parsed the
 * file far enough to compute them.
 */
export type ProxySessionFile = Readonly<{
  sessionKey?: string;
  name: string;
  sourceIp?: string;
  malformed: boolean;
  aliveUntil?: string;
  eligible?: boolean;
  wallActive?: boolean;
}>;

/** What `reportSessionReconciliation` needs: an observation, and nothing else. */
export type SessionReconcileReportInput = Readonly<{
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  io: SessionAdmissionDockerExecutor;
  proxyId: string;
  env?: NodeJS.ProcessEnv;
  dockerOptions?: childProcess.SpawnSyncOptions;
}>;

function observationUnavailable(proxyId: string, observation: string, cause?: unknown): RuntimeObservationError {
  return new RuntimeObservationError({
    kind: "observation-unavailable",
    subject: "proxy",
    expectedIdentity: proxyId,
    phase: "read-served-set",
    observation,
  }, cause);
}

/**
 * The reconcile-boundary refusal for a dead owner's teardown blocked at the
 * delete step (`blockedAt: "delete-session-file"`).
 *
 * `teardownSessionRecord` reports the raw `RuntimeObservationError` the
 * delete script raised — stderr text with no remedy — which is the right
 * shape for the launch owner's own teardown (its ladder already reports
 * causes verbatim) but not for a background reconcile pass whose operator
 * needs to know what to do next. This wraps it into an operator-actionable
 * refusal: which session was blocked, that its record is kept on purpose so
 * the session's address stays reserved, and the two remedies that reclaim it
 * — a rerun for a transient proxy hiccup, `destroy --force` for a session
 * file the proxy refuses to remove. The original error is preserved as
 * `cause` for `--verbose` diagnostics, never in the message itself.
 */
function blockedSessionFileTeardownRefusal(sessionId: string, cause: unknown): CliError {
  return Object.assign(
    new CliError(
      `session ${sessionId}: its session file could not be removed from the proxy; `
      + "its record is kept so the session's address stays reserved; "
      + `run \`${remedy.up()}\` and retry, or \`${remedy.destroyForce()}\` if the file will not go away`,
    ),
    { cause },
  );
}

function parseProxySessionFile(value: unknown): ProxySessionFile | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const entry = value as Record<string, unknown>;
  const key = typeof entry.sessionKey === "string" && SESSION_KEY_PATTERN.test(entry.sessionKey)
    ? entry.sessionKey
    : undefined;
  if (entry.malformed === true) {
    // A `.json` whose stem is not a session key carries a name and no key. It
    // cannot be deleted through the pinned command's basename rule, and the
    // proxy's own scanner drops it, so it is reported rather than repaired.
    if (typeof entry.name !== "string" || entry.name.length === 0) return undefined;
    return Object.freeze({ ...(key === undefined ? {} : { sessionKey: key }), name: entry.name, malformed: true });
  }
  if (key === undefined || typeof entry.sourceIp !== "string" || entry.sourceIp.length === 0) return undefined;
  return Object.freeze({
    sessionKey: key,
    name: `${key}.json`,
    sourceIp: entry.sourceIp,
    malformed: false,
    ...(typeof entry.aliveUntil === "string" ? { aliveUntil: entry.aliveUntil } : {}),
    ...(typeof entry.eligible === "boolean" ? { eligible: entry.eligible } : {}),
    ...(typeof entry.wallActive === "boolean" ? { wallActive: entry.wallActive } : {}),
  });
}

/**
 * What the proxy currently holds, or a refusal.
 *
 * This is the module's only view of the session files, so both halves of "no
 * answer" — a non-zero exit and output that does not parse — are the same
 * typed observation failure, raised before the first repair effect.
 *
 * Exported for the consumers that must not act while the proxy still holds a
 * file they cannot account for: image GC (an image a served session may still
 * be running) and the destroy teardown (a file that must go before its record).
 * Every one of them treats the refusal the same way this module does — no
 * observation is not "no files".
 */
export function readProxySessionFiles(
  input: Pick<SessionReconcileInput, "io" | "proxyId" | "dockerOptions">,
): readonly ProxySessionFile[] {
  let result: CaptureResult;
  try {
    result = executeSessionFileCommand(
      input.io,
      servedSetReadCommand(input.proxyId),
      input.dockerOptions ?? {},
    );
  } catch (error) {
    throw observationUnavailable(
      input.proxyId,
      `the proxy could not report its session files (${
        error instanceof RuntimeObservationError ? error.evidence.observation : String(error)
      }); run \`${remedy.up()}\` and retry`,
      error,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    parsed = undefined;
  }
  if (!Array.isArray(parsed)) {
    throw observationUnavailable(
      input.proxyId,
      `the proxy's session file listing is unreadable; run \`${remedy.up()}\` and retry`,
    );
  }
  const files: ProxySessionFile[] = [];
  for (const entry of parsed) {
    const file = parseProxySessionFile(entry);
    if (!file) {
      throw observationUnavailable(
        input.proxyId,
        `the proxy's session file listing is unreadable; run \`${remedy.up()}\` and retry`,
      );
    }
    files.push(file);
  }
  return Object.freeze(files);
}

function unique(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)]);
}

/** The identifier a caller can act on, or recognise, one reported file by. */
function fileIdentity(file: ProxySessionFile): string {
  return file.sessionKey ?? file.name;
}

/**
 * Stops and removes one session container no record claims.
 *
 * The same authority the launch-time orphan cleanup uses: a fresh exact Docker
 * classification, re-checked against the registry under the held lock, and an
 * absence proof before the pass reports the container gone.
 */
function removeOrphanContainer(
  input: SessionReconcileInput,
  network: SessionContainerNetworkIdentity,
  classification: Parameters<typeof authorizeSessionContainerOrphanCleanup>[0] & { kind: "container-only" },
): void {
  const authority = authorizeSessionContainerOrphanCleanup(
    classification,
    input.expectedProject,
    network,
    input.stateDir,
    input.lifecycleLock,
  );
  const executor = (executable: "docker", args: readonly string[], options?: childProcess.SpawnSyncOptions) =>
    input.io.capture(executable, [...args], options ?? {});
  if (classification.container.running) {
    input.lifecycleLock.assertHeld();
    const stopped = executeSessionContainerCleanupCommand(
      orphanSessionContainerStopCommand(authority),
      executor,
      input.dockerOptions ?? {},
    );
    // Tolerated, exactly as it is at launch time: the removal below is the step
    // that must succeed, and a container that has already exited is the state
    // this one was trying to reach.
    if (stopped.status !== 0) {
      warn(`Docker could not stop orphan session container ${authority.containerId}; removing it anyway`);
    }
  }
  input.lifecycleLock.assertHeld();
  const removed = executeSessionContainerCleanupCommand(
    orphanSessionContainerRemoveCommand(authority),
    executor,
    input.dockerOptions ?? {},
  );
  if (removed.status !== 0) {
    throw new Error(
      `Docker failed to remove an exact orphan session container: ${
        removed.stderr.trim() || removed.stdout.trim() || `exit ${removed.status}`
      }`,
    );
  }
  proveSessionContainerOrphanAbsent(executor, authority, input.dockerOptions ?? {});
  input.lifecycleLock.assertHeld();
}

/**
 * Ends a dead owner's session whose record never bound a container.
 *
 * The ordered teardown needs an exact container id, and this record has none:
 * nothing was ever started under it, so there is nothing to disconnect, stop,
 * or remove. The file order is kept anyway — a file this record's key names is
 * taken away before the record that reserves its address is dropped — because
 * a record in this state may still have been written between the two.
 *
 * If a container does exist under this record's name, removing the record here
 * is precisely the record-first recovery the launch path already performs: the
 * container becomes an orphan for the fresh inventory below to remove.
 */
function removeUnboundDeadRecord(input: SessionReconcileInput, record: SessionContainerRecordV2): void {
  input.lifecycleLock.assertHeld();
  stampTerminal(input, record);
  input.lifecycleLock.assertHeld();
  executeSessionFileCommand(
    input.io,
    sessionFileDeleteCommand(input.proxyId, record.sessionPrincipal),
    input.dockerOptions ?? {},
  );
  input.lifecycleLock.assertHeld();
  removeExactSessionContainerRecordV2(input.stateDir, input.expectedProject, record);
  removeSessionHostStatus(input.stateDir, record.sessionId);
}

/**
 * Marks one record's stamp terminal: its teardown has begun.
 *
 * Advisory at every call site, like every other stamp write: a state directory
 * this host cannot write is evidence about the host, never about the session,
 * and must not stop a teardown.
 */
function stampTerminal(input: SessionReconcileInput, record: SessionContainerRecordV2): void {
  const now = new Date().toISOString();
  try {
    writeSessionHostStatus(input.stateDir, {
      v: 1,
      sessionId: record.sessionId,
      lastHeartbeatAt: now,
      aliveUntil: now,
      served: "unknown",
      terminal: "revoking",
    });
  } catch (error) {
    warn(`session status stamp unwritable: ${error instanceof Error ? error.message : String(error)}; the reconcile is unaffected`);
  }
}

/**
 * Republishes the project's session eligibility from the records that survived.
 *
 * Invariant 9 in both directions. Narrowing: an agent materialization that only
 * a now-removed record still named disappears from the admitted set here, after
 * its file is gone. Widening: a launch whose desired agent is newer than the
 * last publication widens the set here, before its session file is written.
 * Identical bytes cost no `docker exec`, so the common case is free.
 */
function republishEligibility(
  input: SessionReconcileInput,
  records: readonly SessionContainerRecordV2[],
): void {
  const effective = readEffectiveControlPlaneV2(input.stateDir);
  const desired = readRetainedDesiredSessionAgentV2(input.stateDir);
  if (!effective || !desired) {
    throw new Error(
      "session reconcile requires the selected control plane and the retained current agent template",
    );
  }
  input.lifecycleLock.assertHeld();
  ensureSessionEligibilityPublished({
    io: input.io,
    proxyId: input.proxyId,
    stateDir: input.stateDir,
    effective,
    desired,
    records,
    proxyStartedAt: observeProxyStartedAt(input.io, input.proxyId, input.dockerOptions ?? {}),
    dockerOptions: input.dockerOptions ?? {},
  });
  input.lifecycleLock.assertHeld();
}

/**
 * The same three-list observation with none of the repair.
 *
 * Synchronous, because it is a pure observation: `runfree sessions` reports
 * what a project holds from a plain function call, and could not take the
 * lifecycle lock even if it wanted to. It tolerates exactly the states repair
 * fixes — a record with no file, a file with no record — and names them.
 */
export function reportSessionReconciliation(input: SessionReconcileReportInput): SessionReconcileResult {
  const files = readProxySessionFiles(input);
  return describeSessions(
    input,
    files,
    unique(files.flatMap((file) => (file.sourceIp === undefined ? [] : [file.sourceIp]))),
  );
}

function describeSessions(
  input: Pick<SessionReconcileInput, "stateDir" | "expectedProject" | "env">,
  files: readonly ProxySessionFile[],
  reservedSourceIps: readonly string[],
): SessionReconcileResult {
  // Peeked, not listed: a report tolerates an unreadable record the same way it
  // tolerates a half-finished teardown, and `runfree sessions` already reports
  // unreadable records itself.
  const records = peekSessionContainerRecordsV2(input.stateDir, input.expectedProject).records;
  const recordKeys = new Set(records.map((record) => record.sessionPrincipal));
  const fileKeys = new Set(files.flatMap((file) => (file.sessionKey === undefined ? [] : [file.sessionKey])));
  return Object.freeze({
    orphanFilesDeleted: Object.freeze([]),
    deadOwnersRevoked: Object.freeze([]),
    orphanContainersRemoved: Object.freeze([]),
    unknownOwners: Object.freeze(records
      .filter((record) => sessionRecordOwnerLiveness(record, input.env) === "unknown")
      .map((record) => record.sessionId)),
    reservedSourceIps,
    orphanFiles: Object.freeze(files
      .filter((file) => file.malformed || file.sessionKey === undefined || !recordKeys.has(file.sessionKey))
      .map(fileIdentity)),
    recordsWithoutFiles: Object.freeze(records
      .filter((record) => !fileKeys.has(record.sessionPrincipal))
      .map((record) => record.sessionId)),
    // A report deletes nothing, so nothing was withheld from deletion. The
    // states a quarantined record produces are already reported here as an
    // orphan file and an unreadable record.
    quarantinedFiles: Object.freeze([]),
  });
}

/**
 * Reconciles the proxy's session files, the host's lifecycle records, and
 * Docker's session containers for one project.
 *
 * In `repair` the caller must hold the project lifecycle lock for the whole
 * call and through the allocation that follows it: a peer that allocated
 * between the sweep and the allocation could be handed an address this pass
 * had just freed.
 */
export async function reconcileSessions(input: SessionReconcileInput): Promise<SessionReconcileResult> {
  const files = readProxySessionFiles(input);
  const reservedSourceIps = unique(files.flatMap((file) => (file.sourceIp === undefined ? [] : [file.sourceIp])));
  if (input.mode === "report") return describeSessions(input, files, reservedSourceIps);

  const network = input.network;
  if (!network) throw new Error("session reconcile requires the project's exact internal network");
  const lock = () => input.lifecycleLock.assertHeld();
  lock();

  // Step 1. Files no record accounts for, and files the proxy's own reader
  // drops. A failed delete is reported and carried: its address stays reserved,
  // so the file grants nothing a later launch can collide with.
  const initialRecords = listSessionContainerRecordsV2(input.stateDir, input.expectedProject);
  // "No record accounts for it" is only true of a registry this host could
  // read in full. The listing above is itself the enumeration that quarantines
  // an unreadable record, and a quarantined record's own key is exactly what
  // cannot be read out of it — its file name carries the session id, and a
  // session file is named by the session principal. So a quarantined record
  // could claim any of the files below, including a live session's, and one
  // peer launch would take that session's authority away.
  //
  // The honest answer is therefore the conservative one: while the registry is
  // partially legible, no unclaimed file is deleted. Their addresses are still
  // reserved (`reservedSourceIps` is built from every well-formed file above),
  // so nothing can be handed out from under them, and both callers already
  // fail closed on quarantine right after this pass — the launch driver
  // through its own quarantined-record refusal, image GC through the
  // equivalent gate. `listQuarantinedSessionContainerRecordNamesV2` is the
  // same enumeration `readExactLifecycleRegistry` consults, and it is complete
  // here because the listing above throws when a quarantine could not be
  // persisted.
  const quarantinedRecords = listQuarantinedSessionContainerRecordNamesV2(input.stateDir);
  const recordKeys = new Set(initialRecords.map((record) => record.sessionPrincipal));
  const initialFileKeys = new Set(files.flatMap((file) => (file.sessionKey === undefined ? [] : [file.sessionKey])));
  const orphanFiles: string[] = [];
  const orphanFilesDeleted: string[] = [];
  const quarantinedFiles: string[] = [];
  for (const file of files) {
    if (!file.malformed && file.sessionKey !== undefined && recordKeys.has(file.sessionKey)) continue;
    orphanFiles.push(fileIdentity(file));
    if (quarantinedRecords.length > 0) {
      quarantinedFiles.push(fileIdentity(file));
      warn(`the proxy's session file ${file.name} is unclaimed, but the lifecycle registry holds ${
        quarantinedRecords.length
      } quarantined record(s) that could claim it; the file is kept and its address stays reserved`);
      continue;
    }
    if (file.sessionKey === undefined) {
      warn(`the proxy holds a session file this host cannot address: ${file.name}; it grants nothing and is ignored`);
      continue;
    }
    lock();
    try {
      executeSessionFileCommand(
        input.io,
        sessionFileDeleteCommand(input.proxyId, file.sessionKey),
        input.dockerOptions ?? {},
      );
      orphanFilesDeleted.push(file.sessionKey);
    } catch (error) {
      warn(`could not delete the unclaimed session file ${file.name}: ${
        error instanceof Error ? error.message : String(error)
      }; its address stays reserved`);
    }
  }

  // Step 2. Records whose owner is provably gone, through the one ordered
  // teardown both callers share. Nothing is transitioned: under this source the
  // record stays what it was until it is deleted, and the terminal stamp the
  // teardown writes is what tells a peer this is cleanup.
  const deadOwnersRevoked: string[] = [];
  const failures: unknown[] = [];
  for (const record of initialRecords) {
    if (sessionRecordOwnerLiveness(record, input.env) !== "dead") continue;
    lock();
    try {
      if (record.containerId === undefined) {
        removeUnboundDeadRecord(input, record);
        deadOwnersRevoked.push(record.sessionId);
        continue;
      }
      const teardown = teardownSessionRecord({
        io: input.io,
        proxyId: input.proxyId,
        record,
        expectedProject: input.expectedProject,
        networkId: network.networkId,
        lock,
        markTerminal: () => stampTerminal(input, record),
        clearStamp: () => removeSessionHostStatus(input.stateDir, record.sessionId),
        removeRecord: () => removeExactSessionContainerRecordV2(input.stateDir, input.expectedProject, record),
        dockerOptions: input.dockerOptions ?? {},
      });
      if (teardown.completed) deadOwnersRevoked.push(record.sessionId);
      else failures.push(blockedSessionFileTeardownRefusal(record.sessionId, teardown.error));
    } catch (error) {
      failures.push(error);
    }
  }

  // Step 3. Containers no surviving record claims. The inventory is taken after
  // the teardowns above so a record removed there leaves its container visible
  // here, which is the record-first order the launch path already uses.
  const records = listSessionContainerRecordsV2(input.stateDir, input.expectedProject);
  const orphanContainersRemoved: string[] = [];
  const classifications = classifySessionContainerReconciliation({
    expectedProject: input.expectedProject,
    records,
    containers: inspectSessionContainerInventory(
      (executable, args, options) => input.io.capture(executable, [...args], options ?? {}),
      input.expectedProject,
      input.dockerOptions ?? {},
    ),
  });
  // Only `container-only` is acted on. An uncertain classification is a live
  // container this pass cannot account for, and destroying it would be worse
  // than carrying it: the launch path's own orphan cleanup still refuses to
  // admit beside one, which is where that refusal belongs.
  for (const classification of classifications) {
    if (classification.kind !== "container-only") continue;
    lock();
    try {
      removeOrphanContainer(input, network, classification);
      orphanContainersRemoved.push(classification.container.containerId);
    } catch (error) {
      failures.push(error);
    }
  }

  // Step 4. Owners that can be proved neither way. Reported, never acted on.
  const unknownOwners = records
    .filter((record) => sessionRecordOwnerLiveness(record, input.env) === "unknown")
    .map((record) => record.sessionId);

  // Step 5. What the surviving records make admissible. Collected into
  // `failures` rather than left to propagate: a teardown or orphan-container
  // failure above must still be reported even when this step also fails,
  // instead of one throw silently discarding the other.
  try {
    republishEligibility(input, records);
  } catch (error) {
    failures.push(error);
  }

  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, "session reconciliation did not complete");
  }
  return Object.freeze({
    orphanFilesDeleted: Object.freeze(orphanFilesDeleted),
    deadOwnersRevoked: Object.freeze(deadOwnersRevoked),
    orphanContainersRemoved: Object.freeze(orphanContainersRemoved),
    unknownOwners: Object.freeze(unknownOwners),
    reservedSourceIps,
    orphanFiles: Object.freeze(orphanFiles),
    recordsWithoutFiles: Object.freeze(initialRecords
      .filter((record) => !initialFileKeys.has(record.sessionPrincipal))
      .map((record) => record.sessionId)),
    quarantinedFiles: Object.freeze(quarantinedFiles),
  });
}
