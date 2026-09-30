// Finishing an interrupted session teardown at startup, once Docker proves it
// is safe to.
//
// A session's owner ends it through the ordered teardown in
// `session-file-teardown.ts`: terminal stamp, file delete, container removal,
// record removal. When the Docker daemon dies under a live session, that owner
// stamps its record terminal and then cannot delete the session file, so it
// keeps the record — correctly: a delete this host could not perform is not
// proof the file is gone, and the record is what keeps the session's address
// reserved. The owner then exits.
//
// Startup reads a terminal-stamped record as "a session admission is pending"
// and, before this module, refused with `runfree rebuild` as the only remedy.
// That refusal was sound but had no reclaim path of its own: a daemon restart,
// which is an ordinary event, forced a full rebuild.
//
// This module is that reclaim path. Under the lifecycle lock, for each pending
// record, it finishes the same ordered teardown — but only after Docker has
// proved each of the following, and it keeps the record otherwise:
//
//   1. The owner is provably dead. A live owner is still running its own
//      teardown; an owner whose liveness cannot be proved may be a session.
//   2. The session container is absent or stopped. A stopped container can be
//      removed; a running one may still send packets, and this path does not
//      decide that it may be stopped.
//   3. The session file cannot be served. Either the selected proxy is running
//      and the ordinary delete succeeds, or the selected proxy is absent or
//      stopped: session files live on the proxy's tmpfs, which Docker discards
//      when the container stops, and a restarted proxy starts deny-all with an
//      empty session directory. No other proxy for the project may be running,
//      because only the selected proxy is ever handed a session file.
//   4. After removal, the session container is absent. The record — the
//      address reservation — is dropped only after that proof.
//
// Every observation this host could not make is a refusal, not an absence:
// "Docker did not answer" is never "the container is gone". A refusal names
// the session, the reason, and the remedy, and leaves the record exactly as it
// was (a refusal after the teardown has begun may have rewritten its terminal
// stamp, which keeps it pending either way), so the same pass run again once
// Docker answers finishes the job.
//
// A pending control-plane rebind is not touched here. The planner lets that
// journal take precedence over a pending admission, and its own recovery
// already classifies dead-owner participants, so this pass steps aside.

import type * as childProcess from "node:child_process";

import { PROXY_SESSION_REGISTRY_DIR } from "@runfree/runtime-contracts/session-registry";

import { remedy } from "../remedies.ts";
import { PROJECT_ID_LABEL } from "./constants.ts";
import { readEffectiveControlPlaneV2 } from "./component-state-v2.ts";
import { CONTAINER_ROLE_LABEL, composeServiceContainerFilters } from "./container-inventory.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import { observeExactProxy } from "./proxy-containment.ts";
import {
  listSessionContainerRecordsV2,
  removeExactSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { provesContainerAbsent } from "./session-file-heartbeat.ts";
import {
  executeSessionFileCommand,
  sessionFileDeleteCommand,
  type SessionAdmissionDockerExecutor,
} from "./session-file-publisher.ts";
import { removeSessionMcpCallbackIngress } from "./session-callback-ingress.ts";
import { teardownSessionRecord } from "./session-file-teardown.ts";
import {
  readSessionHostStatus,
  removeSessionHostStatus,
  writeSessionHostStatus,
} from "./session-host-status.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { DockerContainerInspect } from "./types.ts";

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
/** The proxy's session registry; the session files live in `sessions/` below it. */
const SESSION_REGISTRY_PATH = PROXY_SESSION_REGISTRY_DIR;
const SESSION_CONTAINER_ROLE = "session-agent";
const SESSION_CONTAINER_OBSERVATION_TIMEOUT_MS = 5_000;
const PROXY_INVENTORY_TIMEOUT_MS = 5_000;
const OBSERVATION_MAX_BYTES = 1024 * 1024;

// How long an allocation may sit without a container before it stops being an
// admission in flight and becomes one that needs recovery. Allocation binds a
// created container within one Docker create; a minute is far outside that and
// far inside any human's retry.
export const SESSION_FILE_ALLOCATION_WINDOW_MS = 60_000;

/**
 * What "a session admission is pending" means under the session-file source.
 *
 * There is no admission journal here, so the evidence is the registry itself,
 * in the two shapes that say a session's admission is unfinished:
 *
 *   - a record its owner stamped `terminal`: revocation started and did not
 *     finish, so the address is still reserved and the proxy may still hold the
 *     file;
 *   - an `allocated` record with no container id, older than the allocation
 *     window: the address was reserved and the container never appeared.
 *
 * Everything else — a young allocation, a bound record, a record beating
 * normally — is ordinary concurrent state that no runtime upgrade may be
 * refused over. Reading the stamp never throws; an unreadable one is absent,
 * which leaves only the allocation rule.
 */
export function pendingSessionFileAdmissionRecords(input: Readonly<{
  stateDir: string;
  records: readonly SessionContainerRecordV2[];
  nowEpochMs: number;
}>): readonly SessionContainerRecordV2[] {
  return input.records.filter((record) => {
    if (readSessionHostStatus(input.stateDir, record.sessionId)?.terminal === "revoking") return true;
    if (record.state !== "allocated" || record.containerId !== undefined) return false;
    const createdAtMs = Date.parse(record.createdAt);
    return Number.isFinite(createdAtMs)
      && input.nowEpochMs - createdAtMs > SESSION_FILE_ALLOCATION_WINDOW_MS;
  });
}

export type PendingSessionAdmissionReclaimInput = Readonly<{
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  io: SessionAdmissionDockerExecutor;
  /** Held for the whole pass and asserted before every effect. */
  lifecycleLock: ProjectLifecycleLock;
  /** Host identity inputs for owner liveness (boot id, process start). */
  env?: NodeJS.ProcessEnv;
  /** Docker client options (the project's Docker context environment). */
  dockerOptions?: childProcess.SpawnSyncOptions;
  nowEpochMs: number;
}>;

export type PendingSessionAdmissionReclaimResult =
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "reclaimed"; sessionIds: readonly string[] }>
  | Readonly<{ kind: "refused"; sessionIds: readonly string[]; reasons: readonly string[] }>;

/** Why one record was kept: a sentence that already names its remedy. */
class ReclaimRefusal extends Error {}

type ContainerObservation =
  | Readonly<{ kind: "absent" }>
  | Readonly<{ kind: "present"; containerId: string; stopped: boolean; status: string }>;

function shortId(id: string): string {
  return id.slice(0, 12);
}

function describeFailure(error: unknown): string {
  if (error instanceof RuntimeObservationError) return error.evidence.observation;
  return error instanceof Error ? error.message : String(error);
}

function dockerUnavailable(sessionId: string, what: string, detail: string): ReclaimRefusal {
  return new ReclaimRefusal(
    `session ${sessionId}: Docker could not report ${what} (${detail}); its record is kept so the session's address`
      + ` stays reserved; start Docker, then run \`${remedy.up()}\` or retry the command`,
  );
}

/**
 * A container Docker reports as not running, and not about to be.
 *
 * `created`, `exited`, and `dead` are the only states in which the container
 * has no process; `paused`, `restarting`, and `removing` still hold one (or
 * are about to), so they are not stopped for this purpose.
 */
function stoppedState(state: DockerContainerInspect["State"]): boolean {
  if (!state || state.Running !== false) return false;
  return state.Status === "created" || state.Status === "exited" || state.Status === "dead";
}

/**
 * One exact session container, by the record's container id or — for a record
 * that never bound one — by its reserved name.
 *
 * Absence is proved only by Docker's own definitive "no such container" for
 * this exact reference. Any other failure is no observation at all. A present
 * container must be this project's session container: anything else under
 * this reference is a contradiction this pass will not act on.
 */
function observeSessionContainer(
  input: PendingSessionAdmissionReclaimInput,
  record: SessionContainerRecordV2,
): ContainerObservation {
  const reference = record.containerId ?? record.containerName;
  if (record.containerId !== undefined && !DOCKER_OBJECT_ID_PATTERN.test(record.containerId)) {
    throw new ReclaimRefusal(
      `session ${record.sessionId}: its record names no exact container id; inspect the runtime, then recreate it`
        + ` with \`${remedy.rebuild()}\``,
    );
  }
  input.lifecycleLock.assertHeld();
  const inspected = input.io.capture("docker", ["container", "inspect", reference], {
    ...(input.dockerOptions ?? {}),
    timeout: SESSION_CONTAINER_OBSERVATION_TIMEOUT_MS,
    maxBuffer: OBSERVATION_MAX_BYTES,
  });
  input.lifecycleLock.assertHeld();
  if (inspected.status !== 0) {
    if (provesContainerAbsent(inspected.stderr, reference)) return Object.freeze({ kind: "absent" as const });
    throw dockerUnavailable(
      record.sessionId,
      "its session container",
      inspected.stderr.trim() || inspected.stdout.trim() || `exit ${inspected.status}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspected.stdout);
  } catch {
    parsed = undefined;
  }
  const container = Array.isArray(parsed) && parsed.length === 1
    ? parsed[0] as DockerContainerInspect
    : undefined;
  if (!container) {
    throw dockerUnavailable(record.sessionId, "its session container", "the inspection is malformed");
  }
  const labels = container.Config?.Labels ?? {};
  const exactReference = record.containerId !== undefined
    ? container.Id === record.containerId
    : container.Name === `/${record.containerName}`;
  if (!exactReference
    || typeof container.Id !== "string"
    || !DOCKER_OBJECT_ID_PATTERN.test(container.Id)
    || labels[PROJECT_ID_LABEL] !== input.expectedProject.projectId
    || labels[CONTAINER_ROLE_LABEL] !== SESSION_CONTAINER_ROLE) {
    throw new ReclaimRefusal(
      `session ${record.sessionId}: the container Docker reports under ${
        record.containerId === undefined ? "its reserved name" : "its container id"
      } is not this project's session container; inspect the runtime, then recreate it with \`${remedy.rebuild()}\``,
    );
  }
  return Object.freeze({
    kind: "present" as const,
    containerId: container.Id,
    stopped: stoppedState(container.State),
    status: container.State?.Status ?? "unknown",
  });
}

/**
 * This project's running proxy containers, by Compose identity.
 *
 * Only the selected proxy is ever handed a session file, so a second running
 * proxy is a state this pass cannot reason about and refuses over.
 */
function runningProjectProxyIds(input: PendingSessionAdmissionReclaimInput, sessionId: string): readonly string[] {
  input.lifecycleLock.assertHeld();
  // Uncorroborated on purpose: any running container Compose would call this
  // project's proxy counts, which can only widen what refuses.
  const listed = input.io.capture("docker", [
    "ps", "--quiet", "--no-trunc",
    ...composeServiceContainerFilters(input.expectedProject.composeProject, "proxy"),
  ], { ...(input.dockerOptions ?? {}), timeout: PROXY_INVENTORY_TIMEOUT_MS, maxBuffer: OBSERVATION_MAX_BYTES });
  input.lifecycleLock.assertHeld();
  if (listed.status !== 0 || listed.stderr.trim()) {
    throw dockerUnavailable(
      sessionId,
      "the project's running proxies",
      listed.stderr.trim() || `exit ${listed.status}`,
    );
  }
  return Object.freeze(listed.stdout.trim().split(/\s+/u).filter(Boolean));
}

type ProxyObservation = "running" | "not-serving";

/**
 * Whether this proxy's session registry is a tmpfs Docker discards on stop,
 * with nothing persistent mounted inside it.
 *
 * The same two places the security contract reads a tmpfs from
 * (`HostConfig.Tmpfs` for Compose's `tmpfs:`, or a `tmpfs` entry in `Mounts`).
 */
function sessionFilesOnTmpfs(proxy: DockerContainerInspect): boolean {
  const tmpfs = proxy.HostConfig?.Tmpfs;
  const mounts = proxy.Mounts ?? [];
  const registryIsTmpfs = Boolean(tmpfs && Object.hasOwn(tmpfs, SESSION_REGISTRY_PATH))
    || mounts.some((mount) => mount.Destination === SESSION_REGISTRY_PATH && mount.Type === "tmpfs");
  const persistentInside = mounts.some((mount) => mount.Type !== "tmpfs"
    && typeof mount.Destination === "string"
    && (mount.Destination === SESSION_REGISTRY_PATH || mount.Destination.startsWith(`${SESSION_REGISTRY_PATH}/`)));
  return registryIsTmpfs && !persistentInside;
}

/**
 * Whether the selected proxy could still hold this session's file.
 *
 * `not-serving` is a proof: the selected proxy is absent, or stopped, and no
 * other proxy for this project is running. `running` is not a proof of
 * anything; it means the file must be deleted the ordinary way.
 */
function observeSelectedProxy(
  input: PendingSessionAdmissionReclaimInput,
  proxyId: string,
  sessionId: string,
): ProxyObservation {
  let proxy: DockerContainerInspect | undefined;
  try {
    proxy = observeExactProxy({
      proxyId,
      projectId: input.expectedProject.projectId,
      composeProject: input.expectedProject.composeProject,
      io: input.io,
      ...(input.dockerOptions?.env === undefined ? {} : { env: input.dockerOptions.env }),
      assertAuthority: () => input.lifecycleLock.assertHeld(),
    });
  } catch (error) {
    if (error instanceof RuntimeObservationError && error.evidence.kind === "observation-unavailable") {
      throw dockerUnavailable(sessionId, "the selected proxy", describeFailure(error));
    }
    throw new ReclaimRefusal(
      `session ${sessionId}: the selected proxy's identity contradicts the runtime (${describeFailure(error)});`
        + ` inspect the runtime, then recreate it with \`${remedy.rebuild()}\``,
    );
  }
  const others = runningProjectProxyIds(input, sessionId).filter((id) => id !== proxyId);
  if (others.length > 0) {
    throw new ReclaimRefusal(
      `session ${sessionId}: a proxy other than the selected one is running for this project`
        + ` (${others.map(shortId).join(", ")}); inspect the runtime, then recreate it with \`${remedy.rebuild()}\``,
    );
  }
  if (!proxy) return "not-serving";
  if (stoppedState(proxy.State)) {
    // The claim that a stopped proxy holds no file rests on the session
    // directory being tmpfs, so it is read off this exact container rather
    // than assumed from the topology it was meant to have.
    if (!sessionFilesOnTmpfs(proxy)) {
      throw new ReclaimRefusal(
        `session ${sessionId}: the stopped selected proxy does not keep its session files on tmpfs, so a stopped`
          + ` proxy does not prove them gone; inspect the runtime, then recreate it with \`${remedy.rebuild()}\``,
      );
    }
    return "not-serving";
  }
  if (proxy.State?.Running === true) return "running";
  throw new ReclaimRefusal(
    `session ${sessionId}: the selected proxy is ${proxy.State?.Status ?? "in an unknown state"}, neither running`
      + ` nor stopped; retry the command once it settles`,
  );
}

function stampTerminal(input: PendingSessionAdmissionReclaimInput, record: SessionContainerRecordV2): void {
  const now = new Date(input.nowEpochMs).toISOString();
  try {
    writeSessionHostStatus(input.stateDir, {
      v: 1,
      sessionId: record.sessionId,
      lastHeartbeatAt: now,
      aliveUntil: now,
      served: "unknown",
      terminal: "revoking",
    });
  } catch {
    // Advisory, exactly like every other stamp write: a state directory this
    // host cannot write is evidence about the host, never about the session.
  }
}

/**
 * Finishes one pending record's teardown, or throws the refusal that keeps it.
 */
function removeCallbackIngress(input: PendingSessionAdmissionReclaimInput, record: SessionContainerRecordV2): void {
  try {
    removeSessionMcpCallbackIngress({
      io: input.io,
      ...(input.dockerOptions === undefined ? {} : { dockerOptions: input.dockerOptions }),
      projectId: input.expectedProject.projectId,
      sessionId: record.sessionId,
      sourceIp: record.sourceIp,
    });
  } catch (error) {
    throw new ReclaimRefusal(
      `session ${record.sessionId}: its MCP OAuth callback forwarder could not be proved removed`
        + ` (${describeFailure(error)}); its record is kept so the session's address stays reserved; retry the command`,
    );
  }
}

function reclaimRecord(
  input: PendingSessionAdmissionReclaimInput,
  record: SessionContainerRecordV2,
  controlPlane: Readonly<{ proxyContainerId: string; agentInternalNetworkId: string }>,
): void {
  // 1. The owner. Re-read under the lock; nothing below runs for an owner that
  //    is, or may be, still running.
  const owner = sessionRecordOwnerLiveness(record, input.env);
  if (owner === "alive") {
    throw new ReclaimRefusal(
      `session ${record.sessionId}: its owner (host process ${record.hostPid}) is still finishing its teardown;`
        + " retry the command once it exits",
    );
  }
  if (owner !== "dead") {
    throw new ReclaimRefusal(
      `session ${record.sessionId}: its owner (host process ${record.hostPid}) cannot be proved gone; if no Runfree`
        + ` session for this project is still running, run \`${remedy.destroyForce()}\``,
    );
  }

  // 2. The session container: absent, or stopped. A running one is kept.
  const container = observeSessionContainer(input, record);
  if (container.kind === "present" && !container.stopped) {
    throw new ReclaimRefusal(
      `session ${record.sessionId}: its session container ${shortId(container.containerId)} is still`
        + ` ${container.status} although its owner is gone; inspect it with \`${remedy.sessions()}\`, then recreate`
        + ` the runtime with \`${remedy.rebuild()}\``,
    );
  }
  if (record.containerId === undefined && container.kind === "present") {
    // A container under the reserved name of a record that never bound one:
    // removing it by name is not an authority this pass holds.
    throw new ReclaimRefusal(
      `session ${record.sessionId}: a container holds its reserved name but its record never bound it; inspect the`
        + ` runtime, then recreate it with \`${remedy.rebuild()}\``,
    );
  }

  // 3. The session file. Observed now, and re-proved at the step itself.
  const proxy = observeSelectedProxy(input, controlPlane.proxyContainerId, record.sessionId);
  const removeSessionFile = proxy === "running"
    ? () => {
      executeSessionFileCommand(
        input.io,
        sessionFileDeleteCommand(controlPlane.proxyContainerId, record.sessionPrincipal),
        input.dockerOptions ?? {},
      );
    }
    : () => {
      if (observeSelectedProxy(input, controlPlane.proxyContainerId, record.sessionId) !== "not-serving") {
        throw new ReclaimRefusal(
          `session ${record.sessionId}: the selected proxy started during reclaim; retry the command`,
        );
      }
    };

  // 4. Absence, proved before the record — the address reservation — goes.
  const proveContainerGone = (): void => {
    const after = observeSessionContainer(input, record);
    if (after.kind !== "absent") {
      throw new ReclaimRefusal(
        `session ${record.sessionId}: its session container ${shortId(after.containerId)} is still present after`
          + ` removal; its record is kept; inspect it with \`${remedy.sessions()}\`, then retry the command`,
      );
    }
  };
  const removeRecord = (): boolean => {
    proveContainerGone();
    input.lifecycleLock.assertHeld();
    return removeExactSessionContainerRecordV2(input.stateDir, input.expectedProject, record);
  };

  if (record.containerId === undefined) {
    // Nothing was ever started under this record: no container to disconnect,
    // stop, or remove. The file order is kept anyway.
    input.lifecycleLock.assertHeld();
    stampTerminal(input, record);
    input.lifecycleLock.assertHeld();
    removeSessionFile();
    // No bound forwarder can exist without a container, but an unbound
    // (pre-session-owned) callback forwarder may still route to this address;
    // it is proved gone before the record releases the address.
    input.lifecycleLock.assertHeld();
    removeCallbackIngress(input, record);
    input.lifecycleLock.assertHeld();
    removeRecord();
    removeSessionHostStatus(input.stateDir, record.sessionId);
    return;
  }

  const teardown = teardownSessionRecord({
    io: input.io,
    proxyId: controlPlane.proxyContainerId,
    record,
    expectedProject: input.expectedProject,
    networkId: controlPlane.agentInternalNetworkId,
    lock: () => input.lifecycleLock.assertHeld(),
    markTerminal: () => stampTerminal(input, record),
    clearStamp: () => removeSessionHostStatus(input.stateDir, record.sessionId),
    removeRecord,
    removeSessionFile,
    ...(input.dockerOptions === undefined ? {} : { dockerOptions: input.dockerOptions }),
  });
  if (!teardown.completed) {
    if (teardown.error instanceof ReclaimRefusal) throw teardown.error;
    throw new ReclaimRefusal(
      `session ${record.sessionId}: its session file could not be removed from the proxy`
        + ` (${describeFailure(teardown.error)}); its record is kept so the session's address stays reserved;`
        + ` run \`${remedy.up()}\` and retry, or \`${remedy.destroyForce()}\` if the file will not go away`,
    );
  }
}

/**
 * Finishes every pending session admission Docker proves is safe to finish.
 *
 * Returns `none` when nothing is pending (or a control-plane rebind journal
 * owns the recovery), `reclaimed` when every pending record was torn down, and
 * `refused` — with one remedy-bearing sentence per kept record — otherwise.
 * Records reclaimed before a refusal stay reclaimed: each one's teardown is
 * complete on its own.
 */
export function reclaimPendingSessionAdmissions(
  input: PendingSessionAdmissionReclaimInput,
): PendingSessionAdmissionReclaimResult {
  input.lifecycleLock.assertHeld();
  if (readControlPlaneRebindTransaction(input.stateDir, input.expectedProject)) {
    return Object.freeze({ kind: "none" as const });
  }
  const pending = pendingSessionFileAdmissionRecords({
    stateDir: input.stateDir,
    records: listSessionContainerRecordsV2(input.stateDir, input.expectedProject),
    nowEpochMs: input.nowEpochMs,
  });
  if (pending.length === 0) return Object.freeze({ kind: "none" as const });

  const effective = readEffectiveControlPlaneV2(input.stateDir);
  if (!effective) {
    return Object.freeze({
      kind: "refused" as const,
      sessionIds: Object.freeze(pending.map((record) => record.sessionId)),
      reasons: Object.freeze([
        "an interrupted session teardown has no selected control plane to prove its proxy against; inspect the"
          + ` runtime, then recreate it with \`${remedy.rebuild()}\``,
      ]),
    });
  }
  const controlPlane = Object.freeze({
    proxyContainerId: effective.selection.proxyContainerId,
    agentInternalNetworkId: effective.selection.networkIds.agentInternal,
  });

  const reclaimed: string[] = [];
  const refused: string[] = [];
  const reasons: string[] = [];
  for (const record of pending) {
    input.lifecycleLock.assertHeld();
    try {
      reclaimRecord(input, record, controlPlane);
      reclaimed.push(record.sessionId);
    } catch (error) {
      refused.push(record.sessionId);
      reasons.push(error instanceof ReclaimRefusal
        ? error.message
        : `session ${record.sessionId}: its interrupted teardown could not be finished (${describeFailure(error)});`
          + ` its record is kept; retry the command, or inspect the runtime and recreate it with \`${remedy.rebuild()}\``);
    }
  }
  if (refused.length > 0) {
    return Object.freeze({
      kind: "refused" as const,
      sessionIds: Object.freeze(refused),
      reasons: Object.freeze(reasons),
    });
  }
  return Object.freeze({ kind: "reclaimed" as const, sessionIds: Object.freeze(reclaimed) });
}
