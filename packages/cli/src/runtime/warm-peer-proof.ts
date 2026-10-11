// Warm launch validation beside live peer sessions.
//
// A warm launch skips the full runtime validation when a stable-fact warm
// match (`WarmValidation`, `warm-proof.ts`) holds. With live peers in the
// lifecycle registry that match is not enough: peers and their callback
// forwarders are internal-network participants the stable record cannot bind.
// This module earns the skip beside them with an exact, current accounting of
// every peer and every internal-network participant, judged under the held
// lifecycle lock within one proxy incarnation.
//
// What a match authorizes, and nothing more: startup may skip the full
// validation, and may skip `restoreSameProxySessionAdmission` when the
// consumption binding still holds after the startup reconcile. It grants no
// restore, rebind, heartbeat renewal, eligibility widening, or control-plane
// selection, and it never enters the launch handoff. Every miss is read-only
// (Docker `ps`/`inspect` only; the registry enumeration may quarantine an
// unreadable record, as every enumeration does), and the caller then takes
// the full validation, reconcile, and restore exactly as without a match.

import type * as childProcess from "node:child_process";

import { sha256Digest, stableJson } from "../strict-primitives.ts";
import type {
  ControlPlaneEffectiveSelectionV2,
  ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import type { RuntimeDocker } from "./docker.ts";
import { createDockerClient } from "./docker-client.ts";
import { sessionRegistryDigest } from "./launch-handoff.ts";
import { createRetainedSessionRebindProofPlan } from "./session-admission-driver-preflight.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
  isSessionPoolSourceIp,
  SESSION_CONTAINER_CONCURRENCY_CAP,
  type SessionContainerInventoryExecutor,
} from "./session-container-reconciliation.ts";
import { validateSessionContainerInspect } from "./session-container-proof.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readSessionHostStatus } from "./session-host-status.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import type { ProxySessionFile } from "./session-reconcile.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { DockerContainerInspect, RuntimeIO } from "./types.ts";
import { describeInternalNetworkParticipant } from "./utility-containers.ts";
import { assertWarmValidation, type WarmValidation } from "./warm-proof.ts";

/**
 * Why a launch beside peers takes the full validation. Every reason is a miss:
 * the caller deletes nothing and changes nothing because of it, and the full
 * path (validation, reconcile, restore) runs exactly as it does today.
 */
export const WARM_PEER_MISS_REASONS = [
  "no-peers",
  "registry-unreadable",
  "quarantined-records",
  "pending-rebind",
  "peer-count-exceeded",
  "peer-state",
  "peer-terminal-stamp",
  "peer-owner-dead",
  "peer-owner-unknown",
  "peer-generation",
  "peer-container-missing",
  "peer-container-mismatch",
  "peer-container-unproven",
  "peer-file-missing",
  "peer-file-ineligible",
  "peer-file-expired",
  "peer-file-address",
  "orphan-file",
  "orphan-container",
  "unaccounted-participant",
  "callback-unbound",
  "ingress-target-unaccounted",
  "consumer-firewall",
  "consumer-request-proxy",
  "ip-assignment",
  "proxy-incarnation",
  "inventory-unreadable",
  "evidence-unreadable",
  "cancelled",
] as const;

export type WarmPeerMissReason = typeof WARM_PEER_MISS_REASONS[number];

/**
 * The peer evidence the stable warm observation's own inspect and root batch
 * collect, carried on the sealed `WarmValidation` as `peerEvidence`. Same
 * proxy incarnation and the same observation as the stable facts; never read
 * from a host record.
 */
export type WarmPeerEvidence = Readonly<{
  /** The served-set section: every file in the proxy's session directory. */
  sessionFiles: readonly ProxySessionFile[];
  /** The kernel `@session_ipv4` members, from the batch's `nft -j list table` section. */
  sessionSetMembers: readonly string[];
  /** Every IP assignment binding under the proxy's reuse root. */
  ipAssignments: Readonly<Record<string, Readonly<{ sessionKey: string; state: "draining" | "ready" }>>>;
  /** The request proxy's status line: the effective policy generation it serves. */
  requestProxyGeneration?: string;
  /** Every internal-network endpoint the network inspect named, by container id. */
  internalNetworkContainers: Readonly<Record<string, Readonly<{ IPv4Address: string; EndpointID: string }>>>;
  /** The inspect of every container `internalNetworkContainers` names, the proxy included. */
  participants: readonly DockerContainerInspect[];
  /**
   * The non-session participants (`vnc`/`port` forwarders and any other
   * utility) the stable comparison found exactly equal to the record's
   * `fixedParticipants`. Absent means none.
   */
  fixedParticipants?: readonly WarmFixedParticipant[];
}>;

/** One recorded participant that is neither the proxy nor session-bound. */
export type WarmFixedParticipant = Readonly<{
  id: string;
  ipv4: string;
  endpointId: string;
  role: string;
  purpose?: string;
  target?: string;
}>;

export type WarmPeerProofInput = Readonly<{
  /** This launch's stable-fact match; the peer judgement only extends it. */
  stable: WarmValidation;
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  /** The durable effective control-plane selection, re-read under the held lock. */
  effective: ControlPlaneEffectiveSelectionV2;
  effectiveManifest: ControlPlaneMaterializationManifestV2;
  /** The selected effective policy generation. */
  effectivePolicyGeneration: string;
  lifecycleLock: ProjectLifecycleLock;
  /** Docker reads only: the session-container inventory and the incarnation re-read. */
  io: RuntimeIO;
  /** Image reads for each peer's exact proof plan. */
  docker: Pick<RuntimeDocker, "inspectImage">;
  dockerOptions: childProcess.SpawnSyncOptions;
  /** Host identity for owner liveness. */
  env?: NodeJS.ProcessEnv;
  runfreeVersion: string;
  signal?: AbortSignal;
}>;

/** One accounted peer, exactly as the judgement proved it. */
export type WarmPeer = Readonly<{
  sessionId: string;
  sessionPrincipal: string;
  sessionIncarnation: string;
  containerId: string;
  sourceIp: string;
  endpointId: string;
  /** The peer's own mcp-callback forwarder, when it has one. */
  callbackForwarderId?: string;
}>;

/**
 * A sealed, one-shot match: only this module mints one (by identity, like
 * `WarmValidation` and the warm-empty state), and only for a judgement whose
 * every peer and participant was accounted for.
 */
export type WarmPeerValidation = Readonly<{
  kind: "warm-peer";
  /** The stable match this extends (the same object). */
  stable: WarmValidation;
  proxyId: string;
  proxyStartedAt: string;
  proxyPid: number;
  bootId: string;
  /** `sessionRegistryDigest` taken under the held lock during the judgement. */
  registryDigest: string;
  peers: readonly WarmPeer[];
  /**
   * `sha256Digest(stableJson(entries))`, entries `{ containerId, ipv4Address,
   * endpointId }` for every endpoint of the internal network (proxy included),
   * `ipv4Address` exactly as the network inspect reported it, sorted by
   * `containerId`.
   */
  participantDigest: string;
  /** The incarnation bracket: StartedAt before the batch and after the last read. */
  observationEpoch: Readonly<{ startedAtBefore: string; startedAtAfter: string; observedAtEpochMs: number }>;
  lockOwnerToken: string;
  effectivePolicyGeneration: string;
  controlPlaneGenerationDigest: string;
  controlPlaneMaterializationDigest: string;
  admissionContractEpoch: number;
}>;

export type WarmPeerVerdict =
  | Readonly<{ kind: "match"; validation: WarmPeerValidation }>
  | Readonly<{ kind: "miss"; reason: WarmPeerMissReason; detail?: string }>;

/** What the restore-skip decision re-reads and must find equal to the minted validation. */
export type WarmPeerConsumptionBinding = Readonly<{
  lockOwnerToken: string;
  proxyId: string;
  proxyStartedAt: string;
  registryDigest: string;
  effectivePolicyGeneration: string;
  controlPlaneGenerationDigest: string;
  controlPlaneMaterializationDigest: string;
  admissionContractEpoch: number;
}>;

const minted = new WeakSet<object>();

export function assertWarmPeerValidation(value: unknown): asserts value is WarmPeerValidation {
  if (!value || typeof value !== "object" || !minted.has(value)) {
    throw new Error("warm peer validation was not minted by the warm peer judgement");
  }
}

/** Raised by the cancellable Docker executor; never escapes this module. */
class WarmPeerCancelled extends Error {}

type Miss = Readonly<{ kind: "miss"; reason: WarmPeerMissReason; detail?: string }>;

function miss(reason: WarmPeerMissReason, detail?: string): Miss {
  return Object.freeze({ kind: "miss", reason, ...(detail !== undefined ? { detail } : {}) });
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** `172.31.90.20/24` -> `172.31.90.20`; Docker reports endpoint addresses with their prefix. */
function endpointAddress(value: string): string {
  const slash = value.indexOf("/");
  return slash < 0 ? value : value.slice(0, slash);
}

function wellFormedEvidence(evidence: WarmPeerEvidence | undefined): evidence is WarmPeerEvidence {
  return evidence !== undefined
    && Array.isArray(evidence.sessionFiles)
    && Array.isArray(evidence.sessionSetMembers)
    && typeof evidence.ipAssignments === "object" && evidence.ipAssignments !== null
    && typeof evidence.internalNetworkContainers === "object" && evidence.internalNetworkContainers !== null
    && Array.isArray(evidence.participants)
    && (evidence.fixedParticipants === undefined || Array.isArray(evidence.fixedParticipants));
}

/** The internal-network endpoint id an inspect reports for `networkName`, or undefined. */
function inspectEndpointId(container: DockerContainerInspect | undefined, networkName: string): string | undefined {
  const endpointId = container?.NetworkSettings?.Networks?.[networkName]?.EndpointID;
  return typeof endpointId === "string" ? endpointId : undefined;
}

function startedAtOf(container: DockerContainerInspect | undefined): unknown {
  return (container?.State as Record<string, unknown> | undefined)?.StartedAt;
}

/**
 * Whether a launch beside live peers may skip the full validation, judged
 * under the held lifecycle lock over the stable match's own observation plus
 * one host-wide container inventory, each peer's exact proof plan, and one
 * fresh proxy inspect.
 *
 * The first failing check decides the reason, in this order: the lock (a lost
 * lock throws), cancellation (checked before every Docker call and after each
 * answer), unreadable evidence, then the registry, each record, the container
 * inventory, each peer's container proof, the session files, the consumers,
 * every internal-network participant, and the proxy incarnation. Never throws
 * except for a lost lock (or a stable match this process did not mint).
 */
export function tryWarmPeerValidation(input: WarmPeerProofInput): WarmPeerVerdict {
  const { lifecycleLock, expectedProject, effective } = input;
  lifecycleLock.assertHeld();
  const cancelled = (): boolean => input.signal?.aborted === true;
  if (cancelled()) return miss("cancelled");
  assertWarmValidation(input.stable);
  const evidence = input.stable.peerEvidence;
  if (!wellFormedEvidence(evidence)) return miss("evidence-unreadable");
  const proxyId = effective.proxyContainerId;
  if (input.stable.runtimeProof.proxyId !== proxyId) return miss("proxy-incarnation", "the stable match names another proxy");
  const internalNetwork = `${expectedProject.composeProject}_agent_internal`;

  // Condition 1: the registry, read in full under the lock.
  let records: SessionContainerRecordV2[];
  let registryDigest: string;
  try {
    records = listSessionContainerRecordsV2(input.stateDir, expectedProject);
    if (listQuarantinedSessionContainerRecordNamesV2(input.stateDir).length > 0) return miss("quarantined-records");
    registryDigest = sessionRegistryDigest(input.stateDir, expectedProject);
  } catch (error) {
    return miss("registry-unreadable", errorText(error));
  }
  if (records.length === 0) return miss("no-peers");
  try {
    if (readControlPlaneRebindTransaction(input.stateDir, expectedProject)) return miss("pending-rebind");
  } catch (error) {
    return miss("pending-rebind", `the rebind journal is unreadable: ${errorText(error)}`);
  }
  if (records.length > SESSION_CONTAINER_CONCURRENCY_CAP) return miss("peer-count-exceeded");

  // Condition 2: every record is an attached, live-owned peer of this control plane.
  for (const record of records) {
    if (record.state !== "attached" || record.containerId === undefined) return miss("peer-state", record.sessionId);
    let terminal: unknown;
    try {
      terminal = readSessionHostStatus(input.stateDir, record.sessionId)?.terminal;
    } catch (error) {
      return miss("peer-terminal-stamp", `${record.sessionId}: ${errorText(error)}`);
    }
    if (terminal !== undefined) return miss("peer-terminal-stamp", record.sessionId);
    const owner = sessionRecordOwnerLiveness(record, input.env);
    if (owner === "dead") return miss("peer-owner-dead", record.sessionId);
    if (owner === "unknown") return miss("peer-owner-unknown", record.sessionId);
    if (record.controlPlaneGenerationDigest !== effective.controlPlaneGenerationDigest
      || record.admissionContractEpoch !== effective.admissionContractEpoch) {
      return miss("peer-generation", record.sessionId);
    }
  }

  // Every Docker call below goes through this executor: cancellation is
  // checked before the call and again after its answer, and the inventory's
  // raw inspect bytes are kept so each peer's two snapshots can be compared.
  const inventoryInspects = new Map<string, DockerContainerInspect>();
  const executor: SessionContainerInventoryExecutor = (executable, args, options) => {
    if (cancelled()) throw new WarmPeerCancelled();
    const result = input.io.capture(executable, [...args], options ?? {});
    if (cancelled()) throw new WarmPeerCancelled();
    const inspecting = args[0] === "inspect" || (args[0] === "container" && args[1] === "inspect");
    if (inspecting && typeof result.stdout === "string" && result.stdout.length > 0) {
      try {
        const parsed: unknown = JSON.parse(result.stdout);
        if (Array.isArray(parsed)) {
          for (const entry of parsed) {
            const container = entry as DockerContainerInspect | null;
            if (container && typeof container.Id === "string") inventoryInspects.set(container.Id, container);
          }
        }
      } catch {
        // The inventory parser judges these bytes; unparseable output is its refusal.
      }
    }
    return result;
  };

  try {
    // Condition 3: one host-wide inventory, every record's exact container and nothing else.
    let classifications: ReturnType<typeof classifySessionContainerReconciliation>;
    try {
      classifications = classifySessionContainerReconciliation({
        expectedProject,
        records,
        containers: inspectSessionContainerInventory(executor, expectedProject, input.dockerOptions),
      });
    } catch (error) {
      if (error instanceof WarmPeerCancelled) throw error;
      return miss("inventory-unreadable", errorText(error));
    }
    for (const classification of classifications) {
      if (classification.kind === "record-only") return miss("peer-container-missing", classification.record.sessionId);
      if (classification.kind === "mismatch" || classification.kind === "unbound-created") {
        return miss("peer-container-mismatch", classification.record.sessionId);
      }
    }
    for (const classification of classifications) {
      if (classification.kind === "container-only" || classification.kind === "untrusted-container") {
        return miss("orphan-container", classification.container.containerId);
      }
    }
    // A record the classification did not name as matching is not accounted for.
    const matched = new Set(classifications.flatMap((classification) => (
      classification.kind === "matching" ? [classification.record.sessionId] : []
    )));
    const unmatched = records.find((record) => !matched.has(record.sessionId));
    if (unmatched) return miss("peer-container-missing", unmatched.sessionId);

    // Condition 4: each peer's container, on the internal network at its
    // address, proved by the same running proof restore runs, over the
    // stable observation's participant inspect, which must agree with the
    // inventory's inspect and with the network's endpoint map.
    const peers: WarmPeer[] = [];
    for (const record of records) {
      const containerId = record.containerId as string;
      const endpoint = evidence.internalNetworkContainers[containerId];
      if (!endpoint || endpointAddress(endpoint.IPv4Address) !== record.sourceIp) {
        return miss("peer-container-missing", record.sessionId);
      }
      const participant = evidence.participants.find((container) => container.Id === containerId);
      const inventory = inventoryInspects.get(containerId);
      if (!participant || !inventory) return miss("peer-container-mismatch", record.sessionId);
      const participantStartedAt = startedAtOf(participant);
      if (participant.Id !== inventory.Id
        || inspectEndpointId(participant, internalNetwork) !== endpoint.EndpointID
        || inspectEndpointId(inventory, internalNetwork) !== endpoint.EndpointID
        || typeof participantStartedAt !== "string"
        || participantStartedAt !== startedAtOf(inventory)) {
        return miss("peer-container-mismatch", record.sessionId);
      }
      if (cancelled()) throw new WarmPeerCancelled();
      let plan: ReturnType<typeof createRetainedSessionRebindProofPlan>;
      try {
        plan = createRetainedSessionRebindProofPlan({
          stateDir: input.stateDir,
          expectedProject,
          replacementRecord: record,
          candidateControlPlane: effective,
          candidateMaterialization: input.effectiveManifest,
          docker: input.docker,
          lifecycleLock,
          runfreeVersion: input.runfreeVersion,
        });
      } catch (error) {
        // A lost lock is a refusal, not an unproven peer.
        lifecycleLock.assertHeld();
        if (cancelled()) throw new WarmPeerCancelled();
        return miss("peer-container-unproven", `${record.sessionId}: ${errorText(error)}`);
      }
      if (cancelled()) throw new WarmPeerCancelled();
      try {
        validateSessionContainerInspect(JSON.stringify([participant]), plan, { kind: "active-running" });
      } catch (error) {
        return miss("peer-container-mismatch", `${record.sessionId}: ${errorText(error)}`);
      }
      peers.push({
        sessionId: record.sessionId,
        sessionPrincipal: record.sessionPrincipal,
        sessionIncarnation: record.sessionIncarnation,
        containerId,
        sourceIp: record.sourceIp,
        endpointId: endpoint.EndpointID,
      });
    }

    // Condition 5: exactly one well-formed, current session file per peer, and no other.
    const principals = new Set(records.map((record) => record.sessionPrincipal));
    for (const record of records) {
      const files = evidence.sessionFiles.filter((file) => !file.malformed && file.sessionKey === record.sessionPrincipal);
      if (files.length === 0) return miss("peer-file-missing", record.sessionId);
      if (files.length > 1) return miss("orphan-file", record.sessionId);
      const [file] = files as [ProxySessionFile];
      if (file.sourceIp !== record.sourceIp) return miss("peer-file-address", record.sessionId);
      if (file.eligible !== true) return miss("peer-file-ineligible", record.sessionId);
      if (file.wallActive !== true) return miss("peer-file-expired", record.sessionId);
    }
    const orphan = evidence.sessionFiles.find((file) => (
      file.malformed || file.sessionKey === undefined || !principals.has(file.sessionKey)
    ));
    if (orphan) return miss("orphan-file", orphan.name);

    // Condition 6: the proxy's consumers serve exactly these peers, on this policy.
    const peerAddresses = new Set(records.map((record) => record.sourceIp));
    const members = new Set(evidence.sessionSetMembers);
    if (members.size !== evidence.sessionSetMembers.length || members.size !== peerAddresses.size
      || [...peerAddresses].some((address) => !members.has(address))) {
      return miss("consumer-firewall");
    }
    if (evidence.requestProxyGeneration !== input.effectivePolicyGeneration) return miss("consumer-request-proxy");
    for (const record of records) {
      const assignment = evidence.ipAssignments[record.sourceIp];
      if (assignment?.state !== "ready" || assignment.sessionKey !== record.sessionPrincipal) {
        return miss("ip-assignment", record.sessionId);
      }
    }

    // Condition 7: every other internal-network participant is a peer's own
    // callback forwarder or an exactly recorded fixed forwarder.
    const peerByContainer = new Map(peers.map((peer) => [peer.containerId, peer]));
    const callbackForwarders = new Map<string, string>();
    for (const [id, endpoint] of Object.entries(evidence.internalNetworkContainers)) {
      if (id === proxyId || peerByContainer.has(id)) continue;
      const container = evidence.participants.find((participant) => participant.Id === id);
      if (!container) return miss("unaccounted-participant", id);
      const identity = describeInternalNetworkParticipant(container, expectedProject.projectId);
      const endpointAgrees = inspectEndpointId(container, internalNetwork) === endpoint.EndpointID;
      if (identity.kind === "ingress-forwarder" && identity.purpose === "mcp-callback") {
        const owner = identity.callbackSessionContainerId === undefined
          ? undefined
          : peerByContainer.get(identity.callbackSessionContainerId);
        if (!owner || owner.sessionId !== identity.callbackSessionId || identity.target !== owner.sourceIp
          || callbackForwarders.has(owner.containerId)) {
          return miss("callback-unbound", id);
        }
        if (!endpointAgrees) return miss("unaccounted-participant", id);
        callbackForwarders.set(owner.containerId, id);
        continue;
      }
      const fixed = evidence.fixedParticipants?.find((participant) => participant.id === id);
      if (identity.kind !== "ingress-forwarder" || !fixed || !endpointAgrees
        || fixed.ipv4 !== endpoint.IPv4Address || fixed.endpointId !== endpoint.EndpointID
        || fixed.role !== "ingress-forwarder" || fixed.purpose !== identity.purpose || fixed.target !== identity.target) {
        return miss("unaccounted-participant", id);
      }
      if (identity.target !== undefined && isSessionPoolSourceIp(identity.target) && !peerAddresses.has(identity.target)) {
        return miss("ingress-target-unaccounted", id);
      }
    }

    // Condition 8: the incarnation bracket. The stable observation's start
    // (taken before its batch) must be the start a fresh exact inspect shows
    // now, after the inventory, with the proxy still running.
    const reread = createDockerClient({ capture: executor }, input.dockerOptions).inspect([proxyId], { type: "container" });
    let startedAtAfter: string | undefined;
    try {
      const parsed: unknown = reread.status === 0 ? JSON.parse(reread.stdout) : undefined;
      if (Array.isArray(parsed) && parsed.length === 1) {
        const proxy = parsed[0] as DockerContainerInspect | null;
        const state = proxy?.State as Record<string, unknown> | undefined;
        if (proxy?.Id === proxyId && state?.Running === true && typeof state.StartedAt === "string") {
          startedAtAfter = state.StartedAt;
        }
      }
    } catch {
      // Unreadable is not the same incarnation.
    }
    // The lock is asserted after the last read: a verdict is never returned
    // from a judgement whose lock was lost while it read.
    lifecycleLock.assertHeld();
    if (startedAtAfter === undefined || startedAtAfter !== input.stable.proxyStartedAt) {
      return miss("proxy-incarnation");
    }

    const participantDigest = sha256Digest(stableJson(Object.entries(evidence.internalNetworkContainers)
      .map(([containerId, endpoint]) => ({ containerId, ipv4Address: endpoint.IPv4Address, endpointId: endpoint.EndpointID }))
      .sort((left, right) => left.containerId.localeCompare(right.containerId))));
    const validation: WarmPeerValidation = Object.freeze({
      kind: "warm-peer",
      stable: input.stable,
      proxyId,
      proxyStartedAt: input.stable.proxyStartedAt,
      proxyPid: input.stable.proxyPid,
      bootId: input.stable.bootId,
      registryDigest,
      peers: Object.freeze(peers.map((peer) => Object.freeze({
        ...peer,
        ...(callbackForwarders.has(peer.containerId) ? { callbackForwarderId: callbackForwarders.get(peer.containerId) as string } : {}),
      }))),
      participantDigest,
      observationEpoch: Object.freeze({
        startedAtBefore: input.stable.proxyStartedAt,
        startedAtAfter,
        observedAtEpochMs: Date.now(),
      }),
      lockOwnerToken: lifecycleLock.ownerToken,
      effectivePolicyGeneration: input.effectivePolicyGeneration,
      controlPlaneGenerationDigest: effective.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: effective.controlPlaneMaterializationDigest,
      admissionContractEpoch: effective.admissionContractEpoch,
    });
    minted.add(validation);
    return Object.freeze({ kind: "match", validation });
  } catch (error) {
    if (error instanceof WarmPeerCancelled) return miss("cancelled");
    throw error;
  }
}

/**
 * One-shot: true exactly once, for a minted validation whose every bound field
 * equals `binding`. Any refusal leaves the validation as it was.
 */
export function consumeWarmPeerValidation(value: unknown, binding: WarmPeerConsumptionBinding): boolean {
  if (!value || typeof value !== "object" || !minted.has(value)) return false;
  const validation = value as WarmPeerValidation;
  if (validation.kind !== "warm-peer"
    || validation.lockOwnerToken !== binding.lockOwnerToken
    || validation.proxyId !== binding.proxyId
    || validation.proxyStartedAt !== binding.proxyStartedAt
    || validation.registryDigest !== binding.registryDigest
    || validation.effectivePolicyGeneration !== binding.effectivePolicyGeneration
    || validation.controlPlaneGenerationDigest !== binding.controlPlaneGenerationDigest
    || validation.controlPlaneMaterializationDigest !== binding.controlPlaneMaterializationDigest
    || validation.admissionContractEpoch !== binding.admissionContractEpoch) {
    return false;
  }
  return minted.delete(value);
}
