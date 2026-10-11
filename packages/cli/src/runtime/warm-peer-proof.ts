// Warm launch validation beside live peer sessions: the contract only.
//
// A warm launch today skips the full runtime validation only when the project
// holds no lifecycle record (`warm-proof.ts`, `startup.ts` "live-sessions").
// This module is where a launch beside live peers will earn the same skip: a
// stable-fact warm match (`WarmValidation`) plus an exact, current accounting
// of every peer and every internal-network participant, judged under the held
// lifecycle lock within one proxy incarnation.
//
// Nothing here is implemented yet. `tryWarmPeerValidation` throws, so no
// caller can take a warm path beside peers, and `consumeWarmPeerValidation`
// refuses everything. The types are the interface the design fixes; the
// acceptance tests in `warm-peer-proof.test.ts` are expected to fail until the
// implementation lands.
//
// What a match will authorize, and nothing more: startup may skip the full
// validation, and may skip `restoreSameProxySessionAdmission` when the
// consumption binding still holds. It grants no restore, rebind, heartbeat
// renewal, eligibility widening, or control-plane selection, and it never
// enters the launch handoff.

import type * as childProcess from "node:child_process";

import type {
  ControlPlaneEffectiveSelectionV2,
  ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import type { RuntimeDocker } from "./docker.ts";
import type { ProxySessionFile } from "./session-reconcile.ts";
import type { SessionContainerProjectIdentity } from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { DockerContainerInspect, RuntimeIO } from "./types.ts";
import type { WarmValidation } from "./warm-proof.ts";

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
  /** sha256 of the sorted exact participant set: container id, IPv4, endpoint id. */
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

/**
 * Whether a launch beside live peers may skip the full validation. Not
 * implemented: throws, so no launch takes this path yet.
 */
export function tryWarmPeerValidation(_input: WarmPeerProofInput): WarmPeerVerdict {
  throw new Error("warm validation beside live peers is not implemented");
}

/**
 * One-shot: true exactly once, for a minted validation whose every bound field
 * equals `binding`. Nothing is minted yet, so this refuses everything.
 */
export function consumeWarmPeerValidation(_value: unknown, _binding: WarmPeerConsumptionBinding): boolean {
  return false;
}
