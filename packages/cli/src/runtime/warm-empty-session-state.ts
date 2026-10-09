// The warm-empty session state.
//
// Startup reconciles the project's sessions under the lifecycle lock before a
// launch may be admitted: it makes the proxy's session files, the host's
// lifecycle records, and Docker's session containers agree. When a warm
// handoff launch's own evidence already shows all three are empty, there is
// nothing to make agree, so startup mints this state instead of reconciling
// and hands it to the launch's admission with the lock.
//
// The three pieces of evidence, all taken under the one held lock:
// - the warm proof's root batch listed no session file in the proxy, and the
//   internal network held no participant beside the proxy except ingress
//   forwarders (`WarmValidation.sessionState`);
// - the lifecycle registry, re-read here, holds no record and no quarantined
//   record;
// - one host-wide container listing shows nothing the reconciler would treat
//   as one of this project's sessions.
//
// The state selects a path; it authorizes nothing. It is sealed (only this
// module mints one, by identity), one-shot (admission consumes it), and bound
// to the empty registry digest, the proxy id and `StartedAt`, and the
// lifecycle lock owner token. A copy, a hand-built twin, a second use, or a
// binding that differs in any field is refused, and a refused state leaves
// admission on its full preflight, which reconciles exactly as before.

import type childProcess from "node:child_process";

import { sha256Digest, stableJson } from "../strict-primitives.ts";
import { sessionRegistryDigest } from "./launch-handoff.ts";
import {
  assertSessionContainersAbsent,
  observeSessionContainersAbsent,
} from "./session-container-reconciliation.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  type SessionContainerProjectIdentity,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeIO } from "./types.ts";
import { assertWarmValidation, type WarmValidation } from "./warm-proof.ts";

export type WarmEmptySessionState = Readonly<{
  kind: "warm-empty";
  registryDigest: string;
  proxyId: string;
  proxyStartedAt: string;
  lockOwnerToken: string;
}>;

/** `sessionRegistryDigest` of a registry that holds no record. */
export const EMPTY_SESSION_REGISTRY_DIGEST: string = sha256Digest(stableJson([]));

export type WarmEmptyVerdict =
  | Readonly<{ kind: "empty"; state: WarmEmptySessionState }>
  | Readonly<{ kind: "blocked"; reason: string }>;

const minted = new WeakSet<object>();

function blocked(reason: string): WarmEmptyVerdict {
  return Object.freeze({ kind: "blocked", reason });
}

/**
 * Mints the warm-empty state when this launch's evidence proves the project
 * holds no session state, or names the first piece of evidence that did not.
 *
 * Throws only when the lock is not held or the warm validation was not minted
 * by the warm-proof comparison: both mean the caller is not the startup that
 * proved anything.
 */
export function proveWarmEmptySessionState(input: Readonly<{
  warm: WarmValidation;
  io: RuntimeIO;
  stateDir: string;
  expectedProject: SessionContainerProjectIdentity;
  proxyId: string;
  proxyStartedAt: string;
  lifecycleLock: ProjectLifecycleLock;
  dockerOptions: childProcess.SpawnSyncOptions;
}>): WarmEmptyVerdict {
  input.lifecycleLock.assertHeld();
  assertWarmValidation(input.warm);
  if (input.warm.sessionState.kind !== "empty") return blocked(input.warm.sessionState.reason);
  // The listing was taken from this proxy incarnation, or it proves nothing
  // about the one admission will check against.
  if (input.warm.proxyStartedAt !== input.proxyStartedAt) return blocked("proxy-incarnation");
  if (listSessionContainerRecordsV2(input.stateDir, input.expectedProject).length > 0) {
    return blocked("registry-not-empty");
  }
  // After the enumeration above, which quarantines what it cannot read.
  if (listQuarantinedSessionContainerRecordNamesV2(input.stateDir).length > 0) return blocked("quarantined-records");
  if (sessionRegistryDigest(input.stateDir, input.expectedProject) !== EMPTY_SESSION_REGISTRY_DIGEST) {
    return blocked("registry-not-empty");
  }
  const observed = observeSessionContainersAbsent(
    (executable, args, options) => input.io.capture(executable, [...args], options ?? {}),
    input.expectedProject,
    input.dockerOptions,
  );
  if (observed.kind === "present") return blocked("session-containers-present");
  if (observed.kind === "unreadable") return blocked("session-containers-unreadable");
  assertSessionContainersAbsent(observed);
  input.lifecycleLock.assertHeld();
  const state: WarmEmptySessionState = Object.freeze({
    kind: "warm-empty",
    registryDigest: EMPTY_SESSION_REGISTRY_DIGEST,
    proxyId: input.proxyId,
    proxyStartedAt: input.proxyStartedAt,
    lockOwnerToken: input.lifecycleLock.ownerToken,
  });
  minted.add(state);
  return Object.freeze({ kind: "empty", state });
}

/** Whether `value` is a minted state not yet consumed. Does not consume it. */
export function isWarmEmptySessionState(value: unknown): value is WarmEmptySessionState {
  return typeof value === "object" && value !== null && minted.has(value);
}

/**
 * One-shot: true exactly once, for a minted state whose every bound field
 * equals `binding`. Any refusal leaves the state as it was.
 */
export function consumeWarmEmptySessionState(value: unknown, binding: Readonly<{
  registryDigest: string;
  proxyId: string;
  proxyStartedAt: string;
  lockOwnerToken: string;
}>): boolean {
  if (!isWarmEmptySessionState(value)) return false;
  if (value.kind !== "warm-empty"
    || value.registryDigest !== binding.registryDigest
    || value.proxyId !== binding.proxyId
    || value.proxyStartedAt !== binding.proxyStartedAt
    || value.lockOwnerToken !== binding.lockOwnerToken) {
    return false;
  }
  return minted.delete(value);
}
