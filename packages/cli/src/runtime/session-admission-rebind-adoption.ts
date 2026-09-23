import { isDeepStrictEqual } from "node:util";

import { remedy } from "../remedies.ts";
import {
  parseEffectiveControlPlaneSelectionV2,
  readEffectiveControlPlaneV2,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneGenerationV2,
  type ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import { readControlPlaneRebindTransaction, type ControlPlaneRebindPhase } from "./control-plane-rebind.ts";
import {
  assertAttachedSessionContainerControlPlaneRebindV2,
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  readSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";

/**
 * Client-side authority rebind for a session that outlives a compatible proxy
 * rebind.
 *
 * A launch process holds its admission control plane from launch time: proxy
 * container id, agent-internal network, control digest, and epoch. A durable
 * compatible rebind replaces the proxy and rebinds this session's lifecycle
 * record to the candidate control plane while the container keeps running.
 * The launch-time authority is then dead — the proxy it names is gone — so
 * lease renewal and revocation would either fail or, worse, act on the current
 * registry with a control plane that no longer selects it.
 *
 * This module lets the trusted foreground driver adopt exactly that rebind:
 * the durable effective control plane, plus this session's rebound record, and
 * nothing else. Every other divergence between held and durable authority is a
 * refusal before any durable side effect.
 */

export type AdoptedSessionControlPlaneRebind = Readonly<{
  effectiveControlPlane: ControlPlaneEffectiveSelectionV2;
  candidateMaterialization: ControlPlaneMaterializationManifestV2;
  record: SessionContainerRecordV2;
}>;

export class SessionReplacementPendingError extends Error {
  constructor(readonly transactionId: string, readonly phase: ControlPlaneRebindPhase) {
    super(
      `a control-plane rebind is pending at ${phase}; session authority cannot converge until it completes; `
      + `run \`${remedy.up()}\` to resume it, or \`${remedy.destroyForce()}\` to clear a stuck one`,
    );
    this.name = "SessionReplacementPendingError";
  }
}

/**
 * Refuses while a control-plane rebind transaction is journaled.
 *
 * A journal means the project's proxy is mid-replacement: the durable state a
 * caller is about to read, mutate, or converge against is exactly what the
 * rebind (or its recovery) is moving. Every entry point that touches session
 * authority runs this before its first effect, so the refusal costs nothing,
 * and both of its reclamations are the same either way: `runfree up` resumes
 * the rebind, and `runfree destroy --force` clears one that is stuck.
 */
export function assertNoPendingControlPlaneReplacement(
  stateDir: string,
  project: SessionContainerProjectIdentity,
): void {
  const pending = readControlPlaneRebindTransaction(stateDir, project);
  if (pending) throw new SessionReplacementPendingError(pending.transactionId, pending.phase);
}

/**
 * Adopts one completed compatible control-plane rebind for one attached
 * session, or returns undefined when the durable effective control plane is
 * still the held one. Reads only; the caller swaps its held authority to the
 * returned values. Throws — before any durable write — for every divergence
 * that is not an exact completed compatible rebind of this session:
 * a pending rebind journal, another project, a changed admission epoch or
 * control topology, a moved agent-internal network, a missing or non-attached
 * registry record, or a registry record that differs from the held one in
 * anything besides the rebind writer's exact fields (control digest plus a
 * freshly advanced lease).
 */
export function adoptCompatibleSessionControlPlaneRebind(input: Readonly<{
  stateDir: string;
  lifecycleLock: ProjectLifecycleLock;
  expectedProject: SessionContainerProjectIdentity;
  boundControlPlane: ControlPlaneEffectiveSelectionV2;
  launchControlPlaneGeneration: ControlPlaneGenerationV2;
  attachedRecord: SessionContainerRecordV2;
}>): AdoptedSessionControlPlaneRebind | undefined {
  input.lifecycleLock.assertHeld();
  assertNoPendingControlPlaneReplacement(input.stateDir, input.expectedProject);
  const bound = parseEffectiveControlPlaneSelectionV2(input.boundControlPlane);
  if (!bound) throw new Error("session control-plane adoption holds an invalid bound selection");
  const held = parseSessionContainerRecordV2(input.attachedRecord);
  if (!held || held.state !== "attached") {
    throw new Error("session control-plane adoption requires an attached lifecycle record");
  }
  assertSessionContainerRecordProject(held, input.expectedProject);
  if (held.controlPlaneGenerationDigest !== bound.controlPlaneGenerationDigest
    || held.admissionContractEpoch !== bound.admissionContractEpoch) {
    throw new Error("session control-plane adoption holds a record outside its bound control plane");
  }
  const durable = readEffectiveControlPlaneV2(input.stateDir);
  input.lifecycleLock.assertHeld();
  if (!durable) throw new Error("session control-plane adoption requires a durable effective control plane");
  if (isDeepStrictEqual(bound, durable.selection)) return undefined;
  // A pending journal means a rebind crashed mid-transaction. Its recovery
  // owns the registry and may re-mint replacement batches, so a surviving
  // client must neither adopt nor mutate anything until that settles.
  if (durable.selection.projectId !== input.expectedProject.projectId
    || durable.selection.composeProject !== input.expectedProject.composeProject) {
    throw new Error("durable effective control plane belongs to a different project");
  }
  // Only the exact compatible transition is adoptable: same admission epoch,
  // same control topology, and the same agent-internal network this session's
  // container is attached to. Anything else is an incompatible update the
  // rebind contract itself refuses to perform under live sessions.
  if (durable.selection.admissionContractEpoch !== bound.admissionContractEpoch
    || durable.manifest.generation.admissionContractEpoch !== bound.admissionContractEpoch
    || durable.manifest.generation.controlPlaneTopologyDigest
      !== input.launchControlPlaneGeneration.controlPlaneTopologyDigest
    || durable.selection.networkIds.agentInternal !== bound.networkIds.agentInternal) {
    throw new Error("durable effective control plane is not a compatible rebind of the session's launch authority");
  }
  const observed = readSessionContainerRecordV2(input.stateDir, input.expectedProject, held.sessionId);
  input.lifecycleLock.assertHeld();
  if (!observed || observed.state !== "attached") {
    throw new Error("compatible control-plane rebind retained no attached record for this session");
  }
  // The registry record must be exactly the held record advanced by the rebind
  // writer, and not one other field. What "advanced" means is the writer's own
  // batch shape: the durable control digest alone, because the record's lease
  // is neither this session's authority nor renewed by anything. Proven by
  // construction, then by the shared rebind transition assert. A rebind that
  // replaces the proxy container under an unchanged control generation leaves
  // the record untouched, and the exact-record equality above is the whole of
  // that proof.
  const expected = parseSessionContainerRecordV2({
    ...held,
    controlPlaneGenerationDigest: durable.selection.controlPlaneGenerationDigest,
  });
  if (!expected
    || serializeSessionContainerRecordV2(observed) !== serializeSessionContainerRecordV2(expected)) {
    throw new Error("retained session record is not an exact rebind of the held lifecycle authority");
  }
  if (observed.controlPlaneGenerationDigest !== held.controlPlaneGenerationDigest) {
    assertAttachedSessionContainerControlPlaneRebindV2(held, observed);
  }
  return Object.freeze({
    effectiveControlPlane: durable.selection,
    candidateMaterialization: durable.manifest,
    record: observed,
  });
}
