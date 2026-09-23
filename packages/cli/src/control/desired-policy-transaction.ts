// The one typed desired-policy transaction, shared by every typed mutation
// family (host, service, credential).
//
// The A2 invariant (2026-09-01 evolution-strategy decision) is an ORDER, not a
// step: capture -> approved-base -> atomic write -> re-read -> exact-match
// verify -> checkout re-check -> content-addressed approve, all inside the
// lifecycle lock. Each family used to own a private copy of that order, which
// meant three places for it to drift; the order now exists once, here, and a
// family supplies only its genuine difference — how it plans the next policy
// for its layer, and what it reports.
//
// Error text stays per-family on purpose: the nouns are read by operators and
// asserted by tests, so the transaction takes them as data rather than
// flattening them into one generic message.

import {
  canonicalDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { CliError } from "../errors.ts";
import { projectRunfreePath } from "../runfree-consumer-registry.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { safeReplaceProjectFile } from "../safe-fs.ts";
import {
  approveNetworkCandidate,
  readApprovedNetworkPolicy,
  readControlApprovalSelection,
  readOrApproveAuthorityFreeNetworkBase,
  type ControlApprovalSelection,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate, type DesiredPolicyCandidate } from "./candidates.ts";
import { withQuiescedProject } from "./quiesce.ts";
import { checkoutFingerprint, networkControlSubject, type ControlSubject } from "./subjects.ts";

/** Which of the two desired-policy layers a transaction edits. */
export type DesiredPolicyLayer = "local" | "project";

export type DesiredPolicyLayerSubjectType = "network-local" | "network-project";

export function desiredLayerSubjectType(layer: DesiredPolicyLayer): DesiredPolicyLayerSubjectType {
  return layer === "local" ? "network-local" : "network-project";
}

export function desiredLayerPolicy(candidate: DesiredPolicyCandidate, layer: DesiredPolicyLayer): DesiredNetworkPolicyJson {
  return layer === "local" ? candidate.local : candidate.project;
}

export function desiredLayerSubject(candidate: DesiredPolicyCandidate, layer: DesiredPolicyLayer): ControlSubject {
  return layer === "local" ? candidate.localSubject : candidate.projectSubject;
}

/**
 * The per-family nouns in the two approved-base refusals. Both messages end in
 * the same `runfree policy` hints, keyed off the layer.
 */
export type DesiredPolicyApprovalSubject = {
  /** Subject of the drift refusal, e.g. `local desired policy`. */
  driftSubject: string;
  layer: DesiredPolicyLayer;
  /** Subject of the missing-base refusal, e.g. `checkout-local policy`. */
  missingBaseSubject: string;
};

/**
 * Refuses a captured candidate whose layer does not exactly match its approved
 * base — the guard that makes agent-authored drift inert rather than adopted.
 *
 * Approving is opt-in because writing is the special case: a show-only query
 * must not create durable authority, and `readOrApproveAuthorityFreeNetworkBase`
 * auto-approves an authority-free scaffold, which would let a lookup that then
 * fails still persist an approval as a side effect.
 */
export function assertApprovedDesiredBase(
  context: RuntimeContext,
  candidate: DesiredPolicyCandidate,
  subject: DesiredPolicyApprovalSubject,
  options: { approveAuthorityFreeBase?: boolean } = {},
): void {
  const subjectType = desiredLayerSubjectType(subject.layer);
  const approved = options.approveAuthorityFreeBase === true
    ? readOrApproveAuthorityFreeNetworkBase(context.projectRoot, context.project, candidate, subjectType)
    : readApprovedNetworkPolicy(context.projectRoot, context.project, subjectType);
  if (!approved) {
    throw new CliError([
      `${subject.missingBaseSubject} has no approved base`,
      `review it with: runfree policy review --${subject.layer}`,
      `approve it with: runfree policy approve --${subject.layer}`,
    ].join("\n"));
  }
  if (canonicalDesiredNetworkPolicy(approved) !== canonicalDesiredNetworkPolicy(desiredLayerPolicy(candidate, subject.layer))) {
    throw new CliError([
      `${subject.driftSubject} changed outside a trusted Runfree transaction`,
      `review it with: runfree policy diff --${subject.layer}`,
      `approve it with: runfree policy approve --${subject.layer}`,
    ].join("\n"));
  }
}

/** What a family's planner must produce; families may return more fields. */
export type DesiredPolicyPlan = {
  changed: boolean;
  policy: DesiredNetworkPolicyJson;
};

export type DesiredPolicyTransaction<TPlan extends DesiredPolicyPlan, TResult> = {
  approvalSubject: DesiredPolicyApprovalSubject;
  /**
   * The family's genuine difference: derive the layer's next policy from the
   * captured candidate. Runs after the approved-base check and before the
   * write, so every refusal it raises still precedes the file mutation.
   */
  plan: (before: DesiredPolicyCandidate) => TPlan;
  /** Runs first inside the lock, before anything is captured. */
  prepare?: () => void;
  /** Runs under the lock after base/compile checks, before the desired write. */
  beforeWrite?: (before: DesiredPolicyCandidate, planned: TPlan) => undefined | (() => void);
  /** Optional synchronous store lock, acquired inside the lifecycle lock. */
  withWriteLock?: <T>(action: () => T) => T;
  /** Builds the family result from the verified candidate and the selection. */
  result: (outcome: {
    candidate: DesiredPolicyCandidate;
    plan: TPlan;
    selection: ControlApprovalSelection;
  }) => TResult;
  /**
   * When the plan changes nothing, reuse the existing approval selection
   * instead of re-approving an identical candidate. Absent means always
   * approve.
   */
  reuseSelectionWhenUnchanged?: { missingSelectionMessage: string };
  /**
   * Family noun in the checkout-identity refusal, e.g. `host` in "…during the
   * typed host transaction".
   */
  transactionNoun: string;
  /**
   * Subject of the exact-match refusal, e.g. `project policy write` in "…did
   * not produce the exact planned candidate".
   */
  writeSubject: string;
};

/**
 * Runs one typed desired-policy mutation under the project lifecycle lock.
 *
 * The order below IS the A2 agent-drift guarantee and must not be reordered:
 * the approval at the end publishes the exact in-memory candidate that was
 * re-read and verified under the lock, never a fresh read of the worktree, so
 * an agent edit landing in any window is refused or left as inert unapproved
 * drift. Approval stays inside the lock (released after this body returns) so a
 * concurrent mutation on the other layer cannot clobber the approval selection
 * between the write and its approval.
 */
export async function withDesiredPolicyTransaction<TPlan extends DesiredPolicyPlan, TResult>(
  context: RuntimeContext,
  io: RuntimeIO,
  transaction: DesiredPolicyTransaction<TPlan, TResult>,
): Promise<TResult> {
  const layer = transaction.approvalSubject.layer;
  const subjectType = desiredLayerSubjectType(layer);
  // `withQuiescedProject` migrates the approvals record in its locked prelude,
  // so every read below — including the reuse read near the end — is behind the
  // migration funnel and can never see a record predating the current schema.
  return withQuiescedProject(context, io, () => {
    transaction.prepare?.();
    const run = () => {
      const capturedCheckout = checkoutFingerprint(context.projectRoot);
      const before = captureDesiredPolicyCandidate(context.projectRoot, context.project.paths.controlCandidatesDir);
      assertApprovedDesiredBase(context, before, transaction.approvalSubject, { approveAuthorityFreeBase: true });
      const planned = transaction.plan(before);
      if (checkoutFingerprint(context.projectRoot) !== capturedCheckout) {
        throw new Error(`project checkout identity changed before the typed ${transaction.transactionNoun} write`);
      }
      let rollback: undefined | (() => void);
      let approved = false;
      try {
        if (transaction.beforeWrite) {
          rollback = transaction.beforeWrite(before, planned);
          // Host-state preparation can overlap an agent edit. Recheck the
          // captured base before replacing its file.
          const afterPreparation = captureDesiredPolicyCandidate(context.projectRoot, context.project.paths.controlCandidatesDir);
          assertApprovedDesiredBase(context, afterPreparation, transaction.approvalSubject);
          if (checkoutFingerprint(context.projectRoot) !== capturedCheckout) {
            throw new Error(`project checkout identity changed before the typed ${transaction.transactionNoun} write`);
          }
        }
        if (planned.changed) {
          safeReplaceProjectFile(
            context.projectRoot,
            projectRunfreePath(context.projectRoot, layer === "local" ? "networkPolicyLocal" : "networkPolicy"),
            `${canonicalDesiredNetworkPolicy(planned.policy)}\n`,
            0o600,
          );
        }
        const candidate = captureDesiredPolicyCandidate(context.projectRoot, context.project.paths.controlCandidatesDir);
        if (desiredLayerSubject(candidate, layer).digest !== networkControlSubject(subjectType, planned.policy).digest
          || canonicalDesiredNetworkPolicy(desiredLayerPolicy(candidate, layer)) !== canonicalDesiredNetworkPolicy(planned.policy)) {
          throw new Error(`${transaction.writeSubject} did not produce the exact planned candidate`);
        }
        if (checkoutFingerprint(context.projectRoot) !== capturedCheckout) {
          throw new Error(
            `project checkout identity changed during the typed ${transaction.transactionNoun} transaction; desired changes remain pending approval`,
          );
        }
        const reuse = transaction.reuseSelectionWhenUnchanged;
        let selection: ControlApprovalSelection;
        if (reuse && !planned.changed) {
          const reused = readControlApprovalSelection(context.projectRoot, context.project);
          if (!reused) throw new Error(reuse.missingSelectionMessage);
          selection = reused;
        } else {
          selection = approveNetworkCandidate(context.projectRoot, context.project, candidate, subjectType, "typed-host-command");
        }
        approved = true;
        return transaction.result({ candidate, plan: planned, selection });
      } catch (error) {
        if (!approved && rollback) {
          try { rollback(); } catch (rollbackError) {
            throw new AggregateError([error, rollbackError], "desired policy transaction and host-state rollback failed");
          }
        }
        throw error;
      }
    };
    return transaction.withWriteLock ? transaction.withWriteLock(run) : run();
  }, { allowLiveSessions: true });
}
