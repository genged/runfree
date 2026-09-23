// Bringing the approvals record up to the current schema.
//
// Migration is an explicit step, never a side effect of reading: readers and
// status inspection never mutate records. It runs in the lifecycle-locked
// prelude of `withQuiescedProject` — and therefore of every typed desired-policy
// transaction, which goes through it — rather than on the launch path, because
// the approvals file is written from paths that never reach startup: the typed
// mutation families, the automatic-reduction path, `runfree image
// approve-context`, and both `policy approve` and `control approve`. Running it
// in the funnel makes "reaching any writer" imply "the record is already
// current".
//
// The recovery gate calls it too, because the funnel is not on the launch path
// before the gate. See `migrateControlApprovalRecord` below.

import type { ProjectInfo } from "../config.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import {
  classifyApprovalSource,
  CONTROL_APPROVAL_SELECTION_VERSION,
  readApprovalSource,
  verifyApprovedRuntimeSnapshot,
  verifyNetworkSnapshot,
  type ControlApprovalRecord,
  type ControlApprovalSelection,
} from "./approvals.ts";
import { observeCheckoutBinding } from "./checkout-binding.ts";
import { verifyApprovedImageSnapshot } from "./image-approval.ts";
import { withControlLock } from "./lock.ts";

export type ApprovalMigrationOutcome =
  /** No record exists yet; nothing to migrate. */
  | "absent"
  /** Already on the current schema (a mismatched record is current too). */
  | "current"
  /** Rewritten to the current schema, preserving every approval. */
  | "migrated"
  /**
   * A well-formed v1 record whose own hash no longer describes this checkout.
   * It carries no authority, it is left exactly as it is, and the recovery gate
   * owns its consent — the same disposition a v2 `mismatch` gets.
   */
  | "superseded"
  /** Cannot be migrated safely; the writers refuse and name the reclamation. */
  | "unmigratable";

/**
 * Migrate the approvals record if it needs it.
 *
 * This holds the control lock across read → verify → replace and re-compares
 * the bytes it read before replacing them, which is what makes it safe to call
 * both from the lifecycle-locked funnel prelude and from the recovery gate. The
 * gate needs it: every public launch reaches the gate *before* any funnel, so a
 * v1 record that only the funnel could migrate could never be started again.
 * Migration is still never a side effect of reading — both callers are paths
 * that own approval state, not readers of it.
 *
 * A mismatched or superseded record is deliberately left alone: it carries no
 * authority, and the recovery gate owns its consent. Migrating it would
 * silently rebind approvals granted against a different checkout.
 */
export function migrateControlApprovalRecord(projectRoot: string, project: ProjectInfo): ApprovalMigrationOutcome {
  return withControlLock(project, () => {
    const source = readApprovalSource(project);
    if (source === undefined) return "absent";
    const read = classifyApprovalSource(source, projectRoot, project);
    if (read.kind === "valid" || read.kind === "mismatch") return "current";
    if (read.kind === "superseded") return "superseded";
    if (read.kind !== "legacy") return "unmigratable";

    // Classification already proved this record's own hash still verifies under
    // its own contract, which is continuity of path, device, AND inode together
    // — strictly stronger than the v2 binding it becomes. No device value is
    // ever guessed: a bounded search over historical device numbers would
    // recover one extra prompt, once, for projects that rebooted before this
    // shipped, and is rejected on cost. Do not add it.
    const legacy = read.selection;

    // Verify every selected subject snapshot before rewriting the record. A
    // corrupt optional image snapshot blocks whole-selection migration: it is
    // never dropped while reporting migration as successful.
    try {
      for (const [subjectType, record] of Object.entries(legacy.subjects) as Array<
        [string, ControlApprovalRecord | undefined]
      >) {
        if (!record) continue;
        if (subjectType === "network-project" || subjectType === "network-local") {
          verifyNetworkSnapshot(project, subjectType, record.digest);
        } else if (subjectType === "runtime-isolation") {
          verifyApprovedRuntimeSnapshot(project, record.digest);
        } else {
          verifyApprovedImageSnapshot(project, record.digest);
        }
      }
    } catch {
      return "unmigratable";
    }

    // Digests, mechanisms, and approval timestamps are preserved exactly: this
    // is a re-expression of the same consent, not a fresh one.
    const next: ControlApprovalSelection = {
      schemaVersion: CONTROL_APPROVAL_SELECTION_VERSION,
      projectId: legacy.projectId,
      configVersion: legacy.configVersion,
      checkoutBinding: observeCheckoutBinding(projectRoot),
      subjects: legacy.subjects,
    };
    if (readApprovalSource(project) !== source) return "current";
    atomicReplaceFile(project.paths.controlApprovalsPath, `${JSON.stringify(next, null, 2)}\n`, 0o600);
    return "migrated";
  });
}
