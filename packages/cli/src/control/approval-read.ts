// The approvals record layer: what one saved selection is, and what reading it
// against the current checkout means.
//
// This file is pure — no filesystem, no project state — so classification is
// unit-testable without a project fixture and cannot form an import cycle with
// `approvals.ts`, which owns the I/O and the writers.

import { remedy } from "../remedies.ts";
import {
  compareCheckoutBinding,
  validateCheckoutBinding,
  type CheckoutBinding,
  type CheckoutBindingField,
} from "./checkout-binding.ts";
import { parseStrictJson } from "./strict-json.ts";
import type { ControlSubjectType } from "./subjects.ts";
import { ControlApprovalUnusableError } from "./refusals.ts";
import { assertAllowedKeys as exactKeys, isDigest, isRecord } from "../strict-primitives.ts";

export const CONTROL_APPROVAL_SELECTION_VERSION = 2 as const;
/**
 * Every selection version this release can still read. Published host manifests
 * record the version that was current when they were written, so a bump must
 * not make historical manifests unparseable.
 */
export const CONTROL_APPROVAL_HISTORICAL_VERSIONS = [1, 2] as const;
export type ControlApprovalSelectionVersion = typeof CONTROL_APPROVAL_HISTORICAL_VERSIONS[number];
export const CONTROL_APPROVAL_MECHANISMS = [
  "interactive",
  "digest-command",
  "typed-host-command",
  "automatic-reduction",
  "legacy-enforced-generation",
] as const;
export type ControlApprovalMechanism = typeof CONTROL_APPROVAL_MECHANISMS[number];
export type ControlApprovalRecord = {
  approvedAt: string;
  digest: string;
  mechanism: ControlApprovalMechanism;
};
export type ControlApprovalSelection = {
  checkoutBinding: CheckoutBinding;
  configVersion: number;
  projectId: string;
  schemaVersion: typeof CONTROL_APPROVAL_SELECTION_VERSION;
  subjects: Partial<Record<ControlSubjectType, ControlApprovalRecord>>;
};

/**
 * The v1 record: one digest over realpath, device, and inode together. It is
 * read only to migrate it. The device number's participation in that hash is
 * the incident this work fixes — a reboot that renumbers the volume invalidates
 * every approval, and the hash cannot say which field moved.
 */
export type ControlApprovalSelectionV1 = {
  checkoutFingerprint: string;
  configVersion: number;
  projectId: string;
  schemaVersion: 1;
  subjects: Partial<Record<ControlSubjectType, ControlApprovalRecord>>;
};

export type ControlApprovalBinding = {
  checkoutBinding: CheckoutBinding;
  configVersion: number;
  projectId: string;
};

export type ApprovalBindingMismatch = "project-scope" | "config-version" | CheckoutBindingField;

export type ControlApprovalRead =
  | { kind: "valid"; selection: ControlApprovalSelection }
  | { kind: "missing" }
  | { kind: "legacy"; selection: ControlApprovalSelectionV1 }
  | { kind: "superseded"; selection: ControlApprovalSelectionV1 }
  | { kind: "mismatch"; reason: ApprovalBindingMismatch; stored: ControlApprovalSelection }
  | { kind: "corrupt"; error: Error };

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.toISOString() === value;
}

function validateCommonFields(raw: Record<string, unknown>): {
  configVersion: number;
  projectId: string;
  subjects: Partial<Record<ControlSubjectType, ControlApprovalRecord>>;
} {
  if (typeof raw.projectId !== "string" || !/^[a-f0-9]{12}$/.test(raw.projectId)) throw new Error("control approval projectId is malformed");
  if (!Number.isSafeInteger(raw.configVersion) || Number(raw.configVersion) < 1) throw new Error("control approval configVersion is malformed");
  if (!isRecord(raw.subjects)) throw new Error("control approval subjects must be an object");
  const allowedSubjects: ControlSubjectType[] = ["network-project", "network-local", "runtime-isolation", "image-build"];
  exactKeys(raw.subjects, allowedSubjects, "control approval subjects");
  const subjects: Partial<Record<ControlSubjectType, ControlApprovalRecord>> = {};
  for (const [subjectType, value] of Object.entries(raw.subjects)) {
    if (!isRecord(value)) throw new Error(`control approval ${subjectType} must be an object`);
    exactKeys(value, ["approvedAt", "digest", "mechanism"], `control approval ${subjectType}`);
    if (!isDigest(value.digest)) throw new Error(`control approval ${subjectType} digest is malformed`);
    if (!canonicalTimestamp(value.approvedAt)) throw new Error(`control approval ${subjectType} approvedAt is malformed`);
    if (!CONTROL_APPROVAL_MECHANISMS.includes(value.mechanism as ControlApprovalMechanism)) {
      throw new Error(`control approval ${subjectType} mechanism is unsupported`);
    }
    subjects[subjectType as ControlSubjectType] = {
      approvedAt: value.approvedAt,
      digest: value.digest,
      mechanism: value.mechanism as ControlApprovalMechanism,
    };
  }
  return { projectId: raw.projectId, configVersion: Number(raw.configVersion), subjects };
}

export function validateControlApprovalSelection(raw: unknown): ControlApprovalSelection {
  if (!isRecord(raw)) throw new Error("control approval selection must be an object");
  exactKeys(raw, ["checkoutBinding", "configVersion", "projectId", "schemaVersion", "subjects"], "control approval selection");
  if (raw.schemaVersion !== CONTROL_APPROVAL_SELECTION_VERSION) throw new Error("unsupported control approval selection version");
  return {
    schemaVersion: CONTROL_APPROVAL_SELECTION_VERSION,
    checkoutBinding: validateCheckoutBinding(raw.checkoutBinding),
    ...validateCommonFields(raw),
  };
}

/** Parse a v1 record for migration. Never used to authorize anything. */
export function validateControlApprovalSelectionV1(raw: unknown): ControlApprovalSelectionV1 {
  if (!isRecord(raw)) throw new Error("control approval selection must be an object");
  exactKeys(raw, ["checkoutFingerprint", "configVersion", "projectId", "schemaVersion", "subjects"], "control approval selection");
  if (raw.schemaVersion !== 1) throw new Error("unsupported control approval selection version");
  if (!isDigest(raw.checkoutFingerprint)) throw new Error("control approval checkoutFingerprint is malformed");
  return {
    schemaVersion: 1,
    checkoutFingerprint: raw.checkoutFingerprint,
    ...validateCommonFields(raw),
  };
}

const MISMATCH_SENTENCE: Record<ApprovalBindingMismatch, string> = {
  "project-scope": "these saved approvals belong to another project scope",
  "config-version": "the project config generation changed since these approvals were saved",
  "resolved-root": "this path now resolves somewhere else than when these approvals were saved",
  "root-inode": "the directory at this path was replaced since these approvals were saved",
};

/**
 * Classify one approvals record against the current binding.
 *
 * `legacy` is its own kind, not a flavour of `mismatch`: "this record predates
 * the current schema" and "this checkout was replaced" are different events
 * with opposite correct handling, and collapsing them is unsafe.
 *
 * A well-formed v1 record splits in two, because those two also have opposite
 * correct handling. `legacy` still describes this checkout under its own
 * contract, so migration can carry every approval forward with no prompt.
 * `superseded` does not, so it carries no authority and belongs in recovery,
 * exactly like a v2 `mismatch` — collapsing the two is what wedged projects
 * that rebooted before the binding change shipped. A v1 record is still never
 * compared field-wise against the v2 binding: its hash is a different contract,
 * evaluated only against `legacyCheckoutFingerprint`, and it can never say
 * *which* field moved.
 *
 * `corrupt` is decided before any binding comparison: an unparseable record
 * says nothing about which checkout it belonged to.
 */
export function classifyControlApprovalSource(
  source: string | undefined,
  binding: ControlApprovalBinding,
  legacyCheckoutFingerprint: string,
): ControlApprovalRead {
  if (source === undefined) return { kind: "missing" };
  let parsed: unknown;
  try {
    parsed = parseStrictJson(source);
  } catch (error) {
    return { kind: "corrupt", error: error instanceof Error ? error : new Error(String(error)) };
  }
  const version = isRecord(parsed) ? parsed.schemaVersion : undefined;
  try {
    if (version === 1) {
      const legacy = validateControlApprovalSelectionV1(parsed);
      const describesThisCheckout = legacy.projectId === binding.projectId
        && legacy.configVersion === binding.configVersion
        && legacy.checkoutFingerprint === legacyCheckoutFingerprint;
      return { kind: describesThisCheckout ? "legacy" : "superseded", selection: legacy };
    }
    const selection = validateControlApprovalSelection(parsed);
    if (selection.projectId !== binding.projectId) return { kind: "mismatch", reason: "project-scope", stored: selection };
    if (selection.configVersion !== binding.configVersion) return { kind: "mismatch", reason: "config-version", stored: selection };
    const field = compareCheckoutBinding(selection.checkoutBinding, binding.checkoutBinding);
    if (field) return { kind: "mismatch", reason: field, stored: selection };
    return { kind: "valid", selection };
  } catch (error) {
    return { kind: "corrupt", error: error instanceof Error ? error : new Error(String(error)) };
  }
}

/**
 * The operator-facing refusal sentence for a non-valid read, with its
 * reclamation path. Every command named here comes from the remedy registry, so
 * `scripts/emitted-commands.test.ts` proves it still parses under the real app.
 */
export function approvalReadRefusal(read: ControlApprovalRead): string {
  switch (read.kind) {
    case "valid":
      throw new Error("a valid approval read has no refusal");
    case "missing":
      return `this checkout has no saved approvals\nreview them with: ${remedy.policyReview("project")}`;
    case "legacy":
      // Named command, not a description: starting the runtime crosses the
      // recovery gate, which migrates a record that still describes this
      // checkout without asking for anything. `policy review` is read-only and
      // cannot clear this state, so it must not be named here.
      return `the saved approvals predate this version of runfree\nmigrate them with: ${remedy.up()}`;
    case "superseded":
      return [
        "the saved approvals predate this version of runfree and no longer describe this checkout",
        `review them with: ${remedy.policyReview("project")}`,
      ].join("\n");
    case "mismatch":
      return `${MISMATCH_SENTENCE[read.reason]}\nreview them with: ${remedy.policyReview("project")}`;
    case "corrupt":
      return [
        `the saved approvals could not be read: ${read.error.message}`,
        `inspect the record with: ${remedy.policyStatus()}`,
        `after removing it, re-review with: ${remedy.policyReview("project")}`,
      ].join("\n");
  }
}

/**
 * The subject set a new selection starts from.
 *
 * On `mismatch` and `superseded` the base is empty: those subjects were
 * approved against a different binding and are never usable authority for this
 * one. On `legacy` and `corrupt` the writer refuses rather than guessing —
 * "not valid" must never collapse into "start from empty".
 *
 * The `legacy` refusal stays even though the recovery gate now migrates: a
 * writer reached without crossing either the gate or the lifecycle-locked
 * funnel must not overwrite a record whose approvals are still carryable.
 */
export function approvalWriteBase(
  read: ControlApprovalRead,
): Partial<Record<ControlSubjectType, ControlApprovalRecord>> {
  switch (read.kind) {
    case "valid":
      return read.selection.subjects;
    case "missing":
    case "mismatch":
    case "superseded":
      return {};
    case "legacy":
    case "corrupt":
      throw new ControlApprovalUnusableError(approvalReadRefusal(read), read);
  }
}
