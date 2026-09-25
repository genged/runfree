import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import type { ProjectInfo } from "../config.ts";
import { publishImmutableDirectory } from "../generation-kernel.ts";
import { projectHash } from "../project-identity.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import { verifyDesiredPolicyCandidate, type DesiredPolicyCandidate } from "./candidates.ts";
import { observeCheckoutBinding } from "./checkout-binding.ts";
import { withControlLock } from "./lock.ts";
import { parseStrictJson } from "./strict-json.ts";
import {
  approvalReadRefusal,
  approvalWriteBase,
  classifyControlApprovalSource,
  CONTROL_APPROVAL_SELECTION_VERSION,
  type ControlApprovalBinding,
  type ControlApprovalMechanism,
  type ControlApprovalRead,
  type ControlApprovalRecord,
  type ControlApprovalSelection,
} from "./approval-read.ts";
import { ControlApprovalUnusableError } from "./refusals.ts";
import {
  checkoutFingerprintOf,
  controlDigest,
  networkControlSubject,
  runtimeIsolationControlSubject,
  type ControlSubject,
  type ControlSubjectType,
} from "./subjects.ts";
import { assertAllowedKeys as exactKeys, isDigest, isRecord } from "../strict-primitives.ts";

export {
  CONTROL_APPROVAL_HISTORICAL_VERSIONS,
  CONTROL_APPROVAL_MECHANISMS,
  CONTROL_APPROVAL_SELECTION_VERSION,
  validateControlApprovalSelection,
  validateControlApprovalSelectionV1,
} from "./approval-read.ts";
export type {
  ApprovalBindingMismatch,
  ControlApprovalMechanism,
  ControlApprovalRead,
  ControlApprovalRecord,
  ControlApprovalSelection,
  ControlApprovalSelectionV1,
  ControlApprovalSelectionVersion,
} from "./approval-read.ts";

export type ApprovedRuntimeIsolation = {
  agentIp: string;
  dependencyOverlays: string;
  proxyIp: string;
  subnet: string;
  writeApprovalHoldSeconds: number;
};




export function selectionBinding(projectRoot: string, project: ProjectInfo): ControlApprovalBinding {
  return {
    projectId: projectHash(projectRoot),
    checkoutBinding: observeCheckoutBinding(projectRoot),
    configVersion: project.config.version,
  };
}

export function readApprovalSource(project: ProjectInfo): string | undefined {
  try {
    return fs.readFileSync(project.paths.controlApprovalsPath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

/**
 * Read the approvals record and report what it is. This never throws for a
 * record that merely carries no authority; callers route on `kind` and, for a
 * mismatch, on `reason`.
 */
export function readControlApprovalRecord(projectRoot: string, project: ProjectInfo): ControlApprovalRead {
  return classifyApprovalSource(readApprovalSource(project), projectRoot, project);
}

/**
 * Classify against one observation of the checkout.
 *
 * The v2 binding and the v1 fingerprint are derived from the same
 * `observeCheckoutBinding` call, so a v1 and a v2 record are always classified
 * against the same checkout even if the directory is replaced mid-read.
 */
export function classifyApprovalSource(
  source: string | undefined,
  projectRoot: string,
  project: ProjectInfo,
): ControlApprovalRead {
  const binding = selectionBinding(projectRoot, project);
  return classifyControlApprovalSource(source, binding, checkoutFingerprintOf(binding.checkoutBinding));
}

/**
 * The strict reader: any record that is not `valid` is a refusal here, and a
 * `missing` one is `undefined`. Call sites that must recover rather than refuse
 * use `readControlApprovalRecord` and route on `kind`.
 */
export function readControlApprovalSelection(
  projectRoot: string,
  project: ProjectInfo,
): ControlApprovalSelection | undefined {
  const read = readControlApprovalRecord(projectRoot, project);
  if (read.kind === "valid") return read.selection;
  if (read.kind === "missing") return undefined;
  throw new ControlApprovalUnusableError(approvalReadRefusal(read), read);
}


export function approvedSubjectDirectory(project: ProjectInfo, subjectType: ControlSubjectType, digest: string): string {
  if (!isDigest(digest)) throw new Error("approved subject digest is malformed");
  return path.join(project.paths.controlApprovedDir, subjectType, digest.slice("sha256:".length));
}

function snapshotContents(policy: DesiredNetworkPolicyJson) {
  return { policyContents: `${canonicalDesiredNetworkPolicy(policy)}\n` };
}

export function publishNetworkSnapshot(project: ProjectInfo, subject: ControlSubject, policy: DesiredNetworkPolicyJson): void {
  const target = approvedSubjectDirectory(project, subject.subjectType, subject.digest);
  publishImmutableDirectory({
    parent: path.dirname(target),
    name: path.basename(target),
    // The digest-named directory plus the canonical policy file IS the
    // snapshot: the verifier recomputes the subject digest from these bytes,
    // so a stored subject/manifest copy would only duplicate that proof.
    files: { "network-policy.json": snapshotContents(policy).policyContents },
    directoryMode: 0o700,
    fileMode: 0o400,
    parentMode: 0o700,
    tempPrefix: ".approved-",
    parentSetup: "when-creating",
    verify: () => verifyNetworkSnapshot(project, subject.subjectType as "network-local" | "network-project", subject.digest),
  });
}

function readRegularSingleLink(filePath: string, label: string): string {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`${label} is not a regular single-link file`);
  return fs.readFileSync(filePath, "utf8");
}

export function verifyNetworkSnapshot(
  project: ProjectInfo,
  subjectType: "network-local" | "network-project",
  digest: string,
): DesiredNetworkPolicyJson {
  // The digest recompute IS the proof: the canonical policy bytes must
  // rederive the exact subject digest the directory is named for. Extra files
  // written by older releases (subject.json, manifest.json) are ignored, so
  // approvals recorded before the store slimmed down keep verifying.
  const directory = approvedSubjectDirectory(project, subjectType, digest);
  const policyContents = readRegularSingleLink(path.join(directory, "network-policy.json"), "approved network policy");
  const policy = validateDesiredNetworkPolicy(parseStrictJson(policyContents));
  const subject = networkControlSubject(subjectType, policy);
  if (subject.digest !== digest) throw new Error("approved network snapshot has the wrong subject digest");
  if (snapshotContents(policy).policyContents !== policyContents) {
    throw new Error("approved network snapshot payload hash is corrupt");
  }
  return policy;
}

/**
 * Preserve the evidence a replacement would otherwise destroy.
 *
 * `atomicReplaceFile` overwrites the record in place, so without this copy the
 * subjects a mismatched record loses would be gone. The previous implementation
 * renamed the live selector on a nominally read-only path, before any consent,
 * and nothing ever read the renamed file back — worse recoverability than this,
 * and a mutation where none was expected. A failed copy throws, so it refuses
 * before the selection changes.
 */
export function copyAsideControlApprovalRecord(project: ProjectInfo): void {
  const source = project.paths.controlApprovalsPath;
  if (!fs.existsSync(source)) return;
  const copy = `${source}.superseded-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  atomicReplaceFile(copy, fs.readFileSync(source), 0o400);
}

/**
 * Approve one or more subjects in a single lock-held read → verify → replace.
 *
 * The control lock is held across the whole sequence and the on-disk bytes are
 * re-read and compared before the replacement, because `atomicReplaceFile`
 * prevents torn records but not lost updates. The lifecycle lock does not cover
 * this: `captureQuiescedDesiredPolicyCandidate` acquires and releases it inside
 * itself, so every approval write after a capture runs outside it. Without the
 * re-read, a losing writer under the empty-base rule can land a record built
 * from a subject set it never saw.
 *
 * Route on the read kind, never on message text. `approvalWriteBase` refuses
 * for `legacy` and `corrupt` and returns an empty base for `mismatch`, so
 * "not valid" can never collapse into "start from empty" by accident.
 *
 * `options.afterRead` exists only so a test can interleave a concurrent write
 * deterministically. Production callers never pass it.
 */
export function selectSubjectApprovals(
  projectRoot: string,
  project: ProjectInfo,
  subjects: readonly ControlSubject[],
  mechanism: ControlApprovalMechanism,
  now: Date,
  options: { afterRead?: () => void } = {},
): ControlApprovalSelection {
  if (subjects.length === 0) throw new Error("an approval selection requires at least one subject");
  return withControlLock(project, () => {
    const source = readApprovalSource(project);
    const read = classifyApprovalSource(source, projectRoot, project);
    const base = approvalWriteBase(read);
    options.afterRead?.();
    if (readApprovalSource(project) !== source) {
      throw new Error("the approvals record changed while it was being approved; retry the review");
    }
    if (read.kind !== "valid") copyAsideControlApprovalRecord(project);
    const nextSubjects: Partial<Record<ControlSubjectType, ControlApprovalRecord>> = { ...base };
    for (const subject of subjects) {
      const existing = base[subject.subjectType];
      nextSubjects[subject.subjectType] = existing?.digest === subject.digest
        ? existing
        : { digest: subject.digest, approvedAt: now.toISOString(), mechanism };
    }
    const next: ControlApprovalSelection = {
      schemaVersion: CONTROL_APPROVAL_SELECTION_VERSION,
      ...selectionBinding(projectRoot, project),
      subjects: nextSubjects,
    };
    atomicReplaceFile(project.paths.controlApprovalsPath, `${JSON.stringify(next, null, 2)}\n`, 0o600);
    return next;
  });
}

export function selectSubjectApproval(
  projectRoot: string,
  project: ProjectInfo,
  subject: ControlSubject,
  mechanism: ControlApprovalMechanism,
  now: Date,
): ControlApprovalSelection {
  return selectSubjectApprovals(projectRoot, project, [subject], mechanism, now);
}

export function approveNetworkCandidate(
  projectRoot: string,
  project: ProjectInfo,
  candidate: DesiredPolicyCandidate,
  subjectType: "network-local" | "network-project",
  mechanism: ControlApprovalMechanism,
  now = new Date(),
): ControlApprovalSelection {
  verifyDesiredPolicyCandidate(candidate);
  const policy = subjectType === "network-project" ? candidate.project : candidate.local;
  const subject = subjectType === "network-project" ? candidate.projectSubject : candidate.localSubject;
  if (subject.subjectType !== subjectType) throw new Error("candidate subject type mismatch");
  publishNetworkSnapshot(project, subject, policy);

  return selectSubjectApproval(projectRoot, project, subject, mechanism, now);
}

export function readApprovedNetworkPolicy(
  projectRoot: string,
  project: ProjectInfo,
  subjectType: "network-local" | "network-project",
): DesiredNetworkPolicyJson | undefined {
  const selection = readControlApprovalSelection(projectRoot, project);
  const record = selection?.subjects[subjectType];
  if (!record) return undefined;
  return verifyNetworkSnapshot(project, subjectType, record.digest);
}

export function readOrApproveAuthorityFreeNetworkBase(
  projectRoot: string,
  project: ProjectInfo,
  candidate: DesiredPolicyCandidate,
  subjectType: "network-local" | "network-project",
): DesiredNetworkPolicyJson | undefined {
  const approved = readApprovedNetworkPolicy(projectRoot, project, subjectType);
  if (approved) return approved;
  const policy = subjectType === "network-project" ? candidate.project : candidate.local;
  if (canonicalDesiredNetworkPolicy(policy) !== canonicalDesiredNetworkPolicy({ version: 2, hosts: [] })) {
    return undefined;
  }
  approveNetworkCandidate(projectRoot, project, candidate, subjectType, "automatic-reduction");
  return readApprovedNetworkPolicy(projectRoot, project, subjectType);
}

/**
 * A display identity for the approval set. Its value changes with the schema
 * bump; nothing depends on it but the status line (`control/status.ts` ->
 * `commands/policy.ts`), so no authority moves with it.
 */
export function approvalSetDigest(selection: ControlApprovalSelection): string {
  return controlDigest({
    schemaVersion: CONTROL_APPROVAL_SELECTION_VERSION,
    subjectType: "approval-set",
    projectId: selection.projectId,
    checkoutBinding: selection.checkoutBinding,
    subjects: Object.fromEntries(Object.entries(selection.subjects).sort().map(([type, record]) => [type, record?.digest])),
  });
}

function runtimeSnapshotContents(subject: ControlSubject): string {
  return `${JSON.stringify(subject.payload, null, 2)}\n`;
}

export function verifyApprovedRuntimeSnapshot(project: ProjectInfo, digest: string): ApprovedRuntimeIsolation {
  const directory = approvedSubjectDirectory(project, "runtime-isolation", digest);
  const contents = readRegularSingleLink(path.join(directory, "subject.json"), "approved runtime-isolation subject");
  const payload = parseStrictJson(contents);
  if (!isRecord(payload)) throw new Error("approved runtime-isolation payload is malformed");
  exactKeys(payload, ["compilerVersion", "runtime", "schemaVersion", "subjectType"], "approved runtime-isolation payload");
  if (payload.schemaVersion !== 1 || payload.subjectType !== "runtime-isolation" || typeof payload.compilerVersion !== "string") {
    throw new Error("approved runtime-isolation payload identity is malformed");
  }
  if (!isRecord(payload.runtime)) throw new Error("approved runtime-isolation runtime is malformed");
  exactKeys(
    payload.runtime,
    ["agentIp", "dependencyOverlays", "proxyIp", "subnet", "writeApprovalHoldSeconds"],
    "approved runtime-isolation runtime",
  );
  if (typeof payload.runtime.subnet !== "string"
    || typeof payload.runtime.proxyIp !== "string"
    || typeof payload.runtime.agentIp !== "string"
    || typeof payload.runtime.dependencyOverlays !== "string"
    || !Number.isSafeInteger(payload.runtime.writeApprovalHoldSeconds)) {
    throw new Error("approved runtime-isolation runtime is malformed");
  }
  // The subject payload is the store; its digest recompute against the
  // directory name is the proof. A manifest written by an older release is
  // ignored rather than required.
  if (controlDigest(payload) !== digest) throw new Error("approved runtime-isolation snapshot has the wrong digest");
  return payload.runtime as ApprovedRuntimeIsolation;
}

export function publishRuntimeSnapshot(project: ProjectInfo, subject: ControlSubject): void {
  const target = approvedSubjectDirectory(project, "runtime-isolation", subject.digest);
  publishImmutableDirectory({
    parent: path.dirname(target),
    name: path.basename(target),
    files: { "subject.json": runtimeSnapshotContents(subject) },
    directoryMode: 0o700,
    fileMode: 0o400,
    parentMode: 0o700,
    tempPrefix: ".approved-",
    parentSetup: "when-creating",
    verify: () => verifyApprovedRuntimeSnapshot(project, subject.digest),
  });
}

export function approveRuntimeIsolationControl(
  projectRoot: string,
  project: ProjectInfo,
  mechanism: ControlApprovalMechanism,
  now = new Date(),
): ControlApprovalSelection {
  const subject = runtimeIsolationControlSubject(project.config);
  return approveRuntimeIsolationSubject(projectRoot, project, subject, mechanism, now);
}

export function approveRuntimeIsolationSubject(
  projectRoot: string,
  project: ProjectInfo,
  subject: ControlSubject,
  mechanism: ControlApprovalMechanism,
  now = new Date(),
): ControlApprovalSelection {
  if (subject.subjectType !== "runtime-isolation") throw new Error("runtime-isolation approval subject type mismatch");
  publishRuntimeSnapshot(project, subject);
  return selectSubjectApproval(projectRoot, project, subject, mechanism, now);
}

export function readApprovedRuntimeIsolation(
  projectRoot: string,
  project: ProjectInfo,
): ApprovedRuntimeIsolation | undefined {
  const selection = readControlApprovalSelection(projectRoot, project);
  const record = selection?.subjects["runtime-isolation"];
  return record ? verifyApprovedRuntimeSnapshot(project, record.digest) : undefined;
}
