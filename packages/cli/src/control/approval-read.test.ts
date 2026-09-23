import { describe, expect, test } from "vitest";

import {
  approvalWriteBase,
  classifyControlApprovalSource,
  type ControlApprovalBinding,
  validateControlApprovalSelectionV1,
  type ControlApprovalRead,
  type ControlApprovalSelection,
} from "./approval-read.ts";
import type { CheckoutBinding } from "./checkout-binding.ts";

const checkoutBinding: CheckoutBinding = {
  resolvedRoot: "/Users/mg/code/capshelf",
  rootDevice: "16777229",
  rootInode: "166957006",
};

const binding: ControlApprovalBinding = {
  projectId: "0123456789ab",
  checkoutBinding,
  configVersion: 4,
};

const subjects = {
  "network-project": {
    approvedAt: "2026-09-16T00:00:00.000Z",
    digest: `sha256:${"b".repeat(64)}`,
    mechanism: "interactive" as const,
  },
};

function record(overrides: Record<string, unknown> = {}): string {
  return `${JSON.stringify({
    schemaVersion: 2,
    projectId: binding.projectId,
    checkoutBinding,
    configVersion: binding.configVersion,
    subjects,
    ...overrides,
  }, null, 2)}\n`;
}

/** The v1 fingerprint this checkout observes, as `checkoutFingerprintOf` derives it. */
const legacyFingerprint = `sha256:${"a".repeat(64)}`;

function v1Record(overrides: Record<string, unknown> = {}): string {
  return `${JSON.stringify({
    schemaVersion: 1,
    projectId: binding.projectId,
    checkoutFingerprint: legacyFingerprint,
    configVersion: binding.configVersion,
    subjects,
    ...overrides,
  }, null, 2)}\n`;
}

function classify(source: string | undefined, against: ControlApprovalBinding): ControlApprovalRead {
  return classifyControlApprovalSource(source, against, legacyFingerprint);
}

describe("control approval read classification", () => {
  test("an absent record is missing, never corrupt", () => {
    expect(classify(undefined, binding)).toEqual({ kind: "missing" });
  });

  test("a matching record is valid", () => {
    const read = classify(record(), binding);
    expect(read.kind).toBe("valid");
    if (read.kind !== "valid") throw new Error("unreachable");
    expect(read.selection.subjects["network-project"]?.mechanism).toBe("interactive");
  });

  // The reported incident: a reboot renumbered the volume, and every approval
  // became invalid because the device number was hashed into the identity.
  test("a changed device number alone is not a mismatch", () => {
    const read = classify(
      record({ checkoutBinding: { ...checkoutBinding, rootDevice: "999999999" } }),
      binding,
    );
    expect(read.kind).toBe("valid");
  });

  test("each compared field names its own reason", () => {
    expect(classify(record({ projectId: "ffffffffffff" }), binding))
      .toMatchObject({ kind: "mismatch", reason: "project-scope" });
    expect(classify(record({ configVersion: 3 }), binding))
      .toMatchObject({ kind: "mismatch", reason: "config-version" });
    expect(classify(record({ checkoutBinding: { ...checkoutBinding, resolvedRoot: "/elsewhere" } }), binding))
      .toMatchObject({ kind: "mismatch", reason: "resolved-root" });
    expect(classify(record({ checkoutBinding: { ...checkoutBinding, rootInode: "2" } }), binding))
      .toMatchObject({ kind: "mismatch", reason: "root-inode" });
  });

  test("a mismatch keeps the stored record for display", () => {
    const read = classify(
      record({ checkoutBinding: { ...checkoutBinding, rootInode: "2" } }),
      binding,
    );
    if (read.kind !== "mismatch") throw new Error("unreachable");
    expect(read.stored.subjects["network-project"]?.digest).toBe(`sha256:${"b".repeat(64)}`);
  });

  test("a v1 record whose own hash still holds is legacy, never a mismatch and never valid", () => {
    const read = classify(v1Record(), binding);
    expect(read.kind).toBe("legacy");
    if (read.kind !== "legacy") throw new Error("unreachable");
    // Its own hash is a different contract; only migration may evaluate it.
    expect(read.selection.checkoutFingerprint).toBe(legacyFingerprint);
    expect(read.selection.subjects["network-project"]?.digest).toBe(`sha256:${"b".repeat(64)}`);
  });

  // The wedge: before this split, every v1 record classified `legacy`, and
  // `legacy` refused everywhere. A project that rebooted before the binding
  // change shipped had no command left that could clear it.
  test("a v1 record whose own hash no longer holds is superseded, not legacy", () => {
    const read = classify(v1Record({ checkoutFingerprint: `sha256:${"c".repeat(64)}` }), binding);
    expect(read.kind).toBe("superseded");
    if (read.kind !== "superseded") throw new Error("unreachable");
    // The subjects are kept for display; they are never usable authority.
    expect(read.selection.subjects["network-project"]?.digest).toBe(`sha256:${"b".repeat(64)}`);
  });

  test("a v1 record whose project scope or config generation moved is superseded", () => {
    expect(classify(v1Record({ projectId: "ffffffffffff" }), binding).kind).toBe("superseded");
    expect(classify(v1Record({ configVersion: 3 }), binding).kind).toBe("superseded");
  });

  // Downgrade across this schema change is unsupported: an older CLI must
  // refuse a v2 record, not reinterpret one. Its reader is the v1 validator,
  // which this release still ships for migration.
  test("the older reader refuses a v2 record instead of reinterpreting it", () => {
    // `2a` gave the binding a new key name precisely so that a stale reader
    // fails on a missing key rather than misreading a present one.
    expect(() => validateControlApprovalSelectionV1(JSON.parse(record())))
      .toThrow("control approval selection has unknown fields: checkoutBinding");
    // And the version itself refuses, so a record that merely claims a future
    // schema never parses under the old contract either.
    expect(() => validateControlApprovalSelectionV1(JSON.parse(v1Record({ schemaVersion: 2 }))))
      .toThrow("unsupported control approval selection version");
  });

  test("a malformed record is corrupt, never missing and never a mismatch", () => {
    const read = classify("{ not json", binding);
    expect(read.kind).toBe("corrupt");
    if (read.kind !== "corrupt") throw new Error("unreachable");
    expect(read.error).toBeInstanceOf(Error);

    expect(classify(record({ subjects: { bogus: {} } }), binding).kind).toBe("corrupt");
    expect(classify(record({ schemaVersion: 99 }), binding).kind).toBe("corrupt");
    // A v1 record that is itself malformed stays corrupt, not legacy.
    expect(classify(v1Record({ checkoutFingerprint: "not-a-digest" }), binding).kind).toBe("corrupt");
  });

  test("binding validation rejects unknown keys and unbounded fields", () => {
    expect(classify(record({ checkoutBinding: { ...checkoutBinding, extra: 1 } }), binding).kind).toBe("corrupt");
    expect(classify(record({ checkoutBinding: { ...checkoutBinding, rootInode: "12x" } }), binding).kind).toBe("corrupt");
    expect(classify(record({ checkoutBinding: { ...checkoutBinding, resolvedRoot: "relative/path" } }), binding).kind).toBe("corrupt");
  });

  test("a corrupt record whose binding also differs is corrupt, not a mismatch", () => {
    const read = classify(
      record({ checkoutBinding: { ...checkoutBinding, rootInode: "2" }, subjects: { bogus: {} } }),
      binding,
    );
    expect(read.kind).toBe("corrupt");
  });
});

describe("approval write base", () => {
  const selection = (overrides: Partial<ControlApprovalSelection> = {}): ControlApprovalSelection => ({
    schemaVersion: 2,
    projectId: binding.projectId,
    checkoutBinding,
    configVersion: 4,
    subjects,
    ...overrides,
  });

  test("a valid record carries its subjects forward", () => {
    expect(approvalWriteBase({ kind: "valid", selection: selection() })).toEqual(subjects);
  });

  test("a missing record starts empty", () => {
    expect(approvalWriteBase({ kind: "missing" })).toEqual({});
  });

  test("a mismatched record starts empty and never carries its subjects forward", () => {
    expect(approvalWriteBase({
      kind: "mismatch",
      reason: "root-inode",
      stored: selection({ checkoutBinding: { ...checkoutBinding, rootInode: "2" } }),
    })).toEqual({});
  });

  const v1Selection = {
    schemaVersion: 1 as const,
    projectId: binding.projectId,
    checkoutFingerprint: legacyFingerprint,
    configVersion: 4,
    subjects,
  };

  test("legacy and corrupt refuse in the writer, each with its own reclamation path", () => {
    // The named reclamation has to be a command that clears the state. `policy
    // review` is read-only, so naming it here would point at a wedge; the gate
    // `runfree up` crosses is what migrates the record.
    expect(() => approvalWriteBase({ kind: "legacy", selection: v1Selection }))
      .toThrow("predate this version of runfree\nmigrate them with: runfree up");
    expect(() => approvalWriteBase({ kind: "corrupt", error: new Error("payload hash is corrupt") }))
      .toThrow("payload hash is corrupt");
  });

  test("a superseded v1 record starts empty in the writer, exactly as a mismatch does", () => {
    expect(approvalWriteBase({
      kind: "superseded",
      selection: { ...v1Selection, checkoutFingerprint: `sha256:${"c".repeat(64)}` },
    })).toEqual({});
  });
});
