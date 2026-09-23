import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
} from "./session-container.test-harness.ts";

import {
  SESSION_CONTAINER_LEASE_MAX_DURATION_MS,
  SESSION_CONTAINER_LEASE_MIN_DURATION_MS,
  assertSessionContainerTransitionV2,
  enumerateSessionContainerRecordsV2,
  listQuarantinedSessionContainerRecordNamesV2,
  sessionContainerQuarantineRoot,
  bindAllocatedSessionContainerIdV2,
  bindExactAllocatedSessionContainerRecordIdV2,
  createAllocatedSessionContainerRecordV2,
  listSessionContainerRecordsV2,
  mintSessionContainerLeaseV2,
  mintSessionIncarnation,
  mintSessionPrincipal,
  parseSessionContainerRecordV2,
  peekSessionContainerRecordsV2,
  readSessionContainerRecordV2,
  renewAttachedSessionContainerLeaseV2,
  replaceExactSessionContainerRecordV2,
  removeExactSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  sessionContainerLabels,
  sessionContainerName,
  sessionContainerRecordPath,
  sessionContainerRecordsRoot,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  transitionSessionContainerToRevokingV2,
  type SessionContainerRecordV2,
  type SessionContainerStateV2,
  writeSessionContainerRecordV2,
} from "./session-containers.ts";
import { createSessionLaunchTarget } from "./session-launch.ts";

const roots: string[] = [];
const PROJECT = { projectId: "0123456789ab", composeProject: "runfree-0123456789ab" };
const OTHER_PROJECT = { projectId: "abcdef012345", composeProject: "runfree-abcdef012345" };
const SESSION_ID = "rf-20260805-a1b2c3";
const INCARNATION = "1".repeat(64);
const PRINCIPAL = "2".repeat(64);
const CONTAINER_ID = "3".repeat(64);

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function temporaryState(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-containers-"));
  roots.push(root);
  return root;
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function allocated(overrides: Partial<SessionContainerRecordV2> = {}): SessionContainerRecordV2 {
  return {
    ...createAllocatedSessionContainerRecordV2({
      sessionId: SESSION_ID,
      sessionIncarnation: INCARNATION,
      sessionPrincipal: PRINCIPAL,
      displayName: "payments refactor",
      command: "codex",
      launch: createSessionLaunchTarget({
        path: "/usr/local/bin/codex",
        args: ["--dangerously-bypass-approvals-and-sandbox"],
        interactive: true,
        tty: true,
      }),
      sourceIp: "172.31.90.20",
      materialization: sessionAgentMaterializationFixture(),
      effectiveControlPlane: effectiveControlPlaneFixture(),
      hostPid: 1234,
      hostBootId: "linux:boot-id",
      hostProcessStart: "linux:123",
      createdAt: "2026-08-05T12:00:00.000Z",
    }),
    ...overrides,
  };
}

function state(record: SessionContainerRecordV2, next: SessionContainerStateV2): SessionContainerRecordV2 {
  if (next === "provisioning-running" || next === "attached") {
    return {
      ...record,
      state: next,
      containerId: record.containerId ?? CONTAINER_ID,
      admittedAt: record.admittedAt ?? "2026-08-05T12:00:10.000Z",
      leaseGeneration: record.leaseGeneration ?? "4".repeat(32),
      leaseExpiresAt: record.leaseExpiresAt ?? "2026-08-05T12:01:10.000Z",
    };
  }
  return { ...record, state: next };
}

describe("session-container lifecycle records", () => {
  test("mints independent opaque incarnation and principal values", () => {
    const incarnation = mintSessionIncarnation();
    const principal = mintSessionPrincipal();
    expect(incarnation).toMatch(/^[a-f0-9]{64}$/);
    expect(principal).toMatch(/^[a-f0-9]{64}$/);
    expect(incarnation).not.toBe(principal);
  });

  test("mints bounded leases consumed by preparation and renewal without replacing admission time", () => {
    const initialNow = Date.parse("2026-08-05T12:00:10.000Z");
    const initialLease = mintSessionContainerLeaseV2({
      durationMs: SESSION_CONTAINER_LEASE_MIN_DURATION_MS,
      nowEpochMs: () => initialNow,
      randomBytes: (size) => new Uint8Array(size).fill(0xab),
    });
    expect(initialLease).toEqual({
      admittedAt: "2026-08-05T12:00:10.000Z",
      leaseGeneration: "ab".repeat(32),
      leaseExpiresAt: "2026-08-05T12:00:11.000Z",
    });
    expect(Object.isFrozen(initialLease)).toBe(true);

    const bound = bindAllocatedSessionContainerIdV2(allocated(), CONTAINER_ID);
    const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
      transitionBoundAllocatedSessionContainerToProvisioningRunningV2(bound, initialLease),
    );
    const renewedLease = mintSessionContainerLeaseV2({
      durationMs: SESSION_CONTAINER_LEASE_MAX_DURATION_MS,
      nowEpochMs: () => Date.parse("2026-08-05T12:00:20.000Z"),
      randomBytes: (size) => new Uint8Array(size).fill(0xcd),
    });
    const renewed = renewAttachedSessionContainerLeaseV2(attached, renewedLease);

    expect(renewed).toMatchObject({
      admittedAt: initialLease.admittedAt,
      leaseGeneration: "cd".repeat(32),
      leaseExpiresAt: "2026-08-05T12:05:20.000Z",
    });
    expect(() => assertSessionContainerTransitionV2(attached, renewed)).not.toThrow();
  });

  test("rejects lease durations outside the exact inclusive bounds before consuming randomness", () => {
    const randomBytes = vi.fn((size: number) => new Uint8Array(size));
    for (const durationMs of [
      SESSION_CONTAINER_LEASE_MIN_DURATION_MS - 1,
      SESSION_CONTAINER_LEASE_MAX_DURATION_MS + 1,
      SESSION_CONTAINER_LEASE_MIN_DURATION_MS + 0.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      expect(() => mintSessionContainerLeaseV2({
        durationMs,
        nowEpochMs: () => 0,
        randomBytes,
      })).toThrow("lease duration must be an integer between");
    }
    expect(randomBytes).not.toHaveBeenCalled();
  });

  test("rejects invalid clocks and expiry overflow before consuming randomness", () => {
    const randomBytes = vi.fn((size: number) => new Uint8Array(size));
    for (const nowEpochMs of [
      -1,
      0.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.MAX_SAFE_INTEGER,
      8_640_000_000_000_000,
    ]) {
      expect(() => mintSessionContainerLeaseV2({
        durationMs: SESSION_CONTAINER_LEASE_MIN_DURATION_MS,
        nowEpochMs: () => nowEpochMs,
        randomBytes,
      })).toThrow(/lease (clock|expiry)/);
    }
    expect(randomBytes).not.toHaveBeenCalled();
  });

  test("uses exactly one injected 32-byte generation and preserves millisecond expiry arithmetic", () => {
    let generation = 0;
    const requestedSizes: number[] = [];
    const randomBytes = (size: number): Uint8Array => {
      requestedSizes.push(size);
      generation += 1;
      return new Uint8Array(size).fill(generation);
    };
    const nowEpochMs = Date.parse("2026-12-31T23:59:59.999Z");
    const first = mintSessionContainerLeaseV2({ durationMs: 1_001, nowEpochMs: () => nowEpochMs, randomBytes });
    const second = mintSessionContainerLeaseV2({ durationMs: 1_001, nowEpochMs: () => nowEpochMs, randomBytes });

    expect(requestedSizes).toEqual([32, 32]);
    expect(first.leaseGeneration).toBe("01".repeat(32));
    expect(second.leaseGeneration).toBe("02".repeat(32));
    expect(first.leaseGeneration).not.toBe(second.leaseGeneration);
    expect(first.leaseExpiresAt).toBe("2027-01-01T00:00:01.000Z");
    expect(Date.parse(first.leaseExpiresAt) - Date.parse(first.admittedAt)).toBe(1_001);

    for (const bytes of [new Uint8Array(31), new Uint8Array(33), [] as unknown as Uint8Array]) {
      expect(() => mintSessionContainerLeaseV2({
        durationMs: 1_001,
        nowEpochMs: () => nowEpochMs,
        randomBytes: () => bytes,
      })).toThrow("requires exactly 32 random bytes");
    }
  });

  test("uses the cryptographic default to mint independent opaque lease generations", () => {
    const options = {
      durationMs: SESSION_CONTAINER_LEASE_MIN_DURATION_MS,
      nowEpochMs: () => Date.parse("2026-08-05T12:00:10.000Z"),
    };
    const first = mintSessionContainerLeaseV2(options);
    const second = mintSessionContainerLeaseV2(options);

    expect(first.leaseGeneration).toMatch(/^[a-f0-9]{64}$/);
    expect(second.leaseGeneration).toMatch(/^[a-f0-9]{64}$/);
    expect(first.leaseGeneration).not.toBe(second.leaseGeneration);
  });

  test("accepts only the strict project-bound schema", () => {
    const record = allocated();
    expect(parseSessionContainerRecordV2(record)).toEqual(record);
    expect(Object.isFrozen(record.launchArgs)).toBe(true);
    expect(parseSessionContainerRecordV2({
      ...record,
      schemaVersion: 3,
      finalizedSessionImageRef: "runfree/session-agent:old",
      finalizedSessionImageInputDigest: digest("8"),
      finalizedSessionImageId: digest("9"),
    })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, schemaVersion: 1 })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, unknown: true })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, composeProject: OTHER_PROJECT.composeProject })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, containerName: "attacker-selected" })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, sessionPrincipal: record.sessionIncarnation })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, sourceIp: "172.31.090.20" })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, imageId: record.selectedAgentImageId })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, launchPath: "usr/local/bin/codex" })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, launchArgs: ["safe", "bad\u0000arg"] })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, interactive: false, tty: true })).toBeUndefined();
    expect(parseSessionContainerRecordV2({ ...record, command: "x".repeat(65) })).toBeUndefined();
  });

  test("keeps the lifecycle display command within the shared registry bound", () => {
    expect(parseSessionContainerRecordV2(allocated({ command: "x".repeat(64) }))).toBeDefined();
    expect(parseSessionContainerRecordV2(allocated({ command: "x".repeat(65) }))).toBeUndefined();
  });

  test("derives allocation authority only from strict materialization and effective control-plane evidence", () => {
    const manifest = sessionAgentMaterializationFixture();
    const controlPlane = effectiveControlPlaneFixture();
    const record = createAllocatedSessionContainerRecordV2({
      sessionId: SESSION_ID,
      sessionIncarnation: INCARNATION,
      sessionPrincipal: PRINCIPAL,
      displayName: "payments refactor",
      command: "codex",
      launch: createSessionLaunchTarget({
        path: "/usr/local/bin/codex",
        args: ["--dangerously-bypass-approvals-and-sandbox"],
        interactive: true,
        tty: true,
      }),
      sourceIp: "172.31.90.20",
      materialization: manifest,
      effectiveControlPlane: controlPlane,
      hostPid: 1234,
      createdAt: "2026-08-05T12:00:00.000Z",
      imageRef: "attacker.example/forged:latest",
      imageId: digest("0"),
    } as never);
    expect(record).toMatchObject({
      projectId: manifest.projectId,
      composeProject: manifest.composeProject,
      selectedAgentImageRef: manifest.selectedAgentImageRef,
      selectedAgentImageId: manifest.selectedAgentImageId,
      sessionAgentMaterializationDigest: manifest.sessionAgentMaterializationDigest,
      controlPlaneGenerationDigest: controlPlane.controlPlaneGenerationDigest,
      admissionContractEpoch: controlPlane.admissionContractEpoch,
    });
    expect("imageRef" in record).toBe(false);
    expect("imageId" in record).toBe(false);
    expect(() => createAllocatedSessionContainerRecordV2({
      ...record,
      launch: createSessionLaunchTarget({
        path: record.launchPath,
        args: record.launchArgs,
        interactive: record.interactive,
        tty: record.tty,
      }),
      materialization: { ...manifest, finalizedSessionImageId: digest("0") },
      effectiveControlPlane: controlPlane,
    } as never)).toThrow("materialization is invalid");
    expect(() => createAllocatedSessionContainerRecordV2({
      ...record,
      launch: createSessionLaunchTarget({
        path: record.launchPath,
        args: record.launchArgs,
        interactive: record.interactive,
        tty: record.tty,
      }),
      materialization: manifest,
      effectiveControlPlane: { ...controlPlane, admissionContractEpoch: controlPlane.admissionContractEpoch + 1 },
    } as never)).toThrow("incompatible admission epochs");
    expect(() => createAllocatedSessionContainerRecordV2({
      ...record,
      launch: {
        version: 1,
        path: record.launchPath,
        args: record.launchArgs,
        interactive: record.interactive,
        tty: record.tty,
      },
      materialization: manifest,
      effectiveControlPlane: controlPlane,
    } as never)).toThrow("canonical launch builder");
  });

  test("persists records under runtime/v2/session-containers with atomic single-link files", () => {
    const stateDir = temporaryState();
    const record = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, record);

    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    expect(filePath).toBe(path.join(stateDir, "runtime", "v2", "session-containers", `${SESSION_ID}.json`));
    expect(fs.lstatSync(filePath).nlink).toBe(1);
    expect(fs.statSync(filePath).mode & 0o777).toBe(0o600);
    expect(readSessionContainerRecordV2(stateDir, PROJECT, SESSION_ID)).toEqual(record);
    expect(listSessionContainerRecordsV2(stateDir, PROJECT)).toEqual([record]);
    expect(fs.readdirSync(sessionContainerRecordsRoot(stateDir))).toEqual([`${SESSION_ID}.json`]);
  });

  test("rejects malformed, duplicate-key, wrong-project, symlink, and hard-link state", () => {
    const stateDir = temporaryState();
    const record = allocated();
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, serializeSessionContainerRecordV2(record).replace("{", "{\"schemaVersion\":2,"));
    expect(() => readSessionContainerRecordV2(stateDir, PROJECT, SESSION_ID)).toThrow("malformed");

    fs.writeFileSync(filePath, serializeSessionContainerRecordV2(record));
    expect(() => readSessionContainerRecordV2(stateDir, OTHER_PROJECT, SESSION_ID)).toThrow("different project");

    fs.unlinkSync(filePath);
    fs.symlinkSync("missing", filePath);
    expect(() => writeSessionContainerRecordV2(stateDir, PROJECT, record)).toThrow("already exists");

    fs.unlinkSync(filePath);
    fs.writeFileSync(filePath, serializeSessionContainerRecordV2(record));
    fs.linkSync(filePath, `${filePath}.hardlink`);
    expect(() => writeSessionContainerRecordV2(stateDir, PROJECT, record)).toThrow("already exists");
  });

  test("publishes allocation once and never clobbers an existing lifecycle record", () => {
    const stateDir = temporaryState();
    const first = allocated();
    const colliding = allocated({ displayName: "colliding session" });
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    writeSessionContainerRecordV2(stateDir, PROJECT, first);
    const before = fs.readFileSync(filePath, "utf8");

    expect(() => writeSessionContainerRecordV2(stateDir, PROJECT, first)).toThrow("already exists");
    expect(fs.readFileSync(filePath, "utf8")).toBe(before);
    expect(() => writeSessionContainerRecordV2(stateDir, PROJECT, colliding)).toThrow("already exists");
    expect(fs.readFileSync(filePath, "utf8")).toBe(before);
    expect(readSessionContainerRecordV2(stateDir, PROJECT, SESSION_ID)).toEqual(first);
  });

  test("allows only ordered transitions and preserves lifecycle identity", () => {
    const allocatedRecord = allocated();
    const bound = bindAllocatedSessionContainerIdV2(allocatedRecord, CONTAINER_ID);
    const provisioning = state(bound, "provisioning-running");
    const attached = state(provisioning, "attached");
    const revoking = state(attached, "revoking");

    for (const [before, after] of [
      [bound, provisioning],
      [provisioning, attached],
      [attached, revoking],
    ] as const) {
      expect(() => assertSessionContainerTransitionV2(before, after)).not.toThrow();
    }

    expect(() => assertSessionContainerTransitionV2(allocatedRecord, attached)).toThrow("allocated -> attached");
    expect(() => assertSessionContainerTransitionV2(allocatedRecord, provisioning)).toThrow("must be bound");
    expect(() => assertSessionContainerTransitionV2(bound, { ...provisioning, sessionPrincipal: "9".repeat(64) })).toThrow("immutable sessionPrincipal");
    expect(() => assertSessionContainerTransitionV2(bound, {
      ...provisioning,
      selectedAgentImageId: digest("9"),
    })).toThrow("immutable selectedAgentImageId");
    expect(() => assertSessionContainerTransitionV2(provisioning, {
      ...attached,
      launchArgs: ["different"],
    })).toThrow("immutable launchArgs");
    expect(() => assertSessionContainerTransitionV2(provisioning, { ...attached, displayName: "renamed session" })).not.toThrow();
    expect(parseSessionContainerRecordV2({
      ...allocatedRecord,
      state: "revoking",
      admittedAt: "2026-08-05T12:00:10.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-08-05T12:01:10.000Z",
    })).toBeUndefined();
    expect(bound).toMatchObject({ state: "allocated", containerId: CONTAINER_ID });
    expect(() => bindAllocatedSessionContainerIdV2(bound, "5".repeat(64))).toThrow("already has");
  });

  test("constructs only the start-first transition sequence and valid revocation", () => {
    const allocatedRecord = allocated();
    const bound = bindAllocatedSessionContainerIdV2(allocatedRecord, CONTAINER_ID);
    const lease = {
      admittedAt: "2026-08-05T12:00:10.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-08-05T12:01:10.000Z",
    };
    const provisioning = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(bound, lease);
    const attached = transitionProvisioningRunningSessionContainerToAttachedV2(provisioning);
    const revokingBeforeCreate = transitionSessionContainerToRevokingV2(allocatedRecord);
    const revokingAfterProvisioning = transitionSessionContainerToRevokingV2(provisioning);
    const revokingAfterAdmission = transitionSessionContainerToRevokingV2(attached);

    expect(provisioning).toEqual({ ...bound, state: "provisioning-running", ...lease });
    expect(attached).toEqual({ ...provisioning, state: "attached" });
    expect(revokingBeforeCreate).toEqual({ ...allocatedRecord, state: "revoking" });
    expect(revokingAfterProvisioning).toEqual({ ...provisioning, state: "revoking" });
    expect(revokingAfterAdmission).toEqual({ ...attached, state: "revoking" });
    expect(revokingAfterAdmission).toMatchObject({
      containerId: attached.containerId,
      sessionIncarnation: attached.sessionIncarnation,
      sessionPrincipal: attached.sessionPrincipal,
      admittedAt: attached.admittedAt,
      leaseGeneration: attached.leaseGeneration,
      leaseExpiresAt: attached.leaseExpiresAt,
    });
    expect(() => transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocatedRecord, lease))
      .toThrow("bound allocated");
    expect(() => transitionBoundAllocatedSessionContainerToProvisioningRunningV2(provisioning, lease))
      .toThrow("bound allocated");
    expect(() => transitionProvisioningRunningSessionContainerToAttachedV2(bound))
      .toThrow("provisioning-running");
    expect(() => transitionSessionContainerToRevokingV2(revokingAfterProvisioning))
      .toThrow("already revoking");
  });

  test("compare-and-swap binds the Docker-created id to the exact allocated record", () => {
    const stateDir = temporaryState();
    const current = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, current);

    const bound = bindExactAllocatedSessionContainerRecordIdV2(
      stateDir,
      PROJECT,
      current,
      CONTAINER_ID,
    );

    expect(bound).toEqual({ ...current, containerId: CONTAINER_ID });
    expect(current.containerId).toBeUndefined();
    expect(readSessionContainerRecordV2(stateDir, PROJECT, SESSION_ID)).toEqual(bound);
    const persisted = fs.lstatSync(sessionContainerRecordPath(stateDir, SESSION_ID));
    expect(persisted.isFile()).toBe(true);
    expect(persisted.nlink).toBe(1);
    expect(persisted.mode & 0o777).toBe(0o600);
  });

  test("rejects stale allocated state without changing the persisted lifecycle record", () => {
    const stateDir = temporaryState();
    const stale = allocated();
    const persisted = allocated({ displayName: "newer lifecycle authority" });
    writeSessionContainerRecordV2(stateDir, PROJECT, persisted);
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    const before = fs.readFileSync(filePath, "utf8");

    expect(() => bindExactAllocatedSessionContainerRecordIdV2(
      stateDir,
      PROJECT,
      stale,
      CONTAINER_ID,
    )).toThrow("changed before container-id binding");

    expect(fs.readFileSync(filePath, "utf8")).toBe(before);
    expect(readSessionContainerRecordV2(stateDir, PROJECT, SESSION_ID)).toEqual(persisted);
  });

  test("rejects linked container-id binding targets before overwriting them", () => {
    const stateDir = temporaryState();
    const current = allocated();
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    writeSessionContainerRecordV2(stateDir, PROJECT, current);

    const hardLink = `${filePath}.hardlink`;
    fs.linkSync(filePath, hardLink);
    expect(() => bindExactAllocatedSessionContainerRecordIdV2(
      stateDir,
      PROJECT,
      current,
      CONTAINER_ID,
    )).toThrow("regular single-link");
    expect(fs.readFileSync(hardLink, "utf8")).toBe(serializeSessionContainerRecordV2(current));

    fs.unlinkSync(hardLink);
    fs.unlinkSync(filePath);
    const symlinkTarget = `${filePath}.symlink-target`;
    fs.writeFileSync(symlinkTarget, serializeSessionContainerRecordV2(current));
    fs.symlinkSync(symlinkTarget, filePath);
    expect(() => bindExactAllocatedSessionContainerRecordIdV2(
      stateDir,
      PROJECT,
      current,
      CONTAINER_ID,
    )).toThrow("regular single-link");
    expect(fs.readFileSync(symlinkTarget, "utf8")).toBe(serializeSessionContainerRecordV2(current));
  });

  test("replaces only an exact current lifecycle record with an ordered transition", () => {
    const stateDir = temporaryState();
    const bound = bindAllocatedSessionContainerIdV2(allocated(), CONTAINER_ID);
    const provisioning = transitionBoundAllocatedSessionContainerToProvisioningRunningV2(bound, {
      admittedAt: "2026-08-05T12:00:10.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-08-05T12:01:10.000Z",
    });
    writeSessionContainerRecordV2(stateDir, PROJECT, bound);

    replaceExactSessionContainerRecordV2(stateDir, PROJECT, bound, provisioning);

    expect(readSessionContainerRecordV2(stateDir, PROJECT, SESSION_ID)).toEqual(provisioning);
    expect(fs.statSync(sessionContainerRecordPath(stateDir, SESSION_ID)).mode & 0o777).toBe(0o600);
  });

  test("rejects stale, cross-project, and invalid-transition replacements without mutation", () => {
    const stateDir = temporaryState();
    const bound = bindAllocatedSessionContainerIdV2(allocated(), CONTAINER_ID);
    const provisioning = state(bound, "provisioning-running");
    writeSessionContainerRecordV2(stateDir, PROJECT, bound);
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    const before = fs.readFileSync(filePath, "utf8");

    expect(() => replaceExactSessionContainerRecordV2(
      stateDir,
      PROJECT,
      { ...bound, displayName: "stale name" },
      { ...provisioning, displayName: "stale name" },
    )).toThrow("changed before replacement");
    expect(fs.readFileSync(filePath, "utf8")).toBe(before);

    expect(() => replaceExactSessionContainerRecordV2(stateDir, OTHER_PROJECT, bound, provisioning))
      .toThrow("different project");
    expect(fs.readFileSync(filePath, "utf8")).toBe(before);

    expect(() => replaceExactSessionContainerRecordV2(stateDir, PROJECT, bound, state(bound, "attached")))
      .toThrow("allocated -> attached");
    expect(fs.readFileSync(filePath, "utf8")).toBe(before);
  });

  test("renews only attached lease authority with a new generation and later expiry", () => {
    const attached = state(
      state(bindAllocatedSessionContainerIdV2(allocated(), CONTAINER_ID), "provisioning-running"),
      "attached",
    );
    const renewed = renewAttachedSessionContainerLeaseV2(attached, {
      leaseGeneration: "5".repeat(32),
      leaseExpiresAt: "2026-08-05T12:02:10.000Z",
    });
    expect(renewed).toEqual({
      ...attached,
      leaseGeneration: "5".repeat(32),
      leaseExpiresAt: "2026-08-05T12:02:10.000Z",
    });
    expect(() => assertSessionContainerTransitionV2(attached, renewed)).not.toThrow();
    expect(() => renewAttachedSessionContainerLeaseV2(attached, {
      leaseGeneration: attached.leaseGeneration as string,
      leaseExpiresAt: "2026-08-05T12:02:10.000Z",
    })).toThrow("advance exact lease authority");
    expect(() => renewAttachedSessionContainerLeaseV2(attached, {
      leaseGeneration: "5".repeat(32),
      leaseExpiresAt: attached.leaseExpiresAt as string,
    })).toThrow("advance exact lease authority");
    expect(() => renewAttachedSessionContainerLeaseV2(state(attached, "revoking"), {
      leaseGeneration: "5".repeat(32),
      leaseExpiresAt: "2026-08-05T12:02:10.000Z",
    })).toThrow("requires an attached session container");
  });

  test("rejects link and non-file replacement targets before overwriting them", () => {
    const stateDir = temporaryState();
    const bound = bindAllocatedSessionContainerIdV2(allocated(), CONTAINER_ID);
    const provisioning = state(bound, "provisioning-running");
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    writeSessionContainerRecordV2(stateDir, PROJECT, bound);

    const hardLink = `${filePath}.hardlink`;
    fs.linkSync(filePath, hardLink);
    expect(() => replaceExactSessionContainerRecordV2(stateDir, PROJECT, bound, provisioning))
      .toThrow("regular single-link");
    expect(fs.readFileSync(hardLink, "utf8")).toBe(serializeSessionContainerRecordV2(bound));

    fs.unlinkSync(hardLink);
    fs.unlinkSync(filePath);
    const symlinkTarget = `${filePath}.symlink-target`;
    fs.writeFileSync(symlinkTarget, serializeSessionContainerRecordV2(bound));
    fs.symlinkSync(symlinkTarget, filePath);
    expect(() => replaceExactSessionContainerRecordV2(stateDir, PROJECT, bound, provisioning))
      .toThrow("regular single-link");
    expect(fs.readFileSync(symlinkTarget, "utf8")).toBe(serializeSessionContainerRecordV2(bound));

    fs.unlinkSync(filePath);
    fs.mkdirSync(filePath);
    expect(() => replaceExactSessionContainerRecordV2(stateDir, PROJECT, bound, provisioning))
      .toThrow("regular single-link");
    expect(fs.lstatSync(filePath).isDirectory()).toBe(true);
  });

  test("detects a path replacement race after reading the expected current record", () => {
    const stateDir = temporaryState();
    const bound = bindAllocatedSessionContainerIdV2(allocated(), CONTAINER_ID);
    const provisioning = state(bound, "provisioning-running");
    const filePath = sessionContainerRecordPath(stateDir, SESSION_ID);
    const attackerTarget = `${filePath}.attacker-target`;
    writeSessionContainerRecordV2(stateDir, PROJECT, bound);
    fs.writeFileSync(attackerTarget, serializeSessionContainerRecordV2(bound));

    const originalRandomBytes = crypto.randomBytes.bind(crypto);
    const randomBytes = vi.spyOn(crypto, "randomBytes").mockImplementationOnce(((size: number) => {
      fs.unlinkSync(filePath);
      fs.symlinkSync(attackerTarget, filePath);
      return originalRandomBytes(size);
    }) as typeof crypto.randomBytes);
    try {
      expect(() => replaceExactSessionContainerRecordV2(stateDir, PROJECT, bound, provisioning))
        .toThrow("regular single-link");
    } finally {
      randomBytes.mockRestore();
    }

    expect(fs.lstatSync(filePath).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(attackerTarget, "utf8")).toBe(serializeSessionContainerRecordV2(bound));
    expect(fs.readdirSync(path.dirname(filePath)).some((entry) => entry.endsWith(".tmp"))).toBe(false);
  });

  test("publishes exact non-Compose labels without exposing the session principal", () => {
    const record = allocated();
    const labels = sessionContainerLabels(record, "0.2.0");
    expect(labels).toEqual({
      "io.runfree.managed": "true",
      "io.runfree.container-role": "session-agent",
      "io.runfree.lifecycle-owner": "session",
      "io.runfree.label-schema": "1",
      "io.runfree.project-id": PROJECT.projectId,
      "io.runfree.compose-project": PROJECT.composeProject,
      "io.runfree.session-id": SESSION_ID,
      "io.runfree.session-incarnation": INCARNATION,
      "io.runfree.selected-agent-image-input-digest": record.selectedAgentImageInputDigest,
      "io.runfree.selected-agent-image-id": record.selectedAgentImageId,
      "io.runfree.session-agent-materialization-digest": record.sessionAgentMaterializationDigest,
      "io.runfree.session-agent-generation-digest": record.sessionAgentGenerationDigest,
      "io.runfree.session-template-digest": record.sessionTemplateDigest,
      "io.runfree.admission-contract-epoch": String(record.admissionContractEpoch),
      "io.runfree.version": "0.2.0",
    });
    expect(Object.keys(labels).some((label) => label.startsWith("com.docker.compose."))).toBe(false);
    expect(Object.values(labels)).not.toContain(PRINCIPAL);
    expect(sessionContainerName(PROJECT.projectId, SESSION_ID)).toBe(`runfree-${PROJECT.projectId}-session-${SESSION_ID}`);
  });

  test("removes only the exact unchanged project record", () => {
    const stateDir = temporaryState();
    const record = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, record);
    expect(() => removeExactSessionContainerRecordV2(stateDir, PROJECT, { ...record, command: "shell" })).toThrow("changed before removal");
    expect(fs.existsSync(sessionContainerRecordPath(stateDir, SESSION_ID))).toBe(true);
    expect(removeExactSessionContainerRecordV2(stateDir, PROJECT, record)).toBe(true);
    expect(removeExactSessionContainerRecordV2(stateDir, PROJECT, record)).toBe(false);
  });
});

describe("total record enumeration and quarantine", () => {
  const SECOND_SESSION_ID = "rf-20260805-d4e5f6";

  function secondRecord(): SessionContainerRecordV2 {
    const record = {
      ...allocated(),
      sessionId: SECOND_SESSION_ID,
      containerName: sessionContainerName(PROJECT.projectId, SECOND_SESSION_ID),
    };
    expect(parseSessionContainerRecordV2(record)).toBeTruthy();
    return record;
  }

  test("one unreadable record is quarantined, named, and does not hide the readable ones", () => {
    const stateDir = temporaryState();
    const readable = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, readable);
    const other = secondRecord();
    writeSessionContainerRecordV2(stateDir, PROJECT, other);
    const corruptName = "rf-20260805-zz9999.json";
    const corruptPath = path.join(sessionContainerRecordsRoot(stateDir), corruptName);
    fs.writeFileSync(corruptPath, "{\"schemaVersion\":", { mode: 0o600 });

    // The pre-fix behaviour was an exception from the scan; every readable
    // record must survive one bad byte.
    const enumeration = enumerateSessionContainerRecordsV2(stateDir, PROJECT);
    expect(enumeration.records).toEqual([readable, other]);
    expect(enumeration.quarantined).toHaveLength(1);
    const [quarantined] = enumeration.quarantined;
    expect(quarantined?.fileName).toBe(corruptName);
    expect(quarantined?.reason).toContain("malformed");

    // Quarantined, not deleted: the bytes survive as evidence beside the root,
    // under the original name plus a collision-proof suffix.
    expect(fs.existsSync(corruptPath)).toBe(false);
    expect(path.dirname(quarantined?.quarantinedPath ?? "")).toBe(sessionContainerQuarantineRoot(stateDir));
    expect(path.basename(quarantined?.quarantinedPath ?? "")).toMatch(
      new RegExp(`^${corruptName.replace(/\./g, "\\.")}\\.[0-9a-f]{8}$`),
    );
    expect(fs.readFileSync(quarantined?.quarantinedPath ?? "", "utf8")).toBe("{\"schemaVersion\":");
    const names = listQuarantinedSessionContainerRecordNamesV2(stateDir);
    expect(names).toHaveLength(1);
    expect(names[0]?.startsWith(`${corruptName}.`)).toBe(true);

    expect(listSessionContainerRecordsV2(stateDir, PROJECT)).toEqual([readable, other]);
    const repeated = enumerateSessionContainerRecordsV2(stateDir, PROJECT);
    expect(repeated.records).toEqual([readable, other]);
    expect(repeated.quarantined).toEqual([]);
  });

  test("quarantines invalid filenames, cross-project records, and mismatched filenames", () => {
    const stateDir = temporaryState();
    const readable = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, readable);
    const root = sessionContainerRecordsRoot(stateDir);
    fs.writeFileSync(path.join(root, "not-a-session.json"), "{}", { mode: 0o600 });
    const foreign = { ...allocated(), projectId: OTHER_PROJECT.projectId, composeProject: OTHER_PROJECT.composeProject };
    fs.writeFileSync(
      path.join(root, `${SECOND_SESSION_ID}.json`),
      `${JSON.stringify(foreign)}\n`,
      { mode: 0o600 },
    );

    const enumeration = enumerateSessionContainerRecordsV2(stateDir, PROJECT);
    expect(enumeration.records).toEqual([readable]);
    expect(enumeration.quarantined.map((entry) => entry.fileName).sort()).toEqual([
      "not-a-session.json",
      `${SECOND_SESSION_ID}.json`,
    ]);
    expect(listQuarantinedSessionContainerRecordNamesV2(stateDir).length).toBe(2);
  });

  test("returns empty partitions when no records were ever written", () => {
    const stateDir = temporaryState();
    expect(enumerateSessionContainerRecordsV2(stateDir, PROJECT)).toEqual({ records: [], quarantined: [] });
    expect(listQuarantinedSessionContainerRecordNamesV2(stateDir)).toEqual([]);
  });

  test("never unlinks a record that a concurrent writer replaced mid-quarantine", () => {
    const stateDir = temporaryState();
    const replacement = secondRecord();
    const entryPath = path.join(sessionContainerRecordsRoot(stateDir), `${SECOND_SESSION_ID}.json`);
    fs.mkdirSync(sessionContainerRecordsRoot(stateDir), { recursive: true, mode: 0o700 });
    fs.writeFileSync(entryPath, "{\"schemaVersion\":", { mode: 0o600 });

    // Interleave a concurrent writer inside the quarantine operation: while
    // the quarantine directory is being prepared — after the failed reads and
    // before the pathname is moved — a fresh valid record is renamed over the
    // same pathname. The inode pre-check must detect the replacement so the
    // fresh record is read rather than condemned for its predecessor's bytes.
    const realMkdir = fs.mkdirSync.bind(fs);
    const mkdirSpy = vi.spyOn(fs, "mkdirSync").mockImplementation((target, options) => {
      const created = realMkdir(target, options as fs.MakeDirectoryOptions);
      if (String(target).includes("session-containers-quarantine")) {
        const staged = `${entryPath}.staged`;
        fs.writeFileSync(staged, serializeSessionContainerRecordV2(replacement), { mode: 0o600 });
        fs.renameSync(staged, entryPath);
      }
      return created;
    });
    try {
      const enumeration = enumerateSessionContainerRecordsV2(stateDir, PROJECT);
      expect(enumeration.records).toEqual([replacement]);
      expect(enumeration.quarantined).toEqual([]);
    } finally {
      mkdirSpy.mockRestore();
    }
    expect(fs.readFileSync(entryPath, "utf8")).toBe(serializeSessionContainerRecordV2(replacement));
    expect(listQuarantinedSessionContainerRecordNamesV2(stateDir)).toEqual([]);
  });

  test("propagates transient filesystem errors instead of quarantining a possibly valid record", () => {
    const stateDir = temporaryState();
    const record = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, record);
    const recordPath = sessionContainerRecordPath(stateDir, SESSION_ID);

    // A host resource error describes the machine, not the bytes: it must
    // surface as the enumeration's failure, never as corruption of the record.
    const openSpy = vi.spyOn(fs, "openSync").mockImplementation(() => {
      throw Object.assign(new Error("EMFILE: too many open files"), { code: "EMFILE" });
    });
    try {
      expect(() => enumerateSessionContainerRecordsV2(stateDir, PROJECT)).toThrow("EMFILE");
    } finally {
      openSpy.mockRestore();
    }
    expect(fs.existsSync(recordPath)).toBe(true);
    expect(listQuarantinedSessionContainerRecordNamesV2(stateDir)).toEqual([]);
    expect(listSessionContainerRecordsV2(stateDir, PROJECT)).toEqual([record]);
  });

  test("fails the strict listing closed when quarantine cannot be persisted", () => {
    const stateDir = temporaryState();
    const readable = allocated();
    writeSessionContainerRecordV2(stateDir, PROJECT, readable);
    const corruptName = "rf-20260805-zz9999.json";
    fs.writeFileSync(path.join(sessionContainerRecordsRoot(stateDir), corruptName), "{", { mode: 0o600 });
    // A regular file where the quarantine directory belongs makes every
    // preservation attempt fail, which models filesystems where the move
    // cannot be persisted at all.
    fs.writeFileSync(sessionContainerQuarantineRoot(stateDir), "not a directory", { mode: 0o600 });

    // Total enumeration still reports both partitions, but marks the
    // quarantine as unpersisted...
    const enumeration = enumerateSessionContainerRecordsV2(stateDir, PROJECT);
    expect(enumeration.records).toEqual([readable]);
    expect(enumeration.quarantined).toHaveLength(1);
    expect(enumeration.quarantined[0]?.quarantinedPath).toBeUndefined();
    expect(fs.existsSync(path.join(sessionContainerRecordsRoot(stateDir), corruptName))).toBe(true);

    // ...and the strict listing used by authority paths refuses to present the
    // partial registry as complete, because quarantine-directory guards cannot
    // see an unpersisted quarantine.
    expect(() => listSessionContainerRecordsV2(stateDir, PROJECT))
      .toThrow("quarantine could not be persisted");
  });

  test("the read-only peek reports readable records and counts the unreadable without quarantining", () => {
    const stateDir = temporaryState();
    const record = state(allocated(), "attached");
    writeSessionContainerRecordV2(stateDir, PROJECT, record);
    const corruptPath = path.join(sessionContainerRecordsRoot(stateDir), "rf-20260805-zz9999.json");
    fs.writeFileSync(corruptPath, "not json", { mode: 0o600 });

    const peek = peekSessionContainerRecordsV2(stateDir, PROJECT);

    expect(peek.records.map((entry) => entry.sessionId)).toEqual([record.sessionId]);
    expect(peek.unreadable).toBe(1);
    // Strictly read-only: the corrupted record stays in place and no
    // quarantine directory is created, unlike the enumerating reader.
    expect(fs.readFileSync(corruptPath, "utf8")).toBe("not json");
    expect(fs.existsSync(sessionContainerQuarantineRoot(stateDir))).toBe(false);
  });

  test("the read-only peek treats an absent records root as an empty registry", () => {
    expect(peekSessionContainerRecordsV2(temporaryState(), PROJECT)).toEqual({ records: [], unreadable: 0 });
  });

  test("never replaces earlier quarantined evidence when the same name reoffends", () => {
    const stateDir = temporaryState();
    const root = sessionContainerRecordsRoot(stateDir);
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    const corruptName = "rf-20260805-zz9999.json";
    fs.writeFileSync(path.join(root, corruptName), "first", { mode: 0o600 });
    const first = enumerateSessionContainerRecordsV2(stateDir, PROJECT);
    fs.writeFileSync(path.join(root, corruptName), "second", { mode: 0o600 });
    const second = enumerateSessionContainerRecordsV2(stateDir, PROJECT);

    const names = listQuarantinedSessionContainerRecordNamesV2(stateDir);
    expect(names).toHaveLength(2);
    for (const name of names) expect(name.startsWith(`${corruptName}.`)).toBe(true);
    expect(fs.readFileSync(first.quarantined[0]?.quarantinedPath ?? "", "utf8")).toBe("first");
    expect(fs.readFileSync(second.quarantined[0]?.quarantinedPath ?? "", "utf8")).toBe("second");
  });
});
