import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import { sessionFilePath } from "@runfree/runtime-contracts/session-file";

import { sha256Digest } from "./component-state.ts";
import {
  controlPlaneEffectiveSelectionPathV2,
  createControlPlaneGenerationV2,
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import {
  controlPlaneRebindTransactionPath,
  createControlPlaneRebindTransaction,
  prepareControlPlaneRebindTransaction,
} from "./control-plane-rebind.ts";
import {
  runFencedProjectDestroy,
  runFencedProjectRebuildTeardown,
  type FencedProjectDestroyInput,
  type FencedProjectRebuildTeardownInput,
} from "./destroy.ts";
import type { RuntimeDocker } from "./docker.ts";
import {
  SESSION_TEST_PROJECT,
  SESSION_TEST_PROJECT_ROOT,
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  sessionTestProjectInfo,
} from "./session-container.test-harness.ts";
import {
  enumerateSessionContainerRecordsV2,
  listQuarantinedSessionContainerRecordNamesV2,
  sessionContainerRecordPath,
  sessionContainerQuarantineRoot,
  sessionContainerRecordsRoot,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { sessionHostStatusPath, writeSessionHostStatus } from "./session-host-status.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

// The fixture registry is pinned to SESSION_TEST_PROJECT, so project identity
// derivation is pinned to the same values rather than to a hash of the
// temporary directory the test happens to run in.
vi.mock("../project-identity.ts", async (importOriginal) => {
  const original = await importOriginal<typeof import("../project-identity.ts")>();
  return {
    ...original,
    projectHash: () => "0123456789ab",
    composeProjectName: () => "runfree-0123456789ab",
  };
});

const COMPOSE_PROJECT = SESSION_TEST_PROJECT.composeProject;
const SESSION_CONTAINER_ID = "3".repeat(64);
const PROXY_CONTAINER_ID = "7".repeat(64);
const RESIDUE_CONTAINER_ID = "c".repeat(64);

const LEASE = Object.freeze({
  admittedAt: "2026-08-14T11:55:00.000Z",
  leaseGeneration: "e".repeat(32),
  leaseExpiresAt: "2026-08-14T12:05:00.000Z",
});
const DURING_LEASE_MS = Date.parse("2026-08-14T12:00:00.000Z");
const AFTER_LEASE_MS = Date.parse("2026-08-14T13:00:00.000Z");

// Above the PID maximum on supported hosts, so ownership is provably dead.
const DEAD_PID = 4_194_305;

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function temporaryState(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-destroy-"));
  roots.push(root);
  return root;
}

function attachedRecord(
  overrides: Partial<SessionContainerRecordV2> = {},
  options: { hostPid?: number } = {},
): SessionContainerRecordV2 {
  const allocated = sessionContainerRecordFixture({
    containerId: SESSION_CONTAINER_ID,
    // The owner defaults to provably dead so plain destroy may proceed; a
    // "live" case passes this process's pid, whose ownership the lease then
    // arbitrates because the record carries no boot identity.
    overrides: { hostPid: options.hostPid ?? DEAD_PID },
  });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, LEASE),
  );
  return { ...attached, ...overrides };
}

type Harness = Readonly<{
  input: FencedProjectDestroyInput;
  stateDir: string;
  calls: string[][];
  composeDownCalls: string[];
  beforeTeardown: ReturnType<typeof vi.fn>;
  clearResidue: () => void;
}>;

function harness(options: {
  force?: boolean;
  nowEpochMs?: number;
  project?: string | undefined;
  proxyId?: string | undefined;
  residueIds?: string[];
  residueRunning?: boolean;
  failSessionRemove?: boolean;
  failProxyStop?: boolean;
  failResidueStop?: boolean;
  agentSessions?: unknown[];
  composeNetworkRemains?: boolean;
  composeImageRemains?: boolean;
  inspectOperationalError?: boolean;
  composeDownFailsWhileResidueRemains?: boolean;
  composeDownFails?: boolean;
} = {}): Harness {
  const stateDir = temporaryState();
  const projectInfo = sessionTestProjectInfo();
  const context = {
    projectRoot: SESSION_TEST_PROJECT_ROOT,
    project: {
      ...projectInfo,
      paths: { ...projectInfo.paths, stateDir, sessionsDir: path.join(stateDir, "sessions") },
    },
    runtimeRoot: path.join(stateDir, "runtime-root"),
    env: {},
  } as unknown as RuntimeContext;

  const calls: string[][] = [];
  const composeDownCalls: string[] = [];
  const removedContainers = new Set<string>();
  let residueIds = [...(options.residueIds ?? [])];

  const capture = (command: string, args: string[]): CaptureResult => {
    calls.push([command, ...args]);
    const ok = (stdout = ""): CaptureResult => ({ status: 0, stdout, stderr: "" });
    const fail = (stderr: string): CaptureResult => ({ status: 1, stdout: "", stderr });
    if (command !== "docker") throw new Error(`unexpected command: ${command}`);
    if (args[0] === "container" && args[1] === "stop") {
      if (options.failProxyStop) return fail("simulated stop failure");
      if (options.failResidueStop) {
        const targets = args.slice(args.indexOf("--time") + 2);
        if (targets.length > 0 && targets.every((id) => residueIds.includes(id))) {
          return fail("simulated stop failure");
        }
      }
      return ok();
    }
    if (args[0] === "container" && args[1] === "rm") {
      const id = args.at(-1) ?? "";
      if (options.failSessionRemove && id === SESSION_CONTAINER_ID) return fail("simulated removal failure");
      removedContainers.add(id);
      residueIds = residueIds.filter((candidate) => candidate !== id);
      return ok();
    }
    if (args[0] === "container" && args[1] === "inspect") {
      if (options.inspectOperationalError) return fail("Cannot connect to the Docker daemon");
      const format = args[args.indexOf("--format") + 1] ?? "";
      if (format.includes("com.docker.compose.project")) {
        const ids = args.slice(args.indexOf("--format") + 2);
        return ok(`${ids.map((id) => `${id}\t`).join("\n")}\n`);
      }
      const id = args.at(-1) ?? "";
      if (removedContainers.has(id)) return fail(`Error: No such container: ${id}`);
      return ok(`/${id.slice(0, 12)}\timage:test\trunning\n`);
    }
    if (args[0] === "ps") {
      const filter = args[args.indexOf("--filter") + 1] ?? "";
      if (!filter.startsWith("label=io.runfree.project-id=")) return ok("");
      if (args.includes("-q") && options.residueRunning === false) return ok("");
      return ok(`${residueIds.join("\n")}\n`);
    }
    if (args[0] === "network" && args[1] === "ls") {
      return ok(options.composeNetworkRemains ? "feedfacecafe\n" : "");
    }
    if (args[0] === "volume" && args[1] === "ls") return ok("");
    if (args[0] === "image" && args[1] === "ls") {
      return ok(options.composeImageRemains ? "sha256:1234\n" : "");
    }
    throw new Error(`unexpected docker invocation: ${args.join(" ")}`);
  };

  const io = {
    capture: vi.fn(capture),
    run: vi.fn(() => 0),
    commandExists: vi.fn(() => true),
  } as unknown as RuntimeIO;

  const composeDown = (project: string): number => {
    composeDownCalls.push(project);
    calls.push(["compose-down", project]);
    // Docker refuses to remove a network with active endpoints, so Compose
    // teardown fails while an unclaimed container is still attached.
    if (options.composeDownFailsWhileResidueRemains && residueIds.length > 0) return 1;
    return options.composeDownFails ? 1 : 0;
  };
  const docker = {
    projectForWorkspace: vi.fn(() => (Object.hasOwn(options, "project") ? options.project : COMPOSE_PROJECT)),
    serviceContainerId: vi.fn((_project: string, service: string) => (
      service === "proxy" ? (Object.hasOwn(options, "proxyId") ? options.proxyId : PROXY_CONTAINER_ID) : undefined
    )),
    composeDown: vi.fn(composeDown),
    destroyProject: vi.fn(composeDown),
    activeAgentSessions: vi.fn(() => options.agentSessions ?? []),
  } as unknown as RuntimeDocker;

  const lifecycleLock: ProjectLifecycleLock = {
    ownerToken: "test-owner",
    assertHeld: () => {},
    release: () => {},
  };

  const beforeTeardown = vi.fn();
  const clearResidue = () => { residueIds = []; };
  return Object.freeze({
    input: Object.freeze({
      context,
      io,
      docker,
      lifecycleLock,
      force: options.force === true,
      beforeTeardown,
      nowEpochMs: () => options.nowEpochMs ?? AFTER_LEASE_MS,
    }),
    stateDir,
    calls,
    composeDownCalls,
    beforeTeardown,
    clearResidue,
  });
}

function writeRecord(stateDir: string, record: SessionContainerRecordV2): void {
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
}

function prepareRebindTransaction(stateDir: string, record: SessionContainerRecordV2): string {
  const oldTarget = sessionGenerationFixture().target;
  const candidateControl = createControlPlaneGenerationV2({
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProject: SESSION_TEST_PROJECT.composeProject,
    proxyImageInputDigest: sha256Digest("destroy-candidate-proxy"),
    controlPlaneTopologyDigest: oldTarget.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: oldTarget.controlPlane.admissionContractEpoch,
  });
  const candidateTarget = { ...oldTarget, controlPlane: candidateControl };
  const transaction = createControlPlaneRebindTransaction({
    expectedProject: SESSION_TEST_PROJECT,
    lockOwnerToken: "b".repeat(64),
    oldControlPlane: effectiveControlPlaneFixture({ target: oldTarget }),
    oldMaterialization: controlPlaneMaterializationFixture({ target: oldTarget }),
    candidateMaterialization: controlPlaneMaterializationFixture({ target: candidateTarget }),
    oldRecords: [record],
    now: () => new Date("2026-08-14T12:00:00.000Z"),
    randomBytes: () => new Uint8Array(32).fill(0xcd),
  });
  prepareControlPlaneRebindTransaction(stateDir, transaction);
  return controlPlaneRebindTransactionPath(stateDir);
}

function rebuildInput(input: FencedProjectDestroyInput): FencedProjectRebuildTeardownInput {
  return Object.freeze({
    context: input.context,
    io: input.io,
    docker: input.docker,
    lifecycleLock: input.lifecycleLock,
    nowEpochMs: input.nowEpochMs,
  });
}

function completeRebuildState(stateDir: string): Readonly<{
  rebindPath: string;
  recordPath: string;
  selectionPath: string;
}> {
  publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture({}));
  selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture({}));
  const record = attachedRecord();
  writeRecord(stateDir, record);
  return Object.freeze({
    rebindPath: prepareRebindTransaction(stateDir, record),
    recordPath: sessionContainerRecordPath(stateDir, record.sessionId),
    selectionPath: controlPlaneEffectiveSelectionPathV2(stateDir),
  });
}

function failOnceBeforeUnlink(targetPath: string): void {
  const original = fs.unlinkSync.bind(fs);
  const spy = vi.spyOn(fs, "unlinkSync");
  spy.mockImplementation(((candidate) => {
    if (candidate === targetPath) {
      spy.mockRestore();
      throw new Error(`simulated crash before unlinking ${path.basename(targetPath)}`);
    }
    return original(candidate);
  }) as typeof fs.unlinkSync);
}

function failOnceBeforeRemove(targetPath: string): void {
  const original = fs.rmSync.bind(fs);
  const spy = vi.spyOn(fs, "rmSync");
  spy.mockImplementation(((candidate, options) => {
    if (candidate === targetPath) {
      spy.mockRestore();
      throw new Error(`simulated crash before removing ${path.basename(targetPath)}`);
    }
    return original(candidate, options);
  }) as typeof fs.rmSync);
}

function expectRebuildRetryConverges(
  input: FencedProjectDestroyInput,
  stateDir: string,
  afterCrash: () => void,
): void {
  expect(() => runFencedProjectRebuildTeardown(rebuildInput(input))).toThrow("simulated crash");
  afterCrash();
  expect(runFencedProjectRebuildTeardown(rebuildInput(input))).toBe(0);
  expect(fs.existsSync(controlPlaneEffectiveSelectionPathV2(stateDir))).toBe(false);
  expect(fs.existsSync(controlPlaneRebindTransactionPath(stateDir))).toBe(false);
  expect(fs.existsSync(sessionContainerRecordsRoot(stateDir))).toBe(false);
}

describe("fenced project rebuild teardown", () => {
  test("drains a pending rebind before Compose recreation and removes its durable state last", () => {
    const { input, stateDir, calls, composeDownCalls } = harness();
    publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture({}));
    selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture({}));
    const record = attachedRecord();
    writeRecord(stateDir, record);
    const rebindPath = prepareRebindTransaction(stateDir, record);

    expect(runFencedProjectRebuildTeardown(rebuildInput(input))).toBe(0);

    const effects = calls
      .filter((call) => call[0] === "compose-down"
        || (call[1] === "container" && (call[2] === "stop" || call[2] === "rm")))
      .map((call) => (call[0] === "compose-down" ? "compose-down" : `${call[2]} ${call.at(-1)}`));
    expect(effects).toEqual([
      `stop ${PROXY_CONTAINER_ID}`,
      `rm ${SESSION_CONTAINER_ID}`,
      "compose-down",
    ]);
    expect(composeDownCalls).toEqual([COMPOSE_PROJECT]);
    expect(fs.existsSync(rebindPath)).toBe(false);
    expect(fs.existsSync(controlPlaneEffectiveSelectionPathV2(stateDir))).toBe(false);
    expect(fs.existsSync(sessionContainerRecordsRoot(stateDir))).toBe(false);
  });

  test("keeps revoking lifecycle evidence when Compose teardown fails", () => {
    const { input, stateDir } = harness({ composeDownFails: true });
    publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture({}));
    selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture({}));
    const record = attachedRecord();
    writeRecord(stateDir, record);
    const transactionPath = prepareRebindTransaction(stateDir, record);

    expect(runFencedProjectRebuildTeardown(rebuildInput(input))).toBe(1);

    const enumeration = enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT);
    expect(enumeration.records).toHaveLength(1);
    expect(enumeration.records[0]?.state).toBe("revoking");
    expect(fs.existsSync(transactionPath)).toBe(true);
    expect(fs.existsSync(controlPlaneEffectiveSelectionPathV2(stateDir))).toBe(true);
  });

  test("a crash after selection removal keeps the journal and records, and one retry converges", () => {
    const { input, stateDir } = harness();
    const state = completeRebuildState(stateDir);
    failOnceBeforeUnlink(state.rebindPath);

    expectRebuildRetryConverges(input, stateDir, () => {
      expect(fs.existsSync(state.selectionPath)).toBe(false);
      expect(fs.existsSync(state.rebindPath)).toBe(true);
      expect(fs.existsSync(state.recordPath)).toBe(true);
    });
  });

  test("a crash after rebind-journal removal keeps the exact revoking record, and one retry converges", () => {
    const { input, stateDir } = harness();
    const state = completeRebuildState(stateDir);
    failOnceBeforeUnlink(state.recordPath);

    expectRebuildRetryConverges(input, stateDir, () => {
      expect(fs.existsSync(state.selectionPath)).toBe(false);
      expect(fs.existsSync(state.rebindPath)).toBe(false);
      expect(fs.existsSync(state.recordPath)).toBe(true);
      expect(enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT).records[0]?.state).toBe("revoking");
    });
  });

  test("a crash after exact record removal leaves no authority, and one retry removes the empty registry", () => {
    const { input, stateDir } = harness();
    const state = completeRebuildState(stateDir);
    failOnceBeforeRemove(sessionContainerRecordsRoot(stateDir));

    expectRebuildRetryConverges(input, stateDir, () => {
      expect(fs.existsSync(state.selectionPath)).toBe(false);
      expect(fs.existsSync(state.rebindPath)).toBe(false);
      expect(fs.existsSync(state.recordPath)).toBe(false);
      expect(fs.existsSync(sessionContainerRecordsRoot(stateDir))).toBe(true);
    });
  });

  test("refuses an obstructing rebind journal directory before any teardown effect", () => {
    const { input, stateDir, calls, composeDownCalls } = harness();
    const rebindPath = controlPlaneRebindTransactionPath(stateDir);
    fs.mkdirSync(rebindPath, { recursive: true, mode: 0o700 });
    const prepareUtilities = vi.fn();

    expect(runFencedProjectRebuildTeardown({ ...rebuildInput(input), prepareUtilities })).toBe(1);

    expect(prepareUtilities).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(composeDownCalls).toEqual([]);
    expect(fs.statSync(rebindPath).isDirectory()).toBe(true);
  });

  test("refuses malformed effective control state before any rebuild teardown effect", () => {
    const { input, stateDir, calls, composeDownCalls } = harness();
    const record = attachedRecord();
    writeRecord(stateDir, record);
    const selectionPath = controlPlaneEffectiveSelectionPathV2(stateDir);
    fs.mkdirSync(path.dirname(selectionPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(selectionPath, "{}", { mode: 0o600 });
    const remove = vi.fn();
    const prepareUtilities = vi.fn(() => ({ claimedContainerIds: [], remove }));

    expect(() => runFencedProjectRebuildTeardown({ ...rebuildInput(input), prepareUtilities }))
      .toThrow("durable control plane cannot name its proxy consumer");

    expect(prepareUtilities).toHaveBeenCalledOnce();
    expect(remove).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(composeDownCalls).toEqual([]);
    expect(enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT).records[0]).toEqual(record);
    expect(fs.existsSync(selectionPath)).toBe(true);
  });

  test("claims validated ingress utilities before the refusal gate and removes them after it passes", () => {
    const forwarderId = "d".repeat(64);
    const { input, clearResidue, composeDownCalls } = harness({ residueIds: [forwarderId] });
    const remove = vi.fn(clearResidue);
    const prepareUtilities = vi.fn(() => ({ claimedContainerIds: [forwarderId], remove }));

    expect(runFencedProjectRebuildTeardown({ ...rebuildInput(input), prepareUtilities })).toBe(0);

    expect(prepareUtilities).toHaveBeenCalledOnce();
    expect(remove).toHaveBeenCalledOnce();
    expect(composeDownCalls).toEqual([COMPOSE_PROJECT]);
  });

  test("does not remove a validated ingress utility when another unclaimed container refuses rebuild", () => {
    const forwarderId = "d".repeat(64);
    const staleId = "e".repeat(64);
    const { input, clearResidue, calls, composeDownCalls } = harness({ residueIds: [forwarderId, staleId] });
    const remove = vi.fn(clearResidue);
    const prepareUtilities = vi.fn(() => ({ claimedContainerIds: [forwarderId], remove }));

    expect(runFencedProjectRebuildTeardown({ ...rebuildInput(input), prepareUtilities })).toBe(1);

    expect(prepareUtilities).toHaveBeenCalledOnce();
    expect(remove).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(composeDownCalls).toEqual([]);
  });

  test("refuses stopped unclaimed project residue before teardown effects", () => {
    const residueId = "d".repeat(64);
    const { input, calls, composeDownCalls } = harness({ residueIds: [residueId], residueRunning: false });

    expect(runFencedProjectRebuildTeardown(rebuildInput(input))).toBe(1);
    expect(calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(composeDownCalls).toEqual([]);
  });
});

describe("fenced project destroy", () => {
  test("refuses a live non-revoking session held only by a valid journal", () => {
    const { input, stateDir, calls, beforeTeardown } = harness({ nowEpochMs: DURING_LEASE_MS });
    const live = attachedRecord({}, { hostPid: process.pid });
    const transactionPath = prepareRebindTransaction(stateDir, live);

    expect(runFencedProjectDestroy(input)).toBe(1);

    expect(beforeTeardown).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container")).toEqual([]);
    expect(fs.existsSync(transactionPath)).toBe(true);
  });

  test("runs strict utility cleanup for plain destroy but bypasses it for the forced residue sweep", () => {
    const plain = harness();
    const plainUtilityPreparation = vi.fn();
    const plainUtilityCleanup = vi.fn();
    const plainPostForceCleanup = vi.fn();
    plainUtilityPreparation.mockReturnValue({ claimedContainerIds: [], remove: plainUtilityCleanup });
    expect(runFencedProjectDestroy({
      ...plain.input,
      afterForcedResidueTeardown: plainPostForceCleanup,
      prepareUtilities: plainUtilityPreparation,
    })).toBe(0);
    expect(plainUtilityPreparation).toHaveBeenCalledOnce();
    expect(plain.beforeTeardown).toHaveBeenCalledOnce();
    expect(plainUtilityCleanup).toHaveBeenCalledOnce();
    expect(plainPostForceCleanup).not.toHaveBeenCalled();

    const forced = harness({ force: true });
    const forcedPostSweepCleanup = vi.fn();
    const forcedUtilityPreparation = vi.fn(() => {
      throw new Error("strict utility proof must not block --force");
    });
    expect(runFencedProjectDestroy({
      ...forced.input,
      afterForcedResidueTeardown: forcedPostSweepCleanup,
      prepareUtilities: forcedUtilityPreparation,
    })).toBe(0);
    expect(forced.beforeTeardown).toHaveBeenCalledOnce();
    expect(forcedUtilityPreparation).not.toHaveBeenCalled();
    expect(forcedPostSweepCleanup).toHaveBeenCalledOnce();
  });

  test("claims a validated running utility before the plain-destroy residue gate", () => {
    const utilityId = "8".repeat(64);
    const { input, clearResidue } = harness({ residueIds: [utilityId] });
    const remove = vi.fn(clearResidue);
    const prepareUtilities = vi.fn(() => ({ claimedContainerIds: [utilityId], remove }));

    expect(runFencedProjectDestroy({ ...input, prepareUtilities })).toBe(0);

    expect(prepareUtilities).toHaveBeenCalledOnce();
    expect(remove).toHaveBeenCalledOnce();
  });

  test("refuses to end a live session without --force and removes nothing", () => {
    const { input, stateDir, calls, beforeTeardown } = harness({ nowEpochMs: DURING_LEASE_MS });
    writeRecord(stateDir, attachedRecord({}, { hostPid: process.pid }));
    const utilityRemove = vi.fn();
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((message?: unknown) => { errors.push(String(message)); });

    expect(runFencedProjectDestroy({
      ...input,
      prepareUtilities: () => ({ claimedContainerIds: [], remove: utilityRemove }),
    })).toBe(1);
    // The refusal happens before any teardown effect: no Docker mutation ran
    // and the record is untouched.
    expect(beforeTeardown).not.toHaveBeenCalled();
    expect(utilityRemove).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container")).toEqual([]);
    expect(calls.filter((call) => call[0] === "compose-down")).toEqual([]);
    const enumeration = enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT);
    expect(enumeration.records).toHaveLength(1);
    expect(enumeration.records[0]?.state).toBe("attached");
    expect(errors.filter((line) => line.includes("rf-20260808-abcdef"))).toHaveLength(1);
  });

  test("destroys a stale session without --force: revoke, stop proxy, remove by record id, compose down, records last", () => {
    const { input, stateDir, calls, composeDownCalls } = harness();
    const record = attachedRecord();
    writeRecord(stateDir, record);
    const transactionPath = prepareRebindTransaction(stateDir, record);

    expect(runFencedProjectDestroy(input)).toBe(0);

    const effects = calls
      .filter((call) => call[0] === "compose-down"
        || (call[1] === "container" && (call[2] === "stop" || call[2] === "rm")))
      .map((call) => (call[0] === "compose-down" ? "compose-down" : `${call[2]} ${call.at(-1)}`));
    // Ordering is the security property: consumers (the proxy) lose authority
    // before any session container is removed, and Compose runs after both.
    expect(effects).toEqual([
      `stop ${PROXY_CONTAINER_ID}`,
      `rm ${SESSION_CONTAINER_ID}`,
      "compose-down",
    ]);
    expect(composeDownCalls).toEqual([COMPOSE_PROJECT]);
    expect(fs.existsSync(sessionContainerRecordsRoot(stateDir))).toBe(false);
    expect(fs.existsSync(transactionPath)).toBe(false);
  });

  test("removes an exact interrupted control-plane rebind journal", () => {
    const { input, stateDir } = harness();
    const record = attachedRecord();
    writeRecord(stateDir, record);
    const rebindPath = prepareRebindTransaction(stateDir, record);

    expect(runFencedProjectDestroy(input)).toBe(0);

    expect(fs.existsSync(rebindPath)).toBe(false);
    expect(fs.existsSync(sessionContainerRecordsRoot(stateDir))).toBe(false);
  });

  test("plain destroy refuses malformed journal evidence; --force removes its exact path", () => {
    const plain = harness();
    const plainPath = controlPlaneRebindTransactionPath(plain.stateDir);
    fs.mkdirSync(plainPath, { recursive: true, mode: 0o700 });

    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.beforeTeardown).not.toHaveBeenCalled();
    expect(plain.composeDownCalls).toEqual([]);
    expect(fs.statSync(plainPath).isDirectory()).toBe(true);

    const forced = harness({ force: true });
    const forcedPath = controlPlaneRebindTransactionPath(forced.stateDir);
    fs.mkdirSync(forcedPath, { recursive: true, mode: 0o700 });

    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(fs.existsSync(forcedPath)).toBe(false);
  });

  test("--force persists each journal removal before deleting later recovery evidence", () => {
    const forced = harness({ force: true });
    publishControlPlaneMaterializationV2(forced.stateDir, controlPlaneMaterializationFixture({}));
    selectEffectiveControlPlaneV2(forced.stateDir, effectiveControlPlaneFixture({}));
    const record = attachedRecord();
    writeRecord(forced.stateDir, record);
    // Unreadable journal evidence: `--force` takes the exact-path removal
    // route, which is the one that must persist each step before the next.
    const rebindPath = controlPlaneRebindTransactionPath(forced.stateDir);
    fs.mkdirSync(path.dirname(rebindPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(rebindPath, "{}", { mode: 0o600 });
    const recordPath = sessionContainerRecordPath(forced.stateDir, record.sessionId);

    let rebindRemoved = false;
    const originalRemove = fs.rmSync.bind(fs);
    const removeSpy = vi.spyOn(fs, "rmSync").mockImplementation(((candidate, options) => {
      originalRemove(candidate, options);
      if (candidate === rebindPath) rebindRemoved = true;
    }) as typeof fs.rmSync);
    const originalFsync = fs.fsyncSync.bind(fs);
    const fsyncSpy = vi.spyOn(fs, "fsyncSync").mockImplementation(((descriptor) => {
      if (rebindRemoved) throw new Error("simulated crash after forced rebind-journal removal");
      return originalFsync(descriptor);
    }) as typeof fs.fsyncSync);
    try {
      expect(() => runFencedProjectDestroy(forced.input)).toThrow("simulated crash");
    } finally {
      removeSpy.mockRestore();
      fsyncSpy.mockRestore();
    }

    expect(fs.existsSync(rebindPath)).toBe(false);
    expect(fs.existsSync(recordPath)).toBe(true);
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(fs.existsSync(recordPath)).toBe(false);
  });

  test("--force refuses an unsafe journal parent before any teardown effect", () => {
    const forced = harness({ force: true });
    const external = temporaryState();
    fs.mkdirSync(path.join(forced.stateDir, "runtime"), { recursive: true, mode: 0o700 });
    fs.symlinkSync(external, path.join(forced.stateDir, "runtime", "v2"), "dir");

    expect(runFencedProjectDestroy(forced.input)).toBe(1);

    expect(forced.beforeTeardown).not.toHaveBeenCalled();
    expect(forced.calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(forced.composeDownCalls).toEqual([]);
    expect(fs.lstatSync(path.join(forced.stateDir, "runtime", "v2")).isSymbolicLink()).toBe(true);
  });

  test("--force ends live sessions through the same fenced sequence", () => {
    const { input, stateDir } = harness({ force: true, nowEpochMs: DURING_LEASE_MS });
    writeRecord(stateDir, attachedRecord());
    expect(runFencedProjectDestroy(input)).toBe(0);
    expect(enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT).records).toEqual([]);
  });

  test("keeps lifecycle records when a recorded session container cannot be removed", () => {
    const { input, stateDir, composeDownCalls } = harness({ failSessionRemove: true });
    writeRecord(stateDir, attachedRecord());

    expect(runFencedProjectDestroy(input)).toBe(1);
    // The record survives (now revoking) so a re-run can still find the
    // container by its record-bound id, and Compose teardown never ran.
    const enumeration = enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT);
    expect(enumeration.records).toHaveLength(1);
    expect(enumeration.records[0]?.state).toBe("revoking");
    expect(composeDownCalls).toEqual([]);
  });

  test("reports unclaimed project residue and removes it only under --force", () => {
    const plain = harness({ residueIds: [RESIDUE_CONTAINER_ID], residueRunning: false });
    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.calls.some((call) => call[1] === "container" && call[2] === "rm" && call.at(-1) === RESIDUE_CONTAINER_ID)).toBe(false);

    const forced = harness({ residueIds: [RESIDUE_CONTAINER_ID], force: true });
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(forced.calls.some((call) => call[1] === "container" && call[2] === "rm" && call.at(-1) === RESIDUE_CONTAINER_ID)).toBe(true);
  });

  test("plain destroy refuses a quarantined unreadable record; --force proceeds and clears the evidence", () => {
    // An unreadable record's liveness is unknowable, so it is treated like a
    // live session: plain destroy fails closed before any teardown effect.
    const plain = harness();
    const corruptName = "rf-20260814-zz9999.json";
    fs.mkdirSync(sessionContainerRecordsRoot(plain.stateDir), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(sessionContainerRecordsRoot(plain.stateDir), corruptName), "{", { mode: 0o600 });
    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.beforeTeardown).not.toHaveBeenCalled();
    expect(plain.calls.filter((call) => call[1] === "container")).toEqual([]);
    expect(plain.composeDownCalls).toEqual([]);
    const retained = listQuarantinedSessionContainerRecordNamesV2(plain.stateDir);
    expect(retained).toHaveLength(1);
    expect(retained[0]?.startsWith(`${corruptName}.`)).toBe(true);

    const forced = harness({ force: true });
    fs.mkdirSync(sessionContainerRecordsRoot(forced.stateDir), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(sessionContainerRecordsRoot(forced.stateDir), corruptName), "{", { mode: 0o600 });
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(fs.existsSync(sessionContainerQuarantineRoot(forced.stateDir))).toBe(false);
  });

  test("a record belonging to another project is quarantined and refused, and its container is never removed", () => {
    const { input, stateDir, calls } = harness();
    const foreign = {
      ...attachedRecord(),
      projectId: "abcdef012345",
      composeProject: "runfree-abcdef012345",
    };
    fs.mkdirSync(sessionContainerRecordsRoot(stateDir), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(sessionContainerRecordsRoot(stateDir), `${foreign.sessionId}.json`),
      `${JSON.stringify(foreign)}\n`,
      { mode: 0o600 },
    );

    expect(runFencedProjectDestroy(input)).toBe(1);
    expect(calls.filter((call) => call[1] === "container")).toEqual([]);
    const quarantinedForeign = listQuarantinedSessionContainerRecordNamesV2(stateDir);
    expect(quarantinedForeign).toHaveLength(1);
    expect(quarantinedForeign[0]?.startsWith(`${foreign.sessionId}.json.`)).toBe(true);
  });

  test("an obstructed quarantine path refuses plain destroy and is cleared by --force", () => {
    // Destroy is the documented remedy for quarantine residue, so a regular
    // file where the quarantine directory belongs must not wedge it: the
    // listing failure reads as "may hide records", and --force removes the
    // obstruction with the rest.
    const plain = harness();
    fs.mkdirSync(path.dirname(sessionContainerQuarantineRoot(plain.stateDir)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(sessionContainerQuarantineRoot(plain.stateDir), "not a directory", { mode: 0o600 });
    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.beforeTeardown).not.toHaveBeenCalled();

    const forced = harness({ force: true });
    fs.mkdirSync(path.dirname(sessionContainerQuarantineRoot(forced.stateDir)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(sessionContainerQuarantineRoot(forced.stateDir), "not a directory", { mode: 0o600 });
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(fs.existsSync(sessionContainerQuarantineRoot(forced.stateDir))).toBe(false);
  });

  test("an inspection failure is not proof of absence: a failed proxy stop aborts before any removal", () => {
    // `docker inspect` can fail because the daemon is momentarily unavailable,
    // not only because the container is gone. Treating that as absence would
    // let session containers be removed under a proxy that still holds
    // authority.
    const { input, stateDir, calls } = harness({ failProxyStop: true, inspectOperationalError: true });
    writeRecord(stateDir, attachedRecord());

    expect(() => runFencedProjectDestroy(input)).toThrow("could not prove container");
    expect(calls.some((call) => call[1] === "container" && call[2] === "rm")).toBe(false);
    expect(enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT).records).toHaveLength(1);
  });

  test("--force clears residue that wedged the Compose teardown, then retries it once", () => {
    // The wedge shape: an unclaimed container attached to the internal network
    // makes `compose down` fail at network removal. --force must remove the
    // residue and retry Compose, or the promised remedy could never finish.
    const forced = harness({ residueIds: [RESIDUE_CONTAINER_ID], force: true, composeDownFailsWhileResidueRemains: true });
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(forced.composeDownCalls).toEqual([COMPOSE_PROJECT, COMPOSE_PROJECT]);

    // Without --force the wedge is reported, records are kept, and the exit is
    // non-zero rather than a clean-looking partial teardown.
    const plain = harness({ residueIds: [RESIDUE_CONTAINER_ID], residueRunning: false, composeDownFailsWhileResidueRemains: true });
    writeRecord(plain.stateDir, attachedRecord());
    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.composeDownCalls).toEqual([COMPOSE_PROJECT]);
    expect(enumerateSessionContainerRecordsV2(plain.stateDir, SESSION_TEST_PROJECT).records).toHaveLength(1);
  });

  test("refuses for a live agent session even when Compose discovery finds nothing", () => {
    // The live-session gate must not ride on `projectForWorkspace()`, which
    // returns nothing on a transient Docker failure: the agent-session
    // inventory derives its Compose name deterministically and consults host
    // metadata, so it runs unconditionally.
    const { input, composeDownCalls, beforeTeardown } = harness({
      project: undefined,
      agentSessions: [{
        name: "legacy",
        command: "claude",
        containerTty: "pts/1",
        processCount: 1,
      }],
    });

    expect(runFencedProjectDestroy(input)).toBe(1);
    expect(beforeTeardown).not.toHaveBeenCalled();
    expect(composeDownCalls).toEqual([]);
  });

  test("fences the durable control plane's proxy even when Compose discovery finds nothing", () => {
    // Compose discovery rides on `docker ps` and can return nothing on a
    // transient daemon failure or lost Compose metadata. The durable effective
    // control plane names the exact proxy holding consumer authority, so the
    // fence must come from it independently.
    const { input, stateDir, calls } = harness({ project: undefined });
    const materialization = controlPlaneMaterializationFixture({});
    publishControlPlaneMaterializationV2(stateDir, materialization);
    selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture({}));
    writeRecord(stateDir, attachedRecord());

    expect(runFencedProjectDestroy(input)).toBe(0);
    const effects = calls
      .filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))
      .map((call) => `${call[2]} ${call.at(-1)}`);
    expect(effects).toEqual([
      `stop ${PROXY_CONTAINER_ID}`,
      `rm ${SESSION_CONTAINER_ID}`,
    ]);
  });

  test("refuses malformed effective control state before any destroy effect", () => {
    const { input, stateDir, calls, composeDownCalls, beforeTeardown } = harness();
    const record = attachedRecord();
    writeRecord(stateDir, record);
    const selectionPath = controlPlaneEffectiveSelectionPathV2(stateDir);
    fs.mkdirSync(path.dirname(selectionPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(selectionPath, "{}", { mode: 0o600 });

    expect(() => runFencedProjectDestroy(input))
      .toThrow("durable control plane cannot name its proxy consumer");

    expect(beforeTeardown).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(composeDownCalls).toEqual([]);
    expect(enumerateSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT).records[0]).toEqual(record);
    expect(fs.existsSync(selectionPath)).toBe(true);
  });

  test("runs Compose teardown for surviving networks or volumes when container discovery is empty", () => {
    // Containers can all be gone while the project's networks and volumes
    // survive; skipping Compose teardown on container discovery alone would
    // report success while retaining that persistent data.
    const { input, composeDownCalls } = harness({ project: undefined, proxyId: undefined, composeNetworkRemains: true });
    expect(runFencedProjectDestroy(input)).toBe(0);
    expect(composeDownCalls).toEqual([COMPOSE_PROJECT]);
  });

  test("a structurally unsafe records tree stays fatal even under --force", () => {
    // Renaming through an unvalidated tree and later recursively removing the
    // aside could reach outside the state directory, so a safe-path failure
    // must abort rather than enter the illegible-registry recovery.
    const { input, stateDir } = harness({ force: true });
    const recordsRoot = sessionContainerRecordsRoot(stateDir);
    fs.mkdirSync(path.dirname(recordsRoot), { recursive: true, mode: 0o700 });
    const real = path.join(stateDir, "elsewhere");
    fs.mkdirSync(real, { recursive: true, mode: 0o700 });
    fs.symlinkSync(real, recordsRoot);

    expect(() => runFencedProjectDestroy(input)).toThrow("not a safe directory");
    expect(fs.lstatSync(recordsRoot).isSymbolicLink()).toBe(true);
  });

  test("runs Compose teardown when only a Compose-built local image remains", () => {
    const { input, composeDownCalls } = harness({ project: undefined, proxyId: undefined, composeImageRemains: true });
    expect(runFencedProjectDestroy(input)).toBe(0);
    expect(composeDownCalls).toEqual([COMPOSE_PROJECT]);
  });

  test("rediscovers an interrupted illegible-registry aside: plain destroy refuses, --force clears it", () => {
    // A destroy interrupted after the registry rename leaves the aside behind
    // with no in-process variable pointing at it, so later invocations must
    // find it by name pattern rather than report a clean teardown over it.
    const asideName = "session-containers-illegible-deadbeef";
    const plain = harness();
    const plainAside = path.join(path.dirname(sessionContainerRecordsRoot(plain.stateDir)), asideName);
    fs.mkdirSync(plainAside, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(plainAside, "rf-20260814-zz9999.json"), "{}", { mode: 0o600 });
    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.beforeTeardown).not.toHaveBeenCalled();
    expect(fs.existsSync(plainAside)).toBe(true);

    const forced = harness({ force: true });
    const forcedAside = path.join(path.dirname(sessionContainerRecordsRoot(forced.stateDir)), asideName);
    fs.mkdirSync(forcedAside, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(forcedAside, "rf-20260814-zz9999.json"), "{}", { mode: 0o600 });
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(fs.existsSync(forcedAside)).toBe(false);
  });

  test("plain destroy refuses a running unclaimed project container before any effect", () => {
    // A running container that neither a record nor Compose claims may be a
    // live session whose record was lost: plain destroy must refuse rather
    // than stop it and report afterwards.
    const staleId = "d".repeat(64);
    const { input, calls, composeDownCalls, beforeTeardown } = harness({ residueIds: [staleId] });

    expect(runFencedProjectDestroy(input)).toBe(1);
    expect(beforeTeardown).not.toHaveBeenCalled();
    expect(calls.filter((call) => call[1] === "container" && (call[2] === "stop" || call[2] === "rm"))).toEqual([]);
    expect(composeDownCalls).toEqual([]);
  });

  test("--force stops a stale project-labeled container before removing session containers", () => {
    // Under --force, a consumer from an earlier generation — in neither the
    // Compose set nor the durable plane — is stopped before any
    // address-freeing removal, then swept with the rest of the residue.
    const staleId = "d".repeat(64);
    const { input, stateDir, calls } = harness({ force: true, residueIds: [staleId] });
    writeRecord(stateDir, attachedRecord());

    expect(runFencedProjectDestroy(input)).toBe(0);
    const stopIndex = calls.findIndex((call) => call[1] === "container" && call[2] === "stop" && call.at(-1) === staleId);
    const removeIndex = calls.findIndex((call) => call[1] === "container" && call[2] === "rm" && call.at(-1) === SESSION_CONTAINER_ID);
    expect(stopIndex).toBeGreaterThan(-1);
    expect(removeIndex).toBeGreaterThan(stopIndex);
  });

  test("--force stops every running project container in one Docker call", () => {
    // Docker stops the ids of a multi-id `stop` concurrently, so N live
    // project-labeled containers share one grace period instead of paying
    // for N sequential ones.
    const ids = ["d".repeat(64), "e".repeat(64)];
    const { input, stateDir, calls } = harness({ force: true, residueIds: ids });
    writeRecord(stateDir, attachedRecord());

    expect(runFencedProjectDestroy(input)).toBe(0);
    const residueStops = calls.filter(
      (call) => call[1] === "container" && call[2] === "stop" && ids.some((id) => call.includes(id)),
    );
    expect(residueStops).toEqual([["docker", "container", "stop", "--time", "10", ...ids]]);
  });

  test("a failed batch stop falls back to per-container stops and names the failure", () => {
    // `failProxyStop` fails every `container stop`, including the proxy stop
    // that runs before this sweep — so it would end the destroy before this
    // call is reached. `failResidueStop` fails only stops whose ids are all
    // residue ids, letting the proxy stop succeed and the batch residue stop
    // fail, so the fallback per-id loop below is what this test exercises.
    const ids = ["d".repeat(64), "e".repeat(64)];
    const { input, stateDir, calls } = harness({ force: true, residueIds: ids, failResidueStop: true });
    writeRecord(stateDir, attachedRecord());

    expect(() => runFencedProjectDestroy(input)).toThrow(
      `project container could not be stopped (${ids[0]})`,
    );
    const stopTargets = calls
      .filter((call) => call[1] === "container" && call[2] === "stop")
      .map((call) => call.slice(5));
    expect(stopTargets).toContainEqual(ids);
    expect(stopTargets).toContainEqual([ids[0]]);
  });

  test("--force recovers an over-limit registry that enumeration refuses to scan", () => {
    // 257 record files exceed the bounded scan, which used to throw out of
    // every enumeration — including destroy, the remedy. Plain destroy still
    // refuses (the registry is illegible), and --force proceeds with the
    // project-label sweep and clears the registry last.
    const plain = harness();
    fs.mkdirSync(sessionContainerRecordsRoot(plain.stateDir), { recursive: true, mode: 0o700 });
    for (let index = 0; index < 257; index += 1) {
      fs.writeFileSync(path.join(sessionContainerRecordsRoot(plain.stateDir), `overflow-${index}.json`), "{}", { mode: 0o600 });
    }
    expect(runFencedProjectDestroy(plain.input)).toBe(1);
    expect(plain.beforeTeardown).not.toHaveBeenCalled();

    const forced = harness({ force: true });
    fs.mkdirSync(sessionContainerRecordsRoot(forced.stateDir), { recursive: true, mode: 0o700 });
    for (let index = 0; index < 257; index += 1) {
      fs.writeFileSync(path.join(sessionContainerRecordsRoot(forced.stateDir), `overflow-${index}.json`), "{}", { mode: 0o600 });
    }
    expect(runFencedProjectDestroy(forced.input)).toBe(0);
    expect(fs.existsSync(sessionContainerRecordsRoot(forced.stateDir))).toBe(false);
    // The illegible registry was moved aside atomically (registry-first, so an
    // interrupted destroy leaves no authorizing record behind) and the aside
    // copy was cleaned up with the rest.
    const siblings = fs.readdirSync(path.dirname(sessionContainerRecordsRoot(forced.stateDir)));
    expect(siblings.filter((entry) => entry.includes("illegible"))).toEqual([]);
  });

  test("skips Compose teardown when no Compose containers exist but still clears session state", () => {
    const { input, stateDir, composeDownCalls, calls } = harness({ project: undefined, proxyId: undefined });
    writeRecord(stateDir, attachedRecord());
    expect(runFencedProjectDestroy(input)).toBe(0);
    expect(composeDownCalls).toEqual([]);
    expect(calls.some((call) => call[1] === "container" && call[2] === "rm" && call.at(-1) === SESSION_CONTAINER_ID)).toBe(true);
    expect(fs.existsSync(sessionContainerRecordsRoot(stateDir))).toBe(false);
  });

  // The file-backed admission source. There is no admission journal to read;
  // what says "a session is mid-teardown" is its host status stamp, and what
  // still authorizes egress is the proxy's own session file.
  describe("under the file-backed admission source", () => {
    function selectFileSourceControlPlane(stateDir: string): void {
      publishControlPlaneMaterializationV2(
        stateDir,
        controlPlaneMaterializationFixture(),
      );
      selectEffectiveControlPlaneV2(stateDir, effectiveControlPlaneFixture());
    }

    // Deterministic proof of a running owner across platforms: the fake-docker
    // overrides pin this host's boot id and process-start stamp, so a record
    // carrying the same pair plus a real live PID reads as provably alive.
    const PROVABLE_BOOT_ID = "linux:0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f";
    const PROVABLE_PROCESS_START = "linux:12345";

    function withProvableOwnerEnv(input: FencedProjectDestroyInput): FencedProjectDestroyInput {
      return Object.freeze({
        ...input,
        context: {
          ...input.context,
          env: {
            RUNFREE_TEST_FAKE_DOCKER: "1",
            RUNFREE_TEST_HOST_BOOT_ID: PROVABLE_BOOT_ID,
            RUNFREE_TEST_HOST_PROCESS_START: PROVABLE_PROCESS_START,
          },
        } as RuntimeContext,
      });
    }

    function liveOwnerRecord(): SessionContainerRecordV2 {
      return attachedRecord(
        { hostBootId: PROVABLE_BOOT_ID, hostProcessStart: PROVABLE_PROCESS_START },
        { hostPid: process.pid },
      );
    }

    function stamp(stateDir: string, record: SessionContainerRecordV2, overrides: {
      aliveUntil?: string;
      terminal?: "revoking";
    } = {}): void {
      writeSessionHostStatus(stateDir, {
        v: 1,
        sessionId: record.sessionId,
        lastHeartbeatAt: "2026-08-14T11:59:30.000Z",
        aliveUntil: overrides.aliveUntil ?? "2026-08-14T12:05:00.000Z",
        served: "served",
        ...(overrides.terminal ? { terminal: overrides.terminal } : {}),
      });
    }

    /**
     * The destroy harness's Docker surface plus the sealed session-file
     * channel, recording for every session-file effect whether the record it
     * belongs to still exists. Ordering is the property under test: a record
     * removed before its file would leave the proxy serving an address nothing
     * on the host claims.
     */
    function withSessionFileChannel(
      base: FencedProjectDestroyInput,
      recordPath: string,
      servedKeys: readonly string[],
    ): { input: FencedProjectDestroyInput; events: string[]; deletedPaths: string[] } {
      const events: string[] = [];
      const deletedPaths: string[] = [];
      const capture = (command: string, args: string[]): CaptureResult => {
        if (command === "docker" && args[0] === "exec") {
          const read = args.length === 8;
          events.push(`${read ? "read-served-set" : "delete-session-file"}:${
            fs.existsSync(recordPath) ? "record-present" : "record-gone"
          }`);
          if (!read) deletedPaths.push(args[8] ?? "");
          return {
            status: 0,
            stdout: read
              ? JSON.stringify(servedKeys.map((sessionKey) => ({
                sessionKey,
                sourceIp: "172.31.90.20",
                malformed: false,
              })))
              : "",
            stderr: "",
          };
        }
        return base.io.capture(command, args, {});
      };
      return {
        input: Object.freeze({ ...base, io: { ...base.io, capture: vi.fn(capture) } as unknown as RuntimeIO }),
        events,
        deletedPaths,
      };
    }

    test("a terminal stamp does not prove owner death; explicit force reclaims uncertain teardown", () => {
      const record = attachedRecord({}, { hostPid: process.pid });
      const refusing = harness({ nowEpochMs: DURING_LEASE_MS });
      selectFileSourceControlPlane(refusing.stateDir);
      writeRecord(refusing.stateDir, record);
      stamp(refusing.stateDir, record, { terminal: "revoking" });
      vi.spyOn(console, "error").mockImplementation(() => {});
      expect(runFencedProjectDestroy(refusing.input)).toBe(1);
      expect(refusing.beforeTeardown).not.toHaveBeenCalled();
      expect(fs.existsSync(sessionContainerRecordPath(refusing.stateDir, record.sessionId))).toBe(true);

      const forced = harness({ force: true, nowEpochMs: DURING_LEASE_MS });
      selectFileSourceControlPlane(forced.stateDir);
      writeRecord(forced.stateDir, record);
      stamp(forced.stateDir, record, { terminal: "revoking" });
      const channel = withSessionFileChannel(
        forced.input,
        sessionContainerRecordPath(forced.stateDir, record.sessionId),
        [record.sessionPrincipal],
      );
      expect(runFencedProjectDestroy(channel.input)).toBe(0);
      expect(fs.existsSync(sessionContainerRecordsRoot(forced.stateDir))).toBe(false);
      expect(fs.existsSync(sessionHostStatusPath(forced.stateDir, record.sessionId))).toBe(false);
    });

    // The stamp exclusion above narrows only destroy's own record gate. A
    // teardown whose owner is still running is a live process, and
    // `refuseLiveWork`'s other term — `activeOrStartingAgentSessions`, which
    // classifies the same records without that exclusion — must still refuse
    // it. Without this case the exclusion could be widened to "any terminal
    // stamp, whatever the owner does" and nothing would fail.
    test("a provably live owner is still refused behind a terminal stamp, and --force ends it", () => {
      const record = liveOwnerRecord();
      const refusing = harness({ nowEpochMs: DURING_LEASE_MS });
      selectFileSourceControlPlane(refusing.stateDir);
      writeRecord(refusing.stateDir, record);
      stamp(refusing.stateDir, record, { terminal: "revoking" });
      const errors: string[] = [];
      vi.spyOn(console, "error").mockImplementation((message?: unknown) => { errors.push(String(message)); });

      expect(runFencedProjectDestroy(withProvableOwnerEnv(refusing.input))).toBe(1);
      expect(refusing.beforeTeardown).not.toHaveBeenCalled();
      expect(errors.filter((line) => line.includes(record.sessionId))).toHaveLength(1);
      expect(fs.existsSync(sessionContainerRecordPath(refusing.stateDir, record.sessionId))).toBe(true);

      const forced = harness({ force: true, nowEpochMs: DURING_LEASE_MS });
      selectFileSourceControlPlane(forced.stateDir);
      writeRecord(forced.stateDir, record);
      stamp(forced.stateDir, record, { terminal: "revoking" });
      const channel = withSessionFileChannel(
        withProvableOwnerEnv(forced.input),
        sessionContainerRecordPath(forced.stateDir, record.sessionId),
        [record.sessionPrincipal],
      );

      expect(runFencedProjectDestroy(channel.input)).toBe(0);
      expect(fs.existsSync(sessionContainerRecordsRoot(forced.stateDir))).toBe(false);
      expect(fs.existsSync(sessionHostStatusPath(forced.stateDir, record.sessionId))).toBe(false);
    });

    test.each([[true], [false]])("teardown with --force %s deletes the proxy session file before removing the record", (force) => {
      const { input, stateDir, beforeTeardown } = harness({ force, nowEpochMs: AFTER_LEASE_MS });
      selectFileSourceControlPlane(stateDir);
      const record = attachedRecord();
      writeRecord(stateDir, record);
      stamp(stateDir, record);
      const recordPath = sessionContainerRecordPath(stateDir, record.sessionId);
      const channel = withSessionFileChannel(input, recordPath, [record.sessionPrincipal]);

      expect(runFencedProjectDestroy(channel.input)).toBe(0);

      expect(beforeTeardown).toHaveBeenCalledOnce();
      // Invariant 3, read straight off the effects: the delete ran while the
      // record still existed, and the record is gone afterwards.
      expect(channel.events).toEqual(["read-served-set:record-present", "delete-session-file:record-present"]);
      expect(channel.deletedPaths).toEqual([sessionFilePath(record.sessionPrincipal)]);
      expect(fs.existsSync(recordPath)).toBe(false);
      expect(fs.existsSync(sessionHostStatusPath(stateDir, record.sessionId))).toBe(false);
    });

    // The owner verdict is the fence either way. A project whose control plane
    // was never published has no proxy to take a file back from, so the same
    // destroy must still refuse a live owner and still clear a dead one's
    // record — otherwise a runtime that predates the current materialization
    // would be undestroyable.
    test.each([["a published control plane"], ["no published control plane"]] as const)(
      "with %s: destroy refuses a live owner and proceeds on a dead one",
      (label) => {
        const published = label === "a published control plane";
        const live = harness({ nowEpochMs: DURING_LEASE_MS });
        if (published) selectFileSourceControlPlane(live.stateDir);
        const liveRecord = attachedRecord({}, { hostPid: process.pid });
        writeRecord(live.stateDir, liveRecord);
        if (published) stamp(live.stateDir, liveRecord);
        vi.spyOn(console, "error").mockImplementation(() => {});

        expect(runFencedProjectDestroy(live.input)).toBe(1);
        expect(live.beforeTeardown).not.toHaveBeenCalled();

        const dead = harness({ nowEpochMs: DURING_LEASE_MS });
        if (published) selectFileSourceControlPlane(dead.stateDir);
        const deadRecord = attachedRecord();
        writeRecord(dead.stateDir, deadRecord);
        if (published) stamp(dead.stateDir, deadRecord);
        const channel = published
          ? withSessionFileChannel(dead.input, sessionContainerRecordPath(dead.stateDir, deadRecord.sessionId), [])
          : { input: dead.input };

        expect(runFencedProjectDestroy(channel.input)).toBe(0);
        expect(fs.existsSync(sessionContainerRecordsRoot(dead.stateDir))).toBe(false);
      },
    );
  });
});
