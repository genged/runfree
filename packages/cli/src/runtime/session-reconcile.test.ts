// Reconcile's proof: three lists — the proxy's session files, the host's
// lifecycle records, and Docker's session containers — are made to agree
// before any address is allocated, and nothing that belongs to a live owner is
// touched on the way.
//
// Everything here runs against a real state directory and the real sealed
// Docker commands; only the Docker daemon is a fake, and it answers by exact
// argv so an effect can never be mistaken for another. The single ordered
// event list is what proves the order rather than merely the set of effects.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { parseSessionAdmissionEligibility } from "@runfree/runtime-contracts/session-admission";
import { SESSION_ELIGIBILITY_PATH, SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";

import {
  AGENT_PROJECT_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
} from "./constants.ts";
import {
  bindSessionAgentImageV2,
  createControlPlaneMaterializationManifestV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentGenerationInputsV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  selectDesiredSessionAgentV2,
  selectEffectiveControlPlaneV2,
  type SessionAgentGenerationV2,
} from "./component-state-v2.ts";
import { sha256Digest } from "./component-state.ts";
import { CliError } from "../errors.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import type { SessionContainerNetworkIdentity } from "./session-container-cleanup.ts";
import type { SessionContainerSnapshot } from "./session-container-reconciliation.ts";
import {
  effectiveControlPlaneFixture,
  sessionAgentMaterializationFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  listQuarantinedSessionContainerRecordNamesV2,
  listSessionContainerRecordsV2,
  sessionContainerQuarantineRoot,
  sessionContainerRecordsRoot,
  sessionContainerLabels,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readSessionHostStatus, writeSessionHostStatus } from "./session-host-status.ts";
import { reconcileSessions } from "./session-reconcile.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

const PROXY_ID = "7".repeat(64);
const PROXY_STARTED_AT = "2026-09-07T12:00:05.123456789Z";
const TEMPLATE_ARTIFACT = "session-template-artifact";
const BOOT_THIS = "linux:11111111-2222-3333-4444-555555555555";
const BOOT_PREVIOUS = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
const PROCESS_THIS = "linux:12345";

const NETWORK: SessionContainerNetworkIdentity = Object.freeze({
  networkId: "8".repeat(64),
  networkName: `${SESSION_TEST_PROJECT.composeProject}_agent_internal`,
  subnet: "172.31.90.0/24",
});

/** Host identity under which the fixture records below are alive or gone. */
const ENV: NodeJS.ProcessEnv = Object.freeze({
  RUNFREE_TEST_FAKE_DOCKER: "1",
  RUNFREE_TEST_HOST_BOOT_ID: BOOT_THIS,
  RUNFREE_TEST_HOST_PROCESS_START: PROCESS_THIS,
});

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-reconcile-"));
});

afterEach(() => fs.rmSync(stateDir, { recursive: true, force: true }));

function lifecycleLock(): ProjectLifecycleLock {
  return { ownerToken: "a".repeat(64), assertHeld: vi.fn(), release: vi.fn() };
}

function success(stdout = ""): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

/** Publishes the control plane this project's proxy was started from. */
function selectFileBackedControlPlane(): void {
  const target = sessionGenerationFixture().target;
  const selection = effectiveControlPlaneFixture({ target });
  const manifest = createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation: target.controlPlane,
    proxyImageRef: "runfree/proxy:test",
    proxyImageId: selection.proxyImageId,
    renderedControlPlaneSha256: target.controlPlane.controlPlaneTopologyDigest,
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(stateDir, manifest);
  selectEffectiveControlPlaneV2(stateDir, {
    ...selection,
    controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
  });
}

/** The project's current agent template, which eligibility always names. */
function selectDesiredAgent(): void {
  const manifest = sessionAgentMaterializationFixture();
  publishSessionAgentMaterializationV2(stateDir, manifest, TEMPLATE_ARTIFACT);
  selectDesiredSessionAgentV2(stateDir, createSessionAgentDesiredSelectionV2(manifest));
}

/** One published agent materialization older than the desired one. */
function olderAgentGeneration(seed: string): SessionAgentGenerationV2 {
  const target = sessionGenerationFixture().target;
  const generation = bindSessionAgentImageV2(createSessionAgentGenerationInputsV2({
    selectedAgentImageInputDigest: sha256Digest(`${seed}-agent-image-input`),
    sessionTemplateDigest: sha256Digest(`${seed}-session-template`),
    admissionContractEpoch: target.controlPlane.admissionContractEpoch,
  }), sha256Digest(`${seed}-agent-image-id`));
  publishSessionAgentMaterializationV2(
    stateDir,
    sessionAgentMaterializationFixture({ generation }),
    TEMPLATE_ARTIFACT,
  );
  return generation;
}

type OwnerLiveness = "alive" | "dead" | "unknown";

/** Ownership fields that make a record's owner provably alive, gone, or unprovable. */
function ownership(liveness: OwnerLiveness): Partial<SessionContainerRecordV2> {
  if (liveness === "dead") return { hostPid: process.pid, hostBootId: BOOT_PREVIOUS, hostProcessStart: PROCESS_THIS };
  if (liveness === "alive") return { hostPid: process.pid, hostBootId: BOOT_THIS, hostProcessStart: PROCESS_THIS };
  // Same boot and a live PID, but no process-start stamp to settle whether it
  // is the same process: exactly the record ownership cannot judge.
  return { hostPid: process.pid, hostBootId: BOOT_THIS };
}

let sequence = 0;

/** Persists one lifecycle record with a distinct identity and address. */
function writeRecord(input: {
  liveness: OwnerLiveness;
  host: number;
  containerId?: string;
  generation?: SessionAgentGenerationV2;
  state?: "attached";
}): SessionContainerRecordV2 {
  sequence += 1;
  const index = sequence;
  const digit = String(index % 10);
  const base = sessionContainerRecordFixture({
    ...(input.generation ? { generation: input.generation } : {}),
    ...(input.containerId === undefined ? {} : { containerId: input.containerId }),
    overrides: {
      sessionId: `rf-20260907-abcde${digit}`,
      sessionIncarnation: digit.repeat(64),
      sessionPrincipal: `${digit}${"f".repeat(63)}`,
      containerName: `runfree-${SESSION_TEST_PROJECT.projectId}-session-rf-20260907-abcde${digit}`,
      sourceIp: `172.31.90.${input.host}`,
      ...ownership(input.liveness),
    },
  });
  const record = input.state === "attached"
    ? {
      ...base,
      state: "attached" as const,
      admittedAt: "2026-09-07T12:00:00.000Z",
      leaseGeneration: "8".repeat(32),
      leaseExpiresAt: "2026-09-07T12:05:00.000Z",
    }
    : base;
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
  return record;
}

/**
 * Persists one lifecycle record this host cannot read, which the next
 * enumeration moves into quarantine. Its session principal — the only thing
 * that could map it to a session file — is unrecoverable, which is the whole
 * point of the guard it exercises.
 */
function corruptRecord(sessionId: string): void {
  fs.mkdirSync(sessionContainerRecordsRoot(stateDir), { recursive: true });
  fs.writeFileSync(path.join(sessionContainerRecordsRoot(stateDir), `${sessionId}.json`), "{not json\n");
}

/** The proxy's answer for one well-formed session file. */
function servedFile(record: SessionContainerRecordV2, overrides: Record<string, unknown> = {}) {
  return {
    sessionKey: record.sessionPrincipal,
    sourceIp: record.sourceIp,
    aliveUntil: "2026-09-07T12:05:00.000Z",
    nonce: "a".repeat(32),
    eligible: true,
    wallActive: true,
    ...overrides,
  };
}

function snapshotOf(
  record: SessionContainerRecordV2,
  overrides: Partial<SessionContainerSnapshot> = {},
): SessionContainerSnapshot {
  return {
    containerId: record.containerId as string,
    containerName: record.containerName,
    imageId: record.selectedAgentImageId,
    labels: {
      ...sessionContainerLabels(record, "0.3.0"),
      [RUNFREE_IMAGE_ROLE_LABEL]: AGENT_PROJECT_IMAGE_ROLE,
      [RUNFREE_DIGEST_SCHEMA_LABEL]: RUNFREE_DIGEST_SCHEMA_VERSION,
      [RUNFREE_IMAGE_INPUT_DIGEST_LABEL]: record.selectedAgentImageInputDigest,
    },
    sourceIp: record.sourceIp,
    internalNetworkId: NETWORK.networkId,
    running: true,
    ...overrides,
  };
}

function inventoryInspection(snapshots: readonly SessionContainerSnapshot[]): string {
  return JSON.stringify(snapshots.map((snapshot) => ({
    Id: snapshot.containerId,
    Name: `/${snapshot.containerName}`,
    Image: snapshot.imageId,
    Config: { Labels: snapshot.labels },
    State: { Running: snapshot.running },
    NetworkSettings: {
      Networks: snapshot.sourceIp === undefined ? {} : {
        [NETWORK.networkName]: {
          NetworkID: snapshot.internalNetworkId ?? NETWORK.networkId,
          IPAddress: snapshot.sourceIp,
        },
      },
    },
  })));
}

type Fake = Readonly<{
  io: RuntimeIO;
  events: string[];
  inputs: Map<string, string>;
  effects: () => string[];
}>;

/**
 * One fake Docker daemon, answering by exact argv.
 *
 * Every session-file command runs as a pinned `docker exec ... node -e
 * <script> [path [digest]]`, whose argv is thousands of characters of inlined
 * script, so those are named by what they target and how many arguments they
 * carry instead of by their text.
 */
function fakeDocker(options: {
  served?: unknown;
  servedRaw?: string;
  servedStatus?: number;
  containers?: readonly SessionContainerSnapshot[];
  deleteAnswer?: CaptureResult;
  networkAttachments?: Record<string, unknown>;
  /** Answers the proxy inspect eligibility republication makes with not-running, so publishing eligibility fails. */
  proxyInspectFails?: boolean;
  /** Runs as each effect is answered, so a test can observe host state mid-pass. */
  observe?: (label: string) => void;
} = {}): Fake {
  const events: string[] = [];
  const inputs = new Map<string, string>();
  const containers = options.containers ?? [];
  const capture = vi.fn((_command: string, args: string[], captureOptions?: { input?: string }): CaptureResult => {
    const label = ((): string => {
      if (args[0] === "exec" && args[6] === "-e") {
        if (args.length === 8) return "read-served-set";
        const target = args[8] ?? "";
        if (target === SESSION_ELIGIBILITY_PATH) return "publish-eligibility";
        return `delete-session-file:${target.slice(SESSION_FILES_DIR.length + 1)}`;
      }
      if (args[0] === "container" && args[1] === "ls") {
        return args.includes("--filter") ? `absence-list:${args[5]?.slice(3)}` : "inventory-list";
      }
      if (args[0] === "container" && args[1] === "inspect") {
        return args[2] === PROXY_ID ? "inspect-proxy" : `inventory-inspect:${args.slice(2).join(",")}`;
      }
      if (args[0] === "network" && args[1] === "inspect") return "network-inspect";
      return `docker:${args.join(" ")}`;
    })();
    events.push(label);
    options.observe?.(label);
    if (captureOptions?.input !== undefined) inputs.set(label, captureOptions.input);
    if (label === "read-served-set") {
      if (options.servedStatus !== undefined && options.servedStatus !== 0) {
        return { status: options.servedStatus, stdout: "", stderr: "proxy is gone" };
      }
      if (options.servedRaw !== undefined) return success(options.servedRaw);
      return success(`${JSON.stringify(options.served ?? [])}\n`);
    }
    if (label.startsWith("delete-session-file:") && options.deleteAnswer) return { ...options.deleteAnswer };
    if (label === "inventory-list") {
      return success(containers.length === 0 ? "" : `${containers.map((one) => one.containerId).join("\n")}\n`);
    }
    if (label.startsWith("inventory-inspect:")) return success(inventoryInspection(containers));
    if (label.startsWith("absence-list:")) return success("");
    if (label === "inspect-proxy") {
      if (options.proxyInspectFails) return success(JSON.stringify([{ Id: PROXY_ID, State: { Running: false } }]));
      return success(JSON.stringify([{ Id: PROXY_ID, State: { Running: true, StartedAt: PROXY_STARTED_AT } }]));
    }
    if (label === "network-inspect") {
      return success(JSON.stringify([{
        Id: NETWORK.networkId,
        Name: NETWORK.networkName,
        Containers: options.networkAttachments ?? {},
      }]));
    }
    return success();
  });
  return Object.freeze({
    io: { capture } as unknown as RuntimeIO,
    events,
    inputs,
    // The observation reads are not effects: they change nothing.
    effects: () => events.filter((event) => event !== "read-served-set"
      && event !== "inspect-proxy"
      && event !== "inventory-list"
      && !event.startsWith("inventory-inspect:")),
  });
}

function repair(fake: Fake, lock = lifecycleLock()) {
  return reconcileSessions({
    stateDir,
    expectedProject: SESSION_TEST_PROJECT,
    io: fake.io,
    proxyId: PROXY_ID,
    network: NETWORK,
    env: ENV,
    lifecycleLock: lock,
    mode: "repair",
  });
}

function publishedAgents(fake: Fake): string[] {
  const input = fake.inputs.get("publish-eligibility");
  if (input === undefined) return [];
  const eligibility = parseSessionAdmissionEligibility(JSON.parse(input));
  if (!eligibility) throw new Error("published eligibility does not parse");
  return eligibility.allowedSessionAgents.map((agent) => agent.selectedAgentImageId).sort();
}

describe("reconcile before allocation", () => {
  beforeEach(() => {
    selectFileBackedControlPlane();
    selectDesiredAgent();
  });

  test("deletes a session file no record claims, and reserves its address either way", async () => {
    const orphan = { ...servedFile(sessionContainerRecordFixture()), sessionKey: "c".repeat(64), sourceIp: "172.31.90.33" };
    const fake = fakeDocker({ served: [orphan] });

    const result = await repair(fake);

    expect(result.orphanFilesDeleted).toEqual(["c".repeat(64)]);
    // The delete is the first effect of the sweep, and it happens after the
    // one read that is reconcile's only view of the files.
    expect(fake.events[0]).toBe("read-served-set");
    expect(fake.effects()[0]).toBe(`delete-session-file:${"c".repeat(64)}.json`);
    // F1b: the address a proxy file named is reserved whatever the delete did.
    expect(result.reservedSourceIps).toEqual(["172.31.90.33"]);
  });

  test("reserves the address of a file whose delete failed, and does not refuse the launch", async () => {
    const orphan = { ...servedFile(sessionContainerRecordFixture()), sessionKey: "c".repeat(64), sourceIp: "172.31.90.34" };
    const fake = fakeDocker({ served: [orphan], deleteAnswer: { status: 1, stdout: "", stderr: "unsafe session file" } });

    const result = await repair(fake);

    expect(result.orphanFilesDeleted).toEqual([]);
    expect(result.reservedSourceIps).toEqual(["172.31.90.34"]);
  });

  test("reports a file whose name is not a session key instead of treating it as a wedge", async () => {
    const fake = fakeDocker({ served: [{ name: "notes.json", malformed: true }] });

    const result = await repair(fake);

    expect(result.orphanFilesDeleted).toEqual([]);
    expect(result.orphanFiles).toEqual(["notes.json"]);
    expect(fake.effects().some((event) => event.startsWith("delete-session-file:"))).toBe(false);
  });

  test("deletes a malformed file that does name a session key", async () => {
    const fake = fakeDocker({ served: [{ sessionKey: "c".repeat(64), name: `${"c".repeat(64)}.json`, malformed: true }] });

    const result = await repair(fake);

    expect(result.orphanFilesDeleted).toEqual(["c".repeat(64)]);
    // A malformed file claims no address, so there is nothing to reserve.
    expect(result.reservedSourceIps).toEqual([]);
  });

  // Invariant 7's edge. A quarantined record is one whose bytes this host
  // could not read, so the session principal it claims — the only thing that
  // maps a record to a file — is exactly what is unreadable. Every unclaimed
  // file below could be its file, including a live session's, so while the
  // registry is partially legible none of them may be deleted.
  test("keeps unclaimed session files while the registry holds a quarantined record", async () => {
    const live = writeRecord({ liveness: "alive", host: 20, containerId: "a".repeat(64), state: "attached" });
    corruptRecord("rf-20260907-abcde9");
    const stranded = { ...servedFile(sessionContainerRecordFixture()), sessionKey: "c".repeat(64), sourceIp: "172.31.90.33" };
    const fake = fakeDocker({ served: [servedFile(live), stranded], containers: [snapshotOf(live)] });

    const result = await repair(fake);

    expect(result.quarantinedFiles).toEqual(["c".repeat(64)]);
    expect(result.orphanFiles).toEqual(["c".repeat(64)]);
    expect(result.orphanFilesDeleted).toEqual([]);
    expect(fake.effects().some((event) => event.startsWith("delete-session-file:"))).toBe(false);
    // Kept, not lost: the address it named is still reserved, so no peer can
    // be allocated over a session the registry cannot currently account for.
    expect(result.reservedSourceIps).toContain("172.31.90.33");
    // The record really was quarantined by this pass's own enumeration.
    expect(listQuarantinedSessionContainerRecordNamesV2(stateDir)).toHaveLength(1);
  });

  // The reclamation, and the proof the ordinary sweep is unchanged: with the
  // registry legible again the very same file is deleted.
  test("deletes the same unclaimed file once the quarantine is cleared", async () => {
    const live = writeRecord({ liveness: "alive", host: 20, containerId: "a".repeat(64), state: "attached" });
    corruptRecord("rf-20260907-abcde9");
    const stranded = { ...servedFile(sessionContainerRecordFixture()), sessionKey: "c".repeat(64), sourceIp: "172.31.90.33" };
    const served = [servedFile(live), stranded];

    const kept = await repair(fakeDocker({ served, containers: [snapshotOf(live)] }));
    expect(kept.orphanFilesDeleted).toEqual([]);

    fs.rmSync(sessionContainerQuarantineRoot(stateDir), { recursive: true, force: true });
    const fake = fakeDocker({ served, containers: [snapshotOf(live)] });
    const result = await repair(fake);

    expect(result.quarantinedFiles).toEqual([]);
    expect(result.orphanFilesDeleted).toEqual(["c".repeat(64)]);
    expect(fake.effects()[0]).toBe(`delete-session-file:${"c".repeat(64)}.json`);
  });

  test("refuses before any effect when the proxy cannot report its files", async () => {
    writeRecord({ liveness: "dead", host: 20, containerId: "a".repeat(64) });
    const fake = fakeDocker({ servedStatus: 1 });

    await expect(repair(fake)).rejects.toMatchObject({
      name: "RuntimeObservationError",
      evidence: { kind: "observation-unavailable", subject: "proxy", expectedIdentity: PROXY_ID },
    });

    expect(fake.effects()).toEqual([]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(1);
  });

  test("refuses an unparseable listing and names the remedy that reclaims it", async () => {
    const fake = fakeDocker({ servedRaw: "not json\n" });

    await expect(repair(fake)).rejects.toThrow(/runfree up/);

    expect(fake.effects()).toEqual([]);
  });

  test("a rerun once the proxy answers proceeds through the same sweep", async () => {
    const orphan = { ...servedFile(sessionContainerRecordFixture()), sessionKey: "c".repeat(64), sourceIp: "172.31.90.35" };
    await expect(repair(fakeDocker({ servedStatus: 1 }))).rejects.toThrow();

    const answering = fakeDocker({ served: [orphan] });
    const result = await repair(answering);

    expect(result.orphanFilesDeleted).toEqual(["c".repeat(64)]);
  });

  test("tears a dead owner's session down file first and drops its record last", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 20, containerId: "a".repeat(64), state: "attached" });
    const fake = fakeDocker({ served: [servedFile(abandoned)] });

    const result = await repair(fake);

    expect(result.deadOwnersRevoked).toEqual([abandoned.sessionId]);
    expect(fake.effects()).toEqual([
      `delete-session-file:${abandoned.sessionPrincipal}.json`,
      `docker:network disconnect ${NETWORK.networkId} ${"a".repeat(64)}`,
      `docker:container stop --time 10 ${"a".repeat(64)}`,
      `docker:container rm --force ${"a".repeat(64)}`,
      "publish-eligibility",
    ]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toEqual([]);
    // The terminal stamp is written before the file is touched and cleared
    // once the record is gone.
    expect(readSessionHostStatus(stateDir, abandoned.sessionId)).toBeUndefined();
  });

  test("keeps a dead owner's record until its own file is proved gone", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 20, containerId: "a".repeat(64), state: "attached" });
    const survivingRecords: number[] = [];
    const fake = fakeDocker({
      served: [servedFile(abandoned)],
      observe: (label) => {
        if (!label.startsWith("delete-session-file:")) return;
        survivingRecords.push(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT).length);
      },
    });

    await repair(fake);

    // The record reserves the session's address, so it may not be released
    // until the file that grants the session anything is gone.
    expect(survivingRecords).toEqual([1]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toEqual([]);
  });

  test("refuses, and keeps everything, when a dead owner's file cannot be deleted", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 20, containerId: "a".repeat(64), state: "attached" });
    const fake = fakeDocker({
      served: [servedFile(abandoned)],
      deleteAnswer: { status: 1, stdout: "", stderr: "unsafe session file" },
    });

    // The raw delete-script failure (stderr text, no remedy) is wrapped at the
    // reconcile boundary into an operator-actionable refusal: it names the
    // blocked session, says the record is kept on purpose, and names both
    // reclamations — a rerun for a transient hiccup, `destroy --force` for a
    // file the proxy refuses to remove — never the raw stderr or a stack.
    const refusal: unknown = await repair(fake).catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(CliError);
    const message = (refusal as Error).message;
    expect(message).toContain(abandoned.sessionId);
    expect(message).toContain("its session file could not be removed from the proxy");
    expect(message).toContain("runfree up");
    expect(message).toContain("runfree destroy --force");
    expect(message).not.toContain("unsafe session file");

    // Stopped at the delete: no disconnect, no stop, no removal, and above all
    // the record — and therefore the address — is still reserved. The
    // eligibility that follows names the same surviving record, so it takes
    // nothing away either.
    expect(fake.effects()).toEqual([
      `delete-session-file:${abandoned.sessionPrincipal}.json`,
      "publish-eligibility",
    ]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(1);
  });

  test("a rerun once the blocked delete succeeds completes the teardown and drops the record", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 23, containerId: "a".repeat(64), state: "attached" });
    const blocked = fakeDocker({
      served: [servedFile(abandoned)],
      deleteAnswer: { status: 1, stdout: "", stderr: "unsafe session file" },
    });

    await expect(repair(blocked)).rejects.toMatchObject({ name: "CliError" });
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(1);

    const succeeding = fakeDocker({ served: [servedFile(abandoned)] });
    const result = await repair(succeeding);

    expect(result.deadOwnersRevoked).toEqual([abandoned.sessionId]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toEqual([]);
  });

  test("collects a failed eligibility republish instead of dropping an earlier teardown failure", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 24, containerId: "a".repeat(64), state: "attached" });
    const fake = fakeDocker({
      served: [servedFile(abandoned)],
      deleteAnswer: { status: 1, stdout: "", stderr: "unsafe session file" },
      proxyInspectFails: true,
    });

    const refusal: unknown = await repair(fake).catch((error: unknown) => error);

    // Both failures must survive: the blocked teardown from step 2, and the
    // eligibility publish that step 5 could not make because the proxy answers
    // not-running. Before this fix, republishEligibility's own throw replaced
    // failures collected earlier instead of joining them.
    expect(refusal).toBeInstanceOf(AggregateError);
    const errors = (refusal as AggregateError).errors;
    expect(errors).toHaveLength(2);
    expect(errors.some((error) => error instanceof CliError)).toBe(true);
    expect(errors.some((error) => error instanceof RuntimeObservationError)).toBe(true);
    // Neither failure took an effect it should not have: the record survives.
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(1);
  });

  test("removes a dead owner's record that never bound a container", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 21 });
    const fake = fakeDocker({ served: [] });

    const result = await repair(fake);

    expect(result.deadOwnersRevoked).toEqual([abandoned.sessionId]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toEqual([]);
    expect(fake.effects().some((event) => event.startsWith("docker:container"))).toBe(false);
  });

  test("leaves a live owner's record, file, and container exactly as it found them", async () => {
    const live = writeRecord({ liveness: "alive", host: 20, containerId: "a".repeat(64), state: "attached" });
    const fake = fakeDocker({ served: [servedFile(live)], containers: [snapshotOf(live)] });

    const result = await repair(fake);

    expect(result).toMatchObject({
      orphanFilesDeleted: [],
      deadOwnersRevoked: [],
      orphanContainersRemoved: [],
      unknownOwners: [],
    });
    // Nothing but the eligibility publication, which names the live session's
    // own materialization and takes nothing away.
    expect(fake.effects()).toEqual(["publish-eligibility"]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(1);
  });

  test("reports an unprovable owner and leaves its session alone", async () => {
    const unknown = writeRecord({ liveness: "unknown", host: 20, containerId: "a".repeat(64), state: "attached" });
    const fake = fakeDocker({ served: [servedFile(unknown)], containers: [snapshotOf(unknown)] });

    const result = await repair(fake);

    expect(result.unknownOwners).toEqual([unknown.sessionId]);
    expect(result.deadOwnersRevoked).toEqual([]);
    expect(fake.effects()).toEqual(["publish-eligibility"]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(1);
  });

  test("removes a session container no record claims", async () => {
    const claimed = sessionContainerRecordFixture({
      containerId: "b".repeat(64),
      overrides: {
        sessionId: "rf-20260907-orphan1",
        sessionIncarnation: "9".repeat(64),
        sessionPrincipal: `9${"e".repeat(63)}`,
        containerName: `runfree-${SESSION_TEST_PROJECT.projectId}-session-rf-20260907-orphan1`,
        sourceIp: "172.31.90.25",
      },
    });
    const fake = fakeDocker({ served: [], containers: [snapshotOf(claimed)] });

    const result = await repair(fake);

    expect(result.orphanContainersRemoved).toEqual(["b".repeat(64)]);
    expect(fake.effects()).toEqual([
      `docker:container stop --time 10 ${"b".repeat(64)}`,
      `docker:container rm ${"b".repeat(64)}`,
      `absence-list:${"b".repeat(64)}`,
      "network-inspect",
      "publish-eligibility",
    ]);
  });

  test("narrows eligibility once a retired materialization's last record is gone, and keeps a live one", async () => {
    const retired = olderAgentGeneration("retired");
    const surviving = olderAgentGeneration("surviving");
    const abandoned = writeRecord({
      liveness: "dead",
      host: 20,
      containerId: "a".repeat(64),
      generation: retired,
      state: "attached",
    });
    const live = writeRecord({
      liveness: "alive",
      host: 21,
      containerId: "b".repeat(64),
      generation: surviving,
      state: "attached",
    });
    const fake = fakeDocker({
      served: [servedFile(abandoned), servedFile(live)],
      containers: [snapshotOf(live)],
    });

    await repair(fake);

    expect(publishedAgents(fake)).toEqual([
      sessionAgentMaterializationFixture().selectedAgentImageId,
      surviving.selectedAgentImageId,
    ].sort());
    expect(publishedAgents(fake)).not.toContain(retired.selectedAgentImageId);
  });

  test("publishes eligibility once: a second reconcile that changes nothing writes nothing", async () => {
    const live = writeRecord({ liveness: "alive", host: 20, containerId: "a".repeat(64), state: "attached" });
    const first = fakeDocker({ served: [servedFile(live)], containers: [snapshotOf(live)] });
    await repair(first);

    const second = fakeDocker({ served: [servedFile(live)], containers: [snapshotOf(live)] });
    await repair(second);

    expect(first.effects()).toEqual(["publish-eligibility"]);
    expect(second.effects()).toEqual([]);
  });

  test("holds the lifecycle lock before every effect", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 20, containerId: "a".repeat(64), state: "attached" });
    const fake = fakeDocker({ served: [servedFile(abandoned)] });
    let held = true;
    const lock: ProjectLifecycleLock = {
      ownerToken: "a".repeat(64),
      assertHeld: vi.fn(() => {
        if (!held) throw new Error("lifecycle lock is not held");
      }),
      release: vi.fn(),
    };

    await repair(fake, lock);
    expect(lock.assertHeld).toHaveBeenCalled();

    held = false;
    await expect(repair(fakeDocker({ served: [] }), lock)).rejects.toThrow("lifecycle lock is not held");
  });
});

describe("reconcile in report mode", () => {
  beforeEach(() => {
    selectFileBackedControlPlane();
    selectDesiredAgent();
  });

  test("issues no write, delete, or stop, and never takes the lock", async () => {
    const abandoned = writeRecord({ liveness: "dead", host: 20, containerId: "a".repeat(64), state: "attached" });
    const unknown = writeRecord({ liveness: "unknown", host: 21, containerId: "b".repeat(64), state: "attached" });
    writeSessionHostStatus(stateDir, {
      v: 1,
      sessionId: abandoned.sessionId,
      lastHeartbeatAt: "2026-09-07T12:00:00.000Z",
      aliveUntil: "2026-09-07T12:05:00.000Z",
      served: "served",
    });
    const orphanKey = "c".repeat(64);
    const fake = fakeDocker({
      served: [servedFile(unknown), { ...servedFile(abandoned), sessionKey: orphanKey, sourceIp: "172.31.90.40" }],
    });
    const lock = lifecycleLock();

    const result = await reconcileSessions({
      stateDir,
      expectedProject: SESSION_TEST_PROJECT,
      io: fake.io,
      proxyId: PROXY_ID,
      env: ENV,
      lifecycleLock: lock,
      mode: "report",
    });

    expect(fake.events).toEqual(["read-served-set"]);
    expect(lock.assertHeld).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      orphanFilesDeleted: [],
      deadOwnersRevoked: [],
      orphanContainersRemoved: [],
      unknownOwners: [unknown.sessionId],
    });
    // Mid-teardown states are reported, not repaired.
    expect(result.orphanFiles).toEqual([orphanKey]);
    expect(result.recordsWithoutFiles).toEqual([abandoned.sessionId]);
    expect(listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT)).toHaveLength(2);
    expect(readSessionHostStatus(stateDir, abandoned.sessionId)?.served).toBe("served");
  });

  test("still refuses when the proxy cannot report its files", async () => {
    const fake = fakeDocker({ servedStatus: 1 });

    await expect(reconcileSessions({
      stateDir,
      expectedProject: SESSION_TEST_PROJECT,
      io: fake.io,
      proxyId: PROXY_ID,
      env: ENV,
      lifecycleLock: lifecycleLock(),
      mode: "report",
    })).rejects.toBeInstanceOf(RuntimeObservationError);
  });
});
