// Warm validation beside live peer sessions: the acceptance contract.
//
// `tryWarmPeerValidation` is not implemented yet, so every test that asks it
// for a verdict is declared `test.fails`: it fails today and must pass once the
// implementation lands, at which point `.fails` comes off. The fixture
// self-checks at the top run normally: they prove the healthy-peer fixture is
// exactly what the validators restore and reconcile already run accept, so
// the positive cases below fail only because the judgement does not exist.
//
// Real state directory and real lifecycle records; only the Docker daemon is a
// fake, the stable warm validation's seal is bypassed so a test can hand it
// any peer evidence, and each peer's proof plan is the harness plan its
// container inspect was rendered from (the plan restore would rebuild).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("./warm-proof.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./warm-proof.ts")>(),
  assertWarmValidation: () => undefined,
}));
vi.mock("./session-admission-driver-preflight.ts", async (importOriginal) => {
  const harness = await import("./session-container.test-harness.ts");
  return {
    ...await importOriginal<typeof import("./session-admission-driver-preflight.ts")>(),
    createRetainedSessionRebindProofPlan: (input: Readonly<{ replacementRecord: SessionContainerRecordV2 }>) => (
      harness.sessionContainerCreatePlanFixture({ record: input.replacementRecord })
    ),
  };
});

import { sessionRegistryDigest } from "./launch-handoff.ts";
import { boundCallbackForwarder } from "./session-callback-ingress.test-harness.ts";
import {
  classifySessionContainerReconciliation,
  inspectSessionContainerInventory,
} from "./session-container-reconciliation.ts";
import { validateSessionContainerInspect } from "./session-container-proof.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  sessionContainerCreatePlanFixture,
  sessionContainerInspectJsonFixture,
  sessionContainerRecordFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  listSessionContainerRecordsV2,
  sessionContainerRecordsRoot,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { writeSessionHostStatus } from "./session-host-status.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import { parseProxySessionFileListing } from "./session-reconcile.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeIO } from "./types.ts";
import { validateInternalNetworkParticipants } from "./utility-containers.ts";
import {
  assertWarmPeerValidation,
  consumeWarmPeerValidation,
  tryWarmPeerValidation,
  type WarmPeerConsumptionBinding,
  type WarmPeerEvidence,
  type WarmPeerMissReason,
  type WarmPeerProofInput,
  type WarmPeerValidation,
  type WarmPeerVerdict,
} from "./warm-peer-proof.ts";
import type { WarmValidation } from "./warm-proof.ts";

const EFFECTIVE = effectiveControlPlaneFixture();
const PROXY_ID = EFFECTIVE.proxyContainerId;
const PROXY_STARTED_AT = "2026-10-11T09:00:05.123456789Z";
const PROXY_IP = "172.31.90.2";
const PROXY_ENDPOINT = "1".repeat(64);
const INTERNAL_NETWORK = `${SESSION_TEST_PROJECT.composeProject}_agent_internal`;
const EFFECTIVE_POLICY_GENERATION = `sha256:${"4".repeat(64)}`;
const BOOT_THIS = "linux:11111111-2222-3333-4444-555555555555";
const BOOT_PREVIOUS = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
const PROCESS_THIS = "linux:12345";
const PROCESS_OTHER = "linux:54321";

/** Host identity under which the fixture owners are alive. */
const ENV: NodeJS.ProcessEnv = Object.freeze({
  RUNFREE_TEST_FAKE_DOCKER: "1",
  RUNFREE_TEST_HOST_BOOT_ID: BOOT_THIS,
  RUNFREE_TEST_HOST_PROCESS_START: PROCESS_THIS,
});

type OwnerLiveness = "alive" | "dead-boot" | "other-process" | "unknown";

function ownership(liveness: OwnerLiveness): Partial<SessionContainerRecordV2> {
  if (liveness === "dead-boot") return { hostPid: process.pid, hostBootId: BOOT_PREVIOUS, hostProcessStart: PROCESS_THIS };
  // A live PID that is not the owner: same boot, another process start.
  if (liveness === "other-process") return { hostPid: process.pid, hostBootId: BOOT_THIS, hostProcessStart: PROCESS_OTHER };
  if (liveness === "unknown") return { hostPid: process.pid, hostBootId: BOOT_THIS };
  return { hostPid: process.pid, hostBootId: BOOT_THIS, hostProcessStart: PROCESS_THIS };
}

let tmp: string;
let stateDir: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-warm-peer-"));
  stateDir = path.join(tmp, "state");
  fs.mkdirSync(stateDir, { recursive: true });
});

afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

/** One attached peer record with a distinct identity and address. */
function peerRecord(index: number, options: {
  liveness?: OwnerLiveness;
  state?: SessionContainerRecordV2["state"];
  overrides?: Partial<SessionContainerRecordV2>;
} = {}): SessionContainerRecordV2 {
  const digit = String(index % 10);
  const sessionId = `rf-20261011-peer${String(index).padStart(2, "0")}`;
  const base = sessionContainerRecordFixture({
    containerId: `${(index % 16).toString(16)}${"c".repeat(63)}`,
    overrides: {
      sessionId,
      sessionIncarnation: `${digit}${"d".repeat(63)}`,
      sessionPrincipal: `${(index % 16).toString(16)}${"f".repeat(63)}`,
      containerName: `runfree-${SESSION_TEST_PROJECT.projectId}-session-${sessionId}`,
      sourceIp: `172.31.90.${20 + index}`,
      ...ownership(options.liveness ?? "alive"),
    },
  });
  return {
    ...base,
    state: options.state ?? "attached",
    admittedAt: "2026-10-11T09:01:00.000Z",
    leaseGeneration: "8".repeat(32),
    leaseExpiresAt: "2026-10-11T09:06:00.000Z",
    ...options.overrides,
  };
}

function writePeer(record: SessionContainerRecordV2): SessionContainerRecordV2 {
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
  return record;
}

function endpointOf(record: SessionContainerRecordV2): string {
  return `${record.sessionPrincipal.slice(0, 1)}${"e".repeat(63)}`;
}

/** The running peer container exactly as Docker reports it, from the plan restore would rebuild. */
function peerInspect(record: SessionContainerRecordV2): DockerContainerInspect {
  const [inspect] = JSON.parse(sessionContainerInspectJsonFixture(
    sessionContainerCreatePlanFixture({ record }),
    { running: true },
  )) as DockerContainerInspect[];
  const network = inspect.NetworkSettings?.Networks?.[INTERNAL_NETWORK] as Record<string, unknown> | undefined;
  if (network) network.EndpointID = endpointOf(record);
  return inspect;
}

const PROXY_INSPECT: DockerContainerInspect = Object.freeze({
  Id: PROXY_ID,
  Config: { Labels: {} },
  HostConfig: {},
  State: { Running: true, Status: "running", StartedAt: PROXY_STARTED_AT, Pid: 4242 },
}) as DockerContainerInspect;

/** Everything the stable observation's inspect and batch would report for these healthy peers. */
function healthyEvidence(records: readonly SessionContainerRecordV2[]): WarmPeerEvidence {
  return {
    sessionFiles: records.map((record) => ({
      sessionKey: record.sessionPrincipal,
      name: `${record.sessionPrincipal}.json`,
      sourceIp: record.sourceIp,
      malformed: false,
      aliveUntil: "2026-10-11T09:06:00.000Z",
      eligible: true,
      wallActive: true,
    })),
    sessionSetMembers: records.map((record) => record.sourceIp),
    ipAssignments: Object.fromEntries(records.map((record) => [
      record.sourceIp,
      { sessionKey: record.sessionPrincipal, state: "ready" as const },
    ])),
    requestProxyGeneration: EFFECTIVE_POLICY_GENERATION,
    internalNetworkContainers: {
      [PROXY_ID]: { IPv4Address: `${PROXY_IP}/24`, EndpointID: PROXY_ENDPOINT },
      ...Object.fromEntries(records.map((record) => [
        record.containerId as string,
        { IPv4Address: `${record.sourceIp}/24`, EndpointID: endpointOf(record) },
      ])),
    },
    participants: [PROXY_INSPECT, ...records.map(peerInspect)],
  };
}

/** A stable warm match carrying `evidence`; the seal is bypassed by the mock above. */
function stable(evidence: WarmPeerEvidence | undefined, proxyStartedAt = PROXY_STARTED_AT): WarmValidation {
  return {
    runtimeProof: { proxyId: PROXY_ID },
    proxyStartedAt,
    proxyPid: 4242,
    bootId: "0b0b0b0b-1111-2222-3333-444444444444",
    sessionState: { kind: "blocked", reason: "session-files-present" },
    ...(evidence ? { peerEvidence: evidence } : {}),
  } as unknown as WarmValidation;
}

type FakeDocker = Readonly<{ io: RuntimeIO; calls: string[][] }>;

/**
 * Docker answering the judgement's reads by argv: the host-wide inventory
 * listing (`ps`), container inspects (the inventory, or the proxy's incarnation
 * re-read), and image inspects. Anything else is recorded and refused, so a
 * test can assert that a verdict made no other Docker call.
 */
function fakeDocker(options: {
  inventory: readonly DockerContainerInspect[];
  proxyAfter?: Readonly<{ running: boolean; startedAt: string }>;
  listStatus?: number;
  inspectStatus?: number | null;
}): FakeDocker {
  const calls: string[][] = [];
  const capture = (_command: string, args: string[]): CaptureResult => {
    calls.push([...args]);
    if (args[0] === "ps" && !args.includes("--filter")) {
      if (options.listStatus !== undefined) return { status: options.listStatus, stdout: "", stderr: "daemon unavailable" };
      return { status: 0, stdout: options.inventory.map((container) => `${container.Id}\n`).join(""), stderr: "" };
    }
    const inspectIds = args[0] === "inspect" ? args.slice(1).filter((arg) => /^[a-f0-9]{64}$/.test(arg))
      : args[0] === "container" && args[1] === "inspect" ? args.slice(2).filter((arg) => /^[a-f0-9]{64}$/.test(arg))
        : undefined;
    if (inspectIds?.length === 1 && inspectIds[0] === PROXY_ID) {
      const after = options.proxyAfter ?? { running: true, startedAt: PROXY_STARTED_AT };
      return {
        status: 0,
        stdout: JSON.stringify([{ ...PROXY_INSPECT, State: { ...PROXY_INSPECT.State, Running: after.running, StartedAt: after.startedAt } }]),
        stderr: "",
      };
    }
    if (inspectIds) {
      if (options.inspectStatus !== undefined) {
        return { status: options.inspectStatus as number, stdout: "", stderr: "timed out" };
      }
      return {
        status: 0,
        stdout: JSON.stringify(inspectIds.map((id) => options.inventory.find((container) => container.Id === id))),
        stderr: "",
      };
    }
    return { status: 1, stdout: "", stderr: `unexpected docker call: ${args.join(" ")}` };
  };
  return { io: { capture } as unknown as RuntimeIO, calls };
}

/** Every Docker call a verdict may make: reads only. */
function onlyReads(calls: readonly string[][]): boolean {
  return calls.every((args) => args[0] === "ps"
    || args[0] === "inspect"
    || (args[0] === "container" && args[1] === "inspect")
    || (args[0] === "image" && args[1] === "inspect"));
}

function heldLock(): ProjectLifecycleLock {
  return { ownerToken: "a".repeat(64), assertHeld: vi.fn(), release: vi.fn() };
}

function input(overrides: Partial<WarmPeerProofInput> & { fake: FakeDocker }): WarmPeerProofInput {
  const { fake, ...rest } = overrides;
  return {
    stable: stable(undefined),
    stateDir,
    expectedProject: SESSION_TEST_PROJECT,
    effective: EFFECTIVE,
    effectiveManifest: controlPlaneMaterializationFixture(),
    effectivePolicyGeneration: EFFECTIVE_POLICY_GENERATION,
    lifecycleLock: heldLock(),
    io: fake.io,
    docker: { inspectImage: vi.fn(() => undefined) },
    dockerOptions: {},
    env: ENV,
    runfreeVersion: "0.3.0",
    ...rest,
  };
}

/** The bytes of every lifecycle record, so a test can prove a verdict changed none. */
function registryBytes(): Record<string, string> {
  const root = sessionContainerRecordsRoot(stateDir);
  if (!fs.existsSync(root)) return {};
  return Object.fromEntries(fs.readdirSync(root).sort().map((name) => [name, fs.readFileSync(path.join(root, name), "utf8")]));
}

/**
 * Healthy peers, with evidence and a daemon that agree on them. `recorded`
 * changes what the registry holds for a peer (records are written once, never
 * replaced) while the evidence still shows the healthy peer.
 */
function healthyPeers(
  count: number,
  recorded: (record: SessionContainerRecordV2, index: number) => SessionContainerRecordV2 = (record) => record,
) {
  const records = Array.from({ length: count }, (_, index) => peerRecord(index));
  for (const [index, record] of records.entries()) writePeer(recorded(record, index));
  const evidence = healthyEvidence(records);
  const inventory = records.map(peerInspect);
  return { records, evidence, inventory };
}

function expectMiss(verdict: WarmPeerVerdict, reason: WarmPeerMissReason): void {
  expect(verdict.kind).toBe("miss");
  if (verdict.kind === "miss") expect(verdict.reason).toBe(reason);
}

describe("the healthy-peer fixture (self-check, runs today)", () => {
  test.each([1, 10])("%i healthy peers pass the validators restore and reconcile already run", (count) => {
    const { records, evidence, inventory } = healthyPeers(count);
    const fake = fakeDocker({ inventory });
    const listed = listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT);
    expect(listed).toHaveLength(count);
    // Reconcile's classification: every record has exactly its container.
    const classifications = classifySessionContainerReconciliation({
      expectedProject: SESSION_TEST_PROJECT,
      records: listed,
      containers: inspectSessionContainerInventory(
        (executable, args, options) => fake.io.capture(executable, [...args], options ?? {}),
        SESSION_TEST_PROJECT,
      ),
    });
    expect(classifications.map((classification) => classification.kind)).toEqual(records.map(() => "matching"));
    for (const record of records) {
      // Restore's per-session proof over the same inspect bytes.
      const plan = sessionContainerCreatePlanFixture({ record });
      expect(() => validateSessionContainerInspect(JSON.stringify([peerInspect(record)]), plan, { kind: "active-running" }))
        .not.toThrow();
      expect(sessionRecordOwnerLiveness(record, ENV)).toBe("alive");
    }
    expect(parseProxySessionFileListing(JSON.stringify(evidence.sessionFiles))).toHaveLength(count);
    // The topology's participant rule accepts the proxy and the session agents.
    expect(validateInternalNetworkParticipants({
      attached: [...evidence.participants],
      internalNetwork: INTERNAL_NETWORK,
      projectId: SESSION_TEST_PROJECT.projectId,
      proxy: PROXY_INSPECT,
    })).toEqual([]);
    expect(onlyReads(fake.calls)).toBe(true);
  });

  test("the owner fixtures read as the liveness they are named for", () => {
    expect(sessionRecordOwnerLiveness(peerRecord(0, { liveness: "dead-boot" }), ENV)).toBe("dead");
    expect(sessionRecordOwnerLiveness(peerRecord(0, { liveness: "other-process" }), ENV)).toBe("dead");
    expect(sessionRecordOwnerLiveness(peerRecord(0, { liveness: "unknown" }), ENV)).toBe("unknown");
  });
});

describe("the sealed warm peer validation (runs today)", () => {
  test("cannot be built by hand", () => {
    const forged = { kind: "warm-peer", proxyId: PROXY_ID, peers: [] };
    expect(() => assertWarmPeerValidation(forged)).toThrow("warm peer validation was not minted by the warm peer judgement");
  });

  test("a hand-built twin is never consumed", () => {
    const binding: WarmPeerConsumptionBinding = {
      lockOwnerToken: "a".repeat(64),
      proxyId: PROXY_ID,
      proxyStartedAt: PROXY_STARTED_AT,
      registryDigest: `sha256:${"0".repeat(64)}`,
      effectivePolicyGeneration: EFFECTIVE_POLICY_GENERATION,
      controlPlaneGenerationDigest: EFFECTIVE.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: EFFECTIVE.controlPlaneMaterializationDigest,
      admissionContractEpoch: EFFECTIVE.admissionContractEpoch,
    };
    for (const value of [undefined, null, "warm-peer", { kind: "warm-peer", ...binding }]) {
      expect(consumeWarmPeerValidation(value, binding)).toBe(false);
    }
  });
});

describe("tryWarmPeerValidation: matches (acceptance, fails until implemented)", () => {
  test.fails.each([1, 2, 10])("%i fully accounted, live-owned, currently bound peers match", (count) => {
    const { records, evidence, inventory } = healthyPeers(count);
    const fake = fakeDocker({ inventory });
    const before = registryBytes();
    const lock = heldLock();
    const verdict = tryWarmPeerValidation(input({ fake, stable: stable(evidence), lifecycleLock: lock }));
    expect(verdict.kind).toBe("match");
    if (verdict.kind !== "match") return;
    const validation: WarmPeerValidation = verdict.validation;
    expect(() => assertWarmPeerValidation(validation)).not.toThrow();
    expect(Object.isFrozen(validation)).toBe(true);
    expect(validation.peers.map((peer) => peer.sessionId).sort()).toEqual(records.map((record) => record.sessionId).sort());
    expect(validation.registryDigest).toBe(sessionRegistryDigest(stateDir, SESSION_TEST_PROJECT));
    expect(validation.proxyId).toBe(PROXY_ID);
    expect(validation.proxyStartedAt).toBe(PROXY_STARTED_AT);
    expect(validation.observationEpoch.startedAtBefore).toBe(PROXY_STARTED_AT);
    expect(validation.observationEpoch.startedAtAfter).toBe(PROXY_STARTED_AT);
    expect(validation.lockOwnerToken).toBe(lock.ownerToken);
    expect(validation.effectivePolicyGeneration).toBe(EFFECTIVE_POLICY_GENERATION);
    expect(validation.controlPlaneGenerationDigest).toBe(EFFECTIVE.controlPlaneGenerationDigest);
    // Judged under the held lock, with reads only, changing no record.
    expect(lock.assertHeld).toHaveBeenCalled();
    expect(onlyReads(fake.calls)).toBe(true);
    expect(registryBytes()).toEqual(before);
  });

  test.fails("a peer with its own mcp-callback forwarder matches and names that forwarder", () => {
    const { records, evidence, inventory } = healthyPeers(1);
    const peer = records[0] as SessionContainerRecordV2;
    const forwarder = boundCallbackForwarder({
      composeProject: SESSION_TEST_PROJECT.composeProject,
      projectId: SESSION_TEST_PROJECT.projectId,
      hostPort: "47100",
      containerId: "b".repeat(64),
      sessionId: peer.sessionId,
      sessionContainerId: peer.containerId as string,
      target: peer.sourceIp,
    });
    const verdict = tryWarmPeerValidation(input({
      fake: fakeDocker({ inventory }),
      stable: stable({
        ...evidence,
        internalNetworkContainers: {
          ...evidence.internalNetworkContainers,
          [forwarder.Id as string]: { IPv4Address: "172.31.90.12/24", EndpointID: "b".repeat(64) },
        },
        participants: [...evidence.participants, forwarder],
      }),
    }));
    expect(verdict.kind).toBe("match");
    if (verdict.kind === "match") expect(verdict.validation.peers[0]?.callbackForwarderId).toBe(forwarder.Id);
  });

  test.fails("a matched validation is consumed once, only with its exact binding", () => {
    const { evidence, inventory } = healthyPeers(2);
    const lock = heldLock();
    const verdict = tryWarmPeerValidation(input({ fake: fakeDocker({ inventory }), stable: stable(evidence), lifecycleLock: lock }));
    if (verdict.kind !== "match") throw new Error(`expected a match, got ${verdict.reason}`);
    const validation = verdict.validation;
    const binding: WarmPeerConsumptionBinding = {
      lockOwnerToken: lock.ownerToken,
      proxyId: PROXY_ID,
      proxyStartedAt: PROXY_STARTED_AT,
      registryDigest: sessionRegistryDigest(stateDir, SESSION_TEST_PROJECT),
      effectivePolicyGeneration: EFFECTIVE_POLICY_GENERATION,
      controlPlaneGenerationDigest: EFFECTIVE.controlPlaneGenerationDigest,
      controlPlaneMaterializationDigest: EFFECTIVE.controlPlaneMaterializationDigest,
      admissionContractEpoch: EFFECTIVE.admissionContractEpoch,
    };
    // Any one field that differs refuses and leaves the validation unconsumed.
    for (const change of [
      { lockOwnerToken: "f".repeat(64) },
      { proxyId: "9".repeat(64) },
      { proxyStartedAt: "2026-10-11T09:30:00.000000000Z" },
      { registryDigest: `sha256:${"1".repeat(64)}` },
      { effectivePolicyGeneration: `sha256:${"5".repeat(64)}` },
      { controlPlaneGenerationDigest: `sha256:${"6".repeat(64)}` },
      { controlPlaneMaterializationDigest: `sha256:${"7".repeat(64)}` },
      { admissionContractEpoch: binding.admissionContractEpoch + 1 },
    ] satisfies Partial<WarmPeerConsumptionBinding>[]) {
      expect(consumeWarmPeerValidation(validation, { ...binding, ...change })).toBe(false);
    }
    expect(consumeWarmPeerValidation({ ...validation }, binding)).toBe(false);
    expect(consumeWarmPeerValidation(validation, binding)).toBe(true);
    expect(consumeWarmPeerValidation(validation, binding)).toBe(false);
  });
});

/**
 * One falsification case: a change to the healthy two-peer world, and the miss
 * it must produce. Every miss is a read-only verdict that changes no record.
 */
type MissCase = Readonly<{
  label: string;
  reason: WarmPeerMissReason;
  /** What the registry holds for the first peer instead of its healthy record. */
  firstRecorded?: (record: SessionContainerRecordV2) => SessionContainerRecordV2;
  arrange?: (world: {
    records: SessionContainerRecordV2[];
    evidence: WarmPeerEvidence;
    inventory: DockerContainerInspect[];
  }) => Readonly<{
    evidence?: WarmPeerEvidence;
    inventory?: DockerContainerInspect[];
    docker?: Partial<Parameters<typeof fakeDocker>[0]>;
    stableEvidence?: "absent";
  }> | undefined;
}>;

const EXTERNAL_ID = "e1".repeat(32);
const ORPHAN_SESSION_ID = "rf-20261011-orphan";

const MISS_CASES: readonly MissCase[] = [
  {
    label: "a peer record whose container is gone from the network and the inventory (an omitted peer)",
    reason: "peer-container-missing",
    arrange: ({ records, evidence, inventory }) => {
      const [first] = records as [SessionContainerRecordV2];
      const { [first.containerId as string]: _gone, ...containers } = evidence.internalNetworkContainers;
      return {
        evidence: { ...evidence, internalNetworkContainers: containers, participants: evidence.participants.filter((one) => one.Id !== first.containerId) },
        inventory: inventory.filter((one) => one.Id !== first.containerId),
      };
    },
  },
  {
    label: "a peer whose session file the proxy does not hold",
    reason: "peer-file-missing",
    arrange: ({ records, evidence }) => ({
      evidence: { ...evidence, sessionFiles: evidence.sessionFiles.filter((file) => file.sessionKey !== records[0]?.sessionPrincipal) },
    }),
  },
  {
    label: "a peer whose session file has expired on the proxy's clock",
    reason: "peer-file-expired",
    arrange: ({ evidence }) => ({
      evidence: { ...evidence, sessionFiles: evidence.sessionFiles.map((file, index) => (index === 0 ? { ...file, wallActive: false } : file)) },
    }),
  },
  {
    label: "a peer whose session file the proxy's eligibility does not admit",
    reason: "peer-file-ineligible",
    arrange: ({ evidence }) => ({
      evidence: { ...evidence, sessionFiles: evidence.sessionFiles.map((file, index) => (index === 0 ? { ...file, eligible: false } : file)) },
    }),
  },
  {
    label: "a peer whose session file names another address",
    reason: "peer-file-address",
    arrange: ({ evidence }) => ({
      evidence: { ...evidence, sessionFiles: evidence.sessionFiles.map((file, index) => (index === 0 ? { ...file, sourceIp: "172.31.90.99" } : file)) },
    }),
  },
  {
    label: "a session file no record claims",
    reason: "orphan-file",
    arrange: ({ evidence }) => ({
      evidence: {
        ...evidence,
        sessionFiles: [...evidence.sessionFiles, {
          sessionKey: "9".repeat(64), name: `${"9".repeat(64)}.json`, sourceIp: "172.31.90.60", malformed: false, eligible: true, wallActive: true,
        }],
      },
    }),
  },
  {
    label: "a malformed session file",
    reason: "orphan-file",
    arrange: ({ evidence }) => ({
      evidence: { ...evidence, sessionFiles: [...evidence.sessionFiles, { name: "not-a-key.json", malformed: true }] },
    }),
  },
  {
    label: "a forged owner: the recorded PID is live but is another process",
    reason: "peer-owner-dead",
    firstRecorded: (record) => ({ ...record, ...ownership("other-process") }),
  },
  {
    label: "an owner recorded on a previous host boot",
    reason: "peer-owner-dead",
    firstRecorded: (record) => ({ ...record, ...ownership("dead-boot") }),
  },
  {
    label: "an owner that cannot be proved either way (unknown is never dead, and never live)",
    reason: "peer-owner-unknown",
    firstRecorded: ({ hostProcessStart: _unprovable, ...record }) => ({ ...record, ...ownership("unknown") }),
  },
  {
    label: "a peer record still provisioning-running",
    reason: "peer-state",
    firstRecorded: (record) => ({ ...record, state: "provisioning-running" }),
  },
  {
    label: "a peer record in revoking",
    reason: "peer-state",
    firstRecorded: (record) => ({ ...record, state: "revoking" }),
  },
  {
    label: "an attached peer whose host stamp is terminal",
    reason: "peer-terminal-stamp",
    arrange: ({ records }) => {
      const now = new Date().toISOString();
      writeSessionHostStatus(stateDir, {
        v: 1, sessionId: (records[0] as SessionContainerRecordV2).sessionId, lastHeartbeatAt: now, aliveUntil: now, served: "unknown", terminal: "revoking",
      });
      return undefined;
    },
  },
  {
    label: "a peer bound to another control plane generation",
    reason: "peer-generation",
    firstRecorded: (record) => ({ ...record, controlPlaneGenerationDigest: `sha256:${"6".repeat(64)}` }),
  },
  {
    label: "a peer container attached to a second network",
    reason: "peer-container-mismatch",
    arrange: ({ records, evidence, inventory }) => {
      const id = (records[0] as SessionContainerRecordV2).containerId;
      const widen = (container: DockerContainerInspect): DockerContainerInspect => (container.Id !== id ? container : {
        ...container,
        NetworkSettings: {
          ...container.NetworkSettings,
          Networks: { ...container.NetworkSettings?.Networks, bridge: { NetworkID: "a".repeat(64), IPAddress: "172.17.0.9" } },
        },
      });
      return { evidence: { ...evidence, participants: evidence.participants.map(widen) }, inventory: inventory.map(widen) };
    },
  },
  {
    label: "a container with no Runfree identity attached to the internal network (an external participant)",
    reason: "unaccounted-participant",
    arrange: ({ evidence, inventory }) => {
      const external = { Id: EXTERNAL_ID, Name: "/someone-elses", Config: { Labels: {} }, HostConfig: {}, State: { Running: true } } as DockerContainerInspect;
      return {
        evidence: {
          ...evidence,
          internalNetworkContainers: { ...evidence.internalNetworkContainers, [EXTERNAL_ID]: { IPv4Address: "172.31.90.70/24", EndpointID: "2".repeat(64) } },
          participants: [...evidence.participants, external],
        },
        inventory: [...inventory, external],
      };
    },
  },
  {
    label: "an ephemeral helper left on the internal network",
    reason: "unaccounted-participant",
    arrange: ({ evidence }) => {
      const helper = {
        Id: "3".repeat(64),
        Name: `/runfree-${SESSION_TEST_PROJECT.projectId}-helper`,
        Config: { Labels: { "io.runfree.project-id": SESSION_TEST_PROJECT.projectId, "io.runfree.container-role": "ephemeral-helper" } },
        HostConfig: {},
        State: { Running: true },
      } as DockerContainerInspect;
      return {
        evidence: {
          ...evidence,
          internalNetworkContainers: { ...evidence.internalNetworkContainers, [helper.Id as string]: { IPv4Address: "172.31.90.19/24", EndpointID: "3".repeat(64) } },
          participants: [...evidence.participants, helper],
        },
      };
    },
  },
  {
    label: "a session container no record claims (an orphan)",
    reason: "orphan-container",
    arrange: ({ evidence, inventory }) => {
      // A well-formed session container whose record was never written.
      const orphan = peerInspect(peerRecord(7));
      return {
        evidence: {
          ...evidence,
          internalNetworkContainers: { ...evidence.internalNetworkContainers, [orphan.Id as string]: { IPv4Address: "172.31.90.27/24", EndpointID: "7".repeat(64) } },
          participants: [...evidence.participants, orphan],
        },
        inventory: [...inventory, orphan],
      };
    },
  },
  {
    label: "an mcp-callback forwarder bound to a session no peer is",
    reason: "callback-unbound",
    arrange: ({ evidence }) => {
      const forwarder = boundCallbackForwarder({
        composeProject: SESSION_TEST_PROJECT.composeProject,
        projectId: SESSION_TEST_PROJECT.projectId,
        hostPort: "47101",
        containerId: "b".repeat(64),
        sessionId: ORPHAN_SESSION_ID,
        sessionContainerId: "d".repeat(64),
        target: "172.31.90.61",
      });
      return {
        evidence: {
          ...evidence,
          internalNetworkContainers: { ...evidence.internalNetworkContainers, [forwarder.Id as string]: { IPv4Address: "172.31.90.12/24", EndpointID: "b".repeat(64) } },
          participants: [...evidence.participants, forwarder],
        },
      };
    },
  },
  {
    label: "a peer address the firewall's kernel session set does not hold",
    reason: "consumer-firewall",
    arrange: ({ evidence }) => ({ evidence: { ...evidence, sessionSetMembers: evidence.sessionSetMembers.slice(1) } }),
  },
  {
    label: "a kernel session-set member no peer accounts for",
    reason: "consumer-firewall",
    arrange: ({ evidence }) => ({ evidence: { ...evidence, sessionSetMembers: [...evidence.sessionSetMembers, "172.31.90.62"] } }),
  },
  {
    label: "a request proxy serving another effective policy generation",
    reason: "consumer-request-proxy",
    arrange: ({ evidence }) => ({ evidence: { ...evidence, requestProxyGeneration: `sha256:${"5".repeat(64)}` } }),
  },
  {
    label: "an unreadable request-proxy status",
    reason: "consumer-request-proxy",
    arrange: ({ evidence }) => {
      const { requestProxyGeneration: _unread, ...rest } = evidence;
      return { evidence: rest };
    },
  },
  {
    label: "a peer address whose IP assignment is still draining",
    reason: "ip-assignment",
    arrange: ({ records, evidence }) => {
      const first = records[0] as SessionContainerRecordV2;
      return { evidence: { ...evidence, ipAssignments: { ...evidence.ipAssignments, [first.sourceIp]: { sessionKey: first.sessionPrincipal, state: "draining" } } } };
    },
  },
  {
    label: "a peer address whose IP assignment names another session",
    reason: "ip-assignment",
    arrange: ({ records, evidence }) => {
      const first = records[0] as SessionContainerRecordV2;
      return { evidence: { ...evidence, ipAssignments: { ...evidence.ipAssignments, [first.sourceIp]: { sessionKey: "9".repeat(64), state: "ready" } } } };
    },
  },
  {
    label: "the same proxy id restarted in place during the judgement",
    reason: "proxy-incarnation",
    arrange: () => ({ docker: { proxyAfter: { running: true, startedAt: "2026-10-11T09:30:00.000000000Z" } } }),
  },
  {
    label: "the proxy not running at the incarnation re-read",
    reason: "proxy-incarnation",
    arrange: () => ({ docker: { proxyAfter: { running: false, startedAt: PROXY_STARTED_AT } } }),
  },
  {
    label: "a host-wide container listing that fails",
    reason: "inventory-unreadable",
    arrange: () => ({ docker: { listStatus: 1 } }),
  },
  {
    label: "a container inventory inspection cut off by its timeout",
    reason: "inventory-unreadable",
    arrange: () => ({ docker: { inspectStatus: null } }),
  },
  {
    label: "a stable match that carries no peer evidence",
    reason: "evidence-unreadable",
    arrange: () => ({ stableEvidence: "absent" }),
  },
  {
    label: "a lifecycle record this host cannot read (quarantined)",
    reason: "quarantined-records",
    arrange: () => {
      fs.writeFileSync(path.join(sessionContainerRecordsRoot(stateDir), "rf-20261011-garbled.json"), "{not json\n");
      // The enumeration quarantines it now, so the judgement's own listing
      // moves nothing the read-only assertion below would see.
      listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT);
      return undefined;
    },
  },
];

describe("tryWarmPeerValidation: misses (acceptance, fails until implemented)", () => {
  test.fails.each(MISS_CASES)("$label misses with $reason, read-only, changing no record", ({ reason, firstRecorded, arrange }) => {
    const { records, evidence, inventory } = healthyPeers(
      2,
      (record, index) => (index === 0 && firstRecorded ? firstRecorded(record) : record),
    );
    const arranged = arrange?.({ records, evidence, inventory }) ?? {};
    const fake = fakeDocker({ inventory: arranged.inventory ?? inventory, ...arranged.docker });
    const before = registryBytes();
    const verdict = tryWarmPeerValidation(input({
      fake,
      stable: stable(arranged.stableEvidence === "absent" ? undefined : arranged.evidence ?? evidence),
    }));
    expectMiss(verdict, reason);
    expect(onlyReads(fake.calls)).toBe(true);
    expect(registryBytes()).toEqual(before);
  });

  test.fails("an empty registry is not a peer judgement: it misses with no-peers and asks Docker nothing", () => {
    const fake = fakeDocker({ inventory: [] });
    expectMiss(tryWarmPeerValidation(input({ fake, stable: stable(healthyEvidence([])) })), "no-peers");
    expect(fake.calls).toEqual([]);
  });

  test.fails("a cancelled judgement misses with cancelled and makes no Docker call after the cancellation", () => {
    const { evidence, inventory } = healthyPeers(2);
    const fake = fakeDocker({ inventory });
    const controller = new AbortController();
    controller.abort();
    expectMiss(tryWarmPeerValidation(input({ fake, stable: stable(evidence), signal: controller.signal })), "cancelled");
    expect(fake.calls).toEqual([]);
  });

  test.fails("a lifecycle lock that is not held refuses before any observation", () => {
    const { evidence, inventory } = healthyPeers(2);
    const fake = fakeDocker({ inventory });
    const lock: ProjectLifecycleLock = {
      ownerToken: "a".repeat(64),
      assertHeld: vi.fn(() => { throw new Error("project lifecycle lock is no longer held"); }),
      release: vi.fn(),
    };
    expect(() => tryWarmPeerValidation(input({ fake, stable: stable(evidence), lifecycleLock: lock })))
      .toThrow("project lifecycle lock is no longer held");
    expect(fake.calls).toEqual([]);
  });

  test.fails("a lifecycle lock lost during the judgement refuses instead of returning a verdict", () => {
    const { evidence, inventory } = healthyPeers(2);
    const fake = fakeDocker({ inventory });
    let checks = 0;
    const lock: ProjectLifecycleLock = {
      ownerToken: "a".repeat(64),
      assertHeld: vi.fn(() => {
        checks += 1;
        if (checks > 1) throw new Error("project lifecycle lock is no longer held");
      }),
      release: vi.fn(),
    };
    const before = registryBytes();
    expect(() => tryWarmPeerValidation(input({ fake, stable: stable(evidence), lifecycleLock: lock })))
      .toThrow("project lifecycle lock is no longer held");
    expect(onlyReads(fake.calls)).toBe(true);
    expect(registryBytes()).toEqual(before);
  });
});
