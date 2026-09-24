// The startup half of session-file admission: what the same-container restore
// path does to a restarted proxy.
//
// `restoreSameProxySessionAdmission` is the one publication point that is
// reachable as an exported function: the restarted proxy gets its eligibility
// file back and nothing else.
//
// The two per-session proofs the loop runs before either branch
// (`createRetainedSessionRebindProofPlan` and `validateSessionContainerInspect`)
// are replaced here: they need a complete retained image/template fixture and
// prove nothing about which admission source is in force. Everything else on
// the path — the re-proof of the recorded control plane, the record scan, the
// eligibility compile, the sealed Docker argv — is real.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { beforeEach, expect, test, vi } from "vitest";

import { SESSION_ELIGIBILITY_PATH } from "@runfree/runtime-contracts/session-file";

import { sha256Digest, createRuntimeComponentState } from "./component-state.ts";
import {
  createControlPlaneMaterializationManifestV2,
  createSessionAgentDesiredSelectionV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  readPublishedSessionEligibilityV2,
  recordPublishedSessionEligibilityV2,
  selectDesiredSessionAgentV2,
} from "./component-state-v2.ts";
import { observeDenyByDefaultViaFirewallV1 } from "./control-plane-deny-proof.ts";
import { proveAndSelectEffectiveControlPlaneV2 } from "./control-plane-effective-proof.ts";
import { proxyNftablesTableJson } from "../proxy-nftables-proof.fixture.ts";
import { validateRuntimeSecurityContractEvidence } from "./security-contract.ts";
import {
  sessionAgentMaterializationFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  mintSessionContainerLeaseV2,
  sessionContainerRecordPath,
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  writeSessionContainerRecordV2,
} from "./session-containers.ts";
import { writeSessionHostStatus } from "./session-host-status.ts";
import { sessionAdmissionFirewallSetReadCommand } from "./session-file-publisher.ts";
import { restoreSameProxySessionAdmission } from "./startup.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeValidationProof } from "./state.ts";
import type { CaptureResult, RuntimeIO } from "./types.ts";

vi.mock("./session-admission-driver-preflight.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./session-admission-driver-preflight.ts")>(),
  createRetainedSessionRebindProofPlan: vi.fn(() => ({ retainedSessionProofPlan: true })),
}));
vi.mock("./session-container-proof.ts", async (importOriginal) => ({
  ...await importOriginal<typeof import("./session-container-proof.ts")>(),
  validateSessionContainerInspect: vi.fn(),
}));

const PROXY_ID = "7".repeat(64);
const PROXY_IMAGE_ID = sha256Digest("proxy-image-id");
const INTERNAL_ID = "8".repeat(64);
const EGRESS_ID = "9".repeat(64);
const SECURITY_HASH = sha256Digest("security-contract");
const CONTAINER_ID = "a".repeat(64);
const TEMPLATE_ARTIFACT = "session-template-artifact";
const SESSION_ID = "rf-20260808-abcdef";
const PROXY_STARTED_AT = "2026-08-08T12:00:05.123456789Z";

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-startup-eligibility-"));
});

function lifecycleLock(): ProjectLifecycleLock {
  return { ownerToken: "test-owner", assertHeld: vi.fn(), release: vi.fn() };
}

type Effect =
  | "read-firewall-set"
  | "publish-eligibility"
  | "read-base-state"
  | "session-container-inspect"
  | "control-plane-inspect";

// The proof reads every path makes regardless of admission source. Filtered out
// of the asserted effect sequences so those name only admission effects.
const PROOF_EFFECTS: readonly Effect[] = ["control-plane-inspect", "read-base-state"];

const BASE_STATE_PATHS: readonly string[] = [SESSION_ELIGIBILITY_PATH];

const NO_STDIN_COMMANDS: ReadonlyArray<readonly [string, Effect]> = [
  [sessionAdmissionFirewallSetReadCommand(PROXY_ID).args.join("\0"), "read-firewall-set"],
];

function classify(args: readonly string[]): Effect {
  if (args[0] === "network") return "control-plane-inspect";
  if (args[0] === "container") {
    return args[2] === CONTAINER_ID ? "session-container-inspect" : "control-plane-inspect";
  }
  if (args[0] !== "exec") throw new Error(`unexpected Docker command: ${args.join(" ")}`);
  if (args[3] !== "-i") {
    const joined = args.join("\0");
    const known = NO_STDIN_COMMANDS.find(([expected]) => expected === joined)?.[1];
    if (known) return known;
    // The one remaining no-stdin exec: the deny-by-default base-state probe the
    // control-plane re-proof makes. Anything else is a command this test does
    // not know about, and bucketing it would hide it from every assertion.
    if (args[3] === PROXY_ID && args[4] === "node" && args[6]?.includes("existsSync")
      && args.slice(7).join("\0") === BASE_STATE_PATHS.join("\0")) return "read-base-state";
    throw new Error(`unexpected proxy exec: ${args.join(" ")}`);
  }
  if (args[8] === SESSION_ELIGIBILITY_PATH) return "publish-eligibility";
  throw new Error(`unexpected sealed session admission command: ${args.join(" ")}`);
}

/**
 * One `docker` surface for the whole restore path: the live control-plane
 * inspections the re-proof makes, the session inspection the loop makes, and
 * the sealed session-file channel.
 */
function restoreIo(): { io: RuntimeIO; effects: Effect[]; inputs: Map<Effect, string> } {
  const effects: Effect[] = [];
  const inputs = new Map<Effect, string>();
  const capture = vi.fn((
    _command: string,
    args: string[],
    options?: { input?: string },
  ): CaptureResult => {
    const effect = classify(args);
    effects.push(effect);
    if (options?.input !== undefined) inputs.set(effect, options.input);
    if (effect === "control-plane-inspect") {
      const stdout = args[0] === "network"
        ? JSON.stringify([
          { Id: INTERNAL_ID, Name: `${SESSION_TEST_PROJECT.composeProject}_agent_internal` },
          { Id: EGRESS_ID, Name: `${SESSION_TEST_PROJECT.composeProject}_proxy_egress` },
        ])
        : JSON.stringify([{
          Id: PROXY_ID,
          Image: PROXY_IMAGE_ID,
          State: { Running: true, StartedAt: PROXY_STARTED_AT },
          NetworkSettings: {
            Networks: {
              [`${SESSION_TEST_PROJECT.composeProject}_agent_internal`]: { NetworkID: INTERNAL_ID },
              [`${SESSION_TEST_PROJECT.composeProject}_proxy_egress`]: { NetworkID: EGRESS_ID },
            },
          },
        }]);
      return { status: 0, stdout, stderr: "" };
    }
    if (effect === "read-base-state") {
      return { status: 0, stdout: JSON.stringify(BASE_STATE_PATHS.map(() => false)), stderr: "" };
    }
    if (effect === "read-firewall-set") {
      return {
        status: 0,
        stdout: JSON.stringify({ nftables: [{ set: {
          family: "inet", table: "runfree_proxy", name: "session_ipv4",
        } }] }),
        stderr: "",
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  });
  return { io: { capture } as unknown as RuntimeIO, effects, inputs };
}

type RestoreFixture = {
  plan: ActiveRuntimePlan;
  io: RuntimeIO;
  effects: Effect[];
  inputs: Map<Effect, string>;
  runtimeProof: RuntimeValidationProof;
  securityProof: ReturnType<typeof validateRuntimeSecurityContractEvidence>;
};

/** Publishes and selects a control plane, a desired agent, and one live session. */
function restoreFixture(): RestoreFixture {
  const { target } = sessionGenerationFixture();
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: sha256Digest("embedded-agent"),
    selectedAgentImageInputDigest: sha256Digest("selected-agent"),
    selectedAgentImageKind: "project",
    proxyImageInputDigest: target.controlPlane.proxyImageInputDigest,
    topologyDigest: sha256Digest("topology"),
    hostHelperDigest: sha256Digest("host-helper"),
  });
  const proxyImageRef = "runfree/proxy-runtime:test";
  const manifest = createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation: target.controlPlane,
    proxyImageRef,
    proxyImageId: PROXY_IMAGE_ID,
    renderedControlPlaneSha256: target.controlPlane.controlPlaneTopologyDigest,
    sessionAdmissionSource: "files",
  });
  publishControlPlaneMaterializationV2(stateDir, manifest);

  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    projectRoot: stateDir,
    baseRuntimeRoot: path.join(stateDir, "runtime"),
    generationV2: target,
    components,
    paths: { stateDir },
    activeRuntime: {
      proxyImage: proxyImageRef,
      controlPlaneMaterializationDigest: manifest.controlPlaneMaterializationDigest,
    },
    execution: {
      dockerClientEnv: { DOCKER_HOST: "unix:///trusted-docker.sock" },
      adminEnvProvider: {
        dockerClient: { DOCKER_HOST: "unix:///trusted-docker.sock" },
        resolveChildEnv: () => ({}),
      },
    },
    mcpOAuth: {},
    runfreeVersion: "0.3.0-test",
  } as unknown as ActiveRuntimePlan;

  const runtimeProof: RuntimeValidationProof = {
    components: { ...target.controlPlane },
    contractHash: SECURITY_HASH,
    mcpOAuthCallbackPort: 48484,
    mcpOAuthCallbackTopologyVersion: 2,
    projectId: SESSION_TEST_PROJECT.projectId,
    proofVersion: 4,
    proxyId: PROXY_ID,
  };
  const securityProof = validateRuntimeSecurityContractEvidence({
    version: 2,
    runtimeId: SESSION_TEST_PROJECT.composeProject,
    components: runtimeProof.components,
    contractHash: SECURITY_HASH,
    writeApprovalHoldSeconds: 120,
    containers: [],
    topologyAssertions: [],
  }, {}, { requireLiveProbes: true, scope: "startup" });
  const denyByDefaultObservation = observeDenyByDefaultViaFirewallV1({
    projectId: SESSION_TEST_PROJECT.projectId,
    controlPlaneGenerationDigest: target.controlPlane.controlPlaneGenerationDigest,
    proxyContainerId: PROXY_ID,
    nftables: {
      rawJson: proxyNftablesTableJson(),
      internalIface: "eth0",
      egressIface: "eth1",
      serverUid: "1001",
    },
  });

  const selecting = restoreIo();
  proveAndSelectEffectiveControlPlaneV2({
    plan, runtimeProof, securityProof, denyByDefaultObservation,
    lifecycleLock: lifecycleLock(), io: selecting.io,
  });

  const agentManifest = sessionAgentMaterializationFixture();
  publishSessionAgentMaterializationV2(stateDir, agentManifest, TEMPLATE_ARTIFACT);
  selectDesiredSessionAgentV2(stateDir, createSessionAgentDesiredSelectionV2(agentManifest));

  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
      sessionContainerRecordFixture({ target, containerId: CONTAINER_ID }),
      mintSessionContainerLeaseV2({ durationMs: 240_000 }),
    ),
  );
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, attached);

  const { io, effects, inputs } = restoreIo();
  return { plan, io, effects, inputs, runtimeProof, securityProof };
}

async function restore(fixture: RestoreFixture): Promise<void> {
  await restoreSameProxySessionAdmission({
    plan: fixture.plan,
    io: fixture.io,
    lifecycleLock: lifecycleLock(),
    proxyId: PROXY_ID,
    validation: { status: 0, proof: fixture.runtimeProof, securityProof: fixture.securityProof },
  });
}

test("restores a restarted proxy with eligibility alone", async () => {
  const fixture = restoreFixture();

  await restore(fixture);

  expect(fixture.effects.filter((effect) => !PROOF_EFFECTS.includes(effect))).toEqual([
    "publish-eligibility",
    "session-container-inspect",
  ]);
  expect(fixture.inputs.get("publish-eligibility")).toBeDefined();
  expect(readPublishedSessionEligibilityV2(stateDir)?.proxyContainerId).toBe(PROXY_ID);
});

test("proves the kernel set empty when no session survived the restart", async () => {
  const fixture = restoreFixture();
  fs.rmSync(sessionContainerRecordPath(stateDir, SESSION_ID), { force: true });

  await restore(fixture);

  // A restarted proxy recreated its session-file directory empty, so the
  // eligibility must come back even though nothing survived to be admitted;
  // deny-by-default is then proved from the live kernel set.
  expect(fixture.effects.filter((effect) => !PROOF_EFFECTS.includes(effect)))
    .toEqual(["publish-eligibility", "read-firewall-set"]);
  expect(readPublishedSessionEligibilityV2(stateDir)?.proxyContainerId).toBe(PROXY_ID);
});

test("republishes eligibility into the same restarted container despite an earlier record", async () => {
  const fixture = restoreFixture();
  // Exactly the receipt that would suppress a republish if the same container
  // id alone counted as "already published".
  recordPublishedSessionEligibilityV2(stateDir, {
    schemaVersion: 2,
    ...SESSION_TEST_PROJECT,
    proxyContainerId: PROXY_ID,
    proxyStartedAt: PROXY_STARTED_AT,
    eligibilitySha256: sha256Digest("whatever was published before the restart"),
  });

  await restore(fixture);

  expect(fixture.effects).toContain("publish-eligibility");
});

// The two remaining journal/lease reads on the restore path.
//
// There is no admission journal, so what refuses a same-container restore is a
// record its owner stamped terminal — its teardown is mid-flight and the
// restore would republish authority over an address that is being freed. And
// the record's own lease freezes at admission, so the gate that decides "did
// any session survive the restart?" reads the stamp beside the record instead.
const FROZEN_LEASE = Object.freeze({
  admittedAt: "2026-08-08T12:00:00.000Z",
  leaseGeneration: "e".repeat(32),
  leaseExpiresAt: "2026-08-08T12:05:00.000Z",
});

function replaceRecordWithFrozenLease(): void {
  const { target } = sessionGenerationFixture();
  fs.rmSync(sessionContainerRecordPath(stateDir, SESSION_ID), { force: true });
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(
      // A live PID with no boot identity: ownership is unprovable, which is
      // the state the stamp exists to arbitrate. A provably dead owner is
      // reclaimable residue however fresh its last stamp, and a provably live
      // one needs no stamp at all.
      sessionContainerRecordFixture({
        target,
        containerId: CONTAINER_ID,
        overrides: { hostPid: process.pid },
      }),
      FROZEN_LEASE,
    ),
  ));
}

function stampSession(overrides: { aliveUntil?: string; terminal?: "revoking" } = {}): void {
  writeSessionHostStatus(stateDir, {
    v: 1,
    sessionId: SESSION_ID,
    lastHeartbeatAt: "2026-08-08T11:59:30.000Z",
    aliveUntil: overrides.aliveUntil ?? new Date(Date.now() + 60_000).toISOString(),
    served: "served",
    ...(overrides.terminal ? { terminal: overrides.terminal } : {}),
  });
}

test("a terminal-stamped record refuses the same-container restore", async () => {
  const fixture = restoreFixture();
  stampSession({ terminal: "revoking" });

  const refusal = await restore(fixture).then(() => undefined, (error: unknown) => error as Error);
  expect(refusal?.message).toContain("session admission is pending");
  // The refusal names the command that reclaims it (output contract D4).
  expect(refusal?.message).toContain("run `runfree up` again once that teardown finishes");
  // Nothing was published: the refusal lands before the eligibility write.
  expect(fixture.effects).not.toContain("publish-eligibility");
});

test.each([
  ["a future stamp", true, ["publish-eligibility", "session-container-inspect"]],
  ["a lapsed stamp", false, ["publish-eligibility", "session-container-inspect"]],
] as const)(
  "restore re-proves an unknown owner with %s",
  async (_name, live, expected) => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-startup-eligibility-"));
    const fixture = restoreFixture();
    replaceRecordWithFrozenLease();
    stampSession(live ? {} : { aliveUntil: "2026-08-08T12:05:00.000Z" });

    await restore(fixture);

    expect(fixture.effects.filter((effect) => !PROOF_EFFECTS.includes(effect))).toEqual(expected);
  },
);

// Review C4: `runtime reload-policy --force` reaches the restore with no
// validation, so the restore runs the ephemeral helpers itself. It must
// reclaim helper-run residue first, through the unbudgeted containment IO.
function writeHelperResidue(intent: string, cid?: string): string {
  const runDir = path.join(stateDir, "helper-runs", "run-Crash1");
  fs.mkdirSync(runDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(runDir, "intent.json"), intent, { mode: 0o600 });
  if (cid !== undefined) fs.writeFileSync(path.join(runDir, "cid"), cid);
  return runDir;
}

const HELPER_INTENT = JSON.stringify({
  v: 1, projectId: SESSION_TEST_PROJECT.projectId, purpose: "trust-bundle", image: "runfree-agent:crashed",
  network: "none", nonce: "5".repeat(32), createdAt: "2026-09-24T12:00:00.000Z",
});

test("reload-policy restore refuses untrusted helper residue before any Docker call", async () => {
  const fixture = restoreFixture();
  const runDir = writeHelperResidue("{ torn");
  const containment = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));
  const before = vi.mocked(fixture.io.capture).mock.calls.length;

  await expect(restoreSameProxySessionAdmission({
    plan: fixture.plan, io: fixture.io, lifecycleLock: lifecycleLock(), proxyId: PROXY_ID,
    containmentIO: { capture: containment } as unknown as RuntimeIO,
  })).rejects.toThrow(/runfree destroy --force/u);
  expect(vi.mocked(fixture.io.capture).mock.calls.length).toBe(before);
  expect(containment).not.toHaveBeenCalled();
  expect(fs.existsSync(runDir)).toBe(true);
});

test("reload-policy restore reclaims helper residue through the containment IO before validating", async () => {
  const fixture = restoreFixture();
  const runDir = writeHelperResidue(HELPER_INTENT, "4".repeat(64));
  const containment = vi.fn((_command: string, _args: string[]) => ({ status: 0, stdout: "", stderr: "" }));

  // The validation that follows needs a full runtime; only its precondition is
  // under test here.
  await restoreSameProxySessionAdmission({
    plan: fixture.plan, io: fixture.io, lifecycleLock: lifecycleLock(), proxyId: PROXY_ID,
    containmentIO: { capture: containment } as unknown as RuntimeIO,
  }).catch(() => undefined);
  expect(containment.mock.calls.map(([, args]) => args)).toEqual([
    ["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${"4".repeat(64)}`],
  ]);
  expect(fs.existsSync(runDir)).toBe(false);
});

test("reload-policy restore without validation refuses without the containment IO", async () => {
  const fixture = restoreFixture();
  const before = vi.mocked(fixture.io.capture).mock.calls.length;
  await expect(restoreSameProxySessionAdmission({
    plan: fixture.plan, io: fixture.io, lifecycleLock: lifecycleLock(), proxyId: PROXY_ID,
  })).rejects.toThrow(/lifecycle fence/u);
  expect(vi.mocked(fixture.io.capture).mock.calls.length).toBe(before);
});
