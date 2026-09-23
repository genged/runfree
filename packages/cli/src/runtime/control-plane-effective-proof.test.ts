import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { beforeEach, expect, test, vi } from "vitest";

import { sha256Digest, createRuntimeComponentState } from "./component-state.ts";
import {
  createControlPlaneMaterializationManifestV2,
  createRuntimeTopologyGenerationV2,
  createSessionAgentDesiredSelectionV2,
  createSessionAgentGenerationInputsV2,
  publishControlPlaneMaterializationV2,
  publishSessionAgentMaterializationV2,
  readEffectiveControlPlaneV2,
  selectDesiredSessionAgentV2,
} from "./component-state-v2.ts";
import {
  effectiveControlPlaneMatchesLiveRuntimeValidationV2,
  effectiveControlPlaneMatchesRuntimeValidationV2,
  proveAndSelectEffectiveControlPlaneV2,
  proveCandidateControlPlaneV2,
  reproveRecordedCandidateControlPlaneV2,
} from "./control-plane-effective-proof.ts";
import { observeDenyByDefaultViaFirewallV1 } from "./control-plane-deny-proof.ts";
import { proxyNftablesTableJson } from "../proxy-nftables-proof.fixture.ts";
import { validateRuntimeSecurityContractEvidence } from "./security-contract.ts";
import {
  SESSION_TEST_PROJECT,
  sessionAgentMaterializationFixture,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import { writeSessionContainerRecordV2 } from "./session-containers.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import { restoreSameProxySessionAdmission } from "./startup.ts";
import type { RuntimeValidationProof } from "./state.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeIO } from "./types.ts";

const PROXY_ID = "7".repeat(64);
const PROXY_IMAGE_ID = sha256Digest("proxy-image-id");
const INTERNAL_ID = "8".repeat(64);
const EGRESS_ID = "9".repeat(64);
const SECURITY_HASH = sha256Digest("security-contract");
let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-plane-proof-"));
});

function fixture() {
  const target = sessionGenerationFixture().target;
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: sha256Digest("embedded-agent"),
    selectedAgentImageInputDigest: sha256Digest("selected-agent"),
    selectedAgentImageKind: "project",
    proxyImageInputDigest: target.controlPlane.proxyImageInputDigest,
    topologyDigest: sha256Digest("topology"),
    hostHelperDigest: sha256Digest("host-helper"),
  });
  const proxyImageRef = "runfree/proxy-runtime:test";
  const controlPlaneMaterialization = createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT,
    generation: target.controlPlane,
    proxyImageRef,
    proxyImageId: PROXY_IMAGE_ID,
    renderedControlPlaneSha256: target.controlPlane.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
  const plan = {
    projectId: SESSION_TEST_PROJECT.projectId,
    composeProjectName: SESSION_TEST_PROJECT.composeProject,
    generationV2: target,
    components,
    paths: { stateDir },
    activeRuntime: {
      proxyImage: proxyImageRef,
      controlPlaneMaterializationDigest: controlPlaneMaterialization.controlPlaneMaterializationDigest,
    },
    execution: { dockerClientEnv: { DOCKER_HOST: "unix:///trusted-docker.sock" } },
    mcpOAuth: {},
    runfreeVersion: "0.3.0-test",
  } as unknown as ActiveRuntimePlan;
  publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterialization);
  // The restore path republishes the project's session eligibility, which is
  // compiled from the retained current agent template.
  const agentManifest = sessionAgentMaterializationFixture();
  publishSessionAgentMaterializationV2(stateDir, agentManifest, "session-template-artifact");
  selectDesiredSessionAgentV2(stateDir, createSessionAgentDesiredSelectionV2(agentManifest));
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
  // Post-cutover the deny-by-default proof is firewall-origin: there is no
  // shared agent to run the canonical exec probe, so the observation is minted
  // from the live session-only nft ruleset (INPUT policy drop + @session_ipv4).
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
  return { denyByDefaultObservation, plan, runtimeProof, securityProof };
}

type LiveOverrides = {
  proxyContainerId?: string;
  proxyImageId?: string;
  internalId?: string;
  containerInternalId?: string;
  networkInternalId?: string;
  egressId?: string;
  baseState?: boolean[];
  firewallElements?: string[];
  mutateSecondNetworkInspect?: boolean;
  malformedContainerInspect?: boolean;
  malformedNetworkInspect?: boolean;
};

function liveIo(overrides: LiveOverrides = {}): RuntimeIO {
  let containerInspections = 0;
  let networkInspections = 0;
  const capture = vi.fn((_command: string, args: string[]) => {
    if (args[0] === "container") {
      containerInspections += 1;
      if (overrides.malformedContainerInspect) return { status: 0, stdout: "{", stderr: "" };
      const internalId = overrides.mutateSecondNetworkInspect && containerInspections === 2
        ? "c".repeat(64)
        : overrides.containerInternalId ?? overrides.internalId ?? INTERNAL_ID;
      const containers = [{
        Id: overrides.proxyContainerId ?? PROXY_ID,
        Image: overrides.proxyImageId ?? PROXY_IMAGE_ID,
        // `StartedAt` is read by the eligibility publication's incarnation
        // check, which the restore path runs on this same inspection shape.
        State: { Running: true, StartedAt: "2026-08-08T12:00:05.123456789Z" },
        NetworkSettings: { Networks: {
          [`${SESSION_TEST_PROJECT.composeProject}_agent_internal`]: { NetworkID: internalId },
          [`${SESSION_TEST_PROJECT.composeProject}_proxy_egress`]: { NetworkID: overrides.egressId ?? EGRESS_ID },
        } },
      }];
      return { status: 0, stdout: JSON.stringify(containers), stderr: "" };
    }
    if (args[0] === "network") {
      networkInspections += 1;
      if (overrides.malformedNetworkInspect) return { status: 0, stdout: "{", stderr: "" };
      const internalId = overrides.mutateSecondNetworkInspect && networkInspections === 2
        ? "c".repeat(64)
        : overrides.networkInternalId ?? overrides.internalId ?? INTERNAL_ID;
      const networks = [
        { Id: internalId, Name: `${SESSION_TEST_PROJECT.composeProject}_agent_internal` },
        { Id: overrides.egressId ?? EGRESS_ID, Name: `${SESSION_TEST_PROJECT.composeProject}_proxy_egress` },
      ];
      return { status: 0, stdout: JSON.stringify(networks), stderr: "" };
    }
    if (args.includes("node")) {
      return { status: 0, stdout: JSON.stringify(overrides.baseState ?? [false]), stderr: "" };
    }
    if (args.includes("nft")) {
      return {
        status: 0,
        stdout: JSON.stringify({ nftables: [{ set: {
          family: "inet",
          table: "runfree_proxy",
          name: "session_ipv4",
          ...(overrides.firewallElements ? { elem: overrides.firewallElements } : {}),
        } }] }),
        stderr: "",
      };
    }
    throw new Error(`unexpected Docker command: ${args.join(" ")}`);
  });
  return { capture } as unknown as RuntimeIO;
}

function lifecycleLock(): ProjectLifecycleLock {
  return {
    ownerToken: "test-owner",
    assertHeld: vi.fn(),
    release: vi.fn(),
  };
}

test.each([false, true])("accepts changing valid firewall observations through the real rebind coordinator (recovery=%s)", async (recovery) => {
  const { runCompatibleControlPlaneRebind } = await import("./control-plane-rebind-coordinator.ts");
  const { readControlPlaneRebindTransaction } = await import("./control-plane-rebind.ts");
  const { createControlPlaneGenerationV2, selectEffectiveControlPlaneV2 } = await import("./component-state-v2.ts");
  const { effectiveControlPlaneFixture, controlPlaneMaterializationFixture } = await import("./session-container.test-harness.ts");
  const input = fixture();
  const oldControl = createControlPlaneGenerationV2({
    ...SESSION_TEST_PROJECT, proxyImageInputDigest: sha256Digest("old-proxy-input"),
    controlPlaneTopologyDigest: input.plan.generationV2.controlPlane.controlPlaneTopologyDigest,
    admissionContractEpoch: input.plan.generationV2.controlPlane.admissionContractEpoch,
  });
  const oldTarget = { ...input.plan.generationV2, controlPlane: oldControl };
  const oldManifest = controlPlaneMaterializationFixture({ target: oldTarget });
  const oldSelection = effectiveControlPlaneFixture({ target: oldTarget });
  publishControlPlaneMaterializationV2(stateDir, oldManifest);
  selectEffectiveControlPlaneV2(stateDir, oldSelection);
  const candidateManifest = createControlPlaneMaterializationManifestV2({
    ...SESSION_TEST_PROJECT, generation: input.plan.generationV2.controlPlane,
    proxyImageRef: input.plan.activeRuntime.proxyImage, proxyImageId: PROXY_IMAGE_ID,
    renderedControlPlaneSha256: input.plan.generationV2.controlPlane.controlPlaneTopologyDigest,
  
    sessionAdmissionSource: "files",
  });
  const selections: ReturnType<typeof proveCandidateControlPlaneV2>[] = [];
  const prove = async () => {
    const table = JSON.parse(proxyNftablesTableJson()) as { nftables: Array<{ set?: { name: string; elem?: string[] } }> };
    const allowed = table.nftables.find((entry) => entry.set?.name === "allowed_ipv4")?.set;
    if (!allowed) throw new Error("fixture lacks allowed set");
    allowed.elem = [selections.length === 0 ? "1.1.1.1" : "8.8.8.8"];
    const observation = observeDenyByDefaultViaFirewallV1({
      projectId: input.plan.projectId, controlPlaneGenerationDigest: input.plan.generationV2.controlPlane.controlPlaneGenerationDigest,
      proxyContainerId: PROXY_ID,
      nftables: { rawJson: JSON.stringify(table), internalIface: "eth0", egressIface: "eth1", serverUid: "1001" },
    });
    const selection = proveCandidateControlPlaneV2({ ...input, denyByDefaultObservation: observation, lifecycleLock: lifecycleLock(), io: liveIo() });
    selections.push(selection);
    return selection;
  };
  const finalize = vi.fn(async () => ({ preparedRuntime: Object.freeze({ version: 1 }) as never, tokenResolutionReceipts: [] }));
  const args = {
    plan: input.plan, lifecycleLock: { ...lifecycleLock(), ownerToken: "a".repeat(64) }, io: liveIo(),
    oldControlPlane: { selection: oldSelection, manifest: oldManifest }, candidateMaterialization: candidateManifest,
    services: {
      startAndProveCandidate: prove, proveCandidate: prove,
      reproveCandidate: async (recorded: ReturnType<typeof proveCandidateControlPlaneV2>) => {
        reproveRecordedCandidateControlPlaneV2({ ...input, recorded, lifecycleLock: lifecycleLock(), io: liveIo() });
      },
      proveSession: () => { throw new Error("zero-session fixture must not prove a session"); }, finalize,
    },
  };
  try {
    if (recovery) {
      await expect(runCompatibleControlPlaneRebind({ ...args, services: { ...args.services, proveCandidate: async () => { throw new Error("interrupted after creation"); } } }))
        .rejects.toThrow("interrupted after creation");
      expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)?.phase).toBe("proxy-started-deny-all");
      args.lifecycleLock.ownerToken = "b".repeat(64);
    }
    const result = await runCompatibleControlPlaneRebind(args);
    expect(selections.length).toBeGreaterThan(1);
    expect(selections[0].denyByDefaultBaseProofHash).not.toBe(selections[1].denyByDefaultBaseProofHash);
    expect(result.selection).toEqual(selections[0]);
    expect(readEffectiveControlPlaneV2(stateDir)?.selection).toEqual(selections[0]);
    expect(readControlPlaneRebindTransaction(stateDir, SESSION_TEST_PROJECT)).toBeUndefined();
    expect(finalize).toHaveBeenCalledOnce();
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("selects exact live Docker identity only after a stable deny-by-default reinspection", () => {
  const input = fixture();
  const selected = proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
    now: () => new Date("2026-08-08T12:00:00.000Z"),
  });

  expect(selected).toMatchObject({
    proxyContainerId: PROXY_ID,
    proxyImageId: PROXY_IMAGE_ID,
    networkIds: { agentInternal: INTERNAL_ID, proxyEgress: EGRESS_ID },
    securityContractHash: SECURITY_HASH,
  });
  expect(selected.denyByDefaultBaseProofHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(readEffectiveControlPlaneV2(stateDir)?.selection).toEqual(selected);
  expect(effectiveControlPlaneMatchesRuntimeValidationV2(input.plan, input.runtimeProof)).toBe(true);
});

test("warm reuse performs only one bounded container and network identity inspection", () => {
  const input = fixture();
  proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
  });
  const io = liveIo();

  expect(effectiveControlPlaneMatchesLiveRuntimeValidationV2(input.plan, input.runtimeProof, io)).toBe(true);
  expect(io.capture).toHaveBeenCalledTimes(2);
  expect(vi.mocked(io.capture).mock.calls.map(([, args]) => args.slice(0, 2))).toEqual([
    ["container", "inspect"],
    ["network", "inspect"],
  ]);
  expect(vi.mocked(io.capture).mock.calls.flatMap(([, args]) => args)).not.toContain("exec");
  expect(vi.mocked(io.capture).mock.calls.flatMap(([, args]) => args)).not.toContain("nft");
});

test("a session-agent-only roll keeps the recorded control-plane selection reusable", () => {
  // Regression: with live sessions holding lifecycle records, a fresh full
  // selection is refused, so a template or agent-image roll must reuse the
  // recorded selection. The proof and contract bind only the control plane,
  // so session-input changes may not turn the recorded selection stale.
  const input = fixture();
  proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
  });
  const rolledTemplateDigest = sha256Digest("rolled-session-template");
  const rolledPlan = {
    ...input.plan,
    generationV2: {
      ...input.plan.generationV2,
      topology: createRuntimeTopologyGenerationV2({
        controlPlaneTopologyDigest: input.plan.generationV2.controlPlane.controlPlaneTopologyDigest,
        sessionTemplateDigest: rolledTemplateDigest,
      }),
      sessionAgent: createSessionAgentGenerationInputsV2({
        selectedAgentImageInputDigest: sha256Digest("rolled-agent-image"),
        sessionTemplateDigest: rolledTemplateDigest,
        admissionContractEpoch: input.plan.generationV2.sessionAgent.admissionContractEpoch,
      }),
    },
    components: createRuntimeComponentState({
      embeddedAgentImageInputDigest: sha256Digest("embedded-agent"),
      selectedAgentImageInputDigest: sha256Digest("rolled-agent-image"),
      selectedAgentImageKind: "project",
      proxyImageInputDigest: input.plan.generationV2.controlPlane.proxyImageInputDigest,
      topologyDigest: sha256Digest("rolled-topology"),
      hostHelperDigest: sha256Digest("host-helper"),
    }),
  } as ActiveRuntimePlan;

  expect(effectiveControlPlaneMatchesRuntimeValidationV2(rolledPlan, input.runtimeProof)).toBe(true);
  expect(effectiveControlPlaneMatchesLiveRuntimeValidationV2(rolledPlan, input.runtimeProof, liveIo())).toBe(true);
});

test.each([
  ["proxy image replacement", { proxyImageId: sha256Digest("replacement") }],
  ["proxy container replacement", { proxyContainerId: "c".repeat(64) }],
  ["network replacement", { internalId: "c".repeat(64) }],
  ["cross-bound endpoint", { containerInternalId: "c".repeat(64) }],
  ["malformed container evidence", { malformedContainerInspect: true }],
  ["malformed network evidence", { malformedNetworkInspect: true }],
] as const)("warm reuse rejects %s", (_label, overrides) => {
  const input = fixture();
  proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
  });

  expect(effectiveControlPlaneMatchesLiveRuntimeValidationV2(
    input.plan,
    input.runtimeProof,
    liveIo(overrides as LiveOverrides),
  )).toBe(false);
});


test.each([
  ["proxy image replacement", { proxyImageId: sha256Digest("wrong-image") }, "immutable image"],
  ["duplicate network IDs", { egressId: INTERNAL_ID }, "network identity"],
  ["a published session eligibility", { baseState: [true] }, "not deny-by-default"],
  ["nonempty firewall set", { firewallElements: ["172.31.90.20"] }, "not empty"],
  ["identity drift", { mutateSecondNetworkInspect: true }, "changed before effective selection"],
] as const)("rejects %s before publishing effective authority", (_label, overrides, message) => {
  const input = fixture();
  expect(() => proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(overrides as LiveOverrides),
  })).toThrow(message);
  expect(readEffectiveControlPlaneV2(stateDir)).toBeUndefined();
});

test("rejects forged security and denial proofs before Docker inspection", () => {
  const input = fixture();
  const io = { capture: vi.fn() } as unknown as RuntimeIO;
  expect(() => proveAndSelectEffectiveControlPlaneV2({
    ...input,
    securityProof: { ...input.securityProof },
    lifecycleLock: lifecycleLock(),
    io,
  })).toThrow("not minted");
  expect(io.capture).not.toHaveBeenCalled();

  expect(() => proveAndSelectEffectiveControlPlaneV2({
    ...input,
    denyByDefaultObservation: { ...input.denyByDefaultObservation },
    lifecycleLock: lifecycleLock(),
    io,
  })).toThrow("not minted");
  expect(io.capture).not.toHaveBeenCalled();
  expect(readEffectiveControlPlaneV2(stateDir)).toBeUndefined();
});

test("rejects genuinely sealed startup proofs from another runtime identity", () => {
  const input = fixture();
  const io = { capture: vi.fn() } as unknown as RuntimeIO;
  const variants = [
    {
      label: "runtime id",
      runtimeId: `${SESSION_TEST_PROJECT.composeProject}-other`,
      components: input.runtimeProof.components,
      contractHash: SECURITY_HASH,
    },
    {
      label: "contract hash",
      runtimeId: SESSION_TEST_PROJECT.composeProject,
      components: input.runtimeProof.components,
      contractHash: sha256Digest("other-security-contract"),
    },
    {
      label: "runtime components",
      runtimeId: SESSION_TEST_PROJECT.composeProject,
      components: {
        ...input.runtimeProof.components,
        controlPlaneTopologyDigest: sha256Digest("other-topology"),
      },
      contractHash: SECURITY_HASH,
    },
  ];

  for (const variant of variants) {
    const securityProof = validateRuntimeSecurityContractEvidence({
      version: 2,
      runtimeId: variant.runtimeId,
      components: variant.components,
      contractHash: variant.contractHash,
      writeApprovalHoldSeconds: 120,
      containers: [],
      topologyAssertions: [],
    }, {}, { requireLiveProbes: true, scope: "startup" });
    expect(() => proveAndSelectEffectiveControlPlaneV2({
      ...input,
      securityProof,
      lifecycleLock: lifecycleLock(),
      io,
    }), variant.label).toThrow("belongs to another runtime identity");
    expect(io.capture, variant.label).not.toHaveBeenCalled();
    expect(readEffectiveControlPlaneV2(stateDir), variant.label).toBeUndefined();
  }
});

test("rejects genuinely sealed deny observations from another control-plane identity", () => {
  const input = fixture();
  const selectionIo = { capture: vi.fn() } as unknown as RuntimeIO;
  // Post-cutover the deny proof is firewall-origin, which binds no agent
  // identity; its control-plane binding is project + generation + proxy container.
  const variants: Array<{
    label: string;
    projectId?: string;
    controlPlaneGenerationDigest?: string;
    proxyContainerId?: string;
  }> = [
    { label: "project", projectId: "f".repeat(12) },
    { label: "generation", controlPlaneGenerationDigest: sha256Digest("other-control-plane") },
    { label: "proxy", proxyContainerId: "d".repeat(64) },
  ];

  for (const variant of variants) {
    const denyByDefaultObservation = observeDenyByDefaultViaFirewallV1({
      projectId: variant.projectId ?? SESSION_TEST_PROJECT.projectId,
      controlPlaneGenerationDigest: variant.controlPlaneGenerationDigest
        ?? input.plan.generationV2.controlPlane.controlPlaneGenerationDigest,
      proxyContainerId: variant.proxyContainerId ?? PROXY_ID,
      nftables: {
        rawJson: proxyNftablesTableJson(),
        internalIface: "eth0",
        egressIface: "eth1",
        serverUid: "1001",
      },
    });
    expect(() => proveAndSelectEffectiveControlPlaneV2({
      ...input,
      denyByDefaultObservation,
      lifecycleLock: lifecycleLock(),
      io: selectionIo,
    }), variant.label).toThrow("belongs to another control-plane identity");
    expect(selectionIo.capture, variant.label).not.toHaveBeenCalled();
    expect(readEffectiveControlPlaneV2(stateDir), variant.label).toBeUndefined();
  }
});

test("blocks selection while lifecycle records await reconciliation", () => {
  const input = fixture();
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, sessionContainerRecordFixture({
    target: input.plan.generationV2,
  }));
  const io = { capture: vi.fn() } as unknown as RuntimeIO;
  expect(() => proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io,
  })).toThrow("requires session lifecycle reconciliation");
  expect(io.capture).not.toHaveBeenCalled();
  expect(readEffectiveControlPlaneV2(stateDir)).toBeUndefined();
});

test("a lost lifecycle lock cannot publish selection", () => {
  const input = fixture();
  const lock = lifecycleLock();
  vi.mocked(lock.assertHeld).mockImplementation(() => {
    throw new Error("lifecycle lock lost");
  });
  const io = { capture: vi.fn() } as unknown as RuntimeIO;
  expect(() => proveAndSelectEffectiveControlPlaneV2({
    ...input,
    lifecycleLock: lock,
    io,
  })).toThrow("lifecycle lock lost");
  expect(io.capture).not.toHaveBeenCalled();
  expect(readEffectiveControlPlaneV2(stateDir)).toBeUndefined();
});

test("re-proves a recorded candidate identity while the published admission overlay exists", () => {
  const input = fixture();
  const recorded = proveCandidateControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
    now: () => new Date("2026-08-27T12:00:00.000Z"),
  });
  // A published snapshot: selection pointers/statuses present and one admitted
  // session IP. The strict deny-all proof refuses this exact live state...
  const published = { baseState: [true, false, true, false], firewallElements: ["172.30.0.10"] };
  expect(() => proveCandidateControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(published),
  })).toThrow("session-admission base state is not deny-by-default");
  // ...while the identity re-proof accepts it without ever reading admission
  // state: only bounded container and network inspections, no proxy exec.
  const io = liveIo(published);
  reproveRecordedCandidateControlPlaneV2({
    plan: input.plan,
    recorded,
    runtimeProof: input.runtimeProof,
    securityProof: input.securityProof,
    lifecycleLock: lifecycleLock(),
    io,
  });
  const commands = vi.mocked((io as unknown as { capture: ReturnType<typeof vi.fn> }).capture).mock.calls;
  expect(commands.length).toBe(2);
  for (const call of commands) {
    expect((call as unknown[])[1]).not.toContain("exec");
  }
});

test("re-proof refuses a recorded candidate that contradicts the validated runtime before any inspection", () => {
  const input = fixture();
  const recorded = proveCandidateControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
  });
  const io = { capture: vi.fn() } as unknown as RuntimeIO;
  expect(() => reproveRecordedCandidateControlPlaneV2({
    plan: input.plan,
    recorded: { ...recorded, proxyContainerId: "5".repeat(64) },
    runtimeProof: input.runtimeProof,
    securityProof: input.securityProof,
    lifecycleLock: lifecycleLock(),
    io,
  })).toThrow("recorded rebind candidate contradicts the validated runtime");
  expect(() => reproveRecordedCandidateControlPlaneV2({
    plan: input.plan,
    recorded: { ...recorded, controlPlaneMaterializationDigest: sha256Digest("drifted-materialization") },
    runtimeProof: input.runtimeProof,
    securityProof: input.securityProof,
    lifecycleLock: lifecycleLock(),
    io,
  })).toThrow("recorded rebind candidate has no exact materialization identity");
  expect(io.capture).not.toHaveBeenCalled();
});

test("re-proof refuses live identity drift from the recorded candidate", () => {
  const input = fixture();
  const recorded = proveCandidateControlPlaneV2({
    ...input,
    lifecycleLock: lifecycleLock(),
    io: liveIo(),
  });
  expect(() => reproveRecordedCandidateControlPlaneV2({
    plan: input.plan,
    recorded,
    runtimeProof: input.runtimeProof,
    securityProof: input.securityProof,
    lifecycleLock: lifecycleLock(),
    io: liveIo({ proxyImageId: sha256Digest("other-live-image") }),
  })).toThrow("running proxy container does not use the materialized immutable image");
  const driftedNetwork = "d".repeat(64);
  expect(() => reproveRecordedCandidateControlPlaneV2({
    plan: input.plan,
    recorded,
    runtimeProof: input.runtimeProof,
    securityProof: input.securityProof,
    lifecycleLock: lifecycleLock(),
    io: liveIo({ containerInternalId: driftedNetwork, networkInternalId: driftedNetwork }),
  })).toThrow("recorded rebind candidate contradicts live Docker identity");
});


test.each(["missing", "conflicting", "image-drift"] as const)(
  "same-proxy restart restores from retained materialization with a reconstructed plan (%s)", async (kind) => {
    const input = fixture();
    const selected = proveAndSelectEffectiveControlPlaneV2({ ...input, lifecycleLock: lifecycleLock(), io: liveIo() });
    const plan: ActiveRuntimePlan = {
      ...input.plan,
      projectRoot: stateDir,
      baseRuntimeRoot: path.join(stateDir, "runtime"),
      execution: { ...input.plan.execution, adminEnvProvider: { dockerClient: input.plan.execution.dockerClientEnv, resolveChildEnv: () => ({}) } },
      activeRuntime: { ...input.plan.activeRuntime,
        controlPlaneMaterializationDigest: kind === "conflicting" ? sha256Digest("other-materialization") : undefined },
    };
    const io = liveIo(kind === "image-drift" ? { proxyImageId: sha256Digest("other-image") } : {});
    const restore = () => restoreSameProxySessionAdmission({ plan, io, proxyId: PROXY_ID,
      lifecycleLock: lifecycleLock(), validation: { status: 0, proof: input.runtimeProof, securityProof: input.securityProof } });
    if (kind === "missing") {
      await expect(restore()).resolves.toBeUndefined();
      expect(vi.mocked(io.capture).mock.calls.some(([, args]) => args.includes("node"))).toBe(true);
    } else {
      await expect(restore()).rejects.toThrow(kind === "conflicting" ? "no exact materialization identity" : "immutable image");
      // No admission mutation or proxy exec is allowed after a contradictory proof.
      expect(vi.mocked(io.capture).mock.calls.some(([, args]) => args.includes("exec"))).toBe(false);
      // Repair the input and prove the same selected proxy can recover without rebuild.
      plan.activeRuntime.controlPlaneMaterializationDigest = undefined;
      await expect(restoreSameProxySessionAdmission({ plan, io: liveIo(), proxyId: PROXY_ID,
        lifecycleLock: lifecycleLock(), validation: { status: 0, proof: input.runtimeProof, securityProof: input.securityProof } }))
        .resolves.toBeUndefined();
    }
    expect(readEffectiveControlPlaneV2(stateDir)?.selection).toEqual(selected);
  },
);
