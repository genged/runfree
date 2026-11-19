import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test } from "vitest";

import {
  assertRuntimeStartupSecurityContractProof,
  createRuntimeSecurityContract,
  hashRuntimeSecurityContract,
  parseRuntimeSecurityContractProbe,
  runtimeSecurityContractProbeScript,
  validateRuntimeSecurityContractEvidence,
} from "./security-contract.ts";
import type {
  RuntimeContainerContract,
  RuntimeSecurityContract,
  RuntimeSecurityContractEvidence,
  RuntimeSecurityContractValidationScope,
} from "./security-contract.ts";
import type { DockerContainerInspect } from "./types.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import { createRuntimeComponentState, sha256Digest } from "./component-state.ts";
import {
  createControlPlaneGenerationV2,
  createRuntimeTopologyGenerationV2,
  createSessionAgentGenerationInputsV2,
} from "./component-state-v2.ts";
import { projectControlPaths } from "../config.ts";

function makeActivePlan(projectRoot: string): ActiveRuntimePlan {
  const runfreeDir = path.join(projectRoot, ".runfree");
  const stateDir = path.join(runfreeDir, "state");
  const paths = {
    agentEnvPath: path.join(runfreeDir, "config", "agent.env"),
    claudeConfigPath: path.join(stateDir, "claude.json"),
    claudeMcpConfigPath: path.join(stateDir, "mounts", "claude-mcp.json"),
    claudeDir: path.join(stateDir, "claude"),
    codexDir: path.join(stateDir, "codex"),
    configPath: path.join(runfreeDir, "runfree.json"),
    ...projectControlPaths(stateDir),
    gitConfigPath: path.join(stateDir, "gitconfig"),
    inboxDir: path.join(stateDir, "inbox"),
    projectCodexDirMaskPath: path.join(stateDir, "mounts", "project-codex-mask"),
    mcpOperationPolicyPath: path.join(stateDir, "mcp-operation-policy.json"),
    mcpOAuthPolicyPath: path.join(stateDir, "oauth-mediation-policy.json"),
    policyPath: path.join(runfreeDir, "network-policy.json"),
    proxyCaCertDir: path.join(stateDir, "proxy-ca", "public"),
    proxyCaKeyDir: path.join(stateDir, "proxy-ca", "private"),
    runfreeDir,
    sessionsDir: path.join(stateDir, "sessions"),
    stateDir,
    tokenConfigPath: path.join(stateDir, "tokens.json"),
  };
  fs.mkdirSync(runfreeDir, { recursive: true });
  fs.mkdirSync(path.dirname(paths.claudeMcpConfigPath), { recursive: true });
  fs.writeFileSync(paths.claudeMcpConfigPath, '{\n  "mcpServers": {}\n}\n');
  fs.writeFileSync(path.join(projectRoot, ".mcp.json"), "{}\n");
  const components = createRuntimeComponentState({
    embeddedAgentImageInputDigest: sha256Digest("embedded"),
    selectedAgentImageInputDigest: sha256Digest("agent"),
    selectedAgentImageKind: "embedded",
    proxyImageInputDigest: sha256Digest("proxy"),
    topologyDigest: sha256Digest("topology"),
    hostHelperDigest: sha256Digest("helper"),
  });
  const generationV2 = {
    topology: createRuntimeTopologyGenerationV2({
      controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
      sessionTemplateDigest: sha256Digest("session-template"),
    }),
    controlPlane: createControlPlaneGenerationV2({
      projectId: "0123456789ab",
      composeProject: "runfree-0123456789ab",
      proxyImageInputDigest: sha256Digest("proxy"),
      controlPlaneTopologyDigest: sha256Digest("control-plane-topology"),
      admissionContractEpoch: 1,
    }),
    sessionAgent: createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: sha256Digest("agent"),
      sessionTemplateDigest: sha256Digest("session-template"),
      admissionContractEpoch: 1,
    }),
  };

  return {
    activeRuntime: {
      activeRuntimeRoot: path.join(stateDir, "runtime"),
      agentImage: "runfree/agent-runtime:test",
      composeDirectory: path.join(stateDir, "runtime", "agent"),
      composeFile: path.join(stateDir, "runtime", "agent", "compose.yaml"),
      materialized: true,
      proxyImage: "runfree/proxy-runtime:test",
      runtimeDigest: "sha256:test",
    },
    baseRuntimeRoot: path.join(projectRoot, "runtime"),
    components,
    generationV2,
    composeProjectName: "runfree-test",
    dependencyOverlays: { mode: "off", overlays: [], storeVolumes: [], installCommands: [] },
    execution: {
      adminEnvProvider: { dockerClient: {}, resolveChildEnv: () => ({}) },
      composeEnv: {},
      dockerClientEnv: {},
      runtimeInputBuildEnv: {},
    },
    gitLayout: {
      containerProjectRoot: "/workspace",
      kind: "root",
      projectRoot,
    },
    gitRepositoryShape: { kind: "root", projectRoot },
    mcpOAuth: {
      callbackPort: 48484,
      callbackUrl: "http://localhost:48484/callback",
    },
    network: {
      agentIp: "172.30.0.11",
      callbackSidecarIp: "172.30.0.12",
      gatewayIp: "172.30.0.1",
      proxyEgressGatewayIp: "172.31.0.1",
      proxyEgressSubnet: "172.31.0.0/24",
      proxyIp: "172.30.0.10",
      subnet: "172.30.0.0/24",
    },
    paths,
    project: {
      config: { version: 3, runtime: {} },
      paths,
    },
    projectId: "project-id",
    projectRoot,
    projectRuntimeRoot: path.join(stateDir, "runtime"),
    runfreeVersion: "0.0.0-test",
    runtimeDigest: "sha256:test",
  } as unknown as ActiveRuntimePlan;
}

test("runtime security contract includes the fixed proxy invariants and is agent-free post-cutover", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  // Post-cutover the fixed control-plane contract is proxy-only. Each session
  // agent's mounts are attested exactly at admission (assertExactMounts in
  // session-container-proof), not by this control-plane contract.
  expect(contract.containers.find((container) => container.name === "agent")).toBeUndefined();
  const proxy = contract.containers.find((container) => container.name === "proxy");

  expect(proxy?.mounts).toContainEqual(expect.objectContaining({
    code: "proxy-effective-control-read-only",
    containerPath: "/app/runfree-effective",
    requiredMode: "ro",
  }));
  // The MCP operation policy is an effective-generation payload, not a mount.
  expect(proxy?.mounts.some((mount) => mount.containerPath.includes("mcp-operation-policy"))).toBe(false);
  expect(proxy?.mounts).toContainEqual(expect.objectContaining({
    code: "proxy-token-store-tmpfs",
    containerPath: "/run/runfree-proxy-secrets",
    requiredMode: "tmpfs",
  }));
  expect(proxy?.mounts).toContainEqual(expect.objectContaining({
    code: "proxy-audit-tmpfs",
    containerPath: "/run/runfree-proxy-audit",
    requiredMode: "tmpfs",
  }));
  expect(proxy?.mounts).toContainEqual(expect.objectContaining({
    code: "proxy-session-registry-tmpfs",
    containerPath: "/run/runfree-sessions",
    requiredMode: "tmpfs",
  }));
  expect(proxy?.pathStats).toContainEqual(expect.objectContaining({
    code: "proxy-token-store-tmpfs",
    containerPath: "/run/runfree-proxy-secrets",
    expectedGid: 1001,
    expectedMode: "700",
    expectedUid: 1001,
  }));
  expect(proxy?.pathStats).toContainEqual(expect.objectContaining({
    code: "proxy-session-files-dir",
    containerPath: "/run/runfree-sessions/sessions",
    expectedGid: 0,
    expectedMode: "755",
    expectedUid: 0,
  }));
});

test("runtime security contract hash is stable for equivalent contracts", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-hash-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const reordered = {
    ...contract,
    containers: [...contract.containers].reverse(),
  };

  expect(hashRuntimeSecurityContract(contract)).toBe(hashRuntimeSecurityContract(contract));
  expect(hashRuntimeSecurityContract(reordered)).not.toBe(hashRuntimeSecurityContract(contract));
});

function inspect(mounts: NonNullable<DockerContainerInspect["Mounts"]>, tmpfs: Record<string, string> = {}): DockerContainerInspect {
  return {
    HostConfig: { Tmpfs: tmpfs },
    Mounts: mounts,
  };
}

function validStartupEvidence(contract: ReturnType<typeof createRuntimeSecurityContract>) {
  const proxy = contract.containers.find((container) => container.name === "proxy");
  const proxyMounts = Object.fromEntries((proxy?.mounts ?? []).map((mount) => [mount.containerPath, {
    fsType: mount.requiredMode === "tmpfs" ? "tmpfs" : "ext4",
    options: mount.requiredMode === "ro" ? "ro,relatime" : "rw,relatime",
    status: 0,
    target: mount.containerPath,
  }]));
  // Post-cutover the fixed control-plane contract is proxy-only; each session
  // agent's mounts are attested at admission, not by this contract.
  return {
    proxy: {
      inspect: inspect([
        { Destination: "/ca/private", Type: "bind", RW: true },
        { Destination: "/ca/public", Type: "bind", RW: true },
        {
          Destination: "/app/runfree-effective",
          Source: proxy?.mounts.find((entry) => entry.code === "proxy-effective-control-read-only")?.source,
          Type: "bind",
          RW: false,
        },
      ], {
        "/run/runfree-proxy-secrets": "",
        "/run/runfree-proxy-audit": "",
        "/run/runfree-proxy-audit-spool": "",
        "/run/runfree-proxy-status": "",
        "/run/runfree-sessions": "",
        "/run/runfree-approvals/pending": "",
        "/run/runfree-approvals/decisions": "",
      }),
      contentChecks: {},
      mountProbes: proxyMounts,
      pathStats: {
        "/run/runfree-proxy-secrets": { gid: 1001, mode: "700", status: 0, uid: 1001 },
        "/run/runfree-proxy-audit": { gid: 0, mode: "755", status: 0, uid: 0 },
        "/run/runfree-proxy-audit-spool": { gid: 1001, mode: "755", status: 0, uid: 1001 },
        "/run/runfree-proxy-status": { gid: 0, mode: "755", status: 0, uid: 0 },
        "/run/runfree-proxy-status/request-proxy": { gid: 1001, mode: "755", status: 0, uid: 1001 },
        "/run/runfree-sessions": { gid: 0, mode: "755", status: 0, uid: 0 },
        "/run/runfree-sessions/sessions": { gid: 0, mode: "755", status: 0, uid: 0 },
        "/run/runfree-approvals/pending": { gid: 1001, mode: "700", status: 0, uid: 1001 },
        "/run/runfree-approvals/decisions": { gid: 0, mode: "755", status: 0, uid: 0 },
      },
      presentPaths: [],
    },
  };
}

/**
 * Validate startup evidence and report whether the boundary side channel fired.
 *
 * `startup.ts` routes on exactly this bit: a boundary violation contains the
 * validation proxy and fails as `boundary-violation`, while an issue that
 * merely could not be observed fails as `observation-unavailable` and leaves
 * the proxy running. Every mount rejection below asserts which one it is, so a
 * change that downgraded a real breach to an observation gap fails here rather
 * than silently skipping containment.
 */
function startupProof(
  contract: ReturnType<typeof createRuntimeSecurityContract>,
  evidence: ReturnType<typeof validStartupEvidence>,
): { boundaryViolated: boolean; proof: ReturnType<typeof validateRuntimeSecurityContractEvidence> } {
  let boundaryViolated = false;
  const proof = validateRuntimeSecurityContractEvidence(contract, evidence, {
    requireLiveProbes: true,
    scope: "startup",
    onBoundaryViolation: () => { boundaryViolated = true; },
  });
  return { boundaryViolated, proof };
}

test("startup refuses a read-only proxy mount that is writable in the live mount namespace", () => {
  // /app/runfree-effective delivers the effective policy and token
  // destinations the request proxy is bound by. Writable, the UID-1001 server
  // could rewrite its own authority, so this is a breach to be contained —
  // not an unobservable runtime.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-rw-effective-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  evidence.proxy.mountProbes["/app/runfree-effective"].options = "rw,relatime";

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-effective-control-read-only",
    container: "proxy",
    detail: "/app/runfree-effective is not read-only in the live mount namespace",
  });
  expect(boundaryViolated).toBe(true);
  expect(() => assertRuntimeStartupSecurityContractProof(proof)).toThrow();
});

test("startup refuses a read-only proxy mount that Docker inspect reports writable", () => {
  // The live probe and Docker inspect are independent observations and both
  // must agree: a bind created `rw` is refused even when the namespace it was
  // probed in happens to report `ro`.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-inspect-rw-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  const policyMount = evidence.proxy.inspect.Mounts
    ?.find((mount) => mount.Destination === "/app/runfree-effective");
  if (!policyMount) throw new Error("test fixture missing effective control mount");
  policyMount.RW = true;

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(evidence.proxy.mountProbes["/app/runfree-effective"].options).toMatch(/^ro,/);
  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-effective-control-read-only",
    container: "proxy",
    detail: "/app/runfree-effective is not mounted as ro",
  });
  expect(boundaryViolated).toBe(true);
});

test("startup refuses a read-only proxy mount whose host source is not the contracted one", () => {
  // Destination and mode alone do not bind the mount: a different host
  // directory presented read-only at /app/runfree-effective would feed the
  // proxy an effective policy the host never converged.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-wrong-source-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  const effectiveMount = evidence.proxy.inspect.Mounts
    ?.find((mount) => mount.Destination === "/app/runfree-effective");
  if (!effectiveMount) throw new Error("test fixture missing effective control mount");
  effectiveMount.Source = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-foreign-"));

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-effective-control-read-only",
    container: "proxy",
    detail: "/app/runfree-effective is not mounted as ro",
  });
  expect(boundaryViolated).toBe(true);
});

test("startup refuses a proxy token store delivered as a host bind instead of a tmpfs", () => {
  // Proxy-managed tokens live only in a proxy-only tmpfs. A host bind at the
  // same destination would persist them to disk, so the tmpfs requirement is
  // checked against inspect and not inferred from the probe's fsType alone.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-token-bind-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  delete evidence.proxy.inspect.HostConfig?.Tmpfs?.["/run/runfree-proxy-secrets"];
  evidence.proxy.inspect.Mounts?.push({
    Destination: "/run/runfree-proxy-secrets",
    Source: projectRoot,
    Type: "bind",
    RW: true,
  });

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-token-store-tmpfs",
    container: "proxy",
    detail: "/run/runfree-proxy-secrets is not mounted as tmpfs",
  });
  expect(boundaryViolated).toBe(true);
});

test("an unprobed proxy mount refuses startup without claiming a boundary violation", () => {
  // A mount nobody managed to probe is an observation gap, not a breach:
  // startup still refuses new authority, but containment must not run on
  // evidence that never showed a violation.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-unprobed-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  delete evidence.proxy.mountProbes["/app/runfree-effective"];

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-effective-control-read-only",
    container: "proxy",
    detail: "/app/runfree-effective was not live-probed",
  });
  expect(boundaryViolated).toBe(false);
});

test("a proxy mount probe that failed to run refuses startup as a boundary violation only when it succeeded", () => {
  // The probe's own exit status separates the two: a non-zero probe observed
  // nothing, while a zero-status probe that disagrees with the contract
  // observed a live breach.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-probe-status-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  evidence.proxy.mountProbes["/run/runfree-sessions"].status = 1;

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-session-registry-tmpfs",
    container: "proxy",
    detail: "/run/runfree-sessions live mount probe exited 1",
  });
  expect(boundaryViolated).toBe(false);
});

test("missing proxy inspect evidence refuses startup, and the absent orchestrator is not an issue", () => {
  // The orchestrator carries no invariants and is skipped by the loop before
  // its evidence is ever looked up; the proxy is not, so a runtime whose proxy
  // could not be inspected must refuse rather than pass vacuously.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-no-inspect-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));

  const { boundaryViolated, proof } = startupProof(contract, {} as ReturnType<typeof validStartupEvidence>);

  expect(proof.ok).toBe(false);
  expect(proof.issues).toEqual([{
    code: "proxy-inspect-missing",
    container: "proxy",
    detail: "missing Docker inspect evidence",
  }]);
  expect(boundaryViolated).toBe(false);
});


test("runtime security contract validation accepts Docker Desktop translated host source paths", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-host-mnt-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  const effectiveMount = evidence.proxy.inspect.Mounts?.find((mount) => mount.Destination === "/app/runfree-effective");
  if (!effectiveMount?.Source) throw new Error("test fixture missing effective control mount");
  fs.mkdirSync(effectiveMount.Source, { recursive: true });
  effectiveMount.Source = `/host_mnt${fs.realpathSync(effectiveMount.Source)}`;

  const proof = validateRuntimeSecurityContractEvidence(contract, evidence, { requireLiveProbes: true, scope: "startup" });

  expect(proof.ok).toBe(true);
  expect(() => assertRuntimeStartupSecurityContractProof(proof)).not.toThrow();
  expect(() => assertRuntimeStartupSecurityContractProof({ ...proof })).toThrow("not minted");
});

test("runtime security contract probe parses directory emptiness evidence", () => {
  const parsed = parseRuntimeSecurityContractProbe("directory\t/workspace/.codex\t0\t1\n");

  expect(parsed.directoryChecks).toEqual({
    "/workspace/.codex": { status: 0, empty: true },
  });
});

test("runtime security contract probe script executes directory checks under sh", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-probe-script-"));
  const emptyMask = path.join(projectRoot, "empty-mask");
  fs.mkdirSync(emptyMask);

  const result = childProcess.spawnSync("sh", ["-c", runtimeSecurityContractProbeScript({
    name: "agent",
    mounts: [],
    writeProbes: [],
    absenceProbes: [],
    contentChecks: [],
    directoryChecks: [
      {
        code: "agent-codex-dir-masked",
        containerPath: emptyMask,
        expected: "empty",
      },
    ],
    pathStats: [],
  })], { encoding: "utf8" });

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(result.stdout).toContain(`directory\t${emptyMask}\t0\t1`);
});

test("startup runtime security contract validation rejects wrong proxy tmpfs ownership", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-stat-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  evidence.proxy.pathStats["/run/runfree-proxy-secrets"] = { gid: 0, mode: "700", status: 0, uid: 0 };

  const proof = validateRuntimeSecurityContractEvidence(contract, evidence, { requireLiveProbes: true, scope: "startup" });

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual(expect.objectContaining({ code: "proxy-token-store-tmpfs" }));
});

test("startup runtime security contract rejects proxy-writable session authority", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-sessions-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  evidence.proxy.pathStats["/run/runfree-sessions"] = { gid: 1001, mode: "755", status: 0, uid: 1001 };

  const proof = validateRuntimeSecurityContractEvidence(
    contract,
    evidence,
    { requireLiveProbes: true, scope: "startup" },
  );

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual(expect.objectContaining({ code: "proxy-session-registry-tmpfs" }));
});

test("write-approval hold seconds are host-resolved into the contract and change its hash", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-hold-"));
  const plan = makeActivePlan(projectRoot);
  const base = createRuntimeSecurityContract(plan);
  expect(base.writeApprovalHoldSeconds).toBe(120);

  const changedPlan = {
    ...plan,
    project: {
      ...plan.project,
      config: { ...plan.project.config, runtime: { ...plan.project.config.runtime, writeApprovalHoldSeconds: 60 } },
    },
  } as typeof plan;
  const changed = createRuntimeSecurityContract(changedPlan);
  expect(changed.writeApprovalHoldSeconds).toBe(60);
  // Changing the hold window requires runtime recreation/revalidation, never
  // a hot policy reload: the value is part of the hashed contract.
  expect(changed.contractHash).not.toBe(base.contractHash);
});

test("session-agent input changes do not change the control-plane contract hash", () => {
  // The contract attests only the fixed proxy control plane; sessions are
  // attested by admission. A template or agent-image roll must leave the hash
  // unchanged, or the durable effective selection (which records this hash)
  // would go stale while sessions are live and block per-session rolling
  // upgrades. Control-plane input changes must still change it.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-scope-"));
  const plan = makeActivePlan(projectRoot);
  const base = createRuntimeSecurityContract(plan);

  const sessionRolled = {
    ...plan,
    components: createRuntimeComponentState({
      embeddedAgentImageInputDigest: sha256Digest("embedded"),
      selectedAgentImageInputDigest: sha256Digest("rolled-agent"),
      selectedAgentImageKind: "project",
      proxyImageInputDigest: sha256Digest("proxy"),
      topologyDigest: sha256Digest("rolled-topology"),
      hostHelperDigest: sha256Digest("helper"),
    }),
    generationV2: {
      ...plan.generationV2,
      topology: createRuntimeTopologyGenerationV2({
        controlPlaneTopologyDigest: plan.generationV2.controlPlane.controlPlaneTopologyDigest,
        sessionTemplateDigest: sha256Digest("rolled-session-template"),
      }),
      sessionAgent: createSessionAgentGenerationInputsV2({
        selectedAgentImageInputDigest: sha256Digest("rolled-agent"),
        sessionTemplateDigest: sha256Digest("rolled-session-template"),
        admissionContractEpoch: 1,
      }),
    },
  } as typeof plan;
  expect(createRuntimeSecurityContract(sessionRolled).contractHash).toBe(base.contractHash);

  const proxyRolled = {
    ...plan,
    generationV2: {
      ...plan.generationV2,
      controlPlane: createControlPlaneGenerationV2({
        projectId: plan.generationV2.controlPlane.projectId,
        composeProject: plan.generationV2.controlPlane.composeProject,
        proxyImageInputDigest: sha256Digest("rolled-proxy"),
        controlPlaneTopologyDigest: plan.generationV2.controlPlane.controlPlaneTopologyDigest,
        admissionContractEpoch: 1,
      }),
    },
  } as typeof plan;
  expect(createRuntimeSecurityContract(proxyRolled).contractHash).not.toBe(base.contractHash);
});

test("startup runtime security contract validation rejects wrong approvals tmpfs ownership", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-approvals-"));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  const evidence = validStartupEvidence(contract);
  // A uid-1001 decisions dir would let the proxy process mint its own
  // approvals; startup must fail before token sync or agent attach.
  evidence.proxy.pathStats["/run/runfree-approvals/decisions"] = { gid: 1001, mode: "755", status: 0, uid: 1001 };

  const proof = validateRuntimeSecurityContractEvidence(contract, evidence, { requireLiveProbes: true, scope: "startup" });

  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual(expect.objectContaining({ code: "proxy-approvals-decisions-tmpfs" }));
});

// ---------------------------------------------------------------------------
// Probe script under `sh -c` with stub findmnt/stat/sha256sum.
// ---------------------------------------------------------------------------

const STUB_DIGEST = "ab".repeat(32);

function argvLogger(name: string): string {
  return `{ printf '${name}'; for arg in "$@"; do printf '\\t%s' "$arg"; done; printf '\\n'; } >> "$STUB_LOG"`;
}

/**
 * A temp `bin` dir holding stub findmnt/stat/sha256sum. Each stub appends its
 * argv (tab-joined) to `$STUB_LOG` and prints a fixed value derived from it:
 * findmnt reports the queried path as an exact tmpfs mountpoint, stat reports
 * `1001:1001:$STUB_MODE`, and sha256sum reports STUB_DIGEST.
 */
function makeStubTools(root: string): { bin: string; log: string } {
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  const log = path.join(root, "argv.log");
  fs.writeFileSync(path.join(bin, "findmnt"), [
    "#!/bin/sh",
    argvLogger("findmnt"),
    "case \"$5\" in",
    "  TARGET) printf '%s\\n' \"$2\" ;;",
    "  FSTYPE) printf 'tmpfs\\n' ;;",
    "  OPTIONS) printf 'rw,nosuid,nodev\\n' ;;",
    "esac",
    "",
  ].join("\n"), { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "stat"), [
    "#!/bin/sh",
    argvLogger("stat"),
    "printf '1001:1001:%s\\n' \"${STUB_MODE:-700}\"",
    "",
  ].join("\n"), { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "sha256sum"), [
    "#!/bin/sh",
    argvLogger("sha256sum"),
    `printf '%s  %s\\n' '${STUB_DIGEST}' "$1"`,
    "",
  ].join("\n"), { mode: 0o755 });
  return { bin, log };
}

function runProbeWithStubs(
  container: RuntimeContainerContract,
  stubs: { bin: string; log: string },
  stubMode: string,
) {
  fs.rmSync(stubs.log, { force: true });
  const result = childProcess.spawnSync("sh", ["-c", runtimeSecurityContractProbeScript(container)], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${stubs.bin}${path.delimiter}${process.env.PATH ?? ""}`,
      STUB_LOG: stubs.log,
      STUB_MODE: stubMode,
    },
  });
  const argv = fs.existsSync(stubs.log)
    ? fs.readFileSync(stubs.log, "utf8").split("\n").filter(Boolean).map((line) => line.split("\t"))
    : [];
  return { argv, result };
}

test("the probe script prints one line per invariant in kind order, with quoted paths intact", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-stub-probe-"));
  const stubs = makeStubTools(root);
  // A space and a single quote: the path must survive shell quoting verbatim.
  const quotedDir = path.join(root, "it's a dir");
  fs.mkdirSync(quotedDir);
  const contentFile = path.join(quotedDir, "mask's file");
  fs.writeFileSync(contentFile, "mask\n");
  const missingContent = path.join(root, "missing content");
  const missingAbsence = path.join(root, "missing absence");
  const missingStat = path.join(root, "missing 'stat'");

  const container: RuntimeContainerContract = {
    name: "proxy",
    mounts: [{ code: "probe-tmpfs", containerPath: quotedDir, requiredMode: "tmpfs" }],
    writeProbes: [],
    contentChecks: [
      { code: "probe-content", containerPath: contentFile, expectedSha256: STUB_DIGEST },
      { code: "probe-content-missing", containerPath: missingContent, expectedSha256: STUB_DIGEST },
    ],
    directoryChecks: [],
    absenceProbes: [
      { code: "probe-absence-present", containerPath: quotedDir },
      { code: "probe-absence", containerPath: missingAbsence },
    ],
    pathStats: [
      { code: "probe-stat", containerPath: quotedDir, expectedUid: 1001, expectedGid: 1001, expectedMode: "700" },
      { code: "probe-stat-missing", containerPath: missingStat },
    ],
  };

  const { argv, result } = runProbeWithStubs(container, stubs, "700");

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(result.stdout.split("\n").filter(Boolean)).toEqual([
    `mount\t${quotedDir}\t0\t${quotedDir}\ttmpfs\trw,nosuid,nodev`,
    `content\t${contentFile}\t0\t${STUB_DIGEST}`,
    `content\t${missingContent}\t1\t`,
    `absence\t${quotedDir}\t1`,
    `absence\t${missingAbsence}\t0`,
    `stat\t${quotedDir}\t0\t1001:1001:700`,
    `stat\t${missingStat}\t1\t::`,
  ]);
  // Missing paths never reach the stubs: the script checks existence first.
  expect(argv).toEqual([
    ["findmnt", "-T", quotedDir, "-n", "-o", "TARGET"],
    ["findmnt", "-T", quotedDir, "-n", "-o", "FSTYPE"],
    ["findmnt", "-T", quotedDir, "-n", "-o", "OPTIONS"],
    ["sha256sum", contentFile],
    ["stat", "-c", "%u:%g:%a", quotedDir],
  ]);

  // Round trip: the real probe output, parsed and validated, proves a
  // contract whose expectations match what the stubs observed.
  const validated: RuntimeContainerContract = {
    ...container,
    contentChecks: [container.contentChecks[0]],
    absenceProbes: [container.absenceProbes[1]],
    pathStats: [container.pathStats[0]],
  };
  const contract = handBuiltContract(root, validated);
  const evidenceFor = (stdout: string): RuntimeSecurityContractEvidence => ({
    proxy: { ...parseRuntimeSecurityContractProbe(stdout), inspect: inspect([], { [quotedDir]: "" }) },
  });

  const okRun = validateWithCallback(contract, evidenceFor(result.stdout), "all");
  expect(okRun.proof).toMatchObject({ ok: true, issues: [] });
  expect(okRun.boundaryViolated).toBe(false);

  const loose = runProbeWithStubs(container, stubs, "777");
  expect(loose.result.status).toBe(0);
  const looseRun = validateWithCallback(contract, evidenceFor(loose.result.stdout), "all");
  expect(looseRun.proof.ok).toBe(false);
  expect(looseRun.proof.issues).toEqual([{
    code: "probe-stat",
    container: "proxy",
    detail: `${quotedDir} mode is 777, expected 700`,
  }]);
  expect(looseRun.boundaryViolated).toBe(true);
});

// ---------------------------------------------------------------------------
// Parser.
// ---------------------------------------------------------------------------

test("the probe parser turns mount, content, absence and stat lines into evidence", () => {
  const parsed = parseRuntimeSecurityContractProbe([
    "mount\t/run/a\t0\t/run/a\ttmpfs\trw,nosuid",
    "content\t/etc/mask\t0\tdeadbeef",
    "content\t/etc/missing\t1\t",
    "absence\t/present\t1",
    "absence\t/absent\t0",
    "stat\t/run/a\t0\t1001:0:0700",
    "stat\t/run/missing\t1\t::",
    "",
  ].join("\n"));

  expect(parsed).toEqual({
    mountProbes: { "/run/a": { status: 0, target: "/run/a", fsType: "tmpfs", options: "rw,nosuid" } },
    contentChecks: {
      "/etc/mask": { status: 0, sha256: "deadbeef" },
      "/etc/missing": { status: 1, sha256: "" },
    },
    directoryChecks: {},
    presentPaths: ["/present"],
    pathStats: {
      "/run/a": { status: 0, uid: 1001, gid: 0, mode: "0700" },
      "/run/missing": { status: 1, uid: undefined, gid: undefined, mode: "" },
    },
  });
});

test("the probe parser accepts CRLF and skips blank, kind-only and unknown lines", () => {
  const parsed = parseRuntimeSecurityContractProbe([
    "",
    "   ",
    "stat",
    "mount\t",
    "write\t/run/a\t0",
    "directory\t/workspace/.codex\t0\t0",
    "absence\t/present\t1",
    "",
  ].join("\r\n"));

  expect(parsed).toEqual({
    mountProbes: {},
    contentChecks: {},
    directoryChecks: { "/workspace/.codex": { status: 0, empty: false } },
    presentPaths: ["/present"],
    pathStats: {},
  });
});

// ---------------------------------------------------------------------------
// Live mount probe results on the production proxy contract.
// ---------------------------------------------------------------------------

function productionStartup(name: string) {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), `runfree-security-contract-${name}-`));
  const contract = createRuntimeSecurityContract(makeActivePlan(projectRoot));
  return { contract, evidence: validStartupEvidence(contract) };
}

test("the unmodified startup evidence fixture proves the production contract", () => {
  const { contract, evidence } = productionStartup("baseline");
  const { boundaryViolated, proof } = startupProof(contract, evidence);
  expect(proof).toMatchObject({ ok: true, issues: [] });
  expect(boundaryViolated).toBe(false);
});

test("startup refuses a tmpfs whose live mountpoint is its parent mount", () => {
  // findmnt -T resolves to the enclosing mount: a token store that is only a
  // directory on /run is not a tmpfs of its own.
  const { contract, evidence } = productionStartup("parent-mount");
  evidence.proxy.mountProbes["/run/runfree-proxy-secrets"].target = "/run";

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.issues).toEqual([{
    code: "proxy-token-store-tmpfs",
    container: "proxy",
    detail: "/run/runfree-proxy-secrets is not an exact live mountpoint",
  }]);
  expect(boundaryViolated).toBe(true);
});

test("startup accepts a live mountpoint reported with a trailing slash", () => {
  const { contract, evidence } = productionStartup("trailing-slash");
  evidence.proxy.mountProbes["/run/runfree-proxy-secrets"].target = "/run/runfree-proxy-secrets/";

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof).toMatchObject({ ok: true, issues: [] });
  expect(boundaryViolated).toBe(false);
});

test("startup refuses a tmpfs mount that is live-mounted as another filesystem", () => {
  const { contract, evidence } = productionStartup("overlay");
  evidence.proxy.mountProbes["/run/runfree-proxy-secrets"].fsType = "overlay";

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.issues).toEqual([{
    code: "proxy-token-store-tmpfs",
    container: "proxy",
    detail: "/run/runfree-proxy-secrets is not a live tmpfs mount",
  }]);
  expect(boundaryViolated).toBe(true);
});

test("startup refuses a writable proxy mount that is read-only in the live mount namespace", () => {
  const { contract, evidence } = productionStartup("ro-private");
  evidence.proxy.mountProbes["/ca/private"].options = "ro,relatime";

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof.issues).toEqual([{
    code: "proxy-ca-private-mounted",
    container: "proxy",
    detail: "/ca/private is read-only in the live mount namespace",
  }]);
  expect(boundaryViolated).toBe(true);
});

test("startup does not read errors=remount-ro as the ro mount option", () => {
  const { contract, evidence } = productionStartup("remount-ro");
  evidence.proxy.mountProbes["/ca/private"].options = "rw,relatime,errors=remount-ro";

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof).toMatchObject({ ok: true, issues: [] });
  expect(boundaryViolated).toBe(false);
});

// ---------------------------------------------------------------------------
// Docker inspect mount modes.
// ---------------------------------------------------------------------------

test("startup accepts a tmpfs reported only as a tmpfs entry in Mounts", () => {
  const { contract, evidence } = productionStartup("tmpfs-mounts");
  delete evidence.proxy.inspect.HostConfig?.Tmpfs?.["/run/runfree-proxy-secrets"];
  evidence.proxy.inspect.Mounts?.push({ Destination: "/run/runfree-proxy-secrets", Type: "tmpfs" });

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(proof).toMatchObject({ ok: true, issues: [] });
  expect(boundaryViolated).toBe(false);
});

test("startup reads ro from the bind Mode list when RW is unset", () => {
  const { contract, evidence } = productionStartup("mode-ro");
  const effective = evidence.proxy.inspect.Mounts?.find((mount) => mount.Destination === "/app/runfree-effective");
  if (!effective) throw new Error("test fixture missing effective control mount");
  delete effective.RW;
  effective.Mode = "z,ro";

  expect(startupProof(contract, evidence).proof).toMatchObject({ ok: true, issues: [] });

  effective.Mode = "rw";
  const { boundaryViolated, proof } = startupProof(contract, evidence);
  expect(proof.issues).toEqual([{
    code: "proxy-effective-control-read-only",
    container: "proxy",
    detail: "/app/runfree-effective is not mounted as ro",
  }]);
  expect(boundaryViolated).toBe(true);
});

// ---------------------------------------------------------------------------
// Path stats.
// ---------------------------------------------------------------------------

test("startup reports each path-stat mismatch with its exact detail and callback", () => {
  const cases: Array<{
    evidence: { gid?: number; mode?: string; status: number; uid?: number } | undefined;
    detail: string | undefined;
    fired: boolean;
  }> = [
    { evidence: { uid: 1001, gid: 0, mode: "700", status: 0 }, detail: "gid is 0, expected 1001", fired: true },
    { evidence: { uid: 1001, gid: 1001, mode: "750", status: 0 }, detail: "mode is 750, expected 700", fired: true },
    { evidence: { uid: 0, gid: 1001, mode: "700", status: 0 }, detail: "uid is 0, expected 1001", fired: true },
    { evidence: { gid: 1001, mode: "700", status: 0 }, detail: "uid is unknown, expected 1001", fired: true },
    { evidence: { uid: 1001, gid: 1001, mode: "0700", status: 0 }, detail: undefined, fired: false },
    { evidence: { uid: undefined, gid: undefined, mode: "", status: 1 }, detail: "stat probe exited 1", fired: false },
    { evidence: undefined, detail: "was not stat-probed", fired: false },
  ];
  for (const entry of cases) {
    const { contract, evidence } = productionStartup("path-stat");
    if (entry.evidence) {
      (evidence.proxy.pathStats as Record<string, unknown>)["/run/runfree-proxy-secrets"] = entry.evidence;
    } else {
      delete (evidence.proxy.pathStats as Record<string, unknown>)["/run/runfree-proxy-secrets"];
    }

    const { boundaryViolated, proof } = startupProof(contract, evidence);

    expect(proof.issues, JSON.stringify(entry)).toEqual(entry.detail === undefined ? [] : [{
      code: "proxy-token-store-tmpfs",
      container: "proxy",
      detail: `/run/runfree-proxy-secrets ${entry.detail}`,
    }]);
    expect(boundaryViolated, JSON.stringify(entry)).toBe(entry.fired);
  }
});

test("startup collects every broken invariant in one run", () => {
  const { contract, evidence } = productionStartup("two-broken");
  evidence.proxy.pathStats["/run/runfree-approvals/pending"] = { gid: 1001, mode: "755", status: 0, uid: 1001 };
  evidence.proxy.mountProbes["/run/runfree-proxy-audit"].fsType = "ext4";

  const { proof } = startupProof(contract, evidence);

  expect(proof.issues).toEqual([
    {
      code: "proxy-audit-tmpfs",
      container: "proxy",
      detail: "/run/runfree-proxy-audit is not a live tmpfs mount",
    },
    {
      code: "proxy-approvals-pending-tmpfs",
      container: "proxy",
      detail: "/run/runfree-approvals/pending mode is 755, expected 700",
    },
  ]);
});

// ---------------------------------------------------------------------------
// Hand-built contracts for invariant kinds the fixed proxy contract leaves empty.
// ---------------------------------------------------------------------------

function handBuiltContract(projectRoot: string, container: RuntimeContainerContract): RuntimeSecurityContract {
  return { ...createRuntimeSecurityContract(makeActivePlan(projectRoot)), containers: [container] };
}

function emptyContainer(overrides: Partial<RuntimeContainerContract>): RuntimeContainerContract {
  return {
    name: "proxy",
    mounts: [],
    forbiddenMounts: [],
    writeProbes: [],
    absenceProbes: [],
    contentChecks: [],
    directoryChecks: [],
    pathStats: [],
    ...overrides,
  };
}

function validateWithCallback(
  contract: RuntimeSecurityContract,
  evidence: RuntimeSecurityContractEvidence,
  scope: RuntimeSecurityContractValidationScope,
) {
  let boundaryViolated = false;
  const proof = validateRuntimeSecurityContractEvidence(contract, evidence, {
    requireLiveProbes: true,
    scope,
    onBoundaryViolation: () => { boundaryViolated = true; },
  });
  return { boundaryViolated, proof };
}

test("a protected read-only mount refuses writable aliases and nothing else", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-alias-"));
  const parent = path.join(root, "parent");
  const source = path.join(parent, ".runfree");
  fs.mkdirSync(source, { recursive: true });
  const unrelated = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-alias-other-"));
  const protectedPath = "/x/.runfree";
  const contract = handBuiltContract(root, emptyContainer({
    mounts: [{
      code: "test-protected-ro",
      containerPath: protectedPath,
      noWritableAlias: true,
      requiredMode: "ro",
      source,
    }],
  }));
  const evidenceWith = (extra: NonNullable<DockerContainerInspect["Mounts"]>): RuntimeSecurityContractEvidence => ({
    proxy: {
      inspect: inspect([{ Destination: protectedPath, Source: source, Type: "bind", RW: false }, ...extra]),
      mountProbes: {
        [protectedPath]: { status: 0, target: protectedPath, fsType: "ext4", options: "ro,relatime" },
      },
    },
  });
  const alias = [{
    code: "agent-runfree-no-rw-alias",
    container: "proxy",
    detail: `${protectedPath} has a writable alias`,
  }];

  const cases: Array<{ name: string; extra: NonNullable<DockerContainerInspect["Mounts"]>; issues: unknown[] }> = [
    { name: "no extra mount", extra: [], issues: [] },
    {
      name: "rw mount below the protected path",
      extra: [{ Destination: `${protectedPath}/sub`, Source: unrelated, Type: "bind", RW: true }],
      issues: alias,
    },
    {
      name: "rw parent source exposing the source elsewhere",
      extra: [{ Destination: "/y", Source: parent, Type: "bind", RW: true }],
      issues: alias,
    },
    {
      name: "rw parent source exposing the source exactly at the protected path",
      extra: [{ Destination: "/x", Source: parent, Type: "bind", RW: true }],
      issues: [],
    },
    {
      name: "ro parent source exposing the source elsewhere",
      extra: [{ Destination: "/y", Source: parent, Type: "bind", RW: false }],
      issues: [],
    },
    {
      name: "rw sibling sharing a string prefix",
      extra: [{ Destination: `${protectedPath}-other`, Source: unrelated, Type: "bind", RW: true }],
      issues: [],
    },
  ];
  for (const entry of cases) {
    const { boundaryViolated, proof } = validateWithCallback(contract, evidenceWith(entry.extra), "all");
    expect(proof.issues, entry.name).toEqual(entry.issues);
    expect(boundaryViolated, entry.name).toBe(entry.issues.length > 0);
  }
});

test("forbidden mounts refuse an exact destination, and descendants only when asked", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-forbidden-"));
  const run = (includeDescendants: boolean, destination: string) => validateWithCallback(
    handBuiltContract(root, emptyContainer({
      forbiddenMounts: [{ code: "test-forbidden", containerPath: "/w/.runfree", includeDescendants }],
    })),
    { proxy: { inspect: inspect([{ Destination: destination, Source: root, Type: "bind", RW: false }]) } },
    "all",
  );
  const forbidden = [{
    code: "test-forbidden",
    container: "proxy",
    detail: "/w/.runfree must not be an explicit runtime mount",
  }];

  expect(run(false, "/w/.runfree")).toEqual({ boundaryViolated: true, proof: expect.objectContaining({ issues: forbidden }) });
  expect(run(false, "/w/.runfree/nested")).toEqual({ boundaryViolated: false, proof: expect.objectContaining({ ok: true }) });
  expect(run(true, "/w/.runfree/nested")).toEqual({ boundaryViolated: true, proof: expect.objectContaining({ issues: forbidden }) });
  expect(run(true, "/w/.runfree-other")).toEqual({ boundaryViolated: false, proof: expect.objectContaining({ ok: true }) });
});

test("an absence probe refuses a visible path", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-absence-"));
  const contract = handBuiltContract(root, emptyContainer({
    absenceProbes: [{ code: "test-absent", containerPath: "/ca/private" }],
  }));

  expect(validateWithCallback(contract, { proxy: { inspect: inspect([]), presentPaths: ["/ca/private"] } }, "all")).toEqual({
    boundaryViolated: true,
    proof: expect.objectContaining({ issues: [{ code: "test-absent", container: "proxy", detail: "/ca/private is visible" }] }),
  });
  expect(validateWithCallback(contract, { proxy: { inspect: inspect([]), presentPaths: [] } }, "all")).toEqual({
    boundaryViolated: false,
    proof: expect.objectContaining({ ok: true }),
  });
});

test("a content check separates an unobserved mask from a wrong one", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-content-"));
  const contract = handBuiltContract(root, emptyContainer({
    contentChecks: [{ code: "test-content", containerPath: "/w/.mcp.json", expectedSha256: STUB_DIGEST }],
  }));
  const run = (contentChecks: Record<string, { sha256?: string; status: number }>) =>
    validateWithCallback(contract, { proxy: { inspect: inspect([]), contentChecks } }, "all");
  const mismatch = [{ code: "test-content", container: "proxy", detail: "/w/.mcp.json content does not match the Runfree mask" }];

  expect(run({})).toEqual({
    boundaryViolated: false,
    proof: expect.objectContaining({
      issues: [{ code: "test-content", container: "proxy", detail: "/w/.mcp.json content was not live-probed" }],
    }),
  });
  expect(run({ "/w/.mcp.json": { sha256: "", status: 1 } }))
    .toEqual({ boundaryViolated: false, proof: expect.objectContaining({ issues: mismatch }) });
  expect(run({ "/w/.mcp.json": { sha256: "cd".repeat(32), status: 0 } }))
    .toEqual({ boundaryViolated: true, proof: expect.objectContaining({ issues: mismatch }) });
  expect(run({ "/w/.mcp.json": { sha256: STUB_DIGEST, status: 0 } }))
    .toEqual({ boundaryViolated: false, proof: expect.objectContaining({ ok: true, issues: [] }) });
});

test("a directory check separates an unobserved mask from a non-empty one", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-security-contract-directory-"));
  const contract = handBuiltContract(root, emptyContainer({
    directoryChecks: [{ code: "test-directory", containerPath: "/w/.codex", expected: "empty" }],
  }));
  const run = (directoryChecks: Record<string, { empty?: boolean; status: number }>) =>
    validateWithCallback(contract, { proxy: { inspect: inspect([]), directoryChecks } }, "all");
  const issue = (detail: string) => expect.objectContaining({
    issues: [{ code: "test-directory", container: "proxy", detail: `/w/.codex ${detail}` }],
  });

  expect(run({})).toEqual({ boundaryViolated: false, proof: issue("directory was not live-probed") });
  expect(run({ "/w/.codex": { empty: false, status: 1 } }))
    .toEqual({ boundaryViolated: false, proof: issue("directory probe exited 1") });
  expect(run({ "/w/.codex": { empty: false, status: 0 } }))
    .toEqual({ boundaryViolated: true, proof: issue("is not an empty Runfree mask directory") });
  expect(run({ "/w/.codex": { empty: true, status: 0 } }))
    .toEqual({ boundaryViolated: false, proof: expect.objectContaining({ ok: true }) });
});

// ---------------------------------------------------------------------------
// Scope and proof sealing.
// ---------------------------------------------------------------------------

test("startup scope ignores invariants outside the startup sets that scope all reports", () => {
  const { contract, evidence } = productionStartup("scope");
  const proxy = contract.containers.find((container) => container.name === "proxy");
  if (!proxy) throw new Error("test fixture missing proxy container");
  proxy.pathStats.push({ code: "test-non-startup-stat", containerPath: "/run/not-probed", expectedUid: 0 });

  expect(startupProof(contract, evidence).proof).toMatchObject({ ok: true, issues: [] });
  expect(validateWithCallback(contract, evidence, "all").proof.issues).toEqual([{
    code: "test-non-startup-stat",
    container: "proxy",
    detail: "/run/not-probed was not stat-probed",
  }]);
});

test("only a live startup proof is sealed, and only for its own runtime identity", () => {
  const { contract, evidence } = productionStartup("seal");
  const expected = {
    runtimeId: contract.runtimeId,
    components: contract.components,
    contractHash: contract.contractHash ?? "",
  };

  const allScope = validateRuntimeSecurityContractEvidence(contract, evidence, { requireLiveProbes: true, scope: "all" });
  expect(allScope.ok).toBe(true);
  expect(() => assertRuntimeStartupSecurityContractProof(allScope)).toThrow("not minted");
  const shapeOnly = validateRuntimeSecurityContractEvidence(contract, evidence, { requireLiveProbes: false, scope: "startup" });
  expect(shapeOnly.ok).toBe(true);
  expect(() => assertRuntimeStartupSecurityContractProof(shapeOnly)).toThrow("not minted");

  const sealed = validateRuntimeSecurityContractEvidence(contract, evidence, { requireLiveProbes: true, scope: "startup" });
  expect(() => assertRuntimeStartupSecurityContractProof(sealed, expected)).not.toThrow();
  expect(() => assertRuntimeStartupSecurityContractProof(sealed, { ...expected, runtimeId: "runfree-other" }))
    .toThrow("belongs to another runtime identity");
  expect(() => assertRuntimeStartupSecurityContractProof(sealed, { ...expected, contractHash: sha256Digest("other") }))
    .toThrow("belongs to another runtime identity");
  expect(() => assertRuntimeStartupSecurityContractProof(sealed, {
    ...expected,
    components: { ...expected.components, proxyImageInputDigest: sha256Digest("other-proxy") },
  })).toThrow("belongs to another runtime identity");
});

test("a contract without a stored hash is proved under its computed hash", () => {
  const { contract, evidence } = productionStartup("no-hash");
  const { contractHash, ...unhashed } = contract;

  const proof = validateRuntimeSecurityContractEvidence(unhashed, evidence, { requireLiveProbes: true, scope: "startup" });

  expect(proof.contractHash).toBe(hashRuntimeSecurityContract(unhashed));
  expect(proof.contractHash).toBe(contractHash);
});
