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
  expect(proxy?.mounts).toContainEqual(expect.objectContaining({
    code: "proxy-mcp-operation-policy-read-only",
    containerPath: "/app/proxy/mcp-operation-policy.json",
    requiredMode: "ro",
  }));
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
        { Destination: "/app/proxy/mcp-operation-policy.json", Type: "bind", RW: false },
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
    ?.find((mount) => mount.Destination === "/app/proxy/mcp-operation-policy.json");
  if (!policyMount) throw new Error("test fixture missing mcp operation policy mount");
  policyMount.RW = true;

  const { boundaryViolated, proof } = startupProof(contract, evidence);

  expect(evidence.proxy.mountProbes["/app/proxy/mcp-operation-policy.json"].options).toBe("ro,relatime");
  expect(proof.ok).toBe(false);
  expect(proof.issues).toContainEqual({
    code: "proxy-mcp-operation-policy-read-only",
    container: "proxy",
    detail: "/app/proxy/mcp-operation-policy.json is not mounted as ro",
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
