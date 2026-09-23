
import fs from "node:fs";
import path from "node:path";

import type { ActiveRuntimePlan } from "./plan.ts";
import type { ControlPlaneGenerationV2 } from "./component-state-v2.ts";
import { REQUIRED_TOPOLOGY_ASSERTIONS } from "./topology.ts";
import type { DockerContainerInspect } from "./types.ts";
import { stableJsonDroppingUndefined as stableJson, sha256Digest } from "../strict-primitives.ts";

export type RuntimeContainerName = "agent" | "proxy" | "orchestrator";

export type RuntimeMountMode = "ro" | "rw" | "tmpfs";

export interface RuntimeSecurityContract {
  version: 2;
  runtimeId: string;
  // The control-plane generation this contract binds. Session-agent inputs are
  // deliberately outside the hash: this contract attests only the fixed proxy
  // control plane, and the durable effective selection records its hash, so a
  // session-template or agent-image roll must leave it unchanged or every live
  // session would falsely invalidate control-plane authority.
  components: ControlPlaneGenerationV2;
  contractHash?: string;
  // Host-resolved enforcement-affecting runtime env, folded into the contract
  // hash: changing it requires runtime recreation/revalidation rather than a
  // hot policy reload.
  writeApprovalHoldSeconds: number;
  containers: RuntimeContainerContract[];
  topologyAssertions: string[];
}

export interface RuntimeContainerContract {
  name: RuntimeContainerName;
  mounts: RuntimeMountInvariant[];
  forbiddenMounts?: RuntimeForbiddenMountInvariant[];
  writeProbes: RuntimeWriteProbeInvariant[];
  absenceProbes: RuntimeAbsenceInvariant[];
  contentChecks: RuntimeContentInvariant[];
  directoryChecks: RuntimeDirectoryInvariant[];
  pathStats: RuntimePathStatInvariant[];
}

export interface RuntimeForbiddenMountInvariant {
  code: string;
  containerPath: string;
  includeDescendants?: boolean;
}

export interface RuntimeMountInvariant {
  code: string;
  containerPath: string;
  source?: string;
  requiredMode: RuntimeMountMode;
  requiredPropagation?: "rprivate";
  noWritableAlias?: boolean;
  sourceMustExist?: boolean;
}

export interface RuntimeWriteProbeInvariant {
  code: string;
  containerPath: string;
}

export interface RuntimeAbsenceInvariant {
  code: string;
  containerPath: string;
}

export interface RuntimeContentInvariant {
  code: string;
  containerPath: string;
  expectedSha256: string;
}

export interface RuntimeDirectoryInvariant {
  code: string;
  containerPath: string;
  expected: "empty";
}

export interface RuntimePathStatInvariant {
  code: string;
  containerPath: string;
  expectedGid?: number;
  expectedMode?: string;
  expectedUid?: number;
}

export interface RuntimeSecurityContractIssue {
  code: string;
  container: RuntimeContainerName;
  detail: string;
}

export interface RuntimeSecurityContractProof {
  contractHash: string;
  issues: RuntimeSecurityContractIssue[];
  ok: boolean;
}

const sealedStartupSecurityProofs = new WeakMap<object, Readonly<{
  runtimeId: string;
  components: ControlPlaneGenerationV2;
}>>();

export function assertRuntimeStartupSecurityContractProof(
  proof: RuntimeSecurityContractProof,
  expected?: Readonly<{
    runtimeId: string;
    components: ControlPlaneGenerationV2;
    contractHash: string;
  }>,
): void {
  const identity = sealedStartupSecurityProofs.get(proof);
  if (!identity || !proof.ok) {
    throw new Error("runtime security-contract proof was not minted by live startup validation");
  }
  if (expected && (
    identity.runtimeId !== expected.runtimeId
    || proof.contractHash !== expected.contractHash
    || JSON.stringify(identity.components) !== JSON.stringify(expected.components)
  )) {
    throw new Error("runtime security-contract proof belongs to another runtime identity");
  }
}

export interface RuntimeMountProbeEvidence {
  fsType?: string;
  options?: string;
  status: number;
  target?: string;
}

export interface RuntimeContentCheckEvidence {
  sha256?: string;
  status: number;
}

export interface RuntimeDirectoryCheckEvidence {
  empty?: boolean;
  status: number;
}

export interface RuntimePathStatEvidence {
  gid?: number;
  mode?: string;
  status: number;
  uid?: number;
}

export type RuntimeSecurityContractEvidence = Partial<Record<RuntimeContainerName, {
  contentChecks?: Record<string, RuntimeContentCheckEvidence>;
  directoryChecks?: Record<string, RuntimeDirectoryCheckEvidence>;
  inspect: DockerContainerInspect;
  mountProbes?: Record<string, RuntimeMountProbeEvidence>;
  pathStats?: Record<string, RuntimePathStatEvidence>;
  presentPaths?: string[];
}>>;

export type RuntimeSecurityContractValidationScope = "all" | "startup";

// Both fields are required, deliberately. As optionals they defaulted toward the
// weaker validation in both directions at once: an omitted `requireLiveProbes`
// makes absent probe evidence report *no issue* rather than "unverified"
// (`directoryCheckIssue` and its siblings below), while an omitted `scope`
// selects the full invariant set instead of the startup subset. A caller that
// simply forgot the options object therefore got the most thorough-looking
// validation available and verified nothing at all.
//
// Requiring both costs one object literal per call site and makes shape-only
// validation something a caller states rather than something it inherits.
export type RuntimeSecurityContractValidationOptions = {
  onBoundaryViolation?(): void;
  requireLiveProbes: boolean;
  scope: RuntimeSecurityContractValidationScope;
};

const STARTUP_MOUNT_INVARIANTS = new Set([
  "agent-mcp-config-read-only",
  "agent-inbox-read-only",
  "agent-codex-dir-masked",
  "agent-proxy-ca-read-only",
  "proxy-ca-private-mounted",
  "proxy-ca-public-mounted",
  "proxy-effective-control-read-only",
  "proxy-mcp-operation-policy-read-only",
  "proxy-token-store-tmpfs",
  "proxy-audit-tmpfs",
  "proxy-audit-spool-tmpfs",
  "proxy-status-tmpfs",
  "proxy-session-registry-tmpfs",
  "proxy-approvals-pending-tmpfs",
  "proxy-approvals-decisions-tmpfs",
]);

const STARTUP_FORBIDDEN_MOUNT_INVARIANTS = new Set([
  "agent-runfree-nested-mount-absent",
  "agent-mcp-json-mask-absent",
]);

const STARTUP_ABSENCE_INVARIANTS = new Set([
  "agent-proxy-ca-private-absent",
]);

const STARTUP_CONTENT_INVARIANTS = new Set([
  "agent-mcp-config-content",
]);

const STARTUP_DIRECTORY_INVARIANTS = new Set([
  "agent-codex-dir-masked",
]);

const STARTUP_PATH_STAT_INVARIANTS = new Set([
  "proxy-token-store-tmpfs",
  "proxy-audit-tmpfs",
  "proxy-audit-spool-tmpfs",
  "proxy-status-tmpfs",
  "proxy-status-request-proxy-dir",
  "proxy-session-registry-tmpfs",
  "proxy-session-files-dir",
  "proxy-approvals-pending-tmpfs",
  "proxy-approvals-decisions-tmpfs",
]);


function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function contractPayload(contract: RuntimeSecurityContract): RuntimeSecurityContract {
  const { contractHash: _contractHash, ...payload } = contract;
  return payload;
}

export function hashRuntimeSecurityContract(contract: RuntimeSecurityContract): string {
  return sha256Digest(stableJson(contractPayload(contract)));
}

function proxyMounts(plan: ActiveRuntimePlan): RuntimeMountInvariant[] {
  const mcpOperationPolicyPath = plan.paths.mcpOperationPolicyPath ?? path.join(plan.paths.stateDir, "mcp-operation-policy.json");
  return [
    {
      code: "proxy-ca-private-mounted",
      containerPath: "/ca/private",
      source: plan.paths.proxyCaKeyDir,
      requiredMode: "rw",
      sourceMustExist: true,
    },
    {
      code: "proxy-ca-public-mounted",
      containerPath: "/ca/public",
      source: plan.paths.proxyCaCertDir,
      requiredMode: "rw",
      sourceMustExist: true,
    },
    {
      code: "proxy-effective-control-read-only",
      containerPath: "/app/runfree-effective",
      source: plan.paths.controlProxyDir,
      requiredMode: "ro",
      sourceMustExist: true,
    },
    {
      code: "proxy-mcp-operation-policy-read-only",
      containerPath: "/app/proxy/mcp-operation-policy.json",
      source: mcpOperationPolicyPath,
      requiredMode: "ro",
    },
    {
      code: "proxy-token-store-tmpfs",
      containerPath: "/run/runfree-proxy-secrets",
      requiredMode: "tmpfs",
    },
    {
      code: "proxy-audit-tmpfs",
      containerPath: "/run/runfree-proxy-audit",
      requiredMode: "tmpfs",
    },
    {
      code: "proxy-audit-spool-tmpfs",
      containerPath: "/run/runfree-proxy-audit-spool",
      requiredMode: "tmpfs",
    },
    {
      code: "proxy-status-tmpfs",
      containerPath: "/run/runfree-proxy-status",
      requiredMode: "tmpfs",
    },
    // Root-owned immutable session admission generations. The request proxy
    // may read selected snapshots but cannot mint or select authority.
    {
      code: "proxy-session-registry-tmpfs",
      containerPath: "/run/runfree-sessions",
      requiredMode: "tmpfs",
    },
    // Approve-on-write channel: live-proved before token sync or agent
    // attach. Pending records are proxy-owned; decisions are root-owned so
    // the UID-1001 server can read but never mint one.
    {
      code: "proxy-approvals-pending-tmpfs",
      containerPath: "/run/runfree-approvals/pending",
      requiredMode: "tmpfs",
    },
    {
      code: "proxy-approvals-decisions-tmpfs",
      containerPath: "/run/runfree-approvals/decisions",
      requiredMode: "tmpfs",
    },
  ];
}

export function createRuntimeSecurityContract(plan: ActiveRuntimePlan): RuntimeSecurityContract {
  const contract: RuntimeSecurityContract = {
    version: 2,
    runtimeId: plan.composeProjectName,
    components: { ...plan.generationV2.controlPlane },
    writeApprovalHoldSeconds: plan.project.config.runtime.writeApprovalHoldSeconds ?? 120,
    containers: [
      // The fixed runtime has no shared agent container: each session's security
      // properties are attested by session admission, not by this control-plane
      // contract.
      {
        name: "proxy",
        mounts: proxyMounts(plan),
        forbiddenMounts: [],
        writeProbes: [],
        absenceProbes: [],
        contentChecks: [],
        directoryChecks: [],
        pathStats: [
          {
            code: "proxy-token-store-tmpfs",
            containerPath: "/run/runfree-proxy-secrets",
            expectedGid: 1001,
            expectedMode: "700",
            expectedUid: 1001,
          },
          {
            code: "proxy-audit-tmpfs",
            containerPath: "/run/runfree-proxy-audit",
            expectedGid: 0,
            expectedMode: "755",
            expectedUid: 0,
          },
          {
            code: "proxy-audit-spool-tmpfs",
            containerPath: "/run/runfree-proxy-audit-spool",
            expectedGid: 1001,
            expectedMode: "755",
            expectedUid: 1001,
          },
          // Generation status files: firewall.json lives in the root-owned
          // tmpfs root (uid-1001 must not be able to write it); the request
          // proxy writes only inside its own subdirectory.
          {
            code: "proxy-status-tmpfs",
            containerPath: "/run/runfree-proxy-status",
            expectedGid: 0,
            expectedMode: "755",
            expectedUid: 0,
          },
          {
            code: "proxy-status-request-proxy-dir",
            containerPath: "/run/runfree-proxy-status/request-proxy",
            expectedGid: 1001,
            expectedMode: "755",
            expectedUid: 1001,
          },
          {
            code: "proxy-session-registry-tmpfs",
            containerPath: "/run/runfree-sessions",
            expectedGid: 0,
            expectedMode: "755",
            expectedUid: 0,
          },
          {
            code: "proxy-session-files-dir",
            containerPath: "/run/runfree-sessions/sessions",
            expectedGid: 0,
            expectedMode: "755",
            expectedUid: 0,
          },
          {
            code: "proxy-approvals-pending-tmpfs",
            containerPath: "/run/runfree-approvals/pending",
            expectedGid: 1001,
            expectedMode: "700",
            expectedUid: 1001,
          },
          {
            code: "proxy-approvals-decisions-tmpfs",
            containerPath: "/run/runfree-approvals/decisions",
            expectedGid: 0,
            expectedMode: "755",
            expectedUid: 0,
          },
        ],
      },
      {
        name: "orchestrator",
        mounts: [],
        writeProbes: [],
        absenceProbes: [],
        contentChecks: [],
        directoryChecks: [],
        pathStats: [],
      },
    ],
    topologyAssertions: REQUIRED_TOPOLOGY_ASSERTIONS.map((entry) => entry.code),
  };
  return { ...contract, contractHash: hashRuntimeSecurityContract(contract) };
}

export function runtimeSecurityContractProbeScript(container: RuntimeContainerContract): string {
  const commands = [
    "set +e",
    ": runfree_security_contract_probe",
  ];
  for (const mount of container.mounts) {
    commands.push([
      `target=${shellSingleQuote(mount.containerPath)}`,
      "actual=$(findmnt -T \"$target\" -n -o TARGET 2>/dev/null | head -n 1)",
      "target_status=$?",
      "fstype=$(findmnt -T \"$target\" -n -o FSTYPE 2>/dev/null | head -n 1)",
      "options=$(findmnt -T \"$target\" -n -o OPTIONS 2>/dev/null | head -n 1)",
      "printf 'mount\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$target\" \"$target_status\" \"$actual\" \"$fstype\" \"$options\"",
    ].join("; "));
  }
  for (const content of container.contentChecks) {
    commands.push([
      `target=${shellSingleQuote(content.containerPath)}`,
      "if [ -e \"$target\" ]; then",
      "  digest=$(sha256sum \"$target\" 2>/dev/null | awk '{print $1}')",
      "  status=$?",
      "else",
      "  digest=",
      "  status=1",
      "fi",
      "printf 'content\\t%s\\t%s\\t%s\\n' \"$target\" \"$status\" \"$digest\"",
    ].join("\n"));
  }
  for (const directory of container.directoryChecks) {
    commands.push([
      `target=${shellSingleQuote(directory.containerPath)}`,
      "if [ -d \"$target\" ]; then",
      "  first=$(find \"$target\" -mindepth 1 -print -quit 2>/dev/null)",
      "  if [ -z \"$first\" ]; then empty=1; else empty=0; fi",
      "  status=0",
      "else",
      "  empty=0",
      "  status=1",
      "fi",
      "printf 'directory\\t%s\\t%s\\t%s\\n' \"$target\" \"$status\" \"$empty\"",
    ].join("\n"));
  }
  for (const absence of container.absenceProbes) {
    commands.push([
      `target=${shellSingleQuote(absence.containerPath)}`,
      "if [ -e \"$target\" ]; then present=1; else present=0; fi",
      "printf 'absence\\t%s\\t%s\\n' \"$target\" \"$present\"",
    ].join("; "));
  }
  for (const stat of container.pathStats) {
    commands.push([
      `target=${shellSingleQuote(stat.containerPath)}`,
      "if [ -e \"$target\" ]; then",
      "  value=$(stat -c '%u:%g:%a' \"$target\" 2>/dev/null)",
      "  status=$?",
      "else",
      "  value=::",
      "  status=1",
      "fi",
      "printf 'stat\\t%s\\t%s\\t%s\\n' \"$target\" \"$status\" \"$value\"",
    ].join("\n"));
  }
  commands.push("exit 0");
  return commands.join("\n");
}

export function parseRuntimeSecurityContractProbe(stdout: string): Omit<NonNullable<RuntimeSecurityContractEvidence["agent"]>, "inspect"> {
  const mountProbes: NonNullable<RuntimeSecurityContractEvidence["agent"]>["mountProbes"] = {};
  const contentChecks: NonNullable<RuntimeSecurityContractEvidence["agent"]>["contentChecks"] = {};
  const directoryChecks: NonNullable<RuntimeSecurityContractEvidence["agent"]>["directoryChecks"] = {};
  const pathStats: NonNullable<RuntimeSecurityContractEvidence["agent"]>["pathStats"] = {};
  const presentPaths: string[] = [];

  for (const line of stdout.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const [kind, containerPath, statusOrPresent, first, second, third] = line.split("\t");
    if (!kind || !containerPath) continue;
    if (kind === "mount") {
      mountProbes[containerPath] = {
        status: Number(statusOrPresent),
        target: first,
        fsType: second,
        options: third,
      };
      continue;
    }
    if (kind === "content") {
      contentChecks[containerPath] = {
        status: Number(statusOrPresent),
        sha256: first,
      };
      continue;
    }
    if (kind === "directory") {
      directoryChecks[containerPath] = {
        status: Number(statusOrPresent),
        empty: first === "1",
      };
      continue;
    }
    if (kind === "absence") {
      if (statusOrPresent === "1") presentPaths.push(containerPath);
      continue;
    }
    if (kind === "stat") {
      const [uid, gid, mode] = (first ?? "").split(":");
      pathStats[containerPath] = {
        status: Number(statusOrPresent),
        uid: uid === "" ? undefined : Number(uid),
        gid: gid === "" ? undefined : Number(gid),
        mode,
      };
    }
  }

  return { contentChecks, directoryChecks, mountProbes, pathStats, presentPaths };
}

function mountMode(mount: NonNullable<DockerContainerInspect["Mounts"]>[number]): RuntimeMountMode {
  if (mount.Type === "tmpfs") return "tmpfs";
  if (mount.RW === false || mount.Mode?.split(",").includes("ro")) return "ro";
  return "rw";
}

function mountMatches(invariant: RuntimeMountInvariant, inspect: DockerContainerInspect): boolean {
  if (invariant.requiredMode === "tmpfs") {
    const tmpfs = inspect.HostConfig?.Tmpfs;
    return Boolean(tmpfs && Object.hasOwn(tmpfs, invariant.containerPath))
      || Boolean((inspect.Mounts ?? []).find((mount) => mount.Destination === invariant.containerPath && mount.Type === "tmpfs"));
  }
  const mount = (inspect.Mounts ?? []).find((entry) => entry.Destination === invariant.containerPath);
  if (!mount) return false;
  if (invariant.source && mount.Source && normalizeHostPath(mount.Source) !== normalizeHostPath(invariant.source)) return false;
  return mountMode(mount) === invariant.requiredMode;
}

function mountProbeIssue(invariant: RuntimeMountInvariant, probe: RuntimeMountProbeEvidence | undefined): string | undefined {
  if (!probe) return `${invariant.containerPath} was not live-probed`;
  if (probe.status !== 0) return `${invariant.containerPath} live mount probe exited ${probe.status}`;
  if (normalizeContainerPath(probe.target) !== normalizeContainerPath(invariant.containerPath)) {
    return `${invariant.containerPath} is not an exact live mountpoint`;
  }
  if (invariant.requiredMode === "tmpfs" && probe.fsType !== "tmpfs") {
    return `${invariant.containerPath} is not a live tmpfs mount`;
  }
  const options = `,${probe.options ?? ""},`;
  if (invariant.requiredMode === "ro" && !options.includes(",ro,")) {
    return `${invariant.containerPath} is not read-only in the live mount namespace`;
  }
  if (invariant.requiredMode === "rw" && options.includes(",ro,")) {
    return `${invariant.containerPath} is read-only in the live mount namespace`;
  }
  return undefined;
}

function hasWritableAlias(invariant: RuntimeMountInvariant, inspect: DockerContainerInspect): boolean {
  const protectedPath = normalizeContainerPath(invariant.containerPath);
  const protectedSource = normalizeHostPath(invariant.source);
  return (inspect.Mounts ?? []).some((mount) => {
    if (mountMode(mount) !== "rw") return false;
    const destination = normalizeContainerPath(mount.Destination);
    if (isSameOrDescendantContainerPath(destination, protectedPath)) return true;
    if (!protectedSource) return false;
    const source = normalizeHostPath(mount.Source);
    if (!source) return false;
    const relative = relativeHostPath(source, protectedSource);
    if (relative === undefined) return false;
    const exposedPath = normalizeContainerPath(joinContainerPath(destination, relative));
    return exposedPath !== protectedPath;
  });
}

function normalizeContainerPath(value: string | undefined): string {
  if (!value) return "";
  if (value === "/") return "/";
  return value.replace(/\/+$/, "");
}

function normalizeHostPath(value: string | undefined): string {
  if (!value) return "";
  const hostPath = value.startsWith("/host_mnt/") ? value.slice("/host_mnt".length) : value;
  let normalized: string;
  try {
    normalized = fs.realpathSync.native(hostPath);
  } catch {
    normalized = path.resolve(hostPath);
  }
  return normalized === "/" ? "/" : normalized.replace(/\/+$/, "");
}

function relativeHostPath(parent: string, child: string): string | undefined {
  const relative = path.relative(parent, child);
  if (relative === "") return "";
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return undefined;
  return relative;
}

function joinContainerPath(parent: string, relativeHostPathValue: string): string {
  const relativeParts = relativeHostPathValue.split(path.sep).filter(Boolean);
  return path.posix.join(parent, ...relativeParts);
}

function isSameOrDescendantContainerPath(candidate: string, parent: string): boolean {
  if (!candidate || !parent) return false;
  if (candidate === parent) return true;
  if (parent === "/") return candidate.startsWith("/");
  return candidate.startsWith(`${parent}/`);
}

function pathStatIssue(invariant: RuntimePathStatInvariant, evidence: RuntimePathStatEvidence | undefined): string | undefined {
  if (!evidence) return `${invariant.containerPath} was not stat-probed`;
  if (evidence.status !== 0) return `${invariant.containerPath} stat probe exited ${evidence.status}`;
  if (invariant.expectedUid !== undefined && evidence.uid !== invariant.expectedUid) {
    return `${invariant.containerPath} uid is ${evidence.uid ?? "unknown"}, expected ${invariant.expectedUid}`;
  }
  if (invariant.expectedGid !== undefined && evidence.gid !== invariant.expectedGid) {
    return `${invariant.containerPath} gid is ${evidence.gid ?? "unknown"}, expected ${invariant.expectedGid}`;
  }
  if (invariant.expectedMode !== undefined && normalizeMode(evidence.mode) !== normalizeMode(invariant.expectedMode)) {
    return `${invariant.containerPath} mode is ${evidence.mode ?? "unknown"}, expected ${invariant.expectedMode}`;
  }
  return undefined;
}

function directoryCheckIssue(
  invariant: RuntimeDirectoryInvariant,
  evidence: RuntimeDirectoryCheckEvidence | undefined,
  options: RuntimeSecurityContractValidationOptions,
): string | undefined {
  if (!evidence) {
    return options.requireLiveProbes ? `${invariant.containerPath} directory was not live-probed` : undefined;
  }
  if (evidence.status !== 0) return `${invariant.containerPath} directory probe exited ${evidence.status}`;
  if (invariant.expected === "empty" && evidence.empty !== true) {
    return `${invariant.containerPath} is not an empty Runfree mask directory`;
  }
  return undefined;
}

function normalizeMode(mode: string | undefined): string {
  const normalized = (mode ?? "").replace(/^0+/, "");
  return normalized === "" ? "0" : normalized;
}

// No default for `options`: `= {}` was what let a caller omit validation intent
// entirely and still get a passing proof over every invariant with nothing
// probed. Making it required means a caller states what it is validating.
export function validateRuntimeSecurityContractEvidence(
  contract: RuntimeSecurityContract,
  evidence: RuntimeSecurityContractEvidence,
  options: RuntimeSecurityContractValidationOptions,
): RuntimeSecurityContractProof {
  const issues: RuntimeSecurityContractIssue[] = [];
  for (const container of contract.containers) {
    const mounts = options.scope === "startup"
      ? container.mounts.filter((invariant) => STARTUP_MOUNT_INVARIANTS.has(invariant.code))
      : container.mounts;
    const forbiddenMounts = options.scope === "startup"
      ? (container.forbiddenMounts ?? []).filter((invariant) => STARTUP_FORBIDDEN_MOUNT_INVARIANTS.has(invariant.code))
      : container.forbiddenMounts ?? [];
    const absenceProbes = options.scope === "startup"
      ? container.absenceProbes.filter((invariant) => STARTUP_ABSENCE_INVARIANTS.has(invariant.code))
      : container.absenceProbes;
    const contentChecks = options.scope === "startup"
      ? container.contentChecks.filter((invariant) => STARTUP_CONTENT_INVARIANTS.has(invariant.code))
      : container.contentChecks;
    const directoryChecks = options.scope === "startup"
      ? container.directoryChecks.filter((invariant) => STARTUP_DIRECTORY_INVARIANTS.has(invariant.code))
      : container.directoryChecks;
    const pathStats = options.scope === "startup"
      ? container.pathStats.filter((invariant) => STARTUP_PATH_STAT_INVARIANTS.has(invariant.code))
      : container.pathStats;
    if (
      mounts.length === 0
      && forbiddenMounts.length === 0
      && absenceProbes.length === 0
      && contentChecks.length === 0
      && directoryChecks.length === 0
      && pathStats.length === 0
    ) continue;
    const containerEvidence = evidence[container.name];
    if (!containerEvidence) {
      if (container.name !== "orchestrator") {
        issues.push({
          code: `${container.name}-inspect-missing`,
          container: container.name,
          detail: "missing Docker inspect evidence",
        });
      }
      continue;
    }
    for (const invariant of mounts) {
      if (options.requireLiveProbes) {
        const issue = mountProbeIssue(invariant, containerEvidence.mountProbes?.[invariant.containerPath]);
        if (issue) {
          if (containerEvidence.mountProbes?.[invariant.containerPath]?.status === 0) options.onBoundaryViolation?.();
          issues.push({
            code: invariant.code,
            container: container.name,
            detail: issue,
          });
          continue;
        }
      }
      if (!mountMatches(invariant, containerEvidence.inspect)) {
        options.onBoundaryViolation?.();
        issues.push({
          code: invariant.code,
          container: container.name,
          detail: `${invariant.containerPath} is not mounted as ${invariant.requiredMode}`,
        });
        continue;
      }
      if (invariant.noWritableAlias && hasWritableAlias(invariant, containerEvidence.inspect)) {
        options.onBoundaryViolation?.();
        issues.push({
          code: "agent-runfree-no-rw-alias",
          container: container.name,
          detail: `${invariant.containerPath} has a writable alias`,
        });
      }
    }
    for (const invariant of forbiddenMounts) {
      const forbiddenPath = normalizeContainerPath(invariant.containerPath);
      const mounted = (containerEvidence.inspect.Mounts ?? [])
        .some((mount) => {
          const destination = normalizeContainerPath(mount.Destination);
          return destination === forbiddenPath
            || (invariant.includeDescendants === true && isSameOrDescendantContainerPath(destination, forbiddenPath));
        });
      if (mounted) {
        options.onBoundaryViolation?.();
        issues.push({
          code: invariant.code,
          container: container.name,
          detail: `${invariant.containerPath} must not be an explicit runtime mount`,
        });
      }
    }
    for (const absence of absenceProbes) {
      if (containerEvidence.presentPaths?.includes(absence.containerPath)) {
        options.onBoundaryViolation?.();
        issues.push({
          code: absence.code,
          container: container.name,
          detail: `${absence.containerPath} is visible`,
        });
      }
    }
    for (const content of contentChecks) {
      const observed = containerEvidence.contentChecks?.[content.containerPath];
      if (!observed) {
        if (options.requireLiveProbes) {
          issues.push({
            code: content.code,
            container: container.name,
            detail: `${content.containerPath} content was not live-probed`,
          });
        }
        continue;
      }
      if (observed.status !== 0 || observed.sha256 !== content.expectedSha256) {
        if (observed.status === 0) options.onBoundaryViolation?.();
        issues.push({
          code: content.code,
          container: container.name,
          detail: `${content.containerPath} content does not match the Runfree mask`,
        });
      }
    }
    for (const directory of directoryChecks) {
      const issue = directoryCheckIssue(directory, containerEvidence.directoryChecks?.[directory.containerPath], options);
      if (issue) {
        if (containerEvidence.directoryChecks?.[directory.containerPath]?.status === 0) options.onBoundaryViolation?.();
        issues.push({
          code: directory.code,
          container: container.name,
          detail: issue,
        });
      }
    }
    for (const stat of pathStats) {
      const issue = pathStatIssue(stat, containerEvidence.pathStats?.[stat.containerPath]);
      if (issue) {
        if (containerEvidence.pathStats?.[stat.containerPath]?.status === 0) options.onBoundaryViolation?.();
        issues.push({
          code: stat.code,
          container: container.name,
          detail: issue,
        });
      }
    }
  }
  const proof: RuntimeSecurityContractProof = Object.freeze({
    contractHash: contract.contractHash ?? hashRuntimeSecurityContract(contract),
    issues: Object.freeze(issues) as RuntimeSecurityContractIssue[],
    ok: issues.length === 0,
  });
  if (proof.ok && options.requireLiveProbes && options.scope === "startup") {
    sealedStartupSecurityProofs.set(proof, Object.freeze({
      runtimeId: contract.runtimeId,
      components: Object.freeze({ ...contract.components }),
    }));
  }
  return proof;
}
