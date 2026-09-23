import fs from "node:fs";
import path from "node:path";

import {
  BUILTIN_AGENT_DESCRIPTORS,
  agentStateHostPath,
  type AgentStateMount,
} from "../agents.ts";
import type { ProjectInfo } from "../config.ts";
import { die } from "../errors.ts";
import { cleanupInbox, ensureInbox } from "../inbox.ts";
import {
  assertNoSymlinkPath,
  assertRegularNonHardLinkedFile,
  relativeProjectPath,
  safeRemoveEmptyProjectDir,
} from "../safe-fs.ts";
import { warn } from "../warnings.ts";
import { ROOT_UID_GID, RUNTIME_VALIDATION_MARKER_PATH } from "./constants.ts";
import { updateCodexConfig } from "./codex-config.ts";
import { dockerClientEnvOptions, envOptions, serviceContainerId, shellSingleQuote } from "./docker.ts";
import { composeProjectName, projectHash } from "./env.ts";
import { assertHostGitSupportsRelativeWorktrees } from "./git-layout.ts";
import {
  mcpOAuthCallbackPort,
  ensureClaudeMcpConfigFile,
  ensureMcpOperationPolicyFile,
  ensureMcpOAuthPolicyFile,
  ensureMcpProjectMasks,
} from "./mcp.ts";
import {
  parseControlPlaneGenerationV2,
  type ControlPlaneGenerationV2,
} from "./component-state-v2.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";
import { isRecord } from "../strict-primitives.ts";

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

export type RuntimeValidationProof = NonNullable<RuntimeContext["validatedRuntime"]>;

type RuntimeValidationMarkerOptions = {
  contractHash?: string;
  expectedProxyId?: string;
};

type RuntimeValidationMarkerResult = {
  issue?: string;
  proof?: RuntimeValidationProof;
};

// The marker binds the schema-v2 control-plane generation, not the composite
// v1 components: the marker attests control-plane validation, and a
// session-template or agent-image roll must not turn a proved control plane
// stale. Session generations are attested by admission.
function runtimeValidationComponents(context: RuntimeContext): ControlPlaneGenerationV2 | undefined {
  const controlPlane = context.runtimeGenerationV2?.controlPlane;
  if (!controlPlane) return undefined;
  return { ...controlPlane };
}

function runtimeValidationComponentsIssue(
  value: unknown,
  expected: ControlPlaneGenerationV2,
): string | undefined {
  // Exact-shape and digest-recomputing parse: a marker written by an older
  // binary (composite v1 shape) fails here and forces revalidation.
  const parsed = parseControlPlaneGenerationV2(value);
  if (!parsed) return "runtime validation marker has malformed component identity";
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (parsed[key as keyof ControlPlaneGenerationV2] !== expectedValue) {
      return "runtime validation marker is stale for runtime components";
    }
  }
  return undefined;
}

export function observeRuntimeValidationProof(
  context: RuntimeContext,
  io: RuntimeIO,
  options: RuntimeValidationMarkerOptions = {},
): RuntimeValidationMarkerResult {
  const components = runtimeValidationComponents(context);
  if (!components) return { issue: "runtime component state is unavailable for validation marker" };
  const project = composeProjectName(context.projectRoot);
  // The per-session runtime has no shared agent to inspect or bind. Startup
  // validation covers the fixed control plane (the proxy); sessions are
  // validated individually by admission, and the MCP OAuth callback is a
  // per-session ingress forwarder outside the fixed control plane.
  const proxyId = serviceContainerId(project, "proxy", context, io);
  if (!proxyId) {
    return { issue: "could not find runtime containers for validation marker" };
  }
  if (options.expectedProxyId && proxyId !== options.expectedProxyId) return { issue: "exact proxy changed before validation receipt" };
  const proof: RuntimeValidationProof = {
    components,
    ...(options.contractHash ? { contractHash: options.contractHash } : {}),
    mcpOAuthCallbackPort: mcpOAuthCallbackPort(context.projectRoot),
    mcpOAuthCallbackTopologyVersion: 2,
    projectId: projectHash(context.projectRoot),
    proofVersion: 4,
    proxyId,
  };
  return { proof };
}

export function writeRuntimeValidationMarkerResult(
  context: RuntimeContext, io: RuntimeIO, options: RuntimeValidationMarkerOptions = {},
): RuntimeValidationMarkerResult {
  const resultProof = observeRuntimeValidationProof(context, io, options);
  if (!resultProof.proof) return resultProof;
  const proof = resultProof.proof;
  const proxyId = proof.proxyId;
  const tmpPath = `${RUNTIME_VALIDATION_MARKER_PATH}.tmp`;
  const marker = JSON.stringify(proof);
  const command = [
    "set -e",
    "umask 077",
    `rm -f ${shellSingleQuote(tmpPath)}`,
    `cat > ${shellSingleQuote(tmpPath)}`,
    `chmod 600 ${shellSingleQuote(tmpPath)}`,
    `mv ${shellSingleQuote(tmpPath)} ${shellSingleQuote(RUNTIME_VALIDATION_MARKER_PATH)}`,
  ].join("; ");
  const result = io.capture(
    "docker",
    ["exec", "--user", ROOT_UID_GID, "-i", proxyId, "sh", "-c", command],
    { ...dockerClientEnvOptions(context), input: marker },
  );
  if (result.status !== 0) {
    return { issue: `could not write runtime validation marker: ${compactDiagnostic(`${result.stderr}\n${result.stdout}`) || `exit ${result.status}`}` };
  }
  return { proof };
}

export function writeRuntimeValidationMarker(context: RuntimeContext, io: RuntimeIO): string | undefined {
  return writeRuntimeValidationMarkerResult(context, io).issue;
}

export function runtimeValidationMarkerStatus(
  context: RuntimeContext,
  io: RuntimeIO,
  options: RuntimeValidationMarkerOptions = {},
): RuntimeValidationMarkerResult {
  const components = runtimeValidationComponents(context);
  if (!components) return { issue: "runtime component state is unavailable for validation marker" };
  const { agentId, proxyId } = runtimeValidationMarkerContainerIds(context, io);
  if (!proxyId) {
    return { issue: "runtime containers are not both running" };
  }
  if (agentId) {
    return { issue: "shared agent container is running but the per-session runtime forbids it" };
  }
  const result = io.capture(
    "docker",
    ["exec", "--user", ROOT_UID_GID, proxyId, "cat", RUNTIME_VALIDATION_MARKER_PATH],
    dockerClientEnvOptions(context),
  );
  if (result.status !== 0) return { issue: "runtime validation marker is missing" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout) as unknown;
  } catch {
    return { issue: "runtime validation marker is malformed" };
  }
  if (!isRecord(parsed)) return { issue: "runtime validation marker is malformed" };
  if (parsed.proofVersion !== 4) return { issue: "runtime validation marker has stale proof version" };
  if (parsed.projectId !== projectHash(context.projectRoot)) return { issue: "runtime validation marker belongs to another project" };
  // The per-session marker names no agent; a marker carrying an agent id is
  // stale from before the cutover.
  if (parsed.agentId !== undefined) {
    return { issue: "runtime validation marker is stale for the per-session runtime shape" };
  }
  if (parsed.proxyId !== proxyId) return { issue: "runtime validation marker belongs to another proxy container" };
  if (parsed.mcpOAuthCallbackTopologyVersion !== 2) {
    return { issue: "runtime validation marker is stale for MCP OAuth callback topology" };
  }
  const callbackPort = mcpOAuthCallbackPort(context.projectRoot);
  if (parsed.mcpOAuthCallbackPort !== callbackPort) {
    return { issue: "runtime validation marker is stale for MCP OAuth callback port" };
  }
  // A marker carrying any retired Compose-relay field was written by an older
  // binary; refuse it so the runtime revalidates rather than trusting a proof
  // surface this binary no longer mints.
  if (parsed.mcpOAuthRequiresCallbackBridge !== undefined
    || parsed.mcpOAuthCallbackSidecarId !== undefined
    || parsed.mcpOAuthCallbackSidecarIp !== undefined
    || parsed.mcpOAuthCallbackSidecarService !== undefined) {
    return { issue: "runtime validation marker is stale for MCP OAuth callback sidecar" };
  }
  const componentIssue = runtimeValidationComponentsIssue(parsed.components, components);
  if (componentIssue) return { issue: componentIssue };
  if (options.contractHash && parsed.contractHash !== options.contractHash) {
    return { issue: "runtime validation marker is stale for runtime security contract" };
  }
  return {
    proof: {
      components,
      mcpOAuthCallbackPort: callbackPort,
      mcpOAuthCallbackTopologyVersion: 2,
      projectId: projectHash(context.projectRoot),
      proofVersion: 4,
      proxyId,
      ...(typeof parsed.contractHash === "string" ? { contractHash: parsed.contractHash } : {}),
    },
  };
}

export function runtimeValidationMarkerIssue(context: RuntimeContext, io: RuntimeIO): string | undefined {
  return runtimeValidationMarkerStatus(context, io).issue;
}

export function removeRuntimeValidationMarker(context: RuntimeContext, io: RuntimeIO): string | undefined {
  const project = composeProjectName(context.projectRoot);
  const proxyId = serviceContainerId(project, "proxy", context, io, { runningOnly: true })
    ?? serviceContainerId(project, "proxy", context, io);
  if (!proxyId) return "could not find proxy container for validation marker reset";
  const tmpPath = `${RUNTIME_VALIDATION_MARKER_PATH}.tmp`;
  const command = [
    "set -e",
    `rm -f ${shellSingleQuote(RUNTIME_VALIDATION_MARKER_PATH)} ${shellSingleQuote(tmpPath)}`,
  ].join("; ");
  const result = io.capture(
    "docker",
    ["exec", "--user", ROOT_UID_GID, proxyId, "sh", "-c", command],
    dockerClientEnvOptions(context),
  );
  if (result.status !== 0) {
    return `could not remove stale runtime validation marker: ${compactDiagnostic(`${result.stderr}\n${result.stdout}`) || `exit ${result.status}`}`;
  }
  return undefined;
}

function runtimeValidationMarkerContainerIds(context: RuntimeContext, io: RuntimeIO): { agentId?: string; proxyId?: string } {
  const project = composeProjectName(context.projectRoot);
  return {
    agentId: serviceContainerId(project, "agent", context, io, { runningOnly: true }),
    proxyId: serviceContainerId(project, "proxy", context, io, { runningOnly: true }),
  };
}


function ensureCodexConfig(codexHome: string): void {
  const required = 'cli_auth_credentials_store = "file"';
  updateCodexConfig(codexHome, (current) => {
    if (current === undefined) return `${required}\n`;
    if (/^\s*cli_auth_credentials_store\s*=/.test(current) || /\n\s*cli_auth_credentials_store\s*=/.test(current)) {
      return undefined;
    }
    return `${required}\n${current}`;
  });
}

function ensureAgentStateMount(project: ProjectInfo, mount: AgentStateMount): void {
  const hostPath = agentStateHostPath(project, mount);
  switch (mount.bootstrap.type) {
    case "empty-directory":
      fs.mkdirSync(hostPath, { recursive: true, mode: mount.mode });
      fs.chmodSync(hostPath, mount.mode);
      return;
    case "empty-json-file":
      fs.mkdirSync(path.dirname(hostPath), { recursive: true, mode: 0o700 });
      if (!fs.existsSync(hostPath)) {
        fs.writeFileSync(hostPath, "{}\n", { mode: mount.mode });
      }
      fs.chmodSync(hostPath, mount.mode);
      return;
    case "codex-file-credential-store":
      fs.mkdirSync(hostPath, { recursive: true, mode: mount.mode });
      fs.chmodSync(hostPath, mount.mode);
      ensureCodexConfig(hostPath);
      return;
  }
}

export function assertSafeRuntimePolicyPath(context: RuntimeContext): void {
  const projectRoot = context.projectRoot;
  const policyPath = context.project.paths.policyPath;
  if (!fs.existsSync(policyPath)) {
    die(`missing project network policy: ${relativeProjectPath(projectRoot, policyPath)}`);
  }

  try {
    assertNoSymlinkPath(projectRoot, policyPath);
    assertRegularNonHardLinkedFile(projectRoot, policyPath);
  } catch {
    const relative = relativeProjectPath(projectRoot, policyPath);
    die(`network policy path contains symlinks or the policy file is not a regular non-hard-linked file: ${relative}
replace symlinked path components or hard links with normal directories/files`);
  }
}

export function ensureAgentState(context: RuntimeContext): void {
  fs.mkdirSync(context.project.paths.stateDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(context.project.paths.stateDir, 0o700);
  const legacyProjectInbox = path.join(context.projectRoot, ".runfree-images");
  const legacyProjectInboxResult = safeRemoveEmptyProjectDir(context.projectRoot, legacyProjectInbox);
  if (legacyProjectInboxResult === "kept") {
    try {
      fs.lstatSync(legacyProjectInbox);
      warn(`legacy Runfree image inbox was kept at ${legacyProjectInbox}; delete it by hand after reviewing its contents`);
    } catch (error) {
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
        warn(`could not inspect legacy Runfree image inbox ${legacyProjectInbox}; delete it by hand if it still exists`);
      }
    }
  }
  ensureInbox(context.project.paths.inboxDir);
  cleanupInbox(context.project.paths.inboxDir);
  for (const descriptor of BUILTIN_AGENT_DESCRIPTORS) {
    for (const mount of descriptor.stateMounts) {
      ensureAgentStateMount(context.project, mount);
    }
  }
  ensureClaudeMcpConfigFile(context.project.paths.claudeMcpConfigPath);
  ensureMcpProjectMasks(context.project.paths);
  ensureMcpOAuthPolicyFile(context.project.paths.mcpOAuthPolicyPath, context.projectRoot);
  ensureMcpOperationPolicyFile(
    context.project.paths.mcpOperationPolicyPath ?? path.join(context.project.paths.stateDir, "mcp-operation-policy.json"),
  );
  fs.mkdirSync(path.dirname(context.project.paths.proxyCaKeyDir), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(context.project.paths.proxyCaKeyDir), 0o700);
  fs.mkdirSync(context.project.paths.proxyCaKeyDir, { recursive: true, mode: 0o1733 });
  fs.mkdirSync(context.project.paths.proxyCaCertDir, { recursive: true, mode: 0o1777 });
  fs.chmodSync(context.project.paths.proxyCaKeyDir, 0o1733);
  fs.chmodSync(context.project.paths.proxyCaCertDir, 0o1777);
}

function resolvedGitConfigValue(key: "user.email" | "user.name", context: RuntimeContext, io: RuntimeIO): string | undefined {
  const result = io.capture("git", ["-C", context.projectRoot, "config", "--get", key], envOptions(context.env));
  if (result.status !== 0) return undefined;
  const value = result.stdout.trim();
  return value === "" ? undefined : value;
}

function gitConfigValue(value: string): string {
  return JSON.stringify(value);
}

/**
 * Repository roots the sandbox's Git may use, as container paths.
 *
 * Both forms are needed per root: Git treats a bare path as an exact match and
 * only a trailing `/*` as "everything below", so `/workspace/*` alone does not
 * cover `/workspace` itself. The glob does recurse to any depth, which is what
 * covers a mount nested inside another mount.
 */
const SANDBOX_GIT_SAFE_ROOTS = ["/workspace", "/runfree/git-layout"] as const;

function sandboxGitSafeDirectoryEntries(): string[] {
  return SANDBOX_GIT_SAFE_ROOTS.flatMap((root) => [
    `\tdirectory = ${root}`,
    `\tdirectory = ${root}/*`,
  ]);
}

function sandboxGitConfigSource(name: string | undefined, email: string | undefined): string {
  const entries: string[] = [];
  if (name) entries.push(`\tname = ${gitConfigValue(name)}`);
  if (email) entries.push(`\temail = ${gitConfigValue(email)}`);
  return [
    "[worktree]",
    "\tuseRelativePaths = true",
    // Docker maps the owner of a bind-mount root independently of its contents,
    // and the mapping is the host runtime's business, not ours: it has differed
    // between Docker Desktop versions, and in one observed layout the same path
    // reported a different owner once a second mount was nested inside it. Git
    // then refuses the workspace outright with "detected dubious ownership".
    //
    // Declaring the roots safe by path is invariant under every one of those
    // mappings, where matching uids would have to be re-derived each time the
    // host runtime changes. It is inert wherever ownership already lines up,
    // because Git only consults this list when the owner differs.
    //
    // This costs nothing here that is not already granted: the agent is the
    // untrusted party and already has write access to these trees, so it can
    // set Git config and hooks in them regardless. The entries stay scoped to
    // the two roots Runfree mounts rather than the blanket `*`, and this file
    // is the container's global config only -- host-side Git in `git-layout.ts`
    // runs with `GIT_CONFIG_GLOBAL=/dev/null` and never reads it.
    "[safe]",
    ...sandboxGitSafeDirectoryEntries(),
    ...(entries.length > 0 ? ["[user]", ...entries] : []),
    "",
  ].join("\n");
}

export function ensureSandboxGitConfig(context: RuntimeContext, io: RuntimeIO): void {
  // Relative-link creation upgrades shared Git metadata. Refuse before exposing
  // that default when the host cannot read the resulting repository extension.
  assertHostGitSupportsRelativeWorktrees(context, io);
  const gitConfigPath = context.env?.RUNFREE_GIT_CONFIG ?? context.project.paths.gitConfigPath;
  fs.mkdirSync(path.dirname(gitConfigPath), { recursive: true, mode: 0o700 });
  const source = sandboxGitConfigSource(
    resolvedGitConfigValue("user.name", context, io),
    resolvedGitConfigValue("user.email", context, io),
  );
  fs.writeFileSync(gitConfigPath, source, { mode: 0o600 });
  fs.chmodSync(gitConfigPath, 0o644);
}
