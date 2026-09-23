import path from "node:path";

import {
  dependencyArtifactKindForPathSuffix,
  dependencyArtifactKindForRelativePath,
} from "./dependency-artifacts.ts";
import {
  DEPENDENCY_STORE_DEFINITIONS,
  type JavaScriptPackageManagerName,
  dependencyStoreTargets,
} from "./dependency-stores.ts";
import type { RuntimeComposeMount } from "./compose.ts";

export const AGENT_HOME_TARGETS = {
  claudeDir: "/home/agent/.claude",
  claudeJson: "/home/agent/.claude.json",
  codexHome: "/home/agent/.codex",
  piAgentDir: "/home/agent/.pi/agent",
  gitConfig: "/home/agent/.gitconfig",
} as const;

export const RUNFREE_RUNTIME_TARGETS = {
  claudeMcpConfig: "/runfree/mcp/claude.json",
  inbox: "/runfree/inbox",
} as const;

const WORKSPACE_METADATA_NAMES = {
  codex: ".codex",
} as const;

export type AgentHomeTargetKey = keyof typeof AGENT_HOME_TARGETS;
export type WorkspaceMetadataKey = keyof typeof WORKSPACE_METADATA_NAMES;

export type AgentMountTargetPolicy = {
  physicalWorkspaceRoots: string[];
};

declare const allowedAgentMountTargetBrand: unique symbol;

export type AllowedAgentMountTarget = string & {
  readonly [allowedAgentMountTargetBrand]: true;
};

type AgentMountTargetClassificationBase = {
  kind: string;
  reason: string;
};

export type AgentMountTargetClassification =
  | (AgentMountTargetClassificationBase & {
    decision: "allowed";
    target: AllowedAgentMountTarget;
  })
  | (AgentMountTargetClassificationBase & {
    decision: "reserved" | "denied";
  });

export function normalizeContainerPath(value: string): string {
  if (!value.startsWith("/")) throw new Error(`invalid runtime compose mount target: ${value || "<empty>"}`);
  // Resolve "." / ".." and collapse slashes so the reserved-path guards and the
  // dependency-artifact matcher classify the same physical target. The artifact
  // matcher normalizes internally, so without this a segment like "/workspace/.."
  // or "/workspace/./.runfree" would slip past the reserved checks while still
  // matching as an allowed artifact. Absolute normalize clamps at root.
  const normalized = path.posix.normalize(value).replace(/\/+$/g, "");
  return normalized === "" ? "/" : normalized;
}

export function isGitLayoutTarget(target: string): boolean {
  return /^\/runfree\/git-layout\/[a-f0-9]{12}(?:\/.+)?$/.test(target);
}

export function isInboxTarget(target: string): boolean {
  return normalizeContainerPath(target) === RUNFREE_RUNTIME_TARGETS.inbox;
}

export function agentHomeTarget(key: AgentHomeTargetKey): string {
  return AGENT_HOME_TARGETS[key];
}

export function workspaceMetadataTarget(containerRoot: string, key: WorkspaceMetadataKey): string {
  return `${normalizeContainerPath(containerRoot)}/${WORKSPACE_METADATA_NAMES[key]}`;
}

export function dependencyStoreTarget(packageManager: JavaScriptPackageManagerName): string {
  return DEPENDENCY_STORE_DEFINITIONS[packageManager].target;
}

export function dependencyArtifactTarget(containerRoot: string, relativePath: string): string {
  const root = normalizeContainerPath(containerRoot);
  const normalizedRelative = path.posix.normalize(relativePath.replaceAll("\\", "/").replace(/\/+$/g, ""));
  if (normalizedRelative === "." || path.posix.isAbsolute(normalizedRelative) || normalizedRelative.split("/").includes("..")) {
    throw new Error(`invalid dependency artifact target relative path: ${relativePath || "<empty>"}`);
  }
  return `${root}/${normalizedRelative}`;
}

function insideOrEqual(target: string, root: string): boolean {
  return target === root || target.startsWith(`${root}/`);
}

function isWorkspaceRunfreeTarget(target: string): boolean {
  return target === "/workspace/.runfree" || target.startsWith("/workspace/.runfree/");
}

function isRootRunfreeTarget(target: string, root: string): boolean {
  return target === `${root}/.runfree` || target.startsWith(`${root}/.runfree/`);
}

function projectMountRoot(target: string): string | undefined {
  if (target === "/workspace") return target;
  if (!isGitLayoutTarget(target)) return undefined;
  if (target.endsWith("/.runfree") || target.includes("/.runfree/")) return undefined;
  if (target.endsWith("/.git") || target.includes("/.git/")) return undefined;
  return target;
}

export function createAgentMountTargetPolicy(projectMounts: readonly RuntimeComposeMount[]): AgentMountTargetPolicy {
  const roots = new Set<string>();
  for (const mount of projectMounts) {
    const target = normalizeContainerPath(mount.target);
    const root = projectMountRoot(target);
    if (root) roots.add(root);
  }
  return { physicalWorkspaceRoots: [...roots].sort() };
}

function allowed(target: string, kind: string, reason: string): AgentMountTargetClassification {
  // This classifier branch is the sole mint for the mount-target brand. The
  // target has already been normalized and accepted by the policy below.
  return { decision: "allowed", target: target as AllowedAgentMountTarget, kind, reason };
}

function reserved(kind: string, reason: string): AgentMountTargetClassification {
  return { decision: "reserved", kind, reason };
}

function denied(reason: string): AgentMountTargetClassification {
  return { decision: "denied", kind: "unknown", reason };
}

export function classifyAgentMountTarget(
  value: string,
  policy: AgentMountTargetPolicy,
): AgentMountTargetClassification {
  const target = normalizeContainerPath(value);
  if (target === "/workspace") return reserved("workspace-root", "project root is rendered through project mounts");
  if (isWorkspaceRunfreeTarget(target)) return reserved("runfree-policy", "project .runfree control paths cannot be shadowed by agent-state mounts");
  if (target === "/etc" || target.startsWith("/etc/")) return reserved("system-etc", "/etc is reserved for runtime trust material");
  if (target === "/ca" || target.startsWith("/ca/")) return reserved("proxy-ca", "/ca is reserved for proxy private CA material");
  for (const root of policy.physicalWorkspaceRoots) {
    if (isRootRunfreeTarget(target, root)) {
      return reserved("runfree-policy", "project .runfree control paths cannot be shadowed by agent-state mounts");
    }
  }

  if ((Object.values(AGENT_HOME_TARGETS) as string[]).includes(target)) {
    return allowed(target, "agent-home", "built-in agent state target");
  }
  if (target === RUNFREE_RUNTIME_TARGETS.claudeMcpConfig) {
    return allowed(target, "runfree-mcp-config", "Runfree-rendered Claude MCP config target");
  }
  if (isInboxTarget(target)) {
    return allowed(target, "runfree-inbox", "Runfree inbox mount target");
  }
  if (dependencyStoreTargets().includes(target)) {
    return allowed(target, "dependency-store", "package-manager store target");
  }

  for (const root of policy.physicalWorkspaceRoots) {
    if (!insideOrEqual(target, root)) continue;
    const relativePath = target === root ? "." : target.slice(root.length + 1);
    if ((Object.values(WORKSPACE_METADATA_NAMES) as string[]).includes(relativePath)) {
      return allowed(target, "workspace-metadata", "workspace metadata mask target");
    }
    if (dependencyArtifactKindForRelativePath(relativePath) !== undefined) {
      return allowed(target, "dependency-artifact", "workspace dependency artifact target");
    }
  }

  if (isGitLayoutTarget(target) && dependencyArtifactKindForPathSuffix(target) !== undefined) {
    return denied(`dependency artifact target is outside rendered project roots: ${target}`);
  }

  if ((target === "/runfree" || target.startsWith("/runfree/")) && !isGitLayoutTarget(target)) {
    return reserved("runfree-namespace", "/runfree is reserved for Runfree-owned container paths");
  }

  return denied(`runtime compose mount target is not allowed: ${target}`);
}
