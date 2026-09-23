import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";

import { builtinAgent } from "../agents.ts";
import { resolveAgentCommand, resolveAgentResumeCommand } from "../config.ts";
import { readActiveEffectiveControl } from "../control/effective.ts";
import { projectHash } from "../project-identity.ts";
import { runfreeStateRoot } from "../paths.ts";
import { sanitizeForTerminal } from "../../../../scripts/domain-diagnostics.ts";
import { formatTerminalTable } from "../terminal-table.ts";
import { AGENT_UID_GID } from "./constants.ts";
import { dockerClientEnvOptions } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import { compareHostBootId, compareHostProcessStart, hostBootId, hostProcessStart } from "./host-identity.ts";
import { peekSessionContainerRecordsV2, type SessionContainerRecordV2 } from "./session-containers.ts";
import { readSessionHostStatus } from "./session-host-status.ts";
import { classifySessionRecordLiveness } from "./session-record-liveness.ts";
import {
  processAlive,
  projectLifecycleLockPath,
  type ProjectLifecycleLock,
  tryAcquireProjectLifecycleLockWithRetry,
} from "./sessions.ts";
import type { ActiveAgentSession, RuntimeContext, RuntimeIO, SessionMetadata } from "./types.ts";
import { isRecord } from "../strict-primitives.ts";

const PROJECT_ID_RE = /^[0-9a-f]{12}$/;
const SESSION_ID_RE = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/;
const RECOVERY_ID_RE = /^rfr-[0-9a-f]{24}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLAUDE_REGISTRY_FILE_RE = /^[0-9]+\.json$/;
const HOST_SESSION_FILE_RE = /^rf-[0-9]{8}-[a-z0-9]{6,32}\.json$/;

export const RECOVERY_LIMITS = {
  maxProjects: 1_024,
  maxFilesPerKindPerProject: 2_048,
  maxFilesGlobal: 10_000,
  maxBytesPerKindPerProject: 16 * 1024 * 1024,
  maxFileBytes: 64 * 1024,
} as const;

export type RecoveryState = "active" | "interrupted" | "unverified" | "claimed" | "unrecoverable";
export type RecoveryEvidenceKind = "host" | "claude";

export type EvidenceFingerprint = {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
  schemaId: string;
  sha256: string;
};

export type RecoveryItem = {
  id: string;
  projectId: string;
  projectRoot?: string;
  projectName: string;
  stateDir: string;
  state: RecoveryState;
  evidenceKind: RecoveryEvidenceKind;
  evidencePath: string;
  fingerprint: EvidenceFingerprint;
  sourceId: string;
  agent: string;
  command?: string;
  conversationId?: string;
  conversationName?: string;
  conversationStatus?: string;
  startedAt?: string;
  updatedAt?: string;
  terminalHint?: string;
  reason?: string;
  resumeBlockedReason?: string;
  hostMetadata?: SessionMetadata;
  claudeRegistry?: ClaudeRegistryEvidence;
};

export type RecoveryInventory = {
  items: RecoveryItem[];
  truncated: boolean;
  invalidFiles: number;
};

export type ResumeLaunchPlan = {
  argv: string[];
  env: Record<string, string>;
  precision: "exact" | "picker";
  label: string;
  shellCommand?: string;
};

type ClaudeRegistryEvidence = {
  pid: number;
  sessionId: string;
  cwd: string;
  startedAt: number;
  procStart: string;
  name?: string;
  status?: string;
  updatedAt: number;
};

type SecureRead = {
  value: unknown;
  stat: fs.Stats;
  sha256: string;
};

type ProjectMapping = {
  projectRoot?: string;
  projectName: string;
  valid: boolean;
  reason?: string;
};

type ScanBudget = {
  files: number;
  bytes: number;
};

type GlobalScanBudget = {
  files: number;
  truncated: boolean;
  invalidFiles: number;
};

type ScannedHostEvidence = {
  metadata: SessionMetadata;
  path: string;
  stat: fs.Stats;
  sha256: string;
};

type ScannedClaudeEvidence = {
  registry: ClaudeRegistryEvidence;
  path: string;
  stat: fs.Stats;
  sha256: string;
};

export type SessionContainerRecoveryInputs = {
  records: readonly SessionContainerRecordV2[];
  /**
   * True when the registry view is partial. Classification must degrade to
   * `unverified` for session-world evidence rather than read a partial
   * registry as "no live session".
   */
  unreadable: boolean;
};

export type RecoveryLiveInputs = {
  activeSessions: ActiveAgentSession[];
  agentContainerId?: string;
  /**
   * Per-session lifecycle registry view for sessions launched as per-session
   * containers through the admission path. Their liveness is decided from the
   * host-owned lifecycle record — exact session id, container binding, owner
   * identity, lease — never by probing or trusting an old container.
   */
  sessionContainers?: SessionContainerRecoveryInputs;
};

/**
 * Builds the read-only per-session registry inputs for live classification.
 * Uses the non-mutating peek: recovery listing and classification are
 * contractually side-effect-free, so unreadable records are reported as an
 * unprovable view here and quarantined only by admission itself.
 */
export function sessionContainerRecoveryLiveInputs(context: RuntimeContext): SessionContainerRecoveryInputs {
  try {
    const peek = peekSessionContainerRecordsV2(context.project.paths.stateDir, {
      projectId: projectHash(context.projectRoot),
      composeProject: composeProjectName(context.projectRoot),
    });
    return { records: peek.records, unreadable: peek.unreadable > 0 };
  } catch {
    return { records: [], unreadable: true };
  }
}


function isoString(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function boundedString(value: unknown, max = 4_096): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function safeReadJson(filePath: string, knownStat?: fs.Stats): SecureRead | undefined {
  let before: fs.Stats;
  try {
    before = knownStat ?? fs.lstatSync(filePath);
  } catch {
    return undefined;
  }
  if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > RECOVERY_LIMITS.maxFileBytes) {
    return undefined;
  }
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (
      !opened.isFile()
      || opened.nlink !== 1
      || opened.dev !== before.dev
      || opened.ino !== before.ino
      || opened.size !== before.size
    ) return undefined;
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < buffer.length) {
      const read = fs.readSync(fd, buffer, offset, buffer.length - offset, null);
      if (read === 0) return undefined;
      offset += read;
    }
    const after = fs.fstatSync(fd);
    if (
      !after.isFile()
      || after.nlink !== 1
      || after.dev !== opened.dev
      || after.ino !== opened.ino
      || after.size !== opened.size
      || after.mtimeMs !== opened.mtimeMs
    ) return undefined;
    return {
      value: JSON.parse(buffer.toString("utf8")),
      stat: after,
      sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
    };
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseHostEvidence(value: unknown, fileSessionId: string): SessionMetadata | undefined {
  if (!isRecord(value) || value.id !== fileSessionId || !SESSION_ID_RE.test(fileSessionId)) return undefined;
  if (!boundedString(value.projectRoot) || !boundedString(value.composeProject) || !boundedString(value.command)) {
    return undefined;
  }
  if (!Number.isInteger(value.hostPid) || (value.hostPid as number) <= 0) return undefined;
  if (!isoString(value.startedAt) || !isoString(value.lastSeenAt)) return undefined;
  if (value.endedAt !== undefined && !isoString(value.endedAt)) return undefined;
  if (value.exitStatus !== undefined && !Number.isInteger(value.exitStatus)) return undefined;
  if (value.outcome !== undefined && value.outcome !== "interrupted") return undefined;
  const optionalStrings = [
    "agentCommand",
    "hostBootId",
    "hostProcessStart",
    "sessionContainerName",
    "resumeConversationId",
    "hostTty",
    "termProgram",
    "termProgramVersion",
    "termSessionId",
    "itermSessionId",
    "wtSession",
    "hostInbox",
    "containerInbox",
  ];
  for (const key of optionalStrings) {
    if (value[key] !== undefined && typeof value[key] !== "string") return undefined;
  }
  return value as unknown as SessionMetadata;
}

function parseClaudeRegistry(value: unknown): ClaudeRegistryEvidence | undefined {
  if (!isRecord(value)) return undefined;
  if (!Number.isInteger(value.pid) || (value.pid as number) <= 0) return undefined;
  if (typeof value.sessionId !== "string" || !UUID_RE.test(value.sessionId)) return undefined;
  if (!boundedString(value.cwd) || typeof value.procStart !== "string" || !/^[0-9]+$/.test(value.procStart)) {
    return undefined;
  }
  if (!Number.isInteger(value.startedAt) || (value.startedAt as number) <= 0) return undefined;
  if (!Number.isInteger(value.updatedAt) || (value.updatedAt as number) <= 0) return undefined;
  if (value.name !== undefined && typeof value.name !== "string") return undefined;
  if (value.status !== undefined && typeof value.status !== "string") return undefined;
  return {
    pid: value.pid as number,
    sessionId: value.sessionId.toLowerCase(),
    cwd: value.cwd,
    startedAt: value.startedAt as number,
    procStart: value.procStart,
    ...(typeof value.name === "string" ? { name: value.name } : {}),
    ...(typeof value.status === "string" ? { status: value.status } : {}),
    updatedAt: value.updatedAt as number,
  };
}

function fingerprint(stat: fs.Stats, schemaId: string, sha256: string): EvidenceFingerprint {
  return { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs, schemaId, sha256 };
}

function recoveryId(projectId: string, kind: RecoveryEvidenceKind, sourceId: string): string {
  const digest = crypto.createHash("sha256").update(`${projectId}\0${kind}\0${sourceId}`).digest("hex");
  return `rfr-${digest.slice(0, 24)}`;
}

type DirectoryIdentity = { dev: number; ino: number };

function verifiedDirectoryIdentity(anchor: string, directoryPath: string): DirectoryIdentity | undefined {
  const root = path.resolve(anchor);
  const target = path.resolve(directoryPath);
  const relative = path.relative(root, target);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return undefined;
  let current = root;
  for (const component of ["", ...relative.split(path.sep).filter(Boolean)]) {
    if (component) current = path.join(current, component);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) return undefined;
      if (current === target) return { dev: stat.dev, ino: stat.ino };
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function directoryIdentityMatches(directoryPath: string, expected: DirectoryIdentity): boolean {
  try {
    const stat = fs.lstatSync(directoryPath);
    return !stat.isSymbolicLink()
      && stat.isDirectory()
      && stat.dev === expected.dev
      && stat.ino === expected.ino;
  } catch {
    return false;
  }
}

function entryResolvesInsideDirectory(
  directoryPath: string,
  filePath: string,
  expectedDirectory: DirectoryIdentity,
  expectedFile?: fs.Stats,
): boolean {
  if (!directoryIdentityMatches(directoryPath, expectedDirectory)) return false;
  try {
    const realDirectory = fs.realpathSync(directoryPath);
    const realFile = fs.realpathSync(filePath);
    if (path.dirname(realFile) !== realDirectory) return false;
    if (!expectedFile) return true;
    const stat = fs.statSync(realFile);
    return stat.dev === expectedFile.dev && stat.ino === expectedFile.ino;
  } catch {
    return false;
  }
}

function scanFixedDirectory<T>(input: {
  anchor: string;
  dir: string;
  fileName: RegExp;
  budget: ScanBudget;
  global: GlobalScanBudget;
  parse(filePath: string, name: string, read: SecureRead): T | undefined;
}): T[] {
  const results: T[] = [];
  let directory: fs.Dir | undefined;
  const directoryIdentity = verifiedDirectoryIdentity(input.anchor, input.dir);
  if (!directoryIdentity) return results;
  try {
    directory = fs.opendirSync(input.dir);
    if (!directoryIdentityMatches(input.dir, directoryIdentity)) return results;
    while (true) {
      const entry = directory.readSync();
      if (!entry) break;
      if (!input.fileName.test(entry.name)) continue;
      if (
        input.budget.files >= RECOVERY_LIMITS.maxFilesPerKindPerProject
        || input.global.files >= RECOVERY_LIMITS.maxFilesGlobal
      ) {
        input.global.truncated = true;
        break;
      }
      input.budget.files += 1;
      input.global.files += 1;
      if (!directoryIdentityMatches(input.dir, directoryIdentity)) {
        input.global.invalidFiles += 1;
        break;
      }
      const filePath = path.join(input.dir, entry.name);
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(filePath);
      } catch {
        input.global.invalidFiles += 1;
        continue;
      }
      if (input.budget.bytes + stat.size > RECOVERY_LIMITS.maxBytesPerKindPerProject) {
        input.global.truncated = true;
        break;
      }
      input.budget.bytes += Math.max(0, stat.size);
      if (!entryResolvesInsideDirectory(input.dir, filePath, directoryIdentity, stat)) {
        input.global.invalidFiles += 1;
        continue;
      }
      const read = safeReadJson(filePath, stat);
      if (!read || !entryResolvesInsideDirectory(input.dir, filePath, directoryIdentity, read.stat)) {
        input.global.invalidFiles += 1;
        continue;
      }
      const parsed = input.parse(filePath, entry.name, read);
      if (parsed === undefined) input.global.invalidFiles += 1;
      else results.push(parsed);
    }
  } catch {
    return results;
  } finally {
    directory?.closeSync();
  }
  return results;
}

function scanHostEvidence(stateDir: string, global: GlobalScanBudget): ScannedHostEvidence[] {
  return scanFixedDirectory({
    anchor: stateDir,
    dir: path.join(stateDir, "sessions"),
    fileName: HOST_SESSION_FILE_RE,
    budget: { files: 0, bytes: 0 },
    global,
    parse: (filePath, name, read) => {
      const metadata = parseHostEvidence(read.value, name.slice(0, -".json".length));
      return metadata ? { metadata, path: filePath, stat: read.stat, sha256: read.sha256 } : undefined;
    },
  });
}

function scanClaudeEvidence(stateDir: string, global: GlobalScanBudget): ScannedClaudeEvidence[] {
  return scanFixedDirectory({
    anchor: stateDir,
    dir: path.join(stateDir, "claude", "sessions"),
    fileName: CLAUDE_REGISTRY_FILE_RE,
    budget: { files: 0, bytes: 0 },
    global,
    parse: (filePath, _name, read) => {
      const registry = parseClaudeRegistry(read.value);
      return registry ? { registry, path: filePath, stat: read.stat, sha256: read.sha256 } : undefined;
    },
  });
}

function projectMapping(stateDir: string, projectId: string, hostEvidence: ScannedHostEvidence[]): ProjectMapping {
  const pointerPath = path.join(stateDir, "project.json");
  const pointerExists = (() => {
    try {
      fs.lstatSync(pointerPath);
      return true;
    } catch {
      return false;
    }
  })();
  let candidate: string | undefined;
  if (pointerExists) {
    const read = safeReadJson(pointerPath);
    if (!read || !isRecord(read.value) || !boundedString(read.value.projectRoot) || !isoString(read.value.updatedAt)) {
      return { projectName: projectId, valid: false, reason: "invalid project mapping" };
    }
    candidate = read.value.projectRoot;
  } else {
    candidate = [...hostEvidence]
      .sort((left, right) => Date.parse(right.metadata.lastSeenAt) - Date.parse(left.metadata.lastSeenAt))[0]
      ?.metadata.projectRoot;
  }
  if (!candidate) return { projectName: projectId, valid: false, reason: "project mapping unavailable" };
  const projectRoot = path.resolve(candidate);
  if (projectHash(projectRoot) !== projectId) {
    return {
      projectRoot,
      projectName: path.basename(projectRoot) || projectId,
      valid: false,
      reason: `project moved or mapping does not match ${projectId}`,
    };
  }
  try {
    if (!fs.statSync(projectRoot).isDirectory()) throw new Error("not a directory");
  } catch {
    return {
      projectRoot,
      projectName: path.basename(projectRoot) || projectId,
      valid: false,
      reason: `project moved or deleted: ${projectRoot}`,
    };
  }
  return { projectRoot, projectName: path.basename(projectRoot) || projectId, valid: true };
}

function hostOwnerState(metadata: SessionMetadata, env: NodeJS.ProcessEnv): "active" | "dead" | "unknown" {
  if (metadata.outcome === "interrupted") return "dead";
  const boot = compareHostBootId(metadata.hostBootId, env);
  if (boot === "mismatch") return "dead";
  if (!Number.isInteger(metadata.hostPid) || metadata.hostPid <= 0 || !processAlive(metadata.hostPid)) return "dead";
  const processStart = compareHostProcessStart(metadata.hostProcessStart, metadata.hostPid, env);
  if (boot === "match" && processStart === "mismatch") return "dead";
  if (boot === "match" && processStart === "match") return "active";
  return "unknown";
}

function claimPath(item: RecoveryItem): string {
  if (!RECOVERY_ID_RE.test(item.id)) throw new Error(`invalid recovery id: ${item.id}`);
  const agentScope = crypto.createHash("sha256").update(item.agent.toLowerCase()).digest("hex").slice(0, 24);
  return path.join(item.stateDir, "sessions", "recovery-claims", `agent-${agentScope}.json`);
}

function parsedClaimIsLive(value: unknown, env: NodeJS.ProcessEnv): boolean {
  if (!isRecord(value) || !Number.isInteger(value.ownerPid) || (value.ownerPid as number) <= 0) return true;
  const pid = value.ownerPid as number;
  if (compareHostBootId(value.hostBootId, env) === "mismatch") return false;
  if (!processAlive(pid)) return false;
  if (
    compareHostBootId(value.hostBootId, env) === "match"
    && compareHostProcessStart(value.hostProcessStart, pid, env) === "mismatch"
  ) return false;
  // Unknown identity with a live PID fails closed as a live claim. It may need
  // manual cleanup, but it can never admit two resume executions.
  return true;
}

function itemClaimed(item: RecoveryItem, env: NodeJS.ProcessEnv): boolean {
  const read = safeReadJson(claimPath(item));
  return read ? parsedClaimIsLive(read.value, env) : false;
}

function itemFromHost(
  projectId: string,
  stateDir: string,
  mapping: ProjectMapping,
  evidence: ScannedHostEvidence,
  env: NodeJS.ProcessEnv,
): RecoveryItem {
  const metadata = evidence.metadata;
  const item: RecoveryItem = {
    id: recoveryId(projectId, "host", metadata.id),
    projectId,
    ...(mapping.projectRoot ? { projectRoot: mapping.projectRoot } : {}),
    projectName: mapping.projectName,
    stateDir,
    state: mapping.valid && hostOwnerState(metadata, env) === "active" ? "active" : "unverified",
    evidenceKind: "host",
    evidencePath: evidence.path,
    fingerprint: fingerprint(evidence.stat, metadata.id, evidence.sha256),
    sourceId: metadata.id,
    agent: metadata.command,
    command: metadata.agentCommand,
    // Lineage from an admission-path resume launch: the exact conversation the
    // crashed session was resuming. Strict-format validated here and again at
    // argv composition, so a corrupted value degrades to picker precision
    // rather than being trusted.
    ...(metadata.resumeConversationId !== undefined && UUID_RE.test(metadata.resumeConversationId)
      ? { conversationId: metadata.resumeConversationId.toLowerCase() }
      : {}),
    startedAt: metadata.startedAt,
    updatedAt: metadata.endedAt ?? metadata.lastSeenAt,
    terminalHint: metadata.hostTty ?? metadata.termProgram,
    hostMetadata: metadata,
    ...(!mapping.valid ? { state: "unrecoverable", reason: mapping.reason } : {}),
  };
  if (mapping.valid && itemClaimed(item, env)) item.state = "claimed";
  const consumedAt = metadata.command.toLowerCase() === "claude" ? claudeRecoveryEpoch(stateDir) : undefined;
  const evidenceActivity = metadata.endedAt ?? metadata.lastSeenAt;
  if (consumedAt && Date.parse(evidenceActivity) <= Date.parse(consumedAt)) {
    item.resumeBlockedReason = "an exact Claude recovery completed after this host-only evidence was created";
  }
  return item;
}

function itemFromClaude(
  projectId: string,
  stateDir: string,
  mapping: ProjectMapping,
  evidence: ScannedClaudeEvidence,
  env: NodeJS.ProcessEnv,
): RecoveryItem {
  const registry = evidence.registry;
  const item: RecoveryItem = {
    id: recoveryId(projectId, "claude", registry.sessionId),
    projectId,
    ...(mapping.projectRoot ? { projectRoot: mapping.projectRoot } : {}),
    projectName: mapping.projectName,
    stateDir,
    state: mapping.valid ? "unverified" : "unrecoverable",
    evidenceKind: "claude",
    evidencePath: evidence.path,
    fingerprint: fingerprint(evidence.stat, registry.sessionId, evidence.sha256),
    sourceId: registry.sessionId,
    agent: "claude",
    conversationId: registry.sessionId,
    conversationName: registry.name,
    conversationStatus: registry.status,
    startedAt: new Date(registry.startedAt).toISOString(),
    updatedAt: new Date(registry.updatedAt).toISOString(),
    claudeRegistry: registry,
    ...(!mapping.valid ? { reason: mapping.reason } : {}),
  };
  if (mapping.valid && itemClaimed(item, env)) item.state = "claimed";
  return item;
}

export function scanRecoveryInventory(input: {
  env?: NodeJS.ProcessEnv;
  projectRoot?: string;
} = {}): RecoveryInventory {
  const env = input.env ?? process.env;
  const projectsRoot = path.join(runfreeStateRoot(env), "projects");
  const requestedRoot = input.projectRoot ? path.resolve(input.projectRoot) : undefined;
  const requestedProjectId = requestedRoot ? projectHash(requestedRoot) : undefined;
  const global: GlobalScanBudget = { files: 0, truncated: false, invalidFiles: 0 };
  const items: RecoveryItem[] = [];
  let projects: fs.Dir | undefined;
  let inspectedProjects = 0;
  try {
    projects = fs.opendirSync(projectsRoot);
    while (true) {
      const entry = projects.readSync();
      if (!entry) break;
      if (!entry.isDirectory() || !PROJECT_ID_RE.test(entry.name)) continue;
      if (requestedProjectId && entry.name !== requestedProjectId) continue;
      if (inspectedProjects >= RECOVERY_LIMITS.maxProjects) {
        global.truncated = true;
        break;
      }
      inspectedProjects += 1;
      const stateDir = path.join(projectsRoot, entry.name);
      const hostEvidence = scanHostEvidence(stateDir, global);
      const claudeEvidence = scanClaudeEvidence(stateDir, global);
      const mapping = projectMapping(stateDir, entry.name, hostEvidence);
      if (requestedRoot && mapping.projectRoot !== requestedRoot) continue;
      items.push(...hostEvidence.map((evidence) => itemFromHost(entry.name, stateDir, mapping, evidence, env)));
      items.push(...claudeEvidence.map((evidence) => itemFromClaude(entry.name, stateDir, mapping, evidence, env)));
      if (global.files >= RECOVERY_LIMITS.maxFilesGlobal) {
        global.truncated = true;
        break;
      }
    }
  } catch {
    return { items: [], truncated: false, invalidFiles: 0 };
  } finally {
    projects?.closeSync();
  }
  const deduped = Array.from(new Map(
    items
      .filter((item) => !itemWasConsumed(item))
      .sort((left, right) => Date.parse(right.updatedAt ?? right.startedAt ?? "") - Date.parse(left.updatedAt ?? left.startedAt ?? ""))
      .map((item) => [item.id, item]),
  ).values());
  return { items: deduped, truncated: global.truncated, invalidFiles: global.invalidFiles };
}

function publicRecoveryItem(item: RecoveryItem): object {
  return {
    id: item.id,
    project: item.projectRoot,
    projectName: sanitizeForTerminal(item.projectName).slice(0, 120),
    agent: sanitizeForTerminal(item.agent).slice(0, 80),
    state: item.state,
    evidence: item.evidenceKind,
    conversationId: item.conversationId,
    conversationName: item.conversationName === undefined
      ? undefined
      : sanitizeForTerminal(item.conversationName).slice(0, 160),
    status: item.conversationStatus === undefined
      ? undefined
      : sanitizeForTerminal(item.conversationStatus).slice(0, 40),
    updatedAt: item.updatedAt,
    terminal: item.terminalHint === undefined
      ? undefined
      : sanitizeForTerminal(item.terminalHint).slice(0, 120),
    reason: item.reason === undefined ? undefined : sanitizeForTerminal(item.reason).slice(0, 240),
  };
}

export function recoveryInventoryJson(inventory: RecoveryInventory): string {
  return `${JSON.stringify({
    items: inventory.items.map(publicRecoveryItem),
    truncated: inventory.truncated,
    invalidFiles: inventory.invalidFiles,
  }, null, 2)}\n`;
}

function displayTime(value: string | undefined): string {
  if (!value || !Number.isFinite(Date.parse(value))) return "-";
  return new Date(value).toISOString().replace("T", " ").slice(0, 16);
}

export function formatRecoveryInventory(inventory: RecoveryInventory): string {
  if (inventory.items.length === 0) return "no interrupted or unverified Runfree sessions";
  const table = formatTerminalTable({
    columns: [
      { label: "ID" },
      { label: "PROJECT" },
      { label: "AGENT" },
      { label: "STATE" },
      { label: "CONVERSATION" },
      { label: "LAST ACTIVITY" },
      { label: "TERMINAL" },
    ],
    rows: inventory.items.map((item) => [
      item.id,
      sanitizeForTerminal(item.projectName).slice(0, 40),
      sanitizeForTerminal(item.agent).slice(0, 24),
      item.state,
      sanitizeForTerminal(item.conversationName ?? item.conversationId ?? "-").slice(0, 60),
      displayTime(item.updatedAt ?? item.startedAt),
      sanitizeForTerminal(item.terminalHint ?? "-").slice(0, 40),
    ]),
  });
  return inventory.truncated ? `${table}\nwarning: recovery inventory was truncated at its safety limit` : table;
}

function evidenceDirectory(item: RecoveryItem): string | undefined {
  const expected = item.evidenceKind === "host"
    ? path.join(item.stateDir, "sessions")
    : path.join(item.stateDir, "claude", "sessions");
  if (path.dirname(item.evidencePath) !== expected) return undefined;
  const name = path.basename(item.evidencePath);
  if (item.evidenceKind === "host" ? !HOST_SESSION_FILE_RE.test(name) : !CLAUDE_REGISTRY_FILE_RE.test(name)) {
    return undefined;
  }
  return expected;
}

function safeReadEvidence(item: RecoveryItem): SecureRead | undefined {
  const directoryPath = evidenceDirectory(item);
  if (!directoryPath) return undefined;
  const identity = verifiedDirectoryIdentity(item.stateDir, directoryPath);
  if (!identity || !entryResolvesInsideDirectory(directoryPath, item.evidencePath, identity)) return undefined;
  const read = safeReadJson(item.evidencePath);
  return read && entryResolvesInsideDirectory(directoryPath, item.evidencePath, identity, read.stat) ? read : undefined;
}

function rereadEvidence(item: RecoveryItem): RecoveryItem | undefined {
  const read = safeReadEvidence(item);
  if (!read) return undefined;
  if (item.evidenceKind === "host") {
    const metadata = parseHostEvidence(read.value, item.sourceId);
    if (!metadata) return undefined;
    return {
      ...item,
      fingerprint: fingerprint(read.stat, metadata.id, read.sha256),
      hostMetadata: metadata,
      startedAt: metadata.startedAt,
      updatedAt: metadata.endedAt ?? metadata.lastSeenAt,
    };
  }
  const registry = parseClaudeRegistry(read.value);
  if (!registry || registry.sessionId !== item.sourceId) return undefined;
  return {
    ...item,
    fingerprint: fingerprint(read.stat, registry.sessionId, read.sha256),
    claudeRegistry: registry,
    updatedAt: new Date(registry.updatedAt).toISOString(),
  };
}

function sameFingerprint(left: EvidenceFingerprint, right: EvidenceFingerprint): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.schemaId === right.schemaId
    && left.sha256 === right.sha256;
}

export function evidenceMatches(item: RecoveryItem): boolean {
  const current = rereadEvidence(item);
  return current !== undefined && sameFingerprint(current.fingerprint, item.fingerprint);
}

// Container probes run against untrusted containers, which fully control what
// the exec returns and how long it takes. A container that replaces its own
// binaries must not be able to hang `runfree sessions` or a resume selection
// indefinitely, so every probe is time- and size-bounded; a timeout surfaces
// as a failed capture, which classifies as `unverified` — never as proof.
const CONTAINER_PROBE_TIMEOUT_MS = 10_000;
const CONTAINER_PROBE_MAX_BUFFER = 1024 * 1024;

// The per-capture bound alone still multiplies: one classification pass probes
// up to every claude item against every recorded claude container, so several
// stalling containers could cost items × containers × 10s. Each pass — one
// `RecoveryLiveInputs` value — therefore also carries an aggregate budget of
// probe captures and wall-clock time, and deduplicates the item-independent
// container inspections. An exhausted budget answers `unverified`, never a
// guess, so a stalled daemon degrades listing precision rather than blocking
// the terminal for hours.
const CONTAINER_PROBE_PASS_MAX_CAPTURES = 32;
const CONTAINER_PROBE_PASS_DEADLINE_MS = 60_000;

type ContainerProbePassState = {
  captures: number;
  startedAtMs?: number;
  inspects: Map<string, ReturnType<RuntimeIO["capture"]>>;
};

const probePassStates = new WeakMap<RecoveryLiveInputs, ContainerProbePassState>();

function containerProbePassState(live: RecoveryLiveInputs): ContainerProbePassState {
  const existing = probePassStates.get(live);
  if (existing) return existing;
  const created: ContainerProbePassState = { captures: 0, inspects: new Map() };
  probePassStates.set(live, created);
  return created;
}

function containerProbeAllowed(state: ContainerProbePassState): boolean {
  if (state.captures >= CONTAINER_PROBE_PASS_MAX_CAPTURES) return false;
  if (state.startedAtMs !== undefined && Date.now() - state.startedAtMs > CONTAINER_PROBE_PASS_DEADLINE_MS) {
    return false;
  }
  return true;
}

function countContainerProbe(state: ContainerProbePassState): void {
  state.startedAtMs ??= Date.now();
  state.captures += 1;
}

function containerProbeOptions(context: RuntimeContext) {
  return {
    ...dockerClientEnvOptions(context),
    timeout: CONTAINER_PROBE_TIMEOUT_MS,
    maxBuffer: CONTAINER_PROBE_MAX_BUFFER,
  };
}

// Docker's answer when the inspected object does not exist ("Error: No such
// object" / "Error response from daemon: No such container"). Matched so a
// container a crash already removed reads as decisively gone: a stale record
// can survive its container (removal precedes record deletion), and treating
// that ordinary residue as indecisive pinned every Claude item in the project
// at `unverified` — refusing resume before the driver preflight that would
// have reclaimed the record could ever run. Anything that does not match
// stays `unverified`, so daemon failures and timeouts still prove nothing.
const CONTAINER_ABSENT_PATTERN = /no such (object|container)/i;

function probeClaudeRegistryInContainer(
  registry: ClaudeRegistryEvidence,
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string,
  pass: ContainerProbePassState,
): "active" | "gone" | "unverified" {
  // The running/StartedAt inspection is item-independent, so one pass asks
  // Docker once per container however many items name it.
  let inspect = pass.inspects.get(containerId);
  if (!inspect) {
    if (!containerProbeAllowed(pass)) return "unverified";
    countContainerProbe(pass);
    inspect = io.capture(
      "docker",
      ["inspect", "--format", "{{.State.Running}}\t{{.State.StartedAt}}", containerId],
      containerProbeOptions(context),
    );
    pass.inspects.set(containerId, inspect);
  }
  if (inspect.status !== 0) {
    return CONTAINER_ABSENT_PATTERN.test(inspect.stderr) ? "gone" : "unverified";
  }
  const [running, startedAtRaw] = inspect.stdout.trim().split("\t");
  if (running !== "true") return "gone";
  const containerStartedAt = Date.parse(startedAtRaw ?? "");
  if (!Number.isFinite(containerStartedAt)) return "unverified";
  if (containerStartedAt > registry.updatedAt) return "gone";
  if (!containerProbeAllowed(pass)) return "unverified";
  countContainerProbe(pass);
  const probe = io.capture(
    "docker",
    [
      "exec",
      "-i",
      "--user",
      AGENT_UID_GID,
      containerId,
      "node",
      "-e",
      [
        "const fs=require('node:fs');",
        "const pid=process.argv[1];",
        "try{",
        "const s=fs.readFileSync('/proc/'+pid+'/stat','utf8');",
        "const i=s.lastIndexOf(')');",
        "if(i<0)process.exit(3);",
        "const f=s.slice(i+1).trim().split(/\\s+/);",
        "if(!f[19])process.exit(3);",
        "process.stdout.write(f[19]);",
        "}catch(e){if(e&&e.code==='ENOENT')process.exit(2);process.exit(3);}",
      ].join(""),
      String(registry.pid),
    ],
    containerProbeOptions(context),
  );
  if (probe.status === 2) return "gone";
  if (probe.status !== 0 || !/^[0-9]+$/.test(probe.stdout.trim())) return "unverified";
  return probe.stdout.trim() === registry.procStart ? "active" : "gone";
}

function claudeSessionContainerIds(inputs: SessionContainerRecoveryInputs | undefined): string[] {
  return (inputs?.records ?? [])
    .filter((record) => record.containerId !== undefined
      && path.posix.basename(record.launchPath) === "claude")
    .map((record) => record.containerId as string);
}

/**
 * Classifies agent-registry evidence against every container that could host
 * the recorded conversation process: the legacy shared agent when it runs,
 * plus every record-bound per-session claude container. Any container proving
 * the exact pid/starttime live makes the item active; an indecisive probe or a
 * partial registry view leaves it unverified; only a decisive miss everywhere
 * is interrupted.
 *
 * Accepted fail directions, stated so they stay deliberate: the probe execs
 * inside untrusted containers, so a compromised claude session container can
 * answer "active" for any pid and pin every claude item in the project to
 * active/unverified — a recovery denial against its own project's UX, in the
 * refusing direction. Lying "gone" enables at worst a double-resume beside its
 * own claude process, which has no more authority than the probe target — the
 * same direction the pre-existing shared-agent probe already accepts. Probe
 * output never feeds admission or activation authority.
 */
function probeClaudeRegistry(
  item: RecoveryItem,
  context: RuntimeContext,
  io: RuntimeIO,
  live: RecoveryLiveInputs,
): RecoveryState {
  const registry = item.claudeRegistry;
  if (!registry) return "unverified";
  const candidates = [
    ...(live.agentContainerId ? [live.agentContainerId] : []),
    ...claudeSessionContainerIds(live.sessionContainers),
  ];
  const pass = containerProbePassState(live);
  let indecisive = live.sessionContainers?.unreadable === true;
  for (const containerId of candidates) {
    const result = probeClaudeRegistryInContainer(registry, context, io, containerId, pass);
    if (result === "active") return "active";
    if (result === "unverified") indecisive = true;
  }
  return indecisive ? "unverified" : "interrupted";
}

function probeHostContainerSession(
  item: RecoveryItem,
  context: RuntimeContext,
  io: RuntimeIO,
  containerId: string | undefined,
  pass: ContainerProbePassState,
): "active" | "dead" | "unknown" {
  if (!containerId) return "dead";
  const inspectorPath = path.join(context.runtimeRoot, "agent", "inspect-active-sessions.sh");
  let inspector: string;
  try {
    inspector = fs.readFileSync(inspectorPath, "utf8");
  } catch {
    return "unknown";
  }
  if (!containerProbeAllowed(pass)) return "unknown";
  countContainerProbe(pass);
  const probe = io.capture(
    "docker",
    ["exec", "-i", "--user", AGENT_UID_GID, containerId, "sh", "-s"],
    { ...containerProbeOptions(context), input: inspector },
  );
  if (probe.status !== 0) return "unknown";
  for (const line of probe.stdout.trim().split(/\n+/).filter(Boolean)) {
    const columns = line.split("\t");
    if (columns.length >= 4 && columns[2] === item.sourceId) return "active";
  }
  return "dead";
}

export function classifyRecoveryItemLive(
  item: RecoveryItem,
  context: RuntimeContext,
  io: RuntimeIO,
  live: RecoveryLiveInputs,
  options: { ignoreClaim?: boolean } = {},
): RecoveryItem {
  const current = rereadEvidence(item);
  if (!current) return { ...item, state: "unverified", reason: "recovery evidence changed or became unreadable" };
  if (item.state === "unrecoverable" || !item.projectRoot) return current;
  if (!options.ignoreClaim && itemClaimed(current, context.env ?? process.env)) return { ...current, state: "claimed" };
  if (current.evidenceKind === "host") {
    const owner = current.hostMetadata
      ? hostOwnerState(current.hostMetadata, context.env ?? process.env)
      : "unknown";
    if (owner === "active") return { ...current, state: "active" };
    if (owner === "unknown") {
      return { ...current, state: "unverified", reason: "host process identity could not be proved" };
    }
    if (current.resumeBlockedReason) {
      return { ...current, state: "unverified", reason: current.resumeBlockedReason };
    }
    const sessionWorld = classifyHostEvidenceAgainstSessionRegistry(current, context, live.sessionContainers);
    if (sessionWorld) return { ...current, ...sessionWorld };
    if (live.activeSessions.some((session) => session.sessionId === current.sourceId)) {
      return { ...current, state: "active" };
    }
    const containerSession = probeHostContainerSession(current, context, io, live.agentContainerId, containerProbePassState(live));
    if (containerSession === "active") return { ...current, state: "active" };
    if (containerSession === "unknown") {
      return { ...current, state: "unverified", reason: "could not verify the exact container session id" };
    }
    return {
      ...current,
      state: "interrupted",
    };
  }
  return { ...current, state: probeClaudeRegistry(current, context, io, live) };
}

/**
 * Decides a host-evidence item from the per-session lifecycle registry when it
 * belongs to the session-container world. The record is host-owned and exact,
 * so nothing here execs into a container: a live record is an active session,
 * a stale or revoked-and-gone record is an interrupted one, and a partial
 * registry view proves nothing. Legacy shared-agent evidence returns
 * `undefined` and falls through to the shared-agent probes.
 */
function classifyHostEvidenceAgainstSessionRegistry(
  item: RecoveryItem,
  context: RuntimeContext,
  inputs: SessionContainerRecoveryInputs | undefined,
): { state: RecoveryState; reason?: string } | undefined {
  if (!inputs) return undefined;
  const match = inputs.records.find((record) => record.sessionId === item.sourceId);
  if (match) {
    const liveness = classifySessionRecordLiveness(match, {
      nowEpochMs: Date.now(),
      env: context.env,
      stamp: readSessionHostStatus(context.project.paths.stateDir, match.sessionId),
    });
    if (match.state === "revoking") {
      // A revoking record is terminal teardown, not a session: the conversation
      // already ended. While its owner still runs, the owner is about to
      // finalize this same evidence, so acting on it would race that client.
      return liveness.kind === "live"
        ? { state: "unverified", reason: "session container teardown is in progress" }
        : { state: "interrupted" };
    }
    return liveness.kind === "live" ? { state: "active" } : { state: "interrupted" };
  }
  if (item.hostMetadata?.sessionContainerName !== undefined) {
    // Accepted gap: an *absent* records root reads as an empty registry here,
    // deliberately — it is the normal state after `runfree destroy`, and
    // treating it as unprovable would leave every surviving evidence item
    // unresumable exactly when resume is the recovery story. The scenario this
    // gives up requires host-side state-dir damage (the records root deleted
    // while a session container survives), which no agent can cause: the root
    // is never mounted into a container. Admission resume is protected anyway
    // by driver preflight orphan cleanup; the residual exposure is the legacy
    // picker guard.
    return inputs.unreadable
      ? { state: "unverified", reason: "per-session lifecycle registry could not be fully read" }
      : { state: "interrupted" };
  }
  return undefined;
}

/**
 * Whether an imprecise (picker) Claude resume must be refused because another
 * Claude session may be live in this project. The picker would offer every
 * conversation, including one an active session owns, so the check fails
 * closed: an unreadable per-session registry blocks the picker the same way a
 * proven live session does.
 *
 * A *stale* claude record blocks by default too. A dead host owner is not
 * proof the container died with it — the ordinary attached-crash residue is a
 * stale record whose container still runs its claude process, invisible to
 * the shared-agent `activeSessions` probe. Only a caller whose launch
 * provably reclaims that residue before the picker's claude starts (the
 * admission driver's preflight, under the same lifecycle lock) may pass
 * `staleRecordsReclaimedBeforeLaunch` and ignore it; the legacy shared-agent
 * path cannot reclaim anything and must stay blocked until reclamation runs.
 */
export function liveClaudeSessionBlocksPicker(
  context: RuntimeContext,
  live: RecoveryLiveInputs,
  options: Readonly<{ staleRecordsReclaimedBeforeLaunch?: boolean }> = {},
): boolean {
  if (live.activeSessions.some((session) => session.command.toLowerCase().includes("claude"))) return true;
  const inputs = live.sessionContainers;
  if (!inputs) return false;
  if (inputs.unreadable) return true;
  return inputs.records.some((record) => {
    if (record.state === "revoking") return false;
    if (path.posix.basename(record.launchPath) !== "claude") return false;
    if (classifySessionRecordLiveness(record, {
      nowEpochMs: Date.now(),
      env: context.env,
      stamp: readSessionHostStatus(context.project.paths.stateDir, record.sessionId),
    }).kind === "live") {
      return true;
    }
    return options.staleRecordsReclaimedBeforeLaunch !== true;
  });
}

export function buildResumeLaunchPlan(context: RuntimeContext, item: RecoveryItem): ResumeLaunchPlan | undefined {
  const descriptor = builtinAgent(item.agent);
  if (!descriptor?.resume) return undefined;
  const configuredCommand = resolveAgentCommand(context.project.config, item.agent);
  if (!configuredCommand) return undefined;
  const customResumeCommand = resolveAgentResumeCommand(context.project.config, item.agent);
  const managedCommand = configuredCommand === descriptor.defaultCommand
    || descriptor.legacyDefaultCommands?.includes(configuredCommand) === true;
  if (!managedCommand) {
    if (!customResumeCommand) return undefined;
    return {
      argv: ["zsh", "-c", "exec zsh -c \"$RUNFREE_RESUME_COMMAND\""],
      env: {
        RUNFREE_RESUME_COMMAND: customResumeCommand,
        ...(item.conversationId ? { RUNFREE_RESUME_SESSION: item.conversationId } : {}),
      },
      precision: item.conversationId ? "exact" : "picker",
      label: `${descriptor.label} custom resume command`,
      shellCommand: customResumeCommand,
    };
  }
  if (item.conversationId && descriptor.resume.exactArgvPrefix) {
    if (!UUID_RE.test(item.conversationId)) return undefined;
    return {
      argv: [...descriptor.resume.exactArgvPrefix, item.conversationId],
      env: {},
      precision: "exact",
      label: `${descriptor.label} conversation ${item.conversationId}`,
    };
  }
  if (!descriptor.resume.pickerArgv) return undefined;
  return {
    argv: [...descriptor.resume.pickerArgv],
    env: {},
    precision: "picker",
    label: `${descriptor.label} resume picker`,
  };
}

function atomicWriteJson(filePath: string, value: unknown, mode = 0o600): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, { mode, flag: "wx" });
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    fs.rmSync(tmpPath, { force: true });
    throw error;
  }
}

export function writeProjectRecoveryPointer(context: RuntimeContext, now = new Date()): void {
  const effective = readActiveEffectiveControl(context.project);
  if (!effective) throw new Error("selected effective controls are required before recovery state publication");
  validateNetworkPolicy(effective.policy, effective.networkPolicyPath);
  atomicWriteJson(path.join(context.project.paths.stateDir, "project.json"), {
    projectRoot: context.projectRoot,
    updatedAt: now.toISOString(),
  });
}

type RecoveryClaimRecord = {
  v: 1;
  recoveryId: string;
  action: "resume";
  ownerPid: number;
  hostBootId?: string;
  hostProcessStart?: string;
  createdAt: string;
  evidence: EvidenceFingerprint;
};

export type RecoveryClaim = {
  path: string;
  release(): void;
};

export class RecoveryClaimLifecycleLockTimeoutError extends Error {
  constructor(context: RuntimeContext) {
    super(`recovery claim deferred because a runtime lifecycle change is in progress (lock: ${projectLifecycleLockPath(context)})`);
    this.name = "RecoveryClaimLifecycleLockTimeoutError";
  }
}

type RecoveryClaimOwnerIdentity = Readonly<{
  bootId?: string;
  processStart?: string;
}>;

type RecoveryConsumedRecord = {
  v: 1;
  recoveryId: string;
  evidence: EvidenceFingerprint;
  consumedAt: string;
};

type AgentRecoveryEpoch = {
  v: 1;
  agent: "claude";
  consumedAt: string;
};

function consumedPath(item: RecoveryItem): string {
  if (!RECOVERY_ID_RE.test(item.id)) throw new Error(`invalid recovery id: ${item.id}`);
  return path.join(item.stateDir, "sessions", "recovery-consumed", `${item.id}.json`);
}

function claudeRecoveryEpochPath(stateDir: string): string {
  return path.join(stateDir, "sessions", "recovery-consumed", "agent-claude.json");
}

function claudeRecoveryEpoch(stateDir: string): string | undefined {
  const read = safeReadJson(claudeRecoveryEpochPath(stateDir));
  if (
    !read
    || !isRecord(read.value)
    || read.value.v !== 1
    || read.value.agent !== "claude"
    || !isoString(read.value.consumedAt)
  ) return undefined;
  return read.value.consumedAt;
}

function parseFingerprint(value: unknown): EvidenceFingerprint | undefined {
  if (!isRecord(value)) return undefined;
  if (
    !Number.isInteger(value.dev)
    || !Number.isInteger(value.ino)
    || !Number.isInteger(value.size)
    || typeof value.mtimeMs !== "number"
    || !Number.isFinite(value.mtimeMs)
    || typeof value.schemaId !== "string"
    || typeof value.sha256 !== "string"
    || !/^[0-9a-f]{64}$/.test(value.sha256)
  ) return undefined;
  return value as EvidenceFingerprint;
}

function itemWasConsumed(item: RecoveryItem): boolean {
  if (item.evidenceKind !== "claude") return false;
  const read = safeReadJson(consumedPath(item));
  if (
    !read
    || !isRecord(read.value)
    || read.value.v !== 1
    || read.value.recoveryId !== item.id
    || !isoString(read.value.consumedAt)
  ) return false;
  const recorded = parseFingerprint(read.value.evidence);
  return recorded !== undefined && sameFingerprint(recorded, item.fingerprint);
}

function unlinkIfFingerprintMatches(filePath: string, expected: EvidenceFingerprint): boolean {
  const read = safeReadJson(filePath);
  if (!read) return false;
  const actual = fingerprint(read.stat, expected.schemaId, read.sha256);
  if (!sameFingerprint(actual, expected)) return false;
  fs.unlinkSync(filePath);
  return true;
}

export async function acquireRecoveryClaim(
  context: RuntimeContext,
  item: RecoveryItem,
  now = new Date(),
): Promise<RecoveryClaim | undefined> {
  if (!RECOVERY_ID_RE.test(item.id) || !evidenceMatches(item) || itemWasConsumed(item)) return undefined;
  // Probed before taking the lifecycle lock: both are process-local identity
  // reads (`hostProcessStart` shells out to `ps` on macOS), and keeping them
  // inside the hold stretched a milliseconds-scale critical section into tens
  // of milliseconds — wide enough to consume much of a concurrent selector's
  // bounded lock-acquisition window.
  const owner = recoveryClaimOwnerIdentity(context);
  const lifecycle = await tryAcquireProjectLifecycleLockWithRetry(context);
  if (!lifecycle) {
    // A changed or consumed item remains the ordinary undefined result. If the
    // same evidence still exists, name the real blocker instead of claiming a
    // different selector won the claim.
    if (!evidenceMatches(item) || itemWasConsumed(item)) return undefined;
    throw new RecoveryClaimLifecycleLockTimeoutError(context);
  }
  try {
    return createRecoveryClaimUnderLifecycle(context, item, now, owner, lifecycle);
  } finally {
    lifecycle.release();
  }
}

function recoveryClaimOwnerIdentity(context: RuntimeContext): RecoveryClaimOwnerIdentity {
  const bootId = hostBootId(context.env);
  const processStart = hostProcessStart(process.pid, context.env);
  return Object.freeze({
    ...(bootId ? { bootId } : {}),
    ...(processStart ? { processStart } : {}),
  });
}

function createRecoveryClaimUnderLifecycle(
  context: RuntimeContext,
  item: RecoveryItem,
  now: Date,
  owner: RecoveryClaimOwnerIdentity,
  lifecycle: ProjectLifecycleLock,
): RecoveryClaim | undefined {
  lifecycle.assertHeld();
  // Recheck after acquisition because a bounded retry can wait while the
  // agent-owned evidence changes or disappears.
  if (!RECOVERY_ID_RE.test(item.id) || !evidenceMatches(item) || itemWasConsumed(item)) return undefined;
  const filePath = claimPath(item);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const existing = safeReadJson(filePath);
  if (existing) {
    if (parsedClaimIsLive(existing.value, context.env ?? process.env)) return undefined;
    const existingFingerprint = fingerprint(existing.stat, item.id, existing.sha256);
    if (!unlinkIfFingerprintMatches(filePath, existingFingerprint)) return undefined;
  } else {
    try {
      if (fs.lstatSync(filePath)) return undefined;
    } catch {
      // Absent is the expected path.
    }
  }
  const record: RecoveryClaimRecord = {
    v: 1,
    recoveryId: item.id,
    action: "resume",
    ownerPid: process.pid,
    ...(owner.bootId ? { hostBootId: owner.bootId } : {}),
    ...(owner.processStart ? { hostProcessStart: owner.processStart } : {}),
    createdAt: now.toISOString(),
    evidence: item.fingerprint,
  };
  try {
    fs.writeFileSync(filePath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "EEXIST") return undefined;
    throw error;
  }
  const created = safeReadJson(filePath);
  if (!created) {
    fs.rmSync(filePath, { force: true });
    return undefined;
  }
  const createdFingerprint = fingerprint(created.stat, item.id, created.sha256);
  return {
    path: filePath,
    release() {
      unlinkIfFingerprintMatches(filePath, createdFingerprint);
    },
  };
}

export function consumeRecoveryEvidence(item: RecoveryItem): boolean {
  const current = rereadEvidence(item);
  if (!current || !sameFingerprint(current.fingerprint, item.fingerprint)) return false;
  if (item.evidenceKind === "host") {
    return unlinkIfFingerprintMatches(item.evidencePath, item.fingerprint);
  }
  const record: RecoveryConsumedRecord = {
    v: 1,
    recoveryId: item.id,
    evidence: item.fingerprint,
    consumedAt: new Date().toISOString(),
  };
  const epoch: AgentRecoveryEpoch = { v: 1, agent: "claude", consumedAt: record.consumedAt };
  atomicWriteJson(claudeRecoveryEpochPath(item.stateDir), epoch);
  atomicWriteJson(consumedPath(item), record);
  return itemWasConsumed(item);
}

export async function runWithRecoveryClaim(
  context: RuntimeContext,
  item: RecoveryItem,
  action: () => number | Promise<number>,
): Promise<{ status: number; consumed: boolean } | undefined> {
  // An attached session can briefly own the lifecycle lock for renewal. A
  // selector must ride out that transient hold before it decides that the
  // recovery item changed or another selector claimed it.
  const claim = await acquireRecoveryClaim(context, item);
  if (!claim) return undefined;
  try {
    const status = await action();
    return {
      status,
      consumed: status === 0 ? consumeRecoveryEvidence(item) : false,
    };
  } finally {
    claim.release();
  }
}

export function recoveryIdIsValid(value: string): boolean {
  return RECOVERY_ID_RE.test(value);
}
