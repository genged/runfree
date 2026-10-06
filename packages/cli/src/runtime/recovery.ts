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
import { createDockerClient, type DockerCallOptions } from "./docker-client.ts";
import { composeProjectName } from "./env.ts";
import { compareHostBootId, compareHostProcessStart, hostBootId, hostProcessStart } from "./host-identity.ts";
import { peekSessionContainerRecordsV2, type SessionContainerRecordV2 } from "./session-containers.ts";
import { readSessionHostStatus } from "./session-host-status.ts";
import { classifySessionRecordLiveness } from "./session-record-liveness.ts";
import { parseTerminalIdentity, type TerminalIdentity } from "./terminal-identity.ts";
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
  // Pass-1 name budget (review F4): every directory entry counts against this,
  // matching or not, so a directory an attacker fills with junk names cannot
  // make the scan expensive by volume alone. Deliberately larger than
  // `maxFilesPerKindPerProject`, which bounds the much costlier pass-2 work
  // (open, read, parse) that only matching names reach.
  maxNamesPerKindPerProject: 16_384,
  maxFilesGlobal: 10_000,
  maxBytesPerKindPerProject: 16 * 1024 * 1024,
  maxFileBytes: 64 * 1024,
  // Wall-clock backstop for one directory scan, independent of the name and
  // file budgets above: a slow filesystem (or a budget set too high) must
  // still bound the time a listing command spends on one project.
  scanDeadlineMs: 2_000,
} as const;

export type RecoveryState = "active" | "interrupted" | "unverified" | "claimed" | "unrecoverable";
export type RecoveryEvidenceKind = "host" | "claude";

// Whether a claim's recorded owner can be shown alive ("live"), shown gone
// ("dead" — a different boot, or the same boot with a dead pid or a mismatched
// process start), or neither ("unprovable" — no record, no usable `ownerPid`,
// or a live pid with no boot/start identity to check it against). An
// "unprovable" claim older than `UNPROVABLE_CLAIM_MAX_AGE_MS` counts as "dead"
// (decision 9, review F2): the risk accepted is that a resumed session
// running longer than that with an unknown owner identity can lose its claim.
export type ClaimLiveness = "live" | "dead" | "unprovable";
export const UNPROVABLE_CLAIM_MAX_AGE_MS = 24 * 60 * 60 * 1000;

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
  // Where a *copied* `conversationName` came from — set only when a host
  // item's name was copied from somewhere else (see `joinHostAndClaudeItems`
  // for "claude-reported"; a later task sets "codex-index"). Absent when the
  // item's own evidence names its own conversation.
  conversationNameSource?: "claude-reported" | "codex-index";
  startedAt?: string;
  updatedAt?: string;
  terminalHint?: string;
  reason?: string;
  resumeBlockedReason?: string;
  hostMetadata?: SessionMetadata;
  claudeRegistry?: ClaudeRegistryEvidence;
  // 2 for host evidence written by the same-terminal resume release; absent
  // for everything else (older Runfree, and all Claude-registry evidence).
  recordVersion?: number;
  // Where `conversationId` came from. "host-chosen"/"resume-lineage" are
  // host-side lineage on host evidence; "claude-reported" is the Claude
  // registry naming its own conversation; "codex-match" is reserved for a
  // later task.
  conversationSource?: "host-chosen" | "resume-lineage" | "claude-reported" | "codex-match";
  // Host-side process/boot identity verdict for host evidence only (from
  // `hostOwnerState`). Absent on Claude-registry items, which have no host
  // owner of their own to check.
  ownerState?: "active" | "dead" | "unknown";
  // Every Claude-registry item for this host item's own reported
  // conversation (see `joinHostAndClaudeItems`), newest first. A crashed
  // original process and a crashed resumed process can each leave their own
  // registry file for the same conversation — normally, and also by a
  // forged duplicate — so this is a list, not a single value. Once linked,
  // none of these Claude items appear as a separate inventory entry.
  linkedClaude?: readonly Readonly<{ id: string; evidencePath: string; fingerprint: EvidenceFingerprint }>[];
  // Every other host item that names this item's own exact conversation (see
  // `joinHostItemsBySameConversation`) — what a killed host client leaves:
  // the original launch's record, plus a later resume's record for the same
  // conversation. This item is the newest by `startedAt`; consuming or
  // dismissing it also removes every file named here (security review F3,
  // decision 10).
  linkedHost?: readonly Readonly<{ evidencePath: string; fingerprint: EvidenceFingerprint; sourceId: string }>[];
  // Host-only terminal identity for host evidence (terminal-identity.ts).
  terminal?: Readonly<{ ids: TerminalIdentity; tty?: string; termProgram?: string; bootId?: string }>;
  // Set only when this item's own claim scope holds an unprovable claim (its
  // owner could not be shown alive or dead) — the reason; the row is hidden
  // from the prompt and the picker. Never set from a *cross-scope* unprovable
  // claim, which must not block or annotate another record (review F2).
  claimUnprovable?: string;
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

// The bounded, TOCTOU-safe read without the JSON parse: `safeReadJson` is
// this plus `JSON.parse`. Kept separate so a claim file that fails to parse
// (the direct, non-atomic `wx` write in `createRecoveryClaimUnderLifecycle`
// can be interrupted mid-write by a crash) still yields a trustworthy stat
// and content hash — enough to age it and to reclaim it with
// `unlinkIfFingerprintMatches` — without ever reading an unbounded file.
type SecureBytes = {
  buffer: Buffer;
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

function safeReadBytes(filePath: string, knownStat?: fs.Stats): SecureBytes | undefined {
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
      buffer,
      stat: after,
      sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
    };
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function safeReadJson(filePath: string, knownStat?: fs.Stats): SecureRead | undefined {
  const bytes = safeReadBytes(filePath, knownStat);
  if (!bytes) return undefined;
  try {
    return { value: JSON.parse(bytes.buffer.toString("utf8")), stat: bytes.stat, sha256: bytes.sha256 };
  } catch {
    return undefined;
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
  if (value.recordVersion !== undefined && value.recordVersion !== 2) return undefined;
  if (value.terminalIds !== undefined && parseTerminalIdentity(value.terminalIds) === undefined) return undefined;
  if (value.launchConversationId !== undefined
    && (typeof value.launchConversationId !== "string" || !UUID_RE.test(value.launchConversationId))) return undefined;
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

type DirectoryCandidate = { name: string; mtimeMs: number };

function scanFixedDirectory<T>(input: {
  anchor: string;
  dir: string;
  fileName: RegExp;
  budget: ScanBudget;
  global: GlobalScanBudget;
  parse(filePath: string, name: string, read: SecureRead): T | undefined;
}): T[] {
  const results: T[] = [];
  const directoryIdentity = verifiedDirectoryIdentity(input.anchor, input.dir);
  if (!directoryIdentity) return results;

  // Pass 1: a cheap, non-authoritative enumeration. It reads only entry names
  // and, for a matching name, one `lstat` for `mtimeMs`; every entry — match
  // or not — counts against `maxNamesPerKindPerProject`, so a directory an
  // attacker fills with junk names cannot make this pass expensive by volume
  // alone (review F4). A wall-clock deadline bounds it independently, in case
  // the name budget is ever raised past what the deadline allows. Nothing
  // decided here is trusted: pass 2 below repeats every existing identity and
  // content check against the real filesystem state before any file opens.
  const deadlineAt = Date.now() + RECOVERY_LIMITS.scanDeadlineMs;
  const candidates: DirectoryCandidate[] = [];
  let names = 0;
  let directory: fs.Dir | undefined;
  try {
    directory = fs.opendirSync(input.dir);
    if (!directoryIdentityMatches(input.dir, directoryIdentity)) return results;
    while (true) {
      if (Date.now() >= deadlineAt) {
        input.global.truncated = true;
        break;
      }
      const entry = directory.readSync();
      if (!entry) break;
      names += 1;
      if (names > RECOVERY_LIMITS.maxNamesPerKindPerProject) {
        input.global.truncated = true;
        break;
      }
      if (!input.fileName.test(entry.name)) continue;
      try {
        candidates.push({ name: entry.name, mtimeMs: fs.lstatSync(path.join(input.dir, entry.name)).mtimeMs });
      } catch {
        // Gone already, or otherwise unreadable: sorts as oldest, and pass 2
        // below will hit the same failure again and count it as invalid.
        candidates.push({ name: entry.name, mtimeMs: 0 });
      }
    }
  } catch {
    return results;
  } finally {
    directory?.closeSync();
  }

  // Newest first, then by name, so a per-kind cap in pass 2 always keeps the
  // most recently active evidence rather than whatever order the filesystem
  // happened to return it in.
  candidates.sort((left, right) => right.mtimeMs - left.mtimeMs || left.name.localeCompare(right.name));

  // Pass 2: the existing per-file loop, unchanged, now walking the sorted
  // candidate list instead of raw readdir order.
  for (const candidate of candidates) {
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
    const filePath = path.join(input.dir, candidate.name);
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
    const parsed = input.parse(filePath, candidate.name, read);
    if (parsed === undefined) input.global.invalidFiles += 1;
    else results.push(parsed);
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

function agentScopeHash(agent: string): string {
  return crypto.createHash("sha256").update(agent.toLowerCase()).digest("hex").slice(0, 24);
}

function recoveryClaimsDir(item: RecoveryItem): string {
  return path.join(item.stateDir, "sessions", "recovery-claims");
}

/**
 * The claim key for one recovery item (section 4, decision 9): exact resume
 * (a conversation id the agent's descriptor can resume exactly) claims its
 * own conversation; everything else claims the whole agent, the picker
 * scope. Two exact claims of different conversations stay concurrent (H1); a
 * picker claim excludes every exact claim of that agent, and vice versa.
 */
export function recoveryClaimScope(item: RecoveryItem): Readonly<{ kind: "conversation" | "agent"; path: string }> {
  if (!RECOVERY_ID_RE.test(item.id)) throw new Error(`invalid recovery id: ${item.id}`);
  const agentScope = agentScopeHash(item.agent);
  const exact = item.conversationId !== undefined && builtinAgent(item.agent)?.resume?.exactArgvPrefix !== undefined;
  if (exact) {
    const conversationScope = crypto.createHash("sha256").update(item.conversationId as string).digest("hex").slice(0, 24);
    return Object.freeze({
      kind: "conversation" as const,
      path: path.join(recoveryClaimsDir(item), `conv-${agentScope}-${conversationScope}.json`),
    });
  }
  return Object.freeze({ kind: "agent" as const, path: path.join(recoveryClaimsDir(item), `agent-${agentScope}.json`) });
}

// Identity-only liveness, with no notion of age: "unprovable" covers both no
// record at all and a live pid the record cannot otherwise verify. Age is
// folded in by `claimFileLiveness`, the only caller, once it has a trustworthy
// timestamp to measure against.
function parsedClaimLivenessFromRecord(value: unknown, env: NodeJS.ProcessEnv): ClaimLiveness {
  if (!isRecord(value) || !Number.isInteger(value.ownerPid) || (value.ownerPid as number) <= 0) return "unprovable";
  const pid = value.ownerPid as number;
  const boot = compareHostBootId(value.hostBootId, env);
  if (boot === "mismatch" || !processAlive(pid)) return "dead";
  const processStart = compareHostProcessStart(value.hostProcessStart, pid, env);
  if (boot === "match" && processStart === "mismatch") return "dead";
  if (boot === "match" && processStart === "match") return "live";
  // Boot unknown, or boot known but start unknown, with a live pid: cannot be
  // shown either way (review F2 — this used to fail closed as "live").
  return "unprovable";
}

function unprovableClaimAgeMs(createdAt: unknown, fallbackMtimeMs: number, now: Date): number {
  const nowMs = now.getTime();
  const createdAtMs = isoString(createdAt) ? Date.parse(createdAt) : undefined;
  // A `createdAt` (or, failing that, an mtime) in the future is not a
  // trustworthy age: fall back from one to the other, and if even the
  // fallback is in the future, report an age of 0 rather than a negative
  // number that would read as younger than fresh.
  const effectiveMs = createdAtMs !== undefined && createdAtMs <= nowMs ? createdAtMs : fallbackMtimeMs;
  return Math.max(0, nowMs - effectiveMs);
}

type MalformedClaimStat = Readonly<{ dev: number; ino: number; size: number; mtimeMs: number }>;
type ClaimFileLiveness = { liveness: ClaimLiveness; bytes?: SecureBytes; malformedStat?: MalformedClaimStat };

/**
 * `lstat` alone, for a claim file `safeReadBytes` refused to read (size 0 —
 * what a crash leaves between the claim's direct `wx` open and its write —
 * over the byte cap, or an unstable TOCTOU read). Only a plain regular,
 * non-hardlinked file counts: anything else (a directory, a symlink, a
 * hardlinked file) is left alone entirely, exactly as a file `lstat` cannot
 * even see is left alone — there is nothing here this function may trust
 * enough to age or reclaim.
 */
function malformedClaimStat(filePath: string): fs.Stats | undefined {
  try {
    const stat = fs.lstatSync(filePath);
    return stat.isFile() && stat.nlink === 1 ? stat : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The full liveness of one claim file: absent is "dead" (nothing to block
 * on), a record that can be parsed is judged on identity, and content that
 * cannot be parsed or read at all — unreadable JSON, or a file
 * `safeReadBytes` refuses outright (size 0, over the cap, an unstable
 * read) — is "unprovable" from its `lstat` mtime alone, since the claim
 * write is a direct, non-atomic `wx` that a crash mid-write can leave in
 * either state. Either way, an "unprovable" verdict past
 * `UNPROVABLE_CLAIM_MAX_AGE_MS` is promoted to "dead" (decision 9). The
 * returned `bytes` or `malformedStat`, when present, is exactly what the
 * caller needs to reclaim the file under the lock — by content fingerprint
 * when there is content to hash, otherwise by a plain stat match.
 */
function claimFileLiveness(filePath: string, env: NodeJS.ProcessEnv, now: Date): ClaimFileLiveness {
  const bytes = safeReadBytes(filePath);
  if (bytes) {
    let value: unknown;
    try {
      value = JSON.parse(bytes.buffer.toString("utf8"));
    } catch {
      const age = unprovableClaimAgeMs(undefined, bytes.stat.mtimeMs, now);
      return { liveness: age > UNPROVABLE_CLAIM_MAX_AGE_MS ? "dead" : "unprovable", bytes };
    }
    const base = parsedClaimLivenessFromRecord(value, env);
    if (base !== "unprovable") return { liveness: base, bytes };
    const createdAt = isRecord(value) ? value.createdAt : undefined;
    const age = unprovableClaimAgeMs(createdAt, bytes.stat.mtimeMs, now);
    return { liveness: age > UNPROVABLE_CLAIM_MAX_AGE_MS ? "dead" : "unprovable", bytes };
  }
  const stat = malformedClaimStat(filePath);
  if (!stat) return { liveness: "dead" };
  const age = unprovableClaimAgeMs(undefined, stat.mtimeMs, now);
  return {
    liveness: age > UNPROVABLE_CLAIM_MAX_AGE_MS ? "dead" : "unprovable",
    malformedStat: { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs },
  };
}

/**
 * Reclaims a claim file this function could not read as content (size 0, or
 * over the byte cap) but could `lstat`: an unlink bound to an immediately
 * re-checked dev/ino/size/mtime match, the same TOCTOU discipline as
 * `unlinkIfFingerprintMatches`, just without a content hash to check against.
 */
function unlinkIfStatMatches(filePath: string, expected: MalformedClaimStat): boolean {
  let actual: fs.Stats;
  try {
    actual = fs.lstatSync(filePath);
  } catch {
    return false;
  }
  if (
    !actual.isFile()
    || actual.nlink !== 1
    || actual.dev !== expected.dev
    || actual.ino !== expected.ino
    || actual.size !== expected.size
    || actual.mtimeMs !== expected.mtimeMs
  ) return false;
  fs.unlinkSync(filePath);
  return true;
}

/**
 * Whether the claim on the *other* scope for this item's agent is live. An
 * exact (conversation) item's cross scope is the single agent-wide picker
 * claim; a picker (agent) item's cross scope is every exact claim of that
 * agent, bounded-listed. Age never matters here: only "live" blocks, and an
 * unprovable or dead claim can never read as live (review F2 — a cross-scope
 * claim that cannot be proved live must never block another record).
 */
function crossScopeClaimIsLive(
  item: RecoveryItem,
  scope: Readonly<{ kind: "conversation" | "agent"; path: string }>,
  env: NodeJS.ProcessEnv,
): boolean {
  const agentScope = agentScopeHash(item.agent);
  const claimsDir = recoveryClaimsDir(item);
  if (scope.kind === "conversation") {
    const pickerPath = path.join(claimsDir, `agent-${agentScope}.json`);
    const read = safeReadJson(pickerPath);
    return read !== undefined && parsedClaimLivenessFromRecord(read.value, env) === "live";
  }
  // Picker scope: every exact claim of this agent must be seen, or a live
  // one the listing missed would let this claim through. A claims directory
  // that plainly does not exist yet is safe — it is the only place either
  // kind of claim file can ever live, and both are only ever created under
  // this same per-project lifecycle lock, so its absence proves no claim of
  // either scope exists. Anything else that keeps the listing from being
  // authoritative — a verification failure (wrong type, a symlink swapped
  // in, a broken parent) or a truncated scan — fails closed instead of
  // reading a partial or unreadable view as "no live claims" (review F2).
  let exists = true;
  try {
    fs.lstatSync(claimsDir);
  } catch {
    exists = false;
  }
  if (!exists) return false;
  if (!verifiedDirectoryIdentity(item.stateDir, claimsDir)) return true;
  const global: GlobalScanBudget = { files: 0, truncated: false, invalidFiles: 0 };
  const liveExactClaims = scanFixedDirectory<true>({
    anchor: item.stateDir,
    dir: claimsDir,
    fileName: new RegExp(`^conv-${agentScope}-[0-9a-f]{24}\\.json$`),
    budget: { files: 0, bytes: 0 },
    global,
    parse: (_filePath, _name, read) => (parsedClaimLivenessFromRecord(read.value, env) === "live" ? true : undefined),
  });
  return global.truncated || liveExactClaims.length > 0;
}

/**
 * The claim state visible to the scan and to classification: "claimed" when
 * this item's own scope is live, or the cross scope is live; "unprovable"
 * when only this item's own scope cannot be shown alive or dead (and the
 * cross scope is not live); "free" otherwise. An own-scope claim past the
 * unprovable age limit reads as "free" here too — the next actual claim
 * attempt reclaims it, so display should not keep hiding it as unprovable.
 */
function itemClaimState(item: RecoveryItem, env: NodeJS.ProcessEnv): "free" | "claimed" | "unprovable" {
  const scope = recoveryClaimScope(item);
  const own = claimFileLiveness(scope.path, env, new Date()).liveness;
  if (own === "live" || crossScopeClaimIsLive(item, scope, env)) return "claimed";
  return own === "unprovable" ? "unprovable" : "free";
}

const CLAIM_UNPROVABLE_REASON = "a recovery claim's owner could not be proved alive or dead";

/** Applies the scan-time claim verdict to a freshly built item, in place. */
function applyClaimState(item: RecoveryItem, env: NodeJS.ProcessEnv): void {
  const state = itemClaimState(item, env);
  if (state === "claimed") item.state = "claimed";
  else if (state === "unprovable") item.claimUnprovable = CLAIM_UNPROVABLE_REASON;
}

function validConversationId(value: string | undefined): string | undefined {
  return value !== undefined && UUID_RE.test(value) ? value.toLowerCase() : undefined;
}

function itemFromHost(
  projectId: string,
  stateDir: string,
  mapping: ProjectMapping,
  evidence: ScannedHostEvidence,
  env: NodeJS.ProcessEnv,
): RecoveryItem {
  const metadata = evidence.metadata;
  // Strict-format validated here and again at argv composition, so a
  // corrupted value degrades to picker precision rather than being trusted.
  // `resumeConversationId` (lineage from an admission-path resume launch)
  // wins over `launchConversationId` (the id a fresh launch minted for
  // itself) when a record somehow carries both, since it names the
  // conversation this launch actually resumed.
  const resumeId = validConversationId(metadata.resumeConversationId);
  const launchId = validConversationId(metadata.launchConversationId);
  const exactId = resumeId ?? launchId;
  const conversationSource: RecoveryItem["conversationSource"] = resumeId !== undefined
    ? "resume-lineage"
    : launchId !== undefined
      ? "host-chosen"
      : undefined;
  const ownerState = hostOwnerState(metadata, env);
  const item: RecoveryItem = {
    id: recoveryId(projectId, "host", metadata.id),
    projectId,
    ...(mapping.projectRoot ? { projectRoot: mapping.projectRoot } : {}),
    projectName: mapping.projectName,
    stateDir,
    state: mapping.valid && ownerState === "active" ? "active" : "unverified",
    evidenceKind: "host",
    evidencePath: evidence.path,
    fingerprint: fingerprint(evidence.stat, metadata.id, evidence.sha256),
    sourceId: metadata.id,
    agent: metadata.command,
    command: metadata.agentCommand,
    ...(exactId !== undefined ? { conversationId: exactId, conversationSource } : {}),
    recordVersion: metadata.recordVersion,
    ownerState,
    terminal: {
      ids: metadata.terminalIds ?? {},
      tty: metadata.hostTty,
      termProgram: metadata.termProgram,
      bootId: metadata.hostBootId,
    },
    startedAt: metadata.startedAt,
    updatedAt: metadata.endedAt ?? metadata.lastSeenAt,
    terminalHint: metadata.hostTty ?? metadata.termProgram,
    hostMetadata: metadata,
    ...(!mapping.valid ? { state: "unrecoverable", reason: mapping.reason } : {}),
  };
  if (mapping.valid) applyClaimState(item, env);
  // The Claude-wide exact-recovery epoch (H2) only protects *imprecise*
  // host-only evidence: an item that already names its own conversation
  // cannot be shadowed by a different exact Claude recovery completing.
  if (exactId === undefined) {
    const consumedAt = metadata.command.toLowerCase() === "claude" ? claudeRecoveryEpoch(stateDir) : undefined;
    const evidenceActivity = metadata.endedAt ?? metadata.lastSeenAt;
    if (consumedAt && Date.parse(evidenceActivity) <= Date.parse(consumedAt)) {
      item.resumeBlockedReason = "an exact Claude recovery completed after this host-only evidence was created";
    }
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
    conversationSource: "claude-reported",
    conversationName: registry.name,
    conversationStatus: registry.status,
    startedAt: new Date(registry.startedAt).toISOString(),
    updatedAt: new Date(registry.updatedAt).toISOString(),
    claudeRegistry: registry,
    ...(!mapping.valid ? { reason: mapping.reason } : {}),
  };
  if (mapping.valid) applyClaimState(item, env);
  return item;
}

/**
 * Folds every one of a host item's own reported Claude registry items into
 * it, so a crashed session that left both an exact host record and one or
 * more live Claude registry entries for the same conversation appears once,
 * not once-per-registry-file. A crashed original process and a crashed
 * resumed process can each leave their own `claude/sessions/<pid>.json` file
 * naming the same conversation — ordinary duplicate residue, and also
 * forgeable by an agent — and `recoveryId` hashes only `(projectId, kind,
 * sourceId)`, so two such files collide on the same recovery id. Joining
 * must therefore gather *every* match for the key, not just one, or a
 * duplicate survives as a standalone row whose id equals the linked id.
 *
 * Joining is keyed by `(projectId, conversationId)` on a host item whose
 * `agent` is Claude — the only `agent` the scanned Claude evidence can ever
 * report — and only against Claude evidence nothing has consumed yet: a
 * consumed duplicate is neither linked nor shown (it is dropped by the
 * caller's `itemWasConsumed` filter same as always). The surviving matches
 * are sorted newest first (by the Claude item's own `updatedAt`, then
 * evidence `mtimeMs`); `conversationName`/`conversationStatus` are copied
 * from the newest, onto a host item that has none of its own. Every joined
 * Claude item is removed from the flat list so none of them appear as a
 * separate entry.
 */
function joinHostAndClaudeItems(items: readonly RecoveryItem[]): RecoveryItem[] {
  const claudeIndexesByKey = new Map<string, number[]>();
  items.forEach((item, index) => {
    if (item.evidenceKind === "claude" && item.conversationId !== undefined) {
      const key = `${item.projectId}\0${item.conversationId}`;
      const existing = claudeIndexesByKey.get(key);
      if (existing) existing.push(index);
      else claudeIndexesByKey.set(key, [index]);
    }
  });
  const joinedClaudeIndexes = new Set<number>();
  const joined = items.map((item) => {
    if (item.evidenceKind !== "host" || item.conversationId === undefined || item.agent.toLowerCase() !== "claude") {
      return item;
    }
    const key = `${item.projectId}\0${item.conversationId}`;
    const matches = (claudeIndexesByKey.get(key) ?? [])
      .filter((index) => !joinedClaudeIndexes.has(index))
      .map((index) => ({ index, claudeItem: items[index] }))
      .filter((entry): entry is { index: number; claudeItem: RecoveryItem } =>
        entry.claudeItem !== undefined && !itemWasConsumed(entry.claudeItem));
    if (matches.length === 0) return item;
    matches.sort((left, right) => {
      const byUpdatedAt = Date.parse(right.claudeItem.updatedAt ?? "") - Date.parse(left.claudeItem.updatedAt ?? "");
      return byUpdatedAt !== 0 ? byUpdatedAt : right.claudeItem.fingerprint.mtimeMs - left.claudeItem.fingerprint.mtimeMs;
    });
    for (const match of matches) joinedClaudeIndexes.add(match.index);
    const newest = matches[0]?.claudeItem;
    return {
      ...item,
      linkedClaude: matches.map(({ claudeItem }) => ({
        id: claudeItem.id,
        evidencePath: claudeItem.evidencePath,
        fingerprint: claudeItem.fingerprint,
      })),
      ...(item.conversationName === undefined && newest?.conversationName !== undefined
        ? { conversationName: newest.conversationName, conversationNameSource: "claude-reported" as const }
        : {}),
      ...(item.conversationStatus === undefined && newest?.conversationStatus !== undefined
        ? { conversationStatus: newest.conversationStatus }
        : {}),
    };
  });
  return joined.filter((_item, index) => !joinedClaudeIndexes.has(index));
}

/**
 * Deduplicates `linkedClaude` entries by `evidencePath` (the greater
 * `mtimeMs` wins a collision), newest first by `mtimeMs` — the only ordering
 * information a linked entry itself carries. Used when merging the
 * `linkedClaude` lists of several host items into the one each is folded
 * into (`joinHostItemsBySameConversation`).
 */
function dedupeLinkedClaudeNewestFirst(
  entries: readonly Readonly<{ id: string; evidencePath: string; fingerprint: EvidenceFingerprint }>[],
): Readonly<{ id: string; evidencePath: string; fingerprint: EvidenceFingerprint }>[] {
  const byPath = new Map<string, Readonly<{ id: string; evidencePath: string; fingerprint: EvidenceFingerprint }>>();
  for (const entry of entries) {
    const existing = byPath.get(entry.evidencePath);
    if (!existing || entry.fingerprint.mtimeMs > existing.fingerprint.mtimeMs) byPath.set(entry.evidencePath, entry);
  }
  return Array.from(byPath.values()).sort((left, right) => right.fingerprint.mtimeMs - left.fingerprint.mtimeMs);
}

/**
 * Joins every host item that names the same exact conversation as another
 * host item — what a killed host client leaves behind: the original
 * launch's own record, plus a later resume's record for the same
 * conversation (a resume's transient evidence is removed on a clean exit,
 * but kept, as its own interrupted record, when the resumed session reached
 * `attached` and then ended non-zero — `finalizeSessionEvidence`, security
 * review F3, decision 10). Grouped by `(projectId, agent, conversationId)`
 * so only an exact id joins, never a picker item.
 *
 * Keeps the item with the newest `startedAt` (ties broken by evidence
 * `mtimeMs`) — its terminal ids are what the next `runfree resume` in that
 * terminal should match — and names every other member `linkedHost`, so
 * consuming or dismissing the kept item also removes them
 * (`consumeRecoveryEvidence`). `linkedClaude` entries already attached to
 * any grouped member (`joinHostAndClaudeItems`, run first) are merged onto
 * the kept item.
 */
function joinHostItemsBySameConversation(items: readonly RecoveryItem[]): RecoveryItem[] {
  const indexesByKey = new Map<string, number[]>();
  items.forEach((item, index) => {
    if (item.evidenceKind === "host" && item.conversationId !== undefined) {
      const key = `${item.projectId}\0${item.agent.toLowerCase()}\0${item.conversationId}`;
      const existing = indexesByKey.get(key);
      if (existing) existing.push(index);
      else indexesByKey.set(key, [index]);
    }
  });
  const dropped = new Set<number>();
  const mergedByPrimaryIndex = new Map<number, RecoveryItem>();
  for (const group of indexesByKey.values()) {
    if (group.length <= 1) continue;
    const members = group
      .map((index) => ({ index, member: items[index] }))
      .filter((entry): entry is { index: number; member: RecoveryItem } => entry.member !== undefined);
    members.sort((left, right) => {
      const byStartedAt = Date.parse(right.member.startedAt ?? "") - Date.parse(left.member.startedAt ?? "");
      return byStartedAt !== 0 ? byStartedAt : right.member.fingerprint.mtimeMs - left.member.fingerprint.mtimeMs;
    });
    const primary = members[0];
    if (!primary) continue;
    const others = members.slice(1);
    for (const other of others) dropped.add(other.index);
    const mergedLinkedClaude = dedupeLinkedClaudeNewestFirst([
      ...(primary.member.linkedClaude ?? []),
      ...others.flatMap(({ member }) => member.linkedClaude ?? []),
    ]);
    mergedByPrimaryIndex.set(primary.index, {
      ...primary.member,
      ...(mergedLinkedClaude.length > 0 ? { linkedClaude: mergedLinkedClaude } : {}),
      linkedHost: others.map(({ member }) => ({
        evidencePath: member.evidencePath,
        fingerprint: member.fingerprint,
        sourceId: member.sourceId,
      })),
    });
  }
  return items
    .map((item, index) => mergedByPrimaryIndex.get(index) ?? item)
    .filter((_item, index) => !dropped.has(index));
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
  // Newest first, then kept-first-wins on a duplicate id (an orphan Claude
  // item without a host record to join can share its recovery id with
  // another registry file naming the same conversation — `recoveryId` hashes
  // only the conversation). A `Map` built from `[id, item]` pairs keeps the
  // *last* `set` for a repeated key, which is the oldest once the array is
  // sorted newest-first — the opposite of what the picker and the one
  // question must see — so this dedups by hand instead, skipping every id
  // already seen, which keeps the first (newest) occurrence.
  const sorted = joinHostItemsBySameConversation(joinHostAndClaudeItems(items))
    .filter((item) => !itemWasConsumed(item))
    .sort((left, right) => Date.parse(right.updatedAt ?? right.startedAt ?? "") - Date.parse(left.updatedAt ?? left.startedAt ?? ""));
  const seenIds = new Set<string>();
  const deduped: RecoveryItem[] = [];
  for (const item of sorted) {
    if (seenIds.has(item.id)) continue;
    seenIds.add(item.id);
    deduped.push(item);
  }
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

const CONTAINER_PROBE_CALL_OPTIONS: DockerCallOptions = {
  timeout: CONTAINER_PROBE_TIMEOUT_MS,
  maxBuffer: CONTAINER_PROBE_MAX_BUFFER,
};

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
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  // The running/StartedAt inspection is item-independent, so one pass asks
  // Docker once per container however many items name it.
  let inspect = pass.inspects.get(containerId);
  if (!inspect) {
    if (!containerProbeAllowed(pass)) return "unverified";
    countContainerProbe(pass);
    inspect = client.inspect(
      [containerId],
      { format: "{{.State.Running}}\t{{.State.StartedAt}}" },
      CONTAINER_PROBE_CALL_OPTIONS,
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
  const probe = client.exec(
    containerId,
    [
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
    { interactive: true, user: AGENT_UID_GID },
    CONTAINER_PROBE_CALL_OPTIONS,
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
  const probe = createDockerClient(io, dockerClientEnvOptions(context)).exec(
    containerId,
    ["sh", "-s"],
    { interactive: true, user: AGENT_UID_GID },
    { ...CONTAINER_PROBE_CALL_OPTIONS, input: inspector },
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
  let current = rereadEvidence(item);
  if (!current) return { ...item, state: "unverified", reason: "recovery evidence changed or became unreadable" };
  if (item.state === "unrecoverable" || !item.projectRoot) return current;
  if (!options.ignoreClaim) {
    const claimState = itemClaimState(current, context.env ?? process.env);
    if (claimState === "claimed") return { ...current, state: "claimed" };
    if (claimState === "unprovable") current = { ...current, claimUnprovable: CLAIM_UNPROVABLE_REASON };
  }
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

/**
 * A claim without a provable boot id and process start can never be told
 * apart later from an unrelated process that happens to reuse its pid after
 * a reboot (`host-identity.ts`), so it could neither exclude a cross-scope
 * claim nor ever be proved dead for reclaim — it would sit there "live"
 * forever. Fail closed at write time instead (controller ruling): refuse to
 * create the claim at all. `dismissRecoveryItem` never hits this, because it
 * writes no claim.
 */
export class RecoveryClaimOwnerIdentityError extends Error {
  constructor() {
    super("cannot claim the recovery item: this process's boot id or start time could not be read; retry");
    this.name = "RecoveryClaimOwnerIdentityError";
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
  // `safeReadBytes`, not `safeReadJson`: the fingerprint is over the raw bytes
  // (stat plus content hash), so this reclaims a malformed claim file — one a
  // crash left mid-write through the claim's direct, non-atomic `wx` — the
  // same way it reclaims any other evidence.
  const bytes = safeReadBytes(filePath);
  if (!bytes) return false;
  const actual = fingerprint(bytes.stat, expected.schemaId, bytes.sha256);
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
  if (!owner.bootId || !owner.processStart) throw new RecoveryClaimOwnerIdentityError();
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

/**
 * Sweeps every dead claim file of `item`'s own agent scope — every
 * `conv-<agentScope>-*.json` and the `agent-<agentScope>.json` picker claim
 * — before the cross-scope check below ever reads the same directory.
 * Without this, a dead `conv-*` claim is reclaimed only when its own
 * conversation is claimed again (the single-scope reclaim further down this
 * function), so a resume that never retries that exact conversation left its
 * dead claim behind for good (AGENTS.md: every fail-closed refusal ships its
 * reclaim path). Each dead file is unlinked by the same fingerprint- or
 * stat-bound check the single-scope reclaim uses below — never a blind
 * unlink — and the directory walk shares `scanFixedDirectory`'s own scan
 * budget, the same one every other recovery directory read uses, so an
 * attacker-filled claims directory cannot make this unbounded. A live or
 * unprovable claim — of this scope or another agent's scope entirely — is
 * left exactly alone.
 */
function sweepDeadClaimsForAgentScope(item: RecoveryItem, env: NodeJS.ProcessEnv, now: Date): void {
  const agentScope = agentScopeHash(item.agent);
  const claimsDir = recoveryClaimsDir(item);
  const global: GlobalScanBudget = { files: 0, truncated: false, invalidFiles: 0 };
  const candidatePaths = [
    path.join(claimsDir, `agent-${agentScope}.json`),
    ...scanFixedDirectory<string>({
      anchor: item.stateDir,
      dir: claimsDir,
      fileName: new RegExp(`^conv-${agentScope}-[0-9a-f]{24}\\.json$`),
      budget: { files: 0, bytes: 0 },
      global,
      parse: (filePath) => filePath,
    }),
  ];
  for (const filePath of candidatePaths) {
    const liveness = claimFileLiveness(filePath, env, now);
    if (liveness.liveness !== "dead") continue;
    if (liveness.bytes) {
      unlinkIfFingerprintMatches(filePath, fingerprint(liveness.bytes.stat, "recovery-claim", liveness.bytes.sha256));
    } else if (liveness.malformedStat) {
      unlinkIfStatMatches(filePath, liveness.malformedStat);
    }
  }
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
  const env = context.env ?? process.env;
  const scope = recoveryClaimScope(item);
  // Reclaim this agent's own dead claim residue before the cross-scope check
  // below reads the same directory (see `sweepDeadClaimsForAgentScope`).
  sweepDeadClaimsForAgentScope(item, env, now);
  // A live cross-scope claim excludes this one outright (section 4): an
  // unprovable cross-scope claim never blocks (review F2), so it is not
  // checked again here.
  if (crossScopeClaimIsLive(item, scope, env)) return undefined;
  const filePath = scope.path;
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const existing = claimFileLiveness(filePath, env, now);
  if (existing.liveness === "live" || existing.liveness === "unprovable") return undefined;
  // "dead": reclaim it under this same lock, the only place a claim is ever
  // unlinked — by content fingerprint when there was content to hash,
  // otherwise (a 0-byte or over-cap file `safeReadBytes` refused to read) by
  // a plain stat match. Neither `bytes` nor `malformedStat` is present only
  // when the path is simply free (no file), or fails even the loosest
  // `lstat`-only check on an existing, unaccountable file (not a regular,
  // single-link file) — either way there is nothing this function may
  // unlink; a lingering, unaccountable file is left for the `wx` write below
  // to refuse against.
  if (existing.bytes) {
    const existingFingerprint = fingerprint(existing.bytes.stat, item.id, existing.bytes.sha256);
    if (!unlinkIfFingerprintMatches(filePath, existingFingerprint)) return undefined;
  } else if (existing.malformedStat) {
    if (!unlinkIfStatMatches(filePath, existing.malformedStat)) return undefined;
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

/**
 * Marks one linked Claude registry item consumed, keyed by its own id and
 * the fingerprint it had at join time — but only once that fingerprint is
 * re-verified against the registry file *now*: a fingerprint a later re-scan
 * would no longer accept (the file changed since joining) means this entry
 * must be left alone, not marked consumed under a snapshot it no longer
 * matches. A write failure, same as a non-matching fingerprint, must not
 * fail the primary (host) consumption this is always called around — this
 * is best-effort per entry, so one bad entry cannot wedge the rest.
 */
function writeLinkedClaudeConsumedRecord(
  stateDir: string,
  linked: Readonly<{ id: string; evidencePath: string; fingerprint: EvidenceFingerprint }>,
): void {
  if (!RECOVERY_ID_RE.test(linked.id)) return;
  try {
    const read = safeReadJson(linked.evidencePath);
    if (!read) return;
    const current = fingerprint(read.stat, linked.fingerprint.schemaId, read.sha256);
    if (!sameFingerprint(current, linked.fingerprint)) return;
    const record: RecoveryConsumedRecord = {
      v: 1,
      recoveryId: linked.id,
      evidence: linked.fingerprint,
      consumedAt: new Date().toISOString(),
    };
    atomicWriteJson(path.join(stateDir, "sessions", "recovery-consumed", `${linked.id}.json`), record);
  } catch {
    // Best-effort: see the doc comment above.
  }
}

export function consumeRecoveryEvidence(item: RecoveryItem): boolean {
  const current = rereadEvidence(item);
  if (!current || !sameFingerprint(current.fingerprint, item.fingerprint)) return false;
  if (item.evidenceKind === "host") {
    // A joined item's own linked Claude ids are marked consumed *before* the
    // host record is unlinked (section 4: one conversation, one item —
    // consuming either consumes both). The reverse order would leave a
    // window, once the host record is gone, where those linked registry
    // files scan as fresh, unclaimed standalone items — inviting a second
    // resume of the conversation this one just finished. This never touches
    // the Claude-wide epoch: that epoch only protects *imprecise* host-only
    // evidence (H2), and a host item that reached here already named its
    // own exact conversation.
    for (const linked of item.linkedClaude ?? []) writeLinkedClaudeConsumedRecord(item.stateDir, linked);
    const consumed = unlinkIfFingerprintMatches(item.evidencePath, item.fingerprint);
    // Every other host item this one was joined with (`linkedHost`,
    // decision 10) is unlinked after the primary, by the same
    // fingerprint-bound check: a mismatch — the file changed since the scan
    // — just leaves that one file alone, and never fails the primary's own
    // consumption above.
    for (const linked of item.linkedHost ?? []) unlinkIfFingerprintMatches(linked.evidencePath, linked.fingerprint);
    return consumed;
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

/**
 * An action's result when a non-zero status must still consume the claimed
 * evidence: a resume whose own session reached `attached` and then ended
 * non-zero (a second Docker stop) keeps its own record instead of the
 * claimed original's, so that new record supersedes it (security review F3,
 * decision 10) — the original must be consumed even though `status` here is
 * non-zero.
 */
export type RecoveryActionResult = Readonly<{ status: number; supersededByNewRecord: boolean }>;

export async function runWithRecoveryClaim(
  context: RuntimeContext,
  item: RecoveryItem,
  action: () => (number | RecoveryActionResult) | Promise<number | RecoveryActionResult>,
): Promise<{ status: number; consumed: boolean } | undefined> {
  // An attached session can briefly own the lifecycle lock for renewal. A
  // selector must ride out that transient hold before it decides that the
  // recovery item changed or another selector claimed it.
  const claim = await acquireRecoveryClaim(context, item);
  if (!claim) return undefined;
  try {
    const result = await action();
    const status = typeof result === "number" ? result : result.status;
    const supersededByNewRecord = typeof result === "number" ? false : result.supersededByNewRecord;
    return {
      status,
      consumed: status === 0 || supersededByNewRecord ? consumeRecoveryEvidence(item) : false,
    };
  } finally {
    claim.release();
  }
}

/**
 * "Forget it" (section 5): dismisses one recovery item without resuming it.
 * Reuses the same fingerprint-checked consumption as a successful resume,
 * under the same lifecycle lock, so a dismiss races a concurrent claim the
 * same way a resume does and never deletes evidence a live claim still
 * owns. Writes only under `<stateDir>/sessions/` and deletes nothing when it
 * returns anything other than "dismissed" (review F9: a lock timeout is
 * reported as "deferred", never "claimed").
 */
export async function dismissRecoveryItem(
  context: RuntimeContext,
  item: RecoveryItem,
  options: { lifecycleLockRetry?: { attempts?: number; delayMs?: number } } = {},
): Promise<"dismissed" | "changed" | "claimed" | "deferred"> {
  if (!evidenceMatches(item)) return "changed";
  const lifecycle = await tryAcquireProjectLifecycleLockWithRetry(context, options.lifecycleLockRetry);
  if (!lifecycle) return "deferred";
  try {
    const env = context.env ?? process.env;
    // An unprovable own-scope claim blocks a dismiss exactly like a live one:
    // either could still be a live resume in progress.
    if (itemClaimState(item, env) !== "free") return "claimed";
    return consumeRecoveryEvidence(item) ? "dismissed" : "changed";
  } finally {
    lifecycle.release();
  }
}

export function recoveryIdIsValid(value: string): boolean {
  return RECOVERY_ID_RE.test(value);
}
