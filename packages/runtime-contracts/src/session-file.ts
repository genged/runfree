import { randomBytes } from "node:crypto";

import { isRecord } from "./primitives.js";
import { type SessionAdmissionEligibility } from "./session-admission.js";
import {
  SESSION_ADMISSION_LEASE_MAX_DURATION_MS,
  SESSION_DISPLAY_AGENT_COMMAND_MAX_CHARACTERS,
  SESSION_DISPLAY_COMMAND_MAX_CHARACTERS,
  SESSION_DISPLAY_HOST_FIELD_MAX_CHARACTERS,
  SESSION_DISPLAY_NAME_MAX_CHARACTERS,
  SESSION_ID_PATTERN,
  SESSION_KEY_PATTERN,
  SESSION_SAFE_ID_PATTERN,
  isExactSessionSourceIpv4,
  type ProxySessionStableIdentity,
} from "./session-registry.js";

// Root-owned per-session file, one per session, read by the proxy in place of
// the shared session-admission snapshot/registry transaction. This module
// owns the exact bytes both the host writer and the proxy reader accept.
export const SESSION_FILES_DIR = "/run/runfree-sessions/sessions";
export const SESSION_ELIGIBILITY_PATH = "/run/runfree-sessions/eligibility.json";
export const SESSION_IP_REUSE_DIR = "/run/runfree-sessions/ip-reuse";
export type SessionIpAssignment = {
  v: 1;
  sourceIp: string;
  sessionKey: string;
  nonce: string;
  state: "draining" | "ready";
};
export const SESSION_FILE_SCHEMA_VERSION = 1 as const;
export const SESSION_FILE_MAX_BYTES = 8 * 1024;
export const SESSION_FILE_NONCE_PATTERN = /^[a-f0-9]{32}$/;

// The identity shapes come from the wire contract itself, so a session file
// parses under exactly the same field rules as a registry record.
// `sessionIncarnation` shares `sessionKey`'s 64-hex shape, so one pattern
// serves both.
const PROJECT_ID_PATTERN = SESSION_SAFE_ID_PATTERN;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const OBJECT_ID = /^[a-f0-9]{64}$/;
// Equivalent to a control-character class covering C0 and C1 codes,
// built from character codes rather than escape literals so the ranges
// land in this file's source bytes exactly, never as raw control bytes.
const CONTROL_CHARACTERS = new RegExp(
  `[${String.fromCharCode(0x00)}-${String.fromCharCode(0x1f)}${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}]`,
  "u",
);

const KEYS = [
  "v",
  "projectId",
  "sessionKey",
  "sessionId",
  "sessionIncarnation",
  "sourceIp",
  "containerId",
  "networkId",
  "selectedAgentImageId",
  "sessionAgentGenerationDigest",
  "controlPlaneGenerationDigest",
  "admissionContractEpoch",
  "name",
  "command",
  "agentCommand",
  "hostTty",
  "hostTermProgram",
  "startedAt",
  "nonce",
  "inspectedAt",
  "aliveUntil",
] as const;
const OPTIONAL_KEYS = new Set<string>(["agentCommand", "hostTty", "hostTermProgram"]);

export type SessionFileV1 = ProxySessionStableIdentity & {
  v: typeof SESSION_FILE_SCHEMA_VERSION;
  projectId: string;
  sessionId: string;
  name: string;
  command: string;
  agentCommand?: string;
  hostTty?: string;
  hostTermProgram?: string;
  startedAt: string;
  nonce: string;
  inspectedAt: string;
  aliveUntil: string;
};

export function sessionFilePath(sessionKey: string): string {
  if (!SESSION_KEY_PATTERN.test(sessionKey)) throw new Error("invalid session key");
  return `${SESSION_FILES_DIR}/${sessionKey}.json`;
}

export function mintSessionFileNonce(random: (size: number) => Buffer = randomBytes): string {
  return random(16).toString("hex");
}

function boundedDisplay(value: unknown, maximum: number, required: boolean): value is string {
  if (typeof value !== "string") return false;
  if (value !== value.trim() || CONTROL_CHARACTERS.test(value)) return false;
  const length = Array.from(value).length;
  return length <= maximum && (!required || length > 0);
}

function isoTimestamp(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : undefined;
}

export function parseSessionFileV1(raw: string, expectedKeyFromName: string): SessionFileV1 | undefined {
  if (Buffer.byteLength(raw) > SESSION_FILE_MAX_BYTES) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  const value = parsed;
  for (const key of Object.keys(value)) if (!(KEYS as readonly string[]).includes(key)) return undefined;
  for (const key of KEYS) if (!OPTIONAL_KEYS.has(key) && !(key in value)) return undefined;

  if (value.v !== SESSION_FILE_SCHEMA_VERSION) return undefined;
  if (typeof value.sessionKey !== "string" || !SESSION_KEY_PATTERN.test(value.sessionKey)) return undefined;
  if (value.sessionKey !== expectedKeyFromName) return undefined;
  if (typeof value.containerId !== "string" || !OBJECT_ID.test(value.containerId)) return undefined;
  if (typeof value.networkId !== "string" || !OBJECT_ID.test(value.networkId)) return undefined;
  if (typeof value.sourceIp !== "string" || !isExactSessionSourceIpv4(value.sourceIp)) return undefined;
  if (typeof value.selectedAgentImageId !== "string" || !SHA256.test(value.selectedAgentImageId)) return undefined;
  if (typeof value.sessionAgentGenerationDigest !== "string"
    || !SHA256.test(value.sessionAgentGenerationDigest)) return undefined;
  if (typeof value.controlPlaneGenerationDigest !== "string"
    || !SHA256.test(value.controlPlaneGenerationDigest)) return undefined;
  if (typeof value.admissionContractEpoch !== "number"
    || !Number.isSafeInteger(value.admissionContractEpoch)
    || value.admissionContractEpoch < 1) return undefined;
  if (typeof value.nonce !== "string" || !SESSION_FILE_NONCE_PATTERN.test(value.nonce)) return undefined;

  const inspectedAt = isoTimestamp(value.inspectedAt);
  const aliveUntil = isoTimestamp(value.aliveUntil);
  const startedAt = isoTimestamp(value.startedAt);
  if (inspectedAt === undefined || aliveUntil === undefined || startedAt === undefined) return undefined;
  if (aliveUntil <= inspectedAt || aliveUntil - inspectedAt > SESSION_ADMISSION_LEASE_MAX_DURATION_MS) return undefined;

  if (typeof value.projectId !== "string" || !PROJECT_ID_PATTERN.test(value.projectId)) return undefined;
  if (typeof value.sessionId !== "string" || !SESSION_ID_PATTERN.test(value.sessionId)) return undefined;
  if (typeof value.sessionIncarnation !== "string" || !SESSION_KEY_PATTERN.test(value.sessionIncarnation)) return undefined;
  if (!boundedDisplay(value.name, SESSION_DISPLAY_NAME_MAX_CHARACTERS, true)) return undefined;
  if (!boundedDisplay(value.command, SESSION_DISPLAY_COMMAND_MAX_CHARACTERS, true)) return undefined;
  if (value.agentCommand !== undefined
    && !boundedDisplay(value.agentCommand, SESSION_DISPLAY_AGENT_COMMAND_MAX_CHARACTERS, false)) return undefined;
  if (value.hostTty !== undefined
    && !boundedDisplay(value.hostTty, SESSION_DISPLAY_HOST_FIELD_MAX_CHARACTERS, false)) return undefined;
  if (value.hostTermProgram !== undefined
    && !boundedDisplay(value.hostTermProgram, SESSION_DISPLAY_HOST_FIELD_MAX_CHARACTERS, false)) return undefined;

  return value as SessionFileV1;
}

export function serializeSessionFileV1(file: SessionFileV1): string {
  const source = file as unknown as Record<string, unknown>;
  const ordered: Record<string, unknown> = {};
  for (const key of KEYS) {
    if (source[key] !== undefined) ordered[key] = source[key];
  }
  return `${JSON.stringify(ordered)}\n`;
}

export function isSessionFileEligible(file: SessionFileV1, eligibility: SessionAdmissionEligibility): boolean {
  return file.projectId === eligibility.projectId
    && file.controlPlaneGenerationDigest === eligibility.controlPlaneGenerationDigest
    && file.admissionContractEpoch === eligibility.admissionContractEpoch
    && file.networkId === eligibility.agentInternalNetworkId
    && eligibility.allowedSessionAgents.some((candidate) => {
      return candidate.sessionAgentGenerationDigest === file.sessionAgentGenerationDigest
        && candidate.selectedAgentImageId === file.selectedAgentImageId;
    });
}
