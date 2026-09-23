import { isIP } from "node:net";
import { isRecord } from "./primitives.js";

// The source-IP session identity both runtimes share: the directory the proxy
// reads a session's state out of, the identity fields that say a session is
// still the same session, and the bounds on what a session may display.
export const PROXY_SESSION_REGISTRY_DIR = "/run/runfree-sessions";
// One lease bound for every producer and consumer. The host must not mint a
// lease the proxy privately shortens: a session file's `aliveUntil` is checked
// against the proxy's own clock, so two different maxima would let the host
// believe a session is served past the point the proxy stops serving it. Keep
// this in the shared contract rather than in either runtime.
export const SESSION_ADMISSION_LEASE_MAX_DURATION_MS = 5 * 60 * 1000;

export const SESSION_DISPLAY_NAME_MAX_CHARACTERS = 80;
export const SESSION_DISPLAY_COMMAND_MAX_CHARACTERS = 64;
export const SESSION_DISPLAY_AGENT_COMMAND_MAX_CHARACTERS = 256;
export const SESSION_DISPLAY_HOST_FIELD_MAX_CHARACTERS = 128;

// The identity shapes both wire contracts accept. Exported so `session-file.ts`
// parses a session file under exactly these rules rather than under a second
// copy of them.
export const SESSION_SAFE_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
export const SESSION_ID_PATTERN = /^rf-[0-9]{8}-[a-z0-9]{6,32}$/;
export const SESSION_KEY_PATTERN = /^[a-f0-9]{64}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;

/**
 * The identity a session keeps for as long as it is the same session.
 *
 * Every field is exact runtime identity, so two values that compare equal name
 * the same container on the same network under the same control plane. The
 * session file (`session-file.ts`) carries these fields and the proxy compares
 * them by this shape.
 */
export type ProxySessionStableIdentity = {
  sessionKey: string;
  sessionIncarnation: string;
  containerId: string;
  sourceIp: string;
  networkId: string;
  selectedAgentImageId: string;
  sessionAgentGenerationDigest: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
};

export function proxySessionStableIdentity(record: ProxySessionStableIdentity): string {
  return [
    record.sessionKey,
    record.sessionIncarnation,
    record.containerId,
    record.sourceIp,
    record.networkId,
    record.selectedAgentImageId,
    record.sessionAgentGenerationDigest,
    record.controlPlaneGenerationDigest,
    record.admissionContractEpoch,
  ].join("\0");
}

export function sameProxySessionStableIdentity(
  left: ProxySessionStableIdentity,
  right: ProxySessionStableIdentity,
): boolean {
  return proxySessionStableIdentity(left) === proxySessionStableIdentity(right);
}

/** The session fields an approval prompt may show, and nothing else. */
export type PendingApprovalSession = {
  sessionId: string;
  name: string;
  command: string;
  agentCommand?: string;
  hostTty?: string;
  hostTermProgram?: string;
  startedAt: string;
};

export type ApprovalRequestSession = PendingApprovalSession & {
  kind: "session";
  sessionKey: string;
  authenticated: true;
};

export type ApprovalRequestOnlyPrincipal = {
  kind: "anonymous-utility";
  authenticated: boolean;
  label: string;
};

export type ApprovalRequestPrincipal = ApprovalRequestSession | ApprovalRequestOnlyPrincipal;


function boundedDisplay(value: unknown, maximum: number, required: boolean): value is string {
  if (typeof value !== "string") return false;
  if (value !== value.trim() || CONTROL_CHARACTERS.test(value)) return false;
  const length = Array.from(value).length;
  return length <= maximum && (!required || length > 0);
}

function exactTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 32) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

const PENDING_SESSION_KEYS = new Set([
  "sessionId",
  "name",
  "command",
  "agentCommand",
  "hostTty",
  "hostTermProgram",
  "startedAt",
]);

export function parsePendingApprovalSession(value: unknown): PendingApprovalSession | undefined {
  if (!isRecord(value) || Object.keys(value).some((key) => !PENDING_SESSION_KEYS.has(key))) return undefined;
  if (typeof value.sessionId !== "string" || !SESSION_ID_PATTERN.test(value.sessionId)) return undefined;
  if (!boundedDisplay(value.name, SESSION_DISPLAY_NAME_MAX_CHARACTERS, true)) return undefined;
  if (!boundedDisplay(value.command, SESSION_DISPLAY_COMMAND_MAX_CHARACTERS, true)) return undefined;
  if (value.agentCommand !== undefined
    && !boundedDisplay(value.agentCommand, SESSION_DISPLAY_AGENT_COMMAND_MAX_CHARACTERS, false)) return undefined;
  if (value.hostTty !== undefined
    && !boundedDisplay(value.hostTty, SESSION_DISPLAY_HOST_FIELD_MAX_CHARACTERS, false)) return undefined;
  if (value.hostTermProgram !== undefined
    && !boundedDisplay(value.hostTermProgram, SESSION_DISPLAY_HOST_FIELD_MAX_CHARACTERS, false)) return undefined;
  if (!exactTimestamp(value.startedAt)) return undefined;
  return value as PendingApprovalSession;
}

export function isExactSessionSourceIpv4(value: string): boolean {
  if (isIP(value) !== 4) return false;
  return value.split(".").map((part) => String(Number(part))).join(".") === value;
}

export function proxySessionRegistryDirFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.RUNFREE_SESSION_REGISTRY_DIR ?? PROXY_SESSION_REGISTRY_DIR;
}

export function pendingApprovalSession(record: PendingApprovalSession): PendingApprovalSession {
  return {
    sessionId: record.sessionId,
    name: record.name,
    command: record.command,
    ...(record.agentCommand !== undefined ? { agentCommand: record.agentCommand } : {}),
    ...(record.hostTty !== undefined ? { hostTty: record.hostTty } : {}),
    ...(record.hostTermProgram !== undefined ? { hostTermProgram: record.hostTermProgram } : {}),
    startedAt: record.startedAt,
  };
}
