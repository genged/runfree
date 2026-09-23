import { parseSessionContainerRecordV2, type SessionContainerRecordV2 } from "./session-containers.ts";
import { exactKeySet, isRecord } from "../strict-primitives.ts";

export const REBIND_RECOVERY_BUDGET_MS = 120_000;
export const REBIND_RECOVERY_CREATIONS = 2;
// The effect the phase's own case body still owes. `eligibility-published`
// carries the last identity re-proof, the eligibility publication, and the
// selection — so what it owes is the selection.
export const REBIND_PHASE_EFFECTS = { prepared: "create", "proxy-started-deny-all": "none", "sessions-revalidated": "records",
  "records-rebound": "eligibility", "eligibility-published": "select",
  "control-selected": "credentials", "tokens-synced": "complete", complete: "none" } as const;

export type RebindRecoveryAllowance = Readonly<{
  number: number;
  startedAt: string;
  deadlineAt: string;
  lastObservedAt: string;
  creations: number;
  exhausted: boolean;
}>;

export type RebindRecoveryState = Readonly<{
  candidateAttempt: number;
  creationChargedAttempt?: number;
  batchRevision: number;
  allowance: RebindRecoveryAllowance;
  /** Immutable, bounded serialized prior attempts/allowances; never secrets. */
  retired: readonly string[];
  originalV1?: string;
  trustReceipt?: string;
  batchInputs?: readonly SessionContainerRecordV2[];
  finalizationReceipt?: Readonly<{ proxyContainerId: string; candidateAttempt: number; batchRevision: number; sourceReceiptDigest: string }>;
  outstandingEffect: "create" | "records" | "eligibility" | "select" | "credentials" | "complete" | "none";
}>;

const effects = new Set(["create", "records", "eligibility", "select", "credentials", "complete", "none"]);
const integer = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const timestamp = (value: unknown): value is string => typeof value === "string" && Number.isFinite(Date.parse(value))
  && new Date(Date.parse(value)).toISOString() === value;

export function parseRebindRecoveryState(value: unknown): RebindRecoveryState | undefined {
  if (!isRecord(value) || !exactKeySet(value, ["candidateAttempt", "batchRevision", "allowance", "retired", "outstandingEffect",
    ...(Object.hasOwn(value, "trustReceipt") ? ["trustReceipt"] : []),
    ...(Object.hasOwn(value, "creationChargedAttempt") ? ["creationChargedAttempt"] : []),
    ...(Object.hasOwn(value, "batchInputs") ? ["batchInputs"] : []),
    ...(Object.hasOwn(value, "originalV1") ? ["originalV1"] : []),
    ...(Object.hasOwn(value, "finalizationReceipt") ? ["finalizationReceipt"] : [])])
    || !integer(value.candidateAttempt) || !integer(value.batchRevision)
    || (value.creationChargedAttempt !== undefined && (!integer(value.creationChargedAttempt) || value.creationChargedAttempt > value.candidateAttempt))
    || typeof value.outstandingEffect !== "string" || !effects.has(value.outstandingEffect)
    || !Array.isArray(value.retired) || value.retired.length > 32
    || value.retired.some((entry) => typeof entry !== "string" || Buffer.byteLength(entry) > 512 * 1024)
    || (value.originalV1 !== undefined && (typeof value.originalV1 !== "string" || Buffer.byteLength(value.originalV1) > 512 * 1024))) return undefined;
  if (value.trustReceipt !== undefined) {
    if (typeof value.trustReceipt !== "string" || Buffer.byteLength(value.trustReceipt) > 8192) return undefined;
    try {
      const trust = JSON.parse(value.trustReceipt);
      if (!isRecord(trust) || !exactKeySet(trust, ["certificateDigest", "publicKeyDigest", "directories", "volume"])
        || ![trust.certificateDigest, trust.publicKeyDigest].every((digest) => typeof digest === "string" && /^sha256:[a-f0-9]{64}$/u.test(digest))
        || !Array.isArray(trust.directories) || trust.directories.length !== 2
        || trust.directories.some((directory) => !isRecord(directory) || !exactKeySet(directory, ["path", "device", "inode"])
          || typeof directory.path !== "string" || !integer(directory.device) || !integer(directory.inode))
        || !isRecord(trust.volume) || !exactKeySet(trust.volume, ["name", "createdAt", "mountpoint", "driver", "scope"])
        || Object.values(trust.volume).some((entry) => typeof entry !== "string" || !entry)) return undefined;
    } catch { return undefined; }
  }
  if (value.batchInputs !== undefined && (!Array.isArray(value.batchInputs) || value.batchInputs.length > 64
    || value.batchInputs.some((record) => !parseSessionContainerRecordV2(record))
    || new Set(value.batchInputs.map((record) => record.sessionId)).size !== value.batchInputs.length)) return undefined;
  if (value.finalizationReceipt !== undefined) {
    const receipt = value.finalizationReceipt;
    if (!isRecord(receipt) || !exactKeySet(receipt, ["proxyContainerId", "candidateAttempt", "batchRevision", "sourceReceiptDigest"])
      || typeof receipt.proxyContainerId !== "string" || !/^[a-f0-9]{64}$/u.test(receipt.proxyContainerId)
      || receipt.candidateAttempt !== value.candidateAttempt || receipt.batchRevision !== value.batchRevision
      || typeof receipt.sourceReceiptDigest !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(receipt.sourceReceiptDigest)) return undefined;
  }
  const allowance = value.allowance;
  if (!isRecord(allowance) || !exactKeySet(allowance, ["number", "startedAt", "deadlineAt", "lastObservedAt", "creations", "exhausted"])
    || !integer(allowance.number) || !integer(allowance.creations) || allowance.creations > REBIND_RECOVERY_CREATIONS
    || typeof allowance.exhausted !== "boolean" || !timestamp(allowance.startedAt) || !timestamp(allowance.deadlineAt)
    || !timestamp(allowance.lastObservedAt)
    || Date.parse(allowance.deadlineAt) - Date.parse(allowance.startedAt) !== REBIND_RECOVERY_BUDGET_MS
    || Date.parse(allowance.lastObservedAt) < Date.parse(allowance.startedAt)) return undefined;
  return Object.freeze({ ...value, allowance: Object.freeze({ ...allowance }), retired: Object.freeze([...value.retired]) }) as RebindRecoveryState;
}

export function initialRebindRecoveryState(now: Date): RebindRecoveryState {
  return Object.freeze({ candidateAttempt: 0, batchRevision: 0, retired: [], outstandingEffect: "create",
    allowance: Object.freeze({ number: 0, startedAt: now.toISOString(),
      deadlineAt: new Date(now.getTime() + REBIND_RECOVERY_BUDGET_MS).toISOString(), lastObservedAt: now.toISOString(),
      creations: 0, exhausted: false }) });
}

export class RebindRecoveryExhaustedError extends Error {
  constructor(readonly transactionId: string, readonly phase: string) {
    super(`proxy recovery ${transactionId} is incomplete at ${phase}; automatic allowance ended; sessions remain running; repair the reported failure, then use \`runfree runtime recover --retry\``);
    this.name = "RebindRecoveryExhaustedError";
  }
}
