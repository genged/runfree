import { isRecord, exactKeySet as exactKeys, stableJson } from "./primitives.js";

// The bound on how many session identities one project may admit at once, and
// therefore on the eligibility payload and on the session-file directory the
// proxy scans.
export const SESSION_ADMISSION_MAX_RECORDS = 256;
export const SESSION_ADMISSION_ROOT = "/run/runfree-sessions";
export const SESSION_ADMISSION_ELIGIBILITY_SCHEMA_VERSION = 2 as const;
// A session peer may send exactly this non-forwarding HTTP request to ask
// whether its session file has landed. The guard answers it locally; no policy,
// credential, DNS, or upstream path is entered.
export const SESSION_ADMISSION_PROVISIONING_HOST = "runfree-provisioning.invalid";
export const SESSION_ADMISSION_PROVISIONING_PATH = "/.well-known/runfree/session-ready";
export const SESSION_ADMISSION_PROVISIONING_REQUEST = [
  `GET http://${SESSION_ADMISSION_PROVISIONING_HOST}${SESSION_ADMISSION_PROVISIONING_PATH} HTTP/1.1`,
  `Host: ${SESSION_ADMISSION_PROVISIONING_HOST}`,
  "Connection: close",
  "",
  "",
].join("\r\n");

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const PROJECT_ID = /^[a-f0-9]{12}$/;

export type SessionAdmissionEligibleAgent = {
  sessionAgentGenerationDigest: string;
  selectedAgentImageId: string;
};

export type SessionAdmissionEligibility = {
  v: typeof SESSION_ADMISSION_ELIGIBILITY_SCHEMA_VERSION;
  projectId: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  agentInternalNetworkId: string;
  allowedSessionAgents: SessionAdmissionEligibleAgent[];
};

type Json = boolean | null | number | string | Json[] | { [key: string]: Json };




function normalizedEligibleAgents(value: readonly SessionAdmissionEligibleAgent[]): SessionAdmissionEligibleAgent[] {
  if (value.length > SESSION_ADMISSION_MAX_RECORDS) {
    throw new Error(`session admission eligibility exceeds ${SESSION_ADMISSION_MAX_RECORDS} agent generations`);
  }
  const result = value.map((entry) => {
    if (!isRecord(entry)
      || !exactKeys(entry, [
        "sessionAgentGenerationDigest",
        "selectedAgentImageId",
      ])
      || typeof entry.sessionAgentGenerationDigest !== "string"
      || !SHA256.test(entry.sessionAgentGenerationDigest)
      || typeof entry.selectedAgentImageId !== "string"
      || !SHA256.test(entry.selectedAgentImageId)) {
      throw new Error("session admission eligibility contains an invalid agent generation");
    }
    return {
      sessionAgentGenerationDigest: entry.sessionAgentGenerationDigest,
      selectedAgentImageId: entry.selectedAgentImageId,
    };
  }).sort((left, right) => {
    return left.sessionAgentGenerationDigest.localeCompare(right.sessionAgentGenerationDigest)
      || left.selectedAgentImageId.localeCompare(right.selectedAgentImageId);
  });
  const identities = new Set<string>();
  for (const entry of result) {
    const identity = [
      entry.sessionAgentGenerationDigest,
      entry.selectedAgentImageId,
    ].join("\0");
    if (identities.has(identity)) {
      throw new Error("session admission eligibility repeats an agent generation and image identity");
    }
    identities.add(identity);
  }
  return result;
}

export function createSessionAdmissionEligibility(input: {
  projectId: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  agentInternalNetworkId: string;
  allowedSessionAgents: readonly SessionAdmissionEligibleAgent[];
}): SessionAdmissionEligibility {
  if (!PROJECT_ID.test(input.projectId)) throw new Error("invalid session admission eligibility project id");
  if (!SHA256.test(input.controlPlaneGenerationDigest)) {
    throw new Error("invalid session admission eligibility control-plane generation");
  }
  if (!Number.isSafeInteger(input.admissionContractEpoch) || input.admissionContractEpoch < 1) {
    throw new Error("invalid session admission eligibility epoch");
  }
  if (!/^[a-f0-9]{64}$/.test(input.agentInternalNetworkId)) {
    throw new Error("invalid session admission eligibility internal network id");
  }
  return {
    v: SESSION_ADMISSION_ELIGIBILITY_SCHEMA_VERSION,
    projectId: input.projectId,
    controlPlaneGenerationDigest: input.controlPlaneGenerationDigest,
    admissionContractEpoch: input.admissionContractEpoch,
    agentInternalNetworkId: input.agentInternalNetworkId,
    allowedSessionAgents: normalizedEligibleAgents(input.allowedSessionAgents),
  };
}

export function parseSessionAdmissionEligibility(value: unknown): SessionAdmissionEligibility | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "v",
    "projectId",
    "controlPlaneGenerationDigest",
    "admissionContractEpoch",
    "agentInternalNetworkId",
    "allowedSessionAgents",
  ])) return undefined;
  if (value.v !== SESSION_ADMISSION_ELIGIBILITY_SCHEMA_VERSION
    || typeof value.projectId !== "string"
    || typeof value.controlPlaneGenerationDigest !== "string"
    || typeof value.admissionContractEpoch !== "number"
    || typeof value.agentInternalNetworkId !== "string"
    || !Array.isArray(value.allowedSessionAgents)) return undefined;
  let expected: SessionAdmissionEligibility;
  try {
    expected = createSessionAdmissionEligibility({
      projectId: value.projectId,
      controlPlaneGenerationDigest: value.controlPlaneGenerationDigest,
      admissionContractEpoch: value.admissionContractEpoch,
      agentInternalNetworkId: value.agentInternalNetworkId,
      allowedSessionAgents: value.allowedSessionAgents as SessionAdmissionEligibleAgent[],
    });
  } catch {
    return undefined;
  }
  if (stableJson(expected.allowedSessionAgents as unknown as Json)
    !== stableJson(value.allowedSessionAgents as unknown as Json)) return undefined;
  return expected;
}

export function serializeSessionAdmissionEligibility(eligibility: SessionAdmissionEligibility): string {
  const parsed = parseSessionAdmissionEligibility(eligibility);
  if (!parsed) throw new Error("invalid session admission eligibility");
  return `${stableJson(parsed as unknown as Json)}\n`;
}
