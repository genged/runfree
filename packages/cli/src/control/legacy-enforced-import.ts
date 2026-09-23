// Authoring-side consumer of a pre-recorded legacy enforced-network proof.
// The runtime-side producer (`recordLegacyEnforcedNetworkProof`, which minted
// this proof from a live v3 runtime) was deleted with the pre-v4 runtime
// paths, so only proofs recorded by an older release can still exist. When no
// proof is present, config migration falls back to the normal exact-review
// approval path.
import fs from "node:fs";

import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";
import type { DesiredNetworkPolicyJson } from "@runfree/runtime-contracts/desired-network-policy";

import type { ProjectInfo } from "../config.ts";
import { projectHash } from "../project-identity.ts";
import { importLegacyEnforcedNetworkPolicyApproval } from "./approvals.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import { parseStrictJson } from "./strict-json.ts";
import { checkoutFingerprint } from "./subjects.ts";
import { exactKeySet as exactKeys, isRecord } from "../strict-primitives.ts";

const LEGACY_PROOF_SCHEMA_VERSION = 1 as const;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const CONTAINER_ID = /^[a-f0-9]{12,64}$/;
const MAX_PROOF_BYTES = 16 * 1024;

type LegacyEnforcedNetworkProof = {
  agentId: string;
  checkoutFingerprint: string;
  configVersion: number;
  overlayModel: "none";
  policyGeneration: string;
  projectId: string;
  proxyId: string;
  recordedAt: string;
  runtimeGenerationDigest: string;
  schemaVersion: typeof LEGACY_PROOF_SCHEMA_VERSION;
};



function parseProof(value: unknown): LegacyEnforcedNetworkProof | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "agentId",
    "checkoutFingerprint",
    "configVersion",
    "overlayModel",
    "policyGeneration",
    "projectId",
    "proxyId",
    "recordedAt",
    "runtimeGenerationDigest",
    "schemaVersion",
  ])) return undefined;
  if (value.schemaVersion !== LEGACY_PROOF_SCHEMA_VERSION
    || !Number.isSafeInteger(value.configVersion) || Number(value.configVersion) < 1 || Number(value.configVersion) >= 4
    || value.overlayModel !== "none"
    || typeof value.projectId !== "string" || !/^[a-f0-9]{12}$/.test(value.projectId)
    || typeof value.agentId !== "string" || !CONTAINER_ID.test(value.agentId)
    || typeof value.proxyId !== "string" || !CONTAINER_ID.test(value.proxyId)
    || typeof value.checkoutFingerprint !== "string" || !SHA256.test(value.checkoutFingerprint)
    || typeof value.policyGeneration !== "string" || !SHA256.test(value.policyGeneration)
    || typeof value.runtimeGenerationDigest !== "string" || !SHA256.test(value.runtimeGenerationDigest)
    || typeof value.recordedAt !== "string" || new Date(value.recordedAt).toISOString() !== value.recordedAt) {
    return undefined;
  }
  return value as LegacyEnforcedNetworkProof;
}

function readProof(project: ProjectInfo): LegacyEnforcedNetworkProof | undefined {
  try {
    const stat = fs.lstatSync(project.paths.controlLegacyEnforcedNetworkPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > MAX_PROOF_BYTES) return undefined;
    return parseProof(parseStrictJson(fs.readFileSync(project.paths.controlLegacyEnforcedNetworkPath, "utf8")));
  } catch {
    return undefined;
  }
}

/** Import only authority whose exact v3 policy generation has prior proof. */
export function importProvenLegacyNetworkApproval(
  projectRoot: string,
  legacyProject: ProjectInfo,
  migratedProject: ProjectInfo,
  desiredPolicy: DesiredNetworkPolicyJson,
  now = new Date(),
): boolean {
  const proof = readProof(legacyProject);
  if (!proof
    || proof.projectId !== projectHash(projectRoot)
    || proof.checkoutFingerprint !== checkoutFingerprint(projectRoot)
    || proof.configVersion !== legacyProject.config.version
    || migratedProject.config.version !== 4) return false;
  const compiled = compileDesiredPolicies({
    project: desiredPolicy,
    local: { version: 2, hosts: [] },
  });
  if (validateNetworkPolicy(compiled.policy).generation !== proof.policyGeneration) return false;
  importLegacyEnforcedNetworkPolicyApproval(projectRoot, migratedProject, desiredPolicy, now);
  return true;
}
