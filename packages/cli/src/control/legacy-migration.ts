

import {
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
  type DesiredServiceEntry,
} from "@runfree/runtime-contracts/desired-network-policy";
import {
  validateNetworkPolicy,
  type PolicyJson,
  type WriteAction,
} from "@runfree/runtime-contracts/network-policy";
import {
  service,
  serviceHostNames,
} from "../../../../scripts/services.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import { stableJsonDroppingUndefined as stableJson, isRecord, sha256Digest } from "../strict-primitives.ts";

type LegacyServiceRecord = {
  digest?: string;
  hosts?: string[];
  revision: number;
  skippedHosts?: string[];
  writeMode?: "allow-write" | "read-only";
};



function digest(value: unknown): string {
  return sha256Digest(stableJson(value));
}

function legacyServiceRecords(value: unknown): Record<string, LegacyServiceRecord> {
  if (value === undefined) return {};
  if (!isRecord(value)) throw new Error("legacy services must be an object");
  const records: Record<string, LegacyServiceRecord> = {};
  for (const [id, raw] of Object.entries(value)) {
    if (!isRecord(raw) || !Number.isSafeInteger(raw.revision) || Number(raw.revision) < 1) {
      throw new Error(`legacy service ${id} has an invalid revision record`);
    }
    const strings = (entry: unknown): string[] | undefined =>
      Array.isArray(entry) && entry.every((item) => typeof item === "string") ? entry as string[] : undefined;
    const hosts = strings(raw.hosts);
    const skippedHosts = strings(raw.skippedHosts);
    if (raw.hosts !== undefined && !hosts) throw new Error(`legacy service ${id}.hosts must be a string array`);
    if (raw.skippedHosts !== undefined && !skippedHosts) throw new Error(`legacy service ${id}.skippedHosts must be a string array`);
    if (raw.digest !== undefined && (typeof raw.digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(raw.digest))) {
      throw new Error(`legacy service ${id}.digest is malformed`);
    }
    records[id] = {
      revision: Number(raw.revision),
      ...(typeof raw.digest === "string" ? { digest: raw.digest } : {}),
      ...(hosts ? { hosts } : {}),
      ...(skippedHosts ? { skippedHosts } : {}),
      ...(raw.writeMode === "allow-write" || raw.writeMode === "read-only"
        ? { writeMode: raw.writeMode }
        : {}),
    };
  }
  return records;
}

function samePolicy(left: PolicyJson, right: PolicyJson): boolean {
  return stableJson(validateNetworkPolicy(left).raw) === stableJson(validateNetworkPolicy(right).raw);
}

/** Convert the exact legacy enforced policy into desired v2 without widening. */
export function migrateLegacyDesiredPolicy(input: {
  configWriteApproval?: WriteAction;
  onNote?: (note: string) => void;
  policy: unknown;
  services?: unknown;
}): DesiredNetworkPolicyJson {
  if (isRecord(input.policy) && input.policy.version === 2) {
    return validateDesiredNetworkPolicy(input.policy);
  }
  const legacy = validateNetworkPolicy(input.policy).raw;
  if (legacy.writeApproval !== undefined && input.configWriteApproval !== undefined
    && legacy.writeApproval !== input.configWriteApproval) {
    throw new Error(
      `legacy writeApproval conflict: network policy is ${legacy.writeApproval} but runtime.writeApproval is ${input.configWriteApproval}`,
    );
  }
  const effectiveWriteApproval = legacy.writeApproval ?? input.configWriteApproval;
  const directHosts = new Set(legacy.hosts);
  const directRequests = structuredClone(legacy.requests ?? {});
  const directTokens = structuredClone(legacy.tokens ?? {});
  const services: Record<string, DesiredServiceEntry> = {};

  // A legacy service record becomes a service entry only when the current
  // registry can prove it. Everything it contributed to the enforced policy is
  // already held directly, so an unprovable record costs provenance, never
  // authority: dropping it changes nothing the proxy enforces, and the
  // exact-preservation assertion below still covers the result. Migration must
  // never dead-end, because `runfree init` is the only path to config v4 and a
  // refusal strands the project with no way forward.
  const drop = (id: string, reason: string): void => {
    input.onNote?.(`service ${id} kept as direct hosts: ${reason}; re-enable it with: runfree service enable ${id}`);
  };
  for (const [id, record] of Object.entries(legacyServiceRecords(input.services)).sort(([left], [right]) => left.localeCompare(right))) {
    const definition = service(id);
    if (!definition) {
      // A user-defined service, or one the curated registry has retired.
      drop(id, "no pinned definition is available under this Runfree");
      continue;
    }
    if (record.revision > definition.revision) {
      drop(id, `it records revision ${record.revision}, ahead of the available revision ${definition.revision}`);
      continue;
    }
    if (record.digest) {
      drop(id, "it carries a source digest that cannot be proven against the curated registry");
      continue;
    }
    // A stale recorded revision is normal: the curated registry advances while
    // project configs do not. Keep it verbatim so `service diff` reports the
    // gap and can step it forward through the pinned migrations under normal
    // approval.
    const candidateHosts = serviceHostNames(definition).filter((host) => !(record.skippedHosts ?? []).includes(host));
    const hosts = candidateHosts.filter((host) => directHosts.has(host)).sort();
    if (hosts.length === 0) {
      drop(id, "none of its current hosts are in the enforced policy");
      continue;
    }
    // A v3 service record proves that the named service was enabled, but it
    // does not record which allowlist, request-rule, or token entries were
    // created by that enable versus independently authored before or after it.
    // Keep every legacy authority-bearing entry direct. The service retains its
    // resolved host selection for provenance and future reconciliation, while
    // disabling it cannot silently delete authority whose ownership was never
    // proven. A later explicit `service diff --apply` may materialize current
    // service-owned rules and credential destinations under normal approval.
    const resolved = { hosts };
    services[id] = {
      definitionDigest: record.digest && /^sha256:[a-f0-9]{64}$/.test(record.digest)
        ? record.digest
        : digest({ kind: "legacy-enforced-service", id, record, resolved }),
      revision: record.revision,
      ...((record.skippedHosts?.length ?? 0) > 0 || record.writeMode
        ? {
            selection: {
              ...(record.skippedHosts?.length ? { skippedHosts: [...record.skippedHosts].sort() } : {}),
              ...(record.writeMode ? { writeMode: record.writeMode } : {}),
            },
          }
        : {}),
      resolved,
    };
  }

  const desired = validateDesiredNetworkPolicy({
    version: 2,
    hosts: [...directHosts].sort(),
    ...(Object.keys(directRequests).length > 0 ? { requests: directRequests } : {}),
    ...(Object.keys(directTokens).length > 0 ? { tokens: directTokens } : {}),
    ...(Object.keys(services).length > 0 ? { services } : {}),
    ...(effectiveWriteApproval ? { writeApproval: effectiveWriteApproval } : {}),
  });
  const compiled = compileDesiredPolicies({ project: desired, local: { version: 2, hosts: [] } }).policy;
  const expected = validateNetworkPolicy({
    ...legacy,
    ...(effectiveWriteApproval ? { writeApproval: effectiveWriteApproval } : {}),
  }).raw;
  if (!samePolicy(compiled, expected)) {
    throw new Error("legacy desired-policy migration did not preserve exact effective network authority");
  }
  return desired;
}
