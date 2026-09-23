// The canonical desired-policy review body, as lines.
//
// There is one review surface. `runfree policy approve` renders it, and so does
// the checkout-binding recovery gate — a mismatch review that showed only three
// subject digests would be consenting to a replaced checkout by digest alone,
// which is precisely the case the binding exists to catch. Returning lines
// rather than printing them is what lets both callers share it without either
// owning the other's output.

import type { DesiredNetworkPolicyJson } from "@runfree/runtime-contracts/desired-network-policy";
import type { RuntimeContext } from "../runtime/types.ts";
import { readApprovedNetworkPolicy } from "./approvals.ts";
import type { DesiredPolicyCandidate } from "./candidates.ts";
import { compileDesiredPolicies, type CompiledDesiredPolicy } from "./compiler.ts";
import { isControlApprovalUnusableError } from "./refusals.ts";
import type { ControlSubject } from "./subjects.ts";

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stable(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function describeRecordChanges(
  label: string,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): string[] {
  const changes: string[] = [];
  for (const key of Array.from(new Set([...Object.keys(before), ...Object.keys(after)])).sort()) {
    if (stable(before[key]) === stable(after[key])) continue;
    changes.push(`${label} ${key}: ${JSON.stringify(before[key] ?? null)} -> ${JSON.stringify(after[key] ?? null)}`);
  }
  return changes;
}

export function describeCompiledPolicyChanges(
  before: CompiledDesiredPolicy,
  after: CompiledDesiredPolicy,
): string[] {
  const changes: string[] = [];
  const beforeHosts = new Set(before.policy.hosts);
  const afterHosts = new Set(after.policy.hosts);
  for (const host of after.policy.hosts.filter((host) => !beforeHosts.has(host))) changes.push(`host ${host}: added`);
  for (const host of before.policy.hosts.filter((host) => !afterHosts.has(host))) changes.push(`host ${host}: removed`);
  changes.push(...describeRecordChanges("request", before.policy.requests ?? {}, after.policy.requests ?? {}));
  changes.push(...describeRecordChanges("credential", before.policy.tokens ?? {}, after.policy.tokens ?? {}));
  changes.push(...describeRecordChanges("OAuth", before.oauth, after.oauth));
  changes.push(...describeRecordChanges("service", before.selectedServices, after.selectedServices));
  changes.push(...describeRecordChanges(
    "provenance",
    before.provenance.sources as unknown as Record<string, unknown>,
    after.provenance.sources as unknown as Record<string, unknown>,
  ));
  if (before.policy.writeApproval !== after.policy.writeApproval) {
    changes.push(`writeApproval: ${before.policy.writeApproval ?? "ask (default)"} -> ${after.policy.writeApproval ?? "ask (default)"}`);
  }
  const beforeEnv = new Set(before.agentEnv);
  const afterEnv = new Set(after.agentEnv);
  for (const name of after.agentEnv.filter((name) => !beforeEnv.has(name))) changes.push(`agent env ${name}: added`);
  for (const name of before.agentEnv.filter((name) => !afterEnv.has(name))) changes.push(`agent env ${name}: removed`);
  return changes;
}

/** The approved layer, or `undefined` when the record carries no authority. */
function approvedLayerOrUndefined(
  runtime: RuntimeContext,
  subjectType: "network-local" | "network-project",
): DesiredNetworkPolicyJson | undefined {
  try {
    return readApprovedNetworkPolicy(runtime.projectRoot, runtime.project, subjectType);
  } catch (error) {
    if (!isControlApprovalUnusableError(error)) throw error;
    return undefined;
  }
}

/**
 * The content of one desired-policy approval decision.
 *
 * The semantic-change block needs both previously approved layers. Under a
 * binding mismatch they carry no authority, so this degrades to the canonical
 * body rather than refusing: the canonical policy IS the whole review in that
 * case, and it is the only thing that makes the consent meaningful.
 */
export function desiredPolicyReviewLines(
  runtime: RuntimeContext,
  candidate: DesiredPolicyCandidate,
  subject: ControlSubject,
  scope: "local" | "project",
): string[] {
  const policy = scope === "project" ? candidate.project : candidate.local;
  const lines = [
    `scope: ${scope}`,
    `subject: ${subject.subjectType}`,
    `subject digest: ${subject.digest}`,
    "canonical desired policy:",
    JSON.stringify(policy, null, 2),
  ];
  const previousProject = approvedLayerOrUndefined(runtime, "network-project");
  const previousLocal = approvedLayerOrUndefined(runtime, "network-local");
  if (previousProject && previousLocal) {
    const before = compileDesiredPolicies({ project: previousProject, local: previousLocal });
    const after = compileDesiredPolicies({
      project: scope === "project" ? candidate.project : previousProject,
      local: scope === "local" ? candidate.local : previousLocal,
    });
    lines.push("effective semantic changes:");
    const changes = describeCompiledPolicyChanges(before, after);
    if (changes.length === 0) lines.push("  none (provenance-only or canonical no-op)");
    else for (const change of changes) lines.push(`  - ${change}`);
  }
  lines.push("This approval applies only to this exact canonical policy input.");
  return lines;
}
