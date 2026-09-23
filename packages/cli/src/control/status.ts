import {
  effectiveWriteAction,
  normalizeHostname,
  type PolicyJson,
  type RequestPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  approvalSetDigest,
  readApprovedNetworkPolicy,
  readControlApprovalRecord,
  verifyNetworkSnapshot,
  type ControlApprovalRead,
  type ControlApprovalSelection,
} from "./approvals.ts";
import { approvalReadRefusal } from "./approval-read.ts";
import { isControlApprovalUnusableError } from "./refusals.ts";
import { discoverLiveProxyId } from "./activation.ts";
import { compareCompiledAuthority } from "./comparator.ts";
import { compileDesiredPolicies, type CompiledDesiredPolicy } from "./compiler.ts";
// The review body and its change description live beside the review surface
// they render, not here; status is one of their consumers.
export { describeCompiledPolicyChanges } from "./review-render.ts";
import { describeCompiledPolicyChanges } from "./review-render.ts";
import {
  readActiveControlSelection,
  readConvergedPolicyReceipt,
  readEffectiveControlProvenance,
  readEffectiveNetworkPolicy,
  verifyEffectivePolicyGeneration,
  type ConvergedPolicyReceipt,
  type EffectiveControlProvenanceSnapshot,
} from "./effective.ts";
import {
  captureQuiescedDesiredPolicyCandidate,
  captureQuiescedProjectControlCandidates,
} from "./workflow.ts";
import type { DesiredNetworkPolicyJson } from "@runfree/runtime-contracts/desired-network-policy";

export type NetworkLayerControlStatus = {
  approvedDigest?: string;
  desiredDigest?: string;
  drift: "absent" | "approved" | "invalid" | "pending";
};

export type ControlStatus = {
  active?: {
    controlGeneration: string;
    policyGeneration: string;
    selectedSubjects: Record<string, string>;
  };
  activeError?: string;
  approvalSetDigest?: string;
  approvalError?: string;
  /** What the saved approvals record is, by name. Reported, never acted on here. */
  approvalRead: ControlApprovalRead["kind"];
  converged?: ConvergedPolicyReceipt;
  /** Whether a proxy container is running right now. Qualifies `converged`. */
  proxyLive: boolean;
  convergenceError?: string;
  desiredError?: string;
  layers: {
    local: NetworkLayerControlStatus;
    project: NetworkLayerControlStatus;
  };
  subjects: {
    imageBuild: NetworkLayerControlStatus;
    runtimeIsolation: NetworkLayerControlStatus;
  };
};

export type NetworkPolicyDiff = {
  approvedDigest?: string;
  classification: "approval-required" | "reduction" | "unchanged" | "unapproved";
  changes: string[];
  desiredDigest: string;
  reasons: string[];
  scope: "local" | "project";
};

export type NetworkPolicyReview = {
  diffs: NetworkPolicyDiff[];
  policies: Partial<Record<"local" | "project", DesiredNetworkPolicyJson>>;
};

export type PolicyHostView = {
  allowlisted: boolean;
  credentials: string[];
  hostSources: string[];
  requestRule?: RequestPolicyJson;
  requestSource?: string;
  writeAction: "allow" | "ask" | "deny";
};

export type PolicyHostExplanation = {
  approvals: Partial<Record<"local" | "project", { approvedAt: string; digest: string; mechanism: string }>>;
  approved?: PolicyHostView;
  desired?: PolicyHostView;
  desiredError?: string;
  effective?: PolicyHostView;
  effectiveApprovals: Partial<Record<"local" | "project", { digest: string; mechanism: string }>>;
  host: string;
  pendingChanges: string[];
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stable(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hostView(
  policy: PolicyJson,
  provenance: EffectiveControlProvenanceSnapshot["provenance"],
  host: string,
): PolicyHostView {
  const credentials = Object.entries(policy.tokens ?? {}).flatMap(([tokenName, token]) =>
    token.credentials.some((credential) => credential.host === host) ? [tokenName] : []);
  return {
    allowlisted: policy.hosts.includes(host),
    credentials: credentials.sort(),
    hostSources: provenance.sources.hosts[host] ?? (policy.hosts.includes(host) ? ["host-owned:prepared-effective"] : []),
    ...(policy.requests?.[host] ? { requestRule: policy.requests[host] } : {}),
    ...(provenance.sources.requests[host]
      ? { requestSource: provenance.sources.requests[host] }
      : policy.requests?.[host] ? { requestSource: "host-owned:prepared-effective" } : {}),
    writeAction: effectiveWriteAction({ requests: policy.requests ?? {}, writeApproval: policy.writeApproval }, host),
  };
}

function compiledHostView(compiled: CompiledDesiredPolicy, host: string): PolicyHostView {
  return hostView(compiled.policy, compiled.provenance, host);
}

function describeHostChanges(before: PolicyHostView | undefined, after: PolicyHostView | undefined): string[] {
  if (!before && !after) return [];
  if (!before) return ["host semantics are newly desired"];
  if (!after) return ["host semantics are no longer desired"];
  const changes: string[] = [];
  if (before.allowlisted !== after.allowlisted) changes.push(`allowlisted: ${before.allowlisted} -> ${after.allowlisted}`);
  if (stable(before.hostSources) !== stable(after.hostSources)) {
    changes.push(`host sources: ${before.hostSources.join(", ") || "none"} -> ${after.hostSources.join(", ") || "none"}`);
  }
  if (stable(before.requestRule) !== stable(after.requestRule)) {
    changes.push(`request rules: ${JSON.stringify(before.requestRule ?? null)} -> ${JSON.stringify(after.requestRule ?? null)}`);
  }
  if (before.requestSource !== after.requestSource) {
    changes.push(`request source: ${before.requestSource ?? "none"} -> ${after.requestSource ?? "none"}`);
  }
  if (before.writeAction !== after.writeAction) changes.push(`write action: ${before.writeAction} -> ${after.writeAction}`);
  if (stable(before.credentials) !== stable(after.credentials)) {
    changes.push(`credentials: ${before.credentials.join(", ") || "none"} -> ${after.credentials.join(", ") || "none"}`);
  }
  return changes;
}

/**
 * Status inspection is read-only: it names what the record is and never
 * migrates or rewrites it. A non-valid record contributes no approved digests,
 * which is what makes the drift columns read `pending` rather than pretending
 * to an approval that carries no authority.
 */
function inspectApprovalRecord(context: RuntimeContext): {
  approvalError?: string;
  read: ControlApprovalRead;
  selection: ControlApprovalSelection | undefined;
} {
  const read = readControlApprovalRecord(context.projectRoot, context.project);
  return {
    read,
    selection: read.kind === "valid" ? read.selection : undefined,
    ...(read.kind === "valid" || read.kind === "missing"
      ? {}
      : { approvalError: approvalReadRefusal(read) }),
  };
}

export async function inspectControlStatus(context: RuntimeContext, io: RuntimeIO): Promise<ControlStatus> {
  const { approvalError, read, selection } = inspectApprovalRecord(context);
  let active: ReturnType<typeof readActiveControlSelection>;
  let generation: ReturnType<typeof verifyEffectivePolicyGeneration> | undefined;
  let activeError: string | undefined;
  try {
    active = readActiveControlSelection(context.project);
    generation = active ? verifyEffectivePolicyGeneration(context.project, active.controlGeneration) : undefined;
  } catch (error) {
    activeError = errorMessage(error);
  }
  // The receipt is cleared only when the generation changes, and the generation
  // no longer moves on a reboot. Reporting it without checking live state would
  // print "(ruleset verified)" with no proxy running. This is display only —
  // enforcement re-reads live proxy state on its own paths — but the display
  // must not outlive the thing it describes.
  let proxyLive: boolean;
  try {
    proxyLive = discoverLiveProxyId(context, io) !== undefined;
  } catch {
    proxyLive = false;
  }
  let converged: ConvergedPolicyReceipt | undefined;
  let convergenceError: string | undefined;
  try {
    converged = readConvergedPolicyReceipt(context.project);
  } catch (error) {
    convergenceError = errorMessage(error);
  }
  const layer = (
    desiredDigest: string | undefined,
    approvedDigest: string | undefined,
    absentIsValid = false,
  ): NetworkLayerControlStatus => ({
    ...(desiredDigest ? { desiredDigest } : {}),
    ...(approvedDigest ? { approvedDigest } : {}),
    drift: desiredDigest === undefined
      ? absentIsValid && approvedDigest === undefined ? "absent" : "invalid"
      : desiredDigest === approvedDigest ? "approved" : "pending",
  });
  let candidates: Awaited<ReturnType<typeof captureQuiescedProjectControlCandidates>> | undefined;
  let desiredError: string | undefined;
  try {
    candidates = await captureQuiescedProjectControlCandidates(context, io);
  } catch (error) {
    desiredError = errorMessage(error);
  }
  return {
    layers: {
      project: layer(candidates?.network.projectSubject.digest, selection?.subjects["network-project"]?.digest),
      local: layer(candidates?.network.localSubject.digest, selection?.subjects["network-local"]?.digest),
    },
    subjects: {
      runtimeIsolation: layer(candidates?.runtimeSubject.digest, selection?.subjects["runtime-isolation"]?.digest),
      imageBuild: layer(candidates?.image?.subject.digest, selection?.subjects["image-build"]?.digest, true),
    },
    approvalRead: read.kind,
    ...(selection ? { approvalSetDigest: approvalSetDigest(selection) } : {}),
    ...(approvalError ? { approvalError } : {}),
    ...(desiredError ? { desiredError } : {}),
    ...(activeError ? { activeError } : {}),
    proxyLive,
    ...(converged && proxyLive ? { converged } : {}),
    ...(convergenceError ? { convergenceError } : {}),
    ...(active && generation
      ? {
          active: {
            controlGeneration: active.controlGeneration,
            policyGeneration: generation.policyGeneration,
            selectedSubjects: generation.hostManifest.selectedSubjects,
          },
        }
      : {}),
  };
}

/** The approved layer, or `undefined` when the record carries no authority. */
function approvedLayerOrUndefined(
  context: RuntimeContext,
  subjectType: "network-local" | "network-project",
): DesiredNetworkPolicyJson | undefined {
  try {
    return readApprovedNetworkPolicy(context.projectRoot, context.project, subjectType);
  } catch (error) {
    if (!isControlApprovalUnusableError(error)) throw error;
    return undefined;
  }
}

export async function inspectNetworkPolicyReview(
  context: RuntimeContext,
  io: RuntimeIO,
  scope?: "local" | "project",
): Promise<NetworkPolicyReview> {
  const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);
  const { selection } = inspectApprovalRecord(context);
  // `runfree policy review` is the reclamation path every approval refusal
  // names. It therefore has to render under a record that carries no authority
  // — otherwise the refusal would point at a wedge. A non-valid record supplies
  // no approved baseline, so every scope classifies as `unapproved` and the
  // review shows the full canonical desired policy.
  const previousProject = approvedLayerOrUndefined(context, "network-project");
  const previousLocal = approvedLayerOrUndefined(context, "network-local");
  const scopes = scope ? [scope] as const : ["project", "local"] as const;
  const diffs = scopes.map((currentScope): NetworkPolicyDiff => {
    const desiredSubject = currentScope === "project" ? candidate.projectSubject : candidate.localSubject;
    const approvedDigest = selection?.subjects[currentScope === "project" ? "network-project" : "network-local"]?.digest;
    if (desiredSubject.digest === approvedDigest) {
      return {
        scope: currentScope,
        desiredDigest: desiredSubject.digest,
        ...(approvedDigest ? { approvedDigest } : {}),
        classification: "unchanged",
        reasons: [],
        changes: [],
      };
    }
    if (!previousProject || !previousLocal) {
      return {
        scope: currentScope,
        desiredDigest: desiredSubject.digest,
        ...(approvedDigest ? { approvedDigest } : {}),
        classification: "unapproved",
        reasons: ["no complete approved network baseline"],
        changes: ["no complete approved baseline; review the full canonical desired policy"],
      };
    }
    const before = compileDesiredPolicies({ project: previousProject, local: previousLocal });
    const after = compileDesiredPolicies({
        project: currentScope === "project" ? candidate.project : previousProject,
        local: currentScope === "local" ? candidate.local : previousLocal,
      });
    const comparison = compareCompiledAuthority(before, after);
    return {
      scope: currentScope,
      desiredDigest: desiredSubject.digest,
      ...(approvedDigest ? { approvedDigest } : {}),
      classification: comparison.provenReduction ? "reduction" : "approval-required",
      reasons: comparison.reasons,
      changes: describeCompiledPolicyChanges(before, after),
    };
  });
  return {
    diffs,
    policies: {
      ...(scope === undefined || scope === "project" ? { project: candidate.project } : {}),
      ...(scope === undefined || scope === "local" ? { local: candidate.local } : {}),
    },
  };
}

export async function inspectPolicyHost(
  context: RuntimeContext,
  io: RuntimeIO,
  hostInput: string,
): Promise<PolicyHostExplanation> {
  const host = normalizeHostname(hostInput);
  let desired: PolicyHostView | undefined;
  let desiredError: string | undefined;
  try {
    const candidate = await captureQuiescedDesiredPolicyCandidate(context, io);
    desired = compiledHostView(compileDesiredPolicies({ project: candidate.project, local: candidate.local }), host);
  } catch (error) {
    desiredError = errorMessage(error);
  }

  const { selection } = inspectApprovalRecord(context);
  const approvals: PolicyHostExplanation["approvals"] = {};
  for (const [scope, subjectType] of [["project", "network-project"], ["local", "network-local"]] as const) {
    const record = selection?.subjects[subjectType];
    if (record) approvals[scope] = record;
  }

  let approved: PolicyHostView | undefined;
  if (selection?.subjects["network-project"] && selection.subjects["network-local"]) {
    approved = compiledHostView(compileDesiredPolicies({
      project: verifyNetworkSnapshot(context.project, "network-project", selection.subjects["network-project"].digest),
      local: verifyNetworkSnapshot(context.project, "network-local", selection.subjects["network-local"].digest),
    }), host);
  }

  let effective: PolicyHostView | undefined;
  const effectiveApprovals: PolicyHostExplanation["effectiveApprovals"] = {};
  const active = readActiveControlSelection(context.project);
  if (active) {
    const generation = verifyEffectivePolicyGeneration(context.project, active.controlGeneration);
    const snapshot = readEffectiveControlProvenance(context.project, active.controlGeneration);
    const policy = readEffectiveNetworkPolicy(context.project, active.controlGeneration);
    effective = hostView(policy, snapshot.provenance, host);
    for (const [scope, subjectType] of [["project", "network-project"], ["local", "network-local"]] as const) {
      const digest = generation.hostManifest.selectedSubjects[subjectType];
      if (!digest) continue;
      const current = selection?.subjects[subjectType];
      effectiveApprovals[scope] = {
        digest,
        mechanism: current?.digest === digest ? current.mechanism : "historical mechanism unavailable",
      };
    }
  }
  return {
    host,
    approvals,
    ...(desired ? { desired } : {}),
    ...(desiredError ? { desiredError } : {}),
    ...(approved ? { approved } : {}),
    ...(effective ? { effective } : {}),
    effectiveApprovals,
    pendingChanges: describeHostChanges(effective, desired),
  };
}
