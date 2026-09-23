import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
  type DesiredServiceEntry,
} from "@runfree/runtime-contracts/desired-network-policy";
import { CliError } from "../errors.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { readApprovedNetworkPolicy, type ControlApprovalSelection } from "./approvals.ts";
import { compileDesiredPolicies, sameControlValue } from "./compiler.ts";
import {
  desiredLayerPolicy,
  desiredLayerSubject,
  withDesiredPolicyTransaction,
  type DesiredPolicyApprovalSubject,
  type DesiredPolicyLayer,
} from "./desired-policy-transaction.ts";
import { ensureCheckoutLocalPolicyExcluded } from "./git-exclude.ts";
import type { DesiredPolicyCandidate } from "./candidates.ts";

export type DesiredServiceLayer = DesiredPolicyLayer;
export type DesiredServiceMutation =
  | { kind: "enable"; id: string; entry: DesiredServiceEntry }
  | { kind: "disable"; id: string };

export type DesiredServiceMutationResult = {
  changed: boolean;
  id: string;
  layer: DesiredServiceLayer;
  layerDigest: string;
  selection: ControlApprovalSelection;
};

// Both refusals use the bare layer name for this family.
function serviceApprovalSubject(layer: DesiredServiceLayer): DesiredPolicyApprovalSubject {
  return { layer, missingBaseSubject: `${layer} desired policy`, driftSubject: `${layer} desired policy` };
}

export function reconcileDesiredService(
  current: DesiredNetworkPolicyJson,
  mutation: DesiredServiceMutation,
): { changed: boolean; id: string; policy: DesiredNetworkPolicyJson } {
  const policy = structuredClone(validateDesiredNetworkPolicy(current));
  const id = mutation.id.toLowerCase();
  const before = canonicalDesiredNetworkPolicy(policy);
  if (mutation.kind === "enable") {
    const entry = structuredClone(mutation.entry);
    policy.services = { ...(policy.services ?? {}), [id]: entry };
    // A token has exactly one owner in the compiled policy. A direct token of
    // the same name is the pre-service form of the same credential
    // destination: legacy migration keeps every legacy token direct precisely
    // because it cannot prove which enable created it. Enabling the service is
    // that proof, so transfer an identical destination to the service instead
    // of writing a policy that cannot compile. A destination that differs is
    // not this service's to take, and silently dropping it would move where a
    // credential is injected.
    const directTokens = policy.tokens;
    if (directTokens) {
      for (const [tokenName, token] of Object.entries(entry.resolved.tokens ?? {})) {
        const direct = directTokens[tokenName];
        if (direct === undefined) continue;
        if (!sameControlValue(direct, token)) {
          throw new CliError([
            `token ${tokenName} is already defined directly with a different credential destination than service ${id} provides`,
            `review it with: runfree policy diff`,
            `remove the direct token first with: runfree credential remove ${tokenName}`,
          ].join("\n"));
        }
        delete directTokens[tokenName];
      }
      if (Object.keys(directTokens).length === 0) delete policy.tokens;
    }
  } else {
    if (!policy.services?.[id]) throw new CliError(`${id} service is not enabled in the selected desired policy layer`);
    delete policy.services[id];
    if (Object.keys(policy.services).length === 0) delete policy.services;
  }
  const validated = validateDesiredNetworkPolicy(policy);
  return {
    changed: canonicalDesiredNetworkPolicy(validated) !== before,
    id,
    policy: validated,
  };
}

export async function mutateDesiredService(
  context: RuntimeContext,
  io: RuntimeIO,
  layer: DesiredServiceLayer,
  mutation: DesiredServiceMutation,
  hostState: {
    beforeWrite?: (before: Pick<DesiredPolicyCandidate, "project" | "local">, planned: Pick<DesiredPolicyCandidate, "project" | "local">) => undefined | (() => void);
    withWriteLock?: <T>(action: () => T) => T;
  } = {},
): Promise<DesiredServiceMutationResult> {
  // The empty substitutions below apply only to a genuinely absent approval:
  // every other non-valid record refuses inside the read. Widening them back to
  // a catch would plan this mutation against an empty baseline without saying
  // so, which is exactly what a replaced checkout needs to be refused.
  const approvedPolicies = () => ({
    project: readApprovedNetworkPolicy(context.projectRoot, context.project, "network-project") ?? { version: 2 as const, hosts: [] },
    local: readApprovedNetworkPolicy(context.projectRoot, context.project, "network-local") ?? { version: 2 as const, hosts: [] },
  });
  return withDesiredPolicyTransaction<ReturnType<typeof reconcileDesiredService>, DesiredServiceMutationResult>(context, io, {
    approvalSubject: serviceApprovalSubject(layer),
    writeSubject: "desired service write",
    transactionNoun: "service",
    withWriteLock: hostState.withWriteLock,
    beforeWrite: hostState.beforeWrite ? (_before, planned) => {
      const approved = approvedPolicies();
      const next = { ...approved, [layer]: planned.policy };
      compileDesiredPolicies(next);
      return hostState.beforeWrite?.(approved, next);
    } : undefined,
    reuseSelectionWhenUnchanged: {
      missingSelectionMessage: "desired service base approval disappeared during unchanged mutation",
    },
    prepare: () => {
      if (layer === "local") ensureCheckoutLocalPolicyExcluded(context.projectRoot, io);
    },
    plan: (before) => {
      const planned = reconcileDesiredService(desiredLayerPolicy(before, layer), mutation);
      // Schema validation alone cannot see cross-layer ownership: only the
      // compiler resolves project and local together. Compile the planned pair
      // before the write so no mutation can persist a desired policy that later
      // refuses to compile and wedges every command that reads effective control.
      compileDesiredPolicies({
        project: layer === "project" ? planned.policy : before.project,
        local: layer === "local" ? planned.policy : before.local,
      });
      return planned;
    },
    result: ({ candidate, plan, selection }) => {
      return {
        changed: plan.changed,
        id: plan.id,
        layer,
        layerDigest: desiredLayerSubject(candidate, layer).digest,
        selection,
      };
    },
  });
}
