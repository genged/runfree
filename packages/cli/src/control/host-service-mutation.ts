// Typed `runfree host-service add|remove` desired-policy mutations.
//
// Same transaction as every typed desired-policy family
// (`withDesiredPolicyTransaction`): capture -> approved-base -> plan -> atomic
// write -> re-read -> exact-match -> approve the in-memory candidate. The
// family's difference lives in `plan`, which runs before the write, so every
// refusal below — name, static port, duplicate port or name across layers,
// compile, and the live port admission (SR5/SR13) — precedes the policy file
// mutation and the approval.

import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { HOST_SERVICE_NAME_RE, refusedHostServicePortReason } from "@runfree/runtime-contracts/host-services";

import { CliError } from "../errors.ts";
import { admitHostServicePort } from "../host-service-port-owner.ts";
import { remedy } from "../remedies.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import type { ControlApprovalSelection } from "./approvals.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import {
  desiredLayerSubject,
  withDesiredPolicyTransaction,
  type DesiredPolicyApprovalSubject,
  type DesiredPolicyLayer,
} from "./desired-policy-transaction.ts";
import { ensureCheckoutLocalPolicyExcluded } from "./git-exclude.ts";

export type DesiredHostServiceScope = DesiredPolicyLayer;

export type DesiredHostServiceMutation =
  | { kind: "add"; name: string; port: number }
  | { kind: "remove"; name: string };

export type DesiredHostServiceMutationResult = {
  changed: boolean;
  digest: string;
  name: string;
  /** The admitted listener (add only): what the operator approved. */
  owner?: { command: string; pid: number };
  scope: DesiredHostServiceScope;
  selection: ControlApprovalSelection;
  warnings: string[];
};

export type HostServiceMutationDependencies = {
  admit?: typeof admitHostServicePort;
};

function layerName(scope: DesiredHostServiceScope): string {
  return scope === "local" ? "checkout-local" : "project";
}

function otherScope(scope: DesiredHostServiceScope): DesiredHostServiceScope {
  return scope === "local" ? "project" : "local";
}

function hostServiceApprovalSubject(scope: DesiredHostServiceScope): DesiredPolicyApprovalSubject {
  return {
    layer: scope,
    missingBaseSubject: `${layerName(scope)} policy`,
    driftSubject: `${scope} desired policy`,
  };
}

function assertMutationName(name: string): void {
  if (!HOST_SERVICE_NAME_RE.test(name)) {
    throw new CliError(`${JSON.stringify(name)} is not a valid host-service name (must match ${HOST_SERVICE_NAME_RE.source})`);
  }
}

function assertMutationPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new CliError(`host-service port must be an integer from 1 to 65535, got ${port}`);
  }
  const refused = refusedHostServicePortReason(port);
  if (refused !== undefined) throw new CliError(`port ${port} is refused: ${refused}`);
}

type PlannedHostService = {
  changed: boolean;
  owner?: { command: string; pid: number };
  policy: DesiredNetworkPolicyJson;
  warnings: string[];
};

function planPolicy(
  layers: { local: DesiredNetworkPolicyJson; project: DesiredNetworkPolicyJson },
  scope: DesiredHostServiceScope,
  mutation: DesiredHostServiceMutation,
): Omit<PlannedHostService, "owner"> {
  assertMutationName(mutation.name);
  const current = layers[scope];
  const other = layers[otherScope(scope)];
  const policy = structuredClone(current);
  const before = canonicalDesiredNetworkPolicy(policy);
  const warnings: string[] = [];

  if (mutation.kind === "add") {
    assertMutationPort(mutation.port);
    if (other.hostServices?.[mutation.name] !== undefined) {
      throw new CliError(
        `host service ${mutation.name} is already approved in the ${layerName(otherScope(scope))} layer; `
          + "a name is approved in one layer only",
      );
    }
    for (const [layer, services] of [[scope, current.hostServices], [otherScope(scope), other.hostServices]] as const) {
      for (const [name, entry] of Object.entries(services ?? {})) {
        if (name !== mutation.name && entry.port === mutation.port) {
          throw new CliError(`port ${mutation.port} is already used by host service ${name} in the ${layerName(layer)} layer`);
        }
      }
    }
    policy.hostServices = { ...(policy.hostServices ?? {}), [mutation.name]: { target: "host-loopback", port: mutation.port } };
  } else {
    if (policy.hostServices?.[mutation.name] !== undefined) {
      const { [mutation.name]: _removed, ...rest } = policy.hostServices;
      if (Object.keys(rest).length > 0) policy.hostServices = rest;
      else delete policy.hostServices;
    } else if (other.hostServices?.[mutation.name] !== undefined) {
      warnings.push(
        `host service ${mutation.name} is approved in the ${layerName(otherScope(scope))} layer, not this one; `
          + "nothing was removed",
      );
    }
  }

  let validated: DesiredNetworkPolicyJson;
  try {
    validated = validateDesiredNetworkPolicy(policy);
    // Schema validation sees one layer; only the compiler resolves project and
    // local together, so compile the planned pair before the write.
    compileDesiredPolicies(scope === "local" ? { project: other, local: validated } : { project: validated, local: other });
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(error instanceof Error ? error.message : String(error));
  }
  return { changed: canonicalDesiredNetworkPolicy(validated) !== before, policy: validated, warnings };
}

export async function mutateDesiredHostService(
  context: RuntimeContext,
  io: RuntimeIO,
  scope: DesiredHostServiceScope,
  mutation: DesiredHostServiceMutation,
  deps: HostServiceMutationDependencies = {},
): Promise<DesiredHostServiceMutationResult> {
  const admit = deps.admit ?? admitHostServicePort;
  return withDesiredPolicyTransaction(context, io, {
    approvalSubject: hostServiceApprovalSubject(scope),
    writeSubject: `${scope} policy write`,
    transactionNoun: "host-service",
    prepare: () => {
      if (scope === "local") ensureCheckoutLocalPolicyExcluded(context.projectRoot, io, context.env);
    },
    plan: (before): PlannedHostService => {
      const planned = planPolicy({ project: before.project, local: before.local }, scope, mutation);
      if (mutation.kind !== "add") return planned;
      // Port admission (SR5/SR13) last: every cheaper refusal above already
      // ran, and this still precedes the write and the approval.
      const admission = admit(context, io, mutation.port);
      if (!admission.ok) {
        throw new CliError([
          `cannot approve host service ${mutation.name} on port ${mutation.port}: ${admission.reason}`,
          `start the service on the host's 127.0.0.1:${mutation.port} (not a Docker-published port), then run: `
            + remedy.hostServiceAdd(mutation.name, mutation.port),
        ].join("\n"));
      }
      return { ...planned, owner: admission.owner };
    },
    result: ({ candidate, plan, selection }) => ({
      changed: plan.changed,
      digest: desiredLayerSubject(candidate, scope).digest,
      name: mutation.name,
      ...(plan.owner ? { owner: plan.owner } : {}),
      scope,
      selection,
      warnings: plan.warnings,
    }),
  });
}

