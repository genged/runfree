import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import {
  HTTP_METHODS,
  isHttpMethod,
  normalizeHostname,
  normalizePathPrefix,
  READ_ONLY_METHODS,
  type HttpMethod,
  type RequestPolicyJson,
  type WriteAction,
} from "@runfree/runtime-contracts/network-policy";
import type { RequestRuleInput } from "../admin/options.ts";
import { CliError } from "../errors.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import type { ControlApprovalSelection } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import {
  assertApprovedDesiredBase,
  desiredLayerPolicy,
  desiredLayerSubject,
  withDesiredPolicyTransaction,
  type DesiredPolicyApprovalSubject,
  type DesiredPolicyLayer,
} from "./desired-policy-transaction.ts";
import { ensureCheckoutLocalPolicyExcluded } from "./git-exclude.ts";
import { withQuiescedProject } from "./quiesce.ts";

export type DesiredHostScope = DesiredPolicyLayer;

export type DesiredHostMutation =
  | { kind: "add"; host: string; requestRule?: RequestRuleInput }
  | { kind: "remove"; host: string }
  | { kind: "rules"; host: string; clear: boolean; requestRule?: RequestRuleInput; write?: WriteAction };

export type DesiredHostMutationResult = {
  changed: boolean;
  digest: string;
  host: string;
  scope: DesiredHostScope;
  selection: ControlApprovalSelection;
  // Direct authority is one of several owners in the compiled policy, so a
  // direct edit does not always mean what it looks like. These say what the
  // compiled result actually is, for the caller to report.
  warnings: string[];
};

export type DesiredHostRulesResult = {
  host: string;
  rule?: RequestPolicyJson;
  scope: DesiredHostScope;
};

function sortedMethods(methods: Iterable<HttpMethod>): HttpMethod[] {
  return Array.from(new Set(methods)).sort((left, right) => HTTP_METHODS.indexOf(left) - HTTP_METHODS.indexOf(right));
}

function hasRequestRuleFlags(input: RequestRuleInput | undefined): input is RequestRuleInput {
  return input !== undefined && (input.readOnly || input.methods.length > 0 || input.pathPrefixes.length > 0 || input.denyGitPush);
}

function requestRule(input: RequestRuleInput, write?: WriteAction): RequestPolicyJson {
  if (input.readOnly && input.methods.length > 0) {
    throw new CliError("--read-only conflicts with --method; it is shorthand for --method GET --method HEAD --method OPTIONS");
  }
  const methods: HttpMethod[] = [];
  for (const raw of input.methods) {
    const method = raw.toUpperCase();
    if (!isHttpMethod(method)) throw new CliError(`--method must be one of: ${HTTP_METHODS.join(", ")}`);
    methods.push(method);
  }
  if (input.readOnly) methods.push(...READ_ONLY_METHODS);
  const pathPrefixes = input.pathPrefixes.map((prefix) => {
    try {
      return normalizePathPrefix(prefix);
    } catch (error) {
      throw new CliError(`--request-path-prefix ${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  return {
    ...(methods.length > 0 ? { methods: sortedMethods(methods) } : {}),
    ...(pathPrefixes.length > 0 ? { pathPrefixes: Array.from(new Set(pathPrefixes)).sort() } : {}),
    ...(input.denyGitPush ? { gitPush: "deny" as const } : {}),
    ...(write === undefined ? {} : { writeAction: write }),
  };
}

function normalizeMutationHost(host: string): string {
  try {
    return normalizeHostname(host);
  } catch (error) {
    throw new CliError(error instanceof Error ? error.message : String(error));
  }
}

function pairFor(
  candidate: { local: DesiredNetworkPolicyJson; project: DesiredNetworkPolicyJson },
  scope: DesiredHostScope,
  policy: DesiredNetworkPolicyJson,
): { local: DesiredNetworkPolicyJson; project: DesiredNetworkPolicyJson } {
  return scope === "local"
    ? { project: candidate.project, local: policy }
    : { project: policy, local: candidate.local };
}

function serviceOwners(origins: string[] | undefined): string[] {
  return (origins ?? []).filter((origin) => origin.startsWith("service:")).sort();
}

/**
 * A direct host entry is not the only source of authority for that host, and
 * `compileDesiredPolicies` resolves the layers differently than the single
 * layer this mutation edits: services also contribute hosts, and a direct
 * request rule replaces a service-owned rule for the same host outright. Say
 * so, rather than reporting a write that did not change what the proxy
 * enforces or that silently dropped a service's request classification.
 */
function compiledWarnings(
  before: ReturnType<typeof compileDesiredPolicies>,
  after: ReturnType<typeof compileDesiredPolicies>,
  mutation: DesiredHostMutation,
  host: string,
): string[] {
  const warnings: string[] = [];
  if (mutation.kind === "remove" && after.policy.hosts.includes(host)) {
    const owners = serviceOwners(after.provenance.hosts[host]);
    warnings.push(owners.length > 0
      ? `${host} is still allowlisted by ${owners.join(", ")}; disable it with: runfree service disable ${owners[0].slice("service:".length)}`
      : `${host} is still allowlisted by the other desired policy layer`);
  }
  const previousOwner = before.provenance.requests[host];
  const previousRule = before.policy.requests?.[host];
  const nextRule = after.policy.requests?.[host];
  if (previousOwner?.startsWith("service:")
    && after.provenance.requests[host] === "direct"
    && JSON.stringify(previousRule) !== JSON.stringify(nextRule)) {
    warnings.push(
      `the direct rule replaces the whole request rule ${previousOwner} set for ${host}: ${JSON.stringify(previousRule)} is now ${JSON.stringify(nextRule)}`,
    );
  }
  return warnings;
}

function credentialNamesForHost(policy: DesiredNetworkPolicyJson, host: string): string[] {
  return Object.entries(policy.tokens ?? {}).flatMap(([name, token]) =>
    token.credentials.some((credential) => credential.host === host) ? [name] : []);
}

function mutatePolicy(
  current: DesiredNetworkPolicyJson,
  mutation: DesiredHostMutation,
  scope: DesiredHostScope,
): { changed: boolean; host: string; policy: DesiredNetworkPolicyJson } {
  const policy = structuredClone(current);
  const host = normalizeMutationHost(mutation.host);
  const before = canonicalDesiredNetworkPolicy(policy);
  const layer = scope === "local" ? "checkout-local" : "project";

  if (mutation.kind === "add") {
    if (!policy.hosts.includes(host)) policy.hosts = [...policy.hosts, host].sort();
    if (hasRequestRuleFlags(mutation.requestRule)) {
      policy.requests ??= {};
      policy.requests[host] = requestRule(mutation.requestRule);
    }
  } else if (mutation.kind === "remove") {
    if (!policy.hosts.includes(host)) throw new CliError(`${host} is not allowlisted in ${layer} policy`);
    const credentials = credentialNamesForHost(policy, host);
    if (credentials.length > 0) {
      throw new CliError(`${host} is still used by ${layer} credential mappings: ${credentials.join(", ")}`);
    }
    policy.hosts = policy.hosts.filter((candidate) => candidate !== host);
    if (policy.requests?.[host]) {
      delete policy.requests[host];
      if (Object.keys(policy.requests).length === 0) delete policy.requests;
    }
  } else {
    const ruleInput = mutation.requestRule;
    const hasRuleFlags = hasRequestRuleFlags(ruleInput);
    if (mutation.clear && (mutation.write !== undefined || hasRuleFlags)) {
      throw new CliError("--clear conflicts with --write and request-rule flags; clear the rules or set rules, not both");
    }
    if (!policy.hosts.includes(host)) {
      const localFlag = scope === "local" ? " --local" : "";
      throw new CliError(`${host} is not allowlisted in ${layer} policy; add it with: runfree host add ${host}${localFlag}`);
    }
    if (mutation.clear) {
      if (policy.requests?.[host]) {
        delete policy.requests[host];
        if (Object.keys(policy.requests).length === 0) delete policy.requests;
      }
    } else if (hasRuleFlags) {
      policy.requests ??= {};
      policy.requests[host] = requestRule(ruleInput, mutation.write);
    } else if (mutation.write !== undefined) {
      policy.requests ??= {};
      policy.requests[host] = { ...(policy.requests[host] ?? {}), writeAction: mutation.write };
    }
  }

  const validated = validateDesiredNetworkPolicy(policy);
  return { changed: canonicalDesiredNetworkPolicy(validated) !== before, host, policy: validated };
}

// The refusal nouns this family has always used: `checkout-local policy` in the
// missing-base message but `local desired policy` in the drift message.
function hostApprovalSubject(scope: DesiredHostScope): DesiredPolicyApprovalSubject {
  return {
    layer: scope,
    missingBaseSubject: `${scope === "local" ? "checkout-local" : "project"} policy`,
    driftSubject: `${scope} desired policy`,
  };
}

export async function readDesiredHostRules(
  context: RuntimeContext,
  io: RuntimeIO,
  scope: DesiredHostScope,
  rawHost: string,
): Promise<DesiredHostRulesResult> {
  return withQuiescedProject(context, io, () => {
    const candidate = captureDesiredPolicyCandidate(context.projectRoot, context.project.paths.controlCandidatesDir);
    // This read runs beside live agent sessions, so the desired file it just
    // captured may be agent-authored. Hold it to the same approved base the
    // typed mutations require: printing unapproved drift as "the host's rules"
    // would hand the operator attacker-controlled text at exactly the moment
    // they are deciding whether to intervene. It does NOT opt into approving
    // an authority-free scaffold: a show-only query must not create durable
    // authority as a side effect.
    assertApprovedDesiredBase(context, candidate, hostApprovalSubject(scope));
    const policy = desiredLayerPolicy(candidate, scope);
    const host = normalizeMutationHost(rawHost);
    const layer = scope === "local" ? "checkout-local" : "project";
    if (!policy.hosts.includes(host)) throw new CliError(`${host} is not allowlisted in ${layer} policy`);
    return { host, rule: policy.requests?.[host], scope };
  }, { allowLiveSessions: true });
}

export async function mutateDesiredHost(
  context: RuntimeContext,
  io: RuntimeIO,
  scope: DesiredHostScope,
  mutation: DesiredHostMutation,
): Promise<DesiredHostMutationResult> {
  return withDesiredPolicyTransaction(context, io, {
    approvalSubject: hostApprovalSubject(scope),
    writeSubject: `${scope} policy write`,
    transactionNoun: "host",
    prepare: () => {
      if (scope === "local") ensureCheckoutLocalPolicyExcluded(context.projectRoot, io);
    },
    plan: (before) => {
      const planned = mutatePolicy(desiredLayerPolicy(before, scope), mutation, scope);
      // Schema validation sees one layer; only the compiler resolves project and
      // local together. Compile the planned pair before the write so no host
      // mutation can persist a desired policy that later refuses to compile.
      const warnings = compiledWarnings(
        compileDesiredPolicies({ project: before.project, local: before.local }),
        compileDesiredPolicies(pairFor(before, scope, planned.policy)),
        mutation,
        planned.host,
      );
      return { ...planned, warnings };
    },
    result: ({ candidate, plan, selection }) => ({
      changed: plan.changed,
      digest: desiredLayerSubject(candidate, scope).digest,
      host: plan.host,
      scope,
      selection,
      warnings: plan.warnings,
    }),
  });
}
