import {
  canonicalDesiredNetworkPolicy,
  serviceHostRuleNarrowingIssues,
  validateDesiredNetworkPolicy,
  withRequiredDesiredNetworkPolicyVersion,
  type DesiredNetworkPolicyJson,
  type DesiredServiceHostRule,
} from "@runfree/runtime-contracts/desired-network-policy";
import { isReservedRunfreeHostname } from "@runfree/runtime-contracts/host-services";
import {
  HTTP_METHODS,
  hostRulesCommand,
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
import { remedy } from "../remedies.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { readApprovedNetworkPolicy, type ControlApprovalSelection } from "./approvals.ts";
import { captureDesiredPolicyCandidate, type DesiredPolicyCandidate } from "./candidates.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import {
  assertApprovedDesiredBase,
  desiredLayerSubject,
  desiredLayerSubjectType,
  withDesiredPolicyTransaction,
  type DesiredPolicyApprovalSubject,
  type DesiredPolicyLayer,
} from "./desired-policy-transaction.ts";
import { ensureCheckoutLocalPolicyExcluded } from "./git-exclude.ts";
import {
  assertDirectHost,
  assertServiceLayer,
  directRuleFor,
  hostRuleProviders,
  layerPolicyLabel,
  legacyDirectRuleMessage,
  namedProvider,
  otherLayer,
  resolveHostRuleOwner,
  serviceRuleFor,
  serviceSettingFor,
  unskippableServiceHostReason,
  type HostRuleOwner,
  type HostRulePair,
} from "./host-rule-owner.ts";
import { withQuiescedProject } from "./quiesce.ts";


export type DesiredHostScope = DesiredPolicyLayer;

export type DesiredHostMutation =
  | { kind: "add"; host: string; requestRule?: RequestRuleInput }
  | { kind: "remove"; host: string }
  | {
    kind: "rules";
    host: string;
    clear: boolean;
    requestRule?: RequestRuleInput;
    // Names the owning service when more than one service provides the host.
    service?: string;
    write?: WriteAction;
  };

/** Who owns a host's compiled request rule: a direct rule, a service, or nobody. */
export type HostRuleOwnerLabel = "direct" | "none" | `service:${string}`;

export type DesiredHostMutationResult = {
  // The compiled rule for the host before and after the write.
  after?: RequestPolicyJson;
  before?: RequestPolicyJson;
  changed: boolean;
  digest: string;
  host: string;
  owner: HostRuleOwnerLabel;
  ownerLayer?: DesiredHostScope;
  scope: DesiredHostScope;
  selection: ControlApprovalSelection;
  // Direct authority is one of several owners in the compiled policy, so a
  // direct edit does not always mean what it looks like. These say what the
  // compiled result actually is, for the caller to report.
  warnings: string[];
};

export type DesiredHostRulesResult = {
  // The compiled rule the proxy enforces for the host.
  enforced?: RequestPolicyJson;
  host: string;
  owner: HostRuleOwnerLabel;
  ownerLayer?: DesiredHostScope;
  scope: DesiredHostScope;
  // For a service-owned rule: the service's stored rule, and the user's
  // setting laid over it.
  serviceRule?: RequestPolicyJson;
  userSetting?: DesiredServiceHostRule;
};

const NO_RULE_FLAGS: RequestRuleInput = { readOnly: false, methods: [], pathPrefixes: [], denyGitPush: false };

function sortedMethods(methods: Iterable<HttpMethod>): HttpMethod[] {
  return Array.from(new Set(methods)).sort((left, right) => HTTP_METHODS.indexOf(left) - HTTP_METHODS.indexOf(right));
}

function hasRequestRuleFlags(input: RequestRuleInput | undefined): input is RequestRuleInput {
  return input !== undefined && (input.readOnly || input.methods.length > 0 || input.pathPrefixes.length > 0 || input.denyGitPush);
}

// The fields the given flags set. A set patches only these fields of the
// host's rule (spec §9 O-1); a field given again replaces that field.
function requestRule(input: RequestRuleInput, write?: WriteAction): DesiredServiceHostRule {
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
  let normalized: string;
  try {
    normalized = normalizeHostname(host);
  } catch (error) {
    throw new CliError(error instanceof Error ? error.message : String(error));
  }
  if (isReservedRunfreeHostname(normalized)) {
    throw new CliError(`${normalized} uses the reserved runfree.internal suffix`);
  }
  return normalized;
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

function compiledRule(compiled: ReturnType<typeof compileDesiredPolicies>, host: string): RequestPolicyJson | undefined {
  const requests = compiled.policy.requests;
  return requests !== undefined && Object.hasOwn(requests, host) ? requests[host] : undefined;
}

function compiledRuleOwner(
  compiled: ReturnType<typeof compileDesiredPolicies>,
  host: string,
): { owner: HostRuleOwnerLabel; ownerLayer?: DesiredHostScope } {
  const owner = Object.hasOwn(compiled.provenance.requests, host) ? compiled.provenance.requests[host] : undefined;
  if (owner === undefined) return { owner: "none" };
  const source = compiled.provenance.sources.requests[host] ?? "";
  return {
    owner: owner === "direct" ? "direct" : owner as `service:${string}`,
    ownerLayer: source.startsWith("local:") ? "local" : "project",
  };
}

/**
 * A direct host entry is not the only source of authority for that host, and
 * `compileDesiredPolicies` resolves the layers differently than the single
 * layer this mutation edits: services also contribute hosts, and a direct
 * request rule replaces a service-owned rule for the same host outright. Say
 * so, rather than reporting a write that did not change what the proxy
 * enforces or that silently dropped a service's request classification.
 * The `host` commands no longer create such a direct rule (spec §4.6); the
 * replace warning stays as a backstop.
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
    if (owners.length > 0) {
      const id = owners[0].slice("service:".length);
      warnings.push(`${host} is still allowlisted by ${owners.join(", ")}; disable it with: ${
        remedy.serviceDisable(id, { local: after.provenance.sources.services[id] === "local" })}`);
    } else {
      warnings.push(`${host} is still allowlisted by the other desired policy layer`);
    }
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

function patchDirectRule(policy: DesiredNetworkPolicyJson, host: string, delta: DesiredServiceHostRule): void {
  policy.requests ??= {};
  policy.requests[host] = { ...(directRuleFor(policy, host) ?? {}), ...delta };
}

function removeDirectRule(policy: DesiredNetworkPolicyJson, host: string): void {
  if (!policy.requests || directRuleFor(policy, host) === undefined) return;
  delete policy.requests[host];
  if (Object.keys(policy.requests).length === 0) delete policy.requests;
}

function editedServiceEntry(policy: DesiredNetworkPolicyJson, id: string) {
  const entry = policy.services !== undefined && Object.hasOwn(policy.services, id) ? policy.services[id] : undefined;
  // The owner was resolved in this layer, so its entry is here.
  if (!entry) throw new Error(`service ${id} is not in the edited desired policy layer`);
  return entry;
}

function patchServiceSetting(
  policy: DesiredNetworkPolicyJson,
  owner: Extract<HostRuleOwner, { kind: "service" }>,
  host: string,
  delta: DesiredServiceHostRule,
): void {
  const entry = editedServiceEntry(policy, owner.id);
  const provider = { entry, id: owner.id, layer: owner.layer };
  const next: DesiredServiceHostRule = { ...serviceSettingFor(provider, host), ...delta };
  // Named here, before any write; the schema refuses the same (spec §4.5).
  const issues = serviceHostRuleNarrowingIssues(serviceRuleFor(provider, host), next);
  if (issues.length > 0) {
    throw new CliError(
      `service ${owner.id} sets the methods or path prefixes for ${host}, and a host rule there can only narrow them: ${issues.join("; ")}`,
    );
  }
  entry.selection = { ...entry.selection, hostRules: { ...entry.selection?.hostRules, [host]: next } };
}

/**
 * `--clear` removes one thing per run, in this order (plan R7): the edited
 * layer's direct rule; else refuse while the other layer holds a direct rule
 * on this service host; else the owning service's setting. Nothing to clear
 * leaves the policy unchanged.
 */
function clearHostRule(
  pair: HostRulePair,
  policy: DesiredNetworkPolicyJson,
  scope: DesiredHostScope,
  host: string,
  service: string | undefined,
): void {
  if (directRuleFor(policy, host) !== undefined) {
    removeDirectRule(policy, host);
    return;
  }
  const providers = hostRuleProviders(pair, host);
  const named = namedProvider(providers, host, service);
  if (providers.length === 0) {
    assertDirectHost(pair, scope, host);
    return;
  }
  const other = otherLayer(scope);
  if (directRuleFor(pair[other], host) !== undefined) {
    const replaced = providers.find((provider) =>
      serviceRuleFor(provider, host) !== undefined || serviceSettingFor(provider, host) !== undefined);
    throw new CliError(replaced
      ? legacyDirectRuleMessage(host, replaced.id, other)
      : `${host} has a direct rule in the ${layerPolicyLabel(other)} desired policy; remove it with: ${
        remedy.hostRulesClear(host, { local: other === "local" })}`);
  }
  const holders = (named ? [named] : providers).filter((provider) => serviceSettingFor(provider, host) !== undefined);
  if (holders.length === 0) return;
  if (holders.length > 1) {
    throw new CliError([
      `${host} has settings in ${holders.length} services (${holders.map((provider) => provider.id).join(", ")}); name one:`,
      ...holders.map((provider) => `  ${remedy.hostRulesClear(host, { local: provider.layer === "local", service: provider.id })}`),
    ].join("\n"));
  }
  const target = holders[0];
  assertServiceLayer(target, scope, host);
  const entry = editedServiceEntry(policy, target.id);
  const hostRules = { ...entry.selection?.hostRules };
  delete hostRules[host];
  const selection = { ...entry.selection };
  delete selection.hostRules;
  const nextSelection = Object.keys(hostRules).length > 0 ? { ...selection, hostRules } : selection;
  if (Object.keys(nextSelection).length > 0) entry.selection = nextSelection;
  else delete entry.selection;
}

function serviceOnlyHostRemoveRefusal(host: string, providers: ReturnType<typeof hostRuleProviders>, scope: DesiredHostScope): CliError {
  const lines = [
    `${host} is allowlisted by ${providers.map((provider) => `service ${provider.id}`).join(", ")}, not by a host entry in ${layerPolicyLabel(scope)} policy`,
  ];
  for (const provider of providers) {
    const local = provider.layer === "local";
    lines.push(`remove the service with: ${remedy.serviceDisable(provider.id, { local })}`);
    const reason = unskippableServiceHostReason(provider.entry, host);
    if (reason) {
      lines.push(`service ${provider.id} cannot skip ${host}: ${reason}`);
      continue;
    }
    const selection = provider.entry.selection;
    lines.push(`or keep the service without this host: ${remedy.serviceEnableSkipHost(provider.id, host, {
      alreadySkipped: selection?.skippedHosts ?? [],
      local,
      writeMode: selection?.writeMode,
    })}`);
  }
  return new CliError(lines.join("\n"));
}

function mutatePolicy(
  pair: HostRulePair,
  mutation: DesiredHostMutation,
  scope: DesiredHostScope,
): { changed: boolean; host: string; policy: DesiredNetworkPolicyJson } {
  const policy = structuredClone(pair[scope]);
  const host = normalizeMutationHost(mutation.host);
  const before = canonicalDesiredNetworkPolicy(policy);
  const layer = layerPolicyLabel(scope);

  if (mutation.kind === "add") {
    const delta = hasRequestRuleFlags(mutation.requestRule) ? requestRule(mutation.requestRule) : undefined;
    if (delta) {
      // A direct rule on a service host would replace the service's rule
      // (spec §4.6, plan R5): the rule belongs with the service.
      const providers = hostRuleProviders(pair, host);
      if (providers.length > 0) {
        const provider = providers.find((candidate) =>
          serviceRuleFor(candidate, host) !== undefined || serviceSettingFor(candidate, host) !== undefined) ?? providers[0];
        const rules = [
          hostRulesCommand(host, delta).command,
          ...(provider.layer === "local" ? ["--local"] : []),
          ...(providers.length > 1 ? ["--service", provider.id] : []),
        ].join(" ");
        throw new CliError(`${host} gets its request rules from service ${provider.id}; add it without rule flags and set them with: ${rules}`);
      }
    }
    if (!policy.hosts.includes(host)) policy.hosts = [...policy.hosts, host].sort();
    if (delta) patchDirectRule(policy, host, delta);
  } else if (mutation.kind === "remove") {
    if (!policy.hosts.includes(host)) {
      const providers = hostRuleProviders(pair, host);
      if (providers.length > 0) throw serviceOnlyHostRemoveRefusal(host, providers, scope);
      throw new CliError(`${host} is not allowlisted in ${layer} policy`);
    }
    const credentials = credentialNamesForHost(policy, host);
    if (credentials.length > 0) {
      throw new CliError(`${host} is still used by ${layer} credential mappings: ${credentials.join(", ")}`);
    }
    policy.hosts = policy.hosts.filter((candidate) => candidate !== host);
    removeDirectRule(policy, host);
  } else {
    const ruleInput = mutation.requestRule;
    const hasRuleFlags = hasRequestRuleFlags(ruleInput);
    if (mutation.clear && (mutation.write !== undefined || hasRuleFlags)) {
      throw new CliError("--clear conflicts with --write and request-rule flags; clear the rules or set rules, not both");
    }
    const service = mutation.service?.toLowerCase();
    if (mutation.clear) {
      clearHostRule(pair, policy, scope, host, service);
    } else {
      const owner = resolveHostRuleOwner({ host, scope, pair, service });
      const delta = requestRule(ruleInput ?? NO_RULE_FLAGS, mutation.write);
      if (Object.keys(delta).length > 0) {
        if (owner.kind === "direct") patchDirectRule(policy, host, delta);
        else patchServiceSetting(policy, owner, host, delta);
      }
    }
  }

  // A hostRules setting needs desired policy version 4, and clearing the last
  // one lowers it again: the edited layer declares what its content needs.
  const validated = validateDesiredNetworkPolicy(withRequiredDesiredNetworkPolicyVersion(policy));
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

/**
 * The layer pair owner resolution and show read (plan R1): the edited layer
 * as captured (the caller holds it to its approved base) and the other layer
 * as approved, never its unapproved worktree file.
 */
function approvedPair(context: RuntimeContext, candidate: DesiredPolicyCandidate, scope: DesiredHostScope): HostRulePair {
  const other = otherLayer(scope);
  const approvedOther = readApprovedNetworkPolicy(context.projectRoot, context.project, desiredLayerSubjectType(other))
    ?? { version: 2 as const, hosts: [] };
  return scope === "local"
    ? { project: approvedOther, local: candidate.local }
    : { project: candidate.project, local: approvedOther };
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
    const host = normalizeMutationHost(rawHost);
    const pair = approvedPair(context, candidate, scope);
    const compiled = compileDesiredPolicies(pair);
    if (!compiled.policy.hosts.includes(host)) {
      throw new CliError(`${host} is not allowlisted in project or checkout-local policy; add it with: ${
        remedy.hostAdd(host, { local: scope === "local" })}`);
    }
    const owner = compiledRuleOwner(compiled, host);
    const enforced = compiledRule(compiled, host);
    const result: DesiredHostRulesResult = { host, scope, ...owner, ...(enforced ? { enforced } : {}) };
    if (owner.owner.startsWith("service:")) {
      const id = owner.owner.slice("service:".length);
      const provider = hostRuleProviders(pair, host).find((candidateProvider) => candidateProvider.id === id);
      const serviceRule = provider ? serviceRuleFor(provider, host) : undefined;
      const userSetting = provider ? serviceSettingFor(provider, host) : undefined;
      if (serviceRule) result.serviceRule = serviceRule;
      if (userSetting) result.userSetting = userSetting;
    }
    return result;
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
      if (scope === "local") ensureCheckoutLocalPolicyExcluded(context.projectRoot, io, context.env);
    },
    plan: (before) => {
      const planned = mutatePolicy(approvedPair(context, before, scope), mutation, scope);
      // Schema validation sees one layer; only the compiler resolves project and
      // local together. Compile the planned pair before the write so no host
      // mutation can persist a desired policy that later refuses to compile.
      const compiledBefore = compileDesiredPolicies({ project: before.project, local: before.local });
      const compiledAfter = compileDesiredPolicies(pairFor(before, scope, planned.policy));
      const warnings = compiledWarnings(compiledBefore, compiledAfter, mutation, planned.host);
      const ruleBefore = compiledRule(compiledBefore, planned.host);
      const ruleAfter = compiledRule(compiledAfter, planned.host);
      return {
        ...planned,
        ...compiledRuleOwner(compiledAfter, planned.host),
        ...(ruleBefore ? { before: ruleBefore } : {}),
        ...(ruleAfter ? { after: ruleAfter } : {}),
        warnings,
      };
    },
    result: ({ candidate, plan, selection }) => ({
      ...(plan.before ? { before: plan.before } : {}),
      ...(plan.after ? { after: plan.after } : {}),
      changed: plan.changed,
      digest: desiredLayerSubject(candidate, scope).digest,
      host: plan.host,
      owner: plan.owner,
      ...(plan.ownerLayer ? { ownerLayer: plan.ownerLayer } : {}),
      scope,
      selection,
      warnings: plan.warnings,
    }),
  });
}
