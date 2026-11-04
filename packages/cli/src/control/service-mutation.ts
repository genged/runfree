import {
  canonicalDesiredNetworkPolicy,
  overlayServiceHostRule,
  serviceHostRuleGitPushFits,
  serviceHostRuleNarrowingIssues,
  validateDesiredNetworkPolicy,
  withRequiredDesiredNetworkPolicyVersion,
  type DesiredNetworkPolicyJson,
  type DesiredServiceEntry,
  type DesiredServiceHostRule,
} from "@runfree/runtime-contracts/desired-network-policy";
import type { RequestPolicyJson, TokenPolicyJson, WriteAction } from "@runfree/runtime-contracts/network-policy";
import { describeCredential } from "../admin/credential-describe.ts";
import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
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
import { layerPolicyLabel, legacyDirectRuleMessage, otherLayer, ownValue } from "./host-rule-owner.ts";
import { PROJECT_RUNFREE_PATHS } from "../runfree-consumer-registry.ts";
import type { DesiredPolicyCandidate } from "./candidates.ts";

export type DesiredServiceLayer = DesiredPolicyLayer;
export type DesiredServiceMutation =
  // `sourceArgs` repeats the operator's credential-source flags in remedies.
  | { kind: "enable"; id: string; entry: DesiredServiceEntry; sourceArgs?: string }
  | { kind: "disable"; id: string };

export type DesiredServiceMutationResult = {
  changed: boolean;
  id: string;
  layer: DesiredServiceLayer;
  layerDigest: string;
  // Stdout lines: a direct rule the service took over (spec §4.6).
  notices: string[];
  selection: ControlApprovalSelection;
  // `runfree warning:` lines: a direct rule that still replaces the service rule.
  warnings: string[];
};

export type DesiredServiceReconciliation = {
  changed: boolean;
  id: string;
  notices: string[];
  policy: DesiredNetworkPolicyJson;
  /** Direct rules this enable deleted because the service took them over. */
  takenOver: Array<{ direct: RequestPolicyJson; host: string }>;
  warnings: string[];
};

// Both refusals use the bare layer name for this family.
function serviceApprovalSubject(layer: DesiredServiceLayer): DesiredPolicyApprovalSubject {
  return { layer, missingBaseSubject: `${layer} desired policy`, driftSubject: `${layer} desired policy` };
}

/**
 * Why a saved `selection.hostRules` setting cannot ride along into
 * `nextEntry` (spec §4.5, §4.7): its host is skipped or no longer in the
 * service, or it is broader than the service's new OAuth token-host rule.
 * Each issue names the clear that reclaims it.
 */
export function serviceHostRulesFitIssues(
  idInput: string,
  hostRules: Readonly<Record<string, DesiredServiceHostRule>>,
  nextEntry: DesiredServiceEntry,
  options: { local?: boolean } = {},
): string[] {
  const id = idInput.toLowerCase();
  const issues: string[] = [];
  for (const host of Object.keys(hostRules).sort()) {
    const clear = remedy.hostRulesClear(host, { local: options.local, service: id });
    if (!nextEntry.resolved.hosts.includes(host)) {
      issues.push((nextEntry.selection?.skippedHosts ?? []).includes(host)
        ? `--skip-host ${host} cannot skip ${host} in service ${id}: it has a host rule setting; remove it first with: ${clear}`
        : `service ${id} revision ${nextEntry.revision} no longer allows ${host}, which has a host rule setting; remove it first with: ${clear}`);
      continue;
    }
    const serviceRule = ownValue(nextEntry.resolved.requests, host);
    if (!serviceHostRuleGitPushFits(serviceRule, hostRules[host])) {
      issues.push(`service ${id} revision ${nextEntry.revision} has no git handling for ${host}, which has a --deny-git-push setting; remove it with: ${clear}`);
      continue;
    }
    const narrowing = serviceHostRuleNarrowingIssues(serviceRule, hostRules[host]);
    if (narrowing.length > 0) {
      issues.push(`the host rule setting for ${host} is broader than service ${id} revision ${nextEntry.revision} allows (${
        narrowing.join("; ")}); remove it with: ${clear}`);
    }
  }
  return issues;
}

/** Refuses, before any write, a saved setting the next entry cannot hold. */
export function assertServiceHostRulesFit(
  id: string,
  hostRules: Readonly<Record<string, DesiredServiceHostRule>> | undefined,
  nextEntry: DesiredServiceEntry,
  options: { local?: boolean } = {},
): void {
  if (hostRules === undefined) return;
  const issues = serviceHostRulesFitIssues(id, hostRules, nextEntry, options);
  if (issues.length > 0) throw new CliError(issues.join("\n"));
}

// Most to least restrictive. A per-host write setting outranks the service's
// write mode (spec §4.3), so one that is weaker than the mode deserves a word.
const WRITE_ACTION_RANK: Readonly<Record<WriteAction, number>> = { deny: 0, ask: 1, allow: 2 };

/**
 * Warnings for carried `hostRules` write settings weaker than the write
 * action the entry's write mode stamps on that host (S2): the per-host
 * setting wins, so the service-wide mode does not hold there.
 */
export function weakerHostWriteSettingWarnings(
  idInput: string,
  hostRules: Readonly<Record<string, DesiredServiceHostRule>>,
  entry: DesiredServiceEntry,
  options: { local?: boolean } = {},
): string[] {
  const id = idInput.toLowerCase();
  const mode = entry.selection?.writeMode;
  if (mode === undefined) return [];
  const warnings: string[] = [];
  for (const host of Object.keys(hostRules).sort()) {
    const own = hostRules[host].writeAction;
    const service = ownValue(entry.resolved.requests, host)?.writeAction;
    if (own === undefined || service === undefined || WRITE_ACTION_RANK[own] <= WRITE_ACTION_RANK[service]) continue;
    warnings.push(`${host} keeps its own write setting (${own}) from host rules, which is weaker than service ${id}'s ${mode} write mode; remove it with: ${
      remedy.hostRulesClear(host, { local: options.local, service: id })}`);
  }
  return warnings;
}

// The fields of a request rule that restrict requests, as opposed to the
// fields that only classify them (spec §4.2).
function hasPermissionField(rule: RequestPolicyJson): boolean {
  return rule.methods !== undefined || rule.pathPrefixes !== undefined || rule.writeAction !== undefined || rule.gitPush === "deny";
}

/**
 * Direct rules in `policy` on the service's hosts that replace the service's
 * rule (compiler.ts applies direct rules last). Pure: callers decide what to
 * do with each.
 */
function directRulesOverService(
  policy: DesiredNetworkPolicyJson,
  entry: DesiredServiceEntry,
): Array<{ direct: RequestPolicyJson; host: string; serviceRule: RequestPolicyJson }> {
  const found: Array<{ direct: RequestPolicyJson; host: string; serviceRule: RequestPolicyJson }> = [];
  for (const host of entry.resolved.hosts) {
    const direct = ownValue(policy.requests, host);
    if (direct === undefined) continue;
    const serviceRule = overlayServiceHostRule(ownValue(entry.resolved.requests, host), ownValue(entry.selection?.hostRules, host));
    // R3: a direct rule on a service host the service sets no rule for is an
    // ordinary direct rule, not a replacement.
    if (serviceRule === undefined) continue;
    found.push({ direct, host, serviceRule });
  }
  return found;
}

/** Warnings for direct rules in the layer this mutation does not edit. */
export function otherLayerDirectRuleWarnings(
  id: string,
  other: DesiredNetworkPolicyJson,
  otherLayerName: DesiredPolicyLayer,
  entry: DesiredServiceEntry | undefined,
): string[] {
  if (entry === undefined) return [];
  return directRulesOverService(other, entry).map(({ host }) => legacyDirectRuleMessage(host, id, otherLayerName));
}

/**
 * S4: a checkout-local entry replaces the project entry of the same id in the
 * compiled policy, so the project entry's `host rules` settings stop applying.
 */
export function shadowedProjectHostRulesWarnings(id: string, project: DesiredNetworkPolicyJson): string[] {
  const hosts = Object.keys(ownValue(project.services, id)?.selection?.hostRules ?? {}).sort();
  if (hosts.length === 0) return [];
  return [`service ${id} in the ${layerPolicyLabel("local")} desired policy replaces the project entry, so its host rule settings for ${
    hosts.join(", ")} no longer apply; remove the local entry with: ${remedy.serviceDisable(id, { local: true })}`];
}

// Where and how a token is sent: every field but its description. Credential
// order counts: the proxy applies a host's mappings in list order.
function sameTokenDestination(left: TokenPolicyJson, right: TokenPolicyJson): boolean {
  return (left.allowAnonymous === true) === (right.allowAnonymous === true)
    && sameControlValue(left.credentials, right.credentials);
}

/**
 * The refusal for a direct token the enabling service cannot take over: a
 * side-by-side of both destination sets, where the direct token lives, and
 * the choices that reclaim it.
 */
export function directTokenConflictMessage(input: {
  direct: TokenPolicyJson;
  entry: DesiredServiceEntry;
  id: string;
  layer: DesiredPolicyLayer;
  service: TokenPolicyJson;
  sourceArgs?: string;
  tokenName: string;
}): string {
  const { direct, entry, id, layer, service, tokenName } = input;
  const key = (credential: TokenPolicyJson["credentials"][number]) => JSON.stringify([
    credential.host, credential.header, credential.scheme, credential.username, credential.pathPrefix, credential.protocol,
  ]);
  const directKeys = new Set(direct.credentials.map(key));
  const serviceKeys = new Set(service.credentials.map(key));
  const rows: Array<[string, string, string]> = [];
  const seen = new Set<string>();
  for (const credential of [...service.credentials, ...direct.credentials]) {
    const k = key(credential);
    if (seen.has(k)) continue;
    seen.add(k);
    rows.push([describeCredential(credential), directKeys.has(k) ? "yes" : "-", serviceKeys.has(k) ? "yes" : "-"]);
  }
  const anonymous = (token: TokenPolicyJson) => token.allowAnonymous === true ? "sent anonymously" : "refused";
  if ((direct.allowAnonymous === true) !== (service.allowAnonymous === true)) {
    rows.push(["requests with no token stored", anonymous(direct), anonymous(service)]);
  }
  const header: [string, string, string] = ["destination", "direct", `service ${id}`];
  const widths = [0, 1, 2].map((column) => Math.max(...[header, ...rows].map((row) => row[column].length)));
  const render = (row: [string, string, string]) =>
    `    ${row[0].padEnd(widths[0])}   ${row[1].padEnd(widths[1])}   ${row[2]}`.trimEnd();
  const sameSet = directKeys.size === serviceKeys.size && [...directKeys].every((k) => serviceKeys.has(k));
  const local = layer === "local";
  const file = local ? PROJECT_RUNFREE_PATHS.networkPolicyLocal : PROJECT_RUNFREE_PATHS.networkPolicy;
  const retry = {
    local,
    skippedHosts: entry.selection?.skippedHosts,
    sourceArgs: input.sourceArgs,
  };
  // A direct token in the checkout-local layer has no `credential` command;
  // it is edited by hand.
  const removeDirect = local ? `remove tokens.${tokenName} from ${file}` : remedy.credentialRemove(tokenName);
  const writeMode = entry.selection?.writeMode;
  return [
    `token ${tokenName} conflicts with service ${id}`,
    `  the ${layerPolicyLabel(layer)} layer (${file}) already defines token ${tokenName} directly,`,
    sameSet
      ? `  and service ${id} sends it differently:`
      : `  and service ${id} would send it to different destinations:`,
    "",
    render(header),
    ...rows.map(render),
    ...(sameSet && rows.every((row) => row[1] === row[2]) ? ["    (the same destinations in a different order)"] : []),
    "",
    `  direct token description: ${JSON.stringify(direct.description)}`,
    "",
    "  choose one:",
    `    keep the direct token and leave service ${id} off:`,
    `      nothing to do; allow other hosts with: ${remedy.hostAdd("<host>", { local })}`,
    `    let service ${id} own the token:`,
    `      ${removeDirect}`,
    `      ${remedy.serviceEnableRetry(id, { ...retry, writeMode })}`,
    ...(writeMode === "read-only" ? [] : [
      "    the same, with writes refused:",
      `      ${removeDirect}`,
      `      ${remedy.serviceEnableRetry(id, { ...retry, writeMode: "read-only" })}`,
    ]),
    "",
    `  full service definition: ${remedy.serviceExplain(id)}`,
  ].join("\n");
}

export function reconcileDesiredService(
  current: DesiredNetworkPolicyJson,
  mutation: DesiredServiceMutation,
  options: { layer?: DesiredPolicyLayer; keepDirect?: ReadonlySet<string> } = {},
): DesiredServiceReconciliation {
  const layer = options.layer ?? "project";
  const policy = structuredClone(validateDesiredNetworkPolicy(current));
  const id = mutation.id.toLowerCase();
  const before = canonicalDesiredNetworkPolicy(policy);
  const warnings: string[] = [];
  const notices: string[] = [];
  const takenOver: Array<{ direct: RequestPolicyJson; host: string }> = [];
  if (mutation.kind === "enable") {
    const entry = structuredClone(mutation.entry);
    // A re-enable rebuilds the entry from its own flags; the user's per-host
    // settings are the one selection field carried across (spec §4.7). A
    // setting the new entry cannot hold refuses here, in plan, before any
    // write or host-state bind. The settings come from the policy read under
    // the lock, never from the planned entry: `service diff --apply` plans
    // before it takes the lock, and a `host rules` change approved in between
    // must not be reverted to the planned copy.
    const hostRules = ownValue(policy.services, id)?.selection?.hostRules;
    if (entry.selection?.hostRules !== undefined) {
      const { hostRules: _planned, ...selection } = entry.selection;
      if (Object.keys(selection).length > 0) entry.selection = selection;
      else delete entry.selection;
    }
    if (hostRules !== undefined) {
      assertServiceHostRulesFit(id, hostRules, entry, { local: layer === "local" });
      entry.selection = { ...entry.selection, hostRules: structuredClone(hostRules) };
      warnings.push(...weakerHostWriteSettingWarnings(id, hostRules, entry, { local: layer === "local" }));
    }
    policy.services = { ...(policy.services ?? {}), [id]: entry };
    // Spec §4.6, O-2: a same-layer direct rule equal to the service's rule is
    // the service's rule written by hand, so the service takes it over (the
    // hosts entry stays: it only allows the host). Only a rule of
    // classification fields moves: one that carries a permission field (a
    // restriction) stays direct, because a takeover would let `service
    // disable` remove that restriction while the host stays allowed. A rule
    // that stays still replaces the service rule; warn, never refuse, so a
    // project with such a rule can still upgrade its services.
    // `keepDirect` names hosts where the caller found that the other layer
    // would change the enforced rule if this one were deleted
    // (unsafeServiceTakeovers).
    for (const { direct, host, serviceRule } of directRulesOverService(policy, entry)) {
      if (!options.keepDirect?.has(host) && !hasPermissionField(direct) && sameControlValue(direct, serviceRule)) {
        delete policy.requests?.[host];
        takenOver.push({ direct, host });
        notices.push(`${host}: the direct rule matched service ${id}'s rule and now belongs to the service; service disable removes it`);
      } else {
        warnings.push(legacyDirectRuleMessage(host, id, layer));
      }
    }
    if (policy.requests && Object.keys(policy.requests).length === 0) delete policy.requests;
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
        if (!sameTokenDestination(direct, token)) {
          throw new CliError(directTokenConflictMessage({
            direct,
            entry,
            id,
            layer,
            service: token,
            sourceArgs: mutation.sourceArgs,
            tokenName,
          }));
        }
        if (direct.description !== token.description) {
          notices.push(`token ${tokenName}: the direct token had the same destinations as service ${id} and now belongs to the service; its description changes to ${
            JSON.stringify(token.description)}; service disable removes it`);
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
  // A service entry can bring v3 fields (basic, username, protocol); the
  // candidate declares what its content needs.
  const validated = validateDesiredNetworkPolicy(withRequiredDesiredNetworkPolicyVersion(policy));
  return {
    changed: canonicalDesiredNetworkPolicy(validated) !== before,
    id,
    notices,
    policy: validated,
    takenOver,
    warnings,
  };
}

/**
 * Hosts whose takeover would change the enforced rule once the other layer
 * is compiled in: a same-id local entry that replaces the project entry, or a
 * direct rule in the other layer that the deleted one was overriding. A
 * policy pair that does not compile counts as unsafe.
 */
export function unsafeServiceTakeovers(
  planned: DesiredServiceReconciliation,
  layer: DesiredPolicyLayer,
  others: readonly DesiredNetworkPolicyJson[],
): Set<string> {
  const unsafe = new Set<string>();
  const enforced = (edited: DesiredNetworkPolicyJson, other: DesiredNetworkPolicyJson, host: string) =>
    ownValue(compileDesiredPolicies(layer === "project" ? { project: edited, local: other } : { project: other, local: edited })
      .policy.requests, host);
  for (const { direct, host } of planned.takenOver) {
    const restored = structuredClone(planned.policy);
    restored.requests = { ...restored.requests, [host]: direct };
    for (const other of others) {
      try {
        if (!sameControlValue(enforced(planned.policy, other, host), enforced(restored, other, host))) unsafe.add(host);
      } catch {
        unsafe.add(host);
      }
    }
  }
  return unsafe;
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
  return withDesiredPolicyTransaction<DesiredServiceReconciliation, DesiredServiceMutationResult>(context, io, {
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
      if (layer === "local") ensureCheckoutLocalPolicyExcluded(context.projectRoot, io, context.env);
    },
    plan: (before) => {
      const other = otherLayer(layer);
      const approvedOther = approvedPolicies()[other];
      const current = desiredLayerPolicy(before, layer);
      let planned = reconcileDesiredService(current, mutation, { layer });
      // A takeover must leave the enforced rule as it was. Either copy of the
      // other layer counts: skipping a takeover is the conservative choice
      // when the two disagree.
      const keepDirect = unsafeServiceTakeovers(planned, layer, [approvedOther, desiredLayerPolicy(before, other)]);
      if (keepDirect.size > 0) planned = reconcileDesiredService(current, mutation, { layer, keepDirect });
      // Schema validation alone cannot see cross-layer ownership: only the
      // compiler resolves project and local together. Compile the planned pair
      // before the write so no mutation can persist a desired policy that later
      // refuses to compile and wedges every command that reads effective control.
      compileDesiredPolicies({
        project: layer === "project" ? planned.policy : before.project,
        local: layer === "local" ? planned.policy : before.local,
      });
      // The other layer is read from its approval, as the host commands
      // resolve owners (plan R1): its direct rules are not this write's to
      // take over, so they only warn.
      const enabled = mutation.kind === "enable" ? ownValue(planned.policy.services, planned.id) : undefined;
      return {
        ...planned,
        warnings: [
          ...planned.warnings,
          ...otherLayerDirectRuleWarnings(planned.id, approvedOther, other, enabled),
          ...(layer === "local" && enabled ? shadowedProjectHostRulesWarnings(planned.id, approvedOther) : []),
        ],
      };
    },
    result: ({ candidate, plan, selection }) => {
      return {
        changed: plan.changed,
        id: plan.id,
        layer,
        layerDigest: desiredLayerSubject(candidate, layer).digest,
        notices: plan.notices,
        selection,
        warnings: plan.warnings,
      };
    },
  });
}
