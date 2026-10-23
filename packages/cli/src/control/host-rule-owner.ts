// Who owns a host's request rule, for the `host` commands (spec 2026-10-23
// service host rules §4.4, §4.6, §4.8).
//
// A host's rule has exactly one owner in the compiled policy: a direct rule,
// or the one service that provides the host (its resolved rule with the
// user's `selection.hostRules` setting laid over it). The `host` commands
// write to that owner, and refuse where a write would be ambiguous, would
// create a second owner, or would land in the wrong layer.
//
// Pure: the caller passes the layer pair it resolves against — the edited
// layer's approved candidate and the other layer's approved policy (plan R1).

import type {
  DesiredNetworkPolicyJson,
  DesiredServiceEntry,
  DesiredServiceHostRule,
} from "@runfree/runtime-contracts/desired-network-policy";
import type { RequestPolicyJson } from "@runfree/runtime-contracts/network-policy";
import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import type { DesiredPolicyLayer } from "./desired-policy-transaction.ts";

export type HostRulePair = { local: DesiredNetworkPolicyJson; project: DesiredNetworkPolicyJson };

export type HostRuleOwner =
  | { kind: "direct" }
  | { kind: "service"; id: string; layer: DesiredPolicyLayer };

export type HostRuleProvider = { entry: DesiredServiceEntry; id: string; layer: DesiredPolicyLayer };

export function otherLayer(layer: DesiredPolicyLayer): DesiredPolicyLayer {
  return layer === "local" ? "project" : "local";
}

export function layerPolicyLabel(layer: DesiredPolicyLayer): string {
  return layer === "local" ? "checkout-local" : "project";
}

/** An own property of a policy record, never an inherited one such as `__proto__`. */
export function ownValue<T>(record: Readonly<Record<string, T>> | undefined, key: string): T | undefined {
  return record !== undefined && Object.hasOwn(record, key) ? record[key] : undefined;
}

export function directRuleFor(policy: DesiredNetworkPolicyJson, host: string): RequestPolicyJson | undefined {
  return ownValue(policy.requests, host);
}

export function serviceRuleFor(provider: HostRuleProvider, host: string): RequestPolicyJson | undefined {
  return ownValue(provider.entry.resolved.requests, host);
}

export function serviceSettingFor(provider: HostRuleProvider, host: string): DesiredServiceHostRule | undefined {
  return ownValue(provider.entry.selection?.hostRules, host);
}

function ownsRule(provider: HostRuleProvider, host: string): boolean {
  return serviceRuleFor(provider, host) !== undefined || serviceSettingFor(provider, host) !== undefined;
}

/**
 * The services whose resolved hosts include `host`, with a local entry
 * replacing the project entry of the same id as the compiler does.
 */
export function hostRuleProviders(pair: HostRulePair, host: string): HostRuleProvider[] {
  const merged = new Map<string, HostRuleProvider>();
  for (const [id, entry] of Object.entries(pair.project.services ?? {})) merged.set(id, { entry, id, layer: "project" });
  for (const [id, entry] of Object.entries(pair.local.services ?? {})) merged.set(id, { entry, id, layer: "local" });
  return Array.from(merged.values())
    .filter((provider) => provider.entry.resolved.hosts.includes(host))
    .sort((left, right) => left.id.localeCompare(right.id));
}

/** Today's refusal for a host the edited layer does not allow. */
export function assertDirectHost(pair: HostRulePair, scope: DesiredPolicyLayer, host: string): void {
  if (pair[scope].hosts.includes(host)) return;
  throw new CliError(
    `${host} is not allowlisted in ${layerPolicyLabel(scope)} policy; add it with: ${remedy.hostAdd(host, { local: scope === "local" })}`,
  );
}

/** Refuses a provider that `--service` names when it does not provide the host. */
export function namedProvider(providers: HostRuleProvider[], host: string, service: string | undefined): HostRuleProvider | undefined {
  if (service === undefined) return undefined;
  const named = providers.find((provider) => provider.id === service);
  if (named) return named;
  throw new CliError(providers.length === 0
    ? `service ${service} does not provide ${host}; no enabled service provides it`
    : `service ${service} does not provide ${host}; services that provide it: ${providers.map((provider) => provider.id).join(", ")}`);
}

/**
 * What the operator asked `host rules` to do, so a refusal can print the
 * same command with the owner and layer fixed: a set with the fields its
 * flags set, or a `--clear`.
 */
export type HostRulesRequest = { kind: "clear" } | { kind: "set"; delta: DesiredServiceHostRule };

/** The operator's command, aimed at `provider` in the layer that holds it. */
export function hostRulesRemedy(host: string, request: HostRulesRequest, provider: Pick<HostRuleProvider, "id" | "layer">): string {
  const options = { local: provider.layer === "local", service: provider.id };
  return request.kind === "clear" ? remedy.hostRulesClear(host, options) : remedy.hostRulesSet(host, request.delta, options);
}

/** A service's settings live in the layer that holds the service entry (§4.8). */
export function assertServiceLayer(
  provider: HostRuleProvider,
  scope: DesiredPolicyLayer,
  host: string,
  request: HostRulesRequest,
): void {
  if (provider.layer === scope) return;
  const where = `${host} gets its request rules from service ${provider.id}, which is enabled in the ${layerPolicyLabel(provider.layer)} desired policy`;
  throw new CliError(`${where}; run the command ${provider.layer === "project" ? "without" : "with"} --local: ${
    hostRulesRemedy(host, request, provider)}`);
}

export function legacyDirectRuleMessage(host: string, serviceId: string, directLayer: DesiredPolicyLayer): string {
  return `${host} has a direct rule that replaces the rule from service ${serviceId}; remove it with: ${
    remedy.hostRulesClear(host, { local: directLayer === "local" })}`;
}

/**
 * The owner a `host rules` set writes to. Refuses: a `--service` that does not
 * provide the host; a legacy direct rule that replaces a service rule (§4.6);
 * two providers without `--service`, or a `--service` beside another
 * service's rule (§4.4); a service in the other layer (§4.8, both
 * directions); a host no layer allows.
 */
export function resolveHostRuleOwner(input: {
  host: string;
  pair: HostRulePair;
  // The set being resolved; refusals repeat its flags.
  request: Extract<HostRulesRequest, { kind: "set" }>;
  scope: DesiredPolicyLayer;
  service?: string;
}): HostRuleOwner {
  const { host, pair, request, scope } = input;
  const providers = hostRuleProviders(pair, host);
  const named = namedProvider(providers, host, input.service);
  if (providers.length === 0) {
    assertDirectHost(pair, scope, host);
    return { kind: "direct" };
  }
  const ruleOwners = providers.filter((provider) => ownsRule(provider, host));
  const directLayers = ([scope, otherLayer(scope)] as const).filter((layer) => directRuleFor(pair[layer], host) !== undefined);
  if (directLayers.length > 0) {
    // R3: legacy only when a service rule is really being replaced.
    if (ruleOwners.length > 0) {
      const replaced = ruleOwners.find((provider) => provider.id === named?.id) ?? ruleOwners[0];
      throw new CliError(legacyDirectRuleMessage(host, replaced.id, directLayers[0]));
    }
    assertDirectHost(pair, scope, host);
    return { kind: "direct" };
  }
  let chosen: HostRuleProvider;
  if (named) {
    const other = ruleOwners.find((provider) => provider.id !== named.id);
    if (other) {
      throw new CliError(
        `${host} already has a request rule from service ${other.id}; a host rule has one owner, set it with: ${
          hostRulesRemedy(host, request, other)}`,
      );
    }
    chosen = named;
  } else if (providers.length > 1) {
    throw new CliError([
      `${host} is provided by ${providers.length} services (${providers.map((provider) => provider.id).join(", ")}); name the one that owns its rule:`,
      ...providers.map((provider) => `  ${hostRulesRemedy(host, request, provider)}`),
    ].join("\n"));
  } else {
    chosen = providers[0];
  }
  assertServiceLayer(chosen, scope, host, request);
  return { kind: "service", id: chosen.id, layer: chosen.layer };
}

/**
 * Why `host` cannot be skipped from a service: the resolved entry still
 * points a credential or an OAuth endpoint at it (mirrors
 * `unskippableServiceHosts` in admin/service-policy.ts, read from the stored
 * entry rather than the live definition).
 */
export function unskippableServiceHostReason(entry: DesiredServiceEntry, host: string): string | undefined {
  for (const [tokenName, token] of Object.entries(entry.resolved.tokens ?? {})) {
    if (token.credentials.some((credential) => credential.host === host)) return `it receives the ${tokenName} credential`;
  }
  for (const provider of Object.values(entry.resolved.oauth ?? {})) {
    if (provider.resourceHost === host) return "it is the OAuth resource host";
    if (provider.tokenEndpoints.some((endpoint) => endpoint.host === host)) return "it is the OAuth token endpoint";
    if ((provider.registrationEndpoints ?? []).some((endpoint) => endpoint.host === host)) return "it is the OAuth registration endpoint";
  }
  return undefined;
}
