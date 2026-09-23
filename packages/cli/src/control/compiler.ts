import {
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
  type DesiredOAuthProvider,
  type DesiredServiceEntry,
} from "@runfree/runtime-contracts/desired-network-policy";
import {
  validateNetworkPolicy,
  type PolicyJson,
  type RequestPolicyJson,
  type TokenPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import { stableJson } from "../strict-primitives.ts";

export type EffectiveControlProvenance = {
  hosts: Record<string, string[]>;
  oauth: Record<string, string>;
  requests: Record<string, string>;
  tokens: Record<string, string>;
  sources: {
    agentEnv: Record<string, string>;
    hosts: Record<string, string[]>;
    oauth: Record<string, string>;
    requests: Record<string, string>;
    services: Record<string, "local" | "project">;
    tokens: Record<string, string>;
  };
};

export type CompiledDesiredPolicy = {
  agentEnv: string[];
  oauth: Record<string, DesiredOAuthProvider>;
  policy: PolicyJson;
  provenance: EffectiveControlProvenance;
  selectedServices: Record<string, DesiredServiceEntry>;
};


/** Exact value equality for owned control entries, independent of key order. */
export function sameControlValue(left: unknown, right: unknown): boolean {
  return stableJson(left) === stableJson(right);
}

export function overlayDesiredPolicies(
  projectInput: DesiredNetworkPolicyJson,
  localInput: DesiredNetworkPolicyJson,
): DesiredNetworkPolicyJson {
  const project = validateDesiredNetworkPolicy(projectInput);
  const local = validateDesiredNetworkPolicy(localInput);
  return validateDesiredNetworkPolicy({
    version: 2,
    hosts: Array.from(new Set([...project.hosts, ...local.hosts])).sort(),
    services: { ...(project.services ?? {}), ...(local.services ?? {}) },
    requests: { ...(project.requests ?? {}), ...(local.requests ?? {}) },
    tokens: { ...(project.tokens ?? {}), ...(local.tokens ?? {}) },
    writeApproval: local.writeApproval ?? project.writeApproval,
  });
}

function assignOwned<T>(
  target: Record<string, T>,
  owners: Record<string, string>,
  key: string,
  value: T,
  owner: string,
  kind: string,
): void {
  const existingOwner = owners[key];
  if (existingOwner && !sameControlValue(target[key], value)) {
    throw new Error(`${kind} ${key} conflicts between ${existingOwner} and ${owner}`);
  }
  if (existingOwner && existingOwner !== owner) {
    throw new Error(`${kind} ${key} has duplicate owners ${existingOwner} and ${owner}`);
  }
  target[key] = value;
  owners[key] = owner;
}

export function compileDesiredPolicies(input: {
  local: DesiredNetworkPolicyJson;
  project: DesiredNetworkPolicyJson;
}): CompiledDesiredPolicy {
  const merged = overlayDesiredPolicies(input.project, input.local);
  const hosts = new Set<string>();
  const hostOrigins: Record<string, string[]> = {};
  const requests: Record<string, RequestPolicyJson> = {};
  const requestOwners: Record<string, string> = {};
  const tokens: Record<string, TokenPolicyJson> = {};
  const tokenOwners: Record<string, string> = {};
  const oauth: Record<string, DesiredOAuthProvider> = {};
  const oauthOwners: Record<string, string> = {};
  const envOwners: Record<string, string> = {};
  const serviceLayers: Record<string, "local" | "project"> = {};
  const hostSources: Record<string, string[]> = {};
  const requestSources: Record<string, string> = {};
  const tokenSources: Record<string, string> = {};
  const oauthSources: Record<string, string> = {};
  const envSources: Record<string, string> = {};

  for (const [serviceId, entry] of Object.entries(merged.services ?? {}).sort(([left], [right]) => left.localeCompare(right))) {
    const owner = `service:${serviceId}`;
    const layer = input.local.services?.[serviceId] ? "local" : "project";
    const source = `${layer}:${owner}`;
    serviceLayers[serviceId] = layer;
    for (const host of entry.resolved.hosts) {
      hosts.add(host);
      hostOrigins[host] ??= [];
      hostOrigins[host].push(owner);
      hostSources[host] ??= [];
      hostSources[host].push(source);
    }
    for (const [host, rule] of Object.entries(entry.resolved.requests ?? {})) {
      assignOwned(requests, requestOwners, host, rule, owner, "request rule");
      requestSources[host] = source;
    }
    for (const [tokenName, token] of Object.entries(entry.resolved.tokens ?? {})) {
      assignOwned(tokens, tokenOwners, tokenName, token, owner, "token");
      tokenSources[tokenName] = source;
    }
    for (const [providerId, provider] of Object.entries(entry.resolved.oauth ?? {})) {
      assignOwned(oauth, oauthOwners, providerId, provider, owner, "OAuth provider");
      oauthSources[providerId] = source;
    }
    for (const envName of entry.resolved.agentEnv ?? []) {
      const existing = envOwners[envName];
      if (existing && existing !== owner) throw new Error(`agent env ${envName} has duplicate owners ${existing} and ${owner}`);
      envOwners[envName] = owner;
      envSources[envName] = source;
    }
  }

  for (const host of merged.hosts) {
    hosts.add(host);
    hostOrigins[host] ??= [];
    hostOrigins[host].push("direct");
  }
  for (const [layer, policy] of [["project", input.project], ["local", input.local]] as const) {
    for (const host of policy.hosts) {
      hostSources[host] ??= [];
      hostSources[host].push(`${layer}:direct`);
    }
  }
  for (const [host, rule] of Object.entries(merged.requests ?? {})) {
    requests[host] = rule;
    requestOwners[host] = "direct";
    requestSources[host] = `${input.local.requests?.[host] ? "local" : "project"}:direct`;
  }
  for (const [tokenName, token] of Object.entries(merged.tokens ?? {})) {
    if (tokenOwners[tokenName]) throw new Error(`token ${tokenName} conflicts between ${tokenOwners[tokenName]} and direct`);
    tokens[tokenName] = token;
    tokenOwners[tokenName] = "direct";
    tokenSources[tokenName] = `${input.local.tokens?.[tokenName] ? "local" : "project"}:direct`;
  }

  for (const [providerId, provider] of Object.entries(oauth)) {
    const endpointHosts = [
      provider.resourceHost,
      ...provider.tokenEndpoints.map((endpoint) => endpoint.host),
      ...(provider.registrationEndpoints ?? []).map((endpoint) => endpoint.host),
    ];
    for (const host of endpointHosts) {
      if (!hosts.has(host)) throw new Error(`OAuth provider ${providerId} references host ${host} outside effective hosts`);
    }
  }

  const loaded = validateNetworkPolicy({
    hosts: Array.from(hosts).sort(),
    ...(Object.keys(requests).length > 0 ? { requests } : {}),
    ...(Object.keys(tokens).length > 0 ? { tokens } : {}),
    ...(merged.writeApproval ? { writeApproval: merged.writeApproval } : {}),
  });
  return {
    policy: loaded.raw,
    oauth: Object.fromEntries(Object.entries(oauth).sort()),
    agentEnv: Object.keys(envOwners).sort(),
    selectedServices: merged.services ?? {},
    provenance: {
      hosts: Object.fromEntries(Object.entries(hostOrigins).sort().map(([host, owners]) => [host, [...owners].sort()])),
      requests: Object.fromEntries(Object.entries(requestOwners).sort()),
      tokens: Object.fromEntries(Object.entries(tokenOwners).sort()),
      oauth: Object.fromEntries(Object.entries(oauthOwners).sort()),
      sources: {
        agentEnv: Object.fromEntries(Object.entries(envSources).sort()),
        hosts: Object.fromEntries(Object.entries(hostSources).sort().map(([host, sources]) => [host, [...new Set(sources)].sort()])),
        oauth: Object.fromEntries(Object.entries(oauthSources).sort()),
        requests: Object.fromEntries(Object.entries(requestSources).sort()),
        services: Object.fromEntries(Object.entries(serviceLayers).sort()),
        tokens: Object.fromEntries(Object.entries(tokenSources).sort()),
      },
    },
  };
}
