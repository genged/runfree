import {
  DEFAULT_WRITE_ACTION,
  type CredentialPolicyJson,
  type HttpMethod,
  type PolicyJson,
  type RequestPolicyJson,
  type WriteAction,
  validateNetworkPolicy,
} from "@runfree/runtime-contracts/network-policy";
import type { CompiledDesiredPolicy } from "./compiler.ts";
import { stableJsonDroppingUndefined as stableJson } from "../strict-primitives.ts";

export type ReductionComparison = {
  provenReduction: boolean;
  reasons: string[];
};


function writeRank(action: WriteAction): number {
  if (action === "allow") return 0;
  if (action === "ask") return 1;
  return 2;
}

function effectiveWriteAction(policy: PolicyJson, host: string): WriteAction {
  return policy.requests?.[host]?.writeAction ?? policy.writeApproval ?? DEFAULT_WRITE_ACTION;
}

function prefixContains(outer: string, inner: string): boolean {
  if (outer === "/" || outer === inner) return true;
  const child = outer.endsWith("/") ? outer : `${outer}/`;
  return inner.startsWith(child);
}

function nextPrefixesAreNarrower(previous: string[] | undefined, next: string[] | undefined): boolean {
  if (next === undefined) return previous === undefined;
  if (previous === undefined) return true;
  return next.every((prefix) => previous.some((oldPrefix) => prefixContains(oldPrefix, prefix)));
}

function nextMethodsAreNarrower(previous: HttpMethod[] | undefined, next: HttpMethod[] | undefined): boolean {
  if (next === undefined) return previous === undefined;
  if (previous === undefined) return true;
  const allowed = new Set(previous);
  return next.every((method) => allowed.has(method));
}

function writePrefixesAreNoWeaker(previous: string[] | undefined, next: string[] | undefined): boolean {
  if (previous === undefined) return true;
  if (next === undefined) return false;
  return previous.every((oldPrefix) => next.some((nextPrefix) => prefixContains(nextPrefix, oldPrefix)));
}

function readPrefixesAreNoWider(previous: string[] | undefined, next: string[] | undefined): boolean {
  if (next === undefined) return true;
  if (previous === undefined) return false;
  return next.every((prefix) => previous.some((oldPrefix) => prefixContains(oldPrefix, prefix)));
}

function gitPushIsNoWeaker(previous: RequestPolicyJson["gitPush"], next: RequestPolicyJson["gitPush"]): boolean {
  if (previous === next) return true;
  return previous === "write" && next === "deny";
}

function requestRuleIsNoMorePermissive(
  previousPolicy: PolicyJson,
  nextPolicy: PolicyJson,
  host: string,
  reasons: string[],
): void {
  const previous = previousPolicy.requests?.[host] ?? {};
  const next = nextPolicy.requests?.[host] ?? {};
  if (!nextMethodsAreNarrower(previous.methods, next.methods)) reasons.push(`${host}: request methods widened`);
  if (!nextPrefixesAreNarrower(previous.pathPrefixes, next.pathPrefixes)) reasons.push(`${host}: request paths widened`);
  if (writeRank(effectiveWriteAction(nextPolicy, host)) < writeRank(effectiveWriteAction(previousPolicy, host))) {
    reasons.push(`${host}: write action weakened`);
  }
  if (!readPrefixesAreNoWider(previous.readPathPrefixes, next.readPathPrefixes)) {
    reasons.push(`${host}: read classifier widened`);
  }
  if (!writePrefixesAreNoWeaker(previous.writePathPrefixes, next.writePathPrefixes)) {
    reasons.push(`${host}: write classifier weakened`);
  }
  if (!gitPushIsNoWeaker(previous.gitPush, next.gitPush)) reasons.push(`${host}: git-push classification is incomparable or weaker`);
  if (stableJson(previous.graphql) !== stableJson(next.graphql)) reasons.push(`${host}: GraphQL classification changed`);
}

function credentialKey(tokenName: string, credential: CredentialPolicyJson): string {
  return [tokenName, credential.host, credential.header.toLowerCase(), credential.scheme].join("\0");
}

function credentialMappings(policy: PolicyJson): Array<{ credential: CredentialPolicyJson; tokenName: string }> {
  return Object.entries(policy.tokens ?? {}).flatMap(([tokenName, token]) =>
    token.credentials.map((credential) => ({ tokenName, credential })));
}

function mappingIsContained(
  previous: { credential: CredentialPolicyJson; tokenName: string },
  next: { credential: CredentialPolicyJson; tokenName: string },
): boolean {
  if (credentialKey(previous.tokenName, previous.credential) !== credentialKey(next.tokenName, next.credential)) return false;
  const previousPath = previous.credential.pathPrefix;
  const nextPath = next.credential.pathPrefix;
  if (nextPath === undefined) return previousPath === undefined;
  return previousPath === undefined || prefixContains(previousPath, nextPath);
}

function compareCredentialAuthority(previous: PolicyJson, next: PolicyJson, reasons: string[]): void {
  const previousMappings = credentialMappings(previous);
  for (const mapping of credentialMappings(next)) {
    if (!previousMappings.some((candidate) => mappingIsContained(candidate, mapping))) {
      reasons.push(`${mapping.credential.host}: credential mapping added or widened for ${mapping.tokenName}`);
    }
  }
  for (const [tokenName, token] of Object.entries(next.tokens ?? {})) {
    if (token.allowAnonymous === true && previous.tokens?.[tokenName]?.allowAnonymous !== true) {
      reasons.push(`${tokenName}: anonymous credential fallback enabled`);
    }
  }
}

function compareOAuthAndAgentEnvironment(
  previous: CompiledDesiredPolicy,
  next: CompiledDesiredPolicy,
  reasons: string[],
): void {
  for (const [providerId, provider] of Object.entries(next.oauth)) {
    if (stableJson(previous.oauth[providerId]) !== stableJson(provider)) {
      reasons.push(`${providerId}: OAuth authority added or changed`);
    }
  }
  const previousEnv = new Set(previous.agentEnv);
  for (const name of next.agentEnv) {
    if (!previousEnv.has(name)) reasons.push(`${name}: agent-visible service environment added`);
  }
}

export function compareCompiledAuthority(
  previousInput: CompiledDesiredPolicy,
  nextInput: CompiledDesiredPolicy,
): ReductionComparison {
  const previous = validateNetworkPolicy(previousInput.policy).raw;
  const next = validateNetworkPolicy(nextInput.policy).raw;
  const reasons: string[] = [];
  const previousHosts = new Set(previous.hosts);
  for (const host of next.hosts) {
    if (!previousHosts.has(host)) reasons.push(`${host}: host added`);
    else requestRuleIsNoMorePermissive(previous, next, host, reasons);
  }
  if (writeRank(next.writeApproval ?? DEFAULT_WRITE_ACTION) < writeRank(previous.writeApproval ?? DEFAULT_WRITE_ACTION)) {
    reasons.push("default write action weakened");
  }
  compareCredentialAuthority(previous, next, reasons);
  compareOAuthAndAgentEnvironment(previousInput, nextInput, reasons);
  return { provenReduction: reasons.length === 0, reasons: Array.from(new Set(reasons)).sort() };
}

export function compareRuntimeIsolationAuthority(
  previous: { dependencyOverlays: string },
  next: { dependencyOverlays: string },
): ReductionComparison {
  if (previous.dependencyOverlays === next.dependencyOverlays) return { provenReduction: true, reasons: [] };
  if (previous.dependencyOverlays === "off" && next.dependencyOverlays === "auto") {
    return { provenReduction: true, reasons: [] };
  }
  return { provenReduction: false, reasons: ["dependency overlays became less isolated or changed incompatibly"] };
}
