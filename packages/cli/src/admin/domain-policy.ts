// Host typed intents + enforcement (split from options.ts). Shared policy and
// proxy machinery lives in admin-core.ts.

import {
  DEFAULT_WRITE_ACTION,
  effectiveWriteAction,
  HTTP_METHODS,
  type HttpMethod,
  httpMethodList,
  isHttpMethod,
  type LoadedNetworkPolicy,
  normalizePathPrefix,
  type PolicyJson,
  READ_ONLY_METHODS,
  type RequestPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import {
  credentialRefsForHost,
  describeRequestRules,
  die,
  type DomainExplainInput,
  loadPolicy,
  normalizeCliHost,
  policyJson,
  type RequestRuleInput,
} from "./admin-core.ts";

function sortedHttpMethods(methods: Iterable<HttpMethod>): HttpMethod[] {
  return Array.from(new Set(methods)).sort((left, right) => HTTP_METHODS.indexOf(left) - HTTP_METHODS.indexOf(right));
}

function _hasRequestRuleFlags(input: RequestRuleInput | undefined): input is RequestRuleInput {
  return input !== undefined && (input.readOnly || input.methods.length > 0 || input.pathPrefixes.length > 0 || input.denyGitPush);
}

// Enforcement: validate a typed request-rule selection and build the policy rule.
// Flag-agnostic; assumes the caller already decided a rule is intended.
function _buildRequestRule(input: RequestRuleInput, write?: RequestPolicyJson["writeAction"]): RequestPolicyJson {
  if (input.readOnly && input.methods.length > 0) {
    die("--read-only conflicts with --method; it is shorthand for --method GET --method HEAD --method OPTIONS");
  }

  const methods: HttpMethod[] = [];
  for (const methodArg of input.methods) {
    const method = methodArg.toUpperCase();
    if (!isHttpMethod(method)) die(`--method must be one of: ${httpMethodList()}`);
    methods.push(method);
  }
  if (input.readOnly) methods.push(...READ_ONLY_METHODS);

  const pathPrefixes: string[] = [];
  for (const prefixArg of input.pathPrefixes) {
    try {
      pathPrefixes.push(normalizePathPrefix(prefixArg));
    } catch (error) {
      die(`--request-path-prefix ${prefixArg}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    ...(methods.length > 0 ? { methods: sortedHttpMethods(methods) } : {}),
    ...(pathPrefixes.length > 0 ? { pathPrefixes: Array.from(new Set(pathPrefixes)).sort() } : {}),
    ...(input.denyGitPush ? { gitPush: "deny" as const } : {}),
    ...(write !== undefined ? { writeAction: write } : {}),
  };
}

// Replaces (never merges) the host's requests entry, printing the before/after
// diff so a re-run that drops rules is visible.
function _applyRequestRule(policy: PolicyJson, host: string, rule: RequestPolicyJson): { changed: boolean } {
  policy.requests ??= {};
  const before = policy.requests[host];
  const changed = policyJson(before ?? null) !== policyJson(rule);
  policy.requests[host] = rule;
  console.log(`request rules: ${changed ? (before ? "replaced" : "added") : "unchanged"}`);
  if (before) console.log(`  before: ${describeRequestRules(before)}`);
  console.log(`  after:  ${describeRequestRules(rule)}`);
  return { changed };
}

// Human-readable effective write posture with its precedence source, shown by
// `host explain` and `host rules`.
export function describeWritePosture(policy: Pick<LoadedNetworkPolicy, "requests" | "writeApproval">, host: string): string {
  const effective = effectiveWriteAction(policy, host);
  const source = policy.requests[host]?.writeAction !== undefined
    ? "per-host rule"
    : policy.writeApproval !== undefined
      ? "project writeApproval"
      : `built-in default ${DEFAULT_WRITE_ACTION}`;
  return `${effective} (${source})`;
}

export function domainList(): void {
  const policy = loadPolicy();
  for (const host of [...policy.raw.hosts].sort()) console.log(host);
}

export function domainExplainIntent(input: DomainExplainInput): void {
  const host = normalizeCliHost(input.host);
  const policy = loadPolicy();
  const allowlisted = policy.raw.hosts.includes(host);
  const credentialRefs = credentialRefsForHost(policy.raw, host);

  if (!allowlisted) {
    console.log(`${host} is not allowlisted`);
    console.log(`add it with: runfree host add ${host}`);
    return;
  }

  console.log(`${host} is allowlisted`);
  if (credentialRefs.length > 0) {
    for (const { tokenName, credential } of credentialRefs) {
      console.log(`credential: ${tokenName} -> ${credential.header} (${credential.scheme})`);
    }
  } else {
    console.log("credential: none");
  }
  console.log(`request rules: ${describeRequestRules(policy.requests[host])}`);
  console.log(`write action: ${describeWritePosture(policy, host)}`);
}
