// Service typed intents + enforcement (split from options.ts). Shared policy,
// token store, and OAuth-mediation machinery lives in admin-core.ts.

import {
  cancel as clackCancel,
  confirm as clackConfirm,
  intro,
  isCancel,
  log as clackLog,
  multiselect,
  outro,
  select,
  text as clackText,
} from "@clack/prompts";
import {
  sanitizeForTerminal,
} from "../../../../scripts/domain-diagnostics.ts";
import {
  isUserServiceId,
  RUNFREE_PLACEHOLDER_VALUE,
  service,
  type Service,
  type ServiceParameter,
  serviceBroadHosts,
  serviceHasCredential,
  serviceHasOAuthCredential,
  serviceHostNames,
  serviceNames,
  serviceParameters,
} from "../../../../scripts/services.ts";
import {
  canonicalUserServiceId,
  destinationPathForUserService,
  displayUserServicePath,
  loadUserServiceCatalog,
  lookupUserService,
  readUserServiceImportSource,
  removeUserServiceDefinition,
  validateUserServiceDefinitionObject,
  writeUserServiceDefinition,
  type LoadedUserServiceDefinition,
} from "../user-services.ts";
import {
  warn,
} from "../warnings.ts";
import type {
  DesiredServiceEntry,
  DesiredServiceParameter,
  DesiredServiceResolved,
} from "@runfree/runtime-contracts/desired-network-policy";
import type {
  CredentialPolicyJson,
  HttpMethod,
  RequestPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import {
  withTokenStoreLock,
  readOAuthSeedHandleStore,
  saveOAuthSeedHandleStore,
  saveTokenConfig,
  removeAgentEnvValues,
  saveAgentEnv,
  assertTokenSourceCanBeSaved,
  childEnv,
  describeCredential,
  die,
  loadServiceRecords,
  loadTokenConfig,
  readAgentEnv,
  readOnePasswordRef,
  resolveHostExecutable,
  saveTokenSource,
  saveUserServiceTokenSource,
  isUserServiceOwnedTokenSource,
  type ServiceConfigureInput,
  type ServiceDefineInput,
  type ServiceEnableInput,
  type ServiceUndefineInput,
  serviceOAuthAgentSeedEnv,
  serviceOAuthProviderId,
  type ServiceWriteMode,
  setAgentEnvValues,
  tokenEndpointParts,
  type TokenSource,
  tokenSourceFromSelection,
  currentAdminState,
} from "./admin-core.ts";
import { sha256Digest } from "../strict-primitives.ts";
import { compileDesiredPolicies } from "../control/compiler.ts";
import type { DesiredPolicyCandidate } from "../control/candidates.ts";
import { remedy } from "../remedies.ts";


type ResolvedService = {
  svc: Service;
  origin: "registry" | "user";
  path?: string;
  digest?: string;
  loaded?: LoadedUserServiceDefinition;
};

function adminProjectRoot(): string {
  return currentAdminState().projectRoot;
}

function adminEnv(): NodeJS.ProcessEnv {
  return currentAdminState().env.child;
}

function userCatalog() {
  return loadUserServiceCatalog(adminProjectRoot(), adminEnv());
}

function resolveService(id: string): ResolvedService | undefined {
  const normalized = id.toLowerCase();
  if (isUserServiceId(normalized)) {
    const loaded = lookupUserService(adminProjectRoot(), adminEnv(), normalized);
    if (!loaded) return undefined;
    if ("reason" in loaded) die(`invalid user-defined service ${normalized}: ${loaded.reason}`);
    return { svc: loaded.svc, origin: "user", path: loaded.path, digest: loaded.digest, loaded };
  }
  const svc = service(normalized);
  return svc ? { svc, origin: "registry" } : undefined;
}

function knownServiceNames(): string[] {
  return [...serviceNames(), ...Object.keys(userCatalog().services)].sort();
}

function userOriginBanner(resolved: ResolvedService): string[] {
  if (resolved.origin !== "user") return [];
  return [
    `origin: user-defined (${displayUserServicePath(resolved.path ?? "", adminEnv())} — not curated by Runfree; hosts and credential mapping are author-supplied)`,
  ];
}

function validateSkipHosts(svc: Service, skipHosts: string[]): string[] {
  const hostSet = new Set(serviceHostNames(svc));
  const normalized = Array.from(new Set(skipHosts.map((host) => host.toLowerCase()))).sort();
  for (const host of normalized) {
    if (!hostSet.has(host)) die(`--skip-host ${host} is not a host in service ${svc.id}`);
  }
  return normalized;
}

/**
 * Hosts a service's credential wiring names directly. Skipping one drops the
 * host from the allowlist while the credential link or OAuth endpoint keeps
 * pointing at it, which is an entry that cannot compile: a credential on a
 * non-allowlisted host, or an OAuth provider outside the effective hosts.
 * Refuse the selection here, where the flag that caused it can be named.
 */
function unskippableServiceHosts(svc: Service): Map<string, string> {
  const reasons = new Map<string, string>();
  if (serviceHasCredential(svc)) {
    for (const credential of svc.credential.credentials) {
      reasons.set(credential.host, `it receives the ${svc.credential.tokenName} credential`);
    }
  }
  if (serviceHasOAuthCredential(svc)) {
    reasons.set(svc.oauthCredential.resourceHost, "it is the OAuth resource host");
    reasons.set(tokenEndpointParts(svc.oauthCredential.tokenEndpoint).host, "it is the OAuth token endpoint");
  }
  return reasons;
}

/** Reject a final skip selection, however it was assembled, that would strand credential wiring. */
function assertSkippableHosts(svc: Service, skippedHosts: string[], skipBroad: boolean): void {
  const unskippable = unskippableServiceHosts(svc);
  const broad = new Set(serviceBroadHosts(svc).map((host) => host.host));
  for (const host of skippedHosts) {
    const reason = unskippable.get(host);
    if (!reason) continue;
    const flag = skipBroad && broad.has(host) ? "--skip-broad" : `--skip-host ${host}`;
    die(`${flag} cannot skip ${host} in service ${svc.id}: ${reason}. Disable the service instead, or enable it without that flag.`);
  }
}

// Expansion of the maintainer read-only profile plus the tri-state selection
// into per-host request-rule fields. Profile refinements (POST-read prefixes,
// git handling, GraphQL endpoints) are stamped on every enable so the write
// classifier is precise under any ask/deny posture (MED-6); writeAction is
// stamped only when the user picked --read-only or --allow-write.
function serviceWriteRuleFields(svc: Service, host: string, mode: ServiceWriteMode | undefined): RequestPolicyJson {
  const fields: RequestPolicyJson = {};
  if (mode === "read-only") fields.writeAction = "deny";
  if (mode === "allow-write") fields.writeAction = "allow";
  const profile = svc.readOnly?.[host];
  if (profile) {
    if (profile.readPathPrefixes) fields.readPathPrefixes = [...profile.readPathPrefixes].sort();
    if (profile.writePathPrefixes) fields.writePathPrefixes = [...profile.writePathPrefixes].sort();
    if (profile.gitPush) fields.gitPush = profile.gitPush;
    if (profile.graphql) fields.graphql = { endpoints: [...profile.graphql.endpoints].sort(), writeOps: "mutation" };
  }
  return fields;
}

export type DesiredServicePolicy = {
  hosts: string[];
  requestRules: Record<string, RequestPolicyJson>;
  credential?: {
    tokenName: string;
    description: string;
    allowAnonymous: boolean;
    links: CredentialPolicyJson[];
    agentEnv: string[];
  };
};

// Pure projection of a trusted service definition plus the descriptive choices
// retained in project state. The proxy still receives only ordinary policy;
// service identity never crosses the host-side compiler boundary.
export function desiredServicePolicy(
  svc: Service,
  record: { skippedHosts?: string[]; writeMode?: ServiceWriteMode } = {},
): DesiredServicePolicy {
  const skipped = new Set(record.skippedHosts ?? []);
  const hosts = serviceHostNames(svc).filter((host) => !skipped.has(host)).sort();
  const requestRules: Record<string, RequestPolicyJson> = {};
  const oauthEndpoint = serviceHasOAuthCredential(svc)
    ? tokenEndpointParts(svc.oauthCredential.tokenEndpoint)
    : undefined;
  for (const host of hosts) {
    const rule = oauthEndpoint?.host === host
      ? { methods: ["POST"] as HttpMethod[], pathPrefixes: [oauthEndpoint.path] }
      : serviceWriteRuleFields(svc, host, record.writeMode ?? svc.defaultWriteMode);
    if (Object.keys(rule).length > 0) requestRules[host] = rule;
  }
  return {
    hosts,
    requestRules,
    ...(serviceHasCredential(svc)
      ? {
          credential: {
            tokenName: svc.credential.tokenName,
            description: svc.credential.tokenDescription,
            allowAnonymous: svc.credential.allowAnonymous === true,
            links: [...svc.credential.credentials].sort((left, right) => credentialIdentity(left).localeCompare(credentialIdentity(right))),
            agentEnv: [...svc.credential.agentEnv].sort(),
          },
        }
      : {}),
  };
}

function serviceDefinitionDigest(svc: Service, sourceDigest?: string): string {
  if (sourceDigest) return sourceDigest;
  return sha256Digest(stableServiceDiffJson(svc));
}

/**
 * Resolve a registry service into the complete, immutable authoring payload
 * stored in desired policy v2. Runtime compilation consumes only this block;
 * it never reinterprets the live registry.
 */
export function desiredServiceEntry(
  svc: Service,
  selection: { skippedHosts?: string[]; writeMode?: ServiceWriteMode } = {},
  sourceDigest?: string,
): DesiredServiceEntry {
  const projected = desiredServicePolicy(svc, selection);
  const tokens: NonNullable<DesiredServiceResolved["tokens"]> = {};
  if (projected.credential) {
    tokens[projected.credential.tokenName] = {
      description: projected.credential.description,
      credentials: projected.credential.links,
      ...(projected.credential.allowAnonymous ? { allowAnonymous: true } : {}),
    };
  }
  if (serviceHasOAuthCredential(svc)) {
    for (const seed of svc.oauthCredential.seeds) {
      tokens[seed.tokenName] = { description: seed.description, credentials: [] };
    }
  }

  const oauth = serviceHasOAuthCredential(svc)
    ? {
        [serviceOAuthProviderId(svc)]: {
          resourceHost: svc.oauthCredential.resourceHost,
          ...(svc.oauthCredential.resourcePathPrefix
            ? { resourcePathPrefix: svc.oauthCredential.resourcePathPrefix }
            : {}),
          tokenEndpoints: [tokenEndpointParts(svc.oauthCredential.tokenEndpoint)],
          seeds: svc.oauthCredential.seeds.map((seed) => ({
            description: seed.description,
            envVar: seed.envVar,
            field: seed.field,
            tokenName: seed.tokenName,
          })),
        },
      }
    : undefined;
  const parameters: DesiredServiceParameter[] = serviceParameters(svc)
    .map((parameter) => ({
      description: parameter.description,
      envVar: parameter.envVar,
      key: parameter.key,
      ...(parameter.oauthField ? { oauthField: parameter.oauthField } : {}),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
  const agentEnv = Array.from(new Set([
    ...(projected.credential?.agentEnv ?? []),
    ...(serviceHasOAuthCredential(svc) ? svc.oauthCredential.seeds.map((seed) => seed.envVar) : []),
    ...parameters.map((parameter) => parameter.envVar),
  ])).sort();
  const normalizedSelection = {
    ...(selection.writeMode ? { writeMode: selection.writeMode } : {}),
    ...(selection.skippedHosts && selection.skippedHosts.length > 0
      ? { skippedHosts: [...selection.skippedHosts].sort() }
      : {}),
  };

  return {
    definitionDigest: serviceDefinitionDigest(svc, sourceDigest),
    revision: svc.revision,
    ...(Object.keys(normalizedSelection).length > 0 ? { selection: normalizedSelection } : {}),
    resolved: {
      hosts: projected.hosts,
      ...(Object.keys(projected.requestRules).length > 0 ? { requests: projected.requestRules } : {}),
      ...(Object.keys(tokens).length > 0 ? { tokens } : {}),
      ...(oauth ? { oauth } : {}),
      ...(parameters.length > 0 ? { parameters } : {}),
      ...(agentEnv.length > 0 ? { agentEnv } : {}),
    },
  };
}

export type DesiredServiceEnablePlan = {
  entry: DesiredServiceEntry;
  id: string;
  origin: ResolvedService["origin"];
  // Resolved declared-parameter values keyed by agent env name; complete and
  // validated, or the plan was refused.
  parameterValues: Record<string, string>;
  service: Service;
  skippedHosts: string[];
  source?: TokenSource;
  sourceItemRef?: string;
  sourceItemBindings?: Array<{ name: string; source: TokenSource }>;
  writeMode?: ServiceWriteMode;
};

export type ServiceParameterSource = "flag" | "1password-item" | "host-env" | "existing";

export type ServiceParameterResolution = {
  // envVar -> validated value
  values: Record<string, string>;
  // envVar -> where the value came from
  sources: Record<string, ServiceParameterSource>;
  missing: ServiceParameter[];
  invalid: Array<{ parameter: ServiceParameter; source: ServiceParameterSource; reason: string }>;
};

// One agent env line per value: C0/C1 controls and the Unicode line/paragraph
// separators (which JS `.` does not match, so the line parsers would refuse
// the file afterwards) are rejected before anything is written.
function validateParameterValue(parameter: ServiceParameter, value: string): string | undefined {
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value)) return "value contains control or line-separator characters";
  if (parameter.pattern !== undefined && !new RegExp(parameter.pattern).test(value)) {
    return `value must match ${parameter.pattern}${parameter.example ? ` (example: ${parameter.example})` : ""}`;
  }
  return undefined;
}

/**
 * Pure precedence resolver for a service's declared parameters. The first
 * defined, non-empty candidate wins and is validated; an invalid winner is
 * reported with its source and does not fall through to a lower source, so an
 * operator sees exactly which input was wrong.
 */
export function resolveServiceParameters(
  svc: Service,
  input: {
    // parsed --param values keyed by parameter key (parseParamFlags canonicalizes)
    flags?: Record<string, string>;
    // values read from a 1Password item, keyed by env name
    itemValues?: Record<string, string>;
    hostEnv: NodeJS.ProcessEnv;
    // current host-owned agent env entries
    existing: Record<string, string>;
  },
): ServiceParameterResolution {
  const resolution: ServiceParameterResolution = { values: {}, sources: {}, missing: [], invalid: [] };
  for (const parameter of serviceParameters(svc)) {
    const candidates: Array<[ServiceParameterSource, string | undefined]> = [
      ["flag", input.flags?.[parameter.key]],
      ["1password-item", input.itemValues?.[parameter.envVar]],
      ["host-env", input.hostEnv[parameter.envVar]],
      ["existing", input.existing[parameter.envVar] === RUNFREE_PLACEHOLDER_VALUE ? undefined : input.existing[parameter.envVar]],
    ];
    const winner = candidates.find(([, value]) => value !== undefined && value !== "");
    if (!winner || winner[1] === undefined) {
      resolution.missing.push(parameter);
      continue;
    }
    const [source, value] = winner;
    const reason = validateParameterValue(parameter, value);
    if (reason) {
      resolution.invalid.push({ parameter, source, reason });
      continue;
    }
    resolution.values[parameter.envVar] = value;
    resolution.sources[parameter.envVar] = source;
  }
  return resolution;
}

/**
 * Parse raw `--param <key>=<value>` arguments against the service's declared
 * parameters. A key may be the parameter key or its env name; the result is
 * keyed by parameter key. Refuses unknown keys, repeats, and bare keys.
 */
export function parseParamFlags(svc: Service, raw: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};
  if (raw.length === 0) return parsed;
  const parameters = serviceParameters(svc);
  if (parameters.length === 0) die(`${svc.id} service declares no parameters; drop --param`);
  const known = parameters.map((parameter) => parameter.key).join(", ");
  for (const entry of raw) {
    // Never echo the argument past the separator: a swapped or bare argument
    // may hold the value the operator meant to keep off the terminal.
    const separator = entry.indexOf("=");
    if (separator <= 0) die(`--param arguments must be <key>=<value> (known keys: ${known})`);
    const keyOrEnv = entry.slice(0, separator);
    const value = entry.slice(separator + 1);
    const parameter = parameters.find((candidate) => candidate.key === keyOrEnv || candidate.envVar === keyOrEnv);
    if (!parameter) die(`${svc.id} has no parameter ${keyOrEnv} (known: ${known})`);
    if (parameter.key in parsed) die(`--param ${parameter.key} given more than once`);
    if (value === "") die(`--param ${parameter.key} needs a value`);
    parsed[parameter.key] = value;
  }
  return parsed;
}

// Agent env names a service entry recorded host-side at enable time: OAuth seed
// handles, legacy passthrough names, and declared parameters. Static credential
// names are never written to the host-owned file, so they are not listed.
export function recordedAgentEnvNamesForServiceEntry(entry: DesiredServiceEntry): string[] {
  const names = new Set<string>();
  for (const provider of Object.values(entry.resolved.oauth ?? {})) {
    for (const seed of provider.seeds ?? []) names.add(seed.envVar);
    for (const passthrough of provider.passthrough ?? []) names.add(passthrough.envVar);
  }
  for (const parameter of entry.resolved.parameters ?? []) names.add(parameter.envVar);
  return Array.from(names).sort();
}

// Repeat the credential-source flags the operator gave so the rendered remedy
// is their command plus the missing parameter.
function credentialSourceArgs(input: ServiceEnableInput): string | undefined {
  if (input.fromOnePasswordItem) return `--from-1password-item ${input.fromOnePasswordItem}`;
  switch (input.tokenSource.kind) {
    case "named":
      return `--from-source ${input.tokenSource.name}`;
    case "env":
      return `--from-env ${input.tokenSource.env}`;
    case "1password":
      return `--from-1password ${input.tokenSource.ref}`;
    case "stdin":
      return "--from-stdin";
    default:
      return undefined;
  }
}

// `service explain` view: which declared parameters carry a recorded value.
// Values are never printed; only declared parameter env names are consulted.
export function serviceParameterStatus(
  parameters: ReadonlyArray<Pick<DesiredServiceParameter, "key" | "envVar">>,
  recorded: Record<string, string>,
): Record<string, "set" | "unset"> {
  return Object.fromEntries(parameters.map((parameter) => {
    const value = recorded[parameter.envVar];
    return [parameter.key, value !== undefined && value !== "" && value !== RUNFREE_PLACEHOLDER_VALUE ? "set" : "unset"];
  }));
}

export type ServiceParameterPromptIO = {
  interactive: boolean;
  // Test seam; the default asks with a clack text prompt.
  ask?: (parameter: ServiceParameter, retryReason: string | undefined) => Promise<string | symbol>;
};

/**
 * On a TTY, ask for every declared parameter that the flag, host env, and
 * recorded value cannot supply, and return the enable input with the answers
 * appended as `<key>=<value>` entries. Non-interactive callers get the input
 * back unchanged and the plan refuses with the remedy text instead. A
 * `--from-1password-item` enable is never prompted: the item is expected to
 * carry every parameter field, and the plan reads it exactly once.
 */
export async function promptForMissingServiceParameters(
  input: ServiceEnableInput,
  io: ServiceParameterPromptIO,
): Promise<ServiceEnableInput> {
  if (!io.interactive || input.fromOnePasswordItem) return input;
  const resolved = resolveService(input.id);
  if (!resolved) return input;
  const svc = resolved.svc;
  if (serviceParameters(svc).length === 0) return input;
  const flags = parseParamFlags(svc, input.parameters ?? []);
  const resolution = resolveServiceParameters(svc, { flags, hostEnv: childEnv(), existing: readAgentEnv() });
  const toAsk = [
    ...resolution.missing.map((parameter) => ({ parameter, reason: undefined as string | undefined })),
    ...resolution.invalid
      .filter(({ source }) => source !== "flag")
      .map(({ parameter, source, reason }) => ({ parameter, reason: `${source === "host-env" ? `host env ${parameter.envVar}` : "recorded value"}: ${reason}` })),
  ];
  if (toAsk.length === 0) return input;
  const ask = io.ask ?? (async (parameter, retryReason) => clackText({
    message: `${svc.id} parameter ${parameter.key}: ${parameter.description}${retryReason ? ` (${retryReason})` : ""}`,
    placeholder: parameter.example,
  }));
  const answers: string[] = [];
  for (const { parameter, reason: initialReason } of toAsk) {
    let reason = initialReason;
    for (;;) {
      const answer = await ask(parameter, reason);
      cancelIfClack(answer);
      const value = String(answer);
      reason = value === "" ? "a value is required" : validateParameterValue(parameter, value);
      if (reason === undefined) {
        answers.push(`${parameter.key}=${value}`);
        break;
      }
    }
  }
  return { ...input, parameters: [...(input.parameters ?? []), ...answers] };
}

export function serviceParameterRefusal(
  svc: Service,
  resolution: ServiceParameterResolution,
  input: ServiceEnableInput,
): string {
  const problems = [
    ...resolution.missing.map((parameter) => ({ parameter, detail: undefined as string | undefined })),
    ...resolution.invalid.map(({ parameter, source, reason }) => ({
      parameter,
      detail: `${reason}; the ${source === "flag" ? "--param value" : source === "host-env" ? `host env ${parameter.envVar}` : source === "existing" ? "recorded value" : "1Password item field"} is not usable`,
    })),
  ];
  const retryParameters = serviceParameters(svc).filter((parameter) =>
    resolution.sources[parameter.envVar] === "flag" || problems.some((problem) => problem.parameter.key === parameter.key));
  const count = problems.length;
  const sourceArgs = credentialSourceArgs(input);
  const lines = [
    `${svc.id} needs ${count} parameter${count === 1 ? "" : "s"} before it can be enabled:`,
    ...problems.map(({ parameter, detail }) =>
      `  ${parameter.key}  ${parameter.description}  [${parameter.envVar}]${detail ? `\n    ${detail}` : ""}`),
    `supply ${count === 1 ? "it" : "them"} with one of:`,
    `  ${remedy.serviceEnable(svc.id)}${sourceArgs ? ` ${sourceArgs}` : ""} ${retryParameters.map((parameter) => `--param ${parameter.key}=<value>`).join(" ")}`,
    ...(sourceArgs && !input.fromOnePasswordItem
      ? [`  ${retryParameters.map((parameter) => `${parameter.envVar}=<value>`).join(" ")} ${remedy.serviceEnable(svc.id)} ${sourceArgs}`]
      : []),
    ...(serviceHasOAuthCredential(svc) && !input.fromOnePasswordItem
      ? [`  ${remedy.serviceEnableFromItem(svc.id)}   (field${count === 1 ? "" : "s"} ${problems.map(({ parameter }) => parameter.envVar).join(", ")})`]
      : []),
  ];
  return lines.join("\n");
}

// Bind and prune under both project locks, before approving the declaration.
// Keep names still selected by either approved layer or another service.
export function serviceHostState(idInput: string, bind: () => void) {
  const id = idInput.toLowerCase();
  let removedEnvNames: string[] = [];
  return {
    get removedEnvNames(): readonly string[] { return removedEnvNames; },
    withWriteLock: <T>(action: () => T): T => withTokenStoreLock(action, { wait: false }),
    beforeWrite: (before: Pick<DesiredPolicyCandidate, "project" | "local">, next: Pick<DesiredPolicyCandidate, "project" | "local">) => {
      const previous = compileDesiredPolicies(before).selectedServices[id];
      const previousNames = previous ? recordedAgentEnvNamesForServiceEntry(previous) : [];
      const previousValues = readAgentEnv();
      const previousSources = loadTokenConfig();
      const previousHandles = readOAuthSeedHandleStore();
      // These three stores are project-scoped and protected by this lock.
      const restore = () => {
        const failures: unknown[] = [];
        for (const write of [
          () => saveTokenConfig(previousSources),
          () => saveOAuthSeedHandleStore(previousHandles),
          () => saveAgentEnv(previousValues),
        ]) {
          try { write(); } catch (error) { failures.push(error); }
        }
        if (failures.length > 0) throw new AggregateError(failures, "service host-state rollback failed");
      };
      const declared = new Set(compileDesiredPolicies(next).agentEnv);
      try {
        bind();
        removedEnvNames = removeAgentEnvValues(previousNames.filter((name) => !declared.has(name)));
      } catch (error) {
        try { restore(); } catch (rollbackError) {
          throw new AggregateError([error, rollbackError], "service binding and host-state rollback failed");
        }
        throw error;
      }
      return restore;
    },

  };
}

/**
 * The exact credential entry an enable will write: its token-config key and
 * the source as stored.
 *
 * One derivation, used by both the plan's refusal check and the bind that
 * performs the write. They used to derive it separately and disagreed for a
 * user-defined service: the check looked under `credential.tokenName` with the
 * caller's source, while the bind wrote under `svc.id` with the owner marker
 * `saveUserServiceTokenSource` adds. Re-enabling with the existing source then
 * compared as a change and was refused, naming the source the caller had just
 * asked for. Predicting a write by any route other than the write's own is how
 * that happens, so there is deliberately no second route here.
 */
function plannedServiceCredentialBinding(
  svc: Service,
  origin: ResolvedService["origin"],
  source: TokenSource,
): { name: string; source: TokenSource } | undefined {
  if (serviceHasOAuthCredential(svc) && !serviceHasCredential(svc)) {
    return { name: svc.oauthCredential.seeds[0].tokenName, source };
  }
  if (!serviceHasCredential(svc)) return undefined;
  return origin === "user"
    ? { name: svc.id, source: { ...source, runfreeUserServiceOwner: svc.id } }
    : { name: svc.credential.tokenName, source };
}

export function planDesiredServiceEnable(input: ServiceEnableInput): DesiredServiceEnablePlan {
  const resolved = resolveService(input.id);
  if (!resolved) die(`unknown service: ${input.id} (known: ${knownServiceNames().join(", ")})`);
  const svc = resolved.svc;
  if (resolved.origin === "user" && input.expectedUserServiceDigest && resolved.digest !== input.expectedUserServiceDigest) {
    die(`${svc.id} definition changed after review; rerun runfree service configure ${svc.id}`);
  }
  if (input.readOnly && input.allowWrite) die("--read-only conflicts with --allow-write; pick one write posture");
  const explicitSkippedHosts = validateSkipHosts(svc, input.skipHosts ?? []);
  const skipped = new Set(explicitSkippedHosts);
  if (input.skipBroad) {
    for (const host of serviceBroadHosts(svc)) skipped.add(host.host);
  }
  const skippedHosts = Array.from(skipped).sort();
  assertSkippableHosts(svc, skippedHosts, input.skipBroad === true);
  const writeMode: ServiceWriteMode | undefined = input.readOnly
    ? "read-only"
    : input.allowWrite
      ? "allow-write"
      : svc.defaultWriteMode;
  const hasStatic = serviceHasCredential(svc);
  const hasOAuth = serviceHasOAuthCredential(svc);
  const hasTokenSource = input.tokenSource.kind !== "none";
  const itemRef = input.fromOnePasswordItem;
  const singleSeedOAuth = hasOAuth && !hasStatic && svc.oauthCredential.seeds.length === 1;
  if (!hasStatic && !hasOAuth && (hasTokenSource || itemRef !== undefined)) {
    die(`${svc.id} service does not accept credential source options; allow private indexes with exact hosts and proxy credential policy`);
  }
  if (itemRef && hasTokenSource) die("choose only one credential source");
  if (itemRef && !hasOAuth) die(`${svc.id} service does not accept --from-1password-item`);
  if (resolved.origin === "user" && hasOAuth) die("internal error: user-defined services cannot carry OAuth credentials");
  if (hasOAuth && !itemRef && !(singleSeedOAuth && hasTokenSource)) {
    die(singleSeedOAuth
      ? `${svc.id} service requires a credential source: --from-1password-item op://..., or --from-source/--from-env/--from-1password to bind its OAuth seed`
      : `${svc.id} service requires --from-1password-item op://... to configure OAuth seed handles`);
  }
  const source = itemRef ? undefined : tokenSourceFromSelection(input.tokenSource, false);
  const parameterValues = resolvePlannedParameters(svc, input, itemRef);
  if (resolved.origin === "user" && serviceHasCredential(svc)) {
    const existingSource = loadTokenConfig()[svc.id];
    if (existingSource && !isUserServiceOwnedTokenSource(existingSource, svc.id)) {
      die(`${svc.id} credential source already exists without a user-service ownership marker; remove or rename that host-owned token config entry before enabling this user-defined service`);
    }
  }
  let sourceItemBindings: Array<{ name: string; source: TokenSource }> | undefined;
  if (itemRef && serviceHasOAuthCredential(svc)) {
    const opPath = resolveHostExecutable("op");
    if (!opPath) die("op CLI not found on sanitized host PATH");
    sourceItemBindings = svc.oauthCredential.seeds.map((seed) => ({
      name: seed.tokenName, source: { source: "1password" as const, ref: onePasswordItemFieldRef(itemRef, seed.envVar) },
    }));
    if (serviceHasCredential(svc)) sourceItemBindings.push({
      name: svc.credential.tokenName,
      source: { source: "1password", ref: onePasswordItemFieldRef(itemRef, svc.credential.agentEnv[0] ?? svc.credential.tokenName.toUpperCase()) },
    });
    for (const binding of sourceItemBindings) {
      if (binding.source.source !== "1password") throw new Error("invalid prepared item source");
      try { readOnePasswordRef(opPath, binding.source.ref); }
      catch (error) { die(error instanceof Error ? error.message : String(error)); }
    }
  }
  for (const binding of sourceItemBindings ?? []) {
    assertTokenSourceCanBeSaved(binding.name, binding.source, { replaceSource: input.replaceSource });
  }
  if (source) {
    const planned = plannedServiceCredentialBinding(svc, resolved.origin, source);
    if (planned) {
      assertTokenSourceCanBeSaved(planned.name, planned.source, { replaceSource: input.replaceSource });
    }
  }
  return {
    id: svc.id,
    service: svc,
    origin: resolved.origin,
    parameterValues,
    skippedHosts,
    writeMode,
    ...(source ? { source } : {}),
    ...(itemRef ? { sourceItemRef: itemRef, sourceItemBindings } : {}),
    entry: desiredServiceEntry(svc, { skippedHosts, writeMode }, resolved.digest),
  };
}

// Plan-time parameter resolution: every declared parameter must resolve here,
// before any token, agent env, or desired policy write. The 1Password item
// fields are read now (a failing read refuses the plan, as it did at bind).
function resolvePlannedParameters(svc: Service, input: ServiceEnableInput, itemRef: string | undefined): Record<string, string> {
  const parameters = serviceParameters(svc);
  const flags = parseParamFlags(svc, input.parameters ?? []);
  if (parameters.length === 0) return {};
  let itemValues: Record<string, string> | undefined;
  if (itemRef) {
    if (!itemRef.startsWith("op://")) die("--from-1password-item requires an op:// item reference");
    const opPath = resolveHostExecutable("op");
    if (!opPath) die("op CLI not found on sanitized host PATH");
    itemValues = {};
    for (const parameter of parameters) {
      if (flags[parameter.key] !== undefined) continue;
      try {
        itemValues[parameter.envVar] = readOnePasswordRef(opPath, onePasswordItemFieldRef(itemRef, parameter.envVar));
      } catch (error) {
        die(error instanceof Error ? error.message : String(error));
      }
    }
  }
  const resolution = resolveServiceParameters(svc, { flags, itemValues, hostEnv: childEnv(), existing: readAgentEnv() });
  if (resolution.missing.length > 0 || resolution.invalid.length > 0) die(serviceParameterRefusal(svc, resolution, input));
  return resolution.values;
}

/** Catalog updates retain credential sources but must validate new parameters. */
export function planServiceParameterUpdate(svc: Service): Record<string, string> {
  const existing = readAgentEnv();
  const preserved = Object.fromEntries(serviceParameters(svc).flatMap((parameter) => {
    const value = existing[parameter.envVar];
    return value && value !== RUNFREE_PLACEHOLDER_VALUE && validateParameterValue(parameter, value) === undefined
      ? [[parameter.key, value]] : [];
  }));
  const resolution = resolveServiceParameters(svc, { flags: preserved, hostEnv: childEnv(), existing });
  const problems = [
    ...resolution.missing.map((parameter) => ({ parameter, reason: "missing value" })),
    ...resolution.invalid,
  ];
  if (problems.length > 0) {
    die([
      `${svc.id} needs valid parameters before its catalog update:`,
      ...problems.map(({ parameter, reason }) => `  ${parameter.envVar}: ${reason}`),
      `retry with: ${problems.map(({ parameter }) => `${parameter.envVar}=<value>`).join(" ")} runfree service diff --apply`,
    ].join("\n"));
  }
  return resolution.values;
}

export function bindDesiredServiceCredentialSources(
  plan: DesiredServiceEnablePlan,
  replaceSource: boolean,
): string[] {
  const svc = plan.service;
  const changed: string[] = [];
  if (plan.sourceItemRef) {
    if (!serviceHasOAuthCredential(svc) || !plan.sourceItemBindings) die("OAuth item sources must be prepared before binding");
    for (const binding of plan.sourceItemBindings) {
      assertTokenSourceCanBeSaved(binding.name, binding.source, { replaceSource });
    }
    for (const binding of plan.sourceItemBindings) {
      if (saveTokenSource(binding.name, binding.source, { replaceSource }).changed) changed.push(binding.name);
    }
    setAgentEnvValues({ ...serviceOAuthAgentSeedEnv(svc), ...plan.parameterValues });
    return changed.sort();
  }
  if (!plan.source) {
    // No credential source: a parameter-only enable (or a re-enable that
    // keeps its source) still records the resolved parameter values.
    if (Object.keys(plan.parameterValues).length > 0) setAgentEnvValues(plan.parameterValues);
    return [];
  }
  if (serviceHasOAuthCredential(svc) && !serviceHasCredential(svc)) {
    const seed = svc.oauthCredential.seeds[0];
    if (saveTokenSource(seed.tokenName, plan.source, { replaceSource }).changed) changed.push(seed.tokenName);
    setAgentEnvValues({ ...serviceOAuthAgentSeedEnv(svc), ...plan.parameterValues });
  } else if (serviceHasCredential(svc)) {
    // The same derivation the plan checked against, so the check and the write
    // cannot drift apart again.
    const planned = plannedServiceCredentialBinding(svc, plan.origin, plan.source);
    if (!planned) throw new Error("service credential binding vanished between plan and bind");
    const result = plan.origin === "user"
      ? saveUserServiceTokenSource(planned.name, plan.source, { replaceSource })
      : saveTokenSource(planned.name, plan.source, { replaceSource });
    if (result.changed) changed.push(planned.name);
    if (Object.keys(plan.parameterValues).length > 0) setAgentEnvValues(plan.parameterValues);
  }
  return changed.sort();
}

function credentialIdentity(credential: CredentialPolicyJson): string {
  return `${credential.host}\u0000${credential.header.toLowerCase()}\u0000${credential.scheme}\u0000${credential.pathPrefix ?? ""}`;
}

function onePasswordItemFieldRef(itemRef: string, field: string): string {
  return `${itemRef.replace(/\/+$/, "")}/${field}`;
}

function stableServiceDiffJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((entry) => stableServiceDiffJson(entry)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableServiceDiffJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function requireInteractive(label: string): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    die(`${label} requires an interactive TTY; use the non-interactive service enable/define flags instead`);
  }
}

function cancelIfClack(value: unknown): asserts value is Exclude<typeof value, symbol> {
  if (!isCancel(value)) return;
  clackCancel("No changes applied.");
  die("cancelled");
}

function printUserDefinitionPreview(loaded: Omit<LoadedUserServiceDefinition, "path">, sourcePath: string): void {
  console.log(`source: ${sourcePath}`);
  console.log(`destination: ${displayUserServicePath(destinationPathForUserService(adminProjectRoot(), adminEnv(), loaded.svc.id), adminEnv())}`);
  console.log(`definition digest: ${loaded.digest}`);
  console.log("definition contents:");
  // Sanitize per line: this preview is the import chokepoint, so author text
  // must never reach the terminal unsanitized (sanitizeForTerminal strips
  // newlines, hence line-by-line).
  for (const line of JSON.stringify(loaded.definition, null, 2).split("\n")) {
    console.log(sanitizeForTerminal(line));
  }
  for (const host of loaded.svc.hosts) {
    console.log(`host: ${host.host}${host.broad ? " (broad)" : ""}${host.explanation ? ` — ${sanitizeForTerminal(host.explanation)}` : ""}`);
  }
  if (serviceHasCredential(loaded.svc)) {
    console.log(`credential token: ${loaded.svc.id}`);
    for (const credential of loaded.svc.credential.credentials) console.log(`credential: ${describeCredential(credential)}`);
    console.log(`agent env: ${loaded.svc.credential.agentEnv.join(", ")} placeholders`);
  }
}

export async function serviceDefineIntent(input: ServiceDefineInput): Promise<void> {
  const id = canonicalUserServiceId(input.id);
  if (!isUserServiceId(id)) die(`user-defined service id must match user-[a-z0-9][a-z0-9-]*`);
  if (input.fromFile) {
    let imported: ReturnType<typeof readUserServiceImportSource>;
    try {
      imported = readUserServiceImportSource(input.fromFile);
    } catch (error) {
      die(error instanceof Error ? error.message : String(error));
    }
    if (imported.loaded.svc.id !== id) die(`definition id ${imported.loaded.svc.id} does not match requested id ${id}`);
    printUserDefinitionPreview(imported.loaded, input.fromFile);
    if (!input.yes) {
      requireInteractive("service custom add --from-file");
      const confirmed = await clackConfirm({ message: `Import ${id} as a user-defined service?`, initialValue: false });
      cancelIfClack(confirmed);
      if (!confirmed) {
        console.log("not imported");
        return;
      }
    }
    let reread: ReturnType<typeof readUserServiceImportSource>;
    try {
      reread = readUserServiceImportSource(input.fromFile);
    } catch (error) {
      die(error instanceof Error ? error.message : String(error));
    }
    if (reread.loaded.digest !== imported.loaded.digest) {
      die("definition source changed after preview; review it again before importing");
    }
    const destination = writeUserServiceDefinition(adminProjectRoot(), adminEnv(), imported.loaded.definition, {
      replace: input.replace,
      provenance: {
        importedFrom: input.fromFile,
        importedAt: new Date().toISOString(),
        digest: imported.loaded.digest,
      },
    });
    console.log(`user-defined service ${id} imported to ${displayUserServicePath(destination, adminEnv())}`);
    console.log(`enable it with: runfree service enable ${id}`);
    return;
  }

  requireInteractive("service custom add");
  intro(`Define ${id}`);
  const label = await clackText({ message: "Label", placeholder: "Acme internal API" });
  cancelIfClack(label);
  const hostText = await clackText({ message: "Hosts (comma-separated exact hostnames)", placeholder: "api.acme.example" });
  cancelIfClack(hostText);
  const explanationText = await clackText({ message: "Explanation", placeholder: "Acme API: api.acme.example" });
  cancelIfClack(explanationText);
  const wantsCredential = await clackConfirm({ message: "Add a static header credential block?", initialValue: false });
  cancelIfClack(wantsCredential);
  const hosts = String(hostText).split(",").map((host) => host.trim()).filter(Boolean).map((host) => ({ host }));
  const raw: Record<string, unknown> = {
    schemaVersion: 1,
    id,
    label: String(label),
    revision: 1,
    hosts,
    explanations: [String(explanationText)],
  };
  if (wantsCredential) {
    const envName = await clackText({ message: "Agent placeholder env name", placeholder: `${id.toUpperCase().replaceAll("-", "_")}_TOKEN` });
    cancelIfClack(envName);
    raw.credential = {
      tokenDescription: `${String(label)} token`,
      agentEnv: [String(envName)],
      credentials: hosts.map((host) => ({ host: host.host, header: "Authorization", scheme: "bearer" })),
    };
  }
  // Validate in memory: nothing lands in the live services directory until the
  // user confirms the previewed, validated definition.
  const loaded = (() => {
    try {
      return validateUserServiceDefinitionObject(JSON.parse(JSON.stringify(raw)) as unknown);
    } catch (error) {
      return die(error instanceof Error ? error.message : String(error));
    }
  })();
  printUserDefinitionPreview(loaded, "interactive wizard");
  const confirmed = await clackConfirm({ message: `Write ${id}?`, initialValue: true });
  cancelIfClack(confirmed);
  if (!confirmed) {
    console.log("not written");
    return;
  }
  const destination = writeUserServiceDefinition(adminProjectRoot(), adminEnv(), loaded.definition, { replace: input.replace });
  outro(`user-defined service ${id} written to ${displayUserServicePath(destination, adminEnv())}`);
}

export function serviceUndefineIntent(input: ServiceUndefineInput): void {
  const id = canonicalUserServiceId(input.id);
  if (!isUserServiceId(id)) die(`user-defined service id must match user-[a-z0-9][a-z0-9-]*`);
  const records = loadServiceRecords();
  if (records[id]) warn(`${id} is enabled in this project; disable it with: runfree service disable ${id}`);
  const result = removeUserServiceDefinition(adminProjectRoot(), adminEnv(), id);
  console.log(result.removed
    ? `user-defined service ${id} removed from ${displayUserServicePath(result.path, adminEnv())}`
    : `user-defined service ${id} is not defined at ${displayUserServicePath(result.path, adminEnv())}`);
}

export type DesiredServiceConfigureOptions = {
  apply: (input: ServiceEnableInput) => Promise<void>;
  currentEntry?: DesiredServiceEntry;
};

export async function serviceConfigureIntent(
  input: ServiceConfigureInput,
  desired: DesiredServiceConfigureOptions,
): Promise<void> {
  requireInteractive("service configure");
  const resolved = resolveService(input.id);
  if (!resolved) die(`unknown service: ${input.id} (known: ${knownServiceNames().join(", ")})`);
  const svc = resolved.svc;
  const record = desired.currentEntry
    ? {
        revision: desired.currentEntry.revision,
        skippedHosts: desired.currentEntry.selection?.skippedHosts,
        writeMode: desired.currentEntry.selection?.writeMode,
      }
    : undefined;
  intro(`Configure ${svc.id}`);
  for (const line of userOriginBanner(resolved)) clackLog.warn(line);
  if (record) clackLog.info(`currently enabled at revision ${record.revision}`);
  const previousSkipped = new Set(record?.skippedHosts ?? []);
  const selectedHosts = await multiselect({
    message: "Select hosts to allow",
    required: true,
    options: svc.hosts.map((host) => ({
      value: host.host,
      label: `${host.host}${host.broad ? ` (broad — ${sanitizeForTerminal(host.explanation ?? "")})` : ""}${resolved.origin === "user" ? " (author-supplied)" : ""}`,
      hint: host.broad ? "broad hosts are deselected by default" : undefined,
    })),
    // Fresh setup deselects broad hosts; reconfigure preloads the prior enable
    // state (skipped hosts stay deselected, previously enabled broad hosts stay
    // selected).
    initialValues: svc.hosts
      .filter((host) => (record ? !previousSkipped.has(host.host) : !host.broad))
      .map((host) => host.host),
  });
  cancelIfClack(selectedHosts);
  const selected = new Set((selectedHosts as string[]).map((host) => host.toLowerCase()));
  const skipHosts = serviceHostNames(svc).filter((host) => !selected.has(host));
  const posture = await select({
    message: "Write posture",
    options: [
      { value: "default", label: "Use project default (writes ask for approval)", hint: "nothing pinned on these hosts; follows the project default if it changes" },
      { value: "read-only", label: "Read-only", hint: "writes to these hosts are blocked" },
      { value: "allow-write", label: "Allow writes", hint: "writes to these hosts proceed without approval" },
    ],
    initialValue: record?.writeMode ?? "default",
  });
  cancelIfClack(posture);
  const postureValue = String(posture);
  let tokenSource: ServiceEnableInput["tokenSource"] = { kind: "none" };
  let fromOnePasswordItem: string | undefined;
  if (serviceHasCredential(svc) || serviceHasOAuthCredential(svc)) {
    const sourceKind = await select({
      message: "Credential source",
      options: [
        { value: "skip", label: "Skip for now" },
        { value: "env", label: "Host environment variable" },
        { value: "1password", label: "1Password secret reference" },
        ...(serviceHasOAuthCredential(svc) ? [{ value: "1password-item", label: "1Password item (OAuth seed fields)" }] : []),
        { value: "source", label: "Existing named source" },
      ],
      initialValue: "skip",
    });
    cancelIfClack(sourceKind);
    if (sourceKind === "env") {
      const envName = await clackText({ message: "Env var name" });
      cancelIfClack(envName);
      tokenSource = { kind: "env", env: String(envName) };
    } else if (sourceKind === "1password") {
      const ref = await clackText({ message: "1Password ref", placeholder: "op://Vault/Item/field" });
      cancelIfClack(ref);
      tokenSource = { kind: "1password", ref: String(ref) };
    } else if (sourceKind === "1password-item") {
      const ref = await clackText({ message: "1Password item ref", placeholder: "op://Vault/Item" });
      cancelIfClack(ref);
      fromOnePasswordItem = String(ref);
    } else if (sourceKind === "source") {
      const name = await clackText({ message: "Named source" });
      cancelIfClack(name);
      tokenSource = { kind: "named", name: String(name) };
    }
  }
  const parameterAnswers = (await promptForMissingServiceParameters({
    id: svc.id,
    tokenSource,
    fromOnePasswordItem,
    replaceSource: false,
    skipBroad: false,
    reloadProxy: input.reloadProxy,
  }, { interactive: true })).parameters ?? [];
  clackLog.info([
    ...userOriginBanner(resolved),
    `service: ${svc.id}`,
    `hosts to allow: ${serviceHostNames(svc).filter((host) => !skipHosts.includes(host)).join(", ") || "none"}`,
    `hosts to skip: ${skipHosts.join(", ") || "none"}`,
    `write posture: ${postureValue === "read-only"
      ? "read-only (writes to these hosts are blocked)"
      : postureValue === "allow-write"
        ? "allow writes (writes to these hosts proceed without approval)"
        : "project default (writes ask for approval; nothing pinned on these hosts)"}`,
    ...(resolved.digest ? [`definition digest: ${resolved.digest}`, `definition path: ${displayUserServicePath(resolved.path ?? "", adminEnv())}`] : []),
    serviceHasCredential(svc) ? `credential token: ${svc.credential.tokenName}` : "credential: none",
    ...(serviceParameters(svc).length > 0
      ? [`parameters: ${serviceParameters(svc).map((parameter) => `${parameter.key} [${parameter.envVar}]`).join(", ")}`]
      : []),
  ].join("\n"));
  const confirmed = await clackConfirm({ message: "Apply this service configuration?", initialValue: false });
  cancelIfClack(confirmed);
  if (!confirmed) {
    console.log("not applied");
    return;
  }
  const enableInput: ServiceEnableInput = {
    id: svc.id,
    tokenSource,
    fromOnePasswordItem,
    ...(parameterAnswers.length > 0 ? { parameters: parameterAnswers } : {}),
    replaceSource: false,
    skipBroad: false,
    skipHosts,
    expectedUserServiceDigest: resolved.digest,
    readOnly: postureValue === "read-only",
    allowWrite: postureValue === "allow-write",
    reloadProxy: input.reloadProxy,
  };
  await desired.apply(enableInput);
  outro(`${svc.id} configured`);
}
