// Spec 2026-10-24 google-service-account-source §5.1 (review M1): the write
// action lives in desired policy and the token scope in the host source
// registry, and nothing keeps the two in agreement. This module decides the
// unsafe pair (a google-search-console binding whose scope is not proven
// read-only, plus write action allow on the host) from those two inputs
// only. It never reads 1Password.
import {
  effectiveWriteAction,
  type PolicyJson,
  type WriteAction,
} from "@runfree/runtime-contracts/network-policy";

import { projectInfo, type ProjectInfo } from "../config.ts";
import { readApprovedNetworkPolicy } from "../control/approvals.ts";
import { compileDesiredPolicies } from "../control/compiler.ts";
import { knownProjectPointers } from "../host-service-registry.ts";
import { runfreeStateRoot } from "../paths.ts";
import { remedy } from "../remedies.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { warn } from "../warnings.ts";
import {
  childEnv,
  describeSource,
  die,
  loadSourceRegistry,
  loadTokenConfig,
  type NamedSource,
  type SourceRegistry,
  type TokenSource,
} from "./admin-core.ts";
import { GOOGLE_SA_READ_ONLY_SCOPE } from "./google-service-account.ts";

export const SEARCH_CONSOLE_HOST = "searchconsole.googleapis.com";
export const SEARCH_CONSOLE_TOKEN = "google-search-console";
export const SEARCH_CONSOLE_SERVICE = "google-search-console";

export type BindingScope = "read-only" | "write" | "unknown";

/**
 * undefined: the token has no binding. Only a google-service-account source
 * can prove its scope (its registry record lists it); every other binding,
 * and a named binding whose source is missing, is "unknown".
 */
export function searchConsoleBindingScope(
  binding: TokenSource | undefined,
  registry: SourceRegistry | undefined,
): BindingScope | undefined {
  if (!binding) return undefined;
  if (binding.source !== "named") return "unknown";
  const source = registry && Object.hasOwn(registry, binding.name) ? registry[binding.name] : undefined;
  return source?.type === "google-service-account" ? googleServiceAccountScope(source.scopes) : "unknown";
}

function googleServiceAccountScope(scopes: readonly string[]): BindingScope {
  return scopes.every((scope) => scope === GOOGLE_SA_READ_ONLY_SCOPE) ? "read-only" : "write";
}

/**
 * True when a source with `nextScopes` could grant Search Console writes that
 * `previous` did not provably grant: the next scopes are not read-only, and
 * the previous record is missing, has an unknown scope (not a service-account
 * source), or was read-only.
 */
export function scopesAddWrite(previous: NamedSource | undefined, nextScopes: readonly string[]): boolean {
  if (googleServiceAccountScope(nextScopes) === "read-only") return false;
  if (previous?.type !== "google-service-account") return true;
  return googleServiceAccountScope(previous.scopes) === "read-only";
}

export function searchConsoleWriteScopeWarning(input: {
  writeAction: WriteAction;
  scope: BindingScope | undefined;
  sourceLabel: string;
  local?: boolean;
}): string | undefined {
  if (input.scope === undefined || input.scope === "read-only" || input.writeAction !== "allow") return undefined;
  const why = input.scope === "write"
    ? "has a Search Console write scope"
    : "has a scope Runfree cannot read";
  return [
    `${SEARCH_CONSOLE_HOST} writes run without approval (write action allow), and credential ${SEARCH_CONSOLE_TOKEN} uses ${input.sourceLabel}, which ${why};`,
    "sitemap PUT and site DELETE will not prompt;",
    `restore the prompt with: ${remedy.hostRulesSet(SEARCH_CONSOLE_HOST, { writeAction: "ask" }, { local: input.local })}`,
  ].join(" ");
}

/** The warning for a compiled policy and the project's current binding, or undefined. */
export function searchConsoleWarningFor(input: {
  policy: Pick<PolicyJson, "requests" | "writeApproval">;
  binding: TokenSource | undefined;
  registry: SourceRegistry | undefined;
  local?: boolean;
}): string | undefined {
  return searchConsoleWriteScopeWarning({
    writeAction: effectiveWriteAction({ requests: input.policy.requests ?? {}, writeApproval: input.policy.writeApproval }, SEARCH_CONSOLE_HOST),
    scope: searchConsoleBindingScope(input.binding, input.registry),
    sourceLabel: describeSource(input.binding),
    ...(input.local === undefined ? {} : { local: input.local }),
  });
}

type ApprovedSearchConsolePair = {
  /** True when the compiled policy allowlists the host at all. */
  hostAllowed: boolean;
  /** The layer that holds the service entry, for the remedy's --local. */
  local: boolean;
  policy: Parameters<typeof effectiveWriteAction>[0];
};

/** The approved desired pair compiled for one checkout, or undefined when nothing is approved. */
function approvedSearchConsolePair(projectRoot: string, project: ProjectInfo): ApprovedSearchConsolePair | undefined {
  const approvedProject = readApprovedNetworkPolicy(projectRoot, project, "network-project");
  const approvedLocal = readApprovedNetworkPolicy(projectRoot, project, "network-local");
  if (!approvedProject && !approvedLocal) return undefined;
  const empty = { version: 2 as const, hosts: [] };
  const compiled = compileDesiredPolicies({ project: approvedProject ?? empty, local: approvedLocal ?? empty });
  return {
    hostAllowed: compiled.policy.hosts.includes(SEARCH_CONSOLE_HOST),
    local: approvedLocal?.services !== undefined && Object.hasOwn(approvedLocal.services, SEARCH_CONSOLE_SERVICE),
    policy: { requests: compiled.policy.requests ?? {}, writeApproval: compiled.policy.writeApproval },
  };
}

/**
 * The warning for the project's approved desired pair and its current
 * binding, or undefined. Runs inside an admin action (it reads the host
 * credential config) and after the desired-policy transaction, never under
 * its lock. The remedy names the layer that holds the service entry.
 */
export function searchConsoleWarningForApprovedPolicy(runtime: RuntimeContext): string | undefined {
  const pair = approvedSearchConsolePair(runtime.projectRoot, runtime.project);
  if (!pair) return undefined;
  const binding = loadTokenConfig()[SEARCH_CONSOLE_TOKEN];
  return searchConsoleWarningFor({
    policy: pair.policy,
    binding,
    registry: binding?.source === "named" ? loadSourceRegistry() : undefined,
    local: pair.local,
  });
}

/**
 * Spec §5.1 refusal (plans P-D1, P-D2). A source change that adds a write
 * scope is refused while any project that binds the source to
 * google-search-console has write action allow on the host in its approved
 * desired policy: that change removes the approval prompt for sitemap PUT
 * and site DELETE, and nobody would see it. Reads the state pointers and
 * approved policies only; never 1Password. A binding project whose checkout
 * or approval cannot be read cannot launch, so it warns and does not refuse
 * (the warning names its project id; `credential status`, `service enable`,
 * and `host rules` warn there once the checkout is back).
 */
export function assertReplaceKeepsSearchConsoleApproval(input: {
  sourceName: string;
  previous: NamedSource | undefined;
  nextScopes: readonly string[];
  /** Project ids whose host credential config binds google-search-console to this source. */
  bindingProjectIds: readonly string[];
}): void {
  if (input.bindingProjectIds.length === 0 || !scopesAddWrite(input.previous, input.nextScopes)) return;
  const env = childEnv();
  const roots = new Map(knownProjectPointers(runfreeStateRoot(env)).map((pointer) => [pointer.id, pointer.root]));
  const unsafe: string[] = [];
  for (const id of [...input.bindingProjectIds].sort()) {
    const root = roots.get(id);
    let pair: ApprovedSearchConsolePair | undefined;
    try {
      if (root === undefined) throw new Error("no project pointer");
      pair = approvedSearchConsolePair(root, projectInfo(root, env));
    } catch {
      warn(`${input.sourceName} source: project ${id} binds ${SEARCH_CONSOLE_TOKEN} to it, but its checkout or approved policy cannot be read, so its Search Console write action was not checked; once that checkout is back, credential status in it reports an unsafe write pair`);
      continue;
    }
    if (!pair?.hostAllowed || effectiveWriteAction(pair.policy, SEARCH_CONSOLE_HOST) !== "allow") continue;
    unsafe.push(`${root} (restore the prompt there with: ${remedy.hostRulesSet(SEARCH_CONSOLE_HOST, { writeAction: "ask" }, { local: pair.local })})`);
  }
  if (unsafe.length === 0) return;
  die([
    `${input.sourceName} source change adds a Search Console write scope, and ${SEARCH_CONSOLE_HOST} writes run without approval (write action allow) in a project that binds ${SEARCH_CONSOLE_TOKEN} to it: ${unsafe.join("; ")};`,
    `then run the replace again, or keep --scope ${GOOGLE_SA_READ_ONLY_SCOPE}`,
  ].join(" "));
}
