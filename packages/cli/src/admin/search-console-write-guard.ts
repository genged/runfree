// Spec 2026-10-24 google-service-account-source §5.1 (review M1): the write
// action lives in desired policy and the token scope in the host source
// registry, and nothing keeps the two in agreement. This module decides the
// unsafe pair (a google-search-console binding whose scope is not proven
// read-only, plus write action allow on the host) from those two inputs
// only. It never reads 1Password.
import path from "node:path";

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
import { projectHash } from "../project-identity.ts";
import { remedy } from "../remedies.ts";
import { printable } from "../runtime/mcp.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { warn, warnOnce } from "../warnings.ts";
import {
  childEnv,
  describeSource,
  die,
  loadSourceRegistry,
  loadTokenConfig,
  type NamedSource,
  projectRoot,
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

type ProjectLocation = Pick<RuntimeContext, "projectRoot" | "project">;

/**
 * The warning for a checkout's approved desired pair and `binding`, or
 * undefined. Reads the approval records, the source registry, and nothing
 * else. The remedy names the layer that holds the service entry.
 */
function approvedPolicyWarning(location: ProjectLocation, binding: TokenSource | undefined): string | undefined {
  if (!binding) return undefined;
  const pair = approvedSearchConsolePair(location.projectRoot, location.project);
  if (!pair) return undefined;
  return searchConsoleWarningFor({
    policy: pair.policy,
    binding,
    registry: binding.source === "named" ? loadSourceRegistry() : undefined,
    local: pair.local,
  });
}

/**
 * The warning for the project's approved desired pair and its current
 * binding, or undefined. Runs inside an admin action (it reads the host
 * credential config) and after the desired-policy transaction, never under
 * its lock.
 */
export function searchConsoleWarningForApprovedPolicy(runtime: ProjectLocation): string | undefined {
  return approvedPolicyWarning(runtime, loadTokenConfig()[SEARCH_CONSOLE_TOKEN]);
}

/**
 * The warning for the admin action's own project (its approved desired pair)
 * and `binding`, or undefined. Warn-only, so it never throws: a policy or
 * source it cannot read becomes a warning of its own.
 */
export function searchConsoleWarningForCurrentProject(binding: TokenSource | undefined): string | undefined {
  if (!binding) return undefined;
  try {
    const root = projectRoot();
    return approvedPolicyWarning({ projectRoot: root, project: projectInfo(root, childEnv()) }, binding);
  } catch {
    return `${SEARCH_CONSOLE_TOKEN} is bound, but its approved policy or source could not be read, so the ${SEARCH_CONSOLE_HOST} write action was not checked against its scope; run runfree credential status to check it`;
  }
}

/**
 * Spec §5.1 at every launch and `credential sync` (both run
 * credentialSyncIntent): warns for the unsafe pair of the admin action's
 * project. Never fails the sync. A project with no google-search-console
 * binding reads nothing more than its credential config. `warnOnce`, because
 * a launch whose first sync defers runs a second one.
 */
export function warnSearchConsoleWritePairAtSync(): void {
  let binding: TokenSource | undefined;
  try {
    binding = loadTokenConfig()[SEARCH_CONSOLE_TOKEN];
  } catch {
    // The sync itself reports an unreadable credential config.
    return;
  }
  const message = searchConsoleWarningForCurrentProject(binding);
  if (message) warnOnce(message);
}

type BindingProject =
  | { id: string; root: string; pair: ApprovedSearchConsolePair | undefined }
  | { id: string; root: undefined };

/**
 * Maps each binding project id to its checkout and approved pair. The
 * current checkout (the admin action's project root) is resolved directly,
 * so a project that never launched is checked when the command runs in it;
 * every other id goes through the state pointer a launch writes. An id with
 * no checkout, or whose checkout or approval cannot be read, has no root.
 */
function bindingProjects(bindingProjectIds: readonly string[], cwdProjectRoot: string | undefined): BindingProject[] {
  const env = childEnv();
  const roots = new Map(knownProjectPointers(runfreeStateRoot(env)).map((pointer) => [pointer.id, pointer.root]));
  if (cwdProjectRoot !== undefined) {
    const cwdRoot = path.resolve(cwdProjectRoot);
    const cwdId = projectHash(cwdRoot);
    if (bindingProjectIds.includes(cwdId)) roots.set(cwdId, cwdRoot);
  }
  const result: BindingProject[] = [];
  for (const id of [...new Set(bindingProjectIds)].sort()) {
    const root = roots.get(id);
    try {
      if (root === undefined) throw new Error("no project checkout");
      result.push({ id, root, pair: approvedSearchConsolePair(root, projectInfo(root, env)) });
    } catch {
      result.push({ id, root: undefined });
    }
  }
  return result;
}

function unsafeProject(project: BindingProject): project is { id: string; root: string; pair: ApprovedSearchConsolePair } {
  return project.root !== undefined
    && project.pair !== undefined
    && project.pair.hostAllowed
    && effectiveWriteAction(project.pair.policy, SEARCH_CONSOLE_HOST) === "allow";
}

function restorePromptRemedy(pair: ApprovedSearchConsolePair): string {
  return remedy.hostRulesSet(SEARCH_CONSOLE_HOST, { writeAction: "ask" }, { local: pair.local });
}

// P-D1: a binding project that cannot be resolved warns and does not refuse.
function uncheckedProjectWarning(sourceName: string, id: string, check: "refusal" | "warning"): string {
  return `${sourceName} source: project ${printable(id)} binds ${SEARCH_CONSOLE_TOKEN} to it, but its checkout or approved policy cannot be read, so the Search Console write-scope ${check} could not be checked for it; run this command inside that checkout to check it, and its next launch or credential sync warns if its ${SEARCH_CONSOLE_HOST} writes run without approval`;
}

type BindingInput = {
  sourceName: string;
  /** Project ids whose host credential config binds google-search-console to this source. */
  bindingProjectIds: readonly string[];
  /** The admin action's project root (the current checkout), when there is one. */
  cwdProjectRoot?: string;
};

/**
 * Spec §5.1 refusal (plans P-D1, P-D2). A source change that adds a write
 * scope is refused while any project that binds the source to
 * google-search-console has write action allow on the host in its approved
 * desired policy: that change removes the approval prompt for sitemap PUT
 * and site DELETE, and nobody would see it. Reads the state pointers and
 * approved policies only; never 1Password. A binding project whose checkout
 * or approval cannot be read warns and does not refuse; its next launch or
 * credential sync warns (warnSearchConsoleWritePairAtSync).
 */
export function assertReplaceKeepsSearchConsoleApproval(input: BindingInput & {
  previous: NamedSource | undefined;
  nextScopes: readonly string[];
}): void {
  if (input.bindingProjectIds.length === 0 || !scopesAddWrite(input.previous, input.nextScopes)) return;
  const unsafe: string[] = [];
  for (const project of bindingProjects(input.bindingProjectIds, input.cwdProjectRoot)) {
    if (project.root === undefined) {
      warn(uncheckedProjectWarning(input.sourceName, project.id, "refusal"));
      continue;
    }
    if (!unsafeProject(project)) continue;
    unsafe.push(`${printable(project.root)} (restore the prompt there with: ${restorePromptRemedy(project.pair)})`);
  }
  if (unsafe.length === 0) return;
  die([
    `${input.sourceName} source change adds a Search Console write scope, and ${SEARCH_CONSOLE_HOST} writes run without approval (write action allow) in a project that binds ${SEARCH_CONSOLE_TOKEN} to it: ${unsafe.join("; ")};`,
    `then run the replace again, or keep --scope ${GOOGLE_SA_READ_ONLY_SCOPE}`,
  ].join(" "));
}

/**
 * Spec §5.1 for a jwt or command source: its scope is unknown, so a replace
 * of a source bound to google-search-console under write action allow warns
 * and never refuses. Returns the warnings, so the caller emits them only
 * once the replace is saved. Reads what the refusal reads; never 1Password.
 */
export function replaceWithUnknownScopeWarnings(input: BindingInput & { sourceType: "command" | "jwt" }): string[] {
  if (input.bindingProjectIds.length === 0) return [];
  const warnings: string[] = [];
  for (const project of bindingProjects(input.bindingProjectIds, input.cwdProjectRoot)) {
    if (project.root === undefined) {
      warnings.push(uncheckedProjectWarning(input.sourceName, project.id, "warning"));
      continue;
    }
    if (!unsafeProject(project)) continue;
    warnings.push([
      `${input.sourceName} source is bound to ${SEARCH_CONSOLE_TOKEN} in ${printable(project.root)}, where ${SEARCH_CONSOLE_HOST} writes run without approval (write action allow), and a ${input.sourceType} source has a scope Runfree cannot read;`,
      "sitemap PUT and site DELETE will not prompt if it grants the webmasters write scope;",
      `restore the prompt there with: ${restorePromptRemedy(project.pair)}`,
    ].join(" "));
  }
  return warnings;
}
