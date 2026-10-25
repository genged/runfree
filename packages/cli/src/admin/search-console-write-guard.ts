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

import { readApprovedNetworkPolicy } from "../control/approvals.ts";
import { compileDesiredPolicies } from "../control/compiler.ts";
import { remedy } from "../remedies.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import {
  describeSource,
  loadSourceRegistry,
  loadTokenConfig,
  type SourceRegistry,
  type TokenSource,
} from "./admin-core.ts";

export const SEARCH_CONSOLE_HOST = "searchconsole.googleapis.com";
export const SEARCH_CONSOLE_TOKEN = "google-search-console";
export const SEARCH_CONSOLE_SERVICE = "google-search-console";

export type BindingScope = "read-only" | "write" | "unknown";

/** undefined: the token has no binding. Phase 1: every binding is "unknown". */
export function searchConsoleBindingScope(
  binding: TokenSource | undefined,
  _registry: SourceRegistry | undefined,
): BindingScope | undefined {
  if (!binding) return undefined;
  // No source kind exposes its scope yet; a google-service-account source
  // (Phase 2) is the first that can prove one.
  return "unknown";
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

/**
 * The warning for the project's approved desired pair and its current
 * binding, or undefined. Runs inside an admin action (it reads the host
 * credential config) and after the desired-policy transaction, never under
 * its lock. The remedy names the layer that holds the service entry.
 */
export function searchConsoleWarningForApprovedPolicy(runtime: RuntimeContext): string | undefined {
  const project = readApprovedNetworkPolicy(runtime.projectRoot, runtime.project, "network-project");
  const local = readApprovedNetworkPolicy(runtime.projectRoot, runtime.project, "network-local");
  if (!project && !local) return undefined;
  const empty = { version: 2 as const, hosts: [] };
  const compiled = compileDesiredPolicies({ project: project ?? empty, local: local ?? empty });
  const binding = loadTokenConfig()[SEARCH_CONSOLE_TOKEN];
  return searchConsoleWarningFor({
    policy: compiled.policy,
    binding,
    registry: binding?.source === "named" ? loadSourceRegistry() : undefined,
    local: local?.services !== undefined && Object.hasOwn(local.services, SEARCH_CONSOLE_SERVICE),
  });
}
