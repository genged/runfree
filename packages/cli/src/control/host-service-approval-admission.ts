// Port admission on every host-side approval path (ruling R21).
//
// `runfree host-service add` admits its port before it writes policy. A
// `hostServices` entry can also reach an approval another way: the agent edits
// the desired policy, and the operator approves the whole candidate through
// the startup review, `runfree policy approve`, `runfree control approve`, the
// checkout-binding review, or the setup wizard's base review. Each of those
// paths calls `admitCandidateHostServices` for every entry that is added or
// changed relative to the approved layer, before the approval is written, and
// outside the project lifecycle lock (the candidate capture has already
// released it, as in R14). A refusal names the reason and the remedy; an
// admission returns the listener the review line names.

import type { DesiredNetworkPolicyJson } from "@runfree/runtime-contracts/desired-network-policy";
import type { HostServiceJson, HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { CliError } from "../errors.ts";
import { admitHostServicePort } from "../host-service-port-owner.ts";
import { remedy } from "../remedies.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { readApprovedNetworkPolicy } from "./approvals.ts";
import { isControlApprovalUnusableError } from "./refusals.ts";

export type AdmittedHostServiceOwner = Readonly<{ port: number; command: string; pid: number }>;

/** Admitted listeners keyed by host-service name. */
export type AdmittedHostServiceOwners = ReadonlyMap<string, AdmittedHostServiceOwner>;

export type HostServiceAdmit = typeof admitHostServicePort;

type Layer = "local" | "project";

function sameEntry(left: HostServiceJson | undefined, right: HostServiceJson): boolean {
  return left !== undefined && left.target === right.target && left.port === right.port;
}

/** Entries of `after` that are new or differ (port or target) from `before`. */
export function addedOrChangedHostServices(
  before: HostServicesJson | undefined,
  after: HostServicesJson | undefined,
): Array<{ name: string; entry: HostServiceJson }> {
  return Object.entries(after ?? {})
    .filter(([name, entry]) => !sameEntry(before?.[name], entry))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, entry]) => ({ name, entry }));
}

/**
 * The approved layer the candidate is compared against. An approval record
 * that carries no authority (a binding mismatch) or no approval at all
 * compares against nothing, so every candidate entry is admitted.
 */
function approvedLayer(runtime: RuntimeContext, layer: Layer): DesiredNetworkPolicyJson | undefined {
  try {
    return readApprovedNetworkPolicy(runtime.projectRoot, runtime.project, layer === "project" ? "network-project" : "network-local");
  } catch (error) {
    if (!isControlApprovalUnusableError(error)) throw error;
    return undefined;
  }
}

/**
 * Runs the live port admission for every host service the candidate layers
 * add or change. Throws a `CliError` naming every refusal and its remedy
 * before any approval is written; otherwise returns the admitted owners.
 */
export function admitCandidateHostServices(
  runtime: RuntimeContext,
  io: RuntimeIO,
  candidate: Partial<Record<Layer, DesiredNetworkPolicyJson>>,
  admit: HostServiceAdmit = admitHostServicePort,
): AdmittedHostServiceOwners {
  const owners = new Map<string, AdmittedHostServiceOwner>();
  const refusals: string[] = [];
  const refusedLayers = new Set<Layer>();
  for (const layer of ["project", "local"] as const) {
    const policy = candidate[layer];
    if (!policy) continue;
    for (const { name, entry } of addedOrChangedHostServices(approvedLayer(runtime, layer)?.hostServices, policy.hostServices)) {
      const admission = admit(runtime, io, entry.port);
      if (admission.ok) {
        owners.set(name, { port: entry.port, ...admission.owner });
      } else {
        refusals.push(`host service ${name} (127.0.0.1:${entry.port}, ${layer} layer): ${admission.reason}`);
        refusedLayers.add(layer);
      }
    }
  }
  if (refusals.length > 0) {
    // The entry is unapproved desired-policy drift, so `host-service remove`
    // (which refuses drift) is not the remedy: edit the layer, then review.
    throw new CliError([
      "refusing to approve the desired policy: a host service it adds or changes failed the port admission",
      ...refusals.map((line) => `  ${line}`),
      "start the service listening on 127.0.0.1, or delete the entry from that layer's hostServices; then review again with:",
      ...[...refusedLayers].map((layer) => `  ${remedy.policyReview(layer)}`),
    ].join("\n"));
  }
  return owners;
}

/** `127.0.0.1:10882 (idb_companion, pid 4242)` — the review's view of an admitted entry. */
export function admittedOwnerText(owner: AdmittedHostServiceOwner): string {
  return `127.0.0.1:${owner.port} (${owner.command}, pid ${owner.pid})`;
}

/** Review lines for admitted owners, for review surfaces with no change list. */
export function admittedOwnerReviewLines(owners: AdmittedHostServiceOwners): string[] {
  if (owners.size === 0) return [];
  return [
    "host services admitted (listener at review time):",
    ...[...owners.entries()].sort(([left], [right]) => left.localeCompare(right))
      .map(([name, owner]) => `  - host service ${name}: ${admittedOwnerText(owner)}`),
  ];
}
