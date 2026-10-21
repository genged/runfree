// The claim checks and share groups that `mcp enable` and every projection
// run over MCP servers (cross-host token endpoint design: X1, X3, R1-R3, R9,
// R16, R17). `mcp-oauth-claims.ts` holds the rules; this module applies them
// to a server's declared OAuth configuration and its enable records, so the
// review and the projection refuse exactly the same claims.

import type { McpEnabledEndpoint, McpEnabledHost, McpEnabledRecord } from "./mcp-enabled.ts";
import {
  type ClaimEndpoint,
  type ClaimRefusal,
  type ClaimUse,
  endpointUrlText,
  type OAuthClaimRules,
  oauthEndpointRefusal,
  oauthHostRefusal,
} from "./mcp-oauth-claims.ts";

// One claimant as the rules see it: a prepared MCP server, or one share
// group, whose members count once. `key` is unique per claimant.
export type ClaimServerView = {
  key: string;
  label: string;
  resourceHost?: string;
  // The descriptor's declared OAuth configuration (R9, R17).
  declaredMetadataUrl?: string;
  declaredTokenEndpoints: ReadonlyArray<{ host: string; path: string }>;
  // The enable records joined to this claimant's members.
  records: readonly McpEnabledRecord[];
};

export type ClaimBase = {
  credentialHosts: ReadonlySet<string>;
  curatedHosts: ReadonlySet<string>;
  // Service OAuth providers (their endpoints only).
  serviceUses: readonly ClaimUse[];
};

function urlEndpoint(raw: string): { host: string; path: string } | undefined {
  try {
    const url = new URL(raw);
    return { host: url.hostname.toLowerCase(), path: url.pathname || "/" };
  } catch {
    return undefined;
  }
}

function recordClaimEndpoint(endpoint: McpEnabledEndpoint): ClaimEndpoint {
  return { kind: endpoint.kind, host: endpoint.host, path: endpoint.path, ...(endpoint.exact ? { exact: true as const } : {}) };
}

/** Every host and endpoint a claimant uses, as another claimant's rules see them (R2). */
export function claimUseOf(view: ClaimServerView): ClaimUse {
  const hosts = new Set<string>();
  const endpoints: ClaimEndpoint[] = [];
  if (view.resourceHost) hosts.add(view.resourceHost);
  const metadata = view.declaredMetadataUrl ? urlEndpoint(view.declaredMetadataUrl) : undefined;
  if (metadata) {
    hosts.add(metadata.host);
    endpoints.push({ kind: "metadata", ...metadata });
  }
  for (const endpoint of view.declaredTokenEndpoints) {
    hosts.add(endpoint.host);
    endpoints.push({ kind: "token", host: endpoint.host, path: endpoint.path });
  }
  for (const record of view.records) {
    for (const host of record.oauthHosts) hosts.add(host.host);
    for (const endpoint of record.oauthEndpoints ?? []) endpoints.push(recordClaimEndpoint(endpoint));
  }
  return { label: view.label, hosts: [...hosts].sort(), endpoints };
}

/** The rules for one claimant: every other claimant and service provider is "another use". */
export function claimRulesFor(views: readonly ClaimServerView[], key: string, base: ClaimBase): OAuthClaimRules {
  return {
    credentialHosts: base.credentialHosts,
    curatedHosts: base.curatedHosts,
    others: [...views.filter((view) => view.key !== key).map(claimUseOf), ...base.serviceUses],
  };
}

export type ClaimDrop = {
  // What was dropped, for the warning: "OAuth host x", "token endpoint https://...".
  subject: string;
  refusal: ClaimRefusal;
};

export type FilteredClaims = {
  // Copies of the records without any refused host or endpoint. A cross-host
  // host loses its endpoints with it, and the reverse (X3).
  records: McpEnabledRecord[];
  refusedDeclaredTokenEndpoints: Array<{ host: string; path: string }>;
  metadataUrlRefused: boolean;
  drops: ClaimDrop[];
};

/**
 * Apply the claim rules to a claimant's declared configuration and records.
 * The claimant's own resource host is exempt, as the proxy exempts it.
 */
export function filterClaims(view: ClaimServerView, rules: OAuthClaimRules): FilteredClaims {
  const own = view.resourceHost ?? "";
  const drops: ClaimDrop[] = [];
  const seen = new Set<string>();
  const drop = (subject: string, refusal: ClaimRefusal): void => {
    if (seen.has(subject)) return;
    seen.add(subject);
    drops.push({ subject, refusal });
  };

  const refusedDeclaredTokenEndpoints: Array<{ host: string; path: string }> = [];
  for (const endpoint of view.declaredTokenEndpoints) {
    const refusal = oauthEndpointRefusal(rules, { kind: "token", host: endpoint.host, path: endpoint.path }, own);
    if (!refusal) continue;
    refusedDeclaredTokenEndpoints.push({ host: endpoint.host, path: endpoint.path });
    drop(`declared token endpoint ${endpointUrlText(endpoint)}`, refusal);
  }
  let metadataUrlRefused = false;
  const metadata = view.declaredMetadataUrl ? urlEndpoint(view.declaredMetadataUrl) : undefined;
  if (metadata) {
    const refusal = oauthHostRefusal(rules, metadata.host, own);
    if (refusal) {
      metadataUrlRefused = true;
      drop(`declared metadata URL ${endpointUrlText(metadata)}`, refusal);
    }
  }

  const records = view.records.map((record): McpEnabledRecord => {
    const droppedHosts = new Set<string>();
    for (const host of record.oauthHosts) {
      const refusal = oauthHostRefusal(rules, host.host, own);
      if (refusal) {
        droppedHosts.add(host.host);
        drop(`OAuth host ${host.host}`, refusal);
      }
    }
    const endpointRefused = (endpoint: McpEnabledEndpoint): ClaimRefusal | undefined => (endpoint.kind === "metadata"
      ? oauthHostRefusal(rules, endpoint.host, own)
      : oauthEndpointRefusal(rules, recordClaimEndpoint(endpoint), own));
    for (const endpoint of record.oauthEndpoints ?? []) {
      if (droppedHosts.has(endpoint.host)) continue;
      const refusal = endpointRefused(endpoint);
      if (!refusal) continue;
      drop(`${endpoint.kind} endpoint ${endpointUrlText(endpoint)}`, refusal);
      // A cross-host host exists only for its endpoints: it goes with them.
      const host = record.oauthHosts.find((entry) => entry.host === endpoint.host);
      if (host?.crossHost) droppedHosts.add(endpoint.host);
    }
    const keptHosts: McpEnabledHost[] = record.oauthHosts.filter((host) => !droppedHosts.has(host.host));
    const keptEndpoints = (record.oauthEndpoints ?? []).filter((endpoint) => !droppedHosts.has(endpoint.host) && !endpointRefused(endpoint));
    return {
      ...record,
      oauthHosts: keptHosts,
      ...(record.oauthEndpoints !== undefined ? { oauthEndpoints: keptEndpoints } : {}),
    };
  });
  return { records, refusedDeclaredTokenEndpoints, metadataUrlRefused, drops };
}

// --- Share groups (R16) -----------------------------------------------------

export type ShareGroupInput = {
  digest: string;
  members: ReadonlyArray<{ providerId: string; enabledAt?: string }>;
};

export type ShareGroupBump = {
  digest: string;
  providerIds: string[];
  reason: "formed" | "moved";
};

export type ShareGroupSettlement = {
  owners: Map<string, string>;
  state: Record<string, { owner: string }>;
  bumps: ShareGroupBump[];
};

export type StoredShareGroup = { owner: string; released?: true };

// The member that owns a group that has no valid stored owner: the one
// enabled first, then the lexically smallest provider id.
function pickOwner(members: ShareGroupInput["members"]): string {
  const sorted = [...members].sort((left, right) => {
    if (left.enabledAt !== right.enabledAt) {
      if (left.enabledAt === undefined) return 1;
      if (right.enabledAt === undefined) return -1;
      return left.enabledAt < right.enabledAt ? -1 : 1;
    }
    return left.providerId < right.providerId ? -1 : left.providerId > right.providerId ? 1 : 0;
  });
  return sorted[0]?.providerId ?? "";
}

/**
 * Settle each group's sticky owner. A stored owner that is still a member
 * stays. A group with no stored owner forms now: a group of one needs no
 * clear, but a group that forms with several members may hold handles from
 * before it shared (the upgrade case), so every member's OAuth state is
 * cleared. An owner that left, or that `mcp revoke` released, moves to
 * another member, which clears every member's state, because handles are tied
 * to the owner's server identity. Groups with no member in this projection
 * are forgotten.
 */
export function settleShareGroupOwners(
  groups: readonly ShareGroupInput[],
  stored: Readonly<Record<string, StoredShareGroup>>,
): ShareGroupSettlement {
  const owners = new Map<string, string>();
  const state: Record<string, { owner: string }> = {};
  const bumps: ShareGroupBump[] = [];
  for (const group of groups) {
    const providerIds = [...new Set(group.members.map((member) => member.providerId))].sort();
    const previous = stored[group.digest];
    let owner: string;
    if (previous !== undefined && !previous.released && providerIds.includes(previous.owner)) {
      owner = previous.owner;
    } else if (previous !== undefined) {
      const others = group.members.filter((member) => member.providerId !== previous.owner);
      owner = pickOwner(others.length > 0 ? others : group.members);
      bumps.push({ digest: group.digest, providerIds, reason: "moved" });
    } else {
      owner = pickOwner(group.members);
      if (providerIds.length > 1) bumps.push({ digest: group.digest, providerIds, reason: "formed" });
    }
    owners.set(group.digest, owner);
    state[group.digest] = { owner };
  }
  return { owners, state, bumps };
}
