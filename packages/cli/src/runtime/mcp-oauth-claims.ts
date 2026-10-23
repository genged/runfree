// Host-side OAuth claim rules for MCP servers (cross-host token endpoint
// design: X1, R1, R2, R9, R17, R20).
//
// An MCP server "claims" a host or an endpoint when its record or its declared
// OAuth configuration would make the proxy file token replies there under that
// server's handles. A claim is refused where another login's tokens pass:
//
// - a credential destination (the proxy injects a credential on that host);
// - a curated service host: every host of every bundle in
//   `scripts/services.ts`, enabled or not (the well-known login hosts);
// - a host another prepared MCP server uses (its resource host, its declared
//   hosts, and its recorded hosts), because that server's run-time endpoints
//   are not visible here;
// - an endpoint that equals, or for a prefix-matched registration endpoint
//   overlaps, another OAuth provider's endpoint (another MCP server or a
//   service).
//
// A server's own resource host is never refused for itself, as the proxy's
// `refusedHosts` exempts it. The same rules run at `mcp enable` (before any
// write) and at every projection, so a later change that makes a refusal apply
// drops the claim there.

import { normalizeHostname, pathMatchesPrefix } from "@runfree/runtime-contracts/network-policy";
import { SERVICES, type Service } from "../../../../scripts/services.ts";

export type ClaimEndpointKind = "metadata" | "token" | "registration";

export type ClaimEndpoint = {
  kind: ClaimEndpointKind;
  host: string;
  path: string;
  // Registration endpoints match by path prefix unless `exact`.
  exact?: true;
};

// One other user of hosts and endpoints: another prepared MCP server (one
// share group counts once) or a service OAuth provider.
export type ClaimUse = {
  label: string;
  hosts: readonly string[];
  endpoints: readonly ClaimEndpoint[];
};

export type OAuthClaimRules = {
  credentialHosts: ReadonlySet<string>;
  curatedHosts: ReadonlySet<string>;
  others: readonly ClaimUse[];
};

export type ClaimRefusal = {
  use: "credential" | "curated" | "server" | "endpoint";
  reason: string;
};

function normalizedOrUndefined(host: string): string | undefined {
  try {
    return normalizeHostname(host);
  } catch {
    return undefined;
  }
}

/** Every host of every curated service bundle, enabled or not, plus hosts a bundle dropped. */
export function curatedServiceHosts(registry: Record<string, Service> = SERVICES): Set<string> {
  const hosts = new Set<string>();
  for (const svc of Object.values(registry)) {
    for (const raw of [...svc.hosts.map((entry) => entry.host), ...(svc.removedHosts ?? [])]) {
      const host = normalizedOrUndefined(raw);
      if (host) hosts.add(host);
    }
  }
  return hosts;
}

/** Hosts where the proxy injects a credential, from a network policy's tokens. */
export function credentialDestinationHosts(tokens: Record<string, { credentials: ReadonlyArray<{ host: string }> }> | undefined): Set<string> {
  const hosts = new Set<string>();
  for (const token of Object.values(tokens ?? {})) {
    for (const credential of token.credentials) {
      const host = normalizedOrUndefined(credential.host);
      if (host) hosts.add(host);
    }
  }
  return hosts;
}

function matchesByPrefix(endpoint: ClaimEndpoint): boolean {
  return endpoint.kind === "registration" && endpoint.exact !== true;
}

/**
 * Whether two endpoints can match the same request: the same host and path,
 * or one is a prefix-matched registration endpoint whose prefix covers the
 * other's path.
 */
export function oauthEndpointsOverlap(left: ClaimEndpoint, right: ClaimEndpoint): boolean {
  if (left.host !== right.host) return false;
  if (left.path === right.path) return true;
  return (matchesByPrefix(left) && pathMatchesPrefix(right.path, left.path))
    || (matchesByPrefix(right) && pathMatchesPrefix(left.path, right.path));
}

export function endpointUrlText(endpoint: { host: string; path: string }): string {
  return `https://${endpoint.host}${endpoint.path}`;
}

/** Why `host` may not be claimed by a server whose resource host is `ownResourceHost`, if refused. */
export function oauthHostRefusal(rules: OAuthClaimRules, host: string, ownResourceHost: string): ClaimRefusal | undefined {
  if (host === ownResourceHost) return undefined;
  if (rules.credentialHosts.has(host)) {
    return { use: "credential", reason: `${host} is a credential destination: the proxy injects a credential there` };
  }
  if (rules.curatedHosts.has(host)) {
    return { use: "curated", reason: `${host} is a well-known host; other logins there would be captured` };
  }
  const other = rules.others.find((use) => use.hosts.includes(host));
  if (other) return { use: "server", reason: `${host} is used by ${other.label}` };
  return undefined;
}

/** Why `endpoint` may not be claimed by a server whose resource host is `ownResourceHost`, if refused. */
export function oauthEndpointRefusal(rules: OAuthClaimRules, endpoint: ClaimEndpoint, ownResourceHost: string): ClaimRefusal | undefined {
  const host = oauthHostRefusal(rules, endpoint.host, ownResourceHost);
  if (host) return host;
  for (const use of rules.others) {
    const collision = use.endpoints.find((other) => oauthEndpointsOverlap(endpoint, other));
    if (collision) {
      return {
        use: "endpoint",
        reason: `${endpointUrlText(endpoint)} overlaps ${use.label}'s ${collision.kind} endpoint ${endpointUrlText(collision)}`,
      };
    }
  }
  return undefined;
}
