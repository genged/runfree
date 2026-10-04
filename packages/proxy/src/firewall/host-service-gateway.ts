// Host-service gateway address (design "Gateway address", SR2/SR6/SR7/SR18).
//
// The address comes from the daemon, never from DNS: Compose writes
// `gateway.runfree.internal:host-gateway` into the proxy's /etc/hosts, and the
// root firewall supervisor reads that one entry. These helpers are pure; the
// supervisor owns the read, the pin, and the sticky refusal after the pin.

import { HOST_SERVICE_GATEWAY_ALIAS } from "@runfree/runtime-contracts/host-services";

import type { FirewallPlan } from "./nftables.js";

// The digest and its canonical form live in the shared status contract so the
// host CLI recomputes it with the same code.
export {
  hostServiceEntryKey,
  hostServiceSetDigest,
  sortHostServiceEntries,
  type HostServiceSetEntry,
} from "@runfree/runtime-contracts/proxy-status";

export type EtcHostsStat = { uid: number; mode: number; isFile: boolean };

const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
// Canonical dotted quad only: a leading-zero octet is read as octal by some
// resolvers, and the request proxy's gateway-file parser refuses it too.
const CANONICAL_IPV4_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);

// Exact alias-token match; `#` starts a comment anywhere on a line. IPv6 lines
// are ignored (Docker Desktop writes one for host-gateway; `proxy_egress` has
// IPv6 disabled and the nftables rule is IPv4 only). The matching IPv4 lines
// must agree on exactly one address.
export function parseHostServiceGatewayFromEtcHosts(text: string): { ip: string } | { error: string } {
  const addresses = new Set<string>();
  for (const rawLine of text.split("\n")) {
    const commentAt = rawLine.indexOf("#");
    const line = commentAt === -1 ? rawLine : rawLine.slice(0, commentAt);
    const tokens = line.trim().split(/\s+/).filter((token) => token !== "");
    if (tokens.length < 2) continue;
    const [address, ...names] = tokens;
    if (!names.includes(HOST_SERVICE_GATEWAY_ALIAS)) continue;
    if (address.includes(":")) continue;
    if (!CANONICAL_IPV4_RE.test(address)) {
      return { error: `${HOST_SERVICE_GATEWAY_ALIAS} has a malformed address in /etc/hosts` };
    }
    addresses.add(address);
  }
  if (addresses.size === 0) {
    return { error: `${HOST_SERVICE_GATEWAY_ALIAS} IPv4 entry missing from /etc/hosts` };
  }
  if (addresses.size > 1) {
    return {
      error: `${HOST_SERVICE_GATEWAY_ALIAS} has more than one IPv4 address in /etc/hosts: ${Array.from(addresses).sort().join(", ")}`,
    };
  }
  return { ip: Array.from(addresses)[0] };
}

// Root stats /etc/hosts before each read: only a root-owned regular file that
// no group or other user can write is trusted as the daemon's entry.
export function checkEtcHostsFile(stat: EtcHostsStat): string | undefined {
  if (!stat.isFile) return "/etc/hosts is not a regular file";
  if (stat.uid !== 0) return `/etc/hosts must be owned by uid 0, not uid ${stat.uid}`;
  if ((stat.mode & 0o022) !== 0) {
    return `/etc/hosts is group- or other-writable (mode ${(stat.mode & 0o7777).toString(8)})`;
  }
  return undefined;
}

// Amendment A2: the gateway gets its own validator, because the resolved-answer
// classifier rejects 192.168/16 where Docker Desktop's gateway lives. RFC 1918
// is required; loopback, link-local, the runtime subnets, and the proxy's own
// egress gateway and addresses are refused.
export function validateHostServiceGateway(ip: string, plan: FirewallPlan): string | undefined {
  if (!CANONICAL_IPV4_RE.test(ip)) return `host-service gateway ${ip} is not a canonical IPv4 address`;
  const value = ipv4ToInt(ip);
  if (cidrContains("127.0.0.0/8", value)) return `host-service gateway ${ip} is a loopback address`;
  if (cidrContains("169.254.0.0/16", value)) return `host-service gateway ${ip} is a link-local address`;
  if (![
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
  ].some((cidr) => cidrContains(cidr, value))) {
    return `host-service gateway ${ip} is not an RFC 1918 private address`;
  }
  if (ip === plan.egress.gatewayIp) return `host-service gateway ${ip} is the proxy egress gateway`;
  if (ip === plan.egress.sourceIp || ip === plan.internal.proxyIp) {
    return `host-service gateway ${ip} is a proxy address`;
  }
  for (const cidr of plan.runtimeSubnets ?? []) {
    if (cidrContains(cidr, value)) return `host-service gateway ${ip} is inside the runtime subnet ${cidr}`;
  }
  return undefined;
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((value, octet) => ((value << 8) + Number(octet)) >>> 0, 0);
}

function cidrContains(cidr: string, ip: number): boolean {
  const [networkRaw, prefixRaw] = cidr.split("/");
  // Runtime subnets come from env and were checked as IPv4 CIDRs at plan
  // build time; accept any four-octet form here so none is silently skipped.
  if (!networkRaw || !prefixRaw || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(networkRaw)) return false;
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (ipv4ToInt(networkRaw) & mask);
}
