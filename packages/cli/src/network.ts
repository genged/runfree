import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import type { ProjectInfo } from "./config.ts";
import { die } from "./errors.ts";

export type RuntimeNetwork = {
  subnet: string;
  proxyIp: string;
  agentIp: string;
  callbackSidecarIp: string;
  proxyEgressSubnet: string;
  proxyEgressGateway: string;
  proxyEgressIp: string;
};

type InternalRuntimeNetwork = {
  subnet: string;
  proxyIp: string;
  agentIp: string;
  callbackSidecarIp: string;
};

function subnetOctets(cidr: string): [number, number, number, number] | undefined {
  const match = cidr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/24$/);
  if (!match) return undefined;
  const octets = match.slice(1).map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return undefined;
  return octets as [number, number, number, number];
}

/**
 * The fixed low addresses of the internal /24. Only `.10` holds a container in
 * the current topology; `.11` and `.12` are reservations, and the difference
 * matters when reading `runtime-network.json`:
 *
 * - `.10` proxy. The trust boundary, and the only ingress the session firewall
 *   rules point at.
 * - `.11` the retired shared agent position. Every agent runs in its own
 *   session container, so nothing is created here. It is still live input:
 *   `validateProxyFirewall` routes to it (`ip route get`) to learn the proxy's
 *   internal interface for the nftables proof — a route lookup needs an
 *   address in the subnet, not an occupant — and it is the
 *   `RUNFREE_CONTAINER_IP` the v2 control-plane topology contract validates.
 * - `.12` the retired Compose `mcp_callback` relay position. The relay is
 *   deleted; MCP OAuth callbacks are per-session ingress forwarders that
 *   target the live session address instead. Nothing recognizes this address
 *   anymore: a container occupying it is an unknown participant and fails
 *   allocation closed.
 *
 * Reclaiming either address would change the runtime-isolation approval subject
 * and the v2 topology digest — a forced re-approval and full recreate for every
 * project — to free two addresses nothing else can use: sessions are allocated
 * from SESSION_SOURCE_IP_FIRST_HOST upward, which is deliberately above these
 * (asserted in network.test.ts). Any container that does occupy `.11` or `.12`
 * without being a recognized control-plane participant is an unknown
 * participant, and session allocation fails closed on it.
 *
 * A pinned `runtime.agentIp` is held only to distinctness and subnet membership,
 * so it can be placed inside the session pool. That is inert rather than a
 * conflict, because no container is created at the agent position at all.
 */
function internalNetworkFromSubnet(subnet: string): InternalRuntimeNetwork {
  const octets = subnetOctets(subnet);
  if (!octets || octets[3] !== 0) {
    die(`runtime subnet must be an IPv4 /24 ending in .0: ${subnet}`);
  }
  const prefix = `${octets[0]}.${octets[1]}.${octets[2]}`;
  return {
    subnet,
    proxyIp: `${prefix}.10`,
    agentIp: `${prefix}.11`,
    callbackSidecarIp: `${prefix}.12`,
  };
}

function egressNetworkFromSubnet(subnet: string): Pick<RuntimeNetwork, "proxyEgressSubnet" | "proxyEgressGateway" | "proxyEgressIp"> {
  const octets = subnetOctets(subnet);
  if (!octets || octets[3] !== 0) {
    die(`runtime proxy egress subnet must be an IPv4 /24 ending in .0: ${subnet}`);
  }
  const prefix = `${octets[0]}.${octets[1]}.${octets[2]}`;
  return {
    proxyEgressSubnet: subnet,
    proxyEgressGateway: `${prefix}.1`,
    proxyEgressIp: `${prefix}.10`,
  };
}

function shiftedSubnet(subnet: string, offset: number): string | undefined {
  const octets = subnetOctets(subnet);
  if (!octets || octets[3] !== 0) return undefined;
  return `${octets[0]}.${octets[1]}.${(octets[2] + offset) % 256}.0/24`;
}

function networkFromSubnets(internal: InternalRuntimeNetwork, proxyEgressSubnet: string): RuntimeNetwork {
  assertDistinctInternalRuntimeIps(internal);
  return {
    ...internal,
    ...egressNetworkFromSubnet(proxyEgressSubnet),
  };
}

function assertDistinctInternalRuntimeIps(internal: InternalRuntimeNetwork): void {
  const values = [
    ["proxyIp", internal.proxyIp],
    ["agentIp", internal.agentIp],
    ["callbackSidecarIp", internal.callbackSidecarIp],
  ] as const;
  const seen = new Map<string, string>();
  for (const [name, value] of values) {
    const previous = seen.get(value);
    if (previous) die(`runtime ${name} must be distinct from ${previous}: ${value}`);
    seen.set(value, name);
  }
  const range = cidrRange(internal.subnet);
  for (const [name, value] of values) {
    const ip = ipToNumber(value);
    if (!range || ip === undefined || ip <= range.start || ip >= range.end) {
      die(`runtime ${name} must be inside runtime subnet ${internal.subnet}: ${value}`);
    }
  }
}

export function networkFromSubnet(subnet: string): RuntimeNetwork {
  const internal = internalNetworkFromSubnet(subnet);
  const proxyEgressSubnet = shiftedSubnet(subnet, 1);
  if (!proxyEgressSubnet || subnetOverlaps(subnet, proxyEgressSubnet)) {
    die(`could not derive a proxy egress subnet from runtime subnet ${subnet}`);
  }
  return networkFromSubnets(internal, proxyEgressSubnet);
}

function candidateSubnets(projectRoot: string): string[] {
  const digest = crypto.createHash("sha256").update(projectRoot).digest();
  const third = digest[0];
  return [
    `172.30.${third}.0/24`,
    `172.31.${third}.0/24`,
    `172.28.${third}.0/24`,
    `172.29.${third}.0/24`,
    `10.${64 + (digest[1] % 64)}.${third}.0/24`,
  ];
}

function ipToNumber(ip: string): number | undefined {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function cidrRange(cidr: string): { start: number; end: number } | undefined {
  const match = cidr.match(/^([0-9.]+)\/(\d{1,2})$/);
  if (!match) return undefined;
  const ip = ipToNumber(match[1]);
  const prefix = Number(match[2]);
  if (ip === undefined || prefix < 0 || prefix > 32) return undefined;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (ip & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return { start, end: start + size - 1 };
}

export function subnetOverlaps(left: string, right: string): boolean {
  const leftRange = cidrRange(left);
  const rightRange = cidrRange(right);
  if (!leftRange || !rightRange) return false;
  return leftRange.start <= rightRange.end && rightRange.start <= leftRange.end;
}

function runtimeNetworkPath(project: ProjectInfo): string {
  return path.join(project.paths.stateDir, "runtime-network.json");
}

function normalizeRuntimeNetwork(parsed: Partial<RuntimeNetwork>): RuntimeNetwork | undefined {
  if (!parsed.subnet || !parsed.proxyIp || !parsed.agentIp) return undefined;
  const defaultInternal = internalNetworkFromSubnet(parsed.subnet);
  const internal = {
    subnet: parsed.subnet,
    proxyIp: parsed.proxyIp,
    agentIp: parsed.agentIp,
    callbackSidecarIp: parsed.callbackSidecarIp ?? defaultInternal.callbackSidecarIp,
  };
  const proxyEgressSubnet = parsed.proxyEgressSubnet ?? shiftedSubnet(parsed.subnet, 1);
  if (!proxyEgressSubnet) return undefined;
  const network = networkFromSubnets(internal, proxyEgressSubnet);
  if (parsed.proxyEgressGateway) network.proxyEgressGateway = parsed.proxyEgressGateway;
  if (parsed.proxyEgressIp) network.proxyEgressIp = parsed.proxyEgressIp;
  return network;
}

export function readPersistedRuntimeNetwork(project: ProjectInfo): RuntimeNetwork | undefined {
  try {
    const parsed = JSON.parse(fs.readFileSync(runtimeNetworkPath(project), "utf8")) as Partial<RuntimeNetwork>;
    return normalizeRuntimeNetwork(parsed);
  } catch {
    return undefined;
  }
}

function writePersistedNetwork(project: ProjectInfo, network: RuntimeNetwork): void {
  fs.mkdirSync(project.paths.stateDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(runtimeNetworkPath(project), `${JSON.stringify(network, null, 2)}\n`, { mode: 0o600 });
}

function manualNetwork(project: ProjectInfo): InternalRuntimeNetwork | undefined {
  const runtime = project.config.runtime ?? {};
  if (!runtime.subnet && !runtime.proxyIp && !runtime.agentIp) return undefined;
  if (!runtime.subnet || !runtime.proxyIp || !runtime.agentIp) {
    die("runtime subnet, proxyIp, and agentIp must be set together");
  }
  return {
    subnet: runtime.subnet,
    proxyIp: runtime.proxyIp,
    agentIp: runtime.agentIp,
    callbackSidecarIp: internalNetworkFromSubnet(runtime.subnet).callbackSidecarIp,
  };
}

function networkOverlapsAny(network: RuntimeNetwork, subnets: string[]): boolean {
  return subnets.some((subnet) => subnetOverlaps(network.subnet, subnet)
    || subnetOverlaps(network.proxyEgressSubnet, subnet));
}

function chooseProxyEgressSubnet(projectRoot: string, internalSubnet: string, existingSubnets: string[]): string | undefined {
  const candidates = [
    shiftedSubnet(internalSubnet, 1),
    ...candidateSubnets(`${projectRoot}\0proxy-egress`),
    ...candidateSubnets(`${projectRoot}\0proxy-egress-fallback`),
  ].filter((subnet): subnet is string => Boolean(subnet));

  for (const subnet of Array.from(new Set(candidates))) {
    if (subnetOverlaps(internalSubnet, subnet)) continue;
    if (existingSubnets.some((existing) => subnetOverlaps(subnet, existing))) continue;
    return subnet;
  }
  return undefined;
}

export function resolveRuntimeNetwork(
  projectRoot: string,
  project: ProjectInfo,
  existingSubnets: string[],
  options: { persist?: boolean } = {},
): RuntimeNetwork {
  const configured = manualNetwork(project);
  if (configured) {
    const overlaps = existingSubnets.find((subnet) => subnetOverlaps(configured.subnet, subnet));
    if (overlaps) die(`configured runtime subnet ${configured.subnet} overlaps existing Docker network ${overlaps}`);
    const proxyEgressSubnet = chooseProxyEgressSubnet(projectRoot, configured.subnet, existingSubnets);
    if (!proxyEgressSubnet) die("could not find a non-overlapping Docker subnet for proxy egress");
    return networkFromSubnets(configured, proxyEgressSubnet);
  }

  const persisted = readPersistedRuntimeNetwork(project);
  if (persisted && !networkOverlapsAny(persisted, existingSubnets)) {
    return persisted;
  }

  for (const subnet of candidateSubnets(projectRoot)) {
    if (existingSubnets.some((existing) => subnetOverlaps(subnet, existing))) continue;
    const internal = internalNetworkFromSubnet(subnet);
    const proxyEgressSubnet = chooseProxyEgressSubnet(projectRoot, subnet, existingSubnets);
    if (!proxyEgressSubnet) continue;
    const network = networkFromSubnets(internal, proxyEgressSubnet);
    if (options.persist !== false) writePersistedNetwork(project, network);
    return network;
  }

  die("could not find a non-overlapping Docker subnet for this project");
}
