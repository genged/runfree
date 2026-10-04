// Host services: agent access to an approved service on the Docker Desktop
// host's loopback. See local/specs/2026-10-03-host-services-design.md.
//
// This module holds the pure, side-effect-free policy contract: the reserved
// `runfree.internal` hostname suffix, the desired/effective policy shape for
// `hostServices`, and the `RUNFREE_HOST_SERVICES` env-list codec shared by the
// session template and the agent-side relay. It does not dial, resolve, or
// touch the filesystem. The reserved-suffix *refusal* lives in policy
// validation (`network-policy.ts`) and the proxy's `classifyConnect`, not
// here — `isReservedRunfreeHostname` is a predicate only.

import { isRecord } from "./primitives.js";

export const HOST_SERVICE_RESERVED_SUFFIX = "runfree.internal";
export const HOST_SERVICE_GATEWAY_ALIAS = "gateway.runfree.internal";
export const HOST_SERVICE_NAME_RE = /^[a-z][a-z0-9-]{0,62}$/;
export const HOST_SERVICE_TARGETS = ["host-loopback"] as const;
export type HostServiceTarget = typeof HOST_SERVICE_TARGETS[number];
export type HostServiceJson = { target: HostServiceTarget; port: number };
export type HostServicesJson = Record<string, HostServiceJson>;
export const HOST_SERVICES_ENV = "RUNFREE_HOST_SERVICES";
export const HOST_SERVICE_GATEWAY_STATUS_FILE = "host-service-gateway.json";

// Static port refusals (design "Policy shape", Port admission at add, SR5):
// Docker Engine's own TCP ports, a precautionary proxy port, runfree's own
// VNC default, and runfree's own MCP callback block. These never depend on
// what is reachable on a given host; the owner check (a later task) adds the
// live, per-host refusals.
const STATIC_REFUSED_PORT_REASONS: ReadonlyMap<number, string> = new Map([
  [2375, "the Docker Engine TCP port"],
  [2376, "the Docker Engine TLS port"],
  [3128, "a precautionary proxy port"],
  [5901, "runfree's own VNC default port"],
]);
const CALLBACK_BLOCK_START = 47100;
const CALLBACK_BLOCK_END = 48099;

function stripTrailingDot(host: string): string {
  return host.endsWith(".") ? host.slice(0, -1) : host;
}

export function isReservedRunfreeHostname(host: string): boolean {
  const normalized = stripTrailingDot(host.toLowerCase());
  return normalized === HOST_SERVICE_RESERVED_SUFFIX || normalized.endsWith(`.${HOST_SERVICE_RESERVED_SUFFIX}`);
}

export function refusedHostServicePortReason(port: number): string | undefined {
  const staticReason = STATIC_REFUSED_PORT_REASONS.get(port);
  if (staticReason !== undefined) return staticReason;
  if (port >= CALLBACK_BLOCK_START && port <= CALLBACK_BLOCK_END) return "runfree's own MCP callback block";
  return undefined;
}

export function hostServiceAuthority(name: string, port: number): string {
  return `${name}.${HOST_SERVICE_RESERVED_SUFFIX}:${port}`;
}

export type ParsedHostServiceAuthority =
  | { kind: "not-reserved" }
  | { kind: "malformed" }
  | { kind: "service"; name: string; port: number };

const HOST_SERVICE_AUTHORITY_RE = /^([a-z][a-z0-9-]{0,62})\.runfree\.internal:([1-9][0-9]{0,4})$/;

export function parseHostServiceAuthority(authority: string): ParsedHostServiceAuthority {
  const lastColon = authority.lastIndexOf(":");
  const hostPart = lastColon === -1 ? authority : authority.slice(0, lastColon);
  if (!isReservedRunfreeHostname(hostPart)) return { kind: "not-reserved" };

  const match = HOST_SERVICE_AUTHORITY_RE.exec(authority);
  if (!match) return { kind: "malformed" };
  const port = Number(match[2]);
  if (port > 65535) return { kind: "malformed" };
  return { kind: "service", name: match[1], port };
}

const HOST_SERVICE_ENTRY_KEYS = ["target", "port"];

function validateHostServiceEntry(
  name: string,
  value: unknown,
  prefix: string,
  issues: string[],
): HostServiceJson | undefined {
  const entryPrefix = `${prefix}.${name}`;
  if (!isRecord(value)) {
    issues.push(`${entryPrefix} must be an object`);
    return undefined;
  }

  for (const key of Object.keys(value)) {
    if (!HOST_SERVICE_ENTRY_KEYS.includes(key)) {
      issues.push(`${entryPrefix}.${key} is not a known field (known: ${HOST_SERVICE_ENTRY_KEYS.join(", ")})`);
    }
  }

  const target = value.target;
  if (target === "address") {
    issues.push(`${entryPrefix}.target address is not supported yet`);
    return undefined;
  }
  if (target !== "host-loopback") {
    issues.push(`${entryPrefix}.target must be "host-loopback"`);
    return undefined;
  }

  const port = value.port;
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    issues.push(`${entryPrefix}.port must be an integer from 1 to 65535`);
    return undefined;
  }

  const refusedReason = refusedHostServicePortReason(port as number);
  if (refusedReason !== undefined) {
    issues.push(`${entryPrefix}.port ${port} is refused: ${refusedReason}`);
    return undefined;
  }

  return { target: "host-loopback", port: port as number };
}

export function validateHostServices(raw: unknown, prefix: string, issues: string[]): HostServicesJson {
  if (!isRecord(raw)) {
    issues.push(`${prefix} must be an object`);
    return {};
  }

  const result: Record<string, HostServiceJson> = {};
  const portOwners = new Map<number, string>();

  for (const [name, value] of Object.entries(raw)) {
    if (!HOST_SERVICE_NAME_RE.test(name)) {
      issues.push(`${prefix} key ${name} is not a valid host-service name (must match ${HOST_SERVICE_NAME_RE.source})`);
      continue;
    }

    const entry = validateHostServiceEntry(name, value, prefix, issues);
    if (entry === undefined) continue;

    const existingOwner = portOwners.get(entry.port);
    if (existingOwner !== undefined) {
      issues.push(`${prefix} has duplicate port ${entry.port} used by ${existingOwner} and ${name}`);
      continue;
    }
    portOwners.set(entry.port, name);
    result[name] = entry;
  }

  return Object.fromEntries(Object.entries(result).sort(([left], [right]) => left.localeCompare(right)));
}

export function formatHostServicesEnv(services: HostServicesJson): string {
  return Object.entries(services)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, entry]) => `${name}:${entry.port}`)
    .join(",");
}

const HOST_SERVICES_ENV_PAIR_RE = /^([a-z][a-z0-9-]{0,62}):([1-9][0-9]{0,4})$/;

export function parseHostServicesEnv(value: string): Array<{ name: string; port: number }> {
  const seenNames = new Set<string>();
  const seenPorts = new Set<number>();
  const result: Array<{ name: string; port: number }> = [];

  for (const pair of value.split(",")) {
    const match = HOST_SERVICES_ENV_PAIR_RE.exec(pair);
    if (!match) throw new Error(`invalid ${HOST_SERVICES_ENV} entry: ${JSON.stringify(pair)}`);
    const name = match[1];
    const port = Number(match[2]);
    if (port > 65535) throw new Error(`invalid ${HOST_SERVICES_ENV} port: ${pair}`);
    if (seenNames.has(name)) throw new Error(`invalid ${HOST_SERVICES_ENV} duplicate name: ${name}`);
    if (seenPorts.has(port)) throw new Error(`invalid ${HOST_SERVICES_ENV} duplicate port: ${port}`);
    seenNames.add(name);
    seenPorts.add(port);
    result.push({ name, port });
  }

  return result;
}
