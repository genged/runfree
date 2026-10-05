// Proxy policy-generation status contract (see the convergent proxy token
// store design spec). Both halves of the host↔proxy convergence ack import
// this module: the proxy-side writers (root firewall supervisor →
// firewall.json; uid-1001 request proxy → request-proxy/request-proxy.json)
// and the CLI-side reader that polls the files over docker exec. Keeping the
// paths, shapes, and single-line JSON framing here means a proxy-side change
// cannot silently diverge from the CLI parser.

import { HOST_SERVICE_NAME_RE } from "./host-services.js";
import { sha256Digest } from "./primitives.js";

// Fixed by contract, like the .runfree/network-policy.json path: an env knob
// honored by only one side of the host↔proxy ack protocol would silently
// break convergence.
export const DEFAULT_PROXY_STATUS_DIR = "/run/runfree-proxy-status";

export function firewallStatusPath(statusDir: string = DEFAULT_PROXY_STATUS_DIR): string {
  return `${statusDir}/firewall.json`;
}

// request-proxy.json lives in a uid-1001-owned subdirectory pre-created by the
// entrypoint; the status root stays root-owned so the uid-1001 request proxy
// can never write firewall.json (the convergence claim that matters for
// policy removals).
export function requestProxyStatusDir(statusDir: string = DEFAULT_PROXY_STATUS_DIR): string {
  return `${statusDir}/request-proxy`;
}

export function requestProxyStatusPath(statusDir: string = DEFAULT_PROXY_STATUS_DIR): string {
  return `${requestProxyStatusDir(statusDir)}/request-proxy.json`;
}

type GenerationStatusIdentity = {
  generation: string;
  controlGeneration?: string;
  policyGeneration?: string;
};

export type FirewallGenerationStatus = GenerationStatusIdentity & {
  rulesetVerified: boolean;
  appliedAt: string;
  // Diagnostics only (R23): nothing reads these to decide convergence.
  // `hostServiceSetDigest` (below) is over the root supervisor's applied
  // record of `@host_service` and `host_service_draining`, updated only after
  // an atomic `nft -f` batch succeeds; not a kernel read-back. The host proof
  // reads the kernel sets separately. `hostServiceDraining` is the number of
  // pairs still draining. A host-service removal converges by ordering
  // instead: the supervisor cuts before it publishes a status naming the new
  // effective policy generation, and activation waits for that status.
  hostServiceSetDigest?: string;
  hostServiceDraining?: number;
};

export type RequestProxyGenerationStatus = GenerationStatusIdentity & {
  appliedAt: string;
  // This request proxy deletes OAuth state stamped with a provider state
  // epoch other than the applied policy's before it publishes the status, so
  // a status naming a generation proves that generation's clears happened.
  // A proxy without the marker predates epochs and proves nothing.
  oauthStateEpochs?: 1;
  // Live (and dialling) host-service splices per name, for diagnostics only
  // (R23). A name absent from the map has no splice. Convergence of a removal
  // comes from ordering, not from this field: the request proxy cuts splices
  // of a removed entry before it publishes the status naming the effective
  // policy generation that removed it, and activation waits for that status.
  hostServiceSplices?: Record<string, number>;
};

export type ParsedGenerationStatus = {
  controlGeneration?: string;
  generation: string;
  hostServiceDraining?: number;
  hostServiceSetDigest?: string;
  hostServiceSplices?: Record<string, number>;
  oauthStateEpochs?: true;
  policyGeneration?: string;
  rulesetVerified?: boolean;
};

// Root-written hand-off of the pinned host-service gateway to the uid-1001
// request proxy (design "Gateway address"). The root firewall supervisor is
// the only writer; it validates the address before writing. Exactly one of
// `gatewayIp` and `unavailableReason` is present.
export type HostServiceGatewayStatus = {
  schemaVersion: 1;
  policyGeneration: string;
  gatewayIp?: string;
  unavailableReason?: string;
  writtenAt: string;
};

const HOST_SERVICE_GATEWAY_STATUS_KEYS = new Set([
  "schemaVersion",
  "policyGeneration",
  "gatewayIp",
  "unavailableReason",
  "writtenAt",
]);
const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
const STRICT_DOTTED_QUAD_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);
const UNAVAILABLE_REASON_LIMIT = 512;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

export function parseHostServiceGatewayStatus(text: string): HostServiceGatewayStatus {
  const parsed = JSON.parse(text) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("host-service gateway status must be a JSON object");
  }
  const record = parsed as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!HOST_SERVICE_GATEWAY_STATUS_KEYS.has(key)) {
      throw new Error(`host-service gateway status has an unknown key: ${key}`);
    }
  }
  if (record.schemaVersion !== 1) throw new Error("host-service gateway status schemaVersion must be 1");
  if (!isNonEmptyString(record.policyGeneration)) {
    throw new Error("host-service gateway status policyGeneration must be a non-empty string");
  }
  if (!isNonEmptyString(record.writtenAt)) {
    throw new Error("host-service gateway status writtenAt must be a non-empty string");
  }
  const hasGatewayIp = "gatewayIp" in record;
  const hasUnavailableReason = "unavailableReason" in record;
  if (hasGatewayIp === hasUnavailableReason) {
    throw new Error("host-service gateway status must carry exactly one of gatewayIp and unavailableReason");
  }
  if (hasGatewayIp) {
    if (typeof record.gatewayIp !== "string" || !STRICT_DOTTED_QUAD_RE.test(record.gatewayIp)) {
      throw new Error("host-service gateway status gatewayIp must be a dotted-quad IPv4 address");
    }
    return {
      schemaVersion: 1,
      policyGeneration: record.policyGeneration,
      gatewayIp: record.gatewayIp,
      writtenAt: record.writtenAt,
    };
  }
  if (!isNonEmptyString(record.unavailableReason) || record.unavailableReason.length > UNAVAILABLE_REASON_LIMIT) {
    throw new Error(`host-service gateway status unavailableReason must be a non-empty string of at most ${UNAVAILABLE_REASON_LIMIT} characters`);
  }
  return {
    schemaVersion: 1,
    policyGeneration: record.policyGeneration,
    unavailableReason: record.unavailableReason,
    writtenAt: record.writtenAt,
  };
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

// Malformed optional fields are dropped, like `rulesetVerified`: a reader
// that needs the field then sees it absent and does not claim convergence.
function parseHostServiceSplices(value: unknown): Record<string, number> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const result: Record<string, number> = {};
  for (const [name, count] of Object.entries(value)) {
    if (!HOST_SERVICE_NAME_RE.test(name) || !isNonNegativeInteger(count)) return undefined;
    result[name] = count;
  }
  return result;
}

// One `<ipv4> . <port>` member of `@host_service` or `host_service_draining`.
export type HostServiceSetEntry = { ip: string; port: number };

export function hostServiceEntryKey(entry: HostServiceSetEntry): string {
  return `${entry.ip} . ${entry.port}`;
}

function ipv4SortKey(ip: string): number {
  return ip.split(".").reduce((value, octet) => ((value << 8) + Number(octet)) >>> 0, 0);
}

// De-duplicated, ordered by numeric address then port.
export function sortHostServiceEntries(entries: readonly HostServiceSetEntry[]): HostServiceSetEntry[] {
  const unique = new Map<string, HostServiceSetEntry>();
  for (const entry of entries) unique.set(hostServiceEntryKey(entry), { ip: entry.ip, port: entry.port });
  return Array.from(unique.values()).sort((left, right) =>
    ipv4SortKey(left.ip) - ipv4SortKey(right.ip) || left.port - right.port);
}

// The firewall status `hostServiceSetDigest`. Canonical form:
// `sha256:` + hex sha256 of
// `JSON.stringify({ accept: [...keys], draining: [...keys] })`, where each
// list is `sortHostServiceEntries(...)` mapped through `hostServiceEntryKey`
// ("192.168.65.254 . 10882"). The proxy writer and the host reader both call
// this function, so the two sides cannot drift.
export function hostServiceSetDigest(
  accept: readonly HostServiceSetEntry[],
  draining: readonly HostServiceSetEntry[],
): string {
  return sha256Digest(JSON.stringify({
    accept: sortHostServiceEntries(accept).map(hostServiceEntryKey),
    draining: sortHostServiceEntries(draining).map(hostServiceEntryKey),
  }));
}

// The CLI reads both files in one exec and splits on lines, so each status
// file must serialize to exactly one JSON line. This serializer is the only
// sanctioned writer framing; JSON.stringify never emits raw newlines, so the
// invariant holds by construction.
export function serializeGenerationStatus(
  status: FirewallGenerationStatus | RequestProxyGenerationStatus | HostServiceGatewayStatus,
): string {
  return `${JSON.stringify(status)}\n`;
}

export function parseGenerationStatusLine(raw: string): ParsedGenerationStatus | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
  const record = parsed as Record<string, unknown>;
  if (typeof record.generation !== "string" || record.generation === "") return undefined;
  const hasControlGeneration = typeof record.controlGeneration === "string" && record.controlGeneration !== "";
  const hasPolicyGeneration = typeof record.policyGeneration === "string" && record.policyGeneration !== "";
  if (hasControlGeneration !== hasPolicyGeneration) return undefined;
  if (hasPolicyGeneration && record.policyGeneration !== record.generation) return undefined;
  const hostServiceSplices = parseHostServiceSplices(record.hostServiceSplices);
  return {
    generation: record.generation,
    ...(hasControlGeneration ? {
      controlGeneration: record.controlGeneration as string,
      policyGeneration: record.policyGeneration as string,
    } : {}),
    ...(typeof record.rulesetVerified === "boolean" ? { rulesetVerified: record.rulesetVerified } : {}),
    ...(record.oauthStateEpochs === 1 ? { oauthStateEpochs: true as const } : {}),
    ...(isNonEmptyString(record.hostServiceSetDigest) ? { hostServiceSetDigest: record.hostServiceSetDigest } : {}),
    ...(isNonNegativeInteger(record.hostServiceDraining) ? { hostServiceDraining: record.hostServiceDraining } : {}),
    ...(hostServiceSplices !== undefined ? { hostServiceSplices } : {}),
  };
}


