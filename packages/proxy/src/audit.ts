// audit.ts — network-policy audit mode primitives shared by the request proxy
// and the firewall supervisor.
//
// Audit mode relaxes exactly one check (the proxy hostname allowlist) for a
// bounded time. Its state lives in a root-owned proxy tmpfs marker that the
// UID-1001 proxy server can read but never write; both consumers evaluate the
// marker independently per read with the same clamp:
// effectiveExpiry = min(expiresAt, min(enabledAt, proxyNow) + MAX_DURATION).
// Malformed, missing, or expired markers always mean enforce mode.

import fs from "node:fs";

import { normalizeHostname } from "@runfree/runtime-contracts/network-policy";

import {
  DENIAL_PATH_LIMIT,
  displayHostname,
  displayMethod,
  safePathname,
  UNPARSEABLE_HOST,
} from "./denial.js";

export const AUDIT_MARKER_VERSION = 1;
export const AUDIT_MAX_DURATION_MS = 8 * 60 * 60 * 1000;
export const DEFAULT_AUDIT_MARKER_DIR = "/run/runfree-proxy-audit";
export const DEFAULT_AUDIT_MARKER_PATH = `${DEFAULT_AUDIT_MARKER_DIR}/active.json`;
export const DEFAULT_AUDIT_SPOOL_DIR = "/run/runfree-proxy-audit-spool";
export const DEFAULT_AUDIT_SPOOL_PATH = `${DEFAULT_AUDIT_SPOOL_DIR}/spool.txt`;
export const DEFAULT_AUDIT_RESOLVED_HOSTS_PATH = `${DEFAULT_AUDIT_MARKER_DIR}/resolved-hosts.json`;
export const AUDIT_EVENT_PREFIX = "proxy-audit: ";
// Hostnames are bounded at 253 octets; anything longer in the spool is noise
// or an attack and is rejected before validation work.
export const AUDIT_SPOOL_MAX_LINE_LENGTH = 255;
const AUDIT_SPOOL_DEFAULT_MAX_BYTES = 64 * 1024;
const AUDIT_METHOD_LIMIT = 16;

export function auditMarkerPathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.PROXY_AUDIT_MARKER_PATH ?? DEFAULT_AUDIT_MARKER_PATH;
}

export function auditSpoolPathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.PROXY_AUDIT_SPOOL_PATH ?? DEFAULT_AUDIT_SPOOL_PATH;
}

export function auditResolvedHostsPathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.PROXY_AUDIT_RESOLVED_HOSTS_PATH ?? DEFAULT_AUDIT_RESOLVED_HOSTS_PATH;
}

export type AuditMarkerState =
  | { active: false }
  | { active: true; enabledAtMs: number; effectiveExpiryMs: number };

const INACTIVE: AuditMarkerState = { active: false };

// Read-time invariant computed identically by both consumers from the proxy
// container clock: a far-future expiresAt (however it got there) is honored
// only to min(enabledAt, now) + 8h, and a future-dated enabledAt written by a
// skewed host clock cannot extend the window.
export function effectiveAuditExpiryMs(enabledAtMs: number, expiresAtMs: number, nowMs: number): number {
  const effectiveEnabledAtMs = Math.min(enabledAtMs, nowMs);
  return Math.min(expiresAtMs, effectiveEnabledAtMs + AUDIT_MAX_DURATION_MS);
}

// Parses raw marker file contents. Anything that does not parse as the exact
// recognized shape with an unexpired effective expiry yields enforce mode.
export function parseAuditMarker(raw: string | undefined, nowMs: number): AuditMarkerState {
  if (raw === undefined) return INACTIVE;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return INACTIVE;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return INACTIVE;
  const marker = parsed as Record<string, unknown>;
  if (marker.v !== AUDIT_MARKER_VERSION) return INACTIVE;
  if (typeof marker.enabledAt !== "string" || typeof marker.expiresAt !== "string") return INACTIVE;
  const enabledAtMs = Date.parse(marker.enabledAt);
  const expiresAtMs = Date.parse(marker.expiresAt);
  if (!Number.isFinite(enabledAtMs) || !Number.isFinite(expiresAtMs)) return INACTIVE;
  const effectiveExpiryMs = effectiveAuditExpiryMs(enabledAtMs, expiresAtMs, nowMs);
  if (effectiveExpiryMs <= nowMs) return INACTIVE;
  return { active: true, enabledAtMs, effectiveExpiryMs };
}

export function readAuditMarkerState(markerPath: string, nowMs: number): AuditMarkerState {
  let raw: string;
  try {
    raw = fs.readFileSync(markerPath, "utf8");
  } catch {
    return INACTIVE;
  }
  return parseAuditMarker(raw, nowMs);
}

// --- Spool ------------------------------------------------------------------
// The spool is the one intentional UID-1001 → root channel: the unprivileged
// request proxy appends normalized hostnames, the privileged supervisor
// re-validates every line before acting on it.

export type AuditSpoolWriter = {
  record(rawHost: string): void;
  reset(): void;
};

export function createAuditSpoolWriter(options: {
  path: string;
  appendFile?: (path: string, data: string) => void;
  log?: (line: string) => void;
  maxBytes?: number;
}): AuditSpoolWriter {
  const appendFile = options.appendFile ?? ((path: string, data: string) => {
    fs.appendFileSync(path, data, { mode: 0o644 });
  });
  const log = options.log ?? console.log;
  const maxBytes = options.maxBytes ?? AUDIT_SPOOL_DEFAULT_MAX_BYTES;
  const written = new Set<string>();
  let bytesWritten = 0;
  let capLogged = false;

  return {
    record(rawHost: string): void {
      let host: string;
      try {
        host = normalizeHostname(rawHost);
      } catch {
        return;
      }
      if (written.has(host)) return;
      const line = `${host}\n`;
      if (bytesWritten + line.length > maxBytes) {
        if (!capLogged) {
          capLogged = true;
          log("proxy-audit: spool size cap reached; further observed hosts are not spooled");
        }
        return;
      }
      try {
        appendFile(options.path, line);
      } catch (error) {
        log(`proxy-audit: spool append failed: ${error instanceof Error ? error.message : String(error)}`);
        return;
      }
      written.add(host);
      bytesWritten += line.length;
    },
    reset(): void {
      written.clear();
      bytesWritten = 0;
      capLogged = false;
    },
  };
}

export type AuditSpoolValidation = {
  hosts: string[];
  rejectedLines: number;
};

// Privileged-consumer re-validation of spool lines. The writer's normalization
// is never trusted: every line is length-bounded and re-run through
// normalizeHostname; failures are counted, never acted on.
export function validateAuditSpoolLines(lines: readonly string[]): AuditSpoolValidation {
  const hosts: string[] = [];
  const seen = new Set<string>();
  let rejectedLines = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    if (trimmed.length > AUDIT_SPOOL_MAX_LINE_LENGTH) {
      rejectedLines += 1;
      continue;
    }
    let host: string;
    try {
      host = normalizeHostname(trimmed);
    } catch {
      rejectedLines += 1;
      continue;
    }
    if (seen.has(host)) continue;
    seen.add(host);
    hosts.push(host);
  }
  return { hosts, rejectedLines };
}

// --- Observation events -------------------------------------------------------
// `proxy-audit:` lines share the proxy-denial event bounds: hostnames are
// re-normalized before display, paths are reduced to a truncated pathname with
// query/fragment stripped (DENIAL_PATH_LIMIT), and emission is rate-coalesced
// per host so a hostile request loop cannot grow proxy logs without bound.

export type AuditEventInput = {
  host: string;
  method?: string;
  // Raw request URL or path; reduced to a bounded pathname before emission.
  path?: string;
  generation: string;
};

export type AuditEventEmitterOptions = {
  log?: (line: string) => void;
  now?: () => Date;
  maxEventsPerWindow?: number;
  windowMs?: number;
  maxTrackedHosts?: number;
};

type AuditBucket = {
  host: string;
  windowStartMs: number;
  emitted: number;
  suppressed: number;
};

export type AuditEventEmitter = {
  emit(input: AuditEventInput): void;
};

export const AUDIT_PATH_LIMIT = DENIAL_PATH_LIMIT;

export function createAuditEventEmitter(options: AuditEventEmitterOptions = {}): AuditEventEmitter {
  const log = options.log ?? console.log;
  const now = options.now ?? (() => new Date());
  const maxEventsPerWindow = options.maxEventsPerWindow ?? 10;
  const windowMs = options.windowMs ?? 60_000;
  const maxTrackedHosts = options.maxTrackedHosts ?? 1_000;

  const buckets = new Map<string, AuditBucket>();

  function eventLine(fields: Record<string, unknown>): string {
    return `${AUDIT_EVENT_PREFIX}${JSON.stringify(fields)}`;
  }

  function flushSuppressed(bucket: AuditBucket, timestamp: Date, generation: string): void {
    if (bucket.suppressed === 0) return;
    log(eventLine({
      v: 1,
      ts: timestamp.toISOString(),
      host: bucket.host,
      suppressed: bucket.suppressed,
      generation,
    }));
    bucket.suppressed = 0;
  }

  return {
    emit(input: AuditEventInput): void {
      const timestamp = now();
      const nowMs = timestamp.getTime();
      const host = displayHostname(input.host);
      if (host === UNPARSEABLE_HOST) return;

      let bucket = buckets.get(host);
      if (!bucket) {
        if (buckets.size >= maxTrackedHosts) {
          const oldestKey = buckets.keys().next().value;
          if (oldestKey !== undefined) {
            const oldest = buckets.get(oldestKey);
            if (oldest) flushSuppressed(oldest, timestamp, input.generation);
            buckets.delete(oldestKey);
          }
        }
        bucket = { host, windowStartMs: nowMs, emitted: 0, suppressed: 0 };
        buckets.set(host, bucket);
      }

      if (nowMs - bucket.windowStartMs >= windowMs) {
        flushSuppressed(bucket, timestamp, input.generation);
        bucket.windowStartMs = nowMs;
        bucket.emitted = 0;
      }

      if (bucket.emitted >= maxEventsPerWindow) {
        bucket.suppressed += 1;
        return;
      }
      bucket.emitted += 1;

      const path = safePathname(input.path);
      log(eventLine({
        v: 1,
        ts: timestamp.toISOString(),
        host,
        ...(input.method !== undefined ? { method: displayMethod(input.method).slice(0, AUDIT_METHOD_LIMIT) } : {}),
        ...(path !== undefined ? { path } : {}),
        generation: input.generation,
      }));
    },
  };
}
