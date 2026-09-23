import { hostRulesCommand, isHttpMethod, normalizeHostname, type PolicyJson } from "@runfree/runtime-contracts/network-policy";

export type BlockedHostStatus = "missing" | "allowlisted" | "request-shape";

export type BlockedHostDiagnostic = {
  host: string;
  status: BlockedHostStatus;
  // Set for request-shape denials only.
  reason?: string;
  method?: string;
  mcpOAuthIssuer?: McpOAuthIssuerDiagnostic;
  command: string;
  // "fix": pasting `command` widens policy; "inspect": it only shows the rule.
  // Absent for allowlist/missing diagnoses, whose commands are always fixes.
  commandKind?: "fix" | "inspect";
  count: number;
};

export type McpOAuthIssuerDiagnostic = {
  serverName: string;
  resourceHost: string;
};

// Request-shape denial reasons from the proxy's denial-event vocabulary.
// Shape denials are diagnosed per (host, reason, method) so each distinct
// denied method gets its own exact widening command.
const SHAPE_DENIAL_REASONS = new Set(["method-not-allowed", "path-not-allowed", "git-push-denied"]);

// Structured `proxy-denial:` event from proxy stdout. Unknown fields are
// tolerated; only the fields used here are typed.
export type ProxyDenialEvent = {
  v?: unknown;
  ts?: string;
  reason?: string;
  host?: string;
  method?: string;
  path?: string;
  mcpOAuthIssuer?: unknown;
  generation?: string;
  suppressed?: number;
};

const DENIAL_EVENT_PREFIX = "proxy-denial: ";

export function domainAddCommandForHost(host: string): string {
  return `runfree host add ${host}`;
}

// The exact widening command for a method denial. `runfree host rules` with
// rule flags replaces the host's requests entry, so the command enumerates the
// currently allowed methods plus the denied one instead of suggesting a bare
// `--method <M>` that would drop the existing rule.
// `runfree host rules` replaces the host's whole rule, so every widening
// command reproduces the full current rule plus the delta (shared builder).
export function methodWideningCommand(policy: PolicyJson, host: string, method: string): string {
  const rule = policy.requests?.[host];
  if (!isHttpMethod(method)) return hostRulesCommand(host, rule).command;
  return hostRulesCommand(host, rule, { method }).command;
}

export function pathWideningCommand(policy: PolicyJson, host: string): string {
  return hostRulesCommand(host, policy.requests?.[host], { pathPrefix: "<prefix>" }).command;
}

// Strip ANSI escape sequences and control characters before rendering
// attacker-influenced values (hosts, paths) to the operator's terminal.
const ANSI_CSI_SEQUENCE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const ANSI_OTHER_ESCAPE = /\x1b[@-_]?/g;
const CONTROL_CHARACTERS = /[\x00-\x1f\x7f-\x9f]/g;

export function sanitizeForTerminal(value: string): string {
  return value
    .replace(ANSI_CSI_SEQUENCE, "")
    .replace(ANSI_OTHER_ESCAPE, "")
    .replace(CONTROL_CHARACTERS, "");
}

// Denials raised by the proxy's connection guard before any host is known: a
// non-HTTP/1.1 client protocol, a client-supplied Proxy-Authorization, an
// oversized or stalled request head. They carry `host: "<unparseable>"`, which
// `normalizeHostname` rejects, so `denialOccurrencesFromEvents` drops them —
// correctly, since they are not blocked *hosts* and have no widening command.
// They would otherwise be invisible to the operator entirely, so they are
// summarised separately, by reason and count only. No host, path or method from
// these events is ever rendered.
export type ProtocolDenialSummary = { reason: string; count: number };

const PROTOCOL_DENIAL_REASONS = new Set([
  "unsupported-client-protocol",
  "proxy-authorization-not-allowed",
  "request-head-too-large",
  "request-head-timeout",
  "malformed-connect",
]);

export function summarizeProtocolDenials(logs: string): ProtocolDenialSummary[] {
  const counts = new Map<string, number>();
  for (const event of extractDenialEvents(logs)) {
    if (typeof event.reason !== "string" || !PROTOCOL_DENIAL_REASONS.has(event.reason)) continue;
    // A reason that also carries a usable host is already reported as a host
    // denial; only the hostless ones are summarised here.
    if (typeof event.host === "string") {
      try {
        normalizeHostname(event.host);
        continue;
      } catch {
        // Hostless — fall through and summarise.
      }
    }
    const suppressed = typeof event.suppressed === "number" && Number.isFinite(event.suppressed) && event.suppressed > 0
      ? Math.floor(event.suppressed)
      : 1;
    counts.set(event.reason, (counts.get(event.reason) ?? 0) + suppressed);
  }
  return Array.from(counts.entries())
    .map(([reason, count]) => ({ reason, count }))
    .sort((left, right) => right.count - left.count || left.reason.localeCompare(right.reason));
}

// Parses `proxy-denial: {...}` lines, tolerating unknown fields and skipping
// malformed JSON.
export function extractDenialEvents(logs: string): ProxyDenialEvent[] {
  const events: ProxyDenialEvent[] = [];
  for (const line of logs.split(/\r?\n/)) {
    const start = line.indexOf(DENIAL_EVENT_PREFIX);
    if (start === -1) continue;
    const raw = line.slice(start + DENIAL_EVENT_PREFIX.length).trim();
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) continue;
      events.push(parsed as ProxyDenialEvent);
    } catch {
      // Skip malformed event lines; logs are untrusted input.
    }
  }
  return events;
}

export function latestUniqueHosts(hosts: string[], limit = 5): string[] {
  const seen = new Set<string>();
  const latest: string[] = [];
  for (let index = hosts.length - 1; index >= 0; index -= 1) {
    const host = hosts[index];
    if (seen.has(host)) continue;
    seen.add(host);
    latest.push(host);
    if (latest.length >= limit) break;
  }
  return latest;
}

type DenialOccurrence = {
  host: string;
  // Aggregation key: host alone for allowlist denials, (host, reason,
  // method) for request-shape denials.
  key: string;
  reason?: string;
  method?: string;
  mcpOAuthIssuer?: McpOAuthIssuerDiagnostic;
  count: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function mcpOAuthIssuerFromEvent(value: unknown): McpOAuthIssuerDiagnostic | undefined {
  if (!isRecord(value)) return undefined;
  if (typeof value.serverName !== "string" || typeof value.resourceHost !== "string") return undefined;
  let resourceHost: string;
  try {
    resourceHost = normalizeHostname(value.resourceHost);
  } catch {
    return undefined;
  }
  const serverName = sanitizeForTerminal(value.serverName).replace(/[^A-Za-z0-9_.-]/g, "-").slice(0, 80);
  if (serverName === "") return undefined;
  return { serverName, resourceHost };
}

// Re-validates each event host through normalizeHostname (and each method
// through the closed HTTP verb set) so log lines can never inject an
// unverified value into a suggested command.
function denialOccurrencesFromEvents(events: ProxyDenialEvent[]): DenialOccurrence[] {
  const occurrences: DenialOccurrence[] = [];
  for (const event of events) {
    if (typeof event.host !== "string") continue;
    let host: string;
    try {
      host = normalizeHostname(event.host);
    } catch {
      continue;
    }
    const suppressed = typeof event.suppressed === "number" && Number.isFinite(event.suppressed) && event.suppressed > 0
      ? Math.floor(event.suppressed)
      : undefined;
    const reason = typeof event.reason === "string" && SHAPE_DENIAL_REASONS.has(event.reason)
      ? event.reason
      : undefined;
    const method = reason !== undefined && typeof event.method === "string" && isHttpMethod(event.method.toUpperCase())
      ? event.method.toUpperCase()
      : undefined;
    const mcpOAuthIssuer = mcpOAuthIssuerFromEvent(event.mcpOAuthIssuer);
    occurrences.push({
      host,
      key: reason !== undefined ? `${host}\0${reason}\0${method ?? ""}` : host,
      reason,
      method,
      ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
      count: suppressed ?? 1,
    });
  }
  return occurrences;
}

function latestUniqueOccurrences(occurrences: DenialOccurrence[], limit: number): DenialOccurrence[] {
  const seen = new Set<string>();
  const latest: DenialOccurrence[] = [];
  for (let index = occurrences.length - 1; index >= 0; index -= 1) {
    const occurrence = occurrences[index];
    if (seen.has(occurrence.key)) continue;
    seen.add(occurrence.key);
    latest.push(occurrence);
    if (latest.length >= limit) break;
  }
  return latest;
}

// Distinct blocked (host, reason, method) entries in the logs — the total a
// capped diagnosis is a window onto, so a summary can say "showing N of M"
// instead of reporting the cap as the count.
export function countBlockedHostDiagnoses(logs: string): number {
  return new Set(denialOccurrencesFromEvents(extractDenialEvents(logs)).map((occurrence) => occurrence.key)).size;
}

export function diagnoseBlockedHosts(logs: string, policy: PolicyJson, limit = 5): BlockedHostDiagnostic[] {
  // Structured `proxy-denial:` events are the single denial log format; the
  // emitter and this parser ship together, so there is no older-runtime
  // free-text fallback to honor.
  const occurrences = denialOccurrencesFromEvents(extractDenialEvents(logs));

  const counts = new Map<string, number>();
  for (const occurrence of occurrences) {
    counts.set(occurrence.key, (counts.get(occurrence.key) ?? 0) + occurrence.count);
  }

  // Last-seen ordering: most recently denied hosts first.
  return latestUniqueOccurrences(occurrences, limit).map((occurrence) => {
    const { host, reason, method, mcpOAuthIssuer } = occurrence;
    const count = counts.get(occurrence.key) ?? 1;
    if (reason !== undefined) {
      return {
        host,
        status: "request-shape" as const,
        reason,
        ...(method !== undefined ? { method } : {}),
        ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
        command: reason === "method-not-allowed" && method !== undefined
          ? methodWideningCommand(policy, host, method)
          : reason === "path-not-allowed"
            ? pathWideningCommand(policy, host)
            : `runfree host rules ${host}`,
        // A widening command is a fix to paste; the bare `host rules` form only
        // shows the rule and must not be labeled as a fix.
        commandKind: (reason === "method-not-allowed" && method !== undefined) || reason === "path-not-allowed"
          ? "fix" as const
          : "inspect" as const,
        count,
      };
    }
    if (policy.hosts.includes(host)) {
      return {
        host,
        status: "allowlisted" as const,
        ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
        command: "runfree runtime reload-policy",
        count,
      };
    }

    return {
      host,
      status: "missing" as const,
      ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
      command: domainAddCommandForHost(host),
      count,
    };
  });
}
