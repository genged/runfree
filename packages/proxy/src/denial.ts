// denial.ts — synthetic denial responses and structured denial events.
//
// Every value rendered into a denial body or a `proxy-denial:` event is
// bounded here: hostnames are re-normalized through the shared
// `normalizeHostname` contract (never echoing raw request data), paths are
// reduced to a truncated pathname with query/fragment stripped, and event
// emission is rate-bounded per (host, reason) so a hostile denial loop cannot
// grow proxy logs without bound.

import {
  describeRequestRule,
  hostRulesCommand,
  isHttpMethod,
  normalizeHostname,
  type HostRulesCommand,
  type RequestPolicyJson,
} from "@runfree/runtime-contracts/network-policy";

export const DENIAL_REASONS = [
  "host-not-allowlisted",
  "non-https-port",
  "non-https-url",
  "non-wss-url",
  "missing-required-token",
  "malformed-connect",
  "unsupported-client-protocol",
  "request-head-too-large",
  "request-head-timeout",
  "proxy-authorization-not-allowed",
  "unregistered-session-peer",
  "missing-admission-record",
  "connect-host-mismatch",
  "connect-sni-mismatch",
  "websocket-host-not-allowlisted",
  "method-not-allowed",
  "path-not-allowed",
  "git-push-denied",
  "write-denied",
  "write-approval-required",
  "write-approval-timeout",
  "write-approval-capacity",
  "write-approval-session-denied",
  "policy-denied",
] as const;

export type DenialReason = typeof DENIAL_REASONS[number];

// Request-shape denials are coalesced per (host, reason, method) instead of
// (host, reason) so doctor sees every distinct denied method per host.
export const SHAPE_DENIAL_REASONS = new Set<DenialReason>([
  "method-not-allowed",
  "path-not-allowed",
  "git-push-denied",
  "write-denied",
  "write-approval-required",
  "write-approval-timeout",
  "write-approval-capacity",
  "write-approval-session-denied",
]);

export const UNPARSEABLE_HOST = "<unparseable>";
export const DENIAL_EVENT_PREFIX = "proxy-denial: ";
export const DENIAL_PATH_LIMIT = 256;
const DENIAL_METHOD_LIMIT = 16;
const HTTP_TOKEN_CHAR_RE = /[^A-Za-z0-9!#$%&'*+.^_`|~-]/g;

const DENIAL_REASON_TEXT: Record<DenialReason, string> = {
  "host-not-allowlisted": "host is not in the project network allowlist",
  "non-https-port": "CONNECT to a non-HTTPS port is not allowed",
  "non-https-url": "only HTTPS outbound requests are allowed",
  "non-wss-url": "only WSS (secure WebSocket) outbound requests are allowed",
  "missing-required-token": "a required proxy-managed token is not configured for this host",
  "malformed-connect": "malformed CONNECT request",
  "unsupported-client-protocol": "the proxy only accepts HTTP/1.1 proxy requests on this port",
  "request-head-too-large": "the request head exceeds the proxy's size limit",
  "request-head-timeout": "the request head was not completed before the proxy's timeout",
  "proxy-authorization-not-allowed": "the proxy never accepts Proxy-Authorization from the agent",
  "unregistered-session-peer": "the source peer has no active Runfree session admission",
  "missing-admission-record": "the connection did not pass the Runfree CONNECT admission boundary",
  "connect-host-mismatch": "the request host does not match the admitted CONNECT host",
  "connect-sni-mismatch": "TLS SNI does not match the admitted CONNECT host",
  "websocket-host-not-allowlisted": "websocket host is not in the project network allowlist",
  "method-not-allowed": "method is not permitted for this host",
  "path-not-allowed": "path is not permitted for this host",
  "git-push-denied": "git push is denied for this host",
  "write-denied": "writes to this host are blocked (read-only)",
  "write-approval-required": "writes need approval but no approver is attached",
  "write-approval-timeout": "held for approval — no response before the hold timed out",
  "write-approval-capacity": "too many writes already waiting for approval",
  // A session-wide deny covers this session until the operator clears it;
  // the reason code stays stable as a wire identifier.
  "write-approval-session-denied": "the operator denied writes for this session until they clear the deny",
  // Defensive catch-all for a denial no earlier classification arm named. The
  // 403 body carries the precise message; this text serves doctor/summary.
  "policy-denied": "blocked by proxy policy",
};

// Re-normalize before display. `requestHost()` output admits a broader
// charset than `normalizeHostname` (underscores, trailing dots, raw IDN), so
// the raw value must never be rendered directly.
export function displayHostname(raw: string): string {
  try {
    return normalizeHostname(raw);
  } catch {
    return UNPARSEABLE_HOST;
  }
}

// Pathname only — never query string or fragment — truncated to a fixed
// bound. Returns undefined when no usable pathname exists.
export function safePathname(url: string | undefined): string | undefined {
  if (!url) return undefined;
  let pathname: string;
  try {
    pathname = new URL(url, "https://placeholder.invalid").pathname;
  } catch {
    return undefined;
  }
  if (pathname === "") return undefined;
  return pathname.slice(0, DENIAL_PATH_LIMIT);
}

// Bounded HTTP-token rendering for an attacker-controlled request method.
export function displayMethod(raw: string): string {
  const cleaned = raw.replace(HTTP_TOKEN_CHAR_RE, "").slice(0, 16);
  return cleaned === "" ? "<unparseable>" : cleaned;
}

export type ShapeDenialBodyDetails = {
  method?: string;
  // Raw pathname; reduced to a bounded pathname (never a query string).
  path?: string;
  allowedMethods?: readonly string[];
  allowedPathPrefixes?: readonly string[];
  // The host's full current request rule. A widening remedy reproduces it so
  // `runfree host rules` (which replaces the whole rule) keeps every existing
  // restriction; without it the remedy names only the delta.
  rule?: RequestPolicyJson;
};

// The exact widening command for a method denial. Repeating `runfree host rules`
// with rule flags replaces the host's entry, so the suggestion reproduces the
// full current rule plus the denied method; otherwise following the suggestion
// would silently drop the existing rule.
export function methodWideningCommand(
  host: string,
  method: string,
  allowedMethods: readonly string[],
  rule?: RequestPolicyJson,
): HostRulesCommand | undefined {
  const cleaned = method.toUpperCase();
  if (!isHttpMethod(cleaned)) return undefined;
  const current: RequestPolicyJson = rule ?? { methods: allowedMethods.filter(isHttpMethod) };
  return hostRulesCommand(host, current, { method: cleaned });
}

export const PATH_PREFIX_PLACEHOLDER = "<prefix>";

// The widening command for a path denial. The operator chooses the prefix; the
// rest of the rule is reproduced so the paste replaces like with like.
export function pathWideningCommand(
  host: string,
  allowedPathPrefixes: readonly string[] | undefined,
  rule?: RequestPolicyJson,
): HostRulesCommand {
  const current: RequestPolicyJson = rule ?? (allowedPathPrefixes ? { pathPrefixes: [...allowedPathPrefixes] } : {});
  return hostRulesCommand(host, current, { pathPrefix: PATH_PREFIX_PLACEHOLDER });
}

// The remedy block for a widening command: the command, the rule it produces
// (so the replace semantics are visible before pasting), and the fields the
// command cannot carry.
export function wideningRemedyLines(command: HostRulesCommand): string[] {
  const lines = [
    "The person operating Runfree can widen this on the host machine:",
    "",
    `  ${command.command}`,
    "",
    `This replaces the host's request rule with: ${describeRequestRule(command.resultingRule)}`,
  ];
  if (command.unexpressible.length > 0) {
    lines.push(
      `Note: the current rule also sets ${command.unexpressible.join(", ")}, which \`runfree host rules\` cannot express;`,
      "pasting the command drops them. Edit the rule in .runfree/network-policy.json instead.",
    );
  }
  lines.push("");
  return lines;
}

function shapeDenialLines(host: string, reason: DenialReason, details: ShapeDenialBodyDetails): string[] {
  const method = details.method !== undefined ? displayMethod(details.method) : undefined;
  const path = safePathname(details.path);
  const reasonSuffix = reason === "method-not-allowed" && details.allowedMethods !== undefined
    ? ` (allowed: ${details.allowedMethods.join(", ")})`
    : reason === "path-not-allowed" && details.allowedPathPrefixes !== undefined
      ? ` (allowed prefixes: ${details.allowedPathPrefixes.join(", ")})`
      : "";
  const lines = [
    "Runfree blocked this request.",
    "",
    `  host:   ${host}`,
    ...(method !== undefined ? [`  method: ${method}`] : []),
    ...(reason !== "method-not-allowed" && path !== undefined ? [`  path:   ${path}`] : []),
    `  reason: ${DENIAL_REASON_TEXT[reason]}${reasonSuffix}`,
    "",
  ];
  if (host === UNPARSEABLE_HOST) {
    lines.push(
      "The person operating Runfree can inspect recent denials by running",
      "`runfree doctor` on the host machine.",
    );
    return lines;
  }
  if (reason === "write-denied") {
    lines.push(
      "This host's policy blocks writes. The person operating Runfree can",
      "switch writes to ask-for-approval on the host machine:",
      "",
      `  runfree host rules ${host} --write ask`,
      "",
    );
  } else if (reason === "write-approval-required") {
    lines.push(
      "Writes to this host need a human approval, and no approver is attached.",
      "The person operating Runfree can attach an approver on the host machine:",
      "",
      "  runfree approvals --watch",
      "",
      "or allow writes to this host in project policy:",
      "",
      `  runfree host rules ${host} --write allow`,
      "",
    );
  } else if (reason === "write-approval-timeout") {
    lines.push(
      "This write was held for approval and denied when nobody responded.",
      "The person operating Runfree can approve the next attempt:",
      "",
      "  runfree approvals",
      "",
      "then retry the request.",
    );
  } else if (reason === "write-approval-capacity") {
    lines.push(
      "The person operating Runfree can decide the pending approvals with",
      "`runfree approvals`, then retry the request.",
    );
  } else if (reason === "write-approval-session-denied") {
    // Deliberate operator decision: no remedy line.
  } else if (reason === "method-not-allowed") {
    const command = method !== undefined && details.allowedMethods !== undefined
      ? methodWideningCommand(host, method, details.allowedMethods, details.rule)
      : undefined;
    if (command) {
      lines.push(...wideningRemedyLines(command));
    } else {
      lines.push(
        "The person operating Runfree can review the rule on the host machine:",
        "",
        `  runfree host rules ${host}`,
        "",
      );
    }
  } else if (reason === "path-not-allowed") {
    lines.push(...wideningRemedyLines(pathWideningCommand(host, details.allowedPathPrefixes, details.rule)));
  } else {
    lines.push(
      "This host's policy denies git pushes. The person operating Runfree can",
      "review or replace the rule on the host machine:",
      "",
      `  runfree host rules ${host}`,
      "",
    );
  }
  lines.push(`Current rules: runfree host explain ${host}`);
  return lines;
}

export function syntheticDenialBody(rawHost: string, reason: DenialReason, details?: ShapeDenialBodyDetails): string {
  const host = displayHostname(rawHost);
  if (SHAPE_DENIAL_REASONS.has(reason)) {
    return `${shapeDenialLines(host, reason, details ?? {}).join("\n")}\n`;
  }
  const lines = [
    "Runfree blocked this request.",
    "",
    `  host:   ${host}`,
    `  reason: ${DENIAL_REASON_TEXT[reason]}`,
    "",
    "This block is enforced by the Runfree proxy outside the agent container.",
  ];
  const allowlistDenial = reason === "host-not-allowlisted" || reason === "websocket-host-not-allowlisted";
  if (reason === "missing-admission-record" && host !== UNPARSEABLE_HOST) {
    // A connection denied at CONNECT stays denied even after the host is
    // allowlisted: the guard cannot upgrade it in place. The remedy is a new
    // connection, not another policy change.
    lines.push(
      "This connection was denied when it was opened and cannot be upgraded in",
      "place, even if the host has since been allowed. Retry on a new connection:",
      "rerun the failed command; a client that pools connections must reconnect.",
      "",
      `Current rules: runfree host explain ${host}`,
    );
  } else if (allowlistDenial && host !== UNPARSEABLE_HOST) {
    lines.push(
      "If this host should be reachable, the person operating Runfree can run",
      "on the host machine:",
      "",
      `  runfree host add ${host}`,
      "",
      "Policy reloads automatically; rerun the failed command afterwards.",
    );
  } else {
    lines.push(
      "The person operating Runfree can inspect recent denials by running",
      "`runfree doctor` on the host machine.",
    );
  }
  return `${lines.join("\n")}\n`;
}

export type DenialEventInput = {
  reason: DenialReason;
  host: string;
  method?: string;
  // Raw request URL or path; reduced to a bounded pathname before emission.
  path?: string;
  mcp?: {
    agent: "claude" | "codex";
    server: string;
    method: string;
    tool?: string;
  };
  mcpOAuthIssuer?: McpOAuthIssuerDenialContext;
  generation: string;
};

export type McpOAuthIssuerDenialContext = {
  serverName: string;
  resourceHost: string;
};

export type DenialEventEmitterOptions = {
  log?: (line: string) => void;
  now?: () => Date;
  maxEventsPerWindow?: number;
  windowMs?: number;
  maxTrackedKeys?: number;
};

type DenialBucket = {
  host: string;
  reason: DenialReason;
  method?: string;
  mcpOAuthIssuer?: McpOAuthIssuerDenialContext;
  windowStartMs: number;
  emitted: number;
  suppressed: number;
};

export type DenialEventEmitter = {
  emit(input: DenialEventInput): void;
};

export function createDenialEventEmitter(options: DenialEventEmitterOptions = {}): DenialEventEmitter {
  const log = options.log ?? console.log;
  const now = options.now ?? (() => new Date());
  const maxEventsPerWindow = options.maxEventsPerWindow ?? 10;
  const windowMs = options.windowMs ?? 60_000;
  const maxTrackedKeys = options.maxTrackedKeys ?? 1_000;

  const buckets = new Map<string, DenialBucket>();
  let trackedGeneration: string | undefined;

  function eventLine(fields: Record<string, unknown>): string {
    return `${DENIAL_EVENT_PREFIX}${JSON.stringify(fields)}`;
  }

  function displayMcpOAuthIssuer(value: McpOAuthIssuerDenialContext | undefined): McpOAuthIssuerDenialContext | undefined {
    if (!value) return undefined;
    const resourceHost = displayHostname(value.resourceHost);
    if (resourceHost === UNPARSEABLE_HOST) return undefined;
    const serverName = value.serverName.replace(/[^A-Za-z0-9_.-]/g, "-").slice(0, 80);
    if (serverName === "") return undefined;
    return { serverName, resourceHost };
  }

  function flushSuppressed(bucket: DenialBucket, timestamp: Date, generation: string): void {
    if (bucket.suppressed === 0) return;
    log(eventLine({
      v: 1,
      ts: timestamp.toISOString(),
      reason: bucket.reason,
      host: bucket.host,
      ...(bucket.method !== undefined ? { method: bucket.method } : {}),
      ...(bucket.mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer: bucket.mcpOAuthIssuer } : {}),
      suppressed: bucket.suppressed,
      generation,
    }));
    bucket.suppressed = 0;
  }

  return {
    emit(input: DenialEventInput): void {
      const timestamp = now();
      const nowMs = timestamp.getTime();

      // Coalescing state resets on policy generation change so the user gets
      // fresh denial feedback right after editing policy.
      if (input.generation !== trackedGeneration) {
        buckets.clear();
        trackedGeneration = input.generation;
      }

      const host = displayHostname(input.host);
      const mcpOAuthIssuer = displayMcpOAuthIssuer(input.mcpOAuthIssuer);
      const coalescedMethod = SHAPE_DENIAL_REASONS.has(input.reason)
        ? (input.method ?? "").slice(0, DENIAL_METHOD_LIMIT)
        : undefined;
      const key = coalescedMethod !== undefined
        ? `${host}\0${input.reason}\0${coalescedMethod}`
        : `${host}\0${input.reason}`;
      let bucket = buckets.get(key);
      if (!bucket) {
        if (buckets.size >= maxTrackedKeys) {
          // Evict the oldest tracked key, flushing its pending summary so
          // suppressed counts are not silently dropped.
          const oldestKey = buckets.keys().next().value;
          if (oldestKey !== undefined) {
            const oldest = buckets.get(oldestKey);
            if (oldest) flushSuppressed(oldest, timestamp, input.generation);
            buckets.delete(oldestKey);
          }
        }
        bucket = {
          host,
          reason: input.reason,
          ...(coalescedMethod !== undefined ? { method: coalescedMethod } : {}),
          ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
          windowStartMs: nowMs,
          emitted: 0,
          suppressed: 0,
        };
        buckets.set(key, bucket);
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
        reason: input.reason,
        host,
        ...(input.method !== undefined ? { method: input.method.slice(0, DENIAL_METHOD_LIMIT) } : {}),
        ...(path !== undefined ? { path } : {}),
        ...(input.mcp !== undefined ? { mcp: input.mcp } : {}),
        ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
        generation: input.generation,
      }));
    },
  };
}
