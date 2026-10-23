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
  "host-service-not-configured",
  "host-service-unavailable",
  "host-service-capacity",
  "oauth-endpoint-not-mediated",
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
  "host-service-not-configured": "this host service is not approved for the project",
  "host-service-unavailable": "the host-service gateway or the host service is not available",
  "host-service-capacity": "too many host-service connections are already open",
  "oauth-endpoint-not-mediated": "an OAuth token or client registration request to an endpoint the proxy does not mediate",
  // Defensive catch-all for a denial no earlier classification arm named. The
  // 403 body carries the precise message; this text serves doctor/summary.
  "policy-denied": "blocked by proxy policy",
};

export function denialReasonText(reason: DenialReason): string {
  return DENIAL_REASON_TEXT[reason];
}

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
  // The request was an OAuth token POST whose client_id is a client metadata
  // URL Runfree does not recognize (fixed text; the value is never echoed).
  oauthUnlistedClientIdUrl?: boolean;
  // Why an OAuth-shaped request was refused as not mediated.
  oauthEndpoint?: OAuthEndpointDenialDetails;
};

// The parts of an unmediated-OAuth refusal a denial body shows. Every value
// is from a closed set except `providers`, which is re-sanitized here.
export type OAuthEndpointDenialDetails = {
  // A closed set of OAuth field names (never request data).
  field?: "code" | "grant_type" | "redirect_uris" | "refresh_token";
  finding: "grant-shaped" | "missing-length" | "multipart" | "oversize" | "undecodable" | "websocket";
  providers?: readonly string[];
  target: "blocked-endpoint" | "endpoint-collision" | "mediated-endpoint" | "policy-unavailable" | "record-endpoint-host" | "record-only-host";
};

const OAUTH_FIELD_TEXT: Record<NonNullable<OAuthEndpointDenialDetails["field"]>, string> = {
  code: "code with code_verifier (an authorization code exchange)",
  grant_type: "grant_type (a token exchange)",
  redirect_uris: "redirect_uris (a client registration)",
  refresh_token: "refresh_token (a token refresh)",
};

const OAUTH_UNREADABLE_TEXT: Record<Exclude<OAuthEndpointDenialDetails["finding"], "grant-shaped" | "websocket">, string> = {
  "missing-length": "its body has no Content-Length",
  multipart: "it is multipart/form-data",
  oversize: "its body is larger than 16 KiB",
  undecodable: "its body or content encoding cannot be decoded",
};

const OAUTH_TARGET_TEXT: Record<OAuthEndpointDenialDetails["target"], string[]> = {
  "blocked-endpoint": [
    "The OAuth settings of an MCP server name this endpoint, but the proxy does",
    "not mediate it: another use of the host conflicts with that claim.",
  ],
  "mediated-endpoint": [
    "The proxy mediates this OAuth endpoint for HTTPS requests only.",
  ],
  "endpoint-collision": [
    "More than one OAuth server claims this endpoint, so none of them mediates",
    "it: a token reply here could be filed under the wrong server.",
  ],
  "policy-unavailable": [
    "The OAuth mediation policy of the proxy is unavailable, so it refuses",
    "every OAuth token request it cannot mediate.",
  ],
  "record-endpoint-host": [
    "The OAuth settings of an MCP server name this host, and the proxy does",
    "not mediate this endpoint.",
  ],
  "record-only-host": [
    "Only MCP OAuth settings allow this host, and the proxy does not mediate",
    "this endpoint.",
  ],
};

function displayProviderId(raw: string): string {
  return raw.replace(/[^A-Za-z0-9_.:-]/g, "-").slice(0, 80);
}

function oauthEndpointLines(host: string, details: OAuthEndpointDenialDetails | undefined): string[] {
  const lines: string[] = [];
  if (details === undefined) {
    lines.push(
      "The proxy holds the real OAuth tokens of MCP servers and gives the agent handles.",
      "It does not mediate this endpoint, so the request was not sent.",
      "",
    );
  } else {
    lines.push(...OAUTH_TARGET_TEXT[details.target]);
    if (details.finding === "grant-shaped") {
      const field = details.field !== undefined ? OAUTH_FIELD_TEXT[details.field] : "an OAuth grant field";
      lines.push(
        `The request carries ${field}. Its reply would hand real tokens`,
        "to the agent instead of handles, so the request was not sent.",
      );
    } else if (details.finding === "websocket") {
      lines.push(
        "This is a WebSocket upgrade. The proxy cannot read its reply, which",
        "could carry real tokens, so the upgrade was not sent.",
      );
    } else {
      lines.push(
        `The proxy cannot check this request for an OAuth token exchange: ${OAUTH_UNREADABLE_TEXT[details.finding]}.`,
        "The request was not sent.",
      );
    }
    const providers = (details.providers ?? []).map(displayProviderId).filter((id) => id !== "").slice(0, 4);
    if (providers.length > 0) {
      lines.push(`OAuth providers involved: ${providers.join(", ")}`);
    }
    lines.push("");
  }
  if (details?.target === "policy-unavailable") {
    lines.push(
      "The person operating Runfree can inspect the proxy by running",
      "`runfree doctor` on the host machine.",
    );
    return lines;
  }
  if (details?.target === "mediated-endpoint") {
    lines.push("Send this request over HTTPS instead.", "");
    return lines;
  }
  if (details?.target === "endpoint-collision") {
    lines.push(
      "The person operating Runfree can revoke one of the servers on the host",
      "machine, so the other one mediates the endpoint:",
      "",
      "  runfree mcp revoke <agent> <server>",
      "",
    );
  } else {
    lines.push(
      "If the login of an MCP server uses this endpoint, the person operating",
      "Runfree can enable the server again on the host machine, so the proxy",
      "records and mediates the endpoint:",
      "",
      "  runfree mcp enable <agent> <server>",
      "",
      "or remove the server and its OAuth hosts:",
      "",
      "  runfree mcp revoke <agent> <server>",
      "",
    );
  }
  if (details?.target === "record-only-host" && details.finding !== "grant-shaped" && host !== UNPARSEABLE_HOST) {
    // A broad --oauth-host host also takes ordinary traffic; allowing it
    // outside MCP stops it being record-only, and so ends the grant refusal.
    const traffic = details.finding === "websocket" ? "WebSocket connections" : "ordinary uploads";
    lines.push(
      `If this host should also take ${traffic}, the person operating Runfree`,
      "can allow it outside MCP. The proxy then stops refusing OAuth token",
      "requests to this host that it does not mediate, so their real tokens",
      "would reach the agent:",
      "",
      `  runfree host add ${host}`,
      "",
    );
  }
  return lines;
}

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
  if (details.oauthUnlistedClientIdUrl === true && reason.startsWith("write-approval")) {
    lines.push(
      "This OAuth token request names a client metadata URL as its client_id that",
      "Runfree does not recognize. The authorization server fetches that URL, so",
      "the request counts as a write. Runfree treats only the published Claude Code",
      "and Codex client metadata URLs as OAuth protocol reads.",
      "",
    );
  }
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

// The host placeholder in a WebSocket refusal body. mockttp rejects an
// upgrade with a body fixed per rule, so the body cannot name the request's
// host; the structured denial event carries the host, method, and path.
export const WEBSOCKET_DENIAL_HOST_PLACEHOLDER = "<host>";

/**
 * The fixed body of a refused WebSocket upgrade where the proxy guards
 * OAuth: the same explanation and remedy lines as the HTTPS denial, for one
 * (target, finding) pair, with `<host>` in place of the host.
 */
export function webSocketOAuthDenialBody(details: Pick<OAuthEndpointDenialDetails, "finding" | "target">): string {
  return `${[
    "Runfree blocked this WebSocket upgrade.",
    "",
    `  reason: ${DENIAL_REASON_TEXT["oauth-endpoint-not-mediated"]}`,
    "",
    ...oauthEndpointLines(WEBSOCKET_DENIAL_HOST_PLACEHOLDER, { finding: details.finding, target: details.target }),
    `Current rules: runfree host explain ${WEBSOCKET_DENIAL_HOST_PLACEHOLDER}`,
  ].join("\n")}\n`;
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
  if (reason === "oauth-endpoint-not-mediated") {
    const method = details?.method !== undefined ? displayMethod(details.method) : undefined;
    const path = safePathname(details?.path);
    return `${[
      "Runfree blocked this request.",
      "",
      `  host:   ${host}`,
      ...(method !== undefined ? [`  method: ${method}`] : []),
      ...(path !== undefined ? [`  path:   ${path}`] : []),
      `  reason: ${DENIAL_REASON_TEXT[reason]}`,
      "",
      ...oauthEndpointLines(host, details?.oauthEndpoint),
      ...(host !== UNPARSEABLE_HOST ? [`Current rules: runfree host explain ${host}`] : []),
    ].join("\n")}\n`;
  }
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
  // The requested port of a host-service denial, so `runfree doctor` can
  // name the exact `host-service add` remedy. Dropped unless an integer port.
  port?: number;
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
  port?: number;
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
      ...(bucket.port !== undefined ? { port: bucket.port } : {}),
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
      const port = input.port !== undefined && Number.isInteger(input.port) && input.port >= 1 && input.port <= 65535
        ? input.port
        : undefined;
      const baseKey = coalescedMethod !== undefined
        ? `${host}\0${input.reason}\0${coalescedMethod}`
        : `${host}\0${input.reason}`;
      const key = port !== undefined ? `${baseKey}\0${port}` : baseKey;
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
          ...(port !== undefined ? { port } : {}),
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
        ...(port !== undefined ? { port } : {}),
        ...(input.method !== undefined ? { method: input.method.slice(0, DENIAL_METHOD_LIMIT) } : {}),
        ...(path !== undefined ? { path } : {}),
        ...(input.mcp !== undefined ? { mcp: input.mcp } : {}),
        ...(mcpOAuthIssuer !== undefined ? { mcpOAuthIssuer } : {}),
        generation: input.generation,
      }));
    },
  };
}
