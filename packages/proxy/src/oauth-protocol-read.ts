// OAuth protocol-read classification: the request-shape half.
//
// A POST to an exact, recorded (`runfree mcp enable`), statically mediated
// OAuth token or registration endpoint is a read, not a write, so login and
// refresh do not wait on write approval (`ask`). The mediator decides whether
// the endpoint is mediated (OAuthMediator.protocolReadEndpoint); this module
// decides whether the request is protocol-shaped. Anything else on the host
// keeps the normal write classification. Every check fails toward "write".

import { parseJsonStrict } from "./mcp-classify.js";

export type ProtocolReadKind = "registration" | "token";

export const PROTOCOL_READ_BODY_CAP_BYTES = 16 * 1024;
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_PER_WINDOW = 30;

type HeaderValue = string | string[] | undefined;

const TOKEN_GRANTS = new Set(["authorization_code", "refresh_token"]);
const TOKEN_FIELDS = new Set([
  "grant_type",
  "code",
  "redirect_uri",
  "code_verifier",
  "refresh_token",
  "client_id",
  "client_secret",
  "scope",
  "resource",
]);
const REGISTRATION_FIELDS = new Set([
  "client_name",
  "redirect_uris",
  "grant_types",
  "response_types",
  "token_endpoint_auth_method",
  "scope",
]);
const REGISTRATION_AUTH_METHODS = new Set(["none", "client_secret_basic", "client_secret_post"]);
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/**
 * The published client ID metadata document URLs of the agents Runfree pins.
 * An authorization server that supports client ID metadata documents fetches a
 * URL-valued client_id, so a URL is a protocol read only on exact string
 * equality with one of these: a fixed, public vendor URL carries no bytes the
 * agent chose. Any other URL (another path, a query, a case or encoding
 * variant, an in-container override) stays a write. The live mcp-enable
 * tranche proves each value is in the pinned agent binary.
 */
export const CLIENT_ID_METADATA_URLS: ReadonlySet<string> = new Set([
  // Claude Code (MCP_OAUTH_CLIENT_METADATA_URL default)
  "https://claude.ai/oauth/claude-code-client-metadata",
  // Codex (rmcp CIMD client)
  "https://chatgpt.com/oauth/codex/client.json",
]);

// A client_id an issuer may treat as a URL to fetch.
function urlLikeClientId(clientId: string): boolean {
  return /[:/]/.test(clientId);
}

/**
 * The request-target path exactly as the client sent it, before any URL
 * normalization (`new URL()` resolves dot segments, so `/a/../oauth/token`
 * would compare equal to `/oauth/token` while an origin may route it
 * elsewhere). Undefined for anything that is not a plain, unambiguous path:
 * a query or fragment, percent-encoding, `;`, a backslash, `//`, a dot
 * segment, or a byte outside printable ASCII.
 */
export function plainRequestPath(rawUrl: string): string | undefined {
  const match = /^https:\/\/[^/?#]+(\/[^?#]*)?$/i.exec(rawUrl);
  if (!match) return undefined;
  const pathName = match[1] ?? "/";
  if (!/^\/[\x21-\x7e]*$/.test(pathName)) return undefined;
  if (/[%;\\]/.test(pathName) || pathName.includes("//")) return undefined;
  if (pathName.split("/").some((segment) => segment === "." || segment === "..")) return undefined;
  return pathName;
}

function singleHeader(headers: Record<string, HeaderValue> | undefined, name: string): string | undefined | null {
  let found: string | undefined;
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() !== name) continue;
    if (found !== undefined || Array.isArray(value)) return null;
    found = value;
  }
  return found;
}

function mediaType(value: string): string {
  return value.split(";", 1)[0].trim().toLowerCase();
}

function loopbackRedirect(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 512) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "http:"
    && url.username === ""
    && url.password === ""
    && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
}

function stringSubset(value: unknown, allowed: Set<string>): boolean {
  return Array.isArray(value) && value.length > 0 && value.length <= 4
    && value.every((entry) => typeof entry === "string" && allowed.has(entry));
}

// A `resource` (RFC 8707) must name this server's own resource host; a
// URL-valued `client_id` must be a pinned agent metadata URL, because an
// authorization server that supports client ID metadata documents fetches it.
function resourceIndicatorAllowed(value: string, resourceHost: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.username === "" && url.password === "" && url.port === ""
    && url.hostname.toLowerCase() === resourceHost;
}

function tokenBodyAllowed(bodyText: string, resourceHost: string): boolean {
  const params = new URLSearchParams(bodyText);
  const seen = new Set<string>();
  for (const [key, value] of params) {
    if (seen.has(key) || !TOKEN_FIELDS.has(key) || value.length > 4096) return false;
    seen.add(key);
  }
  if (!TOKEN_GRANTS.has(params.get("grant_type") ?? "")) return false;
  const clientId = params.get("client_id");
  if (clientId !== null && (clientId.length > 256 || !PRINTABLE_ASCII.test(clientId))) return false;
  if (clientId !== null && urlLikeClientId(clientId) && !CLIENT_ID_METADATA_URLS.has(clientId)) return false;
  const resource = params.get("resource");
  if (resource !== null && !resourceIndicatorAllowed(resource, resourceHost)) return false;
  const redirect = params.get("redirect_uri");
  return redirect === null || loopbackRedirect(redirect);
}

function registrationBodyAllowed(bodyText: string): boolean {
  const parsed = parseJsonStrict(bodyText);
  const value = parsed.value;
  if (parsed.reason !== undefined || value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const body = value as Record<string, unknown>;
  if (!Object.keys(body).every((key) => REGISTRATION_FIELDS.has(key))) return false;
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 || body.redirect_uris.length > 8
    || !body.redirect_uris.every(loopbackRedirect)) {
    return false;
  }
  if (body.client_name !== undefined
    && (typeof body.client_name !== "string" || body.client_name.length > 200 || !PRINTABLE_ASCII.test(body.client_name))) {
    return false;
  }
  if (body.grant_types !== undefined && !stringSubset(body.grant_types, TOKEN_GRANTS)) return false;
  if (body.response_types !== undefined && !stringSubset(body.response_types, new Set(["code"]))) return false;
  if (body.token_endpoint_auth_method !== undefined
    && (typeof body.token_endpoint_auth_method !== "string" || !REGISTRATION_AUTH_METHODS.has(body.token_endpoint_auth_method))) {
    return false;
  }
  if (body.scope !== undefined && (typeof body.scope !== "string" || body.scope.length > 1000 || !PRINTABLE_ASCII.test(body.scope))) {
    return false;
  }
  return true;
}

/**
 * True when the request body is the protocol's own shape: a form-encoded
 * authorization-code or refresh-token grant for a token endpoint, and a
 * loopback-only dynamic client registration for a registration endpoint. No
 * field an issuer may fetch (sector_identifier_uri, jwks_uri, logo_uri,
 * request_uris, software_statement, client assertions) is allowed, so the
 * issuer is never made to contact a host the agent chose: a URL `client_id`
 * must be one of CLIENT_ID_METADATA_URLS, and a `resource` must name the
 * server's own resource host.
 */
export function protocolReadBodyAllowed(input: {
  bodyText: string | undefined;
  headers: Record<string, HeaderValue> | undefined;
  kind: ProtocolReadKind;
  // The MCP server's resource host, the only host a `resource` may name.
  resourceHost: string;
}): boolean {
  const contentType = singleHeader(input.headers, "content-type");
  const contentEncoding = singleHeader(input.headers, "content-encoding");
  const contentLength = singleHeader(input.headers, "content-length");
  if (typeof contentType !== "string" || contentEncoding === null || typeof contentLength !== "string") return false;
  if (contentEncoding !== undefined && contentEncoding.trim().toLowerCase() !== "identity") return false;
  if (singleHeader(input.headers, "transfer-encoding") !== undefined) return false;
  if (!/^\d{1,6}$/.test(contentLength) || Number(contentLength) > PROTOCOL_READ_BODY_CAP_BYTES) return false;
  const bodyText = input.bodyText;
  if (bodyText === undefined || Buffer.byteLength(bodyText) !== Number(contentLength)) return false;
  if (input.kind === "token") {
    return mediaType(contentType) === "application/x-www-form-urlencoded" && tokenBodyAllowed(bodyText, input.resourceHost);
  }
  return mediaType(contentType) === "application/json" && registrationBodyAllowed(bodyText);
}

/**
 * True when a token body carries a single URL-valued client_id that is not a
 * pinned agent metadata URL. Display only: it lets a write-approval denial say
 * why the request was not a protocol read. The value itself is never echoed.
 */
export function unlistedClientIdMetadataUrl(bodyText: string): boolean {
  const values = new URLSearchParams(bodyText).getAll("client_id");
  return values.length === 1 && urlLikeClientId(values[0]) && !CLIENT_ID_METADATA_URLS.has(values[0]);
}

/** The grant type to log for a token request, never a secret. */
export function protocolReadGrantType(kind: ProtocolReadKind, bodyText: string): string {
  if (kind !== "token") return "registration";
  const grant = new URLSearchParams(bodyText).get("grant_type") ?? "";
  return TOKEN_GRANTS.has(grant) ? grant : "unknown";
}

/**
 * Per-provider budget for unattended protocol reads. Past it, requests fall
 * back to the normal write classification (and so to write approval).
 */
export class ProtocolReadRateLimiter {
  private readonly windows = new Map<string, number[]>();

  constructor(private readonly options: { maxPerWindow?: number; now?: () => number; windowMs?: number } = {}) {}

  private recent(provider: string, now: number): number[] {
    const windowMs = this.options.windowMs ?? RATE_WINDOW_MS;
    const recent = (this.windows.get(provider) ?? []).filter((at) => now - at < windowMs);
    this.windows.set(provider, recent);
    return recent;
  }

  /** Whether a read is still in budget; spends nothing. */
  available(provider: string): boolean {
    return this.recent(provider, this.options.now?.() ?? Date.now()).length < (this.options.maxPerWindow ?? RATE_MAX_PER_WINDOW);
  }

  /** Spends one read; false when the budget is already spent. */
  take(provider: string): boolean {
    const now = this.options.now?.() ?? Date.now();
    const recent = this.recent(provider, now);
    if (recent.length >= (this.options.maxPerWindow ?? RATE_MAX_PER_WINDOW)) return false;
    recent.push(now);
    return true;
  }
}
