// Host-side OAuth host discovery for `runfree mcp enable`.
//
// The MCP endpoint URL comes from MCP config, which for project entries is
// untrusted project input. Every request here is therefore hardened as an
// SSRF surface: HTTPS on the default port only; a hostname that is valid for
// the network policy and is not an IP literal; every resolved address public;
// a TLS socket opened to the checked IP itself (the hostname is used only for
// SNI and certificate verification, so no second resolution can happen); no
// redirects, credentials, cookies, compression, or proxy; fixed headers;
// absolute timeouts; header and body caps; a JSON content type; and a JSON
// object body. The transport is a raw `tls.connect` plus a fixed HTTP/1.1
// request so the same guarantees hold in the Bun-compiled release binary,
// which does not share Node's `http` lookup-hook semantics.
//
// Discovery only proposes hosts and endpoints. It never writes anything; the
// caller shows every candidate with its origin in one review and records only
// what the user approves. A host is proposed only when validated metadata
// shows an endpoint that the proxy's OAuth mediator binds for this server
// (`packages/proxy/src/oauth-mediation.ts` `serverBindingHosts` /
// `effectiveBindingHosts`); the endpoints themselves are recorded too, so the
// proxy mediates them statically instead of relying on run-time capture.

import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";

import { isReservedRunfreeHostname } from "@runfree/runtime-contracts/host-services";
import { normalizeHostname, normalizePathPrefix } from "@runfree/runtime-contracts/network-policy";

export const DISCOVERY_LIMITS = Object.freeze({
  requestTimeoutMs: 5_000,
  totalBudgetMs: 20_000,
  maxRequests: 12,
  maxHeaderBytes: 16 * 1024,
  maxBodyBytes: 64 * 1024,
  maxIssuers: 4,
  maxHosts: 16,
});

export type ResolvedAddress = { address: string; family: 4 | 6 };

export type DiscoveryHttpResult =
  | { kind: "response"; status: number; contentType: string | undefined; body: Buffer }
  | { kind: "error"; reason: string };

export type DiscoveryRequestOptions = { timeoutMs: number; maxBodyBytes: number };

export type DiscoveryDeps = {
  resolve?: (host: string) => Promise<ResolvedAddress[]>;
  // Performs one GET against already-checked addresses (tried in order).
  request?: (url: URL, targets: ResolvedAddress[], options: DiscoveryRequestOptions) => Promise<DiscoveryHttpResult>;
  now?: () => number;
};

export type McpOAuthDiscoveryInput = {
  // The MCP endpoint URL (HTTPS) from the resolved MCP entry.
  endpointUrl: string;
  // Declared, host-trusted OAuth configuration from the reviewed descriptor.
  declaredMetadataUrls: string[];
  declaredTokenHosts: string[];
};

export type DiscoveredOAuthHost = {
  host: string;
  evidence: string[];
};

export type OAuthEndpointKind = "metadata" | "token" | "registration";

export type DiscoveredOAuthEndpoint = {
  kind: OAuthEndpointKind;
  host: string;
  path: string;
};

export type DiscoveryContact = {
  url: string;
  outcome: string;
};

export type McpOAuthDiscoveryResult = {
  contacted: DiscoveryContact[];
  // Hosts validated metadata named, for the user to approve. Excludes the MCP
  // endpoint host and declared hosts, which the approval already projects.
  hosts: DiscoveredOAuthHost[];
  // Exact validated metadata/token/registration endpoints on bound hosts
  // (including the endpoint host), recorded for static proxy mediation.
  endpoints: DiscoveredOAuthEndpoint[];
  // Bound hosts that are already projected with the server.
  covered: string[];
  // Human-readable refusals: sources dropped and endpoints not added.
  rejected: string[];
  // Browser-facing authorization endpoint origins (display only).
  authorizationEndpoints: string[];
  // Whether any valid OAuth metadata was found.
  oauthDetected: boolean;
};

// --- Hostname and address rules -------------------------------------------

/**
 * An exact, policy-valid hostname that is not an IP literal in any form a
 * resolver accepts (WHATWG "ends in a number": decimal or hex last label).
 * Used for discovered hosts, fetch targets, and `--oauth-host` values.
 */
export function checkPolicyHostname(input: string): { ok: true; host: string } | { ok: false; reason: string } {
  let host: string;
  try {
    host = normalizeHostname(input);
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? (error.message.split("\n")[0] ?? error.message) : String(error) };
  }
  if (isReservedRunfreeHostname(host)) {
    return { ok: false, reason: `${host} uses the reserved runfree.internal suffix` };
  }
  const labels = host.split(".");
  const last = labels[labels.length - 1] ?? "";
  if (net.isIP(host) !== 0 || /^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/.test(last)) {
    return { ok: false, reason: "IP addresses are not allowed; use a hostname" };
  }
  if (host === "localhost" || host.endsWith(".localhost")) return { ok: false, reason: "localhost names are not allowed" };
  let reparsed: string;
  try {
    reparsed = new URL(`https://${host}/`).hostname;
  } catch {
    return { ok: false, reason: "not a valid URL hostname" };
  }
  if (reparsed !== host) return { ok: false, reason: "not a canonical hostname" };
  return { ok: true, host };
}

function ipv4ToInt(address: string): number | undefined {
  const parts = address.split(".");
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    value = value * 256 + octet;
  }
  return value;
}

// IANA IPv4 special-purpose blocks that are not globally reachable, plus
// multicast and the reserved class E space.
const IPV4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function ipv4Public(address: string): boolean {
  const value = ipv4ToInt(address);
  if (value === undefined) return false;
  for (const [base, bits] of IPV4_BLOCKED) {
    const baseValue = ipv4ToInt(base) as number;
    const size = 2 ** (32 - bits);
    if (value >= baseValue && value < baseValue + size) return false;
  }
  return true;
}

function ipv6Hextets(address: string): number[] | undefined {
  if (address.includes("%")) return undefined; // zone ids are link-scoped
  let text = address.toLowerCase();
  const dotted = /(^|:)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/.exec(text);
  if (dotted?.[2]) {
    const value = ipv4ToInt(dotted[2]);
    if (value === undefined) return undefined;
    text = `${text.slice(0, text.length - dotted[2].length)}${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const parse = (part: string): number[] | undefined => {
    if (part === "") return [];
    const out: number[] = [];
    for (const group of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined;
      out.push(Number.parseInt(group, 16));
    }
    return out;
  };
  const head = parse(halves[0] ?? "");
  const tail = halves.length === 2 ? parse(halves[1] ?? "") : [];
  if (!head || !tail) return undefined;
  if (halves.length === 1) return head.length === 8 ? head : undefined;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return undefined;
  return [...head, ...new Array<number>(missing).fill(0), ...tail];
}

function ipv6Public(address: string): boolean {
  const h = ipv6Hextets(address);
  if (!h) return false;
  const [first = 0, second = 0] = h;
  // Allowlist: only global unicast 2000::/3 ...
  if ((first & 0xe000) !== 0x2000) return false;
  // ... minus the special-purpose and translation blocks inside it. NAT64,
  // 6to4, and Teredo are refused outright, not decoded.
  if (first === 0x2001 && second < 0x0200) return false; // 2001::/23 (Teredo, ORCHID, benchmarking, ...)
  if (first === 0x2001 && second === 0x0db8) return false; // documentation
  if (first === 0x2002) return false; // 6to4
  if (first === 0x3fff && second < 0x1000) return false; // 3fff::/20 documentation
  return true;
}

/**
 * Whether an address may be contacted by host-side discovery: an allowlist of
 * plainly public unicast space. IPv4-mapped/compatible, NAT64 (both prefixes,
 * which lie outside 2000::/3), 6to4, Teredo, zone-scoped, and unparseable
 * addresses are refused.
 */
export function isPublicAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return ipv4Public(address);
  if (family === 6) return ipv6Public(address);
  return false;
}

// --- URL rules -------------------------------------------------------------

function parseHttpsUrl(value: unknown): URL | undefined {
  if (typeof value !== "string" || value.length > 2048) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "") return undefined;
  if (!checkPolicyHostname(url.hostname).ok) return undefined;
  return url;
}

function issuerUrl(value: unknown): URL | undefined {
  const url = parseHttpsUrl(value);
  if (!url || url.search !== "" || url.hash !== "") return undefined;
  return url;
}

export const MAX_ENDPOINT_PATH_CHARS = 1024;

/**
 * Whether an endpoint can be recorded by `runfree mcp enable`: the one
 * predicate discovery filters with and the record reader validates with, so
 * the review never shows an endpoint that cannot be saved. The path must be
 * printable ASCII, equal its own URL-parsed form, be a valid request-rule
 * prefix, and not be `/` (a `/` prefix would open the whole host). Metadata
 * endpoints must be `/.well-known/` documents.
 */
export function isRecordableEndpoint(kind: OAuthEndpointKind, host: string, pathName: string): boolean {
  const checked = checkPolicyHostname(host);
  if (!checked.ok || checked.host !== host) return false;
  if (pathName === "/" || !pathName.startsWith("/") || pathName.length > MAX_ENDPOINT_PATH_CHARS) return false;
  if (!/^[\x21-\x7e]+$/.test(pathName)) return false;
  try {
    if (new URL(`https://${host}${pathName}`).pathname !== pathName) return false;
    if (normalizePathPrefix(pathName) !== pathName) return false;
  } catch {
    return false;
  }
  return kind !== "metadata" || pathName.includes("/.well-known/");
}

// An endpoint the proxy can match exactly: HTTPS, no query/fragment, and a
// recordable path.
function endpointUrl(value: unknown, kind: OAuthEndpointKind): URL | undefined {
  const url = parseHttpsUrl(value);
  if (!url || url.search !== "" || url.hash !== "") return undefined;
  return isRecordableEndpoint(kind, url.hostname, url.pathname) ? url : undefined;
}

function issuerPath(url: URL): string {
  return url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
}

function sameIssuer(left: URL, right: URL): boolean {
  return left.hostname === right.hostname && issuerPath(left) === issuerPath(right);
}

export function protectedResourceMetadataUrls(endpoint: URL): string[] {
  const origin = `https://${endpoint.hostname}`;
  const pathPart = endpoint.pathname === "/" ? "" : endpoint.pathname.replace(/\/$/, "");
  return [
    ...(pathPart ? [`${origin}/.well-known/oauth-protected-resource${pathPart}`] : []),
    `${origin}/.well-known/oauth-protected-resource`,
  ];
}

export function authorizationServerMetadataUrls(issuer: URL): string[] {
  const origin = `https://${issuer.hostname}`;
  const pathPart = issuerPath(issuer);
  return pathPart
    ? [
      `${origin}/.well-known/oauth-authorization-server${pathPart}`,
      `${origin}/.well-known/openid-configuration${pathPart}`,
      `${origin}${pathPart}/.well-known/openid-configuration`,
    ]
    : [
      `${origin}/.well-known/oauth-authorization-server`,
      `${origin}/.well-known/openid-configuration`,
    ];
}

// --- Transport -------------------------------------------------------------

async function defaultResolve(host: string): Promise<ResolvedAddress[]> {
  const results = await dns.promises.lookup(host, { all: true, verbatim: true });
  return results.map((result) => ({ address: result.address, family: result.family === 6 ? 6 : 4 }));
}

function mediaType(contentType: string | undefined): string | undefined {
  return contentType?.split(";")[0]?.trim().toLowerCase();
}

type ParsedHead = { status: number; headers: Map<string, string>; bodyStart: number };

function parseHead(raw: Buffer): ParsedHead | "incomplete" | string {
  const end = raw.indexOf("\r\n\r\n");
  if (end === -1) return raw.length > DISCOVERY_LIMITS.maxHeaderBytes ? "response headers too large" : "incomplete";
  if (end > DISCOVERY_LIMITS.maxHeaderBytes) return "response headers too large";
  const lines = raw.subarray(0, end).toString("latin1").split("\r\n");
  const statusMatch = /^HTTP\/1\.[01] ([0-9]{3})(?: .*)?$/.exec(lines[0] ?? "");
  if (!statusMatch?.[1]) return "malformed HTTP status line";
  const headers = new Map<string, string>();
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0) return "malformed HTTP header";
    const rawName = line.slice(0, colon);
    // RFC 9110 token characters only; no whitespace before the colon.
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(rawName)) return "malformed HTTP header";
    const name = rawName.toLowerCase();
    const value = line.slice(colon + 1).trim();
    const existing = headers.get(name);
    if (existing !== undefined && (name === "content-length" || name === "transfer-encoding" || name === "content-type")) {
      if (existing !== value) return `conflicting ${name} headers`;
    }
    headers.set(name, existing !== undefined && existing !== value ? `${existing}, ${value}` : value);
  }
  return { status: Number(statusMatch[1]), headers, bodyStart: end + 4 };
}

// Decode a complete chunked body; "incomplete" until the terminal chunk.
function decodeChunked(raw: Buffer, maxBodyBytes: number): Buffer | "incomplete" | string {
  const chunks: Buffer[] = [];
  let offset = 0;
  let total = 0;
  for (;;) {
    const lineEnd = raw.indexOf("\r\n", offset);
    if (lineEnd === -1) return "incomplete";
    const sizeText = raw.subarray(offset, lineEnd).toString("latin1").split(";")[0]?.trim() ?? "";
    if (!/^[0-9a-fA-F]{1,8}$/.test(sizeText)) return "malformed chunked body";
    const size = Number.parseInt(sizeText, 16);
    offset = lineEnd + 2;
    if (size === 0) return Buffer.concat(chunks);
    total += size;
    if (total > maxBodyBytes) return `response larger than ${maxBodyBytes} bytes`;
    if (raw.length < offset + size + 2) return "incomplete";
    if (raw[offset + size] !== 0x0d || raw[offset + size + 1] !== 0x0a) return "malformed chunked body";
    chunks.push(raw.subarray(offset, offset + size));
    offset += size + 2;
  }
}

function requestOnce(url: URL, target: ResolvedAddress, options: DiscoveryRequestOptions & { testCa?: string | Buffer; testPort?: number; deadline: number }): Promise<DiscoveryHttpResult & { connectFailed?: boolean }> {
  return new Promise((resolve) => {
    let settled = false;
    // Only a failure before the TCP connect lets the next checked address be
    // tried; a TLS or HTTP failure after it is the answer for this request.
    let tcpConnected = false;
    let raw = Buffer.alloc(0);
    let head: ParsedHead | undefined;
    // The socket goes to the checked IP; `servername` drives SNI and the
    // certificate identity check. `rejectUnauthorized: true` is explicit, so
    // NODE_TLS_REJECT_UNAUTHORIZED=0 in the host env cannot weaken it. No
    // proxy is involved: this is a direct socket.
    const socket = tls.connect({
      host: target.address,
      port: options.testPort ?? 443,
      servername: url.hostname,
      rejectUnauthorized: true,
      ALPNProtocols: ["http/1.1"],
      ...(options.testCa ? { ca: options.testCa } : {}),
    });
    const finish = (result: DiscoveryHttpResult & { connectFailed?: boolean }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish({ kind: "error", reason: `timed out after ${options.timeoutMs} ms`, ...(tcpConnected ? {} : { connectFailed: true }) });
    }, Math.max(1, Math.min(options.timeoutMs, options.deadline - Date.now())));
    const complete = () => {
      if (!head) return;
      const transferEncoding = head.headers.get("transfer-encoding")?.toLowerCase();
      const contentLength = head.headers.get("content-length");
      const bodyRaw = raw.subarray(head.bodyStart);
      const contentType = head.headers.get("content-type");
      if (transferEncoding !== undefined) {
        const decoded = decodeChunked(bodyRaw, options.maxBodyBytes);
        if (decoded === "incomplete") return;
        if (typeof decoded === "string") return finish({ kind: "error", reason: decoded });
        return finish({ kind: "response", status: head.status, contentType, body: decoded });
      }
      if (contentLength !== undefined) {
        const length = Number(contentLength);
        if (bodyRaw.length < length) return;
        return finish({ kind: "response", status: head.status, contentType, body: bodyRaw.subarray(0, length) });
      }
    };
    socket.once("connect", () => {
      tcpConnected = true;
    });
    socket.once("secureConnect", () => {
      if (socket.alpnProtocol && socket.alpnProtocol !== "http/1.1") {
        finish({ kind: "error", reason: "server did not accept HTTP/1.1" });
        return;
      }
      const target = `${url.pathname}${url.search}`;
      socket.write([
        `GET ${target} HTTP/1.1`,
        `Host: ${url.hostname}`,
        "Accept: application/json",
        "Accept-Encoding: identity",
        "User-Agent: runfree-mcp-discovery",
        "Connection: close",
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk: Buffer) => {
      raw = Buffer.concat([raw, chunk]);
      if (raw.length > DISCOVERY_LIMITS.maxHeaderBytes + options.maxBodyBytes * 2) {
        finish({ kind: "error", reason: `response larger than ${options.maxBodyBytes} bytes` });
        return;
      }
      if (!head) {
        const parsed = parseHead(raw);
        if (parsed === "incomplete") return;
        if (typeof parsed === "string") return finish({ kind: "error", reason: parsed });
        head = parsed;
        const encoding = head.headers.get("content-encoding")?.toLowerCase();
        if (encoding !== undefined && encoding !== "identity") return finish({ kind: "error", reason: "compressed responses are not accepted" });
        const transferEncoding = head.headers.get("transfer-encoding")?.toLowerCase();
        if (transferEncoding !== undefined && transferEncoding !== "chunked") return finish({ kind: "error", reason: "unsupported transfer encoding" });
        const contentLength = head.headers.get("content-length");
        if (contentLength !== undefined && (!/^[0-9]{1,9}$/.test(contentLength) || transferEncoding !== undefined)) {
          return finish({ kind: "error", reason: "malformed content length" });
        }
        if (contentLength !== undefined && Number(contentLength) > options.maxBodyBytes) {
          return finish({ kind: "error", reason: `response larger than ${options.maxBodyBytes} bytes` });
        }
        // Only a 200 needs its body; answer everything else from the head.
        if (head.status !== 200) {
          return finish({ kind: "response", status: head.status, contentType: head.headers.get("content-type"), body: Buffer.alloc(0) });
        }
      }
      complete();
    });
    socket.on("end", () => {
      if (!head) return finish({ kind: "error", reason: "connection closed before a response" });
      complete();
      if (settled) return;
      if (head.headers.get("transfer-encoding") !== undefined || head.headers.get("content-length") !== undefined) {
        return finish({ kind: "error", reason: "connection closed before the full response" });
      }
      const body = raw.subarray(head.bodyStart);
      if (body.length > options.maxBodyBytes) return finish({ kind: "error", reason: `response larger than ${options.maxBodyBytes} bytes` });
      finish({ kind: "response", status: head.status, contentType: head.headers.get("content-type"), body });
    });
    socket.on("error", (error: NodeJS.ErrnoException) => {
      finish({
        kind: "error",
        reason: error.code ? `request failed (${error.code})` : "request failed",
        ...(tcpConnected ? {} : { connectFailed: true }),
      });
    });
  });
}

/**
 * One GET against already-checked addresses, tried in order on connect
 * failure only (never re-resolved). Exported for the TLS test; `testCa` and
 * `testPort` exist only so the test can reach its own local server.
 */
export async function pinnedHttpsGet(
  url: URL,
  targets: ResolvedAddress[],
  options: DiscoveryRequestOptions & { testCa?: string | Buffer; testPort?: number },
): Promise<DiscoveryHttpResult> {
  const deadline = Date.now() + options.timeoutMs;
  let last: DiscoveryHttpResult = { kind: "error", reason: "no checked address" };
  for (const target of targets) {
    if (Date.now() >= deadline) break;
    const result = await requestOnce(url, target, { ...options, deadline });
    if (result.kind === "response" || !result.connectFailed) {
      const { connectFailed: _connectFailed, ...plain } = result;
      return plain as DiscoveryHttpResult;
    }
    last = { kind: "error", reason: result.reason };
  }
  return last;
}

// --- Discovery -------------------------------------------------------------

type FetchOutcome =
  | { kind: "json"; value: Record<string, unknown>; url: URL }
  | { kind: "not-found" }
  | { kind: "failed" };

class DiscoverySession {
  readonly contacted: DiscoveryContact[] = [];
  private requests = 0;
  private readonly deadline: number;
  private readonly resolve: NonNullable<DiscoveryDeps["resolve"]>;
  private readonly request: NonNullable<DiscoveryDeps["request"]>;
  private readonly now: () => number;
  private readonly checkedAddresses = new Map<string, ResolvedAddress[] | string>();

  constructor(deps: DiscoveryDeps) {
    this.resolve = deps.resolve ?? defaultResolve;
    this.request = deps.request ?? ((url, targets, options) => pinnedHttpsGet(url, targets, options));
    this.now = deps.now ?? Date.now;
    this.deadline = this.now() + DISCOVERY_LIMITS.totalBudgetMs;
  }

  private record(url: string, outcome: string): void {
    this.contacted.push({ url, outcome });
  }

  // Resolve once per host and refuse unless every address is public.
  private async addresses(host: string): Promise<ResolvedAddress[] | string> {
    const cached = this.checkedAddresses.get(host);
    if (cached !== undefined) return cached;
    let result: ResolvedAddress[] | string;
    try {
      const addresses = await this.resolve(host);
      if (addresses.length === 0) result = "no addresses";
      else if (addresses.some((entry) => !isPublicAddress(entry.address))) {
        result = "resolves to a non-public or translated address (on a DNS64-only network, use --no-discover)";
      } else result = addresses;
    } catch {
      result = "DNS lookup failed";
    }
    this.checkedAddresses.set(host, result);
    return result;
  }

  async fetchJson(rawUrl: string): Promise<FetchOutcome> {
    const url = parseHttpsUrl(rawUrl);
    if (!url || url.hash !== "") {
      this.record("(invalid URL)", "skipped: not an HTTPS URL on a policy-valid hostname");
      return { kind: "failed" };
    }
    const shown = url.href;
    if (this.requests >= DISCOVERY_LIMITS.maxRequests) {
      this.record(shown, "skipped: request limit reached");
      return { kind: "failed" };
    }
    const remaining = this.deadline - this.now();
    if (remaining <= 0) {
      this.record(shown, "skipped: discovery time budget used up");
      return { kind: "failed" };
    }
    const targets = await this.addresses(url.hostname);
    if (typeof targets === "string") {
      this.record(shown, `refused: ${targets}`);
      return { kind: "failed" };
    }
    this.requests += 1;
    const response = await this.request(url, targets, {
      timeoutMs: Math.min(DISCOVERY_LIMITS.requestTimeoutMs, remaining),
      maxBodyBytes: DISCOVERY_LIMITS.maxBodyBytes,
    });
    if (response.kind === "error") {
      this.record(shown, `failed: ${response.reason}`);
      return { kind: "failed" };
    }
    if (response.status === 404 || response.status === 410) {
      this.record(shown, `not found (${response.status})`);
      return { kind: "not-found" };
    }
    if (response.status >= 300 && response.status < 400) {
      this.record(shown, `refused: redirect (${response.status}) not followed`);
      return { kind: "failed" };
    }
    if (response.status !== 200) {
      this.record(shown, `failed: HTTP ${response.status}`);
      return { kind: "failed" };
    }
    if (mediaType(response.contentType) !== "application/json") {
      this.record(shown, "refused: content type is not application/json");
      return { kind: "failed" };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body.toString("utf8"));
    } catch {
      this.record(shown, "refused: body is not valid JSON");
      return { kind: "failed" };
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      this.record(shown, "refused: body is not a JSON object");
      return { kind: "failed" };
    }
    this.record(shown, "ok");
    return { kind: "json", value: parsed as Record<string, unknown>, url };
  }
}

type AuthServerMetadata = {
  metadataUrl: URL;
  tokenEndpoint: URL;
  registrationEndpoint?: URL;
  authorizationEndpoint?: URL;
};

function validateAuthServerMetadata(
  value: Record<string, unknown>,
  metadataUrl: URL,
  expectedIssuer: URL,
  rejected: string[],
): AuthServerMetadata | undefined {
  const source = metadataUrl.href;
  const issuer = issuerUrl(value.issuer);
  if (!issuer || !sameIssuer(issuer, expectedIssuer)) {
    rejected.push(`${source}: issuer does not match ${expectedIssuer.href}`);
    return undefined;
  }
  const tokenEndpoint = endpointUrl(value.token_endpoint, "token");
  if (!tokenEndpoint) {
    rejected.push(`${source}: token_endpoint is missing or is not an exact HTTPS URL on a policy-valid hostname`);
    return undefined;
  }
  const registrationEndpoint = endpointUrl(value.registration_endpoint, "registration");
  if (value.registration_endpoint !== undefined && !registrationEndpoint) {
    rejected.push(`${source}: registration_endpoint is not an exact HTTPS URL on a policy-valid hostname`);
  }
  const authorizationEndpoint = parseHttpsUrl(value.authorization_endpoint);
  return {
    metadataUrl,
    tokenEndpoint,
    ...(registrationEndpoint ? { registrationEndpoint } : {}),
    ...(authorizationEndpoint ? { authorizationEndpoint } : {}),
  };
}

async function fetchAuthServerMetadata(
  session: DiscoverySession,
  issuer: URL,
  rejected: string[],
): Promise<AuthServerMetadata | undefined> {
  for (const candidate of authorizationServerMetadataUrls(issuer)) {
    const outcome = await session.fetchJson(candidate);
    if (outcome.kind !== "json") continue;
    const metadata = validateAuthServerMetadata(outcome.value, outcome.url, issuer, rejected);
    if (metadata) return metadata;
  }
  return undefined;
}

export async function discoverMcpOAuthHosts(
  input: McpOAuthDiscoveryInput,
  deps: DiscoveryDeps = {},
): Promise<McpOAuthDiscoveryResult> {
  const endpoint = parseHttpsUrl(input.endpointUrl);
  if (!endpoint) throw new Error("MCP endpoint must be an HTTPS URL on a policy-valid hostname");
  const session = new DiscoverySession(deps);
  const rejected: string[] = [];
  const endpointHost = endpoint.hostname;
  const declaredHosts = new Set<string>();
  const declaredMetadata: URL[] = [];
  for (const raw of input.declaredMetadataUrls) {
    const url = issuerUrl(raw);
    if (!url) {
      rejected.push("declared authServerMetadataUrl is not an HTTPS URL on a policy-valid hostname without query or port; not fetched");
      continue;
    }
    declaredHosts.add(url.hostname);
    declaredMetadata.push(url);
  }
  for (const host of input.declaredTokenHosts) declaredHosts.add(host);
  const projected = new Set<string>([endpointHost, ...declaredHosts]);

  // 1. RFC 9728 protected-resource metadata on the endpoint host.
  const issuers: URL[] = [];
  let protectedResourceUrl: URL | undefined;
  for (const candidate of protectedResourceMetadataUrls(endpoint)) {
    const outcome = await session.fetchJson(candidate);
    if (outcome.kind !== "json") continue;
    const resource = parseHttpsUrl(outcome.value.resource);
    if (!resource || resource.hostname !== endpointHost) {
      rejected.push(`${outcome.url.href}: resource does not name ${endpointHost}`);
      continue;
    }
    protectedResourceUrl = outcome.url;
    const servers = outcome.value.authorization_servers;
    if (servers !== undefined && !Array.isArray(servers)) {
      rejected.push(`${outcome.url.href}: authorization_servers is not a list`);
    } else {
      for (const [index, entry] of (servers ?? []).entries()) {
        const issuer = issuerUrl(entry);
        if (!issuer) {
          rejected.push(`${outcome.url.href}: authorization_servers[${index}] is not an HTTPS issuer URL on a policy-valid hostname`);
          continue;
        }
        if (issuers.some((existing) => sameIssuer(existing, issuer))) continue;
        if (issuers.length >= DISCOVERY_LIMITS.maxIssuers) {
          rejected.push(`${outcome.url.href}: more than ${DISCOVERY_LIMITS.maxIssuers} authorization servers; ignored ${issuer.href}`);
          continue;
        }
        issuers.push(issuer);
      }
    }
    break;
  }

  // The mediator's binding set: the endpoint host, declared hosts, and the
  // issuer hosts that the endpoint host's own metadata named.
  const bindingHosts = new Set<string>([endpointHost, ...declaredHosts, ...issuers.map((issuer) => issuer.hostname)]);

  // 2. Authorization-server metadata: named issuers, declared metadata URLs,
  // and the 2025-03-26 resource-origin fallback.
  const found: Array<{ metadata: AuthServerMetadata; via: string }> = [];
  for (const issuer of issuers) {
    const metadata = await fetchAuthServerMetadata(session, issuer, rejected);
    if (metadata) found.push({ metadata, via: `authorization server ${issuer.href} named by ${protectedResourceUrl?.href ?? endpoint.origin}` });
    else rejected.push(`${issuer.href}: no valid authorization-server metadata; its host is not added`);
  }
  for (const url of declaredMetadata) {
    const outcome = await session.fetchJson(url.href);
    if (outcome.kind !== "json") continue;
    const metadata = validateAuthServerMetadata(outcome.value, outcome.url, new URL(`https://${url.hostname}`), rejected);
    if (metadata) found.push({ metadata, via: `declared metadata ${url.href}` });
  }
  if (!protectedResourceUrl && declaredMetadata.length === 0) {
    const metadata = await fetchAuthServerMetadata(session, new URL(`https://${endpointHost}`), rejected);
    if (metadata) found.push({ metadata, via: `authorization server at ${endpoint.origin}` });
  }

  // 3. Candidates: a host is proposed only with validated metadata and a
  // token endpoint inside the binding set.
  const candidates = new Map<string, string[]>();
  const covered = new Set<string>();
  const endpoints = new Map<string, DiscoveredOAuthEndpoint>();
  const addHost = (host: string, evidence: string): void => {
    if (projected.has(host)) {
      covered.add(host);
      return;
    }
    const list = candidates.get(host) ?? [];
    if (!list.includes(evidence)) list.push(evidence);
    candidates.set(host, list);
  };
  const addEndpoint = (kind: OAuthEndpointKind, url: URL): void => {
    endpoints.set(`${kind}\0${url.hostname}\0${url.pathname}`, { kind, host: url.hostname, path: url.pathname });
  };
  const authorizationEndpoints: string[] = [];
  for (const { metadata, via } of found) {
    const token = metadata.tokenEndpoint;
    if (!bindingHosts.has(token.hostname)) {
      rejected.push(`token_endpoint ${token.origin}${token.pathname} is not on the MCP endpoint host or a named authorization server; the proxy would not mediate its tokens, so ${metadata.metadataUrl.hostname} is not added`);
      continue;
    }
    addHost(metadata.metadataUrl.hostname, `${via}; metadata ${metadata.metadataUrl.href}`);
    if (isRecordableEndpoint("metadata", metadata.metadataUrl.hostname, metadata.metadataUrl.pathname)) {
      addEndpoint("metadata", metadata.metadataUrl);
    }
    addHost(token.hostname, `token_endpoint ${token.origin}${token.pathname}`);
    addEndpoint("token", token);
    const registration = metadata.registrationEndpoint;
    if (registration) {
      if (bindingHosts.has(registration.hostname)) {
        addHost(registration.hostname, `registration_endpoint ${registration.origin}${registration.pathname}`);
        addEndpoint("registration", registration);
      } else {
        rejected.push(`registration_endpoint ${registration.origin}${registration.pathname} is not on the MCP endpoint host or a named authorization server; not added`);
      }
    }
    if (metadata.authorizationEndpoint && !authorizationEndpoints.includes(metadata.authorizationEndpoint.origin)) {
      authorizationEndpoints.push(metadata.authorizationEndpoint.origin);
    }
  }

  const hosts = [...candidates.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([host, evidence]) => ({ host, evidence }));
  if (hosts.length > DISCOVERY_LIMITS.maxHosts) {
    rejected.push(`more than ${DISCOVERY_LIMITS.maxHosts} OAuth hosts; kept the first ${DISCOVERY_LIMITS.maxHosts}`);
    hosts.length = DISCOVERY_LIMITS.maxHosts;
  }
  const keptHosts = new Set([...hosts.map((entry) => entry.host), ...projected]);
  return {
    contacted: session.contacted,
    hosts,
    endpoints: [...endpoints.values()]
      .filter((entry) => keptHosts.has(entry.host))
      .sort((left, right) => `${left.kind}\0${left.host}\0${left.path}`.localeCompare(`${right.kind}\0${right.host}\0${right.path}`)),
    covered: [...covered].sort(),
    rejected,
    authorizationEndpoints,
    oauthDetected: found.length > 0,
  };
}
