// oauth-grant-shape.ts — request-side detection of unmediated OAuth grant and
// client-registration requests.
//
// The proxy never reads replies on hosts that only MCP enable records allow
// (record-only hosts): mockttp buffers a whole response for any rule with a
// response callback, which would break streaming. So the control on those
// hosts is request-side: a request that looks like an OAuth grant or a client
// registration is refused before any upstream connection, so the issuer never
// mints tokens or consumes the code for an exchange the proxy does not
// mediate.
//
// The agent holds the authorization code and the PKCE verifier, so it chooses
// the request shape. This detector covers the standard shapes, in any method
// and any content type. A non-standard shape that an issuer still accepts (a
// renamed field, a grant hidden in a path segment) is a documented residual.
//
// Two scopes, and an independent fail-closed switch:
// - "deep": JSON is scanned at every depth, and the body is also read as a
//   form whatever its content type.
// - "top-level" (a record names the host, but it also serves an MCP
//   endpoint): only top-level keys are matched (each element's top-level keys
//   for a top-level array), so MCP JSON-RPC, whose `code` sits under `error`
//   and whose arguments sit under `params`, is never refused by a deep scan.
// - `failClosed` (record-only hosts, blocked endpoints, colliding
//   endpoints): a body the proxy cannot read is itself a finding: multipart,
//   an encoding, charset, or JSON body it cannot decode, a body without
//   Content-Length, and a wire or decoded body over 16 KiB. Without it an
//   unreadable or oversized body passes, and only its query is matched.

import zlib from "node:zlib";

import { isRecord } from "@runfree/runtime-contracts/primitives";
import { MCP_BODY_CAP_BYTES } from "./mcp-classify.js";

// The fail-closed cap for deep scope, on the wire body and on the decoded
// body alike, so a small compressed body cannot expand without limit.
export const UNMEDIATED_GRANT_BODY_CAP_BYTES = 16 * 1024;
// Without fail-closed rules (endpoint hosts carry MCP bodies, which the proxy
// already reads up to this size) a larger body is not scanned and passes.
const LENIENT_BODY_CAP_BYTES = MCP_BODY_CAP_BYTES;

export type GrantShapeScope = "deep" | "top-level";

// The field a grant-shaped finding names: a closed set, never request data.
export type GrantField = "code" | "grant_type" | "redirect_uris" | "refresh_token";

export type GrantShapeFinding =
  | { kind: "grant-shaped"; field: GrantField }
  | { kind: "multipart" }
  | { kind: "undecodable" }
  | { kind: "missing-length" }
  | { kind: "oversize" };

type HeaderValue = string | string[] | undefined;

export type GrantShapeInput = {
  // The raw request body as it travels upstream (content-encoded), or
  // undefined when the request carries none.
  body: Buffer | undefined;
  failClosed: boolean;
  headers: Record<string, HeaderValue> | undefined;
  scope: GrantShapeScope;
  url: URL;
};

function headerValues(headers: Record<string, HeaderValue> | undefined, name: string): string[] {
  const values: string[] = [];
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() !== name) continue;
    if (Array.isArray(value)) values.push(...value);
    else if (value !== undefined) values.push(value);
  }
  return values;
}

// Field names compare case-insensitively and without a PHP-style array
// suffix (`redirect_uris[]`, `redirect_uris[0]`): an issuer that accepts
// either spelling must not get it past the check.
function fieldName(raw: string): string {
  return raw.toLowerCase().replace(/\[[^\]]*\]$/, "");
}

const SINGLE_GRANT_FIELDS = ["grant_type", "refresh_token", "redirect_uris"] as const;

function grantField(fields: ReadonlySet<string>): GrantField | undefined {
  for (const field of SINGLE_GRANT_FIELDS) {
    if (fields.has(field)) return field;
  }
  // An authorization-code exchange needs both; `code` alone is too common
  // (JSON-RPC errors, application payloads) to refuse on.
  if (fields.has("code") && fields.has("code_verifier")) return "code";
  return undefined;
}

function addFormFields(fields: Set<string>, text: string): void {
  for (const key of new URLSearchParams(text).keys()) fields.add(fieldName(key));
}

// Every object key at every depth, iteratively so a deeply nested body
// cannot exhaust the stack.
function addJsonFieldsDeep(fields: Set<string>, value: unknown): void {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (Array.isArray(current)) {
      stack.push(...current);
    } else if (isRecord(current)) {
      for (const [key, entry] of Object.entries(current)) {
        fields.add(fieldName(key));
        stack.push(entry);
      }
    }
  }
}

function addJsonFieldsTopLevel(fields: Set<string>, value: unknown): void {
  for (const entry of Array.isArray(value) ? value : [value]) {
    if (!isRecord(entry)) continue;
    for (const key of Object.keys(entry)) fields.add(fieldName(key));
  }
}

function parseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

type DecodedBody = { ok: true; bytes: Buffer } | { ok: false; reason: "oversize" | "undecodable" };

// Decodes the body with the output bounded, never trusting mockttp's own
// unbounded decoder: a gzip bomb stops at the cap instead of in memory.
function decodeBody(raw: Buffer, encodings: string[], cap: number): DecodedBody {
  const tokens = encodings
    .flatMap((value) => value.split(","))
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token !== "" && token !== "identity");
  if (tokens.length === 0) return raw.length > cap ? { ok: false, reason: "oversize" } : { ok: true, bytes: raw };
  // One coding only: a stacked coding is legal but no OAuth client sends one.
  if (tokens.length > 1) return { ok: false, reason: "undecodable" };
  const options = { maxOutputLength: cap + 1 };
  let bytes: Buffer;
  try {
    switch (tokens[0]) {
      case "gzip":
      case "x-gzip":
        bytes = zlib.gunzipSync(raw, options);
        break;
      case "deflate":
        // HTTP "deflate" is zlib-wrapped, but raw deflate is common in practice.
        try {
          bytes = zlib.inflateSync(raw, options);
        } catch (error) {
          if (error instanceof RangeError) throw error;
          bytes = zlib.inflateRawSync(raw, options);
        }
        break;
      case "br":
        bytes = zlib.brotliDecompressSync(raw, options);
        break;
      default:
        return { ok: false, reason: "undecodable" };
    }
  } catch (error) {
    return { ok: false, reason: error instanceof RangeError ? "oversize" : "undecodable" };
  }
  return bytes.length > cap ? { ok: false, reason: "oversize" } : { ok: true, bytes };
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

function decodeText(bytes: Buffer): string | undefined {
  try {
    return UTF8.decode(bytes);
  } catch {
    return undefined;
  }
}

function declaredContentLength(headers: Record<string, HeaderValue> | undefined): "absent" | "invalid" | number {
  const values = headerValues(headers, "content-length");
  if (values.length === 0) return "absent";
  const distinct = new Set(values.map((value) => value.trim()));
  if (distinct.size !== 1) return "invalid";
  const [value] = distinct;
  return /^\d{1,12}$/.test(value) ? Number(value) : "invalid";
}

/**
 * The finding for one request, or undefined when it may pass. The query is
 * always scanned; the body is scanned when it can be read. In deep scope a
 * body that cannot be read is itself a finding.
 */
export function classifyGrantShape(input: GrantShapeInput): GrantShapeFinding | undefined {
  const deep = input.scope === "deep";
  const failClosed = input.failClosed;
  const cap = failClosed ? UNMEDIATED_GRANT_BODY_CAP_BYTES : LENIENT_BODY_CAP_BYTES;
  const fields = new Set<string>();
  for (const key of input.url.searchParams.keys()) fields.add(fieldName(key));
  const queryOnly = grantField(fields);

  const raw = input.body ?? Buffer.alloc(0);
  const transferEncoded = headerValues(input.headers, "transfer-encoding").length > 0;
  const hasBody = raw.length > 0 || transferEncoded;
  if (!hasBody) return queryOnly !== undefined ? { kind: "grant-shaped", field: queryOnly } : undefined;

  const contentType = headerValues(input.headers, "content-type").join(",").toLowerCase();
  const contentLength = declaredContentLength(input.headers);
  // A query grant is reported before any body rule: it names the field.
  if (queryOnly !== undefined) return { kind: "grant-shaped", field: queryOnly };
  if (failClosed) {
    if (contentType.includes("multipart/")) return { kind: "multipart" };
    // R14: a body must declare its length (HTTP/1.1 chunked and HTTP/2
    // bodies without one alike), and the declaration must be usable.
    if (contentLength === "absent") return { kind: "missing-length" };
    if (contentLength === "invalid") return { kind: "undecodable" };
    if (contentLength > cap || raw.length > cap) return { kind: "oversize" };
  } else if (raw.length > cap) {
    return undefined;
  }

  const decoded = decodeBody(raw, headerValues(input.headers, "content-encoding"), cap);
  const text = decoded.ok ? decodeText(decoded.bytes) : undefined;
  if (text === undefined) {
    if (!failClosed) return undefined;
    return decoded.ok ? { kind: "undecodable" } : { kind: decoded.reason };
  }

  const json = parseJson(text.trim());
  if (deep) {
    if (json.ok) addJsonFieldsDeep(fields, json.value);
    else if (failClosed && contentType.includes("json")) return { kind: "undecodable" };
    // Also read as a form whatever the content type: an issuer that parses
    // forms would find a grant smuggled inside JSON string text.
    addFormFields(fields, text);
  } else if (json.ok) {
    addJsonFieldsTopLevel(fields, json.value);
  } else {
    addFormFields(fields, text);
  }
  const field = grantField(fields);
  return field !== undefined ? { kind: "grant-shaped", field } : undefined;
}

// The sensitive fields of an OAuth token or registration response.
const SENSITIVE_RESPONSE_FIELDS = new Set([
  "access_token",
  "refresh_token",
  "id_token",
  "client_secret",
  "registration_access_token",
]);

/**
 * True when a response body carries a real OAuth secret anywhere: a JSON
 * value of any shape (a top-level array, a nested object) with a non-empty
 * string under a sensitive key at any depth, or a form body with such a key.
 */
export function responseCarriesOAuthSecret(text: string): boolean {
  const json = parseJson(text.trim());
  if (json.ok) {
    const stack: unknown[] = [json.value];
    while (stack.length > 0) {
      const current = stack.pop();
      if (Array.isArray(current)) {
        stack.push(...current);
      } else if (isRecord(current)) {
        for (const [key, entry] of Object.entries(current)) {
          if (SENSITIVE_RESPONSE_FIELDS.has(key.toLowerCase()) && typeof entry === "string" && entry !== "") return true;
          stack.push(entry);
        }
      }
    }
    return false;
  }
  for (const [key, value] of new URLSearchParams(text.trim())) {
    if (SENSITIVE_RESPONSE_FIELDS.has(fieldName(key)) && value !== "") return true;
  }
  return false;
}
