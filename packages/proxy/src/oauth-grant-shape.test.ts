import zlib from "node:zlib";
import { describe, expect, test } from "vitest";

import { classifyGrantShape, responseCarriesOAuthSecret, UNMEDIATED_GRANT_BODY_CAP_BYTES, type GrantShapeScope } from "./oauth-grant-shape.ts";

const URL_BASE = "https://ahrefs.com/oauth/token";

function classify(options: {
  body?: Buffer | string;
  contentType?: string;
  encoding?: string;
  failClosed?: boolean;
  headers?: Record<string, string>;
  length?: "auto" | "none" | string;
  scope?: GrantShapeScope;
  url?: string;
}) {
  const body = options.body === undefined ? undefined : Buffer.isBuffer(options.body) ? options.body : Buffer.from(options.body, "utf8");
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.contentType !== undefined) headers["content-type"] = options.contentType;
  if (options.encoding !== undefined) headers["content-encoding"] = options.encoding;
  const length = options.length ?? "auto";
  if (length === "auto" && body !== undefined) headers["content-length"] = String(body.length);
  else if (length !== "auto" && length !== "none") headers["content-length"] = length;
  return classifyGrantShape({
    body,
    failClosed: options.failClosed ?? true,
    headers,
    scope: options.scope ?? "deep",
    url: new URL(options.url ?? URL_BASE),
  });
}

const FORM = "application/x-www-form-urlencoded";

describe("classifyGrantShape: grant and registration shapes", () => {
  test.each([
    ["a form grant", { body: "grant_type=authorization_code&code=c&code_verifier=v", contentType: FORM }, "grant_type"],
    ["a JSON grant", { body: JSON.stringify({ grant_type: "authorization_code" }), contentType: "application/json" }, "grant_type"],
    ["a JSON grant under text/plain", { body: JSON.stringify({ grant_type: "refresh_token" }), contentType: "text/plain" }, "grant_type"],
    ["a form grant with no content type", { body: "grant_type=refresh_token&refresh_token=r" }, "grant_type"],
    ["a top-level JSON array", { body: JSON.stringify([{ ok: 1 }, { grant_type: "x" }]), contentType: "application/json" }, "grant_type"],
    ["a nested JSON grant", { body: JSON.stringify({ wrapper: { inner: [{ refresh_token: "r" }] } }), contentType: "application/json" }, "refresh_token"],
    ["a registration", { body: JSON.stringify({ client_name: "x", redirect_uris: ["http://127.0.0.1/cb"] }), contentType: "application/json" }, "redirect_uris"],
    ["a refresh without grant_type", { body: "refresh_token=r", contentType: FORM }, "refresh_token"],
    ["code with code_verifier", { body: "code=c&code_verifier=v", contentType: FORM }, "code"],
    ["code with code_verifier across query and body", { url: `${URL_BASE}?code=c`, body: "code_verifier=v", contentType: FORM }, "code"],
    ["an upper-case field", { body: "GRANT_TYPE=x", contentType: FORM }, "grant_type"],
    ["a bracketed array field", { body: "redirect_uris[]=http%3A%2F%2Fx", contentType: FORM }, "redirect_uris"],
    ["a percent-encoded field name", { body: "grant%5Ftype=x", contentType: FORM }, "grant_type"],
    ["a form grant smuggled inside JSON text", { body: JSON.stringify({ q: "a&grant_type=authorization_code&x=" }), contentType: "application/json" }, "grant_type"],
    ["a JSON body with a byte-order mark", { body: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"grant_type":"x"}')]), contentType: "application/json" }, "grant_type"],
  ] as const)("refuses %s", (_label, options, field) => {
    expect(classify(options)).toEqual({ kind: "grant-shaped", field });
  });

  test.each([
    ["a GET with a query grant", `${URL_BASE}?grant_type=authorization_code&code=c`],
    ["a percent-decoded query grant", `${URL_BASE}?grant%5Ftype=x`],
    ["a query registration", `${URL_BASE}?redirect_uris=x`],
  ])("refuses %s with no body", (_label, url) => {
    expect(classify({ url })).toMatchObject({ kind: "grant-shaped" });
  });

  test.each([
    ["a gzip body", "gzip", zlib.gzipSync],
    ["an x-gzip body", "x-gzip", zlib.gzipSync],
    ["a zlib deflate body", "deflate", zlib.deflateSync],
    ["a raw deflate body", "deflate", zlib.deflateRawSync],
    ["a brotli body", "br", zlib.brotliCompressSync],
  ] as const)("decodes %s and refuses its grant", (_label, encoding, compress) => {
    const body = compress(Buffer.from("grant_type=authorization_code&code=c"));
    expect(classify({ body, encoding, contentType: FORM })).toEqual({ kind: "grant-shaped", field: "grant_type" });
  });

  test.each([
    ["a plain JSON payload", { body: JSON.stringify({ query: "x", page: 2 }), contentType: "application/json" }],
    ["code alone", { body: "code=c&state=s", contentType: FORM }],
    ["code and code_verifier as values, not fields", { body: "q=code&r=code_verifier", contentType: FORM }],
    ["a JSON-RPC error with a code", { body: JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32600, message: "x" } }), contentType: "application/json" }],
    ["an empty body", { body: "", contentType: FORM }],
    ["a GET with no body or query", {}],
  ])("passes %s", (_label, options) => {
    expect(classify(options)).toBeUndefined();
  });
});

describe("classifyGrantShape: fail-closed rules", () => {
  test.each([
    ["multipart/form-data", { body: "--b\r\n\r\n--b--", contentType: "multipart/form-data; boundary=b" }, "multipart"],
    ["multipart/mixed", { body: "--b\r\n\r\n--b--", contentType: "multipart/mixed; boundary=b" }, "multipart"],
    ["a body without Content-Length", { body: "hello", length: "none" }, "missing-length"],
    ["a chunked request with no body bytes", { headers: { "transfer-encoding": "chunked" }, length: "none" }, "missing-length"],
    ["a non-numeric Content-Length", { body: "hello", length: "five" }, "undecodable"],
    ["a wire body over 16 KiB", { body: `a=${"x".repeat(UNMEDIATED_GRANT_BODY_CAP_BYTES)}`, contentType: FORM }, "oversize"],
    ["a declared length over 16 KiB", { body: "a=b", length: String(UNMEDIATED_GRANT_BODY_CAP_BYTES + 1) }, "oversize"],
    ["invalid UTF-8", { body: Buffer.from([0x61, 0x3d, 0xff, 0xfe]), contentType: FORM }, "undecodable"],
    ["an unknown content encoding", { body: "grant_type=x", encoding: "zstd" }, "undecodable"],
    ["a stacked content encoding", { body: zlib.gzipSync(zlib.gzipSync("grant_type=x")), encoding: "gzip, gzip" }, "undecodable"],
    ["a gzip body that is not gzip", { body: "grant_type=x", encoding: "gzip" }, "undecodable"],
    ["malformed JSON declared as JSON", { body: "{\"grant_type\":", contentType: "application/json" }, "undecodable"],
  ] as const)("refuses %s", (_label, options, kind) => {
    expect(classify(options)).toEqual({ kind });
  });

  test("refuses a small gzip body that expands past 16 KiB without decoding it all", () => {
    const bomb = zlib.gzipSync(Buffer.alloc(8 * 1024 * 1024, 0x61));
    expect(bomb.length).toBeLessThan(UNMEDIATED_GRANT_BODY_CAP_BYTES);
    expect(classify({ body: bomb, encoding: "gzip", contentType: FORM })).toEqual({ kind: "oversize" });
  });

  test("a query grant is named before a body rule applies", () => {
    expect(classify({ url: `${URL_BASE}?grant_type=x`, body: "--b--", contentType: "multipart/form-data; boundary=b" }))
      .toEqual({ kind: "grant-shaped", field: "grant_type" });
  });

  test("without failClosed an unreadable or oversized body passes, but a readable grant does not", () => {
    for (const options of [
      { body: "--b\r\n\r\n--b--", contentType: "multipart/form-data; boundary=b" },
      { body: "hello", length: "none" as const },
      { body: Buffer.from([0xff, 0xfe]) },
      { body: zlib.gzipSync(Buffer.alloc(8 * 1024 * 1024, 0x61)), encoding: "gzip" },
    ]) {
      expect(classify({ ...options, failClosed: false })).toBeUndefined();
    }
    expect(classify({ body: JSON.stringify({ deep: { grant_type: "x" } }), contentType: "application/json", failClosed: false }))
      .toEqual({ kind: "grant-shaped", field: "grant_type" });
  });
});

describe("classifyGrantShape: top-level scope (hosts that also serve an MCP endpoint)", () => {
  const topLevel = (options: Parameters<typeof classify>[0]) => classify({ ...options, scope: "top-level", failClosed: false });

  test.each([
    ["a top-level JSON grant", { body: JSON.stringify({ grant_type: "authorization_code" }), contentType: "application/json" }],
    ["a top-level form grant", { body: "grant_type=authorization_code", contentType: FORM }],
    ["a grant in a top-level array element", { body: JSON.stringify([{ jsonrpc: "2.0" }, { refresh_token: "r" }]), contentType: "application/json" }],
    ["a query grant", { url: `${URL_BASE}?grant_type=x` }],
  ])("refuses %s", (_label, options) => {
    expect(topLevel(options)).toMatchObject({ kind: "grant-shaped" });
  });

  test.each([
    ["JSON-RPC arguments that carry grant fields", {
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { arguments: { grant_type: "x", refresh_token: "r", code: "c", code_verifier: "v" } } }),
      contentType: "application/json",
    }],
    ["a JSON-RPC error code", { body: JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: 1 } }), contentType: "application/json" }],
    ["a JSON string that embeds a form grant", { body: JSON.stringify({ jsonrpc: "2.0", params: { q: "&grant_type=x" } }), contentType: "application/json" }],
    ["a large MCP body", { body: JSON.stringify({ jsonrpc: "2.0", params: { blob: "x".repeat(100 * 1024) } }), contentType: "application/json" }],
    ["a body without Content-Length", { body: JSON.stringify({ jsonrpc: "2.0" }), length: "none" as const }],
    ["multipart", { body: "--b--", contentType: "multipart/form-data; boundary=b" }],
  ])("passes %s", (_label, options) => {
    expect(topLevel(options)).toBeUndefined();
  });
});

describe("responseCarriesOAuthSecret", () => {
  test.each([
    ["a flat token response", { access_token: "real" }],
    ["a nested token", { data: { tokens: { refresh_token: "real" } } }],
    ["a top-level array", [{ ok: true }, { id_token: "real" }]],
    ["a registration secret", { client_id: "c", client_secret: "real" }],
    ["a registration access token", { registration_access_token: "real" }],
  ])("detects %s", (_label, value) => {
    expect(responseCarriesOAuthSecret(JSON.stringify(value))).toBe(true);
  });

  test("detects a form-encoded token response", () => {
    expect(responseCarriesOAuthSecret("access_token=real&token_type=bearer")).toBe(true);
  });

  test.each([
    ["an error", JSON.stringify({ error: "invalid_grant" })],
    ["an empty token", JSON.stringify({ access_token: "" })],
    ["a non-string token", JSON.stringify({ access_token: 1 })],
    ["metadata", JSON.stringify({ issuer: "https://x", token_endpoint: "https://x/token" })],
    ["plain text", "hello world"],
    ["an empty body", ""],
  ])("passes %s", (_label, text) => {
    expect(responseCarriesOAuthSecret(text)).toBe(false);
  });
});
