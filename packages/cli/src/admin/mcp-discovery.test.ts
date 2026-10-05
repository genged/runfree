import childProcess from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";

import {
  authorizationServerMetadataUrls,
  checkPolicyHostname,
  DISCOVERY_LIMITS,
  type DiscoveryDeps,
  type DiscoveryHttpResult,
  discoverMcpOAuthHosts,
  isPublicAddress,
  isRecordableEndpoint,
  pinnedHttpsGet,
  protectedResourceMetadataUrls,
} from "./mcp-discovery.ts";

type Route = DiscoveryHttpResult | Record<string, unknown>;

function json(value: Record<string, unknown>, contentType = "application/json"): DiscoveryHttpResult {
  return { kind: "response", status: 200, contentType, body: Buffer.from(JSON.stringify(value)) };
}

function status(code: number): DiscoveryHttpResult {
  return { kind: "response", status: code, contentType: "text/plain", body: Buffer.alloc(0) };
}

// A fake network: `routes` maps exact URLs to responses (unlisted URLs are
// 404), `addresses` maps hosts to resolved addresses (unlisted hosts get a
// public address).
function fakeNetwork(routes: Record<string, Route>, addresses: Record<string, string[]> = {}) {
  const requested: string[] = [];
  const resolved: string[] = [];
  const connectedTo: string[] = [];
  const deps: DiscoveryDeps = {
    resolve: async (host) => {
      resolved.push(host);
      return (addresses[host] ?? ["93.184.216.34"]).map((address) => ({ address, family: address.includes(":") ? 6 as const : 4 as const }));
    },
    request: async (url, targets) => {
      requested.push(url.href);
      connectedTo.push(`${url.hostname}@${targets.map((target) => target.address).join(",")}`);
      const route = routes[url.href];
      if (route === undefined) return status(404);
      if ("kind" in route && (route.kind === "response" || route.kind === "error")) return route as DiscoveryHttpResult;
      return json(route as Record<string, unknown>);
    },
  };
  return { deps, requested, resolved, connectedTo };
}

const ENDPOINT = "https://mcp.example.com/mcp";
const PRM_PATH = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
const PRM_ROOT = "https://mcp.example.com/.well-known/oauth-protected-resource";
const AS_META = "https://auth.example.com/.well-known/oauth-authorization-server";
const AS_OIDC = "https://auth.example.com/.well-known/openid-configuration";

function input(overrides: Partial<Parameters<typeof discoverMcpOAuthHosts>[0]> = {}) {
  return { endpointUrl: ENDPOINT, declaredMetadataUrls: [], declaredTokenHosts: [], ...overrides };
}

describe("hostname and address rules", () => {
  test("accepts exact hostnames and refuses IPs, wildcards, URLs, ports, and localhost", () => {
    expect(checkPolicyHostname("Auth.Example.com")).toEqual({ ok: true, host: "auth.example.com" });
    for (const bad of ["10.0.0.1", "1.2.3.4", "1.2.3.0x4", "a.0x7f", "::1", "[::1]", "*.example.com", "https://a.example.com", "a.example.com:8443", "localhost", "x.localhost", "example", "a.b.c.123", "", "gateway.runfree.internal", "runfree.internal"]) {
      expect(checkPolicyHostname(bad).ok, bad).toBe(false);
    }
  });

  test("refuses the reserved runfree.internal suffix with a named reason (SR4/A1)", () => {
    const checked = checkPolicyHostname("gateway.runfree.internal");
    expect(checked.ok).toBe(false);
    expect(checked.ok === false && checked.reason).toMatch(/reserved runfree\.internal suffix/);
  });

  test("only plainly public unicast addresses are eligible", () => {
    for (const good of ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"]) {
      expect(isPublicAddress(good), good).toBe(true);
    }
    for (const bad of [
      "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
      "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
      "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
      "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "::127.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::1",
      "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%en0", "fec0::1", "ff02::1", "2001:db8::1", "2001::1",
      "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2002:c0a8:0101::1", "3fff::1", "100::1", "not-an-ip", "",
    ]) {
      expect(isPublicAddress(bad), bad).toBe(false);
    }
  });

  test("builds the MCP and RFC 8414 / OpenID well-known URL orders", () => {
    expect(protectedResourceMetadataUrls(new URL(ENDPOINT))).toEqual([PRM_PATH, PRM_ROOT]);
    expect(protectedResourceMetadataUrls(new URL("https://mcp.example.com/"))).toEqual([PRM_ROOT]);
    expect(authorizationServerMetadataUrls(new URL("https://auth.example.com"))).toEqual([AS_META, AS_OIDC]);
    expect(authorizationServerMetadataUrls(new URL("https://auth.example.com/tenant1/"))).toEqual([
      "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://auth.example.com/.well-known/openid-configuration/tenant1",
      "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]);
  });
});

describe("discoverMcpOAuthHosts", () => {
  test("finds the issuer, its bound endpoints, and evidence", async () => {
    const net = fakeNetwork({
      [PRM_ROOT]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
      [AS_META]: {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://login.example.org/authorize",
        token_endpoint: "https://auth.example.com/token",
        registration_endpoint: "https://auth.example.com/register",
      },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.oauthDetected).toBe(true);
    expect(result.hosts.map((entry) => entry.host)).toEqual(["auth.example.com"]);
    const evidence = result.hosts[0]?.evidence.join("\n") ?? "";
    expect(evidence).toContain(`authorization server https://auth.example.com/ named by ${PRM_ROOT}`);
    expect(evidence).toContain("token_endpoint https://auth.example.com/token");
    expect(result.endpoints).toEqual([
      { kind: "metadata", host: "auth.example.com", path: "/.well-known/oauth-authorization-server" },
      { kind: "registration", host: "auth.example.com", path: "/register" },
      { kind: "token", host: "auth.example.com", path: "/token" },
    ]);
    // The browser-facing authorization endpoint is shown, never allowlisted.
    expect(result.authorizationEndpoints).toEqual(["https://login.example.org"]);
    expect(result.hosts.map((entry) => entry.host)).not.toContain("login.example.org");
    expect(net.requested).toEqual([PRM_PATH, PRM_ROOT, AS_META]);
  });

  test("an issuer whose token endpoint is outside the mediator binding set is not added", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
      [AS_META]: { issuer: "https://auth.example.com", token_endpoint: "https://tokens.attacker.example/token" },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.endpoints).toEqual([]);
    expect(result.rejected.join("\n")).toContain("tokens.attacker.example");
    expect(result.rejected.join("\n")).toContain("would not mediate");
  });

  test("a registration endpoint outside the binding set is dropped, the rest kept", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
      [AS_META]: {
        issuer: "https://auth.example.com",
        token_endpoint: "https://auth.example.com/token",
        registration_endpoint: "https://register.other.example/r",
      },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts.map((entry) => entry.host)).toEqual(["auth.example.com"]);
    expect(result.endpoints.map((entry) => entry.kind)).toEqual(["metadata", "token"]);
    expect(result.rejected.join("\n")).toContain("register.other.example");
  });

  test("an issuer without valid metadata is not added", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://victim-idp.example"] },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.oauthDetected).toBe(false);
    expect(result.rejected.join("\n")).toContain("https://victim-idp.example/: no valid authorization-server metadata");
  });

  test("endpoint-host and declared hosts are covered, not proposed; their endpoints are recorded", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://mcp.example.com"] },
      "https://mcp.example.com/.well-known/oauth-authorization-server": {
        issuer: "https://mcp.example.com/",
        token_endpoint: "https://mcp.example.com/token",
      },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.covered).toEqual(["mcp.example.com"]);
    expect(result.endpoints).toContainEqual({ kind: "token", host: "mcp.example.com", path: "/token" });
    expect(result.oauthDetected).toBe(true);
  });

  test("falls back to OpenID configuration when RFC 8414 metadata is absent", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
      [AS_OIDC]: { issuer: "https://auth.example.com", token_endpoint: "https://auth.example.com/oauth/token" },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(net.requested).toEqual([PRM_PATH, AS_META, AS_OIDC]);
    expect(result.endpoints).toContainEqual({ kind: "metadata", host: "auth.example.com", path: "/.well-known/openid-configuration" });
  });

  test("an issuer mismatch drops that metadata document", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
      [AS_META]: { issuer: "https://evil.example.net", token_endpoint: "https://auth.example.com/token" },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.rejected.join("\n")).toContain("issuer does not match https://auth.example.com/");
    expect(result.hosts).toEqual([]);
  });

  test("a token endpoint with a query string is refused", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
      [AS_META]: { issuer: "https://auth.example.com", token_endpoint: "https://auth.example.com/token?x=1" },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.rejected.join("\n")).toContain("token_endpoint is missing or is not an exact HTTPS URL");
  });

  test("protected-resource metadata for another resource is ignored", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: "https://other.example.com/mcp", authorization_servers: ["https://auth.example.com"] },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.rejected.join("\n")).toContain("resource does not name mcp.example.com");
  });

  test("an issuer on an IP literal, http, a port, or a wildcard is refused before any request to it", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: {
        resource: ENDPOINT,
        authorization_servers: ["https://10.0.0.5", "http://auth.example.com", "https://auth.example.com:8443", "https://*.example.com"],
      },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.rejected.filter((line) => line.includes("authorization_servers["))).toHaveLength(4);
    expect(net.requested).toEqual([PRM_PATH]);
  });

  test("a host that resolves to any non-public address is never contacted and not added", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
    }, { "auth.example.com": ["93.184.216.34", "10.0.0.7"] });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(net.requested.some((url) => url.includes("auth.example.com"))).toBe(false);
    expect(result.contacted.find((entry) => entry.url === AS_META)?.outcome).toContain("refused: resolves to a non-public or translated address");
    expect(result.hosts).toEqual([]);
  });

  test("the endpoint host resolving to loopback makes no request at all", async () => {
    const net = fakeNetwork({}, { "mcp.example.com": ["127.0.0.1"] });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(net.requested).toEqual([]);
    expect(net.resolved).toEqual(["mcp.example.com"]);
    expect(result.oauthDetected).toBe(false);
  });

  test("each host resolves once and every request goes only to its checked addresses", async () => {
    const net = fakeNetwork({
      [PRM_ROOT]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
    }, { "mcp.example.com": ["93.184.216.34", "93.184.216.35"], "auth.example.com": ["2606:4700:4700::1111"] });
    await discoverMcpOAuthHosts(input(), net.deps);
    expect(net.resolved).toEqual(["mcp.example.com", "auth.example.com"]);
    expect(new Set(net.connectedTo)).toEqual(new Set(["mcp.example.com@93.184.216.34,93.184.216.35", "auth.example.com@2606:4700:4700::1111"]));
  });

  test("redirects, wrong content types, non-JSON, and non-object bodies are failed sources", async () => {
    const net = fakeNetwork({
      [PRM_PATH]: { kind: "response", status: 302, contentType: "text/html", body: Buffer.alloc(0) },
      [PRM_ROOT]: json({ resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] }, "text/html"),
      "https://mcp.example.com/.well-known/oauth-authorization-server": { kind: "response", status: 200, contentType: "application/json", body: Buffer.from("[1]") },
      "https://mcp.example.com/.well-known/openid-configuration": { kind: "response", status: 200, contentType: "application/json; charset=utf-8", body: Buffer.from("{nope") },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    const outcomes = Object.fromEntries(result.contacted.map((entry) => [entry.url, entry.outcome]));
    expect(outcomes[PRM_PATH]).toBe("refused: redirect (302) not followed");
    expect(outcomes[PRM_ROOT]).toBe("refused: content type is not application/json");
    expect(outcomes["https://mcp.example.com/.well-known/oauth-authorization-server"]).toBe("refused: body is not a JSON object");
    expect(outcomes["https://mcp.example.com/.well-known/openid-configuration"]).toBe("refused: body is not valid JSON");
    expect(result.hosts).toEqual([]);
    expect(result.oauthDetected).toBe(false);
  });

  test("the legacy resource-origin fallback can detect OAuth but adds no off-host endpoint", async () => {
    const net = fakeNetwork({
      "https://mcp.example.com/.well-known/oauth-authorization-server": {
        issuer: "https://mcp.example.com",
        token_endpoint: "https://elsewhere.example.net/token",
      },
    });
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.endpoints).toEqual([]);
    expect(result.rejected.join("\n")).toContain("elsewhere.example.net");
  });

  test("a declared metadata URL binds its own host", async () => {
    const declared = "https://login.example.org/.well-known/oauth-authorization-server";
    const net = fakeNetwork({
      [declared]: { issuer: "https://login.example.org", token_endpoint: "https://login.example.org/token" },
    });
    const result = await discoverMcpOAuthHosts(input({ declaredMetadataUrls: [declared] }), net.deps);
    expect(result.hosts).toEqual([]);
    expect(result.covered).toEqual(["login.example.org"]);
    expect(result.endpoints).toContainEqual({ kind: "token", host: "login.example.org", path: "/token" });
    expect(result.oauthDetected).toBe(true);
  });

  test("a root-path or oversized endpoint is refused, so it can never open the whole host", async () => {
    for (const [token, registration] of [
      ["https://auth.example.com/", undefined],
      [`https://auth.example.com/${"t".repeat(1100)}`, undefined],
      ["https://auth.example.com/token", "https://auth.example.com/"],
    ] as const) {
      const net = fakeNetwork({
        [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] },
        [AS_META]: { issuer: "https://auth.example.com", token_endpoint: token, ...(registration ? { registration_endpoint: registration } : {}) },
      });
      const result = await discoverMcpOAuthHosts(input(), net.deps);
      expect(result.endpoints.some((entry) => entry.path === "/" || entry.path.length > 1024), token).toBe(false);
      if (registration) {
        expect(result.endpoints.map((entry) => entry.kind)).toEqual(["metadata", "token"]);
        expect(result.rejected.join("\n")).toContain("registration_endpoint is not an exact HTTPS URL");
      } else {
        expect(result.hosts).toEqual([]);
      }
    }
  });

  test("a declared metadata URL outside /.well-known is used but not recorded as a metadata endpoint", async () => {
    const declared = "https://login.example.org/oauth/metadata";
    const net = fakeNetwork({
      [declared]: { issuer: "https://login.example.org", token_endpoint: "https://login.example.org/token" },
    });
    const result = await discoverMcpOAuthHosts(input({ declaredMetadataUrls: [declared] }), net.deps);
    expect(result.endpoints).toEqual([{ kind: "token", host: "login.example.org", path: "/token" }]);
  });

  test("every endpoint discovery returns passes the record predicate", async () => {
    const net = fakeNetwork(Object.fromEntries([
      [PRM_PATH, { resource: ENDPOINT, authorization_servers: ["https://auth.example.com/tenant"] }],
      ["https://auth.example.com/tenant/.well-known/openid-configuration", {
        issuer: "https://auth.example.com/tenant",
        token_endpoint: "https://auth.example.com/tenant/oauth2/v2.0/token",
        registration_endpoint: "https://auth.example.com/tenant/register",
      }],
    ]));
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.endpoints.length).toBe(3);
    for (const entry of result.endpoints) expect(isRecordableEndpoint(entry.kind, entry.host, entry.path), entry.path).toBe(true);
  });

  test("a declared metadata URL with a port or query is not fetched", async () => {
    const net = fakeNetwork({});
    const result = await discoverMcpOAuthHosts(input({ declaredMetadataUrls: ["https://login.example.org:444/.well-known/x", "https://login.example.org/m?x=1"] }), net.deps);
    expect(net.requested.some((url) => url.includes("login.example.org"))).toBe(false);
    expect(result.rejected.filter((line) => line.includes("declared authServerMetadataUrl"))).toHaveLength(2);
  });

  test("request count and issuer count are bounded", async () => {
    const issuers = Array.from({ length: 8 }, (_, index) => `https://as${index}.example.com`);
    const routes: Record<string, Route> = { [PRM_PATH]: { resource: ENDPOINT, authorization_servers: issuers } };
    for (const issuer of issuers) {
      routes[`${issuer}/.well-known/oauth-authorization-server`] = { issuer, token_endpoint: `${issuer}/token` };
    }
    const net = fakeNetwork(routes);
    const result = await discoverMcpOAuthHosts(input(), net.deps);
    expect(result.hosts).toHaveLength(DISCOVERY_LIMITS.maxIssuers);
    expect(net.requested.length).toBeLessThanOrEqual(DISCOVERY_LIMITS.maxRequests);
    expect(result.rejected.join("\n")).toContain(`more than ${DISCOVERY_LIMITS.maxIssuers} authorization servers`);
  });

  test("the total time budget stops further requests", async () => {
    let clock = 0;
    const net = fakeNetwork({ [PRM_PATH]: { resource: ENDPOINT, authorization_servers: ["https://auth.example.com"] } });
    const request = net.deps.request as NonNullable<DiscoveryDeps["request"]>;
    const result = await discoverMcpOAuthHosts(input(), {
      ...net.deps,
      now: () => clock,
      request: async (...args) => {
        clock += DISCOVERY_LIMITS.totalBudgetMs;
        return request(...args);
      },
    });
    expect(net.requested).toEqual([PRM_PATH]);
    expect(result.contacted.some((entry) => entry.outcome === "skipped: discovery time budget used up")).toBe(true);
  });

  test("an endpoint that is not HTTPS on a policy hostname is refused before any lookup", async () => {
    const net = fakeNetwork({});
    await expect(discoverMcpOAuthHosts(input({ endpointUrl: "http://mcp.example.com/mcp" }), net.deps)).rejects.toThrow("HTTPS");
    await expect(discoverMcpOAuthHosts(input({ endpointUrl: "https://127.0.0.1/mcp" }), net.deps)).rejects.toThrow("HTTPS");
    expect(net.resolved).toEqual([]);
  });
});

describe("pinnedHttpsGet against a local TLS server", () => {
  const HOST = "mcp.discovery.invalid";
  let dir: string;
  let cert: string;
  let server: https.Server;
  let port: number;
  let lastPath = "";
  let lastHeaders: Record<string, unknown> = {};

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-discovery-"));
    const certPath = path.join(dir, "server.crt");
    const keyPath = path.join(dir, "server.key");
    childProcess.execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", keyPath, "-out", certPath, "-subj", `/CN=${HOST}`, "-days", "1",
      "-addext", `subjectAltName=DNS:${HOST}`,
    ], { stdio: "ignore" });
    cert = fs.readFileSync(certPath, "utf8");
    server = https.createServer({ cert, key: fs.readFileSync(keyPath, "utf8") }, (req, res) => {
      lastPath = req.url ?? "";
      lastHeaders = req.headers;
      if (req.url === "/json") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      } else if (req.url === "/chunked") {
        res.writeHead(200, { "content-type": "application/json" });
        res.write('{"part":');
        res.end("1}");
      } else if (req.url === "/gzip") {
        res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
        res.end("xx");
      } else if (req.url === "/redirect") {
        res.writeHead(302, { location: "https://127.0.0.1/json" });
        res.end();
      } else if (req.url === "/big") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(Buffer.alloc(DISCOVERY_LIMITS.maxBodyBytes + 10, 0x20));
      } else if (req.url === "/big-chunked") {
        res.writeHead(200, { "content-type": "application/json" });
        for (let index = 0; index < 20; index += 1) res.write(Buffer.alloc(8 * 1024, 0x20));
        res.end();
      } else if (req.url === "/slow") {
        setTimeout(() => res.end("{}"), 2_000);
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const target = { address: "127.0.0.1", family: 4 as const };
  const get = (pathName: string, extra: { testCa?: string; timeoutMs?: number; targets?: Array<{ address: string; family: 4 | 6 }> } = {}) =>
    pinnedHttpsGet(new URL(`https://${HOST}${pathName}`), extra.targets ?? [target], {
      timeoutMs: extra.timeoutMs ?? 3_000,
      maxBodyBytes: DISCOVERY_LIMITS.maxBodyBytes,
      testPort: port,
      ...("testCa" in extra ? { testCa: extra.testCa } : { testCa: cert }),
    });

  test("connects to the checked address with SNI and fixed headers only (the name does not resolve)", async () => {
    const result = await get("/json");
    expect(result).toMatchObject({ kind: "response", status: 200, contentType: "application/json" });
    expect(result.kind === "response" && JSON.parse(result.body.toString("utf8"))).toEqual({ ok: true });
    expect(lastPath).toBe("/json");
    expect(lastHeaders.host).toBe(HOST);
    expect(lastHeaders.authorization).toBeUndefined();
    expect(lastHeaders.cookie).toBeUndefined();
    expect(lastHeaders["accept-encoding"]).toBe("identity");
    expect(lastHeaders["user-agent"]).toBe("runfree-mcp-discovery");
  });

  test("decodes a chunked body", async () => {
    const result = await get("/chunked");
    expect(result.kind === "response" && JSON.parse(result.body.toString("utf8"))).toEqual({ part: 1 });
  });

  test("refuses compressed responses", async () => {
    expect(await get("/gzip")).toEqual({ kind: "error", reason: "compressed responses are not accepted" });
  });

  test("does not follow redirects", async () => {
    expect(await get("/redirect")).toMatchObject({ kind: "response", status: 302 });
  });

  test("refuses a body over the cap, with or without a length", async () => {
    const reason = `response larger than ${DISCOVERY_LIMITS.maxBodyBytes} bytes`;
    expect(await get("/big")).toEqual({ kind: "error", reason });
    expect(await get("/big-chunked")).toEqual({ kind: "error", reason });
  });

  test("times out a slow response on an absolute deadline", async () => {
    expect(await get("/slow", { timeoutMs: 200 })).toEqual({ kind: "error", reason: "timed out after 200 ms" });
  });

  test("tries the next checked address only when the connect fails", async () => {
    // The server listens on 127.0.0.1 only, so ::1 on the same port is
    // refused at connect on every host. (127.0.0.2 is not portable: macOS
    // does not answer it, so the connect hangs until the deadline.)
    const refused = { address: "::1", family: 6 as const };
    let accepted = 0;
    const onConnection = () => {
      accepted += 1;
    };
    server.on("connection", onConnection);
    try {
      expect(await get("/json", { targets: [refused, target] })).toMatchObject({ kind: "response", status: 200 });
      expect(accepted).toBe(1);
      // A TLS failure after the TCP connect is the answer: the second
      // address is never tried.
      accepted = 0;
      const result = await pinnedHttpsGet(new URL("https://other.discovery.invalid/json"), [target, target], {
        timeoutMs: 3_000,
        maxBodyBytes: DISCOVERY_LIMITS.maxBodyBytes,
        testPort: port,
        testCa: cert,
      });
      expect(result).toEqual({ kind: "error", reason: "request failed (ERR_TLS_CERT_ALTNAME_INVALID)" });
      expect(accepted).toBe(1);
    } finally {
      server.off("connection", onConnection);
    }
  });

  test("verifies the certificate against the URL hostname, not the connected IP", async () => {
    const result = await pinnedHttpsGet(new URL("https://other.discovery.invalid/json"), [target], {
      timeoutMs: 3_000,
      maxBodyBytes: DISCOVERY_LIMITS.maxBodyBytes,
      testPort: port,
      testCa: cert,
    });
    expect(result).toEqual({ kind: "error", reason: "request failed (ERR_TLS_CERT_ALTNAME_INVALID)" });
  });

  test("verifies the certificate even when NODE_TLS_REJECT_UNAUTHORIZED=0", async () => {
    vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
    try {
      const result = await get("/json", { testCa: undefined });
      expect(result.kind).toBe("error");
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe("pinnedHttpsGet parses HTTP/1.1 strictly", () => {
  const HOST = "raw.discovery.invalid";
  let dir: string;
  let cert: string;
  let server: tls.Server;
  let port: number;
  const RESPONSES: Record<string, string> = {
    "/bad-chunk": "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n",
    "/bad-header": "HTTP/1.1 200 OK\r\ncontent-type : application/json\r\ncontent-length: 2\r\n\r\n{}",
    "/cl-and-te": "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    "/two-lengths": "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\ncontent-length: 3\r\n\r\n{} ",
    "/huge-head": `HTTP/1.1 200 OK\r\nx-pad: ${"a".repeat(DISCOVERY_LIMITS.maxHeaderBytes)}\r\n\r\n`,
    "/http2": "HTTP/2 200\r\n\r\n",
  };

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-discovery-raw-"));
    childProcess.execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", path.join(dir, "k"), "-out", path.join(dir, "c"), "-subj", `/CN=${HOST}`, "-days", "1",
      "-addext", `subjectAltName=DNS:${HOST}`,
    ], { stdio: "ignore" });
    cert = fs.readFileSync(path.join(dir, "c"), "utf8");
    server = tls.createServer({ cert, key: fs.readFileSync(path.join(dir, "k"), "utf8") }, (socket) => {
      socket.once("data", (data: Buffer) => {
        const requestPath = /^GET (\S+) HTTP\/1\.1\r\n/.exec(data.toString("latin1"))?.[1] ?? "";
        socket.end(RESPONSES[requestPath] ?? "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
      });
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const get = (pathName: string) => pinnedHttpsGet(new URL(`https://${HOST}${pathName}`), [{ address: "127.0.0.1", family: 4 }], {
    timeoutMs: 3_000,
    maxBodyBytes: DISCOVERY_LIMITS.maxBodyBytes,
    testCa: cert,
    testPort: port,
  });

  test.each([
    ["/bad-chunk", "malformed chunked body"],
    ["/bad-header", "malformed HTTP header"],
    ["/cl-and-te", "malformed content length"],
    ["/two-lengths", "conflicting content-length headers"],
    ["/huge-head", "response headers too large"],
    ["/http2", "malformed HTTP status line"],
  ])("%s is refused: %s", async (pathName, reason) => {
    expect(await get(pathName)).toEqual({ kind: "error", reason });
  });
});
