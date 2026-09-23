import { describe, expect, test } from "vitest";

import {
  createDenialEventEmitter,
  displayHostname,
  displayMethod,
  safePathname,
  syntheticDenialBody,
  UNPARSEABLE_HOST,
} from "./denial.ts";

const GENERATION_A = `sha256:${"a".repeat(64)}`;
const GENERATION_B = `sha256:${"b".repeat(64)}`;

function parseEventLine(line: string): Record<string, unknown> {
  expect(line.startsWith("proxy-denial: ")).toBe(true);
  return JSON.parse(line.slice("proxy-denial: ".length)) as Record<string, unknown>;
}

describe("denial display helpers", () => {
  test("re-normalizes hostnames and never echoes unparseable values", () => {
    expect(displayHostname("API.Example.com")).toBe("api.example.com");
    expect(displayHostname("evil_host.example.")).toBe(UNPARSEABLE_HOST);
    expect(displayHostname("bad\x1b[31mhost")).toBe(UNPARSEABLE_HOST);
    expect(displayHostname("")).toBe(UNPARSEABLE_HOST);
  });

  test("safePathname keeps the pathname only and truncates", () => {
    expect(safePathname("https://api.example.com/v1/data?api_key=secret#frag")).toBe("/v1/data");
    expect(safePathname("/v1/data?api_key=secret")).toBe("/v1/data");
    expect(safePathname(undefined)).toBeUndefined();
    const long = `/${"a".repeat(500)}`;
    expect(safePathname(long)).toHaveLength(256);
  });

  test("synthetic body names the normalized host and the host-side host add command", () => {
    const body = syntheticDenialBody("API.EXAMPLE.COM", "host-not-allowlisted");
    expect(body).toContain("Runfree blocked this request.");
    expect(body).toContain("host:   api.example.com");
    expect(body).toContain("host is not in the project network allowlist");
    expect(body).toContain("runfree host add api.example.com");
    expect(body).toContain("the person operating Runfree can run");
    expect(body).toContain("Policy reloads automatically; rerun the failed command afterwards.");
  });

  test("synthetic body for an unparseable host has no raw echo and no host add command", () => {
    const raw = "ev\x1b[31mil_host..";
    const body = syntheticDenialBody(raw, "host-not-allowlisted");
    expect(body).toContain(`host:   ${UNPARSEABLE_HOST}`);
    expect(body).not.toContain("ev\x1b[31mil_host");
    expect(body).not.toContain("runfree host add ");
    expect(body).toContain("runfree doctor");
  });

  test("method denial body names the dimension and the exact widening command", () => {
    const body = syntheticDenialBody("api.github.com", "method-not-allowed", {
      method: "POST",
      path: "/repos/owner/repo/issues?token=query-secret",
      allowedMethods: ["GET", "HEAD", "OPTIONS"],
    });
    expect(body).toContain("Runfree blocked this request.");
    expect(body).toContain("host:   api.github.com");
    expect(body).toContain("method: POST");
    expect(body).toContain("reason: method is not permitted for this host (allowed: GET, HEAD, OPTIONS)");
    // The widening command enumerates the existing methods so the replace
    // semantics of `runfree host rules` do not silently drop them.
    expect(body).toContain("runfree host rules api.github.com --method GET --method HEAD --method OPTIONS --method POST");
    expect(body).toContain("Current rules: runfree host explain api.github.com");
    expect(body).not.toContain("query-secret");
  });

  test("path denial body includes the truncated pathname and never the query string", () => {
    const longPath = `/denied/${"a".repeat(500)}`;
    const body = syntheticDenialBody("internal.example.com", "path-not-allowed", {
      method: "GET",
      path: `${longPath}?api_key=query-secret`,
      allowedPathPrefixes: ["/api/v2/"],
    });
    expect(body).toContain("reason: path is not permitted for this host (allowed prefixes: /api/v2/)");
    expect(body).toContain(`path:   ${longPath.slice(0, 256)}`);
    expect(body).not.toContain(longPath.slice(0, 257));
    expect(body).not.toContain("query-secret");
    expect(body).toContain("runfree host rules internal.example.com --request-path-prefix");
    expect(body).toContain("Current rules: runfree host explain internal.example.com");
  });

  test("method denial widening reproduces the host's full rule and prints the resulting rule", () => {
    const body = syntheticDenialBody("api.github.com", "method-not-allowed", {
      method: "POST",
      path: "/repos",
      allowedMethods: ["GET", "HEAD"],
      rule: { methods: ["GET", "HEAD"], pathPrefixes: ["/repos/"], gitPush: "deny", writeAction: "ask" },
    });
    // Pasting this must keep the path prefix, the git-push deny, and the write
    // action; a delta-only command would silently delete them.
    expect(body).toContain(
      "  runfree host rules api.github.com --method GET --method HEAD --method POST --request-path-prefix /repos/ --deny-git-push --write ask",
    );
    expect(body).toContain(
      "This replaces the host's request rule with: methods=GET,HEAD,POST pathPrefixes=/repos/ gitPush=deny writeAction=ask",
    );
    expect(body).not.toContain("cannot express");
  });

  test("path denial widening reproduces the host's full rule around the prefix placeholder", () => {
    const body = syntheticDenialBody("internal.example.com", "path-not-allowed", {
      method: "GET",
      path: "/denied",
      allowedPathPrefixes: ["/api/v2/"],
      rule: { methods: ["GET"], pathPrefixes: ["/api/v2/"], writeAction: "deny" },
    });
    expect(body).toContain(
      "  runfree host rules internal.example.com --method GET --request-path-prefix /api/v2/ --request-path-prefix <prefix> --write deny",
    );
    expect(body).toContain("This replaces the host's request rule with: methods=GET pathPrefixes=/api/v2/,<prefix> gitPush=allow writeAction=deny");
  });

  test("widening notes the rule fields host rules cannot express and quotes adversarial prefixes", () => {
    const body = syntheticDenialBody("h.example", "method-not-allowed", {
      method: "POST",
      path: "/x",
      allowedMethods: ["GET"],
      rule: { methods: ["GET"], pathPrefixes: ["/a b/;rm -rf /"], readPathPrefixes: ["/r/"], graphql: { endpoints: ["/graphql"], writeOps: "mutation" } },
    });
    expect(body).toContain("runfree host rules h.example --method GET --method POST --request-path-prefix '/a b/;rm -rf /'");
    expect(body).toContain("Note: the current rule also sets readPathPrefixes, graphql, which `runfree host rules` cannot express;");
    expect(body).toContain("Edit the rule in .runfree/network-policy.json instead.");
  });

  test("a stale denied tunnel names the new-connection remedy, not doctor", () => {
    // After the operator allowlists the host, a pooled connection that was
    // denied at CONNECT keeps failing; the fix is a fresh connection.
    const body = syntheticDenialBody("api.github.com", "missing-admission-record");
    expect(body).toContain("Retry on a new connection:");
    expect(body).toContain("a client that pools connections must reconnect.");
    expect(body).toContain("Current rules: runfree host explain api.github.com");
    expect(body).not.toContain("runfree doctor");
  });

  test("git push denial body points at the rule rather than a widening flag", () => {
    const body = syntheticDenialBody("github.com", "git-push-denied", {
      method: "POST",
      path: "/owner/repo.git/git-receive-pack",
    });
    expect(body).toContain("reason: git push is denied for this host");
    expect(body).toContain("path:   /owner/repo.git/git-receive-pack");
    expect(body).toContain("runfree host rules github.com");
    expect(body).toContain("Current rules: runfree host explain github.com");
  });

  test("shape denial bodies bound attacker-controlled method values", () => {
    expect(displayMethod("P\x1b[31mOST\nINJECTED")).toBe("P31mOSTINJECTED");
    expect(displayMethod("\x1b[31m")).toBe("31m");
    expect(displayMethod("\x1b\n")).toBe("<unparseable>");
    expect(displayMethod("X".repeat(64))).toHaveLength(16);

    const body = syntheticDenialBody("api.example.com", "method-not-allowed", {
      method: "P\x1b[31mOST\nINJECTED",
      allowedMethods: ["GET"],
    });
    expect(body).toContain("method: P31mOSTINJECTED");
    expect(body).not.toContain("\x1b");
    expect(body).not.toContain("\nINJECTED");
    // A non-RFC method gets no widening command, only the rules pointer.
    expect(body).not.toContain("--method");
    expect(body).toContain("runfree host rules api.example.com");
  });
});

describe("denial event emitter", () => {
  function emitterWithClock() {
    const lines: string[] = [];
    let nowMs = Date.parse("2026-06-10T12:00:00.000Z");
    const emitter = createDenialEventEmitter({
      log: (line) => lines.push(line),
      now: () => new Date(nowMs),
    });
    return {
      emitter,
      lines,
      advance: (ms: number) => {
        nowMs += ms;
      },
    };
  }

  function emitDenied(emitter: ReturnType<typeof createDenialEventEmitter>, overrides: Record<string, string> = {}): void {
    emitter.emit({
      reason: "host-not-allowlisted",
      host: overrides.host ?? "api.example.com",
      method: overrides.method,
      path: overrides.path,
      generation: overrides.generation ?? GENERATION_A,
    });
  }

  test("emits exactly one schema-versioned structured event per denial", () => {
    const { emitter, lines } = emitterWithClock();
    emitter.emit({
      reason: "host-not-allowlisted",
      host: "API.Example.com",
      method: "GET",
      path: "https://api.example.com/v1/data?api_key=secret-value",
      generation: GENERATION_A,
    });

    expect(lines).toHaveLength(1);
    const event = parseEventLine(lines[0]);
    expect(event).toEqual({
      v: 1,
      ts: "2026-06-10T12:00:00.000Z",
      reason: "host-not-allowlisted",
      host: "api.example.com",
      method: "GET",
      path: "/v1/data",
      generation: GENERATION_A,
    });
    expect(lines[0]).not.toContain("api_key");
    expect(lines[0]).not.toContain("secret-value");
  });

  test("emits bounded MCP OAuth context for discovered issuer denials", () => {
    const { emitter, lines } = emitterWithClock();
    emitter.emit({
      reason: "host-not-allowlisted",
      host: "oauth.posthog.com",
      generation: GENERATION_A,
      mcpOAuthIssuer: {
        serverName: "posthog",
        resourceHost: "mcp.posthog.com",
      },
    });

    const event = parseEventLine(lines[0]);
    expect(event).toMatchObject({
      reason: "host-not-allowlisted",
      host: "oauth.posthog.com",
      mcpOAuthIssuer: {
        serverName: "posthog",
        resourceHost: "mcp.posthog.com",
      },
    });
  });

  test("omits method and path for raw-guard denials", () => {
    const { emitter, lines } = emitterWithClock();
    emitDenied(emitter);
    const event = parseEventLine(lines[0]);
    expect(event.method).toBeUndefined();
    expect(event.path).toBeUndefined();
  });

  test("coalesces events past the per-(host, reason) bound and flushes a suppressed summary", () => {
    const { emitter, lines, advance } = emitterWithClock();
    for (let index = 0; index < 14; index += 1) emitDenied(emitter);
    // 10 events pass the bound.
    expect(lines).toHaveLength(10);
    expect(lines.filter((line) => line.startsWith("proxy-denial: "))).toHaveLength(10);

    // Another host is bounded independently.
    emitDenied(emitter, { host: "cdn.example.net" });
    expect(lines).toHaveLength(11);

    // The next window flushes a suppressed summary for the coalesced events.
    advance(60_000);
    emitDenied(emitter);
    const suppressed = lines.map(parseEventLineSafe).find((event) => event?.suppressed !== undefined);
    expect(suppressed).toMatchObject({
      v: 1,
      reason: "host-not-allowlisted",
      host: "api.example.com",
      suppressed: 4,
      generation: GENERATION_A,
    });
  });

  test("resets coalescing state when the policy generation changes", () => {
    const { emitter, lines } = emitterWithClock();
    for (let index = 0; index < 12; index += 1) emitDenied(emitter);
    expect(lines.filter((line) => line.startsWith("proxy-denial: "))).toHaveLength(10);

    emitDenied(emitter, { generation: GENERATION_B });
    const events = lines.filter((line) => line.startsWith("proxy-denial: ")).map(parseEventLine);
    expect(events).toHaveLength(11);
    expect(events.at(-1)).toMatchObject({ generation: GENERATION_B, host: "api.example.com" });
  });

  test("coalesces request-shape denials per (host, reason, method)", () => {
    const lines: string[] = [];
    const emitter = createDenialEventEmitter({
      log: (line) => lines.push(line),
      now: () => new Date("2026-06-10T12:00:00.000Z"),
      maxEventsPerWindow: 1,
    });
    const emitShape = (method: string) => emitter.emit({
      reason: "method-not-allowed",
      host: "api.example.com",
      method,
      path: "/v1/data",
      generation: GENERATION_A,
    });

    emitShape("POST");
    emitShape("POST"); // suppressed within the (host, reason, POST) bucket
    emitShape("DELETE"); // distinct method: emitted despite the POST bound

    const events = lines.map(parseEventLineSafe).filter((event) => event !== undefined);
    expect(events.map((event) => event?.method)).toEqual(["POST", "DELETE"]);

    // Host-level denials still coalesce per (host, reason) regardless of method.
    emitter.emit({
      reason: "host-not-allowlisted",
      host: "denied.example.com",
      method: "GET",
      generation: GENERATION_A,
    });
    emitter.emit({
      reason: "host-not-allowlisted",
      host: "denied.example.com",
      method: "POST",
      generation: GENERATION_A,
    });
    const hostEvents = lines.map(parseEventLineSafe)
      .filter((event) => event?.reason === "host-not-allowlisted" && event.suppressed === undefined);
    expect(hostEvents).toHaveLength(1);
  });

  test("suppressed summaries for shape denials carry the coalesced method", () => {
    const lines: string[] = [];
    let nowMs = Date.parse("2026-06-10T12:00:00.000Z");
    const emitter = createDenialEventEmitter({
      log: (line) => lines.push(line),
      now: () => new Date(nowMs),
      maxEventsPerWindow: 1,
    });
    const emitShape = () => emitter.emit({
      reason: "method-not-allowed",
      host: "api.example.com",
      method: "POST",
      path: "/v1/data",
      generation: GENERATION_A,
    });

    emitShape();
    emitShape();
    emitShape();
    nowMs += 60_000;
    emitShape();

    const suppressed = lines.map(parseEventLineSafe).find((event) => event?.suppressed !== undefined);
    expect(suppressed).toMatchObject({
      reason: "method-not-allowed",
      host: "api.example.com",
      method: "POST",
      suppressed: 2,
      generation: GENERATION_A,
    });
  });

  test("non-https-url and missing-required-token denials emit and coalesce per (host, reason)", () => {
    const { emitter, lines } = emitterWithClock();
    const emit = (reason: "non-https-url" | "missing-required-token") => emitter.emit({
      reason,
      host: "api.example.com",
      method: "GET",
      path: "https://api.example.com/v1/data?api_key=secret-value",
      generation: GENERATION_A,
    });

    // These previously fell to legacy logging with no structured event; now
    // they emit a schema-versioned event and never leak the query string.
    emit("non-https-url");
    emit("missing-required-token");
    const events = lines.filter((line) => line.startsWith("proxy-denial: ")).map(parseEventLine);
    expect(events.map((event) => event.reason)).toEqual(["non-https-url", "missing-required-token"]);
    expect(lines.join("\n")).not.toContain("api_key");
    expect(lines.join("\n")).not.toContain("secret-value");

    // The host-level reasons coalesce per (host, reason) regardless of method.
    for (let index = 0; index < 12; index += 1) emit("non-https-url");
    const nonHttps = lines
      .filter((line) => line.startsWith("proxy-denial: "))
      .map(parseEventLine)
      .filter((event) => event.reason === "non-https-url" && event.suppressed === undefined);
    // 1 from the first emit + 9 more before the per-window bound of 10 is hit.
    expect(nonHttps).toHaveLength(10);
  });

  test("bounds tracked (host, reason) keys and flushes evicted suppressed counts", () => {
    const lines: string[] = [];
    const emitter = createDenialEventEmitter({
      log: (line) => lines.push(line),
      now: () => new Date("2026-06-10T12:00:00.000Z"),
      maxEventsPerWindow: 1,
      maxTrackedKeys: 2,
    });
    const emit = (host: string) => emitter.emit({
      reason: "host-not-allowlisted",
      host,
      generation: GENERATION_A,
    });

    emit("a.example.com");
    emit("a.example.com"); // suppressed
    emit("b.example.com");
    emit("c.example.com"); // evicts a.example.com, flushing its suppressed count

    const suppressed = lines.map(parseEventLineSafe).find((event) => event?.suppressed !== undefined);
    expect(suppressed).toMatchObject({ host: "a.example.com", suppressed: 1 });
  });
});

function parseEventLineSafe(line: string): Record<string, unknown> | undefined {
  if (!line.startsWith("proxy-denial: ")) return undefined;
  try {
    return JSON.parse(line.slice("proxy-denial: ".length)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}
