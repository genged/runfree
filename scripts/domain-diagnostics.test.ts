import { describe, expect, test } from "vitest";

import {
  domainAddCommandForHost,
  diagnoseBlockedHosts,
  extractDenialEvents,
  sanitizeForTerminal,
  summarizeProtocolDenials,
} from "./domain-diagnostics.ts";
import type { PolicyJson } from "@runfree/runtime-contracts/network-policy";

const policy: PolicyJson = {
  hosts: ["api.anthropic.com", "api.github.com", "registry.npmjs.org", "api.deps.dev"],
  tokens: {},
};

const GENERATION = `sha256:${"a".repeat(64)}`;

function denialLine(fields: Record<string, unknown>): string {
  return `proxy-denial: ${JSON.stringify({
    v: 1,
    ts: "2026-06-10T12:00:00.000Z",
    generation: GENERATION,
    ...fields,
  })}`;
}

describe("domain diagnostics", () => {
  test("builds host add commands for missing hosts", () => {
    expect(domainAddCommandForHost("platform.claude.com")).toBe(
      "runfree host add platform.claude.com",
    );
  });

  test("parses structured denial events, tolerating unknown fields and skipping malformed lines", () => {
    const logs = [
      denialLine({ reason: "host-not-allowlisted", host: "platform.claude.com", method: "GET", path: "/v1" }),
      'proxy-denial: {"v":1,"reason":"host-not-allowlisted","host":"future.example","unknownField":{"nested":true}}',
      "proxy-denial: {not json",
      "proxy-denial: [1, 2, 3]",
      'proxy-denial: "just a string"',
      "proxy: blocked host=legacy-only.example reason=blocked outbound host: legacy-only.example",
    ].join("\n");

    const events = extractDenialEvents(logs);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      reason: "host-not-allowlisted",
      host: "platform.claude.com",
      method: "GET",
      path: "/v1",
      generation: GENERATION,
    });
    expect(events[1]).toMatchObject({ host: "future.example" });
  });

  test("diagnoses missing and stale-runtime allowlisted hosts from structured events", () => {
    const logs = [
      denialLine({ reason: "host-not-allowlisted", host: "platform.claude.com" }),
      denialLine({ reason: "host-not-allowlisted", host: "api.anthropic.com" }),
      denialLine({ reason: "host-not-allowlisted", host: "platform.claude.com" }),
    ].join("\n");

    expect(diagnoseBlockedHosts(logs, policy)).toEqual([
      {
        host: "platform.claude.com",
        status: "missing",
        command: "runfree host add platform.claude.com",
        count: 2,
      },
      {
        host: "api.anthropic.com",
        status: "allowlisted",
        command: "runfree runtime reload-policy",
        count: 1,
      },
    ]);
  });

  test("reads only structured denial events and reports counts in last-seen order", () => {
    const logs = [
      // Free-text noise mentioning a host with no structured event: never
      // parsed — structured events are the only denial log format.
      "proxy: blocked host=legacy-only.example reason=blocked outbound host: legacy-only.example",
      denialLine({ reason: "host-not-allowlisted", host: "cdn.example.net" }),
      denialLine({ reason: "host-not-allowlisted", host: "platform.claude.com" }),
      denialLine({ reason: "host-not-allowlisted", host: "platform.claude.com" }),
      denialLine({ reason: "host-not-allowlisted", host: "platform.claude.com", suppressed: 9 }),
      denialLine({ reason: "host-not-allowlisted", host: "api.anthropic.com" }),
      // Hosts that fail re-normalization never reach the diagnosis.
      denialLine({ reason: "host-not-allowlisted", host: "<unparseable>" }),
      denialLine({ reason: "host-not-allowlisted", host: "evil\u001b[31m.example" }),
    ].join("\n");

    expect(diagnoseBlockedHosts(logs, policy)).toEqual([
      {
        host: "api.anthropic.com",
        status: "allowlisted",
        command: "runfree runtime reload-policy",
        count: 1,
      },
      {
        host: "platform.claude.com",
        status: "missing",
        command: "runfree host add platform.claude.com",
        count: 11,
      },
      {
        host: "cdn.example.net",
        status: "missing",
        command: "runfree host add cdn.example.net",
        count: 1,
      },
    ]);
  });

  test("preserves MCP OAuth issuer context for missing host diagnostics", () => {
    const logs = denialLine({
      reason: "host-not-allowlisted",
      host: "oauth.posthog.com",
      mcpOAuthIssuer: {
        serverName: "posthog",
        resourceHost: "mcp.posthog.com",
      },
    });

    expect(diagnoseBlockedHosts(logs, policy)).toEqual([
      {
        host: "oauth.posthog.com",
        status: "missing",
        command: "runfree host add oauth.posthog.com",
        count: 1,
        mcpOAuthIssuer: {
          serverName: "posthog",
          resourceHost: "mcp.posthog.com",
        },
      },
    ]);
  });

  test("caps the number of diagnosed hosts", () => {
    const logs = Array.from({ length: 8 }, (_, index) => (
      denialLine({ reason: "host-not-allowlisted", host: `host-${index}.example` })
    )).join("\n");

    const diagnostics = diagnoseBlockedHosts(logs, policy, 5);
    expect(diagnostics).toHaveLength(5);
    expect(diagnostics[0].host).toBe("host-7.example");
  });

  test("diagnoses request-shape denials per (host, reason, method) with exact widening commands", () => {
    const ruledPolicy: PolicyJson = {
      hosts: ["api.github.com", "github.com"],
      tokens: {},
      requests: {
        // The api rule carries more than methods: the widening command must
        // reproduce every field, because `host rules` replaces the whole rule.
        "api.github.com": { methods: ["GET", "HEAD"], pathPrefixes: ["/repos/"], gitPush: "deny", writeAction: "ask" },
        "github.com": { gitPush: "deny" },
      },
    };
    const logs = [
      denialLine({ reason: "method-not-allowed", host: "api.github.com", method: "POST", path: "/repos" }),
      denialLine({ reason: "method-not-allowed", host: "api.github.com", method: "POST", suppressed: 3 }),
      denialLine({ reason: "method-not-allowed", host: "api.github.com", method: "DELETE", path: "/repos" }),
      denialLine({ reason: "path-not-allowed", host: "api.github.com", method: "GET", path: "/denied" }),
      denialLine({ reason: "git-push-denied", host: "github.com", method: "POST", path: "/o/r.git/git-receive-pack" }),
    ].join("\n");

    expect(diagnoseBlockedHosts(logs, ruledPolicy)).toEqual([
      {
        host: "github.com",
        status: "request-shape",
        reason: "git-push-denied",
        method: "POST",
        command: "runfree host rules github.com",
        commandKind: "inspect",
        count: 1,
      },
      {
        host: "api.github.com",
        status: "request-shape",
        reason: "path-not-allowed",
        method: "GET",
        command: "runfree host rules api.github.com --method GET --method HEAD --request-path-prefix /repos/ --request-path-prefix <prefix> --deny-git-push --write ask",
        commandKind: "fix",
        count: 1,
      },
      {
        host: "api.github.com",
        status: "request-shape",
        reason: "method-not-allowed",
        method: "DELETE",
        command: "runfree host rules api.github.com --method GET --method HEAD --method DELETE --request-path-prefix /repos/ --deny-git-push --write ask",
        commandKind: "fix",
        count: 1,
      },
      {
        host: "api.github.com",
        status: "request-shape",
        reason: "method-not-allowed",
        method: "POST",
        command: "runfree host rules api.github.com --method GET --method HEAD --method POST --request-path-prefix /repos/ --deny-git-push --write ask",
        commandKind: "fix",
        count: 4,
      },
    ]);
  });

  test("shape events with unvalidatable methods never reach a suggested command", () => {
    const logs = [
      denialLine({ reason: "method-not-allowed", host: "api.github.com", method: "FET[31mCH" }),
    ].join("\n");

    expect(diagnoseBlockedHosts(logs, policy)).toEqual([
      {
        host: "api.github.com",
        status: "request-shape",
        reason: "method-not-allowed",
        command: "runfree host rules api.github.com",
        commandKind: "inspect",
        count: 1,
      },
    ]);
  });

  test("surfaces hostless connection-guard denials that the host diagnosis necessarily drops", () => {
    const logs = [
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "unsupported-client-protocol", host: "<unparseable>" })}`,
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "unsupported-client-protocol", host: "<unparseable>" })}`,
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "proxy-authorization-not-allowed", host: "<unparseable>", suppressed: 4 })}`,
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "request-head-timeout", host: "<unparseable>" })}`,
      // A real host denial belongs to the host diagnosis, not here.
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "host-not-allowlisted", host: "blocked.example.com" })}`,
      // A guard reason that did resolve a host is already reported as a host.
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "malformed-connect", host: "named.example.com" })}`,
    ].join("\n");

    // These carry `host: "<unparseable>"`, which normalizeHostname rejects, so
    // diagnoseBlockedHosts drops them entirely — they are not blocked hosts and
    // have no widening command. Without a separate summary they are invisible
    // to both `runfree doctor` and the session summary.
    expect(diagnoseBlockedHosts(logs, policy).map((diagnostic) => diagnostic.host))
      .toEqual(["named.example.com", "blocked.example.com"]);

    expect(summarizeProtocolDenials(logs)).toEqual([
      { reason: "proxy-authorization-not-allowed", count: 4 },
      { reason: "unsupported-client-protocol", count: 2 },
      { reason: "request-head-timeout", count: 1 },
    ]);
  });

  test("protocol denial summary ignores unrelated reasons and malformed lines", () => {
    expect(summarizeProtocolDenials("")).toEqual([]);
    expect(summarizeProtocolDenials("proxy-denial: not json")).toEqual([]);
    expect(summarizeProtocolDenials(
      `proxy-denial: ${JSON.stringify({ v: 1, reason: "host-not-allowlisted", host: "<unparseable>" })}`,
    )).toEqual([]);
  });

  test("strips ANSI escapes and control characters for terminal rendering", () => {
    expect(sanitizeForTerminal("plain.example.com")).toBe("plain.example.com");
    expect(sanitizeForTerminal("evil\u001b[31mred\u001b[0mhost")).toBe("evilredhost");
    expect(sanitizeForTerminal("title\u001b]0;owned\u0007bar")).toBe("title0;ownedbar");
    expect(sanitizeForTerminal("tab\thost\r\nnewline\u0000null\u009cc1")).toBe("tabhostnewlinenullc1");
  });
});
