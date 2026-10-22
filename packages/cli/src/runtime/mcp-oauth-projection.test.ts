import { describe, expect, test } from "vitest";

import { oauthEndpointsOverlap } from "./mcp-oauth-claims.ts";
import { type ClaimServerView, claimRulesFor, filterClaims, settleShareGroupOwners } from "./mcp-oauth-projection.ts";
import type { McpEnabledRecord } from "./mcp-enabled.ts";

const BASE = { credentialHosts: new Set<string>(), curatedHosts: new Set<string>(["github.com"]), serviceUses: [] };

function record(overrides: Partial<McpEnabledRecord> = {}): McpEnabledRecord {
  return {
    schemaVersion: 1,
    identity: "id",
    agent: "claude",
    source: "user",
    server: "srv",
    enabledAt: "2026-10-21T00:00:00.000Z",
    oauthHosts: [{ host: "tokens.example.com", origin: "discovered", crossHost: true, crossHostKinds: ["token"] }],
    oauthEndpoints: [{ kind: "token", host: "tokens.example.com", path: "/oauth/token" }],
    ...overrides,
  };
}

function view(key: string, overrides: Partial<ClaimServerView> = {}): ClaimServerView {
  return { key, label: `claude server ${key}`, resourceHost: `${key}.example.net`, declaredTokenEndpoints: [], records: [], ...overrides };
}

describe("endpoint overlap", () => {
  test("token endpoints match exactly; a prefix registration endpoint covers paths under it in either direction", () => {
    const token = { kind: "token" as const, host: "a.example.com", path: "/oauth/token" };
    expect(oauthEndpointsOverlap(token, { ...token })).toBe(true);
    expect(oauthEndpointsOverlap(token, { ...token, path: "/oauth/token/x" })).toBe(false);
    expect(oauthEndpointsOverlap(token, { kind: "registration", host: "a.example.com", path: "/oauth" })).toBe(true);
    expect(oauthEndpointsOverlap({ kind: "registration", host: "a.example.com", path: "/oauth" }, token)).toBe(true);
    expect(oauthEndpointsOverlap(token, { kind: "registration", host: "a.example.com", path: "/oauth", exact: true })).toBe(false);
    expect(oauthEndpointsOverlap(token, { kind: "registration", host: "a.example.com", path: "/oau" })).toBe(false);
    expect(oauthEndpointsOverlap(token, { ...token, host: "b.example.com" })).toBe(false);
  });
});

describe("filterClaims", () => {
  test("a refused cross-host endpoint takes its host with it; other claims stay", () => {
    const self = view("self", {
      records: [record({
        oauthHosts: [
          { host: "tokens.example.com", origin: "discovered", crossHost: true, crossHostKinds: ["token"] },
          { host: "issuer.example.com", origin: "discovered" },
        ],
        oauthEndpoints: [
          { kind: "token", host: "tokens.example.com", path: "/oauth/token" },
          { kind: "metadata", host: "issuer.example.com", path: "/.well-known/oauth-authorization-server" },
        ],
      })],
    });
    const other = view("other", { declaredTokenEndpoints: [{ host: "tokens.example.com", path: "/oauth/token" }], resourceHost: "other.example.net" });
    const result = filterClaims(self, claimRulesFor([self, other], "self", BASE));
    expect(result.records[0]?.oauthHosts.map((host) => host.host)).toEqual(["issuer.example.com"]);
    expect(result.records[0]?.oauthEndpoints).toEqual([{ kind: "metadata", host: "issuer.example.com", path: "/.well-known/oauth-authorization-server" }]);
    expect(result.drops.map((drop) => drop.subject)).toEqual(["OAuth host tokens.example.com"]);
  });

  test("R9, R17: a declared token endpoint and metadata URL on a curated host are refused; the own resource host never is", () => {
    const self = view("self", {
      resourceHost: "github.com",
      declaredMetadataUrl: "https://github.com/.well-known/oauth-authorization-server",
      declaredTokenEndpoints: [{ host: "github.com", path: "/token" }],
    });
    expect(filterClaims(self, claimRulesFor([self], "self", BASE)).drops).toEqual([]);
    const hostile = view("hostile", {
      declaredMetadataUrl: "https://github.com/.well-known/oauth-authorization-server",
      declaredTokenEndpoints: [{ host: "github.com", path: "/login/oauth/access_token" }],
    });
    const result = filterClaims(hostile, claimRulesFor([hostile], "hostile", BASE));
    expect(result.refusedDeclaredTokenEndpoints).toEqual([{ host: "github.com", path: "/login/oauth/access_token" }]);
    expect(result.metadataUrlRefused).toBe(true);
    expect(result.drops.every((drop) => drop.refusal.use === "curated")).toBe(true);
  });
});

describe("share group owners (R16)", () => {
  const digest = "a".repeat(64);
  const members = [{ providerId: "mcp:claude-srv", enabledAt: "2026-10-21T00:00:02.000Z" }, { providerId: "mcp:codex-srv", enabledAt: "2026-10-21T00:00:01.000Z" }];

  test("a stored owner that is still a member stays, with no clear", () => {
    const settled = settleShareGroupOwners([{ digest, members }], { [digest]: { owner: "mcp:claude-srv" } });
    expect(settled.owners.get(digest)).toBe("mcp:claude-srv");
    expect(settled.bumps).toEqual([]);
  });

  test("a group of one forms quietly; a group of several forms with a clear of every member", () => {
    expect(settleShareGroupOwners([{ digest, members: [members[0] as never] }], {}).bumps).toEqual([]);
    const formed = settleShareGroupOwners([{ digest, members }], {});
    // The member enabled first owns it.
    expect(formed.owners.get(digest)).toBe("mcp:codex-srv");
    expect(formed.bumps).toEqual([{ digest, providerIds: ["mcp:claude-srv", "mcp:codex-srv"], reason: "formed" }]);
    expect(formed.state).toEqual({ [digest]: { owner: "mcp:codex-srv" } });
  });

  test("an owner that left moves, with a clear; an owner still a member stays; unrelated stored groups are forgotten", () => {
    const left = settleShareGroupOwners([{ digest, members: [members[0] as never] }], { [digest]: { owner: "mcp:codex-srv" }, ["b".repeat(64)]: { owner: "mcp:x-y" } });
    expect(left.owners.get(digest)).toBe("mcp:claude-srv");
    expect(left.bumps[0]?.reason).toBe("moved");
    expect(Object.keys(left.state)).toEqual([digest]);
    const stays = settleShareGroupOwners([{ digest, members }], { [digest]: { owner: "mcp:codex-srv" } });
    expect(stays.owners.get(digest)).toBe("mcp:codex-srv");
    expect(stays.bumps).toEqual([]);
    expect(stays.state[digest]).toEqual({ owner: "mcp:codex-srv" });
  });
});
