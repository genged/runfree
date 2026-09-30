import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectHash } from "../project-identity.ts";
import { flushWarnings } from "../warnings.ts";
import {
  boundedEvidence,
  type McpEnabledRecord,
  mcpEnabledPath,
  projectEnabledOAuthEndpoints,
  projectEnabledOAuthHosts,
  readMcpEnabled,
  removeMcpEnabledRecords,
  saveMcpEnabledRecord,
} from "./mcp-enabled.ts";

let tmp: string;
let projectRoot: string;
let stateDir: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-enabled-"));
  projectRoot = path.join(tmp, "project");
  stateDir = path.join(tmp, "state");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(stateDir, { recursive: true });
});

afterEach(() => {
  flushWarnings();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function record(overrides: Partial<McpEnabledRecord> = {}): McpEnabledRecord {
  return {
    schemaVersion: 1,
    identity: "project:claude:srv:abc",
    agent: "claude",
    source: "project",
    server: "srv",
    enabledAt: "2026-09-30T00:00:00.000Z",
    oauthHosts: [{ host: "auth.example.com", origin: "discovered", evidence: ["token_endpoint https://auth.example.com/token"] }],
    oauthEndpoints: [{ kind: "token", host: "auth.example.com", path: "/token" }],
    ...overrides,
  };
}

function writeRaw(records: Record<string, unknown>, extra: Record<string, unknown> = {}): void {
  fs.writeFileSync(mcpEnabledPath(stateDir), JSON.stringify({ schemaVersion: 1, projectHash: projectHash(projectRoot), records, ...extra }));
}

describe("mcp-enabled store", () => {
  test("round-trips a valid record with 0600 permissions", () => {
    saveMcpEnabledRecord(projectRoot, mcpEnabledPath(stateDir), record());
    expect(fs.statSync(mcpEnabledPath(stateDir)).mode & 0o777).toBe(0o600);
    const read = readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true });
    expect(read.file.records["project:claude:srv:abc"]).toEqual(record());
    expect(read.invalidRecords).toBe(0);
  });

  test("each invalid record shape grants nothing", () => {
    const bad: Array<Record<string, unknown>> = [
      { ...record(), identity: "other-key" },
      { ...record(), extra: true },
      { ...record(), agent: "pi" },
      { ...record(), source: "team" },
      { ...record(), server: "" },
      { ...record(), enabledAt: "yesterday" },
      { ...record(), oauthHosts: [{ host: "10.0.0.1", origin: "user" }] },
      { ...record(), oauthHosts: [{ host: "*.example.com", origin: "user" }] },
      { ...record(), oauthHosts: [{ host: "Auth.example.com", origin: "user" }] },
      { ...record(), oauthHosts: [{ host: "auth.example.com", origin: "remote" }] },
      { ...record(), oauthHosts: [{ host: "a.example.com", origin: "user" }, { host: "a.example.com", origin: "user" }] },
      { ...record(), oauthHosts: [{ host: "a.example.com", origin: "discovered", evidence: ["bad\u001b[2J"] }] },
      { ...record(), oauthHosts: Array.from({ length: 17 }, (_, index) => ({ host: `h${index}.example.com`, origin: "user" })) },
      { ...record(), oauthEndpoints: [{ kind: "token", host: "auth.example.com", path: "token" }] },
      { ...record(), oauthEndpoints: [{ kind: "token", host: "auth.example.com", path: "/a/../token" }] },
      { ...record(), oauthEndpoints: [{ kind: "metadata", host: "auth.example.com", path: "/meta" }] },
      { ...record(), oauthEndpoints: [{ kind: "authorize", host: "auth.example.com", path: "/authorize" }] },
    ];
    writeRaw(Object.fromEntries(bad.map((value, index) => {
      const key = index === 0 ? "project:claude:srv:abc" : `key-${index}`;
      return [key, { ...value, identity: index === 0 ? "other-key" : key }];
    })));
    const read = readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true });
    expect(read.file.records).toEqual({});
    expect(read.invalidRecords).toBe(bad.length);
  });

  test("a file inside the project, for another project, oversized, or not a regular file grants nothing", () => {
    const inside = path.join(projectRoot, ".runfree", "mcp-enabled.json");
    fs.mkdirSync(path.dirname(inside), { recursive: true });
    fs.writeFileSync(inside, JSON.stringify({ schemaVersion: 1, projectHash: projectHash(projectRoot), records: { k: record({ identity: "k" }) } }));
    expect(readMcpEnabled(projectRoot, inside, { quiet: true })).toMatchObject({ malformed: true, file: { records: {} } });
    expect(() => saveMcpEnabledRecord(projectRoot, inside, record())).toThrow("outside the project");

    writeRaw({ k: record({ identity: "k" }) }, { projectHash: "other" });
    expect(readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true }).file.records).toEqual({});

    fs.writeFileSync(mcpEnabledPath(stateDir), " ".repeat(300 * 1024));
    expect(readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true }).malformed).toBe(true);

    fs.rmSync(mcpEnabledPath(stateDir));
    fs.mkdirSync(mcpEnabledPath(stateDir));
    expect(readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true }).malformed).toBe(true);
  });

  test("a symlinked file grants nothing and the next write replaces the link, not its target", () => {
    const target = path.join(tmp, "elsewhere.json");
    fs.writeFileSync(target, "sentinel");
    fs.symlinkSync(target, mcpEnabledPath(stateDir));
    expect(readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true }).malformed).toBe(true);
    saveMcpEnabledRecord(projectRoot, mcpEnabledPath(stateDir), record());
    expect(fs.readFileSync(target, "utf8")).toBe("sentinel");
    expect(fs.lstatSync(mcpEnabledPath(stateDir)).isFile()).toBe(true);
  });

  test("saving replaces every record for the same server and drops invalid records (reclaim)", () => {
    writeRaw({
      "project:claude:srv:old": record({ identity: "project:claude:srv:old" }),
      "project:claude:other:x": record({ identity: "project:claude:other:x", server: "other" }),
      broken: { nope: true },
    });
    const result = saveMcpEnabledRecord(projectRoot, mcpEnabledPath(stateDir), record());
    expect(result.droppedInvalid).toBe(1);
    expect(result.removed.map((entry) => entry.identity)).toEqual(["project:claude:srv:old"]);
    expect(Object.keys(readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true }).file.records).sort())
      .toEqual(["project:claude:other:x", "project:claude:srv:abc"]);
  });

  test("removing by agent and server leaves other servers and sources", () => {
    writeRaw({
      a: record({ identity: "a" }),
      b: record({ identity: "b", source: "user" }),
      c: record({ identity: "c", server: "other" }),
    });
    const onlyProject = removeMcpEnabledRecords(projectRoot, mcpEnabledPath(stateDir), { agent: "claude", server: "srv", source: "project" });
    expect(onlyProject.removed.map((entry) => entry.identity)).toEqual(["a"]);
    const all = removeMcpEnabledRecords(projectRoot, mcpEnabledPath(stateDir), { agent: "claude", server: "srv" });
    expect(all.removed.map((entry) => entry.identity)).toEqual(["b"]);
    expect(Object.keys(readMcpEnabled(projectRoot, mcpEnabledPath(stateDir), { quiet: true }).file.records)).toEqual(["c"]);
  });

  test("removing nothing from a clean file does not rewrite it", () => {
    writeRaw({ c: record({ identity: "c", server: "other" }) });
    const before = fs.statSync(mcpEnabledPath(stateDir)).mtimeMs;
    const result = removeMcpEnabledRecords(projectRoot, mcpEnabledPath(stateDir), { agent: "claude", server: "srv" });
    expect(result).toEqual({ droppedInvalid: 0, removed: [] });
    expect(fs.statSync(mcpEnabledPath(stateDir)).mtimeMs).toBe(before);
  });

  test("evidence is clamped to printable ASCII", () => {
    expect(boundedEvidence(["a\u001bb‮c", "x".repeat(600), "3", "4", "5"])).toEqual(["a?b?c", "x".repeat(512), "3", "4"]);
  });
});

describe("projection", () => {
  test("hosts only records add are narrowed to .well-known and their exact endpoints", () => {
    const policy: { hosts: string[]; requests?: Record<string, { methods?: string[]; pathPrefixes?: string[] }> } = { hosts: ["mcp.example.com"] };
    projectEnabledOAuthHosts(policy, [record({
      oauthEndpoints: [
        { kind: "metadata", host: "auth.example.com", path: "/tenant/.well-known/openid-configuration" },
        { kind: "token", host: "auth.example.com", path: "/token" },
      ],
    })]);
    expect(policy.hosts).toEqual(["auth.example.com", "mcp.example.com"]);
    expect(policy.requests).toEqual({
      "auth.example.com": {
        methods: ["GET", "HEAD", "OPTIONS", "POST"],
        pathPrefixes: ["/.well-known", "/tenant/.well-known/openid-configuration", "/token"],
      },
    });
  });

  test("a host already allowed keeps its rules; a user host is allowed as given", () => {
    const policy: { hosts: string[]; requests?: Record<string, { methods?: string[]; pathPrefixes?: string[] }> } = {
      hosts: ["auth.example.com"],
      requests: { "auth.example.com": { methods: ["GET"] } },
    };
    projectEnabledOAuthHosts(policy, [
      record(),
      record({ identity: "k2", server: "two", oauthHosts: [{ host: "sso.example.org", origin: "user" }], oauthEndpoints: [] }),
      record({ identity: "k3", server: "three", oauthHosts: [{ host: "sso.example.org", origin: "discovered" }], oauthEndpoints: [] }),
    ]);
    expect(policy.hosts).toEqual(["auth.example.com", "sso.example.org"]);
    expect(policy.requests).toEqual({ "auth.example.com": { methods: ["GET"] } });
  });

  test("record endpoints join the OAuth policy only on bound hosts", () => {
    const oauthPolicy: Parameters<typeof projectEnabledOAuthEndpoints>[0] = {
      resourceHost: "mcp.example.com",
      tokenEndpoints: [{ host: "declared.example.com", path: "/t" }],
    };
    const applied = projectEnabledOAuthEndpoints(oauthPolicy, record({
      oauthEndpoints: [
        { kind: "token", host: "auth.example.com", path: "/token" },
        { kind: "token", host: "mcp.example.com", path: "/oauth/token" },
        { kind: "token", host: "declared.example.com", path: "/t" },
        { kind: "registration", host: "auth.example.com", path: "/register" },
        { kind: "token", host: "unbound.example.net", path: "/token" },
        { kind: "metadata", host: "auth.example.com", path: "/.well-known/oauth-authorization-server" },
      ],
    }));
    // Only the recorded token and registration endpoints now mediated
    // statically: never a metadata endpoint, never an unbound host.
    expect(applied).toEqual([
      { host: "auth.example.com", path: "/token" },
      { host: "mcp.example.com", path: "/oauth/token" },
      { host: "declared.example.com", path: "/t" },
      { host: "auth.example.com", path: "/register" },
    ]);
    expect(oauthPolicy.tokenEndpoints).toEqual([
      { host: "declared.example.com", path: "/t" },
      { host: "auth.example.com", path: "/token" },
      { host: "mcp.example.com", path: "/oauth/token" },
    ]);
    expect(oauthPolicy.registrationEndpoints).toEqual([{ host: "auth.example.com", path: "/register" }]);
  });
});
