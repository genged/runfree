import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectHash } from "../project-identity.ts";
import {
  mcpOAuthEpochsPath,
  mcpOAuthStateEpoch,
  readMcpOAuthEpochs,
  updateMcpOAuthEpochs,
} from "./mcp-oauth-epochs.ts";

let tmp: string;
let projectRoot: string;
let stateDir: string;
let counter: number;
const random = () => `epoch${String(++counter).padStart(27, "0")}`;
const nth = (index: number) => `epoch${String(index).padStart(27, "0")}`;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-oauth-epochs-"));
  projectRoot = path.join(tmp, "project");
  stateDir = path.join(tmp, "state");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(stateDir, { recursive: true });
  counter = 0;
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function file(): string {
  return mcpOAuthEpochsPath(stateDir);
}

describe("MCP OAuth state epochs (revoke tombstones)", () => {
  test("a missing store is created with a base epoch that every provider publishes", () => {
    const result = updateMcpOAuthEpochs(projectRoot, file(), { random });
    expect(result).toEqual({ base: nth(1), revoked: {}, reset: "created" });
    expect(fs.statSync(file()).mode & 0o777).toBe(0o600);
    expect(mcpOAuthStateEpoch(result, "mcp:claude-linear")).toBe(nth(1));
    expect(mcpOAuthStateEpoch(result, "mcp:codex-other")).toBe(nth(1));
  });

  test("a revoke gives exactly that provider a new epoch, and every revoke gives another", () => {
    updateMcpOAuthEpochs(projectRoot, file(), { random });
    const first = updateMcpOAuthEpochs(projectRoot, file(), { revoke: ["mcp:claude-linear"], random });
    expect(mcpOAuthStateEpoch(first, "mcp:claude-linear")).toBe(nth(2));
    expect(mcpOAuthStateEpoch(first, "mcp:codex-other")).toBe(nth(1));
    const second = updateMcpOAuthEpochs(projectRoot, file(), { revoke: ["mcp:claude-linear"], random });
    expect(mcpOAuthStateEpoch(second, "mcp:claude-linear")).toBe(nth(3));
    expect(readMcpOAuthEpochs(projectRoot, file())).toEqual({ base: nth(1), revoked: { "mcp:claude-linear": nth(3) } });
  });

  test("a revoke against a missing store creates the base and the revoke together", () => {
    const result = updateMcpOAuthEpochs(projectRoot, file(), { revoke: ["mcp:claude-linear"], random });
    expect(result.reset).toBe("created");
    expect(mcpOAuthStateEpoch(result, "mcp:claude-linear")).not.toBe(result.base);
  });

  test("a later preparation keeps the stored epochs stable and writes nothing", () => {
    updateMcpOAuthEpochs(projectRoot, file(), { revoke: ["mcp:claude-linear"], random });
    const before = fs.readFileSync(file(), "utf8");
    const prepared = updateMcpOAuthEpochs(projectRoot, file(), { random });
    expect(prepared.reset).toBeUndefined();
    expect(fs.readFileSync(file(), "utf8")).toBe(before);
  });

  test.each([
    ["malformed JSON", "{ nope"],
    ["an unknown top-level key", JSON.stringify({ schemaVersion: 1, projectHash: "PH", base: nth(9), providers: {}, extra: 1 })],
    ["a missing base", JSON.stringify({ schemaVersion: 1, projectHash: "PH", providers: {} })],
    ["a bad provider epoch", JSON.stringify({ schemaVersion: 1, projectHash: "PH", base: nth(9), providers: { "mcp:claude-linear": { epoch: "short", revokedAt: "2026-09-30T00:00:00.000Z" } } })],
    ["a bad provider id", JSON.stringify({ schemaVersion: 1, projectHash: "PH", base: nth(9), providers: { "service:x": { epoch: nth(8), revokedAt: "2026-09-30T00:00:00.000Z" } } })],
    ["another project", JSON.stringify({ schemaVersion: 1, projectHash: "other", base: nth(9), providers: {} })],
    ["a duplicate key", `{"schemaVersion":1,"projectHash":"PH","base":"${nth(9)}","base":"${nth(8)}","providers":{}}`],
  ])("fails closed on %s: a new base changes every provider's epoch, and the rewrite reclaims the store", (_label, contents) => {
    fs.writeFileSync(file(), contents.replace("PH", projectHash(projectRoot)));
    const result = updateMcpOAuthEpochs(projectRoot, file(), { random });
    expect(result).toEqual({ base: nth(1), revoked: {}, reset: "reclaimed" });
    // Every provider, revoked earlier or never, now publishes an epoch no
    // stored state can carry.
    expect(mcpOAuthStateEpoch(result, "mcp:claude-linear")).toBe(nth(1));
    expect(readMcpOAuthEpochs(projectRoot, file())).toEqual({ base: nth(1), revoked: {} });
    expect(updateMcpOAuthEpochs(projectRoot, file(), { random }).reset).toBeUndefined();
  });

  test("a revoke that finds the store invalid reclaims it rather than failing", () => {
    fs.writeFileSync(file(), "{ nope");
    const result = updateMcpOAuthEpochs(projectRoot, file(), { revoke: ["mcp:claude-linear"], random });
    expect(result.reset).toBe("reclaimed");
    expect(readMcpOAuthEpochs(projectRoot, file())?.revoked["mcp:claude-linear"]).toBe(nth(2));
  });

  test("a symlinked store is invalid, and the reclaim replaces the link, not its target", () => {
    const target = path.join(tmp, "elsewhere.json");
    fs.writeFileSync(target, "untouched");
    fs.symlinkSync(target, file());
    expect(readMcpOAuthEpochs(projectRoot, file())).toBeUndefined();
    const result = updateMcpOAuthEpochs(projectRoot, file(), { random });
    expect(result.reset).toBe("reclaimed");
    expect(fs.readFileSync(target, "utf8")).toBe("untouched");
    expect(fs.lstatSync(file()).isSymbolicLink()).toBe(false);
  });

  test("refuses a store inside the project before writing anything", () => {
    const inside = path.join(projectRoot, "mcp-oauth-epochs.json");
    expect(() => updateMcpOAuthEpochs(projectRoot, inside, { revoke: ["mcp:claude-linear"], random })).toThrow(/outside the project/);
    expect(fs.existsSync(inside)).toBe(false);
  });

  test("revokes a server with a very long name (no length limit to wedge revoke)", () => {
    const providerId = `mcp:claude-${"a".repeat(500)}`;
    const result = updateMcpOAuthEpochs(projectRoot, file(), { revoke: [providerId], random });
    expect(readMcpOAuthEpochs(projectRoot, file())?.revoked[providerId]).toBe(mcpOAuthStateEpoch(result, providerId));
  });

  test("refuses a provider id that is not an MCP provider id before writing", () => {
    expect(() => updateMcpOAuthEpochs(projectRoot, file(), { revoke: ["service:x"], random })).toThrow(/MCP OAuth provider id/);
    expect(fs.existsSync(file())).toBe(false);
  });
});
