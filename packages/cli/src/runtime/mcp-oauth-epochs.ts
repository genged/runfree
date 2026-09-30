// Host-owned MCP OAuth state epochs: the tombstones `runfree mcp revoke`
// leaves so the proxy clears that server's OAuth state (handles, the real
// tokens behind them, discovered issuers and endpoints).
//
// The proxy keeps that state in its own volume, which the host cannot reach
// without Docker and which exists even while the proxy is stopped. So revoke
// does not delete it directly. It writes a new random epoch for the server's
// OAuth provider id. Every effective preparation publishes an epoch for every
// MCP provider (the provider's own after a revoke, else the store's `base`),
// and the proxy deletes state stamped with any other epoch whenever it
// activates a policy (at start and at every reload). The epoch persists, so
// the clear happens at the next start when no proxy runs now, whether or not
// the server is enabled again.
//
// The store lives in XDG project state, which the agent cannot see. A missing
// or invalid store cannot say which servers were revoked, so it fails closed:
// the next update writes a new store with a new `base` and no per-provider
// epochs, which changes every provider's epoch and clears all MCP OAuth state
// (each server needs a new login). That rewrite is the reclaim. State from
// before epochs existed carries none and never matches, so it is cleared once.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { OAUTH_STATE_EPOCH_RE } from "@runfree/runtime-contracts/oauth-mediation-policy";
import { parseStrictJson } from "../control/strict-json.ts";
import { projectHash } from "../project-identity.ts";
import { atomicReplaceFile, isPathInsideByRealpath } from "../safe-fs.ts";
import { isRecord } from "../strict-primitives.ts";

export const MCP_OAUTH_EPOCHS_FILE = "mcp-oauth-epochs.json";
const MAX_FILE_BYTES = 256 * 1024;
// The shape `mcpOAuthProviderId` produces.
const MCP_PROVIDER_ID_RE = /^mcp:[a-z0-9_-]+$/;
const FILE_KEYS = new Set(["schemaVersion", "projectHash", "base", "providers"]);
const ENTRY_KEYS = new Set(["epoch", "revokedAt"]);

type EpochEntry = { epoch: string; revokedAt: string };

type EpochFile = {
  schemaVersion: 1;
  projectHash: string;
  base: string;
  providers: Record<string, EpochEntry>;
};

export type McpOAuthEpochs = {
  base: string;
  // Providers revoked since the base was created, with their own epochs.
  revoked: Record<string, string>;
};

export type McpOAuthEpochsUpdate = McpOAuthEpochs & {
  // The store was missing or invalid and was written with a new base.
  reset: "created" | "reclaimed" | undefined;
};

export function mcpOAuthEpochsPath(stateDir: string): string {
  return path.join(stateDir, MCP_OAUTH_EPOCHS_FILE);
}

/** The epoch the effective policy publishes for one MCP provider. */
export function mcpOAuthStateEpoch(epochs: McpOAuthEpochs, providerId: string): string {
  return epochs.revoked[providerId] ?? epochs.base;
}

function onlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

type ReadResult = { file: EpochFile; status: "valid" } | { status: "missing" | "invalid" };

function readFile(projectRoot: string, filePath: string): ReadResult {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return { status: "missing" };
    return { status: "invalid" };
  }
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return { status: "invalid" };
  let parsed: unknown;
  try {
    parsed = parseStrictJson(fs.readFileSync(filePath, "utf8"));
  } catch {
    return { status: "invalid" };
  }
  if (!isRecord(parsed) || !onlyKeys(parsed, FILE_KEYS) || parsed.schemaVersion !== 1
    || parsed.projectHash !== projectHash(projectRoot)
    || typeof parsed.base !== "string" || !OAUTH_STATE_EPOCH_RE.test(parsed.base)
    || !isRecord(parsed.providers)) {
    return { status: "invalid" };
  }
  const providers: Record<string, EpochEntry> = {};
  for (const [providerId, entry] of Object.entries(parsed.providers)) {
    if (!MCP_PROVIDER_ID_RE.test(providerId) || !isRecord(entry) || !onlyKeys(entry, ENTRY_KEYS)
      || typeof entry.epoch !== "string" || !OAUTH_STATE_EPOCH_RE.test(entry.epoch)
      || typeof entry.revokedAt !== "string" || Number.isNaN(Date.parse(entry.revokedAt))) {
      return { status: "invalid" };
    }
    providers[providerId] = { epoch: entry.epoch, revokedAt: entry.revokedAt };
  }
  return { status: "valid", file: { schemaVersion: 1, projectHash: parsed.projectHash, base: parsed.base, providers } };
}

function epochsOf(file: EpochFile): McpOAuthEpochs {
  return {
    base: file.base,
    revoked: Object.fromEntries(Object.entries(file.providers).map(([id, entry]) => [id, entry.epoch])),
  };
}

function freshEpoch(): string {
  return crypto.randomBytes(16).toString("hex");
}

/**
 * Read the store and give each `revoke` provider a new epoch. A missing or
 * invalid store is replaced by one with a new base (fail closed). Writes only
 * when something changed. Throws before any write on an invalid provider id
 * or a store directory inside the project.
 */
export function updateMcpOAuthEpochs(
  projectRoot: string,
  filePath: string,
  input: { now?: Date; random?: () => string; revoke?: readonly string[] } = {},
): McpOAuthEpochsUpdate {
  const revoke = input.revoke ?? [];
  for (const providerId of revoke) {
    if (!MCP_PROVIDER_ID_RE.test(providerId)) throw new Error(`not an MCP OAuth provider id: ${providerId}`);
  }
  // Checked on the directory: a symlink at the file path is replaced by the
  // atomic rename, never followed.
  if (isPathInsideByRealpath(projectRoot, path.dirname(filePath))) {
    throw new Error("MCP OAuth epoch store must be outside the project");
  }
  const random = input.random ?? freshEpoch;
  const current = readFile(projectRoot, filePath);
  const file: EpochFile = current.status === "valid"
    ? current.file
    : { schemaVersion: 1, projectHash: projectHash(projectRoot), base: random(), providers: {} };
  const revokedAt = (input.now ?? new Date()).toISOString();
  for (const providerId of revoke) file.providers[providerId] = { epoch: random(), revokedAt };
  if (current.status !== "valid" || revoke.length > 0) {
    const sorted: EpochFile = {
      ...file,
      providers: Object.fromEntries(Object.entries(file.providers).sort(([left], [right]) => left.localeCompare(right))),
    };
    atomicReplaceFile(filePath, `${JSON.stringify(sorted, null, 2)}\n`, 0o600);
  }
  return {
    ...epochsOf(file),
    reset: current.status === "missing" ? "created" : current.status === "invalid" ? "reclaimed" : undefined,
  };
}

/** Read-only view; undefined when the store is missing or invalid. */
export function readMcpOAuthEpochs(projectRoot: string, filePath: string): McpOAuthEpochs | undefined {
  if (isPathInsideByRealpath(projectRoot, path.dirname(filePath))) return undefined;
  const current = readFile(projectRoot, filePath);
  return current.status === "valid" ? epochsOf(current.file) : undefined;
}
