// Shared strict-parsing primitives. One audited definition instead of a copy
// per consumer: both halves of every host↔proxy contract parse hostile or
// semi-trusted JSON with these, so the acceptance behavior must be identical
// everywhere. Behavior is frozen — callers depend on exact key ordering and
// exact rejection semantics feeding content-addressed digests.

import crypto from "node:crypto";

export function sha256Hex(value: string | Buffer): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function sha256Digest(value: string | Buffer): string {
  return `sha256:${sha256Hex(value)}`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Exact key-set equality: rejects extra AND missing keys. */
export function exactKeySet(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

/**
 * Deterministic JSON: object keys sorted with `localeCompare`, arrays in
 * order, everything else `JSON.stringify`. Feeds content-addressed digests, so
 * the ordering and the treatment of `undefined` (emitted as the literal text
 * `undefined`, exactly like `JSON.stringify`) are contract, not style.
 */
export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
