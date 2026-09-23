// Shared strict primitives for the CLI: one audited definition of the
// deterministic-JSON, digest, key-set, and bounded-read helpers that used to
// exist as per-file copies. Behavior is frozen — every variant here feeds
// content-addressed digests or fail-closed parsers, so the exact key
// ordering, `undefined` handling, error text, and rejection semantics are
// contract, not style. The base definitions live in
// `@runfree/runtime-contracts/primitives` so the proxy shares them.

import fs from "node:fs";

export {
  exactKeySet,
  isRecord,
  sha256Digest,
  sha256Hex,
  stableJson,
} from "@runfree/runtime-contracts/primitives";

/**
 * `stableJson`, but object keys whose value is `undefined` are dropped
 * (matching `JSON.stringify`'s object behavior) instead of being emitted as
 * the literal text `undefined`. Used where optional fields must not disturb a
 * digest.
 */
export function stableJsonDroppingUndefined(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((entry) => stableJsonDroppingUndefined(entry)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJsonDroppingUndefined(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * `stableJson` that throws the caller's exact message on a non-finite number
 * instead of serializing it as `null`. Each digest family keeps its own
 * message so the rejection names the artifact being hashed.
 */
export function strictStableJson(value: unknown, nonFiniteMessage: string): string {
  if (Array.isArray(value)) return `[${value.map((entry) => strictStableJson(entry, nonFiniteMessage)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${strictStableJson(entry, nonFiniteMessage)}`).join(",")}}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new Error(nonFiniteMessage);
  }
  return JSON.stringify(value);
}

/** Allow-list key check: rejects unknown keys, permits missing ones. */
export function assertAllowedKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
}

export function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

export type BoundedRegularFileReadOptions = Readonly<{
  maxBytes: number;
  /**
   * How the post-open size is validated: `"exact"` requires the open
   * descriptor's size to equal the lstat observation; `"cap"` only re-applies
   * the byte bound. Callers keep their historical strictness.
   */
  sizeRecheck: "exact" | "cap";
  /** Error when the path is not a bounded regular single-link file. */
  notFileMessage: (filePath: string) => string;
  /** Error when the open descriptor no longer matches the lstat observation. */
  changedMessage: (filePath: string) => string;
}>;

export type BoundedRegularFileRead = Readonly<{
  source: string;
  dev: number;
  ino: number;
  size: number;
}>;

/**
 * Reads a bounded, regular, single-link file with a TOCTOU re-check:
 * `lstat` proves shape and size, the `O_NOFOLLOW` open plus `fstat` proves the
 * same inode is still what was observed. `ENOENT` resolves to `undefined`;
 * every other deviation throws the caller's exact message.
 */
export function readBoundedRegularFile(
  filePath: string,
  options: BoundedRegularFileReadOptions,
): BoundedRegularFileRead | undefined {
  let before: fs.Stats;
  try {
    before = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > options.maxBytes) {
    throw new Error(options.notFileMessage(filePath));
  }
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile()
      || opened.nlink !== 1
      || opened.dev !== before.dev
      || opened.ino !== before.ino
      || (options.sizeRecheck === "exact" && opened.size !== before.size)
      || opened.size > options.maxBytes) {
      throw new Error(options.changedMessage(filePath));
    }
    return { source: fs.readFileSync(descriptor, "utf8"), dev: opened.dev, ino: opened.ino, size: opened.size };
  } finally {
    fs.closeSync(descriptor);
  }
}
