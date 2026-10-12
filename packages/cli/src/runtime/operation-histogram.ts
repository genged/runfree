// Per-operation launch instrumentation (companion to timings.ts).
//
// Under `RUNFREE_TIMINGS=1`, startup wraps its RuntimeIO so every subprocess
// is counted and timed by category. Categories carry only the Docker
// subcommand verbs, never arguments, ids, paths, or output, so a timing line
// cannot leak a secret.

import type { SpawnSyncOptions } from "node:child_process";
import path from "node:path";
import { performance } from "node:perf_hooks";
import type { RuntimeIO } from "./types.ts";

const VERB = /^[a-z][a-z-]*$/;
const OBJECT_COMMANDS = new Set(["container", "image", "network", "volume"]);
// A non-docker command name, never a full path: the category is logged, and
// an absolute path could carry directory structure that is not a secret but
// is also not a Docker subcommand verb, so anything that is not a bare
// lowercase command name collapses to "?".
const COMMAND_NAME = /^[a-z][a-z0-9._-]*$/;

export type OperationHistogramBucket = Readonly<{ count: number; totalMs: number }>;

export type OperationHistogram = Readonly<{
  record(category: string, durationMs: number, startedAt?: number): void;
  lines(): string[];
  /** A copy of every category's count and total; keys are categories only. */
  snapshot(): Readonly<Record<string, OperationHistogramBucket>>;
}>;

export function subprocessCategory(command: string, args: readonly string[]): string {
  if (command !== "docker") {
    const base = path.basename(command);
    return COMMAND_NAME.test(base) ? base : "?";
  }
  const [first, second] = args;
  if (!first || !VERB.test(first)) return "docker ?";
  if (OBJECT_COMMANDS.has(first) && second && VERB.test(second)) return `docker ${first} ${second}`;
  return `docker ${first}`;
}

export function createOperationHistogram(
  trace?: (category: string, startedAt: number, endedAt: number) => void,
): OperationHistogram {
  const buckets = new Map<string, { count: number; totalMs: number }>();
  return Object.freeze({
    record(category: string, durationMs: number, startedAt?: number): void {
      const bucket = buckets.get(category) ?? { count: 0, totalMs: 0 };
      bucket.count += 1;
      bucket.totalMs += durationMs;
      buckets.set(category, bucket);
      if (startedAt !== undefined) trace?.(category, startedAt, startedAt + durationMs);
    },
    lines(): string[] {
      return [...buckets.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, bucket]) => `${category} count=${bucket.count} total=${bucket.totalMs.toFixed(1)}ms`);
    },
    snapshot(): Readonly<Record<string, OperationHistogramBucket>> {
      return Object.freeze(Object.fromEntries([...buckets.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, bucket]) => [category, Object.freeze({ count: bucket.count, totalMs: bucket.totalMs })])));
    },
  });
}

export function withOperationHistogram(io: RuntimeIO, histogram: OperationHistogram): RuntimeIO {
  const timed = <T>(command: string, args: string[], call: () => T): T => {
    const startedAt = performance.now();
    try {
      return call();
    } finally {
      histogram.record(subprocessCategory(command, args), performance.now() - startedAt, startedAt);
    }
  };
  const timedAsync = async <T>(command: string, args: string[], call: () => Promise<T>): Promise<T> => {
    const startedAt = performance.now();
    try {
      return await call();
    } finally {
      histogram.record(subprocessCategory(command, args), performance.now() - startedAt, startedAt);
    }
  };
  const { captureAsync } = io;
  return {
    ...io,
    capture: (command, args, options) => timed(command, args, () => io.capture(command, args, options)),
    run: (command, args, options) => timed(command, args, () => io.run(command, args, options)),
    ...(captureAsync ? {
      captureAsync: (command: string, args: string[], options?: SpawnSyncOptions) =>
        timedAsync(command, args, () => captureAsync.call(io, command, args, options)),
    } : {}),
  };
}
