// Per-operation launch instrumentation (companion to timings.ts).
//
// Under `RUNFREE_TIMINGS=1`, startup wraps its RuntimeIO so every subprocess
// is counted and timed by category. Categories carry only the Docker
// subcommand verbs, never arguments, ids, paths, or output, so a timing line
// cannot leak a secret.

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

export type OperationHistogram = Readonly<{
  record(category: string, durationMs: number): void;
  lines(): string[];
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

export function createOperationHistogram(): OperationHistogram {
  const buckets = new Map<string, { count: number; totalMs: number }>();
  return Object.freeze({
    record(category: string, durationMs: number): void {
      const bucket = buckets.get(category) ?? { count: 0, totalMs: 0 };
      bucket.count += 1;
      bucket.totalMs += durationMs;
      buckets.set(category, bucket);
    },
    lines(): string[] {
      return [...buckets.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, bucket]) => `${category} count=${bucket.count} total=${bucket.totalMs.toFixed(1)}ms`);
    },
  });
}

export function withOperationHistogram(io: RuntimeIO, histogram: OperationHistogram): RuntimeIO {
  const timed = <T>(command: string, args: string[], call: () => T): T => {
    const startedAt = performance.now();
    try {
      return call();
    } finally {
      histogram.record(subprocessCategory(command, args), performance.now() - startedAt);
    }
  };
  return {
    ...io,
    capture: (command, args, options) => timed(command, args, () => io.capture(command, args, options)),
    run: (command, args, options) => timed(command, args, () => io.run(command, args, options)),
  };
}
