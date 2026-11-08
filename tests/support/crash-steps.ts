// Crash-at-every-step harness for lifecycle drivers.
//
// A lifecycle driver (a session teardown, a destroy, a generation publish)
// moves durable state through a sequence of filesystem writes. A host crash
// can land after any one of them, and AGENTS.md promises that every state a
// crash leaves behind has a `runfree` command that reclaims it. This harness
// makes that promise testable against the real driver instead of a hand-drawn
// model of it: it counts the publishing writes the driver makes under one
// root, and on request it "crashes" the driver right after the k-th one.
//
// A crash here is: the k-th write completes, the driver's call stack is
// unwound with `SimulatedCrash`, and every later publishing write under the
// root is refused (also with `SimulatedCrash`) so a `catch` in the driver
// cannot keep mutating the disk a dead process could not have touched. The
// state directory after the call is therefore exactly what the k-th write left.
//
// Publishing writes are the primitives that change what a later reader sees:
// rename, unlink, rm, rmdir, writeFile/appendFile/copyFile/truncate on a path.
// Directory creation and writes to a temp file descriptor are not counted —
// Runfree publishes files by writing a temp file and renaming it, so the
// rename is the step, and an extra `runtime/v2/...` directory is never a
// state transition on its own. Only the synchronous `node:fs` API is
// intercepted; the lifecycle drivers are synchronous by design.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export class SimulatedCrash extends Error {
  constructor(readonly afterWrites: number) {
    super(`simulated crash after durable write ${afterWrites}`);
    this.name = "SimulatedCrash";
  }
}

const PUBLISHING_WRITES = [
  "renameSync",
  "unlinkSync",
  "rmSync",
  "rmdirSync",
  "writeFileSync",
  "appendFileSync",
  "copyFileSync",
  "truncateSync",
] as const;

type PublishingWrite = (typeof PUBLISHING_WRITES)[number];

export type CrashStepOutcome<T> =
  /** The driver ran to completion with no crash requested or reached. */
  | Readonly<{ kind: "completed"; value: T; writes: number }>
  /** The crash fired after write `writes`; `swallowed` means the driver returned normally anyway. */
  | Readonly<{ kind: "crashed"; writes: number; swallowed: boolean }>
  /** The driver threw something other than the crash. */
  | Readonly<{ kind: "threw"; error: unknown; writes: number }>;

function pathOf(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString();
  if (value instanceof URL) return fileURLToPath(value);
  return undefined;
}

function under(root: string, candidate: unknown): boolean {
  const file = pathOf(candidate);
  if (file === undefined) return false;
  const resolved = path.resolve(file);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

/**
 * Runs `fn`, counting the publishing writes it makes under `root`, and — when
 * `crashAfter` is given — crashes it right after that many writes.
 *
 * Run once with `crashAfter: undefined` to learn how many writes a complete
 * run makes, then once per `k` in `1..writes` to visit every crash point.
 */
export function runWithCrashAfter<T>(root: string, crashAfter: number | undefined, fn: () => T): CrashStepOutcome<T> {
  const resolvedRoot = path.resolve(root);
  let writes = 0;
  let crashed = false;
  const originals = new Map<PublishingWrite, (...args: unknown[]) => unknown>();
  const exists = (candidate: unknown): boolean => {
    const file = pathOf(candidate);
    if (file === undefined) return false;
    try {
      fs.lstatSync(file);
      return true;
    } catch {
      return false;
    }
  };
  const touches = (method: PublishingWrite, args: unknown[]): boolean => {
    if (method === "renameSync" || method === "copyFileSync") {
      return under(resolvedRoot, args[0]) || under(resolvedRoot, args[1]);
    }
    if (!under(resolvedRoot, args[0])) return false;
    // Removing what is not there changes nothing a reader could see: the
    // `rm -f` of an already-renamed temp file is cleanup, not a step.
    if (method === "unlinkSync" || method === "rmSync" || method === "rmdirSync") return exists(args[0]);
    return true;
  };
  for (const method of PUBLISHING_WRITES) {
    const original = fs[method] as unknown as (...args: unknown[]) => unknown;
    originals.set(method, original);
    (fs as unknown as Record<string, unknown>)[method] = (...args: unknown[]): unknown => {
      if (!touches(method, args)) return original.apply(fs, args);
      if (crashed) throw new SimulatedCrash(crashAfter ?? writes);
      writes += 1;
      const result = original.apply(fs, args);
      if (crashAfter !== undefined && writes === crashAfter) {
        crashed = true;
        throw new SimulatedCrash(crashAfter);
      }
      return result;
    };
  }
  try {
    const value = fn();
    if (crashed) return Object.freeze({ kind: "crashed" as const, writes, swallowed: true });
    return Object.freeze({ kind: "completed" as const, value, writes });
  } catch (error) {
    if (crashed) return Object.freeze({ kind: "crashed" as const, writes, swallowed: false });
    return Object.freeze({ kind: "threw" as const, error, writes });
  } finally {
    for (const [method, original] of originals) {
      (fs as unknown as Record<string, unknown>)[method] = original;
    }
  }
}

/** How many publishing writes a complete run of `fn` makes under `root`. */
export function countPublishingWrites(root: string, fn: () => unknown): number {
  const outcome = runWithCrashAfter(root, undefined, fn);
  if (outcome.kind === "threw") throw outcome.error;
  return outcome.writes;
}

/**
 * Visits every crash point of a driver.
 *
 * `prepare` rebuilds the starting state (it runs before the counting run and
 * before every crash run), `run` is the driver, and `inspect` receives the
 * crash point and the outcome with the state directory frozen as the crash
 * left it. Returns the number of crash points visited.
 */
export function forEachCrashPoint<T>(input: Readonly<{
  root: string;
  prepare: () => void;
  run: () => T;
  inspect: (point: number, outcome: CrashStepOutcome<T>) => void;
}>): number {
  input.prepare();
  const total = countPublishingWrites(input.root, input.run);
  for (let point = 1; point <= total; point += 1) {
    input.prepare();
    input.inspect(point, runWithCrashAfter(input.root, point, input.run));
  }
  return total;
}
