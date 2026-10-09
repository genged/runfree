import os from "node:os";

import type { SpawnSyncOptions, SpawnSyncReturns } from "node:child_process";

export type SpawnStatus = {
  status: number;
  timedOut?: true;
  signal?: NodeJS.Signals;
};

// Reserved statuses. None of them is 1, which many callers read as a definite
// "no" (git's "not found", grep's "no match"); an unfinished call must never
// look like that answer.
const TIMEOUT_STATUS = 124;
const SPAWN_ERROR_STATUS = 125;

/**
 * Maps a `spawnSync` result to an exit status that fails closed.
 *
 * `result.status` alone is not an answer: when a `timeout` fires and the child
 * ignores SIGTERM, Node waits for it, and the child's later exit code (0, 1,
 * anything) is reported as `status` beside `error: ETIMEDOUT`. The same holds
 * for an ENOBUFS overrun. So the child's own status is used only when the call
 * finished cleanly; otherwise:
 * - a timeout is always 124 (`timedOut: true`);
 * - a terminating signal is 128 + its number (`signal` set);
 * - any other spawn error (ENOENT, ...) is 125.
 * An ENOBUFS overrun is reported beside the `killSignal` that ended the
 * child, so it is 128 + that signal; only an overrun by a child that had
 * already exited, with no signal, is 125.
 * Output from such a call is not an answer either.
 */
export function failClosedSpawnStatus(result: Pick<SpawnSyncReturns<unknown>, "status" | "signal" | "error">): SpawnStatus {
  const code = (result.error as NodeJS.ErrnoException | undefined)?.code;
  const timedOut = code === "ETIMEDOUT";
  const signal = result.signal ?? undefined;
  const diagnostics = { ...(timedOut ? { timedOut: true as const } : {}), ...(signal ? { signal } : {}) };
  if (timedOut) return { status: TIMEOUT_STATUS, ...diagnostics };
  if (signal) return { status: 128 + (os.constants.signals[signal] ?? 0), ...diagnostics };
  if (result.error) return { status: SPAWN_ERROR_STATUS, ...diagnostics };
  return { status: result.status ?? SPAWN_ERROR_STATUS, ...diagnostics };
}

/**
 * `spawnSync` throws on a fractional `timeout`, and deadline arithmetic on the
 * monotonic clock produces one. Rounded up, so a bound is never shortened.
 */
export function integerSpawnTimeout<T extends { timeout?: number }>(options: T): T {
  const { timeout } = options;
  return typeof timeout === "number" && Number.isFinite(timeout) && !Number.isInteger(timeout)
    ? { ...options, timeout: Math.ceil(timeout) }
    : options;
}

const SIGNAL_NUMBERS = new Set<number>(Object.values(os.constants.signals));

function outOfRange(name: string, value: unknown): NodeJS.ErrnoException {
  return Object.assign(new RangeError(`spawn option ${name} is out of range: ${String(value)}`), { code: "ERR_OUT_OF_RANGE" });
}

/**
 * The options `spawnSync` refuses before spawning, as an error, or undefined
 * when they are valid. A capture that cannot rely on `spawnSync` to throw
 * (the async capture) checks this first, so an invalid bound is never read as
 * "no bound": a NaN, infinite, or negative `timeout`, a NaN or negative
 * `maxBuffer`, or an unknown `killSignal`. A zero or absent `timeout` means no
 * timeout, as it does for `spawnSync`; a fractional one is valid, since it is
 * rounded up by `integerSpawnTimeout`.
 */
export function spawnOptionsRefusal(options: Pick<SpawnSyncOptions, "timeout" | "maxBuffer" | "killSignal">): NodeJS.ErrnoException | undefined {
  const { timeout, maxBuffer, killSignal } = options;
  if (timeout !== undefined && (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout < 0)) {
    return outOfRange("timeout", timeout);
  }
  if (maxBuffer !== undefined && (typeof maxBuffer !== "number" || Number.isNaN(maxBuffer) || maxBuffer < 0)) {
    return outOfRange("maxBuffer", maxBuffer);
  }
  if (killSignal !== undefined && !(typeof killSignal === "string"
    ? Object.hasOwn(os.constants.signals, killSignal)
    : typeof killSignal === "number" && killSignal > 0 && SIGNAL_NUMBERS.has(killSignal))) {
    return Object.assign(new TypeError(`unknown kill signal: ${String(killSignal)}`), { code: "ERR_UNKNOWN_SIGNAL" });
  }
  return undefined;
}
