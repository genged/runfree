import os from "node:os";

import type { SpawnSyncReturns } from "node:child_process";

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
 * - any other spawn error (ENOENT, ENOBUFS, ...) is 125.
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
