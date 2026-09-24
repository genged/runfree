import os from "node:os";

import type { SpawnSyncReturns } from "node:child_process";

export type SpawnStatus = {
  status: number;
  timedOut?: true;
  signal?: NodeJS.Signals;
};

const TIMEOUT_STATUS = 124;

/**
 * Maps a `spawnSync` result to an exit status that fails closed.
 *
 * `result.status` alone is not an answer: when a `timeout` fires and the child
 * ignores SIGTERM, Node waits for it, and a child that then exits 0 yields
 * `{ status: 0, error: ETIMEDOUT }`. The same holds for an ENOBUFS overrun.
 * Any spawn error or terminating signal therefore yields a non-zero status, so
 * a caller that reads empty output as "absent" never sees an unfinished call
 * as a successful one.
 */
export function failClosedSpawnStatus(result: Pick<SpawnSyncReturns<unknown>, "status" | "signal" | "error">): SpawnStatus {
  const code = (result.error as NodeJS.ErrnoException | undefined)?.code;
  const timedOut = code === "ETIMEDOUT";
  const signal = result.signal ?? undefined;
  const diagnostics = { ...(timedOut ? { timedOut: true as const } : {}), ...(signal ? { signal } : {}) };
  if (!result.error && !signal) return { status: result.status ?? 1, ...diagnostics };
  if (typeof result.status === "number" && result.status !== 0) return { status: result.status, ...diagnostics };
  if (timedOut) return { status: TIMEOUT_STATUS, ...diagnostics };
  if (signal) return { status: 128 + (os.constants.signals[signal] ?? 0), ...diagnostics };
  return { status: 1, ...diagnostics };
}
