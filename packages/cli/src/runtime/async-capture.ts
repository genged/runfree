import * as childProcess from "node:child_process";

import { failClosedSpawnStatus } from "./spawn-status.ts";
import type { CaptureResult } from "./types.ts";

// spawnSync's default per-stream output bound.
const DEFAULT_MAX_BUFFER = 1024 * 1024;

/**
 * `spawnSync`'s timeout must be an integer, and deadline arithmetic produces
 * fractions; rounded up, as the sync capture does, so a bound is never
 * shortened.
 */
function integerTimeout(timeout: number | undefined): number | undefined {
  if (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout <= 0) return undefined;
  return Math.ceil(timeout);
}

/**
 * The asynchronous twin of the host `capture`: the same result for the same
 * call, so a caller can overlap independent subprocesses without changing how
 * it reads them.
 *
 * - `timeout` ends the child with `killSignal` and reports status 124
 *   (`timedOut`), whatever the child later exits with.
 * - Output past `maxBuffer` on either stream (default 1 MiB) ends the child
 *   with `killSignal`, as spawnSync's ENOBUFS does: status 128 + that signal
 *   when the kill ended the child, else 125. Never the child's own status.
 * - A child that cannot be spawned reports status 125.
 * - `input` is written to stdin, which is then closed.
 *
 * The status comes from `failClosedSpawnStatus`, the sync capture's mapping.
 * The promise never rejects.
 */
export function captureAsync(
  command: string,
  args: readonly string[],
  options: childProcess.SpawnSyncOptions = {},
): Promise<CaptureResult> {
  const { input, maxBuffer, timeout, killSignal, encoding: _encoding, stdio: _stdio, ...spawnOptions } = options;
  const bound = typeof maxBuffer === "number" && !Number.isNaN(maxBuffer) ? maxBuffer : DEFAULT_MAX_BUFFER;
  const signal = killSignal ?? "SIGTERM";
  return new Promise<CaptureResult>((resolve) => {
    let settled = false;
    let failure: NodeJS.ErrnoException | undefined;
    let timer: NodeJS.Timeout | undefined;
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const finish = (status: number | null, exitSignal: NodeJS.Signals | null): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({
        ...failClosedSpawnStatus({ status, signal: exitSignal, error: failure }),
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    };

    let child: childProcess.ChildProcess;
    try {
      child = childProcess.spawn(command, [...args], { ...spawnOptions, stdio: ["pipe", "pipe", "pipe"] });
    } catch (error) {
      // Invalid arguments throw synchronously; report them as a spawn failure.
      failure = error as NodeJS.ErrnoException;
      finish(null, null);
      return;
    }

    const fail = (code: "ETIMEDOUT" | "ENOBUFS"): void => {
      // The first failure decides the status, as spawnSync's single error does.
      if (!failure) failure = Object.assign(new Error(`${command} ${code}`), { code });
      try { child.kill(signal); } catch { /* already gone */ }
    };

    const collect = (chunks: Buffer[]) => {
      let length = 0;
      return (chunk: Buffer): void => {
        if (failure?.code === "ENOBUFS") return;
        const room = bound - length;
        if (chunk.length > room) {
          if (room > 0) chunks.push(chunk.subarray(0, room));
          length = bound;
          fail("ENOBUFS");
          return;
        }
        chunks.push(chunk);
        length += chunk.length;
      };
    };
    child.stdout?.on("data", collect(stdout));
    child.stderr?.on("data", collect(stderr));

    child.on("error", (error: NodeJS.ErrnoException) => {
      if (!failure) failure = error;
      // With no pid the child never started and no `close` is guaranteed.
      if (child.pid === undefined) finish(null, null);
    });
    child.on("close", (status, exitSignal) => finish(status, exitSignal));

    const limit = integerTimeout(timeout);
    if (limit !== undefined) timer = setTimeout(() => fail("ETIMEDOUT"), limit);

    // A child that exits without reading stdin closes the pipe under us.
    child.stdin?.on("error", () => {});
    if (input === undefined || input === null) child.stdin?.end();
    else child.stdin?.end(typeof input === "string" ? input : Buffer.from(input.buffer, input.byteOffset, input.byteLength));
  });
}
