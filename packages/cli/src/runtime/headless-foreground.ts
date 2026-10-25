// The output-capturing foreground spawner for a headless run (headless-run
// spec §3.1 "drain", plan Task 9).
//
// It plugs into the admission driver as `foregroundSpawner`, so the start
// (`docker start --attach`) and every re-attach (`docker attach --no-stdin`)
// go through it. It ignores the `stdio: "inherit"` the driver passes and
// spawns with no stdin and both output streams piped, so the host terminal is
// never the agent's and the agent's output reaches the run record.
//
// The Docker child's `exit` can come before its last stdout chunk
// (`session-container-start.ts:181`), so exit is never the drain signal:
// `drain(boundMs)` waits for EOF and `close` on every captured stream and the
// sinks' own flush, all within one bound. A broken stream, a sink failure, a
// re-attach that could not be ordered after the stream before it, or the
// bound passing all report `drained: false`, which the outcome rule turns
// into `unverified`. An undrained capture SIGKILLs any client still running
// and destroys every pipe, so a client wedged on the daemon cannot keep the
// process alive.
//
// Every termination of a captured client is SIGKILL, whatever signal the
// caller names. Without a TTY, `docker start --attach` and `docker attach`
// proxy a caught SIGTERM to the container, so the driver's detach (sent even
// when a failed session-file delete kept the container running for
// revocation) would stop it. SIGKILL cannot be caught, so only the local
// client dies.

import * as childProcess from "node:child_process";
import type { Readable } from "node:stream";

import type {
  SessionContainerForegroundChild,
  SessionContainerForegroundSpawner,
} from "./session-container-start.ts";

export type HeadlessPipedChild = SessionContainerForegroundChild & Readonly<{
  stdout: Readable | null;
  stderr: Readable | null;
  kill(signal: "SIGTERM" | "SIGKILL"): boolean;
}>;

export type HeadlessPipedSpawn = (
  executable: "docker",
  args: readonly string[],
  options: Readonly<{
    shell: false;
    stdio: readonly ["ignore", "pipe", "pipe"];
    env: Readonly<Record<string, string>>;
  }>,
) => HeadlessPipedChild;

export type HeadlessForegroundSinks = Readonly<{
  stdout(chunk: Buffer): void;
  stderr(chunk: Buffer): void;
  /** One captured stdout stream reached EOF (the parser's `endStream`). */
  stdoutEnded?(): void;
  /** The record writes are done; awaited inside the drain bound. */
  flush?(): Promise<void>;
}>;

export type HeadlessForegroundCapture = Readonly<{
  spawn: SessionContainerForegroundSpawner;
  drain(boundMs: number): Promise<Readonly<{ drained: boolean }>>;
  /** A second or later foreground child was spawned (a re-attach). */
  reattached(): boolean;
}>;

/** How long a re-attach's stdout waits for the stream before it to close. */
export const HEADLESS_REATTACH_ORDER_BOUND_MS = 5_000;

const PIPED_STDIO = Object.freeze(["ignore", "pipe", "pipe"] as const);

function defaultPipedSpawn(
  executable: "docker",
  args: readonly string[],
  options: Parameters<HeadlessPipedSpawn>[2],
): HeadlessPipedChild {
  return childProcess.spawn(executable, [...args], {
    env: options.env,
    shell: false,
    stdio: [...options.stdio],
  }) as unknown as HeadlessPipedChild;
}

/** Resolves once `stream` closed: `true` only after a clean EOF with no error. */
function streamClosed(stream: Readable | null): Promise<boolean> {
  if (!stream) return Promise.resolve(false);
  return new Promise<boolean>((resolve) => {
    let ended = false;
    let failed = false;
    stream.once("end", () => {
      ended = true;
    });
    stream.on("error", () => {
      failed = true;
    });
    stream.once("close", () => resolve(ended && !failed));
  });
}

function boundedDelay(ms: number): Promise<"bound"> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve("bound"), ms);
    timer.unref();
  });
}

export function createHeadlessForegroundSpawner(
  sinks: HeadlessForegroundSinks,
  options: Readonly<{ spawnProcess?: HeadlessPipedSpawn; orderBoundMs?: number }> = {},
): HeadlessForegroundCapture {
  const spawnProcess = options.spawnProcess ?? defaultPipedSpawn;
  const orderBoundMs = options.orderBoundMs ?? HEADLESS_REATTACH_ORDER_BOUND_MS;
  const streams: Promise<boolean>[] = [];
  const children: HeadlessPipedChild[] = [];
  let spawned = 0;
  let healthy = true;
  // Closes when the latest stdout stream closed; a re-attach's stdout is
  // consumed only after it, so its bytes always follow the earlier stream's.
  let previousStdout: Promise<boolean> = Promise.resolve(true);

  const guarded = (sink: (chunk: Buffer) => void) => (chunk: Buffer): void => {
    try {
      sink(chunk);
    } catch {
      healthy = false;
    }
  };
  const onStdout = guarded((chunk) => sinks.stdout(chunk));
  const onStderr = guarded((chunk) => sinks.stderr(chunk));

  const spawn: SessionContainerForegroundSpawner = (executable, args, spawnOptions) => {
    const child = spawnProcess(executable, args, { env: spawnOptions.env, shell: false, stdio: PIPED_STDIO });
    const killClient = child.kill.bind(child);
    Object.defineProperty(child, "kill", { value: (): boolean => killClient("SIGKILL") });
    spawned += 1;
    children.push(child);
    const { stdout, stderr } = child;
    const stdoutClosed = streamClosed(stdout);
    streams.push(stdoutClosed, streamClosed(stderr));
    stderr?.on("data", onStderr);
    if (stdout) {
      stdout.once("end", () => {
        try {
          sinks.stdoutEnded?.();
        } catch {
          healthy = false;
        }
      });
      const gate = previousStdout;
      const consume = (): void => {
        stdout.on("data", onStdout);
      };
      if (spawned === 1) {
        consume();
      } else {
        // Left paused, the pipe applies backpressure, so the wait is bounded
        // in memory as well as in time.
        void Promise.race([gate, boundedDelay(orderBoundMs)]).then((closed) => {
          if (closed !== true) healthy = false;
          consume();
        });
      }
    }
    previousStdout = stdoutClosed;
    return child;
  };

  return Object.freeze({
    spawn,
    async drain(boundMs: number): Promise<Readonly<{ drained: boolean }>> {
      if (spawned === 0) return { drained: false };
      const settled = (async (): Promise<boolean> => {
        const closed = await Promise.all(streams);
        if (!closed.every(Boolean)) return false;
        try {
          await sinks.flush?.();
        } catch {
          return false;
        }
        return true;
      })();
      const result = await Promise.race([settled, boundedDelay(boundMs)]);
      if (result !== true) {
        // An undrained client may be wedged on an unresponsive daemon, past
        // the SIGTERM the teardown sent: kill it and close its pipes, so
        // neither keeps this process alive after the run returns its code.
        for (const child of children) {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
          child.stdout?.destroy();
          child.stderr?.destroy();
        }
      }
      return { drained: result === true && healthy };
    },
    reattached: () => spawned > 1,
  });
}
