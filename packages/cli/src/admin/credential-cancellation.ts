// Credential watch cancellation: a session that ends, a Ctrl-C, a parent that
// vanished, or a signal to the watcher stops the credential work it owns.
// Stopping is never a provider failure. Nothing here classifies a source or
// touches the proxy: callers check `assertActive()` before each effect, and
// a `CredentialCancellationError` unwinds them past every failure, removal and
// keep-last-good path.

import fs from "node:fs";
import net from "node:net";

import { deferSignalExit } from "../signal-exit.ts";

export type CredentialStopCause = "lifetime-closed" | "parent-gone" | "SIGINT" | "SIGTERM" | "SIGHUP";

/** The watch was stopped. Never a `TokenResolutionError`: it carries no source verdict. */
export class CredentialCancellationError extends Error {
  readonly stopCause: CredentialStopCause;

  constructor(stopCause: CredentialStopCause) {
    super(`credential watch stopped (${stopCause})`);
    this.name = "CredentialCancellationError";
    this.stopCause = stopCause;
  }
}

/**
 * A synchronous child (a provider or a Docker client) ended by SIGINT, SIGTERM
 * or SIGHUP. The synchronous code cannot tell a host cancellation from the
 * child's own signal, so it does not classify: the async caller decides after
 * `settleHostSignals()`. A Docker client's outcome stays unknown either way.
 */
export class ChildSignaledError extends Error {
  readonly childKind: "provider" | "proxy-client";
  readonly signal: NodeJS.Signals;
  /** A proxy token write's destination, when the child was its client. */
  readonly tokenName?: string;

  constructor(childKind: "provider" | "proxy-client", signal: NodeJS.Signals, tokenName?: string) {
    super(childKind === "proxy-client"
      ? `a proxy token operation ended by ${signal}; its outcome is unknown`
      : `a credential source ended by ${signal}`);
    this.name = "ChildSignaledError";
    this.childKind = childKind;
    this.signal = signal;
    if (tokenName !== undefined) this.tokenName = tokenName;
  }
}

const HOST_STOP_SIGNALS: ReadonlySet<string> = new Set(["SIGINT", "SIGTERM", "SIGHUP"]);

/** Whether a child that ended by `signal` may have been ended by a host stop. */
export function isHostStopSignal(signal: NodeJS.Signals | null | undefined): signal is NodeJS.Signals {
  return signal !== null && signal !== undefined && HOST_STOP_SIGNALS.has(signal);
}

/**
 * Lets a signal that arrived while a synchronous child blocked the event loop
 * reach its JS handler. Two immediates always span a poll phase, whichever
 * phase the caller continues in; one does not from an I/O callback (pinned by
 * signal-exit.test.ts).
 */
export async function settleHostSignals(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
  await new Promise<void>((resolve) => setImmediate(resolve));
}

export type CredentialLifetime = Readonly<{
  /** Aborted on the first stop cause. */
  signal: AbortSignal;
  /** Re-runs the pipe and parent probes; throws `CredentialCancellationError` once stopped. */
  assertActive(): void;
  /** The first stop cause, once stopped. */
  stopCause(): CredentialStopCause | undefined;
  /** Work `close()` must see settled before it resolves. */
  own<T>(work: Promise<T>): Promise<T>;
  /** Stops (if active), joins owned work, and disposes listeners. Never throws. */
  close(): Promise<void>;
}>;

export type CredentialLifetimeOptions = Readonly<{
  /** The inherited read end of the session's lifetime pipe; the parent never writes. */
  lifetimeFd?: number;
  /** Secondary liveness: the parent's PID. Never the only proof (PIDs are recycled). */
  parentAlive?: () => boolean;
  /** Process signals that stop the lifetime. */
  signals?: readonly NodeJS.Signals[];
}>;

const LIFETIME_STOP_SIGNALS: readonly NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];

// The read end, probed synchronously. The socket wrapper made the descriptor
// non-blocking, so a read while the parent still holds the write end fails
// with EAGAIN; end of file reads 0. Any other error is a lost pipe too.
function lifetimePipeEnded(fd: number): boolean {
  try {
    return fs.readSync(fd, Buffer.alloc(1), 0, 1, null) === 0;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "EAGAIN";
  }
}

/**
 * One lifetime per watch process. Transitions `active -> stopping` on the first
 * stop cause (lifetime pipe EOF/close/error, a stop signal, the parent PID
 * probe failing) and `stopping -> joined` in `close()`.
 */
export function createCredentialLifetime(options: CredentialLifetimeOptions = {}): CredentialLifetime {
  const controller = new AbortController();
  let cause: CredentialStopCause | undefined;
  const owned = new Set<Promise<unknown>>();
  const stop = (next: CredentialStopCause): void => {
    if (cause !== undefined) return;
    cause = next;
    controller.abort(new CredentialCancellationError(next));
  };

  // Read through a socket, not a read stream: an fs stream on an inherited
  // pipe keeps `process.exit()` from completing while the parent holds the
  // write end, so a signalled watcher would never exit.
  let socket: net.Socket | undefined;
  let socketOpen = false;
  if (options.lifetimeFd !== undefined) {
    try {
      socket = new net.Socket({ fd: options.lifetimeFd, readable: true, writable: false });
      socketOpen = true;
      // Once the socket has seen the end the probe never runs again: the fd
      // number may by then belong to another descriptor.
      const ended = (): void => {
        socketOpen = false;
        stop("lifetime-closed");
      };
      socket.on("end", ended);
      socket.on("close", ended);
      socket.on("error", ended);
      // The parent never writes; whatever arrives is discarded.
      socket.resume();
    } catch {
      stop("lifetime-closed");
    }
  }

  const signalRelease = deferSignalExit();
  const onSignal = new Map<NodeJS.Signals, () => void>();
  for (const name of options.signals ?? LIFETIME_STOP_SIGNALS) {
    const listener = (): void => stop(name as CredentialStopCause);
    onSignal.set(name, listener);
    process.on(name, listener);
  }

  const probe = (): void => {
    if (cause !== undefined) return;
    if (socketOpen && options.lifetimeFd !== undefined && lifetimePipeEnded(options.lifetimeFd)) {
      stop("lifetime-closed");
      return;
    }
    if (options.parentAlive && !options.parentAlive()) stop("parent-gone");
  };

  let closing: Promise<void> | undefined;
  return Object.freeze({
    signal: controller.signal,
    assertActive(): void {
      probe();
      if (cause !== undefined) throw new CredentialCancellationError(cause);
    },
    stopCause: () => cause,
    own<T>(work: Promise<T>): Promise<T> {
      owned.add(work);
      const forget = (): void => {
        owned.delete(work);
      };
      work.then(forget, forget);
      return work;
    },
    close(): Promise<void> {
      closing ??= (async () => {
        // A close without a prior cause is the watch ending on its own; owned
        // work is still told to stop.
        if (cause === undefined) {
          cause = "lifetime-closed";
          controller.abort(new CredentialCancellationError(cause));
        }
        while (owned.size > 0) await Promise.allSettled([...owned]);
        socketOpen = false;
        socket?.destroy();
        for (const [name, listener] of onSignal) process.off(name, listener);
        onSignal.clear();
        signalRelease();
      })();
      return closing;
    },
  });
}
