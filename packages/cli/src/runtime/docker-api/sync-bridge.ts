import { MessageChannel, receiveMessageOnPort, Worker } from "node:worker_threads";

import { DOCKER_API_WORKER_SOURCE } from "./worker.ts";

export type BridgeRequest = {
  socketPath: string;
  method: "GET" | "POST";
  path: string;
  headers: Record<string, string>;
  body?: Uint8Array;
  /** Hijack the connection (`Connection: Upgrade`), write `stdin`, then half-close. */
  upgrade?: { stdin?: Uint8Array };
  /** Reply bytes past this abort the request and answer `overflow`. */
  maxBytes: number;
};

export type BridgeReply =
  | { kind: "response"; status: number; headers: Record<string, string>; body: Buffer }
  | { kind: "upgraded"; status: number; headers: Record<string, string>; body: Buffer }
  /** `connect`: nothing reached the daemon. `request`/`stream`: it may have. */
  | { kind: "error"; code: string; phase: "connect" | "request" | "stream" }
  | { kind: "overflow" }
  | { kind: "timeout" }
  /** The worker thread is gone; the bridge refuses every later call. */
  | { kind: "dead" };

export type SyncBridge = {
  /** Blocks the calling thread until the reply or `deadline` (a `performance.now()` value). */
  request(req: BridgeRequest, deadline: number): BridgeReply;
  isDead(): boolean;
};

type WorkerMessage = { kind: string; status?: unknown; headers?: unknown; body?: unknown; code?: unknown; phase?: unknown };

function toReply(message: WorkerMessage): BridgeReply {
  switch (message.kind) {
    case "response":
    case "upgraded": {
      const body = message.body instanceof Uint8Array ? Buffer.from(message.body.buffer, message.body.byteOffset, message.body.byteLength) : Buffer.alloc(0);
      const headers = typeof message.headers === "object" && message.headers !== null ? message.headers as Record<string, string> : {};
      return { kind: message.kind, status: typeof message.status === "number" ? message.status : 0, headers, body };
    }
    case "error": {
      const phase = message.phase === "connect" || message.phase === "stream" ? message.phase : "request";
      return { kind: "error", code: typeof message.code === "string" ? message.code : "EUNKNOWN", phase };
    }
    case "overflow":
      return { kind: "overflow" };
    default:
      return { kind: "error", code: "EBADREPLY", phase: "request" };
  }
}

/**
 * A synchronous facade over one worker thread that does the socket I/O.
 *
 * The caller's thread posts the request, then sleeps in `Atomics.wait` on the
 * completion counter until the worker replies or the deadline passes. At the
 * deadline it tells the worker to destroy the request and returns `timeout`;
 * there is no child process that could ignore a signal, so a routed call can
 * never outlive its budget by more than the wake-up latency. The worker is
 * started lazily on the first request and unref'd, so it never keeps the CLI
 * process alive.
 */
export function createSyncBridge(options: { workerSource?: string } = {}): SyncBridge {
  let worker: Worker | undefined;
  let control: Int32Array | undefined;
  let dead = false;
  let nextId = 1;

  const ensureWorker = (): Int32Array | undefined => {
    if (dead) return undefined;
    if (worker && control) return control;
    try {
      control = new Int32Array(new SharedArrayBuffer(8));
      worker = new Worker(options.workerSource ?? DOCKER_API_WORKER_SOURCE, { eval: true, stdout: false, stderr: false });
      worker.unref();
      // An `error` event only arrives when this thread next runs its event
      // loop; the worker's own exit hook sets the dead flag for the blocked
      // path. This listener just keeps an uncaught worker error from
      // becoming a process-level crash.
      worker.on("error", () => {
        dead = true;
      });
      worker.postMessage({ type: "init", ctl: control });
      return control;
    } catch {
      dead = true;
      return undefined;
    }
  };

  return {
    isDead: () => dead || (control !== undefined && Atomics.load(control, 1) === 1),
    request(req, deadline) {
      const ctl = ensureWorker();
      if (!ctl || !worker || Atomics.load(ctl, 1) === 1) {
        dead = true;
        return { kind: "dead" };
      }
      const id = nextId++;
      const { port1, port2 } = new MessageChannel();
      try {
        const seen = Atomics.load(ctl, 0);
        worker.postMessage({ type: "request", id, port: port2, req }, [port2]);
        let observed = seen;
        for (;;) {
          const received = receiveMessageOnPort(port1);
          if (received) return toReply(received.message as WorkerMessage);
          if (Atomics.load(ctl, 1) === 1) {
            dead = true;
            return { kind: "dead" };
          }
          const remaining = deadline - performance.now();
          if (remaining <= 0) {
            worker.postMessage({ type: "abort", id });
            return { kind: "timeout" };
          }
          // Sleep until the counter moves past the last value this call saw.
          // A counter bump without a message on this port (a late reply to an
          // earlier, timed-out call) just loops.
          Atomics.wait(ctl, 0, observed, Math.ceil(remaining));
          observed = Atomics.load(ctl, 0);
        }
      } finally {
        port1.close();
      }
    },
  };
}
