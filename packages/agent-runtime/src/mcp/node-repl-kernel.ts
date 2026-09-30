// The node-repl kernel: one child process per server process, spawned by the
// server with the agent user's rights and the server's working directory. It
// evaluates code cells in its own global scope so state persists across cells:
// top-level `var`, `let`, `const`, and `globalThis` assignments stay defined.
// A cell that uses top-level `await` runs as an async function body instead;
// its own declarations are local to that cell, so it keeps state on
// `globalThis`, and it can `return` a value.
//
// All output reaches the server through the IPC channel, in order with the
// cell's completion. The server enforces the time limit by killing this
// process; the kernel only bounds how much output it sends for one cell.

import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import vm from "node:vm";

import { NODE_REPL_LIMITS, NODE_REPL_MESSAGES } from "./capabilities.ts";
import { isKernelRunRequest, type KernelToServerMessage } from "./kernel-protocol.ts";

const cwd = process.cwd();
// The server creates the scratch directory and removes it when this process
// exits, including after a timeout kill.
const tmpDir = process.env.RUNFREE_NODE_REPL_TMPDIR ?? fs.mkdtempSync(path.join(os.tmpdir(), "runfree-node-repl-"));
delete process.env.RUNFREE_NODE_REPL_TMPDIR;

let currentId: number | undefined;
let sentBytes = 0;
let truncated = false;
let cellCounter = 0;

// Capture the IPC sender and hide it from cell code, so an ordinary cell cannot
// send unbounded messages to the server. (Cell code runs as the agent user and
// could still reach the channel another way; that only exhausts the agent's
// own server, which the agent could do anyway.)
const ipcSend = typeof process.send === "function" ? process.send.bind(process) : undefined;
delete (process as { send?: unknown }).send;

function send(message: KernelToServerMessage): void {
  if (ipcSend && process.connected) ipcSend(message);
}

/** Caps a string at the per-call output limit (UTF-8 bytes). */
function capText(text: string): string {
  if (Buffer.byteLength(text, "utf8") <= NODE_REPL_LIMITS.maxOutputBytes) return text;
  const prefix = Buffer.from(text, "utf8").subarray(0, NODE_REPL_LIMITS.maxOutputBytes).toString("utf8").replace(/\uFFFD$/, "");
  return `${prefix}\n${NODE_REPL_MESSAGES.truncated}`;
}

function emit(text: string): void {
  if (text === "") return;
  // Output from timers or promises that settle after their cell completes is
  // attributed to id -1; the server drops it.
  const id = currentId ?? -1;
  if (truncated) return;
  const bytes = Buffer.byteLength(text, "utf8");
  if (sentBytes + bytes > NODE_REPL_LIMITS.maxOutputBytes) {
    truncated = true;
    send({ type: "output", id, text: `\n${NODE_REPL_MESSAGES.truncated}\n` });
    return;
  }
  sentBytes += bytes;
  send({ type: "output", id, text });
}

function formatValue(value: unknown): string {
  if (typeof value === "string") return value;
  return util.inspect(value, { depth: 6, maxArrayLength: 200, maxStringLength: NODE_REPL_LIMITS.maxOutputBytes, breakLength: 120 });
}

function formatArgs(args: unknown[]): string {
  return `${util.formatWithOptions({ depth: 6, maxArrayLength: 200, breakLength: 120 }, ...args)}\n`;
}

function formatError(error: unknown): string {
  if (error instanceof Error) return error.stack ?? `${error.name}: ${error.message}`;
  return `Uncaught ${formatValue(error)}`;
}

// The kernel's own stdout and stderr stay available to subprocesses the cell
// starts; console and direct process.stdout/stderr writes from cell code are
// routed through IPC so they stay ordered with the cell's completion.
for (const method of ["log", "info", "debug", "warn", "error", "trace"] as const) {
  console[method] = (...args: unknown[]) => emit(formatArgs(args));
}
console.dir = (value: unknown) => emit(`${formatValue(value)}\n`);
for (const stream of [process.stdout, process.stderr]) {
  stream.write = ((chunk: unknown, encoding?: unknown, callback?: unknown) => {
    const text = typeof chunk === "string" ? chunk : Buffer.isBuffer(chunk) || chunk instanceof Uint8Array ? Buffer.from(chunk).toString("utf8") : String(chunk);
    emit(text);
    const done = typeof encoding === "function" ? encoding : callback;
    if (typeof done === "function") queueMicrotask(() => (done as () => void)());
    return true;
  }) as typeof stream.write;
}

process.on("uncaughtException", (error) => emit(`${formatError(error)}\n`));
process.on("unhandledRejection", (reason) => emit(`Unhandled rejection: ${formatError(reason)}\n`));

const nodeRepl = Object.freeze({
  cwd,
  tmpDir,
  write(value: unknown): void {
    emit(formatValue(value));
  },
});

Object.defineProperty(globalThis, "nodeRepl", { value: nodeRepl, enumerable: false, configurable: false, writable: false });
Object.defineProperty(globalThis, "require", {
  value: createRequire(path.join(cwd, "noop.js")),
  enumerable: false,
  configurable: true,
  writable: true,
});

function compile(code: string, filename: string): { script: vm.Script; async: boolean } {
  const options = {
    filename,
    importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
  };
  try {
    return { script: new vm.Script(code, options), async: false };
  } catch (error) {
    if (!(error instanceof SyntaxError) || !/\bawait\b|\breturn\b/.test(code)) throw error;
    try {
      return { script: new vm.Script(`(async () => {\n${code}\n})()`, options), async: true };
    } catch {
      // Report the error against the cell as written.
      throw error;
    }
  }
}

async function runCell(id: number, code: string): Promise<void> {
  currentId = id;
  sentBytes = 0;
  truncated = false;
  cellCounter += 1;
  const filename = path.join(cwd, `[node-repl cell ${cellCounter}]`);
  try {
    const { script } = compile(code, filename);
    let value: unknown = script.runInThisContext({ displayErrors: true });
    if (value instanceof Promise) value = await value;
    send({ type: "done", id, ok: true, ...(value === undefined ? {} : { value: capText(formatValue(value)) }) });
  } catch (error) {
    send({ type: "done", id, ok: false, error: capText(formatError(error)) });
  } finally {
    currentId = undefined;
  }
}

// Cells run one at a time; the server never sends a second cell before the
// first completes, and a queue keeps that true even if it did.
let queue: Promise<void> = Promise.resolve();
process.on("message", (message: unknown) => {
  if (!isKernelRunRequest(message)) return;
  queue = queue.then(() => runCell(message.id, message.code));
});

// Whether this process leads its own process group (the server spawns it
// detached). Read from /proc so a kernel started some other way never signals
// a group it does not own.
function leadsOwnProcessGroup(): boolean {
  try {
    const stat = fs.readFileSync("/proc/self/stat", "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return Number(fields[2]) === process.pid;
  } catch {
    return false;
  }
}

// The server going away ends the kernel, its scratch directory, and the
// processes in its process group.
process.on("disconnect", () => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  if (leadsOwnProcessGroup()) {
    try {
      process.kill(0, "SIGKILL");
    } catch {
      // Fall through to a plain exit.
    }
  }
  process.exit(0);
});
