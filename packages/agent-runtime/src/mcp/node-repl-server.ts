// The portable `node-repl` MCP server. It speaks MCP over stdio and exposes a
// tool surface compatible with the Codex Desktop `node_repl` server: `js` runs
// JavaScript in a persistent kernel and `js_reset` discards the kernel.
//
// It runs inside the untrusted agent container as the agent user. It adds no
// authority: the kernel is an ordinary child process with the agent's mounts,
// network policy, and environment (placeholders only; real proxy-managed
// credentials never reach the agent).

import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { type CallToolResult, CallToolRequestSchema, ListToolsRequestSchema, type Tool } from "@modelcontextprotocol/sdk/types.js";

import { NODE_REPL_LIMITS, NODE_REPL_MESSAGES, RUNFREE_MCP_BUNDLE_VERSION } from "./capabilities.ts";
import { isKernelToServerMessage, type KernelRunRequest } from "./kernel-protocol.ts";

export const NODE_REPL_SERVER_NAME = "runfree-node-repl";

const JS_TOOL: Tool = {
  name: "js",
  description: [
    "Run JavaScript in a persistent Node.js kernel inside the Runfree agent container.",
    "State persists across calls: top-level declarations and globalThis properties stay defined until js_reset or a timeout.",
    "Return output with nodeRepl.write(value); console output and the value of the last expression are returned too.",
    "A cell that uses top-level await runs as an async function body: its own declarations do not persist and its last expression is not returned, so keep state on globalThis and use return or nodeRepl.write for a value.",
    "Redeclaring a top-level let, const, or class from an earlier call is a SyntaxError; assign to it or use var instead.",
    "nodeRepl.cwd is the session workspace and nodeRepl.tmpDir is a private scratch directory.",
    "The kernel runs as the agent user with the agent's files and network policy; host applications are not reachable.",
  ].join(" "),
  inputSchema: {
    type: "object",
    properties: {
      code: { type: "string", description: `JavaScript source, at most ${NODE_REPL_LIMITS.maxCodeBytes} UTF-8 bytes.` },
      timeout_ms: {
        type: "integer",
        minimum: 1,
        maximum: NODE_REPL_LIMITS.maxTimeoutMs,
        description: `Time limit in milliseconds (default ${NODE_REPL_LIMITS.defaultTimeoutMs}). On timeout the kernel is reset.`,
      },
      title: { type: "string", maxLength: NODE_REPL_LIMITS.maxTitleChars, description: "Optional short label for the call." },
    },
    required: ["code"],
    additionalProperties: false,
  },
};

const JS_RESET_TOOL: Tool = {
  name: "js_reset",
  description: "Discard the JavaScript kernel and all of its state. The next js call starts a new kernel.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
};

export const NODE_REPL_TOOLS: readonly Tool[] = Object.freeze([JS_TOOL, JS_RESET_TOOL]);

export type JsArguments = { code: string; timeoutMs: number };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validates `js` arguments; returns an error message instead of throwing. */
export function parseJsArguments(value: unknown): JsArguments | string {
  const args = value === undefined ? {} : value;
  if (!isRecord(args)) return "js arguments must be an object";
  for (const key of Object.keys(args)) {
    if (key !== "code" && key !== "timeout_ms" && key !== "title") return `js does not accept argument ${JSON.stringify(key)}`;
  }
  if (typeof args.code !== "string") return "js requires a string code argument";
  if (Buffer.byteLength(args.code, "utf8") > NODE_REPL_LIMITS.maxCodeBytes) {
    return `js code exceeds ${NODE_REPL_LIMITS.maxCodeBytes} bytes`;
  }
  if (args.title !== undefined && (typeof args.title !== "string" || args.title.length > NODE_REPL_LIMITS.maxTitleChars)) {
    return `js title must be a string of at most ${NODE_REPL_LIMITS.maxTitleChars} characters`;
  }
  let timeoutMs: number = NODE_REPL_LIMITS.defaultTimeoutMs;
  if (args.timeout_ms !== undefined) {
    if (typeof args.timeout_ms !== "number" || !Number.isInteger(args.timeout_ms)
      || args.timeout_ms < 1 || args.timeout_ms > NODE_REPL_LIMITS.maxTimeoutMs) {
      return `js timeout_ms must be an integer from 1 to ${NODE_REPL_LIMITS.maxTimeoutMs}`;
    }
    timeoutMs = args.timeout_ms;
  }
  return { code: args.code, timeoutMs };
}

/** Collects output for one call and caps it at maxOutputBytes UTF-8 bytes. */
export class BoundedOutput {
  private readonly chunks: string[] = [];
  private bytes = 0;
  private truncated = false;

  constructor(private readonly limit = NODE_REPL_LIMITS.maxOutputBytes) {}

  append(text: string): void {
    if (this.truncated || text === "") return;
    const size = Buffer.byteLength(text, "utf8");
    if (this.bytes + size <= this.limit) {
      this.chunks.push(text);
      this.bytes += size;
      return;
    }
    const room = this.limit - this.bytes;
    if (room > 0) {
      // Cut on a character boundary: decoding a byte prefix may end in a
      // partial character, which the decoder turns into U+FFFD; drop it.
      const prefix = Buffer.from(text, "utf8").subarray(0, room).toString("utf8").replace(/\uFFFD$/, "");
      this.chunks.push(prefix);
      this.bytes += Buffer.byteLength(prefix, "utf8");
    }
    this.truncated = true;
  }

  text(): string {
    const body = this.chunks.join("");
    return this.truncated ? `${body}${body.endsWith("\n") || body === "" ? "" : "\n"}${NODE_REPL_MESSAGES.truncated}` : body;
  }
}

type PendingCell = {
  child: ChildProcess;
  id: number;
  output: BoundedOutput;
  settle: (result: CallToolResult) => void;
  timer: NodeJS.Timeout;
};

function textResult(text: string, isError = false): CallToolResult {
  return { content: [{ type: "text", text }], ...(isError ? { isError: true } : {}) };
}

function appendLine(output: BoundedOutput, text: string): void {
  const body = output.text();
  output.append(`${body === "" || body.endsWith("\n") ? "" : "\n"}${text}`);
}

export type NodeReplKernelHostOptions = {
  cwd: string;
  kernelPath: string;
  nodePath?: string;
  // V8 old-space cap for the kernel, in MiB.
  maxOldSpaceMb?: number;
};

// At most one running call and one waiting call. More concurrent calls are
// refused instead of queued without bound.
const MAX_CALLS_IN_FLIGHT = 2;

/** Owns one kernel child process at a time and runs cells in it serially. */
export class NodeReplKernelHost {
  private child: ChildProcess | undefined;
  private pending: PendingCell | undefined;
  private nextId = 1;
  private inFlight = 0;
  private queue: Promise<unknown> = Promise.resolve();
  // Why a kernel was killed, reported to the cell that was running in it.
  private readonly killReasons = new WeakMap<ChildProcess, string>();

  constructor(private readonly options: NodeReplKernelHostOptions) {}

  run(code: string, timeoutMs: number, signal?: AbortSignal): Promise<CallToolResult> {
    if (this.inFlight >= MAX_CALLS_IN_FLIGHT) {
      return Promise.resolve(textResult("js is busy: one call is running and one is waiting; retry later or call js_reset", true));
    }
    this.inFlight += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      this.inFlight -= 1;
    };
    let started = false;
    const next = this.queue.then(() => {
      started = true;
      if (signal?.aborted) return textResult("js call was cancelled before it started", true);
      return this.runNow(code, timeoutMs, signal);
    });
    this.queue = next.catch(() => undefined);
    // A call cancelled while it waits frees its slot at once; it still reaches
    // the queue head later and returns without running.
    const cancelledWhileWaiting = new Promise<CallToolResult>((resolve) => {
      signal?.addEventListener("abort", () => {
        if (started) return;
        release();
        resolve(textResult("js call was cancelled before it started", true));
      }, { once: true });
    });
    return Promise.race([next, cancelledWhileWaiting]).finally(release);
  }

  /** Kills the kernel now, including a running cell, and discards its state. */
  async reset(): Promise<CallToolResult> {
    await this.killKernel(NODE_REPL_MESSAGES.reset);
    return textResult(NODE_REPL_MESSAGES.reset);
  }

  async close(): Promise<void> {
    await this.killKernel("js server is shutting down");
  }

  private ensureKernel(): ChildProcess {
    if (this.child && this.child.exitCode === null && this.child.signalCode === null) return this.child;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-node-repl-"));
    const child = spawn(this.options.nodePath ?? process.execPath, [
      `--max-old-space-size=${this.options.maxOldSpaceMb ?? 2048}`,
      this.options.kernelPath,
    ], {
      cwd: this.options.cwd,
      env: { ...process.env, RUNFREE_NODE_REPL_TMPDIR: tmpDir },
      // stdin is never the server's stdin, which carries MCP requests.
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      serialization: "json",
      // Own process group, so a reset or timeout also kills the processes the
      // cell started in that group (a cell that starts its own session or
      // group with setsid or `detached` escapes it).
      detached: true,
    });
    this.child = child;
    // Output a cell's subprocesses write straight to the kernel's stdout or
    // stderr is attributed to the running cell; anything else is dropped.
    const onRaw = (chunk: string) => {
      if (this.pending?.child === child) this.pending.output.append(chunk);
    };
    // Decode as streams so a character split across chunks stays whole.
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", onRaw);
    child.stderr?.on("data", onRaw);
    child.on("message", (message: unknown) => {
      if (!isKernelToServerMessage(message)) return;
      const pending = this.pending;
      if (!pending || pending.child !== child || message.id !== pending.id) return;
      if (message.type === "output") {
        pending.output.append(message.text);
        return;
      }
      if (message.value !== undefined) appendLine(pending.output, message.value);
      if (!message.ok) appendLine(pending.output, message.error ?? "js execution failed");
      this.finish(pending, textResult(pending.output.text(), !message.ok));
    });
    child.on("exit", (code, signal) => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      if (this.child === child) this.child = undefined;
      const pending = this.pending;
      if (!pending || pending.child !== child) return;
      const reason = this.killReasons.get(child)
        ?? `js kernel exited unexpectedly (${signal ? `signal ${signal}` : `exit code ${code}`}); kernel state was lost; the next js call starts a new kernel`;
      appendLine(pending.output, reason);
      this.finish(pending, textResult(pending.output.text(), true));
    });
    child.on("error", (error) => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      const pending = this.pending;
      if (pending && pending.child === child) {
        this.child = undefined;
        this.finish(pending, textResult(`js kernel could not start: ${error.message}`, true));
      }
    });
    return child;
  }

  private finish(pending: PendingCell, result: CallToolResult): void {
    if (this.pending !== pending) return;
    clearTimeout(pending.timer);
    this.pending = undefined;
    pending.settle(result);
  }

  private runNow(code: string, timeoutMs: number, signal?: AbortSignal): Promise<CallToolResult> {
    return new Promise((resolve) => {
      const child = this.ensureKernel();
      const id = this.nextId++;
      const pending: PendingCell = {
        child,
        id,
        output: new BoundedOutput(),
        settle: resolve,
        timer: setTimeout(() => {
          void this.killKernel(NODE_REPL_MESSAGES.timeout);
        }, timeoutMs),
      };
      this.pending = pending;
      signal?.addEventListener("abort", () => {
        if (this.pending === pending) void this.killKernel("js call was cancelled; kernel reset");
      }, { once: true });
      const request: KernelRunRequest = { type: "run", id, code };
      try {
        child.send(request);
      } catch (error) {
        this.finish(pending, textResult(`js kernel is unavailable: ${error instanceof Error ? error.message : String(error)}`, true));
      }
    });
  }

  private killKernel(reason: string): Promise<void> {
    const child = this.child;
    this.child = undefined;
    if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
    this.killReasons.set(child, reason);
    // The pending cell reports only the reason, not partial output mixed with
    // a kill notice, for timeouts and resets.
    if (this.pending?.child === child && (reason === NODE_REPL_MESSAGES.timeout || reason === NODE_REPL_MESSAGES.reset)) {
      this.finish(this.pending, textResult(reason, true));
    }
    return new Promise((resolve) => {
      child.once("exit", () => resolve());
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    });
  }
}

export function defaultKernelPath(): string {
  return fileURLToPath(new URL("./node-repl-kernel.mjs", import.meta.url));
}

export function createNodeReplServer(host: NodeReplKernelHost): Server {
  const server = new Server(
    { name: NODE_REPL_SERVER_NAME, version: RUNFREE_MCP_BUNDLE_VERSION },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...NODE_REPL_TOOLS] }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra): Promise<CallToolResult> => {
    const { name } = request.params;
    if (name === "js") {
      const parsed = parseJsArguments(request.params.arguments);
      if (typeof parsed === "string") return textResult(parsed, true);
      return host.run(parsed.code, parsed.timeoutMs, extra.signal);
    }
    if (name === "js_reset") return host.reset();
    return textResult(`unknown tool ${JSON.stringify(name)}; this server provides js and js_reset`, true);
  });
  return server;
}

export async function runNodeReplServer(): Promise<void> {
  // stdout carries MCP JSON-RPC only; anything else the server logs goes to stderr.
  console.log = console.error;
  console.info = console.error;
  console.debug = console.error;
  const host = new NodeReplKernelHost({ cwd: process.cwd(), kernelPath: defaultKernelPath() });
  const server = createNodeReplServer(host);
  const transport = new StdioServerTransport();
  const shutdown = () => {
    void host.close().finally(() => process.exit(0));
  };
  process.stdin.on("end", shutdown);
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  server.onclose = shutdown;
  await server.connect(transport);
}
