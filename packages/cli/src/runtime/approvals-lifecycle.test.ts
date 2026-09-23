import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";

import { select, text } from "@clack/prompts";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { APPROVALS_DECISIONS_DIR, APPROVALS_PENDING_DIR, type PendingApprovalRecord } from "@runfree/runtime-contracts/write-approvals";
import { projectInfo } from "../config.ts";
import { approvalsRuntime, approveRuntime } from "./approvals.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

vi.mock("@clack/prompts", async (importOriginal) => ({
  ...await importOriginal<typeof import("@clack/prompts")>(),
  select: vi.fn(),
  text: vi.fn(),
}));

const epoch = "a".repeat(64);
const record: PendingApprovalRecord = {
  v: 1,
  id: "205597d352b86254bce9ab90c9797157",
  processEpoch: epoch,
  host: "api.example.com",
  method: "POST",
  path: "/things",
  category: "method",
  tokenNames: [],
  session: { sessionId: "rf-20260908-abcdef", name: "test", command: "codex", startedAt: "2026-09-08T00:00:00.000Z" },
  generation: "test",
  heldAt: "2026-09-08T00:00:00.000Z",
  expiresAt: "2026-09-08T00:02:00.000Z",
};

const tempDirs: string[] = [];
function context(): RuntimeContext {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approval-lifecycle-"));
  tempDirs.push(root);
  const env = { XDG_STATE_HOME: path.join(root, "state"), XDG_CONFIG_HOME: path.join(root, "config") };
  return { projectRoot: root, project: projectInfo(root, env), runtimeRoot: path.join(root, "runtime"), env };
}

const ok = (stdout = ""): CaptureResult => ({ status: 0, stdout, stderr: "" });

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("decision writer lifecycle", () => {
  test.each(["removed", "already-decided", "restarted", "malformed", "pending"] as const)("handles a %s request at submission", async (state) => {
    const ctx = context();
    const pendingDir = path.join(ctx.projectRoot, "pending");
    const decisionsDir = path.join(ctx.projectRoot, "decisions");
    fs.mkdirSync(pendingDir);
    fs.mkdirSync(decisionsDir);
    fs.writeFileSync(path.join(pendingDir, "process-epoch"), state === "restarted" ? "b".repeat(64) : epoch);
    if (state === "pending" || state === "malformed") {
      fs.writeFileSync(path.join(pendingDir, `${record.id}.json`), state === "malformed" ? "invalid json" : JSON.stringify(record));
    }
    if (state === "already-decided") fs.writeFileSync(path.join(decisionsDir, `${record.id}.json`), "existing decision");
    let writerResult: CaptureResult | undefined;
    const io: RuntimeIO = {
      capture: (_command, args) => {
        if (args[0] === "ps") return ok("proxy-id\n");
        const payload = args.at(-1);
        if (!payload?.startsWith("{")) return ok(JSON.stringify([JSON.stringify(record)]));
        // Execute the exact host writer, changing only its container paths.
        const script = args[args.indexOf("-e") + 1]
          .replaceAll(APPROVALS_PENDING_DIR, pendingDir)
          .replaceAll(APPROVALS_DECISIONS_DIR, decisionsDir);
        const result = spawnSync(process.execPath, ["-e", script, payload], { encoding: "utf8" });
        writerResult = { status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr };
        return writerResult;
      },
      admin: async () => 0,
      commandExists: () => true,
      confirm: () => false,
      run: () => 0,
    };
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const result = await approveRuntime({ id: record.id, deny: false }, ctx, io);
    expect(result).toBe(state === "pending" ? 0 : 1);
    if (state === "pending") {
      expect(JSON.parse(fs.readFileSync(path.join(decisionsDir, `${record.id}.json`), "utf8")))
        .toMatchObject({ id: record.id, processEpoch: epoch, decision: "approve", scope: "request" });
    } else if (state === "already-decided") {
      expect(fs.readFileSync(path.join(decisionsDir, `${record.id}.json`), "utf8")).toBe("existing decision");
    } else {
      expect(fs.readdirSync(decisionsDir)).toEqual([]);
    }
    if (state === "removed" || state === "already-decided") {
      expect(writerResult?.stderr).toContain("no longer pending");
      expect(writerResult?.stderr).not.toMatch(/ENOENT|node:fs|\[eval\]/);
    } else if (state === "restarted") {
      expect(writerResult?.stderr).toContain("proxy restarted");
    } else if (state === "malformed") {
      expect(writerResult?.stderr).toContain("SyntaxError");
      expect(writerResult?.stderr).not.toContain("no longer pending");
    }
  });
});

describe("interactive approval lifecycle", () => {
  let cancel: symbol;
  let dismiss: () => void;
  let promptSignal: AbortSignal | undefined;
  const terminalStreams = [process.stdout, process.stdin];
  const terminalDescriptors = terminalStreams.map((stream) => Object.getOwnPropertyDescriptor(stream, "isTTY"));

  afterEach(() => {
    terminalStreams.forEach((stream, index) => {
      const descriptor = terminalDescriptors[index];
      if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
      else Reflect.deleteProperty(stream, "isTTY");
    });
  });

  beforeEach(async () => {
    vi.useFakeTimers();
    for (const stream of terminalStreams) Object.defineProperty(stream, "isTTY", { configurable: true, value: true });
    dismiss = () => {};
    promptSignal = undefined;
    vi.spyOn(console, "log").mockImplementation(() => {});
    const actual = await vi.importActual<typeof import("@clack/prompts")>("@clack/prompts");
    const input = new PassThrough();
    const output = new PassThrough();
    const cancelled = await actual.text({ message: "cancel", signal: AbortSignal.abort(), input, output });
    input.destroy();
    output.destroy();
    if (typeof cancelled !== "symbol") throw new Error("expected prompt cancellation");
    cancel = cancelled;
    const waitForInput = ({ signal }: { signal?: AbortSignal }) => new Promise<symbol>((resolve) => {
      promptSignal = signal;
      dismiss = () => resolve(cancel);
      if (signal?.aborted) dismiss();
      else signal?.addEventListener("abort", dismiss, { once: true });
    });
    vi.mocked(select).mockReset().mockImplementation(waitForInput);
    vi.mocked(text).mockReset().mockImplementation(waitForInput);
  });

  function watcher(initial: PendingApprovalRecord | PendingApprovalRecord[] = record, kind: "watch" | "list" = "watch") {
    let pending = Array.isArray(initial) ? initial : [initial];
    const decisions: unknown[] = [];
    let heartbeats = 0;
    const io: RuntimeIO = {
      capture: (_command, args) => {
        if (args[0] === "ps") return ok("proxy-id\n");
        if (args.includes("cat")) return { status: 1, stdout: "", stderr: "unavailable" };
        if (args.some((arg) => arg.includes("watcher-heartbeat"))) {
          heartbeats += 1;
          return ok();
        }
        const payload = args.at(-1);
        if (payload?.startsWith("{")) {
          decisions.push(JSON.parse(payload));
          pending = pending.filter((item) => item.id !== JSON.parse(payload).id);
          return ok("ok\n");
        }
        return ok(JSON.stringify(pending.map((item) => JSON.stringify(item))));
      },
      admin: vi.fn(async () => 0),
      commandExists: () => true,
      confirm: () => false,
      run: () => 0,
    };
    const running = approvalsRuntime({ kind, bell: false }, context(), io);
    return {
      decisions,
      io,
      setPending: (next: PendingApprovalRecord[]) => { pending = next; },
      heartbeats: () => heartbeats,
      stop: async () => {
        process.emit("SIGINT");
        dismiss();
        await vi.advanceTimersByTimeAsync(1_000);
        await expect(running).resolves.toBe(0);
        expect(vi.getTimerCount()).toBe(0);
      },
    };
  }

  test.each([false, true])("dismisses a removed request and can approve its retry (MCP: %s)", async (mcp) => {
    const initial = { ...record, ...(mcp ? { mcp: { agent: "codex" as const, server: "example", method: "tools/call", tool: "create" } } : {}) };
    const watch = watcher(initial);
    try {
      watch.setPending([]);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(promptSignal?.aborted).toBe(true);
      expect(watch.decisions).toEqual([]);
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining("no longer pending"));
      vi.mocked(select).mockResolvedValueOnce("request");
      const retry = { ...initial, id: "b".repeat(32) };
      watch.setPending([retry]);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(watch.decisions).toMatchObject([{ id: retry.id, decision: "approve" }]);
    } finally {
      await watch.stop();
    }
  });

  test("dismisses the duration prompt and keeps the heartbeat alive while waiting", async () => {
    vi.mocked(select).mockResolvedValueOnce("ttl");
    const watch = watcher();
    try {
      await vi.advanceTimersByTimeAsync(20_000);
      expect(text).toHaveBeenCalledOnce();
      expect(watch.heartbeats()).toBeGreaterThanOrEqual(3);
      watch.setPending([]);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(promptSignal?.aborted).toBe(true);
      expect(watch.decisions).toEqual([]);
    } finally {
      await watch.stop();
    }
  });

  test("rechecks after input before saving a rule or submitting a decision", async () => {
    let submit: (choice: string) => void = () => {};
    vi.mocked(select).mockImplementationOnce(() => new Promise((resolve) => { submit = resolve; }));
    const watch = watcher({ ...record, mcp: { agent: "codex", server: "example", method: "tools/call", tool: "create" } });
    try {
      watch.setPending([]);
      submit("save-tool");
      await vi.advanceTimersByTimeAsync(0);
      expect(watch.decisions).toEqual([]);
      expect(watch.io.admin).not.toHaveBeenCalled();
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining("no longer pending"));
    } finally {
      await watch.stop();
    }
  });

  test("user cancellation leaves the request pending without repeating the prompt", async () => {
    const watch = watcher();
    try {
      dismiss();
      await vi.advanceTimersByTimeAsync(2_000);
      expect(select).toHaveBeenCalledOnce();
      expect(promptSignal?.aborted).toBe(false);
      expect(watch.decisions).toEqual([]);
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining("ignoring a prompt never decides anything"));
    } finally {
      await watch.stop();
    }
  });
  test("keeps cancellation final when the pending snapshot is unavailable", async () => {
    const watch = watcher();
    const capture = watch.io.capture;
    let unavailable = true;
    watch.io.capture = (command, args, options) => unavailable && args.some((arg) => arg.includes("const records = []"))
      ? { status: 1, stdout: "", stderr: "temporary failure" }
      : capture(command, args, options);
    try {
      dismiss();
      await vi.advanceTimersByTimeAsync(1_000);
      unavailable = false;
      await vi.advanceTimersByTimeAsync(2_000);
      expect(select).toHaveBeenCalledOnce();
      expect(watch.decisions).toEqual([]);
    } finally {
      await watch.stop();
    }
  });

  test("retries the remaining request when reads fail after the first decision", async () => {
    const second = { ...record, id: "b".repeat(32) };
    vi.mocked(select).mockResolvedValueOnce("request");
    const watch = watcher([record, second]);
    const capture = watch.io.capture;
    let unavailable = true;
    watch.io.capture = (command, args, options) => unavailable && watch.decisions.length === 1 && args.some((arg) => arg.includes("const records = []"))
      ? { status: 1, stdout: "", stderr: "temporary failure" }
      : capture(command, args, options);
    try {
      await vi.advanceTimersByTimeAsync(1_000);
      expect(watch.decisions).toMatchObject([{ id: record.id }]);
      unavailable = false;
      vi.mocked(select).mockResolvedValueOnce("request");
      await vi.advanceTimersByTimeAsync(2_000);
      expect(watch.decisions).toMatchObject([{ id: record.id }, { id: second.id }]);
    } finally {
      await watch.stop();
    }
  });

  test.each(["watch", "list"] as const)("retries a still-pending request after a transient decision-write failure (%s)", async (kind) => {
    vi.mocked(select).mockResolvedValueOnce("request");
    const watch = watcher(record, kind);
    const capture = watch.io.capture;
    let failed = false;
    watch.io.capture = (command, args, options) => {
      if (!failed && args.at(-1)?.startsWith("{")) {
        failed = true;
        return { status: 1, stdout: "", stderr: "temporary decision write failure" };
      }
      return capture(command, args, options);
    };
    try {
      await vi.advanceTimersByTimeAsync(0);
      expect(failed).toBe(true);
      expect(watch.decisions).toEqual([]);
      vi.mocked(select).mockResolvedValueOnce("request");
      await vi.advanceTimersByTimeAsync(2_000);
      expect(watch.decisions).toMatchObject([{ id: record.id, decision: "approve" }]);
    } finally {
      await watch.stop();
    }
  });

  test("reprompts an undecided request after pending-read availability recovers", async () => {
    let choose = () => {};
    vi.mocked(select).mockImplementation(({ signal }) => new Promise((resolve) => {
      choose = () => resolve("request");
      dismiss = () => resolve(cancel);
      if (signal?.aborted) dismiss();
      else signal?.addEventListener("abort", dismiss, { once: true });
    }));
    const watch = watcher();
    const capture = watch.io.capture;
    let unavailable = true;
    watch.io.capture = (command, args, options) => {
      if (unavailable && args.some((arg) => arg.includes("const records = []"))) {
        return { status: 1, stdout: "", stderr: "temporary Docker exec failure" };
      }
      return capture(command, args, options);
    };
    try {
      await vi.advanceTimersByTimeAsync(2_000);
      unavailable = false;
      await vi.advanceTimersByTimeAsync(3_000);
      choose();
      await vi.advanceTimersByTimeAsync(0);
      expect(watch.decisions).toMatchObject([{ id: record.id, decision: "approve" }]);
    } finally {
      await watch.stop();
    }
  });
});
