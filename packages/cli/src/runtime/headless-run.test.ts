import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { APPROVAL_HEADLESS_DENIED_EVENT_PREFIX } from "@runfree/runtime-contracts/write-approvals";
import { CliError } from "../errors.ts";
import { headlessTerminalModeActive, hostTerminalInteractive } from "../terminal-mode.ts";
import { pendingWarningsForTest } from "../warnings.ts";
import type { HeadlessRuntimeHooks, HeadlessRuntimeResult } from "../runtime.ts";
import type { HeadlessForegroundCapture, HeadlessForegroundSinks } from "./headless-foreground.ts";
import { acquireHeadlessRunLock, headlessRunLockPath, type HeadlessRunLock } from "./headless-run-lock.ts";
import type { HeadlessRunJson } from "./headless-run-record.ts";
import {
  countHeadlessDenialEvents,
  countHeadlessDenials,
  decideHeadlessRunExit,
  runHeadlessAgent,
  type HeadlessRunDeps,
} from "./headless-run.ts";
import type { PreparedRuntime } from "./prepared-runtime.ts";
import { SessionTeardownIncompleteError } from "./session-admission-probe.ts";
import type { SessionHeadlessLaunchInput, SessionHeadlessLaunchResult } from "./session-public-launch.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const SESSION_ID = "rf-20261025-abc123";
const CONTAINER_NAME = `runfree-0123456789ab-session-${SESSION_ID}`;
const CONTAINER_ID = "c".repeat(64);
const SUCCESS_LINE = `${JSON.stringify({ type: "result", subtype: "success", is_error: false, result: "all done" })}\n`;
const ENV: NodeJS.ProcessEnv = {
  RUNFREE_TEST_FAKE_DOCKER: "1",
  RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
  RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
};

let tmp: string;
let projectRoot: string;
let stateDir: string;
let inboxDir: string;
let promptPath: string;
let context: RuntimeContext;
let stdout: string[];
let events: string[];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-headless-run-"));
  projectRoot = path.join(tmp, "project");
  fs.mkdirSync(path.join(projectRoot, "src"), { recursive: true });
  fs.writeFileSync(path.join(projectRoot, "src", "main.ts"), "export {};\n");
  stateDir = path.join(tmp, "state", "projects", "0123456789ab");
  inboxDir = path.join(stateDir, "inbox");
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  promptPath = path.join(tmp, "task.md");
  fs.writeFileSync(promptPath, "write the summary to report.md\n");
  context = {
    projectRoot,
    project: { paths: { stateDir, inboxDir, sessionsDir: path.join(stateDir, "sessions") } },
    runtimeRoot: path.join(tmp, "runtime"),
    env: ENV,
  } as unknown as RuntimeContext;
  stdout = [];
  events = [];
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const baseIO = {
  isInteractive: () => true,
  confirm: () => true,
  choosePiProvider: () => "custom",
} as unknown as RuntimeIO;

type FakeLaunch = (input: SessionHeadlessLaunchInput, sinks: HeadlessForegroundSinks) => Promise<SessionHeadlessLaunchResult>;

type Harness = Readonly<{
  deps: Partial<HeadlessRunDeps>;
  signals: EventEmitter;
  runtimeCalls: () => number;
  launchCalls: () => number;
  lockCalls: () => number;
  released: () => boolean;
  postureOptions: () => unknown[];
}>;

function promptHostPath(input: SessionHeadlessLaunchInput): string {
  return path.join(inboxDir, path.basename(input.headless.promptContainerPath));
}

function harness(options: Readonly<{
  launch?: FakeLaunch;
  runtime?: (hooks: HeadlessRuntimeHooks<SessionHeadlessLaunchResult>) => Promise<HeadlessRuntimeResult<SessionHeadlessLaunchResult>>;
  refusePosture?: boolean;
  denials?: number | null;
  drained?: boolean;
}> = {}): Harness {
  const signals = new EventEmitter();
  let runtimeCalls = 0;
  let launchCalls = 0;
  let lockCalls = 0;
  let released = false;
  const postureOptions: unknown[] = [];
  let sinks: HeadlessForegroundSinks | undefined;
  const launch: FakeLaunch = options.launch ?? (async (input, out) => {
    input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
    input.headless.observer?.containerCreated(CONTAINER_ID);
    out.stdout(Buffer.from(SUCCESS_LINE));
    out.stdoutEnded?.();
    return { status: 0, cancelled: false };
  });
  const deps: Partial<HeadlessRunDeps> = {
    signals,
    stdout: (line) => stdout.push(line),
    now: () => new Date("2026-10-25T12:00:00.000Z"),
    runtime: async <T>(_context: RuntimeContext, _io: RuntimeIO, _agent: string, _options: unknown, hooks: HeadlessRuntimeHooks<T>) => {
      runtimeCalls += 1;
      if (options.runtime) {
        return await options.runtime(hooks as unknown as HeadlessRuntimeHooks<SessionHeadlessLaunchResult>) as unknown as HeadlessRuntimeResult<T>;
      }
      const refusal = hooks.beforeLaunch(context);
      if (refusal !== undefined) return { kind: "refused", status: refusal };
      return {
        kind: "launched",
        value: await hooks.launch({
          preparedRuntime: {} as PreparedRuntime,
          activeContext: context,
          proxyId: "proxy-id",
          reprepare: async () => ({}) as PreparedRuntime,
        }),
      };
    },
    launch: async (input) => {
      launchCalls += 1;
      events.push("launch");
      if (!sinks) throw new Error("no capture sinks");
      return await launch(input, sinks);
    },
    createSpawner: (out): HeadlessForegroundCapture => {
      sinks = out;
      return {
        spawn: (() => {
          throw new Error("the fake launch spawns nothing");
        }) as unknown as HeadlessForegroundCapture["spawn"],
        drain: async () => ({ drained: options.drained ?? true }),
        reattached: () => false,
      };
    },
    writePosture: (_active, postureInput) => {
      postureOptions.push(postureInput);
      return options.refusePosture && !postureInput.acceptDeniedWrites
        ? { kind: "refuse", status: 65, message: "refusing a headless run: host api.example.com: writes ask", exposure: { askHosts: ["api.example.com"], askMcp: [], globalAskWithMcp: false, unreadable: [] } }
        : { kind: "pass", accepted: postureInput.acceptDeniedWrites, exposure: { askHosts: [], askMcp: [], globalAskWithMcp: false, unreadable: [] } };
    },
    uncheckedAuthority: () => ({ hostServices: ["db"], oauthExchanges: [], localMcpServers: [], unreadable: [] }),
    countDenials: () => {
      events.push("count-denials");
      return options.denials === undefined ? 0 : options.denials;
    },
    acquireLock: (input) => {
      lockCalls += 1;
      const lock = acquireHeadlessRunLock(input);
      return {
        ...lock,
        recordSession: (session) => {
          events.push(`lock-session:${session.sessionId}`);
          lock.recordSession(session);
        },
        recordContainer: (id) => {
          events.push("lock-container");
          lock.recordContainer(id);
        },
        release: () => {
          // §3.5 step order: the prompt is gone and the record final before
          // the lock goes.
          const promptLeft = fs.existsSync(inboxDir) && fs.readdirSync(inboxDir).some((name) => name.endsWith(".prompt"));
          events.push(promptLeft ? "release-with-prompt" : "release");
          expect(runJson()).toBeDefined();
          released = true;
          lock.release();
        },
      } satisfies HeadlessRunLock;
    },
  };
  return {
    deps,
    signals,
    runtimeCalls: () => runtimeCalls,
    launchCalls: () => launchCalls,
    lockCalls: () => lockCalls,
    released: () => released,
    postureOptions: () => postureOptions,
  };
}

function runDirs(): string[] {
  const runs = path.join(stateDir, "runs");
  return fs.existsSync(runs) ? fs.readdirSync(runs) : [];
}

function runJson(): HeadlessRunJson | undefined {
  const [dir] = runDirs();
  if (!dir) return undefined;
  const file = path.join(stateDir, "runs", dir, "run.json");
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) as HeadlessRunJson : undefined;
}

function inboxPrompts(): string[] {
  return fs.existsSync(inboxDir) ? fs.readdirSync(inboxDir).filter((name) => name.endsWith(".prompt")) : [];
}

async function run(h: Harness, overrides: Partial<Parameters<typeof runHeadlessAgent>[3]> = {}, agent = "claude"): Promise<number> {
  return await runHeadlessAgent(context, baseIO, agent, {
    promptFile: promptPath,
    acceptDeniedWrites: false,
    ...overrides,
  }, h.deps);
}

function treeSnapshot(root: string): string[] {
  const entries: string[] = [];
  const walk = (dir: string): void => {
    for (const name of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, name);
      const stat = fs.lstatSync(full);
      entries.push(`${path.relative(root, full)}:${stat.mode}:${stat.size}:${stat.mtimeMs}`);
      if (stat.isDirectory()) walk(full);
    }
  };
  walk(root);
  return entries;
}

/** Resolves once `predicate` holds, polling the event loop. */
async function until(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 500 && !predicate(); attempt += 1) await new Promise((resolve) => setTimeout(resolve, 2));
  if (!predicate()) throw new Error("condition never held");
}

describe("decideHeadlessRunExit (spec §3.6)", () => {
  const success = { outcome: "success", exitCode: 0 } as const;
  test.each([
    [{ stage: "skipped" }, "skipped", 66],
    [{ stage: "refused" }, "refused", 65],
    [{ stage: "refused", aborted: "signal" }, "signal", 67],
    [{ stage: "refused", aborted: "timeout" }, "timeout", 67],
    [{ stage: "launched", aborted: "timeout", agent: success, denials: 0 }, "timeout", 67],
    [{ stage: "launched", aborted: "signal", agent: { outcome: "failed", exitCode: 2 }, denials: 0 }, "signal", 67],
    [{ stage: "launched", agent: { outcome: "failed", exitCode: 2 }, denials: 4 }, "failed", 2],
    [{ stage: "launched", agent: { outcome: "unverified", exitCode: 1 }, denials: 0 }, "unverified", 1],
    [{ stage: "launched", denials: 0 }, "unverified", 1],
    [{ stage: "launched", agent: success, denials: 0 }, "success", 0],
    [{ stage: "launched", agent: success, denials: 3 }, "success", 68],
    [{ stage: "launched", agent: success, denials: 3, acceptDeniedWrites: true }, "success", 0],
    [{ stage: "launched", agent: success, denials: null }, "unverified", 1],
    [{ stage: "launched", agent: success, denials: null, acceptDeniedWrites: true }, "success", 0],
  ] as const)("%j -> %s %i", (input, outcome, exitCode) => {
    expect(decideHeadlessRunExit({ acceptDeniedWrites: false, ...input })).toEqual({ outcome, exitCode });
  });
});

describe("countHeadlessDenialEvents", () => {
  const event = (sessionId: string): string =>
    `${APPROVAL_HEADLESS_DENIED_EVENT_PREFIX}${JSON.stringify({ v: 1, ts: "2026-10-25T12:00:01.000Z", sessionId, host: "api.example.com", method: "POST", path: "/x", category: "http" })}`;

  test("counts only this session's events, each line once, past any repeat limit", () => {
    const lines = [
      ...Array.from({ length: 25 }, () => event(SESSION_ID)),
      event("rf-20261025-other1"),
      `proxy-denial: ${JSON.stringify({ reason: "write-approval-headless-denied", sessionId: SESSION_ID })}`,
      `GET /path?${APPROVAL_HEADLESS_DENIED_EVENT_PREFIX}${JSON.stringify({ v: 1, sessionId: SESSION_ID })}`,
      `${APPROVAL_HEADLESS_DENIED_EVENT_PREFIX}{not json`,
      `${APPROVAL_HEADLESS_DENIED_EVENT_PREFIX}${JSON.stringify({ v: 2, sessionId: SESSION_ID })}`,
      `${APPROVAL_HEADLESS_DENIED_EVENT_PREFIX}${JSON.stringify([SESSION_ID])}`,
    ];
    expect(countHeadlessDenialEvents(`${lines.join("\r\n")}\n`, SESSION_ID)).toBe(25);
  });

  test("countHeadlessDenials reads the run's proxy logs since the run start, and is null when they cannot be read", () => {
    const calls: string[][] = [];
    const io = {
      capture: (_command: string, args: string[]) => {
        calls.push(args);
        return { status: 0, stdout: `${event(SESSION_ID)}\n`, stderr: `${event(SESSION_ID)}\n` };
      },
    } as unknown as RuntimeIO;
    expect(countHeadlessDenials({ context, io, proxyId: "proxy-id", sinceIso: "2026-10-25T11:59:00.000Z", sessionId: SESSION_ID })).toBe(2);
    expect(calls[0]).toEqual(["logs", "--since", "2026-10-25T11:59:00.000Z", "proxy-id"]);

    const failing = { capture: () => ({ status: 1, stdout: "", stderr: "Error: No such container: proxy-id" }) } as unknown as RuntimeIO;
    expect(countHeadlessDenials({ context, io: failing, proxyId: "proxy-id", sinceIso: "2026-10-25T11:59:00.000Z", sessionId: SESSION_ID })).toBeNull();
    const throwing = { capture: () => { throw new Error("spawn docker ENOENT"); } } as unknown as RuntimeIO;
    expect(countHeadlessDenials({ context, io: throwing, proxyId: "proxy-id", sinceIso: "2026-10-25T11:59:00.000Z", sessionId: SESSION_ID })).toBeNull();
  });
});

describe("runHeadlessAgent", () => {
  test("a successful run exits 0, prints the final message and record path, and keeps nothing behind", async () => {
    const before = treeSnapshot(projectRoot);
    let promptSeen: string | undefined;
    const h = harness({
      launch: async (input, out) => {
        promptSeen = fs.readFileSync(promptHostPath(input), "utf8");
        expect(input.headless.promptContainerPath).toMatch(/^\/runfree\/inbox\/run-20261025T120000Z-[a-f0-9]{8}\.prompt$/);
        expect(input.foregroundSpawner).toBeDefined();
        expect(input.io.isInteractive?.()).toBe(false);
        expect(input.io.confirm("Enable? [y/N] ")).toBe(false);
        expect(hostTerminalInteractive({ stdin: { isTTY: true }, stdout: { isTTY: true } })).toBe(false);
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        input.headless.observer?.containerCreated(CONTAINER_ID);
        out.stdout(Buffer.from(SUCCESS_LINE));
        out.stdoutEnded?.();
        return { status: 0, cancelled: false };
      },
    });

    const status = await run(h);

    expect(status).toBe(0);
    expect(promptSeen).toBe("write the summary to report.md\n");
    expect(events).toEqual(["launch", `lock-session:${SESSION_ID}`, "lock-container", "count-denials", "release"]);
    expect(runJson()).toMatchObject({
      v: 1,
      agent: "claude",
      agentStatus: 0,
      outcome: "success",
      exitCode: 0,
      teardown: "confirmed",
      sessionId: SESSION_ID,
      containerId: CONTAINER_ID,
      headlessDenials: 0,
      acceptDeniedWrites: false,
      uncheckedAuthority: { hostServices: ["db"] },
      streamsDrained: true,
    });
    const dir = path.join(stateDir, "runs", runDirs()[0] as string);
    expect(fs.readFileSync(path.join(dir, "transcript.jsonl"), "utf8")).toBe(SUCCESS_LINE);
    expect(fs.readFileSync(path.join(dir, "result.md"), "utf8")).toBe("all done\n");
    expect(stdout).toEqual(["all done", `run record: ${dir}`]);
    expect(inboxPrompts()).toEqual([]);
    expect(fs.existsSync(headlessRunLockPath(stateDir))).toBe(false);
    expect(treeSnapshot(projectRoot)).toEqual(before);
    // The run gave its process-wide holds back.
    expect(headlessTerminalModeActive()).toBe(false);
    expect(h.signals.listenerCount("SIGINT") + h.signals.listenerCount("SIGTERM")).toBe(0);
  });

  test.each([
    [2, 2, "failed"],
    [63, 63, "failed"],
    // The session entry's own 64/66/111 and a signal death never collide with run's codes.
    [64, 1, "failed"],
    [66, 1, "failed"],
    [137, 1, "failed"],
  ])("agent status %i exits %i (%s)", async (agentStatus, exitCode, outcome) => {
    const h = harness({
      launch: async (input) => {
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        input.headless.observer?.containerCreated(CONTAINER_ID);
        return { status: agentStatus, cancelled: false };
      },
    });
    expect(await run(h)).toBe(exitCode);
    expect(runJson()).toMatchObject({ agentStatus, outcome, exitCode });
  });

  test("status 0 without a final success, a lost status, and an undrained stream are unverified (1)", async () => {
    const cases: Array<[number | null, boolean, string]> = [[0, true, ""], [null, true, SUCCESS_LINE], [0, false, SUCCESS_LINE]];
    for (const [agentStatus, drained, line] of cases) {
      fs.rmSync(path.join(stateDir, "runs"), { recursive: true, force: true });
      const h = harness({
        drained,
        launch: async (input, out) => {
          input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
          input.headless.observer?.containerCreated(CONTAINER_ID);
          if (line) out.stdout(Buffer.from(line));
          out.stdoutEnded?.();
          return { status: agentStatus, cancelled: false };
        },
      });
      expect(await run(h)).toBe(1);
      expect(runJson()).toMatchObject({ agentStatus, outcome: "unverified", exitCode: 1, streamsDrained: drained });
    }
  });

  test("headless denials without --accept-denied-writes turn a success into 68 with a warning", async () => {
    const h = harness({ denials: 3 });
    expect(await run(h)).toBe(68);
    expect(runJson()).toMatchObject({ outcome: "success", exitCode: 68, headlessDenials: 3 });
    expect(stdout).toContain("warning: 3 writes were denied (headless)");
  });

  test("--accept-denied-writes skips the posture refusal and keeps a success with denials at 0", async () => {
    const h = harness({ refusePosture: true, denials: 2 });
    expect(await run(h, { acceptDeniedWrites: true })).toBe(0);
    expect(h.postureOptions()).toEqual([{ acceptDeniedWrites: true }]);
    expect(runJson()).toMatchObject({ outcome: "success", exitCode: 0, headlessDenials: 2, acceptDeniedWrites: true });
    expect(stdout).toContain("warning: 2 writes were denied (headless)");
  });

  test("an unreadable denial count fails closed: unverified 1 without the flag, unchanged with it", async () => {
    expect(await run(harness({ denials: null }))).toBe(1);
    expect(runJson()).toMatchObject({ outcome: "unverified", exitCode: 1, headlessDenials: null });
    expect(stdout).toContain("warning: the headless write denials could not be counted");

    fs.rmSync(path.join(stateDir, "runs"), { recursive: true, force: true });
    expect(await run(harness({ denials: null }), { acceptDeniedWrites: true })).toBe(0);
  });

  test("a write-posture exposure refuses with 65 before the launch, and cleans up", async () => {
    const h = harness({ refusePosture: true });
    expect(await run(h)).toBe(65);
    expect(h.launchCalls()).toBe(0);
    const stderr = vi.mocked(console.error).mock.calls.flat().join("\n");
    expect(stderr).toContain("host api.example.com: writes ask");
    // The remedy is the same run plus the flag, and it parses
    // (scripts/emitted-commands.test.ts covers the registry rendering).
    expect(stderr).toMatch(/Rerun accepting the denials: runfree run claude --prompt-file \S+ --accept-denied-writes/);
    expect(runJson()).toMatchObject({ outcome: "refused", exitCode: 65, teardown: "not-started", agentStatus: null });
    expect(inboxPrompts()).toEqual([]);
    expect(h.released()).toBe(true);
  });

  test.each([
    ["a nonzero review status", async () => ({ kind: "refused", status: 1 }) as const],
    ["a pending approval refusal", async () => {
      throw new CliError("saved approvals do not cover this checkout");
    }],
  ])("%s refuses with 65 before the launch", async (_name, runtime) => {
    const h = harness({ runtime });
    expect(await run(h)).toBe(65);
    expect(h.launchCalls()).toBe(0);
    expect(runJson()).toMatchObject({ outcome: "refused", exitCode: 65, teardown: "not-started" });
    expect(inboxPrompts()).toEqual([]);
    expect(h.released()).toBe(true);
  });

  test("a launch refused before its container was created is 65; a failure after it is unverified", async () => {
    const refused = harness({
      launch: async (input) => {
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        throw new CliError("the session image is not built\nclaude did not start");
      },
    });
    expect(await run(refused)).toBe(65);
    expect(runJson()).toMatchObject({ outcome: "refused", exitCode: 65, teardown: "confirmed", sessionId: SESSION_ID });

    fs.rmSync(path.join(stateDir, "runs"), { recursive: true, force: true });
    const failed = harness({
      launch: async (input) => {
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        input.headless.observer?.containerCreated(CONTAINER_ID);
        throw new Error("the running proof failed");
      },
    });
    expect(await run(failed)).toBe(1);
    expect(runJson()).toMatchObject({ outcome: "unverified", exitCode: 1, teardown: "confirmed", containerId: CONTAINER_ID });
    expect(failed.released()).toBe(true);
  });

  test.each([
    ["a success becomes unverified", 0, 1],
    ["an agent failure keeps its code", 2, 2],
  ])("a run record that cannot be finalized: %s", async (_name, agentStatus, exitCode) => {
    const h = harness({
      launch: async (input, out) => {
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        input.headless.observer?.containerCreated(CONTAINER_ID);
        out.stdout(Buffer.from(SUCCESS_LINE));
        out.stdoutEnded?.();
        // run.json cannot be replaced: the record's final write fails.
        fs.mkdirSync(path.join(stateDir, "runs", runDirs()[0] as string, "run.json"));
        return { status: agentStatus, cancelled: false };
      },
    });
    // The plain lock: the harness's release asserts a readable run.json.
    expect(await run({ ...h, deps: { ...h.deps, acquireLock: acquireHeadlessRunLock } })).toBe(exitCode);
    expect(pendingWarningsForTest().map((event) => event.message).join("\n")).toContain("the headless run record could not be finalized");
  });

  test("an unconfirmed teardown keeps the lock and says so; the prompt is still deleted", async () => {
    const h = harness({
      launch: async (input) => {
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        input.headless.observer?.containerCreated(CONTAINER_ID);
        throw new SessionTeardownIncompleteError([new Error("Cannot connect to the Docker daemon")]);
      },
    });
    expect(await run(h)).toBe(1);
    expect(h.released()).toBe(false);
    expect(fs.existsSync(headlessRunLockPath(stateDir))).toBe(true);
    expect(runJson()).toMatchObject({ outcome: "unverified", teardown: "unconfirmed", containerId: CONTAINER_ID });
    expect(stdout).toContain("warning: the session container stop was not confirmed; the run lock is kept until it is gone");
    expect(inboxPrompts()).toEqual([]);
  });

  test("a held lock exits 66 with a skipped record and does no runtime work and no inbox write", async () => {
    const holder = acquireHeadlessRunLock({ stateDir, inboxDir, sessionsDir: path.join(stateDir, "sessions"), io: baseIO, env: ENV });
    try {
      const h = harness();
      expect(await run(h)).toBe(66);
      expect(h.runtimeCalls()).toBe(0);
      expect(inboxPrompts()).toEqual([]);
      expect(runJson()).toMatchObject({ outcome: "skipped", exitCode: 66, teardown: "not-started" });
      expect(vi.mocked(console.error).mock.calls.flat().join("\n")).toContain("another headless run holds this project's run lock");
    } finally {
      holder.release();
    }
  });

  test.each([
    ["a symlink", () => {
      const target = path.join(tmp, "real.md");
      fs.writeFileSync(target, "x");
      fs.rmSync(promptPath);
      fs.symlinkSync(target, promptPath);
    }],
    ["a FIFO", () => {
      fs.rmSync(promptPath);
      const made = childProcess.spawnSync("mkfifo", [promptPath]);
      if (made.status !== 0) throw new Error("mkfifo failed");
    }],
    ["1 MiB + 1", () => {
      fs.writeFileSync(promptPath, Buffer.alloc(1024 * 1024 + 1, 0x61));
    }],
  ])("a prompt that is %s is a usage error (64) before any side effect", async (_name, plant) => {
    plant();
    const h = harness();
    expect(await run(h)).toBe(64);
    expect(h.lockCalls()).toBe(0);
    expect(h.runtimeCalls()).toBe(0);
    expect(fs.existsSync(inboxDir)).toBe(false);
    expect(runDirs()).toEqual([]);
    expect(headlessTerminalModeActive()).toBe(false);
  });

  test("an agent that is not a built-in is a usage error (64)", async () => {
    for (const agent of ["aider", "nobody"]) {
      const h = harness();
      expect(await run(h, {}, agent)).toBe(64);
      expect(h.lockCalls()).toBe(0);
    }
  });

  test("a non-positive timeout is a usage error (64)", async () => {
    const h = harness();
    expect(await run(h, { timeoutMs: 0 })).toBe(64);
    expect(h.lockCalls()).toBe(0);
  });
});

describe("one stop routine for every way a run ends (spec §3.5)", () => {
  /** A driver fake that, once attached, runs the in-driver half of the routine on abort. */
  function attachedDriver(): FakeLaunch {
    return async (input) => {
      input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
      input.headless.observer?.containerCreated(CONTAINER_ID);
      events.push("attached");
      const { signal, escalate } = input.cancellation;
      await new Promise<void>((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }));
      events.push("session-file-delete", "stop");
      // The stop's grace; a second signal shortens it.
      await new Promise<void>((resolve) => {
        if (escalate.aborted) resolve();
        escalate.addEventListener("abort", () => resolve(), { once: true });
        setTimeout(resolve, 50);
      });
      if (escalate.aborted) events.push("stop-now");
      return { status: 143, cancelled: true };
    };
  }

  const routine = ["count-denials", "release"];

  test("a timeout ends through the routine with 67", async () => {
    const h = harness({ launch: attachedDriver() });
    expect(await run(h, { timeoutMs: 20 })).toBe(67);
    expect(events).toEqual(["launch", `lock-session:${SESSION_ID}`, "lock-container", "attached", "session-file-delete", "stop", ...routine]);
    expect(runJson()).toMatchObject({ outcome: "timeout", exitCode: 67, agentStatus: 143, teardown: "confirmed" });
    expect(inboxPrompts()).toEqual([]);
  });

  test("a signal during the run ends through the routine with 67, whatever the agent returned", async () => {
    const h = harness({ launch: attachedDriver() });
    const pending = run(h);
    await until(() => events.includes("attached"));
    h.signals.emit("SIGTERM");
    expect(await pending).toBe(67);
    expect(events).toEqual(["launch", `lock-session:${SESSION_ID}`, "lock-container", "attached", "session-file-delete", "stop", ...routine]);
    expect(runJson()).toMatchObject({ outcome: "signal", exitCode: 67 });
  });

  test("a second signal escalates the stop and still ends with 67", async () => {
    const h = harness({ launch: attachedDriver() });
    const pending = run(h);
    await until(() => events.includes("attached"));
    h.signals.emit("SIGINT");
    await until(() => events.includes("stop"));
    h.signals.emit("SIGINT");
    expect(await pending).toBe(67);
    expect(events).toEqual(["launch", `lock-session:${SESSION_ID}`, "lock-container", "attached", "session-file-delete", "stop", "stop-now", ...routine]);
    expect(h.signals.listenerCount("SIGINT")).toBe(0);
  });

  test("a signal during startup, before any container, skips the launch and ends with 67", async () => {
    let startup!: () => void;
    const h = harness({
      runtime: async (hooks) => {
        await new Promise<void>((resolve) => {
          startup = resolve;
        });
        const refusal = hooks.beforeLaunch(context);
        if (refusal !== undefined) return { kind: "refused", status: refusal };
        throw new Error("the launch must not run after a startup signal");
      },
    });
    const pending = run(h);
    await until(() => startup !== undefined);
    h.signals.emit("SIGTERM");
    startup();
    expect(await pending).toBe(67);
    expect(h.launchCalls()).toBe(0);
    expect(events).toEqual(["release"]);
    expect(runJson()).toMatchObject({ outcome: "signal", exitCode: 67, teardown: "not-started", headlessDenials: 0 });
    expect(inboxPrompts()).toEqual([]);
  });

  test("a signal after allocation but before the container is created is 67, not a refusal", async () => {
    const h = harness({
      launch: async (input) => {
        input.headless.observer?.allocated({ sessionId: SESSION_ID, containerName: CONTAINER_NAME });
        h.signals.emit("SIGTERM");
        // The driver raises SessionLaunchCancelledError at its next step;
        // launchHeadlessAgentThroughAdmission reports it as a cancel.
        return { status: null, cancelled: true };
      },
    });
    expect(await run(h)).toBe(67);
    expect(runJson()).toMatchObject({ outcome: "signal", exitCode: 67, teardown: "confirmed", sessionId: SESSION_ID });
    expect(h.released()).toBe(true);
  });
});

// §5 "with a real PTY on both host streams, `run` never prompts, never starts
// the heartbeat, and never reads fd 0" at the run level (the Task 7 test
// covers each reader). util-linux `script` only, like that test.
const utilLinuxScript = /util-linux/.test(childProcess.spawnSync("script", ["--version"], { encoding: "utf8" }).stdout ?? "");

describe("runHeadlessAgent with a real PTY on both host streams", () => {
  test.skipIf(!utilLinuxScript)("never reads the terminal and answers every prompt no", () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const url = (file: string): string => new URL(file, import.meta.url).href;
    const probe = path.join(tmp, "probe.mts");
    fs.writeFileSync(probe, `
import childProcess from "node:child_process";
import fs from "node:fs";
const reads: number[] = [];
const readSync = fs.readSync;
fs.readSync = ((fd: number, ...rest: unknown[]) => {
  reads.push(fd);
  return (readSync as (...args: unknown[]) => number)(fd, ...rest);
}) as typeof fs.readSync;
const spawned: string[] = [];
const spawn = childProcess.spawn;
(childProcess as { spawn: unknown }).spawn = (command: string, args: string[], ...rest: unknown[]) => {
  spawned.push([command, ...args].join(" "));
  return (spawn as (...a: unknown[]) => unknown)(command, args, ...rest);
};
const { runHeadlessAgent } = await import(${JSON.stringify(url("./headless-run.ts"))});
const { nodeRuntimeIO } = await import(${JSON.stringify(url("../runtime.ts"))});
const { hostTerminalInteractive } = await import(${JSON.stringify(url("../terminal-mode.ts"))});
const answers: Record<string, unknown> = { stdinTty: process.stdin.isTTY === true, stdoutTty: process.stdout.isTTY === true };
const context = {
  projectRoot: ${JSON.stringify(projectRoot)},
  project: { paths: { stateDir: ${JSON.stringify(stateDir)}, inboxDir: ${JSON.stringify(inboxDir)} } },
  runtimeRoot: "/nonexistent",
  env: ${JSON.stringify(ENV)},
};
let sinks: { stdout(chunk: Buffer): void; stdoutEnded?(): void } | undefined;
const status = await runHeadlessAgent(context, nodeRuntimeIO, "claude", { promptFile: ${JSON.stringify(promptPath)}, acceptDeniedWrites: false }, {
  stdout: () => {},
  runtime: async (_c: unknown, io: { confirm(q: string): boolean; isInteractive(): boolean; choosePiProvider(o: unknown[]): unknown }, _a: string, _o: unknown, hooks: { beforeLaunch(c: unknown): number | undefined; launch(i: unknown): Promise<unknown> }) => {
    answers.confirm = io.confirm("Enable? [y/N] ");
    answers.interactive = io.isInteractive();
    answers.piProvider = io.choosePiProvider([{ label: "x", value: "custom" }]) ?? null;
    answers.hostInteractive = hostTerminalInteractive();
    hooks.beforeLaunch(context);
    return { kind: "launched", value: await hooks.launch({ preparedRuntime: {}, activeContext: context, proxyId: "p", reprepare: async () => ({}) }) };
  },
  launch: async (input: { headless: { observer?: { allocated(s: unknown): void; containerCreated(id: string): void } } }) => {
    input.headless.observer?.allocated({ sessionId: ${JSON.stringify(SESSION_ID)}, containerName: ${JSON.stringify(CONTAINER_NAME)} });
    input.headless.observer?.containerCreated(${JSON.stringify(CONTAINER_ID)});
    sinks?.stdout(Buffer.from(${JSON.stringify(SUCCESS_LINE)}));
    sinks?.stdoutEnded?.();
    return { status: 0, cancelled: false };
  },
  createSpawner: (out: typeof sinks) => {
    sinks = out;
    return { spawn: () => { throw new Error("unused"); }, drain: async () => ({ drained: true }), reattached: () => false };
  },
  writePosture: () => ({ kind: "pass", accepted: false, exposure: { askHosts: [], askMcp: [], globalAskWithMcp: false, unreadable: [] } }),
  uncheckedAuthority: () => ({ hostServices: [], oauthExchanges: [], localMcpServers: [], unreadable: [] }),
  countDenials: () => 0,
});
answers.status = status;
answers.fd0Reads = reads.filter((fd) => fd === 0).length;
answers.heartbeats = spawned.filter((line) => line.includes("--heartbeat")).length;
console.log("RESULT " + JSON.stringify(answers));
`);
    const repoRoot = path.resolve(here, "..", "..", "..", "..");
    const command = [process.execPath, "--import", "tsx", probe].map((part) => `'${part.replaceAll("'", "'\\''")}'`).join(" ");
    const result = childProcess.spawnSync("script", ["-qec", command, "/dev/null"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      // Bounded: a reader that blocked on the terminal would hang here.
      timeout: 60_000,
    });
    const line = result.stdout.split(/\r?\n/).find((entry) => entry.startsWith("RESULT "));
    expect(line, `${result.stdout}${result.stderr}`).toBeDefined();
    expect(JSON.parse((line as string).slice("RESULT ".length))).toEqual({
      stdinTty: true,
      stdoutTty: true,
      confirm: false,
      interactive: false,
      piProvider: null,
      hostInteractive: false,
      status: 0,
      fd0Reads: 0,
      heartbeats: 0,
    });
  }, 60_000);
});
