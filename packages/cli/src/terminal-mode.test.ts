import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { adminDockerClient, runAdminAction, runCapture } from "./admin/admin-core.ts";
import { createAdminState } from "./admin/context.ts";
import { mcpConfigureIntent } from "./admin/mcp-admin.ts";
import { serviceConfigureIntent } from "./admin/service-policy.ts";
import { nodeRuntimeIO, withWriteApprovalSession } from "./runtime.ts";
import { createRuntimeDocker } from "./runtime/docker.ts";
import { SESSION_DOCKER_CALL_TIMEOUT_MS } from "./runtime/session-container-contract.ts";
import { captureHostTty } from "./runtime/sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";
import {
  createHeadlessRuntimeIO,
  enterHeadlessTerminalMode,
  headlessTerminalModeActive,
  hostStdoutIsTty,
  hostStreamIsTty,
  hostTerminalInteractive,
} from "./terminal-mode.ts";

// Headless-run spec §3.3 and plan conflict C3: a `run` ignores the host's own
// TTYs (a tmux pane has them), so every direct TTY read on its path answers
// non-interactive while the mode is held, whatever the streams say.

type TtyStream = { isTTY?: boolean };
const streams: Array<[TtyStream, PropertyDescriptor | undefined]> = [];

function stubTty(stream: TtyStream, value: boolean): void {
  streams.push([stream, Object.getOwnPropertyDescriptor(stream, "isTTY")]);
  Object.defineProperty(stream, "isTTY", { configurable: true, value });
}

function stubAllTtys(): void {
  stubTty(process.stdin, true);
  stubTty(process.stdout, true);
  stubTty(process.stderr, true);
}

let releases: Array<() => void> = [];

function headless(): () => void {
  const release = enterHeadlessTerminalMode();
  releases.push(release);
  return release;
}

beforeEach(() => {
  releases = [];
});

afterEach(() => {
  for (const release of releases) release();
  for (const [stream, descriptor] of streams.reverse()) {
    if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
    else delete (stream as { isTTY?: boolean }).isTTY;
  }
  streams.length = 0;
  vi.restoreAllMocks();
});

describe("headless terminal mode", () => {
  test("answers non-interactive only while held, and a release is idempotent", () => {
    const tty = { stdin: { isTTY: true }, stdout: { isTTY: true } };
    expect(headlessTerminalModeActive()).toBe(false);
    expect(hostTerminalInteractive(tty)).toBe(true);
    expect(hostStdoutIsTty(tty.stdout)).toBe(true);
    expect(hostStreamIsTty(tty.stdin)).toBe(true);

    const release = headless();
    expect(headlessTerminalModeActive()).toBe(true);
    expect(hostTerminalInteractive(tty)).toBe(false);
    expect(hostStdoutIsTty(tty.stdout)).toBe(false);
    expect(hostStreamIsTty(tty.stdin)).toBe(false);

    release();
    release();
    expect(headlessTerminalModeActive()).toBe(false);
    expect(hostTerminalInteractive(tty)).toBe(true);
  });

  test("nested holds compose: the mode ends with the last release", () => {
    const tty = { stdin: { isTTY: true }, stdout: { isTTY: true } };
    const outer = headless();
    const inner = headless();
    inner();
    expect(hostTerminalInteractive(tty)).toBe(false);
    outer();
    expect(hostTerminalInteractive(tty)).toBe(true);
  });

  test("outside the mode, a missing TTY on either stream is still not interactive", () => {
    expect(hostTerminalInteractive({ stdin: { isTTY: true }, stdout: {} })).toBe(false);
    expect(hostTerminalInteractive({ stdin: {}, stdout: { isTTY: true } })).toBe(false);
    expect(hostStdoutIsTty({})).toBe(false);
  });
});

describe("headless runtime IO", () => {
  function baseIO(withAsync: boolean): RuntimeIO {
    return {
      run: vi.fn(() => 0),
      capture: vi.fn(() => ({ status: 0, stdout: "ok", stderr: "" })),
      ...(withAsync ? { captureAsync: vi.fn(async () => ({ status: 0, stdout: "async", stderr: "" })) } : {}),
      commandExists: vi.fn(() => true),
      confirm: vi.fn(() => true),
      choosePiProvider: vi.fn(() => "agent-codex" as const),
      isInteractive: vi.fn(() => true),
      admin: vi.fn(async () => 7),
    };
  }

  test("never prompts and delegates everything else", async () => {
    const base = baseIO(true);
    const io = createHeadlessRuntimeIO(base);
    expect(io.confirm("Enable? [y/N] ")).toBe(false);
    expect(io.choosePiProvider?.([{ label: "x", value: "agent-codex" }])).toBeUndefined();
    expect(io.isInteractive?.()).toBe(false);
    expect(base.confirm).not.toHaveBeenCalled();
    expect(base.choosePiProvider).not.toHaveBeenCalled();
    expect(base.isInteractive).not.toHaveBeenCalled();

    expect(io.capture("docker", ["ps"])).toEqual({ status: 0, stdout: "ok", stderr: "" });
    await expect(io.captureAsync?.("docker", ["ps"])).resolves.toEqual({ status: 0, stdout: "async", stderr: "" });
    expect(io.run("docker", ["ps"])).toBe(0);
    expect(io.commandExists("docker")).toBe(true);
    await expect(io.admin({ kind: "prepare" }, {} as RuntimeContext)).resolves.toBe(7);
  });

  test("defines captureAsync only when the base IO has one", () => {
    expect(createHeadlessRuntimeIO(baseIO(false))).not.toHaveProperty("captureAsync");
    expect(createHeadlessRuntimeIO(baseIO(true))).toHaveProperty("captureAsync");
  });

  // A synchronous Docker call blocks the event loop, so with a stalled daemon
  // and no deadline neither the run timer nor a signal could ever fire.
  describe("bounds every Docker call that carries no deadline of its own", () => {
    function stalledDocker() {
      const seen: Array<{ args: string[]; options: childProcess.SpawnSyncOptions | undefined }> = [];
      // The deadline is the only way such a call ends: it reports a kill.
      const stalled = (_command: string, args: string[], options?: childProcess.SpawnSyncOptions) => {
        seen.push({ args, options });
        return { status: null as unknown as number, stdout: "", stderr: "", timedOut: true };
      };
      const base: RuntimeIO = { ...baseIO(true), capture: vi.fn(stalled), run: vi.fn((command: string, args: string[], options?: childProcess.SpawnSyncOptions) => {
        stalled(command, args, options);
        return 1;
      }) };
      return { seen, io: createHeadlessRuntimeIO(base), base };
    }
    const context = { projectRoot: "/workspace/project", env: {} } as unknown as RuntimeContext;
    const deadline = { timeout: SESSION_DOCKER_CALL_TIMEOUT_MS, killSignal: "SIGKILL" };

    test("the startup daemon probe (docker info)", () => {
      const { seen, io } = stalledDocker();
      expect(() => createRuntimeDocker(context, io).assertAvailable()).toThrow();
      expect(seen[0]?.args[0]).toBe("info");
      expect(seen[0]?.options).toMatchObject(deadline);
    });

    test("the admission preflight's image inspection", () => {
      const { seen, io } = stalledDocker();
      expect(createRuntimeDocker(context, io).inspectImage("runfree-agent:test")).toBeUndefined();
      expect(seen.map((call) => call.args.slice(0, 2))).toEqual([["image", "inspect"]]);
      expect(seen[0]?.options).toMatchObject(deadline);
    });

    test("async and terminal calls too; a call's own deadline and non-Docker commands are kept", async () => {
      const { seen, io, base } = stalledDocker();
      await io.captureAsync?.("docker", ["ps"]);
      expect(base.captureAsync).toHaveBeenCalledWith("docker", ["ps"], expect.objectContaining(deadline));
      io.run("docker", ["image", "rm", "x"]);
      io.capture("docker", ["container", "stop", "c"], { timeout: 45_000 });
      io.capture("git", ["status"]);
      expect(seen.map((call) => call.options)).toEqual([
        expect.objectContaining(deadline),
        { timeout: 45_000 },
        undefined,
      ]);
    });

    test("an image build, which can rightly take minutes, is left unbounded", () => {
      const { seen, io } = stalledDocker();
      io.run("docker", ["build", "-t", "x", "."]);
      expect(seen[0]?.options).toBeUndefined();
    });
  });
});

// Warm credential preparation (`RuntimeIO.admin`, `prepareTokenSources`)
// reaches Docker through admin's own synchronous runner, not runtime IO, so
// that runner applies the same headless deadline.
describe("the admin Docker runner under the headless mode", () => {
  const deadline = { timeout: SESSION_DOCKER_CALL_TIMEOUT_MS, killSignal: "SIGKILL" };
  function stalledAdmin() {
    const seen: Array<{ command: string; args: string[]; options: childProcess.SpawnSyncOptions }> = [];
    const processRunner = vi.fn((command: string, args: string[], options: childProcess.SpawnSyncOptions) => {
      seen.push({ command, args, options });
      return { status: null, stdout: "", stderr: "", pid: 1, signal: "SIGKILL", output: [], error: Object.assign(new Error("ETIMEDOUT"), { code: "ETIMEDOUT" }) };
    });
    const state = createAdminState({ env: { PATH: process.env.PATH }, processRunner } as Parameters<typeof createAdminState>[0]);
    return { seen, run: (action: () => void) => runAdminAction(state, action) };
  }

  test("bounds a stalled call with no deadline of its own", async () => {
    headless();
    const { seen, run } = stalledAdmin();
    await run(() => { adminDockerClient().info(); });
    expect(seen[0]?.args[0]).toBe("info");
    expect(seen[0]?.options).toMatchObject(deadline);
  });

  test("keeps a tighter deadline and leaves an image build unbounded", async () => {
    headless();
    const { seen, run } = stalledAdmin();
    await run(() => {
      adminDockerClient().info(undefined, { timeout: 5_000 });
      runCapture("docker", ["build", "-t", "x", "."]);
    });
    expect(seen[0]?.options.timeout).toBe(5_000);
    expect(seen[1]?.options.timeout).toBeUndefined();
  });

  test("an interactive call is unchanged", async () => {
    const { seen, run } = stalledAdmin();
    await run(() => { adminDockerClient().info(); });
    expect(seen[0]?.options.timeout).toBeUndefined();
  });
});

describe("direct TTY reads honor the headless mode", () => {
  test("the node runtime IO never reads fd 0, never offers the Pi chooser, and is not interactive", () => {
    stubAllTtys();
    const readSync = vi.spyOn(fs, "readSync");
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    headless();

    expect(nodeRuntimeIO.confirm("Enable claude-code for this project? [y/N] ")).toBe(false);
    expect(nodeRuntimeIO.choosePiProvider?.([{ label: "x", value: "custom" }])).toBeUndefined();
    expect(nodeRuntimeIO.isInteractive?.()).toBe(false);
    expect(readSync).not.toHaveBeenCalled();
    // Not even the question is written: there is nobody to ask.
    expect(write).not.toHaveBeenCalled();
  });

  test("outside the mode, the same stubbed TTYs make the node runtime IO interactive", () => {
    stubAllTtys();
    expect(nodeRuntimeIO.isInteractive?.()).toBe(true);
  });

  test("the host tty is not captured, and `tty` is never run", () => {
    stubAllTtys();
    headless();
    const io = { capture: vi.fn(() => ({ status: 0, stdout: "/dev/pts/3\n", stderr: "" })) } as unknown as RuntimeIO;
    expect(captureHostTty({ env: {} } as RuntimeContext, io)).toBeUndefined();
    expect(io.capture).not.toHaveBeenCalled();
  });

  test("the write-approval session never starts the approvals heartbeat", async () => {
    stubAllTtys();
    const context = {} as RuntimeContext;
    const startHeartbeat = vi.fn(() => ({ stop: vi.fn() }));
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const deps = { anyAskHost: () => true, startHeartbeat };

    // The seam is live: an interactive session with an ask host starts it.
    await expect(withWriteApprovalSession(context, () => 3, deps)).resolves.toBe(3);
    expect(startHeartbeat).toHaveBeenCalledTimes(1);

    headless();
    startHeartbeat.mockClear();
    log.mockClear();
    await expect(withWriteApprovalSession(context, () => 4, deps)).resolves.toBe(4);
    expect(startHeartbeat).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  test("interactive-only admin flows refuse instead of prompting", async () => {
    stubAllTtys();
    headless();
    await expect(mcpConfigureIntent({} as Parameters<typeof mcpConfigureIntent>[0])).rejects.toThrow("requires a TTY");
    await expect(serviceConfigureIntent(
      { id: "github" } as Parameters<typeof serviceConfigureIntent>[0],
      {} as Parameters<typeof serviceConfigureIntent>[1],
    )).rejects.toThrow("requires an interactive TTY");
  });
});

// §5 "with a real PTY on both host streams, `run` never prompts, never starts
// the heartbeat, and never reads fd 0". Needs a pty: util-linux `script`, as
// on the Linux CI host (the same probe pattern as
// `admin/credential-source-reader.test.ts`). Task 13 repeats this at the
// `run` level.
const utilLinuxScript = /util-linux/.test(childProcess.spawnSync("script", ["--version"], { encoding: "utf8" }).stdout ?? "");

describe("with a real PTY on both host streams", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-terminal-mode-"));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test.skipIf(!utilLinuxScript)("headless mode answers every reader without reading the terminal", () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const url = (file: string): string => new URL(file, import.meta.url).href;
    const probe = path.join(tmp, "probe.mts");
    fs.writeFileSync(probe, `
import fs from "node:fs";
const reads: number[] = [];
const readSync = fs.readSync;
fs.readSync = ((fd: number, ...rest: unknown[]) => {
  reads.push(fd);
  return (readSync as (...args: unknown[]) => number)(fd, ...rest);
}) as typeof fs.readSync;
const mode = await import(${JSON.stringify(url("./terminal-mode.ts"))});
const runtime = await import(${JSON.stringify(url("./runtime.ts"))});
const sessions = await import(${JSON.stringify(url("./runtime/sessions.ts"))});
const result: Record<string, unknown> = {
  stdinTty: process.stdin.isTTY === true,
  stdoutTty: process.stdout.isTTY === true,
  interactiveBefore: runtime.nodeRuntimeIO.isInteractive(),
};
mode.enterHeadlessTerminalMode();
let heartbeats = 0;
result.confirm = runtime.nodeRuntimeIO.confirm("Enable? [y/N] ");
result.piProvider = runtime.nodeRuntimeIO.choosePiProvider([{ label: "x", value: "custom" }]) ?? null;
result.interactive = runtime.nodeRuntimeIO.isInteractive();
result.hostTty = sessions.captureHostTty({ env: process.env }, runtime.nodeRuntimeIO) ?? null;
result.session = await runtime.withWriteApprovalSession({}, () => 0, {
  anyAskHost: () => true,
  startHeartbeat: () => { heartbeats += 1; return { stop() {} }; },
});
result.heartbeats = heartbeats;
result.fd0Reads = reads.filter((fd) => fd === 0).length;
console.log("RESULT " + JSON.stringify(result));
`);
    const repoRoot = path.resolve(here, "..", "..", "..");
    const command = [process.execPath, "--import", "tsx", probe].map((part) => `'${part.replaceAll("'", "'\\''")}'`).join(" ");
    const run = childProcess.spawnSync("script", ["-qec", command, "/dev/null"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      // Bounded: a reader that blocked on the terminal would hang here.
      timeout: 60_000,
    });
    const line = run.stdout.split(/\r?\n/).find((entry) => entry.startsWith("RESULT "));
    expect(line, `${run.stdout}${run.stderr}`).toBeDefined();
    expect(JSON.parse((line as string).slice("RESULT ".length))).toEqual({
      stdinTty: true,
      stdoutTty: true,
      interactiveBefore: true,
      confirm: false,
      piProvider: null,
      interactive: false,
      hostTty: null,
      session: 0,
      heartbeats: 0,
      fd0Reads: 0,
    });
  }, 60_000);
});
