import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { afterEach, describe, expect, test, vi } from "vitest";

import { commandNameFromArgv, installSignalExit, main, SIGNAL_EXIT_CODES, verboseRequested } from "./cli.ts";
import { CliError } from "./errors.ts";
import { setOutputWriterForTest, warn } from "./warnings.ts";

afterEach(() => {
  setOutputWriterForTest(undefined);
  process.exitCode = undefined;
});

function stripStamp(line: string): string {
  return line.replace(/^\d{4}-\d{2}-\d{2}T[^ ]+ /, "");
}

async function runMain(body: () => Promise<number>, argv: string[] = []): Promise<string[]> {
  const lines: string[] = [];
  setOutputWriterForTest((line) => lines.push(line));
  await main(body, argv);
  return lines.map(stripStamp);
}

describe("signal exit contract", () => {
  test("SIGINT and SIGTERM flush, restore the terminal, and exit 130/143 once each", () => {
    const target = new EventEmitter();
    const calls: string[] = [];
    installSignalExit({
      flush: () => calls.push("flush"),
      restore: () => calls.push("restore"),
      exit: (code) => calls.push(`exit:${code}`),
    }, target as unknown as NodeJS.Process);

    target.emit("SIGINT");
    expect(calls).toEqual(["flush", "restore", `exit:${SIGNAL_EXIT_CODES.SIGINT}`]);
    // A second signal takes the default action: the handler does not run again.
    target.emit("SIGINT");
    expect(calls).toHaveLength(3);
    expect(target.listenerCount("SIGINT")).toBe(0);

    target.emit("SIGTERM");
    expect(calls.slice(3)).toEqual(["flush", "restore", `exit:${SIGNAL_EXIT_CODES.SIGTERM}`]);
  });

  test("a failing flush still restores the terminal and exits", () => {
    const target = new EventEmitter();
    const calls: string[] = [];
    installSignalExit({
      flush: () => {
        throw new Error("flush failed");
      },
      restore: () => calls.push("restore"),
      exit: (code) => calls.push(`exit:${code}`),
    }, target as unknown as NodeJS.Process);
    target.emit("SIGTERM");
    expect(calls).toEqual(["restore", "exit:143"]);
  });
});

describe("main() error channel", () => {
  test("a CliError renders at error severity, after buffered warnings, with no stack", async () => {
    const lines = await runMain(async () => {
      warn("something to know first");
      throw new CliError("refused for a named reason\nrun: runfree up", 3);
    });
    expect(lines).toEqual([
      "runfree warning: something to know first",
      "runfree error: refused for a named reason\n  run: runfree up",
    ]);
    expect(process.exitCode).toBe(3);
    expect(lines.join("\n")).not.toMatch(/^\s+at /m);
  });

  test("a CliError detail (usage block) renders raw after the message", async () => {
    const lines = await runMain(async () => {
      throw new CliError("runfree host needs a subcommand", 1, { detail: "Commands:\n  runfree host add <host>\n" });
    });
    expect(lines).toEqual(["runfree error: runfree host needs a subcommand\n\nCommands:\n  runfree host add <host>"]);
  });

  test("an unexpected error hides the stack behind --verbose and names the flag", async () => {
    const boom = new Error("invariant violated");
    boom.stack = "Error: invariant violated\n    at somewhere (file.ts:1:1)";
    const quiet = await runMain(async () => {
      throw boom;
    });
    expect(quiet).toEqual([
      "runfree error: Error: invariant violated\n  run the command again with --verbose to print the stack trace",
    ]);
    expect(process.exitCode).toBe(1);

    const loud = await runMain(async () => {
      throw boom;
    }, ["--verbose"]);
    expect(loud.join("\n")).toContain("at somewhere (file.ts:1:1)");
    expect(loud.join("\n")).not.toContain("--verbose to print");
  });

  test("a successful run flushes warnings at exit and keeps the status", async () => {
    const lines = await runMain(async () => {
      warn("late qualifier");
      return 0;
    });
    expect(lines).toEqual(["runfree warning: late qualifier"]);
    expect(process.exitCode).toBe(0);
  });

  test("verboseRequested scans argv", () => {
    expect(verboseRequested(["host", "list"])).toBe(false);
    expect(verboseRequested(["host", "list", "--verbose"])).toBe(true);
    expect(verboseRequested(["-v"])).toBe(true);
  });
});

// Headless-run spec §3.3: the stty save in `main` reads the host terminal
// directly, so `run` skips it (and the matching restore) entirely.
describe("terminal mode save and restore", () => {
  const descriptors: Array<[{ isTTY?: boolean }, PropertyDescriptor | undefined]> = [];
  function stubTty(stream: { isTTY?: boolean }): void {
    descriptors.push([stream, Object.getOwnPropertyDescriptor(stream, "isTTY")]);
    Object.defineProperty(stream, "isTTY", { configurable: true, value: true });
  }
  afterEach(() => {
    for (const [stream, descriptor] of descriptors.reverse()) {
      if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
      else delete (stream as { isTTY?: boolean }).isTTY;
    }
    descriptors.length = 0;
    vi.restoreAllMocks();
  });

  function sttyCalls(): Array<readonly string[]> {
    const spawnSync = childProcess.spawnSync as unknown as { mock: { calls: unknown[][] } };
    return spawnSync.mock.calls
      .filter((call) => call[0] === "stty")
      .map((call) => call[1] as readonly string[]);
  }

  test("the command name is the first token after the global --workspace options", () => {
    expect(commandNameFromArgv(["--workspace", "/tmp/project", "run", "claude"])).toBe("run");
    expect(commandNameFromArgv(["--workspace=/tmp/project", "run"])).toBe("run");
    expect(commandNameFromArgv(["run", "--workspace", "/x"])).toBe("run");
    expect(commandNameFromArgv(["status"])).toBe("status");
    expect(commandNameFromArgv([])).toBeUndefined();
    // A malformed global option is the command's error to report, not this scan's.
    expect(commandNameFromArgv(["--workspace"])).toBeUndefined();
  });

  test("a run never spawns stty, even with a TTY on both streams", async () => {
    stubTty(process.stdin);
    stubTty(process.stdout);
    vi.spyOn(childProcess, "spawnSync").mockImplementation((() => ({ status: 0, stdout: "saved-mode", stderr: "" })) as never);
    await runMain(async () => 0, ["--workspace", "/tmp/project", "run", "claude", "--prompt-file", "p.md"]);
    expect(sttyCalls()).toEqual([]);
  });

  test("every other command still saves and restores the terminal mode", async () => {
    stubTty(process.stdin);
    stubTty(process.stdout);
    vi.spyOn(childProcess, "spawnSync").mockImplementation((() => ({ status: 0, stdout: "saved-mode", stderr: "" })) as never);
    await runMain(async () => 0, ["--workspace", "/tmp/project", "status"]);
    expect(sttyCalls()).toEqual([["-g"], ["saved-mode"]]);
  });
});
