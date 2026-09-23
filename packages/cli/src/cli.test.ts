import { EventEmitter } from "node:events";
import { afterEach, describe, expect, test } from "vitest";

import { installSignalExit, main, SIGNAL_EXIT_CODES, verboseRequested } from "./cli.ts";
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
