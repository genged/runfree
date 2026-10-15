#!/usr/bin/env node

import childProcess from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCommandApp } from "./commands/app.ts";
import { createCommandContext } from "./commands/context.ts";
import { printHelpTopic } from "./commands/help-topics.ts";
import { CliError, die, renderUnexpectedError, UNEXPECTED_ERROR_RENDER_LIMITS } from "./errors.ts";
import { createRuntimeTimings } from "./runtime/timings.ts";
import { installSignalExit } from "./signal-exit.ts";
import { flushWarnings, runfreeError } from "./warnings.ts";

type ParsedArgs = {
  projectRoot: string;
  invocationCwd: string;
  commandArgs: string[];
};

function currentTerminalMode(): string | undefined {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return undefined;
  const result = childProcess.spawnSync("stty", ["-g"], {
    encoding: "utf8",
    stdio: ["inherit", "pipe", "ignore"],
  });
  if (result.status !== 0) return undefined;
  const mode = typeof result.stdout === "string" ? result.stdout.trim() : "";
  return mode === "" ? undefined : mode;
}

function restoreTerminal(mode: string | undefined): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return;
  const args = mode ? [mode] : ["sane"];
  childProcess.spawnSync("stty", args, { stdio: "ignore" });
}

// Parse the global `--workspace` option. Only leading `--workspace <dir>` and
// `--workspace=<dir>` tokens are global; once the first non-workspace token is
// seen, the remainder belongs to the command and any later `--workspace` token
// is left in `commandArgs` for the command to accept or reject.
function parseArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): ParsedArgs {
  let projectRoot = env.RUNFREE_PROJECT_ROOT;
  const invocationCwd = path.resolve(env.RUNFREE_INVOCATION_CWD ?? projectRoot ?? process.cwd());

  let index = 0;
  for (; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--workspace") {
      const value = argv[index + 1];
      if (!value) die("--workspace requires a directory");
      projectRoot = path.resolve(invocationCwd, value);
      index += 1;
      continue;
    }
    if (arg.startsWith("--workspace=")) {
      projectRoot = path.resolve(invocationCwd, arg.slice("--workspace=".length));
      continue;
    }
    break;
  }

  return {
    projectRoot: path.resolve(invocationCwd, projectRoot ?? "."),
    invocationCwd,
    commandArgs: argv.slice(index),
  };
}

export async function runCli(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const timings = createRuntimeTimings(env);
  if (timings.enabled) {
    timings.report("cli-entry", JSON.stringify({ pid: process.pid, processTimeOriginMs: performance.timeOrigin, entryMs: performance.now() }));
  }
  const { projectRoot, invocationCwd, commandArgs } = parseArgs(argv, env);
  const command = commandArgs[0];

  // Task-oriented help is handled before yargs so it never collides with
  // command-specific syntax help and never materializes assets.
  if (command === "help" || command === "-h" || command === "--help") {
    if (command === "help") {
      if (commandArgs.length > 2) die("usage: runfree help [topic]");
      printHelpTopic(commandArgs[1]);
    } else {
      printHelpTopic(undefined);
    }
    return 0;
  }

  const context = createCommandContext({ projectRoot, invocationCwd, commandName: command ?? "", env });
  // Every command is typed: the `$0 [agent]` default resolves runtime/agent
  // intents itself and never delegates, so the legacy passthrough is gone. The
  // sentinel guards against a future command accidentally calling it.
  return runCommandApp(context, commandArgs, () => {
    throw new Error("internal: runDefault delegation was removed; every command is typed");
  });
}

export { installSignalExit, SIGNAL_EXIT_CODES, type SignalExitHooks } from "./signal-exit.ts";

// `--verbose`/`-v` anywhere in argv turns on stack traces for unexpected
// errors. Scanned rather than parsed: an unexpected error may have escaped
// before or during parsing.
export function verboseRequested(argv: readonly string[]): boolean {
  return argv.includes("--verbose") || argv.includes("-v");
}

// `run` and `argv` are injectable so the error channel is unit-testable
// without spawning the CLI.
export async function main(
  run: (argv: string[]) => Promise<number> = runCli,
  argv: string[] = process.argv.slice(2),
): Promise<void> {
  const terminalMode = currentTerminalMode();
  const restore = onceOnly(() => restoreTerminal(terminalMode));
  installSignalExit({ flush: flushWarnings, restore, exit: (code) => process.exit(code) });
  try {
    process.exitCode = await run(argv);
  } catch (error) {
    // Buffered warnings explain the failure; they render before it.
    flushWarnings();
    if (error instanceof CliError) {
      // Refusals (CliError and its AdminExit subclass) render at error
      // severity with no stack; the status is the exit code.
      runfreeError(error.message, error.detail);
      process.exitCode = error.status;
      return;
    }
    runfreeError(renderUnexpectedError(error, UNEXPECTED_ERROR_RENDER_LIMITS, { stack: verboseRequested(argv) }));
    process.exitCode = 1;
  } finally {
    flushWarnings();
    restore();
  }
}

function onceOnly(action: () => void): () => void {
  let done = false;
  return () => {
    if (done) return;
    done = true;
    action();
  };
}

const entryPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entryPath === fileURLToPath(import.meta.url)) {
  await main();
}
