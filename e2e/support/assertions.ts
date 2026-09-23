import fs from "node:fs";

import { describeCommandResult, type CommandResult } from "./command.ts";

export function assertExit(result: CommandResult, expected: number): void {
  if (result.outcome.kind !== "exit" || result.outcome.exitCode !== expected) {
    throw new Error(`expected exit ${expected}\n${describeCommandResult(result)}`);
  }
}

export function assertOutputContains(result: CommandResult, expected: string): void {
  if (!`${result.stdout}${result.stderr}`.includes(expected)) {
    throw new Error(`expected output to contain ${JSON.stringify(expected)}\n${describeCommandResult(result)}`);
  }
}

export function assertOutputExcludes(result: CommandResult, unexpected: string): void {
  if (`${result.stdout}${result.stderr}`.includes(unexpected)) {
    throw new Error(`expected output to exclude ${JSON.stringify(unexpected)}\n${describeCommandResult(result)}`);
  }
}

export function assertFileMode(file: string, expected: number): void {
  const actual = fs.statSync(file).mode & 0o7777;
  if (actual !== expected) {
    throw new Error(`expected ${file} mode ${expected.toString(8)}, got ${actual.toString(8)}`);
  }
}

export function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}
