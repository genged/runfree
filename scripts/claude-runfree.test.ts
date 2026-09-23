import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

const adapterPath = path.resolve("packages/agent-runtime/agent/claude-runfree.sh");
let tmp: string;
let fakeClaudePath: string;
let installedAdapterPath: string;
let argvPath: string;
let countPath: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-claude-adapter-"));
  const libexecDir = path.join(tmp, "usr", "local", "libexec", "runfree");
  const binDir = path.join(tmp, "usr", "local", "bin");
  fs.mkdirSync(libexecDir, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  const adapterCopyPath = path.join(libexecDir, "claude");
  fs.copyFileSync(adapterPath, adapterCopyPath);
  fs.chmodSync(adapterCopyPath, 0o755);
  installedAdapterPath = path.join(binDir, "claude");
  fs.symlinkSync(path.relative(binDir, adapterCopyPath), installedAdapterPath);
  fakeClaudePath = path.join(libexecDir, "claude-real");
  argvPath = path.join(tmp, "argv.json");
  countPath = path.join(tmp, "count.txt");
  fs.writeFileSync(fakeClaudePath, [
    "#!/usr/bin/env node",
    'const fs = require("node:fs");',
    'fs.writeFileSync(process.env.RUNFREE_TEST_ARGV_PATH, JSON.stringify(process.argv.slice(2)));',
    'fs.appendFileSync(process.env.RUNFREE_TEST_COUNT_PATH, "1\\n");',
    "process.exit(Number(process.env.RUNFREE_TEST_EXIT_STATUS || 0));",
    "",
  ].join("\n"), { mode: 0o755 });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function runAdapter(args: string[], exitStatus = 0): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync(installedAdapterPath, args, {
    encoding: "utf8",
    env: {
      ...process.env,
      RUNFREE_CLAUDE_MCP_CONFIG: "/runfree/mcp/claude.json",
      RUNFREE_TEST_ARGV_PATH: argvPath,
      RUNFREE_TEST_COUNT_PATH: countPath,
      RUNFREE_TEST_EXIT_STATUS: String(exitStatus),
    },
  });
}

function capturedArgv(): string[] {
  return JSON.parse(fs.readFileSync(argvPath, "utf8")) as string[];
}

describe("Runfree Claude launch adapter", () => {
  test("injects the approved config and strict mode while preserving caller argv", () => {
    const result = runAdapter(["--dangerously-skip-permissions", "prompt with spaces"]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual([
      "--mcp-config",
      "/runfree/mcp/claude.json",
      "--strict-mcp-config",
      "--dangerously-skip-permissions",
      "prompt with spaces",
    ]);
  });

  test("preserves a caller MCP config but still injects strict mode exactly once", () => {
    const result = runAdapter(["--mcp-config", "/tmp/custom.json", "--dangerously-skip-permissions"]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual([
      "--strict-mcp-config",
      "--mcp-config",
      "/tmp/custom.json",
      "--dangerously-skip-permissions",
    ]);
  });

  test("does not duplicate flags already supplied by the caller", () => {
    const result = runAdapter([
      "--mcp-config=/tmp/custom.json",
      "--strict-mcp-config",
      "--dangerously-skip-permissions",
    ]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual([
      "--mcp-config=/tmp/custom.json",
      "--strict-mcp-config",
      "--dangerously-skip-permissions",
    ]);
  });

  test("returns the real process failure without retrying in non-strict mode", () => {
    const result = runAdapter(["--dangerously-skip-permissions"], 23);

    expect(result.status).toBe(23);
    expect(fs.readFileSync(countPath, "utf8").trim().split("\n")).toHaveLength(1);
    expect(capturedArgv()).toContain("--strict-mcp-config");
  });
});
