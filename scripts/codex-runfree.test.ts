import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

const adapterPath = path.resolve("packages/agent-runtime/agent/codex-runfree.sh");
let tmp: string;
let installedAdapterPath: string;
let argvPath: string;
let countPath: string;
let portFilePath: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-codex-adapter-"));
  const libexecDir = path.join(tmp, "usr", "local", "libexec", "runfree");
  const binDir = path.join(tmp, "usr", "local", "bin");
  fs.mkdirSync(libexecDir, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  const adapterCopyPath = path.join(libexecDir, "codex");
  fs.copyFileSync(adapterPath, adapterCopyPath);
  fs.chmodSync(adapterCopyPath, 0o755);
  installedAdapterPath = path.join(binDir, "codex");
  fs.symlinkSync(path.relative(binDir, adapterCopyPath), installedAdapterPath);
  argvPath = path.join(tmp, "argv.json");
  countPath = path.join(tmp, "count.txt");
  portFilePath = path.join(tmp, "callback-port");
  fs.writeFileSync(path.join(libexecDir, "codex-real"), [
    "#!/usr/bin/env node",
    'const fs = require("node:fs");',
    "fs.writeFileSync(process.env.RUNFREE_TEST_ARGV_PATH, JSON.stringify(process.argv.slice(2)));",
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
      RUNFREE_MCP_OAUTH_CALLBACK_PORT_FILE: portFilePath,
      RUNFREE_TEST_ARGV_PATH: argvPath,
      RUNFREE_TEST_COUNT_PATH: countPath,
      RUNFREE_TEST_EXIT_STATUS: String(exitStatus),
    },
  });
}

function capturedArgv(): string[] {
  return JSON.parse(fs.readFileSync(argvPath, "utf8")) as string[];
}

describe("Runfree Codex launch adapter", () => {
  test("prepends the session callback port as a root config override", () => {
    fs.writeFileSync(portFilePath, "47612\n");
    const result = runAdapter(["mcp", "login", "posthog"]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual(["-c", "mcp_oauth_callback_port=47612", "mcp", "login", "posthog"]);
  });

  test("passes argv through unchanged without a session callback port", () => {
    const result = runAdapter(["--dangerously-bypass-approvals-and-sandbox", "prompt with spaces"]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual(["--dangerously-bypass-approvals-and-sandbox", "prompt with spaces"]);
  });

  test.each([
    ["empty", ""],
    ["non-numeric", "47612 -c model=x"],
    ["leading zero", "047612"],
    ["privileged", "443"],
    ["out of range", "65536"],
  ])("ignores a session callback port file that is %s", (_label, contents) => {
    fs.writeFileSync(portFilePath, contents);
    const result = runAdapter(["mcp", "list"]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual(["mcp", "list"]);
  });

  test("ignores a symlinked session callback port file", () => {
    const target = path.join(tmp, "elsewhere");
    fs.writeFileSync(target, "47612\n");
    fs.symlinkSync(target, portFilePath);
    const result = runAdapter(["mcp", "list"]);

    expect(result.status, result.stderr).toBe(0);
    expect(capturedArgv()).toEqual(["mcp", "list"]);
  });

  test("returns the real process status exactly once", () => {
    fs.writeFileSync(portFilePath, "47612\n");
    const result = runAdapter(["exec", "x"], 23);

    expect(result.status).toBe(23);
    expect(fs.readFileSync(countPath, "utf8").trim().split("\n")).toHaveLength(1);
  });
});
