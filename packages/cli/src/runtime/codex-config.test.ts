import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test } from "vitest";

import { flushWarnings, pendingWarningsForTest } from "../warnings.ts";
import { updateCodexConfig } from "./codex-config.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-codex-config-"));
});

afterEach(() => {
  flushWarnings();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function updateWith(contents: string) {
  const codexDir = path.join(tmp, "state", "codex");
  return {
    codexDir,
    result: updateCodexConfig(codexDir, () => contents),
  };
}

function expectUnsafeWarning(configPath: string): void {
  expect(pendingWarningsForTest().map((event) => event.message)).toContainEqual(
    expect.stringContaining(`Codex config update skipped:`),
  );
  expect(pendingWarningsForTest().map((event) => event.message).join("\n")).toContain(configPath);
  expect(pendingWarningsForTest().map((event) => event.message).join("\n")).toContain("remove only this config.toml entry");
}

test("creates and atomically updates only the fixed Codex config file", () => {
  const first = updateWith("first = true\n");
  const configPath = path.join(first.codexDir, "config.toml");

  expect(first.result).toBe("updated");
  expect(fs.readFileSync(configPath, "utf8")).toBe("first = true\n");
  expect(fs.statSync(configPath).mode & 0o777).toBe(0o600);
  expect(fs.statSync(first.codexDir).mode & 0o777).toBe(0o700);
  expect(fs.readdirSync(first.codexDir)).toEqual(["config.toml"]);

  const originalInode = fs.statSync(configPath).ino;
  expect(updateCodexConfig(first.codexDir, (current) => current)).toBe("unchanged");
  expect(fs.statSync(configPath).ino).toBe(originalInode);

  expect(updateCodexConfig(first.codexDir, () => "second = true\n")).toBe("updated");
  expect(fs.readFileSync(configPath, "utf8")).toBe("second = true\n");
  expect(fs.statSync(configPath).ino).not.toBe(originalInode);
  expect(fs.readdirSync(first.codexDir)).toEqual(["config.toml"]);
});

test("refuses a config symlink without changing its target", () => {
  const codexDir = path.join(tmp, "state", "codex");
  const outside = path.join(tmp, "outside.toml");
  const configPath = path.join(codexDir, "config.toml");
  fs.mkdirSync(codexDir, { recursive: true });
  fs.writeFileSync(outside, "outside = true\n", { mode: 0o640 });
  const outsideMode = fs.statSync(outside).mode & 0o777;
  fs.symlinkSync(outside, configPath);

  expect(updateCodexConfig(codexDir, () => "attacker = true\n")).toBe("unsafe");

  expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
  expect(fs.statSync(outside).mode & 0o777).toBe(outsideMode);
  expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  expectUnsafeWarning(configPath);
});

test("refuses a dangling config symlink without creating its target", () => {
  const codexDir = path.join(tmp, "state", "codex");
  const outside = path.join(tmp, "missing.toml");
  const configPath = path.join(codexDir, "config.toml");
  fs.mkdirSync(codexDir, { recursive: true });
  fs.symlinkSync(outside, configPath);

  expect(updateCodexConfig(codexDir, () => "created = true\n")).toBe("unsafe");

  expect(fs.existsSync(outside)).toBe(false);
  expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  expectUnsafeWarning(configPath);
});

test("refuses hard links, directories, and FIFOs before writing", () => {
  const outside = path.join(tmp, "outside.toml");
  fs.writeFileSync(outside, "outside = true\n");

  for (const kind of ["hard-link", "directory", "fifo"] as const) {
    const codexDir = path.join(tmp, kind, "codex");
    const configPath = path.join(codexDir, "config.toml");
    fs.mkdirSync(codexDir, { recursive: true });
    if (kind === "hard-link") fs.linkSync(outside, configPath);
    if (kind === "directory") fs.mkdirSync(configPath);
    if (kind === "fifo") {
      const created = childProcess.spawnSync("mkfifo", [configPath], { stdio: "ignore" });
      expect(created.status).toBe(0);
    }

    expect(updateCodexConfig(codexDir, () => "changed = true\n")).toBe("unsafe");
    expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
    expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
    expectUnsafeWarning(configPath);
    flushWarnings();
  }
});

test("refuses an oversized config before allocating or writing replacement state", () => {
  const codexDir = path.join(tmp, "state", "codex");
  const configPath = path.join(codexDir, "config.toml");
  fs.mkdirSync(codexDir, { recursive: true });
  fs.writeFileSync(configPath, Buffer.alloc(1024 * 1024 + 1, 0x61));

  expect(updateCodexConfig(codexDir, () => "small = true\n")).toBe("unsafe");

  expect(fs.statSync(configPath).size).toBe(1024 * 1024 + 1);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  expectUnsafeWarning(configPath);
});

test("refuses a symlinked Codex state root without changing its target", () => {
  const codexDir = path.join(tmp, "state", "codex");
  const outsideDir = path.join(tmp, "outside");
  const sentinel = path.join(outsideDir, "sentinel");
  fs.mkdirSync(path.dirname(codexDir), { recursive: true });
  fs.mkdirSync(outsideDir);
  fs.writeFileSync(sentinel, "outside\n");
  fs.symlinkSync(outsideDir, codexDir, "dir");

  expect(updateCodexConfig(codexDir, () => "created = true\n")).toBe("unsafe");

  expect(fs.readFileSync(sentinel, "utf8")).toBe("outside\n");
  expect(fs.existsSync(path.join(outsideDir, "config.toml"))).toBe(false);
  expect(fs.lstatSync(codexDir).isSymbolicLink()).toBe(true);
  expectUnsafeWarning(path.join(codexDir, "config.toml"));
});
