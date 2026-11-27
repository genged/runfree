// Race and refusal tests for updateCodexConfig. The Codex state directory is
// bind-mounted read-write into the untrusted agent container, so each test
// makes the container's move with a real filesystem change at the moment the
// host is between two checks: inside the `update` callback where it runs at
// that moment, otherwise in a `fs` wrapper that changes the filesystem and then
// calls the real function.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { flushWarnings, pendingWarningsForTest } from "../warnings.ts";
import { updateCodexConfig } from "./codex-config.ts";

const isRoot = process.getuid?.() === 0;
const OLD = "old = true\n";
const NEW = "new = true\n";
const TEMP_PREFIX = ".config.toml.runfree-";

let tmp: string;
let codexDir: string;
let configPath: string;
let restoreModes: Array<[string, number]>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-codex-config-race-"));
  codexDir = path.join(tmp, "state", "codex");
  configPath = path.join(codexDir, "config.toml");
  restoreModes = [];
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const [target, mode] of restoreModes) {
    if (fs.existsSync(target)) fs.chmodSync(target, mode);
  }
  flushWarnings();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function withOldConfig(): void {
  fs.mkdirSync(codexDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath, OLD, { mode: 0o600 });
}

function temporaryNames(): string[] {
  return fs.readdirSync(codexDir).filter((name) => name.startsWith(TEMP_PREFIX));
}

function onlyTemporaryPath(): string {
  const names = temporaryNames();
  expect(names).toHaveLength(1);
  return path.join(codexDir, names[0] ?? "");
}

function isDescriptorFor(descriptor: number, target: string): boolean {
  const opened = fs.fstatSync(descriptor);
  const named = fs.lstatSync(target, { throwIfNoEntry: false });
  return named !== undefined && opened.dev === named.dev && opened.ino === named.ino;
}

function expectUnsafe(result: string, reason: string, warnedPath = configPath): void {
  expect(result).toBe("unsafe");
  const messages = pendingWarningsForTest().map((event) => event.message);
  expect(messages).toHaveLength(1);
  const [first] = (messages[0] ?? "").split("\n");
  expect(first).toBe(`Codex config update skipped: ${reason}: ${warnedPath}`);
  expect(messages[0]).toContain("remove only this config.toml entry");
}

function expectNoWarning(): void {
  expect(pendingWarningsForTest()).toEqual([]);
}

test("R1 refuses a state root that is a regular file without creating anything", () => {
  fs.mkdirSync(path.dirname(codexDir), { recursive: true });
  fs.writeFileSync(codexDir, "not a directory\n");

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "the Codex state root cannot be created safely");
  expect(fs.readFileSync(codexDir, "utf8")).toBe("not a directory\n");
  expect(fs.readdirSync(path.dirname(codexDir))).toEqual(["codex"]);
});

test("R1 refuses a state root whose parent is a regular file without creating anything", () => {
  const parent = path.join(tmp, "state");
  fs.writeFileSync(parent, "parent file\n");

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "the Codex state root cannot be created safely");
  expect(fs.readFileSync(parent, "utf8")).toBe("parent file\n");
  expect(fs.readdirSync(tmp)).toEqual(["state"]);
});

test("refuses a state root removed between its creation and its lstat", () => {
  const realLstat = fs.lstatSync;
  let removals = 0;
  vi.spyOn(fs, "lstatSync").mockImplementation(((...args: Parameters<typeof fs.lstatSync>) => {
    if (args[0] === codexDir && removals === 0) {
      removals += 1;
      fs.rmdirSync(codexDir);
    }
    return realLstat(...args);
  }) as typeof fs.lstatSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "the Codex state root changed or is inaccessible");
  expect(removals).toBe(1);
  expect(fs.readdirSync(path.dirname(codexDir))).toEqual([]);
});

test("refuses a state root swapped for an outside symlink before it is opened", () => {
  withOldConfig();
  const movedAway = path.join(tmp, "moved-codex");
  const outsideDir = path.join(tmp, "outside");
  fs.mkdirSync(outsideDir);
  const realOpen = fs.openSync;
  let swaps = 0;
  vi.spyOn(fs, "openSync").mockImplementation(((...args: Parameters<typeof fs.openSync>) => {
    if (args[0] === codexDir && swaps === 0) {
      swaps += 1;
      fs.renameSync(codexDir, movedAway);
      fs.symlinkSync(outsideDir, codexDir, "dir");
    }
    return realOpen(...args);
  }) as typeof fs.openSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "the Codex state root changed or is inaccessible");
  expect(swaps).toBe(1);
  expect(fs.readdirSync(outsideDir)).toEqual([]);
  expect(fs.lstatSync(codexDir).isSymbolicLink()).toBe(true);
  expect(fs.readFileSync(path.join(movedAway, "config.toml"), "utf8")).toBe(OLD);
});

test("refuses a state root replaced by another directory before it is opened", () => {
  withOldConfig();
  const movedAway = path.join(tmp, "moved-codex");
  const realOpen = fs.openSync;
  let swaps = 0;
  vi.spyOn(fs, "openSync").mockImplementation(((...args: Parameters<typeof fs.openSync>) => {
    if (args[0] === codexDir && swaps === 0) {
      swaps += 1;
      fs.renameSync(codexDir, movedAway);
      fs.mkdirSync(codexDir, { mode: 0o700 });
    }
    return realOpen(...args);
  }) as typeof fs.openSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "the Codex state root changed while it was opened");
  expect(swaps).toBe(1);
  expect(fs.readdirSync(codexDir)).toEqual([]);
  expect(fs.readFileSync(path.join(movedAway, "config.toml"), "utf8")).toBe(OLD);
  expect(fs.readdirSync(movedAway)).toEqual(["config.toml"]);
});

test("refuses when the state root becomes a file before config.toml is inspected", () => {
  withOldConfig();
  const movedAway = path.join(tmp, "moved-codex");
  const realLstat = fs.lstatSync;
  let swaps = 0;
  vi.spyOn(fs, "lstatSync").mockImplementation(((...args: Parameters<typeof fs.lstatSync>) => {
    if (args[0] === configPath && swaps === 0) {
      swaps += 1;
      fs.renameSync(codexDir, movedAway);
      fs.writeFileSync(codexDir, "not a directory\n");
    }
    return realLstat(...args);
  }) as typeof fs.lstatSync);
  const update = vi.fn(() => NEW);

  const result = updateCodexConfig(codexDir, update);

  expectUnsafe(result, "config.toml changed or is inaccessible");
  expect(swaps).toBe(1);
  expect(update).not.toHaveBeenCalled();
  expect(fs.readFileSync(codexDir, "utf8")).toBe("not a directory\n");
  expect(fs.readFileSync(path.join(movedAway, "config.toml"), "utf8")).toBe(OLD);
  expect(fs.readdirSync(movedAway)).toEqual(["config.toml"]);
});

test.skipIf(isRoot)("R2 refuses a config.toml that cannot be opened", () => {
  withOldConfig();
  fs.chmodSync(configPath, 0o000);
  restoreModes.push([configPath, 0o600]);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "config.toml changed before it could be opened safely");
  fs.chmodSync(configPath, 0o600);
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("R3 refuses a config.toml swapped between its lstat and its open", () => {
  withOldConfig();
  const swapped = path.join(tmp, "swapped.toml");
  fs.writeFileSync(swapped, "swapped = true\n", { mode: 0o600 });
  const realOpen = fs.openSync;
  let swaps = 0;
  vi.spyOn(fs, "openSync").mockImplementation(((...args: Parameters<typeof fs.openSync>) => {
    if (args[0] === configPath && swaps === 0) {
      swaps += 1;
      fs.renameSync(swapped, configPath);
    }
    return realOpen(...args);
  }) as typeof fs.openSync);
  const update = vi.fn(() => NEW);

  const result = updateCodexConfig(codexDir, update);

  expectUnsafe(result, "config.toml changed before it could be read safely");
  expect(swaps).toBe(1);
  expect(update).not.toHaveBeenCalled();
  expect(fs.readFileSync(configPath, "utf8")).toBe("swapped = true\n");
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("R4 refuses a config.toml truncated after it was opened", () => {
  withOldConfig();
  const realRead = fs.readSync;
  let reads = 0;
  vi.spyOn(fs, "readSync").mockImplementation(((...args: Parameters<typeof fs.readSync>) => {
    reads += 1;
    if (reads === 1 && isDescriptorFor(args[0], configPath)) fs.truncateSync(configPath, 0);
    return realRead(...args);
  }) as typeof fs.readSync);
  const update = vi.fn(() => NEW);

  const result = updateCodexConfig(codexDir, update);

  expectUnsafe(result, "config.toml changed while it was being read");
  expect(update).not.toHaveBeenCalled();
  expect(fs.readFileSync(configPath, "utf8")).toBe("");
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("R4 refuses a config.toml that changed after the read loop", () => {
  withOldConfig();
  const realRead = fs.readSync;
  let reads = 0;
  vi.spyOn(fs, "readSync").mockImplementation(((...args: Parameters<typeof fs.readSync>) => {
    reads += 1;
    const target = reads === 1 && isDescriptorFor(args[0], configPath);
    const bytesRead = realRead(...args);
    if (target) fs.appendFileSync(configPath, "appended = true\n");
    return bytesRead;
  }) as typeof fs.readSync);
  const update = vi.fn(() => NEW);

  const result = updateCodexConfig(codexDir, update);

  expectUnsafe(result, "config.toml changed while it was being read");
  expect(update).not.toHaveBeenCalled();
  expect(fs.readFileSync(configPath, "utf8")).toBe(`${OLD}appended = true\n`);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("R5 refuses a config.toml replaced by a directory before the commit and removes the temporary file", () => {
  withOldConfig();

  const result = updateCodexConfig(codexDir, () => {
    fs.rmSync(configPath);
    fs.mkdirSync(configPath);
    fs.writeFileSync(path.join(configPath, "attacker"), "attacker\n");
    return NEW;
  });

  expectUnsafe(result, "config.toml changed before it could be replaced safely");
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  expect(fs.lstatSync(configPath).isDirectory()).toBe(true);
  expect(fs.readdirSync(configPath)).toEqual(["attacker"]);
  expect(fs.readFileSync(path.join(configPath, "attacker"), "utf8")).toBe("attacker\n");
});

test.skipIf(isRoot)("R6 refuses a state root that refuses the temporary file", () => {
  withOldConfig();
  restoreModes.push([codexDir, 0o700]);

  const result = updateCodexConfig(codexDir, () => {
    fs.chmodSync(codexDir, 0o500);
    return NEW;
  });

  expectUnsafe(result, "the Codex state root changed or refused a safe temporary file");
  fs.chmodSync(codexDir, 0o700);
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("R7 refuses when every temporary name is already taken and leaves the squatted file", () => {
  withOldConfig();
  const fixed = Buffer.alloc(16, 0xab);
  const squatted = path.join(codexDir, `${TEMP_PREFIX}${process.pid}-${fixed.toString("hex")}.tmp`);
  fs.writeFileSync(squatted, "squatted\n", { mode: 0o644 });
  const squattedIno = fs.statSync(squatted).ino;
  vi.spyOn(crypto, "randomBytes").mockImplementation((() => Buffer.from(fixed)) as unknown as typeof crypto.randomBytes);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "a unique temporary config.toml file could not be created");
  expect(fs.readFileSync(squatted, "utf8")).toBe("squatted\n");
  expect(fs.statSync(squatted).ino).toBe(squattedIno);
  expect(fs.statSync(squatted).mode & 0o777).toBe(0o644);
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir).sort()).toEqual([path.basename(squatted), "config.toml"].sort());
});

test("retries a taken temporary name and commits with the next one", () => {
  withOldConfig();
  const taken = Buffer.alloc(16, 0xab);
  const free = Buffer.alloc(16, 0xcd);
  const squatted = path.join(codexDir, `${TEMP_PREFIX}${process.pid}-${taken.toString("hex")}.tmp`);
  fs.writeFileSync(squatted, "squatted\n");
  let calls = 0;
  vi.spyOn(crypto, "randomBytes").mockImplementation((() => {
    calls += 1;
    return Buffer.from(calls === 1 ? taken : free);
  }) as unknown as typeof crypto.randomBytes);

  const result = updateCodexConfig(codexDir, () => NEW);

  expect(result).toBe("updated");
  expectNoWarning();
  expect(fs.readFileSync(configPath, "utf8")).toBe(NEW);
  expect(fs.readFileSync(squatted, "utf8")).toBe("squatted\n");
  expect(fs.readdirSync(codexDir).sort()).toEqual([path.basename(squatted), "config.toml"].sort());
});

test("R8 refuses a temporary file replaced after its first fsync", () => {
  withOldConfig();
  const movedAway = path.join(tmp, "moved-away.tmp");
  const realFsync = fs.fsyncSync;
  let fsyncs = 0;
  vi.spyOn(fs, "fsyncSync").mockImplementation(((descriptor: number) => {
    fsyncs += 1;
    realFsync(descriptor);
    if (fsyncs !== 1) return;
    const temporaryPath = onlyTemporaryPath();
    expect(isDescriptorFor(descriptor, temporaryPath)).toBe(true);
    fs.renameSync(temporaryPath, movedAway);
    fs.writeFileSync(temporaryPath, NEW, { mode: 0o600 });
  }) as typeof fs.fsyncSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "the temporary config.toml file changed during the update");
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  expect(fs.readFileSync(movedAway, "utf8")).toBe(NEW);
});

test("R9 refuses a config.toml overwritten right after the commit", () => {
  withOldConfig();
  const racer = path.join(tmp, "racer.toml");
  fs.writeFileSync(racer, "racer = true\n", { mode: 0o600 });
  const realRename = fs.renameSync;
  vi.spyOn(fs, "renameSync").mockImplementation(((from: fs.PathLike, to: fs.PathLike) => {
    realRename(from, to);
    if (to === configPath && path.basename(String(from)).startsWith(TEMP_PREFIX)) realRename(racer, configPath);
  }) as typeof fs.renameSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "config.toml changed while the replacement was committed");
  expect(fs.readFileSync(configPath, "utf8")).toBe("racer = true\n");
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("R9 refuses a committed config.toml moved away and replaced while keeping its single link", () => {
  withOldConfig();
  const racer = path.join(tmp, "racer.toml");
  const movedAway = path.join(tmp, "moved-away.toml");
  fs.writeFileSync(racer, "racer = true\n", { mode: 0o600 });
  const realRename = fs.renameSync;
  vi.spyOn(fs, "renameSync").mockImplementation(((from: fs.PathLike, to: fs.PathLike) => {
    realRename(from, to);
    if (to !== configPath || !path.basename(String(from)).startsWith(TEMP_PREFIX)) return;
    realRename(configPath, movedAway);
    realRename(racer, configPath);
  }) as typeof fs.renameSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "config.toml changed while the replacement was committed");
  expect(fs.readFileSync(configPath, "utf8")).toBe("racer = true\n");
  expect(fs.readFileSync(movedAway, "utf8")).toBe(NEW);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

for (const change of ["truncated", "rewritten"] as const) {
  test(`R10 refuses a committed config.toml ${change} before its read-back`, () => {
    fs.mkdirSync(codexDir, { recursive: true, mode: 0o700 });
    const attacker = "bad = true\n";
    expect(attacker.length).toBe(NEW.length);
    const realRead = fs.readSync;
    let changes = 0;
    vi.spyOn(fs, "readSync").mockImplementation(((...args: Parameters<typeof fs.readSync>) => {
      // No config exists yet, so the only reads are the commit's read-back.
      if (changes === 0 && isDescriptorFor(args[0], configPath)) {
        changes += 1;
        if (change === "truncated") fs.truncateSync(configPath, 0);
        else fs.writeFileSync(configPath, attacker);
      }
      return realRead(...args);
    }) as typeof fs.readSync);

    const result = updateCodexConfig(codexDir, () => NEW);

    expectUnsafe(result, "config.toml changed while the replacement was verified");
    expect(changes).toBe(1);
    expect(fs.readFileSync(configPath, "utf8")).toBe(change === "truncated" ? "" : attacker);
    expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  });
}

test("R11 refuses when the temporary file disappears after its fsync", () => {
  withOldConfig();
  const realFsync = fs.fsyncSync;
  let fsyncs = 0;
  vi.spyOn(fs, "fsyncSync").mockImplementation(((descriptor: number) => {
    fsyncs += 1;
    realFsync(descriptor);
    if (fsyncs === 1) fs.unlinkSync(onlyTemporaryPath());
  }) as typeof fs.fsyncSync);

  const result = updateCodexConfig(codexDir, () => NEW);

  expectUnsafe(result, "Codex state changed during the config.toml update");
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("N1 replaces a config.toml swapped for an outside symlink without following it", () => {
  withOldConfig();
  const outside = path.join(tmp, "outside.toml");
  fs.writeFileSync(outside, "outside = true\n");
  fs.chmodSync(outside, 0o640);

  const result = updateCodexConfig(codexDir, () => {
    fs.rmSync(configPath);
    fs.symlinkSync(outside, configPath);
    return NEW;
  });

  expect(result).toBe("updated");
  expectNoWarning();
  expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
  expect(fs.statSync(outside).mode & 0o777).toBe(0o640);
  const entry = fs.lstatSync(configPath);
  expect(entry.isFile()).toBe(true);
  expect(entry.nlink).toBe(1);
  expect(entry.mode & 0o777).toBe(0o600);
  expect(fs.readFileSync(configPath, "utf8")).toBe(NEW);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});

test("N2 leaves no config.toml when update declines and passes the current text", () => {
  const update = vi.fn((_current: string | undefined): string | undefined => undefined);

  expect(updateCodexConfig(codexDir, update)).toBe("unchanged");
  expect(update).toHaveBeenCalledExactlyOnceWith(undefined);
  expect(fs.readdirSync(codexDir)).toEqual([]);
  expect(fs.statSync(codexDir).mode & 0o777).toBe(0o700);

  fs.writeFileSync(configPath, OLD, { mode: 0o600 });
  const ino = fs.statSync(configPath).ino;
  update.mockClear();
  expect(updateCodexConfig(codexDir, update)).toBe("unchanged");
  expect(update).toHaveBeenCalledExactlyOnceWith(OLD);
  expect(fs.statSync(configPath).ino).toBe(ino);
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
  expectNoWarning();
});

test("N3 propagates an error thrown by update without touching state", () => {
  withOldConfig();
  const ino = fs.statSync(configPath).ino;
  const failure = new Error("update failed");

  let thrown: unknown;
  try {
    updateCodexConfig(codexDir, () => {
      throw failure;
    });
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBe(failure);
  expectNoWarning();
  expect(fs.statSync(configPath).ino).toBe(ino);
  expect(fs.readFileSync(configPath, "utf8")).toBe(OLD);
  expect(fs.readdirSync(codexDir)).toEqual(["config.toml"]);
});
