import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  deleteInboxPrompt,
  HEADLESS_PROMPT_CAP_BYTES,
  HeadlessPromptFileError,
  readPromptFileBounded,
  writeInboxPrompt,
} from "./headless-prompt.ts";
import { HEADLESS_PROMPT_CONTAINER_PATH_PATTERN } from "./session-launch.ts";

const RUN_ID = "run-20261025T120000Z-0a1b2c3d";

let tmp: string;
let inbox: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-headless-prompt-"));
  inbox = path.join(tmp, "state", "inbox");
  fs.mkdirSync(path.dirname(inbox), { recursive: true });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function promptFile(contents: string | Buffer, name = "task.md"): string {
  const filePath = path.join(tmp, name);
  fs.writeFileSync(filePath, contents);
  return filePath;
}

describe("readPromptFileBounded", () => {
  test("reads a regular file's exact bytes", () => {
    const bytes = Buffer.from([0x23, 0x20, 0xff, 0x00, 0x0a]);
    expect(readPromptFileBounded(promptFile(bytes))).toEqual(bytes);
  });

  test("accepts a file of exactly the cap and refuses one byte more", () => {
    expect(readPromptFileBounded(promptFile(Buffer.alloc(16, 0x61)), 16)).toHaveLength(16);
    expect(() => readPromptFileBounded(promptFile(Buffer.alloc(17, 0x61), "big.md"), 16))
      .toThrow(HeadlessPromptFileError);
  });

  test("the default cap is 1 MiB", () => {
    expect(HEADLESS_PROMPT_CAP_BYTES).toBe(1024 * 1024);
    const filePath = promptFile(Buffer.alloc(HEADLESS_PROMPT_CAP_BYTES + 1, 0x61));
    expect(() => readPromptFileBounded(filePath)).toThrow(/larger than 1048576 bytes/);
  });

  test("refuses a symlink, even one to a regular file", () => {
    const target = promptFile("hello");
    const link = path.join(tmp, "link.md");
    fs.symlinkSync(target, link);
    expect(() => readPromptFileBounded(link)).toThrow(/symlink/);
  });

  test("refuses a directory and a missing path", () => {
    expect(() => readPromptFileBounded(tmp)).toThrow(/not a regular file/);
    expect(() => readPromptFileBounded(path.join(tmp, "missing.md"))).toThrow(/could not be read/);
  });

  test.skipIf(process.platform === "win32")("refuses a FIFO without blocking on it", (ctx) => {
    const fifo = path.join(tmp, "prompt.fifo");
    const made = childProcess.spawnSync("mkfifo", [fifo]);
    if (made.error || made.status !== 0) ctx.skip();
    const startedAt = Date.now();
    expect(() => readPromptFileBounded(fifo)).toThrow(/not a regular file/);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  test("refuses a file swapped after its lstat (identity mismatch)", () => {
    const filePath = promptFile("first");
    const realLstat = fs.lstatSync;
    let swapped = false;
    const spy = vi.spyOn(fs, "lstatSync").mockImplementation(((target: fs.PathLike, options?: fs.StatSyncOptions) => {
      const stat = realLstat(target, options as fs.StatSyncOptions) as fs.Stats;
      if (!swapped && target === filePath) {
        swapped = true;
        // Created before the rename, so it can never reuse the old inode.
        fs.writeFileSync(`${filePath}.new`, "second");
        fs.renameSync(`${filePath}.new`, filePath);
      }
      return stat;
    }) as typeof fs.lstatSync);
    try {
      expect(() => readPromptFileBounded(filePath)).toThrow(/changed while it was read/);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("inbox prompt", () => {
  test("writes the bytes into the inbox as <runId>.prompt (0600) and returns the container path", () => {
    const containerPath = writeInboxPrompt(inbox, RUN_ID, Buffer.from("do the thing\n"));

    expect(containerPath).toBe(`/runfree/inbox/${RUN_ID}.prompt`);
    expect(HEADLESS_PROMPT_CONTAINER_PATH_PATTERN.test(containerPath)).toBe(true);
    const hostPath = path.join(inbox, `${RUN_ID}.prompt`);
    expect(fs.readFileSync(hostPath, "utf8")).toBe("do the thing\n");
    expect(fs.statSync(hostPath).mode & 0o777).toBe(0o600);
    expect(fs.statSync(inbox).mode & 0o777).toBe(0o700);
  });

  test("refuses a malformed run id before any write", () => {
    expect(() => writeInboxPrompt(inbox, "run-../../x", Buffer.from("x"))).toThrow(/run id/);
    expect(fs.existsSync(inbox)).toBe(false);
  });

  test("never follows or replaces a pre-planted file or symlink", () => {
    fs.mkdirSync(inbox, { mode: 0o700 });
    const outside = path.join(tmp, "outside.txt");
    fs.symlinkSync(outside, path.join(inbox, `${RUN_ID}.prompt`));

    expect(() => writeInboxPrompt(inbox, RUN_ID, Buffer.from("x"))).toThrow();
    expect(fs.existsSync(outside)).toBe(false);
  });

  test("delete removes only that exact regular file and tolerates its absence", () => {
    writeInboxPrompt(inbox, RUN_ID, Buffer.from("x"));
    fs.writeFileSync(path.join(inbox, "clip-2026-10-25-120000-abcd.png"), "image");

    deleteInboxPrompt(inbox, RUN_ID);
    deleteInboxPrompt(inbox, RUN_ID);

    expect(fs.readdirSync(inbox)).toEqual(["clip-2026-10-25-120000-abcd.png"]);
  });

  test("delete leaves a directory planted at the prompt name", () => {
    fs.mkdirSync(path.join(inbox, `${RUN_ID}.prompt`), { recursive: true });
    expect(() => deleteInboxPrompt(inbox, RUN_ID)).toThrow(/not a regular file/);
    expect(fs.statSync(path.join(inbox, `${RUN_ID}.prompt`)).isDirectory()).toBe(true);
  });
});
