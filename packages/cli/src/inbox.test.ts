import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  CONTAINER_INBOX_DIR,
  MAX_IMPORTED_IMAGE_BYTES,
  cleanupInbox,
  containerInboxPath,
  ensureInbox,
  inboxMount,
  importedImageName,
  importImageFromClipboard,
} from "./inbox.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-inbox-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("Runfree inbox Phase 1", () => {
  test("uses one fixed read-only container path outside every project layout", () => {
    const hostInbox = path.join(tmp, "state", "inbox");
    ensureInbox(hostInbox);

    expect(inboxMount()).toEqual({
      type: "bind",
      source: "${RUNFREE_INBOX_DIR:?RUNFREE_INBOX_DIR is required}",
      target: CONTAINER_INBOX_DIR,
      readOnly: true,
    });
    expect(fs.statSync(hostInbox).isDirectory()).toBe(true);
    expect(containerInboxPath("clip-2026-05-14-153012-a8f3.png")).toBe(
      `${CONTAINER_INBOX_DIR}/clip-2026-05-14-153012-a8f3.png`,
    );
  });

  test("generates stable safe image names and rejects unsafe names for container paths", () => {
    expect(importedImageName(new Date("2026-05-14T15:30:12.000Z"), Buffer.from("a8f3", "hex"))).toBe(
      "clip-2026-05-14-153012-a8f3.png",
    );
    expect(() => containerInboxPath("../secret.png")).toThrow("invalid imported image filename");
    expect(() => containerInboxPath("clip-2026-05-14-153012-a8f3.jpg")).toThrow("invalid imported image filename");
  });

  test("imports only bounded PNG clipboard data into the fixed inbox", () => {
    const source = path.join(tmp, "source.png");
    const hostInbox = path.join(tmp, "state", "inbox");
    fs.writeFileSync(source, Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]));

    const result = importImageFromClipboard({
      env: {
        RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source,
        RUNFREE_TEST_INBOX_RANDOM: "a8f3",
      },
      hostInbox,
      now: new Date("2026-05-14T15:30:12.000Z"),
    });

    expect(result.containerPath).toBe(`${CONTAINER_INBOX_DIR}/clip-2026-05-14-153012-a8f3.png`);
    expect(fs.readFileSync(result.hostPath)).toEqual(fs.readFileSync(source));
  });

  test("rejects invalid and oversized clipboard bytes before creating an inbox file", () => {
    const hostInbox = path.join(tmp, "state", "inbox");
    const source = path.join(tmp, "source.png");
    fs.writeFileSync(source, "not png");
    expect(() => importImageFromClipboard({
      env: { RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source },
      hostInbox,
    })).toThrow("did not contain PNG image data");
    expect(fs.readdirSync(hostInbox)).toEqual([]);

    fs.writeFileSync(source, Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      Buffer.alloc(MAX_IMPORTED_IMAGE_BYTES - 3),
    ]));
    expect(() => importImageFromClipboard({
      env: { RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source },
      hostInbox,
    })).toThrow("clipboard image exceeds");
    expect(fs.readdirSync(hostInbox)).toEqual([]);
  });

  test("cleans only minted files and supports an explicit all-files cleanup", () => {
    const hostInbox = path.join(tmp, "state", "inbox");
    ensureInbox(hostInbox);
    const oldImage = path.join(hostInbox, "clip-2026-05-14-153012-a8f3.png");
    const freshImage = path.join(hostInbox, "clip-2026-05-14-153013-a8f4.png");
    const unrelated = path.join(hostInbox, "notes.txt");
    const matchingSymlink = path.join(hostInbox, "clip-2026-05-14-153014-a8f5.png");
    const matchingHardLink = path.join(hostInbox, "clip-2026-05-14-153015-a8f6.png");
    fs.writeFileSync(oldImage, "old");
    fs.writeFileSync(freshImage, "fresh");
    fs.writeFileSync(unrelated, "keep");
    fs.symlinkSync(unrelated, matchingSymlink);
    fs.linkSync(unrelated, matchingHardLink);
    const oldTime = new Date("2026-05-14T15:30:12.000Z");
    const freshTime = new Date("2026-05-15T15:29:13.000Z");
    fs.utimesSync(oldImage, oldTime, oldTime);
    fs.utimesSync(freshImage, freshTime, freshTime);

    expect(cleanupInbox(hostInbox, new Date("2026-05-15T15:30:13.000Z"))).toEqual([oldImage]);
    expect(fs.existsSync(freshImage)).toBe(true);
    expect(fs.lstatSync(matchingSymlink).isSymbolicLink()).toBe(true);
    expect(fs.existsSync(matchingHardLink)).toBe(true);
    expect(cleanupInbox(hostInbox, new Date(), { all: true })).toEqual([freshImage]);
    expect(fs.existsSync(unrelated)).toBe(true);
    expect(fs.lstatSync(matchingSymlink).isSymbolicLink()).toBe(true);
    expect(fs.existsSync(matchingHardLink)).toBe(true);
  });

  test("atomically migrates the legacy host-state directory with files intact", () => {
    const stateDir = path.join(tmp, "state");
    const legacy = path.join(stateDir, "images");
    const inbox = path.join(stateDir, "inbox");
    fs.mkdirSync(legacy, { recursive: true });
    fs.writeFileSync(path.join(legacy, "clip-2026-05-14-153012-a8f3.png"), "legacy");

    ensureInbox(inbox);

    expect(fs.existsSync(legacy)).toBe(false);
    expect(fs.readFileSync(path.join(inbox, "clip-2026-05-14-153012-a8f3.png"), "utf8")).toBe("legacy");
  });

  test("does not merge or follow unsafe legacy state", () => {
    const stateDir = path.join(tmp, "state");
    const legacy = path.join(stateDir, "images");
    const inbox = path.join(stateDir, "inbox");
    fs.mkdirSync(legacy, { recursive: true });
    fs.mkdirSync(inbox, { recursive: true });
    fs.writeFileSync(path.join(legacy, "legacy.png"), "legacy");
    const warnings: string[] = [];

    ensureInbox(inbox, (message) => warnings.push(message));

    expect(warnings).toEqual([expect.stringContaining("new inbox already exists")]);
    expect(fs.readFileSync(path.join(legacy, "legacy.png"), "utf8")).toBe("legacy");

    fs.rmSync(inbox, { recursive: true });
    fs.rmSync(legacy, { recursive: true });
    const outside = path.join(tmp, "outside");
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, legacy, "dir");
    warnings.length = 0;
    ensureInbox(inbox, (message) => warnings.push(message));
    expect(warnings).toEqual([expect.stringContaining("not a normal directory")]);
    expect(fs.lstatSync(legacy).isSymbolicLink()).toBe(true);
    expect(fs.readdirSync(outside)).toEqual([]);
  });
});
