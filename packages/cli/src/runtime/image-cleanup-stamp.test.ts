import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test } from "vitest";

import {
  imageCleanupStampMatches,
  imageCleanupStampPath,
  readImageCleanupStamp,
  removeImageCleanupStamp,
  writeImageCleanupStamp,
} from "./image-cleanup-stamp.ts";

const PROJECT = "0123456789ab";
const DIGEST = `sha256:${"a".repeat(64)}`;
let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-cleanup-stamp-"));
});
afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

test("a written stamp matches only its exact digest and project", () => {
  expect(imageCleanupStampMatches(stateDir, PROJECT, DIGEST)).toBe(false);
  writeImageCleanupStamp(stateDir, PROJECT, DIGEST, new Date("2026-09-30T00:00:00.000Z"));
  expect(imageCleanupStampMatches(stateDir, PROJECT, DIGEST)).toBe(true);
  expect(imageCleanupStampMatches(stateDir, PROJECT, `sha256:${"b".repeat(64)}`)).toBe(false);
  expect(imageCleanupStampMatches(stateDir, "ba9876543210", DIGEST)).toBe(false);
  expect(fs.statSync(imageCleanupStampPath(stateDir)).mode & 0o777).toBe(0o600);
});

test("remove then read is absent", () => {
  writeImageCleanupStamp(stateDir, PROJECT, DIGEST);
  removeImageCleanupStamp(stateDir);
  expect(readImageCleanupStamp(stateDir, PROJECT)).toBeUndefined();
  removeImageCleanupStamp(stateDir);
});

test("a malformed, extra-key, wrong-version, or linked stamp reads as absent", () => {
  writeImageCleanupStamp(stateDir, PROJECT, DIGEST);
  const stampPath = imageCleanupStampPath(stateDir);
  const valid = JSON.parse(fs.readFileSync(stampPath, "utf8")) as Record<string, unknown>;
  for (const contents of [
    "{not json",
    JSON.stringify({ ...valid, extra: true }),
    JSON.stringify({ ...valid, version: 2 }),
    JSON.stringify({ ...valid, inputsDigest: "sha256:short" }),
  ]) {
    fs.writeFileSync(stampPath, contents);
    expect(readImageCleanupStamp(stateDir, PROJECT)).toBeUndefined();
  }
  fs.rmSync(stampPath);
  const outside = path.join(stateDir, "outside.json");
  fs.writeFileSync(outside, JSON.stringify(valid));
  fs.symlinkSync(outside, stampPath);
  expect(readImageCleanupStamp(stateDir, PROJECT)).toBeUndefined();
  fs.rmSync(stampPath);
  fs.linkSync(outside, stampPath);
  expect(readImageCleanupStamp(stateDir, PROJECT)).toBeUndefined();
});

test("a stamp write refuses a symlinked record directory before writing", () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-cleanup-stamp-target-"));
  try {
    fs.mkdirSync(path.join(stateDir, "runtime", "v2"), { recursive: true });
    fs.symlinkSync(target, path.join(stateDir, "runtime", "v2", "launch"));
    expect(() => writeImageCleanupStamp(stateDir, PROJECT, DIGEST)).toThrow();
    expect(fs.readdirSync(target)).toEqual([]);
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});
