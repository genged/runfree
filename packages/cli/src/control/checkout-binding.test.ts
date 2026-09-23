import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, expect, test } from "vitest";

import {
  compareCheckoutBinding,
  observeCheckoutBinding,
  validateCheckoutBinding,
  type CheckoutBinding,
} from "./checkout-binding.ts";

let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-checkout-binding-"));
});
afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

test("the observation is decimal strings, never JavaScript numbers", () => {
  const binding = observeCheckoutBinding(root);

  expect(binding.resolvedRoot).toBe(fs.realpathSync.native(root));
  expect(typeof binding.rootInode).toBe("string");
  expect(typeof binding.rootDevice).toBe("string");
  expect(binding.rootInode).toMatch(/^\d+$/);
  expect(binding.rootDevice).toMatch(/^\d+$/);
});

test("a symlinked project root resolves to its target", () => {
  const link = path.join(os.tmpdir(), `runfree-checkout-binding-link-${process.pid}`);
  fs.symlinkSync(root, link);
  try {
    expect(observeCheckoutBinding(link).resolvedRoot).toBe(fs.realpathSync.native(root));
  } finally {
    fs.rmSync(link);
  }
});

test("a replaced directory at the same path changes the inode", () => {
  const before = observeCheckoutBinding(root);
  const kept = `${root}-kept`;
  // Keep the old directory alive so inode reuse cannot hide the replacement.
  fs.renameSync(root, kept);
  fs.mkdirSync(root);
  try {
    expect(compareCheckoutBinding(before, observeCheckoutBinding(root))).toBe("root-inode");
  } finally {
    fs.rmSync(kept, { recursive: true, force: true });
  }
});

const stored: CheckoutBinding = {
  resolvedRoot: "/Users/mg/code/capshelf",
  rootDevice: "16777229",
  rootInode: "166957006",
};

test("a changed device number alone is not a mismatch", () => {
  expect(compareCheckoutBinding(stored, { ...stored, rootDevice: "999999999" })).toBeUndefined();
});

test("each compared field names itself", () => {
  expect(compareCheckoutBinding(stored, { ...stored, resolvedRoot: "/elsewhere" })).toBe("resolved-root");
  expect(compareCheckoutBinding(stored, { ...stored, rootInode: "2" })).toBe("root-inode");
});

test("validation rejects unknown keys, relative paths, and non-decimal numbers", () => {
  expect(validateCheckoutBinding(stored)).toEqual(stored);
  expect(() => validateCheckoutBinding({ ...stored, extra: 1 })).toThrow("checkoutBinding");
  expect(() => validateCheckoutBinding({ ...stored, resolvedRoot: "relative/path" })).toThrow("resolvedRoot is malformed");
  expect(() => validateCheckoutBinding({ ...stored, resolvedRoot: "/a/../b" })).toThrow("resolvedRoot is malformed");
  expect(() => validateCheckoutBinding({ ...stored, rootInode: "12x" })).toThrow("rootInode is malformed");
  // A bigint inode must survive as text; a number would silently lose precision.
  expect(() => validateCheckoutBinding({ ...stored, rootInode: 166957006 })).toThrow("rootInode is malformed");
  expect(() => validateCheckoutBinding({ ...stored, rootDevice: "" })).toThrow("rootDevice is malformed");
});
