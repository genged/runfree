import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { readBoundedProjectJson } from "./project-json.ts";

describe("bounded project JSON reader", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-project-json-"));
    fs.mkdirSync(path.join(root, ".runfree"));
  });
  afterEach(() => fs.rmSync(root, { recursive: true }));

  test("reads a regular recognized file", () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    expect(readBoundedProjectJson(root, ".runfree/network-policy.json")?.parsed).toEqual({ version: 2, hosts: [] });
  });

  test("rejects duplicates, oversize input, links, and unrecognized paths", () => {
    const policy = path.join(root, ".runfree", "network-policy.json");
    fs.writeFileSync(policy, `{"version":2,"version":2,"hosts":[]}`);
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json")).toThrow("duplicate object key");

    fs.writeFileSync(policy, "x".repeat(65));
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json", { maxBytes: 64 })).toThrow("64-byte limit");

    fs.unlinkSync(policy);
    fs.symlinkSync("../outside.json", policy);
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json")).toThrow("regular, non-hard-linked");
    expect(() => readBoundedProjectJson(root, ".runfree/generated.json")).toThrow("unrecognized");
    expect(() => readBoundedProjectJson(root, ".runfree/generated/policy.json")).toThrow("unrecognized");
  });

  test("rejects a symlinked control root before opening a child", () => {
    fs.rmSync(path.join(root, ".runfree"), { recursive: true });
    fs.symlinkSync(os.tmpdir(), path.join(root, ".runfree"));
    expect(() => readBoundedProjectJson(root, ".runfree/network-policy.json")).toThrow("normal directory");
  });

  test("represents an absent optional file without parsing another path", () => {
    expect(readBoundedProjectJson(root, ".runfree/network-policy.local.json", { allowMissing: true })).toBeUndefined();
  });
});
