import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import type { RuntimeIO } from "../runtime/types.ts";
import { ensureCheckoutLocalPolicyExcluded, LOCAL_POLICY_EXCLUDE_PATTERN } from "./git-exclude.ts";

function command(commandName: string, args: string[]): { status: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(commandName, args, { encoding: "utf8" });
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

const io: RuntimeIO = {
  capture: (commandName, args) => command(commandName, args),
  run: (commandName, args) => command(commandName, args).status,
  commandExists: () => true,
  confirm: () => false,
  admin: async () => 0,
};

describe("checkout-local Git exclusion", () => {
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-local-exclude-"));
  });

  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  function initGit(): string {
    expect(command("git", ["init", "-q", root]).status).toBe(0);
    return path.join(root, ".git", "info", "exclude");
  }

  test("adds the exact anchored pattern once at Git's resolved exclude path", () => {
    const excludePath = initGit();

    expect(ensureCheckoutLocalPolicyExcluded(root, io)).toBe("written");
    expect(ensureCheckoutLocalPolicyExcluded(root, io)).toBe("present");

    const matches = fs.readFileSync(excludePath, "utf8")
      .split(/\r?\n/)
      .filter((line) => line === LOCAL_POLICY_EXCLUDE_PATTERN);
    expect(matches).toEqual([LOCAL_POLICY_EXCLUDE_PATTERN]);
  });

  test("does not require an exclude file outside a Git checkout", () => {
    expect(ensureCheckoutLocalPolicyExcluded(root, io)).toBe("absent-git");
    expect(fs.existsSync(path.join(root, ".git"))).toBe(false);
  });

  test("refuses a tracked local policy before changing the exclude file", () => {
    const excludePath = initGit();
    const originalExclude = fs.readFileSync(excludePath, "utf8");
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.local.json"), '{"version":2,"hosts":[]}\n');
    expect(command("git", ["-C", root, "add", ".runfree/network-policy.local.json"]).status).toBe(0);

    expect(() => ensureCheckoutLocalPolicyExcluded(root, io)).toThrow("checkout-local policy must remain untracked");
    expect(fs.readFileSync(excludePath, "utf8")).toBe(originalExclude);
  });

  test.each(["symlink", "hardlink"] as const)("refuses an unsafe %s exclude without touching its target", (kind) => {
    const excludePath = initGit();
    fs.rmSync(excludePath);
    const outside = path.join(root, `outside-${kind}`);
    fs.writeFileSync(outside, "outside stays unchanged\n");
    if (kind === "symlink") fs.symlinkSync(outside, excludePath);
    else fs.linkSync(outside, excludePath);

    expect(() => ensureCheckoutLocalPolicyExcluded(root, io)).toThrow(/Git exclude/);
    expect(fs.readFileSync(outside, "utf8")).toBe("outside stays unchanged\n");
  });
});
