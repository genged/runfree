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

  describe("a fatal Git shape", () => {
    // Real Git for everything but the capability probe, whose help text decides
    // relative-link support; every capture is recorded, along with the env
    // each probe capture ran with (to prove env threading below).
    function hostGitIO(supported: boolean): { io: RuntimeIO; captured: string[][]; probeEnvs: (NodeJS.ProcessEnv | undefined)[] } {
      const captured: string[][] = [];
      const probeEnvs: (NodeJS.ProcessEnv | undefined)[] = [];
      return {
        captured,
        probeEnvs,
        io: {
          ...io,
          capture: (commandName, args, options) => {
            captured.push(args);
            if (args[0] === "--version") {
              probeEnvs.push(options?.env);
              return { status: 0, stdout: "git version 2.43.0\n", stderr: "" };
            }
            if (args[0] === "worktree") {
              probeEnvs.push(options?.env);
              return { status: 129, stdout: supported ? "    --[no-]relative-paths" : "usage: git worktree repair [<path>...]", stderr: "" };
            }
            return io.capture(commandName, args, options);
          },
        },
      };
    }

    function fatalCheckout(): void {
      fs.mkdirSync(path.join(root, "elsewhere-git"));
      fs.symlinkSync(path.join(root, "elsewhere-git"), path.join(root, ".git"));
    }

    test("names the host Git version requirement on old host Git instead of repair commands it cannot run", () => {
      fatalCheckout();
      const { io: oldGit } = hostGitIO(false);
      let message = "";
      try {
        ensureCheckoutLocalPolicyExcluded(root, oldGit);
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain(".git must not be a symlink");
      expect(message).toContain("requires host Git >= 2.48 (found 2.43.0); run runfree from the main checkout, or upgrade Git");
      expect(message).not.toContain("--relative-paths");
    });

    test("probes with the caller's context env when one is given, instead of the bare process env", () => {
      fatalCheckout();
      const { io: oldGit, probeEnvs } = hostGitIO(false);
      const callerEnv = { ...process.env, RUNFREE_TEST_GIT_EXCLUDE_ENV_MARKER: "from-caller-context" };
      expect(() => ensureCheckoutLocalPolicyExcluded(root, oldGit, callerEnv)).toThrow();
      expect(probeEnvs.length).toBeGreaterThan(0);
      for (const probeEnv of probeEnvs) {
        expect(probeEnv?.RUNFREE_TEST_GIT_EXCLUDE_ENV_MARKER).toBe("from-caller-context");
      }
    });

    test("keeps the repair commands on supported host Git", () => {
      fatalCheckout();
      const { io: newGit } = hostGitIO(true);
      expect(() => ensureCheckoutLocalPolicyExcluded(root, newGit)).toThrow(/Repair it on the host with:\n {2}git -C .* worktree repair --relative-paths/);
    });

    test("a valid checkout never probes host Git", () => {
      initGit();
      const { io: recorded, captured } = hostGitIO(false);
      expect(ensureCheckoutLocalPolicyExcluded(root, recorded)).toBe("written");
      expect(captured.filter((args) => args[0] === "--version" || args[0] === "worktree")).toEqual([]);
    });
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
