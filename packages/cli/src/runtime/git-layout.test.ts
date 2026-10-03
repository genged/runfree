import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { projectInfo } from "../config.ts";

import {
  assertHostGitSupportsRelativeWorktrees,
  classifyGitRepository,
  formatHostGitStatusLine,
  gitLayoutPlanForShape,
  hostGitRelativeWorktreesLaunchWarning,
  prepareGitRepositoryLayoutResult,
  probeHostGitRelativeWorktrees,
  repairWorktreeLinks,
} from "./git-layout.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-git-worktree-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function projectHash(projectRoot: string): string {
  return crypto.createHash("sha256").update(projectRoot).digest("hex").slice(0, 12);
}

function writeCommonConfig(gitCommonDir: string, values: { relativeWorktrees?: boolean; useRelativePaths?: boolean } = {}): void {
  fs.writeFileSync(path.join(gitCommonDir, "config"), [
    "[extensions]",
    values.relativeWorktrees === false ? "" : "\trelativeWorktrees = true",
    "[worktree]",
    values.useRelativePaths === false ? "" : "\tuseRelativePaths = true",
    "",
  ].filter((line) => line !== "").join("\n"));
}

function linkedWorktreeFixture(): { projectRoot: string; gitCommonDir: string; gitDir: string } {
  const repo = path.join(tmp, "repo");
  const projectRoot = path.join(repo, ".worktrees", "feature");
  const gitCommonDir = path.join(repo, ".git");
  const gitDir = path.join(gitCommonDir, "worktrees", "feature");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(gitDir, { recursive: true });
  fs.mkdirSync(path.join(gitCommonDir, "objects", "info"), { recursive: true });
  fs.writeFileSync(path.join(projectRoot, ".git"), "gitdir: ../../.git/worktrees/feature\n");
  fs.writeFileSync(path.join(gitDir, "commondir"), "../..\n");
  fs.writeFileSync(path.join(gitDir, "gitdir"), "../../../.worktrees/feature/.git\n");
  writeCommonConfig(gitCommonDir);
  return { projectRoot, gitCommonDir, gitDir };
}

function expectFatal(projectRoot: string, text: string): void {
  const result = classifyGitRepository(projectRoot);
  expect(result.kind).toBe("fatal");
  if (result.kind !== "fatal") throw new Error("expected fatal Git shape");
  expect(result.reason).toContain(text);
}

test("host capability probing works outside a repository and cleans its disposable repository", () => {
  const projectRoot = path.join(tmp, "plain-project");
  fs.mkdirSync(projectRoot);
  const probeDirs = new Set<string>();
  const io = {
    capture: (command, args, options) => {
      const cwd = typeof options?.cwd === "string" ? options.cwd : projectRoot;
      probeDirs.add(cwd);
      const result = childProcess.spawnSync(command, args, { ...options, cwd, encoding: "utf8" });
      return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
    },
    run: () => 0,
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  } satisfies RuntimeIO;
  const context: RuntimeContext = { projectRoot, project: projectInfo(projectRoot), runtimeRoot: "/runtime", env: { ...process.env, GIT_DIR: path.join(tmp, "broken-git-dir") } };
  assertHostGitSupportsRelativeWorktrees(context, io);
  expect(fs.readdirSync(projectRoot)).toEqual([]);
  expect(probeDirs.size).toBe(1);
  for (const probe of probeDirs) expect(fs.existsSync(probe)).toBe(false);
  // The real host Git reports a display version alongside the capability.
  expect(probeHostGitRelativeWorktrees(context, io)).toEqual({ supported: true, version: expect.stringMatching(/^\d+\.\d+/), found: true });
});

describe("host Git without relative worktree links", () => {
  const OLD_REFUSAL = "requires host Git >= 2.48 (found 2.43.0); run runfree from the main checkout, or upgrade Git";

  // Simulates host Git by its help text: the capability flips on the same
  // signal the real probe reads, and every call is recorded.
  function simulatedHostGit(state: { supported: boolean; version?: string; missing?: boolean }) {
    const calls: string[][] = [];
    const runs: string[][] = [];
    const io = {
      capture: (_command, args) => {
        calls.push(args);
        // A missing binary fails to spawn; the IO reports that as non-zero.
        if (state.missing) return { status: 127, stdout: "", stderr: "spawnSync git ENOENT" };
        if (args[0] === "--version") return { status: 0, stdout: `git version ${state.version ?? "2.43.0"}\n`, stderr: "" };
        if (args[0] === "init") return { status: 0, stdout: "", stderr: "" };
        if (args[0] === "worktree") {
          return { status: 129, stdout: state.supported ? "    --[no-]relative-paths" : "usage: git worktree repair [<path>...]", stderr: "" };
        }
        return { status: 1, stdout: "", stderr: "" };
      },
      run: (_command, args) => {
        runs.push(args);
        return 0;
      },
      commandExists: () => true,
      confirm: () => true,
      admin: async () => 0,
    } satisfies RuntimeIO;
    return { io, calls, runs };
  }

  function layoutContext(projectRoot: string): RuntimeContext {
    return { projectRoot, project: { paths: { stateDir: path.join(tmp, "unpublished-state") } } } as RuntimeContext;
  }

  test("the probe reports unsupported with the parsed version and removes its disposable repository", () => {
    const { io, calls } = simulatedHostGit({ supported: false });
    const context = { projectRoot: tmp, env: { GIT_DIR: "/elsewhere" } } as unknown as RuntimeContext;
    expect(probeHostGitRelativeWorktrees(context, io)).toEqual({ supported: false, version: "2.43.0", found: true });
    expect(calls.map((args) => args[0])).toEqual(["--version", "init", "worktree"]);
    const probeDir = calls[1].at(-1) ?? "";
    expect(probeDir).toContain("runfree-git-probe-");
    expect(fs.existsSync(probeDir)).toBe(false);
  });

  test("an unreadable version reads as unknown and never decides the capability", () => {
    const { io } = simulatedHostGit({ supported: true, version: "unparseable" });
    expect(probeHostGitRelativeWorktrees({ projectRoot: tmp } as RuntimeContext, io)).toEqual({ supported: true, version: "unknown", found: true });
  });

  test("missing host Git reads as not found, keeps the unknown status line, and gets its own launch warning", () => {
    const { io, calls } = simulatedHostGit({ supported: false, missing: true });
    const hostGit = probeHostGitRelativeWorktrees({ projectRoot: tmp } as RuntimeContext, io);
    expect(hostGit).toEqual({ supported: false, version: "unknown", found: false });
    expect(calls.map((args) => args[0])).toEqual(["--version"]);
    expect(formatHostGitStatusLine(hostGit)).toBe("host git: unknown (worktrees: disabled)");
    expect(hostGitRelativeWorktreesLaunchWarning({ projectRoot: tmp }, hostGit)).toBe(
      "host Git not found: Git worktrees created inside the sandbox will make this repository unreadable to host Git older than 2.48; install Git 2.48 or newer",
    );
  });

  test("old host Git on a main checkout that already uses relative worktree links warns that the repository is already unreadable", () => {
    const { gitCommonDir } = linkedWorktreeFixture();
    const main = path.dirname(gitCommonDir);
    const old = { supported: false, version: "2.43.0", found: true };
    expect(hostGitRelativeWorktreesLaunchWarning({ projectRoot: main }, old)).toBe(
      "host Git 2.43.0 is older than 2.48 and cannot read this repository, which uses relative worktree links; upgrade host Git (Ubuntu: sudo add-apt-repository ppa:git-core/ppa && sudo apt install git)",
    );
    // Without the extension the repository is still readable: the existing
    // future-tense warning stays byte-for-byte.
    writeCommonConfig(gitCommonDir, { relativeWorktrees: false });
    expect(hostGitRelativeWorktreesLaunchWarning({ projectRoot: main }, old)).toBe(
      "host Git 2.43.0 is older than 2.48: Git worktrees created inside the sandbox will make this repository unreadable to host Git; upgrade host Git (Ubuntu: sudo add-apt-repository ppa:git-core/ppa && sudo apt install git)",
    );
    expect(hostGitRelativeWorktreesLaunchWarning({ projectRoot: main }, { ...old, supported: true })).toBeUndefined();
  });

  test("a mid-session layout re-validation without a launch probe result probes lazily on a fatal shape only", () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const context = layoutContext(projectRoot);
    const valid = simulatedHostGit({ supported: false });
    expect(prepareGitRepositoryLayoutResult(context, undefined, valid.io).plan.kind).toBe("relative-linked");
    expect(valid.calls).toEqual([]);

    // The worktree link turns absolute mid-session.
    fs.writeFileSync(path.join(projectRoot, ".git"), `gitdir: ${path.join(gitCommonDir, "worktrees", "feature")}\n`);
    const old = simulatedHostGit({ supported: false });
    let message = "";
    try {
      prepareGitRepositoryLayoutResult(context, undefined, old.io);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("must be relative");
    expect(message).toContain(OLD_REFUSAL);
    expect(message).not.toContain("--relative-paths");
    expect(old.calls.map((args) => args[0])).toEqual(["--version", "init", "worktree"]);

    const supported = simulatedHostGit({ supported: true });
    expect(() => prepareGitRepositoryLayoutResult(context, undefined, supported.io)).toThrow(
      /Repair it on the host with:\n {2}git -C .* worktree repair --relative-paths/,
    );
    expect(fs.existsSync(context.project.paths.stateDir)).toBe(false);
  });

  test("a linked worktree launch refuses before the layout plan is published, then proceeds after an upgrade", () => {
    const { projectRoot } = linkedWorktreeFixture();
    const context = layoutContext(projectRoot);
    const state = { supported: false };
    const { io } = simulatedHostGit(state);

    expect(() => prepareGitRepositoryLayoutResult(context, probeHostGitRelativeWorktrees(context, io))).toThrow(OLD_REFUSAL);
    expect(fs.existsSync(context.project.paths.stateDir)).toBe(false);

    state.supported = true;
    expect(prepareGitRepositoryLayoutResult(context, probeHostGitRelativeWorktrees(context, io)).plan.kind).toBe("relative-linked");
  });

  // Both roots below classify a fatal shape over the same broken worktree
  // (an absolute gitdir). Reached directly (from the worktree itself), the
  // "run runfree from the main checkout" clause is a real fix. Reached from
  // the main checkout (classifyMainRepository's refuse() path, e.g. a nested
  // worktree with absolute links), it is not: the caller is already there.
  function fatalNestedWorktreeFixture(): { main: string; projectRoot: string } {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const main = path.dirname(gitCommonDir);
    fs.writeFileSync(path.join(projectRoot, ".git"), `gitdir: ${path.join(gitCommonDir, "worktrees", "feature")}\n`);
    return { main, projectRoot };
  }

  function fatalMessage(context: RuntimeContext, io: RuntimeIO): string {
    try {
      prepareGitRepositoryLayoutResult(context, probeHostGitRelativeWorktrees(context, io));
    } catch (error) {
      return error instanceof Error ? error.message : String(error);
    }
    throw new Error("expected prepareGitRepositoryLayoutResult to throw");
  }

  test("a fatal shape reached from the linked worktree itself names the version requirement instead of repair commands old Git cannot run", () => {
    const { projectRoot } = fatalNestedWorktreeFixture();
    const { io } = simulatedHostGit({ supported: false });
    const context = layoutContext(projectRoot);
    const message = fatalMessage(context, io);
    expect(message).toContain("must be relative");
    expect(message).toContain(OLD_REFUSAL);
    expect(message).not.toContain("--relative-paths");
    expect(message).not.toContain("repair-worktree-links");
    expect(fs.existsSync(context.project.paths.stateDir)).toBe(false);
  });

  test("a fatal shape reached from the main checkout names the nested-worktree fix instead of the self-referential main-checkout clause", () => {
    const { main } = fatalNestedWorktreeFixture();
    const { io } = simulatedHostGit({ supported: false });
    const context = layoutContext(main);
    const message = fatalMessage(context, io);
    expect(message).toContain("must be relative");
    expect(message).toContain("requires host Git >= 2.48 (found 2.43.0); remove or move the nested worktree (e.g. git worktree remove <path>), or upgrade Git");
    expect(message).not.toContain("run runfree from the main checkout");
    expect(message).not.toContain("--relative-paths");
    expect(message).not.toContain("repair-worktree-links");
    expect(fs.existsSync(context.project.paths.stateDir)).toBe(false);
  });

  test("a normal repository and a non-Git project keep their layout on old host Git", () => {
    const normal = path.join(tmp, "normal");
    fs.mkdirSync(path.join(normal, ".git"), { recursive: true });
    const plain = path.join(tmp, "plain");
    fs.mkdirSync(plain);
    const { io } = simulatedHostGit({ supported: false });
    for (const root of [normal, plain]) {
      const context = layoutContext(root);
      expect(prepareGitRepositoryLayoutResult(context, probeHostGitRelativeWorktrees(context, io)).plan.kind).toBe("workspace");
    }
  });

  test("repair-worktree-links refuses before running git worktree repair or git config, then repairs after an upgrade", async () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const main = path.dirname(gitCommonDir);
    const state = { supported: false };
    const { io, runs } = simulatedHostGit(state);
    const context = { projectRoot: main } as RuntimeContext;
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await expect(repairWorktreeLinks(context, io)).rejects.toThrow(
        "repairing worktree links requires host Git >= 2.48 (found 2.43.0); upgrade Git",
      );
      expect(runs).toEqual([]);
      expect(log).not.toHaveBeenCalled();

      state.supported = true;
      expect(await repairWorktreeLinks(context, io)).toBe(0);
      expect(runs.map((args) => args.slice(2, 4))).toEqual([["worktree", "repair"], ["config", "--local"]]);
      expect(runs[0]).toContain(projectRoot);
    } finally {
      log.mockRestore();
    }
  });
});

describe("git repository classifier", () => {
  test.each(["true # portable", "true ; portable", '"true" # portable', "2", "tr\\\nue"])("accepts Git boolean syntax in relative-link settings: %s", (value) => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const config = path.join(gitCommonDir, "config");
    fs.writeFileSync(config, `[extensions] # format\nrelativeWorktrees = ${value}\n[worktree] ; defaults\nuseRelativePaths = ${value}\n`);
    expect(classifyGitRepository(path.dirname(gitCommonDir)).kind).toBe("normal");
    expect(classifyGitRepository(projectRoot).kind).toBe("relative-linked");
  });

  test.each(["[broken", "[worktree]\nuseRelativePaths = invalid"])("invalid Git config refuses layout publication and can be corrected: %s", (source) => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const config = path.join(gitCommonDir, "config");
    fs.appendFileSync(config, `\n${source}\n`);
    const stateDir = path.join(tmp, "unpublished-state");
    const context = { projectRoot, project: { paths: { stateDir } } } as RuntimeContext;
    expect(() => prepareGitRepositoryLayoutResult(context)).toThrow("Git could not read");
    expect(fs.existsSync(stateDir)).toBe(false);
    writeCommonConfig(gitCommonDir);
    expect(prepareGitRepositoryLayoutResult(context).shape.kind).toBe("relative-linked");
  });

  test("file checks use the last direct value without following includes", () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const included = path.join(tmp, "invalid-config");
    fs.writeFileSync(included, "[broken");
    fs.appendFileSync(path.join(gitCommonDir, "config"), `\n[include]\npath = ${included}\n[worktree]\nuseRelativePaths = false\nuseRelativePaths = true\n`);
    expect(classifyGitRepository(projectRoot).kind).toBe("relative-linked");
  });

  test("comment markers inside quoted Git paths remain part of the path", () => {
    const { projectRoot, gitDir } = linkedWorktreeFixture();
    fs.writeFileSync(path.join(gitDir, "config.worktree"), '[core]\nworktree = "/tmp/project#name;part" # comment\n');
    expectFatal(projectRoot, "core.worktree must be relative");
  });

  test.each(["host", "container", "forward-only", "backlink-only"])("main checkout refuses %s absolute nested links before layout publication", (kind) => {
    const { projectRoot, gitCommonDir, gitDir } = linkedWorktreeFixture();
    const main = path.dirname(gitCommonDir);
    if (kind !== "backlink-only") {
      fs.writeFileSync(path.join(projectRoot, ".git"), `gitdir: ${kind === "container" ? "/workspace/.git/worktrees/feature" : gitDir}\n`);
    }
    if (kind !== "forward-only") {
      fs.writeFileSync(path.join(gitDir, "gitdir"), `${kind === "container" ? "/workspace/.worktrees/feature/.git" : path.join(projectRoot, ".git")}\n`);
    }
    const original = fs.readFileSync(path.join(projectRoot, ".git"), "utf8");
    const stateDir = path.join(tmp, "unpublished-state");
    const context = { projectRoot: main, project: { paths: { stateDir } } } as RuntimeContext;

    expectFatal(main, "must be relative");
    expect(() => prepareGitRepositoryLayoutResult(context)).toThrow("repair-worktree-links");
    expect(fs.existsSync(stateDir)).toBe(false);
    expect(fs.readFileSync(path.join(projectRoot, ".git"), "utf8")).toBe(original);
  });

  test("main checkout accepts nested relative links with the sandbox default and ignores worktrees outside its mount", () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const main = path.dirname(gitCommonDir);
    fs.writeFileSync(path.join(gitCommonDir, "config"), "[extensions]\nrelativeWorktrees = true\n");
    const externalEntry = path.join(gitCommonDir, "worktrees", "external");
    fs.mkdirSync(externalEntry);
    fs.writeFileSync(path.join(externalEntry, "gitdir"), `${path.join(tmp, "host-only", ".git")}\n`);

    expect(classifyGitRepository(main).kind).toBe("normal");
    // A separately launched linked-worktree runtime still requires the repo's
    // persistent default for host/container operations on its common metadata.
    expectFatal(projectRoot, "worktree.useRelativePaths must be true");
    fs.appendFileSync(path.join(gitCommonDir, "config"), "[worktree]\nuseRelativePaths = false\n");
    expectFatal(main, "must not disable relative links");
    fs.appendFileSync(path.join(gitCommonDir, "config"), "[worktree]\nuseRelativePaths = true\n");
    expect(classifyGitRepository(main).kind).toBe("normal");
  });

  test("main checkout rejects a symlinked registry backlink without reading its target", () => {
    const { gitCommonDir, gitDir } = linkedWorktreeFixture();
    const backlink = path.join(gitDir, "gitdir");
    const original = fs.readFileSync(backlink);
    fs.unlinkSync(backlink);
    fs.symlinkSync(path.join(tmp, "absent-target"), backlink);
    expectFatal(path.dirname(gitCommonDir), "regular single-link file");
    fs.unlinkSync(backlink);
    fs.writeFileSync(backlink, original);
    expect(classifyGitRepository(path.dirname(gitCommonDir)).kind).toBe("normal");
  });

  test("host repair recovers container-written links from the main checkout", async () => {
    const main = path.join(tmp, "main with spaces");
    fs.mkdirSync(main);
    const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
    const git = (args: string[]) => childProcess.spawnSync("git", args, { encoding: "utf8", env });
    for (const args of [
      ["init", "-q", main],
      ["-C", main, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-qm", "initial"],
      ["-C", main, "worktree", "add", "-qb", "feature", ".worktrees/feature"],
    ]) expect(git(args).status).toBe(0);
    const feature = path.join(main, ".worktrees", "feature");
    fs.writeFileSync(path.join(feature, ".git"), "gitdir: /workspace/.git/worktrees/feature\n");
    fs.writeFileSync(path.join(main, ".git", "worktrees", "feature", "gitdir"), "/workspace/.worktrees/feature/.git\n");
    expectFatal(main, "gitdir must be relative");
    const io = {
      run: (_command, args) => git(args).status ?? 1,
      capture: (_command, args) => {
        const result = git(args);
        return { status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr };
      },
      commandExists: () => true,
      confirm: () => true,
      admin: async () => 0,
    } satisfies RuntimeIO;

    const context = {
      projectRoot: main,
      project: projectInfo(main, { ...env, XDG_STATE_HOME: path.join(tmp, "state") }),
      runtimeRoot: path.join(tmp, "runtime"),
      env,
    } satisfies RuntimeContext;
    expect(await repairWorktreeLinks(context, io)).toBe(0);
    expect(classifyGitRepository(main).kind).toBe("normal");
    expect(git(["-C", feature, "status", "--porcelain"]).status).toBe(0);
    expect(git(["-C", main, "config", "--get", "worktree.useRelativePaths"]).stdout.trim()).toBe("true");
  });

  test("classifies missing git metadata and normal clone directories", () => {
    const missing = path.join(tmp, "missing");
    const normal = path.join(tmp, "normal");
    fs.mkdirSync(path.join(normal, ".git"), { recursive: true });

    expect(classifyGitRepository(missing)).toEqual({ kind: "none" });
    expect(classifyGitRepository(normal)).toEqual({
      kind: "normal",
      gitDir: fs.realpathSync(path.join(normal, ".git")),
    });
  });

  test("classifies a valid relative linked worktree and plans topology-preserving mounts", () => {
    const { projectRoot, gitCommonDir, gitDir } = linkedWorktreeFixture();

    const result = classifyGitRepository(projectRoot);

    expect(result.kind).toBe("relative-linked");
    if (result.kind !== "relative-linked") throw new Error("expected linked worktree");
    expect(result.details.gitCommonDir).toBe(fs.realpathSync(gitCommonDir));
    expect(result.details.gitDir).toBe(fs.realpathSync(gitDir));
    expect(result.details.projectRel).toBe(".worktrees/feature");
    expect(result.details.commonRel).toBe(".git");

    const plan = gitLayoutPlanForShape(projectRoot, result);
    const containerBase = `/runfree/git-layout/${projectHash(fs.realpathSync(projectRoot))}`;
    expect(plan).toMatchObject({
      kind: "relative-linked",
      containerBase,
      containerProjectRoot: `${containerBase}/.worktrees/feature`,
      containerCompatRoot: `${containerBase}/.worktrees/feature`,
      containerGitCommonDir: `${containerBase}/.git`,
      containerGitDir: `${containerBase}/.git/worktrees/feature`,
    });
  });

  test("absolute .git gitdir fails", () => {
    const { projectRoot, gitDir } = linkedWorktreeFixture();
    fs.writeFileSync(path.join(projectRoot, ".git"), `gitdir: ${gitDir}\n`);

    expectFatal(projectRoot, ".git");
    expectFatal(projectRoot, "gitdir must be relative");
  });

  test("relative .git with absolute commondir fails", () => {
    const { projectRoot, gitCommonDir, gitDir } = linkedWorktreeFixture();
    fs.writeFileSync(path.join(gitDir, "commondir"), `${gitCommonDir}\n`);

    expectFatal(projectRoot, "commondir must be relative");
  });

  test("relative .git with absolute backlink gitdir fails", () => {
    const { projectRoot, gitDir } = linkedWorktreeFixture();
    fs.writeFileSync(path.join(gitDir, "gitdir"), `${path.join(projectRoot, ".git")}\n`);

    expectFatal(projectRoot, "backlink gitdir must be relative");
  });

  test("missing relative worktree config keys fail", () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    writeCommonConfig(gitCommonDir, { relativeWorktrees: false });
    expectFatal(projectRoot, "extensions.relativeWorktrees must be true");

    writeCommonConfig(gitCommonDir, { useRelativePaths: false });
    expectFatal(projectRoot, "worktree.useRelativePaths must be true");
  });

  test("absolute config.worktree core.worktree fails", () => {
    const { projectRoot, gitDir } = linkedWorktreeFixture();
    fs.writeFileSync(path.join(gitDir, "config.worktree"), `[core]\n\tworktree = ${projectRoot}\n`);

    expectFatal(projectRoot, "core.worktree must be relative");
  });

  test("absolute object alternate path fails", () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    fs.writeFileSync(path.join(gitCommonDir, "objects", "info", "alternates"), "/tmp/objects\n");

    expectFatal(projectRoot, "object alternate paths must be relative");
  });

  test("absolute initialized submodule gitfile and module core.worktree fail", () => {
    const { projectRoot, gitCommonDir } = linkedWorktreeFixture();
    const submodule = path.join(projectRoot, "vendor", "lib");
    const moduleGitDir = path.join(gitCommonDir, "modules", "vendor", "lib");
    fs.mkdirSync(submodule, { recursive: true });
    fs.mkdirSync(moduleGitDir, { recursive: true });
    fs.writeFileSync(path.join(submodule, ".git"), `gitdir: ${moduleGitDir}\n`);
    expectFatal(projectRoot, "submodule gitdir must be relative");

    fs.writeFileSync(path.join(submodule, ".git"), "gitdir: ../../../../.git/modules/vendor/lib\n");
    fs.writeFileSync(path.join(moduleGitDir, "config"), `[core]\n\tworktree = ${submodule}\n`);
    expectFatal(projectRoot, "core.worktree must be relative");
  });

  test("malformed gitfiles are fatal instead of skipped", () => {
    const projectRoot = path.join(tmp, "malformed");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.writeFileSync(path.join(projectRoot, ".git"), "not-a-gitdir\n");

    expectFatal(projectRoot, ".git file must start with gitdir:");
  });

  test("symlinked gitfiles are fatal without reading the target", () => {
    const projectRoot = path.join(tmp, "symlinked");
    const secretTarget = path.join(tmp, "secret");
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.writeFileSync(secretTarget, "gitdir: /should/not/be/read\n");
    fs.symlinkSync(secretTarget, path.join(projectRoot, ".git"));

    expectFatal(projectRoot, ".git must not be a symlink");
  });

  test("resolves a real relative linked worktree created by git when supported", () => {
    const help = childProcess.spawnSync("git", ["worktree", "add", "-h"], { encoding: "utf8" });
    if (!`${help.stdout}\n${help.stderr}`.includes("--relative-paths")) return;

    const main = path.join(tmp, "repo");
    const feature = path.join(main, ".worktrees", "feature");
    for (const args of [
      ["init", main],
      ["-C", main, "config", "user.email", "test@example.test"],
      ["-C", main, "config", "user.name", "Runfree Test"],
      ["-C", main, "config", "--local", "worktree.useRelativePaths", "true"],
    ]) {
      expect(childProcess.spawnSync("git", args, { stdio: "ignore" }).status).toBe(0);
    }
    fs.writeFileSync(path.join(main, "README.md"), "test\n");
    expect(childProcess.spawnSync("git", ["-C", main, "add", "README.md"], { stdio: "ignore" }).status).toBe(0);
    expect(childProcess.spawnSync("git", ["-C", main, "commit", "-m", "init"], { stdio: "ignore" }).status).toBe(0);
    expect(childProcess.spawnSync("git", ["-C", main, "worktree", "add", "--relative-paths", feature], { stdio: "ignore" }).status).toBe(0);

    const result = classifyGitRepository(feature);

    expect(result.kind).toBe("relative-linked");
    if (result.kind !== "relative-linked") throw new Error("expected linked worktree");
    expect(result.details.relativeGitDir.startsWith("worktrees/")).toBe(true);
  });
});
