import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { projectInfo } from "../config.ts";

import {
  assertHostGitSupportsRelativeWorktrees,
  classifyGitRepository,
  gitLayoutPlanForShape,
  prepareGitRepositoryLayoutResult,
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
