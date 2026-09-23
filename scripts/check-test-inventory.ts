#!/usr/bin/env node

// `make test-all` is the whole gate, and its failure mode is silence: a test
// file no Vitest project globs, or a Makefile filter naming a suite that was
// renamed, both read as a pass. Vitest treats an unmatched filter as "nothing
// to add", not as an error.
//
// This check asks the tools themselves rather than restating their config:
// `vitest list --filesOnly` reports what a run would actually load (globbing
// only — it collects nothing and starts no runtime), and the result is compared
// against the files tracked in git, in both directions: every tracked test file
// must be loaded, and every loaded test file must be one git knows about. The
// second direction catches a gitignored directory (for example the
// maintainer-only `local/`) whose tests a local run would load but CI never
// sees.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

// Only needs to name a backend the config accepts; the live project does not
// exist otherwise, and its files would look unreachable.
const LIVE_BACKEND = "docker-desktop";
const INVENTORY_ARTIFACT = "/bin/true";
const INVENTORY_DOCKER_HOST = "unix:///runfree-e2e-inventory-only.sock";

/**
 * Test files a run would load that git neither tracks nor would track: the
 * files are present only in this clone (gitignored), so the local suite and CI
 * run different sets. `gitVisible` is tracked plus untracked-but-not-ignored
 * files; a new test that has not been `git add`ed yet is not a stray.
 */
export function strayLoadedTestFiles(loaded: Iterable<string>, gitVisible: Iterable<string>): string[] {
  const visible = new Set(gitVisible);
  return [...new Set(loaded)].filter((file) => !visible.has(file)).sort();
}

/** Tracked test files no Vitest project loads. */
export function unreachableTrackedTestFiles(tracked: Iterable<string>, loaded: Iterable<string>): string[] {
  const loadedSet = new Set(loaded);
  return [...new Set(tracked)].filter((file) => !loadedSet.has(file)).sort();
}

const problems: string[] = [];

function report(problem: string, offenders: readonly string[]): void {
  problems.push(`${problem}\n${offenders.map((entry) => `  ${entry}`).join("\n")}`);
}

function run(command: string, args: readonly string[], env: NodeJS.ProcessEnv = {}): string {
  const result = childProcess.spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, ...env },
    shell: false,
  });
  if (result.error || result.status !== 0) {
    console.error(`check-test-inventory: ${command} ${args.join(" ")} failed`);
    if (result.stderr) console.error(result.stderr.trim());
    process.exit(1);
  }
  return result.stdout;
}

function trackedFiles(...patterns: string[]): string[] {
  return run("git", ["ls-files", "-z", "--", ...patterns])
    .split("\0")
    .filter((entry) => entry.length > 0)
    // Verification runs before commit. An intentional working-tree deletion
    // remains in the index, but Vitest cannot load it. Makefile references to
    // deleted tests are checked separately below.
    .filter((entry) => fs.existsSync(path.join(repoRoot, entry)))
    .sort();
}

// Tracked plus untracked-but-not-ignored: every file git would report or
// commit. Anything outside this set is gitignored.
function gitVisibleTestFiles(): string[] {
  return run("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.test.ts"])
    .split("\0")
    .filter((entry) => entry.length > 0);
}

// `vitest list --filesOnly` prints one `[project] path` per line.
function globbedTestFiles(args: readonly string[], env: NodeJS.ProcessEnv = {}): string[] {
  return run("pnpm", ["exec", "vitest", "list", "--filesOnly", ...args], env)
    .split("\n")
    .map((line) => line.replace(/^\[[^\]]+\]\s+/, "").trim())
    .filter((line) => line.endsWith(".test.ts"))
    .sort();
}

function main(): void {
  const tracked = trackedFiles("*.test.ts");
  const defaultProjects = globbedTestFiles([]);
  const liveProject = globbedTestFiles(["--project", "runtime-live"], { TEST_RUNTIME_BACKEND: LIVE_BACKEND });
  const e2eProject = globbedTestFiles(["--project", "cli-e2e"], { RUNFREE_E2E_ARTIFACT: INVENTORY_ARTIFACT });
  const e2eLiveProject = globbedTestFiles(["--project", "cli-e2e-live"], {
    RUNFREE_E2E_ARTIFACT: INVENTORY_ARTIFACT,
    RUNFREE_E2E_DOCKER_HOST: INVENTORY_DOCKER_HOST,
    TEST_RUNTIME_BACKEND: LIVE_BACKEND,
  });
  const globbed = new Set([...defaultProjects, ...liveProject, ...e2eProject, ...e2eLiveProject]);

  // Vacuity guards: an empty set on either side satisfies every comparison below.
  if (tracked.length === 0) {
    console.error("check-test-inventory: git tracks no test files; the comparison would pass vacuously");
    process.exit(1);
  }
  if (defaultProjects.length === 0 || liveProject.length === 0 || e2eProject.length === 0 || e2eLiveProject.length === 0) {
    console.error("check-test-inventory: a Vitest project globbed no files; the comparison would pass vacuously");
    process.exit(1);
  }

  const unreachable = unreachableTrackedTestFiles(tracked, globbed);
  if (unreachable.length > 0) {
    report("test files no Vitest project runs (excluded by config, or outside every include):", unreachable);
  }

  const stray = strayLoadedTestFiles(globbed, gitVisibleTestFiles());
  if (stray.length > 0) {
    report("test files a Vitest project loads that git ignores (local-only; CI never runs them — exclude them in vitest.config.ts):", stray);
  }

  // Every path a Makefile target filters on. An unmatched filter is not an error
  // to Vitest, so a renamed suite drops out of a target with nothing failing.
  const makefile = fs.readFileSync(path.join(repoRoot, "Makefile"), "utf8");
  const testAllPrerequisites = /^test-all:\s+(.+)$/mu.exec(makefile)?.[1]?.trim().split(/\s+/u) ?? [];
  const requiredTestAllPrerequisites = [
    "test",
    "test-templates",
    "test-runtime",
    "test-cli-e2e",
    "test-cli-e2e-live",
  ];
  const omittedTestAllPrerequisites = requiredTestAllPrerequisites.filter(
    (target) => !testAllPrerequisites.includes(target),
  );
  if (omittedTestAllPrerequisites.length > 0) {
    report("Makefile test-all omits required top-level test targets:", omittedTestAllPrerequisites);
  }
  const referenced = [...makefile.matchAll(/[\w./-]+\.test\.ts/g)]
    .map((match) => match[0])
    // Prose in the Makefile also mentions patterns such as `*.live.test.ts`,
    // which name no single file.
    .filter((file) => file.includes("/") && !file.startsWith("."));
  const missing = referenced.filter((file) => !fs.existsSync(path.join(repoRoot, file)));
  if (missing.length > 0) {
    report("Makefile targets filter on test files that no longer exist:", [...new Set(missing)]);
  }

  if (problems.length > 0) {
    console.error(`check-test-inventory: ${problems.join("\n\n")}`);
    process.exit(1);
  }

  console.log(
    `check-test-inventory: ${tracked.length} tracked test files, all reachable, none gitignored ` +
      `(${defaultProjects.length} unit, ${liveProject.length} live, ${e2eProject.length} packaged e2e, ${e2eLiveProject.length} packaged live); ` +
      `${referenced.length} Makefile filters resolve`,
  );
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
