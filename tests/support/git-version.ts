// Which Git the suite runs on, and tests that need a minimum version.
//
// tests/support/pinned-git.ts puts a pinned Git first on PATH and records its
// exact version in RUNFREE_TEST_GIT_VERSION before any worker starts, so a
// test knows its Git without probing it.
//
// `needsGit("2.48")` replaces `test` for a test whose setup cannot exist on an
// older Git. It skips only in a `make test-git` lane below that version, and
// its title carries the requirement, so the lane runner counts it as "not
// applicable"; an undeclared skip on one Git that runs on another fails the
// lane. The default version always runs everything: a requirement above it
// throws.

import { test } from "vitest";

import { compareGitVersions, GIT_VERSION_ENV, readGitBinsLock } from "../../scripts/git-bins.ts";

export function pinnedGitVersion(env: NodeJS.ProcessEnv = process.env): string {
  const version = env[GIT_VERSION_ENV];
  if (!version) {
    throw new Error(`${GIT_VERSION_ENV} is unset: tests/support/pinned-git.ts (the Vitest globalSetup) did not run`);
  }
  return version;
}

export function gitAtLeast(minimum: string, version = pinnedGitVersion()): boolean {
  return compareGitVersions(version, minimum) >= 0;
}

export function needsGit(minimum: string): (name: string, fn: () => void | Promise<void>) => void {
  const defaultVersion = readGitBinsLock().default;
  if (!gitAtLeast(minimum, defaultVersion)) {
    throw new Error(`a test needs Git ${minimum}, above the default pinned Git ${defaultVersion}; raise "default" in git-bins.lock.json`);
  }
  const runs = gitAtLeast(minimum);
  return (name, fn) => (runs ? test : test.skip)(`${name} [needs Git ${minimum}]`, fn);
}
