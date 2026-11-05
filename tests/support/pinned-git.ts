// Vitest globalSetup: run the whole suite on a pinned Git, never the host's.
//
// Tests that spawn the real `git` would otherwise prove behavior on whatever
// Git the OS ships (Ubuntu 24.04 has 2.43, below the 2.48 that relative
// worktree links need). This puts the pinned Git first on PATH before any
// worker starts: the lock file's default version, or the one
// RUNFREE_TEST_GIT_VERSION names (`make test-git` sets it per lane). Product
// code and tests spawn `git` by name, so they all get it.
//
// It never falls back to the host Git and never skips: without the pinned
// binary (offline with an empty cache, an unsupported platform) the run fails
// with the command that fixes it. See CONTRIBUTING.md "Pinned Git".

import { ensurePinnedGit, GIT_VERSION_ENV, prependPath } from "../../scripts/git-bins.ts";

export default function setup(): void {
  const { version, binDir } = ensurePinnedGit();
  process.env.PATH = prependPath(binDir, process.env.PATH);
  // Workers read this to know which Git they run on without probing it.
  process.env[GIT_VERSION_ENV] = version;
}
