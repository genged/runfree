---
name: runfree-git-workflow
description: Use when creating a Runfree worktree, committing on a branch, or rebasing, testing, merging, and cleaning up a contribution.
user-invocable: false
metadata:
  internal: true
---

## Git Workflow

Before any merge, rebase the branch onto `main`; never merge `main` into the
branch. Run every required gate on the rebased head and stop if any suite
fails. An isolated pass does not clear a failing full suite.

Contributions arrive as pull requests (`CONTRIBUTING.md`). These rules apply
wherever an agent commits:

- A worktree inside the repo must sit under `.worktrees/`, the only in-repo
  path that git, Biome, and Vitest all ignore; any other in-repo location breaks
  `pnpm check` and `make test-static` in the main checkout. Run
  `pnpm install` in a new worktree.
- Put a fix on the branch under test unless the user names another.
- To land a branch: rebase it onto `main`, run the gates on the rebased head,
  then `git merge --no-ff <branch>`. Never merge `main` into the branch.
- The checkout may hold other uncommitted work. Stage your own files by exact
  path, never `git add -A`; report other changes in one line and leave them
  alone. "commit" means commit this session's changes without asking.
- Do not merge with failing tests. A flaky test gets fixed or disabled, never
  rerun until green.
