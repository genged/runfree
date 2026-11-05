import { describe, expect, test } from "vitest";

import { staleGitMatrixEntries, strayLoadedTestFiles, unreachableTrackedTestFiles } from "./check-test-inventory.ts";

describe("test inventory comparison", () => {
  test("a loaded test file git ignores is reported as a stray", () => {
    // The regression this gate exists for: a gitignored maintainer directory
    // whose tests the local suite loads but CI never sees.
    const loaded = ["scripts/a.test.ts", "local/scripts/oneshot-release.test.ts"];
    const gitVisible = ["scripts/a.test.ts"];

    expect(strayLoadedTestFiles(loaded, gitVisible)).toEqual(["local/scripts/oneshot-release.test.ts"]);
  });

  test("loaded files that git tracks, or would track once added, are not strays", () => {
    const gitVisible = ["scripts/a.test.ts", "scripts/new-untracked.test.ts"];

    expect(strayLoadedTestFiles(["scripts/a.test.ts", "scripts/new-untracked.test.ts"], gitVisible)).toEqual([]);
  });

  test("a tracked test file no project loads is reported as unreachable", () => {
    expect(unreachableTrackedTestFiles(["scripts/a.test.ts", "scripts/b.test.ts"], ["scripts/a.test.ts"])).toEqual([
      "scripts/b.test.ts",
    ]);
    expect(unreachableTrackedTestFiles(["scripts/a.test.ts"], ["scripts/a.test.ts", "scripts/extra.test.ts"])).toEqual(
      [],
    );
  });

  test("a Git matrix entry that names no tracked test file is stale", () => {
    // A renamed file would otherwise leave `make test-git` green with the file
    // silently dropped from every lane.
    const tracked = ["scripts/a.test.ts", "packages/cli/src/runtime/git-layout.test.ts"];

    expect(staleGitMatrixEntries(["scripts/a.test.ts", "scripts/renamed.test.ts", "scripts/a.ts"], tracked)).toEqual([
      "scripts/a.ts",
      "scripts/renamed.test.ts",
    ]);
    expect(staleGitMatrixEntries(tracked, tracked)).toEqual([]);
  });
});
