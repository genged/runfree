import { describe, expect, test } from "vitest";

import {
  dependencyArtifactKindForPathSuffix,
  dependencyArtifactKindForRelativePath,
} from "./dependency-artifacts.ts";

describe("dependency artifact path classification", () => {
  test("classifies supported dependency artifact relative paths", () => {
    expect(dependencyArtifactKindForRelativePath("node_modules")).toBe("node_modules");
    expect(dependencyArtifactKindForRelativePath("packages/app/node_modules")).toBe("node_modules");
    expect(dependencyArtifactKindForRelativePath(".pnpm-store")).toBe("pnpm-store");
    expect(dependencyArtifactKindForRelativePath(".bun")).toBe("bun");
    expect(dependencyArtifactKindForRelativePath(".yarn/unplugged")).toBe("yarn-unplugged");
    expect(dependencyArtifactKindForRelativePath("packages/app/.yarn/unplugged")).toBe("yarn-unplugged");
    expect(dependencyArtifactKindForRelativePath(".venv")).toBe("python-venv");
    expect(dependencyArtifactKindForRelativePath("tools/generator/scripts/.venv")).toBe("python-venv");
    expect(dependencyArtifactKindForRelativePath("venv")).toBe("python-venv");
    expect(dependencyArtifactKindForRelativePath("tools/generator/scripts/venv")).toBe("python-venv");
    expect(dependencyArtifactKindForRelativePath("__pypackages__")).toBe("python-pypackages");
    expect(dependencyArtifactKindForRelativePath("packages/app/__pypackages__")).toBe("python-pypackages");
  });

  test("leaves non-artifact source paths unclassified", () => {
    expect(dependencyArtifactKindForRelativePath("src")).toBeUndefined();
    expect(dependencyArtifactKindForRelativePath("packages/app/src")).toBeUndefined();
    expect(dependencyArtifactKindForRelativePath(".runfree")).toBeUndefined();
    expect(dependencyArtifactKindForRelativePath("docs/venv-notes")).toBeUndefined();
    expect(dependencyArtifactKindForRelativePath("packages/node_modules-fixture")).toBeUndefined();
  });

  test("classifies artifact suffixes in container mount targets", () => {
    expect(dependencyArtifactKindForPathSuffix("/workspace/packages/app/node_modules")).toBe("node_modules");
    expect(dependencyArtifactKindForPathSuffix("/runfree/git-layout/abc123abc123/.worktrees/app/node_modules")).toBe("node_modules");
    expect(dependencyArtifactKindForPathSuffix("/runfree/git-layout/abc123abc123/.worktrees/app/.pnpm-store")).toBe("pnpm-store");
    expect(dependencyArtifactKindForPathSuffix("/runfree/git-layout/abc123abc123/.worktrees/app/.bun")).toBe("bun");
    expect(dependencyArtifactKindForPathSuffix("/runfree/git-layout/abc123abc123/.worktrees/app/.yarn/unplugged")).toBe("yarn-unplugged");
    expect(dependencyArtifactKindForPathSuffix("/workspace/.agents/skills/gemini-image-generator/scripts/.venv")).toBe("python-venv");
    expect(dependencyArtifactKindForPathSuffix("/runfree/git-layout/abc123abc123/.worktrees/app/tools/.venv")).toBe("python-venv");
    expect(dependencyArtifactKindForPathSuffix("/workspace/packages/app/__pypackages__")).toBe("python-pypackages");
    expect(dependencyArtifactKindForPathSuffix("/runfree/git-layout/abc123abc123/.worktrees/app/__pypackages__")).toBe("python-pypackages");
    expect(dependencyArtifactKindForPathSuffix("/workspace/src")).toBeUndefined();
    expect(dependencyArtifactKindForPathSuffix("/workspace/packages/node_modules-fixture")).toBeUndefined();
  });
});
