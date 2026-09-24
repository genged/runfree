import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  PYPI_PREFLIGHT_REMEDIATION,
  createDependencyOverlayPlan,
  dependencyOverlayEnvironment,
  dependencyOverlayInstallCommand,
  dependencyOverlayMounts,
  dependencyOverlayNamedVolumes,
  dependencyOverlayRuntimeSignature,
  dependencyPrepFixScript,
  dependencyPrepMountpoint,
  dependencyPrepProbeScript,
  depsRuntime,
  ensureComposeManagedSessionVolumes,
  ensureDependencyVolumeOwnership,
  parseDependencyPrepFixRecords,
  parseDependencyPrepProbeRecords,
} from "./dependency-overlays.ts";
import { composeProjectName } from "./env.ts";

let tmp: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-deps-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function writeJson(relativePath: string, value: unknown): void {
  const filePath = path.join(tmp, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

describe("dependency overlay planner", () => {
  test("predicts pnpm workspace node_modules overlays before host installs exist", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.writeFileSync(path.join(tmp, "pnpm-workspace.yaml"), "packages:\n  - packages/*\n  - '!packages/ignored'\n");
    writeJson("packages/app/package.json", { name: "app" });
    writeJson("packages/shared/package.json", { name: "shared" });
    writeJson("packages/ignored/package.json", { name: "ignored" });

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.packageManagers).toEqual(["pnpm"]);
    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual([
      ".",
      "packages/app",
      "packages/shared",
    ]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([
      "node_modules",
      "packages/app/node_modules",
      "packages/shared/node_modules",
    ]);
    expect(dependencyOverlayEnvironment(plan)).toMatchObject({
      NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store",
    });
    expect(dependencyOverlayInstallCommand(plan)).toBe("pnpm install --frozen-lockfile");
  });

  test("parses inline pnpm workspace package arrays", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.writeFileSync(path.join(tmp, "pnpm-workspace.yaml"), "packages: [\"packages/*\", '!packages/ignored']\n");
    writeJson("packages/app/package.json", { name: "app" });
    writeJson("packages/ignored/package.json", { name: "ignored" });

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual([
      ".",
      "packages/app",
    ]);
  });

  test("parses pnpm workspace package lists with a key-line comment", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.writeFileSync(path.join(tmp, "pnpm-workspace.yaml"), "packages: # workspace globs\n  - packages/*\n");
    writeJson("packages/app/package.json", { name: "app" });

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual([
      ".",
      "packages/app",
    ]);
  });

  test("fails loudly on unsupported pnpm workspace YAML syntax", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.writeFileSync(path.join(tmp, "pnpm-workspace.yaml"), "packages: &workspace_packages\n  - packages/*\n");
    writeJson("packages/app/package.json", { name: "app" });

    expect(() => createDependencyOverlayPlan(tmp)).toThrow("unsupported pnpm-workspace.yaml packages syntax");
  });

  test("parses npm workspaces and selects npm ci when a lockfile exists", () => {
    writeJson("package.json", {
      packageManager: "npm@10.0.0",
      workspaces: ["apps/*"],
    });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    writeJson("apps/web/package.json", { name: "web" });

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.packageManagers).toEqual(["npm"]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(expect.arrayContaining([
      "node_modules",
      "apps/web/node_modules",
    ]));
    expect(plan.overlays).toHaveLength(2);
    expect(dependencyOverlayEnvironment(plan)).toMatchObject({
      NPM_CONFIG_CACHE: "/home/agent/.npm",
    });
    expect(dependencyOverlayInstallCommand(plan)).toBe("npm ci");
  });

  test("does not invent node_modules for Yarn PnP but overlays observed unplugged artifacts", () => {
    writeJson("package.json", { packageManager: "yarn@4.0.0", workspaces: ["packages/*"] });
    fs.writeFileSync(path.join(tmp, "yarn.lock"), "\n");
    fs.writeFileSync(path.join(tmp, ".yarnrc.yml"), "nodeLinker: pnp\n");
    writeJson("packages/app/package.json", { name: "app" });

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: [".yarn/unplugged/"],
    });

    expect(plan.packageManagers).toEqual(["yarn"]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([".yarn/unplugged"]);
    expect(plan.overlays[0].reason).toContain("git ignored dependency dir");
    expect(dependencyOverlayInstallCommand(plan)).toBe("yarn install --immutable");
  });

  test("treats lockfile-only Yarn projects as Yarn Classic", () => {
    writeJson("package.json", { name: "classic-yarn" });
    fs.writeFileSync(path.join(tmp, "yarn.lock"), "\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.packageManagers).toEqual(["yarn"]);
    expect(dependencyOverlayInstallCommand(plan)).toBe("yarn install --frozen-lockfile");
  });

  test("uses ignored Git paths as evidence without hiding arbitrary ignored or untracked files", () => {
    writeJson("package.json", { packageManager: "bun@1.1.0" });
    fs.writeFileSync(path.join(tmp, "bun.lock"), "\n");

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: ["examples/demo/node_modules/", "tmp-repro/", ".bun/"],
      gitUntrackedPaths: ["scratch.ts", "notes/"],
    });

    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([
      ".bun",
      "examples/demo/node_modules",
      "node_modules",
    ]);
    expect(plan.ignoredCandidates).toContainEqual({
      hostRelativePath: "tmp-repro",
      reason: "ignored directory did not match dependency artifact allowlist",
    });
    expect(plan.overlays.some((overlay) => overlay.hostRelativePath === "notes")).toBe(false);
  });

  test("does not overlay tracked dependency artifact directories", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    writeJson("node_modules/vendored/package.json", { name: "vendored" });

    const plan = createDependencyOverlayPlan(tmp, {
      gitTrackedPaths: ["node_modules/vendored/package.json"],
    });

    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([]);
  });

  test("does not overlay tracked package-local dependency artifact directories", () => {
    writeJson("package.json", {
      packageManager: "pnpm@10.28.0",
    });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.writeFileSync(path.join(tmp, "pnpm-workspace.yaml"), "packages:\n  - packages/*\n");
    writeJson("packages/app/package.json", { name: "app" });
    writeJson("packages/app/node_modules/vendored/package.json", { name: "vendored" });

    const plan = createDependencyOverlayPlan(tmp, {
      gitTrackedPaths: ["packages/app/node_modules/vendored/package.json"],
    });

    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["node_modules"]);
  });

  test("does not overlay tracked observed dependency artifact directories", () => {
    writeJson("package.json", { packageManager: "bun@1.1.0" });
    fs.writeFileSync(path.join(tmp, "bun.lock"), "\n");

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: [".bun/"],
      gitTrackedPaths: [".bun/install/cache/pkg"],
    });

    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["node_modules"]);
  });

  test("detects nested independent JavaScript projects without scanning dependency trees", () => {
    writeJson("package.json", { name: "root" });
    writeJson("examples/demo/package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "examples/demo/package-lock.json"), "{}\n");
    writeJson("node_modules/pkg/package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "node_modules/pkg/package-lock.json"), "{}\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual(["examples/demo"]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["examples/demo/node_modules"]);
    expect(plan.installCommands).toEqual([{
      ecosystem: "javascript",
      hostRelativePath: "examples/demo",
      packageManager: "npm",
      tool: "npm",
      command: "npm ci",
    }]);
  });

  test("does not scan ignored non-artifact directories for nested package roots", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    writeJson("scratch-checkouts/other-project/package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "scratch-checkouts/other-project/package-lock.json"), "{}\n");

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: ["scratch-checkouts/"],
    });

    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual(["."]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["node_modules"]);
    expect(plan.installCommands).toEqual([{
      ecosystem: "javascript",
      hostRelativePath: ".",
      packageManager: "pnpm",
      tool: "pnpm",
      command: "pnpm install --frozen-lockfile",
    }]);
    expect(plan.ignoredCandidates).toContainEqual({
      hostRelativePath: "scratch-checkouts",
      reason: "ignored directory did not match dependency artifact allowlist",
    });
  });

  test("overlays ignored Python virtualenvs without scanning nested package files", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.mkdirSync(path.join(tmp, ".venv"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".venv", "pyvenv.cfg"), "home = /usr/bin\n");
    writeJson(".venv/tools/package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, ".venv/tools/package-lock.json"), "{}\n");

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: [".venv/"],
    });

    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual(["."]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([".venv", "node_modules"]);
    expect(plan.overlays.find((overlay) => overlay.hostRelativePath === ".venv")?.reason).toContain("python");
    expect(plan.installCommands).toEqual([{
      ecosystem: "javascript",
      hostRelativePath: ".",
      packageManager: "pnpm",
      tool: "pnpm",
      command: "pnpm install --frozen-lockfile",
    }]);
  });

  test("detects uv roots with predicted virtualenv overlays and uv cache stores", () => {
    fs.writeFileSync(path.join(tmp, "uv.lock"), "\n");
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), "[project]\nname = \"app\"\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.roots).toContainEqual(expect.objectContaining({
      ecosystem: "python",
      tool: "uv",
      hostRelativePath: ".",
      evidence: "uv.lock",
      confidence: "high",
    }));
    expect(plan.overlays).toContainEqual(expect.objectContaining({
      hostRelativePath: ".venv",
      reason: "predicted uv project virtualenv",
    }));
    expect(plan.storeVolumes).toContainEqual(expect.objectContaining({
      ecosystem: "python",
      storeName: "uv",
      target: "/home/agent/.cache/uv",
      environment: { UV_CACHE_DIR: "/home/agent/.cache/uv" },
    }));
    expect(plan.installCommands).toEqual([expect.objectContaining({
      ecosystem: "python",
      tool: "uv",
      hostRelativePath: ".",
      command: "uv sync",
    })]);
  });

  test("supports JavaScript and Python roots in the same directory", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.writeFileSync(path.join(tmp, "uv.lock"), "\n");
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), "[tool.uv]\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.roots).toEqual(expect.arrayContaining([
      expect.objectContaining({ ecosystem: "javascript", tool: "pnpm", hostRelativePath: "." }),
      expect.objectContaining({ ecosystem: "python", tool: "uv", hostRelativePath: "." }),
    ]));
    expect(plan.workspaceRoots.filter((entry) => entry.hostRelativePath === ".")).toHaveLength(2);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([".venv", "node_modules"]);
    expect(plan.installCommands).toEqual([
      expect.objectContaining({
        ecosystem: "javascript",
        tool: "pnpm",
        hostRelativePath: ".",
        command: "pnpm install --frozen-lockfile",
      }),
      expect.objectContaining({
        ecosystem: "python",
        tool: "uv",
        hostRelativePath: ".",
        command: "uv sync",
      }),
    ]);
  });

  test("detects nested Poetry projects under JavaScript roots", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0", workspaces: ["packages/*"] });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.mkdirSync(path.join(tmp, "services/api"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "services/api/pyproject.toml"), "[tool.poetry]\nname = \"api\"\n");
    fs.writeFileSync(path.join(tmp, "services/api/poetry.lock"), "\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.roots).toEqual(expect.arrayContaining([
      expect.objectContaining({ ecosystem: "javascript", tool: "pnpm", hostRelativePath: "." }),
      expect.objectContaining({ ecosystem: "python", tool: "poetry", hostRelativePath: "services/api" }),
    ]));
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["node_modules", "services/api/.venv"]);
    expect(plan.storeVolumes.map((store) => store.storeName)).toEqual(["pnpm", "poetry"]);
    expect(plan.installCommands).toEqual([
      expect.objectContaining({ ecosystem: "javascript", tool: "pnpm", hostRelativePath: "." }),
      expect.objectContaining({ ecosystem: "python", tool: "poetry", hostRelativePath: "services/api", command: "poetry install" }),
    ]);
  });

  test("detects pip requirements with the narrowest stable install command", () => {
    fs.writeFileSync(path.join(tmp, "requirements-dev.txt"), "\n");
    fs.writeFileSync(path.join(tmp, "requirements.txt"), "\n");
    fs.writeFileSync(path.join(tmp, "requirements-extra.txt"), "\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.roots).toContainEqual(expect.objectContaining({
      ecosystem: "python",
      tool: "pip",
      hostRelativePath: ".",
      confidence: "medium",
    }));
    expect(plan.installCommands).toEqual([expect.objectContaining({
      ecosystem: "python",
      tool: "pip",
      hostRelativePath: ".",
      command: "python -m venv .venv && .venv/bin/python -m pip install -r 'requirements.txt'",
    })]);
  });

  test("quotes pip requirements filenames in generated install commands", () => {
    fs.writeFileSync(path.join(tmp, "requirements; touch owned.txt"), "\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.installCommands).toEqual([expect.objectContaining({
      ecosystem: "python",
      tool: "pip",
      hostRelativePath: ".",
      command: "python -m venv .venv && .venv/bin/python -m pip install -r 'requirements; touch owned.txt'",
    })]);
  });

  test("reports low-confidence fixture Python projects without overlays or install commands", () => {
    fs.mkdirSync(path.join(tmp, "tests/fixtures/demo"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "tests/fixtures/demo/pyproject.toml"), "[project]\nname = \"demo\"\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.roots).toContainEqual(expect.objectContaining({
      ecosystem: "python",
      tool: "pip",
      hostRelativePath: "tests/fixtures/demo",
      confidence: "low",
    }));
    expect(plan.overlays).toEqual([]);
    expect(plan.storeVolumes).toEqual([]);
    expect(plan.installCommands).toEqual([]);
  });

  test("does not overlay ignored virtualenv candidates without pyvenv.cfg", () => {
    fs.mkdirSync(path.join(tmp, ".venv"), { recursive: true });

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: [".venv/"],
    });

    expect(plan.overlays).toEqual([]);
    expect(plan.ignoredCandidates).toContainEqual({
      hostRelativePath: ".venv",
      reason: "ignored directory did not match dependency artifact allowlist",
    });
  });

  test("does not overlay PDM __pypackages__ without explicit PEP 582 evidence", () => {
    fs.mkdirSync(path.join(tmp, "__pypackages__/3.12/lib"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), "[tool.pdm]\n");
    fs.writeFileSync(path.join(tmp, "pdm.lock"), "\n");

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: ["__pypackages__/"],
    });

    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual([".venv"]);
    expect(plan.ignoredCandidates).toContainEqual({
      hostRelativePath: "__pypackages__",
      reason: "ignored directory did not match dependency artifact allowlist",
    });
  });

  test("warns about credential-bearing Python package index URLs without printing credentials", () => {
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), [
      "[project]",
      "name = \"app\"",
      "[tool.uv]",
      "index-url = \"https://user:secret-token@packages.example.test/simple\"",
      "",
    ].join("\n"));

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.warnings).toContainEqual({
      hostRelativePath: "pyproject.toml",
      reason: "Python package index config may contain a credential-bearing URL; use exact-host allowlisting plus proxy token policy instead",
    });
    expect(JSON.stringify(plan.warnings)).not.toContain("secret-token");
  });

  test("ignores Runfree-owned runtime roots when they live under the project during tests", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    writeJson(".xdg-data/runfree/versions/0.1.0/runtime/agent/agent-tools/package.json", {
      packageManager: "npm@10.0.0",
    });
    fs.writeFileSync(
      path.join(tmp, ".xdg-data/runfree/versions/0.1.0/runtime/agent/agent-tools/package-lock.json"),
      "{}\n",
    );

    const plan = createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: [
        ".xdg-data/runfree/versions/0.1.0/runtime/agent/agent-tools/node_modules/",
      ],
      ignoredRootPaths: [path.join(tmp, ".xdg-data/runfree")],
    });

    expect(plan.workspaceRoots.map((entry) => entry.hostRelativePath)).toEqual(["."]);
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["node_modules"]);
    expect(plan.ignoredCandidates).toEqual([]);
  });

  test("keeps install commands for mixed root and nested package managers", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    writeJson("examples/demo/package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "examples/demo/package-lock.json"), "{}\n");

    const plan = createDependencyOverlayPlan(tmp);

    expect(plan.packageManagers).toEqual(["pnpm", "npm"]);
    expect(plan.installCommands).toEqual([{
      ecosystem: "javascript",
      hostRelativePath: ".",
      packageManager: "pnpm",
      tool: "pnpm",
      command: "pnpm install --frozen-lockfile",
    }, {
      ecosystem: "javascript",
      hostRelativePath: "examples/demo",
      packageManager: "npm",
      tool: "npm",
      command: "npm ci",
    }]);
  });

  test("generates stable safe volume names and compose mounts", () => {
    writeJson("package.json", { packageManager: "pnpm@10.28.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");

    const first = createDependencyOverlayPlan(tmp);
    const second = createDependencyOverlayPlan(tmp);

    expect(first.overlays[0].volume).toBe(second.overlays[0].volume);
    expect(first.overlays[0].volume).toMatch(/^runfree-deps-[a-f0-9]{12}-root-node-modules$/);
    expect(dependencyOverlayMounts(first)).toContainEqual({
      type: "volume",
      source: first.overlays[0].volume,
      target: "/workspace/node_modules",
      noCopy: true,
    });
    expect(dependencyOverlayMounts(first)).toContainEqual({
      type: "volume",
      source: `runfree-deps-${first.workspaceHash}-pnpm-store`,
      target: "/home/agent/.local/share/pnpm/store",
      noCopy: true,
    });
    expect(dependencyOverlayNamedVolumes(first)).toContain(first.overlays[0].volume);
    expect(dependencyOverlayNamedVolumes(first)).toContain(`runfree-deps-${first.workspaceHash}-pnpm-store`);
  });

  test("runtime signature uses the rendered project container root", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");

    const plan = createDependencyOverlayPlan(tmp);
    const signature = dependencyOverlayRuntimeSignature(plan, "/runfree/git-layout/project/worktree");

    expect(signature.mounts).toContainEqual({
      type: "volume",
      source: plan.overlays[0].volume,
      target: "/runfree/git-layout/project/worktree/node_modules",
      noCopy: true,
    });
    expect(signature.environment).toMatchObject({ NPM_CONFIG_CACHE: "/home/agent/.npm" });
  });

  test("fails closed when an overlay target collides with a host file", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.writeFileSync(path.join(tmp, "node_modules"), "not a directory\n");

    expect(() => createDependencyOverlayPlan(tmp)).toThrow("dependency overlay target is a file");
  });

  test("fails closed when an overlay parent path is a symlink", () => {
    writeJson("package.json", { name: "root" });
    const outside = path.join(tmp, "..", "outside-link-target");
    fs.mkdirSync(outside, { recursive: true });
    fs.symlinkSync(outside, path.join(tmp, "linked"));

    expect(() => createDependencyOverlayPlan(tmp, {
      gitIgnoredPaths: ["linked/node_modules/"],
    })).toThrow("dependency overlay parent is a symlink: linked");
  });

  test("does not validate disabled overlay targets", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.writeFileSync(path.join(tmp, "node_modules"), "not a directory\n");

    const plan = createDependencyOverlayPlan(tmp, { mode: "off" });

    expect(plan.mode).toBe("off");
    expect(plan.overlays.map((overlay) => overlay.hostRelativePath)).toEqual(["node_modules"]);
    expect(dependencyOverlayMounts(plan)).toEqual([]);
  });

  test("PyPI preflight remediation points at the python service", () => {
    expect(PYPI_PREFLIGHT_REMEDIATION).toBe("Run: runfree service enable python");
  });
});

type PrepCaptureOptions = {
  fixResult?: (volumeCount: number) => { status: number; stdout: string; stderr: string };
  probeResult?: (volumeCount: number) => { status: number; stdout: string; stderr: string };
  volumeInspect?: (names: string[]) => { status: number; stdout: string; stderr: string };
};

function validVolumeInspectJson(names: string[]): string {
  const project = composeProjectName(tmp);
  return JSON.stringify(names.map((name) => ({
    Name: name,
    Driver: "local",
    Scope: "local",
    Options: null,
    Mountpoint: `/var/lib/docker/volumes/${name}/_data`,
    Labels: {
      "com.docker.compose.project": project,
      "com.docker.compose.volume": name.slice(project.length + 1),
    },
  })));
}

function fixRecords(count: number): string {
  return `${Array.from({ length: count }, (_, index) => `RUNFREE_DEP_PREP ${index} owner=1000:1000 fixed=0`).join("\n")}\n`;
}

function probeRecords(count: number): string {
  return `${Array.from({ length: count }, (_, index) => `RUNFREE_DEP_PREP ${index} probe=ok`).join("\n")}\n`;
}

function prepFixture(plan: ReturnType<typeof createDependencyOverlayPlan>, options: PrepCaptureOptions = {}) {
  const captured: string[][] = [];
  const volumeCount = (args: string[]): number => args.filter((arg) => arg === "-v").length;
  const io = {
    capture: (_command: string, args: string[]) => {
      captured.push(args);
      if (args[0] === "volume" && args[1] === "inspect") {
        const names = args.slice(2);
        return options.volumeInspect?.(names) ?? { status: 0, stdout: validVolumeInspectJson(names), stderr: "" };
      }
      if (args.includes("--cap-add")) {
        return options.fixResult?.(volumeCount(args)) ?? { status: 0, stdout: fixRecords(volumeCount(args)), stderr: "" };
      }
      return options.probeResult?.(volumeCount(args)) ?? { status: 0, stdout: probeRecords(volumeCount(args)), stderr: "" };
    },
  } as unknown as import("./types.ts").RuntimeIO;
  const docker = {
    runningServiceContainerId: () => undefined,
    serviceContainerId: () => undefined,
  } as unknown as import("./docker.ts").RuntimeDocker;
  const context = {
    projectRoot: tmp,
    env: {},
    agentImage: "runfree-agent:selected",
    dependencyOverlayPlan: plan,
    gitLayoutPlan: { containerProjectRoot: "/workspaces/project" },
    project: { config: { agents: { default: "claude" } }, paths: { stateDir: path.join(tmp, ".runfree-test-state") } },
  } as unknown as import("./types.ts").RuntimeContext;
  return { captured, io, docker, context };
}

describe("dependency volume ownership without an agent container", () => {
  test("prepares every volume with two batched helpers: a chown-only root run and a capability-free write probe", () => {
    // The post-cutover shape (L2): no shared agent exists, so preparation runs
    // as two hardened `--rm` helpers IN TOTAL on no network — one root+CHOWN
    // run and one agent-uid probe run — each mounting every volume at an
    // index-keyed scratch leaf, never two runs per volume.
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });
    expect(plan.overlays.length).toBeGreaterThan(0);
    const { captured, io, docker, context } = prepFixture(plan);

    const status = ensureDependencyVolumeOwnership(context, io, docker);

    expect(status).toBe(0);
    // One batched volume inspection plus exactly two helper runs, no matter
    // how many volumes the plan carries.
    const runs = captured.filter((args) => args[0] === "run");
    const inspects = captured.filter((args) => args[0] === "volume");
    expect(captured).toHaveLength(3);
    expect(inspects).toHaveLength(1);
    expect(runs).toHaveLength(2);
    for (const args of runs) {
      expect(args.slice(0, 2)).toEqual(["run", "--rm"]);
      expect(args).toEqual(expect.arrayContaining(["--cap-drop", "ALL", "--network", "none", "--read-only"]));
      expect(args).toContain("runfree-agent:selected");
      expect(args).toEqual(expect.arrayContaining(["--label", "io.runfree.helper-purpose=dependency-prep"]));
    }
    const [fix, probe] = runs;
    expect(fix).toEqual(expect.arrayContaining(["--user", "0:0", "--cap-add", "CHOWN"]));
    expect(probe).toEqual(expect.arrayContaining(["--user", "1000:1000"]));
    expect(probe).not.toContain("--cap-add");
    // Every volume rides the Compose-managed name so helpers and sessions
    // prepare and mount the very same volume — mounted at its index-keyed
    // shallow scratch leaf, never its real (possibly deep) target, so the
    // --read-only helper can always create the mountpoint.
    const expectedVolume = `${composeProjectName(tmp)}_${plan.overlays[0].volume}`;
    expect(fix.join(" ")).toContain(`${expectedVolume}:/mnt/runfree-dep-prep/0`);
    for (const args of runs) {
      const volumeSpecs = args
        .map((arg, index) => (arg === "-v" ? args[index + 1] : undefined))
        .filter((spec): spec is string => spec !== undefined);
      expect(volumeSpecs.length).toBeGreaterThan(0);
      volumeSpecs.forEach((spec, index) => {
        expect(spec.endsWith(`:${dependencyPrepMountpoint(index)}`)).toBe(true);
      });
    }
    // The two runs mount the same volumes at the same indices.
    expect(fix.filter((arg) => arg === "-v")).toEqual(probe.filter((arg) => arg === "-v"));
  });

  test("mounts a deep store target at the indexed scratch path, never its real target", () => {
    // The pnpm store's real target is /home/agent/.local/share/pnpm/store, whose
    // share/pnpm parents the agent image does not ship; a --read-only rootfs
    // cannot create that mountpoint. Prepping at the scratch path sidesteps it —
    // this is the regression that made `runfree deps install`-less startup fail
    // closed with "dependency volume target is missing".
    writeJson("package.json", { packageManager: "pnpm@9.0.0" });
    fs.writeFileSync(path.join(tmp, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });
    const store = plan.storeVolumes.find((volume) => volume.target === "/home/agent/.local/share/pnpm/store");
    expect(store).toBeDefined();
    const { captured, io, docker, context } = prepFixture(plan);

    expect(ensureDependencyVolumeOwnership(context, io, docker)).toBe(0);
    const storeVolume = `${composeProjectName(tmp)}_${store?.volume}`;
    const storeRuns = captured.filter((args) => args[0] === "run" && args.join(" ").includes(`${storeVolume}:`));
    expect(storeRuns).toHaveLength(2);
    for (const args of storeRuns) {
      expect(args.join(" ")).toMatch(new RegExp(`${storeVolume}:/mnt/runfree-dep-prep/\\d+`));
    }
    // The deep real target is never used as a mount destination.
    expect(captured.some((args) => args.join(" ").includes(":/home/agent/.local/share/pnpm/store"))).toBe(false);
  });

  test("refuses a wrong-shaped volume before any dependency-prep container runs", () => {
    // L2 constraint 1: only volumes that pass the Compose-managed local-volume
    // proof may be mounted. A pre-placed local-driver bind mount (Options set)
    // must abort before a `dependency-prep` helper exists.
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });
    const { captured, io, docker, context } = prepFixture(plan, {
      volumeInspect: (names) => {
        const records = JSON.parse(validVolumeInspectJson(names)) as Record<string, unknown>[];
        records[0].Options = { device: "/host/secret", o: "bind", type: "none" };
        return { status: 0, stdout: JSON.stringify(records), stderr: "" };
      },
    });

    expect(ensureDependencyVolumeOwnership(context, io, docker)).toBe(1);
    expect(captured.filter((args) => args[0] === "run")).toHaveLength(0);
  });

  test("a nonzero batch exit fails the launch and names the failed volume's real target", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });
    const { io, docker, context } = prepFixture(plan, {
      fixResult: () => ({ status: 22, stdout: "", stderr: "not-mountpoint 0\n" }),
    });

    expect(ensureDependencyVolumeOwnership(context, io, docker)).toBe(22);
  });

  test("missing, duplicated, reordered, or extra prep records fail the launch", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });
    // A zero-exit fix run whose records are short one volume: no partial
    // "prepared" result may escape the strict indexed parse.
    const { captured, io, docker, context } = prepFixture(plan, {
      fixResult: (count) => ({ status: 0, stdout: fixRecords(count - 1), stderr: "" }),
    });

    expect(ensureDependencyVolumeOwnership(context, io, docker)).toBe(1);
    // The write probe never ran: rejection happened before the second helper.
    expect(captured.filter((args) => args[0] === "run")).toHaveLength(1);
  });

  test("strict record parsers reject every framing deviation", () => {
    const good = "RUNFREE_DEP_PREP 0 owner=1000:1000 fixed=0\nRUNFREE_DEP_PREP 1 owner=0:0 fixed=1\n";
    expect(parseDependencyPrepFixRecords(good, 2)).toEqual([
      { index: 0, owner: "1000:1000", fixed: false },
      { index: 1, owner: "0:0", fixed: true },
    ]);
    for (const bad of [
      "RUNFREE_DEP_PREP 0 owner=1000:1000 fixed=0\n", // missing
      "RUNFREE_DEP_PREP 0 owner=1000:1000 fixed=0\nRUNFREE_DEP_PREP 0 owner=1000:1000 fixed=0\n", // duplicate
      "RUNFREE_DEP_PREP 1 owner=0:0 fixed=1\nRUNFREE_DEP_PREP 0 owner=1000:1000 fixed=0\n", // reordered
      `${good}RUNFREE_DEP_PREP 2 owner=1000:1000 fixed=0\n`, // extra
      "RUNFREE_DEP_PREP 0 owner=agent fixed=0\nRUNFREE_DEP_PREP 1 owner=0:0 fixed=1\n", // non-numeric owner
      `chatter\n${good}`, // unrecognized line
    ]) {
      expect(parseDependencyPrepFixRecords(bad, 2)).toBeUndefined();
    }
    expect(parseDependencyPrepProbeRecords("RUNFREE_DEP_PREP 0 probe=ok\nRUNFREE_DEP_PREP 1 probe=ok\n", 2)).toBe(true);
    expect(parseDependencyPrepProbeRecords("RUNFREE_DEP_PREP 0 probe=ok\n", 2)).toBe(false);
    expect(parseDependencyPrepProbeRecords("RUNFREE_DEP_PREP 1 probe=ok\nRUNFREE_DEP_PREP 0 probe=ok\n", 2)).toBe(false);
  });

  test("the write probe is no-clobber and both scripts stay index-keyed", () => {
    const fix = dependencyPrepFixScript(2);
    expect(fix).toContain("runfree_check 0 /mnt/runfree-dep-prep/0");
    expect(fix).toContain("runfree_check 1 /mnt/runfree-dep-prep/1");
    expect(fix).toContain("mountpoint -q");
    expect(fix).toContain("stat -c '%u:%g'");
    const probe = dependencyPrepProbeScript(2, ".runfree-write-test-123");
    // `set -C` (O_EXCL) is the cross-volume symlink guard: a pre-planted entry
    // at the predictable probe filename fails the probe instead of following.
    expect(probe).toContain("set -C");
    expect(probe).toContain("runfree_probe 0 /mnt/runfree-dep-prep/0/.runfree-write-test-123");
    expect(probe).toContain("runfree_probe 1 /mnt/runfree-dep-prep/1/.runfree-write-test-123");
    expect(() => dependencyPrepProbeScript(1, "evil/../name")).toThrow("probe file name is invalid");
    expect(() => dependencyPrepFixScript(0)).toThrow("at least one volume");
  });

  test("fails closed when no selected agent image is available", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });

    const io = {
      capture: () => {
        throw new Error("no docker invocation may happen without an image");
      },
    } as unknown as import("./types.ts").RuntimeIO;
    const docker = {
      runningServiceContainerId: () => undefined,
      serviceContainerId: () => undefined,
    } as unknown as import("./docker.ts").RuntimeDocker;
    const context = {
      projectRoot: tmp,
      env: {},
      dependencyOverlayPlan: plan,
      gitLayoutPlan: { containerProjectRoot: "/workspaces/project" },
      project: { config: { agents: { default: "claude" } } },
    } as unknown as import("./types.ts").RuntimeContext;

    expect(ensureDependencyVolumeOwnership(context, io, docker)).toBe(1);
  });
});

describe("ensureComposeManagedSessionVolumes", () => {
  test("creates the always-mounted command-history volume even with overlays off", () => {
    const created: Array<[string, string]> = [];
    const docker = {
      createComposeManagedVolume: (project: string, logical: string) => {
        created.push([project, logical]);
        return 0;
      },
    } as unknown as import("./docker.ts").RuntimeDocker;
    const context = {
      projectRoot: tmp,
      env: {},
      dependencyOverlayPlan: { mode: "off" },
    } as unknown as import("./types.ts").RuntimeContext;

    expect(ensureComposeManagedSessionVolumes(context, docker)).toBe(0);
    expect(created).toEqual([[composeProjectName(tmp), "runfree-commandhistory"]]);
  });

  test("also creates every dependency-overlay volume when overlays are active", () => {
    writeJson("package.json", { packageManager: "npm@10.0.0" });
    fs.writeFileSync(path.join(tmp, "package-lock.json"), "{}\n");
    fs.mkdirSync(path.join(tmp, "node_modules"), { recursive: true });
    const plan = createDependencyOverlayPlan(tmp, { mode: "auto" });
    expect(plan.overlays.length).toBeGreaterThan(0);

    const created: string[] = [];
    const docker = {
      createComposeManagedVolume: (_project: string, logical: string) => {
        created.push(logical);
        return 0;
      },
    } as unknown as import("./docker.ts").RuntimeDocker;
    const context = {
      projectRoot: tmp,
      env: {},
      dependencyOverlayPlan: plan,
      gitLayoutPlan: { containerProjectRoot: "/workspaces/project" },
    } as unknown as import("./types.ts").RuntimeContext;

    expect(ensureComposeManagedSessionVolumes(context, docker)).toBe(0);
    expect(created).toContain("runfree-commandhistory");
    for (const overlay of plan.overlays) expect(created).toContain(overlay.volume);
  });

  test("fails closed when a session volume cannot be created", () => {
    const docker = {
      createComposeManagedVolume: () => 1,
    } as unknown as import("./docker.ts").RuntimeDocker;
    const context = {
      projectRoot: tmp,
      env: {},
      dependencyOverlayPlan: { mode: "off" },
    } as unknown as import("./types.ts").RuntimeContext;

    expect(ensureComposeManagedSessionVolumes(context, docker)).toBe(1);
  });
});

test("deps install is refused with a supported message in the per-session runtime", async () => {
  // Post-cutover there is no shared agent to exec the package manager in; the
  // command must fail deliberately with a workaround, not deep in exec-target
  // resolution. (A per-session deps install is tracked follow-up work.)
  await expect(depsRuntime(
    { kind: "install" },
    {} as unknown as import("./types.ts").RuntimeContext,
    {} as unknown as import("./types.ts").RuntimeIO,
    { docker: {} as unknown as import("./docker.ts").RuntimeDocker },
    (async () => ({ status: 0 })) as never,
  )).rejects.toThrow("`runfree deps install` is not yet available in the per-session runtime");
});
