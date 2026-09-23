import { describe, expect, test } from "vitest";

import {
  DEPENDENCY_STORE_DEFINITIONS,
  dependencyStoreEnvironmentNames,
  dependencyStoreTargets,
  dependencyStoreVolumes,
  RUNTIME_TOOL_STORE_DEFINITIONS,
  runtimeToolStoreEnvironmentNames,
  runtimeToolStoreTargets,
  runtimeToolStoreVolumes,
} from "./dependency-stores.ts";

describe("dependency store definitions", () => {
  test("own JavaScript package-manager store targets, env names, and volume suffixes", () => {
    expect(DEPENDENCY_STORE_DEFINITIONS).toEqual({
      pnpm: {
        ecosystem: "javascript",
        volumeSuffix: "pnpm-store",
        target: "/home/agent/.local/share/pnpm/store",
        environment: { NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store" },
      },
      npm: {
        ecosystem: "javascript",
        volumeSuffix: "npm-cache",
        target: "/home/agent/.npm",
        environment: { NPM_CONFIG_CACHE: "/home/agent/.npm" },
      },
      yarn: {
        ecosystem: "javascript",
        volumeSuffix: "yarn-cache",
        target: "/home/agent/.cache/yarn",
        environment: { YARN_CACHE_FOLDER: "/home/agent/.cache/yarn" },
      },
      bun: {
        ecosystem: "javascript",
        volumeSuffix: "bun-cache",
        target: "/home/agent/.bun/install/cache",
        environment: { BUN_INSTALL_CACHE_DIR: "/home/agent/.bun/install/cache" },
      },
    });
  });

  test("owns JavaScript and Python runtime tool store targets, env names, and volume suffixes", () => {
    expect(RUNTIME_TOOL_STORE_DEFINITIONS).toEqual({
      ...DEPENDENCY_STORE_DEFINITIONS,
      pip: {
        ecosystem: "python",
        volumeSuffix: "pip-cache",
        target: "/home/agent/.cache/pip",
        environment: { PIP_CACHE_DIR: "/home/agent/.cache/pip" },
      },
      uv: {
        ecosystem: "python",
        volumeSuffix: "uv-cache",
        target: "/home/agent/.cache/uv",
        environment: { UV_CACHE_DIR: "/home/agent/.cache/uv" },
      },
      poetry: {
        ecosystem: "python",
        volumeSuffix: "poetry-cache",
        target: "/home/agent/.cache/pypoetry",
        environment: {
          POETRY_CACHE_DIR: "/home/agent/.cache/pypoetry",
          POETRY_VIRTUALENVS_IN_PROJECT: "true",
        },
      },
      pipenv: {
        ecosystem: "python",
        volumeSuffix: "pipenv-cache",
        target: "/home/agent/.cache/pipenv",
        environment: {
          PIPENV_CACHE_DIR: "/home/agent/.cache/pipenv",
          PIPENV_VENV_IN_PROJECT: "1",
        },
      },
      pdm: {
        ecosystem: "python",
        volumeSuffix: "pdm-cache",
        target: "/home/agent/.cache/pdm",
        environment: {
          PDM_CACHE_DIR: "/home/agent/.cache/pdm",
          PDM_USE_VENV: "true",
        },
      },
      "hatch-cache": {
        ecosystem: "python",
        volumeSuffix: "hatch-cache",
        target: "/home/agent/.cache/hatch",
        environment: { HATCH_CACHE_DIR: "/home/agent/.cache/hatch" },
      },
      "hatch-data": {
        ecosystem: "python",
        volumeSuffix: "hatch-data",
        target: "/home/agent/.local/share/hatch",
        environment: { HATCH_DATA_DIR: "/home/agent/.local/share/hatch" },
      },
    });

    expect(new Set(runtimeToolStoreTargets()).size).toBe(runtimeToolStoreTargets().length);
    expect(new Set(runtimeToolStoreEnvironmentNames()).size).toBe(runtimeToolStoreEnvironmentNames().length);
    expect(new Set(Object.values(RUNTIME_TOOL_STORE_DEFINITIONS).map((definition) => definition.volumeSuffix)).size)
      .toBe(Object.keys(RUNTIME_TOOL_STORE_DEFINITIONS).length);

    expect(dependencyStoreTargets()).toEqual([
      "/home/agent/.local/share/pnpm/store",
      "/home/agent/.npm",
      "/home/agent/.cache/yarn",
      "/home/agent/.bun/install/cache",
      "/home/agent/.cache/pip",
      "/home/agent/.cache/uv",
      "/home/agent/.cache/pypoetry",
      "/home/agent/.cache/pipenv",
      "/home/agent/.cache/pdm",
      "/home/agent/.cache/hatch",
      "/home/agent/.local/share/hatch",
    ]);
    expect(dependencyStoreEnvironmentNames()).toEqual([
      "NPM_CONFIG_STORE_DIR",
      "NPM_CONFIG_CACHE",
      "YARN_CACHE_FOLDER",
      "BUN_INSTALL_CACHE_DIR",
      "PIP_CACHE_DIR",
      "UV_CACHE_DIR",
      "POETRY_CACHE_DIR",
      "POETRY_VIRTUALENVS_IN_PROJECT",
      "PIPENV_CACHE_DIR",
      "PIPENV_VENV_IN_PROJECT",
      "PDM_CACHE_DIR",
      "PDM_USE_VENV",
      "HATCH_CACHE_DIR",
      "HATCH_DATA_DIR",
    ]);
    expect(runtimeToolStoreTargets()).toEqual(dependencyStoreTargets());
    expect(runtimeToolStoreEnvironmentNames()).toEqual(dependencyStoreEnvironmentNames());
  });

  test("derives stable Docker volumes from selected package managers", () => {
    expect(dependencyStoreVolumes("abc123abc123", ["pnpm", "bun"])).toEqual([
      {
        ecosystem: "javascript",
        packageManager: "pnpm",
        storeName: "pnpm",
        volume: "runfree-deps-abc123abc123-pnpm-store",
        target: "/home/agent/.local/share/pnpm/store",
        environment: { NPM_CONFIG_STORE_DIR: "/home/agent/.local/share/pnpm/store" },
      },
      {
        ecosystem: "javascript",
        packageManager: "bun",
        storeName: "bun",
        volume: "runfree-deps-abc123abc123-bun-cache",
        target: "/home/agent/.bun/install/cache",
        environment: { BUN_INSTALL_CACHE_DIR: "/home/agent/.bun/install/cache" },
      },
    ]);
  });

  test("derives stable Docker volumes from selected Python stores", () => {
    expect(runtimeToolStoreVolumes("abc123abc123", ["pip", "uv", "hatch-cache", "hatch-data"])).toEqual([
      {
        ecosystem: "python",
        storeName: "pip",
        volume: "runfree-deps-abc123abc123-pip-cache",
        target: "/home/agent/.cache/pip",
        environment: { PIP_CACHE_DIR: "/home/agent/.cache/pip" },
      },
      {
        ecosystem: "python",
        storeName: "uv",
        volume: "runfree-deps-abc123abc123-uv-cache",
        target: "/home/agent/.cache/uv",
        environment: { UV_CACHE_DIR: "/home/agent/.cache/uv" },
      },
      {
        ecosystem: "python",
        storeName: "hatch-cache",
        volume: "runfree-deps-abc123abc123-hatch-cache",
        target: "/home/agent/.cache/hatch",
        environment: { HATCH_CACHE_DIR: "/home/agent/.cache/hatch" },
      },
      {
        ecosystem: "python",
        storeName: "hatch-data",
        volume: "runfree-deps-abc123abc123-hatch-data",
        target: "/home/agent/.local/share/hatch",
        environment: { HATCH_DATA_DIR: "/home/agent/.local/share/hatch" },
      },
    ]);
  });
});
