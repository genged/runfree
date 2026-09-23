export type DependencyEcosystem = "javascript" | "python";

export type JavaScriptPackageManagerName = "pnpm" | "npm" | "yarn" | "bun";

export type PythonPackageManagerName = "pip" | "uv" | "poetry" | "pipenv" | "pdm" | "hatch";

export type DependencyToolName = JavaScriptPackageManagerName | PythonPackageManagerName;

export type RuntimeToolStoreName =
  | JavaScriptPackageManagerName
  | "pip"
  | "uv"
  | "poetry"
  | "pipenv"
  | "pdm"
  | "hatch-cache"
  | "hatch-data";

export type RuntimeToolStoreDefinition = {
  ecosystem: DependencyEcosystem;
  volumeSuffix: string;
  target: string;
  environment: Record<string, string>;
};

export type DependencyStoreDefinition = RuntimeToolStoreDefinition;

export type RuntimeToolStoreVolume = {
  ecosystem: DependencyEcosystem;
  storeName: RuntimeToolStoreName;
  packageManager?: JavaScriptPackageManagerName;
  volume: string;
  target: string;
  environment: Record<string, string>;
};

export type DependencyStoreVolume = RuntimeToolStoreVolume;

export const DEPENDENCY_STORE_DEFINITIONS = {
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
} as const satisfies Record<JavaScriptPackageManagerName, RuntimeToolStoreDefinition>;

export const RUNTIME_TOOL_STORE_DEFINITIONS = {
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
} as const satisfies Record<RuntimeToolStoreName, RuntimeToolStoreDefinition>;

export function runtimeToolStoreTargets(): string[] {
  return Object.values(RUNTIME_TOOL_STORE_DEFINITIONS).map((definition) => definition.target);
}

export function runtimeToolStoreEnvironmentNames(): string[] {
  return Object.values(RUNTIME_TOOL_STORE_DEFINITIONS).flatMap((definition) => Object.keys(definition.environment));
}

export function runtimeToolStoreVolumes(
  workspaceHash: string,
  storeNames: readonly RuntimeToolStoreName[],
): RuntimeToolStoreVolume[] {
  return storeNames.map((storeName) => {
    const definition = RUNTIME_TOOL_STORE_DEFINITIONS[storeName];
    return {
      ecosystem: definition.ecosystem,
      storeName,
      ...(definition.ecosystem === "javascript" ? { packageManager: storeName as JavaScriptPackageManagerName } : {}),
      volume: `runfree-deps-${workspaceHash}-${definition.volumeSuffix}`,
      target: definition.target,
      environment: { ...definition.environment },
    };
  });
}

export function dependencyStoreTargets(): string[] {
  return runtimeToolStoreTargets();
}

export function dependencyStoreEnvironmentNames(): string[] {
  return runtimeToolStoreEnvironmentNames();
}

export function dependencyStoreVolumes(
  workspaceHash: string,
  packageManagers: readonly JavaScriptPackageManagerName[],
): DependencyStoreVolume[] {
  return runtimeToolStoreVolumes(workspaceHash, packageManagers);
}
