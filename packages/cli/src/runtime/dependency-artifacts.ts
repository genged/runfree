import path from "node:path";

export type DependencyArtifactKind =
  | "node_modules"
  | "pnpm-store"
  | "yarn-unplugged"
  | "bun"
  | "python-venv"
  | "python-pypackages";

type DependencyArtifactDefinition = {
  kind: DependencyArtifactKind;
  matchesRelativePath(relativePath: string): boolean;
  matchesPathSuffix(pathValue: string): boolean;
};

function normalizeArtifactPath(value: string): string {
  const withoutNul = value.replace(/\0/g, "");
  const normalized = path.posix.normalize(withoutNul.replaceAll("\\", "/").replace(/\/+$/g, ""));
  return normalized === "" ? "." : normalized;
}

function pathSegments(pathValue: string): string[] {
  const normalized = normalizeArtifactPath(pathValue);
  return normalized === "." ? [] : normalized.split("/");
}

function pathBasename(pathValue: string): string {
  return pathSegments(pathValue).at(-1) ?? "";
}

function pathHasSuffix(pathValue: string, suffix: string): boolean {
  const normalized = normalizeArtifactPath(pathValue);
  const normalizedSuffix = normalizeArtifactPath(suffix);
  return normalized === normalizedSuffix || normalized.endsWith(`/${normalizedSuffix}`);
}

const DEPENDENCY_ARTIFACTS: DependencyArtifactDefinition[] = [
  {
    kind: "node_modules",
    matchesRelativePath: (relativePath) => pathBasename(relativePath) === "node_modules",
    matchesPathSuffix: (pathValue) => pathBasename(pathValue) === "node_modules",
  },
  {
    kind: "pnpm-store",
    matchesRelativePath: (relativePath) => normalizeArtifactPath(relativePath) === ".pnpm-store",
    matchesPathSuffix: (pathValue) => pathBasename(pathValue) === ".pnpm-store",
  },
  {
    kind: "yarn-unplugged",
    matchesRelativePath: (relativePath) => pathHasSuffix(relativePath, ".yarn/unplugged"),
    matchesPathSuffix: (pathValue) => pathHasSuffix(pathValue, ".yarn/unplugged"),
  },
  {
    kind: "bun",
    matchesRelativePath: (relativePath) => normalizeArtifactPath(relativePath) === ".bun",
    matchesPathSuffix: (pathValue) => pathBasename(pathValue) === ".bun",
  },
  {
    kind: "python-venv",
    matchesRelativePath: (relativePath) => {
      const basename = pathBasename(relativePath);
      return basename === ".venv" || basename === "venv";
    },
    matchesPathSuffix: (pathValue) => {
      const basename = pathBasename(pathValue);
      return basename === ".venv" || basename === "venv";
    },
  },
  {
    kind: "python-pypackages",
    matchesRelativePath: (relativePath) => pathBasename(relativePath) === "__pypackages__",
    matchesPathSuffix: (pathValue) => pathBasename(pathValue) === "__pypackages__",
  },
];

export function dependencyArtifactKindForRelativePath(relativePath: string): DependencyArtifactKind | undefined {
  return DEPENDENCY_ARTIFACTS.find((artifact) => artifact.matchesRelativePath(relativePath))?.kind;
}

export function dependencyArtifactKindForPathSuffix(pathValue: string): DependencyArtifactKind | undefined {
  return DEPENDENCY_ARTIFACTS.find((artifact) => artifact.matchesPathSuffix(pathValue))?.kind;
}
