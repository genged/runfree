import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export type AgentToolId = "claude" | "codex" | "pi";

type AgentToolDefinition = {
  id: AgentToolId;
  displayName: string;
  packageName: string;
};

export const AGENT_TOOL_PACKAGES: readonly AgentToolDefinition[] = [
  { id: "claude", displayName: "Claude Code", packageName: "@anthropic-ai/claude-code" },
  { id: "codex", displayName: "Codex", packageName: "@openai/codex" },
  { id: "pi", displayName: "Pi", packageName: "@earendil-works/pi-coding-agent" },
] as const;

const EXACT_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const agentToolsDir = path.join(repoRoot, "packages", "agent-runtime", "agent", "agent-tools");
const agentToolsPackageJsonPath = path.join(agentToolsDir, "package.json");
const agentToolsPackageLockPath = path.join(agentToolsDir, "package-lock.json");

export type AgentToolUpdateOptions = {
  dryRun: boolean;
  rebuildAssets: boolean;
  requests: string[];
  showHelp: boolean;
};

export type AgentToolPackageSpec = {
  id: AgentToolId;
  displayName: string;
  packageName: string;
  requestedVersion: string;
  npmSpec: string;
};

type AgentToolVersions = Record<AgentToolId, string>;

type PackageJson = {
  dependencies?: Record<string, string>;
};

type PackageLock = {
  packages?: Record<string, { dependencies?: Record<string, string>; version?: string }>;
};

function usage(): string {
  return `Usage: pnpm run update:agent-tools -- [options] [all|claude|codex|pi|<tool>@<version> ...]

Updates the embedded Runfree agent CLI package pins in:
  packages/agent-runtime/agent/agent-tools/package.json
  packages/agent-runtime/agent/agent-tools/package-lock.json

With no package arguments, updates all bundled coding agents to npm latest.

Options:
  --no-assets     Only update package.json/package-lock.json; skip runtime asset rebuild
  --dry-run       Print the npm specs and follow-up steps without mutating files
  -h, --help      Show this help

Examples:
  pnpm run update:agent-tools
  pnpm run update:agent-tools -- pi@0.78.0
  pnpm run update:agent-tools -- claude@2.1.171 codex@0.139.0 --no-assets
`;
}

export function parseAgentToolUpdateArgs(argv: string[]): AgentToolUpdateOptions {
  const options: AgentToolUpdateOptions = {
    dryRun: false,
    rebuildAssets: true,
    requests: [],
    showHelp: false,
  };

  for (const arg of argv) {
    if (arg === "--") {
      continue;
    }
    if (arg === "--dry-run") {
      options.dryRun = true;
      continue;
    }
    if (arg === "--no-assets") {
      options.rebuildAssets = false;
      continue;
    }
    if (arg === "--assets") {
      options.rebuildAssets = true;
      continue;
    }
    if (arg === "--all") {
      options.requests.push("all");
      continue;
    }
    if (arg === "-h" || arg === "--help") {
      options.showHelp = true;
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`unknown option: ${arg}`);
    }
    options.requests.push(arg);
  }

  if (options.requests.length === 0) options.requests.push("all");
  return options;
}

function splitNameAndVersion(value: string): { name: string; version: string | undefined } {
  if (value.trim() === "") throw new Error("empty agent tool spec");
  if (value.startsWith("@")) {
    const versionSeparator = value.lastIndexOf("@");
    if (versionSeparator > 0) {
      const name = value.slice(0, versionSeparator);
      const version = value.slice(versionSeparator + 1);
      if (version === "") throw new Error(`missing version in agent tool spec: ${value}`);
      return { name, version };
    }
    return { name: value, version: undefined };
  }

  const versionSeparator = value.indexOf("@");
  if (versionSeparator === -1) return { name: value, version: undefined };
  const name = value.slice(0, versionSeparator);
  const version = value.slice(versionSeparator + 1);
  if (name === "" || version === "") throw new Error(`invalid agent tool spec: ${value}`);
  return { name, version };
}

function toolByName(name: string): AgentToolDefinition | undefined {
  return AGENT_TOOL_PACKAGES.find((tool) => tool.id === name || tool.packageName === name);
}

export function agentToolPackageSpecs(requests: string[]): AgentToolPackageSpec[] {
  const selected = new Map<AgentToolId, string>();

  for (const request of requests) {
    const { name, version } = splitNameAndVersion(request);
    if (name === "all") {
      for (const tool of AGENT_TOOL_PACKAGES) selected.set(tool.id, "latest");
      continue;
    }

    const tool = toolByName(name);
    if (!tool) {
      const known = AGENT_TOOL_PACKAGES.flatMap((entry) => [entry.id, entry.packageName]).join(", ");
      throw new Error(`unknown agent tool: ${name}; expected one of ${known}`);
    }
    selected.set(tool.id, version ?? "latest");
  }

  return AGENT_TOOL_PACKAGES
    .filter((tool) => selected.has(tool.id))
    .map((tool) => {
      const requestedVersion = selected.get(tool.id) as string;
      return {
        id: tool.id,
        displayName: tool.displayName,
        packageName: tool.packageName,
        requestedVersion,
        npmSpec: `${tool.packageName}@${requestedVersion}`,
      };
    });
}

function readJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

function exactDependencyVersion(packageJson: PackageJson, packageName: string): string {
  const version = packageJson.dependencies?.[packageName];
  if (!version) throw new Error(`agent-tools package.json missing dependency ${packageName}`);
  if (!EXACT_VERSION_PATTERN.test(version)) {
    throw new Error(`agent-tools dependency ${packageName} must be an exact resolved version, got ${version}`);
  }
  return version;
}

export function readAgentToolVersions(packageJsonPath = agentToolsPackageJsonPath): AgentToolVersions {
  const packageJson = readJson<PackageJson>(packageJsonPath);
  return Object.fromEntries(
    AGENT_TOOL_PACKAGES.map((tool) => [tool.id, exactDependencyVersion(packageJson, tool.packageName)]),
  ) as AgentToolVersions;
}

export function assertAgentToolsPackageLockConsistency(
  packageJson: PackageJson,
  packageLock: PackageLock,
  tools: readonly AgentToolDefinition[] = AGENT_TOOL_PACKAGES,
): void {
  const packages = packageLock.packages;
  if (!packages) throw new Error("agent-tools package-lock.json missing packages");
  const rootDependencies = packages[""]?.dependencies;
  if (!rootDependencies) throw new Error("agent-tools package-lock.json missing root dependencies");

  for (const tool of tools) {
    const expectedVersion = exactDependencyVersion(packageJson, tool.packageName);
    if (rootDependencies[tool.packageName] !== expectedVersion) {
      throw new Error(
        `agent-tools package-lock root dependency ${tool.packageName} must match package.json (${expectedVersion})`,
      );
    }
    const locked = packages[`node_modules/${tool.packageName}`];
    if (!locked) throw new Error(`agent-tools package-lock missing node_modules/${tool.packageName}`);
    if (locked.version !== expectedVersion) {
      throw new Error(`agent-tools package-lock ${tool.packageName} must lock ${expectedVersion}, got ${locked.version}`);
    }
  }
}

function verifyAgentToolsLockfiles(): void {
  const packageJson = readJson<PackageJson>(agentToolsPackageJsonPath);
  const packageLock = readJson<PackageLock>(agentToolsPackageLockPath);
  assertAgentToolsPackageLockConsistency(packageJson, packageLock);
}

function run(command: string, args: string[], options: { cwd: string }): void {
  const result = childProcess.spawnSync(command, args, {
    cwd: options.cwd,
    stdio: "inherit",
    env: { ...process.env, npm_config_save_exact: "true" },
  });
  if (result.error) throw result.error;
  if ((result.status ?? 1) !== 0) {
    throw new Error(`command failed: ${command} ${args.join(" ")}`);
  }
}

function runNpmUpdate(specs: AgentToolPackageSpec[]): void {
  run("npm", [
    "install",
    "--package-lock-only",
    "--save-exact",
    "--ignore-scripts",
    "--fund=false",
    "--audit=false",
    ...specs.map((spec) => spec.npmSpec),
  ], { cwd: agentToolsDir });
}

function rebuildRuntimeAssets(): void {
  run("pnpm", ["run", "build:runtime"], { cwd: repoRoot });
  run("pnpm", ["run", "generate:assets"], { cwd: repoRoot });
}

function printPlan(specs: AgentToolPackageSpec[], options: AgentToolUpdateOptions): void {
  console.log(`agent tools: ${path.relative(repoRoot, agentToolsDir)}`);
  console.log(`npm specs: ${specs.map((spec) => spec.npmSpec).join(" ")}`);
  console.log(`runtime assets: ${options.rebuildAssets ? "rebuild and regenerate" : "skipped (--no-assets)"}`);
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const options = parseAgentToolUpdateArgs(argv);
  if (options.showHelp) {
    process.stdout.write(usage());
    return;
  }

  const specs = agentToolPackageSpecs(options.requests);
  if (specs.length === 0) throw new Error("no agent tools selected");
  printPlan(specs, options);

  if (options.dryRun) return;

  const before = readAgentToolVersions();
  runNpmUpdate(specs);
  verifyAgentToolsLockfiles();
  const after = readAgentToolVersions();

  console.log("agent tool versions:");
  for (const tool of AGENT_TOOL_PACKAGES) {
    const marker = before[tool.id] === after[tool.id] ? "=" : "→";
    console.log(`  ${tool.id}: ${before[tool.id]} ${marker} ${after[tool.id]}`);
  }

  if (options.rebuildAssets) rebuildRuntimeAssets();
  console.log("done");
  if (!options.rebuildAssets) {
    console.log("next: pnpm run build:runtime && pnpm run generate:assets");
  }
}

function isDirectEntrypoint(metaUrl: string, argvPath: string | undefined): boolean {
  return argvPath !== undefined && metaUrl === pathToFileURL(argvPath).href;
}

if (isDirectEntrypoint(import.meta.url, process.argv[1])) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
