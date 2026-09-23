import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  RUNTIME_INPUT_BUILD_ARGUMENTS,
  RUNTIME_INPUT_FILE_REFERENCES,
  type RuntimeImageComponent,
} from "../packages/cli/src/runtime-inputs.ts";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const outputRoot = path.join(repoRoot, "dist", "runtime");
const buildOutputs = [
  path.join(repoRoot, "packages", "runtime-contracts", "dist"),
  path.join(repoRoot, "packages", "runtime-contracts", "tsconfig.tsbuildinfo"),
  path.join(repoRoot, "packages", "proxy", "dist"),
  path.join(repoRoot, "packages", "proxy", "tsconfig.tsbuildinfo"),
  path.join(repoRoot, "packages", "agent-runtime", "dist"),
  path.join(repoRoot, "packages", "agent-runtime", "tsconfig.tsbuildinfo"),
];
// The agent image's readiness probe: TypeScript under `packages/agent-runtime/src`,
// compiled by the same `tsc -b` step as the proxy and shipped as CommonJS next
// to the shell entry it serves. The Dockerfile installs it extensionless.
const AGENT_PROBE_OUTPUT = path.join(repoRoot, "packages", "agent-runtime", "dist", "session-ready-probe.cjs");

export const RUNTIME_ASSET_ROLES = [
  "agent-image",
  "proxy-image",
  "compose-template",
  "host-helper",
  "project-template",
  "runtime-input-source",
] as const;

export type RuntimeAssetRole = typeof RUNTIME_ASSET_ROLES[number];
// `executable` is the only mode dimension a runtime asset may declare. Modes are
// declared here rather than inherited from the build machine so that the
// generated tree — and the component input digests taken over it — stay a pure
// function of this repository. Inheriting a source or freshly-created file's
// mode makes the build depend on the ambient umask: under `umask 077` every
// `tsc`-emitted proxy file lands at 0600, which changes the embedded manifest.
export type RuntimeAssetDescriptor = Readonly<{
  path: string;
  roles: readonly RuntimeAssetRole[];
  executable?: true;
}>;

export const RUNTIME_ASSET_REGULAR_MODE = 0o644;
export const RUNTIME_ASSET_EXECUTABLE_MODE = 0o755;

const agentImage = (assetPath: string): RuntimeAssetDescriptor => ({ path: assetPath, roles: ["agent-image"] });
const proxyImage = (assetPath: string): RuntimeAssetDescriptor => ({ path: assetPath, roles: ["proxy-image"] });

export const RUNTIME_ASSET_DESCRIPTORS: readonly RuntimeAssetDescriptor[] = [
  agentImage("agent/Dockerfile"),
  agentImage("agent/claude-runfree.sh"),
  agentImage("agent/session-entry.sh"),
  agentImage("agent/session-ready-probe.cjs"),
  agentImage("agent/agent-tools/package-lock.json"),
  agentImage("agent/agent-tools/package.json"),
  { path: "agent/compose.yaml", roles: ["compose-template"] as const },
  // Executed directly from host state, so it is the one asset that ships with
  // the execute bit. The agent image chmods its own copied scripts to 0755.
  { path: "agent/inspect-active-sessions.sh", roles: ["host-helper"] as const, executable: true as const },
  proxyImage("proxy/Dockerfile"),
  proxyImage("proxy/admission.js"),
  proxyImage("proxy/approvals.js"),
  proxyImage("proxy/audit.js"),
  proxyImage("proxy/contracts/desired-network-policy.js"),
  proxyImage("proxy/contracts/effective-control.js"),
  proxyImage("proxy/contracts/mcp-operation-policy.js"),
  proxyImage("proxy/contracts/network-policy.js"),
  proxyImage("proxy/contracts/oauth-mediation-policy.js"),
  proxyImage("proxy/contracts/primitives.js"),
  proxyImage("proxy/contracts/proxy-status.js"),
  proxyImage("proxy/contracts/session-admission.js"),
  proxyImage("proxy/contracts/session-file.js"),
  proxyImage("proxy/contracts/session-registry.js"),
  proxyImage("proxy/contracts/write-approvals.js"),
  proxyImage("proxy/denial.js"),
  proxyImage("proxy/entrypoint.js"),
  proxyImage("proxy/firewall/command.js"),
  proxyImage("proxy/firewall/dns.js"),
  proxyImage("proxy/firewall/env.js"),
  proxyImage("proxy/firewall/index.js"),
  proxyImage("proxy/firewall/nftables.js"),
  proxyImage("proxy/firewall/route.js"),
  proxyImage("proxy/firewall/supervisor.js"),
  proxyImage("proxy/graphql-classify.js"),
  proxyImage("proxy/mcp-classify.js"),
  proxyImage("proxy/mockttp-adapter.js"),
  proxyImage("proxy/oauth-mediation.js"),
  proxyImage("proxy/package-lock.json"),
  proxyImage("proxy/package.json"),
  proxyImage("proxy/policy.js"),
  proxyImage("proxy/resolved-hosts.js"),
  proxyImage("proxy/server.js"),
  proxyImage("proxy/session-file-registry.js"),
  proxyImage("proxy/session-identity-config.js"),
  proxyImage("proxy/session-file-validity.js"),
  proxyImage("proxy/session-files.js"),
  proxyImage("proxy/session-ip-reuse.js"),
  proxyImage("proxy/status.js"),
  { path: "runtime-inputs.lock.json", roles: ["runtime-input-source"] as const },
  { path: "templates/network-policy.json", roles: ["project-template"] as const },
  { path: "templates/runfree.json", roles: ["project-template"] as const },
].sort((left, right) => left.path.localeCompare(right.path));

export function expectedRuntimeAssetPaths(): string[] {
  return RUNTIME_ASSET_DESCRIPTORS.map(({ path: assetPath }) => assetPath);
}

export function runtimeAssetsForRole(role: RuntimeAssetRole): readonly RuntimeAssetDescriptor[] {
  return RUNTIME_ASSET_DESCRIPTORS.filter(({ roles }) => roles.includes(role));
}

export function assertRuntimeAssetDescriptors(
  descriptors: readonly RuntimeAssetDescriptor[] = RUNTIME_ASSET_DESCRIPTORS,
): void {
  const seen = new Set<string>();
  for (const descriptor of descriptors) {
    const normalized = descriptor.path.replaceAll("\\", "/");
    if (normalized !== descriptor.path || path.posix.normalize(normalized) !== normalized || path.posix.isAbsolute(normalized)) {
      throw new Error(`runtime asset path is not normalized: ${descriptor.path}`);
    }
    if (seen.has(normalized)) throw new Error(`duplicate runtime asset descriptor: ${normalized}`);
    seen.add(normalized);
    if (descriptor.roles.length === 0) throw new Error(`runtime asset has no declared role: ${normalized}`);
    for (const role of descriptor.roles) {
      if (!RUNTIME_ASSET_ROLES.includes(role)) throw new Error(`runtime asset has unknown role ${role}: ${normalized}`);
    }
  }
  for (const reference of RUNTIME_INPUT_FILE_REFERENCES) {
    const descriptor = descriptors.find(({ path: assetPath }) => assetPath === reference.runtimeAssetPath);
    if (!descriptor?.roles.includes(reference.owner)) {
      throw new Error(
        `runtime input ${reference.lockPath} asset lacks ${reference.owner} role: ${reference.runtimeAssetPath}`,
      );
    }
  }
}

export function isGeneratedRuntimeAssetPath(relativePath: string): boolean {
  if (relativePath.split(/[\\/]/).includes("node_modules")) return false;
  return expectedRuntimeAssetPaths().includes(relativePath.replaceAll("\\", "/"));
}

function runtimeAssetDescriptor(relativePath: string): RuntimeAssetDescriptor | undefined {
  const normalized = relativePath.replaceAll("\\", "/");
  return RUNTIME_ASSET_DESCRIPTORS.find(({ path: assetPath }) => assetPath === normalized);
}

/**
 * The declared mode for a generated runtime asset. Total over declared paths and
 * fail-closed for anything else: an undeclared path reaching a writer or the
 * embedded manifest is a build bug, not a file to guess a mode for.
 */
export function runtimeAssetMode(relativePath: string): number {
  const descriptor = runtimeAssetDescriptor(relativePath);
  if (descriptor === undefined) {
    throw new Error(`undeclared runtime asset: ${relativePath.replaceAll("\\", "/")}`);
  }
  return descriptor.executable === true ? RUNTIME_ASSET_EXECUTABLE_MODE : RUNTIME_ASSET_REGULAR_MODE;
}

function logicalDockerfileLines(dockerfile: string): string[] {
  const logical: string[] = [];
  let pending = "";
  for (const rawLine of dockerfile.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (pending === "" && (line === "" || line.startsWith("#"))) continue;
    const continued = line.endsWith("\\");
    const segment = continued ? line.slice(0, -1).trimEnd() : line;
    pending = pending === "" ? segment : `${pending} ${segment}`;
    if (!continued) {
      logical.push(pending);
      pending = "";
    }
  }
  if (pending !== "") throw new Error("unclassifiable Dockerfile trailing continuation");
  return logical;
}

function dockerfileInstruction(line: string): { name: string; value: string } {
  const match = /^([A-Za-z]+)\s+(.+)$/.exec(line);
  if (!match) throw new Error(`unclassifiable Dockerfile instruction: ${line}`);
  return { name: match[1].toUpperCase(), value: match[2].trim() };
}

function shellWords(value: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote !== undefined) {
      if (character === quote) {
        quote = undefined;
      } else if (character === "\\" && quote === '"') {
        index += 1;
        if (index >= value.length) throw new Error(`unclassifiable Dockerfile escape: ${value}`);
        current += value[index];
      } else {
        current += character;
      }
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
    } else if (/\s/.test(character)) {
      if (current !== "") {
        words.push(current);
        current = "";
      }
    } else if (character === "\\") {
      index += 1;
      if (index >= value.length) throw new Error(`unclassifiable Dockerfile escape: ${value}`);
      current += value[index];
    } else {
      current += character;
    }
  }
  if (quote !== undefined) throw new Error(`unclassifiable Dockerfile quote: ${value}`);
  if (current !== "") words.push(current);
  return words;
}

type DockerCopyInstruction = { from?: string; sources: string[] };

function dockerCopyInstruction(value: string): DockerCopyInstruction {
  const options: string[] = [];
  let remainder = value.trim();
  while (remainder.startsWith("--")) {
    const optionMatch = /^(--[^\s]+)\s+/.exec(remainder);
    if (!optionMatch) throw new Error(`unclassifiable Dockerfile COPY/ADD options: ${value}`);
    options.push(optionMatch[1]);
    remainder = remainder.slice(optionMatch[0].length);
  }
  let paths: string[];
  if (remainder.startsWith("[")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(remainder) as unknown;
    } catch {
      throw new Error(`unclassifiable Dockerfile JSON COPY/ADD: ${value}`);
    }
    if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== "string")) {
      throw new Error(`unclassifiable Dockerfile JSON COPY/ADD: ${value}`);
    }
    paths = parsed;
  } else {
    paths = shellWords(remainder);
  }
  if (paths.length < 2) throw new Error(`unclassifiable Dockerfile COPY/ADD paths: ${value}`);
  const fromOptions = options.filter((option) => option.startsWith("--from="));
  if (fromOptions.length > 1) throw new Error(`unclassifiable Dockerfile COPY/ADD stage: ${value}`);
  return {
    from: fromOptions[0]?.slice("--from=".length),
    sources: paths.slice(0, -1),
  };
}

function globPattern(source: string): RegExp {
  if (source.includes("[")) throw new Error(`unclassifiable Dockerfile glob: ${source}`);
  let pattern = "^";
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (character === "*") {
      if (source[index + 1] === "*") {
        pattern += ".*";
        index += 1;
      } else {
        pattern += "[^/]*";
      }
    } else if (character === "?") {
      pattern += "[^/]";
    } else {
      pattern += character.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`${pattern}$`);
}

function expandLocalDockerSource(source: string, contextFiles: readonly string[]): string[] {
  if (source.includes("$") || /^(?:https?|git):\/\//i.test(source)) {
    throw new Error(`unclassifiable external Dockerfile COPY/ADD source: ${source}`);
  }
  const normalized = path.posix.normalize(source.replaceAll("\\", "/")).replace(/^\.\//, "");
  if (normalized === ".." || normalized.startsWith("../") || path.posix.isAbsolute(normalized)) {
    throw new Error(`Dockerfile COPY/ADD source escapes build context: ${source}`);
  }
  const hasGlob = /[*?[]/.test(normalized);
  const matches = hasGlob
    ? contextFiles.filter((candidate) => globPattern(normalized).test(candidate))
    : contextFiles.filter((candidate) => candidate === normalized || candidate.startsWith(`${normalized.replace(/\/$/, "")}/`));
  if (matches.length === 0) throw new Error(`Dockerfile COPY/ADD source has no generated runtime match: ${source}`);
  return matches;
}

export function assertDockerfileBuildArgumentCompleteness(
  dockerfile: string,
  component: RuntimeImageComponent,
): void {
  const declared = new Set<string>();
  const referenced = new Set<string>();
  const stages = new Set<string>();
  const mappings = RUNTIME_INPUT_BUILD_ARGUMENTS.filter(({ owner }) => owner === component || owner === "shared");
  const mappedNames = new Set(mappings.map(({ name }) => name));
  for (const line of logicalDockerfileLines(dockerfile)) {
    const instruction = dockerfileInstruction(line);
    const tokens = instruction.value.match(/RUNFREE_[A-Z0-9_]+/g) ?? [];
    if (instruction.name === "ARG") {
      const name = instruction.value.split("=", 1)[0].trim();
      if (name.startsWith("RUNFREE_")) declared.add(name);
    } else {
      for (const token of tokens) referenced.add(token);
    }
    if (/https?:\/\//i.test(instruction.value)) {
      throw new Error(`${component} Dockerfile has an unlocked external URL: ${instruction.value}`);
    }
    if (instruction.name === "FROM") {
      const words = shellWords(instruction.value);
      const image = words.find((word) => !word.startsWith("--"));
      if (image === undefined) throw new Error(`unclassifiable Dockerfile FROM: ${instruction.value}`);
      const variable = /^\$\{?(RUNFREE_[A-Z0-9_]+)\}?$/.exec(image)?.[1];
      if (image !== "scratch" && !stages.has(image) && (variable === undefined || !mappedNames.has(variable as never))) {
        throw new Error(`${component} Dockerfile FROM bypasses the runtime input mapping: ${image}`);
      }
      const stage = /\s+AS\s+([^\s]+)$/i.exec(instruction.value)?.[1];
      if (stage !== undefined) stages.add(stage);
    }
  }
  const unknown = [...new Set([...declared, ...referenced])]
    .filter((name) => !mappedNames.has(name as never))
    .sort();
  if (unknown.length > 0) {
    throw new Error(`${component} Dockerfile has unmapped RUNFREE_* input: ${unknown.join(", ")}`);
  }
  const undeclared = [...mappedNames].filter((name) => !declared.has(name)).sort();
  if (undeclared.length > 0) {
    throw new Error(`${component} runtime input mapping is undeclared by Dockerfile: ${undeclared.join(", ")}`);
  }
  const unused = [...mappedNames].filter((name) => !referenced.has(name)).sort();
  if (unused.length > 0) {
    throw new Error(`${component} runtime input mapping is unused by Dockerfile: ${unused.join(", ")}`);
  }
}

export function assertDockerfileLocalSourceCompleteness(
  dockerfile: string,
  component: RuntimeImageComponent,
  contextFiles: readonly string[],
): void {
  const stageNames = new Set<string>();
  for (const line of logicalDockerfileLines(dockerfile)) {
    const instruction = dockerfileInstruction(line);
    if (instruction.name === "FROM") {
      const stage = /\s+AS\s+([^\s]+)$/i.exec(instruction.value)?.[1];
      if (stage !== undefined) stageNames.add(stage);
      continue;
    }
    if (instruction.name !== "COPY" && instruction.name !== "ADD") continue;
    const copy = dockerCopyInstruction(instruction.value);
    if (copy.from !== undefined) {
      if (!stageNames.has(copy.from)) {
        throw new Error(`${component} Dockerfile COPY --from is not a declared stage: ${copy.from}`);
      }
      continue;
    }
    for (const source of copy.sources) {
      for (const match of expandLocalDockerSource(source, contextFiles)) {
        const descriptor = runtimeAssetDescriptor(`${component === "agent-image" ? "agent" : "proxy"}/${match}`);
        if (!descriptor?.roles.includes(component)) {
          throw new Error(`${component} Dockerfile COPY/ADD source lacks ${component} role: ${match}`);
        }
      }
    }
  }
}

function cleanGeneratedRuntimeDir(dir: string): void {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name === "node_modules") continue;
    if (entry.isDirectory()) {
      cleanGeneratedRuntimeDir(entryPath);
      continue;
    }
    fs.rmSync(entryPath, { force: true });
  }
}

function listRuntimeFiles(dir: string, runtimeRoot = dir): string[] {
  if (!fs.existsSync(dir)) return [];
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name === "node_modules") continue;
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listRuntimeFiles(entryPath, runtimeRoot));
      continue;
    }
    if (entry.isFile()) files.push(path.relative(runtimeRoot, entryPath).split(path.sep).join("/"));
  }
  return files.sort();
}

export function assertGeneratedRuntimeManifest(runtimeRoot = outputRoot): void {
  assertRuntimeAssetDescriptors();
  const expected = expectedRuntimeAssetPaths();
  const actual = listRuntimeFiles(runtimeRoot);
  const missing = expected.filter((entry) => !actual.includes(entry));
  if (missing.length > 0) throw new Error(`missing generated runtime asset: ${missing.join(", ")}`);
  const unexpected = actual.filter((entry) => !isGeneratedRuntimeAssetPath(entry));
  if (unexpected.length > 0) throw new Error(`unexpected generated runtime asset: ${unexpected.join(", ")}`);
  // `dist/runtime` is both the local Docker build context and the source the
  // embedded manifest is generated from, so a mode that drifts from the
  // declaration would ship. Report every drifted path rather than the first.
  const drifted = expected
    .map((entry) => ({
      entry,
      actual: fs.statSync(path.join(runtimeRoot, entry)).mode & 0o777,
      declared: runtimeAssetMode(entry),
    }))
    .filter(({ actual: actualMode, declared }) => actualMode !== declared)
    .map(({ entry, actual: actualMode, declared }) => `${entry} is ${actualMode.toString(8)}, declared ${declared.toString(8)}`);
  if (drifted.length > 0) {
    throw new Error(
      `generated runtime asset mode does not match its declaration (rerun \`pnpm run build:runtime\`): ${drifted.join("; ")}`,
    );
  }
  for (const component of ["agent-image", "proxy-image"] as const) {
    const contextDirectory = component === "agent-image" ? "agent" : "proxy";
    const contextFiles = actual
      .filter((entry) => entry.startsWith(`${contextDirectory}/`))
      .map((entry) => entry.slice(contextDirectory.length + 1));
    const dockerfile = fs.readFileSync(path.join(runtimeRoot, contextDirectory, "Dockerfile"), "utf8");
    assertDockerfileBuildArgumentCompleteness(dockerfile, component);
    assertDockerfileLocalSourceCompleteness(dockerfile, component, contextFiles);
  }
}

function cleanPackageBuildOutputs(): void {
  for (const output of buildOutputs) {
    fs.rmSync(output, { recursive: true, force: true });
  }
}

function compileRuntimePackages(): void {
  const result = childProcess.spawnSync("pnpm", [
    "exec",
    "tsc",
    "-b",
    "packages/runtime-contracts",
    "packages/proxy",
    "packages/agent-runtime",
  ], {
    cwd: repoRoot,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if ((result.status ?? 1) !== 0) {
    throw new Error("runtime package compilation failed");
  }
}

/**
 * The only writer into the generated runtime tree. It resolves the destination
 * against the declared asset set and chmods to the declared mode, so neither the
 * source file's mode nor the ambient umask can reach `dist/runtime`.
 */
function writeRuntimeAsset(destination: string, contents: Buffer | string): void {
  const relativePath = path.relative(outputRoot, destination).split(path.sep).join("/");
  const mode = runtimeAssetMode(relativePath);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, contents);
  fs.chmodSync(destination, mode);
}

function copyFile(source: string, destination: string): void {
  writeRuntimeAsset(destination, fs.readFileSync(source));
}

function copyTree(source: string, destination: string, options: {
  include?: (sourcePath: string) => boolean;
  rewriteJs?: boolean;
} = {}): void {
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".tsbuildinfo") continue;
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (entry.isDirectory()) {
      copyTree(sourcePath, destinationPath, options);
      continue;
    }
    if (!entry.isFile()) continue;
    if (options.include && !options.include(sourcePath)) continue;
    copyFile(sourcePath, destinationPath);
    if (options.rewriteJs && destinationPath.endsWith(".js")) {
      rewriteRuntimeContractImports(destinationPath);
    }
  }
}

function rewriteRuntimeContractImports(filePath: string): void {
  const replacements = new Map([
    ["@runfree/runtime-contracts/effective-control", path.join(outputRoot, "proxy", "contracts", "effective-control.js")],
    ["@runfree/runtime-contracts/network-policy", path.join(outputRoot, "proxy", "contracts", "network-policy.js")],
    ["@runfree/runtime-contracts/mcp-operation-policy", path.join(outputRoot, "proxy", "contracts", "mcp-operation-policy.js")],
    ["@runfree/runtime-contracts/oauth-mediation-policy", path.join(outputRoot, "proxy", "contracts", "oauth-mediation-policy.js")],
    ["@runfree/runtime-contracts/primitives", path.join(outputRoot, "proxy", "contracts", "primitives.js")],
    ["@runfree/runtime-contracts/proxy-status", path.join(outputRoot, "proxy", "contracts", "proxy-status.js")],
    ["@runfree/runtime-contracts/session-admission", path.join(outputRoot, "proxy", "contracts", "session-admission.js")],
    ["@runfree/runtime-contracts/session-file", path.join(outputRoot, "proxy", "contracts", "session-file.js")],
    ["@runfree/runtime-contracts/session-registry", path.join(outputRoot, "proxy", "contracts", "session-registry.js")],
    ["@runfree/runtime-contracts/write-approvals", path.join(outputRoot, "proxy", "contracts", "write-approvals.js")],
  ]);
  const source = fs.readFileSync(filePath, "utf8");
  let rewritten = source;
  for (const [specifier, contractPath] of replacements) {
    let relative = path.relative(path.dirname(filePath), contractPath).split(path.sep).join("/");
    if (!relative.startsWith(".")) relative = `./${relative}`;
    rewritten = rewritten.replaceAll(JSON.stringify(specifier), JSON.stringify(relative));
  }
  if (rewritten !== source) writeRuntimeAsset(filePath, rewritten);
}

function proxyRuntimePackageJson(): string {
  const parsed = JSON.parse(fs.readFileSync(path.join(repoRoot, "packages", "proxy", "package.json"), "utf8")) as {
    dependencies?: Record<string, string>;
    description?: string;
    engines?: Record<string, string>;
    name?: string;
    type?: string;
    version?: string;
  };
  return `${JSON.stringify({
    name: parsed.name,
    version: parsed.version,
    description: parsed.description,
    private: true,
    type: parsed.type,
    engines: parsed.engines,
    dependencies: Object.fromEntries(Object.entries(parsed.dependencies ?? {})
      .filter(([name]) => !name.startsWith("@runfree/"))),
  }, null, 2)}\n`;
}

export function buildRuntime(): void {
  cleanGeneratedRuntimeDir(outputRoot);
  cleanPackageBuildOutputs();
  compileRuntimePackages();
  fs.mkdirSync(outputRoot, { recursive: true });

  copyTree(path.join(repoRoot, "packages", "agent-runtime", "agent"), path.join(outputRoot, "agent"));
  copyFile(AGENT_PROBE_OUTPUT, path.join(outputRoot, "agent", "session-ready-probe.cjs"));
  copyFile(
    path.join(repoRoot, "packages", "agent-runtime", "runtime-inputs.lock.json"),
    path.join(outputRoot, "runtime-inputs.lock.json"),
  );
  copyTree(path.join(repoRoot, "packages", "cli", "templates"), path.join(outputRoot, "templates"));

  const proxyRoot = path.join(outputRoot, "proxy");
  fs.mkdirSync(proxyRoot, { recursive: true });
  copyFile(path.join(repoRoot, "packages", "proxy", "Dockerfile"), path.join(proxyRoot, "Dockerfile"));
  writeRuntimeAsset(path.join(proxyRoot, "package.json"), proxyRuntimePackageJson());
  copyFile(path.join(repoRoot, "packages", "proxy", "package-lock.json"), path.join(proxyRoot, "package-lock.json"));
  copyTree(path.join(repoRoot, "packages", "proxy", "dist"), proxyRoot, {
    include: (sourcePath) => sourcePath.endsWith(".js"),
    rewriteJs: true,
  });
  copyTree(path.join(repoRoot, "packages", "runtime-contracts", "dist"), path.join(proxyRoot, "contracts"), {
    include: (sourcePath) => sourcePath.endsWith(".js"),
  });
  assertGeneratedRuntimeManifest();
}

export function isDirectEntrypoint(metaUrl: string, argvPath: string | undefined): boolean {
  return argvPath !== undefined && metaUrl === pathToFileURL(argvPath).href;
}

if (isDirectEntrypoint(import.meta.url, process.argv[1])) {
  buildRuntime();
  console.log(path.relative(repoRoot, outputRoot));
}
