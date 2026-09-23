
import fs from "node:fs";
import path from "node:path";
export { sha256Digest };
import { stableJson, sha256Digest, exactKeySet as exactKeys, isRecord } from "../strict-primitives.ts";

export const RUNTIME_COMPONENT_DIGEST_SCHEMA_VERSION = 1 as const;
export const RUNTIME_GENERATION_MANIFEST_SCHEMA_VERSION = 1 as const;
export const RUNTIME_EFFECTIVE_SELECTION_SCHEMA_VERSION = 1 as const;

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;

export type RuntimeComponentState = {
  digestSchemaVersion: typeof RUNTIME_COMPONENT_DIGEST_SCHEMA_VERSION;
  embeddedAgentImageInputDigest: string;
  selectedAgentImageInputDigest: string;
  selectedAgentImageKind: "embedded" | "project";
  proxyImageInputDigest: string;
  topologyDigest: string;
  hostHelperDigest: string;
  runtimeGenerationDigest: string;
  materializationDigest: string;
};

export type RuntimeGenerationManifest = {
  schemaVersion: typeof RUNTIME_GENERATION_MANIFEST_SCHEMA_VERSION;
  projectId: string;
  composeProject: string;
  components: RuntimeComponentState;
  images: {
    agent: string;
    proxy: string;
  };
  renderedComposeSha256: string;
};

export type RuntimeEffectiveSelection = {
  schemaVersion: typeof RUNTIME_EFFECTIVE_SELECTION_SCHEMA_VERSION;
  materializationDigest: string;
};



function requireDigest(value: string, label: string): string {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} must be a full sha256 digest`);
  return value;
}

export function runtimeGenerationDigest(
  components: Pick<RuntimeComponentState,
    | "digestSchemaVersion"
    | "selectedAgentImageInputDigest"
    | "proxyImageInputDigest"
    | "topologyDigest">,
): string {
  return sha256Digest(stableJson({
    schemaVersion: components.digestSchemaVersion,
    selectedAgentImageInputDigest: requireDigest(
      components.selectedAgentImageInputDigest,
      "selected agent image input digest",
    ),
    proxyImageInputDigest: requireDigest(components.proxyImageInputDigest, "proxy image input digest"),
    topologyDigest: requireDigest(components.topologyDigest, "topology digest"),
  }));
}

export function runtimeMaterializationDigest(
  components: Pick<RuntimeComponentState, "digestSchemaVersion" | "runtimeGenerationDigest" | "hostHelperDigest">,
): string {
  return sha256Digest(stableJson({
    schemaVersion: components.digestSchemaVersion,
    runtimeGenerationDigest: requireDigest(components.runtimeGenerationDigest, "runtime generation digest"),
    hostHelperDigest: requireDigest(components.hostHelperDigest, "host helper digest"),
  }));
}

export function createRuntimeComponentState(input: {
  embeddedAgentImageInputDigest: string;
  selectedAgentImageInputDigest: string;
  selectedAgentImageKind: RuntimeComponentState["selectedAgentImageKind"];
  proxyImageInputDigest: string;
  topologyDigest: string;
  hostHelperDigest: string;
}): RuntimeComponentState {
  const base = {
    digestSchemaVersion: RUNTIME_COMPONENT_DIGEST_SCHEMA_VERSION,
    embeddedAgentImageInputDigest: requireDigest(
      input.embeddedAgentImageInputDigest,
      "embedded agent image input digest",
    ),
    selectedAgentImageInputDigest: requireDigest(
      input.selectedAgentImageInputDigest,
      "selected agent image input digest",
    ),
    selectedAgentImageKind: input.selectedAgentImageKind,
    proxyImageInputDigest: requireDigest(input.proxyImageInputDigest, "proxy image input digest"),
    topologyDigest: requireDigest(input.topologyDigest, "topology digest"),
    hostHelperDigest: requireDigest(input.hostHelperDigest, "host helper digest"),
  } as const;
  const generation = runtimeGenerationDigest(base);
  return {
    ...base,
    runtimeGenerationDigest: generation,
    materializationDigest: runtimeMaterializationDigest({
      digestSchemaVersion: base.digestSchemaVersion,
      runtimeGenerationDigest: generation,
      hostHelperDigest: base.hostHelperDigest,
    }),
  };
}

function digestDirectoryName(digest: string): string {
  return requireDigest(digest, "materialization digest").replace("sha256:", "sha256-");
}

export function runtimeMaterializationsRoot(stateDir: string): string {
  return path.join(stateDir, "runtime", "materializations");
}

export function runtimeMaterializationRoot(stateDir: string, materializationDigest: string): string {
  return path.join(runtimeMaterializationsRoot(stateDir), digestDirectoryName(materializationDigest));
}

export function runtimeGenerationManifestPath(stateDir: string, materializationDigest: string): string {
  return path.join(runtimeMaterializationRoot(stateDir, materializationDigest), "generation.json");
}

export function runtimeEffectiveSelectionPath(stateDir: string): string {
  return path.join(stateDir, "runtime", "effective.json");
}



function parseComponentState(value: unknown): RuntimeComponentState | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "digestSchemaVersion",
    "embeddedAgentImageInputDigest",
    "selectedAgentImageInputDigest",
    "selectedAgentImageKind",
    "proxyImageInputDigest",
    "topologyDigest",
    "hostHelperDigest",
    "runtimeGenerationDigest",
    "materializationDigest",
  ])) return undefined;
  if (value.digestSchemaVersion !== RUNTIME_COMPONENT_DIGEST_SCHEMA_VERSION) return undefined;
  if (value.selectedAgentImageKind !== "embedded" && value.selectedAgentImageKind !== "project") return undefined;
  const digests = [
    value.embeddedAgentImageInputDigest,
    value.selectedAgentImageInputDigest,
    value.proxyImageInputDigest,
    value.topologyDigest,
    value.hostHelperDigest,
    value.runtimeGenerationDigest,
    value.materializationDigest,
  ];
  if (!digests.every((entry) => typeof entry === "string" && SHA256_PATTERN.test(entry))) return undefined;
  const parsed = value as RuntimeComponentState;
  if (runtimeGenerationDigest(parsed) !== parsed.runtimeGenerationDigest) return undefined;
  if (runtimeMaterializationDigest(parsed) !== parsed.materializationDigest) return undefined;
  return parsed;
}

export function parseRuntimeGenerationManifest(value: unknown): RuntimeGenerationManifest | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "projectId",
    "composeProject",
    "components",
    "images",
    "renderedComposeSha256",
  ])) return undefined;
  if (value.schemaVersion !== RUNTIME_GENERATION_MANIFEST_SCHEMA_VERSION) return undefined;
  if (typeof value.projectId !== "string" || value.projectId === "") return undefined;
  if (typeof value.composeProject !== "string" || value.composeProject === "") return undefined;
  if (!isRecord(value.images) || !exactKeys(value.images, ["agent", "proxy"])) return undefined;
  if (typeof value.images.agent !== "string" || value.images.agent === "") return undefined;
  if (typeof value.images.proxy !== "string" || value.images.proxy === "") return undefined;
  if (typeof value.renderedComposeSha256 !== "string" || !SHA256_PATTERN.test(value.renderedComposeSha256)) {
    return undefined;
  }
  const components = parseComponentState(value.components);
  if (!components) return undefined;
  return {
    schemaVersion: RUNTIME_GENERATION_MANIFEST_SCHEMA_VERSION,
    projectId: value.projectId,
    composeProject: value.composeProject,
    components,
    images: { agent: value.images.agent, proxy: value.images.proxy },
    renderedComposeSha256: value.renderedComposeSha256,
  };
}

export function serializeRuntimeGenerationManifest(manifest: RuntimeGenerationManifest): string {
  const parsed = parseRuntimeGenerationManifest(manifest);
  if (!parsed) throw new Error("runtime generation manifest is invalid");
  return `${stableJson(parsed)}\n`;
}

function readRegularFile(filePath: string): string | undefined {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error(`runtime state path is not a normal file: ${filePath}`);
  }
  return fs.readFileSync(filePath, "utf8");
}

export function readRuntimeGenerationManifest(
  stateDir: string,
  materializationDigest: string,
): RuntimeGenerationManifest | undefined {
  const source = readRegularFile(runtimeGenerationManifestPath(stateDir, materializationDigest));
  if (source === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    throw new Error("runtime generation manifest is malformed");
  }
  const manifest = parseRuntimeGenerationManifest(parsed);
  if (!manifest || manifest.components.materializationDigest !== materializationDigest) {
    throw new Error("runtime generation manifest is invalid");
  }
  return manifest;
}

function atomicReplaceHostFile(filePath: string, contents: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(tmpPath, flags, 0o600);
    fs.writeFileSync(descriptor, contents);
    fs.fchmodSync(descriptor, 0o600);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(tmpPath, filePath);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(tmpPath, { force: true });
  }
}

export function selectEffectiveRuntimeGeneration(stateDir: string, materializationDigest: string): void {
  if (!readRuntimeGenerationManifest(stateDir, materializationDigest)) {
    throw new Error("cannot select a missing runtime materialization");
  }
  const selection: RuntimeEffectiveSelection = {
    schemaVersion: RUNTIME_EFFECTIVE_SELECTION_SCHEMA_VERSION,
    materializationDigest,
  };
  atomicReplaceHostFile(runtimeEffectiveSelectionPath(stateDir), `${stableJson(selection)}\n`);
}

export function readEffectiveRuntimeGeneration(stateDir: string): RuntimeGenerationManifest | undefined {
  const source = readRegularFile(runtimeEffectiveSelectionPath(stateDir));
  if (source === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("runtime effective selection is malformed");
  }
  if (!isRecord(value)
    || !exactKeys(value, ["schemaVersion", "materializationDigest"])
    || value.schemaVersion !== RUNTIME_EFFECTIVE_SELECTION_SCHEMA_VERSION
    || typeof value.materializationDigest !== "string"
    || !SHA256_PATTERN.test(value.materializationDigest)) {
    throw new Error("runtime effective selection is invalid");
  }
  const manifest = readRuntimeGenerationManifest(stateDir, value.materializationDigest);
  if (!manifest) throw new Error("runtime effective selection references a missing materialization");
  return manifest;
}
