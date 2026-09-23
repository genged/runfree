
import fs from "node:fs";
import path from "node:path";

import {
  validateNetworkPolicy,
  type PolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import {
  validateOAuthMediationPolicy,
  type OAuthMediationPolicyJson,
  type OAuthProviderPolicy,
  type OAuthProviderPolicyJson,
} from "@runfree/runtime-contracts/oauth-mediation-policy";
import type { ParsedGenerationStatus } from "@runfree/runtime-contracts/proxy-status";
import type { ProjectInfo } from "../config.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import {
  CONTROL_APPROVAL_HISTORICAL_VERSIONS,
  CONTROL_APPROVAL_SELECTION_VERSION,
  readApprovedNetworkPolicy,
  readApprovedRuntimeIsolation,
  readControlApprovalSelection,
  verifyNetworkSnapshot,
  type ControlApprovalSelectionVersion,
} from "./approvals.ts";
import {
  compileDesiredPolicies,
  type EffectiveControlProvenance,
} from "./compiler.ts";
import type { DesiredServiceEntry } from "@runfree/runtime-contracts/desired-network-policy";
import { parseStrictJson } from "./strict-json.ts";
import {
  CONTROL_COMPILER_VERSION,
  controlDigest,
} from "./subjects.ts";
import { withControlLock } from "./lock.ts";
import { publishImmutableDirectory, pollForExactAck } from "../generation-kernel.ts";
import { fsyncDirectory } from "../safe-fs.ts";
import { sha256Digest as sha256, assertAllowedKeys as exactKeys, isDigest } from "../strict-primitives.ts";
import { ControlsNotApprovedError } from "./refusals.ts";

const EFFECTIVE_CONTROL_SCHEMA_VERSION = 1 as const;
const PLACEHOLDER_VALUE = "runfree-placeholder-overwritten-by-proxy";
const HOST_PAYLOADS = ["agent/agent.env", "runtime/control.json"] as const;
// Older releases also stored a runtime/provenance.json payload (a snapshot of
// compiler output that every reader now recomputes on demand). Generations on
// disk may still list it; it stays verifiable but is never written or required.
const LEGACY_OPTIONAL_HOST_PAYLOADS = ["runtime/provenance.json"] as const;
const PROXY_PAYLOADS = ["network-policy.json", "oauth-mediation-policy.json"] as const;

type FileDigests<T extends string> = Record<T, string>;
export type EffectiveHostManifest = {
  approvalSchemaVersion: number;
  compilerVersion: string;
  controlGeneration: string;
  files: FileDigests<typeof HOST_PAYLOADS[number]>
    & Partial<FileDigests<typeof LEGACY_OPTIONAL_HOST_PAYLOADS[number]>>;
  policyGeneration: string;
  schemaVersion: typeof EFFECTIVE_CONTROL_SCHEMA_VERSION;
  selectedSubjects: Record<string, string>;
};
export type EffectiveProxyManifest = {
  compilerVersion: string;
  controlGeneration: string;
  files: FileDigests<typeof PROXY_PAYLOADS[number]>;
  policyGeneration: string;
  schemaVersion: typeof EFFECTIVE_CONTROL_SCHEMA_VERSION;
};
export type ActiveControlSelection = {
  controlGeneration: string;
  hostManifestDigest: string;
  proxyManifestDigest: string;
  schemaVersion: typeof EFFECTIVE_CONTROL_SCHEMA_VERSION;
};
export type EffectivePolicyGeneration = {
  active: ActiveControlSelection;
  agentEnvPath: string;
  controlGeneration: string;
  hostDirectory: string;
  hostManifest: EffectiveHostManifest;
  networkPolicyPath: string;
  oauthPolicyPath: string;
  policy: PolicyJson;
  policyGeneration: string;
  proxyDirectory: string;
  proxyManifest: EffectiveProxyManifest;
  runtimeControlPath: string;
};
export type EffectiveControlProvenanceSnapshot = {
  provenance: EffectiveControlProvenance;
  schemaVersion: 1;
  selectedServices: Record<string, DesiredServiceEntry>;
};
export type EffectiveConsumerReceipts = {
  firewall?: ParsedGenerationStatus;
  requestProxy?: ParsedGenerationStatus;
};
export type ConvergedPolicyReceipt = {
  controlGeneration: string;
  convergedAt: string;
  firewall: {
    controlGeneration: string;
    policyGeneration: string;
    rulesetVerified: true;
  };
  policyGeneration: string;
  requestProxy: {
    controlGeneration: string;
    policyGeneration: string;
  };
  schemaVersion: typeof EFFECTIVE_CONTROL_SCHEMA_VERSION;
};



function fsyncDirectoryIfExists(directory: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(directory);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`effective control state path is not a safe directory: ${directory}`);
  }
  fsyncDirectory(directory);
}

function removeFileDurably(filePath: string): void {
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (!error || typeof error !== "object" || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  fsyncDirectoryIfExists(path.dirname(filePath));
}


function generationName(digest: string): string {
  if (!isDigest(digest)) throw new Error("effective policy generation digest is malformed");
  return digest.slice("sha256:".length);
}

function normalizedProvider(provider: OAuthProviderPolicy): OAuthProviderPolicyJson {
  return {
    kind: provider.kind,
    resourceHost: provider.resourceHost,
    resourcePathPrefix: provider.resourcePathPrefix,
    tokenEndpoints: provider.tokenEndpoints,
    registrationEndpoints: provider.registrationEndpoints,
    metadataEndpoints: provider.metadataEndpoints,
    seeds: provider.seeds,
  };
}

function effectiveOAuthPolicy(
  compiled: ReturnType<typeof compileDesiredPolicies>,
  input: PublishEffectiveControlInput,
): OAuthMediationPolicyJson {
  const base = validateOAuthMediationPolicy(input.baseOAuthPolicy ?? { providers: {} });
  const providers: Record<string, OAuthProviderPolicyJson> = Object.fromEntries(
    base.providers.map((provider) => [provider.providerId, normalizedProvider(provider)]),
  );
  for (const [providerId, provider] of Object.entries(compiled.oauth)) {
    if (providers[providerId]) throw new Error(`OAuth provider ${providerId} conflicts with host-owned OAuth policy`);
    const handles = input.oauthSeedHandles?.[providerId] ?? {};
    providers[providerId] = {
      kind: "service",
      resourceHost: provider.resourceHost,
      ...(provider.resourcePathPrefix ? { resourcePathPrefix: provider.resourcePathPrefix } : {}),
      tokenEndpoints: provider.tokenEndpoints,
      ...(provider.registrationEndpoints ? { registrationEndpoints: provider.registrationEndpoints } : {}),
      ...(provider.seeds ? {
        seeds: provider.seeds.map((seed) => {
          const handle = handles[seed.envVar];
          if (!handle) throw new Error(`OAuth provider ${providerId} has no approved handle for ${seed.envVar}`);
          return { field: seed.field, handle, secretRef: seed.tokenName };
        }),
      } : {}),
    };
  }
  const policy = { providers: Object.fromEntries(Object.entries(providers).sort()) };
  validateOAuthMediationPolicy(policy);
  return policy;
}

function effectiveAgentEnv(
  compiled: ReturnType<typeof compileDesiredPolicies>,
  input: PublishEffectiveControlInput,
): string {
  const values: Record<string, string> = Object.fromEntries(compiled.agentEnv.map((name) => [name, PLACEHOLDER_VALUE]));
  for (const [providerId, provider] of Object.entries(compiled.oauth)) {
    for (const seed of provider.seeds ?? []) {
      const handle = input.oauthSeedHandles?.[providerId]?.[seed.envVar];
      if (!handle) throw new Error(`OAuth provider ${providerId} has no approved handle for ${seed.envVar}`);
      values[seed.envVar] = handle;
    }
    for (const passthrough of provider.passthrough ?? []) {
      values[passthrough.envVar] = input.agentEnvValues?.[passthrough.envVar] ?? PLACEHOLDER_VALUE;
    }
  }
  for (const [name, value] of Object.entries(input.agentEnvValues ?? {})) {
    if (!(name in values)) throw new Error(`agent environment ${name} is not declared by approved policy`);
    values[name] = value;
  }
  for (const [name, value] of Object.entries(values)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || /[\n\0\u2028\u2029]/u.test(value)) {
      throw new Error(`agent environment ${name} is not safely serializable`);
    }
  }
  return Object.entries(values).sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => `${name}=${value}\n`).join("");
}

export type PublishEffectiveControlInput = {
  agentEnvValues?: Record<string, string>;
  baseOAuthPolicy?: OAuthMediationPolicyJson;
  effectiveNetworkPolicy?: PolicyJson;
  oauthSeedHandles?: Record<string, Record<string, string>>;
  runtimeNetwork?: Record<string, unknown>;
};

function publishTree(parent: string, name: string, files: Record<string, string>, publicRead: boolean): string {
  return publishImmutableDirectory({
    parent,
    name,
    files,
    directoryMode: publicRead ? 0o755 : 0o700,
    fileMode: publicRead ? 0o444 : 0o400,
    parentMode: publicRead ? 0o755 : 0o700,
    tempPrefix: ".generation-",
    fsyncParentWhenPresent: true,
    // The paired host/proxy manifests are digest-verified together by
    // verifyEffectivePolicyGeneration after both trees exist.
    verify: () => path.join(parent, name),
  });
}

function regularContents(root: string, relativePath: string): string {
  const filePath = path.join(root, relativePath);
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`${relativePath} is not a regular single-link generation file`);
  return fs.readFileSync(filePath, "utf8");
}


function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function validateDigestMap(
  value: unknown,
  names: readonly string[],
  label: string,
  optionalNames: readonly string[] = [],
): Record<string, string> {
  const raw = record(value, label);
  exactKeys(raw, [...names, ...optionalNames], label);
  const result: Record<string, string> = {};
  for (const name of names) {
    if (!isDigest(raw[name])) throw new Error(`${label}.${name} is malformed`);
    result[name] = raw[name];
  }
  for (const name of optionalNames) {
    if (raw[name] === undefined) continue;
    if (!isDigest(raw[name])) throw new Error(`${label}.${name} is malformed`);
    result[name] = raw[name];
  }
  return result;
}

// Frozen wire: the serialized `controlGeneration` key in the manifests, the
// active selection, and the converged receipt is the effective policy
// generation (renamed in code and docs only, never on disk). It is a different
// family from the runtime `controlPlaneGenerationDigest`; see "Generation
// Families" in docs/architecture.md.
function parseProxyManifest(source: string): EffectiveProxyManifest {
  const raw = record(parseStrictJson(source), "proxy manifest");
  exactKeys(raw, ["compilerVersion", "controlGeneration", "files", "policyGeneration", "schemaVersion"], "proxy manifest");
  if (raw.schemaVersion !== 1 || raw.compilerVersion !== CONTROL_COMPILER_VERSION
    || !isDigest(raw.controlGeneration) || !isDigest(raw.policyGeneration)) throw new Error("proxy manifest identity is malformed");
  return {
    schemaVersion: 1,
    compilerVersion: CONTROL_COMPILER_VERSION,
    controlGeneration: raw.controlGeneration,
    policyGeneration: raw.policyGeneration,
    files: validateDigestMap(raw.files, PROXY_PAYLOADS, "proxy manifest files") as EffectiveProxyManifest["files"],
  };
}

function parseHostManifest(source: string): EffectiveHostManifest {
  const raw = record(parseStrictJson(source), "host manifest");
  exactKeys(
    raw,
    ["approvalSchemaVersion", "compilerVersion", "controlGeneration", "files", "policyGeneration", "schemaVersion", "selectedSubjects"],
    "host manifest",
  );
  // Accept every approval schema version this release can read, and preserve
  // what was read. Pinning to the current constant made every previously
  // published host manifest unparseable the moment the constant moved — a
  // latent bug that the selection bump turned load-bearing.
  if (raw.schemaVersion !== 1
    || !CONTROL_APPROVAL_HISTORICAL_VERSIONS.includes(raw.approvalSchemaVersion as ControlApprovalSelectionVersion)
    || raw.compilerVersion !== CONTROL_COMPILER_VERSION || !isDigest(raw.controlGeneration) || !isDigest(raw.policyGeneration)) {
    throw new Error("host manifest identity is malformed");
  }
  const selectedRaw = record(raw.selectedSubjects, "host manifest selectedSubjects");
  const selectedSubjects: Record<string, string> = {};
  for (const [name, digest] of Object.entries(selectedRaw)) {
    if (!["network-project", "network-local", "runtime-isolation", "image-build"].includes(name) || !isDigest(digest)) {
      throw new Error("host manifest selectedSubjects is malformed");
    }
    selectedSubjects[name] = digest;
  }
  return {
    schemaVersion: 1,
    approvalSchemaVersion: raw.approvalSchemaVersion as ControlApprovalSelectionVersion,
    compilerVersion: CONTROL_COMPILER_VERSION,
    controlGeneration: raw.controlGeneration,
    policyGeneration: raw.policyGeneration,
    selectedSubjects,
    files: validateDigestMap(
      raw.files,
      HOST_PAYLOADS,
      "host manifest files",
      LEGACY_OPTIONAL_HOST_PAYLOADS,
    ) as EffectiveHostManifest["files"],
  };
}

export function verifyEffectivePolicyGeneration(
  project: ProjectInfo,
  controlGeneration: string,
): Omit<EffectivePolicyGeneration, "active" | "policy"> {
  const name = generationName(controlGeneration);
  const hostDirectory = path.join(project.paths.controlEffectiveDir, "generations", name);
  const proxyDirectory = path.join(project.paths.controlProxyDir, "generations", name);
  const hostManifestContents = regularContents(hostDirectory, "manifest.json");
  const proxyManifestContents = regularContents(proxyDirectory, "manifest.json");
  const hostManifest = parseHostManifest(hostManifestContents);
  const proxyManifest = parseProxyManifest(proxyManifestContents);
  if (hostManifest.controlGeneration !== controlGeneration || proxyManifest.controlGeneration !== controlGeneration
    || hostManifest.policyGeneration !== proxyManifest.policyGeneration) throw new Error("effective manifests disagree on generation identity");
  for (const [fileName, digest] of Object.entries(hostManifest.files)) {
    if (sha256(regularContents(hostDirectory, fileName)) !== digest) throw new Error(`host generation payload ${fileName} is corrupt`);
  }
  for (const [fileName, digest] of Object.entries(proxyManifest.files)) {
    if (sha256(regularContents(proxyDirectory, fileName)) !== digest) throw new Error(`proxy generation payload ${fileName} is corrupt`);
  }
  const policy = validateNetworkPolicy(parseStrictJson(regularContents(proxyDirectory, "network-policy.json")));
  if (policy.generation !== hostManifest.policyGeneration) throw new Error("effective network policy generation does not match the manifests");
  validateOAuthMediationPolicy(parseStrictJson(regularContents(proxyDirectory, "oauth-mediation-policy.json")));
  return {
    controlGeneration,
    policyGeneration: policy.generation,
    hostDirectory,
    proxyDirectory,
    hostManifest,
    proxyManifest,
    agentEnvPath: path.join(hostDirectory, "agent", "agent.env"),
    runtimeControlPath: path.join(hostDirectory, "runtime", "control.json"),
    networkPolicyPath: path.join(proxyDirectory, "network-policy.json"),
    oauthPolicyPath: path.join(proxyDirectory, "oauth-mediation-policy.json"),
  };
}

function provenanceSnapshot(compiled: ReturnType<typeof compileDesiredPolicies>): EffectiveControlProvenanceSnapshot {
  return {
    schemaVersion: 1,
    provenance: compiled.provenance,
    selectedServices: compiled.selectedServices,
  };
}

export function readEffectiveControlProvenance(
  project: ProjectInfo,
  controlGeneration: string,
): EffectiveControlProvenanceSnapshot {
  const generation = verifyEffectivePolicyGeneration(project, controlGeneration);
  const projectDigest = generation.hostManifest.selectedSubjects["network-project"];
  const localDigest = generation.hostManifest.selectedSubjects["network-local"];
  if (!projectDigest || !localDigest) throw new Error("effective generation has no selected network subjects");
  const compiled = compileDesiredPolicies({
    project: verifyNetworkSnapshot(project, "network-project", projectDigest),
    local: verifyNetworkSnapshot(project, "network-local", localDigest),
  });
  // Recompute-only: provenance derives entirely from the verified approved
  // subjects, so it is rebuilt on demand rather than stored and compared.
  return provenanceSnapshot(compiled);
}

export function readEffectiveNetworkPolicy(project: ProjectInfo, controlGeneration: string): PolicyJson {
  const generation = verifyEffectivePolicyGeneration(project, controlGeneration);
  return validateNetworkPolicy(parseStrictJson(regularContents(generation.proxyDirectory, "network-policy.json"))).raw;
}

export function readActiveControlSelection(project: ProjectInfo): ActiveControlSelection | undefined {
  let source: string;
  try {
    source = regularContents(project.paths.controlProxyDir, "active.json");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  const raw = record(parseStrictJson(source), "active control selection");
  exactKeys(raw, ["controlGeneration", "hostManifestDigest", "proxyManifestDigest", "schemaVersion"], "active control selection");
  if (raw.schemaVersion !== 1 || !isDigest(raw.controlGeneration)
    || !isDigest(raw.hostManifestDigest) || !isDigest(raw.proxyManifestDigest)) throw new Error("active control selection is malformed");
  const active = raw as ActiveControlSelection;
  const generation = verifyEffectivePolicyGeneration(project, active.controlGeneration);
  if (sha256(regularContents(generation.hostDirectory, "manifest.json")) !== active.hostManifestDigest
    || sha256(regularContents(generation.proxyDirectory, "manifest.json")) !== active.proxyManifestDigest) {
    throw new Error("active control selection manifest digest is corrupt");
  }
  return active;
}

export function readActiveEffectiveControl(project: ProjectInfo): EffectivePolicyGeneration | undefined {
  const active = readActiveControlSelection(project);
  if (!active) return undefined;
  const verified = verifyEffectivePolicyGeneration(project, active.controlGeneration);
  return {
    ...verified,
    active,
    policy: validateNetworkPolicy(parseStrictJson(regularContents(verified.proxyDirectory, "network-policy.json"))).raw,
  };
}

export function effectiveControlSelectionForGeneration(
  project: ProjectInfo,
  controlGeneration: string,
): ActiveControlSelection {
  const generation = verifyEffectivePolicyGeneration(project, controlGeneration);
  return {
    schemaVersion: 1,
    controlGeneration,
    proxyManifestDigest: sha256(regularContents(generation.proxyDirectory, "manifest.json")),
    hostManifestDigest: sha256(regularContents(generation.hostDirectory, "manifest.json")),
  };
}

function selectEffectivePolicyGenerationUnlocked(project: ProjectInfo, controlGeneration: string): ActiveControlSelection {
  const active = effectiveControlSelectionForGeneration(project, controlGeneration);
  fs.mkdirSync(project.paths.controlProxyDir, { recursive: true, mode: 0o755 });
  fs.chmodSync(project.paths.controlProxyDir, 0o755);
  atomicReplaceFile(project.paths.controlProxyActivePath, `${JSON.stringify(active, null, 2)}\n`, 0o444);
  if (JSON.stringify(readActiveControlSelection(project)) !== JSON.stringify(active)) {
    throw new Error("active control selection did not persist exactly");
  }
  return active;
}

export function selectEffectivePolicyGeneration(project: ProjectInfo, controlGeneration: string): ActiveControlSelection {
  return withControlLock(project, () => selectEffectivePolicyGenerationUnlocked(project, controlGeneration));
}

export function clearActiveControlSelection(project: ProjectInfo): void {
  withControlLock(project, () => removeFileDurably(project.paths.controlProxyActivePath));
}

function publishEffectivePolicyGenerationUnlocked(
  projectRoot: string,
  project: ProjectInfo,
  input: PublishEffectiveControlInput = {},
): EffectivePolicyGeneration {
  const projectPolicy = readApprovedNetworkPolicy(projectRoot, project, "network-project");
  const localPolicy = readApprovedNetworkPolicy(projectRoot, project, "network-local");
  const runtimeIsolation = readApprovedRuntimeIsolation(projectRoot, project);
  if (!projectPolicy || !localPolicy || !runtimeIsolation) {
    throw new ControlsNotApprovedError("network-project, network-local, and runtime-isolation approvals are required before control publication");
  }
  const selection = readControlApprovalSelection(projectRoot, project);
  if (!selection) throw new Error("control approval selection is missing");
  const compiled = compileDesiredPolicies({ project: projectPolicy, local: localPolicy });
  const loadedPolicy = validateNetworkPolicy(input.effectiveNetworkPolicy ?? compiled.policy);
  const oauthPolicy = effectiveOAuthPolicy(compiled, input);
  const hostPayloads = {
    "agent/agent.env": effectiveAgentEnv(compiled, input),
    "runtime/control.json": `${JSON.stringify({ isolation: runtimeIsolation, network: input.runtimeNetwork ?? {} }, null, 2)}\n`,
  };
  const proxyPayloads = {
    "network-policy.json": `${JSON.stringify(loadedPolicy.raw, null, 2)}\n`,
    "oauth-mediation-policy.json": `${JSON.stringify(oauthPolicy, null, 2)}\n`,
  };
  const selectedSubjects = Object.fromEntries(Object.entries(selection.subjects).sort().map(([name, approval]) => [name, approval?.digest]));
  const payloadDigests = Object.fromEntries(Object.entries({ ...hostPayloads, ...proxyPayloads }).sort()
    .map(([name, contents]) => [name, sha256(contents)]));
  // The checkout observation is deliberately absent from this content address.
  // It is a mutable filesystem fact, so mixing it in made the generation churn
  // on a reboot, and it is redundant: the binding is already enforced by the
  // selection read above, before anything here runs. Reboot stability of the
  // generation follows from this structure rather than from a test.
  const controlGeneration = controlDigest({
    schemaVersion: EFFECTIVE_CONTROL_SCHEMA_VERSION,
    subjectType: "control-generation",
    selectedSubjects,
    compilerVersion: CONTROL_COMPILER_VERSION,
    approvalSchemaVersion: CONTROL_APPROVAL_SELECTION_VERSION,
    policyGeneration: loadedPolicy.generation,
    payloads: payloadDigests,
  });
  const hostManifest: EffectiveHostManifest = {
    schemaVersion: 1,
    approvalSchemaVersion: CONTROL_APPROVAL_SELECTION_VERSION,
    compilerVersion: CONTROL_COMPILER_VERSION,
    controlGeneration,
    policyGeneration: loadedPolicy.generation,
    selectedSubjects,
    files: Object.fromEntries(Object.entries(hostPayloads).map(([name, contents]) => [name, sha256(contents)])) as EffectiveHostManifest["files"],
  };
  const proxyManifest: EffectiveProxyManifest = {
    schemaVersion: 1,
    compilerVersion: CONTROL_COMPILER_VERSION,
    controlGeneration,
    policyGeneration: loadedPolicy.generation,
    files: Object.fromEntries(Object.entries(proxyPayloads).map(([name, contents]) => [name, sha256(contents)])) as EffectiveProxyManifest["files"],
  };
  const name = generationName(controlGeneration);
  publishTree(
    path.join(project.paths.controlProxyDir, "generations"),
    name,
    { ...proxyPayloads, "manifest.json": `${JSON.stringify(proxyManifest, null, 2)}\n` },
    true,
  );
  publishTree(
    path.join(project.paths.controlEffectiveDir, "generations"),
    name,
    { ...hostPayloads, "manifest.json": `${JSON.stringify(hostManifest, null, 2)}\n` },
    false,
  );
  const verified = verifyEffectivePolicyGeneration(project, controlGeneration);
  const active = selectEffectivePolicyGenerationUnlocked(project, controlGeneration);
  return { ...verified, active, policy: loadedPolicy.raw };
}

export function publishEffectivePolicyGeneration(
  projectRoot: string,
  project: ProjectInfo,
  input: PublishEffectiveControlInput = {},
): EffectivePolicyGeneration {
  return withControlLock(project, () => publishEffectivePolicyGenerationUnlocked(projectRoot, project, input));
}

function parseConvergedPolicyReceipt(source: string): ConvergedPolicyReceipt {
  const raw = record(parseStrictJson(source), "converged policy receipt");
  exactKeys(raw, ["controlGeneration", "convergedAt", "firewall", "policyGeneration", "requestProxy", "schemaVersion"], "converged policy receipt");
  if (raw.schemaVersion !== 1 || !isDigest(raw.controlGeneration) || !isDigest(raw.policyGeneration)
    || typeof raw.convergedAt !== "string" || !Number.isFinite(Date.parse(raw.convergedAt))) {
    throw new Error("converged policy receipt identity is malformed");
  }
  const requestProxy = record(raw.requestProxy, "converged request-proxy receipt");
  exactKeys(requestProxy, ["controlGeneration", "policyGeneration"], "converged request-proxy receipt");
  const firewall = record(raw.firewall, "converged firewall receipt");
  exactKeys(firewall, ["controlGeneration", "policyGeneration", "rulesetVerified"], "converged firewall receipt");
  if (requestProxy.controlGeneration !== raw.controlGeneration || firewall.controlGeneration !== raw.controlGeneration
    || requestProxy.policyGeneration !== raw.policyGeneration || firewall.policyGeneration !== raw.policyGeneration
    || firewall.rulesetVerified !== true) throw new Error("converged consumer receipts disagree");
  return {
    schemaVersion: 1,
    controlGeneration: raw.controlGeneration,
    policyGeneration: raw.policyGeneration,
    convergedAt: raw.convergedAt,
    requestProxy: {
      controlGeneration: raw.controlGeneration,
      policyGeneration: raw.policyGeneration,
    },
    firewall: {
      controlGeneration: raw.controlGeneration,
      policyGeneration: raw.policyGeneration,
      rulesetVerified: true,
    },
  };
}

export function readConvergedPolicyReceipt(project: ProjectInfo): ConvergedPolicyReceipt | undefined {
  try {
    return parseConvergedPolicyReceipt(regularContents(project.paths.controlEffectiveDir, "converged.json"));
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

export function clearConvergedPolicyReceipt(project: ProjectInfo): void {
  removeFileDurably(project.paths.controlConvergedPath);
}

function matchingConsumerReceipts(
  generation: Omit<EffectivePolicyGeneration, "active" | "policy">,
  receipts: EffectiveConsumerReceipts,
): receipts is Required<EffectiveConsumerReceipts> {
  const expectedControl = generation.controlGeneration;
  const expectedPolicy = generation.policyGeneration;
  return receipts.requestProxy?.controlGeneration === expectedControl
    && receipts.requestProxy.policyGeneration === expectedPolicy
    && receipts.firewall?.controlGeneration === expectedControl
    && receipts.firewall.policyGeneration === expectedPolicy
    && receipts.firewall.rulesetVerified === true;
}

async function waitForConsumerReceipts(
  project: ProjectInfo,
  generation: Omit<EffectivePolicyGeneration, "active" | "policy">,
  probe: () => Promise<EffectiveConsumerReceipts>,
  options: { pollIntervalMs: number; timeoutMs: number },
): Promise<Required<EffectiveConsumerReceipts> | undefined> {
  return pollForExactAck({
    beforeProbe: () => {
      if (readActiveControlSelection(project)?.controlGeneration !== generation.controlGeneration) {
        throw new Error("effective policy selection changed during convergence");
      }
    },
    probe: async () => {
      const receipts = await probe();
      return matchingConsumerReceipts(generation, receipts) ? receipts : undefined;
    },
    timeoutMs: options.timeoutMs,
    pollIntervalMs: options.pollIntervalMs,
    deadline: "after-probe",
  });
}

function persistConvergedPolicyReceipt(
  project: ProjectInfo,
  generation: Omit<EffectivePolicyGeneration, "active" | "policy">,
): ConvergedPolicyReceipt {
  const receipt: ConvergedPolicyReceipt = {
    schemaVersion: 1,
    controlGeneration: generation.controlGeneration,
    policyGeneration: generation.policyGeneration,
    convergedAt: new Date().toISOString(),
    requestProxy: {
      controlGeneration: generation.controlGeneration,
      policyGeneration: generation.policyGeneration,
    },
    firewall: {
      controlGeneration: generation.controlGeneration,
      policyGeneration: generation.policyGeneration,
      rulesetVerified: true,
    },
  };
  atomicReplaceFile(project.paths.controlConvergedPath, `${JSON.stringify(receipt, null, 2)}\n`, 0o600);
  return parseConvergedPolicyReceipt(regularContents(project.paths.controlEffectiveDir, "converged.json"));
}

export async function convergeEffectivePolicyGeneration(
  project: ProjectInfo,
  input: {
    previous?: ActiveControlSelection;
    probe: () => Promise<EffectiveConsumerReceipts>;
    stopRuntime: () => Promise<void>;
    pollIntervalMs?: number;
    timeoutMs?: number;
  },
): Promise<ConvergedPolicyReceipt> {
  const selected = readActiveControlSelection(project);
  if (!selected) throw new Error("effective policy selection is missing");
  const generation = verifyEffectivePolicyGeneration(project, selected.controlGeneration);
  const options = {
    pollIntervalMs: input.pollIntervalMs ?? 100,
    timeoutMs: input.timeoutMs ?? 10_000,
  };
  if (await waitForConsumerReceipts(project, generation, input.probe, options)) {
    return persistConvergedPolicyReceipt(project, generation);
  }

  clearConvergedPolicyReceipt(project);
  if (input.previous && input.previous.controlGeneration !== selected.controlGeneration) {
    try {
      selectEffectivePolicyGeneration(project, input.previous.controlGeneration);
      const rollback = verifyEffectivePolicyGeneration(project, input.previous.controlGeneration);
      if (await waitForConsumerReceipts(project, rollback, input.probe, options)) {
        persistConvergedPolicyReceipt(project, rollback);
        throw new Error(`effective policy convergence failed; rolled back to ${rollback.controlGeneration}`);
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("effective policy convergence failed; rolled back")) throw error;
    }
  }
  clearConvergedPolicyReceipt(project);
  await input.stopRuntime();
  throw new Error("effective policy convergence and rollback failed; proxy stopped");
}

export function cleanupEffectivePolicyGenerations(
  project: ProjectInfo,
  input: {
    approvedControlGenerations?: readonly string[];
    liveControlGenerations?: readonly string[];
    retainUnprotected?: number;
    rollbackControlGeneration?: string;
  } = {},
): string[] {
  const hostRoot = path.join(project.paths.controlEffectiveDir, "generations");
  const proxyRoot = path.join(project.paths.controlProxyDir, "generations");
  const roots = [hostRoot, proxyRoot];
  const namesByRoot = roots.map((root) => {
    try {
      return fs.readdirSync(root).sort();
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
      throw error;
    }
  });
  for (const names of namesByRoot) {
    for (const name of names) {
      if (!/^[a-f0-9]{64}$/.test(name)) throw new Error(`unexpected effective generation entry: ${name}`);
    }
  }
  const allNames = new Set(namesByRoot.flat());
  for (const name of allNames) {
    if (!namesByRoot.every((names) => names.includes(name))) throw new Error(`unpaired effective generation entry: ${name}`);
    for (const root of roots) {
      const stat = fs.lstatSync(path.join(root, name));
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`unsafe effective generation entry: ${name}`);
    }
  }
  const protectedDigests = new Set<string>([
    readActiveControlSelection(project)?.controlGeneration,
    readConvergedPolicyReceipt(project)?.controlGeneration,
    input.rollbackControlGeneration,
    ...(input.approvedControlGenerations ?? []),
    ...(input.liveControlGenerations ?? []),
  ].filter((value): value is string => value !== undefined));
  const removable = [...allNames]
    .map((name) => ({ name, mtimeMs: fs.lstatSync(path.join(hostRoot, name)).mtimeMs }))
    .filter(({ name }) => !protectedDigests.has(`sha256:${name}`))
    .sort((left, right) => right.mtimeMs - left.mtimeMs || left.name.localeCompare(right.name))
    .slice(Math.max(0, input.retainUnprotected ?? 2));
  for (const { name } of removable) {
    fs.rmSync(path.join(hostRoot, name), { recursive: true });
    fs.rmSync(path.join(proxyRoot, name), { recursive: true });
  }
  return removable.map(({ name }) => `sha256:${name}`);
}
