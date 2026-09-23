
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  normalizeHostname,
  normalizePathPrefix,
  type CredentialPolicyJson,
} from "@runfree/runtime-contracts/network-policy";

import {
  RUNFREE_PLACEHOLDER_VALUE,
  SERVICES,
  USER_SERVICE_ID_PATTERN,
  isUserServiceId,
  serviceAgentEnvNames,
  validateServiceDefinition,
  type DetectRule,
  type Service,
  type ServiceCredential,
  type ServiceParameter,
  type ServiceHost,
} from "../../../scripts/services.ts";
import { runfreeConfigRoot } from "./paths.ts";
import { runtimeOwnedAgentEnvNames } from "./runtime/agent-env.ts";
import { isPathInsideByRealpath } from "./safe-fs.ts";
import { isRecord, sha256Digest } from "./strict-primitives.ts";

const USER_DEFINITION_MAX_BYTES = 512 * 1024;
const BROAD_EXPLANATION_MIN_CHARS = 20;
const LABEL_MAX_CHARS = 80;
const EXPLANATION_MAX_CHARS = 600;
const DETECT_BASENAME_MAX_CHARS = 128;
const USER_SERVICE_META_DIR = ".metadata";

export type UserServiceDefinitionJson = {
  schemaVersion: 1;
  id: string;
  label: string;
  revision: number;
  hosts: ServiceHost[];
  explanations: string[];
  detect?: DetectRule[];
  credential?: Omit<ServiceCredential, "tokenName">;
  // Declared non-secret inputs (see ServiceParameter); user definitions may
  // not set oauthField because they cannot carry OAuth credentials.
  parameters?: Array<Omit<ServiceParameter, "oauthField">>;
  neverAutoSuggest?: boolean;
};

export type LoadedUserServiceDefinition = {
  svc: Service;
  path: string;
  digest: string;
  definition: UserServiceDefinitionJson;
};

export type InvalidUserServiceDefinition = {
  id: string;
  path: string;
  reason: string;
};

export type UserServiceCatalog = {
  services: Record<string, LoadedUserServiceDefinition>;
  invalid: InvalidUserServiceDefinition[];
  dir: string;
};


function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function userServiceDigest(definition: UserServiceDefinitionJson): string {
  return sha256Digest(stableStringify(definition));
}

function displayPath(filePath: string, env: NodeJS.ProcessEnv = process.env): string {
  const home = env.HOME || os.homedir();
  const relativeHome = path.relative(home, filePath);
  if (relativeHome && !relativeHome.startsWith("..") && !path.isAbsolute(relativeHome)) return `~/${relativeHome}`;
  return filePath;
}

export function displayUserServicePath(filePath: string, env: NodeJS.ProcessEnv = process.env): string {
  return displayPath(filePath, env);
}

function assertOutsideProject(projectRoot: string, label: string, filePath: string): string {
  const resolved = path.resolve(filePath);
  if (isPathInsideByRealpath(projectRoot, resolved)) {
    throw new Error(`${label} must be outside the project: ${path.relative(projectRoot, resolved) || "."}`);
  }
  return resolved;
}

export function userServicesDir(projectRoot: string, env: NodeJS.ProcessEnv = process.env): string {
  const override = env.RUNFREE_USER_SERVICES_DIR;
  const configured = override && override.trim() !== ""
    ? override
    : path.join(runfreeConfigRoot(env), "services");
  if (override && env.RUNFREE_TEST_FAKE_DOCKER !== "1") {
    throw new Error("RUNFREE_USER_SERVICES_DIR is test-only; user service definitions live in XDG config");
  }
  return assertOutsideProject(projectRoot, "user services directory", configured);
}

export function canonicalUserServiceId(id: string): string {
  const normalized = id.trim().toLowerCase();
  return normalized.startsWith("user-") ? normalized : `user-${normalized}`;
}

function ensureOnlyKeys(value: Record<string, unknown>, allowed: Set<string>, owner: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${owner}: unknown key ${key}`);
  }
}

function safeDisplayText(value: unknown, owner: string, maxChars: number, minChars = 1): string {
  if (typeof value !== "string") throw new Error(`${owner} must be a string`);
  const text = value.trim();
  if (text.length < minChars) throw new Error(`${owner} must be non-empty`);
  if (text.length > maxChars) throw new Error(`${owner} must be at most ${maxChars} characters`);
  // Match sanitizeForTerminal's control-character class (C0, DEL, and C1):
  // validated text must already be safe to render, sanitization at render
  // stays defense in depth.
  if (/[\x00-\x1f\x7f-\x9f]/.test(text)) throw new Error(`${owner} must be printable single-line text`);
  return text;
}

function parseHost(value: unknown, owner: string): ServiceHost {
  if (!isRecord(value)) throw new Error(`${owner} must be an object`);
  ensureOnlyKeys(value, new Set(["host", "broad", "explanation"]), owner);
  if (typeof value.host !== "string") throw new Error(`${owner}.host must be a string`);
  let host: string;
  try {
    host = normalizeHostname(value.host);
  } catch (error) {
    throw new Error(`${owner}.host: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (host !== value.host) throw new Error(`${owner}.host must be stored as exact normalized hostname ${host}`);
  if (value.broad !== undefined && value.broad !== true) throw new Error(`${owner}.broad, when present, must be true`);
  const broad = value.broad === true;
  const explanation = value.explanation === undefined
    ? undefined
    : safeDisplayText(value.explanation, `${owner}.explanation`, EXPLANATION_MAX_CHARS, broad ? BROAD_EXPLANATION_MIN_CHARS : 1);
  if (broad && !explanation) throw new Error(`${owner}.explanation is required for broad hosts`);
  return { host, ...(broad ? { broad: true as const, explanation } : explanation ? { explanation } : {}) };
}

function parseDetectRule(value: unknown, owner: string): DetectRule {
  if (!isRecord(value)) throw new Error(`${owner} must be an object`);
  ensureOnlyKeys(value, new Set(["kind", "path"]), owner);
  if (value.kind !== "file") throw new Error(`${owner}.kind must be file`);
  const rulePath = safeDisplayText(value.path, `${owner}.path`, DETECT_BASENAME_MAX_CHARS);
  if (rulePath === "." || rulePath === ".." || rulePath.includes("/") || rulePath.includes("\\") || rulePath.includes("..")) {
    throw new Error(`${owner}.path must be a root-level basename`);
  }
  return { kind: "file", path: rulePath };
}

function parseCredentialPolicy(value: unknown, owner: string): CredentialPolicyJson {
  if (!isRecord(value)) throw new Error(`${owner} must be an object`);
  ensureOnlyKeys(value, new Set(["host", "header", "scheme", "pathPrefix"]), owner);
  if (typeof value.host !== "string") throw new Error(`${owner}.host must be a string`);
  let host: string;
  try {
    host = normalizeHostname(value.host);
  } catch (error) {
    throw new Error(`${owner}.host: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (host !== value.host) throw new Error(`${owner}.host must be stored as exact normalized hostname ${host}`);
  const header = safeDisplayText(value.header, `${owner}.header`, 120);
  if (typeof value.scheme !== "string" || (value.scheme !== "bearer" && value.scheme !== "raw")) {
    throw new Error(`${owner}.scheme must be bearer or raw`);
  }
  if (value.pathPrefix === undefined) return { host, header, scheme: value.scheme };
  if (typeof value.pathPrefix !== "string") throw new Error(`${owner}.pathPrefix must be a string`);
  try {
    return { host, header, scheme: value.scheme, pathPrefix: normalizePathPrefix(value.pathPrefix) };
  } catch (error) {
    throw new Error(`${owner}.pathPrefix: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function parseCredential(value: unknown, owner: string): Omit<ServiceCredential, "tokenName"> {
  if (!isRecord(value)) throw new Error(`${owner} must be an object`);
  ensureOnlyKeys(value, new Set(["tokenDescription", "agentEnv", "credentials"]), owner);
  const tokenDescription = safeDisplayText(value.tokenDescription, `${owner}.tokenDescription`, EXPLANATION_MAX_CHARS);
  if (!Array.isArray(value.agentEnv) || value.agentEnv.length === 0) throw new Error(`${owner}.agentEnv must be a non-empty array`);
  const agentEnv = value.agentEnv.map((entry, index) => {
    const name = safeDisplayText(entry, `${owner}.agentEnv[${index}]`, 128);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`${owner}.agentEnv[${index}] is not a valid env name`);
    return name;
  });
  if (new Set(agentEnv).size !== agentEnv.length) throw new Error(`${owner}.agentEnv contains duplicate names`);
  if (!Array.isArray(value.credentials) || value.credentials.length === 0) throw new Error(`${owner}.credentials must be a non-empty array`);
  const credentials = value.credentials.map((entry, index) => parseCredentialPolicy(entry, `${owner}.credentials[${index}]`));
  return { tokenDescription, agentEnv, credentials };
}

function parseParameters(value: unknown, owner: string): Array<Omit<ServiceParameter, "oauthField">> {
  if (!Array.isArray(value)) throw new Error(`${owner} must be an array`);
  return value.map((entry, index) => {
    const itemOwner = `${owner}[${index}]`;
    if (!isRecord(entry)) throw new Error(`${itemOwner} must be an object`);
    ensureOnlyKeys(entry, new Set(["key", "envVar", "description", "pattern", "example"]), itemOwner);
    const key = safeDisplayText(entry.key, `${itemOwner}.key`, 32);
    const envVar = safeDisplayText(entry.envVar, `${itemOwner}.envVar`, 128);
    if (runtimeOwnedAgentEnvNames().includes(envVar)) throw new Error(`${itemOwner}.envVar ${envVar} is runtime-owned`);
    const description = safeDisplayText(entry.description, `${itemOwner}.description`, EXPLANATION_MAX_CHARS);
    const pattern = entry.pattern === undefined ? undefined : safeDisplayText(entry.pattern, `${itemOwner}.pattern`, 256);
    const example = entry.example === undefined ? undefined : safeDisplayText(entry.example, `${itemOwner}.example`, 256);
    return {
      key,
      envVar,
      description,
      ...(pattern !== undefined ? { pattern } : {}),
      ...(example !== undefined ? { example } : {}),
    };
  });
}

function normalizeUserDefinition(raw: unknown, filenameStem?: string): UserServiceDefinitionJson {
  if (!isRecord(raw)) throw new Error("definition must be a JSON object");
  ensureOnlyKeys(raw, new Set([
    "schemaVersion",
    "id",
    "label",
    "revision",
    "hosts",
    "explanations",
    "detect",
    "credential",
    "parameters",
    "neverAutoSuggest",
  ]), "definition");
  if (raw.schemaVersion !== 1) throw new Error("schemaVersion must be 1");
  const id = safeDisplayText(raw.id, "id", 64);
  if (!USER_SERVICE_ID_PATTERN.test(id)) throw new Error(`id must match ${USER_SERVICE_ID_PATTERN.source}`);
  if (filenameStem !== undefined && id !== filenameStem) throw new Error(`id ${id} must match filename stem ${filenameStem}`);
  const label = safeDisplayText(raw.label, "label", LABEL_MAX_CHARS);
  if (typeof raw.revision !== "number" || !Number.isInteger(raw.revision) || raw.revision < 1) {
    throw new Error("revision must be an integer >= 1");
  }
  if (!Array.isArray(raw.hosts) || raw.hosts.length === 0) throw new Error("hosts must be a non-empty array");
  const hosts = raw.hosts.map((entry, index) => parseHost(entry, `hosts[${index}]`));
  const hostNames = hosts.map((host) => host.host);
  if (new Set(hostNames).size !== hostNames.length) throw new Error("hosts must be unique");
  if (!Array.isArray(raw.explanations) || raw.explanations.length === 0) throw new Error("explanations must be a non-empty array");
  const explanations = raw.explanations.map((entry, index) => safeDisplayText(entry, `explanations[${index}]`, EXPLANATION_MAX_CHARS));
  const detect = raw.detect === undefined
    ? undefined
    : (() => {
      if (!Array.isArray(raw.detect)) throw new Error("detect must be an array");
      return raw.detect.map((entry, index) => parseDetectRule(entry, `detect[${index}]`));
    })();
  const credential = raw.credential === undefined ? undefined : parseCredential(raw.credential, "credential");
  const parameters = raw.parameters === undefined ? undefined : parseParameters(raw.parameters, "parameters");
  if (raw.neverAutoSuggest !== undefined && typeof raw.neverAutoSuggest !== "boolean") throw new Error("neverAutoSuggest must be a boolean");
  const definition: UserServiceDefinitionJson = {
    schemaVersion: 1,
    id,
    label,
    revision: raw.revision,
    hosts,
    explanations,
    ...(detect && detect.length > 0 ? { detect } : {}),
    ...(credential ? { credential } : {}),
    ...(parameters && parameters.length > 0 ? { parameters } : {}),
    ...(raw.neverAutoSuggest === true ? { neverAutoSuggest: true } : {}),
  };
  const svc = userDefinitionToService(definition);
  const issues = validateServiceDefinition(svc, { origin: "user" });
  if (issues.length > 0) throw new Error(issues.join("; "));
  return definition;
}

export function userDefinitionToService(definition: UserServiceDefinitionJson): Service {
  return {
    id: definition.id,
    label: definition.label,
    revision: definition.revision,
    hosts: definition.hosts,
    detect: definition.detect ?? [],
    explanations: definition.explanations,
    ...(definition.neverAutoSuggest === true ? { neverAutoSuggest: true as const } : {}),
    ...(definition.parameters && definition.parameters.length > 0 ? { parameters: definition.parameters } : {}),
    ...(definition.credential
      ? {
        credential: {
          tokenName: definition.id,
          tokenDescription: definition.credential.tokenDescription,
          agentEnv: definition.credential.agentEnv,
          credentials: definition.credential.credentials,
        },
      }
      : {}),
  };
}

function readRegularFileNoFollow(filePath: string): string {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile()) throw new Error("definition file must be a regular file");
  if (stat.size > USER_DEFINITION_MAX_BYTES) throw new Error("definition file is too large");
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const openStat = fs.fstatSync(fd);
    if (!openStat.isFile()) throw new Error("definition file must be a regular file");
    if (openStat.size > USER_DEFINITION_MAX_BYTES) throw new Error("definition file is too large");
    return fs.readFileSync(fd, "utf8");
  } finally {
    fs.closeSync(fd);
  }
}

export function readAndValidateUserServiceFile(filePath: string): LoadedUserServiceDefinition {
  const resolved = path.resolve(filePath);
  const filename = path.basename(resolved);
  if (!filename.endsWith(".json") || filename.endsWith(".meta.json")) throw new Error("definition filename must be <id>.json");
  const filenameStem = filename.slice(0, -".json".length);
  const text = readRegularFileNoFollow(resolved);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const definition = normalizeUserDefinition(parsed, filenameStem);
  return {
    svc: userDefinitionToService(definition),
    path: resolved,
    digest: userServiceDigest(definition),
    definition,
  };
}

function invalidateEnvCollisions(catalog: UserServiceCatalog): void {
  const curatedEnv = new Set(serviceAgentEnvNames(SERVICES));
  const envOwners = new Map<string, string[]>();
  for (const loaded of Object.values(catalog.services)) {
    const ownedEnv = [
      ...(loaded.svc.credential?.agentEnv ?? []),
      ...(loaded.svc.parameters ?? []).map((parameter) => parameter.envVar),
    ];
    for (const envName of ownedEnv) {
      if (curatedEnv.has(envName)) {
        catalog.invalid.push({
          id: loaded.svc.id,
          path: loaded.path,
          reason: `agent env ${envName} collides with a curated service`,
        });
        delete catalog.services[loaded.svc.id];
        continue;
      }
      const owners = envOwners.get(envName) ?? [];
      owners.push(loaded.svc.id);
      envOwners.set(envName, owners);
    }
  }
  const duplicateIds = new Map<string, string>();
  for (const [envName, owners] of envOwners) {
    const liveOwners = owners.filter((id) => catalog.services[id]);
    if (liveOwners.length <= 1) continue;
    for (const id of liveOwners) duplicateIds.set(id, envName);
  }
  for (const [id, envName] of duplicateIds) {
    const loaded = catalog.services[id];
    if (!loaded) continue;
    catalog.invalid.push({
      id,
      path: loaded.path,
      reason: `agent env ${envName} collides with another user-defined service`,
    });
    delete catalog.services[id];
  }
}

export function loadUserServiceCatalog(projectRoot: string, env: NodeJS.ProcessEnv = process.env): UserServiceCatalog {
  const dir = userServicesDir(projectRoot, env);
  const catalog: UserServiceCatalog = { services: {}, invalid: [], dir };
  let entries: string[];
  try {
    entries = fs.readdirSync(dir).filter((entry) => entry.endsWith(".json") && !entry.endsWith(".meta.json")).sort();
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return catalog;
    throw error;
  }
  for (const entry of entries) {
    const filePath = path.join(dir, entry);
    const id = entry.slice(0, -".json".length);
    try {
      const loaded = readAndValidateUserServiceFile(filePath);
      catalog.services[loaded.svc.id] = loaded;
    } catch (error) {
      catalog.invalid.push({
        id,
        path: filePath,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
  invalidateEnvCollisions(catalog);
  catalog.invalid.sort((left, right) => left.id.localeCompare(right.id));
  return catalog;
}

export function lookupUserService(projectRoot: string, env: NodeJS.ProcessEnv, id: string): LoadedUserServiceDefinition | InvalidUserServiceDefinition | undefined {
  if (!isUserServiceId(id)) return undefined;
  const catalog = loadUserServiceCatalog(projectRoot, env);
  return catalog.services[id] ?? catalog.invalid.find((entry) => entry.id === id);
}

export function combinedServiceRegistry(projectRoot: string, env: NodeJS.ProcessEnv = process.env): Record<string, Service> {
  const catalog = loadUserServiceCatalog(projectRoot, env);
  return {
    ...SERVICES,
    ...Object.fromEntries(Object.entries(catalog.services).map(([id, loaded]) => [id, loaded.svc])),
  };
}

function writeHostOwnedFileNoFollow(filePath: string, content: string, options: { replace: boolean; mode?: number }): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile()) throw new Error(`${filePath} exists and is not a regular file`);
    if (!options.replace) throw new Error(`${filePath} already exists; pass --replace to overwrite`);
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
  }
  const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`);
  const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, options.mode ?? 0o600);
  try {
    fs.writeFileSync(fd, content, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
}

export function destinationPathForUserService(projectRoot: string, env: NodeJS.ProcessEnv, id: string): string {
  return path.join(userServicesDir(projectRoot, env), `${id}.json`);
}

export function metadataPathForUserService(projectRoot: string, env: NodeJS.ProcessEnv, id: string): string {
  return path.join(userServicesDir(projectRoot, env), USER_SERVICE_META_DIR, `${id}.json`);
}

export function writeUserServiceDefinition(
  projectRoot: string,
  env: NodeJS.ProcessEnv,
  definition: UserServiceDefinitionJson,
  options: { replace: boolean; provenance?: { importedFrom: string; importedAt: string; digest: string } },
): string {
  const destination = destinationPathForUserService(projectRoot, env, definition.id);
  writeHostOwnedFileNoFollow(destination, `${JSON.stringify(definition, null, 2)}\n`, { replace: options.replace, mode: 0o600 });
  if (options.provenance) {
    const metaPath = metadataPathForUserService(projectRoot, env, definition.id);
    writeHostOwnedFileNoFollow(metaPath, `${JSON.stringify(options.provenance, null, 2)}\n`, { replace: true, mode: 0o600 });
  }
  return destination;
}

export function removeUserServiceDefinition(projectRoot: string, env: NodeJS.ProcessEnv, id: string): { removed: boolean; path: string } {
  const destination = destinationPathForUserService(projectRoot, env, id);
  try {
    const stat = fs.lstatSync(destination);
    if (!stat.isFile()) throw new Error(`${destination} exists and is not a regular file`);
    fs.unlinkSync(destination);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return { removed: false, path: destination };
    throw error;
  }
  try {
    fs.unlinkSync(metadataPathForUserService(projectRoot, env, id));
  } catch {
    // Metadata is best-effort audit context; deleting the definition is the user
    // visible operation.
  }
  return { removed: true, path: destination };
}

export function agentEnvOwnedByUserServices(projectRoot: string, env: NodeJS.ProcessEnv): Set<string> {
  const catalog = loadUserServiceCatalog(projectRoot, env);
  return new Set(Object.values(catalog.services).flatMap((loaded) => loaded.svc.credential?.agentEnv ?? []));
}

export function isPlaceholderValue(value: string | undefined): boolean {
  return value === RUNFREE_PLACEHOLDER_VALUE;
}

// In-memory validation for wizard-built definitions: same strict parse and
// invariants as a file import, without ever placing unvalidated content in the
// live services directory.
export function validateUserServiceDefinitionObject(raw: unknown): Omit<LoadedUserServiceDefinition, "path"> {
  const definition = normalizeUserDefinition(raw);
  return {
    svc: userDefinitionToService(definition),
    digest: userServiceDigest(definition),
    definition,
  };
}

export function readUserServiceImportSource(filePath: string): { text: string; loaded: LoadedUserServiceDefinition } {
  const resolved = path.resolve(filePath);
  const text = readRegularFileNoFollow(resolved);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const definition = normalizeUserDefinition(parsed);
  const loaded: LoadedUserServiceDefinition = {
    svc: userDefinitionToService(definition),
    path: resolved,
    digest: userServiceDigest(definition),
    definition,
  };
  return { text, loaded };
}
