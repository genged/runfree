import { isDeepStrictEqual } from "node:util";
// Shared admin enforcement core (Phase 6 split of options.ts): ambient
// admin-state access, the network-policy and host-owned token/source stores,
// proxy-runtime + security-contract validation, token sync, and reloadProxy.
// This is the one tightly-coupled base module the focused per-family
// enforcement modules import from; it never imports them (no cycles).

import { AsyncLocalStorage } from "node:async_hooks";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { LIFECYCLE_OPERATION_BUDGET_MS, withLifecycleOperationBudget } from "../runtime/lifecycle-operation-budget.ts";
import { assertSessionDisruptionAuthorized } from "../runtime/session-disruption.ts";
import { tryAcquireProjectLifecycleLockWithRetry, type ProjectLifecycleLock } from "../runtime/sessions.ts";
import {
  type CredentialPolicyJson,
  type LoadedNetworkPolicy,
  type PolicyJson,
  READ_ONLY_METHODS,
  type RequestPolicyJson,
  TOKEN_NAME_PATTERN,
  type WriteAction,
  assertTokenName,
  credentialSchemeList,
  describeRequestRule,
  isCredentialScheme,
  isTokenName,
  normalizeHostname,
  normalizePathPrefix,
  validateNetworkPolicy,
} from "@runfree/runtime-contracts/network-policy";
import {
  firewallStatusPath,
  parseGenerationStatusLine,
  requestProxyStatusPath,
  type ParsedGenerationStatus,
} from "@runfree/runtime-contracts/proxy-status";
import {
  RUNFREE_PLACEHOLDER_VALUE,
  SERVICES,
  USER_SERVICE_PREFIX,
  isUserServiceId,
  type Service,
  type ServiceOAuthCredential,
  service,
  serviceAgentEnvNames,
  serviceHasCredential,
  serviceHasOAuthCredential,
  serviceParameters,
  serviceHostNames,
} from "../../../../scripts/services.ts";
import {
  agentEnvOwnedByUserServices,
} from "../user-services.ts";
import {
  isPathInsideByRealpath,
  isPathInside,
  safeReadProjectFile,
  safeReplaceProjectFile,
} from "../safe-fs.ts";
import {
  regularExecutableRealpath as hostRegularExecutableRealpath,
  resolveHostExecutable as hostResolveHostExecutable,
  sanitizedHostExecutionEnv,
} from "../host-path.ts";
import { flushWarnings, runfreeError, runfreeLog, warn } from "../warnings.ts";
import {
  mcpApprovalPath,
  mcpInventory,
  mcpOAuthCallbackPort,
  writeOAuthMediationPolicy,
  type McpAgent,
  type McpSourceScope,
  type OAuthMediationPolicyForWrite,
  type OAuthProviderPolicyForWrite,
} from "../runtime/mcp.ts";
import { projectControlPaths, projectInfo, readRawProjectConfig, type ProjectInfo } from "../config.ts";
import {
  readActiveControlSelection,
  readActiveEffectiveControl,
  readConvergedPolicyReceipt,
} from "../control/effective.ts";
import { tryAcquireControlLock, type ControlLock } from "../control/lock.ts";
import { projectRunfreePath } from "../runfree-consumer-registry.ts";
import {
  compareHostBootId,
  compareHostProcessStart,
  hostBootId,
  hostProcessStart,
} from "../runtime/host-identity.ts";
import { activeRuntimePlanFromContext } from "../runtime/plan.ts";
import type { ActiveRuntimePlan } from "../runtime/plan.ts";
import {
  composeServiceContainerFilters,
  corroboratedComposeProjectContainerFilters,
} from "../runtime/container-inventory.ts";
import {
  parseRuntimeContainerInspectRows,
  runtimeContainerInspectFormat,
} from "../runtime/docker.ts";
import {
  LOCK_PIDLESS_GRACE_MS,
  lockAgeMs,
  lockWrittenOnPreviousBoot,
  processAlive,
  stampLockOwner,
} from "../runtime/sessions.ts";
import {
  createRuntimeSecurityContract,
  parseRuntimeSecurityContractProbe,
  runtimeSecurityContractProbeScript,
  validateRuntimeSecurityContractEvidence,
  type RuntimeContainerContract,
  type RuntimeSecurityContract,
  type RuntimeSecurityContractEvidence,
} from "../runtime/security-contract.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { failClosedSpawnStatus } from "../runtime/spawn-status.ts";
import {
  effectiveControlPlaneComponentEvidenceIssue,
  runtimeComponentEvidenceIssue,
} from "../runtime/upgrade-classification.ts";
import { readEffectiveControlPlaneV2 } from "../runtime/component-state-v2.ts";
import { readControlPlaneRebindTransaction, serializeControlPlaneRebindTransaction, CONTROL_PLANE_REBIND_PHASES } from "../runtime/control-plane-rebind.ts";
import {
  AdminExit,
  createAdminState,
} from "./context.ts";
import type { AdminState } from "./types.ts";
import {
  TokenResolutionError,
  isTransientTokenResolutionError,
  type TokenResolutionLedger,
  type TokenResolutionReceipt,
} from "../token-resolution.ts";
import { stableJsonDroppingUndefined as stableJson, sha256Hex, isRecord } from "../strict-primitives.ts";
import { remedy } from "../remedies.ts";


export type TokenSource =
  | ({ source: "env"; env: string } & TokenRefreshConfig)
  | ({ source: "1password"; ref: string } & TokenRefreshConfig)
  | ({ source: "named"; name: string } & TokenRefreshConfig)
  // Legacy config from the pre-tmpfs implementation. Kept so status/unset can
  // handle old metadata without silently reading plaintext local secret files.
  | ({ source: "file"; path: string } & TokenRefreshConfig)
  | ({ source: "cmd"; command: string } & TokenRefreshConfig);

type TokenRefreshConfig = {
  refreshEverySeconds?: number;
  runfreeUserServiceOwner?: string;
};

type TokenSourceConfig = Record<string, TokenSource>;

export type CommandSource = {
  type: "command";
  argv: string[];
  displayArgv: string[];
  createdAt: string;
};

type SecretRef = { source: "1password"; ref: string };

export type JwtAlgorithm = "ES256";

export type JwtSource = {
  type: "jwt";
  alg: JwtAlgorithm;
  privateKey: SecretRef;
  headers: Record<string, string>;
  claims: Record<string, string>;
  ttlSeconds: number;
  createdAt: string;
};

export type NamedSource = CommandSource | JwtSource;

export type SourceRegistry = Record<string, NamedSource>;

type TokenSyncState = "ok" | "stale" | "failed";

type TokenSyncRecord = {
  source?: string;
  ok: boolean;
  // Tri-state sync outcome. Absent in records written by older CLIs (derive
  // from `ok`). "stale" means a classified-transient resolution failure kept a
  // receipt-proven proxy tmpfs value (see heldValueResolvedAt).
  state?: TokenSyncState;
  heldValueResolvedAt?: string;
  syncedAt: string;
  message: string;
};

type TokenSyncStatus = Record<string, TokenSyncRecord>;
export type ProxyRuntimeState = "ready" | "not-running" | "docker-unavailable" | "validation-required" | "proxy-unreachable";
type ProxyRuntime = {
  id?: string;
  storeGeneration?: string;
  state: ProxyRuntimeState;
  validationMessage?: string;
};
export type JwtPrivateKeyCacheEntry = {
  fingerprint: string;
  key: crypto.KeyObject;
};

type SourceSecretCache = {
  jwtPrivateKeys: Map<string, JwtPrivateKeyCacheEntry>;
};

type TokenResolutionOptions = {
  quiet?: boolean;
  sourceRegistry?: SourceRegistry;
  sourceSecretCache?: SourceSecretCache;
  verbose?: boolean;
};

// Sync modes (see the convergent proxy token store design spec):
// - "source-truth" (default): re-read every configured source. This is the
//   path that observes vault deletion, env unsets, source removal, and
//   rotation. Explicit `runfree credential sync`, startup/full syncs, and due
//   scheduled refreshes run here.
// - "convergence": receipt-gated. A token whose persisted receipt matches the
//   current source fingerprint and live store generation — and whose tmpfs
//   file the proxy provably holds — is skipped without re-resolving. Used by
//   policy-convergence and quiet admin reloads so an unrelated
//   `runfree host`/`service`/`token` command never re-prompts for held
//   credentials. Receipts are advisory for skipping work, never for granting
//   it; convergence intentionally does not claim source-revocation detection.
export type TokenSyncMode = "source-truth" | "convergence";

type TokenSyncOptions = TokenResolutionOptions & {
  exitOnFailure?: boolean;
  resolutionLedger?: TokenResolutionLedger;
  mode?: TokenSyncMode;
};
export type EffectiveTokenRefresh =
  | { mode: "manual" }
  | { mode: "explicit"; seconds: number; sourceName?: string; ttlSeconds?: number }
  | { mode: "derived"; seconds: number; sourceName: string; ttlSeconds: number };

type TokenDueDecision =
  | { due: true; key?: string; reason: string; sourceFingerprint?: string }
  | { due: false; key: string; nextDueAt?: number; reason: string; sourceFingerprint: string };

const defaultAdminState = createAdminState();
// Blocking sleep for the synchronous admin flows (lock waits, readiness and
// convergence polls). One shared buffer; the value never changes, so wait
// always times out after ms.
const sleepSyncBuffer = new Int32Array(new SharedArrayBuffer(4));
function sleepSyncMs(ms: number): void {
  Atomics.wait(sleepSyncBuffer, 0, 0, ms);
}

// Test-only millisecond override, honored only under the fake-docker harness.
function fakeDockerMsOverride(value: string | undefined): number | undefined {
  if (childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && value && /^[0-9]{1,6}$/.test(value)) return Number(value);
  return undefined;
}
const adminStateStorage = new AsyncLocalStorage<AdminState>();
const CONTAINER_SECRET_DIR = "/run/runfree-proxy-secrets";
const RUNTIME_VALIDATION_MARKER_PATH = "/run/runfree-runtime-validation.json";
const PROXY_RUNTIME_USER = "1001:1001";
const SERVICE_AGENT_ENV_NAMES = new Set(serviceAgentEnvNames(SERVICES));

export function currentAdminState(): AdminState {
  return adminStateStorage.getStore() ?? defaultAdminState;
}

export function projectRoot(): string {
  return currentAdminState().projectRoot;
}

export function policyPath(): string {
  return currentAdminState().policyPath;
}

function projectId(): string {
  return currentAdminState().projectId;
}

function tokenConfigPath(): string {
  return currentAdminState().tokenConfigPath;
}

export function sourceConfigPath(): string {
  return currentAdminState().sourceConfigPath;
}

function agentEnvPath(): string {
  return currentAdminState().agentEnvPath;
}

export function stateDir(): string {
  return currentAdminState().stateDir;
}

function syncStatusPath(): string {
  return currentAdminState().syncStatusPath;
}

function composeProjectNameForAdmin(): string {
  return currentAdminState().composeProjectName;
}

function validatedRuntime(): AdminState["validatedRuntime"] {
  return currentAdminState().validatedRuntime;
}

export function childEnv(): NodeJS.ProcessEnv {
  return currentAdminState().env.child;
}

function dockerChildEnv(): NodeJS.ProcessEnv {
  return currentAdminState().env.dockerClient;
}

// Refusal inside an admin action: rendered once by `runAdminAction` (or by
// `main()` if it escapes a command prologue), after any buffered warnings.
export function die(message: string): never {
  throw new AdminExit(message);
}

export function readJsonFile<T>(filePath: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return fallback;
    throw error;
  }
}

export function writeJsonFile(filePath: string, value: unknown, mode = 0o600): void {
  if (isPathInside(projectRoot(), filePath)) {
    safeReplaceProjectFile(projectRoot(), filePath, `${JSON.stringify(value, null, 2)}\n`, mode);
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode });
  fs.renameSync(tmp, filePath);
  fs.chmodSync(filePath, mode);
}

function writeSafeTextFile(filePath: string, contents: string, mode: number): void {
  if (isPathInside(projectRoot(), filePath)) {
    safeReplaceProjectFile(projectRoot(), filePath, contents, mode);
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, contents, { mode });
  fs.renameSync(tmp, filePath);
  fs.chmodSync(filePath, mode);
}

export function policyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}


export { isRecord };

function sha256Json(value: unknown): string {
  return sha256Hex(stableJson(value));
}

export function loadPolicy(): LoadedNetworkPolicy {
  if (currentAdminState().policyAccess === "effective-read-only"
    && !currentAdminState().effectiveControlSelected) {
    die([
      "no effective policy generation is selected for this project yet",
      "start the runtime to review and select controls: runfree up",
      "inspect approval state with: runfree policy status",
    ].join("\n"));
  }
  try {
    return validateNetworkPolicy(readJsonFile<PolicyJson>(policyPath(), { hosts: [], tokens: {} }), policyPath());
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
}


export function parseDurationSeconds(value: string, optionName: string): number {
  const match = /^([1-9][0-9]*)([smhd]?)$/.exec(value.trim());
  if (!match) die(`${optionName} must be a positive duration like 30s, 18m, 1h, or 150d`);
  const amount = Number(match[1]);
  const unit = match[2] || "s";
  const multiplier = unit === "d" ? 86400 : unit === "h" ? 3600 : unit === "m" ? 60 : 1;
  const seconds = amount * multiplier;
  if (!Number.isSafeInteger(seconds) || seconds <= 0) die(`${optionName} is too large`);
  return seconds;
}

export function formatDurationSeconds(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

export function credentialRefsForHost(policy: PolicyJson, host: string): Array<{ tokenName: string; credential: CredentialPolicyJson }> {
  const refs: Array<{ tokenName: string; credential: CredentialPolicyJson }> = [];
  for (const [tokenName, tokenPolicy] of Object.entries(policy.tokens ?? {})) {
    for (const credential of tokenPolicy.credentials) {
      if (credential.host === host) refs.push({ tokenName, credential });
    }
  }
  return refs;
}

export function normalizeCliHost(input: string): string {
  try {
    return normalizeHostname(input);
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
}

// A typed request-rule selection (which restriction flags the user chose):
// `--read-only`, repeatable `--method`, repeatable `--request-path-prefix` (a
// request *permission* scope, unlike the credential `--path-prefix` injection
// scope), and `--deny-git-push`. The yargs `host` command module builds this
// directly; `buildRequestRule` normalizes it into a requests entry.
export type RequestRuleInput = {
  readOnly: boolean;
  methods: string[];
  pathPrefixes: string[];
  denyGitPush: boolean;
};

export function describeRequestRules(rule: RequestPolicyJson | undefined): string {
  return describeRequestRule(rule);
}

function _rulesPermitWriteMethods(policy: PolicyJson, host: string): boolean {
  const methods = policy.requests?.[host]?.methods;
  if (!methods) return true;
  return methods.some((method) => !(READ_ONLY_METHODS as readonly string[]).includes(method));
}

// --- Host: typed intents + enforcement ----------------------------------------
//
// Enforcement re-validates intent (normalizeCliHost) and mutates policy. Per the
// intent-vs-enforcement principle, these take typed intent and know nothing about
// argv. `ensureDomainAllowed` is shared with host/token/service; the removed
// `--category`/`--note` options are excluded by the yargs grammar, so no
// option-map is threaded through.

export type DomainAddInput = {
  host: string;
  requestRule?: RequestRuleInput;
  reloadProxy: boolean;
};
export type DomainRemoveInput = { host: string; reloadProxy: boolean };
export type DomainExplainInput = { host: string };
export type DomainRulesInput = {
  host: string;
  clear: boolean;
  write?: WriteAction;
  requestRule?: RequestRuleInput;
  reloadProxy: boolean;
};
export type DomainMigrateInput = { reloadProxy: boolean };

export function ensureStateDirs(): void {
  fs.mkdirSync(path.dirname(tokenConfigPath()), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.dirname(sourceConfigPath()), { recursive: true, mode: 0o700 });
  fs.mkdirSync(stateDir(), { recursive: true, mode: 0o700 });
}

export function parseTokenSourceConfig(raw: unknown, sourcePath: string): TokenSourceConfig {
  if (!isRecord(raw)) die(`${displayProjectPath(sourcePath)} must be a JSON object`);
  const config: TokenSourceConfig = {};
  for (const [tokenName, value] of Object.entries(raw)) {
    assertValidTokenName(tokenName);
    if (!isRecord(value) || typeof value.source !== "string") {
      die(`${tokenName}: credential source entry must be an object`);
    }
    const refresh = parseRefreshEverySeconds(tokenName, value);
    if (value.source === "env") {
      if (typeof value.env !== "string" || value.env.trim() === "") die(`${tokenName}: env credential source requires env`);
      config[tokenName] = { source: "env", env: value.env, ...refresh };
      continue;
    }
    if (value.source === "1password") {
      if (typeof value.ref !== "string" || value.ref.trim() === "") die(`${tokenName}: 1password credential source requires ref`);
      config[tokenName] = { source: "1password", ref: value.ref, ...refresh };
      continue;
    }
    if (value.source === "named") {
      if (typeof value.name !== "string" || !isTokenName(value.name)) die(`${tokenName}: named credential source requires a valid source name`);
      config[tokenName] = { source: "named", name: value.name, ...refresh };
      continue;
    }
    if (value.source === "file") {
      if (typeof value.path !== "string" || value.path.trim() === "") die(`${tokenName}: legacy file credential source requires path`);
      config[tokenName] = { source: "file", path: value.path, ...refresh };
      continue;
    }
    if (value.source === "cmd") {
      const command = typeof value.command === "string" ? value.command : "";
      config[tokenName] = { source: "cmd", command, ...refresh };
      continue;
    }
    die(`${tokenName}: unsupported credential source ${(value as { source: string }).source}`);
  }
  return config;
}

export function loadTokenConfig(): TokenSourceConfig {
  return parseTokenSourceConfig(readJsonFile<unknown>(tokenConfigPath(), {}), tokenConfigPath());
}

export function readAgentEnv(): Record<string, string> {
  try {
    const entries: Record<string, string> = {};
    const source = isPathInside(projectRoot(), agentEnvPath())
      ? safeReadProjectFile(projectRoot(), agentEnvPath()) ?? ""
      : fs.readFileSync(agentEnvPath(), "utf8");
    for (const line of source.split(/\r?\n/)) {
      if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
      const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
      if (!match) die(`invalid agent env line in ${agentEnvPath()}: ${line}`);
      entries[match[1]] = match[2];
    }
    return entries;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return {};
    throw error;
  }
}

export function saveAgentEnv(entries: Record<string, string>): void {
  const lines = Object.entries(entries)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`);
  // Every line must read back through readAgentEnv's line regex; otherwise
  // one bad value wedges every later enable, explain, and publication.
  for (const line of lines) {
    if (!/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.test(line)) {
      die(`agent env ${line.slice(0, line.indexOf("=") === -1 ? line.length : line.indexOf("="))} cannot be written as a single line`);
    }
  }
  writeSafeTextFile(agentEnvPath(), `${lines.join("\n")}${lines.length > 0 ? "\n" : ""}`, 0o600);
}

export function ensureAgentEnvPlaceholders(envNames: string[]): { added: string[]; unchanged: string[] } {
  const entries = readAgentEnv();
  const added: string[] = [];
  const unchanged: string[] = [];

  for (const envName of envNames) {
    if (entries[envName] === RUNFREE_PLACEHOLDER_VALUE) {
      unchanged.push(envName);
      continue;
    }
    entries[envName] = RUNFREE_PLACEHOLDER_VALUE;
    added.push(envName);
  }

  if (added.length > 0) saveAgentEnv(entries);
  return { added, unchanged };
}

export function normalizeAgentEnvPlaceholders(): void {
  const entries = readAgentEnv();
  const oauthVisibleEnv = serviceHostOwnedAgentEnvValues(entries);
  let changed = false;
  const serviceEnvNames = new Set([
    ...SERVICE_AGENT_ENV_NAMES,
    ...agentEnvOwnedByUserServices(projectRoot(), childEnv()),
  ]);
  const customNames: string[] = [];
  for (const envName of Object.keys(entries)) {
    const oauthValue = oauthVisibleEnv[envName];
    if (oauthValue !== undefined) {
      if (entries[envName] !== oauthValue) {
        entries[envName] = oauthValue;
        changed = true;
      }
      continue;
    }
    if (!serviceEnvNames.has(envName)) customNames.push(envName);
    if (entries[envName] === RUNFREE_PLACEHOLDER_VALUE) continue;
    entries[envName] = RUNFREE_PLACEHOLDER_VALUE;
    changed = true;
  }
  if (changed) saveAgentEnv(entries);
  if (customNames.length > 0) {
    customNames.sort((left, right) => left.localeCompare(right));
    const currentAgentEnvPath = agentEnvPath();
    const displayAgentEnvPath = path.isAbsolute(currentAgentEnvPath) && isPathInside(projectRoot(), currentAgentEnvPath)
      ? path.relative(projectRoot(), currentAgentEnvPath)
      : currentAgentEnvPath;
    warn(`custom agent env entries in ${displayAgentEnvPath} are exposed as placeholders only: ${customNames.join(", ")}`);
  }
}

export function loadTokenStatus(): TokenSyncStatus {
  return readJsonFile<TokenSyncStatus>(syncStatusPath(), {});
}

export function saveTokenConfig(config: TokenSourceConfig): void {
  writeJsonFile(tokenConfigPath(), config, 0o600);
}

export function saveTokenStatus(status: TokenSyncStatus): void {
  writeJsonFile(syncStatusPath(), status, 0o600);
}

function parseRefreshEverySeconds(owner: string, value: Record<string, unknown>): TokenRefreshConfig {
  const config: TokenRefreshConfig = {};
  if (value.refreshEverySeconds !== undefined) {
    if (typeof value.refreshEverySeconds !== "number" || !Number.isInteger(value.refreshEverySeconds) || value.refreshEverySeconds <= 0) {
      die(`${owner}: refreshEverySeconds must be a positive integer`);
    }
    config.refreshEverySeconds = value.refreshEverySeconds;
  }
  if (value.runfreeUserServiceOwner !== undefined) {
    if (typeof value.runfreeUserServiceOwner !== "string" || !isUserServiceId(value.runfreeUserServiceOwner)) {
      die(`${owner}: runfreeUserServiceOwner must be a valid user-defined service id`);
    }
    config.runfreeUserServiceOwner = value.runfreeUserServiceOwner;
  }
  return config;
}

function validateKeyValueRecord(owner: string, value: unknown): Record<string, string> {
  if (!isRecord(value)) die(`${owner} must be an object`);
  const output: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "string") die(`${owner}.${key} must be a string`);
    output[key] = entry;
  }
  return output;
}

function validateJwtSource(name: string, value: Record<string, unknown>): JwtSource {
  if (value.alg !== "ES256") die(`${name}: jwt alg must be ES256`);
  if (!isRecord(value.privateKey) || value.privateKey.source !== "1password" || typeof value.privateKey.ref !== "string" || !value.privateKey.ref.startsWith("op://")) {
    die(`${name}: jwt privateKey must be a 1Password reference`);
  }
  if (typeof value.ttlSeconds !== "number" || !Number.isInteger(value.ttlSeconds) || value.ttlSeconds <= 0) {
    die(`${name}: jwt ttlSeconds must be a positive integer`);
  }
  if (typeof value.createdAt !== "string" || value.createdAt.trim() === "") die(`${name}: createdAt must be a string`);
  const headers = validateKeyValueRecord(`${name}: jwt headers`, value.headers ?? {});
  if (headers.alg !== undefined) die(`${name}: jwt header alg is reserved`);
  const claims = validateKeyValueRecord(`${name}: jwt claims`, value.claims ?? {});
  if (claims.iat !== undefined) die(`${name}: jwt claim iat is reserved`);
  if (claims.exp !== undefined) die(`${name}: jwt claim exp is reserved`);
  return {
    type: "jwt",
    alg: "ES256",
    privateKey: { source: "1password", ref: value.privateKey.ref },
    headers,
    claims,
    ttlSeconds: value.ttlSeconds,
    createdAt: value.createdAt,
  };
}

function validateSourceRegistry(raw: unknown, registryPath = sourceConfigPath()): SourceRegistry {
  if (!isRecord(raw)) die(`${displayProjectPath(registryPath)} must be a JSON object`);
  const registry: SourceRegistry = {};
  for (const [name, value] of Object.entries(raw)) {
    if (!isTokenName(name)) die(`invalid source name in registry: ${name}`);
    if (!isRecord(value) || typeof value.type !== "string") die(`${name}: source must be an object`);
    if (value.type === "jwt") {
      registry[name] = validateJwtSource(name, value);
      continue;
    }
    if (value.type !== "command") die(`${name}: source must be a command or jwt object`);
    if (!Array.isArray(value.argv) || value.argv.length === 0 || !value.argv.every((item) => typeof item === "string")) {
      die(`${name}: argv must be a non-empty string array`);
    }
    if (!Array.isArray(value.displayArgv) || value.displayArgv.length === 0 || !value.displayArgv.every((item) => typeof item === "string")) {
      die(`${name}: displayArgv must be a non-empty string array`);
    }
    if (typeof value.createdAt !== "string" || value.createdAt.trim() === "") die(`${name}: createdAt must be a string`);
    registry[name] = {
      type: "command",
      argv: value.argv,
      displayArgv: value.displayArgv,
      createdAt: value.createdAt,
    };
  }
  return registry;
}

export function loadSourceRegistry(): SourceRegistry {
  return validateSourceRegistry(readJsonFile<unknown>(sourceConfigPath(), {}));
}

export function assertKnownSourceName(name: string): void {
  if (!isTokenName(name)) die(`invalid source name: ${name} (must match ${TOKEN_NAME_PATTERN.source})`);
}

// Sanitized host PATH rules are shared with init-wizard helper detection in
// packages/cli/src/host-path.ts.
export function regularExecutableRealpath(candidatePath: string): string | undefined {
  return hostRegularExecutableRealpath(projectRoot(), candidatePath);
}

export function resolveHostExecutable(command: string): string | undefined {
  return hostResolveHostExecutable(projectRoot(), childEnv(), command);
}

function pathLikeSourceArgCandidates(arg: string): string[] {
  const candidates = [arg];
  const equalsIndex = arg.indexOf("=");
  if (equalsIndex > 0 && equalsIndex < arg.length - 1) candidates.push(arg.slice(equalsIndex + 1));
  return candidates.filter((candidate) => {
    return path.isAbsolute(candidate)
      || candidate.startsWith(".")
      || candidate.includes("/")
      || candidate.includes("\\");
  });
}

export function assertSourceArgumentsOutsideProject(args: string[]): void {
  for (const arg of args) {
    for (const candidate of pathLikeSourceArgCandidates(arg)) {
      const resolved = path.resolve(hostOwnedSourceCwd(), candidate);
      if (isPathInsideByRealpath(projectRoot(), resolved)) {
        throw new Error(`source command argument must not reference project-controlled path: ${arg}`);
      }
    }
  }
}

function sourceExecutionEnv(): NodeJS.ProcessEnv {
  return sanitizedHostExecutionEnv(projectRoot(), childEnv());
}

function hostOwnedSourceCwd(): string {
  fs.mkdirSync(path.dirname(sourceConfigPath()), { recursive: true, mode: 0o700 });
  return path.dirname(sourceConfigPath());
}

function commandSourceTimeoutMs(): number {
  const override = childEnv().RUNFREE_TEST_COMMAND_SOURCE_TIMEOUT_MS;
  if (childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && override && /^[1-9][0-9]{0,5}$/.test(override)) {
    return Number(override);
  }
  return 10_000;
}

function opReadTimeoutMs(): number {
  const testOverride = childEnv().RUNFREE_TEST_OP_READ_TIMEOUT_MS;
  if (childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && testOverride && /^[1-9][0-9]{0,5}$/.test(testOverride)) {
    return Number(testOverride);
  }
  const override = childEnv().RUNFREE_OP_READ_TIMEOUT_MS;
  if (override && /^[1-9][0-9]{3,5}$/.test(override)) return Number(override);
  return 60_000;
}

function sanitizedStderrFirstLine(stderr: unknown): string | undefined {
  if (typeof stderr !== "string") return undefined;
  const line = stderr.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").split(/\r?\n/).map((entry) => entry.trim()).find(Boolean);
  if (!line) return undefined;
  const redacted = line.replace(
    /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{40,})\b/g,
    "[redacted]",
  );
  return redacted.length > 200 ? `${redacted.slice(0, 200)}...` : redacted;
}

function opReadFailureMessage(stderr: unknown): string {
  const detail = sanitizedStderrFirstLine(stderr);
  return detail ? `op read failed: ${detail}` : "op read failed";
}

function opDocumentGetFailureMessage(stderr: unknown): string {
  const detail = sanitizedStderrFirstLine(stderr);
  return detail ? `op document get failed: ${detail}` : "op document get failed";
}

function adminVerbose(options: { verbose?: boolean } | undefined, message: string): void {
  if (options?.verbose) runfreeLog(`verbose: ${message}`);
}

type OnePasswordDocumentRef = {
  item: string;
  vault: string;
};

function decodeOnePasswordRefPart(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error("1Password document references must use valid URI escaping");
  }
}

function parseOnePasswordDocumentRef(ref: string): OnePasswordDocumentRef | undefined {
  if (!ref.startsWith("op://") || ref.includes("?") || ref.includes("#")) return undefined;
  const parts = ref.slice("op://".length).split("/");
  if (parts.length !== 2 || parts.some((part) => part === "")) return undefined;
  return {
    vault: decodeOnePasswordRefPart(parts[0]),
    item: decodeOnePasswordRefPart(parts[1]),
  };
}

function readSpawnedOpOutput(result: childProcess.SpawnSyncReturns<string>, emptyMessage: string): string {
  const value = typeof result.stdout === "string" ? result.stdout.replace(/\r?\n$/, "") : "";
  if (!value) {
    throw new TokenResolutionError({
      classification: "definitive",
      sourceKind: "1password",
      code: "empty-value",
      safeMessage: emptyMessage,
    });
  }
  return value;
}

// Provider adapter for `op` diagnostics: 1Password only exposes text stderr,
// so the transient/definitive mapping lives here (with exact fixture tests in
// scripts/admin-token-policy.test.ts), never in the syncTokens catch block.
// Definitive patterns win: a revocation-shaped message (item/vault not found,
// authorization denied) is fail-closed even when the same line also mentions
// signing in. Unmatched diagnostics are definitive (fail closed).
export function classifyOnePasswordFailure(stderr: unknown): "transient" | "definitive" {
  const line = sanitizedStderrFirstLine(stderr) ?? "";
  const definitive = /not found|no such|does ?n[o']t exist|nonexistent|isn'?t an? (item|vault)|is not an? (item|vault)|doesn'?t look like|invalid (secret )?reference|invalid (item|vault|field)|ambiguous|more than one|unauthorized|access denied|forbidden|does ?n[o']t have access|no vault/i;
  if (definitive.test(line)) return "definitive";
  const transient = /signed in|sign ?in|locked|biometric|authorization prompt|desktop app|time[d ]?out|connection (reset|refused|closed)|network|temporar|unavailable|deadline exceeded|i\/o timeout|session expired|no active session/i;
  if (transient.test(line)) return "transient";
  return "definitive";
}

function opTransportError(code: string, safeMessage: string): TokenResolutionError {
  return new TokenResolutionError({
    classification: "transient",
    sourceKind: "1password",
    code,
    safeMessage,
  });
}

function opExitError(code: string, stderr: unknown, safeMessage: string): TokenResolutionError {
  return new TokenResolutionError({
    classification: classifyOnePasswordFailure(stderr),
    sourceKind: "1password",
    code,
    safeMessage,
  });
}

export function readOnePasswordRef(opPath: string, ref: string, options: { quiet?: boolean } = {}): string {
  if (!options.quiet) runfreeLog("resolving 1Password credential source (Touch ID/passphrase prompt may appear)");
  const timeoutMs = opReadTimeoutMs();
  const result = adminSpawnSync(opPath, ["read", ref], {
    encoding: "utf8",
    env: childEnv(),
    maxBuffer: 128 * 1024,
    shell: false,
    timeout: timeoutMs,
  });
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw opTransportError("op-timeout", `op read timed out waiting for 1Password after ${Math.round(timeoutMs / 1000)}s; unlock 1Password or run \`op signin\` and retry`);
    }
    throw opTransportError("op-spawn-failed", `op read failed: ${result.error.message}`);
  }
  if ((result.status ?? 1) === 0) return readSpawnedOpOutput(result, "op read returned an empty value");

  const documentRef = parseOnePasswordDocumentRef(ref);
  if (!documentRef) throw opExitError("op-read-failed", result.stderr, opReadFailureMessage(result.stderr));

  const documentResult = adminSpawnSync(opPath, ["document", "get", documentRef.item, "--vault", documentRef.vault], {
    encoding: "utf8",
    env: childEnv(),
    maxBuffer: 128 * 1024,
    shell: false,
    timeout: timeoutMs,
  });
  if (documentResult.error) {
    if ((documentResult.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw opTransportError("op-timeout", `op document get timed out waiting for 1Password after ${Math.round(timeoutMs / 1000)}s; unlock 1Password or run \`op signin\` and retry`);
    }
    throw opTransportError("op-spawn-failed", `op document get failed: ${documentResult.error.message}`);
  }
  if ((documentResult.status ?? 1) !== 0) {
    const combined = `${opReadFailureMessage(result.stderr)}; ${opDocumentGetFailureMessage(documentResult.stderr)}`;
    // A document fallback is transient only when both stages look transient.
    throw new TokenResolutionError({
      classification: classifyOnePasswordFailure(result.stderr) === "transient" && classifyOnePasswordFailure(documentResult.stderr) === "transient"
        ? "transient"
        : "definitive",
      sourceKind: "1password",
      code: "op-document-get-failed",
      safeMessage: combined,
    });
  }
  return readSpawnedOpOutput(documentResult, "op document get returned an empty value");
}

export function runCommandSource(source: CommandSource): string {
  const executable = source.argv[0];
  const commandName = path.basename(executable);
  const commandError = (classification: "transient" | "definitive", code: string, safeMessage: string) =>
    new TokenResolutionError({ classification, sourceKind: "command", code, safeMessage });
  const realPath = regularExecutableRealpath(executable);
  if (!realPath || realPath !== executable) {
    throw commandError("definitive", "command-missing", `${commandName} executable is missing or no longer canonical`);
  }
  assertSourceArgumentsOutsideProject(source.argv.slice(1));
  const result = adminSpawnSync(executable, source.argv.slice(1), {
    cwd: hostOwnedSourceCwd(),
    encoding: "utf8",
    env: sourceExecutionEnv(),
    maxBuffer: 128 * 1024,
    shell: false,
    timeout: commandSourceTimeoutMs(),
  });
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw commandError("transient", "command-timeout", `command source timed out: ${commandName}`);
    }
    throw commandError("definitive", "command-spawn-failed", `command source failed: ${commandName}: ${result.error.message}`);
  }
  if ((result.status ?? 1) !== 0) {
    const stderr = sanitizedStderrFirstLine(result.stderr);
    throw commandError("definitive", "command-nonzero", `command source exited nonzero: ${commandName} status ${result.status ?? 1}${stderr ? `: ${stderr}` : ""}`);
  }
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const value = stdout.replace(/\r?\n$/, "");
  if (value === "") throw commandError("definitive", "empty-value", "command source returned an empty value");
  return value;
}

function readSecretRef(ref: SecretRef, options: { quiet?: boolean; verbose?: boolean } = {}): string {
  if (ref.source !== "1password") throw new Error("unsupported secret reference");
  if (!ref.ref.startsWith("op://")) throw new Error("1Password references must start with op://");
  const opPath = resolveHostExecutable("op");
  if (!opPath) throw new Error("op CLI not found on sanitized host PATH");
  adminVerbose(options, "reading JWT private key from 1Password");
  return readOnePasswordRef(opPath, ref.ref, options);
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function jwtSourceFingerprint(source: JwtSource): string {
  return crypto.createHash("sha256").update(policyJson({
    alg: source.alg,
    privateKey: source.privateKey,
    headers: source.headers,
    claims: source.claims,
    ttlSeconds: source.ttlSeconds,
  })).digest("hex");
}

function jwtSigningKey(source: JwtSource, options: TokenResolutionOptions & { sourceName?: string } = {}): string | crypto.KeyObject {
  const cache = options.sourceSecretCache;
  if (!cache || !options.sourceName) return readSecretRef(source.privateKey, options);

  const fingerprint = jwtSourceFingerprint(source);
  const cached = cache.jwtPrivateKeys.get(options.sourceName);
  if (cached?.fingerprint === fingerprint) {
    adminVerbose(options, `using cached JWT private key for source ${options.sourceName}`);
    return cached.key;
  }

  const privateKeyPem = readSecretRef(source.privateKey, options);
  const key = crypto.createPrivateKey(privateKeyPem);
  cache.jwtPrivateKeys.set(options.sourceName, { fingerprint, key });
  return key;
}

export function signJwtSource(source: JwtSource, options: TokenResolutionOptions & { sourceName?: string } = {}): string {
  const privateKey = jwtSigningKey(source, options);
  const now = Math.floor(tokenSyncWatchNowMs() / 1000);
  const header = {
    typ: "JWT",
    ...source.headers,
    alg: source.alg,
  };
  const payload = {
    ...source.claims,
    iat: now,
    exp: now + source.ttlSeconds,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  const signingInputBuffer = Buffer.from(signingInput);
  const signature = typeof privateKey === "string"
    ? crypto.sign("sha256", signingInputBuffer, { key: privateKey, dsaEncoding: "ieee-p1363" })
    : crypto.sign("sha256", signingInputBuffer, { key: privateKey, dsaEncoding: "ieee-p1363" });
  if (signature.length !== 64) throw new Error("ES256 signing did not produce a 64-byte signature");
  return `${signingInput}.${signature.toString("base64url")}`;
}

function resolveNamedSource(source: NamedSource, options: TokenResolutionOptions & { sourceName?: string } = {}): string {
  if (source.type === "command") return runCommandSource(source);
  return signJwtSource(source, options);
}

function semanticNamedSource(sourceName: string, registry: SourceRegistry | undefined): unknown {
  const source = registry?.[sourceName];
  if (!source) throw new Error(`unknown source: ${sourceName}`);
  if (source.type === "command") {
    return {
      type: "command",
      argv: source.argv,
      displayArgv: source.displayArgv,
    };
  }
  return {
    type: "jwt",
    alg: source.alg,
    privateKey: source.privateKey,
    headers: source.headers,
    claims: source.claims,
    ttlSeconds: source.ttlSeconds,
  };
}

export function tokenSourceFingerprint(source: TokenSource, registry: SourceRegistry | undefined): string {
  const base = {
    refreshEverySeconds: source.refreshEverySeconds,
    runfreeUserServiceOwner: source.runfreeUserServiceOwner,
    source: source.source,
  };
  if (source.source === "env") return sha256Json({ ...base, env: source.env });
  if (source.source === "1password") return sha256Json({ ...base, ref: source.ref });
  if (source.source === "named") {
    return sha256Json({
      ...base,
      name: source.name,
      namedSource: semanticNamedSource(source.name, registry),
    });
  }
  if (source.source === "cmd") return sha256Json({ ...base, command: source.command });
  return sha256Json({ ...base, path: source.path });
}

export function assertValidTokenName(name: string): void {
  if (!isTokenName(name)) die(`invalid credential name: ${name} (must match ${TOKEN_NAME_PATTERN.source})`);
}

export function assertNotReservedUserTokenName(name: string, command: string): void {
  if (!name.startsWith(USER_SERVICE_PREFIX)) return;
  die(`runfree ${command} cannot mutate reserved user-service token ${name}; use runfree service enable ${name} or runfree service disable ${name}`);
}

export function tokenSourceUserServiceOwner(source: TokenSource | undefined): string | undefined {
  return source?.runfreeUserServiceOwner;
}

export function isUserServiceOwnedTokenSource(source: TokenSource | undefined, id: string): boolean {
  return tokenSourceUserServiceOwner(source) === id;
}

// Typed credential fields (the --header/--scheme/--path-prefix shape), shared by
// token add/link and host add. `host` is already normalized by the caller.
export type CredentialFieldsInput = { host?: string; header?: string; scheme?: string; pathPrefix?: string };

export function credentialFromHost(host: string, fields: CredentialFieldsInput): CredentialPolicyJson {
  const header = fields.header ?? "Authorization";
  if (header.trim() === "") die("--header must be non-empty");

  const rawScheme = fields.scheme ?? "bearer";
  if (!isCredentialScheme(rawScheme)) die(`--scheme must be one of: ${credentialSchemeList()}`);

  if (fields.pathPrefix === undefined) return { host, header, scheme: rawScheme };

  try {
    return {
      host,
      header,
      scheme: rawScheme,
      pathPrefix: normalizePathPrefix(fields.pathPrefix),
    };
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
}


export function describeCredential(credential: CredentialPolicyJson): string {
  const pathScope = credential.pathPrefix ? `, path ${credential.pathPrefix}` : "";
  return `${credential.host} -> ${credential.header} (${credential.scheme}${pathScope})`;
}

function childEnvForCommand(command: string): NodeJS.ProcessEnv {
  return command === "docker" ? dockerChildEnv() : childEnv();
}

const adminLifecycleDeadline = new AsyncLocalStorage<number>();

function adminSpawnSync(
  command: string,
  args: string[],
  options: childProcess.SpawnSyncOptions = {},
): childProcess.SpawnSyncReturns<string> {
  const deadline = adminLifecycleDeadline.getStore();
  const remaining = deadline === undefined ? undefined : deadline - performance.now();
  if (remaining !== undefined && remaining <= 0) throw new Error("proxy reload lifecycle budget ended; sessions were preserved; retry runtime reload-policy --force");
  const bounded = remaining === undefined ? options : { ...options, timeout: Math.max(1, Math.floor(Math.min(options.timeout || remaining, remaining))) };
  const result = currentAdminState().processRunner?.(command, args, bounded)
    ?? childProcess.spawnSync(command, args, bounded) as childProcess.SpawnSyncReturns<string>;
  if (deadline !== undefined && performance.now() >= deadline) throw new Error("proxy reload lifecycle budget ended; sessions were preserved; retry runtime reload-policy --force");
  return result;
}

function commandExists(command: string): boolean {
  const result = adminSpawnSync("command", ["-v", command], {
    shell: true,
    stdio: "ignore",
    env: childEnvForCommand(command),
  });
  return result.status === 0;
}

export function runCapture(command: string, args: string[], options: childProcess.SpawnSyncOptions = {}): CaptureResult {
  const result = adminSpawnSync(command, args, {
    encoding: "utf8",
    env: childEnvForCommand(command),
    ...options,
  });
  return {
    ...failClosedSpawnStatus(result),
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

export function describeSource(source: TokenSource | undefined): string {
  if (!source) return "unconfigured";
  if (source.source === "env") return `env ${source.env}`;
  if (source.source === "1password") return "1password";
  if (source.source === "named") return `source ${source.name}`;
  if (source.source === "cmd") return "legacy command (unsupported)";
  return "legacy local-file (unsupported)";
}

export function displayProjectPath(filePath: string): string {
  const relative = path.relative(projectRoot(), filePath);
  if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) return relative;
  return filePath;
}

export function suggestedTokenEnvName(tokenName: string): string {
  return `${tokenName.toUpperCase().replaceAll("-", "_")}_TOKEN`;
}

function missingRequiredTokenSourceMessage(tokenName: string): string {
  const bindCommand = isUserServiceId(tokenName)
    ? `set ${suggestedTokenEnvName(tokenName)} in the host shell, then run: runfree service enable ${tokenName} --from-env ${suggestedTokenEnvName(tokenName)}`
    : `set ${suggestedTokenEnvName(tokenName)} in the host shell, then run: runfree credential set-source ${tokenName} --from-env ${suggestedTokenEnvName(tokenName)}`;
  return [
    "missing required credential source",
    `${displayProjectPath(policyPath())} declares tokens.${tokenName}`,
    `${displayProjectPath(tokenConfigPath())} has no ${tokenName} entry`,
    bindCommand,
    `override only if anonymous access is intended: set tokens.${tokenName}.allowAnonymous=true`,
  ].join("; ");
}

function commandSourceExample(tokenName: string): { command: string; name: string } {
  if (tokenName === "github") return { command: "gh auth token", name: "github-cli" };
  return { command: "<trusted-host-command>", name: "<source-name>" };
}

function commandSourceMigrationInstructions(tokenName: string, prefix: string): string {
  const example = commandSourceExample(tokenName);
  return [
    prefix,
    `run: runfree credential source add ${example.name} -- ${example.command}`,
    `then: runfree credential set-source ${tokenName} --from-source ${example.name}`,
  ].join("; ");
}

function resolveTokenSource(tokenName: string, source: TokenSource, options: TokenResolutionOptions = {}): string {
  if (source.source === "env") {
    adminVerbose(options, `${tokenName}: reading host environment source ${source.env}`);
    const value = childEnv()[source.env];
    if (!value) {
      throw new TokenResolutionError({
        classification: "definitive",
        sourceKind: "env",
        code: "env-unset",
        safeMessage: `${source.env} is unset or empty`,
      });
    }
    return value;
  }

  if (source.source === "1password") {
    if (!source.ref.startsWith("op://")) {
      throw new TokenResolutionError({
        classification: "definitive",
        sourceKind: "1password",
        code: "invalid-reference",
        safeMessage: "1Password references must start with op://",
      });
    }
    const opPath = resolveHostExecutable("op");
    if (!opPath) {
      // The op binary disappearing from PATH is a host-tooling problem, not a
      // revocation gesture: the vault item may be untouched.
      throw new TokenResolutionError({
        classification: "transient",
        sourceKind: "1password",
        code: "op-unavailable",
        safeMessage: "op CLI not found on sanitized host PATH",
      });
    }
    adminVerbose(options, `${tokenName}: reading 1Password source with op CLI`);
    return readOnePasswordRef(opPath, source.ref, options);
  }

  if (source.source === "named") {
    adminVerbose(options, `${tokenName}: reading host named source ${source.name}`);
    const registry = options.sourceRegistry ?? loadSourceRegistry();
    const namedSource = registry[source.name];
    if (!namedSource) {
      throw new TokenResolutionError({
        classification: "definitive",
        sourceKind: "named",
        code: "unknown-source",
        safeMessage: `unknown source: ${source.name}`,
      });
    }
    return resolveNamedSource(namedSource, { ...options, sourceName: source.name });
  }

  if (source.source === "cmd") {
    throw new Error(commandSourceMigrationInstructions(tokenName, "unsupported command credential source in token config"));
  }

  throw new Error("legacy local-file credential source is unsupported; reconfigure with --from-1password or --from-env");
}

// A typed token-source selection (which `--from-*` the user chose), independent
// of argv. The yargs command modules build this directly via
// `credentialSourceSelectionFromArgs`.
export type TokenSourceSelection =
  | { kind: "none" }
  | { kind: "stdin" }
  | { kind: "env"; env: string }
  | { kind: "named"; name: string }
  | { kind: "1password"; ref: string };

// Enforcement: resolve a typed selection into a stored TokenSource, re-validating
// that the underlying secret actually resolves (env set, source known, op://
// readable). Flag-agnostic and shared by both front-ends. (Distinct from
// `resolveTokenSource`, which fetches a stored TokenSource's secret value.)
export function tokenSourceFromSelection(selection: TokenSourceSelection, required: boolean): TokenSource | undefined {
  switch (selection.kind) {
    case "none":
      if (required) die("plaintext local token storage is disabled; use --from-1password, --from-env, or --from-source");
      return undefined;
    case "stdin":
      return die("plaintext local token storage is disabled; use --from-1password, --from-env, or --from-source");
    case "env": {
      const value = childEnv()[selection.env];
      if (!value) die(`${selection.env} is unset or empty`);
      return { source: "env", env: selection.env };
    }
    case "named":
      assertKnownSourceName(selection.name);
      if (!loadSourceRegistry()[selection.name]) die(`unknown source: ${selection.name}`);
      return { source: "named", name: selection.name };
    case "1password": {
      if (!selection.ref.startsWith("op://")) die("1Password references must start with op://");
      const opPath = resolveHostExecutable("op");
      if (!opPath) die("op CLI not found on sanitized host PATH");
      try {
        readOnePasswordRef(opPath, selection.ref);
      } catch (error) {
        die(error instanceof Error ? error.message : String(error));
      }
      return { source: "1password", ref: selection.ref };
    }
  }
}

function namedJwtSource(source: TokenSource | undefined, registry?: SourceRegistry): { name: string; source: JwtSource } | undefined {
  if (!source || source.source !== "named") return undefined;
  const sourceRegistry = registry ?? loadSourceRegistry();
  const namedSource = sourceRegistry[source.name];
  if (namedSource?.type !== "jwt") return undefined;
  return { name: source.name, source: namedSource };
}

export function effectiveTokenRefresh(source: TokenSource | undefined, registry?: SourceRegistry): EffectiveTokenRefresh {
  if (!source) return { mode: "manual" };
  const jwt = namedJwtSource(source, registry);
  if (source.refreshEverySeconds !== undefined) {
    return {
      mode: "explicit",
      seconds: source.refreshEverySeconds,
      sourceName: jwt?.name,
      ttlSeconds: jwt?.source.ttlSeconds,
    };
  }
  if (!jwt) return { mode: "manual" };
  const seconds = jwt.source.ttlSeconds - 60;
  if (seconds <= 0) return { mode: "manual" };
  return {
    mode: "derived",
    seconds,
    sourceName: jwt.name,
    ttlSeconds: jwt.source.ttlSeconds,
  };
}

export function assertRefreshBeforeJwtExpiry(refresh: EffectiveTokenRefresh): void {
  if (refresh.mode === "explicit" && refresh.ttlSeconds !== undefined && refresh.seconds >= refresh.ttlSeconds) {
    throw new Error(`--refresh-every must be shorter than source ttl ${formatDurationSeconds(refresh.ttlSeconds)}`);
  }
}

function clearCachedSourceSecret(source: TokenSource | undefined, cache: SourceSecretCache | undefined): void {
  if (!cache || source?.source !== "named") return;
  cache.jwtPrivateKeys.delete(source.name);
}

// Source identity plus refresh cadence and user-service ownership: the same
// comparison the binding refusal (`assertTokenSourceCanBeSaved`) uses, so a
// caller that wants to predict "would this bind be a no-op or a refusal" gets
// the enforcement's own answer rather than a display-string comparison.
export function tokenSourcesEqual(left: TokenSource | undefined, right: TokenSource | undefined): boolean {
  if (!left || !right) return left === right;
  if (left.source !== right.source) return false;
  if ((left.refreshEverySeconds ?? 0) !== (right.refreshEverySeconds ?? 0)) return false;
  if (left.runfreeUserServiceOwner !== right.runfreeUserServiceOwner) return false;
  if (left.source === "env" && right.source === "env") return left.env === right.env;
  if (left.source === "1password" && right.source === "1password") return left.ref === right.ref;
  if (left.source === "named" && right.source === "named") return left.name === right.name;
  if (left.source === "file" && right.source === "file") return left.path === right.path;
  if (left.source === "cmd" && right.source === "cmd") return left.command === right.command;
  return false;
}

export function assertTokenSourceCanBeSaved(name: string, source: TokenSource, opts: { replaceSource: boolean }): void {
  const existing = loadTokenConfig()[name];
  if (existing && !tokenSourcesEqual(existing, source) && !opts.replaceSource) {
    die(`${name} credential source is already ${describeSource(existing)}; pass --replace-source to change it`);
  }
}

function saveTokenSourceInternal(name: string, source: TokenSource, opts: { replaceSource: boolean }): { changed: boolean } {
  ensureStateDirs();
  assertTokenSourceCanBeSaved(name, source, opts);
  const config = loadTokenConfig();
  const existing = config[name];
  if (tokenSourcesEqual(existing, source)) return { changed: false };

  config[name] = source;
  saveTokenConfig(config);
  return { changed: true };
}

export function saveTokenSource(name: string, source: TokenSource, opts: { replaceSource: boolean }): { changed: boolean } {
  assertNotReservedUserTokenName(name, "credential source commands");
  return saveTokenSourceInternal(name, source, opts);
}

export function saveUserServiceTokenSource(name: string, source: TokenSource, opts: { replaceSource: boolean }): { changed: boolean } {
  if (!isUserServiceId(name)) die(`internal error: ${name} is not a user-defined service id`);
  return saveTokenSourceInternal(name, { ...source, runfreeUserServiceOwner: name }, opts);
}

export function removeUserServiceTokenSource(name: string): boolean {
  if (!isUserServiceId(name)) die(`internal error: ${name} is not a user-defined service id`);
  const config = loadTokenConfig();
  const existing = config[name];
  if (!existing || !isUserServiceOwnedTokenSource(existing, name)) return false;
  delete config[name];
  saveTokenConfig(config);
  return true;
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function assertTokenFilename(name: string): void {
  assertTokenName(name);
}

// `--no-trunc` keeps this lookup on the same exact 64-hex container identity the
// runtime validation marker records; a `docker ps -q` short ID would fail the
// marker's agent/proxy identity comparison in proxyRuntimeValidationIssue.
function serviceContainerId(project: string, service: string, options: { runningOnly?: boolean } = {}): string | undefined {
  const ps = runCapture("docker", [
    "ps",
    options.runningOnly ? "-q" : "-aq",
    "--no-trunc",
    ...composeServiceContainerFilters(project, service),
  ]);
  return ps.stdout.trim().split(/\s+/).filter(Boolean)[0];
}

function dockerContainerStartedAt(containerId: string): string | undefined {
  const result = runCapture("docker", ["inspect", "--format", "{{ .State.StartedAt }}", containerId]);
  const startedAt = result.stdout.trim();
  if (result.status !== 0 || startedAt === "" || startedAt === "<no value>") return undefined;
  return startedAt;
}

// One docker exec yields both consumers of the validation marker: the parsed
// record for validation and its fingerprint for the store generation, so a
// proxyRuntime() pass never reads the marker twice.
type ProxyValidationMarker = { parsed?: unknown; fingerprint: string };

function readProxyValidationMarker(proxyId: string): ProxyValidationMarker | undefined {
  const result = runCapture("docker", ["exec", "--user", "0:0", proxyId, "cat", RUNTIME_VALIDATION_MARKER_PATH]);
  if (result.status !== 0) return undefined;
  try {
    const parsed = JSON.parse(result.stdout) as unknown;
    return { parsed, fingerprint: sha256Json(parsed) };
  } catch {
    return { fingerprint: sha256Json({ raw: result.stdout }) };
  }
}

function proxyValidationMarkerFingerprint(proxyId: string): string | undefined {
  return readProxyValidationMarker(proxyId)?.fingerprint;
}

function proxyTokenStoreGeneration(proxyId: string, validationIdentity: unknown): string | undefined {
  const startedAt = dockerContainerStartedAt(proxyId);
  if (!startedAt) return undefined;
  return sha256Json({
    proxyId,
    startedAt,
    validationIdentity,
  });
}

export function proxyRuntime(): ProxyRuntime {
  const prevalidatedRuntime = validatedRuntime();
  if (prevalidatedRuntime
    && prevalidatedRuntime.projectId === projectId()
    && validatedRuntimeCallbackProofMatches(prevalidatedRuntime)) {
    const validation = validatedRuntimeSecurityContractIssue(prevalidatedRuntime);
    if (validation) {
      return { state: "validation-required", id: prevalidatedRuntime.proxyId, validationMessage: validation };
    }
    return readyProxyRuntime(prevalidatedRuntime.proxyId);
  }
  if (!dockerAvailable()) return { state: "docker-unavailable" };
  const project = composeProject();
  if (!project) return { state: "not-running" };
  // The per-session runtime has no shared agent service; token sync validates
  // the proxy control plane, and each session is validated by admission.
  const agentId = undefined;
  const id = proxyContainerId(project);
  if (!id) return { state: "not-running" };
  const running = runCapture("docker", ["inspect", "--format", "{{ .State.Running }}", id]);
  if (running.status !== 0 || running.stdout.trim() !== "true") return { state: "not-running" };
  const marker = readProxyValidationMarker(id);
  const validation = proxyRuntimeValidationIssue(project, id, agentId, marker);
  if (validation) return { state: "validation-required", id, validationMessage: validation };
  return readyProxyRuntime(id, marker?.fingerprint);
}

// The store generation must be deterministic for an unchanged container: a
// transient docker-exec failure reading the validation marker (or a failed
// StartedAt inspect) must fail the sync run without fabricating a different
// generation — a fabricated generation would spuriously invalidate receipts
// and flip a keep-last-good decision into a delete. "proxy-unreachable" makes
// syncTokens report and change nothing.
function readyProxyRuntime(proxyId: string, knownValidationIdentity?: string): ProxyRuntime {
  const validationIdentity = knownValidationIdentity ?? proxyValidationMarkerFingerprint(proxyId);
  if (validationIdentity === undefined) return { state: "proxy-unreachable", id: proxyId };
  const storeGeneration = proxyTokenStoreGeneration(proxyId, validationIdentity);
  if (storeGeneration === undefined) return { state: "proxy-unreachable", id: proxyId };
  return { state: "ready", id: proxyId, storeGeneration };
}

function runtimeStateMessage(state: ProxyRuntimeState, validationMessage?: string): string {
  if (state === "ready") return "synced to proxy tmpfs";
  if (state === "validation-required") {
    return validationMessage ?? `runtime validation required before proxy token sync; run \`${remedy.up()}\``;
  }
  if (state === "docker-unavailable") return "source verified; docker unavailable";
  if (state === "proxy-unreachable") {
    return "proxy runtime could not be inspected (docker exec failed); token store left unchanged";
  }
  return "source verified; proxy not running";
}

function validatedRuntimeCallbackProofMatches(proof: NonNullable<AdminState["validatedRuntime"]>): boolean {
  return proof.mcpOAuthCallbackTopologyVersion === 2
    && proof.mcpOAuthCallbackPort === mcpOAuthCallbackPort(projectRoot());
}

function adminProjectInfo(): ProjectInfo {
  const base = projectInfo(projectRoot(), childEnv());
  const adminState = currentAdminState();
  const adminStateDir = stateDir();
  const mountsDir = path.join(adminStateDir, "mounts");
  return {
    ...base,
    paths: {
      ...base.paths,
      ...projectControlPaths(adminStateDir),
      agentEnvPath: adminState.agentEnvPath,
      claudeConfigPath: childEnv().RUNFREE_CLAUDE_JSON ?? path.join(adminStateDir, "claude.json"),
      claudeMcpConfigPath: childEnv().RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH
        ?? path.join(mountsDir, "claude-mcp.json"),
      claudeDir: childEnv().RUNFREE_CLAUDE_DIR ?? path.join(adminStateDir, "claude"),
      codexDir: childEnv().RUNFREE_CODEX_HOME ?? path.join(adminStateDir, "codex"),
      gitConfigPath: childEnv().RUNFREE_GIT_CONFIG ?? path.join(adminStateDir, "gitconfig"),
      inboxDir: childEnv().RUNFREE_INBOX_DIR ?? path.join(adminStateDir, "inbox"),
      mcpOperationPolicyPath: childEnv().RUNFREE_MCP_OPERATION_POLICY_HOST_PATH
        ?? path.join(adminStateDir, "mcp-operation-policy.json"),
      mcpOAuthPolicyPath: childEnv().RUNFREE_OAUTH_POLICY_HOST_PATH
        ?? childEnv().RUNFREE_MCP_OAUTH_POLICY_HOST_PATH
        ?? path.join(adminStateDir, "oauth-mediation-policy.json"),
      policyPath: adminState.policyPath,
      projectCodexDirMaskPath: path.join(mountsDir, "project-codex-mask"),
      proxyCaCertDir: childEnv().RUNFREE_PROXY_CA_CERT_DIR ?? path.join(adminStateDir, "proxy-ca", "public"),
      proxyCaKeyDir: childEnv().RUNFREE_PROXY_CA_KEY_DIR ?? path.join(adminStateDir, "proxy-ca", "private"),
      sessionsDir: path.join(adminStateDir, "sessions"),
      stateDir: adminStateDir,
      tokenConfigPath: adminState.tokenConfigPath,
    },
  };
}

function runtimeRootForSecurityContract(project: ProjectInfo): string {
  const projectRuntimeRoot = path.join(project.paths.stateDir, "runtime");
  if (fs.existsSync(path.join(projectRuntimeRoot, "agent", "compose.yaml"))) return projectRuntimeRoot;
  return childEnv().RUNFREE_RUNTIME_ROOT ?? currentAdminState().packageRoot;
}

function currentRuntimeValidationTarget(): { contract: RuntimeSecurityContract; plan: ActiveRuntimePlan } | undefined {
  try {
    const supplied = currentAdminState().runtimeContext;
    const project = supplied?.project ?? adminProjectInfo();
    const context: RuntimeContext = supplied ?? {
      projectRoot: projectRoot(),
      project,
      runtimeRoot: runtimeRootForSecurityContract(project),
      env: childEnv(),
    };
    const plan = activeRuntimePlanFromContext(context);
    return { contract: createRuntimeSecurityContract(plan), plan };
  } catch {
    return undefined;
  }
}

function currentRuntimeSecurityContract(): RuntimeSecurityContract | undefined {
  return currentRuntimeValidationTarget()?.contract;
}

function liveRuntimeComponentValidationIssue(
  proof: Record<string, unknown>,
  target: NonNullable<ReturnType<typeof currentRuntimeValidationTarget>>,
): string | undefined {
  const agentId = typeof proof.agentId === "string" ? proof.agentId : undefined;
  const proxyId = typeof proof.proxyId === "string" ? proof.proxyId : undefined;
  // Shape-exact: the per-session proof binds no shared agent or retired relay
  // sidecar. A proof carrying either is stale, not merely malformed.
  if (agentId !== undefined || proof.mcpOAuthCallbackSidecarId !== undefined) {
    return `runtime component identity is stale for the per-session runtime shape; run \`${remedy.up()}\``;
  }
  if (!proxyId) return `runtime component container identity is malformed; run \`${remedy.up()}\``;
  const ids = [proxyId];
  const inspect = runCapture("docker", ["inspect", "--format", runtimeContainerInspectFormat(), ...ids]);
  if (inspect.status !== 0) return `runtime component labels cannot be inspected; run \`${remedy.up()}\``;
  const containers = parseRuntimeContainerInspectRows(inspect.stdout);
  const observedIds = new Set(containers.map((container) => container.id));
  if (containers.length !== ids.length || ids.some((id) => !observedIds.has(id))) {
    return `runtime component container identities changed; run \`${remedy.up()}\``;
  }
  if (containers.some((container) => container.running !== true)) {
    return `runtime component container is not running; run \`${remedy.up()}\``;
  }
  const identity = {
    composeProject: target.plan.composeProjectName,
    projectId: target.plan.projectId,
  };
  // A same-generation effective selection keeps the already-proved schema-v2
  // container and image identity as current authority; the composite topology
  // label is migration evidence only and changes whenever a session-only input
  // changes, so it must not invalidate a live control plane after a roll.
  const effectiveControlPlane = readEffectiveControlPlaneV2(target.plan.paths.stateDir);
  const issue = effectiveControlPlane
      && effectiveControlPlane.manifest.generation.controlPlaneGenerationDigest
        === target.plan.generationV2.controlPlane.controlPlaneGenerationDigest
    ? effectiveControlPlaneComponentEvidenceIssue(containers, effectiveControlPlane, identity)
    : runtimeComponentEvidenceIssue(containers, target.plan.activeRuntime.manifest?.components ?? target.plan.components, {
        agent: target.plan.activeRuntime.agentImage,
        proxy: target.plan.activeRuntime.proxyImage,
      }, identity);
  if (!issue) return undefined;
  // `runfree up` repairs a missing container by recreating the composition, but
  // it refuses duplicated or contradictory evidence by design, so pointing
  // those at `up` would name a command that fails the same way every time.
  const remedyLine = issue.kind === "missing" ? `run \`${remedy.up()}\`` : `run \`${remedy.rebuild()}\``;
  return `${issue.message}; ${remedyLine}`;
}

function inspectById(inspects: DockerContainerInspect[] | undefined, id: string): DockerContainerInspect | undefined {
  return inspects?.find((inspect) => inspect.Id === id);
}

function contractContainer(contract: RuntimeSecurityContract, name: "agent" | "proxy"): RuntimeContainerContract | undefined {
  return contract.containers.find((container) => container.name === name);
}

function runtimeSecurityContractContainerEvidence(
  containerId: string,
  inspect: DockerContainerInspect,
  contract: RuntimeContainerContract | undefined,
): NonNullable<RuntimeSecurityContractEvidence["agent"]> {
  if (!contract) return { inspect };
  const probe = runCapture("docker", ["exec", containerId, "sh", "-c", runtimeSecurityContractProbeScript(contract)]);
  if (probe.status !== 0) return { inspect };
  return {
    inspect,
    ...parseRuntimeSecurityContractProbe(probe.stdout),
  };
}

function runtimeSecurityContractEvidence(contract: RuntimeSecurityContract, agentId: string | undefined, proxyId: string): RuntimeSecurityContractEvidence {
  const evidence: RuntimeSecurityContractEvidence = {};
  const inspectIds = agentId !== undefined ? [agentId, proxyId] : [proxyId];
  const inspectResult = runCapture("docker", ["inspect", ...inspectIds]);
  if (inspectResult.status !== 0) return evidence;
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspectResult.stdout) as unknown;
  } catch {
    return evidence;
  }
  const inspects = Array.isArray(parsed) ? parsed as DockerContainerInspect[] : undefined;
  // No shared agent to inspect in the per-session shape: its security contract
  // is proven per session by admission, not by startup evidence.
  if (agentId !== undefined) {
    const agentInspect = inspectById(inspects, agentId) ?? inspects?.[0];
    if (agentInspect) {
      evidence.agent = runtimeSecurityContractContainerEvidence(agentId, agentInspect, contractContainer(contract, "agent"));
      if (!evidence.agent.presentPaths) {
        const privateCaProbe = runCapture("docker", ["exec", agentId, "sh", "-c", "test ! -e /ca/private/proxy-ca.key"]);
        evidence.agent.presentPaths = privateCaProbe.status === 0 ? [] : ["/ca/private/proxy-ca.key"];
      }
    }
  }
  const proxyInspect = inspectById(inspects, proxyId) ?? inspects?.[agentId !== undefined ? 1 : 0];
  if (proxyInspect) {
    evidence.proxy = runtimeSecurityContractContainerEvidence(proxyId, proxyInspect, contractContainer(contract, "proxy"));
  }
  return evidence;
}

function runtimeSecurityContractValidationIssue(
  marker: Record<string, unknown>,
  agentId: string | undefined,
  proxyId: string,
): string | undefined {
  const contract = currentRuntimeSecurityContract();
  if (!contract?.contractHash) {
    return `runtime security contract cannot be checked; run \`${remedy.up()}\``;
  }
  if (runtimeValidationComponentsIssue(marker.components, contract.components)) {
    return `runtime validation marker is stale for runtime components; run \`${remedy.up()}\``;
  }
  if (marker.contractHash !== contract.contractHash) {
    return `runtime validation marker is stale for runtime security contract; run \`${remedy.up()}\``;
  }
  const proof = validateRuntimeSecurityContractEvidence(
    contract,
    runtimeSecurityContractEvidence(contract, agentId, proxyId),
    { requireLiveProbes: true, scope: "startup" },
  );
  if (proof.ok) return undefined;
  const issue = proof.issues[0];
  if (!issue) return `runtime security contract validation failed; run \`${remedy.up()}\``;
  return `runtime security contract validation failed (${issue.container}: ${issue.code}: ${issue.detail}); run \`runfree up\``;
}

function validatedRuntimeSecurityContractIssue(proof: NonNullable<AdminState["validatedRuntime"]>): string | undefined {
  if (proof.proofVersion !== 4 || typeof proof.contractHash !== "string" || proof.contractHash === "") {
    return `runtime security contract cannot be checked; run \`${remedy.up()}\``;
  }
  const target = currentRuntimeValidationTarget();
  if (!target?.contract.contractHash) return `runtime security contract cannot be checked; run \`${remedy.up()}\``;
  if (runtimeValidationComponentsIssue(proof.components, target.contract.components)) {
    return `runtime validation marker is stale for runtime components; run \`${remedy.up()}\``;
  }
  if (proof.contractHash !== target.contract.contractHash) {
    return `runtime validation marker is stale for runtime security contract; run \`${remedy.up()}\``;
  }
  return liveRuntimeComponentValidationIssue(proof, target);
}

function runtimeValidationComponentsIssue(
  value: unknown,
  expected: RuntimeSecurityContract["components"],
): string | undefined {
  if (!isRecord(value)) return "malformed";
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value[key] !== expectedValue) return "mismatch";
  }
  return undefined;
}

function proxyRuntimeValidationIssue(project: string, proxyId: string, agentId: string | undefined, marker: ProxyValidationMarker | undefined): string | undefined {
  if (!marker) return `runtime validation required before proxy token sync; run \`${remedy.up()}\``;
  const parsed = marker.parsed;
  if (parsed === undefined) return `runtime validation marker is malformed; run \`${remedy.up()}\``;
  if (!isRecord(parsed)) return `runtime validation marker is malformed; run \`${remedy.up()}\``;
  if (parsed.proofVersion !== 4) return `runtime validation marker has stale proof version; run \`${remedy.up()}\``;
  if (parsed.projectId !== projectId()) return `runtime validation marker belongs to another project; run \`${remedy.up()}\``;
  // Shape-exact: the per-session marker names no agent, so one carrying an
  // agent id was written for a different runtime shape than the one running.
  if (parsed.agentId !== undefined) {
    return `runtime validation marker is stale for the per-session runtime shape; run \`${remedy.up()}\``;
  }
  if (typeof parsed.proxyId !== "string" || parsed.proxyId === "") {
    return `runtime validation marker is malformed; run \`${remedy.up()}\``;
  }
  if (parsed.proxyId !== proxyId) {
    return `runtime validation marker belongs to another proxy container; run \`${remedy.up()}\``;
  }
  if (parsed.mcpOAuthCallbackTopologyVersion !== 2) {
    return `runtime validation marker is stale for MCP OAuth callback topology; run \`${remedy.up()}\``;
  }
  if (parsed.mcpOAuthCallbackPort !== mcpOAuthCallbackPort(projectRoot())) {
    return `runtime validation marker is stale for MCP OAuth callback port; run \`${remedy.up()}\``;
  }
  // A marker or live Compose service from the retired relay generation was
  // minted by an older binary; refuse it so the runtime revalidates.
  if (
    serviceContainerId(project, "mcp_callback", { runningOnly: false })
    || parsed.mcpOAuthRequiresCallbackBridge !== undefined
    || parsed.mcpOAuthCallbackSidecarId !== undefined
    || parsed.mcpOAuthCallbackSidecarIp !== undefined
    || parsed.mcpOAuthCallbackSidecarService !== undefined
  ) {
    return `runtime validation marker is stale for MCP OAuth callback sidecar; run \`${remedy.up()}\``;
  }
  const securityContractValidation = runtimeSecurityContractValidationIssue(parsed, agentId, proxyId);
  if (securityContractValidation) return securityContractValidation;
  const target = currentRuntimeValidationTarget();
  if (!target) return `runtime security contract cannot be checked; run \`${remedy.up()}\``;
  return liveRuntimeComponentValidationIssue(parsed, target);
}

function writeProxyRuntimeToken(proxyId: string, name: string, value: string): void {
  assertTokenFilename(name);
  const tokenFile = `${CONTAINER_SECRET_DIR}/${name}`;
  const tmpFile = `${tokenFile}.tmp`;
  const command = [
    "set -e",
    "umask 077",
    `rm -f ${shellSingleQuote(tmpFile)}`,
    `cat > ${shellSingleQuote(tmpFile)}`,
    `chmod 600 ${shellSingleQuote(tmpFile)}`,
    `mv ${shellSingleQuote(tmpFile)} ${shellSingleQuote(tokenFile)}`,
  ].join("; ");
  const result = adminSpawnSync("docker", ["exec", "--user", PROXY_RUNTIME_USER, "-i", proxyId, "sh", "-c", command], {
    input: value,
    encoding: "utf8",
    env: dockerChildEnv(),
  });
  if (failClosedSpawnStatus(result).status !== 0) {
    const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
    throw new Error(stderr || `failed to write ${name} token into proxy tmpfs`);
  }
}

export function removeProxyRuntimeToken(proxyId: string, name: string): void {
  assertTokenFilename(name);
  const tokenFile = `${CONTAINER_SECRET_DIR}/${name}`;
  const tmpFile = `${tokenFile}.tmp`;
  const command = `rm -f ${shellSingleQuote(tokenFile)} ${shellSingleQuote(tmpFile)}`;
  const result = runCapture("docker", ["exec", proxyId, "sh", "-c", command]);
  if (result.status !== 0) throw new Error(result.stderr.trim() || `failed to remove ${name} token from proxy tmpfs`);
}

function tokenConfigNamesForCleanup(): string[] {
  try {
    const raw = readJsonFile<unknown>(tokenConfigPath(), {});
    if (!isRecord(raw)) return [];
    return Object.keys(raw).filter((name) => isTokenName(name));
  } catch {
    return [];
  }
}

function cleanupProxyRuntimeTokens(proxyId: string, tokenNames: Iterable<string>): boolean {
  let changed = false;
  for (const tokenName of Array.from(new Set(tokenNames)).sort((left, right) => left.localeCompare(right))) {
    removeProxyRuntimeToken(proxyId, tokenName);
    changed = true;
  }
  return changed;
}

export function tokenResolutionLedgerKey(tokenName: string, sourceFingerprint: string, proxyStoreGeneration: string): string {
  return `${tokenName}\0${sourceFingerprint}\0${proxyStoreGeneration}`;
}

export function newTokenResolutionLedger(startupReceipts: TokenResolutionReceipt[] = []): TokenResolutionLedger {
  return {
    importedStartupReceipts: new Set<string>(),
    lastResolvedAt: new Map<string, number>(),
    retryAfterFailureAt: new Map<string, number>(),
    startupReceipts,
  };
}

export function isTokenResolutionReceipt(value: unknown): value is TokenResolutionReceipt {
  return isRecord(value)
    && typeof value.tokenName === "string"
    && isTokenName(value.tokenName)
    && typeof value.sourceFingerprint === "string"
    && value.sourceFingerprint !== ""
    && typeof value.proxyStoreGeneration === "string"
    && value.proxyStoreGeneration !== ""
    && typeof value.resolvedAt === "number"
    && Number.isFinite(value.resolvedAt)
    && value.resolvedAt > 0;
}

// Keep-last-good is bounded: past this wall-clock age (measured from the
// receipt's resolvedAt) a transient failure deletes instead of keeping. Fixed
// by design — deliberately not project-configurable.
const TOKEN_STALE_KEEP_BOUND_MS = 24 * 60 * 60 * 1000;

// The keep-last-good decision, pure and in one place: a classified-transient
// failure carries no revocation information, so the receipt is returned (keep
// the tmpfs value, mark `stale`) only when it proves the current, unchanged-
// source, live-held value within the staleness bound. Everything else —
// definitive or unclassifiable error, no receipt, changed fingerprint, dead
// generation, out of bound, value not held — returns undefined (fail-closed
// delete).
function keepLastGoodReceipt(input: {
  error: unknown;
  receipt: TokenResolutionReceipt | undefined;
  sourceFingerprint: string | undefined;
  storeGeneration: string | undefined;
  held: boolean;
  nowMs: number;
}): TokenResolutionReceipt | undefined {
  if (!isTransientTokenResolutionError(input.error)) return undefined;
  if (input.storeGeneration === undefined || input.sourceFingerprint === undefined) return undefined;
  const receipt = input.receipt;
  if (receipt === undefined) return undefined;
  if (receipt.proxyStoreGeneration !== input.storeGeneration) return undefined;
  if (receipt.sourceFingerprint !== input.sourceFingerprint) return undefined;
  if (input.nowMs - receipt.resolvedAt > TOKEN_STALE_KEEP_BOUND_MS) return undefined;
  if (!input.held) return undefined;
  return receipt;
}

// --- Persisted token resolution receipts --------------------------------------
//
// Secret-free proof-of-possession claims (token name, source fingerprint,
// store generation, resolvedAt — hashes and timestamps only) persisted in host
// XDG state next to the sync status file so receipt-gated convergence syncs in
// later CLI processes can skip re-resolving values the proxy already holds.
// The generation half of every comparison is recomputed live from docker
// inspect + the validation marker, never trusted from this file. A corrupted
// file degrades to "no receipts" (fail-open to re-resolution, never to
// skipping validation).

type PersistedTokenReceiptsFile = {
  schemaVersion: 1;
  receipts: TokenResolutionReceipt[];
};

function tokenReceiptsPath(): string {
  return path.join(path.dirname(syncStatusPath()), `token-resolution-receipts-${projectId()}.json`);
}

function loadPersistedTokenReceipts(): Map<string, TokenResolutionReceipt> {
  const receipts = new Map<string, TokenResolutionReceipt>();
  let raw: unknown;
  try {
    raw = readJsonFile<unknown>(tokenReceiptsPath(), undefined);
  } catch {
    return receipts;
  }
  if (!isRecord(raw) || raw.schemaVersion !== 1 || !Array.isArray(raw.receipts)) return receipts;
  for (const entry of raw.receipts) {
    if (isTokenResolutionReceipt(entry)) receipts.set(entry.tokenName, entry);
  }
  return receipts;
}

function savePersistedTokenReceipts(receipts: Map<string, TokenResolutionReceipt>): void {
  const payload: PersistedTokenReceiptsFile = {
    schemaVersion: 1,
    receipts: Array.from(receipts.values()).sort((left, right) => left.tokenName.localeCompare(right.tokenName)),
  };
  writeJsonFile(tokenReceiptsPath(), payload, 0o600);
}

// Advisory snapshot of the persisted receipts for scheduling decisions (the
// watcher's next-delay computation). Read without the token-store lock: a
// racing writer costs at most one redundant wake-up or re-resolution, never a
// skipped validation — the lock-guarded load inside syncTokens still governs
// every skip/keep decision.
export function loadPersistedTokenReceiptsSnapshot(): TokenResolutionReceipt[] {
  return Array.from(loadPersistedTokenReceipts().values());
}

// Retract every receipt for a token (used by delete paths outside syncTokens,
// e.g. `token unset`). Deletion does not change the store generation, so
// generation pruning alone cannot cover retraction.
export function retractPersistedTokenReceipts(tokenName: string): void {
  withTokenStoreLock(() => {
    const receipts = loadPersistedTokenReceipts();
    if (receipts.delete(tokenName)) savePersistedTokenReceipts(receipts);
  });
}

// --- Per-project token-store lock ----------------------------------------------
//
// Serializes receipt load, the batched possession listing, token
// writes/removes, and status/receipt writes across concurrent host CLI
// processes: without it, a second process could delete a token between another
// sync's possession listing and its receipt write, resurrecting a receipt for
// a value the proxy no longer holds. Same host-owned PID-file pattern as the
// runtime lifecycle lock (runtime/sessions.ts). Reentrant within one process
// so token-affecting mutations can hold it through their cleanup/sync step.

const heldTokenStoreLockDepths = new Map<string, number>();

function tokenStoreLockPath(): string {
  return path.join(stateDir(), `token-store-sync-${projectId()}.lock`);
}

function tokenStoreLockWaitMs(): number {
  return fakeDockerMsOverride(childEnv().RUNFREE_TEST_TOKEN_STORE_LOCK_WAIT_MS) ?? 10_000;
}

function removeStaleTokenStoreLock(lockPath: string): boolean {
  // A lock stamped with a different boot cannot be held: PIDs are reissued from
  // low numbers after a reboot, so the PID check alone can match an unrelated
  // process and wedge every token sync for this project. Same rule as the
  // runtime lifecycle lock.
  if (lockWrittenOnPreviousBoot(lockPath, childEnv())) {
    fs.rmSync(lockPath, { recursive: true, force: true });
    return true;
  }
  let pid: number | undefined;
  try {
    pid = Number.parseInt(fs.readFileSync(path.join(lockPath, "pid"), "utf8").trim(), 10);
  } catch {
    pid = undefined;
  }
  if (pid !== undefined && Number.isInteger(pid) && pid !== process.pid && processAlive(pid)) {
    let recordedBootId: string | undefined;
    let recordedProcessStart: string | undefined;
    try {
      recordedBootId = fs.readFileSync(path.join(lockPath, "boot"), "utf8").trim();
      recordedProcessStart = fs.readFileSync(path.join(lockPath, "process-start"), "utf8").trim();
    } catch {
      // Older or partially stamped locks retain the PID-only behavior.
    }
    const boot = compareHostBootId(recordedBootId, childEnv());
    // The first previous-boot check already handles the normal case. Repeat the
    // decisive mismatch rule here because the stamp may have changed between
    // reads; unknown identity still retains the live-PID fallback.
    if (boot !== "mismatch" && (
      boot !== "match"
      || compareHostProcessStart(recordedProcessStart, pid, childEnv()) !== "mismatch"
    )) return false;
  }
  // A missing or garbled pid under host-owned state is stale — unless the lock
  // is young enough to be another process mid-acquisition (pid write pending).
  if ((pid === undefined || !Number.isInteger(pid)) && lockAgeMs(lockPath) < LOCK_PIDLESS_GRACE_MS) {
    return false;
  }
  // Same pre-existing check-then-remove race as the runtime lifecycle lock; see
  // `removeStaleLifecycleLock` for why it is not closable at this layer.
  fs.rmSync(lockPath, { recursive: true, force: true });
  return true;
}

function acquireTokenStoreLock(lockPath: string, wait = true): void {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  // Resolved once, before any mkdir, and never inside the acquisition window.
  // On macOS this spawns `sysctl`; between our mkdir and the pid write that
  // spawn would leave the lock pid-less for the length of the probe, and a
  // contender is entitled to remove a pid-less lock older than the grace. That
  // is two writers in the critical section this lock exists to prevent.
  const bootId = hostBootId(childEnv());
  const processStart = hostProcessStart(process.pid, childEnv());
  const deadline = Date.now() + (wait ? tokenStoreLockWaitMs() : 0);
  while (true) {
    try {
      fs.mkdirSync(lockPath, { mode: 0o700 });
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
      if (removeStaleTokenStoreLock(lockPath)) continue;
      if (Date.now() >= deadline) {
        die(`timed out waiting for the token store lock; another runfree command is syncing tokens for this project (lock: ${lockPath})`);
      }
      sleepSyncMs(100);
      continue;
    }
    try {
      stampLockOwner(lockPath, bootId, processStart);
      return;
    } catch {
      // The lock dir was stolen between our mkdir and the pid write (a
      // contender past the pid-less grace). Drop any remnant of our claim and
      // contend again instead of crashing the sync.
      fs.rmSync(lockPath, { recursive: true, force: true });
    }
  }
}

export function withTokenStoreLock<T>(action: () => T, options: { wait?: boolean } = {}): T {
  const lockPath = tokenStoreLockPath();
  const depth = heldTokenStoreLockDepths.get(lockPath) ?? 0;
  if (depth > 0) {
    heldTokenStoreLockDepths.set(lockPath, depth + 1);
    try {
      return action();
    } finally {
      heldTokenStoreLockDepths.set(lockPath, depth);
    }
  }
  acquireTokenStoreLock(lockPath, options.wait);
  heldTokenStoreLockDepths.set(lockPath, 1);
  try {
    return action();
  } finally {
    heldTokenStoreLockDepths.delete(lockPath);
    fs.rmSync(lockPath, { recursive: true, force: true });
  }
}

// Possession check: one batched listing of the proxy secret directory per sync
// run (never one exec per token), over the same trusted host→proxy channel as
// the token write path. Returns undefined when the listing itself fails — the
// caller must then treat the proxy as unreachable rather than infer absence.
function listProxyRuntimeTokens(proxyId: string): Set<string> | undefined {
  const result = runCapture("docker", ["exec", proxyId, "sh", "-c", `ls -1 ${shellSingleQuote(CONTAINER_SECRET_DIR)}`]);
  if (result.status !== 0) return undefined;
  return new Set(result.stdout.split(/\r?\n/).map((line) => line.trim()).filter((name) => isTokenName(name)));
}

export function importStartupTokenResolutionReceipts(input: {
  config: TokenSourceConfig;
  ledger: TokenResolutionLedger;
  policy: LoadedNetworkPolicy;
  proxyStoreGeneration: string;
  sourceRegistry: SourceRegistry | undefined;
  // Import these receipts instead of the ledger's fd-3 startup receipts (used
  // for persisted receipts loaded from host state). Deduplication still runs
  // through the ledger's importedStartupReceipts set.
  receipts?: TokenResolutionReceipt[];
}): void {
  for (const receipt of input.receipts ?? input.ledger.startupReceipts) {
    const receiptId = `${receipt.tokenName}\0${receipt.sourceFingerprint}\0${receipt.proxyStoreGeneration}\0${receipt.resolvedAt}`;
    if (input.ledger.importedStartupReceipts.has(receiptId)) continue;
    if (receipt.proxyStoreGeneration !== input.proxyStoreGeneration) continue;
    if (!input.policy.tokens[receipt.tokenName]) continue;
    const source = input.config[receipt.tokenName];
    if (!source) continue;
    let sourceFingerprint: string;
    try {
      sourceFingerprint = tokenSourceFingerprint(source, input.sourceRegistry);
    } catch {
      continue;
    }
    if (sourceFingerprint !== receipt.sourceFingerprint) continue;
    const key = tokenResolutionLedgerKey(receipt.tokenName, sourceFingerprint, input.proxyStoreGeneration);
    input.ledger.lastResolvedAt.set(key, receipt.resolvedAt);
    input.ledger.retryAfterFailureAt.delete(key);
    input.ledger.importedStartupReceipts.add(receiptId);
  }
}

// Seed a due-decision ledger from both receipt channels in their documented
// precedence: the fd-3 startup receipts first, then the persisted host-state
// receipts (first import of a receipt id wins via importedStartupReceipts).
// syncTokens passes its lock-guarded, possession-pruned receipt map; advisory
// callers (the watcher's delay computation) default to a fresh snapshot.
export function seedTokenResolutionLedger(input: {
  config: TokenSourceConfig;
  ledger: TokenResolutionLedger;
  policy: LoadedNetworkPolicy;
  proxyStoreGeneration: string;
  sourceRegistry: SourceRegistry | undefined;
  persistedReceipts?: TokenResolutionReceipt[];
}): void {
  importStartupTokenResolutionReceipts(input);
  importStartupTokenResolutionReceipts({
    ...input,
    receipts: input.persistedReceipts ?? loadPersistedTokenReceiptsSnapshot(),
  });
}

function tokenRetryDelayMs(config: TokenSourceConfig, registry: SourceRegistry | undefined): number {
  const intervals = Object.values(config)
    .map((source) => {
      const refresh = effectiveTokenRefresh(source, registry);
      return refresh.mode === "manual" ? undefined : refresh.seconds * 1000;
    })
    .filter((value): value is number => value !== undefined);
  if (intervals.length === 0) return 60_000;
  return Math.min(Math.min(...intervals), 60_000);
}

export function formatDelayMs(delayMs: number): string {
  return formatDurationSeconds(Math.max(1, Math.ceil(delayMs / 1000)));
}

function tokenDueDecision(input: {
  // Live possession listing of the proxy secret dir; undefined when the proxy
  // is not ready. A ledger skip is honored only when the proxy provably holds
  // the token's tmpfs file, so a resurrected receipt (concurrent writer) can
  // only cause a redundant re-resolution, never a skip for an absent value.
  heldTokens: Set<string> | undefined;
  ledger: TokenResolutionLedger | undefined;
  nowMs: number;
  proxyStoreGeneration: string | undefined;
  refresh: EffectiveTokenRefresh;
  source: TokenSource;
  sourceRegistry: SourceRegistry | undefined;
  tokenName: string;
}): TokenDueDecision {
  if (!input.ledger || !input.proxyStoreGeneration) {
    return { due: true, reason: "no current-generation ledger" };
  }
  const sourceFingerprint = tokenSourceFingerprint(input.source, input.sourceRegistry);
  const key = tokenResolutionLedgerKey(input.tokenName, sourceFingerprint, input.proxyStoreGeneration);
  const retryAt = input.ledger.retryAfterFailureAt.get(key);
  if (retryAt !== undefined) {
    if (input.nowMs < retryAt) {
      return {
        due: false,
        key,
        nextDueAt: retryAt,
        reason: `retry pending (next in ${formatDelayMs(retryAt - input.nowMs)})`,
        sourceFingerprint,
      };
    }
    return { due: true, key, reason: "retry after failure", sourceFingerprint };
  }

  const lastResolvedAt = input.ledger.lastResolvedAt.get(key);
  if (lastResolvedAt === undefined) {
    return { due: true, key, reason: "current token-store generation unpopulated", sourceFingerprint };
  }

  if (!input.heldTokens?.has(input.tokenName)) {
    return { due: true, key, reason: "resolved before but proxy does not hold the value", sourceFingerprint };
  }

  if (input.refresh.mode === "manual") {
    return {
      due: false,
      key,
      reason: "manual current token-store generation already populated",
      sourceFingerprint,
    };
  }

  const dueAt = lastResolvedAt + input.refresh.seconds * 1000;
  if (input.nowMs >= dueAt) return { due: true, key, reason: "due", sourceFingerprint };
  return {
    due: false,
    key,
    nextDueAt: dueAt,
    reason: `not due (next in ${formatDelayMs(dueAt - input.nowMs)})`,
    sourceFingerprint,
  };
}

export function tokenSyncWatchNowMs(): number {
  const value = childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS;
  if (childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && value && /^[0-9]{1,13}$/.test(value)) return Number(value);
  return Date.now();
}

type TokenSyncResult = {
  failed: string[];
  // Tokens whose resolution failed transiently but whose receipt-proven proxy
  // value was kept (status `stale`). Separate from `failed` so quiet
  // convergence flows (policy mutations, session startup) can treat them as
  // warnings — the proxy still injects a working value and the watcher
  // retries — while explicit `runfree credential sync` still reports failure.
  stale: string[];
  failedMessages: Record<string, string>;
  changed: boolean;
  receipts: TokenResolutionReceipt[];
  runtimeState: ProxyRuntimeState;
  // Advisory snapshot for schedulers (the watcher's delay computation), so a
  // caller that just synced does not re-derive the runtime via docker.
  storeGeneration?: string;
};

export function syncTokens(options: TokenSyncOptions = {}): TokenSyncResult {
  const effective = assertEffectiveControlConvergedBeforeCredentialResolution();
  try {
    const policy = effective
      ? validateNetworkPolicy(effective.policy, effective.networkPolicyPath)
      : loadPolicy();
    ensureStateDirs();
    return withTokenStoreLock(() => syncTokensUnderLock(options, policy, effective));
  } finally {
    effective?.lock.release();
  }
}

type EffectiveCredentialSnapshot = {
  controlGeneration: string;
  networkPolicyPath: string;
  policy: PolicyJson;
  project: ProjectInfo;
  lock: ControlLock;
};

class EffectiveControlSelectionChanged extends Error {}

const preparedRuntimeTokenSources = new Map<string, {
  controlGeneration: string;
  preparedAt: number;
  admittedAt?: number;
  tokenConfigPath: string;
  sourceConfigPath: string;
  values: Map<string, { fingerprint: string; value: string }>;
}>();

/** Host-only memory. Resolve prompts before proxy disruption; never stage token files. */
export function prepareRuntimeTokenSources(): void {
  const project = currentAdminState().runtimeContext?.project ?? adminProjectInfo();
  preparedRuntimeTokenSources.delete(project.paths.stateDir);
  const active = readActiveEffectiveControl(project);
  if (!active) throw new Error("runtime credential preparation requires approved effective policy");
  const policy = validateNetworkPolicy(active.policy, active.networkPolicyPath);
  const config = loadTokenConfig();
  const registry = Object.values(config).some((source) => source.source === "named") ? loadSourceRegistry() : undefined;
  const values = new Map<string, { fingerprint: string; value: string }>();
  for (const [name, tokenPolicy] of Object.entries(policy.tokens)) {
    const source = config[name];
    if (!source) {
      if (tokenPolicy.allowAnonymous) continue;
      throw new Error(missingRequiredTokenSourceMessage(name));
    }
    const sourceRegistry = source.source === "named" ? registry : undefined;
    values.set(name, { fingerprint: tokenSourceFingerprint(source, sourceRegistry),
      value: resolveTokenSource(name, source, { quiet: true, sourceRegistry }) });
  }
  if (readActiveControlSelection(project)?.controlGeneration !== active.controlGeneration) {
    throw new EffectiveControlSelectionChanged("effective policy changed during credential preparation; retry before proxy disruption");
  }
  preparedRuntimeTokenSources.set(project.paths.stateDir, { controlGeneration: active.controlGeneration, preparedAt: Date.now(), tokenConfigPath: tokenConfigPath(), sourceConfigPath: sourceConfigPath(), values });
}

function assertPreparedTokenSourceInputs(
  prepared: NonNullable<ReturnType<typeof preparedRuntimeTokenSources.get>>,
  policy: LoadedNetworkPolicy,
  config: TokenSourceConfig,
  registry: SourceRegistry | undefined,
): readonly string[] {
  const names = Object.entries(policy.tokens).filter(([name, token]) => config[name] || !token.allowAnonymous).map(([name]) => name).sort();
  if (!isDeepStrictEqual([...prepared.values.keys()].sort(), names)) {
    throw new EffectiveControlSelectionChanged("prepared credential set changed before disruption or sync; resolve current sources and retry");
  }
  for (const name of names) {
    const source = config[name];
    if (!source || source.source === "named" && !registry?.[source.name]
      || prepared.values.get(name)?.fingerprint !== tokenSourceFingerprint(source, source.source === "named" ? registry : undefined)) {
      throw new EffectiveControlSelectionChanged("prepared credential source changed before disruption or sync; resolve current sources and retry");
    }
  }
  return names;
}

/** Bind one prepared source snapshot to one bounded admitted lifecycle operation. */
export function admitPreparedRuntimeTokenSources(project: ProjectInfo): void {
  const prepared = preparedRuntimeTokenSources.get(project.paths.stateDir);
  if (!prepared) return;
  const now = Date.now();
  const anchor = prepared.admittedAt ?? prepared.preparedAt;
  if (now < anchor || now - anchor >= 120_000
    || readActiveControlSelection(project)?.controlGeneration !== prepared.controlGeneration) {
    throw new EffectiveControlSelectionChanged("prepared credential inputs expired or changed before disruption; resolve them again and retry");
  }
  const active = readActiveEffectiveControl(project);
  if (!active || active.controlGeneration !== prepared.controlGeneration) {
    throw new EffectiveControlSelectionChanged("prepared credential policy changed before disruption; resolve current sources and retry");
  }
  // Admission also runs outside admin ambient state during startup. Read the
  // exact host metadata paths captured by preparation, without resolving any
  // credential or invoking an external source while the lifecycle lock is held.
  const config = parseTokenSourceConfig(readJsonFile<unknown>(prepared.tokenConfigPath, {}), prepared.tokenConfigPath);
  const registry = Object.values(config).some((source) => source.source === "named")
    ? validateSourceRegistry(readJsonFile<unknown>(prepared.sourceConfigPath, {}), prepared.sourceConfigPath) : undefined;
  assertPreparedTokenSourceInputs(prepared, validateNetworkPolicy(active.policy, active.networkPolicyPath), config, registry);
  prepared.admittedAt ??= now;
}

export function clearPreparedRuntimeTokenSources(project: ProjectInfo): void {
  preparedRuntimeTokenSources.delete(project.paths.stateDir);
}

function resolvePreparedRuntimeTokenSource(name: string, source: TokenSource, options: TokenResolutionOptions): string {
  const project = currentAdminState().runtimeContext?.project ?? adminProjectInfo();
  const prepared = preparedRuntimeTokenSources.get(project.paths.stateDir);
  if (!prepared) return resolveTokenSource(name, source, options);
  const entry = prepared.values.get(name);
  if (!entry || entry.fingerprint !== tokenSourceFingerprint(source, options.sourceRegistry)
    || readActiveControlSelection(project as ProjectInfo)?.controlGeneration !== prepared.controlGeneration
    || Date.now() < (prepared.admittedAt ?? prepared.preparedAt) || Date.now() - (prepared.admittedAt ?? prepared.preparedAt) >= 120_000) {
    throw new EffectiveControlSelectionChanged("prepared credential inputs changed or expired; rerun runtime recovery to resolve them before disruption");
  }
  return entry.value;
}

function assertEffectiveControlConvergedBeforeCredentialResolution(): EffectiveCredentialSnapshot | undefined {
  if (currentAdminState().policyAccess !== "effective-read-only") return undefined;
  const discovered = projectInfo(projectRoot(), childEnv());
  const project: ProjectInfo = {
    ...discovered,
    paths: {
      ...discovered.paths,
      ...projectControlPaths(stateDir()),
      stateDir: stateDir(),
    },
  };
  const lock = tryAcquireControlLock(project, childEnv());
  if (!lock) die("credential resolution cannot start while another control operation is in progress");
  try {
    const active = readActiveControlSelection(project);
    const converged = readConvergedPolicyReceipt(project);
    if (!active || !converged || converged.controlGeneration !== active.controlGeneration) {
      die("credential resolution requires a selected effective policy generation with complete convergence");
    }
    const runtime = proxyRuntime();
    if (runtime.state !== "ready" || !runtime.id) {
      die(`credential resolution requires a validated running proxy; runtime is ${runtime.state}${runtime.validationMessage ? ` (${runtime.validationMessage})` : ""}`);
    }
    const status = readProxyPolicyStatusFiles(runtime.id);
    const requestProxyMatches = status?.requestProxy?.controlGeneration === active.controlGeneration
      && status.requestProxy.policyGeneration === converged.policyGeneration;
    const firewallMatches = status?.firewall?.controlGeneration === active.controlGeneration
      && status.firewall.policyGeneration === converged.policyGeneration
      && status.firewall.rulesetVerified === true;
    if (!requestProxyMatches || !firewallMatches) {
      die("credential resolution requires request-proxy and firewall acknowledgement of the selected effective policy generation");
    }
    const effective = readActiveEffectiveControl(project);
    if (!effective || effective.controlGeneration !== active.controlGeneration) {
      die("selected effective controls changed during credential preflight");
    }
    return {
      controlGeneration: effective.controlGeneration,
      networkPolicyPath: effective.networkPolicyPath,
      policy: effective.policy,
      project,
      lock,
    };
  } catch (error) {
    lock.release();
    throw error;
  }
}

function syncTokensUnderLock(
  options: TokenSyncOptions,
  policy: LoadedNetworkPolicy,
  effective?: EffectiveCredentialSnapshot,
): TokenSyncResult {
  let exactRuntime: ProxyRuntime | undefined;
  const rebindProject = { projectId: projectId(), composeProject: composeProject() ?? `runfree-${projectId()}` };
  const rebindAtStart = readControlPlaneRebindTransaction(stateDir(), rebindProject);
  const rebindReceipt = rebindAtStart ? serializeControlPlaneRebindTransaction(rebindAtStart) : undefined;
  const assertSelection = (): void => {
    if (effective && readActiveControlSelection(effective.project)?.controlGeneration !== effective.controlGeneration) {
      throw new EffectiveControlSelectionChanged("selected effective controls changed during credential sync");
    }
    if (exactRuntime?.state === "ready") {
      const rebind = readControlPlaneRebindTransaction(stateDir(), rebindProject);
      if ((rebind ? serializeControlPlaneRebindTransaction(rebind) : undefined) !== rebindReceipt
        || rebind && (CONTROL_PLANE_REBIND_PHASES.indexOf(rebind.phase) < CONTROL_PLANE_REBIND_PHASES.indexOf("control-selected")
          || rebind.candidateControlPlane?.proxyContainerId !== exactRuntime.id
          || rebind.recovery && (rebind.recovery.allowance.exhausted || Date.now() >= Date.parse(rebind.recovery.allowance.deadlineAt)
            || Date.now() < Date.parse(rebind.recovery.allowance.lastObservedAt)))) {
        throw new EffectiveControlSelectionChanged("proxy replacement receipt or recovery allowance changed before credential write; resume runtime recover");
      }
      const observed = readyProxyRuntime(exactRuntime.id as string);
      if (observed.state !== "ready" || observed.storeGeneration !== exactRuntime.storeGeneration
        || (readEffectiveControlPlaneV2(stateDir())?.selection.proxyContainerId ?? exactRuntime.id) !== exactRuntime.id) {
        throw new EffectiveControlSelectionChanged("exact proxy or token store changed during credential resolution; retry sync against fresh runtime evidence");
      }
    }
  };
  assertSelection();
  const status = loadTokenStatus();
  const runtime = proxyRuntime();
  exactRuntime = runtime;
  adminVerbose(options, `proxy runtime state is ${runtime.state}`);

  const failed: string[] = [];
  const stale: string[] = [];
  const failedMessages: Record<string, string> = {};
  const receipts: TokenResolutionReceipt[] = [];
  const syncNowMs = options.resolutionLedger ? tokenSyncWatchNowMs() : Date.now();
  let changed = false;

  const persistedReceipts = loadPersistedTokenReceipts();
  let receiptsChanged = false;
  const retractReceipt = (tokenName: string) => {
    if (persistedReceipts.delete(tokenName)) receiptsChanged = true;
  };
  const recordReceipt = (receipt: TokenResolutionReceipt) => {
    persistedReceipts.set(receipt.tokenName, receipt);
    receiptsChanged = true;
  };
  const result = (runtimeState: ProxyRuntimeState): TokenSyncResult => {
    if ((failed.length > 0 || stale.length > 0) && options.exitOnFailure) process.exitCode = 1;
    return { failed, stale, failedMessages, changed, receipts, runtimeState, storeGeneration: runtime.storeGeneration };
  };
  const finish = (): TokenSyncResult => {
    saveTokenStatus(status);
    if (receiptsChanged) savePersistedTokenReceipts(persistedReceipts);
    return result(runtime.state);
  };
  // Shared fail-closed bookkeeping for every per-token failure branch. The
  // unreachable paths below deliberately do NOT use it: they must leave
  // status records untouched.
  const markFailed = (tokenName: string, message: string, extra: { source?: string; syncedAt?: string; report?: string } = {}) => {
    status[tokenName] = {
      ...(extra.source !== undefined ? { source: extra.source } : {}),
      ok: false,
      state: "failed",
      syncedAt: extra.syncedAt ?? new Date().toISOString(),
      message,
    };
    failed.push(tokenName);
    failedMessages[tokenName] = message;
    if (!options.quiet) console.error(`${tokenName}: ${extra.report ?? message}`);
  };
  // "Report, change nothing": the unreachable paths announce the failure and
  // return without touching per-token status records, receipts, or the store —
  // the proxy still holds and injects every value, so rewriting an `ok`/`stale`
  // record to `failed` here would misreport a healthy session.
  const reportRunUnreachable = (): TokenSyncResult => {
    const message = runtimeStateMessage("proxy-unreachable");
    for (const tokenName of Object.keys(policy.tokens)) {
      failed.push(tokenName);
      failedMessages[tokenName] = message;
      if (!options.quiet) console.error(`${tokenName}: ${message}`);
    }
    return result("proxy-unreachable");
  };

  // A transient docker-exec failure (validation marker, StartedAt) means the
  // store generation cannot be determined for an unchanged container. Fail the
  // run: report, delete nothing, resolve nothing, write no receipts.
  if (runtime.state === "proxy-unreachable") {
    return reportRunUnreachable();
  }

  // Possession check: the single batched secret-dir listing for this run.
  // Kept current across writes/removes below so end-of-run receipt pruning
  // sees tokens written this run. A failed listing is a transport failure on
  // the same channel as writes — treated like proxy-unreachable, never as
  // evidence of absence.
  let heldTokens: Set<string> | undefined;
  if (runtime.state === "ready" && runtime.id) {
    heldTokens = listProxyRuntimeTokens(runtime.id);
    if (heldTokens === undefined) {
      return reportRunUnreachable();
    }
  }

  // Prune receipts that no longer prove possession: dead generations (any
  // container restart) and tokens whose tmpfs file is gone (deleted by a
  // concurrent process after this file was written — resurrection guard).
  if (heldTokens && runtime.storeGeneration) {
    for (const [tokenName, receipt] of persistedReceipts) {
      if (receipt.proxyStoreGeneration !== runtime.storeGeneration || !heldTokens.has(tokenName)) {
        retractReceipt(tokenName);
      }
    }
  }

  if (runtime.state === "validation-required") {
    options.sourceSecretCache?.jwtPrivateKeys.clear();
    options.resolutionLedger?.lastResolvedAt.clear();
    options.resolutionLedger?.retryAfterFailureAt.clear();
    const message = runtimeStateMessage(runtime.state, runtime.validationMessage);
    if (runtime.id) {
      changed = cleanupProxyRuntimeTokens(runtime.id, [
        ...Object.keys(policy.tokens),
        ...tokenConfigNamesForCleanup(),
      ]) || changed;
    }
    // The wipe removed every tmpfs value, so every possession claim is void.
    if (persistedReceipts.size > 0) {
      persistedReceipts.clear();
      receiptsChanged = true;
    }
    for (const tokenName of Object.keys(policy.tokens)) {
      markFailed(tokenName, message);
    }
    return finish();
  }
  let config: TokenSourceConfig;
  try {
    config = loadTokenConfig();
  } catch (error) {
    // Project-reachable parse/validation failure: unconditional fail-closed
    // delete (never keep-last-good), and every removal retracts its receipt.
    options.sourceSecretCache?.jwtPrivateKeys.clear();
    options.resolutionLedger?.lastResolvedAt.clear();
    options.resolutionLedger?.retryAfterFailureAt.clear();
    const message = error instanceof Error ? error.message : String(error);
    assertSelection();
    for (const tokenName of Object.keys(policy.tokens)) {
      if (runtime.id) {
        try {
          removeProxyRuntimeToken(runtime.id, tokenName);
          changed = true;
          heldTokens?.delete(tokenName);
        } catch {
          // Keep the config validation failure as the primary user-facing error.
        }
      }
      retractReceipt(tokenName);
      markFailed(tokenName, message);
    }
    return finish();
  }
  let sourceRegistry: SourceRegistry | undefined;
  let sourceRegistryError: unknown;
  if (Object.values(config).some((source) => source.source === "named")) {
    try {
      sourceRegistry = loadSourceRegistry();
    } catch (error) {
      sourceRegistryError = error;
    }
  }
  // The effective ledger for due decisions. Source-truth syncs run ledger-less
  // (every token due, every source re-read — the revocation/rotation path);
  // convergence syncs get a run-local ledger seeded from persisted receipts;
  // the watcher passes its own long-lived ledger and additionally recovers
  // persisted receipts (so a watcher restart does not re-prompt).
  const ledger = options.resolutionLedger
    ?? (options.mode === "convergence" ? newTokenResolutionLedger() : undefined);
  if (ledger && runtime.storeGeneration && sourceRegistryError === undefined) {
    seedTokenResolutionLedger({
      config,
      ledger,
      policy,
      proxyStoreGeneration: runtime.storeGeneration,
      sourceRegistry,
      persistedReceipts: Array.from(persistedReceipts.values()),
    });
  }
  const prepared = preparedRuntimeTokenSources.get(stateDir());
  if (prepared) {
    if (sourceRegistryError) throw new EffectiveControlSelectionChanged("prepared source registry changed; restore its metadata before retrying sync");
    const expectedNames = assertPreparedTokenSourceInputs(prepared, policy, config, sourceRegistry);
    for (const name of expectedNames) resolvePreparedRuntimeTokenSource(name, config[name], { quiet: true, sourceRegistry: config[name].source === "named" ? sourceRegistry : undefined });
  }
  const retryDelayMs = sourceRegistryError === undefined ? tokenRetryDelayMs(config, sourceRegistry) : 60_000;
  // Fences sit before each side-effect phase: the removal below, source
  // resolution, the proxy write, the failure removal, and the post-loop
  // cleanup and persistence. A token that is not due takes no action, so it
  // needs no proxy re-observation.
  for (const [tokenName, tokenPolicy] of Object.entries(policy.tokens)) {
    const source = config[tokenName];
    if (!source) {
      assertSelection();
      // Intentional local state change (source removed): immediate delete and
      // receipt retraction, never receipt-gated.
      if (runtime.id) {
        removeProxyRuntimeToken(runtime.id, tokenName);
        changed = true;
        heldTokens?.delete(tokenName);
      }
      retractReceipt(tokenName);
      if (tokenPolicy.allowAnonymous === true) {
        status[tokenName] = {
          ok: true,
          syncedAt: new Date().toISOString(),
          message: "unconfigured; anonymous fallback enabled",
        };
      } else {
        markFailed(tokenName, missingRequiredTokenSourceMessage(tokenName));
      }
      continue;
    }

    try {
      if (source.source === "named" && sourceRegistryError !== undefined) {
        throw sourceRegistryError;
      }
      const registryForSource = source.source === "named" ? sourceRegistry : undefined;
      const refresh = effectiveTokenRefresh(source, registryForSource);
      assertRefreshBeforeJwtExpiry(refresh);
      const due = tokenDueDecision({
        heldTokens,
        ledger,
        nowMs: syncNowMs,
        proxyStoreGeneration: runtime.storeGeneration,
        refresh,
        source,
        sourceRegistry: registryForSource,
        tokenName,
      });
      if (!due.due) {
        adminVerbose(options, `${tokenName}: skipped (${due.reason})`);
        continue;
      }
      adminVerbose(options, `${tokenName}: resolving ${describeSource(source)} source (${due.reason})`);
      assertSelection();
      const value = resolvePreparedRuntimeTokenSource(tokenName, source, { ...options, sourceRegistry: registryForSource });
      assertSelection();
      if (runtime.id) {
        adminVerbose(options, `${tokenName}: writing token value to proxy-only tmpfs`);
        writeProxyRuntimeToken(runtime.id, tokenName, value);
        changed = true;
        heldTokens?.add(tokenName);
      } else {
        adminVerbose(options, `${tokenName}: source verified; proxy tmpfs write skipped because runtime is ${runtime.state}`);
      }
      if (runtime.storeGeneration) {
        const sourceFingerprint = due.sourceFingerprint ?? tokenSourceFingerprint(source, registryForSource);
        if (due.key) {
          ledger?.lastResolvedAt.set(due.key, syncNowMs);
          ledger?.retryAfterFailureAt.delete(due.key);
        }
        const receipt = {
          tokenName,
          sourceFingerprint,
          proxyStoreGeneration: runtime.storeGeneration,
          resolvedAt: syncNowMs,
        };
        receipts.push(receipt);
        recordReceipt(receipt);
      }
      status[tokenName] = {
        source: source.source,
        ok: true,
        state: "ok",
        syncedAt: new Date(syncNowMs).toISOString(),
        message: runtimeStateMessage(runtime.state),
      };
      if (!options.quiet) console.log(`${tokenName}: ${runtimeStateMessage(runtime.state, runtime.validationMessage)} from ${describeSource(source)}`);
    } catch (error) {
      if (error instanceof EffectiveControlSelectionChanged) throw error;
      clearCachedSourceSecret(source, options.sourceSecretCache);
      let failureFingerprint: string | undefined;
      try {
        const registryForSource = source.source === "named" && sourceRegistryError === undefined ? sourceRegistry : undefined;
        failureFingerprint = tokenSourceFingerprint(source, registryForSource);
      } catch {
        // The source-resolution failure remains the user-facing diagnostic.
      }
      if (ledger && runtime.storeGeneration && failureFingerprint) {
        const key = tokenResolutionLedgerKey(tokenName, failureFingerprint, runtime.storeGeneration);
        ledger.retryAfterFailureAt.set(key, syncNowMs + retryDelayMs);
      }
      const message = error instanceof Error ? error.message : String(error);
      // Keep-last-good: scoped strictly to this source-resolution catch block
      // (see keepLastGoodReceipt for the full decision).
      const keptReceipt = keepLastGoodReceipt({
        error,
        receipt: persistedReceipts.get(tokenName),
        sourceFingerprint: failureFingerprint,
        storeGeneration: runtime.storeGeneration,
        held: heldTokens?.has(tokenName) === true,
        nowMs: syncNowMs,
      });
      if (keptReceipt) {
        const heldValueResolvedAt = new Date(keptReceipt.resolvedAt).toISOString();
        const staleMessage = `${message}; keeping last-good proxy value resolved at ${heldValueResolvedAt} (stale)`;
        status[tokenName] = {
          source: source.source,
          ok: false,
          state: "stale",
          heldValueResolvedAt,
          syncedAt: new Date(syncNowMs).toISOString(),
          message,
        };
        stale.push(tokenName);
        failedMessages[tokenName] = staleMessage;
        if (!options.quiet) console.error(`${tokenName}: sync failed (${staleMessage})`);
        continue;
      }
      // The failure may precede the pre-resolution fence (source registry,
      // refresh, or due checks), so fence the removal itself.
      assertSelection();
      if (runtime.id) {
        try {
          removeProxyRuntimeToken(runtime.id, tokenName);
          changed = true;
          heldTokens?.delete(tokenName);
        } catch {
          // Keep the source-resolution failure as the primary user-facing error.
        }
      }
      retractReceipt(tokenName);
      markFailed(tokenName, message, {
        source: source.source,
        syncedAt: new Date(syncNowMs).toISOString(),
        report: `sync failed (${message})`,
      });
    }
  }

  // Skipped tokens take no fence, so re-observe before the dropped-token
  // removals and the status/receipt persistence in finish().
  assertSelection();
  for (const [tokenName, source] of Object.entries(config)) {
    if (policy.tokens[tokenName]) continue;

    // Token dropped from policy: immediate delete plus receipt retraction.
    if (runtime.id) {
      try {
        removeProxyRuntimeToken(runtime.id, tokenName);
        changed = true;
        heldTokens?.delete(tokenName);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        markFailed(tokenName, message, { source: source.source, report: `cleanup failed (${message})` });
        continue;
      }
    }
    retractReceipt(tokenName);

    status[tokenName] = {
      source: source.source,
      ok: true,
      syncedAt: new Date().toISOString(),
      message: runtime.id
        ? "unused local source; proxy tmpfs token removed"
        : `unused local source; proxy sync pending (${runtime.state})`,
    };
  }

  return finish();
}

// --- Credential: typed intents + enforcement ---------------------------------

export type CredentialAddInput = {
  name: string;
  credential: CredentialFieldsInput;
  description?: string;
  reloadProxy: boolean;
  tokenSource?: TokenSourceSelection;
  refreshEvery?: string;
  replaceSource?: boolean;
  sync?: boolean;
};
export type CredentialLinkInput = { name: string; credential: CredentialFieldsInput; reloadProxy: boolean };
export type CredentialUnlinkInput = { name: string; host: string; header?: string; reloadProxy: boolean };
export type CredentialRemoveInput = { name: string; reloadProxy: boolean };
export type CredentialSetSourceInput = { name: string; tokenSource: TokenSourceSelection; refreshEvery?: string; replaceSource: boolean; sync: boolean };
export type CredentialClearSourceInput = { name: string };
export type CredentialStatusInput = { name?: string };
export type CredentialSyncInput = { verbose: boolean; watch: boolean; quiet: boolean; delayFirstSync: boolean; cacheSourceSecrets: boolean };

// --- Source: typed intents + enforcement ------------------------------------

export type SourceNameInput = { name: string };

// `source add` typed inputs. The yargs front-end performs the `--` split (command
// form) and flag parsing (jwt form); enforcement re-validates everything. JWT
// scalar fields accept string|string[] so a repeated flag becomes a "given once"
// error in enforcement rather than silently taking the last value.
export type SourceAddCommandInput = {
  name: string | undefined;
  replaceSource: boolean;
  command: string[];
};
export type SourceAddJwtInput = {
  name: string | undefined;
  replaceSource: boolean;
  alg: string | string[] | undefined;
  privateKeyRef: string | string[] | undefined;
  ttl: string | string[] | undefined;
  claims: string[];
  headers: string[];
};

type OAuthSeedHandleStore = {
  schemaVersion: 1;
  providers: Record<string, Partial<Record<ServiceOAuthCredential["seeds"][number]["field"], string>>>;
};

export function oauthMediationPolicyPath(): string {
  return childEnv().RUNFREE_OAUTH_POLICY_HOST_PATH
    ?? childEnv().RUNFREE_MCP_OAUTH_POLICY_HOST_PATH
    ?? path.join(stateDir(), "oauth-mediation-policy.json");
}

export function mcpOperationPolicyPath(): string {
  return childEnv().RUNFREE_MCP_OPERATION_POLICY_HOST_PATH
    ?? path.join(stateDir(), "mcp-operation-policy.json");
}

function oauthSeedHandlesPath(): string {
  return path.join(stateDir(), "oauth-handles.json");
}

export function serviceOAuthProviderId(svc: Service): string {
  return `service:${svc.id}`;
}

export function readOAuthSeedHandleStore(): OAuthSeedHandleStore {
  const raw = readJsonFile<unknown>(oauthSeedHandlesPath(), { schemaVersion: 1, providers: {} });
  if (!isRecord(raw) || raw.schemaVersion !== 1 || !isRecord(raw.providers)) {
    return { schemaVersion: 1, providers: {} };
  }
  const providers: OAuthSeedHandleStore["providers"] = {};
  for (const [providerId, handles] of Object.entries(raw.providers)) {
    if (!isRecord(handles)) continue;
    providers[providerId] = {};
    for (const field of ["refresh_token", "client_secret"] as const) {
      const value = handles[field];
      if (typeof value === "string" && value.startsWith(field === "refresh_token" ? "runfree_oauth_refresh_" : "runfree_oauth_secret_")) {
        providers[providerId][field] = value;
      }
    }
  }
  return { schemaVersion: 1, providers };
}

export function saveOAuthSeedHandleStore(store: OAuthSeedHandleStore): void {
  writeJsonFile(oauthSeedHandlesPath(), store, 0o600);
}

function newOAuthSeedHandle(field: ServiceOAuthCredential["seeds"][number]["field"]): string {
  const prefix = field === "refresh_token" ? "runfree_oauth_refresh_" : "runfree_oauth_secret_";
  return `${prefix}${crypto.randomBytes(32).toString("base64url")}`;
}

function ensureOAuthSeedHandles(providerId: string, oauth: ServiceOAuthCredential): Record<string, string> {
  const store = readOAuthSeedHandleStore();
  store.providers[providerId] ??= {};
  let changed = false;
  const handles: Record<string, string> = {};
  for (const seed of oauth.seeds) {
    const existing = store.providers[providerId][seed.field];
    const handle = existing ?? newOAuthSeedHandle(seed.field);
    if (!existing) {
      store.providers[providerId][seed.field] = handle;
      changed = true;
    }
    handles[seed.field] = handle;
  }
  if (changed) saveOAuthSeedHandleStore(store);
  return handles;
}

export function tokenEndpointParts(endpoint: string): { host: string; path: string } {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    die(`invalid OAuth token endpoint in service registry: ${endpoint}`);
  }
  if (parsed.protocol !== "https:") die(`OAuth token endpoint must be HTTPS: ${endpoint}`);
  return {
    host: normalizeHostname(parsed.hostname),
    path: normalizePathPrefix(parsed.pathname || "/"),
  };
}

export function setAgentEnvValues(values: Record<string, string>): { changed: string[]; unchanged: string[] } {
  const entries = readAgentEnv();
  const changed: string[] = [];
  const unchanged: string[] = [];
  for (const [name, value] of Object.entries(values)) {
    if (entries[name] === value) {
      unchanged.push(name);
      continue;
    }
    entries[name] = value;
    changed.push(name);
  }
  if (changed.length > 0) saveAgentEnv(entries);
  return {
    changed: changed.sort(),
    unchanged: unchanged.sort(),
  };
}

export function removeAgentEnvValues(names: string[], expected?: Record<string, string>): string[] {
  const entries = readAgentEnv();
  const removed: string[] = [];
  for (const name of names) {
    if (!(name in entries)) continue;
    if (expected && expected[name] !== undefined && entries[name] !== expected[name]) continue;
    delete entries[name];
    removed.push(name);
  }
  if (removed.length > 0) saveAgentEnv(entries);
  return removed.sort();
}

export function serviceOAuthAgentSeedEnv(svc: Service & { oauthCredential: ServiceOAuthCredential }): Record<string, string> {
  const handles = ensureOAuthSeedHandles(serviceOAuthProviderId(svc), svc.oauthCredential);
  return Object.fromEntries(svc.oauthCredential.seeds.map((seed) => [seed.envVar, handles[seed.field]]));
}

// Agent env values the host keeps as written (never normalized to the
// placeholder): OAuth seed handles for every recorded OAuth service, and the
// recorded value of every declared service parameter.
function serviceHostOwnedAgentEnvValues(entries: Record<string, string>): Record<string, string> {
  const values: Record<string, string> = {};
  const records = loadServiceRecords();
  for (const id of Object.keys(records).sort()) {
    const svc = service(id);
    if (!svc) continue;
    if (serviceHasOAuthCredential(svc)) Object.assign(values, serviceOAuthAgentSeedEnv(svc));
    for (const parameter of serviceParameters(svc)) {
      const current = entries[parameter.envVar];
      if (current !== undefined && current !== RUNFREE_PLACEHOLDER_VALUE) {
        values[parameter.envVar] = current;
      }
    }
  }
  return values;
}

function mergeServiceOAuthProviders(records: ServiceRecords = loadServiceRecords()): Record<string, OAuthProviderPolicyForWrite> {
  const providers: Record<string, OAuthProviderPolicyForWrite> = {};
  for (const id of Object.keys(records).sort()) {
    const svc = service(id);
    if (!svc || !serviceHasOAuthCredential(svc)) continue;
    const providerId = serviceOAuthProviderId(svc);
    const handles = ensureOAuthSeedHandles(providerId, svc.oauthCredential);
    providers[providerId] = {
      kind: "service",
      resourceHost: svc.oauthCredential.resourceHost,
      ...(svc.oauthCredential.resourcePathPrefix ? { resourcePathPrefix: svc.oauthCredential.resourcePathPrefix } : {}),
      tokenEndpoints: [svc.oauthCredential.tokenEndpoint],
      seeds: svc.oauthCredential.seeds.map((seed) => ({
        field: seed.field,
        handle: handles[seed.field],
        secretRef: seed.tokenName,
      })),
    };
  }
  return providers;
}

function readMcpOAuthProvidersForMerge(filePath: string): Record<string, OAuthProviderPolicyForWrite> {
  try {
    const raw = JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
    if (!isRecord(raw)) return {};
    const providers: Record<string, OAuthProviderPolicyForWrite> = {};
    if (isRecord(raw.providers)) {
      for (const [providerId, provider] of Object.entries(raw.providers)) {
        if (!isRecord(provider)) continue;
        const kind = provider.kind === undefined ? "mcp" : provider.kind;
        if (kind !== "mcp") continue;
        providers[providerId] = { ...provider, kind: "mcp" } as OAuthProviderPolicyForWrite;
      }
      return providers;
    }
    if (isRecord(raw.servers)) {
      for (const [providerId, provider] of Object.entries(raw.servers)) {
        if (!isRecord(provider)) continue;
        providers[`mcp:${providerId}`] = { ...provider, kind: "mcp" } as OAuthProviderPolicyForWrite;
      }
    }
    return providers;
  } catch {
    return {};
  }
}

export function writeMergedOAuthMediationPolicy(records: ServiceRecords = loadServiceRecords()): void {
  const callbackPort = Number.parseInt(childEnv().RUNFREE_MCP_OAUTH_CALLBACK_PORT ?? "", 10) || mcpOAuthCallbackPort(projectRoot());
  const filePath = oauthMediationPolicyPath();
  const mcpProviders = readMcpOAuthProvidersForMerge(filePath);
  const serviceProviders = mergeServiceOAuthProviders(records);
  const policy: OAuthMediationPolicyForWrite = {
    callback: {
      port: callbackPort,
      url: `http://localhost:${callbackPort}/callback`,
    },
    providers: {
      ...mcpProviders,
      ...serviceProviders,
    },
  };
  writeOAuthMediationPolicy(filePath, policy);
}

export function enabledOAuthEndpointPaths(records: ServiceRecords): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const id of Object.keys(records)) {
    const svc = service(id);
    if (!svc || !serviceHasOAuthCredential(svc)) continue;
    const endpoint = tokenEndpointParts(svc.oauthCredential.tokenEndpoint);
    const paths = result.get(endpoint.host) ?? new Set<string>();
    paths.add(endpoint.path);
    result.set(endpoint.host, paths);
  }
  return result;
}

export function requestRuleEquals(rule: RequestPolicyJson | undefined, methods: string[], pathPrefixes: string[]): boolean {
  if (!rule) return false;
  return JSON.stringify(rule.methods ?? []) === JSON.stringify(methods)
    && JSON.stringify(rule.pathPrefixes ?? []) === JSON.stringify(pathPrefixes)
    && rule.gitPush === undefined
    && rule.writeAction === undefined
    && rule.readPathPrefixes === undefined
    && rule.writePathPrefixes === undefined
    && rule.graphql === undefined;
}

// --- Service: typed intents + enforcement ------------------------------------

export type ServiceEnableInput = {
  id: string;
  tokenSource: TokenSourceSelection;
  fromOnePasswordItem?: string;
  // Raw `--param <key>=<value>` arguments (or prompt answers in the same
  // shape); parsed and validated by planDesiredServiceEnable against the
  // service's declared parameters.
  parameters?: string[];
  replaceSource: boolean;
  skipBroad: boolean;
  skipHosts?: string[];
  expectedUserServiceDigest?: string;
  // Tri-state selection for the service's hosts: --read-only => deny,
  // --allow-write => allow, neither/absent => no per-host writeAction (the
  // compiled project default / built-in default applies).
  readOnly?: boolean;
  allowWrite?: boolean;
  // Internal agent bootstrap mode: preserve stricter existing writeAction
  // fields and emit only concise changed-state output.
  automatic?: boolean;
  quiet?: boolean;
  reloadProxy: boolean;
};
export type ServiceDisableInput = { id: string; reloadProxy: boolean };
export type ServiceExplainInput = { id: string };
export type ServiceDiffInput = { apply: boolean; reloadProxy: boolean };
export type ServiceDefineInput = { id: string; fromFile?: string; replace: boolean; yes: boolean };
export type ServiceUndefineInput = { id: string };
export type ServiceConfigureInput = { id: string; reloadProxy: boolean };

// --- MCP: typed intents + enforcement ----------------------------------------

export type McpExplainInput = { agent: McpAgent; server: string; source?: McpSourceScope; json: boolean };
export type McpApproveInput = { agent: McpAgent; server: string; tokenSource: TokenSourceSelection; replaceSource: boolean };
export type McpConfigureInput = { agents?: McpAgent[]; server?: string };
export type McpRevokeInput = { agent: McpAgent; server: string };
export type McpRulesInput = { agent: McpAgent; server: string; source?: McpSourceScope; tool?: string; write?: WriteAction };

// --- Services ----------------------------------------------------------------
//
// Services expand to exact hostnames in network-policy.json (and, when a
// credential is configured, proxy token policy); which services are enabled
// (and at which revision) is recorded under the `services` key of
// .runfree/runfree.json. That record is descriptive project content only: no
// code path grants access from it — access comes solely from the policy file.

export type ServiceWriteMode = "read-only" | "allow-write";
export type ServiceRecord = { revision: number; skippedHosts?: string[]; writeMode?: ServiceWriteMode; digest?: string; hosts?: string[] };
export type ServiceRecords = Record<string, ServiceRecord>;

function projectConfigPath(): string {
  return projectRunfreePath(projectRoot(), "config");
}

// The `services` record travels through the raw config object: the typed config
// rebuilt by readConfigResultFromPath drops unknown top-level keys, so reads and
// rewrites must go through readRawProjectConfig (see config.ts).
function loadRawProjectConfig(): Record<string, unknown> {
  try {
    return readRawProjectConfig(projectRoot(), projectConfigPath());
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
}

// Lenient parse: .runfree/runfree.json is project content, so hostile or
// malformed records are ignored loudly instead of trusted or fatal.
export function parseServiceRecords(raw: Record<string, unknown>): ServiceRecords {
  const records: ServiceRecords = {};
  const value = raw.services;
  if (value === undefined) return records;
  if (!isRecord(value)) {
    warn(".runfree/runfree.json service records must be an object; ignoring it");
    return records;
  }
  for (const [id, entry] of Object.entries(value)) {
    if (!isRecord(entry) || typeof entry.revision !== "number" || !Number.isInteger(entry.revision) || entry.revision < 1) {
      warn(`.runfree/runfree.json service record ${id} is malformed; ignoring it`);
      continue;
    }
    let skippedHosts: string[] | undefined;
    if (entry.skippedHosts !== undefined) {
      if (!Array.isArray(entry.skippedHosts) || !entry.skippedHosts.every((host) => typeof host === "string")) {
        warn(`.runfree/runfree.json service record ${id}.skippedHosts is malformed; ignoring it`);
      } else if (entry.skippedHosts.length > 0) {
        skippedHosts = entry.skippedHosts as string[];
      }
    }
    let writeMode: ServiceWriteMode | undefined;
    if (entry.writeMode !== undefined) {
      if (entry.writeMode !== "read-only" && entry.writeMode !== "allow-write") {
        warn(`.runfree/runfree.json service record ${id}.writeMode is malformed; ignoring it`);
      } else {
        writeMode = entry.writeMode;
      }
    }
    let digest: string | undefined;
    if (entry.digest !== undefined) {
      if (typeof entry.digest !== "string" || !entry.digest.startsWith("sha256:")) {
        warn(`.runfree/runfree.json service record ${id}.digest is malformed; ignoring it`);
      } else {
        digest = entry.digest;
      }
    }
    let hosts: string[] | undefined;
    if (entry.hosts !== undefined) {
      const normalizedHost = (host: unknown): host is string => {
        if (typeof host !== "string") return false;
        try {
          return normalizeHostname(host) === host;
        } catch {
          return false;
        }
      };
      if (!Array.isArray(entry.hosts) || !entry.hosts.every(normalizedHost)) {
        warn(`.runfree/runfree.json service record ${id}.hosts is malformed; ignoring it`);
      } else if (entry.hosts.length > 0) {
        hosts = entry.hosts as string[];
      }
    }
    records[id] = {
      revision: entry.revision,
      ...(skippedHosts ? { skippedHosts } : {}),
      ...(writeMode ? { writeMode } : {}),
      ...(digest ? { digest } : {}),
      ...(hosts ? { hosts } : {}),
    };
  }
  return records;
}

export function loadServiceRecords(): ServiceRecords {
  return parseServiceRecords(loadRawProjectConfig());
}

export type CredentialOwner =
  | { kind: "service"; id: string }
  | { kind: "mcp"; agent: McpAgent; server: string };

// Structural low-level credential edits must not drift state owned by a
// composite workflow. Project service records are accepted only when they
// reconcile with a trusted curated definition; user-* names remain reserved by
// construction. MCP ownership comes from the host-owned approval inventory.
export function credentialOwner(name: string): CredentialOwner | undefined {
  if (isUserServiceId(name)) return { kind: "service", id: name };

  const records = loadServiceRecords();
  for (const id of Object.keys(records).sort()) {
    const svc = service(id);
    if (!svc) continue;
    const names = [
      ...(serviceHasCredential(svc) ? [svc.credential.tokenName] : []),
      ...(serviceHasOAuthCredential(svc) ? svc.oauthCredential.seeds.map((seed) => seed.tokenName) : []),
    ];
    if (names.includes(name)) return { kind: "service", id };
  }

  const inventory = mcpInventory({
    projectRoot: projectRoot(),
    env: childEnv(),
    approvalPath: mcpApprovalPath(stateDir()),
  });
  for (const entry of inventory.entries) {
    if (entry.source !== "project" || entry.decision.status !== "approved") continue;
    if (entry.tokenBindings?.some((binding) => binding.tokenName === name)) {
      return { kind: "mcp", agent: entry.agent, server: entry.name };
    }
  }
  return undefined;
}

export function describeCredentialOwner(owner: CredentialOwner): string {
  return owner.kind === "service"
    ? `service ${owner.id}`
    : `project MCP server ${owner.agent} ${owner.server}`;
}

export function credentialOwnerRemediation(owner: CredentialOwner): string {
  return owner.kind === "service"
    ? `runfree service disable ${owner.id}`
    : `runfree mcp revoke ${owner.agent} ${owner.server}`;
}

export function saveServiceRecords(records: ServiceRecords): void {
  const raw = loadRawProjectConfig();
  if (Object.keys(records).length === 0) {
    if (raw.services === undefined) return;
    delete raw.services;
  } else {
    raw.services = Object.fromEntries(Object.keys(records).sort().map((id) => [id, records[id]]));
  }
  writeSafeTextFile(projectConfigPath(), `${policyJson(raw)}\n`, 0o600);
}

export type ServiceHostKeep = { reason: string; requestRule?: boolean };

// Conservative keep computation for `service disable` and `service diff`
// removals: a host is removed only when nothing else requires it. The
// `requests` check is load-bearing — request rules must reference allowlisted
// hosts, so removing a ruled host would write a policy that fails
// validateNetworkPolicy() and break the next cold start. The credential-mapping
// check independently pins any host carrying an injected credential, which also
// covers services enabled by an older CLI (policy-only, no record).
export function serviceHostKeepReason(
  policy: PolicyJson,
  records: ServiceRecords,
  currentId: string,
  host: string,
  registry: Record<string, Service> = SERVICES,
): ServiceHostKeep | undefined {
  if (policy.requests?.[host]) {
    return { reason: "still has request rules", requestRule: true };
  }
  const credentialRefs = credentialRefsForHost(policy, host);
  if (credentialRefs.length > 0) {
    const tokens = Array.from(new Set(credentialRefs.map(({ tokenName }) => tokenName))).sort();
    return { reason: `required by token credential mapping: ${tokens.join(", ")}` };
  }
  for (const id of Object.keys(records).sort()) {
    if (id === currentId) continue;
    const record = records[id];
    if (record.hosts?.includes(host)) {
      return { reason: `required by enabled service ${id}` };
    }
    const other = registry[id];
    if (!other) continue;
    const skipped = new Set(record.skippedHosts ?? []);
    if (serviceHostNames(other).some((otherHost) => otherHost === host && !skipped.has(otherHost))) {
      return { reason: `required by enabled service ${id}` };
    }
  }
  return undefined;
}

export type ServiceDiffEntry = {
  id: string;
  recordedRevision: number;
  currentRevision: number;
  toAdd: string[];
  toRemove: string[];
  kept: Array<{ host: string } & ServiceHostKeep>;
  recordedDigest?: string;
  currentDigest?: string;
  definitionProblem?: string;
  credentialLinksToAdd?: CredentialPolicyJson[];
  credentialLinksToRemove?: CredentialPolicyJson[];
  tokenDescriptionChanged?: boolean;
  tokenAllowAnonymousChange?: { from: boolean; to: boolean };
  tokenPolicyRemove?: boolean;
  agentEnvToAdd?: string[];
  requestRuleChanges?: Array<{
    host: string;
    field: keyof RequestPolicyJson;
    from?: unknown;
    to: unknown;
    reason: "missing" | "reconcile" | "trusted-migration";
  }>;
  acceptedRequestOverrides?: Array<{
    host: string;
    field: keyof RequestPolicyJson;
    actual: unknown;
    desired: unknown;
  }>;
  requestRuleConflicts?: Array<{
    host: string;
    field: keyof RequestPolicyJson;
    actual: unknown;
    desired: unknown;
  }>;
};

export function dockerAvailable(): boolean {
  if (!commandExists("docker")) return false;
  return runCapture("docker", ["info"]).status === 0;
}

export function composeProject(): string | undefined {
  const ps = runCapture("docker", [
    "ps",
    "-aq",
    ...corroboratedComposeProjectContainerFilters(currentAdminState().projectId, composeProjectNameForAdmin()),
  ]);
  const agentId = ps.stdout.trim().split(/\s+/).filter(Boolean)[0];
  if (!agentId) return undefined;
  const inspect = runCapture("docker", [
    "inspect",
    "--format",
    "{{ index .Config.Labels \"com.docker.compose.project\" }}",
    agentId,
  ]);
  const project = inspect.stdout.trim();
  if (inspect.status !== 0 || project === "" || project === "<no value>") return undefined;
  return project;
}

export function proxyContainerId(project: string): string | undefined {
  const ps = runCapture("docker", [
    "ps",
    "-aq",
    "--no-trunc",
    ...composeServiceContainerFilters(project, "proxy"),
  ]);
  return ps.stdout.trim().split(/\s+/).filter(Boolean)[0];
}

function containerRunning(id: string): boolean {
  const running = runCapture("docker", ["inspect", "--format", "{{ .State.Running }}", id]);
  return running.status === 0 && running.stdout.trim() === "true";
}

export type DoctorInput = { postFailure: boolean; tail?: string };

// Level-triggered proxy status files (see the convergent proxy token store
// design spec). Each policy consumer maintains its own generation status file
// in a dedicated proxy status tmpfs: the root firewall supervisor writes
// firewall.json, the uid-1001 request proxy writes request-proxy.json into a
// uid-1001-owned subdirectory pre-created by the entrypoint. Paths, shapes,
// and the single-line JSON framing come from the shared
// @runfree/runtime-contracts/proxy-status contract (also used by the proxy
// writers), so the two halves of the ack protocol cannot silently diverge.
// The CLI reads them over the same trusted host→proxy docker-exec channel as
// token writes. No control decision reads the docker log stream; logs are
// diagnostics only.

// One exec per poll: each status file is a single JSON line, emitted in fixed
// order with `{}` standing in for a missing file so the split stays aligned.
function readProxyPolicyStatusFiles(proxyId: string): { firewall?: ParsedGenerationStatus; requestProxy?: ParsedGenerationStatus } | undefined {
  const script = [firewallStatusPath(), requestProxyStatusPath()]
    .map((file) => `if [ -f ${shellSingleQuote(file)} ]; then cat ${shellSingleQuote(file)}; else printf '{}'; fi; echo`)
    .join("; ");
  const result = runCapture("docker", ["exec", proxyId, "sh", "-c", script]);
  if (result.status !== 0) return undefined;
  const lines = result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length !== 2) return undefined;
  return {
    firewall: parseGenerationStatusLine(lines[0]),
    requestProxy: parseGenerationStatusLine(lines[1]),
  };
}

// Readiness derives from the request proxy's level-triggered status file, not
// a `docker logs` scrape: a missed or rotated log line can no longer produce a
// false timeout, and there is no dependence on the Docker log driver.
function waitForProxy(project: string): void {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const id = proxyContainerId(project);
    if (id) {
      const statusFiles = readProxyPolicyStatusFiles(id);
      if (statusFiles?.requestProxy) return;
    }
    sleepSyncMs(1000);
  }
  die("proxy did not become ready; run 'runfree logs proxy' for details");
}

export function printTokenSyncFailures(sync: { failed: string[]; stale?: string[]; failedMessages: Record<string, string> }): void {
  for (const tokenName of [...sync.failed, ...(sync.stale ?? [])]) {
    const message = sync.failedMessages[tokenName];
    if (message) console.error(`${tokenName}: ${message}`);
  }
}

type ProxyReloadOptions = { continueOnTokenSyncFailure?: boolean; force?: boolean };

// Quiet token sync plus the shared reporting for the reload/convergence
// flows. Hard failures are fatal (exit 1 unless continueOnTokenSyncFailure);
// stale keeps are warnings only — the proxy still injects a receipt-proven
// value and the watcher/next sync retries — so a missed 1Password prompt on
// an unrelated mutation or session start never fails the command.
function runQuietTokenSync(mode: TokenSyncMode, options: ProxyReloadOptions, failureSuffix = ""): { ok: boolean; sync: TokenSyncResult } {
  const sync = syncTokens({ quiet: true, exitOnFailure: false, mode });
  currentAdminState().tokenResolutionReceipts = sync.receipts;
  printTokenSyncFailures(sync);
  if (sync.failed.length > 0) {
    console.error(`runfree: credential sync failed for: ${sync.failed.join(", ")}${failureSuffix}`);
    if (!options.continueOnTokenSyncFailure) {
      process.exitCode = 1;
      return { ok: false, sync };
    }
  }
  return { ok: true, sync };
}

function printProxyReloadSummary(headline: string, policy: LoadedNetworkPolicy, sync: TokenSyncResult): void {
  console.log(headline);
  console.log(`allowed hosts: ${policy.allowedHosts.length}`);
  console.log(`credential tokens: ${Object.keys(policy.tokens).join(", ") || "none"}`);
  const warnings = [...sync.failed, ...sync.stale];
  if (warnings.length > 0) {
    console.log(`credential sync warnings: ${warnings.join(", ")}`);
  }
}

// Shared "proxy is not there" tail for reload/convergence: verify sources,
// report, and explain that policy and tokens apply on the next runfree. No
// sync mode is threaded through: without a live store generation every token
// is due regardless of mode, so the distinction is meaningless here.
function syncTokensWithoutRunningProxy(message: string, options: ProxyReloadOptions): void {
  if (!runQuietTokenSync("source-truth", options).ok) return;
  console.log(message);
}

// A stale-digest runtime (e.g. a proxy image from before a CLI upgrade)
// cannot be fixed by restarting the container: only `runfree up` recreates
// it, and its image may predate the convergence status files entirely, so a
// restart would wipe the token store and then fail readiness for nothing.
function reportRuntimeValidationRequired(runtime: ProxyRuntime, options: ProxyReloadOptions): void {
  console.error(`runfree: ${runtime.validationMessage ?? "runtime validation required; run \`runfree up\`"}`);
  console.error(`runfree: a proxy restart cannot revalidate this runtime; run \`${remedy.up()}\` to recreate it`);
  // Mode is irrelevant here: validation-required syncs wipe fail-closed
  // before any due decision.
  runQuietTokenSync("source-truth", options);
}

/**
 * The restore half of `runtime reload-policy --force`. The restore runs the
 * ephemeral helpers itself (it has no validation to reuse), so it gets the
 * budgeted IO for its work and the unbudgeted base IO as the helpers'
 * containment IO: helper reclaim must be able to run after the budget ends
 * (security review C4).
 */
export async function restoreAdmissionAfterProxyRestart(input: {
  plan: ActiveRuntimePlan;
  lifecycleLock: ProjectLifecycleLock;
  proxyId: string;
  deadline: number;
  baseIO: RuntimeIO;
}): Promise<void> {
  const { restoreSameProxySessionAdmission } = await import("../runtime/startup.ts");
  await restoreSameProxySessionAdmission({
    plan: input.plan,
    io: withLifecycleOperationBudget(input.baseIO, () => input.deadline - performance.now()),
    containmentIO: input.baseIO,
    lifecycleLock: input.lifecycleLock,
    proxyId: input.proxyId,
  });
}

async function restartProxyAndSync(project: string, proxyId: string, policy: LoadedNetworkPolicy, options: ProxyReloadOptions): Promise<void> {
  const hostProject = currentAdminState().runtimeContext?.project ?? adminProjectInfo();
  const context: RuntimeContext = currentAdminState().runtimeContext ?? {
    projectRoot: projectRoot(), project: hostProject, runtimeRoot: runtimeRootForSecurityContract(hostProject), env: childEnv(),
  };
  prepareRuntimeTokenSources();
  try {
  const lifecycleLock = await tryAcquireProjectLifecycleLockWithRetry(context);
  if (!lifecycleLock) die("proxy reload could not acquire the lifecycle lock; retry after the current operation completes");
  try {
    const deadline = performance.now() + LIFECYCLE_OPERATION_BUDGET_MS;
    await adminLifecycleDeadline.run(deadline, async () => {
    assertSessionDisruptionAuthorized({
      stateDir: stateDir(), expectedProject: { projectId: projectId(), composeProject: project },
      lifecycleLock, operation: "runtime reload-policy", force: options.force, env: childEnv(),
    });
    if (proxyContainerId(project) !== proxyId) die("proxy changed before restart; retry runtime reload-policy");
    const wasRunning = containerRunning(proxyId);
    lifecycleLock.assertHeld();
    admitPreparedRuntimeTokenSources(hostProject);
    const result = wasRunning
      ? runCapture("docker", ["restart", proxyId])
      : runCapture("docker", ["start", proxyId]);
    if (result.status !== 0) die(result.stderr.trim() || "docker failed while restarting proxy");
    waitForProxy(project);
    lifecycleLock.assertHeld();
    if (proxyContainerId(project) !== proxyId) die("proxy identity changed during restart; use runfree up to recover");
    // The restore pass runs even with no session to restore: the restarted
    // proxy recreated its session-file directory and removed the
    // host-published eligibility with it, and a proxy holding no eligibility
    // serves nothing when its sessions come back. A project with no durable
    // effective selection has no eligibility to republish and nothing that
    // could be serving, so there is nothing for the pass to act on.
    const { readEffectiveControlPlaneV2 } = await import("../runtime/component-state-v2.ts");
    if (readEffectiveControlPlaneV2(stateDir())) {
      const target = currentRuntimeValidationTarget();
      if (!target) die("proxy restart needs exact runtime inputs to restore sessions; restore the inputs and retry runtime reload-policy --force");
      const { nodeRuntimeIO } = await import("../runtime.ts");
      await restoreAdmissionAfterProxyRestart({ plan: target.plan, lifecycleLock, proxyId, deadline, baseIO: nodeRuntimeIO });
    }
    lifecycleLock.assertHeld();
    console.log("proxy restart: pending requests interrupted; approval grants and remembered denials reset; audit observations may be lost");
    });
  } finally {
    lifecycleLock.release();
  }
  // Credential resolution rechecks the selected policy and exact proxy store.
  // Prompts run after the admission critical section has released its fence.
  const { ok, sync } = runQuietTokenSync("source-truth", options, "; proxy tmpfs token files were removed");
  if (!ok) return;
  printProxyReloadSummary("proxy reload: done", policy, sync);
  } finally { clearPreparedRuntimeTokenSources(hostProject); }
}

// Explicit recovery / big-hammer tool (`runfree runtime reload-policy`): container
// restart plus full source-truth token re-sync. Also required when the proxy
// container is stopped or for changes a running proxy cannot pick up (CA
// material, compose topology). Policy mutations use convergeProxyPolicy.
export async function reloadProxy(options: ProxyReloadOptions = {}): Promise<void> {
  const policy = loadPolicy();

  if (!dockerAvailable()) {
    syncTokensWithoutRunningProxy("proxy not inspected: docker unavailable; policy and tokens will apply on next runfree", options);
    return;
  }

  const project = composeProject();
  const currentProxy = project ? proxyContainerId(project) : undefined;
  if (!project || !currentProxy) {
    syncTokensWithoutRunningProxy("proxy not running; policy and tokens will apply on next runfree", options);
    return;
  }

  if (containerRunning(currentProxy)) {
    const runtime = proxyRuntime();
    if (runtime.state === "validation-required") {
      reportRuntimeValidationRequired(runtime, options);
      return;
    }
  }

  await restartProxyAndSync(project, currentProxy, policy, options);
}

function convergeAckTimeoutMs(): number {
  return fakeDockerMsOverride(childEnv().RUNFREE_TEST_CONVERGE_ACK_TIMEOUT_MS) ?? 10_000;
}

type ProxyPolicyAck =
  | { converged: true }
  | { converged: false; reason: string };

// Wait, bounded, for BOTH policy consumers to report the expected generation
// through their level-triggered status files. Both are required because the
// firewall owns the real egress boundary (nftables allowed_ipv4): a widening
// is not effective, and a removal is not enforced, until the firewall reloads.
// The ack is an observation mechanism only — the proxy's own file watch
// applies policy regardless of whether the CLI observes it.
function awaitProxyPolicyAck(proxyId: string, expectedGeneration: string): ProxyPolicyAck {
  const timeoutMs = convergeAckTimeoutMs();
  const deadline = Date.now() + timeoutMs;
  let lastReason = "no status observed";
  while (true) {
    const statusFiles = readProxyPolicyStatusFiles(proxyId);
    if (statusFiles === undefined) {
      lastReason = "proxy status files could not be read over docker exec";
    } else {
      const firewall = statusFiles.firewall;
      const requestProxy = statusFiles.requestProxy;
      const firewallOk = firewall?.generation === expectedGeneration && firewall.rulesetVerified === true;
      const requestProxyOk = requestProxy?.generation === expectedGeneration;
      if (firewallOk && requestProxyOk) return { converged: true };
      lastReason = !requestProxyOk
        ? `request proxy reports ${requestProxy?.generation ?? "no readable status"}`
        : firewall?.generation !== expectedGeneration
          ? `firewall reports ${firewall?.generation ?? "no readable status"}`
          : "firewall ruleset verification has not passed for the new effective policy generation";
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) return { converged: false, reason: lastReason };
    sleepSyncMs(Math.min(remaining, 500));
  }
}

// Restart-free policy convergence: the default follow-up for policy-mutating
// admin intents. All three proxy policy consumers hot-reload on their own
// (request proxy file watch, firewall supervisor poll, OAuth mediation mtime
// check); this waits for the generation acks and then runs a receipt-gated
// token sync, so the container is never restarted, the store generation stays
// stable, and held credentials are never re-resolved or re-prompted. On ack
// timeout or exec failure it falls back — loudly — to the restart path.
export async function convergeProxyPolicy(options: ProxyReloadOptions = {}): Promise<void> {
  // Re-load the policy file just written through the shared policyGeneration
  // path so CLI and proxy hash identical normalized bytes.
  const policy = loadPolicy();

  if (!dockerAvailable()) {
    syncTokensWithoutRunningProxy("proxy not inspected: docker unavailable; policy and tokens will apply on next runfree", options);
    return;
  }

  const project = composeProject();
  const currentProxy = project ? proxyContainerId(project) : undefined;
  if (!project || !currentProxy) {
    syncTokensWithoutRunningProxy("proxy not running; policy and tokens will apply on next runfree", options);
    return;
  }

  if (!containerRunning(currentProxy)) {
    // A stopped proxy cannot hot-reload; starting it is the restart path (the
    // tmpfs store is empty in either case).
    console.error("runfree: proxy container is not running; starting it (credential sources will re-resolve)");
    await restartProxyAndSync(project, currentProxy, policy, options);
    return;
  }

  const ack = awaitProxyPolicyAck(currentProxy, policy.generation);
  if (!ack.converged) {
    // Distinguish a runtime that cannot acknowledge (stale digest — e.g. a
    // proxy image from before this CLI version, which never writes the status
    // files) from a genuinely unresponsive consumer. Restarting the former
    // wipes the token store and then fails readiness for nothing; only
    // `runfree up` fixes it.
    const runtime = proxyRuntime();
    if (runtime.state === "validation-required") {
      console.error(`runfree: proxy did not acknowledge policy generation ${policy.generation} (${ack.reason})`);
      reportRuntimeValidationRequired(runtime, options);
      return;
    }
    console.error(`runfree: proxy did not acknowledge policy generation ${policy.generation} (${ack.reason}); falling back to a proxy restart`);
    console.error("runfree: the restart resets the proxy token store generation — held credentials will re-resolve from their sources, so source prompts (e.g. 1Password) may reappear");
    await restartProxyAndSync(project, currentProxy, policy, options);
    return;
  }

  // Receipt-gated: only genuinely new or changed tokens resolve. StartedAt is
  // unchanged, the store generation is stable, existing tokens are untouched.
  const { ok, sync } = runQuietTokenSync("convergence", options);
  if (!ok) return;
  printProxyReloadSummary("proxy policy converged (no restart)", policy, sync);
}

// Run an admin action within the admin state, normalizing its exit code and
// AdminExit handling. Yargs admin command modules (and the in-process runtime
// admin) use this to invoke typed enforcement (intent -> host logic) after
// parsing — it is the single execution wrapper for every admin mutation.
export async function runAdminAction(state: AdminState, action: () => Promise<void> | void): Promise<number> {
  const previousExitCode = process.exitCode;
  process.exitCode = undefined;
  state.tokenResolutionReceipts = [];
  try {
    await adminStateStorage.run(state, action);
    const status = typeof process.exitCode === "number" ? process.exitCode : 0;
    process.exitCode = previousExitCode;
    return status;
  } catch (error) {
    process.exitCode = previousExitCode;
    if (error instanceof AdminExit) {
      // The warnings that explain a refusal render before it (contract D3).
      flushWarnings();
      runfreeError(error.message, error.detail);
      return error.status;
    }
    throw error;
  }
}

export function takeLastTokenSyncReceipts(state: AdminState = currentAdminState()): TokenResolutionReceipt[] {
  const receipts = state.tokenResolutionReceipts ?? [];
  state.tokenResolutionReceipts = [];
  return receipts;
}
