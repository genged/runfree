// Token typed intents + enforcement and the token-sync watch loop (split from
// options.ts). Shared policy/token-store/proxy machinery lives in admin-core.ts.

import fs from "node:fs";
import type {
  TokenResolutionLedger,
  TokenResolutionReceipt,
} from "../token-resolution.ts";
import {
  type CredentialPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import {
  assertNotReservedUserTokenName,
  assertRefreshBeforeJwtExpiry,
  assertTokenSourceCanBeSaved,
  assertValidTokenName,
  childEnv,
  type CredentialAddInput,
  type CredentialClearSourceInput,
  type CredentialFieldsInput,
  credentialFromHost,
  credentialOwner,
  credentialOwnerRemediation,
  type CredentialSetSourceInput,
  type CredentialStatusInput,
  type CredentialSyncInput,
  currentAdminState,
  describeCredential,
  describeCredentialOwner,
  describeSource,
  die,
  effectiveTokenRefresh,
  type EffectiveTokenRefresh,
  formatDelayMs,
  formatDurationSeconds,
  isTokenResolutionReceipt,
  type JwtPrivateKeyCacheEntry,
  loadPolicy,
  loadSourceRegistry,
  loadTokenConfig,
  loadTokenStatus,
  newTokenResolutionLedger,
  normalizeCliHost,
  parseDurationSeconds,
  printTokenSyncFailures,
  proxyRuntime,
  type ProxyRuntimeState,
  removeProxyRuntimeToken,
  retractPersistedTokenReceipts,
  saveTokenConfig,
  saveTokenSource,
  saveTokenStatus,
  seedTokenResolutionLedger,
  syncTokens,
  tokenResolutionLedgerKey,
  type TokenSource,
  tokenSourceFingerprint,
  tokenSourceFromSelection,
  type TokenSourceSelection,
  tokenSyncWatchNowMs,
  withTokenStoreLock,
} from "./admin-core.ts";

function assertKnownCredential(name: string): void {
  const policy = loadPolicy();
  if (!policy.tokens[name]) {
    const names = Object.keys(policy.tokens).join(", ") || "<none>";
    if (name === "claude") {
      die(`unknown credential: ${name} (known: ${names})
Claude Code login uses Runfree-managed Claude state; run runfree and complete browser login if prompted.
For a non-login proxy credential, create a credential policy first:
  runfree credential add ${name} --host <host>`);
    }
    die(`unknown credential: ${name} (known: ${names})
create a proxy credential first, for example:
  runfree credential add ${name} --host <host>`);
  }
}

function _credentialFromInput(fields: CredentialFieldsInput): CredentialPolicyJson {
  if (!fields.host) die("credential commands require --host <host>");
  return credentialFromHost(normalizeCliHost(fields.host), fields);
}

// Typed front-end builder for the yargs command modules: turn the parsed
// `--from-*` values (undefined when absent; non-empty when present, since the
// grammar uses requiresArg) into a selection, enforcing "choose only one".
export function credentialSourceSelectionFromArgs(fields: {
  env?: string;
  onePassword?: string;
  source?: string;
  stdin?: boolean;
}): TokenSourceSelection {
  const present =
    [fields.env, fields.onePassword, fields.source].filter((value) => value !== undefined).length +
    (fields.stdin ? 1 : 0);
  if (present > 1) die("choose only one credential source");
  if (fields.stdin) return { kind: "stdin" };
  if (fields.env !== undefined) return { kind: "env", env: fields.env };
  if (fields.source !== undefined) return { kind: "named", name: fields.source };
  if (fields.onePassword !== undefined) return { kind: "1password", ref: fields.onePassword };
  return { kind: "none" };
}

// Apply a typed `--refresh-every` duration (re-validated) to a token source.
function applyRefreshSeconds(source: TokenSource, refreshEvery: string | undefined): TokenSource {
  if (!refreshEvery) return source;
  return {
    ...source,
    refreshEverySeconds: parseDurationSeconds(refreshEvery, "--refresh-every"),
  };
}

function assertTokenSourceRefreshValid(source: TokenSource): void {
  assertRefreshBeforeJwtExpiry(effectiveTokenRefresh(source));
}

function describeEffectiveRefresh(refresh: EffectiveTokenRefresh): string {
  if (refresh.mode === "manual") return "manual";
  if (refresh.mode === "derived") {
    return `every ${formatDurationSeconds(refresh.seconds)} (derived from source ttl ${formatDurationSeconds(refresh.ttlSeconds)})`;
  }
  const suffix = refresh.ttlSeconds !== undefined ? " (override)" : "";
  return `every ${formatDurationSeconds(refresh.seconds)}${suffix}`;
}

// Validate an inherited-descriptor env value: numeric, and never one of the
// standard streams.
function inheritedFdFromEnv(rawFd: string | undefined): number | undefined {
  if (!rawFd || !/^[0-9]{1,5}$/.test(rawFd)) return undefined;
  const fd = Number(rawFd);
  if (!Number.isInteger(fd) || fd < 3) return undefined;
  return fd;
}

function readStartupTokenResolutionReceipts(): TokenResolutionReceipt[] {
  const fd = inheritedFdFromEnv(childEnv().RUNFREE_TOKEN_SYNC_RECEIPT_FD);
  if (fd === undefined) return [];
  let raw = "";
  try {
    raw = fs.readFileSync(fd, "utf8");
  } catch {
    return [];
  }
  if (raw.trim() === "") return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter(isTokenResolutionReceipt) : [];
  } catch {
    return [];
  }
}

// Advisory runtime view for scheduling: the sync that just ran already
// derived the live runtime, so its result snapshot avoids a second full
// docker-inspection pass per watcher iteration. Only pre-sync callers
// (delay-first-sync) fall back to a fresh proxyRuntime() read.
type TokenSyncRuntimeSnapshot = { runtimeState: ProxyRuntimeState; storeGeneration?: string };

function nextTokenSyncDelayMs(ledger: TokenResolutionLedger, snapshot?: TokenSyncRuntimeSnapshot): number | undefined {
  const config = loadTokenConfig();
  const policy = loadPolicy();
  const sourceRegistry = Object.values(config).some((source) => source.source === "named")
    ? loadSourceRegistry()
    : undefined;
  const runtime = snapshot ?? ((): TokenSyncRuntimeSnapshot => {
    const live = proxyRuntime();
    return { runtimeState: live.state, storeGeneration: live.storeGeneration };
  })();
  // A transient docker-exec failure must not read as "nothing to watch": the
  // spec keeps the watcher alive (stale retries, 24h bound) even for
  // manual-source tokens, so schedule a bounded re-probe instead of letting
  // the fall-through below return undefined and end the watch.
  if (runtime.runtimeState === "proxy-unreachable") return TOKEN_SYNC_WATCH_ERROR_RETRY_MS;
  if (runtime.storeGeneration) {
    // Recover persisted receipts too (fd-3 receipts are empty after a
    // convergence-only startup), so the first delay reflects the real
    // schedule instead of forcing an immediate redundant sync.
    seedTokenResolutionLedger({
      config,
      ledger,
      policy,
      proxyStoreGeneration: runtime.storeGeneration,
      sourceRegistry,
    });
  }

  const nowMs = tokenSyncWatchNowMs();
  const deadlines: number[] = [];
  let hasRefreshInterval = false;
  let hasOutstandingPopulation = false;
  for (const tokenName of Object.keys(policy.tokens)) {
    const source = config[tokenName];
    if (!source) continue;
    const refresh = effectiveTokenRefresh(source, sourceRegistry);
    assertRefreshBeforeJwtExpiry(refresh);
    if (refresh.mode !== "manual") hasRefreshInterval = true;

    if (!runtime.storeGeneration) {
      if (refresh.mode !== "manual") deadlines.push(nowMs + refresh.seconds * 1000);
      continue;
    }

    const sourceFingerprint = tokenSourceFingerprint(source, sourceRegistry);
    const key = tokenResolutionLedgerKey(tokenName, sourceFingerprint, runtime.storeGeneration);
    const retryAt = ledger.retryAfterFailureAt.get(key);
    if (retryAt !== undefined) {
      deadlines.push(retryAt);
      continue;
    }

    const lastResolvedAt = ledger.lastResolvedAt.get(key);
    if (lastResolvedAt === undefined) {
      hasOutstandingPopulation = true;
      deadlines.push(nowMs);
      continue;
    }

    if (refresh.mode !== "manual") deadlines.push(lastResolvedAt + refresh.seconds * 1000);
  }

  if (deadlines.length > 0) return Math.max(0, Math.min(...deadlines) - nowMs);
  if (!hasRefreshInterval && !hasOutstandingPopulation) return undefined;
  return 0;
}

// Retry cadence after a failed watch iteration (thrown sync or unreachable
// proxy): bounded, matching the ledger's failure-retry convention.
const TOKEN_SYNC_WATCH_ERROR_RETRY_MS = 60_000;

function tokenSyncWatchIterationsForTests(): number | undefined {
  const value = childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS;
  if (childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && value && /^[1-9][0-9]{0,3}$/.test(value)) return Number(value);
  return undefined;
}

function tokenSyncWatchSleepMs(intervalMs: number): number {
  const value = childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS;
  if (childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && value && /^[0-9]{1,5}$/.test(value)) return Number(value);
  return intervalMs;
}

// Parent liveness: primary signal is an inherited lifetime pipe — the parent
// holds the write end and never writes; EOF/close on the watcher's read end
// means the parent is gone. PIDs are recycled, so the legacy
// `process.kill(pid, 0)` probe alone could keep a watcher (and its 1Password
// access) alive under an unrelated process that landed on the parent's PID;
// it remains only as a belt-and-suspenders secondary signal. The pipe sets a
// flag that the ≤5s sleep chunks below poll — no promise race, so nothing
// accumulates on a long-lived watch and exit latency stays within one tick.
type ParentLifetimeWatch = {
  closed: () => boolean;
};

function parentLifetimePipeFd(): number | undefined {
  return inheritedFdFromEnv(childEnv().RUNFREE_TOKEN_SYNC_LIFETIME_FD);
}

function watchParentLifetimePipe(): ParentLifetimeWatch {
  const fd = parentLifetimePipeFd();
  if (fd === undefined) return { closed: () => false };
  let closed = false;
  const markClosed = () => {
    closed = true;
  };
  let stream: fs.ReadStream;
  try {
    stream = fs.createReadStream("", { fd });
  } catch {
    return { closed: () => true };
  }
  stream.on("end", markClosed);
  stream.on("close", markClosed);
  stream.on("error", markClosed);
  stream.resume();
  return { closed: () => closed };
}

function tokenSyncWatchParentPidAlive(): boolean {
  const value = childEnv().RUNFREE_TOKEN_SYNC_WATCH_PARENT_PID;
  if (!value) return true;
  if (!/^[1-9][0-9]{0,9}$/.test(value)) return false;
  try {
    process.kill(Number(value), 0);
    return true;
  } catch {
    return false;
  }
}

function tokenSyncWatchParentAlive(lifetime: ParentLifetimeWatch): boolean {
  if (lifetime.closed()) return false;
  return tokenSyncWatchParentPidAlive();
}

// Deliberately NOT unref'd: during a manual `runfree credential sync --watch` (no
// lifetime pipe, no other pending handles) this timer is the only thing
// keeping the event loop — and therefore the watch — alive through the sleep.
function sleepWatchTick(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sleepTokenSyncWatch(intervalMs: number, lifetime: ParentLifetimeWatch): Promise<boolean> {
  const sleepMs = tokenSyncWatchSleepMs(intervalMs);
  const deadline = Date.now() + sleepMs;
  while (Date.now() < deadline) {
    if (!tokenSyncWatchParentAlive(lifetime)) return false;
    const remaining = deadline - Date.now();
    await sleepWatchTick(Math.min(remaining, 5_000));
  }
  const alive = tokenSyncWatchParentAlive(lifetime);
  if (alive && childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS !== undefined) {
    childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS = String(tokenSyncWatchNowMs() + intervalMs);
  }
  return alive;
}

async function sleepUntilNextTokenSync(options: { quiet?: boolean; resolutionLedger: TokenResolutionLedger }, lifetime: ParentLifetimeWatch, snapshot?: TokenSyncRuntimeSnapshot): Promise<boolean> {
  const delayMs = nextTokenSyncDelayMs(options.resolutionLedger, snapshot);
  if (delayMs === undefined) {
    if (!options.quiet) console.log("credential sync watch stopped: no credential sources have refresh intervals");
    return false;
  }
  if (!options.quiet && delayMs > 0) console.log(`next credential sync in ${formatDelayMs(delayMs)}`);
  return sleepTokenSyncWatch(delayMs, lifetime);
}

async function syncTokensWatch(options: { cacheSourceSecrets?: boolean; delayFirstSync?: boolean; quiet?: boolean; verbose?: boolean } = {}): Promise<void> {
  let iterations = 0;
  const maxIterations = tokenSyncWatchIterationsForTests();
  if (
    childEnv().RUNFREE_TEST_FAKE_DOCKER === "1"
    && childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS !== undefined
    && childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS === undefined
  ) {
    childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS = String(Date.now());
  }
  const lifetime = watchParentLifetimePipe();
  const sourceSecretCache = options.cacheSourceSecrets === false
    ? undefined
    : { jwtPrivateKeys: new Map<string, JwtPrivateKeyCacheEntry>() };
  const resolutionLedger = newTokenResolutionLedger(readStartupTokenResolutionReceipts());
  if (!options.quiet) console.log(`source secret cache: ${sourceSecretCache ? "memory-only" : "disabled"}`);
  if (options.delayFirstSync && !(await sleepUntilNextTokenSync({ ...options, resolutionLedger }, lifetime))) return;
  while (true) {
    if (!tokenSyncWatchParentAlive(lifetime)) return;
    // The lock is acquired inside syncTokens per iteration, never for the
    // lifetime of the watch process.
    let syncThrew = false;
    let syncSnapshot: TokenSyncRuntimeSnapshot | undefined;
    try {
      const sync = syncTokens({ exitOnFailure: false, quiet: options.quiet, resolutionLedger, sourceSecretCache, verbose: options.verbose });
      syncSnapshot = { runtimeState: sync.runtimeState, storeGeneration: sync.storeGeneration };
      const problems = [...sync.failed, ...sync.stale];
      if (options.quiet && problems.length > 0) console.error(`credential sync watch failed for: ${problems.join(", ")}`);
    } catch (error) {
      // The watcher is the session's only token reconciler: a thrown sync —
      // e.g. the token-store lock timing out behind another command's
      // 1Password prompt — must cost one iteration, never the whole watch.
      syncThrew = true;
      console.error(`credential sync watch iteration failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    iterations += 1;
    if (maxIterations !== undefined && iterations >= maxIterations) return;
    if (syncThrew) {
      if (!(await sleepTokenSyncWatch(TOKEN_SYNC_WATCH_ERROR_RETRY_MS, lifetime))) return;
      continue;
    }
    if (!(await sleepUntilNextTokenSync({ ...options, resolutionLedger }, lifetime, syncSnapshot))) return;
  }
}

function structuralOwner(name: string): ReturnType<typeof credentialOwner> {
  const owner = credentialOwner(name);
  if (owner) {
    die(`${name} is owned by ${describeCredentialOwner(owner)}\nchange or remove it with:\n  ${credentialOwnerRemediation(owner)}`);
  }
  return owner;
}

function prepareCredentialSource(input: CredentialSetSourceInput): TokenSource {
  const parsedSource = tokenSourceFromSelection(input.tokenSource, true);
  if (!parsedSource) throw new Error("internal error: required credential source was not parsed");
  const source = applyRefreshSeconds(parsedSource, input.refreshEvery);
  try {
    assertTokenSourceRefreshValid(source);
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
  assertTokenSourceCanBeSaved(input.name, source, { replaceSource: input.replaceSource });
  return source;
}

function savePreparedCredentialSource(input: CredentialSetSourceInput, source: TokenSource): void {
  const { sourceResult, syncFailed, runtimeState } = withTokenStoreLock(() => {
    const savedSource = saveTokenSource(input.name, source, { replaceSource: input.replaceSource });
    let failedSync = false;
    let state: ProxyRuntimeState | "skipped" = "skipped";
    if (input.sync) {
      const result = syncTokens({ quiet: true, exitOnFailure: false, mode: "convergence" });
      failedSync = result.failed.length > 0;
      state = result.runtimeState;
      printTokenSyncFailures(result);
    }
    return { sourceResult: savedSource, syncFailed: failedSync, runtimeState: state };
  });

  const loadedPolicy = loadPolicy();
  const hosts = loadedPolicy.tokens[input.name]?.credentials.map((credential) => credential.host).join(", ") ?? "";
  const refresh = effectiveTokenRefresh(source);
  console.log(`${input.name} credential ${sourceResult.changed ? "configured" : "source unchanged"}`);
  console.log(`source: ${describeSource(source)}`);
  console.log(`refresh: ${describeEffectiveRefresh(refresh)}`);
  console.log(`used for: ${hosts || "none"}`);
  console.log("agent exposure: no");
  console.log(`proxy sync: ${!input.sync ? "skipped" : syncFailed ? "failed" : runtimeState === "ready" ? "done" : `pending (${runtimeState})`}`);
  if (syncFailed) process.exitCode = 1;
}

/** Bind a source for a newly approved desired credential without reading mutable project policy. */
export function bindDesiredCredentialSource(input: CredentialAddInput): boolean {
  if (!input.tokenSource || input.tokenSource.kind === "none") return false;
  assertValidTokenName(input.name);
  assertNotReservedUserTokenName(input.name, "credential add");
  structuralOwner(input.name);
  const sourceInput: CredentialSetSourceInput = {
    name: input.name,
    tokenSource: input.tokenSource,
    refreshEvery: input.refreshEvery,
    replaceSource: input.replaceSource ?? false,
    sync: false,
  };
  const source = prepareCredentialSource(sourceInput);
  return withTokenStoreLock(() => saveTokenSource(input.name, source, {
    replaceSource: sourceInput.replaceSource,
  }).changed);
}

/** Revoke host/proxy credential state before removing its desired destinations. */
export function revokeDesiredCredentialState(name: string): "removed" | "not-present" {
  assertValidTokenName(name);
  assertNotReservedUserTokenName(name, "credential remove");
  structuralOwner(name);
  const runtime = proxyRuntime();
  if (runtime.state === "docker-unavailable" || runtime.state === "proxy-unreachable") {
    die([
      `${name} was not removed: cannot verify credential revocation while proxy state is ${runtime.state}`,
      "the credential is still bound and still injected",
      "restore Docker access and retry",
    ].join("\n"));
  }
  let present = false;
  withTokenStoreLock(() => {
    if (runtime.id) {
      removeProxyRuntimeToken(runtime.id, name);
      present = true;
    }
    const config = loadTokenConfig();
    if (config[name]) {
      delete config[name];
      saveTokenConfig(config);
      present = true;
    }
    retractPersistedTokenReceipts(name);
    const status = loadTokenStatus();
    if (status[name]) {
      delete status[name];
      saveTokenStatus(status);
      present = true;
    }
  });
  return present ? "removed" : "not-present";
}

export async function credentialSetSourceIntent(input: CredentialSetSourceInput): Promise<void> {
  // Source binding changes remain an intentional post-enable workflow for curated
  // service/MCP credentials; only structural edits are owner-guarded. Reserved
  // user-service credentials remain inaccessible to generic commands.
  assertNotReservedUserTokenName(input.name, "credential set-source");
  assertKnownCredential(input.name);
  const source = prepareCredentialSource(input);
  savePreparedCredentialSource(input, source);
}

export async function credentialClearSourceIntent(input: CredentialClearSourceInput): Promise<void> {
  assertValidTokenName(input.name);
  assertNotReservedUserTokenName(input.name, "credential clear-source");

  withTokenStoreLock(() => {
    const config = loadTokenConfig();
    const policy = loadPolicy();
    if (!policy.tokens[input.name] && !config[input.name]) {
      const names = Array.from(new Set([...Object.keys(policy.tokens), ...Object.keys(config)])).sort().join(", ") || "<none>";
      die(`unknown credential: ${input.name} (known: ${names})`);
    }

    const runtime = proxyRuntime();
    if (runtime.state === "docker-unavailable" || runtime.state === "proxy-unreachable") {
      die([
        `${input.name} source was not cleared: cannot verify credential revocation while proxy state is ${runtime.state}`,
        "the credential is still bound and still injected",
        "restore Docker access and retry",
      ].join("\n"));
    }
    // The proxy line below reports what actually happened to the proxy-held
    // value, never a liveness guess from the runtime state alone.
    let proxyValue: "removed" | "none held" = "none held";
    if (runtime.id) {
      try {
        removeProxyRuntimeToken(runtime.id, input.name);
        proxyValue = "removed";
      } catch (error) {
        die([
          `${input.name} source was not cleared: ${error instanceof Error ? error.message : String(error)}`,
          "the credential is still bound and still injected",
        ].join("\n"));
      }
    }
    // Revoke the live value before removing its recovery metadata. If a later
    // host-state write fails, the safe residual is a configured source with no
    // proxy value, never an unrecoverable stale value still being injected.
    delete config[input.name];
    saveTokenConfig(config);
    retractPersistedTokenReceipts(input.name);
    const status = loadTokenStatus();
    delete status[input.name];
    saveTokenStatus(status);
    console.log(`${input.name} credential source cleared`);
    console.log("agent exposure: no");
    console.log(`proxy-held value: ${proxyValue === "removed" ? "removed from the running proxy" : `none held (proxy ${runtime.state})`}`);
  });
}

export function credentialStatus(input: CredentialStatusInput = {}): void {
  const policy = loadPolicy();
  const config = loadTokenConfig();
  const status = loadTokenStatus();
  const registry = Object.values(config).some((source) => source.source === "named") ? loadSourceRegistry() : undefined;
  const allNames = Array.from(new Set([...Object.keys(policy.tokens), ...Object.keys(config)])).sort();
  const names = input.name ? allNames.filter((name) => name === input.name) : allNames;

  if (input.name && names.length === 0) die(`unknown credential: ${input.name}`);
  if (names.length === 0) {
    console.log("no proxy credentials configured");
    return;
  }

  for (const name of names) {
    const credentialPolicy = policy.tokens[name];
    const source = config[name];
    const sync = status[name];
    const refresh = effectiveTokenRefresh(source, registry);
    console.log(`${name}: ${source ? "configured" : "unconfigured"}${credentialPolicy ? "" : " (unused local source)"}`);
    console.log(`  source: ${describeSource(source)}`);
    console.log("  destinations:");
    if (!credentialPolicy || credentialPolicy.credentials.length === 0) console.log("    none");
    else for (const credential of credentialPolicy.credentials) console.log(`    ${describeCredential(credential)}`);
    const owner = credentialOwner(name);
    console.log(`  owner: ${owner ? describeCredentialOwner(owner) : "manual"}`);
    console.log(`  refresh: ${describeEffectiveRefresh(refresh)}`);
    console.log("  agent exposure: no");
    if (!credentialPolicy && source) {
      console.log(name.startsWith("user-")
        ? `  cleanup: remove or rename the reserved ${name} entry in the host credential config`
        : `  cleanup: runfree credential clear-source ${name}`);
    }
    if (sync?.state === "stale") {
      console.log(`  last sync: stale (${sync.message}) — proxy holds the value resolved at ${sync.heldValueResolvedAt ?? "an earlier sync"}; retried automatically, at ${sync.syncedAt}`);
    } else if (sync) {
      console.log(`  last sync: ${sync.ok ? "ok" : "failed"} (${sync.message}) at ${sync.syncedAt}`);
    } else {
      console.log("  last sync: never");
    }
  }
}

export async function credentialSyncIntent(input: CredentialSyncInput): Promise<void> {
  if (!input.watch && input.quiet) die("--quiet only applies with --watch");
  if (!input.watch && !input.cacheSourceSecrets) die("--no-cache-source-secrets only applies with --watch");
  if (!input.watch && input.delayFirstSync) die("--delay-first-sync only applies with --watch");
  if (input.watch) {
    await syncTokensWatch({
      cacheSourceSecrets: input.cacheSourceSecrets,
      delayFirstSync: input.delayFirstSync,
      quiet: input.quiet,
      verbose: input.verbose,
    });
    return;
  }
  const result = syncTokens({ exitOnFailure: true, verbose: input.verbose, mode: "source-truth" });
  currentAdminState().tokenResolutionReceipts = result.receipts;
  if (result.failed.length === 0 && result.stale.length === 0) {
    console.log(result.runtimeState === "ready"
      ? "credential sync complete"
      : `credential sources verified; proxy sync pending (${result.runtimeState})`);
  }
}
