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
  createCredentialPreparationScope,
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
  forgetLedgerResolutions,
  isTokenResolutionReceipt,
  type JwtPrivateKeyCacheEntry,
  loadPolicy,
  loadSourceRegistry,
  loadTokenConfig,
  loadTokenStatus,
  newTokenResolutionLedger,
  normalizeCliHost,
  parseDurationSeconds,
  planWatchCredentialReads,
  printTokenSyncFailures,
  type ProxyRuntime,
  proxyRuntime,
  type ProxyRuntimeState,
  removeProxyRuntimeToken,
  retractPersistedTokenReceipts,
  saveTokenConfig,
  saveTokenSource,
  saveTokenStatus,
  seedTokenResolutionLedger,
  syncTokens,
  syncTokensSettlingSignals,
  TokenSyncDeferredError,
  type TokenSyncResult,
  withAdminCallTimeout,
  tokenResolutionLedgerKey,
  type TokenSource,
  tokenSourceFingerprint,
  tokenSourceFromSelection,
  type TokenSourceSelection,
  tokenSyncWatchNowMs,
  warmConvergenceSyncIsEmpty,
  type WatchTokenPreparation,
  withTokenStoreLock,
} from "./admin-core.ts";
import {
  ChildSignaledError,
  CredentialCancellationError,
  type CredentialLifetime,
  createCredentialLifetime,
  hasControllingTerminal,
  settleHostSignals,
} from "./credential-cancellation.ts";
import { type CredentialReadInput } from "./credential-source-reader.ts";
import {
  TOKEN_SYNC_DEFERRED_STATUS,
  WARM_TOKEN_SYNC_CALL_TIMEOUT_MS,
  WARM_TOKEN_SYNC_TOTAL_TIMEOUT_MS,
} from "../runtime/constants.ts";

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

// Parent liveness: the primary signal is an inherited lifetime pipe — the
// parent holds the write end and never writes; its end of file means the
// parent is gone. PIDs are recycled, so the `process.kill(pid, 0)` probe alone
// could keep a watcher (and its 1Password access) alive under an unrelated
// process that landed on the parent's PID; it remains only as a secondary
// signal. Both, and SIGINT/SIGTERM/SIGHUP, stop the watch's lifetime, which
// every read and every effect of a pass checks (credential-cancellation.ts).
function parentLifetimePipeFd(): number | undefined {
  return inheritedFdFromEnv(childEnv().RUNFREE_TOKEN_SYNC_LIFETIME_FD);
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

function lifetimeActive(lifetime: CredentialLifetime): boolean {
  try {
    lifetime.assertActive();
    return true;
  } catch (error) {
    if (error instanceof CredentialCancellationError) return false;
    throw error;
  }
}

// Deliberately NOT unref'd: during a manual `runfree credential sync --watch` (no
// lifetime pipe, no other pending handles) this timer is the only thing
// keeping the event loop — and therefore the watch — alive through the sleep.
// A stop wakes it at once.
function sleepWatchTick(ms: number, lifetime: CredentialLifetime): Promise<void> {
  return new Promise((resolve) => {
    if (lifetime.signal.aborted) {
      resolve();
      return;
    }
    const wake = (): void => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      lifetime.signal.removeEventListener("abort", wake);
      resolve();
    }, ms);
    lifetime.signal.addEventListener("abort", wake, { once: true });
  });
}

async function sleepTokenSyncWatch(intervalMs: number, lifetime: CredentialLifetime): Promise<boolean> {
  const sleepMs = tokenSyncWatchSleepMs(intervalMs);
  const deadline = Date.now() + sleepMs;
  while (Date.now() < deadline) {
    if (!lifetimeActive(lifetime)) return false;
    const remaining = deadline - Date.now();
    // Chunks bound how late the PID probe can notice a vanished parent.
    await sleepWatchTick(Math.min(remaining, 5_000), lifetime);
  }
  const alive = lifetimeActive(lifetime);
  if (alive && childEnv().RUNFREE_TEST_FAKE_DOCKER === "1" && childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS !== undefined) {
    childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS = String(tokenSyncWatchNowMs() + intervalMs);
  }
  return alive;
}

async function sleepUntilNextTokenSync(options: { quiet?: boolean; resolutionLedger: TokenResolutionLedger }, lifetime: CredentialLifetime, snapshot?: TokenSyncRuntimeSnapshot): Promise<boolean> {
  const delayMs = nextTokenSyncDelayMs(options.resolutionLedger, snapshot);
  if (delayMs === undefined) {
    if (!options.quiet) console.log("credential sync watch stopped: no credential sources have refresh intervals");
    return false;
  }
  if (!options.quiet && delayMs > 0) console.log(`next credential sync in ${formatDelayMs(delayMs)}`);
  return sleepTokenSyncWatch(delayMs, lifetime);
}

type WatchPassOptions = Readonly<{
  mode?: "source-truth";
  keepLastGoodOnAnyResolutionFailure?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  resolutionLedger: TokenResolutionLedger;
  sourceSecretCache?: { jwtPrivateKeys: Map<string, JwtPrivateKeyCacheEntry> };
}>;

// Reads the planned sources before the lock, one at a time. A cancelled read
// ends the pass with nothing stored for it: cancellation is never a source
// failure. A fresh scope shares a successful exact 1Password read across
// every destination this pass that uses it; it is released with the pass,
// never reused by a later one.
async function prepareWatchReads(reads: readonly CredentialReadInput[], lifetime: CredentialLifetime): Promise<WatchTokenPreparation> {
  const preparation: WatchTokenPreparation = { preparedAt: Date.now(), entries: new Map() };
  const scope = createCredentialPreparationScope();
  try {
    try {
      for (const read of reads) {
        const result = await scope.read(read, lifetime);
        if (result.kind === "cancelled") throw new CredentialCancellationError(lifetime.stopCause() ?? "lifetime-closed");
        preparation.entries.set(read.tokenName, result.kind === "success"
          ? { kind: "resolved", fingerprint: read.fingerprint, value: result.value, resolvedAt: result.resolvedAt }
          : { kind: "source-failure", fingerprint: read.fingerprint, error: result.error });
      }
      return preparation;
    } catch (error) {
      preparation.entries.clear();
      throw error;
    }
  } finally {
    // The pass is done with every value it shared, success, failure or
    // cancellation alike.
    scope.dispose();
  }
}

async function lockedWatchPass(
  options: WatchPassOptions,
  lifetime: CredentialLifetime,
  reads: readonly CredentialReadInput[],
  observedRuntime: ProxyRuntime | undefined,
): Promise<TokenSyncResult> {
  const preparation = await prepareWatchReads(reads, lifetime);
  try {
    lifetime.assertActive();
    return syncTokens({
      exitOnFailure: false,
      quiet: options.quiet,
      verbose: options.verbose,
      resolutionLedger: options.resolutionLedger,
      sourceSecretCache: options.sourceSecretCache,
      ...(options.mode ? { mode: options.mode } : {}),
      ...(options.keepLastGoodOnAnyResolutionFailure ? { keepLastGoodOnAnyResolutionFailure: true } : {}),
      lifetime,
      watchPreparation: preparation,
      ...(observedRuntime ? { observedRuntime } : {}),
    });
  } catch (error) {
    // A Docker client ended by a signal: if that was the watch's own stop,
    // the pass is cancelled; otherwise its outcome stays unknown and the
    // pass fails without a verdict.
    if (error instanceof ChildSignaledError) {
      await settleHostSignals();
      lifetime.assertActive();
      // Not the watch's own stop: an unknown write outcome, so the token's
      // receipt and resolutions no longer prove the held value.
      if (error.tokenName) {
        retractPersistedTokenReceipts(error.tokenName);
        forgetLedgerResolutions(options.resolutionLedger, error.tokenName);
      }
    }
    throw error;
  } finally {
    preparation.entries.clear();
  }
}

/**
 * One watcher pass: plan its reads, read them before the lock, publish under
 * it. A due token the plan did not foresee (the proxy lost a value it held)
 * is read and published by one immediate follow-up pass.
 */
async function runWatchPass(options: WatchPassOptions, lifetime: CredentialLifetime, snapshot?: TokenSyncRuntimeSnapshot): Promise<TokenSyncResult> {
  lifetime.assertActive();
  const planInput = {
    ledger: options.resolutionLedger,
    quiet: options.quiet,
    verbose: options.verbose,
    sourceSecretCache: options.sourceSecretCache,
  };
  const planned = planWatchCredentialReads({ ...planInput, ...(options.mode ? { mode: options.mode } : {}), ...(snapshot ? { snapshot } : {}) });
  const sync = await lockedWatchPass(options, lifetime, planned.reads, planned.observedRuntime);
  if (sync.unprepared.length === 0) return sync;
  const followUp = planWatchCredentialReads({
    ...planInput,
    only: new Set(sync.unprepared),
    snapshot: { runtimeState: sync.runtimeState, storeGeneration: sync.storeGeneration },
  });
  const second = await lockedWatchPass(options, lifetime, followUp.reads, undefined);
  return {
    ...second,
    failed: [...new Set([...sync.failed, ...second.failed])],
    stale: [...new Set([...sync.stale, ...second.stale])],
  };
}

async function syncTokensWatch(options: { cacheSourceSecrets?: boolean; delayFirstSync?: boolean; initialSourceTruth?: boolean; quiet?: boolean; verbose?: boolean } = {}): Promise<void> {
  if (
    childEnv().RUNFREE_TEST_FAKE_DOCKER === "1"
    && childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_SLEEP_MS !== undefined
    && childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS === undefined
  ) {
    childEnv().RUNFREE_TEST_TOKEN_SYNC_WATCH_NOW_MS = String(Date.now());
  }
  const lifetimeFd = parentLifetimePipeFd();
  const lifetime = createCredentialLifetime({
    lifetimeFd,
    parentAlive: tokenSyncWatchParentPidAlive,
    // A session's watcher is detached and has no terminal; a watch run by
    // hand at one keeps its providers able to prompt there.
    providerGroup: lifetimeFd === undefined && hasControllingTerminal() ? "terminal" : "own",
  });
  try {
    await watchCredentialSources(options, lifetime);
  } catch (error) {
    if (!(error instanceof CredentialCancellationError)) throw error;
  } finally {
    // Joins every provider the watch started before the process may exit.
    await lifetime.close();
  }
  const cause = lifetime.stopCause();
  if (cause === "SIGINT" || cause === "SIGTERM" || cause === "SIGHUP") process.exitCode = WATCH_SIGNAL_EXIT_CODES[cause];
}

const WATCH_SIGNAL_EXIT_CODES = Object.freeze({ SIGHUP: 129, SIGINT: 130, SIGTERM: 143 });

async function watchCredentialSources(
  options: { cacheSourceSecrets?: boolean; delayFirstSync?: boolean; initialSourceTruth?: boolean; quiet?: boolean; verbose?: boolean },
  lifetime: CredentialLifetime,
): Promise<void> {
  // A lifetime that ended before the watch began reads and observes nothing.
  lifetime.assertActive();
  let iterations = 0;
  const maxIterations = tokenSyncWatchIterationsForTests();
  const sourceSecretCache = options.cacheSourceSecrets === false
    ? undefined
    : { jwtPrivateKeys: new Map<string, JwtPrivateKeyCacheEntry>() };
  const resolutionLedger = newTokenResolutionLedger(readStartupTokenResolutionReceipts());
  const passOptions = { quiet: options.quiet, verbose: options.verbose, resolutionLedger, sourceSecretCache };
  if (!options.quiet) console.log(`source secret cache: ${sourceSecretCache ? "memory-only" : "disabled"}`);
  if (options.initialSourceTruth) {
    // The launch reused saved credentials without re-reading their sources
    // (launch plan D4), so the watcher owes one source-truth pass now — before
    // the "no refresh intervals" exit below, which would otherwise skip it for
    // manual sources forever. It runs detached and cannot prompt, so every
    // resolution failure keeps the held value (bounded), and only config-level
    // changes delete.
    let firstPass: TokenSyncRuntimeSnapshot | undefined;
    try {
      const sync = await runWatchPass({ ...passOptions, mode: "source-truth", keepLastGoodOnAnyResolutionFailure: true }, lifetime);
      firstPass = { runtimeState: sync.runtimeState, storeGeneration: sync.storeGeneration };
      const problems = [...sync.failed, ...sync.stale];
      if (options.quiet && problems.length > 0) console.error(`credential sync watch failed for: ${problems.join(", ")}`);
    } catch (error) {
      if (error instanceof CredentialCancellationError) throw error;
      console.error(`credential sync watch first source-truth pass failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!(await sleepUntilNextTokenSync({ ...options, resolutionLedger }, lifetime, firstPass))) return;
  } else if (options.delayFirstSync && !(await sleepUntilNextTokenSync({ ...options, resolutionLedger }, lifetime))) return;
  let snapshot: TokenSyncRuntimeSnapshot | undefined;
  while (true) {
    if (!lifetimeActive(lifetime)) return;
    // The lock is acquired inside each pass, never for the lifetime of the
    // watch process.
    let syncThrew = false;
    try {
      const sync = await runWatchPass(passOptions, lifetime, snapshot);
      snapshot = { runtimeState: sync.runtimeState, storeGeneration: sync.storeGeneration };
      const problems = [...sync.failed, ...sync.stale];
      if (options.quiet && problems.length > 0) console.error(`credential sync watch failed for: ${problems.join(", ")}`);
    } catch (error) {
      if (error instanceof CredentialCancellationError) throw error;
      // The watcher is the session's only token reconciler: a thrown sync —
      // e.g. the token-store lock timing out behind another command's
      // 1Password prompt — must cost one iteration, never the whole watch.
      syncThrew = true;
      snapshot = undefined;
      console.error(`credential sync watch iteration failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    iterations += 1;
    if (maxIterations !== undefined && iterations >= maxIterations) return;
    if (syncThrew) {
      if (!(await sleepTokenSyncWatch(TOKEN_SYNC_WATCH_ERROR_RETRY_MS, lifetime))) return;
      continue;
    }
    if (!(await sleepUntilNextTokenSync({ ...options, resolutionLedger }, lifetime, snapshot))) return;
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

async function savePreparedCredentialSource(input: CredentialSetSourceInput, source: TokenSource): Promise<void> {
  const sourceResult = withTokenStoreLock(() => saveTokenSource(input.name, source, { replaceSource: input.replaceSource }));
  // The sync takes the token-store lock itself, after the save released it,
  // so a provider ended by a signal can be settled before any verdict.
  let syncFailed = false;
  let runtimeState: ProxyRuntimeState | "skipped" = "skipped";
  if (input.sync) {
    const result = await syncTokensSettlingSignals({ quiet: true, exitOnFailure: false, mode: "convergence" });
    syncFailed = result.failed.length > 0;
    runtimeState = result.runtimeState;
    printTokenSyncFailures(result);
  }

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
  await savePreparedCredentialSource(input, source);
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
  if (!input.watch && input.initialSourceTruth) die("--initial-source-truth only applies with --watch");
  if (input.watch && input.mode) die("a startup-convergence sync is one-shot");
  if (input.mode === "startup-convergence") {
    // Nothing to write, delete, or prune: the sync would only observe the proxy.
    if (warmConvergenceSyncIsEmpty()) {
      currentAdminState().tokenResolutionReceipts = [];
      return;
    }
    // Launch plan D4: receipt-gated, resolving nothing. A deferral is not a
    // failure: it hands startup back the unlocked source-truth order, before
    // this sync wrote or removed anything.
    try {
      // It may run while the lifecycle lock is held: every child process is
      // bounded, so a stuck Docker call cannot hold the project's lock.
      const result = withAdminCallTimeout(WARM_TOKEN_SYNC_CALL_TIMEOUT_MS, () => (
        syncTokens({ exitOnFailure: true, verbose: input.verbose, mode: "convergence", preparedOnly: true })
      ), WARM_TOKEN_SYNC_TOTAL_TIMEOUT_MS);
      currentAdminState().tokenResolutionReceipts = result.receipts;
    } catch (error) {
      // A Docker client ended by a signal left its operation's outcome
      // unknown: the host's own signal ends the launch during the settle;
      // any other hands startup back the unlocked order, like a deferral.
      if (error instanceof ChildSignaledError) await settleHostSignals();
      else if (!(error instanceof TokenSyncDeferredError)) throw error;
      if (input.verbose) console.log(`credential sync deferred to a source-truth sync: ${error.message}`);
      process.exitCode = TOKEN_SYNC_DEFERRED_STATUS;
    }
    return;
  }
  if (input.watch) {
    await syncTokensWatch({
      cacheSourceSecrets: input.cacheSourceSecrets,
      delayFirstSync: input.delayFirstSync,
      initialSourceTruth: input.initialSourceTruth === true,
      quiet: input.quiet,
      verbose: input.verbose,
    });
    return;
  }
  const result = await syncTokensSettlingSignals({ exitOnFailure: true, verbose: input.verbose, mode: "source-truth" });
  currentAdminState().tokenResolutionReceipts = result.receipts;
  if (result.failed.length === 0 && result.stale.length === 0) {
    console.log(result.runtimeState === "ready"
      ? "credential sync complete"
      : `credential sources verified; proxy sync pending (${result.runtimeState})`);
  }
}
