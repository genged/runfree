import fs from "node:fs";
import path from "node:path";
import { type SessionIpAssignment } from "@runfree/runtime-contracts/session-file";
import { SessionIpAssignments } from "../session-ip-reuse.js";
import { performance } from "node:perf_hooks";

import { SESSION_ADMISSION_ROOT } from "@runfree/runtime-contracts/session-admission";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";
import { createCommandRunner, type CommandRunner } from "./command.js";
import { resolveIpv4 } from "./dns.js";
import {
  applyAuditTeardown,
  applyHostServiceTeardown,
  applyRuleset,
  flushHostServiceDraining,
  isValidIpv4,
  replaceHostServiceSet,
  replaceAllowedSet,
  replaceAuditDrainingSet,
  replaceAuditSet,
  replaceSessionAdmissionSet,
  validateFirewallPlan,
  verifySessionAdmissionSet,
  type FirewallPlan,
  type HostServiceElement,
} from "./nftables.js";
import {
  checkEtcHostsFile,
  hostServiceEntryKey,
  hostServiceSetDigest,
  parseHostServiceGatewayFromEtcHosts,
  sortHostServiceEntries,
  validateHostServiceGateway,
  type EtcHostsStat,
} from "./host-service-gateway.js";
import {
  discoverInterfaces,
  ensureDefaultRoute,
  verifyFirewallState,
} from "./route.js";
import {
  readAuditMarkerState,
  validateAuditSpoolLines,
  type AuditMarkerState,
} from "../audit.js";
import { loadProxyPolicy, type LoadedProxyPolicy } from "../policy.js";
import {
  loadEffectiveProxyControl,
  type LoadedEffectiveProxyControl,
} from "@runfree/runtime-contracts/effective-control";
import { resolvedHostsPathFromEnv, writeResolvedHostsFile, type ResolvedHostsSnapshot } from "../resolved-hosts.js";
import {
  DEFAULT_PROXY_STATUS_DIR,
  firewallStatusPath,
  type HostServiceGatewayStatus,
} from "@runfree/runtime-contracts/proxy-status";
import { HOST_SERVICE_GATEWAY_STATUS_FILE } from "@runfree/runtime-contracts/host-services";
import { scanSessionFiles, type SessionFileScan } from "../session-files.js";
import { servedSessionFiles, type SessionFileObservation } from "../session-file-validity.js";
import {
  writeGenerationStatusFile,
  type FirewallGenerationStatus,
} from "../status.js";

export type { FirewallPlan } from "./nftables.js";

export type FirewallRefreshOptions = {
  refreshDns?: boolean;
};

export type FirewallController = {
  initialize(plan: FirewallPlan): Promise<void>;
  reconcileSessionAdmission(): Promise<void>;
  refreshPolicyAndIps(options?: FirewallRefreshOptions): Promise<void>;
  verify(plan?: FirewallPlan): Promise<void>;
  stop(): Promise<void>;
};

type FirewallControllerDependencies = {
  applyRuleset: (plan: FirewallPlan) => Promise<void>;
  discoverInterfaces: (plan: FirewallPlan) => Promise<FirewallPlan>;
  ensureDefaultRoute: (plan: FirewallPlan) => Promise<void>;
  loadPolicy: (policyPath: string) => LoadedProxyPolicy;
  loadEffectiveControl: (root: string) => LoadedEffectiveProxyControl;
  log: (line: string) => void;
  nowMs: () => number;
  // Level-triggered generation status for the host CLI's convergence ack:
  // written after the initial ruleset verify and after every generation
  // reload's re-verify. Root-owned — the uid-1001 request proxy cannot write
  // it, so firewall convergence cannot be fabricated below root.
  publishFirewallStatus: (status: FirewallGenerationStatus) => void;
  publishResolvedHosts: (snapshot: ResolvedHostsSnapshot) => void;
  // Per-session files: the scan and the second clock the file validity rule
  // needs.
  scanSessionFiles: (assignments?: ReadonlyMap<string, SessionIpAssignment>) => SessionFileScan;
  readIpAssignments: () => Map<string, SessionIpAssignment> | undefined;
  acknowledgeIpAssignment: (assignment: SessionIpAssignment) => void;
  monotonicNowMs: () => number;
  sessionFileLeaseMaxMs: number;
  resolve4: (host: string) => Promise<string[]>;
  replaceAllowedSet: (ips: readonly string[], plan: FirewallPlan) => Promise<void>;
  replaceSessionAdmissionSet: (ips: readonly string[], plan: FirewallPlan) => Promise<void>;
  verifySessionAdmissionSet: (ips: readonly string[], plan: FirewallPlan) => Promise<void>;
  verify: (plan: FirewallPlan) => Promise<void>;
  // Audit mode: marker, spool, audit sets, and the dedicated audit snapshot.
  readAuditMarkerState: (markerPath: string, nowMs: number) => AuditMarkerState;
  readAuditSpool: (spoolPath: string) => string | undefined;
  replaceAuditSet: (ips: readonly string[], plan: FirewallPlan) => Promise<void>;
  replaceAuditDrainingSet: (ips: readonly string[], plan: FirewallPlan) => Promise<void>;
  applyAuditTeardown: (drainingIps: readonly string[], plan: FirewallPlan) => Promise<void>;
  publishAuditResolvedHosts: (path: string, snapshot: ResolvedHostsSnapshot) => void;
  clearAuditResolvedHosts: (path: string) => void;
  clearAuditSpool: (path: string) => void;
  // Host services (design "Gateway address", "Firewall", "Revocation"). The
  // /etc/hosts read runs only on the maintenance path and in initialize,
  // never in the 100 ms session-admission loop.
  readEtcHosts: () => { text: string; stat: EtcHostsStat };
  // Root-written hand-off of the pinned gateway to the uid-1001 request proxy.
  publishHostServiceGateway: (status: HostServiceGatewayStatus) => void;
  // `gateways` is every gateway pinned in this supervisor's lifetime; each
  // batch refills @host_service_gateways with it (R19).
  replaceHostServiceSet: (
    entries: readonly HostServiceElement[],
    plan: FirewallPlan,
    gateways: readonly string[],
  ) => Promise<void>;
  applyHostServiceTeardown: (
    draining: readonly HostServiceElement[],
    remaining: readonly HostServiceElement[],
    plan: FirewallPlan,
    gateways: readonly string[],
  ) => Promise<void>;
  flushHostServiceDraining: (plan: FirewallPlan) => Promise<void>;
};

const ETC_HOSTS_PATH = "/etc/hosts";
const ETC_HOSTS_MAX_BYTES = 64 * 1024;
const HOST_SERVICE_REASON_LIMIT = 512;

// One descriptor for the stat and the read, opened without following a
// symlink, so the checked file is the file whose bytes are parsed.
function readEtcHostsFile(): { text: string; stat: EtcHostsStat } {
  const fd = fs.openSync(ETC_HOSTS_PATH, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (stat.isFile() && stat.size > ETC_HOSTS_MAX_BYTES) {
      throw new Error(`${ETC_HOSTS_PATH} is larger than ${ETC_HOSTS_MAX_BYTES} bytes`);
    }
    const text = stat.isFile() ? fs.readFileSync(fd, "utf8") : "";
    return { text, stat: { uid: stat.uid, mode: stat.mode, isFile: stat.isFile() } };
  } finally {
    fs.closeSync(fd);
  }
}

function hostServiceGatewayStatusPath(): string {
  return process.env.PROXY_HOST_SERVICE_GATEWAY_PATH
    ?? path.posix.join(DEFAULT_PROXY_STATUS_DIR, HOST_SERVICE_GATEWAY_STATUS_FILE);
}

type ResolvedHost = {
  host: string;
  ips: string[];
  lastResolvedAtMs: number;
};

// What this supervisor has installed and verified in `session_ipv4`.
type SessionAdmissionIdentity = Readonly<{
  records: number;
  ips: readonly string[];
}>;

export function createFirewallController(overrides: Partial<FirewallControllerDependencies> = {}): FirewallController {
  const runner: CommandRunner = createCommandRunner();
  const ipAssignments = new SessionIpAssignments(SESSION_ADMISSION_ROOT);
  const deps: FirewallControllerDependencies = {
    applyRuleset: (plan) => applyRuleset(plan, runner),
    discoverInterfaces: (plan) => discoverInterfaces(plan, runner),
    ensureDefaultRoute: (plan) => ensureDefaultRoute(plan, runner),
    loadPolicy: (policyPath) => loadProxyPolicy(policyPath),
    loadEffectiveControl: (root) => loadEffectiveProxyControl(root),
    log: (line) => console.log(line),
    nowMs: () => Date.now(),
    publishFirewallStatus: (status) => writeGenerationStatusFile(firewallStatusPath(), status),
    publishResolvedHosts: (snapshot) => writeResolvedHostsFile(resolvedHostsPathFromEnv(), snapshot),
    // Root-owned by construction: this supervisor runs as root, so ownerUid 0
    // is the only uid whose files it may trust.
    scanSessionFiles: (assignments) => scanSessionFiles({
      root: SESSION_ADMISSION_ROOT,
      assignments,
      ownerUid: 0,
      projectId: process.env.RUNFREE_PROJECT_ID ?? "",
    }),
    readIpAssignments: () => ipAssignments.read(),
    acknowledgeIpAssignment: (assignment) => ipAssignments.acknowledge("firewall", assignment),
    monotonicNowMs: () => performance.now(),
    sessionFileLeaseMaxMs: SESSION_ADMISSION_LEASE_MAX_DURATION_MS,
    resolve4: (host) => resolveIpv4(host),
    replaceAllowedSet: (ips, plan) => replaceAllowedSet(ips, plan, runner),
    replaceSessionAdmissionSet: (ips, plan) => replaceSessionAdmissionSet(ips, plan, runner),
    verifySessionAdmissionSet: (ips, plan) => verifySessionAdmissionSet(ips, plan, runner),
    verify: (plan) => verifyFirewallState(plan, runner),
    readAuditMarkerState: (markerPath, nowMs) => readAuditMarkerState(markerPath, nowMs),
    readAuditSpool: (spoolPath) => {
      try {
        return fs.readFileSync(spoolPath, "utf8");
      } catch {
        return undefined;
      }
    },
    replaceAuditSet: (ips, plan) => replaceAuditSet(ips, plan, runner),
    replaceAuditDrainingSet: (ips, plan) => replaceAuditDrainingSet(ips, plan, runner),
    applyAuditTeardown: (drainingIps, plan) => applyAuditTeardown(drainingIps, plan, runner),
    publishAuditResolvedHosts: (path, snapshot) => writeResolvedHostsFile(path, snapshot),
    clearAuditResolvedHosts: (path) => fs.rmSync(path, { force: true }),
    clearAuditSpool: (path) => {
      // Truncate, never recreate: the file stays owned by the UID-1001
      // request proxy so it can keep appending after a later activation.
      try {
        fs.truncateSync(path, 0);
      } catch {
        // Missing spool means nothing to clear.
      }
    },
    readEtcHosts: () => readEtcHostsFile(),
    publishHostServiceGateway: (status) => writeGenerationStatusFile(hostServiceGatewayStatusPath(), status),
    replaceHostServiceSet: (entries, plan, gateways) => replaceHostServiceSet(entries, runner, plan, gateways),
    applyHostServiceTeardown: (draining, remaining, plan, gateways) =>
      applyHostServiceTeardown(draining, remaining, runner, plan, gateways),
    flushHostServiceDraining: (plan) => flushHostServiceDraining(runner, plan),
    ...overrides,
  };

  let stopped = false;
  let initialized = false;
  let currentPlan: FirewallPlan | undefined;
  let allowedHosts: string[] = [];
  const cache = new Map<string, ResolvedHost>();
  let appliedSessionAdmissionIdentity: SessionAdmissionIdentity | undefined;
  let sessionAdmissionSetKnownEmpty = false;
  // Invariant 5: the firewall's own observation map for the `files` source.
  // The uid-1001 request proxy keeps a separate one and runs the same rule
  // over it; this root process never consumes that process's decision.
  const sessionFileObservations = new Map<string, SessionFileObservation>();

  // --- Audit state (in-memory only; nothing survives a supervisor restart) --
  let auditWasActive = false;
  // host → safe public IPv4 answers currently admitted through audit_ipv4.
  const auditResolvedHosts = new Map<string, string[]>();
  // The exact set of IPs last installed into audit_ipv4 by publishAuditState
  // (after the cap truncation). Teardown computes the draining set from THIS
  // set, never the untruncated map, so the draining add can never exceed the
  // cap and the draining set only ever contains IPs that were actually
  // accepted by the audit-accept rule.
  let auditInstalledIps: string[] = [];
  // Hosts already consumed from the spool (resolved, rejected, or failed).
  const auditProcessedHosts = new Set<string>();
  // Validated hosts waiting for a resolution budget slot.
  let auditPendingHosts: string[] = [];
  // Spool lines already consumed; the spool is append-only between teardowns.
  let auditSpoolLinesConsumed = 0;
  let auditCapLogged = false;
  let auditIpCapLogged = false;
  let auditDraining: { ips: Set<string>; untilMs: number } | undefined;

  // --- Host-service state (in-memory; a new supervisor instance re-pins) ----
  // The gateway is pinned for this supervisor's lifetime. After the pin, a
  // different or invalid read is sticky (HS8): only a new instance re-pins.
  let pinnedGateway: string | undefined;
  let gatewayChangedReason: string | undefined;
  let gatewayUnavailableReason: string | undefined;
  // Set while the last host-service set write failed (or was refused before
  // nftables). The gateway is then not offered to the request proxy, so no
  // splice is dialled toward a pair the firewall is dropping without a named
  // refusal. Cleared by the next successful write.
  let hostServiceWriteFailure: string | undefined;
  // What this supervisor last installed in @host_service and
  // @host_service_draining. The ruleset install creates both sets empty.
  let installedHostServices: HostServiceElement[] = [];
  // Every gateway this supervisor pinned during its lifetime (R19). Never
  // cleared, not even by a re-initialize: the permanent cut must keep
  // covering an address that ever carried an accepted pair.
  const lifetimeGateways = new Set<string>();
  // What the kernel's @host_service_gateways holds (the ruleset install
  // creates it empty).
  let installedGateways: string[] = [];
  let hostServiceDraining: { entries: HostServiceElement[]; untilMs: number } | undefined;
  let lastPublishedGatewayKey: string | undefined;
  let lastPublishedStatusKey: string | undefined;
  let lastRulesetVerified = true;

  function publishStatus(plan: FirewallPlan, rulesetVerified: boolean): void {
    lastRulesetVerified = rulesetVerified;
    const digest = currentHostServiceDigest();
    const draining = hostServiceDraining?.entries.length ?? 0;
    deps.publishFirewallStatus({
      generation: plan.policyGeneration,
      ...(plan.controlGeneration ? {
        controlGeneration: plan.controlGeneration,
        policyGeneration: plan.policyGeneration,
      } : {}),
      rulesetVerified,
      appliedAt: new Date(deps.nowMs()).toISOString(),
      hostServiceSetDigest: digest,
      hostServiceDraining: draining,
    });
    lastPublishedStatusKey = statusKey(plan, rulesetVerified);
  }

  function currentHostServiceDigest(): string {
    return hostServiceSetDigest(installedHostServices, hostServiceDraining?.entries ?? []);
  }

  function statusKey(plan: FirewallPlan, rulesetVerified: boolean): string {
    return JSON.stringify([
      plan.policyGeneration,
      plan.controlGeneration ?? "",
      rulesetVerified,
      currentHostServiceDigest(),
      hostServiceDraining?.entries.length ?? 0,
    ]);
  }

  function resetHostServiceState(): void {
    pinnedGateway = undefined;
    gatewayChangedReason = undefined;
    gatewayUnavailableReason = undefined;
    hostServiceWriteFailure = undefined;
    installedHostServices = [];
    installedGateways = [];
    hostServiceDraining = undefined;
    lastPublishedGatewayKey = undefined;
    lastPublishedStatusKey = undefined;
  }

  // Read, check, and (before the first pin) pin the gateway. Runs only from
  // initialize and the maintenance path.
  function observeGateway(plan: FirewallPlan): void {
    if (gatewayChangedReason !== undefined) return;
    let observed: { ip: string } | { error: string };
    try {
      const read = deps.readEtcHosts();
      const statError = checkEtcHostsFile(read.stat);
      if (statError !== undefined) {
        observed = { error: statError };
      } else {
        const parsed = parseHostServiceGatewayFromEtcHosts(read.text);
        const invalid = "ip" in parsed ? validateHostServiceGateway(parsed.ip, plan) : parsed.error;
        observed = invalid === undefined && "ip" in parsed ? parsed : { error: invalid ?? "invalid gateway entry" };
      }
    } catch (error) {
      observed = { error: `cannot read /etc/hosts: ${formatError(error)}` };
    }

    if (pinnedGateway === undefined) {
      if ("ip" in observed) {
        pinnedGateway = observed.ip;
        lifetimeGateways.add(observed.ip);
        if (gatewayUnavailableReason !== undefined) {
          deps.log(`proxy-firewall: host-service gateway pinned ip=${observed.ip} after earlier refusal`);
        } else {
          deps.log(`proxy-firewall: host-service gateway pinned ip=${observed.ip}`);
        }
        gatewayUnavailableReason = undefined;
      } else {
        const reason = boundedReason(`host-service gateway unavailable: ${observed.error}`);
        if (reason !== gatewayUnavailableReason) deps.log(`proxy-firewall: ${reason}`);
        gatewayUnavailableReason = reason;
      }
      return;
    }
    if ("ip" in observed && observed.ip === pinnedGateway) return;
    const detail = "ip" in observed ? `now ${observed.ip}` : observed.error;
    // The remedy goes before the variable detail so the length bound can
    // never cut it off.
    gatewayChangedReason = boundedReason(
      `host-service gateway address changed from pinned ${pinnedGateway}; `
      + "host services stay refused until runfree rebuild recreates the proxy, which drains every session"
      + ` (${detail})`,
    );
    deps.log(`proxy-firewall: ${gatewayChangedReason}`);
  }

  // The pinned gateway the firewall should program pairs for.
  function pinnedUsableGateway(): string | undefined {
    return gatewayChangedReason === undefined ? pinnedGateway : undefined;
  }

  // The gateway offered to the request proxy: additionally withheld while the
  // set write is failing.
  function offeredGateway(): string | undefined {
    return hostServiceWriteFailure === undefined ? pinnedUsableGateway() : undefined;
  }

  function gatewayList(): string[] {
    return [...lifetimeGateways].sort();
  }

  function desiredHostServiceEntries(plan: FirewallPlan): HostServiceElement[] {
    const gateway = pinnedUsableGateway();
    if (gateway === undefined) return [];
    return sortHostServiceEntries(Object.values(plan.hostServices ?? {}).map(({ port }) => ({ ip: gateway, port })));
  }

  // Converge @host_service on the desired pairs. A pair that leaves the set
  // moves into @host_service_draining in the same batch, so its established
  // flows are cut, not merely no longer accepted. A pair that comes back is
  // taken out of draining at once. Each `nft -f -` batch is atomic, so a
  // failed batch leaves the kernel, and this record of it, unchanged.
  async function applyHostServiceEntries(plan: FirewallPlan, force: boolean): Promise<void> {
    const desired = desiredHostServiceEntries(plan);
    // Refused before any batch: the renderer would refuse it too, but naming
    // the cause here keeps the refusal readable in the gateway file.
    if (desired.length > plan.nftables.hostServiceMaxElements) {
      throw new Error(`the policy approves ${desired.length} host-service pairs but the firewall set holds at most ${plan.nftables.hostServiceMaxElements}`);
    }
    const desiredKeys = new Set(desired.map(hostServiceEntryKey));
    const currentDraining = hostServiceDraining?.entries ?? [];
    const removed = installedHostServices.filter((entry) => !desiredKeys.has(hostServiceEntryKey(entry)));
    const nextDraining = boundedDraining(
      plan,
      removed,
      currentDraining.filter((entry) => !desiredKeys.has(hostServiceEntryKey(entry))),
    );
    const drainingChanged = !sameStringArray(
      currentDraining.map(hostServiceEntryKey),
      nextDraining.map(hostServiceEntryKey),
    );
    const acceptChanged = !sameStringArray(
      installedHostServices.map(hostServiceEntryKey),
      desired.map(hostServiceEntryKey),
    );
    const gatewaysChanged = !sameStringArray(installedGateways, gatewayList());

    if (removed.length > 0 || drainingChanged) {
      await installHostServiceTeardown(plan, nextDraining, desired, removed.length > 0);
      return;
    }
    if (acceptChanged || gatewaysChanged || force) {
      const gateways = gatewayList();
      await deps.replaceHostServiceSet(desired, plan, gateways);
      installedHostServices = desired;
      installedGateways = gateways;
      deps.log(`proxy-firewall: host-service set updated pairs=${desired.length}`);
    }
  }

  async function installHostServiceTeardown(
    plan: FirewallPlan,
    draining: HostServiceElement[],
    remaining: HostServiceElement[],
    restartWindow: boolean,
  ): Promise<void> {
    const gateways = gatewayList();
    await deps.applyHostServiceTeardown(draining, remaining, plan, gateways);
    installedHostServices = remaining;
    installedGateways = gateways;
    hostServiceDraining = draining.length === 0 ? undefined : {
      entries: draining,
      untilMs: restartWindow || hostServiceDraining === undefined
        ? deps.nowMs() + plan.hostServiceDrainSeconds * 1000
        : hostServiceDraining.untilMs,
    };
    deps.log(`proxy-firewall: host-service set updated pairs=${remaining.length} draining=${draining.length}`);
  }

  // Newly removed pairs first: an older draining pair's window is already
  // running, so it is the one dropped when the set is full (logged).
  function boundedDraining(
    plan: FirewallPlan,
    removed: readonly HostServiceElement[],
    previous: readonly HostServiceElement[],
  ): HostServiceElement[] {
    const all = sortHostServiceEntries([...removed, ...previous]);
    if (all.length <= plan.nftables.hostServiceMaxElements) return all;
    const removedKeys = new Set(removed.map(hostServiceEntryKey));
    deps.log(`proxy-firewall: host-service draining set full; keeping ${plan.nftables.hostServiceMaxElements} of ${all.length} pairs`);
    return sortHostServiceEntries([
      ...all.filter((entry) => removedKeys.has(hostServiceEntryKey(entry))),
      ...all.filter((entry) => !removedKeys.has(hostServiceEntryKey(entry))),
    ].slice(0, plan.nftables.hostServiceMaxElements));
  }

  async function maintainHostServiceDrain(plan: FirewallPlan): Promise<void> {
    if (!hostServiceDraining || deps.nowMs() < hostServiceDraining.untilMs) return;
    await deps.flushHostServiceDraining(plan);
    hostServiceDraining = undefined;
    deps.log("proxy-firewall: host-service drain window complete");
  }

  function publishGateway(plan: FirewallPlan): void {
    const gateway = offeredGateway();
    const reason = gatewayChangedReason
      ?? hostServiceWriteFailure
      ?? gatewayUnavailableReason
      ?? "host-service gateway not pinned";
    const key = JSON.stringify([plan.policyGeneration, gateway ?? "", gateway === undefined ? reason : ""]);
    if (key === lastPublishedGatewayKey) return;
    deps.publishHostServiceGateway({
      schemaVersion: 1,
      policyGeneration: plan.policyGeneration,
      ...(gateway !== undefined ? { gatewayIp: gateway } : { unavailableReason: reason }),
      writtenAt: new Date(deps.nowMs()).toISOString(),
    });
    lastPublishedGatewayKey = key;
  }

  // Write the desired pairs. On failure (an nft error, or a refusal before
  // nftables) fail closed: record a named cause that withholds the gateway
  // from the request proxy, and move every accepted pair into draining so
  // nothing stays reachable. Each batch is atomic, so the record still matches
  // the kernel, and the next pass retries from it (the reclaim).
  async function convergeHostServiceSet(plan: FirewallPlan, force: boolean): Promise<void> {
    try {
      await applyHostServiceEntries(plan, force);
      if (hostServiceWriteFailure !== undefined) deps.log("proxy-firewall: host-service set update recovered");
      hostServiceWriteFailure = undefined;
      return;
    } catch (error) {
      const reason = boundedReason(`host-service firewall set update failed: ${formatError(error)}`);
      if (reason !== hostServiceWriteFailure) deps.log(`proxy-firewall: ${reason}`);
      hostServiceWriteFailure = reason;
    }
    if (installedHostServices.length === 0) return;
    try {
      await installHostServiceTeardown(
        plan,
        boundedDraining(plan, installedHostServices, hostServiceDraining?.entries ?? []),
        [],
        true,
      );
    } catch (fallbackError) {
      deps.log(`proxy-firewall: host-service fail-closed teardown failed: ${formatError(fallbackError)}`);
    }
  }

  // Maintenance-path host-service pass. Each step is independent and logged,
  // so a failure never wedges the refresh loop.
  async function refreshHostServices(plan: FirewallPlan): Promise<void> {
    observeGateway(plan);
    try {
      await maintainHostServiceDrain(plan);
    } catch (error) {
      deps.log(`proxy-firewall: host-service drain flush failed: ${formatError(error)}`);
    }
    await convergeHostServiceSet(plan, false);
    try {
      publishGateway(plan);
    } catch (error) {
      deps.log(`proxy-firewall: failed to publish host-service gateway: ${formatError(error)}`);
    }
  }

  function allowedIpsFromCache(): Set<string> {
    const ips = new Set<string>();
    for (const entry of cache.values()) {
      for (const ip of entry.ips) ips.add(ip);
    }
    return ips;
  }

  function verifiedSessionAdmissionIps(): readonly string[] | undefined {
    if (appliedSessionAdmissionIdentity) return appliedSessionAdmissionIdentity.ips;
    return sessionAdmissionSetKnownEmpty ? [] : undefined;
  }

  async function failClosedAfterNftablesError(
    plan: FirewallPlan,
    originalError: unknown,
    retainedErrors: readonly unknown[] = [],
  ): Promise<never> {
    const errors = [...retainedErrors];
    errors.push(originalError);
    appliedSessionAdmissionIdentity = undefined;
    sessionAdmissionSetKnownEmpty = false;
    try {
      await deps.replaceSessionAdmissionSet([], plan);
    } catch (error) {
      errors.push(error);
    }
    try {
      await deps.verifySessionAdmissionSet([], plan);
      sessionAdmissionSetKnownEmpty = true;
    } catch (error) {
      errors.push(error);
    }
    if (errors.length === 1) throw originalError;
    throw new AggregateError(errors, "session admission nftables reconciliation failed and fail-closed cleanup also failed");
  }

  async function replaceAndVerifySessionAdmissionSet(
    ips: readonly string[],
    plan: FirewallPlan,
    retainedErrors: readonly unknown[] = [],
  ): Promise<void> {
    try {
      await deps.replaceSessionAdmissionSet(ips, plan);
      await deps.verifySessionAdmissionSet(ips, plan);
      sessionAdmissionSetKnownEmpty = ips.length === 0;
    } catch (error) {
      await failClosedAfterNftablesError(plan, error, retainedErrors);
    }
  }

  // Each consumer applies the same lease rule independently. The IP fence
  // acknowledges verified exclusion; it does not assume bounded loop skew.
  async function reconcileSessionFileAdmission(plan: FirewallPlan): Promise<void> {
    const assignments = deps.readIpAssignments();
    // A throwing scan is fail-closed identically to `{ kind: "unreadable" }`
    // (see the matching comment in session-file-registry.ts's `refresh()`).
    let scan: SessionFileScan;
    try {
      scan = deps.scanSessionFiles(assignments);
    } catch {
      scan = { kind: "unreadable" };
    }
    // Invariants 1 and 8: an unreadable root, eligibility, or sessions
    // directory admits nothing — the set is cleared and verified empty below.
    // Observations are kept across it: an unreadable scan says nothing about
    // which sessions exist, and dropping them would hand a replayed file a
    // fresh monotonic bound once the state is readable again.
    let desiredIps: string[] = [];
    let servedCount = 0;
    if (scan.kind === "ok" && assignments !== undefined) {
      const { served } = servedSessionFiles(
        scan,
        sessionFileObservations,
        deps.nowMs(),
        deps.monotonicNowMs(),
        deps.sessionFileLeaseMaxMs,
      );
      servedCount = served.size;
      // Files that fail eligibility, fail to parse, or share a source address
      // never reach `served` (session-files.ts), so this is already an exact,
      // unambiguous address list. `expired` is the request path's concern:
      // the firewall's whole action is the set membership computed here.
      desiredIps = dedupe(Array.from(served.values()).filter((file) => {
        const assignment = assignments.get(file.sourceIp);
        return assignment === undefined || (assignment.state === "ready" && assignment.sessionKey === file.sessionKey);
      }).map((file) => file.sourceIp));
    }

    // nftables is touched only when the desired set differs from what this
    // supervisor has verified.
    const verifiedIps = verifiedSessionAdmissionIps();
    if (verifiedIps === undefined || !sameStringArray(verifiedIps, desiredIps)) {
      await replaceAndVerifySessionAdmissionSet(desiredIps, plan);
      appliedSessionAdmissionIdentity = desiredIps.length === 0 ? undefined : Object.freeze({
        records: servedCount,
        ips: Object.freeze(desiredIps),
      });
    }
    for (const assignment of assignments?.values() ?? []) {
      if (assignment.state === "draining") deps.acknowledgeIpAssignment(assignment);
    }
  }

  // Distinct safe IPv4 answers across every currently stored audit host. This
  // is the universe that publishAuditState would install (modulo the cap),
  // bounded at resolution time so it never exceeds auditMaxElements.
  function distinctAuditIps(): Set<string> {
    const ips = new Set<string>();
    for (const hostIps of auditResolvedHosts.values()) {
      for (const ip of hostIps) ips.add(ip);
    }
    return ips;
  }

  function resetAuditTracking(): void {
    auditWasActive = false;
    auditResolvedHosts.clear();
    auditInstalledIps = [];
    auditProcessedHosts.clear();
    auditPendingHosts = [];
    auditSpoolLinesConsumed = 0;
    auditCapLogged = false;
    auditIpCapLogged = false;
  }

  async function publishAuditState(plan: FirewallPlan): Promise<void> {
    let ips = dedupe(Array.from(auditResolvedHosts.values()).flat());
    if (ips.length > plan.nftables.auditMaxElements) {
      deps.log(`proxy-firewall: audit set full; truncating to ${plan.nftables.auditMaxElements} of ${ips.length} IPv4 addresses`);
      ips = ips.slice(0, plan.nftables.auditMaxElements);
    }
    await deps.replaceAuditSet(ips, plan);
    // Record exactly what was installed: teardown derives the draining set
    // from this, so draining can never exceed the cap and only ever names IPs
    // that the audit-accept rule actually admitted. Recorded only after the
    // set update succeeds, so a failed update never leaves a stale claim.
    auditInstalledIps = ips;
    const hosts: Record<string, string[]> = {};
    for (const [host, hostIps] of auditResolvedHosts) hosts[host] = [...hostIps];
    deps.publishAuditResolvedHosts(plan.audit.resolvedHostsPath, {
      generation: plan.policyGeneration,
      hosts,
    });
    deps.log(`proxy-firewall: audit set updated hosts=${auditResolvedHosts.size} ips=${ips.length}`);
  }

  async function teardownAudit(plan: FirewallPlan, reason: string): Promise<void> {
    const allowedIps = allowedIpsFromCache();
    // draining = installedAuditIps − allowedIps. The draining set is derived
    // from the IPs actually installed into audit_ipv4 (post-cap), never the
    // untruncated map, so it is bounded by auditMaxElements and the
    // teardown render can never throw on size. An IP that is also a
    // legitimate enforce-mode destination is never collateral-dropped.
    const drainingIps = auditInstalledIps.filter((ip) => !allowedIps.has(ip));
    // Teardown must be infallible: enforce mode resumes (audit_ipv4 emptied)
    // and all in-memory/on-disk audit state is cleared on the fast tick even
    // if the nft batch errors. The render/apply is preceded by the bounding
    // logic above, so the throw the wrap defends against should not occur;
    // the wrap is defense-in-depth so a future render error cannot wedge
    // enforcement past expiry. On apply failure we still flush audit_ipv4
    // best-effort so the audit-accept rule stops admitting non-allowlisted
    // IPs.
    let applyError: unknown;
    try {
      await deps.applyAuditTeardown(drainingIps, plan);
    } catch (error) {
      applyError = error;
      deps.log(`proxy-firewall: audit teardown apply failed reason=${reason}: ${formatError(error)}`);
      try {
        // Best-effort: empty audit_ipv4 so non-allowlisted IPs stop being
        // accepted even though the draining set may not have been populated.
        await deps.replaceAuditSet([], plan);
      } catch (flushError) {
        deps.log(`proxy-firewall: audit teardown flush fallback failed: ${formatError(flushError)}`);
      }
    }
    // Each cleanup step is independent and best-effort so a failure in one
    // (e.g. a snapshot rm error) never strands the others. In-memory tracking
    // is always reset so enforce mode resumes and a later session starts clean.
    try {
      deps.clearAuditResolvedHosts(plan.audit.resolvedHostsPath);
    } catch (error) {
      deps.log(`proxy-firewall: audit teardown clear snapshot failed: ${formatError(error)}`);
    }
    try {
      deps.clearAuditSpool(plan.audit.spoolPath);
    } catch (error) {
      deps.log(`proxy-firewall: audit teardown clear spool failed: ${formatError(error)}`);
    }
    resetAuditTracking();
    // Only arm the drain window when the teardown batch (which populates the
    // draining set) actually succeeded; a failed apply did not install the
    // draining members, so there is nothing to maintain or release.
    auditDraining = applyError === undefined && drainingIps.length > 0
      ? { ips: new Set(drainingIps), untilMs: deps.nowMs() + plan.audit.drainSeconds * 1000 }
      : undefined;
    deps.log(`proxy-firewall: audit teardown reason=${reason} draining_ips=${drainingIps.length}`);
  }

  async function maintainAuditDrain(plan: FirewallPlan): Promise<void> {
    if (!auditDraining) return;
    const nowMs = deps.nowMs();
    if (nowMs >= auditDraining.untilMs) {
      await deps.replaceAuditDrainingSet([], plan);
      auditDraining = undefined;
      deps.log("proxy-firewall: audit drain window complete");
      return;
    }
    // An IP that becomes a legitimately allowlisted destination during the
    // drain window is removed from the draining set immediately.
    const allowedIps = allowedIpsFromCache();
    const remaining = Array.from(auditDraining.ips).filter((ip) => !allowedIps.has(ip));
    if (remaining.length !== auditDraining.ips.size) {
      auditDraining.ips = new Set(remaining);
      await deps.replaceAuditDrainingSet(remaining, plan);
      deps.log("proxy-firewall: audit drain released newly allowlisted IPv4 addresses");
    }
  }

  function consumeAuditSpool(plan: FirewallPlan): void {
    const raw = deps.readAuditSpool(plan.audit.spoolPath);
    if (raw === undefined) return;
    // The final split element is either the empty string after a trailing
    // newline or a partially written line; neither is consumed, so a partial
    // line is re-read once its newline lands.
    const completeLines = raw.split("\n").slice(0, -1);
    if (completeLines.length < auditSpoolLinesConsumed) {
      // The spool only shrinks when this supervisor truncates it; an
      // unexpected shrink means restart-like state, so start over.
      auditSpoolLinesConsumed = 0;
    }
    const newLines = completeLines.slice(auditSpoolLinesConsumed);
    if (newLines.length === 0) return;
    auditSpoolLinesConsumed = completeLines.length;
    const validation = validateAuditSpoolLines(newLines);
    if (validation.rejectedLines > 0) {
      deps.log(`proxy-firewall: audit spool rejected_lines=${validation.rejectedLines}`);
    }
    const hostCap = plan.nftables.auditMaxElements;
    for (const host of validation.hosts) {
      if (auditProcessedHosts.has(host) || auditPendingHosts.includes(host)) continue;
      if (auditProcessedHosts.size + auditPendingHosts.length >= hostCap) {
        if (!auditCapLogged) {
          auditCapLogged = true;
          deps.log(`proxy-firewall: audit host cap reached cap=${hostCap}; further observed hosts are not admitted`);
        }
        continue;
      }
      auditPendingHosts.push(host);
    }
  }

  async function resolveAuditHosts(plan: FirewallPlan): Promise<boolean> {
    if (auditPendingHosts.length === 0) return false;
    // New-host resolutions are rate-limited per fast tick so a hostile loop
    // of unique hostnames cannot drive unbounded privileged DNS queries.
    const budget = plan.audit.resolveBudgetPerTick;
    const batch = auditPendingHosts.slice(0, budget);
    auditPendingHosts = auditPendingHosts.slice(budget);
    if (auditPendingHosts.length > 0) {
      deps.log(`proxy-firewall: audit resolve budget reached budget=${budget} deferred_hosts=${auditPendingHosts.length}`);
    }
    const ipCap = plan.nftables.auditMaxElements;
    let changed = false;
    for (const host of batch) {
      auditProcessedHosts.add(host);
      try {
        const answers = await deps.resolve4(host);
        const safeIps: string[] = [];
        for (const ip of answers) {
          const classification = classifyResolvedIpv4(ip, plan);
          if (classification.allowed) {
            safeIps.push(ip);
          } else {
            deps.log(`proxy-firewall: audit rejected unsafe DNS answer host=${host} ip=${ip} class=${classification.reason}`);
          }
        }
        if (safeIps.length > 0) {
          // Bound the universe of stored audit IPs at the set cap so it can
          // never exceed auditMaxElements (each host may resolve to several A
          // records). The fast tick only resolves not-yet-stored hosts, so the
          // distinct IPs already stored plus the slots this host's answers
          // would add must stay within the cap; answers that do not fit are
          // dropped (fail-closed: those addresses are not made reachable).
          const dedupedSafeIps = dedupe(safeIps);
          const distinctStored = distinctAuditIps();
          const fits: string[] = [];
          let newSlots = ipCap - distinctStored.size;
          for (const ip of dedupedSafeIps) {
            if (distinctStored.has(ip)) {
              // Already counted toward the universe by another stored host.
              fits.push(ip);
            } else if (newSlots > 0) {
              fits.push(ip);
              newSlots -= 1;
            }
          }
          const dropped = dedupedSafeIps.length - fits.length;
          if (dropped > 0) {
            if (!auditIpCapLogged) {
              auditIpCapLogged = true;
              deps.log(`proxy-firewall: audit IP cap reached cap=${ipCap}; dropping excess DNS answers`);
            }
            deps.log(`proxy-firewall: audit host answers exceed IP cap host=${host} kept=${fits.length} dropped=${dropped}`);
          }
          if (fits.length > 0) {
            auditResolvedHosts.set(host, fits);
            changed = true;
          } else {
            deps.log(`proxy-firewall: audit host not admitted; IP cap full host=${host}`);
          }
        } else {
          deps.log(`proxy-firewall: audit host has no safe IPv4 answers host=${host}`);
        }
      } catch (error) {
        deps.log(`proxy-firewall: audit DNS lookup failed host=${host}: ${formatError(error)}`);
      }
    }
    return changed;
  }

  // Audit work runs on every fast policy tick, decoupled from the slow
  // enforce-mode DNS cadence: a newly observed host becomes reachable within
  // one tick and teardown happens within one tick of expiry.
  async function refreshAuditTick(plan: FirewallPlan): Promise<void> {
    // A failure in audit work must never abort the enforce-mode refresh loop
    // or prevent the next tick from running. teardownAudit is internally
    // best-effort (it always resets in-memory tracking), so a logged error
    // here cannot leave audit state permanently wedged across ticks.
    try {
      await maintainAuditDrain(plan);
      const marker = deps.readAuditMarkerState(plan.audit.markerPath, deps.nowMs());
      if (!marker.active) {
        if (auditWasActive || auditResolvedHosts.size > 0) {
          await teardownAudit(plan, "marker-inactive");
        }
        return;
      }
      if (!auditWasActive) {
        auditWasActive = true;
        deps.log(`proxy-firewall: audit mode active effective_expiry=${new Date(marker.effectiveExpiryMs).toISOString()}`);
        // Publish an empty audit snapshot immediately so the request proxy's
        // bounded lookup retry engages for the first observed host of the
        // session (the retry is gated on the audit snapshot existing).
        deps.publishAuditResolvedHosts(plan.audit.resolvedHostsPath, {
          generation: plan.policyGeneration,
          hosts: {},
        });
      }
      consumeAuditSpool(plan);
      const changed = await resolveAuditHosts(plan);
      if (changed) {
        await publishAuditState(plan);
      }
    } catch (error) {
      deps.log(`proxy-firewall: audit tick failed: ${formatError(error)}`);
    }
  }

  // The startup guard is a statement about CONFIGURED hosts, not about the
  // derived IP set: if hosts are configured, at least one of them must resolve
  // to a safe address, because a configured policy that resolves nothing at
  // all means the runtime's DNS/egress path is broken rather than that the
  // policy authorizes nothing. Zero configured hosts satisfies that vacuously,
  // which is exactly why an empty allowlist is a legitimate fully-enforced
  // deny-all state rather than a startup error.
  //
  // Deliberately NOT "every configured host resolved". DNS answers are
  // attacker-influenced input, so requiring all of them at boot would hand any
  // party who can make one allowlisted host unresolvable a runtime-wide
  // denial-of-service lever. It would also buy no authorization: an unresolved
  // host has no IP in the set and is already denied. Partial resolution is
  // therefore reported, not fatal — see unresolvedHosts below, which is
  // published in the resolved-host snapshot and named in the refresh log so a
  // partial allowlist is observably partial rather than silently partial.
  //
  // The zero-host path performs no DNS resolution at all: the loop below is
  // this function's only resolver call site and an empty host list never
  // enters it. That is both an optimization and proof that a deny-all startup
  // has no hidden external dependency.
  type ResolutionStrictness = "require-any-configured-host" | "best-effort";

  async function refreshResolvedIps(
    strictness: ResolutionStrictness,
    plan: FirewallPlan = currentPlan ?? failNoPlan(),
    targetAllowedHosts: readonly string[] = allowedHosts,
  ): Promise<void> {
    const now = deps.nowMs();
    let unsafeIps = 0;
    const unresolvedHosts: string[] = [];
    let staleHosts = 0;

    for (const host of targetAllowedHosts) {
      try {
        const answers = await deps.resolve4(host);
        const safeIps: string[] = [];
        for (const ip of answers) {
          const classification = classifyResolvedIpv4(ip, plan);
          if (classification.allowed) {
            safeIps.push(ip);
          } else {
            unsafeIps += 1;
            deps.log(`proxy-firewall: rejected unsafe DNS answer host=${host} ip=${ip} class=${classification.reason}`);
          }
        }
        if (safeIps.length > 0) {
          cache.set(host, { host, ips: dedupe(safeIps), lastResolvedAtMs: now });
        }
      } catch (error) {
        deps.log(`proxy-firewall: DNS lookup failed host=${host}: ${formatError(error)}`);
      }
    }

    const currentHostSet = new Set(targetAllowedHosts);
    for (const host of Array.from(cache.keys())) {
      if (!currentHostSet.has(host)) cache.delete(host);
    }

    const resolvedIps: string[] = [];
    const resolvedHostSnapshot: Record<string, string[]> = {};
    for (const host of targetAllowedHosts) {
      const entry = cache.get(host);
      if (!entry) {
        unresolvedHosts.push(host);
        continue;
      }
      const ageSeconds = (now - entry.lastResolvedAtMs) / 1000;
      if (ageSeconds > plan.refresh.maxStaleHostSeconds) {
        cache.delete(host);
        unresolvedHosts.push(host);
        staleHosts += 1;
        continue;
      }
      resolvedIps.push(...entry.ips);
      resolvedHostSnapshot[host] = [...entry.ips];
    }

    const uniqueIps = dedupe(resolvedIps);
    // Rejection precedes every sensitive side effect: no nftables set
    // replacement, no resolved-host snapshot publish, no readiness status, and
    // (in entrypoint.ts) no request-proxy start.
    if (strictness === "require-any-configured-host" && targetAllowedHosts.length > 0 && uniqueIps.length === 0) {
      throw new Error(`no safe IPv4 addresses resolved for allowlisted hosts: ${unresolvedHosts.join(", ")}`);
    }

    await deps.replaceAllowedSet(uniqueIps, plan);
    deps.publishResolvedHosts({
      generation: plan.policyGeneration,
      hosts: resolvedHostSnapshot,
      unresolvedHosts: [...unresolvedHosts],
    });
    deps.log([
      `proxy-firewall: DNS refresh hosts=${targetAllowedHosts.length}`,
      `resolved_ips=${uniqueIps.length}`,
      `stale_hosts=${staleHosts}`,
      `omitted_hosts=${unresolvedHosts.length}`,
      `unsafe_ips=${unsafeIps}`,
      // Name them, not just count them: a partially resolved allowlist is a
      // legitimate running state, so it has to be diagnosable from the log and
      // the snapshot instead of from a startup failure.
      ...(unresolvedHosts.length > 0 ? [`unresolved_hosts=${unresolvedHosts.join(",")}`] : []),
    ].join(" "));
  }

  // The status is level-triggered: a host-service change within one
  // generation (drain window closing, a late pin, a sticky gateway refusal)
  // republishes it so the host's convergence read sees the kernel state.
  function republishStatusIfHostServicesChanged(plan: FirewallPlan): void {
    if (!initialized || lastPublishedStatusKey === undefined) return;
    if (statusKey(plan, lastRulesetVerified) === lastPublishedStatusKey) return;
    try {
      publishStatus(plan, lastRulesetVerified);
    } catch (error) {
      deps.log(`proxy-firewall: failed to publish generation status: ${formatError(error)}`);
    }
  }

  return {
    async initialize(plan) {
      stopped = false;
      initialized = false;
      currentPlan = await deps.discoverInterfaces(plan);
      allowedHosts = [...currentPlan.allowedHosts];
      validateFirewallPlan(currentPlan);
      deps.log(`proxy-firewall: policy loaded path=${currentPlan.policyPath} hosts=${allowedHosts.length} generation=${currentPlan.policyGeneration}`);
      await deps.ensureDefaultRoute(currentPlan);
      deps.log(`proxy-firewall: route egress=${currentPlan.egress.iface} src=${currentPlan.egress.sourceIp} gateway=${currentPlan.egress.gatewayIp}`);
      await deps.applyRuleset(currentPlan);
      deps.log(`proxy-firewall: installed nftables ruleset internal=${currentPlan.internal.iface} egress=${currentPlan.egress.iface} port=${currentPlan.internal.proxyPort}`);
      // Audit state never survives a supervisor restart: the ruleset above
      // recreated empty audit sets, and any stale audit snapshot is removed
      // before the enforce-only baseline is verified.
      resetAuditTracking();
      appliedSessionAdmissionIdentity = undefined;
      sessionAdmissionSetKnownEmpty = false;
      auditDraining = undefined;
      deps.clearAuditResolvedHosts(currentPlan.audit.resolvedHostsPath);
      // The table replacement above creates session_ipv4 empty. Verify that
      // kernel state explicitly before readiness; stale dynamic admission can
      // never survive a supervisor restart on rendered-rule assumptions alone.
      await deps.verifySessionAdmissionSet([], currentPlan);
      sessionAdmissionSetKnownEmpty = true;
      // Zero configured hosts still runs the full enforcement setup above and
      // below: default-DROP ruleset installed, allowed_ipv4 replaced with an
      // empty set, an empty resolved-host snapshot published for the current
      // generation, the live ruleset/route/audit-set state verified, and only
      // then readiness. Deny-all is proven, not merely unconfigured.
      await refreshResolvedIps("require-any-configured-host");
      // Host services: the ruleset above recreated both host-service sets
      // empty; pin the gateway, write the approved pairs explicitly, and hand
      // the gateway to the request proxy before readiness. A missing or
      // invalid gateway entry, or a refused set write, is a named refusal,
      // not a startup failure: the ruleset install above left both sets
      // empty, so nothing is reachable while the refusal stands.
      resetHostServiceState();
      observeGateway(currentPlan);
      await convergeHostServiceSet(currentPlan, true);
      try {
        publishGateway(currentPlan);
      } catch (error) {
        deps.log(`proxy-firewall: failed to publish host-service gateway: ${formatError(error)}`);
      }
      await deps.verify(currentPlan);
      publishStatus(currentPlan, true);
      initialized = true;
    },
    async reconcileSessionAdmission() {
      if (stopped) return;
      if (!initialized || !currentPlan) failNoPlan();
      await reconcileSessionFileAdmission(currentPlan);
    },
    async refreshPolicyAndIps(options = {}) {
      if (stopped || !currentPlan) return;
      const activePlan = currentPlan;
      let nextPolicy: LoadedProxyPolicy;
      let nextControl: LoadedEffectiveProxyControl | undefined;
      try {
        nextControl = activePlan.effectiveProxyRoot
          ? deps.loadEffectiveControl(activePlan.effectiveProxyRoot)
          : undefined;
        nextPolicy = nextControl?.networkPolicy ?? deps.loadPolicy(activePlan.policyPath);
      } catch (error) {
        deps.log(`proxy-firewall: invalid policy reload preserved previous valid policy previous_generation=${activePlan.policyGeneration}: ${formatError(error)}`);
        // Marker expiry must still tear audit state down while an invalid
        // policy edit is preserved-as-previous, so the audit tick runs even
        // on this early-return path. The host-service drain window and the
        // gateway check run here for the same reason.
        await refreshHostServices(activePlan);
        republishStatusIfHostServicesChanged(activePlan);
        await refreshAuditTick(activePlan);
        return;
      }

      const nextAllowedHosts = [...nextPolicy.allowedHosts];
      const nextControlGeneration = nextControl?.active.controlGeneration ?? activePlan.controlGeneration;
      const generationChanged = activePlan.policyGeneration !== nextPolicy.generation
        || activePlan.controlGeneration !== nextControlGeneration;
      const policyChanged = !sameStringArray(allowedHosts, nextAllowedHosts);
      const nextPlan: FirewallPlan = {
        ...activePlan,
        allowedHosts: nextAllowedHosts,
        hostServices: nextPolicy.hostServices,
        ...(nextControl ? { policyPath: nextControl.networkPolicyPath } : {}),
        ...(nextControlGeneration ? { controlGeneration: nextControlGeneration } : {}),
        policyGeneration: nextPolicy.generation,
      };
      if (options.refreshDns !== false || policyChanged) {
        await refreshResolvedIps("best-effort", nextPlan, nextAllowedHosts);
      }

      allowedHosts = nextAllowedHosts;
      currentPlan = nextPlan;
      // Every host-service change (pairs, draining, gateway hand-off) lands
      // before the status naming this generation is published.
      await refreshHostServices(currentPlan);
      if (generationChanged) {
        deps.log(`proxy-firewall: policy reloaded path=${currentPlan.policyPath} hosts=${allowedHosts.length} generation=${currentPlan.policyGeneration}`);
        // Re-verify the installed ruleset for the new generation (the
        // per-mutation restart used to re-run this check on every policy
        // change) and report the result through the level-triggered status
        // file the host CLI polls for its convergence ack. A verify or
        // publish failure is logged, never allowed to wedge the refresh loop;
        // an unwritten/false status simply means the CLI ack times out and
        // falls back to the restart path.
        let rulesetVerified = true;
        try {
          await deps.verify(currentPlan);
        } catch (error) {
          rulesetVerified = false;
          deps.log(`proxy-firewall: ruleset verification failed after policy reload generation=${currentPlan.policyGeneration}: ${formatError(error)}`);
        }
        try {
          publishStatus(currentPlan, rulesetVerified);
        } catch (error) {
          deps.log(`proxy-firewall: failed to publish generation status: ${formatError(error)}`);
        }
      } else {
        republishStatusIfHostServicesChanged(currentPlan);
      }
      await refreshAuditTick(currentPlan);
    },
    async verify(plan) {
      await deps.verify(plan ?? currentPlan ?? failNoPlan());
    },
    async stop() {
      stopped = true;
    },
  };
}

export function classifyResolvedIpv4(ip: string, plan: FirewallPlan): { allowed: true } | { allowed: false; reason: string } {
  if (!isValidIpv4(ip)) return { allowed: false, reason: "invalid-ipv4" };
  const value = ipv4ToInt(ip);
  for (const [cidr, reason] of [
    ["0.0.0.0/8", "current-network"],
    ["10.0.0.0/8", "private"],
    ["100.64.0.0/10", "carrier-grade-nat"],
    ["127.0.0.0/8", "loopback"],
    ["169.254.0.0/16", "link-local"],
    ["172.16.0.0/12", "private"],
    ["192.0.0.0/24", "ietf-protocol"],
    ["192.0.2.0/24", "documentation"],
    ["192.168.0.0/16", "private"],
    ["198.18.0.0/15", "benchmarking"],
    ["198.51.100.0/24", "documentation"],
    ["203.0.113.0/24", "documentation"],
    ["224.0.0.0/4", "multicast"],
    ["240.0.0.0/4", "reserved"],
    ["255.255.255.255/32", "broadcast"],
  ] as const) {
    if (cidrContains(cidr, value)) return { allowed: false, reason };
  }

  for (const cidr of plan.runtimeSubnets ?? []) {
    if (cidrContains(cidr, value)) return { allowed: false, reason: "runfree-runtime-subnet" };
  }

  return { allowed: true };
}

function boundedReason(reason: string): string {
  return reason.length <= HOST_SERVICE_REASON_LIMIT ? reason : `${reason.slice(0, HOST_SERVICE_REASON_LIMIT - 1)}…`;
}

function failNoPlan(): never {
  throw new Error("firewall controller has not been initialized");
}

function dedupe(values: readonly string[]): string[] {
  return Array.from(new Set(values)).sort();
}

function sameStringArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function formatError(error: unknown): string {
  const value = error instanceof Error ? error.message : `non-Error ${typeof error}`;
  return value.length <= 2_048 ? value : `${value.slice(0, 2_047)}…`;
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((value, octet) => ((value << 8) + Number(octet)) >>> 0, 0);
}

function cidrContains(cidr: string, ip: number): boolean {
  const [networkRaw, prefixRaw] = cidr.split("/");
  if (!networkRaw || !prefixRaw || !isValidIpv4(networkRaw)) return false;
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (ipv4ToInt(networkRaw) & mask);
}
