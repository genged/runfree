import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import { classifyResolvedIpv4, createFirewallController, type FirewallPlan } from "./supervisor.ts";
import { renderAuditSetUpdate, renderAuditTeardown } from "./nftables.ts";
import type { AuditMarkerState } from "../audit.ts";
import { validateProxyPolicy } from "../policy.ts";
import type { LoadedEffectiveProxyControl } from "@runfree/runtime-contracts/effective-control";
import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
  type SessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  serializeSessionFileV1,
  type SessionFileV1,
  type SessionIpAssignment,
} from "@runfree/runtime-contracts/session-file";
import { scanSessionFiles } from "../session-files.ts";

// Default the generation status publisher to a no-op so unit tests never touch
// the real /run tmpfs path; status-file tests override it explicitly.
function createTestFirewallController(overrides: Parameters<typeof createFirewallController>[0] = {}): ReturnType<typeof createFirewallController> {
  return createFirewallController({
    publishFirewallStatus: () => {},
    scanSessionFiles: () => ({ kind: "unreadable" }),
    readIpAssignments: () => new Map(),
    acknowledgeIpAssignment: () => {},
    replaceSessionAdmissionSet: async () => {},
    verifySessionAdmissionSet: async () => {},
    ...overrides,
  });
}

const POLICY_GENERATION = `sha256:${"a".repeat(64)}`;
const CONTROL_GENERATION = `sha256:${"c".repeat(64)}`;
const PROJECT_ID = "0123456789ab";
const SESSION_CONTROL_GENERATION = `sha256:${"b".repeat(64)}`;
const SESSION_AGENT_GENERATION = `sha256:${"a".repeat(64)}`;
const SELECTED_AGENT_IMAGE_ID = `sha256:${"d".repeat(64)}`;
const SESSION_NETWORK_ID = "f".repeat(64);

function sessionEligibility(): SessionAdmissionEligibility {
  return createSessionAdmissionEligibility({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: SESSION_CONTROL_GENERATION,
    admissionContractEpoch: 1,
    agentInternalNetworkId: SESSION_NETWORK_ID,
    allowedSessionAgents: [{
      sessionAgentGenerationDigest: SESSION_AGENT_GENERATION,
      selectedAgentImageId: SELECTED_AGENT_IMAGE_ID,
    }],
  });
}

const plan: FirewallPlan = {
  policyPath: "/policy/network-policy.json",
  policyGeneration: POLICY_GENERATION,
  internal: {
    iface: "eth0",
    proxyIp: "172.30.0.10",
    proxyPort: 8080,
  },
  egress: {
    iface: "eth1",
    sourceIp: "172.30.1.10",
    gatewayIp: "172.30.1.1",
  },
  allowedHosts: ["api.github.com"],
  runtimeSubnets: ["172.30.0.0/24", "172.30.1.0/24"],
  nftables: {
    tableName: "runfree_proxy",
    setName: "allowed_ipv4",
    maxElements: 65536,
    sessionSetName: "session_ipv4",
    sessionMaxElements: 256,
    auditSetName: "audit_ipv4",
    auditDrainingSetName: "audit_draining_ipv4",
    auditMaxElements: 256,
  },
  refresh: {
    policyCheckIntervalSeconds: 2,
    dnsRefreshIntervalSeconds: 300,
    maxStaleHostSeconds: 10,
  },
  audit: {
    markerPath: "/run/runfree-proxy-audit/active.json",
    spoolPath: "/run/runfree-proxy-audit-spool/spool.txt",
    resolvedHostsPath: "/run/runfree-proxy-audit/resolved-hosts.json",
    resolveBudgetPerTick: 8,
    drainSeconds: 30,
  },
};

const publishResolvedHosts = () => {};

describe("proxy firewall DNS supervisor", () => {
  function effectiveControl(controlGeneration: string): LoadedEffectiveProxyControl {
    const networkPolicy = validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, "/effective/network-policy.json");
    return {
      active: {
        schemaVersion: 1,
        controlGeneration,
        hostManifestDigest: `sha256:${"d".repeat(64)}`,
        proxyManifestDigest: `sha256:${"e".repeat(64)}`,
      },
      manifest: {
        schemaVersion: 1,
        compilerVersion: "desired-policy-v2-1",
        controlGeneration,
        policyGeneration: networkPolicy.generation,
        files: {
          "network-policy.json": `sha256:${"f".repeat(64)}`,
          "oauth-mediation-policy.json": `sha256:${"0".repeat(64)}`,
        },
      },
      networkPolicy,
      networkPolicyPath: "/effective/network-policy.json",
      oauthPolicy: { providers: [] },
      oauthPolicyPath: "/effective/oauth-mediation-policy.json",
    };
  }

  test("accepts only public IPv4 answers outside runtime subnets", () => {
    expect(classifyResolvedIpv4("8.8.8.8", plan).allowed).toBe(true);

    for (const ip of [
      "0.0.0.1",
      "10.0.0.1",
      "100.64.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "172.30.0.11",
      "172.30.1.10",
      "192.168.0.1",
      "198.18.0.1",
      "224.0.0.1",
      "240.0.0.1",
      "255.255.255.255",
    ]) {
      expect(classifyResolvedIpv4(ip, plan), ip).toMatchObject({ allowed: false });
    }
  });

  test("startup fails closed when no allowlisted host resolves to a safe address", async () => {
    const controller = createTestFirewallController({
      resolve4: async () => ["127.0.0.1"],
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
    });

    await expect(controller.initialize(plan)).rejects.toThrow(/no safe IPv4 addresses resolved/);
  });

  test("removes deleted policy hosts immediately and swaps an empty set after stale expiry", async () => {
    let now = 1_000;
    let hosts = ["api.github.com", "raw.githubusercontent.com"];
    const swaps: string[][] = [];
    const snapshots: Array<{ generation: string; hosts: Record<string, readonly string[]> }> = [];
    const records: Record<string, string[]> = {
      "api.github.com": ["140.82.112.5"],
      "raw.githubusercontent.com": ["185.199.108.133"],
    };
    const controller = createTestFirewallController({
      nowMs: () => now,
      resolve4: async (host) => records[host] ?? [],
      loadPolicy: () => validateProxyPolicy({ hosts, tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts: (snapshot) => {
        snapshots.push(snapshot);
      },
      verify: async () => {},
    });

    await controller.initialize({ ...plan, allowedHosts: hosts });
    expect(swaps.at(-1)?.sort()).toEqual(["140.82.112.5", "185.199.108.133"]);
    expect(snapshots.at(-1)).toEqual({
      generation: plan.policyGeneration,
      hosts: {
        "api.github.com": ["140.82.112.5"],
        "raw.githubusercontent.com": ["185.199.108.133"],
      },
      unresolvedHosts: [],
    });

    hosts = ["api.github.com"];
    records["api.github.com"] = [];
    now += 5_000;
    await controller.refreshPolicyAndIps();
    expect(swaps.at(-1)).toEqual(["140.82.112.5"]);
    expect(snapshots.at(-1)).toEqual({
      generation: validateProxyPolicy({ hosts, tokens: {} }, plan.policyPath).generation,
      hosts: {
        "api.github.com": ["140.82.112.5"],
      },
      unresolvedHosts: [],
    });

    now += 6_000;
    await controller.refreshPolicyAndIps();
    expect(swaps.at(-1)).toEqual([]);
    expect(snapshots.at(-1)).toEqual({
      generation: validateProxyPolicy({ hosts, tokens: {} }, plan.policyPath).generation,
      hosts: {},
      // The host is still configured, it just has no safe address right now.
      unresolvedHosts: ["api.github.com"],
    });
  });

  test("invalid policy reload preserves the previous valid nftables set", async () => {
    let rawPolicy: unknown = { hosts: ["api.github.com"], tokens: {} };
    const swaps: string[][] = [];
    const controller = createTestFirewallController({
      resolve4: async () => ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts,
      verify: async () => {},
    });

    await controller.initialize(plan);
    rawPolicy = { hosts: ["UPPER.EXAMPLE"], tokens: {} };
    await controller.refreshPolicyAndIps();

    expect(swaps).toEqual([["140.82.112.5"]]);
  });

  test("logs policy generation convergence and preserves the previous generation on invalid reload", async () => {
    let rawPolicy: unknown = { hosts: ["api.github.com"], tokens: {} };
    const logs: string[] = [];
    const controller = createTestFirewallController({
      log: (line) => logs.push(line),
      resolve4: async (host) => host === "raw.githubusercontent.com" ? ["185.199.108.133"] : ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
    });
    const initialGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;

    await controller.initialize({ ...plan, policyGeneration: initialGeneration });
    rawPolicy = { hosts: ["api.github.com", "raw.githubusercontent.com"], tokens: {} };
    const reloadedGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    rawPolicy = { hosts: ["UPPER.EXAMPLE"], tokens: {} };
    await controller.refreshPolicyAndIps({ refreshDns: false });

    expect(logs).toContainEqual(expect.stringContaining(`generation=${initialGeneration}`));
    expect(logs).toContainEqual(expect.stringContaining(`generation=${reloadedGeneration}`));
    expect(logs).toContainEqual(expect.stringContaining(`previous_generation=${reloadedGeneration}`));
  });

  test("requests-only policy edits converge the generation without forcing DNS re-resolution", async () => {
    let rawPolicy: unknown = { hosts: ["api.github.com"], tokens: {} };
    const logs: string[] = [];
    const resolve4 = vi.fn(async () => ["140.82.112.5"]);
    const controller = createTestFirewallController({
      log: (line) => logs.push(line),
      resolve4,
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
    });
    const initialGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;

    await controller.initialize({ ...plan, policyGeneration: initialGeneration });
    const initialResolveCalls = resolve4.mock.calls.length;

    rawPolicy = {
      hosts: ["api.github.com"],
      tokens: {},
      requests: { "api.github.com": { methods: ["GET", "HEAD"] } },
    };
    const ruledGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;
    expect(ruledGeneration).not.toBe(initialGeneration);

    // A non-DNS tick: allowedHosts are unchanged, so the request-rule edit
    // converges the generation without re-resolving any host.
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(resolve4.mock.calls.length).toBe(initialResolveCalls);
    expect(logs).toContainEqual(expect.stringContaining(`policy reloaded path=${plan.policyPath} hosts=1 generation=${ruledGeneration}`));
  });

  test("generation reloads re-verify the ruleset and publish level-triggered status", async () => {
    let rawPolicy: unknown = { hosts: ["api.github.com"], tokens: {} };
    let failVerify = false;
    const statuses: Array<{ generation: string; rulesetVerified: boolean; appliedAt: string }> = [];
    const verify = vi.fn(async () => {
      if (failVerify) throw new Error("ruleset drifted");
    });
    const controller = createTestFirewallController({
      log: () => {},
      nowMs: () => 1_750_000_000_000,
      resolve4: async () => ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      publishFirewallStatus: (status) => statuses.push(status),
      verify,
    });
    const initialGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;

    // Startup publishes the verified initial generation.
    await controller.initialize({ ...plan, policyGeneration: initialGeneration });
    expect(statuses.at(-1)).toEqual({
      generation: initialGeneration,
      rulesetVerified: true,
      appliedAt: new Date(1_750_000_000_000).toISOString(),
    });
    const verifiesAfterInit = verify.mock.calls.length;

    // A net-noop tick (unchanged generation) publishes nothing new and does
    // not re-verify: the existing status file is the level-triggered ack.
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(statuses).toHaveLength(1);
    expect(verify.mock.calls.length).toBe(verifiesAfterInit);

    // A generation change re-runs verify (restoring the integrity check the
    // per-mutation restart used to provide) and publishes the new generation.
    rawPolicy = { hosts: ["api.github.com"], tokens: {}, requests: { "api.github.com": { methods: ["GET"] } } };
    const ruledGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(verify.mock.calls.length).toBe(verifiesAfterInit + 1);
    expect(statuses.at(-1)).toMatchObject({ generation: ruledGeneration, rulesetVerified: true });

    // A failed re-verify reports rulesetVerified=false (the CLI ack fails
    // closed to its restart fallback) without wedging the refresh loop.
    rawPolicy = { hosts: ["api.github.com"], tokens: {} };
    failVerify = true;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(statuses.at(-1)).toMatchObject({ generation: initialGeneration, rulesetVerified: false });
  });

  test("acknowledges OAuth-only control changes and preserves the previous acknowledgement on pair-load failure", async () => {
    let loaded = effectiveControl(CONTROL_GENERATION);
    let failLoad = false;
    const statuses: Array<{ controlGeneration?: string; generation: string; policyGeneration?: string }> = [];
    const verify = vi.fn(async () => {});
    const controller = createTestFirewallController({
      loadEffectiveControl: () => {
        if (failLoad) throw new Error("paired manifest mismatch");
        return loaded;
      },
      resolve4: async () => ["140.82.112.5"],
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      publishFirewallStatus: (status) => statuses.push(status),
      verify,
    });
    await controller.initialize({
      ...plan,
      controlGeneration: loaded.active.controlGeneration,
      effectiveProxyRoot: "/effective",
      policyGeneration: loaded.networkPolicy.generation,
    });
    const verifiesAfterInit = verify.mock.calls.length;

    loaded = effectiveControl(`sha256:${"1".repeat(64)}`);
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(verify.mock.calls.length).toBe(verifiesAfterInit + 1);
    expect(statuses.at(-1)).toMatchObject({
      controlGeneration: loaded.active.controlGeneration,
      generation: loaded.networkPolicy.generation,
      policyGeneration: loaded.networkPolicy.generation,
    });

    failLoad = true;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(statuses).toHaveLength(2);
    expect(statuses.at(-1)?.controlGeneration).toBe(loaded.active.controlGeneration);
  });

  test("an invalid policy reload preserves the previous generation status", async () => {
    let rawPolicy: unknown = { hosts: ["api.github.com"], tokens: {} };
    const statuses: Array<{ generation: string }> = [];
    const controller = createTestFirewallController({
      log: () => {},
      resolve4: async () => ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      publishFirewallStatus: (status) => statuses.push(status),
      verify: async () => {},
    });
    const initialGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;
    await controller.initialize({ ...plan, policyGeneration: initialGeneration });

    // The CLI must never observe a generation this supervisor is not enforcing.
    rawPolicy = { hosts: [42], tokens: {} };
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(statuses).toHaveLength(1);
    expect(statuses.at(-1)).toMatchObject({ generation: initialGeneration });
  });

  test("retries host-change firewall refresh after an nftables set update failure", async () => {
    let rawPolicy: unknown = { hosts: ["api.github.com"], tokens: {} };
    let failNextSwap = false;
    const swaps: string[][] = [];
    const logs: string[] = [];
    const controller = createTestFirewallController({
      log: (line) => logs.push(line),
      resolve4: async (host) => host === "raw.githubusercontent.com" ? ["185.199.108.133"] : ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
        if (failNextSwap) {
          failNextSwap = false;
          throw new Error("swap failed");
        }
      },
      publishResolvedHosts,
      verify: async () => {},
    });
    const initialGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;

    await controller.initialize({ ...plan, policyGeneration: initialGeneration });
    rawPolicy = { hosts: ["api.github.com", "raw.githubusercontent.com"], tokens: {} };
    const reloadedGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;
    failNextSwap = true;

    await expect(controller.refreshPolicyAndIps({ refreshDns: false })).rejects.toThrow("swap failed");
    await controller.refreshPolicyAndIps({ refreshDns: false });

    expect(swaps.map((ips) => ips.sort())).toEqual([
      ["140.82.112.5"],
      ["140.82.112.5", "185.199.108.133"],
      ["140.82.112.5", "185.199.108.133"],
    ]);
    expect(logs.filter((line) => line.includes(`generation=${reloadedGeneration}`))).toHaveLength(1);
  });

  test("policy-only refresh skips DNS while policy is unchanged", async () => {
    const resolve4 = vi.fn(async () => ["140.82.112.5"]);
    const controller = createTestFirewallController({
      resolve4,
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
    });

    await controller.initialize(plan);
    await controller.refreshPolicyAndIps({ refreshDns: false });

    expect(resolve4).toHaveBeenCalledTimes(1);
  });

  test("policy-only refresh still resolves immediately after policy host changes", async () => {
    let hosts = ["api.github.com"];
    const resolvedHosts: string[] = [];
    const swaps: string[][] = [];
    const controller = createTestFirewallController({
      resolve4: async (host) => {
        resolvedHosts.push(host);
        return host === "raw.githubusercontent.com" ? ["185.199.108.133"] : ["140.82.112.5"];
      },
      loadPolicy: () => validateProxyPolicy({ hosts, tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts,
      verify: async () => {},
    });

    await controller.initialize(plan);
    hosts = ["api.github.com", "raw.githubusercontent.com"];
    await controller.refreshPolicyAndIps({ refreshDns: false });

    expect(resolvedHosts).toContain("raw.githubusercontent.com");
    expect(swaps.at(-1)?.sort()).toEqual(["140.82.112.5", "185.199.108.133"]);
  });
});

// Zero configured hosts is a legitimate, fully-enforced deny-all state, not an
// error and not a degraded mode. The startup guard is about CONFIGURED hosts
// ("if any host is configured, at least ONE of them must resolve to a safe
// address"), which zero hosts satisfies vacuously, so `runfree host remove` on
// the last host must leave a policy the proxy can still boot on.
//
// It is deliberately NOT "every configured host must resolve" — see the
// rationale on refreshResolvedIps in supervisor.ts. DNS answers are
// attacker-influenced input, so an all-must-resolve rule would turn one
// unresolvable allowlisted host into a runtime-wide startup denial of service
// while buying no authorization (an unresolved host has no IP in the set and
// is already denied). "partial resolution starts successfully and reports the
// unresolved hosts visibly" below is the test that pins this; do not "fix" the
// guard to all-must-resolve.
describe("proxy firewall empty allowlist state", () => {
  const emptyPolicy = { hosts: [] as string[], tokens: {} };
  const EMPTY_GENERATION = validateProxyPolicy(emptyPolicy, plan.policyPath).generation;
  const emptyPlan: FirewallPlan = { ...plan, allowedHosts: [], policyGeneration: EMPTY_GENERATION };
  const NOW_MS = 1_750_000_000_000;

  type Snapshot = { generation: string; hosts: Record<string, readonly string[]>; unresolvedHosts?: readonly string[] };
  type Status = { generation: string; rulesetVerified: boolean; appliedAt: string };

  test("zero configured hosts still runs the full enforcement setup and reaches readiness", async () => {
    const order: string[] = [];
    const swaps: string[][] = [];
    const snapshots: Snapshot[] = [];
    const statuses: Status[] = [];
    const controller = createTestFirewallController({
      nowMs: () => NOW_MS,
      log: () => {},
      resolve4: async () => [],
      loadPolicy: () => validateProxyPolicy(emptyPolicy, plan.policyPath),
      discoverInterfaces: async (candidate) => {
        order.push("discoverInterfaces");
        return candidate;
      },
      ensureDefaultRoute: async () => {
        order.push("ensureDefaultRoute");
      },
      applyRuleset: async () => {
        order.push("applyRuleset");
      },
      clearAuditResolvedHosts: () => {
        order.push("clearAuditResolvedHosts");
      },
      replaceAllowedSet: async (ips) => {
        order.push("replaceAllowedSet");
        swaps.push([...ips]);
      },
      publishResolvedHosts: (snapshot) => {
        order.push("publishResolvedHosts");
        snapshots.push(snapshot as Snapshot);
      },
      verify: async () => {
        order.push("verify");
      },
      publishFirewallStatus: (status) => {
        order.push("publishFirewallStatus");
        statuses.push(status);
      },
    });

    await expect(controller.initialize(emptyPlan)).resolves.toBeUndefined();

    // Deny-all is proven, not merely unconfigured: the route is repaired, the
    // default-DROP ruleset is installed, the allowlist set is replaced with an
    // empty set, an empty snapshot is published for the live generation, and
    // the live firewall state is verified BEFORE readiness is published (which
    // is what gates the request-proxy start in entrypoint.ts).
    expect(order).toEqual([
      "discoverInterfaces",
      "ensureDefaultRoute",
      "applyRuleset",
      "clearAuditResolvedHosts",
      "replaceAllowedSet",
      "publishResolvedHosts",
      "verify",
      "publishFirewallStatus",
    ]);
    expect(swaps).toEqual([[]]);
    expect(snapshots).toEqual([{ generation: EMPTY_GENERATION, hosts: {}, unresolvedHosts: [] }]);
    expect(statuses).toEqual([{
      generation: EMPTY_GENERATION,
      rulesetVerified: true,
      appliedAt: new Date(NOW_MS).toISOString(),
    }]);
  });

  test("the zero-host path performs no DNS resolution at all", async () => {
    const resolve4 = vi.fn(async () => ["140.82.112.5"]);
    const controller = createTestFirewallController({
      log: () => {},
      resolve4,
      loadPolicy: () => validateProxyPolicy(emptyPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      clearAuditResolvedHosts: () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
    });

    await controller.initialize(emptyPlan);
    expect(resolve4).not.toHaveBeenCalled();

    // Even a full DNS-cadence tick resolves nothing: a deny-all startup and a
    // deny-all steady state have no hidden external dependency.
    await controller.refreshPolicyAndIps({ refreshDns: true });
    expect(resolve4).not.toHaveBeenCalled();
  });

  test("a configured host resolving only to unsafe addresses fails startup before any enforcement side effect", async () => {
    const swaps: string[][] = [];
    const snapshots: Snapshot[] = [];
    const statuses: Status[] = [];
    const verify = vi.fn(async () => {});
    const controller = createTestFirewallController({
      log: () => {},
      // Loopback, link-local metadata, and a runtime-subnet answer: every
      // answer is classified unsafe, so the host resolves to nothing usable.
      resolve4: async () => ["127.0.0.1", "169.254.169.254", "172.30.0.11"],
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      clearAuditResolvedHosts: () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts: (snapshot) => {
        snapshots.push(snapshot as Snapshot);
      },
      publishFirewallStatus: (status) => {
        statuses.push(status);
      },
      verify,
    });

    await expect(controller.initialize(plan))
      .rejects.toThrow(/no safe IPv4 addresses resolved for allowlisted hosts: api\.github\.com/);

    // Rejection precedes every sensitive side effect: no nftables set update,
    // no published snapshot, no live verification, and no readiness status —
    // so entrypoint.ts never writes the readiness file and never launches the
    // request proxy.
    expect(swaps).toEqual([]);
    expect(snapshots).toEqual([]);
    expect(verify).not.toHaveBeenCalled();
    expect(statuses).toEqual([]);
  });

  test("partial resolution starts successfully and reports the unresolved hosts visibly", async () => {
    const swaps: string[][] = [];
    const snapshots: Snapshot[] = [];
    const logs: string[] = [];
    const controller = createTestFirewallController({
      log: (line) => logs.push(line),
      resolve4: async (host) => {
        if (host === "raw.githubusercontent.com") throw new Error("NXDOMAIN");
        return ["140.82.112.5"];
      },
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com", "raw.githubusercontent.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      clearAuditResolvedHosts: () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts: (snapshot) => {
        snapshots.push(snapshot as Snapshot);
      },
      verify: async () => {},
    });

    // DNS answers are attacker-influenced input. Failing startup because one
    // allowlisted host is unresolvable would hand that input a runtime-wide
    // denial-of-service lever while buying no authorization: the unresolved
    // host has no IP in the set and is already denied. So this boots.
    await expect(controller.initialize({ ...plan, allowedHosts: ["api.github.com", "raw.githubusercontent.com"] }))
      .resolves.toBeUndefined();

    expect(swaps).toEqual([["140.82.112.5"]]);
    // Observably partial, not silently partial: the snapshot names what did
    // not resolve alongside what did, and the refresh log names it too.
    expect(snapshots.at(-1)).toEqual({
      generation: plan.policyGeneration,
      hosts: { "api.github.com": ["140.82.112.5"] },
      unresolvedHosts: ["raw.githubusercontent.com"],
    });
    expect(logs).toContainEqual(expect.stringContaining("unresolved_hosts=raw.githubusercontent.com"));
  });

  test("startup still fails when configured hosts resolve nothing at all", async () => {
    const swaps: string[][] = [];
    const verify = vi.fn(async () => {});
    const controller = createTestFirewallController({
      log: () => {},
      // Systemic failure, not a single bad host: nothing configured resolved,
      // which means the runtime's DNS/egress path is broken.
      resolve4: async () => {
        throw new Error("SERVFAIL");
      },
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com", "raw.githubusercontent.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      clearAuditResolvedHosts: () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts,
      verify,
    });

    await expect(controller.initialize({ ...plan, allowedHosts: ["api.github.com", "raw.githubusercontent.com"] }))
      .rejects.toThrow(/no safe IPv4 addresses resolved for allowlisted hosts: api\.github\.com, raw\.githubusercontent\.com/);
    expect(swaps).toEqual([]);
    expect(verify).not.toHaveBeenCalled();
  });

  test("reload converges empty -> non-empty and non-empty -> empty", async () => {
    let rawPolicy: unknown = emptyPolicy;
    const swaps: string[][] = [];
    const snapshots: Snapshot[] = [];
    const statuses: Status[] = [];
    const resolvedHosts: string[] = [];
    const controller = createTestFirewallController({
      log: () => {},
      resolve4: async (host) => {
        resolvedHosts.push(host);
        return ["140.82.112.5"];
      },
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      clearAuditResolvedHosts: () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts: (snapshot) => {
        snapshots.push(snapshot as Snapshot);
      },
      publishFirewallStatus: (status) => {
        statuses.push(status);
      },
      verify: async () => {},
    });

    await controller.initialize(emptyPlan);
    expect(swaps).toEqual([[]]);
    expect(resolvedHosts).toEqual([]);

    rawPolicy = { hosts: ["api.github.com"], tokens: {} };
    const populatedGeneration = validateProxyPolicy(rawPolicy, plan.policyPath).generation;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(resolvedHosts).toEqual(["api.github.com"]);
    expect(swaps.at(-1)).toEqual(["140.82.112.5"]);
    expect(snapshots.at(-1)).toEqual({
      generation: populatedGeneration,
      hosts: { "api.github.com": ["140.82.112.5"] },
      unresolvedHosts: [],
    });
    expect(statuses.at(-1)).toMatchObject({ generation: populatedGeneration, rulesetVerified: true });

    rawPolicy = emptyPolicy;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    // Removal is immediate and needs no DNS: the cached host is dropped, the
    // set is replaced with an empty set, and the empty generation converges.
    expect(resolvedHosts).toEqual(["api.github.com"]);
    expect(swaps.at(-1)).toEqual([]);
    expect(snapshots.at(-1)).toEqual({ generation: EMPTY_GENERATION, hosts: {}, unresolvedHosts: [] });
    expect(statuses.at(-1)).toMatchObject({ generation: EMPTY_GENERATION, rulesetVerified: true });
  });

  test("an invalid reload from an empty policy preserves the previous valid empty generation", async () => {
    let rawPolicy: unknown = emptyPolicy;
    const swaps: string[][] = [];
    const statuses: Status[] = [];
    const controller = createTestFirewallController({
      log: () => {},
      resolve4: async () => [],
      loadPolicy: () => validateProxyPolicy(rawPolicy, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      clearAuditResolvedHosts: () => {},
      replaceAllowedSet: async (ips) => {
        swaps.push([...ips]);
      },
      publishResolvedHosts,
      publishFirewallStatus: (status) => {
        statuses.push(status);
      },
      verify: async () => {},
    });

    await controller.initialize(emptyPlan);
    rawPolicy = { hosts: [42], tokens: {} };
    await controller.refreshPolicyAndIps({ refreshDns: false });

    // The CLI must never observe a generation this supervisor is not
    // enforcing, and the enforced empty set must not be disturbed.
    expect(statuses).toHaveLength(1);
    expect(statuses.at(-1)).toMatchObject({ generation: EMPTY_GENERATION });
    expect(swaps).toEqual([[]]);
  });
});

describe("proxy firewall audit mode supervisor", () => {
  const ACTIVE_MARKER: AuditMarkerState = { active: true, enabledAtMs: 0, effectiveExpiryMs: 100_000_000 };
  const INACTIVE_MARKER: AuditMarkerState = { active: false };

  type AuditHarness = {
    controller: ReturnType<typeof createFirewallController>;
    testPlan: FirewallPlan;
    setMarker(state: AuditMarkerState): void;
    setSpool(contents: string): void;
    appendSpool(line: string): void;
    advance(ms: number): void;
    auditSwaps: string[][];
    drainingSwaps: string[][];
    teardowns: string[][];
    auditSnapshots: Array<{ path: string; snapshot: { generation: string; hosts: Record<string, readonly string[]> } }>;
    enforceSnapshots: Array<{ generation: string; hosts: Record<string, readonly string[]>; unresolvedHosts?: readonly string[] }>;
    clearedSnapshots: string[];
    clearedSpools: string[];
    logs: string[];
    resolvedHosts: string[];
  };

  function createAuditHarness(options: {
    records?: Record<string, string[]>;
    auditPlan?: Partial<FirewallPlan["audit"]>;
    nftables?: Partial<FirewallPlan["nftables"]>;
  } = {}): AuditHarness {
    let now = 1_000;
    let marker: AuditMarkerState = INACTIVE_MARKER;
    let spool = "";
    const auditSwaps: string[][] = [];
    const drainingSwaps: string[][] = [];
    const teardowns: string[][] = [];
    const auditSnapshots: AuditHarness["auditSnapshots"] = [];
    const enforceSnapshots: AuditHarness["enforceSnapshots"] = [];
    const clearedSnapshots: string[] = [];
    const clearedSpools: string[] = [];
    const logs: string[] = [];
    const resolvedHosts: string[] = [];
    const records: Record<string, string[]> = {
      "api.github.com": ["140.82.112.5"],
      ...options.records,
    };
    const testPlan: FirewallPlan = {
      ...plan,
      nftables: { ...plan.nftables, ...options.nftables },
      audit: { ...plan.audit, ...options.auditPlan },
    };
    const controller = createTestFirewallController({
      nowMs: () => now,
      log: (line) => logs.push(line),
      resolve4: async (host) => {
        resolvedHosts.push(host);
        const answers = records[host];
        if (!answers) throw new Error(`no DNS records for ${host}`);
        return answers;
      },
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts: (snapshot) => {
        enforceSnapshots.push(snapshot);
      },
      verify: async () => {},
      readAuditMarkerState: () => marker,
      readAuditSpool: () => spool,
      replaceAuditSet: async (ips) => {
        // Render through the real renderer so the audit-set cap is enforced
        // exactly as in production: a >cap install would throw here.
        renderAuditSetUpdate(ips, testPlan);
        auditSwaps.push([...ips]);
      },
      replaceAuditDrainingSet: async (ips) => {
        drainingSwaps.push([...ips]);
      },
      applyAuditTeardown: async (drainingIps) => {
        // Render through the real teardown renderer so a draining set larger
        // than auditMaxElements throws before any side effect, reproducing the
        // production fail-open-on-teardown bug if the bound is ever lost.
        renderAuditTeardown(drainingIps, testPlan);
        teardowns.push([...drainingIps]);
      },
      publishAuditResolvedHosts: (path, snapshot) => {
        auditSnapshots.push({ path, snapshot });
      },
      clearAuditResolvedHosts: (path) => {
        clearedSnapshots.push(path);
      },
      clearAuditSpool: (path) => {
        clearedSpools.push(path);
        spool = "";
      },
    });
    return {
      controller,
      testPlan,
      setMarker: (state) => {
        marker = state;
      },
      setSpool: (contents) => {
        spool = contents;
      },
      appendSpool: (line) => {
        spool += `${line}\n`;
      },
      advance: (ms) => {
        now += ms;
      },
      auditSwaps,
      drainingSwaps,
      teardowns,
      auditSnapshots,
      enforceSnapshots,
      clearedSnapshots,
      clearedSpools,
      logs,
      resolvedHosts,
    };
  }

  test("consumes the spool only while a valid marker is active", async () => {
    const harness = createAuditHarness({ records: { "observed.example": ["9.9.9.9"] } });
    await harness.controller.initialize(harness.testPlan);
    harness.appendSpool("observed.example");

    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.resolvedHosts).not.toContain("observed.example");
    expect(harness.auditSwaps).toEqual([]);

    harness.setMarker(ACTIVE_MARKER);
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.resolvedHosts).toContain("observed.example");
    expect(harness.auditSwaps.at(-1)).toEqual(["9.9.9.9"]);
    // The audit snapshot is dedicated: it goes to the audit path, and the
    // enforce snapshot never carries the audited host.
    expect(harness.auditSnapshots.at(-1)?.path).toBe(harness.testPlan.audit.resolvedHostsPath);
    expect(harness.auditSnapshots.at(-1)?.snapshot.hosts).toEqual({ "observed.example": ["9.9.9.9"] });
    for (const snapshot of harness.enforceSnapshots) {
      expect(Object.keys(snapshot.hosts)).not.toContain("observed.example");
    }
  });

  test("re-validates every spool line and classifies every resolved answer before set insertion", async () => {
    const harness = createAuditHarness({
      records: {
        "good.example": ["8.8.8.8"],
        "metadata.example": ["169.254.169.254"],
      },
    });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool(`${"a".repeat(300)}.example`);
    harness.appendSpool("bad_host!.example");
    harness.appendSpool("metadata.example");
    harness.appendSpool("good.example");

    await harness.controller.refreshPolicyAndIps({ refreshDns: false });

    // Oversized and non-normalizable lines are rejected and counted before
    // any DNS side effect; unsafe answers are rejected after classification.
    expect(harness.resolvedHosts).toEqual(expect.arrayContaining(["metadata.example", "good.example"]));
    expect(harness.resolvedHosts).toHaveLength(3); // initialize() resolves api.github.com
    expect(harness.logs).toContainEqual(expect.stringContaining("audit spool rejected_lines=2"));
    expect(harness.logs).toContainEqual(expect.stringContaining("audit rejected unsafe DNS answer host=metadata.example ip=169.254.169.254 class=link-local"));
    expect(harness.auditSwaps.at(-1)).toEqual(["8.8.8.8"]);
    expect(harness.auditSnapshots.at(-1)?.snapshot.hosts).toEqual({ "good.example": ["8.8.8.8"] });
  });

  test("caps distinct audit hosts and rate-limits new-host resolutions per tick", async () => {
    const harness = createAuditHarness({
      records: {
        "one.example": ["9.9.9.1"],
        "two.example": ["9.9.9.2"],
        "three.example": ["9.9.9.3"],
      },
      nftables: { auditMaxElements: 2 },
      auditPlan: { resolveBudgetPerTick: 1 },
    });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool("one.example");
    harness.appendSpool("two.example");
    harness.appendSpool("three.example");

    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.resolvedHosts.filter((host) => host.endsWith(".example"))).toEqual(["one.example"]);
    expect(harness.logs).toContainEqual(expect.stringContaining("audit host cap reached cap=2"));
    expect(harness.logs).toContainEqual(expect.stringContaining("audit resolve budget reached budget=1"));

    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.resolvedHosts.filter((host) => host.endsWith(".example"))).toEqual(["one.example", "two.example"]);

    // The third host stays out: the cap fails closed.
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.resolvedHosts.filter((host) => host.endsWith(".example"))).toEqual(["one.example", "two.example"]);
    expect(harness.auditSwaps.at(-1)?.sort()).toEqual(["9.9.9.1", "9.9.9.2"]);
  });

  test("teardown moves currentAuditIps minus allowedIps into draining in one atomic batch and clears audit state", async () => {
    const harness = createAuditHarness({
      records: {
        // Overlaps with the enforce-mode answer for api.github.com plus one
        // audit-only address.
        "observed.example": ["140.82.112.5", "9.9.9.9"],
      },
    });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool("observed.example");
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.auditSwaps.at(-1)?.sort()).toEqual(["140.82.112.5", "9.9.9.9"]);

    const clearedBefore = harness.clearedSnapshots.length;
    harness.setMarker(INACTIVE_MARKER);
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });

    // The IP shared with the enforce allowlist is excluded from draining.
    expect(harness.teardowns).toEqual([["9.9.9.9"]]);
    expect(harness.clearedSnapshots.length).toBe(clearedBefore + 1);
    expect(harness.clearedSpools).toContain(harness.testPlan.audit.spoolPath);

    // Idempotent: with audit state gone, later inactive ticks do nothing.
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.teardowns).toHaveLength(1);
  });

  test("drain window: newly allowlisted IPs are released immediately and the set flushes at the deadline", async () => {
    const records: Record<string, string[]> = {
      "api.github.com": ["140.82.112.5"],
      "observed.example": ["9.9.9.9"],
    };
    const harness = createAuditHarness({ records });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool("observed.example");
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });

    harness.setMarker(INACTIVE_MARKER);
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.teardowns).toEqual([["9.9.9.9"]]);

    // The drained IP becomes a legitimate allowlisted destination: it leaves
    // the draining set on the next tick, before the window expires. The
    // records arrays are shared by reference with the harness resolver.
    records["api.github.com"].push("9.9.9.9");
    harness.advance(2_000);
    await harness.controller.refreshPolicyAndIps({ refreshDns: true });
    expect(harness.drainingSwaps.at(-1)).toEqual([]);
    expect(harness.logs).toContainEqual(expect.stringContaining("audit drain released newly allowlisted"));

    // The window deadline flushes whatever remains.
    harness.advance(31_000);
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.drainingSwaps.at(-1)).toEqual([]);
    expect(harness.logs).toContainEqual(expect.stringContaining("audit drain window complete"));
  });

  test("marker expiry tears audit state down even while an invalid policy edit is preserved", async () => {
    let policyValid = true;
    let marker: AuditMarkerState = ACTIVE_MARKER;
    const teardowns: string[][] = [];
    const controller = createTestFirewallController({
      nowMs: () => 1_000,
      log: () => {},
      resolve4: async (host) => host === "observed.example" ? ["9.9.9.9"] : ["140.82.112.5"],
      loadPolicy: () => {
        if (!policyValid) throw new Error("invalid policy");
        return validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath);
      },
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
      readAuditMarkerState: () => marker,
      readAuditSpool: () => "observed.example\n",
      replaceAuditSet: async () => {},
      replaceAuditDrainingSet: async () => {},
      applyAuditTeardown: async (drainingIps) => {
        teardowns.push([...drainingIps]);
      },
      publishAuditResolvedHosts: () => {},
      clearAuditResolvedHosts: () => {},
      clearAuditSpool: () => {},
    });

    await controller.initialize(plan);
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(teardowns).toEqual([]);

    marker = INACTIVE_MARKER;
    policyValid = false;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(teardowns).toEqual([["9.9.9.9"]]);
  });

  test("nothing audit-related persists across supervisor re-initialization", async () => {
    const harness = createAuditHarness({ records: { "observed.example": ["9.9.9.9"] } });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool("observed.example");
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.auditSwaps.at(-1)).toEqual(["9.9.9.9"]);

    // Restart-equivalent: initialize() rebuilds only enforce-mode state and
    // removes any stale audit snapshot.
    const clearedBefore = harness.clearedSnapshots.length;
    await harness.controller.initialize(harness.testPlan);
    expect(harness.clearedSnapshots.length).toBe(clearedBefore + 1);

    // No teardown fires after restart because no in-memory audit state
    // survived; the recreated ruleset already has empty audit sets.
    harness.setMarker(INACTIVE_MARKER);
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.teardowns).toEqual([]);
  });

  test("teardown stays bounded and infallible when many hosts resolve to far more IPs than the cap", async () => {
    // 90 hosts × 3 distinct A records each = 270 safe IPs, well over the cap.
    // Without the resolution-time bound the audit universe would exceed the
    // cap and the teardown render would throw before flushing audit_ipv4,
    // leaving non-allowlisted IPs accepted past expiry (fail-open).
    const cap = 8;
    const records: Record<string, string[]> = { "api.github.com": ["140.82.112.5"] };
    for (let host = 0; host < 90; host += 1) {
      records[`cdn-${host}.example`] = [
        `9.9.${host}.1`,
        `9.9.${host}.2`,
        `9.9.${host}.3`,
      ];
    }
    const harness = createAuditHarness({
      records,
      nftables: { auditMaxElements: cap },
      auditPlan: { resolveBudgetPerTick: 256 },
    });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    for (let host = 0; host < 90; host += 1) harness.appendSpool(`cdn-${host}.example`);

    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    // The installed audit set never exceeds the cap.
    const installed = harness.auditSwaps.at(-1) ?? [];
    expect(installed.length).toBeLessThanOrEqual(cap);
    expect(installed.length).toBe(cap);
    expect(harness.logs).toContainEqual(expect.stringContaining(`audit IP cap reached cap=${cap}`));

    const clearedSnapshotsBefore = harness.clearedSnapshots.length;
    const clearedSpoolsBefore = harness.clearedSpools.length;
    const teardownsBefore = harness.teardowns.length;
    harness.setMarker(INACTIVE_MARKER);
    // No throw, and the teardown actually runs.
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });

    // The atomic teardown batch ran (it flushes audit_ipv4, resuming enforce
    // mode). Draining holds exactly the installed IPs that are not also
    // enforce-allowlisted, bounded by the cap.
    expect(harness.teardowns.length).toBe(teardownsBefore + 1);
    const draining = harness.teardowns.at(-1) ?? [];
    expect(draining.length).toBeLessThanOrEqual(cap);
    const expectedDraining = installed.filter((ip) => ip !== "140.82.112.5");
    expect([...draining].sort()).toEqual([...expectedDraining].sort());
    // The snapshot file and spool are cleared and tracking is reset.
    expect(harness.clearedSnapshots.length).toBe(clearedSnapshotsBefore + 1);
    expect(harness.clearedSpools.length).toBe(clearedSpoolsBefore + 1);

    // The fast-tick retry does not recur: a single teardown completed and
    // subsequent inactive ticks are no-ops.
    const teardownsAfter = harness.teardowns.length;
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    expect(harness.teardowns.length).toBe(teardownsAfter);
  });

  test("the per-host/total IP cap drops excess answers and logs while keeping the universe at the cap", async () => {
    const cap = 4;
    const harness = createAuditHarness({
      records: {
        // Two hosts, four answers each: only the first four distinct IPs fit.
        "a.example": ["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"],
        "b.example": ["2.2.2.1", "2.2.2.2", "2.2.2.3", "2.2.2.4"],
      },
      nftables: { auditMaxElements: cap },
      auditPlan: { resolveBudgetPerTick: 8 },
    });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool("a.example");
    harness.appendSpool("b.example");

    await harness.controller.refreshPolicyAndIps({ refreshDns: false });

    const installed = harness.auditSwaps.at(-1) ?? [];
    expect(installed.length).toBe(cap);
    // a.example fully fits (fills the cap); b.example's answers are all dropped.
    expect([...installed].sort()).toEqual(["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"]);
    expect(harness.logs).toContainEqual(expect.stringContaining(`audit IP cap reached cap=${cap}`));
    expect(harness.logs).toContainEqual(expect.stringContaining("audit host answers exceed IP cap host=b.example"));
  });

  test("audit teardown remains infallible when the nft apply errors and still resumes enforce mode", async () => {
    let now = 1_000;
    let marker: AuditMarkerState = ACTIVE_MARKER;
    let spool = "observed.example\n";
    const auditSwaps: string[][] = [];
    const clearedSnapshots: string[] = [];
    const clearedSpools: string[] = [];
    const logs: string[] = [];
    const controller = createTestFirewallController({
      nowMs: () => now,
      log: (line) => logs.push(line),
      resolve4: async (host) => host === "observed.example" ? ["9.9.9.9"] : ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
      readAuditMarkerState: () => marker,
      readAuditSpool: () => spool,
      replaceAuditSet: async (ips) => {
        auditSwaps.push([...ips]);
      },
      replaceAuditDrainingSet: async () => {},
      // The teardown batch fails, simulating an unexpected nft error after the
      // size bound. Teardown must still empty audit_ipv4, clear state, and not
      // wedge the loop.
      applyAuditTeardown: async () => {
        throw new Error("nft teardown boom");
      },
      publishAuditResolvedHosts: () => {},
      clearAuditResolvedHosts: (path) => {
        clearedSnapshots.push(path);
      },
      clearAuditSpool: (path) => {
        clearedSpools.push(path);
        spool = "";
      },
    });

    await controller.initialize(plan);
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(auditSwaps.at(-1)).toEqual(["9.9.9.9"]);

    marker = INACTIVE_MARKER;
    const swapsBefore = auditSwaps.length;
    // No throw escapes the refresh loop even though the teardown apply errors.
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(logs).toContainEqual(expect.stringContaining("audit teardown apply failed"));
    // Best-effort flush still empties audit_ipv4 so enforce mode resumes.
    expect(auditSwaps.length).toBe(swapsBefore + 1);
    expect(auditSwaps.at(-1)).toEqual([]);
    // State is cleared regardless of the apply error.
    expect(clearedSnapshots).toContain(plan.audit.resolvedHostsPath);
    expect(clearedSpools).toContain(plan.audit.spoolPath);

    // The next inactive tick is a no-op: tracking was reset, so the failing
    // teardown is not retried forever.
    now += 1_000;
    await controller.refreshPolicyAndIps({ refreshDns: false });
    expect(auditSwaps.length).toBe(swapsBefore + 1);
  });

  test("teardown draining set equals installed audit IPs minus the enforce allowlist", async () => {
    const harness = createAuditHarness({
      records: {
        // 140.82.112.5 overlaps the enforce allowlist (api.github.com).
        "observed.example": ["140.82.112.5", "9.9.9.9", "8.8.8.8"],
      },
    });
    await harness.controller.initialize(harness.testPlan);
    harness.setMarker(ACTIVE_MARKER);
    harness.appendSpool("observed.example");
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });

    harness.setMarker(INACTIVE_MARKER);
    await harness.controller.refreshPolicyAndIps({ refreshDns: false });
    // The allowlisted IP is excluded from draining; the audit-only IPs remain.
    expect(harness.teardowns.at(-1)?.sort()).toEqual(["8.8.8.8", "9.9.9.9"]);
  });
});

// `RUNFREE_SESSION_ADMISSION_SOURCE=files`: the supervisor derives session_ipv4
// from the root-owned per-session files instead of the published generation
// transaction. The scan and both clocks are injected so these tests drive a
// tmpdir root owned by the test user; the eligibility filter, the duplicate
// address rule, and the parse rules are the scanner's, exercised here through
// the real `scanSessionFiles`.
describe("proxy firewall session file admission", () => {
  const OWNER_UID = process.getuid?.() ?? 0;
  const T0 = Date.parse("2026-09-07T07:00:00.000Z");
  const MINUTE = 60_000;
  const SESSION_IP_A = "172.30.0.31";
  const SESSION_IP_B = "172.30.0.32";
  const roots: string[] = [];

  afterEach(() => {
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });

  function makeRoot(): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-firewall-session-files-"));
    roots.push(root);
    fs.chmodSync(root, 0o755);
    fs.mkdirSync(path.join(root, "sessions"), { mode: 0o755 });
    fs.writeFileSync(
      path.join(root, "eligibility.json"),
      serializeSessionAdmissionEligibility(sessionEligibility()),
      { mode: 0o644 },
    );
    return root;
  }

  function sessionFile(
    sourceIp: string,
    suffix: string,
    overrides: Partial<SessionFileV1> & { inspectedAtMs?: number; aliveForMs?: number } = {},
  ): SessionFileV1 {
    const { inspectedAtMs, aliveForMs, ...rest } = overrides;
    const inspectedAt = inspectedAtMs ?? T0;
    return {
      v: 1,
      projectId: PROJECT_ID,
      sessionKey: suffix.repeat(64),
      sessionId: `rf-20260907-${suffix.repeat(6)}`,
      sessionIncarnation: suffix.repeat(64),
      sourceIp,
      containerId: suffix.repeat(64),
      networkId: SESSION_NETWORK_ID,
      selectedAgentImageId: SELECTED_AGENT_IMAGE_ID,
      sessionAgentGenerationDigest: SESSION_AGENT_GENERATION,
      controlPlaneGenerationDigest: SESSION_CONTROL_GENERATION,
      admissionContractEpoch: 1,
      name: `session ${suffix}`,
      command: "codex",
      startedAt: "2026-09-07T06:59:00.000Z",
      nonce: suffix.repeat(32),
      inspectedAt: new Date(inspectedAt).toISOString(),
      aliveUntil: new Date(inspectedAt + (aliveForMs ?? MINUTE)).toISOString(),
      ...rest,
    };
  }

  function writeSessionFile(root: string, file: SessionFileV1): void {
    fs.writeFileSync(
      path.join(root, "sessions", `${file.sessionKey}.json`),
      serializeSessionFileV1(file),
      { mode: 0o644 },
    );
  }

  type FilesHarness = {
    root: string;
    controller: ReturnType<typeof createFirewallController>;
    clocks: { now: number; monotonic: number };
    replacements: string[][];
    verified: string[][];
  };

  async function filesHarness(overrides: Parameters<typeof createFirewallController>[0] = {}): Promise<FilesHarness> {
    const root = makeRoot();
    const clocks = { now: T0, monotonic: 10_000 };
    const replacements: string[][] = [];
    const verified: string[][] = [];
    const controller = createTestFirewallController({
      scanSessionFiles: (assignments) => scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID, assignments }),
      nowMs: () => clocks.now,
      monotonicNowMs: () => clocks.monotonic,
      replaceSessionAdmissionSet: async (ips) => {
        replacements.push([...ips]);
      },
      verifySessionAdmissionSet: async (ips) => {
        verified.push([...ips]);
      },
      resolve4: async () => ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
      log: () => {},
      ...overrides,
    });
    await controller.initialize(plan);
    // initialize() proves session_ipv4 empty before readiness; the per-file
    // reconciliation assertions start from there.
    verified.length = 0;
    return { root, controller, clocks, replacements, verified };
  }

  test("installs exactly the served source addresses of the scan", async () => {
    const harness = await filesHarness();
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    writeSessionFile(harness.root, sessionFile(SESSION_IP_B, "2"));

    await harness.controller.reconcileSessionAdmission();

    expect(harness.replacements).toEqual([[SESSION_IP_A, SESSION_IP_B]]);
    expect(harness.verified).toEqual([[SESSION_IP_A, SESSION_IP_B]]);

    // A steady served set costs no further nftables work.
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toHaveLength(1);
    expect(harness.verified).toHaveLength(1);
  });

  test("acknowledges an IP fence only after kernel verification, then admits only its new owner", async () => {
    const assignments = new Map<string, SessionIpAssignment>();
    const events: string[] = [];
    let failVerification = false;
    const harness = await filesHarness({
      readIpAssignments: () => assignments,
      verifySessionAdmissionSet: async (ips) => {
        if (failVerification) throw new Error("kernel verification failed");
        events.push(`verified:${ips.join(",")}`);
      },
      acknowledgeIpAssignment: (assignment) => events.push(`ack:${assignment.nonce}`),
    });
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    writeSessionFile(harness.root, sessionFile(SESSION_IP_B, "2"));
    await harness.controller.reconcileSessionAdmission();
    const assignment: SessionIpAssignment = {
      v: 1, sourceIp: SESSION_IP_A, sessionKey: "3".repeat(64), nonce: "a".repeat(32), state: "draining",
    };
    assignments.set(SESSION_IP_A, assignment);
    events.length = 0;
    failVerification = true;
    await expect(harness.controller.reconcileSessionAdmission()).rejects.toThrow();
    expect(events).toEqual([]);
    failVerification = false;
    await harness.controller.reconcileSessionAdmission();
    expect(events).toEqual([`verified:${SESSION_IP_B}`, `ack:${assignment.nonce}`]);
    assignments.set(SESSION_IP_A, { ...assignment, state: "ready" });
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "3"));
    // The delayed old owner's file still exists. It cannot revive authority
    // or make the new owner ambiguous after the fence completes.
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements.at(-1)).toEqual([SESSION_IP_A, SESSION_IP_B]);
  });

  test("never installs a file that fails eligibility", async () => {
    const harness = await filesHarness();
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    writeSessionFile(harness.root, sessionFile(SESSION_IP_B, "2", {
      controlPlaneGenerationDigest: `sha256:${"9".repeat(64)}`,
    }));

    await harness.controller.reconcileSessionAdmission();

    expect(harness.replacements).toEqual([[SESSION_IP_A]]);
    expect(harness.verified).toEqual([[SESSION_IP_A]]);
  });

  test("an unreadable eligibility clears the session set and verifies it empty", async () => {
    const harness = await filesHarness();
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toEqual([[SESSION_IP_A]]);

    fs.writeFileSync(path.join(harness.root, "eligibility.json"), "{not json");
    await harness.controller.reconcileSessionAdmission();

    expect(harness.replacements).toEqual([[SESSION_IP_A], []]);
    expect(harness.verified).toEqual([[SESSION_IP_A], []]);

    // Still unreadable: the proven-empty set is not re-flushed every loop.
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toHaveLength(2);

    // The reclamation half: a fail-closed flush is not a wedge. The moment the
    // eligibility file parses again, the same unchanged session file is
    // re-admitted by the next loop with no restart and no republication.
    fs.writeFileSync(
      path.join(harness.root, "eligibility.json"),
      serializeSessionAdmissionEligibility(sessionEligibility()),
    );
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toEqual([[SESSION_IP_A], [], [SESSION_IP_A]]);
    expect(harness.verified).toEqual([[SESSION_IP_A], [], [SESSION_IP_A]]);
  });

  test("a scan that throws is fail-closed identically to an unreadable scan", async () => {
    const root = makeRoot();
    writeSessionFile(root, sessionFile(SESSION_IP_A, "1"));
    const clocks = { now: T0, monotonic: 10_000 };
    const replacements: string[][] = [];
    const verified: string[][] = [];
    let throwOnScan = false;
    const controller = createTestFirewallController({
      scanSessionFiles: () => {
        if (throwOnScan) throw new Error("boom");
        return scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID });
      },
      nowMs: () => clocks.now,
      monotonicNowMs: () => clocks.monotonic,
      replaceSessionAdmissionSet: async (ips) => {
        replacements.push([...ips]);
      },
      verifySessionAdmissionSet: async (ips) => {
        verified.push([...ips]);
      },
      resolve4: async () => ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
      log: () => {},
    });
    await controller.initialize(plan);
    verified.length = 0;

    await controller.reconcileSessionAdmission();
    expect(replacements).toEqual([[SESSION_IP_A]]);

    throwOnScan = true;
    await controller.reconcileSessionAdmission();

    expect(replacements).toEqual([[SESSION_IP_A], []]);
    expect(verified).toEqual([[SESSION_IP_A], []]);

    // Still unreadable: the proven-empty set is not re-flushed every loop.
    await controller.reconcileSessionAdmission();
    expect(replacements).toHaveLength(2);

    // The reclamation half: the flush is not terminal. A scan that answers
    // again re-admits the same unchanged file on the very next loop.
    throwOnScan = false;
    await controller.reconcileSessionAdmission();
    expect(replacements).toEqual([[SESSION_IP_A], [], [SESSION_IP_A]]);
    expect(verified).toEqual([[SESSION_IP_A], [], [SESSION_IP_A]]);
  });

  test("an eligibility naming another project admits nothing", async () => {
    const harness = await filesHarness();
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    fs.writeFileSync(
      path.join(harness.root, "eligibility.json"),
      serializeSessionAdmissionEligibility(createSessionAdmissionEligibility({
        projectId: "ba9876543210",
        controlPlaneGenerationDigest: SESSION_CONTROL_GENERATION,
        admissionContractEpoch: 1,
        agentInternalNetworkId: SESSION_NETWORK_ID,
        allowedSessionAgents: [{
          sessionAgentGenerationDigest: SESSION_AGENT_GENERATION,
          selectedAgentImageId: SELECTED_AGENT_IMAGE_ID,
        }],
      })),
    );

    await harness.controller.reconcileSessionAdmission();

    expect(harness.replacements).toEqual([]);
    expect(harness.verified).toEqual([]);
  });

  test("drops an address once its file's wall deadline passes", async () => {
    const harness = await filesHarness();
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toEqual([[SESSION_IP_A]]);

    harness.clocks.now = T0 + MINUTE + 1;
    harness.clocks.monotonic += MINUTE + 1;
    await harness.controller.reconcileSessionAdmission();

    expect(harness.replacements).toEqual([[SESSION_IP_A], []]);
    expect(harness.verified).toEqual([[SESSION_IP_A], []]);
  });

  test("a replayed nonce cannot extend admission past the firewall's own observation", async () => {
    const harness = await filesHarness();
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1"));
    await harness.controller.reconcileSessionAdmission();

    // Only the firewall's own monotonic clock advances: the wall deadline in
    // the file is still in the future, but this consumer's first observation
    // of that nonce has run out.
    harness.clocks.monotonic += MINUTE + 1;
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toEqual([[SESSION_IP_A], []]);

    // Rewriting the same bytes with a later deadline is a replay, not a
    // heartbeat: the observation keyed on that nonce is unchanged.
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1", { aliveForMs: 5 * MINUTE }));
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toEqual([[SESSION_IP_A], []]);

    // A fresh nonce (a real heartbeat rewrite) is admitted again.
    writeSessionFile(harness.root, sessionFile(SESSION_IP_A, "1", { nonce: "b".repeat(32) }));
    await harness.controller.reconcileSessionAdmission();
    expect(harness.replacements).toEqual([[SESSION_IP_A], [], [SESSION_IP_A]]);
  });

  test("aggregates original and cleanup nftables failures without touching the ruleset again", async () => {
    const root = makeRoot();
    writeSessionFile(root, sessionFile(SESSION_IP_A, "1"));
    let initialized = false;
    const controller = createTestFirewallController({
      nowMs: () => T0,
      monotonicNowMs: () => 10_000,
      scanSessionFiles: (assignments) => scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID, assignments }),
      replaceSessionAdmissionSet: async () => {
        if (initialized) throw new Error("replacement unavailable");
      },
      verifySessionAdmissionSet: async (ips) => {
        if (initialized && ips.length === 0) throw new Error("empty proof unavailable");
      },
      resolve4: async () => ["140.82.112.5"],
      loadPolicy: () => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath),
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
      log: () => {},
    });
    await controller.initialize(plan);
    initialized = true;

    const error = await controller.reconcileSessionAdmission().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AggregateError);
    expect((error as AggregateError).errors.map((entry) => (entry as Error).message)).toEqual([
      "replacement unavailable",
      "replacement unavailable",
      "empty proof unavailable",
    ]);
  });

  test("reconciliation is local-only and returns after stop", async () => {
    const root = makeRoot();
    writeSessionFile(root, sessionFile(SESSION_IP_A, "1"));
    const loadPolicy = vi.fn(() => validateProxyPolicy({ hosts: ["api.github.com"], tokens: {} }, plan.policyPath));
    const resolve4 = vi.fn(async () => ["140.82.112.5"]);
    const readAuditMarkerState = vi.fn(() => ({ active: false } as const));
    const scan = vi.fn(() => scanSessionFiles({ root, ownerUid: OWNER_UID, projectId: PROJECT_ID }));
    const controller = createTestFirewallController({
      nowMs: () => T0,
      monotonicNowMs: () => 10_000,
      scanSessionFiles: scan,
      loadPolicy,
      resolve4,
      readAuditMarkerState,
      ensureDefaultRoute: async () => {},
      applyRuleset: async () => {},
      replaceAllowedSet: async () => {},
      publishResolvedHosts,
      verify: async () => {},
    });

    await expect(controller.reconcileSessionAdmission()).rejects.toThrow("not been initialized");
    await controller.initialize(plan);
    loadPolicy.mockClear();
    resolve4.mockClear();
    readAuditMarkerState.mockClear();
    await controller.reconcileSessionAdmission();
    expect(loadPolicy).not.toHaveBeenCalled();
    expect(resolve4).not.toHaveBeenCalled();
    expect(readAuditMarkerState).not.toHaveBeenCalled();

    await controller.stop();
    scan.mockClear();
    await controller.reconcileSessionAdmission();
    expect(scan).not.toHaveBeenCalled();
  });

  test("repeated empty scans retain the startup empty proof without touching nftables", async () => {
    const harness = await filesHarness();
    harness.replacements.length = 0;

    await harness.controller.reconcileSessionAdmission();
    await harness.controller.reconcileSessionAdmission();

    expect(harness.replacements).toEqual([]);
    expect(harness.verified).toEqual([]);
  });
});
