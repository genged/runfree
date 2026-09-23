import { describe, expect, test } from "vitest";

import { buildFirewallPlan } from "./env.ts";

const POLICY_GENERATION = `sha256:${"a".repeat(64)}`;

describe("proxy firewall environment parsing", () => {
  test("builds a plan from normalized policy hosts and runtime addresses", () => {
    const plan = buildFirewallPlan({
      env: {
        RUNFREE_SESSION_ADMISSION_SOURCE: "files",
        PROXY_POLICY_PATH: "/app/proxy/policy/network-policy.json",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
        RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
        RUNFREE_INTERNAL_IFACE: "eth0",
        RUNFREE_EGRESS_IFACE: "eth1",
        RUNFREE_SUBNET: "172.30.0.0/24",
        RUNFREE_PROXY_EGRESS_SUBNET: "172.30.1.0/24",
        PROXY_PORT: "8080",
        PROXY_FIREWALL_POLICY_SECONDS: "2",
        PROXY_FIREWALL_DNS_SECONDS: "300",
        PROXY_FIREWALL_MAX_STALE_SECONDS: "900",
      },
      allowedHosts: ["api.github.com", "raw.githubusercontent.com"],
      policyGeneration: POLICY_GENERATION,
    });

    expect(plan.policyGeneration).toBe(POLICY_GENERATION);
    expect(plan.allowedHosts).toEqual(["api.github.com", "raw.githubusercontent.com"]);
    expect(plan.internal).toEqual({
      iface: "eth0",
      proxyIp: "172.30.0.10",
      proxyPort: 8080,
    });
    expect(plan.egress).toEqual({
      iface: "eth1",
      sourceIp: "172.30.1.10",
      gatewayIp: "172.30.1.1",
    });
    expect(plan.runtimeSubnets).toEqual(["172.30.0.0/24", "172.30.1.0/24"]);
    expect(plan.nftables).toMatchObject({
      sessionSetName: "session_ipv4",
      sessionMaxElements: 256,
      auditSetName: "audit_ipv4",
      auditDrainingSetName: "audit_draining_ipv4",
      auditMaxElements: 256,
    });
    expect(plan.audit).toEqual({
      markerPath: "/run/runfree-proxy-audit/active.json",
      spoolPath: "/run/runfree-proxy-audit-spool/spool.txt",
      resolvedHostsPath: "/run/runfree-proxy-audit/resolved-hosts.json",
      resolveBudgetPerTick: 8,
      drainSeconds: 30,
    });
  });

  // The fixed-agent accept rule no longer exists, so the retired agent-IP env
  // vars must be ignored entirely: a stale RUNFREE_AGENT_IP or
  // RUNFREE_CONTAINER_IP in the environment cannot reintroduce a standing
  // accept for an address no container owns.
  test("ignores the retired agent-IP environment variables", () => {
    const plan = buildFirewallPlan({
      env: {
        RUNFREE_SESSION_ADMISSION_SOURCE: "files",
        PROXY_POLICY_PATH: "/policy.json",
        RUNFREE_CONTAINER_IP: "172.30.0.11",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
        RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
        RUNFREE_INTERNAL_IFACE: "eth0",
        RUNFREE_EGRESS_IFACE: "eth1",
        PROXY_PORT: "8080",
      },
      allowedHosts: ["api.github.com"],
      policyGeneration: POLICY_GENERATION,
    });
    expect(plan.internal).toEqual({ iface: "eth0", proxyIp: "172.30.0.10", proxyPort: 8080 });
  });

  test("audit knobs are tunable through proxy-only environment", () => {
    const plan = buildFirewallPlan({
      env: {
        RUNFREE_SESSION_ADMISSION_SOURCE: "files",
        PROXY_POLICY_PATH: "/policy.json",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
        RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
        PROXY_AUDIT_MARKER_PATH: "/tmp/audit/active.json",
        PROXY_AUDIT_SPOOL_PATH: "/tmp/audit-spool/spool.txt",
        PROXY_AUDIT_RESOLVED_HOSTS_PATH: "/tmp/audit/resolved-hosts.json",
        PROXY_FIREWALL_AUDIT_SET_MAX_ELEMENTS: "16",
        PROXY_FIREWALL_AUDIT_RESOLVE_BUDGET: "2",
        PROXY_FIREWALL_AUDIT_DRAIN_SECONDS: "5",
      },
      allowedHosts: ["api.github.com"],
      policyGeneration: POLICY_GENERATION,
    });

    expect(plan.nftables.auditMaxElements).toBe(16);
    expect(plan.audit).toEqual({
      markerPath: "/tmp/audit/active.json",
      spoolPath: "/tmp/audit-spool/spool.txt",
      resolvedHostsPath: "/tmp/audit/resolved-hosts.json",
      resolveBudgetPerTick: 2,
      drainSeconds: 5,
    });
  });

  test("rejects invalid addresses and ports", () => {
    expect(() => buildFirewallPlan({
      env: {
        RUNFREE_SESSION_ADMISSION_SOURCE: "files",
        PROXY_POLICY_PATH: "/policy.json",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_EGRESS_IP: "bad",
        RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
        PROXY_PORT: "8080",
      },
      allowedHosts: ["api.github.com"],
      policyGeneration: POLICY_GENERATION,
    })).toThrow(/RUNFREE_PROXY_EGRESS_IP must be a valid IPv4 address/);

    expect(() => buildFirewallPlan({
      env: {
        RUNFREE_SESSION_ADMISSION_SOURCE: "files",
        PROXY_POLICY_PATH: "/policy.json",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
        RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
        PROXY_PORT: "0",
      },
      allowedHosts: ["api.github.com"],
      policyGeneration: POLICY_GENERATION,
    })).toThrow(/PROXY_PORT must be a valid TCP port/);
  });

  test("accepts the legacy ipset max-elements knob as a deprecated alias", () => {
    const plan = buildFirewallPlan({
      env: {
        RUNFREE_SESSION_ADMISSION_SOURCE: "files",
        PROXY_POLICY_PATH: "/policy.json",
        RUNFREE_PROXY_IP: "172.30.0.10",
        RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
        RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
        PROXY_FIREWALL_IPSET_MAX_ELEMENTS: "42",
      },
      allowedHosts: ["api.github.com"],
      policyGeneration: POLICY_GENERATION,
    });

    expect(plan.nftables.maxElements).toBe(42);
  });
});

describe("proxy firewall session admission source", () => {
  function planEnv(source?: string): NodeJS.ProcessEnv {
    return {
      ...(source === undefined ? {} : { RUNFREE_SESSION_ADMISSION_SOURCE: source }),
      PROXY_POLICY_PATH: "/policy.json",
      RUNFREE_PROXY_IP: "172.30.0.10",
      RUNFREE_PROXY_EGRESS_IP: "172.30.1.10",
      RUNFREE_PROXY_EGRESS_GATEWAY: "172.30.1.1",
      RUNFREE_INTERNAL_IFACE: "eth0",
      RUNFREE_EGRESS_IFACE: "eth1",
    };
  }

  test("builds a plan only for the one admission source this proxy speaks", () => {
    expect(() => buildFirewallPlan({
      env: planEnv("files"),
      allowedHosts: ["api.github.com"],
      policyGeneration: POLICY_GENERATION,
    })).not.toThrow();
  });

  test.each([undefined, "", "generations", "Files", "snapshot", "files "])(
    "refuses the source %o before any plan exists",
    (source) => {
      expect(() => buildFirewallPlan({
        env: planEnv(source),
        allowedHosts: ["api.github.com"],
        policyGeneration: POLICY_GENERATION,
      })).toThrow(/RUNFREE_SESSION_ADMISSION_SOURCE must be "files"/);
    },
  );
});
