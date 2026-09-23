import { describe, expect, test } from "vitest";

import {
  applyRuleset,
  replaceAllowedSet,
  replaceAuditDrainingSet,
  replaceAuditSet,
  replaceSessionAdmissionSet,
  renderAllowedSetUpdate,
  renderAuditDrainingSetUpdate,
  renderAuditSetUpdate,
  renderAuditTeardown,
  renderRuleset,
  renderSessionAdmissionSetUpdate,
  validateFirewallPlan,
  verifySessionAdmissionSet,
  type FirewallPlan,
} from "./nftables.ts";

const POLICY_GENERATION = `sha256:${"a".repeat(64)}`;

const basePlan: FirewallPlan = {
  policyPath: "/app/proxy/policy/network-policy.json",
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
    maxStaleHostSeconds: 900,
  },
  audit: {
    markerPath: "/run/runfree-proxy-audit/active.json",
    spoolPath: "/run/runfree-proxy-audit-spool/spool.txt",
    resolvedHostsPath: "/run/runfree-proxy-audit/resolved-hosts.json",
    resolveBudgetPerTick: 8,
    drainSeconds: 30,
  },
};

describe("proxy firewall nftables renderer", () => {
  test("renders the exact inet ruleset used by the proxy firewall", () => {
    expect(renderRuleset(basePlan)).toBe([
      "table inet runfree_proxy {",
      "  set allowed_ipv4 {",
      "    type ipv4_addr",
      "    size 65536",
      "  }",
      "  set session_ipv4 {",
      "    type ipv4_addr",
      "    size 256",
      "  }",
      "  set audit_ipv4 {",
      "    type ipv4_addr",
      "    size 256",
      "  }",
      "  set audit_draining_ipv4 {",
      "    type ipv4_addr",
      "    size 256",
      "  }",
      "  chain input {",
      "    type filter hook input priority filter; policy drop;",
      "    iifname \"lo\" accept",
      "    iifname \"eth1\" meta nfproto ipv4 ct state established,related accept",
      "    iifname \"eth0\" ip saddr @session_ipv4 ct state established,related accept",
      "    iifname \"eth0\" ip saddr @session_ipv4 tcp dport 8080 ct state new accept",
      "  }",
      "  chain output_dns_guard {",
      "    type filter hook output priority raw; policy accept;",
      "    meta skuid 1001 udp dport 53 reject",
      "    meta skuid 1001 tcp dport 53 reject",
      "  }",
      "  chain output {",
      "    type filter hook output priority filter; policy drop;",
      "    oifname \"lo\" accept",
      "    oifname \"eth0\" ip daddr @session_ipv4 ct state established,related accept",
      "    oifname \"eth1\" ip daddr @audit_draining_ipv4 drop",
      "    oifname \"eth1\" meta nfproto ipv4 ct state established,related accept",
      "    oifname \"eth1\" ip daddr @allowed_ipv4 tcp dport 443 accept",
      "    oifname \"eth1\" ip daddr @audit_ipv4 tcp dport 443 accept",
      "  }",
      "  chain forward {",
      "    type filter hook forward priority filter; policy drop;",
      "  }",
      "}",
      "",
    ].join("\n"));
    expect(renderRuleset(basePlan)).not.toContain("dport 53 accept");
    expect(renderRuleset(basePlan)).not.toContain("ip6");
  });

  // There is no fixed Compose agent: the only path to the proxy is the
  // admitted session set. A fixed-agent accept rule cannot be expressed at all
  // — pinning a now-unowned 172.30.0.11 would let any container Docker
  // assigned that address reach the proxy without passing source-IP admission.
  test("the admitted session set is the sole agent->proxy path", () => {
    const ruleset = renderRuleset(basePlan);
    expect(ruleset).not.toContain("172.30.0.11");
    expect(ruleset).toContain("iifname \"eth0\" ip saddr @session_ipv4 ct state established,related accept");
    expect(ruleset).toContain("iifname \"eth0\" ip saddr @session_ipv4 tcp dport 8080 ct state new accept");
    expect(ruleset).toContain("oifname \"eth0\" ip daddr @session_ipv4 ct state established,related accept");
    const lines = ruleset.split("\n");
    const firstInternalInputAccept = lines.find((line) =>
      line.includes("iifname \"eth0\" ip saddr"));
    expect(firstInternalInputAccept).toContain("@session_ipv4");
  });

  test("always-present audit sets are empty and the drain-drop sits above the egress established-accept", () => {
    const ruleset = renderRuleset(basePlan);
    // Sets are declared with no elements: enforce mode boots with empty audit
    // state and only set *contents* ever change at runtime.
    expect(ruleset).not.toContain("elements");
    const lines = ruleset.split("\n");
    const drainDropIndex = lines.findIndex((line) => line.includes("@audit_draining_ipv4 drop"));
    const egressEstablishedIndex = lines.findIndex((line) =>
      line.includes("oifname \"eth1\" meta nfproto ipv4 ct state established,related accept"));
    const auditAcceptIndex = lines.findIndex((line) => line.includes("@audit_ipv4 tcp dport 443 accept"));
    expect(drainDropIndex).toBeGreaterThan(0);
    expect(egressEstablishedIndex).toBeGreaterThan(0);
    expect(auditAcceptIndex).toBeGreaterThan(0);
    // First terminal verdict wins: the drop must precede the established
    // accept so teardown severs established audited flows.
    expect(drainDropIndex).toBeLessThan(egressEstablishedIndex);
    expect(auditAcceptIndex).toBeGreaterThan(egressEstablishedIndex);
  });

  test("renders deterministic set updates and enforces the configured set size", () => {
    expect(renderAllowedSetUpdate(["140.82.112.5", "8.8.8.8", "140.82.112.5"], basePlan)).toBe([
      "flush set inet runfree_proxy allowed_ipv4",
      "add element inet runfree_proxy allowed_ipv4 { 140.82.112.5, 8.8.8.8 }",
      "",
    ].join("\n"));
    expect(renderSessionAdmissionSetUpdate(["172.31.90.21", "172.31.90.20", "172.31.90.21"], basePlan)).toBe([
      "flush set inet runfree_proxy session_ipv4",
      "add element inet runfree_proxy session_ipv4 { 172.31.90.20, 172.31.90.21 }",
      "",
    ].join("\n"));
    expect(renderAllowedSetUpdate([], basePlan)).toBe([
      "flush set inet runfree_proxy allowed_ipv4",
      "",
    ].join("\n"));
    expect(() => renderAllowedSetUpdate(["bad"], basePlan)).toThrow(/invalid allowed IPv4/);
    expect(() => renderAllowedSetUpdate(["1.1.1.1", "8.8.8.8"], {
      ...basePlan,
      nftables: { ...basePlan.nftables, maxElements: 1 },
    })).toThrow(/max is 1/);
  });

  test("renders audit set updates against the audit set with the distinct small cap", () => {
    expect(renderAuditSetUpdate(["8.8.8.8", "1.1.1.1", "8.8.8.8"], basePlan)).toBe([
      "flush set inet runfree_proxy audit_ipv4",
      "add element inet runfree_proxy audit_ipv4 { 1.1.1.1, 8.8.8.8 }",
      "",
    ].join("\n"));
    expect(renderAuditSetUpdate([], basePlan)).toBe([
      "flush set inet runfree_proxy audit_ipv4",
      "",
    ].join("\n"));
    expect(() => renderAuditSetUpdate(["bad"], basePlan)).toThrow(/invalid audit IPv4/);
    expect(() => renderAuditSetUpdate(["1.1.1.1", "8.8.8.8"], {
      ...basePlan,
      nftables: { ...basePlan.nftables, auditMaxElements: 1 },
    })).toThrow(/max is 1/);
  });

  test("renders draining set updates and the atomic teardown batch", () => {
    expect(renderAuditDrainingSetUpdate(["9.9.9.9"], basePlan)).toBe([
      "flush set inet runfree_proxy audit_draining_ipv4",
      "add element inet runfree_proxy audit_draining_ipv4 { 9.9.9.9 }",
      "",
    ].join("\n"));
    expect(renderAuditDrainingSetUpdate([], basePlan)).toBe([
      "flush set inet runfree_proxy audit_draining_ipv4",
      "",
    ].join("\n"));
    // One atomic batch: populate draining (severance via the always-present
    // drop rule), then flush the audit accept set. No rules are added or
    // removed.
    expect(renderAuditTeardown(["9.9.9.9", "8.8.8.8"], basePlan)).toBe([
      "flush set inet runfree_proxy audit_draining_ipv4",
      "add element inet runfree_proxy audit_draining_ipv4 { 8.8.8.8, 9.9.9.9 }",
      "flush set inet runfree_proxy audit_ipv4",
      "",
    ].join("\n"));
    expect(renderAuditTeardown([], basePlan)).toBe([
      "flush set inet runfree_proxy audit_draining_ipv4",
      "flush set inet runfree_proxy audit_ipv4",
      "",
    ].join("\n"));
    expect(renderAuditTeardown(["9.9.9.9"], basePlan)).not.toContain("add rule");
    expect(renderAuditTeardown(["9.9.9.9"], basePlan)).not.toContain("delete rule");
  });

  test("replaces only the owned nftables table when applying the ruleset", async () => {
    const calls: Array<{ args: readonly string[]; input?: string }> = [];
    await applyRuleset(basePlan, {
      run: async (_command, args, options) => {
        calls.push({ args, input: options?.input });
        return { stdout: "", stderr: "" };
      },
    });

    expect(calls.map((call) => call.args)).toEqual([
      ["list", "table", "inet", "runfree_proxy"],
      ["-f", "-"],
      ["-f", "-"],
    ]);
    expect(calls[1].input).toBe("flush table inet runfree_proxy\ndelete table inet runfree_proxy\n");
    expect(calls[2].input).toBe(renderRuleset(basePlan));
    expect(calls[2].input).not.toContain("flush ruleset");
  });

  test("verifies the exact kernel session admission set", async () => {
    const runner = {
      run: async () => ({
        stdout: JSON.stringify({
          nftables: [{
            set: {
              family: "inet",
              table: "runfree_proxy",
              name: "session_ipv4",
              elem: ["172.31.90.21", "172.31.90.20"],
            },
          }],
        }),
        stderr: "",
      }),
    };
    await expect(verifySessionAdmissionSet(["172.31.90.20", "172.31.90.21"], basePlan, runner))
      .resolves.toBeUndefined();
    await expect(verifySessionAdmissionSet(["172.31.90.20"], basePlan, runner))
      .rejects.toThrow("session admission set mismatch");
  });

  test("keeps concurrent runtime transactions scoped to their owned sets", async () => {
    const inputs: string[] = [];
    const runner = {
      run: async (_command: string, _args: readonly string[], options?: { input?: string }) => {
        inputs.push(options?.input ?? "");
        await Promise.resolve();
        return { stdout: "", stderr: "" };
      },
    };

    await Promise.all([
      replaceSessionAdmissionSet(["172.31.90.20"], basePlan, runner),
      replaceAllowedSet(["8.8.8.8"], basePlan, runner),
      replaceAuditSet(["9.9.9.9"], basePlan, runner),
      replaceAuditDrainingSet(["1.1.1.1"], basePlan, runner),
    ]);

    expect(inputs).toHaveLength(4);
    expect(inputs.filter((input) => input.includes("session_ipv4"))).toHaveLength(1);
    expect(inputs.filter((input) => input.includes("allowed_ipv4"))).toHaveLength(1);
    expect(inputs.filter((input) => input.includes("audit_ipv4"))).toHaveLength(1);
    expect(inputs.filter((input) => input.includes("audit_draining_ipv4"))).toHaveLength(1);
    for (const input of inputs) {
      expect(input).not.toContain("flush table");
      expect(input).not.toContain("delete table");
      expect(input.match(/flush set/g)).toHaveLength(1);
    }
  });

  test("rejects unsafe plan values before command execution", () => {
    expect(() => validateFirewallPlan({
      ...basePlan,
      internal: { ...basePlan.internal, iface: "eth0; nft flush ruleset" },
    })).toThrow(/invalid internal interface/);

    expect(() => validateFirewallPlan({
      ...basePlan,
      egress: { ...basePlan.egress, sourceIp: "999.1.1.1" },
    })).toThrow(/invalid egress source IP/);

    expect(() => validateFirewallPlan({
      ...basePlan,
      nftables: { ...basePlan.nftables, tableName: "bad-name" },
    } as unknown as FirewallPlan)).toThrow(/invalid nftables table name/);
  });
});
