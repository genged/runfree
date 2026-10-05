import { describe, expect, test } from "vitest";

import {
  applyHostServiceTeardown,
  applyRuleset,
  flushHostServiceDraining,
  readHostServiceSetElements,
  renderHostServiceSetUpdate,
  renderHostServiceTeardown,
  replaceAllowedSet,
  replaceHostServiceSet,
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
    hostServiceSetName: "host_service",
    hostServiceDrainingSetName: "host_service_draining",
    hostServiceGatewaySetName: "host_service_gateways",
    hostServiceGatewayMaxElements: 8,
    hostServiceMaxElements: 64,
  },
  hostServiceDrainSeconds: 30,
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
      "  set host_service {",
      "    type ipv4_addr . inet_service",
      "    size 64",
      "  }",
      "  set host_service_draining {",
      "    type ipv4_addr . inet_service",
      "    size 64",
      "  }",
      "  set host_service_gateways {",
      "    type ipv4_addr",
      "    size 8",
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
      "    oifname \"eth1\" ip daddr . tcp dport @host_service_draining drop",
      "    oifname \"eth1\" ip daddr @host_service_gateways ip daddr . tcp dport != @host_service drop",
      "    oifname \"eth1\" meta nfproto ipv4 ct state established,related accept",
      "    oifname \"eth1\" ip daddr @allowed_ipv4 tcp dport 443 accept",
      "    oifname \"eth1\" ip daddr @audit_ipv4 tcp dport 443 accept",
      "    oifname \"eth1\" meta skuid 1001 ip daddr . tcp dport @host_service accept",
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

  test("the host-service drain-drop precedes the established accept and the accept is uid 1001 on egress only", () => {
    const lines = renderRuleset(basePlan).split("\n");
    const drainDropIndex = lines.findIndex((line) => line.includes("@host_service_draining drop"));
    const egressEstablishedIndex = lines.findIndex((line) =>
      line.includes("oifname \"eth1\" meta nfproto ipv4 ct state established,related accept"));
    expect(drainDropIndex).toBeGreaterThan(0);
    expect(drainDropIndex).toBeLessThan(egressEstablishedIndex);
    const acceptLines = lines.filter((line) => line.endsWith("@host_service accept"));
    expect(acceptLines).toEqual(["    oifname \"eth1\" meta skuid 1001 ip daddr . tcp dport @host_service accept"]);
  });

  test("the permanent gateway cut (R19) precedes the established accept, applies to every uid, and matches only pairs outside @host_service", () => {
    const lines = renderRuleset(basePlan).split("\n");
    const gatewayDrop = "    oifname \"eth1\" ip daddr @host_service_gateways ip daddr . tcp dport != @host_service drop";
    const gatewayDropIndex = lines.indexOf(gatewayDrop);
    const egressEstablishedIndex = lines.findIndex((line) =>
      line.includes("oifname \"eth1\" meta nfproto ipv4 ct state established,related accept"));
    expect(gatewayDropIndex).toBeGreaterThan(0);
    expect(gatewayDropIndex).toBeLessThan(egressEstablishedIndex);
    expect(lines.filter((line) => line.includes("@host_service_gateways"))).toEqual([gatewayDrop]);
    // No uid match: root and uid 1001 flows to a pinned gateway are cut alike.
    expect(gatewayDrop).not.toContain("skuid");
  });

  test("renders the host-service set update as one flush-and-fill batch, gateways first", () => {
    expect(renderHostServiceSetUpdate([{ ip: "192.168.65.254", port: 10882 }], basePlan, ["192.168.65.254"])).toBe([
      "flush set inet runfree_proxy host_service_gateways",
      "add element inet runfree_proxy host_service_gateways { 192.168.65.254 }",
      "flush set inet runfree_proxy host_service",
      "add element inet runfree_proxy host_service { 192.168.65.254 . 10882 }",
      "",
    ].join("\n"));
    expect(renderHostServiceSetUpdate([
      { ip: "192.168.65.254", port: 10882 },
      { ip: "192.168.65.254", port: 5432 },
      { ip: "192.168.65.254", port: 10882 },
    ], basePlan, ["192.168.65.254"])).toBe([
      "flush set inet runfree_proxy host_service_gateways",
      "add element inet runfree_proxy host_service_gateways { 192.168.65.254 }",
      "flush set inet runfree_proxy host_service",
      "add element inet runfree_proxy host_service { 192.168.65.254 . 5432, 192.168.65.254 . 10882 }",
      "",
    ].join("\n"));
    expect(renderHostServiceSetUpdate([], basePlan, [])).toBe([
      "flush set inet runfree_proxy host_service_gateways",
      "flush set inet runfree_proxy host_service",
      "",
    ].join("\n"));
    // An emptied accept set keeps every gateway pinned this lifetime.
    expect(renderHostServiceSetUpdate([], basePlan, ["192.168.65.254"])).toContain(
      "add element inet runfree_proxy host_service_gateways { 192.168.65.254 }",
    );
  });

  test("refuses to accept a pair whose address is not a recorded gateway, and an invalid or oversized gateway list", () => {
    expect(() => renderHostServiceSetUpdate([{ ip: "192.168.65.254", port: 10882 }], basePlan, []))
      .toThrow(/not at a recorded gateway/);
    expect(() => renderHostServiceSetUpdate([{ ip: "192.168.65.254", port: 10882 }], basePlan, ["192.168.65.200"]))
      .toThrow(/not at a recorded gateway/);
    expect(() => renderHostServiceTeardown([], [{ ip: "192.168.65.254", port: 10882 }], basePlan, []))
      .toThrow(/not at a recorded gateway/);
    expect(() => renderHostServiceSetUpdate([], basePlan, ["192.168.65.254; flush ruleset"]))
      .toThrow(/invalid host-service gateway IPv4/);
    expect(() => renderHostServiceSetUpdate([], basePlan, Array.from({ length: 9 }, (_, index) => `192.168.65.${index + 1}`)))
      .toThrow(/gateway set update has 9 elements but max is 8/);
  });

  test("refuses invalid host-service elements and the cap before any command", () => {
    expect(() => renderHostServiceSetUpdate([{ ip: "192.168.65.254; flush ruleset", port: 1 }], basePlan, []))
      .toThrow(/invalid host-service IPv4/);
    expect(() => renderHostServiceSetUpdate([{ ip: "192.168.65.254", port: 0 }], basePlan, ["192.168.65.254"]))
      .toThrow(/invalid host-service port/);
    expect(() => renderHostServiceSetUpdate([{ ip: "192.168.65.254", port: 65536 }], basePlan, ["192.168.65.254"]))
      .toThrow(/invalid host-service port/);
    expect(() => renderHostServiceSetUpdate([
      { ip: "192.168.65.254", port: 1 },
      { ip: "192.168.65.254", port: 2 },
    ], { ...basePlan, nftables: { ...basePlan.nftables, hostServiceMaxElements: 1 } }, ["192.168.65.254"])).toThrow(/max is 1/);
  });

  test("renders the host-service teardown as one batch: gateways, fill draining, then refill the accept set", () => {
    expect(renderHostServiceTeardown(
      [{ ip: "192.168.65.254", port: 10882 }],
      [{ ip: "192.168.65.254", port: 5432 }],
      basePlan,
      ["192.168.65.254"],
    )).toBe([
      "flush set inet runfree_proxy host_service_gateways",
      "add element inet runfree_proxy host_service_gateways { 192.168.65.254 }",
      "flush set inet runfree_proxy host_service_draining",
      "add element inet runfree_proxy host_service_draining { 192.168.65.254 . 10882 }",
      "flush set inet runfree_proxy host_service",
      "add element inet runfree_proxy host_service { 192.168.65.254 . 5432 }",
      "",
    ].join("\n"));
    expect(renderHostServiceTeardown([{ ip: "192.168.65.254", port: 10882 }], [], basePlan, ["192.168.65.254"])).toBe([
      "flush set inet runfree_proxy host_service_gateways",
      "add element inet runfree_proxy host_service_gateways { 192.168.65.254 }",
      "flush set inet runfree_proxy host_service_draining",
      "add element inet runfree_proxy host_service_draining { 192.168.65.254 . 10882 }",
      "flush set inet runfree_proxy host_service",
      "",
    ].join("\n"));
    expect(renderHostServiceTeardown([{ ip: "192.168.65.254", port: 10882 }], [], basePlan, ["192.168.65.254"])).not.toContain("rule");
  });

  test("host-service runners send one nft batch each and read back concat elements", async () => {
    const calls: Array<{ args: readonly string[]; input?: string }> = [];
    let stdout = "";
    const runner = {
      run: async (_command: string, args: readonly string[], options?: { input?: string }) => {
        calls.push({ args, input: options?.input });
        return { stdout, stderr: "" };
      },
    };
    await replaceHostServiceSet([{ ip: "192.168.65.254", port: 10882 }], runner, basePlan, ["192.168.65.254"]);
    await applyHostServiceTeardown([{ ip: "192.168.65.254", port: 10882 }], [], runner, basePlan, ["192.168.65.254"]);
    await flushHostServiceDraining(runner, basePlan);
    expect(calls.map((call) => call.args)).toEqual([["-f", "-"], ["-f", "-"], ["-f", "-"]]);
    expect(calls[0].input).toBe(renderHostServiceSetUpdate([{ ip: "192.168.65.254", port: 10882 }], basePlan, ["192.168.65.254"]));
    expect(calls[1].input).toBe(renderHostServiceTeardown([{ ip: "192.168.65.254", port: 10882 }], [], basePlan, ["192.168.65.254"]));
    expect(calls[2].input).toBe("flush set inet runfree_proxy host_service_draining\n");

    stdout = JSON.stringify({ nftables: [
      { metainfo: { version: "1.0.9" } },
      { set: {
        family: "inet",
        table: "runfree_proxy",
        name: "host_service",
        type: ["ipv4_addr", "inet_service"],
        elem: [{ concat: ["192.168.65.254", 10882] }, { concat: ["192.168.65.254", 5432] }],
      } },
    ] });
    await expect(readHostServiceSetElements(runner, basePlan)).resolves.toEqual([
      { ip: "192.168.65.254", port: 5432 },
      { ip: "192.168.65.254", port: 10882 },
    ]);
    expect(calls.at(-1)?.args).toEqual(["-j", "list", "set", "inet", "runfree_proxy", "host_service"]);

    stdout = JSON.stringify({ nftables: [{ set: { family: "inet", table: "runfree_proxy", name: "host_service" } }] });
    await expect(readHostServiceSetElements(runner, basePlan)).resolves.toEqual([]);

    stdout = JSON.stringify({ nftables: [{ set: {
      family: "inet", table: "runfree_proxy", name: "host_service", elem: [{ concat: ["192.168.65.254", "http"] }],
    } }] });
    await expect(readHostServiceSetElements(runner, basePlan)).rejects.toThrow(/host-service set/);
    stdout = JSON.stringify({ nftables: [] });
    await expect(readHostServiceSetElements(runner, basePlan)).rejects.toThrow(/host-service set/);
    stdout = "not json";
    await expect(readHostServiceSetElements(runner, basePlan)).rejects.toThrow(/malformed JSON/);
  });

  test("rejects duplicate set names using the new set count", () => {
    for (const nftables of [
      { ...basePlan.nftables, hostServiceSetName: "allowed_ipv4" },
      { ...basePlan.nftables, hostServiceDrainingSetName: "host_service" },
      { ...basePlan.nftables, hostServiceDrainingSetName: "audit_draining_ipv4" },
      { ...basePlan.nftables, hostServiceGatewaySetName: "host_service" },
      { ...basePlan.nftables, hostServiceGatewaySetName: "allowed_ipv4" },
    ]) {
      expect(() => validateFirewallPlan({ ...basePlan, nftables } as unknown as FirewallPlan))
        .toThrow(/set names must be distinct/);
    }
    expect(() => validateFirewallPlan({
      ...basePlan,
      nftables: { ...basePlan.nftables, hostServiceSetName: "bad-name" },
    } as unknown as FirewallPlan)).toThrow(/invalid nftables host-service set name/);
    expect(() => validateFirewallPlan({ ...basePlan, hostServiceDrainSeconds: 0 }))
      .toThrow(/invalid host-service drain seconds/);
    expect(() => validateFirewallPlan({
      ...basePlan,
      nftables: { ...basePlan.nftables, hostServiceMaxElements: 0 },
    })).toThrow(/invalid nftables host-service set max elements/);
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
