import { describe, expect, test } from "vitest";

import {
  checkEtcHostsFile,
  hostServiceSetDigest,
  parseHostServiceGatewayFromEtcHosts,
  validateHostServiceGateway,
} from "./host-service-gateway.ts";
import type { FirewallPlan } from "./nftables.ts";

const plan: FirewallPlan = {
  policyPath: "/policy/network-policy.json",
  policyGeneration: `sha256:${"a".repeat(64)}`,
  internal: { iface: "eth0", proxyIp: "172.30.0.10", proxyPort: 8080 },
  egress: { iface: "eth1", sourceIp: "172.30.1.10", gatewayIp: "172.30.1.1" },
  allowedHosts: [],
  runtimeSubnets: ["172.30.0.0/16"],
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
    hostServiceMaxElements: 64,
  },
  hostServiceDrainSeconds: 30,
  refresh: { policyCheckIntervalSeconds: 2, dnsRefreshIntervalSeconds: 300, maxStaleHostSeconds: 900 },
  audit: {
    markerPath: "/run/runfree-proxy-audit/active.json",
    spoolPath: "/run/runfree-proxy-audit-spool/spool.txt",
    resolvedHostsPath: "/run/runfree-proxy-audit/resolved-hosts.json",
    resolveBudgetPerTick: 8,
    drainSeconds: 30,
  },
};

describe("host-service gateway from /etc/hosts", () => {
  test("takes the one IPv4 for the alias and ignores IPv6 and comments", () => {
    const text = "127.0.0.1 localhost\n# 10.0.0.1 gateway.runfree.internal\n192.168.65.254\tgateway.runfree.internal\nfdc4:f303:9324::254 gateway.runfree.internal\n";
    expect(parseHostServiceGatewayFromEtcHosts(text)).toEqual({ ip: "192.168.65.254" });
  });

  test("a repeated line with the same address is one distinct address", () => {
    const text = "192.168.65.254 gateway.runfree.internal\n192.168.65.254 other gateway.runfree.internal # trailing\n";
    expect(parseHostServiceGatewayFromEtcHosts(text)).toEqual({ ip: "192.168.65.254" });
  });

  test.each([
    ["", "missing"],
    ["192.168.65.254 gateway.runfree.internal\n192.168.65.253 gateway.runfree.internal\n", "more than one"],
    ["192.168.65.254 xgateway.runfree.internal\n", "missing"],
    ["192.168.65.254 gateway.runfree.internal.example\n", "missing"],
    ["192.168.65.254 GATEWAY.runfree.internal\n", "missing"],
    ["fdc4:f303:9324::254 gateway.runfree.internal\n", "missing"],
    ["192.168.065.254 gateway.runfree.internal\n", "malformed"],
    ["192.168.65.254#x gateway.runfree.internal\n", "missing"],
  ])("refuses %j", (text, needle) => {
    expect((parseHostServiceGatewayFromEtcHosts(text) as { error: string }).error).toContain(needle);
  });

  test.each([["127.0.0.1"], ["169.254.1.1"], ["8.8.8.8"], ["172.30.0.5"], ["172.30.1.1"], ["100.64.0.1"], ["not-an-ip"]])(
    "validator refuses %s",
    (ip) => {
      expect(validateHostServiceGateway(ip, plan)).toBeTypeOf("string");
    },
  );

  test("validator refuses the egress gateway even outside the runtime subnets", () => {
    const bare = { ...plan, runtimeSubnets: [], egress: { ...plan.egress, gatewayIp: "10.9.0.1" } };
    expect(validateHostServiceGateway("10.9.0.1", bare)).toContain("egress gateway");
  });

  test.each([["192.168.65.254"], ["10.0.0.2"], ["172.16.5.5"]])("validator accepts the RFC 1918 gateway %s", (ip) => {
    expect(validateHostServiceGateway(ip, plan)).toBeUndefined();
  });

  test.each([
    [{ uid: 1001, mode: 0o100644, isFile: true }],
    [{ uid: 0, mode: 0o100666, isFile: true }],
    [{ uid: 0, mode: 0o100664, isFile: true }],
    [{ uid: 0, mode: 0o100644, isFile: false }],
  ])("etc hosts stat %j is refused", (s) => {
    expect(checkEtcHostsFile(s)).toBeTypeOf("string");
  });

  test("a root-owned 0644 regular file is accepted", () => {
    expect(checkEtcHostsFile({ uid: 0, mode: 0o100644, isFile: true })).toBeUndefined();
  });

  test("the set digest is order-independent and covers the draining pairs", () => {
    const a = { ip: "192.168.65.254", port: 10882 };
    const b = { ip: "192.168.65.254", port: 5432 };
    expect(hostServiceSetDigest([a, b], [])).toBe(hostServiceSetDigest([b, a], []));
    expect(hostServiceSetDigest([a], [])).not.toBe(hostServiceSetDigest([a], [b]));
    expect(hostServiceSetDigest([a], [b])).not.toBe(hostServiceSetDigest([a, b], []));
    expect(hostServiceSetDigest([], [])).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});
