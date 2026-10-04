import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import type { HostServiceGatewayStatus } from "@runfree/runtime-contracts/proxy-status";

import { readHostServiceGatewayStatusFile } from "../status.ts";
import { publishHostServiceGatewayStatus } from "./supervisor.ts";
import {
  checkEtcHostsFile,
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
    hostServiceGatewaySetName: "host_service_gateways",
    hostServiceGatewayMaxElements: 8,
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
});

describe("gateway hand-off round trip (supervisor writer -> request proxy reader)", () => {
  const ownerUid = process.getuid?.() ?? 0;

  test.each([
    ["an available gateway", { gatewayIp: "192.168.65.254" }],
    ["an unavailable gateway", { unavailableReason: "host-service gateway address changed from pinned 192.168.65.254; runfree rebuild" }],
  ])("%s reads back exactly as written", (_label, fields) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-gateway-roundtrip-"));
    try {
      const filePath = path.join(dir, "host-service-gateway.json");
      const status = {
        schemaVersion: 1,
        policyGeneration: `sha256:${"b".repeat(64)}`,
        ...fields,
        writtenAt: "2026-10-04T00:00:00.000Z",
      } as HostServiceGatewayStatus;

      publishHostServiceGatewayStatus(status, filePath);
      expect(fs.statSync(filePath).mode & 0o777).toBe(0o644);
      expect(readHostServiceGatewayStatusFile(filePath, ownerUid)).toEqual(status);

      // Rewritten in place (atomic rename), the reader sees the new value.
      const next = { ...status, policyGeneration: `sha256:${"c".repeat(64)}` };
      publishHostServiceGatewayStatus(next, filePath);
      expect(readHostServiceGatewayStatusFile(filePath, ownerUid)).toEqual(next);
      expect(fs.readdirSync(dir)).toEqual(["host-service-gateway.json"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("the reader refuses a group-writable file, another owner, and a missing file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-gateway-roundtrip-"));
    try {
      const filePath = path.join(dir, "host-service-gateway.json");
      expect(readHostServiceGatewayStatusFile(filePath, ownerUid)).toBeUndefined();
      publishHostServiceGatewayStatus({
        schemaVersion: 1,
        policyGeneration: `sha256:${"b".repeat(64)}`,
        gatewayIp: "192.168.65.254",
        writtenAt: "2026-10-04T00:00:00.000Z",
      }, filePath);
      expect(readHostServiceGatewayStatusFile(filePath, ownerUid + 1)).toBeUndefined();
      fs.chmodSync(filePath, 0o664);
      expect(readHostServiceGatewayStatusFile(filePath, ownerUid)).toBeUndefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
