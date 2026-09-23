import { describe, expect, test } from "vitest";

import type { CommandRunner, FirewallCommand, CommandRunOptions, CommandResult } from "./command.ts";
import type { FirewallPlan } from "./nftables.ts";
import { ensureDefaultRoute, verifyFirewallState } from "./route.ts";

const plan: FirewallPlan = {
  policyPath: "/app/proxy/policy/network-policy.json",
  policyGeneration: `sha256:${"a".repeat(64)}`,
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
    policyCheckIntervalSeconds: 1,
    dnsRefreshIntervalSeconds: 300,
    maxStaleHostSeconds: 600,
  },
  audit: {
    markerPath: "/run/runfree-proxy-audit/active.json",
    spoolPath: "/run/runfree-proxy-audit-spool/spool.txt",
    resolvedHostsPath: "/run/runfree-proxy-audit/resolved-hosts.json",
    resolveBudgetPerTick: 8,
    drainSeconds: 30,
  },
};

type RecordedCall = {
  args: readonly string[];
  command: FirewallCommand;
  input?: string;
};

function routeJson(dev: string, src: string): string {
  return JSON.stringify([{ dev, src }]);
}

function createRunner(options: {
  routes: string[];
  nftFails?: boolean;
  nftSetOutputs?: Record<string, string>;
}): { calls: RecordedCall[]; runner: CommandRunner } {
  const calls: RecordedCall[] = [];
  const routes = [...options.routes];
  return {
    calls,
    runner: {
      async run(command: FirewallCommand, args: readonly string[], runOptions?: CommandRunOptions): Promise<CommandResult> {
        calls.push({ command, args, input: runOptions?.input });
        if (command === "ip" && args.join(" ") === "-json route get 1.1.1.1") {
          return { stdout: routes.shift() ?? routeJson("eth9", "172.30.9.10"), stderr: "" };
        }
        if (command === "ip" && args[0] === "route" && args[1] === "replace") {
          return { stdout: "", stderr: "" };
        }
        if (command === "nft") {
          if (options.nftFails) throw new Error("nft unavailable");
          const setName = args[0] === "list" && args[1] === "set" ? args[4] : undefined;
          return { stdout: (setName && options.nftSetOutputs?.[setName]) ?? "", stderr: "" };
        }
        throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
      },
    },
  };
}

describe("proxy firewall route verification", () => {
  test("leaves the default route untouched when it already uses proxy egress", async () => {
    const { calls, runner } = createRunner({
      routes: [routeJson("eth1", "172.30.1.10")],
    });

    await ensureDefaultRoute(plan, runner);

    expect(calls).toEqual([
      { command: "ip", args: ["-json", "route", "get", "1.1.1.1"], input: undefined },
    ]);
  });

  test("repairs the default route through the proxy egress interface and source", async () => {
    const { calls, runner } = createRunner({
      routes: [
        routeJson("eth0", "172.30.0.10"),
        routeJson("eth1", "172.30.1.10"),
      ],
    });

    await ensureDefaultRoute(plan, runner);

    expect(calls).toEqual([
      { command: "ip", args: ["-json", "route", "get", "1.1.1.1"], input: undefined },
      {
        command: "ip",
        args: ["route", "replace", "default", "via", "172.30.1.1", "dev", "eth1", "src", "172.30.1.10"],
        input: undefined,
      },
      { command: "ip", args: ["-json", "route", "get", "1.1.1.1"], input: undefined },
    ]);
  });

  test("fails when route repair does not put egress traffic on the proxy egress interface", async () => {
    const { runner } = createRunner({
      routes: [
        routeJson("eth0", "172.30.0.10"),
        routeJson("eth0", "172.30.0.10"),
      ],
    });

    await expect(ensureDefaultRoute(plan, runner))
      .rejects.toThrow("default egress route still uses eth0 src 172.30.0.10");
  });

  test("verifies route and nftables inspectability without mutating firewall state", async () => {
    const { calls, runner } = createRunner({
      routes: [routeJson("eth1", "172.30.1.10")],
    });

    await verifyFirewallState(plan, runner);

    expect(calls).toEqual([
      { command: "ip", args: ["-json", "route", "get", "1.1.1.1"], input: undefined },
      { command: "nft", args: ["list", "ruleset"], input: undefined },
      { command: "nft", args: ["list", "set", "inet", "runfree_proxy", "allowed_ipv4"], input: undefined },
      { command: "nft", args: ["list", "set", "inet", "runfree_proxy", "session_ipv4"], input: undefined },
      { command: "nft", args: ["list", "set", "inet", "runfree_proxy", "audit_ipv4"], input: undefined },
      { command: "nft", args: ["list", "set", "inet", "runfree_proxy", "audit_draining_ipv4"], input: undefined },
    ]);
  });

  test("fails when nftables state cannot be inspected", async () => {
    const { runner } = createRunner({
      routes: [routeJson("eth1", "172.30.1.10")],
      nftFails: true,
    });

    await expect(verifyFirewallState(plan, runner)).rejects.toThrow("nft unavailable");
  });

  test("fails enforce-mode verification when an always-present audit set is not empty", async () => {
    for (const auditSet of ["audit_ipv4", "audit_draining_ipv4"] as const) {
      const { runner } = createRunner({
        routes: [routeJson("eth1", "172.30.1.10")],
        nftSetOutputs: {
          [auditSet]: [
            `set ${auditSet} {`,
            "  type ipv4_addr",
            "  size 256",
            "  elements = { 203.0.113.7 }",
            "}",
          ].join("\n"),
        },
      });

      await expect(verifyFirewallState(plan, runner))
        .rejects.toThrow(`proxy firewall audit set ${auditSet} is not empty in enforce mode`);
    }
  });
});
