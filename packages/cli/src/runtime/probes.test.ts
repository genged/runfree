import net from "node:net";

import { describe, expect, test } from "vitest";

import type { RuntimeNetwork } from "../network.ts";
import { proxyHostServiceSetJson, proxyNftablesTableJson } from "../proxy-nftables-proof.fixture.ts";
import {
  SERVER_UID_DENIAL_BATCH_SCRIPT,
  SERVER_UID_DENIAL_PROBE_LABELS,
  applyServerUidDenialBatch,
  firewallSectionBatchScript,
  parseFirewallSectionBatch,
  probeMcpCallbackPathWithRetries,
  serverUidDenialBatchScript,
  validateProxyFirewall,
} from "./probes.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const PROXY_ID = "f".repeat(64);
const POLICY_GENERATION = `sha256:${"a".repeat(64)}`;
const GATEWAY = "192.168.65.254";

const NETWORK: RuntimeNetwork = {
  subnet: "172.30.0.0/24",
  proxyIp: "172.30.0.10",
  agentIp: "172.30.0.11",
  callbackSidecarIp: "172.30.0.12",
  proxyEgressSubnet: "172.30.1.0/24",
  proxyEgressGateway: "172.30.1.1",
  proxyEgressIp: "172.30.1.10",
};

function captureResult(status: number, stdout = "", stderr = ""): CaptureResult {
  return { status, stdout, stderr };
}

function sectionOutput(sections: Array<{ exit: number; body: string }>): string {
  return `${sections.map((section, index) => [
    `RUNFREE_FIREWALL_SECTION ${index} exit=${section.exit}`,
    section.body,
    `RUNFREE_FIREWALL_SECTION_END ${index}`,
  ].join("\n")).join("\n")}\n`;
}

function probeRecords(exits: number[]): string {
  return `${exits.map((exit, index) => `RUNFREE_FIREWALL_PROBE ${index} exit=${exit}`).join("\n")}\n`;
}

function gatewayStatus(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schemaVersion: 1,
    policyGeneration: POLICY_GENERATION,
    gatewayIp: GATEWAY,
    writtenAt: "2026-10-04T00:00:00.000Z",
    ...overrides,
  });
}

const ALLOWED_SET_SECTION = {
  exit: 0,
  body: "table inet runfree_proxy {\n  set allowed_ipv4 { type ipv4_addr; elements = { 140.82.112.5 } }\n}",
};
// `stat -c '%u %f'` of a root-owned 0644 regular file.
const ETC_HOSTS_OK = { exit: 0, body: "0 81a4" };

type RootSectionOverrides = {
  allowedSet?: { exit: number; body: string };
  dns?: { exit: number; body: string };
  hostServiceSet?: { exit: number; body: string };
  gateway?: { exit: number; body: string };
  etcHosts?: { exit: number; body: string };
};

function rootSections(overrides: RootSectionOverrides = {}): Array<{ exit: number; body: string }> {
  return [
    overrides.allowedSet ?? ALLOWED_SET_SECTION,
    overrides.dns ?? { exit: 0, body: "" },
    overrides.hostServiceSet ?? { exit: 0, body: proxyHostServiceSetJson([]) },
    overrides.gateway ?? { exit: 0, body: gatewayStatus() },
    overrides.etcHosts ?? ETC_HOSTS_OK,
  ];
}

type FirewallOverrides = {
  routeBatch?: CaptureResult;
  rootBatch?: CaptureResult;
  soloDns?: () => CaptureResult;
  serverBatch?: CaptureResult;
  /** Exit code per proxy-position gateway probe, given the exec identity and the probe script. */
  gatewayProbeExit?: (user: string, script: string) => number;
};

function firewallFixture(overrides: FirewallOverrides = {}) {
  const execs: string[][] = [];
  const io: RuntimeIO = {
    run: () => 0,
    capture(_command, args) {
      execs.push([...args]);
      const text = args.join(" ");
      if (text.includes("RUNFREE_FIREWALL_SECTION") && text.includes("ip -o route get")) {
        return overrides.routeBatch ?? captureResult(0, sectionOutput([
          { exit: 0, body: `${NETWORK.agentIp} dev eth0 src ${NETWORK.proxyIp} uid 1001` },
          { exit: 0, body: `1.1.1.1 via ${NETWORK.proxyEgressGateway} dev eth1 src ${NETWORK.proxyEgressIp} uid 1001` },
        ]));
      }
      if (text.includes("nft -j list table inet runfree_proxy")) {
        return captureResult(0, proxyNftablesTableJson());
      }
      if (text.includes("RUNFREE_FIREWALL_SECTION") && text.includes("allowed_ipv4")) {
        return overrides.rootBatch ?? captureResult(0, sectionOutput(rootSections()));
      }
      if (text.includes("RUNFREE_FIREWALL_PROBE")) {
        if (overrides.serverBatch) return overrides.serverBatch;
        // Five denied server-UID records, plus the uid-1001 gateway probe
        // record (dropped: a timeout) when the batch carries one.
        const script = args.at(-1) ?? "";
        const gateway = script.includes("/dev/tcp/");
        return captureResult(0, probeRecords([1, 1, 1, 1, 1, ...(gateway ? [overrides.gatewayProbeExit?.("1001:1001", script) ?? 124] : [])]));
      }
      if (text.includes("RUNFREE_DENY_PROBE")) {
        const user = args[args.indexOf("--user") + 1] ?? "";
        const script = args.at(-1) ?? "";
        const probes = [...script.matchAll(/runfree_pid_(\d+)=\$!/g)].length;
        const exit = overrides.gatewayProbeExit?.(user, script) ?? 124;
        return captureResult(0, `${Array.from({ length: probes }, (_, index) => `RUNFREE_DENY_PROBE ${index} exit=${exit}`).join("\n")}\n`);
      }
      if (text.includes("@127.0.0.11 example.com")) {
        return overrides.soloDns?.() ?? captureResult(0);
      }
      return captureResult(1, "", `unexpected exec: ${text}`);
    },
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  };
  const context = { env: {}, projectRoot: "/workspace/project" } as unknown as RuntimeContext;
  const issues: string[] = [];
  const observed = { boundaryViolations: 0 };
  return {
    execs,
    issues,
    observed,
    run: (options?: Parameters<typeof validateProxyFirewall>[5]) =>
      validateProxyFirewall(issues, context, io, PROXY_ID, NETWORK, {
        onBoundaryViolation: () => { observed.boundaryViolations += 1; },
        ...options,
      }),
  };
}

test("firewall probes merge into one exec per identity group plus the dedicated nft table fetch", () => {
  const fixture = firewallFixture();
  const proof = fixture.run();

  expect(fixture.issues).toEqual([]);
  // Exactly four execs: default-user route batch, dedicated root table fetch,
  // root batch (allowlist, Docker DNS, host-service set and gateway,
  // /etc/hosts), server-UID denial batch.
  expect(fixture.execs).toHaveLength(4);
  const [routeBatch, tableFetch, rootBatch, serverBatch] = fixture.execs;
  expect(routeBatch.slice(0, 2)).toEqual(["exec", PROXY_ID]);
  expect(tableFetch).toEqual(["exec", "--user", "0:0", PROXY_ID, "nft", "-j", "list", "table", "inet", "runfree_proxy"]);
  expect(rootBatch.slice(0, 3)).toEqual(["exec", "--user", "0:0"]);
  const rootScript = rootBatch.join(" ");
  expect(rootScript).toContain("nft -j list set inet runfree_proxy host_service");
  expect(rootScript).toContain("cat /run/runfree-proxy-status/host-service-gateway.json");
  expect(rootScript).toContain("stat -c '%u %f' /etc/hosts");
  // The denial-group exec carries the exact server identity — the identity is
  // the SUBJECT of these proofs — and never recreates it via su/setpriv/runuser.
  expect(serverBatch.slice(0, 3)).toEqual(["exec", "--user", "1001:1001"]);
  const serverScript = serverBatch.join(" ");
  expect(serverScript).not.toContain("su ");
  expect(serverScript).not.toContain("setpriv");
  expect(serverScript).not.toContain("runuser");
  // The raw table fetch stays dedicated: its stdout is minted verbatim.
  expect(proof.nftablesProofInput?.rawJson).toBe(proxyNftablesTableJson());
  expect(proof.nftablesProofInput?.internalIface).toBe("eth0");
  expect(proof.nftablesProofInput?.egressIface).toBe("eth1");
});

test("the route batch proves the default egress route uses the proxy_egress address", () => {
  const fixture = firewallFixture({
    routeBatch: captureResult(0, sectionOutput([
      { exit: 0, body: `${NETWORK.agentIp} dev eth0 src ${NETWORK.proxyIp} uid 1001` },
      { exit: 0, body: `1.1.1.1 via ${NETWORK.proxyEgressGateway} dev eth1 src 172.30.1.99 uid 1001` },
    ])),
  });
  fixture.run({ expectedEgressSource: NETWORK.proxyEgressIp });
  expect(fixture.issues).toContain(
    `proxy default egress route must use proxy_egress address ${NETWORK.proxyEgressIp}; got 1.1.1.1 via ${NETWORK.proxyEgressGateway} dev eth1 src 172.30.1.99 uid 1001`,
  );
});

test("a matching egress source adds no issue and no extra exec", () => {
  const fixture = firewallFixture();
  fixture.run({ expectedEgressSource: NETWORK.proxyEgressIp });
  expect(fixture.issues).toEqual([]);
  expect(fixture.execs).toHaveLength(4);
});

test("only the root Docker DNS probe retries, solo, after a lost query in the root batch", () => {
  let soloDnsAttempts = 0;
  const fixture = firewallFixture({
    rootBatch: captureResult(0, sectionOutput(rootSections({ dns: { exit: 1, body: "one lost UDP query" } }))),
    soloDns: () => {
      soloDnsAttempts += 1;
      return captureResult(0);
    },
  });
  fixture.run();

  expect(fixture.issues).toEqual([]);
  expect(soloDnsAttempts).toBe(1);
  // The solo retry is a bare root exec of the DNS command alone, issued right
  // after the root batch and before the server-UID batch: no failure-expected
  // probe rides along where a retry could mask a gap.
  const retry = fixture.execs[3];
  expect(retry.slice(0, 3)).toEqual(["exec", "--user", "0:0"]);
  expect(retry.join(" ")).toContain("@127.0.0.11 example.com");
  expect(retry.join(" ")).not.toContain("RUNFREE_FIREWALL_SECTION");
  expect(fixture.execs).toHaveLength(5);
});

test("a missing or garbled root batch fails every section closed without retrying anything", () => {
  const fixture = firewallFixture({
    rootBatch: captureResult(0, "RUNFREE_FIREWALL_SECTION 0 exit=0\ntruncated"),
  });
  const proof = fixture.run({ effectiveHostServices: { policyGeneration: POLICY_GENERATION, ports: [5432] } });

  expect(fixture.issues.some((issue) => issue.includes("proxy nftables allowlist set inspection failed"))).toBe(true);
  expect(fixture.issues.some((issue) => issue.includes("proxy root Docker DNS failed"))).toBe(true);
  expect(fixture.issues.some((issue) => issue.includes("proxy nftables host_service set inspection failed"))).toBe(true);
  expect(fixture.issues.some((issue) => issue.includes("proxy /etc/hosts inspection failed"))).toBe(true);
  // No gateway was read: nothing to probe.
  expect(proof.hostServiceGatewayIp).toBeUndefined();
  // Route batch, table fetch, root batch, server batch — and no solo retry.
  expect(fixture.execs).toHaveLength(4);
});

test("DNS failure retains bounded diagnostics and every attempt without retrying denials", () => {
  let soloDnsAttempts = 0;
  const fixture = firewallFixture({
    rootBatch: captureResult(0, sectionOutput(rootSections({
      allowedSet: { exit: 0, body: "set allowed_ipv4" },
      dns: { exit: 124, body: "first query interrupted" },
    }))),
    soloDns: () => {
      soloDnsAttempts += 1;
      return captureResult(9, `;; connection timed out ${"x".repeat(4000)}`, "resolver unavailable");
    },
  });
  fixture.run();
  const issue = fixture.issues.find((entry) => entry.startsWith("proxy root Docker DNS failed"));
  expect(issue).toContain("resolver=127.0.0.11 query=example.com");
  expect(issue).toContain("attempt 1 exit=124: first query interrupted");
  expect(issue).toContain("attempt 2 exit=9");
  expect(issue).toContain("attempt 3 exit=9");
  expect(issue?.length).toBeLessThan(1700);
  expect(soloDnsAttempts).toBe(2);
  expect(fixture.execs.filter((args) => args.join(" ").includes("RUNFREE_FIREWALL_PROBE"))).toHaveLength(1);
});

test("a garbled route batch fails both route inspections closed", () => {
  const fixture = firewallFixture({ routeBatch: captureResult(1, "", "exec transport error") });
  fixture.run();

  expect(fixture.issues.some((issue) => issue.startsWith("proxy internal route inspection failed"))).toBe(true);
  expect(fixture.issues.some((issue) => issue.startsWith("proxy egress route inspection failed"))).toBe(true);
  expect(fixture.issues).toContain("proxy internal route must expose an interface for nftables proof");
});

// Host services (design "Host-side proof"): the kernel members of
// @host_service equal the effective ports at the published gateway, and the
// proxy-position gateway probes prove the accept is uid 1001 and port-exact.
const HOST_SERVICES = { policyGeneration: POLICY_GENERATION, ports: [5432, 10882] } as const;

function hostServiceFixture(
  sections: RootSectionOverrides,
  overrides: Omit<FirewallOverrides, "rootBatch"> = {},
) {
  return firewallFixture({ ...overrides, rootBatch: captureResult(0, sectionOutput(rootSections(sections))) });
}

const MATCHING_SET = { exit: 0, body: proxyHostServiceSetJson([{ ip: GATEWAY, port: 10882 }, { ip: GATEWAY, port: 5432 }]) };

test("matching host_service members pass; the uid 1001 gateway probe rides the server-UID batch and root probes run alone", () => {
  const fixture = hostServiceFixture({ hostServiceSet: MATCHING_SET });
  const proof = fixture.run({ effectiveHostServices: HOST_SERVICES });

  expect(fixture.issues).toEqual([]);
  expect(proof.hostServiceGatewayIp).toBe(GATEWAY);
  expect(proof.nftablesProofInput?.expectedHostServiceElements).toEqual([{ ip: GATEWAY, port: 5432 }, { ip: GATEWAY, port: 10882 }]);
  expect(proof.nftablesProofInput?.hostServiceElements).toEqual([{ ip: GATEWAY, port: 10882 }, { ip: GATEWAY, port: 5432 }]);
  // Route, table, root batch, server-UID batch (with the gateway record),
  // then the root gateway batch: one exec more than without host services.
  expect(fixture.execs).toHaveLength(5);
  const [serverBatch, rootGateway] = fixture.execs.slice(3);
  expect(serverBatch.slice(0, 3)).toEqual(["exec", "--user", "1001:1001"]);
  expect(serverBatch.join(" ")).toContain("RUNFREE_FIREWALL_PROBE");
  // uid 1001 to a port the policy does not approve, as the sixth record.
  expect(serverBatch.join(" ")).toContain(`timeout 3 bash -c '</dev/tcp/${GATEWAY}/9'`);
  expect(serverBatch.join(" ")).toContain("runfree_pid_5=$!");
  expect(serverBatch.join(" ")).not.toContain(`/dev/tcp/${GATEWAY}/5432`);
  // Root to every approved port: the accept is uid 1001 only.
  expect(rootGateway.slice(0, 3)).toEqual(["exec", "--user", "0:0"]);
  expect(rootGateway.join(" ")).toContain(`/dev/tcp/${GATEWAY}/5432`);
  expect(rootGateway.join(" ")).toContain(`/dev/tcp/${GATEWAY}/10882`);
});

test("without host services the server-UID batch carries no gateway record", () => {
  const fixture = firewallFixture();
  fixture.run();
  expect(fixture.execs).toHaveLength(4);
  expect(fixture.execs[3].join(" ")).not.toContain("/dev/tcp/");
  expect(fixture.execs[3].join(" ")).not.toContain("runfree_pid_5");
});

test("the uid 1001 probe picks a port the policy does not approve", () => {
  const fixture = hostServiceFixture({
    hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([{ ip: GATEWAY, port: 9 }, { ip: GATEWAY, port: 10 }]) },
  });
  fixture.run({ effectiveHostServices: { policyGeneration: POLICY_GENERATION, ports: [9, 10] } });

  expect(fixture.issues).toEqual([]);
  expect(fixture.execs[3].join(" ")).toContain(`/dev/tcp/${GATEWAY}/11`);
});

// Only a timeout (exit 124) proves an nftables output drop: the SYN goes
// unanswered. A refused or unreachable connect (exit 1) means the host
// answered, which also happens when nothing listens: an unproven denial,
// not an escape. Exit 0 is an escape.
describe.each([
  ["uid 1001 to an unapproved port", "1001:1001", ["proxy-position server UID host gateway unapproved port 9"]],
  ["root to each approved port", "0:0", ["proxy-position root host gateway port 5432", "proxy-position root host gateway port 10882"]],
] as const)("the proxy-position gateway probe for %s", (_family, user, labels) => {
  const run = (exit: number) => {
    const fixture = hostServiceFixture({ hostServiceSet: MATCHING_SET }, {
      gatewayProbeExit: (probeUser) => (probeUser === user ? exit : 124),
    });
    fixture.run({ effectiveHostServices: HOST_SERVICES });
    return fixture;
  };

  test("exit 124 (the SYN was dropped) proves the denial", () => {
    const fixture = run(124);
    expect(fixture.issues).toEqual([]);
    expect(fixture.observed.boundaryViolations).toBe(0);
  });

  test("exit 1 (refused or unreachable) is an unproven denial, not a boundary violation", () => {
    const fixture = run(1);
    expect(fixture.issues).toEqual(labels.map((label) =>
      `${label} was answered instead of dropped (exit 1); only a timeout proves the firewall dropped it`));
    expect(fixture.observed.boundaryViolations).toBe(0);
  });

  test("exit 0 (connected) is a boundary violation", () => {
    const fixture = run(0);
    expect(fixture.issues).toEqual(labels.map((label) => `${label} unexpectedly succeeded`));
    expect(fixture.observed.boundaryViolations).toBe(labels.length);
  });
});

test("a failed server-UID batch leaves the uid 1001 gateway probe unproven too", () => {
  const fixture = hostServiceFixture({ hostServiceSet: MATCHING_SET }, {
    serverBatch: captureResult(0, probeRecords([1, 1, 1, 1, 1])),
  });
  fixture.run({ effectiveHostServices: HOST_SERVICES });
  expect(fixture.issues.some((issue) => issue.includes("expected 6 probe records, got 5"))).toBe(true);
  expect(fixture.issues).toContain("proxy-position server UID host gateway unapproved port 9 denial probe did not run: the server UID batch failed");
});

test("an extra host_service member at the status gateway is a refused widening; a missing one refuses without containment", () => {
  const extra = hostServiceFixture({
    hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([{ ip: GATEWAY, port: 5432 }, { ip: GATEWAY, port: 10882 }, { ip: GATEWAY, port: 6379 }]) },
  });
  extra.run({ effectiveHostServices: HOST_SERVICES });
  expect(extra.issues.some((issue) => issue.startsWith("host_service members do not match the effective host services"))).toBe(true);
  expect(extra.observed.boundaryViolations).toBeGreaterThan(0);

  const missing = hostServiceFixture({
    hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([{ ip: GATEWAY, port: 5432 }]) },
  });
  missing.run({ effectiveHostServices: HOST_SERVICES });
  expect(missing.issues.some((issue) => issue.startsWith("host_service members do not match the effective host services"))).toBe(true);
  expect(missing.observed.boundaryViolations).toBe(0);
});

test("host_service members at another address than the status gateway refuse without containment (a re-pin race)", () => {
  const raced = hostServiceFixture({
    hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([{ ip: "192.168.65.253", port: 5432 }, { ip: "192.168.65.253", port: 10882 }]) },
  });
  raced.run({ effectiveHostServices: HOST_SERVICES });
  expect(raced.issues.some((issue) => issue.startsWith("host_service members do not match the effective host services"))).toBe(true);
  expect(raced.observed.boundaryViolations).toBe(0);

  // The same race plus a pair at the status gateway on an unapproved port:
  // that pair is still a widening.
  const widened = hostServiceFixture({
    hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([{ ip: "192.168.65.253", port: 5432 }, { ip: GATEWAY, port: 6379 }]) },
  });
  widened.run({ effectiveHostServices: HOST_SERVICES });
  expect(widened.observed.boundaryViolations).toBeGreaterThan(0);
});

test("a withheld gateway expects an empty host_service set and runs no gateway probe", () => {
  const unavailable = { exit: 0, body: gatewayStatus({ gatewayIp: undefined, unavailableReason: "host-service gateway not pinned" }) };
  const empty = hostServiceFixture({ gateway: unavailable });
  const proof = empty.run({ effectiveHostServices: HOST_SERVICES });
  expect(empty.issues).toEqual([]);
  expect(proof.hostServiceGatewayIp).toBeUndefined();
  expect(proof.nftablesProofInput?.expectedHostServiceElements).toEqual([]);
  expect(empty.execs.some((args) => args.join(" ").includes("/dev/tcp/"))).toBe(false);

  // Pairs left in the kernel while the gateway is withheld are reachable
  // without a gateway the request proxy may use: refused, and with no status
  // address to compare against they are not judged an escape.
  const leftover = hostServiceFixture({
    gateway: unavailable,
    hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([{ ip: GATEWAY, port: 5432 }]) },
  });
  leftover.run({ effectiveHostServices: HOST_SERVICES });
  expect(leftover.issues.some((issue) => issue.startsWith("host_service members do not match the effective host services"))).toBe(true);
  expect(leftover.observed.boundaryViolations).toBe(0);
});

test("a gateway status from another network policy generation refuses and runs no gateway probe", () => {
  const fixture = hostServiceFixture({
    gateway: { exit: 0, body: gatewayStatus({ policyGeneration: `sha256:${"b".repeat(64)}` }) },
    hostServiceSet: MATCHING_SET,
  });
  const proof = fixture.run({ effectiveHostServices: HOST_SERVICES });
  expect(fixture.issues.some((issue) => issue.startsWith("proxy host-service gateway status names network policy generation sha256:bbbb"))).toBe(true);
  expect(proof.hostServiceGatewayIp).toBeUndefined();
  expect(fixture.execs.some((args) => args.join(" ").includes("/dev/tcp/"))).toBe(false);
});

test.each([
  ["a missing gateway status file", { gateway: { exit: 1, body: "cat: no such file" } }, "proxy host-service gateway status inspection failed"],
  ["a malformed gateway status", { gateway: { exit: 0, body: "{\"schemaVersion\":2}" } }, "proxy host-service gateway status is malformed"],
  ["a gateway status with both fields", { gateway: { exit: 0, body: gatewayStatus({ unavailableReason: "x" }) } }, "proxy host-service gateway status is malformed"],
  ["an unreadable host_service set", { hostServiceSet: { exit: 1, body: "Error: No such file or directory" } }, "proxy nftables host_service set inspection failed"],
  ["a host_service set that is not nft JSON", { hostServiceSet: { exit: 0, body: "table inet runfree_proxy {}" } }, "proxy nftables host_service set inspection did not return"],
] as const)("%s fails closed", (_label, sections, issue) => {
  const fixture = hostServiceFixture(sections);
  const proof = fixture.run({ effectiveHostServices: HOST_SERVICES });
  expect(fixture.issues.some((entry) => entry.startsWith(issue))).toBe(true);
  expect(proof.nftablesProofInput?.expectedHostServiceElements === undefined
    || proof.nftablesProofInput?.hostServiceElements === undefined).toBe(true);
});

test.each([
  ["group-writable", "0 81b4"],
  ["other-writable", "0 81a6"],
  ["owned by another uid", "1001 81a4"],
  ["a symlink", "0 a1ff"],
  ["a directory", "0 41ed"],
  ["garbled", "regular file"],
])("an /etc/hosts that is %s refuses", (_label, body) => {
  const fixture = hostServiceFixture({ etcHosts: { exit: 0, body } });
  fixture.run();
  expect(fixture.issues.some((issue) => issue.startsWith("proxy /etc/hosts must be a root-owned regular file"))).toBe(true);
});

test("a root-owned 0600 or 0644 regular /etc/hosts passes", () => {
  for (const body of ["0 8180", "0 81a4"]) {
    const fixture = hostServiceFixture({ etcHosts: { exit: 0, body } });
    fixture.run();
    expect(fixture.issues).toEqual([]);
  }
});

test("firewallSectionBatchScript frames every command in host-declared order and always exits 0", () => {
  const script = firewallSectionBatchScript(["ip -o route get 1.1.1.1", "nft list set inet runfree_proxy allowed_ipv4"]);
  expect(script).toContain("runfree_out_0=$({ ip -o route get 1.1.1.1; } 2>&1); runfree_status_0=$?");
  expect(script).toContain("runfree_out_1=$({ nft list set inet runfree_proxy allowed_ipv4; } 2>&1); runfree_status_1=$?");
  expect(script.trimEnd().endsWith("exit 0")).toBe(true);
});

test.each([
  ["nonzero batch exit", captureResult(1, sectionOutput([{ exit: 0, body: "ok" }]))],
  ["missing section", captureResult(0, sectionOutput([{ exit: 0, body: "ok" }]))],
  ["reordered sections", captureResult(0, "RUNFREE_FIREWALL_SECTION 1 exit=0\nx\nRUNFREE_FIREWALL_SECTION_END 1\nRUNFREE_FIREWALL_SECTION 0 exit=0\ny\nRUNFREE_FIREWALL_SECTION_END 0\n")],
  ["marker inside a body", captureResult(0, "RUNFREE_FIREWALL_SECTION 0 exit=0\nRUNFREE_FIREWALL_SECTION 9 exit=0\nRUNFREE_FIREWALL_SECTION_END 0\nRUNFREE_FIREWALL_SECTION 1 exit=0\nx\nRUNFREE_FIREWALL_SECTION_END 1\n")],
  ["unterminated section", captureResult(0, "RUNFREE_FIREWALL_SECTION 0 exit=0\nbody\n")],
  ["trailing garbage", captureResult(0, `${sectionOutput([{ exit: 0, body: "a" }, { exit: 0, body: "b" }])}extra\n`)],
])("parseFirewallSectionBatch fails closed on %s", (_kind, result) => {
  expect(parseFirewallSectionBatch(result, 2)).toBeUndefined();
});

test("parseFirewallSectionBatch preserves per-section exit codes and bodies", () => {
  const sections = parseFirewallSectionBatch(captureResult(0, sectionOutput([
    { exit: 0, body: "line one\nline two" },
    { exit: 9, body: "denied" },
  ])), 2);
  expect(sections).toEqual([
    { exit: 0, body: "line one\nline two" },
    { exit: 9, body: "denied" },
  ]);
});

test("the server-UID denial batch preflights binaries and records every probe in order", () => {
  expect(SERVER_UID_DENIAL_BATCH_SCRIPT.indexOf("command -v"))
    .toBeLessThan(SERVER_UID_DENIAL_BATCH_SCRIPT.indexOf("runfree_pid_0"));
  for (let index = 0; index < SERVER_UID_DENIAL_PROBE_LABELS.length; index += 1) {
    expect(SERVER_UID_DENIAL_BATCH_SCRIPT).toContain(`wait "$runfree_pid_${index}"; runfree_status_${index}=$?`);
  }
  expect(SERVER_UID_DENIAL_BATCH_SCRIPT.trimEnd().endsWith("exit 0")).toBe(true);
});

test("all-denied server-UID records add no issues; success and could-not-run are distinguished", () => {
  const denied: string[] = [];
  applyServerUidDenialBatch(denied, captureResult(0, probeRecords([1, 1, 1, 1, 1])));
  expect(denied).toEqual([]);

  const mixed: string[] = [];
  applyServerUidDenialBatch(mixed, captureResult(0, probeRecords([0, 1, 127, 1, 1])));
  expect(mixed).toEqual([
    "proxy server UID DNS to 1.1.1.1 unexpectedly succeeded",
    "proxy server UID nftables ruleset inspection could not run inside the proxy (exit 127)",
  ]);
});

test("a nonzero server batch exit is a validation failure even with five denied records", () => {
  const issues: string[] = [];
  applyServerUidDenialBatch(issues, captureResult(96, probeRecords([1, 1, 1, 1, 1]), "missing probe binary: dig"));
  expect(issues).toHaveLength(1);
  expect(issues[0]).toContain("proxy server UID nftables and route denial batch could not run");
});

test.each([
  ["missing record", probeRecords([1, 1, 1, 1])],
  ["duplicate record", "RUNFREE_FIREWALL_PROBE 0 exit=1\nRUNFREE_FIREWALL_PROBE 0 exit=1\nRUNFREE_FIREWALL_PROBE 2 exit=1\nRUNFREE_FIREWALL_PROBE 3 exit=1\nRUNFREE_FIREWALL_PROBE 4 exit=1\n"],
  ["garbled record", "RUNFREE_FIREWALL_PROBE 0 exit=1\nchatter\nRUNFREE_FIREWALL_PROBE 2 exit=1\nRUNFREE_FIREWALL_PROBE 3 exit=1\nRUNFREE_FIREWALL_PROBE 4 exit=1\n"],
  ["extra record", probeRecords([1, 1, 1, 1, 1, 1])],
])("server-UID batch fails closed on a %s", (_kind, stdout) => {
  const issues: string[] = [];
  applyServerUidDenialBatch(issues, captureResult(0, stdout));
  expect(issues).toHaveLength(1);
  expect(issues[0]).toContain("denial batch could not run");
});

test("the callback host probe starts no try once the setup deadline has passed", async () => {
  const started = performance.now();
  const result = await probeMcpCallbackPathWithRetries(1, "challenge", started, () => started + 1);
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("budget ended before the host path was probed");
});

test("a peer that trickles bytes cannot hold a callback host probe past the setup deadline", async () => {
  // The far end of the probe is the in-session bridge: container-controlled.
  // An idle timeout alone would never fire against a byte every 20 ms.
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    const timer = setInterval(() => socket.write("x"), 20);
    socket.on("close", () => clearInterval(timer));
    socket.on("error", () => clearInterval(timer));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  try {
    const started = performance.now();
    const result = await probeMcpCallbackPathWithRetries(port, "challenge", started + 300);
    const elapsed = performance.now() - started;
    expect(result.status).toBe(1);
    expect(elapsed).toBeLessThan(2_000);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

async function loopbackServer(onSocket: (socket: net.Socket) => void, port = 0) {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    onSocket(socket);
  });
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const echoChunks = (socket: net.Socket) => socket.on("data", (chunk) => socket.write(chunk));

test("the callback host probe counts only the echoed challenge", async () => {
  const echo = await loopbackServer(echoChunks);
  const wrong = await loopbackServer((socket) => socket.end("not-the-challenge\n"));
  try {
    expect(await probeMcpCallbackPathWithRetries(echo.port, "challenge-1", performance.now() + 2_000)).toEqual({ status: 0, stdout: "", stderr: "" });
    // A peer that answers anything else is never the proved route.
    const refused = await probeMcpCallbackPathWithRetries(wrong.port, "challenge-1", performance.now() + 250);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toBe("callback host probe closed before echo");
  } finally {
    await echo.close();
    await wrong.close();
  }
});

test("the callback host probe retries a refused route until the forwarder answers", async () => {
  const probe = await loopbackServer(() => {});
  const port = probe.port;
  await probe.close();
  // The first try is refused at once; the retry sleep blocks the event loop,
  // so the listener comes up between tries.
  let late: Awaited<ReturnType<typeof loopbackServer>> | undefined;
  setTimeout(() => {
    void loopbackServer(echoChunks, port).then((server) => {
      late = server;
    });
  }, 30);
  try {
    expect((await probeMcpCallbackPathWithRetries(port, "challenge-2", performance.now() + 2_000)).status).toBe(0);
  } finally {
    await late?.close();
  }
});

type Section = { exit: number; body: string };

function warmEvidence(overrides: Partial<{
  routes: Section[];
  nftTable: Section;
  allowedSet: Section;
  hostServiceSet: Section;
  hostServiceGateway: Section;
  etcHostsStat: Section;
}> = {}) {
  return {
    routes: overrides.routes ?? [
      { exit: 0, body: `${NETWORK.agentIp} dev eth0 src ${NETWORK.proxyIp} uid 1001` },
      { exit: 0, body: `1.1.1.1 via ${NETWORK.proxyEgressGateway} dev eth1 src ${NETWORK.proxyEgressIp} uid 1001` },
    ],
    nftTable: overrides.nftTable ?? { exit: 0, body: proxyNftablesTableJson() },
    allowedSet: overrides.allowedSet ?? { exit: 0, body: "table inet runfree_proxy {\n  set allowed_ipv4 { type ipv4_addr; }\n}" },
    hostServiceSet: overrides.hostServiceSet ?? { exit: 0, body: proxyHostServiceSetJson([{ ip: GATEWAY, port: 5432 }]) },
    hostServiceGateway: overrides.hostServiceGateway ?? { exit: 0, body: gatewayStatus() },
    etcHostsStat: overrides.etcHostsStat ?? ETC_HOSTS_OK,
  };
}

const WARM_HOST_SERVICES = { policyGeneration: POLICY_GENERATION, ports: [5432] } as const;

test("warm firewall evidence is judged with no Docker exec and mints the same nftables proof", () => {
  const fixture = firewallFixture();
  const proof = fixture.run({ expectedEgressSource: NETWORK.proxyEgressIp, warm: warmEvidence(), effectiveHostServices: WARM_HOST_SERVICES });
  expect(fixture.issues).toEqual([]);
  // No Docker call at all: the gateway port probes do not run on a warm match.
  expect(fixture.execs).toEqual([]);
  expect(proof.nftablesProofInput?.rawJson).toBe(proxyNftablesTableJson());
  expect(proof.nftablesProofInput?.internalIface).toBe("eth0");
  expect(proof.nftablesProofInput?.egressIface).toBe("eth1");
  expect(proof.nftablesProofInput?.hostServiceElements).toEqual([{ ip: GATEWAY, port: 5432 }]);
  expect(proof.hostServiceGatewayIp).toBe(GATEWAY);
});

test.each([
  ["a missing route section", warmEvidence({ routes: [{ exit: 0, body: `${NETWORK.agentIp} dev eth0 src ${NETWORK.proxyIp}` }] }), "proxy internal route inspection failed"],
  ["an egress route from another source", warmEvidence({ routes: [
    { exit: 0, body: `${NETWORK.agentIp} dev eth0 src ${NETWORK.proxyIp} uid 1001` },
    { exit: 0, body: `1.1.1.1 via ${NETWORK.proxyEgressGateway} dev eth1 src 172.30.1.99 uid 1001` },
  ] }), "proxy default egress route must use proxy_egress address"],
  ["a failed nftables table read", warmEvidence({ nftTable: { exit: 1, body: "" } }), "proxy nftables owned-table inspection"],
  ["a failed allowlist set read", warmEvidence({ allowedSet: { exit: 1, body: "no such set" } }), "proxy nftables allowlist set inspection failed: no such set"],
  ["an allowlist set without allowed_ipv4", warmEvidence({ allowedSet: { exit: 0, body: "table inet runfree_proxy {}" } }), "proxy firewall must expose the allowed_ipv4 nftables set"],
  ["host_service members that differ", warmEvidence({ hostServiceSet: { exit: 0, body: proxyHostServiceSetJson([]) } }), "host_service members do not match the effective host services"],
  ["an unreadable gateway status", warmEvidence({ hostServiceGateway: { exit: 1, body: "" } }), "proxy host-service gateway status inspection failed"],
  ["a group-writable /etc/hosts", warmEvidence({ etcHostsStat: { exit: 0, body: "0 81b4" } }), "proxy /etc/hosts must be a root-owned regular file"],
])("warm firewall evidence with %s fails closed without falling back to Docker", (_label, warm, issue) => {
  const fixture = firewallFixture();
  fixture.run({ expectedEgressSource: NETWORK.proxyEgressIp, warm, effectiveHostServices: WARM_HOST_SERVICES });
  expect(fixture.issues.some((entry) => entry.includes(issue))).toBe(true);
  expect(fixture.execs).toEqual([]);
});

test("the server-UID batch refuses a gateway probe target that is not an IPv4 literal and a valid port", () => {
  for (const probe of [
    { gatewayIp: "192.168.65.254; reboot", port: 9 },
    { gatewayIp: "192.168.65.999", port: 9 },
    { gatewayIp: "192.168.65.254", port: 0 },
    { gatewayIp: "192.168.65.254", port: 65536 },
  ]) {
    expect(() => serverUidDenialBatchScript(probe)).toThrow("server UID gateway probe needs an IPv4 literal");
  }
  const script = serverUidDenialBatchScript({ gatewayIp: "192.168.65.254", port: 9 });
  expect(script).toContain("for runfree_tool in dig ip nft timeout bash; do");
  expect(script).toContain("RUNFREE_FIREWALL_PROBE 5 exit=%s");
  expect(SERVER_UID_DENIAL_BATCH_SCRIPT).not.toContain("runfree_pid_5");
});
