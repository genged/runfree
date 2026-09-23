import { expect, test } from "vitest";

import type { RuntimeNetwork } from "../network.ts";
import { proxyNftablesTableJson } from "../proxy-nftables-proof.fixture.ts";
import {
  SERVER_UID_DENIAL_BATCH_SCRIPT,
  SERVER_UID_DENIAL_PROBE_LABELS,
  applyServerUidDenialBatch,
  firewallSectionBatchScript,
  parseFirewallSectionBatch,
  validateProxyFirewall,
} from "./probes.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const PROXY_ID = "f".repeat(64);

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

type FirewallOverrides = {
  routeBatch?: CaptureResult;
  rootBatch?: CaptureResult;
  soloDns?: () => CaptureResult;
  serverBatch?: CaptureResult;
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
        return overrides.rootBatch ?? captureResult(0, sectionOutput([
          { exit: 0, body: "table inet runfree_proxy {\n  set allowed_ipv4 { type ipv4_addr; elements = { 140.82.112.5 } }\n}" },
          { exit: 0, body: "" },
        ]));
      }
      if (text.includes("RUNFREE_FIREWALL_PROBE")) {
        return overrides.serverBatch ?? captureResult(0, probeRecords([1, 1, 1, 1, 1]));
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
  return {
    execs,
    issues,
    run: (options?: Parameters<typeof validateProxyFirewall>[5]) =>
      validateProxyFirewall(issues, context, io, PROXY_ID, NETWORK, options),
  };
}

test("firewall probes merge into one exec per identity group plus the dedicated nft table fetch", () => {
  const fixture = firewallFixture();
  const proof = fixture.run();

  expect(fixture.issues).toEqual([]);
  // Exactly four execs: default-user route batch, dedicated root table fetch,
  // root batch (allowlist + Docker DNS), server-UID denial batch.
  expect(fixture.execs).toHaveLength(4);
  const [routeBatch, tableFetch, rootBatch, serverBatch] = fixture.execs;
  expect(routeBatch.slice(0, 2)).toEqual(["exec", PROXY_ID]);
  expect(tableFetch).toEqual(["exec", "--user", "0:0", PROXY_ID, "nft", "-j", "list", "table", "inet", "runfree_proxy"]);
  expect(rootBatch.slice(0, 3)).toEqual(["exec", "--user", "0:0"]);
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
    rootBatch: captureResult(0, sectionOutput([
      { exit: 0, body: "table inet runfree_proxy {\n  set allowed_ipv4 { type ipv4_addr; elements = { 140.82.112.5 } }\n}" },
      { exit: 1, body: "one lost UDP query" },
    ])),
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

test("a missing or garbled root batch fails both sections closed without retrying anything", () => {
  const fixture = firewallFixture({
    rootBatch: captureResult(0, "RUNFREE_FIREWALL_SECTION 0 exit=0\ntruncated"),
  });
  fixture.run();

  expect(fixture.issues.some((issue) => issue.includes("proxy nftables allowlist set inspection failed"))).toBe(true);
  expect(fixture.issues.some((issue) => issue.includes("proxy root Docker DNS failed"))).toBe(true);
  // Route batch, table fetch, root batch, server batch — and no solo retry.
  expect(fixture.execs).toHaveLength(4);
});

test("DNS failure retains bounded diagnostics and every attempt without retrying denials", () => {
  let soloDnsAttempts = 0;
  const fixture = firewallFixture({
    rootBatch: captureResult(0, sectionOutput([
      { exit: 0, body: "set allowed_ipv4" },
      { exit: 124, body: "first query interrupted" },
    ])),
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
