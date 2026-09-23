import crypto from "node:crypto";

import { expect, test } from "vitest";

import { proxyNftablesTableJson } from "../proxy-nftables-proof.fixture.ts";
import type { ProxyNftablesProofInput } from "../proxy-nftables-proof.ts";
import {
  assertDenyByDefaultFirewallObservationV1,
  observeDenyByDefaultViaFirewallV1,
  type DenyByDefaultFirewallObservationV1,
} from "./control-plane-deny-proof.ts";

const PROJECT_ID = "a".repeat(12);
const GENERATION = `sha256:${"b".repeat(64)}`;
const PROXY_ID = "d".repeat(64);

// A valid session-only (@session_ipv4-only) live nft table: INPUT policy drop,
// no fixed-agent accept rule, the session set the sole agent->proxy path — the
// exact ruleset that proves post-cutover deny-by-default for every unadmitted
// source. The proof input carries no agentIp, matching that session-only shape.
function sessionOnlyProofInput(
  overrides: Partial<ProxyNftablesProofInput> = {},
): ProxyNftablesProofInput {
  return {
    rawJson: proxyNftablesTableJson(),
    internalIface: "eth0",
    egressIface: "eth1",
    serverUid: "1001",
    ...overrides,
  };
}

function firewallProof(nftables: ProxyNftablesProofInput = sessionOnlyProofInput()) {
  return observeDenyByDefaultViaFirewallV1({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: GENERATION,
    proxyContainerId: PROXY_ID,
    nftables,
  });
}

test("mints one sealed firewall observation from the exact validated session-only ruleset", () => {
  const nftables = sessionOnlyProofInput();
  const observation = firewallProof(nftables);
  expect(() => assertDenyByDefaultFirewallObservationV1(observation)).not.toThrow();
  expect(observation).toMatchObject({
    origin: "proxy-firewall",
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: GENERATION,
    proxyContainerId: PROXY_ID,
  });
  // The receipt hashes the exact live nft JSON string that was validated.
  expect(observation.nftablesTableSha256).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(observation.nftablesTableSha256).toBe(
    `sha256:${crypto.createHash("sha256").update(nftables.rawJson).digest("hex")}`,
  );
});

// FAIL CLOSED: whenever validateProxyNftablesTableJson reports any issue, the
// mint throws and no observation is produced. Each case models a ruleset that
// would let an unadmitted source through, or evidence that isn't a ruleset.
test.each([
  ["malformed table JSON", sessionOnlyProofInput({ rawJson: "{ not json" })],
  ["empty inspection output", sessionOnlyProofInput({ rawJson: "" })],
  ["a lingering fixed-agent accept rule", sessionOnlyProofInput({ rawJson: fixedAgentResidueTableJson() })],
  ["a non-drop INPUT policy", sessionOnlyProofInput({ rawJson: wrongInputPolicyTableJson() })],
  ["a missing session gate", sessionOnlyProofInput({ rawJson: missingSessionGateTableJson() })],
] as const)("fails closed on %s, minting nothing", (_label, nftables) => {
  expect(() => firewallProof(nftables)).toThrow("rejected the live ruleset");
});

test.each([
  ["invalid project id", { projectId: "nope" }, "invalid project identity"],
  ["invalid control-plane generation", { controlPlaneGenerationDigest: "sha256:short" }, "invalid control-plane generation"],
  ["truncated proxy id", { proxyContainerId: PROXY_ID.slice(0, 12) }, "invalid container identity"],
] as const)("rejects %s before validating the ruleset", (_label, override, message) => {
  expect(() => observeDenyByDefaultViaFirewallV1({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: GENERATION,
    proxyContainerId: PROXY_ID,
    nftables: sessionOnlyProofInput(),
    ...override,
  })).toThrow(message);
});

test("rejects forged firewall observations, including a hand-built lookalike", () => {
  const forged = {
    ...firewallProof(),
    nftablesTableSha256: `sha256:${"e".repeat(64)}`,
  } as DenyByDefaultFirewallObservationV1;
  expect(() => assertDenyByDefaultFirewallObservationV1(forged)).toThrow("not minted");

  // A structurally identical object minted outside the observer is not sealed,
  // so origin cannot be claimed by construction.
  const lookalike = {
    ...JSON.parse(JSON.stringify(firewallProof())),
  } as DenyByDefaultFirewallObservationV1;
  expect(() => assertDenyByDefaultFirewallObservationV1(lookalike)).toThrow("not minted");
});

// A live table carrying a retired fixed-agent accept rule: a standing accept
// for a fixed source address bypasses source-IP admission, and the validator
// can no longer even express a fixed-agent expectation, so this must never
// mint.
function fixedAgentResidueTableJson(): string {
  const table = JSON.parse(proxyNftablesTableJson()) as {
    nftables: Array<Record<string, unknown>>;
  };
  const firstInputRuleIndex = table.nftables.findIndex((statement) => {
    const rule = statement.rule as { chain?: string } | undefined;
    return rule?.chain === "input";
  });
  table.nftables.splice(firstInputRuleIndex, 0, {
    rule: {
      family: "inet",
      table: "runfree_proxy",
      chain: "input",
      expr: [
        { match: { op: "==", left: { meta: { key: "iifname" } }, right: "eth0" } },
        { match: { op: "==", left: { payload: { protocol: "ip", field: "saddr" } }, right: "172.31.90.11" } },
        { match: { op: "in", left: { ct: { key: "state" } }, right: ["established", "related"] } },
        { accept: null },
      ],
    },
  });
  return JSON.stringify(table);
}

// A live table whose INPUT chain accepts by default: an unadmitted source is no
// longer dropped at L3, so this must never mint.
function wrongInputPolicyTableJson(): string {
  const table = JSON.parse(proxyNftablesTableJson()) as {
    nftables: Array<{ chain?: { name?: string; policy?: string } }>;
  };
  for (const statement of table.nftables) {
    if (statement.chain?.name === "input") statement.chain.policy = "accept";
  }
  return JSON.stringify(table);
}

// A live table with the @session_ipv4 accept rules removed: with policy drop but
// no session gate, no admitted source could reach the proxy either — the ruleset
// is not the sanctioned deny-by-default shape, so this must never mint.
function missingSessionGateTableJson(): string {
  const table = JSON.parse(proxyNftablesTableJson()) as {
    nftables: Array<{ rule?: { expr?: Array<{ match?: { right?: unknown } }> } }>;
  };
  table.nftables = table.nftables.filter((statement) => {
    return !statement.rule?.expr?.some((entry) => entry.match?.right === "@session_ipv4");
  });
  return JSON.stringify(table);
}
