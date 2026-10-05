import { describe, expect, test } from "vitest";

import {
  proxyHostServiceSetJson,
  proxyNftablesTableFixture,
  proxyOutputRule,
  proxyOutputRuleIssue,
  swapProxyOutputRules,
} from "./proxy-nftables-proof.fixture.ts";
import { parseHostServiceSetMembers, validateProxyNftablesTableJson } from "./proxy-nftables-proof.ts";

// The runtime is session-only: production carries no fixed-agent bridge rules
// and the proof validator cannot even express a fixed-agent expectation, so a
// lingering bridge rule reads as an unexpected extra rule and fails closed.
const proofInput = {
  internalIface: "eth0",
  egressIface: "eth1",
  serverUid: "1001",
};

function sessionOnlyTable(): ReturnType<typeof proxyNftablesTableFixture> {
  return proxyNftablesTableFixture();
}

// Injects a retired fixed-agent accept rule into the input chain, modelling a
// leftover pre-cutover bridge rule in an otherwise session-only table.
function withFixedAgentBridgeRule(): ReturnType<typeof proxyNftablesTableFixture> {
  const table = sessionOnlyTable();
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
  return table;
}

describe("proxy nftables runtime proof", () => {
  test("accepts the exact owned session-only table shape", () => {
    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(sessionOnlyTable()),
    })).toEqual([]);
  });

  test("rejects a lingering fixed-agent bridge rule in the session-only shape", () => {
    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(withFixedAgentBridgeRule()),
    }).length).toBeGreaterThan(0);
  });

  test("accepts singleton ct state sets in session-set new proxy-port rules", () => {
    const table = sessionOnlyTable();
    for (const statement of table.nftables) {
      const rule = statement.rule as { chain?: string; expr?: Array<{ match?: { left?: unknown; right?: unknown; op?: string } }> } | undefined;
      const newProxyPort = rule?.chain === "input" && rule.expr?.some((entry) => {
        const left = entry.match?.left as { payload?: { protocol?: string; field?: string } } | undefined;
        return left?.payload?.protocol === "tcp" && left.payload.field === "dport" && entry.match?.right === 8080;
      });
      const stateMatch = rule?.expr?.find((entry) => {
        const left = entry.match?.left as { ct?: { key?: string } } | undefined;
        return left?.ct?.key === "state";
      });
      if (newProxyPort && stateMatch?.match) {
        stateMatch.match.op = "in";
        stateMatch.match.right = { set: ["new"] };
        break;
      }
    }

    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    })).toEqual([]);
  });
});

describe("proxy nftables session-only ruleset mutations", () => {

  test("rejects inverted allowlist operators", () => {
    const table = sessionOnlyTable();
    for (const statement of table.nftables) {
      const rule = statement.rule as { chain?: string; expr?: Array<{ match?: { left?: unknown; right?: unknown; op?: string } }> } | undefined;
      const match = rule?.expr?.find((entry) => {
        const left = entry.match?.left as { payload?: { protocol?: string; field?: string } } | undefined;
        return rule.chain === "output"
          && left?.payload?.protocol === "ip"
          && left.payload.field === "daddr"
          && entry.match?.right === "@allowed_ipv4";
      });
      if (match?.match) {
        match.match.op = "!=";
        break;
      }
    }

    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    })).toContain(proxyOutputRuleIssue("egress-interface allowlist-backed HTTPS accept"));
  });

  test("rejects tables missing the always-present audit sets", () => {
    const table = sessionOnlyTable();
    table.nftables = table.nftables.filter((statement) => {
      const set = statement.set as { name?: string } | undefined;
      return set?.name !== "audit_ipv4";
    });

    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    })).toContain("proxy firewall must install the audit_ipv4 IPv4 nftables set");
  });

  test("rejects a missing session admission set", () => {
    const table = sessionOnlyTable();
    table.nftables = table.nftables.filter((statement) => {
      const set = statement.set as { name?: string } | undefined;
      return set?.name !== "session_ipv4";
    });

    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    })).toContain("proxy firewall must install the session_ipv4 IPv4 nftables set");
  });


  test("rejects any owned set broadened to interval addresses", () => {
    for (const setName of ["allowed_ipv4", "session_ipv4", "audit_ipv4", "audit_draining_ipv4", "host_service", "host_service_draining"]) {
      const table = sessionOnlyTable();
      for (const statement of table.nftables) {
        const set = statement.set as { name?: string; flags?: string[] } | undefined;
        if (set?.name === setName) {
          set.flags = ["interval"];
          break;
        }
      }

      expect(validateProxyNftablesTableJson({
        ...proofInput,
        rawJson: JSON.stringify(table),
      })).toContain(`proxy firewall must install the ${setName} set without interval or wildcard flags`);
    }
  });

  test("rejects missing session admission rules", () => {
    const table = sessionOnlyTable();
    table.nftables = table.nftables.filter((statement) => {
      const rule = statement.rule as { expr?: Array<{ match?: { right?: unknown } }> } | undefined;
      return !rule?.expr?.some((entry) => entry.match?.right === "@session_ipv4");
    });

    const issues = validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    });
    expect(issues).toContain("proxy input chain must contain exactly 4 rules; got 2");
    expect(issues).toContain("proxy output chain must contain exactly 9 rules; got 8");
  });

  test("rejects a session ingress rule broadened beyond the admission set", () => {
    const table = sessionOnlyTable();
    for (const statement of table.nftables) {
      const rule = statement.rule as { chain?: string; expr?: Array<{ match?: { left?: unknown; right?: unknown } }> } | undefined;
      const sessionProxyIngress = rule?.chain === "input"
        && rule.expr?.some((entry) => entry.match?.right === "@session_ipv4")
        && rule.expr.some((entry) => entry.match?.right === 8080);
      if (sessionProxyIngress && rule.expr) {
        rule.expr = rule.expr.filter((entry) => entry.match?.right !== "@session_ipv4");
        break;
      }
    }

    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    })).toContain("proxy input rule 4 must match session-set new proxy-port accept");
  });

  test("rejects reordered session ingress rules", () => {
    const table = sessionOnlyTable();
    const inputRules = table.nftables.filter((statement) => {
      const rule = statement.rule as { chain?: string } | undefined;
      return rule?.chain === "input";
    });
    const establishedIndex = table.nftables.indexOf(inputRules[2]);
    const newIndex = table.nftables.indexOf(inputRules[3]);
    [table.nftables[establishedIndex], table.nftables[newIndex]] = [table.nftables[newIndex], table.nftables[establishedIndex]];

    const issues = validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    });
    expect(issues).toContain("proxy input rule 3 must match session-set established ingress accept");
    expect(issues).toContain("proxy input rule 4 must match session-set new proxy-port accept");
  });

  test("rejects broadened or reordered session return-traffic rules", () => {
    const broadened = sessionOnlyTable();
    for (const statement of broadened.nftables) {
      const rule = statement.rule as { chain?: string; expr?: Array<{ match?: { right?: unknown } }> } | undefined;
      const sessionDestination = rule?.chain === "output"
        ? rule.expr?.find((entry) => entry.match?.right === "@session_ipv4")
        : undefined;
      if (sessionDestination?.match) {
        sessionDestination.match.right = "0.0.0.0/0";
        break;
      }
    }
    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(broadened),
    })).toContain(proxyOutputRuleIssue("session-set established internal output accept"));

    const reordered = sessionOnlyTable();
    swapProxyOutputRules(
      reordered,
      "session-set established internal output accept",
      "egress-interface audit drain-drop above established accept",
    );
    const reorderedIssues = validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(reordered),
    });
    expect(reorderedIssues).toContain(proxyOutputRuleIssue("session-set established internal output accept"));
    expect(reorderedIssues).toContain(proxyOutputRuleIssue("egress-interface audit drain-drop above established accept"));
  });

  test("rejects a drain-drop rule placed below the egress established accept", () => {
    // Same rules, severance-breaking order.
    const table = sessionOnlyTable();
    swapProxyOutputRules(
      table,
      "egress-interface audit drain-drop above established accept",
      "egress-interface established output accept",
    );

    const issues = validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    });
    expect(issues).toContain(proxyOutputRuleIssue("egress-interface audit drain-drop above established accept"));
    expect(issues).toContain(proxyOutputRuleIssue("egress-interface established output accept"));
  });

  test("rejects protocol-neutral non-loopback established accepts", () => {
    const table = sessionOnlyTable();
    for (const statement of table.nftables) {
      const rule = statement.rule as { chain?: string; expr?: Array<{ match?: { left?: unknown } }> } | undefined;
      const expr = rule?.expr;
      const egressEstablished = expr?.some((entry) => {
        const match = entry.match as { left?: unknown; right?: unknown } | undefined;
        const left = match?.left as { meta?: { key?: string } } | undefined;
        return left?.meta?.key === "oifname" && match?.right === "eth1";
      }) && expr.some((entry) => {
        const left = entry.match?.left as { ct?: { key?: string } } | undefined;
        return left?.ct?.key === "state";
      });
      if (rule?.chain === "output" && egressEstablished && expr) {
        rule.expr = expr.filter((entry) => {
          const left = entry.match?.left as { meta?: { key?: string } } | undefined;
          return left?.meta?.key !== "nfproto";
        });
        break;
      }
    }

    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    })).toContain(proxyOutputRuleIssue("egress-interface established output accept"));
  });
});

type FixtureRule = { expr: Array<Record<string, unknown> & { match?: { left?: unknown; right?: unknown } }> };

describe("proxy nftables host-service sets and rules", () => {
  test("rejects host_service typed as a plain IPv4 set instead of address . port", () => {
    for (const setName of ["host_service", "host_service_draining"]) {
      const table = sessionOnlyTable();
      const set = table.nftables.find((statement) => (statement.set as { name?: string } | undefined)?.name === setName)
        ?.set as { type?: unknown };
      set.type = "ipv4_addr";

      const issues = validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(table) });
      expect(issues.some((issue) => issue.includes(setName))).toBe(true);
    }
  });

  test("rejects host_service_gateways missing or typed as address . port (R19)", () => {
    const missing = sessionOnlyTable();
    missing.nftables = missing.nftables.filter((statement) => (statement.set as { name?: string } | undefined)?.name !== "host_service_gateways");
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(missing) }))
      .toContain("proxy firewall must install the host_service_gateways IPv4 nftables set");

    const concat = sessionOnlyTable();
    const set = concat.nftables.find((statement) => (statement.set as { name?: string } | undefined)?.name === "host_service_gateways")
      ?.set as { type?: unknown };
    set.type = ["ipv4_addr", "inet_service"];
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(concat) }))
      .toContain("proxy firewall must install the host_service_gateways IPv4 nftables set");
  });

  test("rejects the pinned-gateway cut with a non-negated lookup, without the gateway match, or below the established accept (R19)", () => {
    const label = "egress-interface pinned-gateway cut of unapproved pairs above established accept" as const;
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(sessionOnlyTable()) })).toEqual([]);

    // `==` would drop the approved pairs and let every unapproved one pass.
    const positive = sessionOnlyTable();
    for (const entry of (proxyOutputRule(positive, label).rule as FixtureRule).expr) {
      if (entry.match && entry.match.right === "@host_service") (entry.match as { op?: string }).op = "==";
    }
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(positive) }))
      .toContain(proxyOutputRuleIssue(label));

    // Without the gateway half the rule would also drop public HTTPS.
    const noGateway = sessionOnlyTable();
    const noGatewayRule = proxyOutputRule(noGateway, label).rule as FixtureRule;
    noGatewayRule.expr = noGatewayRule.expr.filter((entry) => entry.match?.right !== "@host_service_gateways");
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(noGateway) }))
      .toContain(proxyOutputRuleIssue(label));

    // Negated against the draining set instead of the accept set.
    const wrongSet = sessionOnlyTable();
    for (const entry of (proxyOutputRule(wrongSet, label).rule as FixtureRule).expr) {
      if (entry.match && entry.match.right === "@host_service") entry.match.right = "@host_service_draining";
    }
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(wrongSet) }))
      .toContain(proxyOutputRuleIssue(label));

    // An accept verdict instead of drop.
    const accepting = sessionOnlyTable();
    const acceptingRule = proxyOutputRule(accepting, label).rule as FixtureRule;
    acceptingRule.expr = acceptingRule.expr.map((entry) => (Object.hasOwn(entry, "drop") ? { accept: null } : entry));
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(accepting) }))
      .toContain(proxyOutputRuleIssue(label));

    const below = sessionOnlyTable();
    swapProxyOutputRules(below, label, "egress-interface established output accept");
    const issues = validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(below) });
    expect(issues).toContain(proxyOutputRuleIssue(label));
    expect(issues).toContain(proxyOutputRuleIssue("egress-interface established output accept"));
  });

  test("rejects a missing host-service set", () => {
    const table = sessionOnlyTable();
    table.nftables = table.nftables.filter((statement) => (statement.set as { name?: string } | undefined)?.name !== "host_service_draining");

    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(table) }))
      .toContain("proxy firewall must install the host_service_draining IPv4 address . port nftables set");
  });

  test("rejects a plain IPv4 set typed as address . port", () => {
    const table = sessionOnlyTable();
    const set = table.nftables.find((statement) => (statement.set as { name?: string } | undefined)?.name === "allowed_ipv4")
      ?.set as { type?: unknown };
    set.type = ["ipv4_addr", "inet_service"];

    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(table) }))
      .toContain("proxy firewall must install the allowed_ipv4 IPv4 nftables set");
  });

  test("rejects the host_service accept without the proxy server UID match", () => {
    // Without `meta skuid 1001` root would also reach the host gateway.
    const table = sessionOnlyTable();
    const rule = proxyOutputRule(table, "egress-interface proxy server UID host-service accept").rule as FixtureRule;
    rule.expr = rule.expr.filter((entry) => (entry.match?.left as { meta?: { key?: string } } | undefined)?.meta?.key !== "skuid");

    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(table) }))
      .toContain(proxyOutputRuleIssue("egress-interface proxy server UID host-service accept"));
  });

  test("rejects the host_service accept for another UID or a plain address match", () => {
    const otherUid = sessionOnlyTable();
    const uidRule = proxyOutputRule(otherUid, "egress-interface proxy server UID host-service accept").rule as FixtureRule;
    for (const entry of uidRule.expr) {
      if ((entry.match?.left as { meta?: { key?: string } } | undefined)?.meta?.key === "skuid" && entry.match) entry.match.right = 0;
    }
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(otherUid) }))
      .toContain(proxyOutputRuleIssue("egress-interface proxy server UID host-service accept"));

    // `ip daddr @host_service` without the port half matches every port.
    const addressOnly = sessionOnlyTable();
    const addressRule = proxyOutputRule(addressOnly, "egress-interface proxy server UID host-service accept").rule as FixtureRule;
    for (const entry of addressRule.expr) {
      if (entry.match && entry.match.right === "@host_service") entry.match.left = { payload: { protocol: "ip", field: "daddr" } };
    }
    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(addressOnly) }))
      .toContain(proxyOutputRuleIssue("egress-interface proxy server UID host-service accept"));
  });

  test("rejects the host-service drain-drop placed below the egress established accept", () => {
    const table = sessionOnlyTable();
    swapProxyOutputRules(
      table,
      "egress-interface host-service drain-drop above established accept",
      "egress-interface established output accept",
    );

    const issues = validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(table) });
    expect(issues).toContain(proxyOutputRuleIssue("egress-interface host-service drain-drop above established accept"));
    expect(issues).toContain(proxyOutputRuleIssue("egress-interface established output accept"));
  });

  test("rejects a host-service drain-drop that drops the wrong set", () => {
    const table = sessionOnlyTable();
    const rule = proxyOutputRule(table, "egress-interface host-service drain-drop above established accept").rule as FixtureRule;
    for (const entry of rule.expr) {
      if (entry.match && entry.match.right === "@host_service_draining") entry.match.right = "@host_service";
    }

    expect(validateProxyNftablesTableJson({ ...proofInput, rawJson: JSON.stringify(table) }))
      .toContain(proxyOutputRuleIssue("egress-interface host-service drain-drop above established accept"));
  });

  test("accepts host_service members equal to the effective host services, in any order", () => {
    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(sessionOnlyTable()),
      hostServiceElements: [{ ip: "192.168.65.254", port: 10882 }, { ip: "192.168.65.254", port: 5432 }],
      expectedHostServiceElements: [{ ip: "192.168.65.254", port: 5432 }, { ip: "192.168.65.254", port: 10882 }],
    })).toEqual([]);
    expect(validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(sessionOnlyTable()),
      hostServiceElements: [],
      expectedHostServiceElements: [],
    })).toEqual([]);
  });

  test("rejects host_service members that differ from the effective host services", () => {
    const mismatch = (hostServiceElements: Array<{ ip: string; port: number }>) => validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(sessionOnlyTable()),
      hostServiceElements,
      expectedHostServiceElements: [{ ip: "192.168.65.254", port: 5432 }],
    }).some((issue) => issue.startsWith("host_service members do not match the effective host services"));

    expect(mismatch([])).toBe(true);
    expect(mismatch([{ ip: "192.168.65.254", port: 5432 }, { ip: "192.168.65.254", port: 6379 }])).toBe(true);
    expect(mismatch([{ ip: "192.168.65.253", port: 5432 }])).toBe(true);
    expect(mismatch([{ ip: "192.168.65.254", port: 5433 }])).toBe(true);
    expect(mismatch([{ ip: "192.168.65.254", port: 5432 }])).toBe(false);
  });
});

describe("host_service set member parsing", () => {
  test("reads concat members from nft JSON, and an empty set as no members", () => {
    expect(parseHostServiceSetMembers(proxyHostServiceSetJson([
      { ip: "192.168.65.254", port: 5432 },
      { ip: "192.168.65.254", port: 10882 },
    ]))).toEqual([{ ip: "192.168.65.254", port: 5432 }, { ip: "192.168.65.254", port: 10882 }]);
    expect(parseHostServiceSetMembers(proxyHostServiceSetJson([]))).toEqual([]);
  });

  test("reads members wrapped with element options", () => {
    const raw = JSON.stringify({
      nftables: [{
        set: {
          family: "inet", name: "host_service", table: "runfree_proxy", type: ["ipv4_addr", "inet_service"],
          elem: [{ elem: { val: { concat: ["192.168.65.254", 5432] }, timeout: 30 } }],
        },
      }],
    });
    expect(parseHostServiceSetMembers(raw)).toEqual([{ ip: "192.168.65.254", port: 5432 }]);
  });

  test("refuses anything that is not exactly the owned host_service set", () => {
    const set = (overrides: Record<string, unknown>) => JSON.stringify({
      nftables: [{
        set: {
          family: "inet", name: "host_service", table: "runfree_proxy", type: ["ipv4_addr", "inet_service"],
          elem: [{ concat: ["192.168.65.254", 5432] }],
          ...overrides,
        },
      }],
    });
    for (const raw of [
      "{not json",
      JSON.stringify({ nftables: [] }),
      set({ name: "host_service_draining" }),
      set({ table: "other" }),
      set({ family: "ip" }),
      set({ elem: [{ concat: ["192.168.65.254"] }] }),
      set({ elem: [{ concat: ["192.168.65.999", 5432] }] }),
      set({ elem: [{ concat: ["192.168.65.254", 0] }] }),
      set({ elem: [{ concat: ["192.168.65.254", "5432"] }] }),
      set({ elem: ["192.168.65.254"] }),
      set({ elem: "192.168.65.254 . 5432" }),
      JSON.stringify({ nftables: [JSON.parse(set({})).nftables[0], JSON.parse(set({})).nftables[0]] }),
    ]) {
      expect(parseHostServiceSetMembers(raw)).toBeUndefined();
    }
  });
});
