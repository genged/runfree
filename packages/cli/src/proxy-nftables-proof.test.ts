import { describe, expect, test } from "vitest";

import { proxyNftablesTableFixture } from "./proxy-nftables-proof.fixture.ts";
import { validateProxyNftablesTableJson } from "./proxy-nftables-proof.ts";

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
    })).toContain("proxy output rule 5 must match egress-interface allowlist-backed HTTPS accept");
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

  test("rejects any owned IPv4 set broadened to interval addresses", () => {
    for (const setName of ["allowed_ipv4", "session_ipv4", "audit_ipv4", "audit_draining_ipv4"]) {
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
    expect(issues).toContain("proxy output chain must contain exactly 6 rules; got 5");
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
    })).toContain("proxy output rule 2 must match session-set established internal output accept");

    const reordered = sessionOnlyTable();
    const outputRules = reordered.nftables.filter((statement) => {
      const rule = statement.rule as { chain?: string } | undefined;
      return rule?.chain === "output";
    });
    const sessionIndex = reordered.nftables.indexOf(outputRules[1]);
    const drainIndex = reordered.nftables.indexOf(outputRules[2]);
    [reordered.nftables[sessionIndex], reordered.nftables[drainIndex]] = [
      reordered.nftables[drainIndex],
      reordered.nftables[sessionIndex],
    ];
    const reorderedIssues = validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(reordered),
    });
    expect(reorderedIssues).toContain("proxy output rule 2 must match session-set established internal output accept");
    expect(reorderedIssues).toContain("proxy output rule 3 must match egress-interface audit drain-drop above established accept");
  });

  test("rejects a drain-drop rule placed below the egress established accept", () => {
    const table = sessionOnlyTable();
    const outputRules = table.nftables.filter((statement) => {
      const rule = statement.rule as { chain?: string } | undefined;
      return rule?.chain === "output";
    });
    // Swap the drain-drop (output rule 3) with the egress established accept
    // (output rule 4): same rules, severance-breaking order.
    const drainIndex = table.nftables.indexOf(outputRules[2]);
    const establishedIndex = table.nftables.indexOf(outputRules[3]);
    [table.nftables[drainIndex], table.nftables[establishedIndex]] = [table.nftables[establishedIndex], table.nftables[drainIndex]];

    const issues = validateProxyNftablesTableJson({
      ...proofInput,
      rawJson: JSON.stringify(table),
    });
    expect(issues).toContain("proxy output rule 3 must match egress-interface audit drain-drop above established accept");
    expect(issues).toContain("proxy output rule 4 must match egress-interface established output accept");
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
    })).toContain("proxy output rule 4 must match egress-interface established output accept");
  });
});
