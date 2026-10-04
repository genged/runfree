type NftStatement = Record<string, unknown>;

type ProxyNftablesTableFixtureInput = {
  internalIface?: string;
  egressIface?: string;
  serverUid?: number;
};

export function nftMatch(left: unknown, right: unknown, op = "=="): { match: { op: string; left: unknown; right: unknown } } {
  return { match: { op, left, right } };
}

export function nftVerdict(verdict: "accept" | "reject" | "drop"): Record<string, null> {
  return { [verdict]: null };
}

export function proxyNftablesTableFixture(input: ProxyNftablesTableFixtureInput = {}): { nftables: NftStatement[] } {
  const internalIface = input.internalIface ?? "eth0";
  const egressIface = input.egressIface ?? "eth1";
  const serverUid = input.serverUid ?? 1001;
  const meta = (key: string) => ({ meta: { key } });
  const payload = (protocol: string, field: string) => ({ payload: { protocol, field } });
  const ct = (key: string) => ({ ct: { key } });
  // `ip daddr . tcp dport` as nft JSON writes a concatenation match.
  const daddrDport = { concat: [payload("ip", "daddr"), payload("tcp", "dport")] };

  return {
    nftables: [
      { metainfo: { json_schema_version: 1 } },
      { table: { family: "inet", name: "runfree_proxy" } },
      { set: { family: "inet", table: "runfree_proxy", name: "allowed_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "session_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "audit_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "audit_draining_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "host_service", type: ["ipv4_addr", "inet_service"], size: 64 } },
      { set: { family: "inet", table: "runfree_proxy", name: "host_service_draining", type: ["ipv4_addr", "inet_service"], size: 64 } },
      { chain: { family: "inet", table: "runfree_proxy", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "input", expr: [nftMatch(meta("iifname"), "lo"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "input", expr: [nftMatch(meta("iifname"), egressIface), nftMatch(meta("nfproto"), "ipv4"), nftMatch(ct("state"), ["established", "related"], "in"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "input", expr: [nftMatch(meta("iifname"), internalIface), nftMatch(payload("ip", "saddr"), "@session_ipv4"), nftMatch(ct("state"), ["established", "related"], "in"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "input", expr: [nftMatch(meta("iifname"), internalIface), nftMatch(payload("ip", "saddr"), "@session_ipv4"), nftMatch(payload("tcp", "dport"), 8080), nftMatch(ct("state"), "new"), nftVerdict("accept")] } },
      { chain: { family: "inet", table: "runfree_proxy", name: "output_dns_guard", type: "filter", hook: "output", prio: -300, policy: "accept" } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output_dns_guard", expr: [nftMatch(meta("skuid"), serverUid), nftMatch(payload("udp", "dport"), 53), nftVerdict("reject")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output_dns_guard", expr: [nftMatch(meta("skuid"), serverUid), nftMatch(payload("tcp", "dport"), 53), nftVerdict("reject")] } },
      { chain: { family: "inet", table: "runfree_proxy", name: "output", type: "filter", hook: "output", prio: 0, policy: "drop" } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), "lo"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), internalIface), nftMatch(payload("ip", "daddr"), "@session_ipv4"), nftMatch(ct("state"), ["established", "related"], "in"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(payload("ip", "daddr"), "@audit_draining_ipv4"), nftVerdict("drop")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(daddrDport, "@host_service_draining"), nftVerdict("drop")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(meta("nfproto"), "ipv4"), nftMatch(ct("state"), ["established", "related"], "in"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(payload("ip", "daddr"), "@allowed_ipv4"), nftMatch(payload("tcp", "dport"), 443), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(payload("ip", "daddr"), "@audit_ipv4"), nftMatch(payload("tcp", "dport"), 443), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(meta("skuid"), serverUid), nftMatch(daddrDport, "@host_service"), nftVerdict("accept")] } },
      { chain: { family: "inet", table: "runfree_proxy", name: "forward", type: "filter", hook: "forward", prio: 0, policy: "drop" } },
    ],
  };
}

export function proxyNftablesTableJson(input: ProxyNftablesTableFixtureInput = {}): string {
  return JSON.stringify(proxyNftablesTableFixture(input));
}

// The output-chain rules in fixture (and production) order, by the label the
// proof reports, so tests address a rule by what it is instead of its index.
export const PROXY_OUTPUT_RULE_LABELS = [
  "loopback output accept",
  "session-set established internal output accept",
  "egress-interface audit drain-drop above established accept",
  "egress-interface host-service drain-drop above established accept",
  "egress-interface established output accept",
  "egress-interface allowlist-backed HTTPS accept",
  "egress-interface audit-set HTTPS accept",
  "egress-interface proxy server UID host-service accept",
] as const;
export type ProxyOutputRuleLabel = typeof PROXY_OUTPUT_RULE_LABELS[number];

/** 1-based position of an output rule, as the proof's issue text numbers it. */
export function proxyOutputRuleNumber(label: ProxyOutputRuleLabel): number {
  return PROXY_OUTPUT_RULE_LABELS.indexOf(label) + 1;
}

/** The proof's issue text for an output rule that does not match its expectation. */
export function proxyOutputRuleIssue(label: ProxyOutputRuleLabel): string {
  return `proxy output rule ${proxyOutputRuleNumber(label)} must match ${label}`;
}

/** The output-chain rule statement with that label in a fixture table. */
export function proxyOutputRule(table: { nftables: NftStatement[] }, label: ProxyOutputRuleLabel): NftStatement {
  const outputRules = table.nftables.filter((statement) => (statement.rule as { chain?: string } | undefined)?.chain === "output");
  const rule = outputRules[PROXY_OUTPUT_RULE_LABELS.indexOf(label)];
  if (!rule) throw new Error(`fixture has no output rule labelled ${label}`);
  return rule;
}

/** Swaps two labelled output rules in place: same rules, different order. */
export function swapProxyOutputRules(
  table: { nftables: NftStatement[] },
  left: ProxyOutputRuleLabel,
  right: ProxyOutputRuleLabel,
): void {
  const leftIndex = table.nftables.indexOf(proxyOutputRule(table, left));
  const rightIndex = table.nftables.indexOf(proxyOutputRule(table, right));
  [table.nftables[leftIndex], table.nftables[rightIndex]] = [table.nftables[rightIndex], table.nftables[leftIndex]];
}

/** `nft -j list set inet runfree_proxy host_service` with these members. */
export function proxyHostServiceSetJson(members: ReadonlyArray<{ ip: string; port: number }>): string {
  return JSON.stringify({
    nftables: [
      { metainfo: { json_schema_version: 1 } },
      {
        set: {
          family: "inet",
          name: "host_service",
          table: "runfree_proxy",
          type: ["ipv4_addr", "inet_service"],
          size: 64,
          ...(members.length > 0 ? { elem: members.map((member) => ({ concat: [member.ip, member.port] })) } : {}),
        },
      },
    ],
  });
}
