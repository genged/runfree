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

  return {
    nftables: [
      { metainfo: { json_schema_version: 1 } },
      { table: { family: "inet", name: "runfree_proxy" } },
      { set: { family: "inet", table: "runfree_proxy", name: "allowed_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "session_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "audit_ipv4", type: "ipv4_addr" } },
      { set: { family: "inet", table: "runfree_proxy", name: "audit_draining_ipv4", type: "ipv4_addr" } },
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
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(meta("nfproto"), "ipv4"), nftMatch(ct("state"), ["established", "related"], "in"), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(payload("ip", "daddr"), "@allowed_ipv4"), nftMatch(payload("tcp", "dport"), 443), nftVerdict("accept")] } },
      { rule: { family: "inet", table: "runfree_proxy", chain: "output", expr: [nftMatch(meta("oifname"), egressIface), nftMatch(payload("ip", "daddr"), "@audit_ipv4"), nftMatch(payload("tcp", "dport"), 443), nftVerdict("accept")] } },
      { chain: { family: "inet", table: "runfree_proxy", name: "forward", type: "filter", hook: "forward", prio: 0, policy: "drop" } },
    ],
  };
}

export function proxyNftablesTableJson(input: ProxyNftablesTableFixtureInput = {}): string {
  return JSON.stringify(proxyNftablesTableFixture(input));
}
