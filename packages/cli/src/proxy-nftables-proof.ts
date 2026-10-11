import {
  hostServiceEntryKey,
  sortHostServiceEntries,
  type HostServiceSetEntry,
} from "@runfree/runtime-contracts/proxy-status";

import { isRecord } from "./strict-primitives.ts";
export type ProxyNftablesProofInput = {
  rawJson: string;
  internalIface: string;
  egressIface: string;
  proxyPort?: number;
  serverUid?: string;
  tableName?: string;
  setName?: string;
  /** Kernel members of `@host_service` (`nft -j list set ... host_service`). */
  hostServiceElements?: HostServiceSetEntry[];
  /** The effective policy's host-service ports paired with the published gateway. */
  expectedHostServiceElements?: HostServiceSetEntry[];
};

type NftJsonStatement = {
  table?: NftTable;
  set?: NftSet;
  chain?: NftChain;
  rule?: NftRule;
  metainfo?: unknown;
};

type NftTable = {
  family?: unknown;
  name?: unknown;
};

type NftSet = {
  family?: unknown;
  table?: unknown;
  name?: unknown;
  type?: unknown;
  flags?: unknown;
};

type NftChain = {
  family?: unknown;
  table?: unknown;
  name?: unknown;
  type?: unknown;
  hook?: unknown;
  prio?: unknown;
  priority?: unknown;
  policy?: unknown;
};

type NftRule = {
  family?: unknown;
  table?: unknown;
  chain?: unknown;
  expr?: unknown;
};

type NftRuleExpectation = {
  label: string;
  exprCount: number;
  matches(expr: readonly unknown[]): boolean;
};

const DEFAULT_TABLE_NAME = "runfree_proxy";
const DEFAULT_SET_NAME = "allowed_ipv4";
const DEFAULT_SESSION_SET_NAME = "session_ipv4";
const DEFAULT_AUDIT_SET_NAME = "audit_ipv4";
const DEFAULT_AUDIT_DRAINING_SET_NAME = "audit_draining_ipv4";
const HOST_SERVICE_SET_NAME = "host_service";
const HOST_SERVICE_DRAINING_SET_NAME = "host_service_draining";
const HOST_SERVICE_GATEWAY_SET_NAME = "host_service_gateways";
// `ipv4_addr . inet_service`, as nft JSON writes a concatenated set type.
const HOST_SERVICE_SET_TYPE = ["ipv4_addr", "inet_service"] as const;
const IPV4_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
const STRICT_IPV4_RE = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);
const DEFAULT_PROXY_PORT = 8080;
const DEFAULT_SERVER_UID = "1001";
const EXPECTED_CHAINS = ["input", "output_dns_guard", "output", "forward"] as const;
type ExpectedChain = typeof EXPECTED_CHAINS[number];


function parseNftJsonTable(raw: string): NftJsonStatement[] | undefined {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed) || !Array.isArray(parsed.nftables)) return undefined;
    return parsed.nftables.filter(isRecord) as NftJsonStatement[];
  } catch {
    return undefined;
  }
}

function nftStatementOwned(statement: { family?: unknown; table?: unknown } | undefined, tableName: string): boolean {
  return statement?.family === "inet" && statement.table === tableName;
}

function nftTableOwned(table: NftTable | undefined, tableName: string): boolean {
  return table?.family === "inet" && table.name === tableName;
}

function nftRightEquals(actual: unknown, expected: string | number | readonly string[]): boolean {
  if (Array.isArray(expected)) {
    if (Array.isArray(actual)) return expected.length === actual.length && expected.every((value, index) => actual[index] === value);
    const actualSet = isRecord(actual) ? actual.set : undefined;
    if (Array.isArray(actualSet)) {
      return expected.length === actualSet.length && expected.every((value, index) => actualSet[index] === value);
    }
    if (typeof actual === "string") return expected.join(",") === actual.replace(/\s+/g, "");
    return false;
  }
  if (Array.isArray(actual)) return actual.length === 1 && String(actual[0]) === String(expected);
  if (isRecord(actual) && typeof expected === "string" && expected.startsWith("@")) {
    const actualSet = actual.set;
    if (Array.isArray(actualSet)) return actualSet.length === 1 && (actualSet[0] === expected || actualSet[0] === expected.slice(1));
    return actualSet === expected || actualSet === expected.slice(1);
  }
  if (typeof actual === "number" || typeof actual === "string") return String(actual) === String(expected);
  return false;
}

function nftLeftMatches(left: unknown, kind: "meta" | "ct" | "payload", expected: Record<string, string>): boolean {
  if (!isRecord(left)) return false;
  const value = left[kind];
  if (!isRecord(value)) return false;
  return Object.entries(expected).every(([key, expectedValue]) => value[key] === expectedValue);
}

// `ip daddr . tcp dport`: exactly the two payload halves, in that order.
function nftLeftIsDaddrDportConcat(left: unknown): boolean {
  if (!isRecord(left) || !Array.isArray(left.concat) || left.concat.length !== 2) return false;
  const [address, port] = left.concat as unknown[];
  return isRecord(address) && Object.keys(address).length === 1 && nftLeftMatches(address, "payload", { protocol: "ip", field: "daddr" })
    && isRecord(port) && Object.keys(port).length === 1 && nftLeftMatches(port, "payload", { protocol: "tcp", field: "dport" });
}

function nftExprHasMatch(
  expr: readonly unknown[],
  left:
    | { kind: "meta"; key: string }
    | { kind: "ct"; key: string }
    | { kind: "payload"; protocol: string; field: string }
    | { kind: "concat-daddr-dport" },
  right: string | number | readonly string[],
  op = "==",
): boolean {
  return expr.some((entry) => {
    if (!isRecord(entry) || !isRecord(entry.match)) return false;
    const match = entry.match;
    if (match.op !== op) return false;
    const actualLeft = match.left;
    const actualRight = match.right;
    if (!nftRightEquals(actualRight, right)) return false;
    if (left.kind === "concat-daddr-dport") return nftLeftIsDaddrDportConcat(actualLeft);
    if (left.kind === "meta") return nftLeftMatches(actualLeft, "meta", { key: left.key });
    if (left.kind === "ct") return nftLeftMatches(actualLeft, "ct", { key: left.key });
    return nftLeftMatches(actualLeft, "payload", { protocol: left.protocol, field: left.field });
  });
}

function normalizeNftRightSet(value: unknown): string[] | undefined {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "string" || typeof value === "number") {
    return String(value).split(",").map((entry) => entry.trim()).filter(Boolean);
  }
  const set = isRecord(value) ? value.set : undefined;
  if (Array.isArray(set)) return set.map(String);
  if (typeof set === "string" || typeof set === "number") return [String(set)];
  return undefined;
}

function nftExprHasCtState(expr: readonly unknown[], expectedStates: readonly string[]): boolean {
  const expected = expectedStates.slice().sort();
  return expr.some((entry) => {
    if (!isRecord(entry) || !isRecord(entry.match)) return false;
    const match = entry.match;
    if (match.op !== "==" && match.op !== "in") return false;
    if (!nftLeftMatches(match.left, "ct", { key: "state" })) return false;
    const actual = normalizeNftRightSet(match.right)?.sort();
    return actual !== undefined
      && actual.length === expected.length
      && expected.every((state, index) => actual[index] === state);
  });
}

function nftExprHasVerdict(expr: readonly unknown[], verdict: "accept" | "reject" | "drop"): boolean {
  return expr.some((entry) => isRecord(entry) && Object.hasOwn(entry, verdict));
}

function nftExprHasControlTransfer(expr: readonly unknown[]): boolean {
  return expr.some((entry) => isRecord(entry) && (Object.hasOwn(entry, "jump") || Object.hasOwn(entry, "goto")));
}

function nftExprHasIpv6Accept(expr: readonly unknown[]): boolean {
  return nftExprHasVerdict(expr, "accept") && expr.some((entry) => {
    if (!isRecord(entry) || !isRecord(entry.match)) return false;
    return nftLeftMatches(entry.match.left, "payload", { protocol: "ip6" });
  });
}

function nftExpressionIsExact(expr: readonly unknown[], count: number): boolean {
  return expr.length === count && expr.every((entry) => {
    if (!isRecord(entry)) return false;
    return Object.hasOwn(entry, "match") || Object.hasOwn(entry, "accept") || Object.hasOwn(entry, "reject") || Object.hasOwn(entry, "drop");
  });
}

function nftSetTypeIsHostService(type: unknown): boolean {
  return Array.isArray(type)
    && type.length === HOST_SERVICE_SET_TYPE.length
    && HOST_SERVICE_SET_TYPE.every((part, index) => type[index] === part);
}

function strictHostServiceEntry(value: unknown): HostServiceSetEntry | undefined {
  if (!isRecord(value) || !Array.isArray(value.concat) || value.concat.length !== 2) return undefined;
  const [ip, port] = value.concat as unknown[];
  if (typeof ip !== "string" || !STRICT_IPV4_RE.test(ip)) return undefined;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return { ip, port };
}

/**
 * Members of `@host_service` from `nft -j list set inet runfree_proxy
 * host_service`. Each element is `{"concat":[ip, port]}`, or that value
 * wrapped as `{"elem":{"val":...}}` when nft prints element options. Anything
 * else, including a second set statement or a malformed element, returns
 * undefined: unreadable kernel state is never read as "no members".
 */
export function parseHostServiceSetMembers(rawJson: string, tableName = DEFAULT_TABLE_NAME): HostServiceSetEntry[] | undefined {
  const statements = parseNftJsonTable(rawJson);
  if (!statements) return undefined;
  const sets = statements.map((statement) => statement.set).filter((set): set is NftSet & { elem?: unknown } => set !== undefined);
  if (sets.length !== 1) return undefined;
  const [set] = sets;
  if (!nftStatementOwned(set, tableName) || set.name !== HOST_SERVICE_SET_NAME || !nftSetTypeIsHostService(set.type)) return undefined;
  if (set.elem === undefined) return [];
  if (!Array.isArray(set.elem)) return undefined;
  const members: HostServiceSetEntry[] = [];
  for (const element of set.elem) {
    const value = isRecord(element) && isRecord(element.elem) ? element.elem.val : element;
    const entry = strictHostServiceEntry(value);
    if (!entry) return undefined;
    members.push(entry);
  }
  return members;
}

/**
 * The kernel `@session_ipv4` members (exact IPv4 addresses) from the whole
 * table's `nft -j list table` output. Exactly one such set must be present
 * and every element must be an exact IPv4 address; anything else returns
 * undefined, so unreadable kernel state is never read as "no members".
 */
export function parseSessionSetMembers(rawJson: string, tableName = DEFAULT_TABLE_NAME): string[] | undefined {
  const statements = parseNftJsonTable(rawJson);
  if (!statements) return undefined;
  const sets = statements.map((statement) => statement.set)
    .filter((set): set is NftSet & { elem?: unknown } => set !== undefined
      && nftStatementOwned(set, tableName) && set.name === DEFAULT_SESSION_SET_NAME);
  if (sets.length !== 1) return undefined;
  const [set] = sets;
  if (set.elem === undefined) return [];
  if (!Array.isArray(set.elem)) return undefined;
  const members: string[] = [];
  for (const element of set.elem) {
    const value = isRecord(element) && isRecord(element.elem) ? element.elem.val : element;
    if (typeof value !== "string" || !STRICT_IPV4_RE.test(value)) return undefined;
    members.push(value);
  }
  return members;
}

function sameHostServiceMembers(left: readonly HostServiceSetEntry[], right: readonly HostServiceSetEntry[]): boolean {
  const leftKeys = sortHostServiceEntries(left).map(hostServiceEntryKey);
  const rightKeys = sortHostServiceEntries(right).map(hostServiceEntryKey);
  // Compared as sets: a kernel set holds each pair once.
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index]);
}

function formatHostServiceMembers(entries: readonly HostServiceSetEntry[]): string {
  const keys = sortHostServiceEntries(entries).map(hostServiceEntryKey);
  return keys.length > 0 ? keys.join(", ") : "<none>";
}

function nftPriorityEquals(actual: unknown, expected: "filter" | "raw"): boolean {
  const expectedValue = expected === "filter" ? 0 : -300;
  return actual === expectedValue || actual === expected || String(actual) === String(expectedValue);
}

function validateNftChain(
  issues: string[],
  chains: Map<string, NftChain>,
  tableName: string,
  name: ExpectedChain,
  expected: { hook: string; priority: "filter" | "raw"; policy: "accept" | "drop" },
): void {
  const chain = chains.get(name);
  if (!chain) {
    issues.push(`proxy firewall must install a ${name} nftables chain`);
    return;
  }
  if (!nftStatementOwned(chain, tableName) || chain.name !== name || chain.type !== "filter" || chain.hook !== expected.hook) {
    issues.push(`proxy ${name} chain must be a filter chain in the ${tableName} inet table`);
  }
  if (!nftPriorityEquals(chain.prio ?? chain.priority, expected.priority)) {
    issues.push(`proxy ${name} chain must use ${expected.priority} priority`);
  }
  if (chain.policy !== expected.policy) {
    issues.push(`proxy ${name} chain must have policy ${expected.policy}`);
  }
}

function validateNftRules(
  issues: string[],
  tableName: string,
  chain: ExpectedChain,
  rules: NftRule[],
  expectations: readonly NftRuleExpectation[],
): void {
  if (rules.length !== expectations.length) {
    issues.push(`proxy ${chain} chain must contain exactly ${expectations.length} rules; got ${rules.length}`);
  }
  rules.forEach((rule, index) => {
    if (!nftStatementOwned(rule, tableName) || rule.chain !== chain) {
      issues.push(`proxy ${chain} chain has a rule outside the owned table`);
    }
    const expr = Array.isArray(rule.expr) ? rule.expr : undefined;
    if (!expr) {
      issues.push(`proxy ${chain} rule ${index + 1} must have nft JSON expressions`);
      return;
    }
    if (nftExprHasControlTransfer(expr)) {
      issues.push(`proxy ${chain} chain must not delegate firewall decisions with jump/goto rules`);
    }
    if (nftExprHasIpv6Accept(expr)) {
      issues.push(`proxy ${chain} chain must not contain an IPv6 accept path`);
    }
    const expectation = expectations[index];
    if (!expectation) {
      issues.push(`proxy ${chain} chain contains unexpected rule ${index + 1}`);
      return;
    }
    if (!nftExpressionIsExact(expr, expectation.exprCount) || !expectation.matches(expr)) {
      issues.push(`proxy ${chain} rule ${index + 1} must match ${expectation.label}`);
    }
  });
}

export function validateProxyNftablesTableJson(input: ProxyNftablesProofInput): string[] {
  const tableName = input.tableName ?? DEFAULT_TABLE_NAME;
  const setName = input.setName ?? DEFAULT_SET_NAME;
  const proxyPort = input.proxyPort ?? DEFAULT_PROXY_PORT;
  const serverUid = input.serverUid ?? DEFAULT_SERVER_UID;
  const issues: string[] = [];
  const statements = parseNftJsonTable(input.rawJson);
  if (!statements) return ["proxy nftables table inspection must return nft JSON"];

  const tables = statements.map((statement) => statement.table).filter((table): table is NftTable => table !== undefined);
  if (tables.length !== 1 || !nftTableOwned(tables[0], tableName)) {
    issues.push(`proxy firewall must expose exactly the ${tableName} inet table`);
  }

  const sets = statements.map((statement) => statement.set).filter((set): set is NftSet => set !== undefined);
  const expectedSets: ReadonlyArray<{ name: string; concat: boolean }> = [
    ...[setName, DEFAULT_SESSION_SET_NAME, DEFAULT_AUDIT_SET_NAME, DEFAULT_AUDIT_DRAINING_SET_NAME, HOST_SERVICE_GATEWAY_SET_NAME]
      .map((name) => ({ name, concat: false })),
    // Exactly these two sets are `ipv4_addr . inet_service`.
    { name: HOST_SERVICE_SET_NAME, concat: true },
    { name: HOST_SERVICE_DRAINING_SET_NAME, concat: true },
  ];
  for (const { name: expectedSet, concat } of expectedSets) {
    const found = sets.filter((set) => nftStatementOwned(set, tableName) && set.name === expectedSet);
    const typeMatches = concat ? nftSetTypeIsHostService(found[0]?.type) : found[0]?.type === "ipv4_addr";
    if (found.length !== 1 || !typeMatches) {
      issues.push(concat
        ? `proxy firewall must install the ${expectedSet} IPv4 address . port nftables set`
        : `proxy firewall must install the ${expectedSet} IPv4 nftables set`);
    }
    const flags = found[0]?.flags;
    if (flags !== undefined && (!Array.isArray(flags) || flags.length !== 0)) {
      issues.push(`proxy firewall must install the ${expectedSet} set without interval or wildcard flags`);
    }
  }
  for (const set of sets) {
    if (!nftStatementOwned(set, tableName)) issues.push("proxy nftables table inspection returned a set outside the owned table");
  }

  const chains = new Map<string, NftChain>();
  for (const chain of statements.map((statement) => statement.chain).filter((chain): chain is NftChain => chain !== undefined)) {
    if (typeof chain.name !== "string") {
      issues.push("proxy nftables table includes an unnamed chain");
      continue;
    }
    if (!EXPECTED_CHAINS.includes(chain.name as ExpectedChain)) {
      issues.push(`proxy nftables table contains unexpected chain ${chain.name}`);
    }
    chains.set(chain.name, chain);
  }
  validateNftChain(issues, chains, tableName, "input", { hook: "input", priority: "filter", policy: "drop" });
  validateNftChain(issues, chains, tableName, "output_dns_guard", { hook: "output", priority: "raw", policy: "accept" });
  validateNftChain(issues, chains, tableName, "output", { hook: "output", priority: "filter", policy: "drop" });
  validateNftChain(issues, chains, tableName, "forward", { hook: "forward", priority: "filter", policy: "drop" });

  const rulesByChain = new Map<string, NftRule[]>();
  for (const rule of statements.map((statement) => statement.rule).filter((rule): rule is NftRule => rule !== undefined)) {
    if (typeof rule.chain !== "string") {
      issues.push("proxy nftables table includes a rule without a chain");
      continue;
    }
    rulesByChain.set(rule.chain, [...(rulesByChain.get(rule.chain) ?? []), rule]);
  }
  for (const chain of rulesByChain.keys()) {
    if (!EXPECTED_CHAINS.includes(chain as ExpectedChain)) {
      issues.push(`proxy nftables table contains a rule for unexpected chain ${chain}`);
    }
  }

  validateNftRules(issues, tableName, "input", rulesByChain.get("input") ?? [], [
    {
      label: "loopback ingress accept",
      exprCount: 2,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "iifname" }, "lo") && nftExprHasVerdict(expr, "accept"),
    },
    {
      label: "egress-interface established ingress accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "iifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "meta", key: "nfproto" }, "ipv4")
        && nftExprHasCtState(expr, ["established", "related"])
        && nftExprHasVerdict(expr, "accept"),
    },
    {
      label: "session-set established ingress accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "iifname" }, input.internalIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "saddr" }, `@${DEFAULT_SESSION_SET_NAME}`)
        && nftExprHasCtState(expr, ["established", "related"])
        && nftExprHasVerdict(expr, "accept"),
    },
    {
      label: "session-set new proxy-port accept",
      exprCount: 5,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "iifname" }, input.internalIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "saddr" }, `@${DEFAULT_SESSION_SET_NAME}`)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "tcp", field: "dport" }, proxyPort)
        && nftExprHasCtState(expr, ["new"])
        && nftExprHasVerdict(expr, "accept"),
    },
  ]);

  validateNftRules(issues, tableName, "output_dns_guard", rulesByChain.get("output_dns_guard") ?? [], [
    {
      label: `UDP DNS reject from proxy server UID ${serverUid}`,
      exprCount: 3,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "skuid" }, Number(serverUid))
        && nftExprHasMatch(expr, { kind: "payload", protocol: "udp", field: "dport" }, 53)
        && nftExprHasVerdict(expr, "reject"),
    },
    {
      label: `TCP DNS reject from proxy server UID ${serverUid}`,
      exprCount: 3,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "skuid" }, Number(serverUid))
        && nftExprHasMatch(expr, { kind: "payload", protocol: "tcp", field: "dport" }, 53)
        && nftExprHasVerdict(expr, "reject"),
    },
  ]);

  validateNftRules(issues, tableName, "output", rulesByChain.get("output") ?? [], [
    {
      label: "loopback output accept",
      exprCount: 2,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, "lo") && nftExprHasVerdict(expr, "accept"),
    },
    {
      label: "session-set established internal output accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.internalIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "daddr" }, `@${DEFAULT_SESSION_SET_NAME}`)
        && nftExprHasCtState(expr, ["established", "related"])
        && nftExprHasVerdict(expr, "accept"),
    },
    {
      // Above the established accept on purpose: the first terminal verdict
      // wins, so teardown severs established audited flows.
      label: "egress-interface audit drain-drop above established accept",
      exprCount: 3,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "daddr" }, `@${DEFAULT_AUDIT_DRAINING_SET_NAME}`)
        && nftExprHasVerdict(expr, "drop"),
    },
    {
      // Above the established accept for the same reason: a removed or
      // re-addressed host-service pair is cut even mid-flow.
      label: "egress-interface host-service drain-drop above established accept",
      exprCount: 3,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "concat-daddr-dport" }, `@${HOST_SERVICE_DRAINING_SET_NAME}`)
        && nftExprHasVerdict(expr, "drop"),
    },
    {
      // The permanent cut (R19): any flow, from any uid, to a gateway pinned
      // this supervisor lifetime on a pair NOT in @host_service is dropped
      // above the established accept. The negated lookup is the load-bearing
      // half: an `==` here would drop the approved pairs instead.
      label: "egress-interface pinned-gateway cut of unapproved pairs above established accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "daddr" }, `@${HOST_SERVICE_GATEWAY_SET_NAME}`)
        && nftExprHasMatch(expr, { kind: "concat-daddr-dport" }, `@${HOST_SERVICE_SET_NAME}`, "!=")
        && nftExprHasVerdict(expr, "drop"),
    },
    {
      label: "egress-interface established output accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "meta", key: "nfproto" }, "ipv4")
        && nftExprHasCtState(expr, ["established", "related"])
        && nftExprHasVerdict(expr, "accept"),
    },
    {
      label: "egress-interface allowlist-backed HTTPS accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "daddr" }, `@${setName}`)
        && nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "tcp", field: "dport" }, 443)
        && nftExprHasVerdict(expr, "accept"),
    },
    {
      label: "egress-interface audit-set HTTPS accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "payload", protocol: "ip", field: "daddr" }, `@${DEFAULT_AUDIT_SET_NAME}`)
        && nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "payload", protocol: "tcp", field: "dport" }, 443)
        && nftExprHasVerdict(expr, "accept"),
    },
    {
      // uid 1001 only: root gets nothing from the host-service set.
      label: "egress-interface proxy server UID host-service accept",
      exprCount: 4,
      matches: (expr) => nftExprHasMatch(expr, { kind: "meta", key: "oifname" }, input.egressIface)
        && nftExprHasMatch(expr, { kind: "meta", key: "skuid" }, Number(serverUid))
        && nftExprHasMatch(expr, { kind: "concat-daddr-dport" }, `@${HOST_SERVICE_SET_NAME}`)
        && nftExprHasVerdict(expr, "accept"),
    },
  ]);

  validateNftRules(issues, tableName, "forward", rulesByChain.get("forward") ?? [], []);

  if (input.hostServiceElements !== undefined && input.expectedHostServiceElements !== undefined
    && !sameHostServiceMembers(input.hostServiceElements, input.expectedHostServiceElements)) {
    issues.push(`host_service members do not match the effective host services: kernel ${formatHostServiceMembers(input.hostServiceElements)}; expected ${formatHostServiceMembers(input.expectedHostServiceElements)}`);
  }
  return issues;
}
