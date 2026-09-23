import type { CommandRunner } from "./command.js";
import { isRecord } from "@runfree/runtime-contracts/primitives";

const IFACE_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const NFT_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
export const PROXY_SERVER_UID = "1001";
export const PROXY_SERVER_GID = "1001";

export type FirewallPlan = {
  controlGeneration?: string;
  effectiveProxyRoot?: string;
  policyPath: string;
  policyGeneration: string;
  internal: {
    iface: string;
    proxyIp: string;
    proxyPort: number;
  };
  egress: {
    iface: string;
    sourceIp: string;
    gatewayIp: string;
  };
  allowedHosts: readonly string[];
  runtimeSubnets?: readonly string[];
  nftables: {
    tableName: "runfree_proxy";
    setName: "allowed_ipv4";
    maxElements: number;
    sessionSetName: "session_ipv4";
    sessionMaxElements: number;
    // Audit sets are always present and empty in enforce mode; only their
    // contents change at runtime. The audit cap is intentionally small and
    // distinct from the enforce-mode allowlist cap.
    auditSetName: "audit_ipv4";
    auditDrainingSetName: "audit_draining_ipv4";
    auditMaxElements: number;
  };
  refresh: {
    policyCheckIntervalSeconds: number;
    dnsRefreshIntervalSeconds: number;
    maxStaleHostSeconds: number;
  };
  audit: {
    markerPath: string;
    spoolPath: string;
    resolvedHostsPath: string;
    // Distinct new-host resolutions permitted per fast policy tick.
    resolveBudgetPerTick: number;
    // Seconds the drain-drop set keeps severing established audited flows
    // after teardown before it is flushed.
    drainSeconds: number;
  };
};

export function validateFirewallPlan(plan: FirewallPlan): void {
  assertInterface(plan.internal.iface, "internal interface");
  assertInterface(plan.egress.iface, "egress interface");
  if (plan.internal.iface === plan.egress.iface) {
    throw new Error(`internal and egress interfaces must differ: ${plan.internal.iface}`);
  }
  assertIpv4(plan.internal.proxyIp, "proxy IP");
  assertIpv4(plan.egress.sourceIp, "egress source IP");
  assertIpv4(plan.egress.gatewayIp, "egress gateway IP");
  if (!Number.isInteger(plan.internal.proxyPort) || plan.internal.proxyPort < 1 || plan.internal.proxyPort > 65535) {
    throw new Error(`invalid proxy port: ${plan.internal.proxyPort}`);
  }
  if (!NFT_NAME_RE.test(plan.nftables.tableName)) {
    throw new Error("invalid nftables table name");
  }
  if (!NFT_NAME_RE.test(plan.nftables.setName)) {
    throw new Error("invalid nftables set name");
  }
  if (!NFT_NAME_RE.test(plan.nftables.sessionSetName)
    || !NFT_NAME_RE.test(plan.nftables.auditSetName)
    || !NFT_NAME_RE.test(plan.nftables.auditDrainingSetName)) {
    throw new Error("invalid nftables audit set name");
  }
  const setNames = new Set([
    plan.nftables.setName,
    plan.nftables.sessionSetName,
    plan.nftables.auditSetName,
    plan.nftables.auditDrainingSetName,
  ]);
  if (setNames.size !== 4) {
    throw new Error("nftables set names must be distinct");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(plan.policyGeneration)) {
    throw new Error(`invalid policy generation: ${plan.policyGeneration}`);
  }
  if (plan.controlGeneration !== undefined && !/^sha256:[a-f0-9]{64}$/.test(plan.controlGeneration)) {
    throw new Error(`invalid control generation: ${plan.controlGeneration}`);
  }
  if (!Number.isInteger(plan.nftables.maxElements) || plan.nftables.maxElements < 1) {
    throw new Error(`invalid nftables set max elements: ${plan.nftables.maxElements}`);
  }
  if (!Number.isInteger(plan.nftables.sessionMaxElements) || plan.nftables.sessionMaxElements < 1) {
    throw new Error(`invalid nftables session set max elements: ${plan.nftables.sessionMaxElements}`);
  }
  if (!Number.isInteger(plan.nftables.auditMaxElements) || plan.nftables.auditMaxElements < 1) {
    throw new Error(`invalid nftables audit set max elements: ${plan.nftables.auditMaxElements}`);
  }
  for (const [label, value] of [
    ["audit marker path", plan.audit.markerPath],
    ["audit spool path", plan.audit.spoolPath],
    ["audit resolved-hosts path", plan.audit.resolvedHostsPath],
  ] as const) {
    if (typeof value !== "string" || value.trim() === "") throw new Error(`invalid ${label}`);
  }
  if (!Number.isInteger(plan.audit.resolveBudgetPerTick) || plan.audit.resolveBudgetPerTick < 1) {
    throw new Error(`invalid audit resolve budget: ${plan.audit.resolveBudgetPerTick}`);
  }
  if (!Number.isInteger(plan.audit.drainSeconds) || plan.audit.drainSeconds < 1) {
    throw new Error(`invalid audit drain seconds: ${plan.audit.drainSeconds}`);
  }
}

export function renderRuleset(plan: FirewallPlan): string {
  validateFirewallPlan(plan);
  const { internal, egress, nftables } = plan;
  // Only the admitted session set (@session_ipv4) may reach the proxy: every
  // agent is a per-session container admitted by source IP, so there is no
  // standing accept for any fixed agent address — all agent->proxy traffic
  // must pass admission.
  // The audit sets and their two rules are always present from first boot and
  // empty in enforce mode, so no rule is added or deleted at runtime. The
  // drain-drop sits ABOVE the egress established-accept on purpose: the first
  // terminal verdict in a base chain wins, so flows to draining destinations
  // are severed even when conntrack already marks them established. This is
  // the sole severance mechanism for in-flight audited flows at teardown
  // (nft + NET_ADMIN only; no conntrack-tools, no NET_RAW).
  return [
    `table inet ${nftables.tableName} {`,
    `  set ${nftables.setName} {`,
    "    type ipv4_addr",
    `    size ${nftables.maxElements}`,
    "  }",
    `  set ${nftables.sessionSetName} {`,
    "    type ipv4_addr",
    `    size ${nftables.sessionMaxElements}`,
    "  }",
    `  set ${nftables.auditSetName} {`,
    "    type ipv4_addr",
    `    size ${nftables.auditMaxElements}`,
    "  }",
    `  set ${nftables.auditDrainingSetName} {`,
    "    type ipv4_addr",
    `    size ${nftables.auditMaxElements}`,
    "  }",
    "  chain input {",
    "    type filter hook input priority filter; policy drop;",
    "    iifname \"lo\" accept",
    `    iifname "${egress.iface}" meta nfproto ipv4 ct state established,related accept`,
    `    iifname "${internal.iface}" ip saddr @${nftables.sessionSetName} ct state established,related accept`,
    `    iifname "${internal.iface}" ip saddr @${nftables.sessionSetName} tcp dport ${internal.proxyPort} ct state new accept`,
    "  }",
    "  chain output_dns_guard {",
    "    type filter hook output priority raw; policy accept;",
    `    meta skuid ${PROXY_SERVER_UID} udp dport 53 reject`,
    `    meta skuid ${PROXY_SERVER_UID} tcp dport 53 reject`,
    "  }",
    "  chain output {",
    "    type filter hook output priority filter; policy drop;",
    "    oifname \"lo\" accept",
    `    oifname "${internal.iface}" ip daddr @${nftables.sessionSetName} ct state established,related accept`,
    `    oifname "${egress.iface}" ip daddr @${nftables.auditDrainingSetName} drop`,
    `    oifname "${egress.iface}" meta nfproto ipv4 ct state established,related accept`,
    `    oifname "${egress.iface}" ip daddr @${nftables.setName} tcp dport 443 accept`,
    `    oifname "${egress.iface}" ip daddr @${nftables.auditSetName} tcp dport 443 accept`,
    "  }",
    "  chain forward {",
    "    type filter hook forward priority filter; policy drop;",
    "  }",
    "}",
    "",
  ].join("\n");
}

export function renderSessionAdmissionSetUpdate(ips: readonly string[], plan: FirewallPlan): string {
  validateFirewallPlan(plan);
  const uniqueIps = Array.from(new Set(ips)).sort();
  if (uniqueIps.length > plan.nftables.sessionMaxElements) {
    throw new Error(`nftables session set update has ${uniqueIps.length} elements but max is ${plan.nftables.sessionMaxElements}`);
  }
  for (const ip of uniqueIps) assertIpv4(ip, "session IPv4");
  const { tableName, sessionSetName } = plan.nftables;
  return [
    `flush set inet ${tableName} ${sessionSetName}`,
    uniqueIps.length > 0
      ? `add element inet ${tableName} ${sessionSetName} { ${uniqueIps.join(", ")} }`
      : undefined,
    "",
  ].filter((line): line is string => line !== undefined).join("\n");
}

export function renderAllowedSetUpdate(ips: readonly string[], plan: FirewallPlan): string {
  validateFirewallPlan(plan);
  const { tableName, setName } = plan.nftables;
  const uniqueIps = Array.from(new Set(ips)).sort();
  if (uniqueIps.length > plan.nftables.maxElements) {
    throw new Error(`nftables set update has ${uniqueIps.length} elements but max is ${plan.nftables.maxElements}`);
  }
  for (const ip of uniqueIps) assertIpv4(ip, "allowed IPv4");
  return [
    `flush set inet ${tableName} ${setName}`,
    uniqueIps.length > 0
      ? `add element inet ${tableName} ${setName} { ${uniqueIps.join(", ")} }`
      : undefined,
    "",
  ].filter((line): line is string => line !== undefined).join("\n");
}

// Audit set render helpers are deliberately separate from the allowed_ipv4
// render path: distinct set names and a distinct, small cap.
function dedupedAuditIps(ips: readonly string[], plan: FirewallPlan, label: string): string[] {
  const uniqueIps = Array.from(new Set(ips)).sort();
  if (uniqueIps.length > plan.nftables.auditMaxElements) {
    throw new Error(`nftables audit set update has ${uniqueIps.length} elements but max is ${plan.nftables.auditMaxElements}`);
  }
  for (const ip of uniqueIps) assertIpv4(ip, label);
  return uniqueIps;
}

export function renderAuditSetUpdate(ips: readonly string[], plan: FirewallPlan): string {
  validateFirewallPlan(plan);
  const { tableName, auditSetName } = plan.nftables;
  const uniqueIps = dedupedAuditIps(ips, plan, "audit IPv4");
  return [
    `flush set inet ${tableName} ${auditSetName}`,
    uniqueIps.length > 0
      ? `add element inet ${tableName} ${auditSetName} { ${uniqueIps.join(", ")} }`
      : undefined,
    "",
  ].filter((line): line is string => line !== undefined).join("\n");
}

export function renderAuditDrainingSetUpdate(ips: readonly string[], plan: FirewallPlan): string {
  validateFirewallPlan(plan);
  const { tableName, auditDrainingSetName } = plan.nftables;
  const uniqueIps = dedupedAuditIps(ips, plan, "audit draining IPv4");
  return [
    `flush set inet ${tableName} ${auditDrainingSetName}`,
    uniqueIps.length > 0
      ? `add element inet ${tableName} ${auditDrainingSetName} { ${uniqueIps.join(", ")} }`
      : undefined,
    "",
  ].filter((line): line is string => line !== undefined).join("\n");
}

// One atomic `nft -f -` batch for teardown: populate the draining set (the
// drain-drop rule severs established flows to its members) and flush the
// audit accept set, so there is no window where an audited destination is
// neither draining nor removed.
export function renderAuditTeardown(drainingIps: readonly string[], plan: FirewallPlan): string {
  validateFirewallPlan(plan);
  const { tableName, auditSetName, auditDrainingSetName } = plan.nftables;
  const uniqueIps = dedupedAuditIps(drainingIps, plan, "audit draining IPv4");
  return [
    `flush set inet ${tableName} ${auditDrainingSetName}`,
    uniqueIps.length > 0
      ? `add element inet ${tableName} ${auditDrainingSetName} { ${uniqueIps.join(", ")} }`
      : undefined,
    `flush set inet ${tableName} ${auditSetName}`,
    "",
  ].filter((line): line is string => line !== undefined).join("\n");
}

export async function applyRuleset(plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  validateFirewallPlan(plan);
  const { tableName } = plan.nftables;
  let tableExists = false;
  try {
    await runner.run("nft", ["list", "table", "inet", tableName]);
    tableExists = true;
  } catch {
    tableExists = false;
  }
  if (tableExists) {
    await runner.run("nft", ["-f", "-"], { input: [
      `flush table inet ${tableName}`,
      `delete table inet ${tableName}`,
      "",
    ].join("\n") });
  }
  await runner.run("nft", ["-f", "-"], { input: renderRuleset(plan) });
}

export async function replaceAllowedSet(ips: readonly string[], plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderAllowedSetUpdate(ips, plan) });
}

export async function replaceSessionAdmissionSet(
  ips: readonly string[],
  plan: FirewallPlan,
  runner: CommandRunner,
): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderSessionAdmissionSetUpdate(ips, plan) });
}

export async function verifySessionAdmissionSet(
  ips: readonly string[],
  plan: FirewallPlan,
  runner: CommandRunner,
): Promise<void> {
  validateFirewallPlan(plan);
  const result = await runner.run("nft", [
    "-j",
    "list",
    "set",
    "inet",
    plan.nftables.tableName,
    plan.nftables.sessionSetName,
  ]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout) as unknown;
  } catch {
    throw new Error("nftables session admission set verification returned malformed JSON");
  }
  const actual = nftSetIpv4Elements(parsed, plan.nftables.tableName, plan.nftables.sessionSetName);
  const expected = Array.from(new Set(ips)).sort();
  if (!actual || !sameStrings(actual, expected)) {
    throw new Error(`nftables session admission set mismatch: expected=${expected.join(",")} actual=${actual?.join(",") ?? "<missing>"}`);
  }
}

export async function replaceAuditSet(ips: readonly string[], plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderAuditSetUpdate(ips, plan) });
}

function nftSetIpv4Elements(value: unknown, tableName: string, setName: string): string[] | undefined {
  if (!isRecord(value) || !Array.isArray(value.nftables)) return undefined;
  for (const item of value.nftables) {
    if (!isRecord(item) || !isRecord(item.set)) continue;
    const set = item.set;
    if (set.family !== "inet" || set.table !== tableName || set.name !== setName) continue;
    const elements = set.elem === undefined ? [] : set.elem;
    if (!Array.isArray(elements) || elements.some((element) => typeof element !== "string" || !isValidIpv4(element))) {
      return undefined;
    }
    return Array.from(new Set(elements as string[])).sort();
  }
  return undefined;
}


function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export async function replaceAuditDrainingSet(ips: readonly string[], plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderAuditDrainingSetUpdate(ips, plan) });
}

export async function applyAuditTeardown(drainingIps: readonly string[], plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderAuditTeardown(drainingIps, plan) });
}

export function isValidIpv4(value: string): boolean {
  const octets = value.split(".");
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const value = Number(octet);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
}

function assertInterface(value: string, label: string): void {
  if (!IFACE_RE.test(value)) throw new Error(`invalid ${label}: ${value || "<empty>"}`);
}

function assertIpv4(value: string, label: string): void {
  if (!isValidIpv4(value)) throw new Error(`invalid ${label}: ${value}`);
}
