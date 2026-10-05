import type { CommandRunner } from "./command.js";
import { isRecord } from "@runfree/runtime-contracts/primitives";
import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";

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
  // The effective policy's approved host services. Members of @host_service
  // are exactly `<pinned gateway> . <port>` for each entry.
  hostServices?: Readonly<HostServicesJson>;
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
    // Host services (design "Firewall"): the uid-1001 accept set and the
    // drain-drop set that severs established flows of removed pairs.
    hostServiceSetName: "host_service";
    hostServiceDrainingSetName: "host_service_draining";
    hostServiceMaxElements: number;
    // Every gateway address the supervisor pinned during its lifetime (R19).
    // A flow to one of these addresses on a pair not currently in
    // @host_service is dropped above the established accept, with no time
    // limit, so a removed or re-addressed pair stays cut even when the
    // request proxy did not cut its splice.
    hostServiceGatewaySetName: "host_service_gateways";
    hostServiceGatewayMaxElements: number;
  };
  // Seconds a removed host-service pair stays in the drain-drop set.
  hostServiceDrainSeconds: number;
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
  if (!NFT_NAME_RE.test(plan.nftables.hostServiceSetName)
    || !NFT_NAME_RE.test(plan.nftables.hostServiceDrainingSetName)
    || !NFT_NAME_RE.test(plan.nftables.hostServiceGatewaySetName)) {
    throw new Error("invalid nftables host-service set name");
  }
  const setNames = new Set([
    plan.nftables.setName,
    plan.nftables.sessionSetName,
    plan.nftables.auditSetName,
    plan.nftables.auditDrainingSetName,
    plan.nftables.hostServiceSetName,
    plan.nftables.hostServiceDrainingSetName,
    plan.nftables.hostServiceGatewaySetName,
  ]);
  if (setNames.size !== 7) {
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
  if (!Number.isInteger(plan.nftables.hostServiceMaxElements) || plan.nftables.hostServiceMaxElements < 1) {
    throw new Error(`invalid nftables host-service set max elements: ${plan.nftables.hostServiceMaxElements}`);
  }
  if (!Number.isInteger(plan.nftables.hostServiceGatewayMaxElements) || plan.nftables.hostServiceGatewayMaxElements < 1) {
    throw new Error(`invalid nftables host-service gateway set max elements: ${plan.nftables.hostServiceGatewayMaxElements}`);
  }
  if (!Number.isInteger(plan.hostServiceDrainSeconds) || plan.hostServiceDrainSeconds < 1) {
    throw new Error(`invalid host-service drain seconds: ${plan.hostServiceDrainSeconds}`);
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
  // Host services follow the same pattern: the always-present
  // host_service_draining drop sits above the established accept so a removed
  // or re-addressed pair is cut even mid-flow, and the host_service accept is
  // uid 1001 only on the egress interface, so root gets nothing from it.
  // The host_service_gateways drop (R19) also sits above the established
  // accept: any flow to a gateway the supervisor ever pinned, on a pair not
  // currently in @host_service, is dropped for as long as the pair is not
  // approved. The draining set stays as defence in depth with its bounded
  // window; this rule is the permanent cut.
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
    `  set ${nftables.hostServiceSetName} {`,
    "    type ipv4_addr . inet_service",
    `    size ${nftables.hostServiceMaxElements}`,
    "  }",
    `  set ${nftables.hostServiceDrainingSetName} {`,
    "    type ipv4_addr . inet_service",
    `    size ${nftables.hostServiceMaxElements}`,
    "  }",
    `  set ${nftables.hostServiceGatewaySetName} {`,
    "    type ipv4_addr",
    `    size ${nftables.hostServiceGatewayMaxElements}`,
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
    `    oifname "${egress.iface}" ip daddr . tcp dport @${nftables.hostServiceDrainingSetName} drop`,
    `    oifname "${egress.iface}" ip daddr @${nftables.hostServiceGatewaySetName} ip daddr . tcp dport != @${nftables.hostServiceSetName} drop`,
    `    oifname "${egress.iface}" meta nfproto ipv4 ct state established,related accept`,
    `    oifname "${egress.iface}" ip daddr @${nftables.setName} tcp dport 443 accept`,
    `    oifname "${egress.iface}" ip daddr @${nftables.auditSetName} tcp dport 443 accept`,
    `    oifname "${egress.iface}" meta skuid ${PROXY_SERVER_UID} ip daddr . tcp dport @${nftables.hostServiceSetName} accept`,
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

export type HostServiceElement = { ip: string; port: number };

function hostServiceElements(entries: readonly HostServiceElement[], plan: FirewallPlan, label: string): string[] {
  const unique = new Map<string, HostServiceElement>();
  for (const entry of entries) {
    assertIpv4(entry.ip, `${label} IPv4`);
    if (!Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65535) {
      throw new Error(`invalid ${label} port: ${entry.port}`);
    }
    unique.set(`${entry.ip} . ${entry.port}`, entry);
  }
  if (unique.size > plan.nftables.hostServiceMaxElements) {
    throw new Error(`nftables host-service set update has ${unique.size} elements but max is ${plan.nftables.hostServiceMaxElements}`);
  }
  return Array.from(unique.values())
    .sort((left, right) => compareIpv4(left.ip, right.ip) || left.port - right.port)
    .map((entry) => `${entry.ip} . ${entry.port}`);
}

function fillSetLines(tableName: string, setName: string, elements: readonly string[]): string[] {
  return [
    `flush set inet ${tableName} ${setName}`,
    ...(elements.length > 0 ? [`add element inet ${tableName} ${setName} { ${elements.join(", ")} }`] : []),
  ];
}

// The gateway set lines lead every host-service batch, and every accepted
// pair's address must be one of those gateways, so no pair is ever accepted
// in a batch that does not also install its permanent cut (R19).
function gatewayElements(
  gateways: readonly string[],
  accepted: readonly HostServiceElement[],
  plan: FirewallPlan,
): string[] {
  const unique = Array.from(new Set(gateways)).sort(compareIpv4);
  for (const gateway of unique) assertIpv4(gateway, "host-service gateway IPv4");
  if (unique.length > plan.nftables.hostServiceGatewayMaxElements) {
    throw new Error(`nftables host-service gateway set update has ${unique.length} elements but max is ${plan.nftables.hostServiceGatewayMaxElements}`);
  }
  const known = new Set(unique);
  for (const entry of accepted) {
    if (!known.has(entry.ip)) {
      throw new Error(`host-service pair ${entry.ip} . ${entry.port} is not at a recorded gateway; refusing to accept it without its permanent cut`);
    }
  }
  return unique;
}

export function renderHostServiceSetUpdate(
  entries: readonly HostServiceElement[],
  plan: FirewallPlan,
  gateways: readonly string[],
): string {
  validateFirewallPlan(plan);
  const elements = hostServiceElements(entries, plan, "host-service");
  const gatewayList = gatewayElements(gateways, entries, plan);
  return [
    ...fillSetLines(plan.nftables.tableName, plan.nftables.hostServiceGatewaySetName, gatewayList),
    ...fillSetLines(plan.nftables.tableName, plan.nftables.hostServiceSetName, elements),
    "",
  ].join("\n");
}

// One atomic `nft -f -` batch: fill the draining set first (its drop rule
// severs established flows to its members), then refill the accept set with
// the pairs that stay, so no removed pair is ever accepted and not draining.
export function renderHostServiceTeardown(
  draining: readonly HostServiceElement[],
  remaining: readonly HostServiceElement[],
  plan: FirewallPlan,
  gateways: readonly string[],
): string {
  validateFirewallPlan(plan);
  const drainingElements = hostServiceElements(draining, plan, "host-service draining");
  const remainingElements = hostServiceElements(remaining, plan, "host-service");
  const gatewayList = gatewayElements(gateways, remaining, plan);
  const { tableName, hostServiceSetName, hostServiceDrainingSetName, hostServiceGatewaySetName } = plan.nftables;
  return [
    ...fillSetLines(tableName, hostServiceGatewaySetName, gatewayList),
    ...fillSetLines(tableName, hostServiceDrainingSetName, drainingElements),
    ...fillSetLines(tableName, hostServiceSetName, remainingElements),
    "",
  ].join("\n");
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

export async function replaceHostServiceSet(
  entries: readonly HostServiceElement[],
  runner: CommandRunner,
  plan: FirewallPlan,
  gateways: readonly string[],
): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderHostServiceSetUpdate(entries, plan, gateways) });
}

export async function applyHostServiceTeardown(
  draining: readonly HostServiceElement[],
  remaining: readonly HostServiceElement[],
  runner: CommandRunner,
  plan: FirewallPlan,
  gateways: readonly string[],
): Promise<void> {
  await runner.run("nft", ["-f", "-"], { input: renderHostServiceTeardown(draining, remaining, plan, gateways) });
}

export async function flushHostServiceDraining(runner: CommandRunner, plan: FirewallPlan): Promise<void> {
  validateFirewallPlan(plan);
  await runner.run("nft", ["-f", "-"], {
    input: `flush set inet ${plan.nftables.tableName} ${plan.nftables.hostServiceDrainingSetName}\n`,
  });
}

// Kernel readback of @host_service from `nft -j list set`. Concat elements
// arrive as `{"concat":["1.2.3.4",5432]}`, or wrapped as
// `{"elem":{"val":{"concat":[...]}}}` when the set carries element options.
export async function readHostServiceSetElements(runner: CommandRunner, plan: FirewallPlan): Promise<HostServiceElement[]> {
  validateFirewallPlan(plan);
  const { tableName, hostServiceSetName } = plan.nftables;
  const result = await runner.run("nft", ["-j", "list", "set", "inet", tableName, hostServiceSetName]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout) as unknown;
  } catch {
    throw new Error("nftables host-service set readback returned malformed JSON");
  }
  const elements = nftSetConcatElements(parsed, tableName, hostServiceSetName);
  if (!elements) throw new Error("nftables host-service set readback is missing or malformed");
  return elements.sort((left, right) => compareIpv4(left.ip, right.ip) || left.port - right.port);
}

function nftSetConcatElements(value: unknown, tableName: string, setName: string): HostServiceElement[] | undefined {
  if (!isRecord(value) || !Array.isArray(value.nftables)) return undefined;
  for (const item of value.nftables) {
    if (!isRecord(item) || !isRecord(item.set)) continue;
    const set = item.set;
    if (set.family !== "inet" || set.table !== tableName || set.name !== setName) continue;
    const raw = set.elem === undefined ? [] : set.elem;
    if (!Array.isArray(raw)) return undefined;
    const elements: HostServiceElement[] = [];
    for (const element of raw) {
      const unwrapped = isRecord(element) && isRecord(element.elem) ? element.elem.val : element;
      if (!isRecord(unwrapped) || !Array.isArray(unwrapped.concat) || unwrapped.concat.length !== 2) return undefined;
      const [ip, port] = unwrapped.concat as unknown[];
      if (typeof ip !== "string" || !isValidIpv4(ip)) return undefined;
      if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
      elements.push({ ip, port });
    }
    return elements;
  }
  return undefined;
}

function compareIpv4(left: string, right: string): number {
  const toInt = (ip: string) => ip.split(".").reduce((value, octet) => ((value << 8) + Number(octet)) >>> 0, 0);
  return toInt(left) - toInt(right);
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
