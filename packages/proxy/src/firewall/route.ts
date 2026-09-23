import type { CommandRunner } from "./command.js";
import { validateFirewallPlan, type FirewallPlan } from "./nftables.js";

type IpAddressEntry = {
  ifname?: string;
  addr_info?: Array<{ family?: string; local?: string }>;
};

type RouteEntry = {
  dev?: string;
  gateway?: string;
  prefsrc?: string;
  src?: string;
};

export async function discoverInterfaces(plan: FirewallPlan, runner: CommandRunner): Promise<FirewallPlan> {
  let internalIface: string | undefined = cleanInterface(plan.internal.iface) || undefined;
  let egressIface: string | undefined = cleanInterface(plan.egress.iface) || undefined;

  if (!internalIface || !egressIface) {
    const addressMap = await localAddressInterfaces(runner);
    internalIface ||= addressMap.get(plan.internal.proxyIp);
    egressIface ||= addressMap.get(plan.egress.sourceIp);
  }

  if (!internalIface) {
    throw new Error(`could not identify internal interface for proxy IP ${plan.internal.proxyIp}`);
  }
  if (!egressIface) {
    throw new Error(`could not identify interface for proxy egress IP ${plan.egress.sourceIp}`);
  }

  const discovered = {
    ...plan,
    internal: { ...plan.internal, iface: internalIface },
    egress: { ...plan.egress, iface: egressIface },
  };
  validateFirewallPlan(discovered);
  return discovered;
}

export async function ensureDefaultRoute(plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  validateFirewallPlan(plan);
  const current = await routeFor("1.1.1.1", runner);
  if (current?.dev === plan.egress.iface && routeSource(current) === plan.egress.sourceIp) {
    return;
  }

  await runner.run("ip", [
    "route",
    "replace",
    "default",
    "via",
    plan.egress.gatewayIp,
    "dev",
    plan.egress.iface,
    "src",
    plan.egress.sourceIp,
  ]);

  const repaired = await routeFor("1.1.1.1", runner);
  if (repaired?.dev !== plan.egress.iface || routeSource(repaired) !== plan.egress.sourceIp) {
    throw new Error(`default egress route still uses ${repaired?.dev ?? "<none>"} src ${routeSource(repaired) ?? "<none>"}`);
  }
}

export async function verifyFirewallState(plan: FirewallPlan, runner: CommandRunner): Promise<void> {
  validateFirewallPlan(plan);
  const route = await routeFor("1.1.1.1", runner);
  if (route?.dev !== plan.egress.iface || routeSource(route) !== plan.egress.sourceIp) {
    throw new Error(`proxy egress route verification failed: dev=${route?.dev ?? "<none>"} src=${routeSource(route) ?? "<none>"}`);
  }
  await runner.run("nft", ["list", "ruleset"]);
  await runner.run("nft", ["list", "set", "inet", plan.nftables.tableName, plan.nftables.setName]);
  // The always-present audit sets must exist and be empty in enforce mode:
  // their only legitimate writer is the supervisor during an active audit
  // window, and verification runs in enforce mode.
  await runner.run("nft", ["list", "set", "inet", plan.nftables.tableName, plan.nftables.sessionSetName]);
  for (const auditSet of [plan.nftables.auditSetName, plan.nftables.auditDrainingSetName]) {
    const result = await runner.run("nft", ["list", "set", "inet", plan.nftables.tableName, auditSet]);
    if (result.stdout.includes("elements")) {
      throw new Error(`proxy firewall audit set ${auditSet} is not empty in enforce mode`);
    }
  }
}

export async function hasIpv6DefaultRoute(runner: CommandRunner): Promise<boolean> {
  const result = await runner.run("ip", ["-json", "-6", "route", "show", "default"]);
  const routes = parseJson<RouteEntry[]>(result.stdout, []);
  return routes.length > 0;
}

async function localAddressInterfaces(runner: CommandRunner): Promise<Map<string, string>> {
  const result = await runner.run("ip", ["-json", "-4", "addr", "show"]);
  const entries = parseJson<IpAddressEntry[]>(result.stdout, []);
  const map = new Map<string, string>();
  for (const entry of entries) {
    const ifname = cleanInterface(entry.ifname ?? "");
    if (!ifname) continue;
    for (const info of entry.addr_info ?? []) {
      if (info.family === "inet" && info.local) map.set(info.local, ifname);
    }
  }
  return map;
}

async function routeFor(target: string, runner: CommandRunner): Promise<RouteEntry | undefined> {
  const result = await runner.run("ip", ["-json", "route", "get", target]);
  return parseJson<RouteEntry[]>(result.stdout, [])[0];
}

function cleanInterface(value: string | undefined): string {
  return (value ?? "").replace(/@.*$/, "").replace(/:$/, "");
}

function routeSource(route: RouteEntry | undefined): string | undefined {
  return route?.prefsrc ?? route?.src;
}

function parseJson<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
