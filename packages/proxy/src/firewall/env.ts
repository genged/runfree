import {
  auditMarkerPathFromEnv,
  auditResolvedHostsPathFromEnv,
  auditSpoolPathFromEnv,
} from "../audit.js";
import { isValidIpv4, type FirewallPlan } from "./nftables.js";
import { assertSessionAdmissionSourceIsFiles } from "../session-identity-config.js";

type BuildFirewallPlanInput = {
  allowedHosts: readonly string[];
  controlGeneration?: string;
  effectiveProxyRoot?: string;
  env?: NodeJS.ProcessEnv;
  policyPath?: string;
  policyGeneration: string;
};

export function buildFirewallPlan(input: BuildFirewallPlanInput): FirewallPlan {
  const env = input.env ?? process.env;
  // The same refusal the request proxy applies to its own start, applied here
  // because this is where the firewall reads its environment: this supervisor
  // consumes per-session files and nothing else, so a container created
  // without the key — or with any other spelling — must not get a plan it
  // would then drive from a protocol it cannot read.
  assertSessionAdmissionSourceIsFiles(env);
  const policyPath = input.policyPath ?? requiredString(env.PROXY_POLICY_PATH, "PROXY_POLICY_PATH");
  const proxyIp = ipv4(env.RUNFREE_PROXY_IP ?? "172.30.0.10", "RUNFREE_PROXY_IP");
  const sourceIp = ipv4(env.RUNFREE_PROXY_EGRESS_IP ?? "172.30.1.10", "RUNFREE_PROXY_EGRESS_IP");
  const gatewayIp = ipv4(env.RUNFREE_PROXY_EGRESS_GATEWAY ?? "172.30.1.1", "RUNFREE_PROXY_EGRESS_GATEWAY");
  const runtimeSubnets = [
    env.RUNFREE_SUBNET,
    env.RUNFREE_PROXY_EGRESS_SUBNET,
  ].filter((value): value is string => typeof value === "string" && value.trim() !== "")
    .map((value) => cidr(value, "RUNFREE runtime subnet"));

  return {
    ...(input.controlGeneration ? { controlGeneration: input.controlGeneration } : {}),
    ...(input.effectiveProxyRoot ? { effectiveProxyRoot: input.effectiveProxyRoot } : {}),
    policyPath,
    policyGeneration: input.policyGeneration,
    internal: {
      iface: env.RUNFREE_INTERNAL_IFACE ?? "",
      proxyIp,
      proxyPort: tcpPort(env.PROXY_PORT ?? env.PORT ?? "8080", "PROXY_PORT"),
    },
    egress: {
      iface: env.RUNFREE_EGRESS_IFACE ?? "",
      sourceIp,
      gatewayIp,
    },
    allowedHosts: [...input.allowedHosts],
    runtimeSubnets,
    nftables: {
      tableName: "runfree_proxy",
      setName: "allowed_ipv4",
      maxElements: positiveInteger(
        env.PROXY_FIREWALL_SET_MAX_ELEMENTS ?? env.PROXY_FIREWALL_IPSET_MAX_ELEMENTS ?? "65536",
        "PROXY_FIREWALL_SET_MAX_ELEMENTS",
      ),
      sessionSetName: "session_ipv4",
      sessionMaxElements: positiveInteger(
        env.PROXY_FIREWALL_SESSION_SET_MAX_ELEMENTS ?? "256",
        "PROXY_FIREWALL_SESSION_SET_MAX_ELEMENTS",
      ),
      auditSetName: "audit_ipv4",
      auditDrainingSetName: "audit_draining_ipv4",
      // Audit is an onboarding window, not a host fleet: the cap is small and
      // distinct from the enforce-mode allowlist bound.
      auditMaxElements: positiveInteger(
        env.PROXY_FIREWALL_AUDIT_SET_MAX_ELEMENTS ?? "256",
        "PROXY_FIREWALL_AUDIT_SET_MAX_ELEMENTS",
      ),
    },
    refresh: {
      policyCheckIntervalSeconds: positiveInteger(env.PROXY_FIREWALL_POLICY_SECONDS ?? "2", "PROXY_FIREWALL_POLICY_SECONDS"),
      dnsRefreshIntervalSeconds: positiveInteger(env.PROXY_FIREWALL_DNS_SECONDS ?? env.PROXY_FIREWALL_REFRESH_SECONDS ?? "300", "PROXY_FIREWALL_DNS_SECONDS"),
      maxStaleHostSeconds: positiveInteger(env.PROXY_FIREWALL_MAX_STALE_SECONDS ?? "900", "PROXY_FIREWALL_MAX_STALE_SECONDS"),
    },
    audit: {
      markerPath: auditMarkerPathFromEnv(env),
      spoolPath: auditSpoolPathFromEnv(env),
      resolvedHostsPath: auditResolvedHostsPathFromEnv(env),
      resolveBudgetPerTick: positiveInteger(env.PROXY_FIREWALL_AUDIT_RESOLVE_BUDGET ?? "8", "PROXY_FIREWALL_AUDIT_RESOLVE_BUDGET"),
      drainSeconds: positiveInteger(env.PROXY_FIREWALL_AUDIT_DRAIN_SECONDS ?? "30", "PROXY_FIREWALL_AUDIT_DRAIN_SECONDS"),
    },
  };
}

function requiredString(value: string | undefined, label: string): string {
  if (value === undefined || value.trim() === "") throw new Error(`${label} is required`);
  return value;
}

function ipv4(value: string, label: string): string {
  if (!isValidIpv4(value)) throw new Error(`${label} must be a valid IPv4 address`);
  return value;
}

function tcpPort(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`${label} must be a valid TCP port`);
  }
  return parsed;
}

function positiveInteger(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function cidr(value: string, label: string): string {
  const [address, prefixRaw] = value.split("/");
  const prefix = Number(prefixRaw);
  if (!address || !isValidIpv4(address) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`${label} must be an IPv4 CIDR`);
  }
  return value;
}
