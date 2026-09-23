import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import type * as Dns from "node:dns";

export const DEFAULT_RESOLVED_HOSTS_PATH = "/run/runfree-resolved-hosts.json";

export type ResolvedHostsSnapshot = {
  generation: string;
  hosts: Record<string, readonly string[]>;
  // Configured allowlist hosts that produced no safe IPv4 answer this round.
  // Purely diagnostic: it makes a partial allowlist observably partial instead
  // of silently partial. Nothing reads it to make an access decision — an
  // unresolved host simply has no address in `hosts` and no element in the
  // nftables set, so it is already denied.
  unresolvedHosts?: readonly string[];
};

export type ResolvedHostsFile = {
  schemaVersion: 1;
  generation: string;
  hosts: Record<string, string[]>;
  unresolvedHosts: string[];
};

type LookupCallback = (
  error: NodeJS.ErrnoException | null,
  address: string | Dns.LookupAddress[],
  family?: number,
) => void;
export type DnsLookupFunction = (
  hostname: string,
  optionsOrCallback: Dns.LookupOptions | number | LookupCallback,
  callback?: LookupCallback,
) => void;

const require = createRequire(import.meta.url);
const INSTALLED_LOOKUP = Symbol.for("runfree.resolved-host-lookup.installed");

type MutableDnsModule = typeof Dns & {
  [INSTALLED_LOOKUP]?: true;
  lookup: typeof Dns.lookup;
};

export function resolvedHostsPathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.PROXY_RESOLVED_HOSTS_PATH ?? DEFAULT_RESOLVED_HOSTS_PATH;
}

export function writeResolvedHostsFile(filePath: string, snapshot: ResolvedHostsSnapshot): void {
  const normalized = normalizeResolvedHostsFile(snapshot);
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(tmpPath, `${JSON.stringify(normalized, null, 2)}\n`, { mode: 0o644 });
    fs.renameSync(tmpPath, filePath);
    fs.chmodSync(filePath, 0o644);
  } catch (error) {
    fs.rmSync(tmpPath, { force: true });
    throw error;
  }
}

export function readResolvedHostsFile(filePath: string): ResolvedHostsFile | undefined {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isObject(parsed)) return undefined;
    if (parsed.schemaVersion !== 1) return undefined;
    return normalizeResolvedHostsFile({
      generation: typeof parsed.generation === "string" ? parsed.generation : "",
      hosts: isObject(parsed.hosts) ? objectToHostMap(parsed.hosts) : {},
      unresolvedHosts: Array.isArray(parsed.unresolvedHosts)
        ? parsed.unresolvedHosts.filter((host): host is string => typeof host === "string")
        : [],
    });
  } catch {
    return undefined;
  }
}

export function createResolvedHostLookup(input: {
  fallbackLookup?: DnsLookupFunction;
  path: string;
  // Dedicated audit-mode snapshot consulted as a secondary source. Isolation
  // from enforce mode is enforced by the firewall sets and supervisor
  // teardown, not by this lookup: a stale audit answer in the teardown window
  // is still firewall-denied.
  auditPath?: string;
  auditRetry?: {
    totalMs?: number;
    intervalMs?: number;
  };
}): DnsLookupFunction {
  const fallbackLookup = input.fallbackLookup ?? ((...args: Parameters<DnsLookupFunction>) => {
    const dns = require("node:dns") as MutableDnsModule;
    return (dns.lookup as unknown as DnsLookupFunction)(...args);
  }) as DnsLookupFunction;
  const retryTotalMs = input.auditRetry?.totalMs ?? 1_000;
  const retryIntervalMs = Math.max(1, input.auditRetry?.intervalMs ?? 100);

  return ((hostnameRaw: string, optionsOrCallback?: unknown, maybeCallback?: unknown) => {
    const { callback, options } = parseLookupArgs(optionsOrCallback, maybeCallback);
    const hostname = normalizeHostname(hostnameRaw);
    if (hostname === "localhost" || net.isIP(hostname) !== 0) {
      fallbackLookup(hostnameRaw, options ?? {}, callback);
      return;
    }

    const collectIps = (): readonly string[] => {
      const snapshot = readResolvedHostsFile(input.path);
      const ips = snapshot?.hosts[hostname];
      if (ips && ips.length > 0) return ips;
      if (!input.auditPath) return [];
      return readResolvedHostsFile(input.auditPath)?.hosts[hostname] ?? [];
    };

    const respond = (selectedIps: readonly string[]): void => {
      if (isLookupAll(options)) {
        const addresses = selectedIps.map((address) => ({ address, family: 4 }));
        callback(null, addresses);
        return;
      }
      callback(null, selectedIps[0], 4);
    };

    // A just-observed audit host fails until the supervisor's next fast tick
    // installs it; while an audit snapshot exists, retry briefly (bounded)
    // before surfacing the error. In enforce mode the audit snapshot is
    // absent, so failures surface immediately as before.
    const attempt = (remainingMs: number): void => {
      const ips = collectIps();
      const family = lookupFamily(options);
      const selectedIps = family === 6 ? [] : ips;
      if (selectedIps.length > 0) {
        respond(selectedIps);
        return;
      }
      if (
        family !== 6
        && remainingMs > 0
        && input.auditPath !== undefined
        && fs.existsSync(input.auditPath)
      ) {
        setTimeout(() => attempt(remainingMs - retryIntervalMs), retryIntervalMs);
        return;
      }
      callback(hostLookupError(hostname), "", 0);
    };

    process.nextTick(() => attempt(retryTotalMs));
    return;
  }) as DnsLookupFunction;
}

export function installResolvedHostLookup(input: {
  path?: string;
  auditPath?: string;
} = {}): void {
  const dns = require("node:dns") as MutableDnsModule;
  if (dns[INSTALLED_LOOKUP]) return;
  const fallbackLookup = dns.lookup.bind(dns) as DnsLookupFunction;
  dns.lookup = createResolvedHostLookup({
    fallbackLookup,
    path: input.path ?? resolvedHostsPathFromEnv(),
    auditPath: input.auditPath,
  }) as typeof Dns.lookup;
  dns[INSTALLED_LOOKUP] = true;
}

function normalizeResolvedHostsFile(snapshot: ResolvedHostsSnapshot): ResolvedHostsFile {
  if (!/^sha256:[a-f0-9]{64}$/.test(snapshot.generation)) {
    throw new Error(`invalid resolved-host generation: ${snapshot.generation || "<empty>"}`);
  }
  const hosts: Record<string, string[]> = {};
  for (const [host, ips] of Object.entries(snapshot.hosts)) {
    const normalizedHost = normalizeHostname(host);
    if (!normalizedHost) continue;
    const safeIps = Array.from(new Set(ips)).filter((ip) => net.isIP(ip) === 4).sort();
    if (safeIps.length > 0) {
      hosts[normalizedHost] = safeIps;
    }
  }
  // A host that did resolve is never also reported unresolved, so the file is
  // internally consistent even if a caller passes overlapping input.
  const unresolvedHosts = Array.from(new Set(
    (snapshot.unresolvedHosts ?? [])
      .map((host) => normalizeHostname(host))
      .filter((host) => host !== "" && hosts[host] === undefined),
  )).sort();
  return {
    schemaVersion: 1,
    generation: snapshot.generation,
    hosts,
    unresolvedHosts,
  };
}

function normalizeHostname(hostname: string): string {
  return hostname.trim().replace(/\.$/, "").toLowerCase();
}

function objectToHostMap(value: Record<string, unknown>): Record<string, string[]> {
  const hosts: Record<string, string[]> = {};
  for (const [host, ips] of Object.entries(value)) {
    hosts[host] = Array.isArray(ips) ? ips.filter((ip): ip is string => typeof ip === "string") : [];
  }
  return hosts;
}

function parseLookupArgs(optionsOrCallback: unknown, maybeCallback: unknown): {
  callback: LookupCallback;
  options: Dns.LookupOptions | number | undefined;
} {
  if (typeof optionsOrCallback === "function") {
    return { callback: optionsOrCallback as LookupCallback, options: undefined };
  }
  if (typeof maybeCallback === "function") {
    return {
      callback: maybeCallback as LookupCallback,
      options: optionsOrCallback as Dns.LookupOptions | number | undefined,
    };
  }
  throw new Error("dns.lookup callback is required");
}

function lookupFamily(options: Dns.LookupOptions | number | undefined): number | undefined {
  if (typeof options === "number") return options;
  if (typeof options?.family === "number") return options.family;
  return undefined;
}

function isLookupAll(options: Dns.LookupOptions | number | undefined): boolean {
  return typeof options === "object" && options !== null && "all" in options && options.all === true;
}

function hostLookupError(hostname: string): NodeJS.ErrnoException {
  const error = new Error(`getaddrinfo ENOTFOUND ${hostname}`) as NodeJS.ErrnoException & { hostname: string };
  error.code = "ENOTFOUND";
  error.errno = -3008;
  error.syscall = "getaddrinfo";
  error.hostname = hostname;
  return error;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
