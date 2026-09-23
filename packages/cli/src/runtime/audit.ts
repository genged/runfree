// audit.ts — host-side network-policy audit mode commands.
//
// Audit mode is enabled only from the host CLI: the marker is written via
// `docker exec` as root into a root-owned proxy tmpfs dir the UID-1001 proxy
// server cannot write, with `enabledAt` stamped from the proxy container
// clock. The CLI never relaxes anything itself; the proxy server and the
// firewall supervisor independently evaluate the marker with a fail-closed
// expiry clamp of min(expiresAt, min(enabledAt, proxyNow) + 8h).

import { normalizeHostname } from "@runfree/runtime-contracts/network-policy";

import { sanitizeForTerminal } from "../../../../scripts/domain-diagnostics.ts";
import { serviceSuggestionLines, type Service } from "../../../../scripts/services.ts";
import { combinedServiceRegistry } from "../user-services.ts";
import { die } from "../errors.ts";
import { runfreeLog } from "../warnings.ts";
import { ROOT_UID_GID } from "./constants.ts";
import { dockerClientEnvOptions, serviceContainerId, shellSingleQuote } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

export const AUDIT_DEFAULT_DURATION_MS = 60 * 60 * 1000;
export const AUDIT_MAX_DURATION_MS = 8 * 60 * 60 * 1000;
// Fixed in-container path; mirrors PROXY_AUDIT_MARKER_PATH in the proxy
// Compose service. Never derived from project content.
const AUDIT_MARKER_PATH = "/run/runfree-proxy-audit/active.json";
const AUDIT_EVENT_PREFIX = "proxy-audit: ";
const AUDIT_REPORT_LOG_TAIL = 5_000;
const LOG_READ_TIMEOUT_MS = 5_000;

// Runs inside the proxy container as root: stamps enabledAt from the proxy
// clock, clamps the requested duration, and writes the marker atomically.
const ENABLE_MARKER_SCRIPT = `
const fs = require("node:fs");
const durationMs = Number(process.argv[1]);
const maxMs = 8 * 60 * 60 * 1000;
if (!Number.isInteger(durationMs) || durationMs <= 0 || durationMs > maxMs) {
  console.error("invalid audit duration");
  process.exit(1);
}
const markerPath = ${JSON.stringify(AUDIT_MARKER_PATH)};
const now = new Date();
const marker = {
  v: 1,
  enabledAt: now.toISOString(),
  expiresAt: new Date(now.getTime() + durationMs).toISOString(),
  sessionHint: process.argv[2] || "runfree-cli",
};
const tmpPath = markerPath + ".tmp";
fs.writeFileSync(tmpPath, JSON.stringify(marker) + "\\n", { mode: 0o644 });
fs.renameSync(tmpPath, markerPath);
fs.chmodSync(markerPath, 0o644);
console.log(JSON.stringify(marker));
`;

// Runs inside the proxy container: evaluates the marker on the proxy clock
// with the same clamp the proxy server and firewall supervisor apply.
const MARKER_STATUS_SCRIPT = `
const fs = require("node:fs");
const markerPath = ${JSON.stringify(AUDIT_MARKER_PATH)};
const maxMs = 8 * 60 * 60 * 1000;
let state = { active: false };
try {
  const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
  if (marker && marker.v === 1 && typeof marker.enabledAt === "string" && typeof marker.expiresAt === "string") {
    const nowMs = Date.now();
    const enabledAtMs = Date.parse(marker.enabledAt);
    const expiresAtMs = Date.parse(marker.expiresAt);
    if (Number.isFinite(enabledAtMs) && Number.isFinite(expiresAtMs)) {
      const effectiveExpiryMs = Math.min(expiresAtMs, Math.min(enabledAtMs, nowMs) + maxMs);
      if (effectiveExpiryMs > nowMs) {
        state = {
          active: true,
          enabledAt: marker.enabledAt,
          expiresInSeconds: Math.max(1, Math.round((effectiveExpiryMs - nowMs) / 1000)),
        };
      }
    }
  }
} catch {}
console.log(JSON.stringify(state));
`;

export type AuditDuration = {
  ms: number;
  clamped: boolean;
};

// `--audit-network` accepts `<n>m`, `<n>h`, or bare minutes; the default is
// 60 minutes and anything above 8 hours is clamped (and reported) per spec.
export function parseAuditDuration(value: string | undefined): AuditDuration {
  if (value === undefined || value === "") return { ms: AUDIT_DEFAULT_DURATION_MS, clamped: false };
  const match = /^(\d{1,4})(m|h)?$/.exec(value.trim());
  if (!match) {
    die(`invalid --audit-network duration: ${value} (use minutes like 45m or hours like 2h, max 8h)`);
  }
  const amount = Number(match[1]);
  if (amount <= 0) die(`invalid --audit-network duration: ${value}`);
  const ms = amount * (match[2] === "h" ? 60 * 60 * 1000 : 60 * 1000);
  if (ms > AUDIT_MAX_DURATION_MS) {
    return { ms: AUDIT_MAX_DURATION_MS, clamped: true };
  }
  return { ms, clamped: false };
}

export type UpOptions = {
  auditDurationMs?: number;
  auditClamped?: boolean;
  verbose?: boolean;
  useApprovedPolicy?: boolean;
};

export function parseUpOptions(rest: string[]): UpOptions {
  const options: UpOptions = {};
  for (const arg of rest) {
    if (arg === "--verbose" || arg === "-v") {
      options.verbose = true;
      continue;
    }
    if (arg === "--audit-network") {
      const duration = parseAuditDuration(undefined);
      options.auditDurationMs = duration.ms;
      options.auditClamped = duration.clamped;
      continue;
    }
    if (arg.startsWith("--audit-network=")) {
      const duration = parseAuditDuration(arg.slice("--audit-network=".length));
      options.auditDurationMs = duration.ms;
      options.auditClamped = duration.clamped;
      continue;
    }
    die("usage: runfree up [--verbose] [--audit-network[=<duration>]]");
  }
  return options;
}

function runningProxyId(context: RuntimeContext, io: RuntimeIO): string | undefined {
  const project = composeProjectName(context.projectRoot);
  return serviceContainerId(project, "proxy", context, io, { runningOnly: true });
}

function execProxyRootNode(context: RuntimeContext, io: RuntimeIO, proxyId: string, script: string, args: string[]): CaptureResult {
  return io.capture(
    "docker",
    ["exec", "--user", ROOT_UID_GID, proxyId, "node", "-e", script, ...args],
    dockerClientEnvOptions(context),
  );
}

function formatDurationMinutes(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60_000));
  if (minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

export function auditActivationBanner(durationMs: number, expiresAt: string): string[] {
  const border = "=".repeat(72);
  return [
    border,
    "WARNING: NETWORK AUDIT MODE ACTIVE",
    "",
    `Non-allowlisted HTTPS hosts will be PERMITTED and logged for ${formatDurationMinutes(durationMs)}`,
    `(until ${expiresAt}, proxy clock). During this window a compromised agent`,
    "can exfiltrate workspace data to any public HTTPS host, with any method.",
    "Use audit mode for trusted onboarding tasks only.",
    "",
    "  review observed hosts:  runfree audit report",
    "  disable immediately:    runfree audit off",
    border,
  ];
}

export function enableAuditMode(context: RuntimeContext, io: RuntimeIO, options: UpOptions): number {
  const durationMs = options.auditDurationMs ?? AUDIT_DEFAULT_DURATION_MS;
  if (options.auditClamped) {
    runfreeLog("--audit-network duration clamped to the 8h maximum");
  }
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    runfreeLog("no running proxy container; audit mode was not enabled");
    return 1;
  }
  const result = execProxyRootNode(context, io, proxyId, ENABLE_MARKER_SCRIPT, [String(durationMs), "runfree-up"]);
  if (result.status !== 0) {
    runfreeLog(`enabling audit mode failed: ${result.stderr.trim() || "docker exec failed"}`);
    return 1;
  }
  let expiresAt = "<unknown>";
  try {
    const marker = JSON.parse(result.stdout.trim()) as { expiresAt?: string };
    if (typeof marker.expiresAt === "string") expiresAt = marker.expiresAt;
  } catch {
    // Banner falls back to the requested duration only.
  }
  for (const line of auditActivationBanner(durationMs, expiresAt)) console.log(line);
  return 0;
}

type AuditMarkerStatus =
  | { active: false }
  | { active: true; enabledAt?: string; expiresInSeconds: number };

function readAuditMarkerStatus(context: RuntimeContext, io: RuntimeIO): AuditMarkerStatus | undefined {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) return undefined;
  const result = execProxyRootNode(context, io, proxyId, MARKER_STATUS_SCRIPT, []);
  if (result.status !== 0) return undefined;
  try {
    const parsed = JSON.parse(result.stdout.trim()) as AuditMarkerStatus;
    if (typeof parsed !== "object" || parsed === null) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

export function formatAuditStatusLine(status: AuditMarkerStatus | undefined): string {
  if (!status) return "network audit: unknown (proxy not running)";
  if (!status.active) return "network audit: inactive (enforce mode)";
  const minutes = Math.max(1, Math.ceil(status.expiresInSeconds / 60));
  return `network audit: ACTIVE, expires in ${minutes}m`;
}

// Best-effort `runfree status` line; never fails the status command.
export function printAuditStatusLine(context: RuntimeContext, io: RuntimeIO): void {
  try {
    console.log(formatAuditStatusLine(readAuditMarkerStatus(context, io)));
  } catch {
    // Status stays useful even when the proxy cannot be inspected.
  }
}

function auditStatusCommand(context: RuntimeContext, io: RuntimeIO): number {
  const status = readAuditMarkerStatus(context, io);
  console.log(formatAuditStatusLine(status));
  if (status?.active) {
    console.log("review observed hosts: runfree audit report");
    console.log("disable immediately:   runfree audit off");
  }
  return 0;
}

function auditOffCommand(context: RuntimeContext, io: RuntimeIO): number {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    console.log("network audit: inactive (proxy not running)");
    return 0;
  }
  const result = io.capture(
    "docker",
    ["exec", "--user", ROOT_UID_GID, proxyId, "sh", "-c", `rm -f ${shellSingleQuote(AUDIT_MARKER_PATH)}`],
    dockerClientEnvOptions(context),
  );
  if (result.status !== 0) {
    runfreeLog(`disabling audit mode failed: ${result.stderr.trim() || "docker exec failed"}`);
    return 1;
  }
  console.log("network audit: disabled; enforcement resumes within seconds");
  console.log("the firewall severs in-flight audited connections on its next fast tick");
  return 0;
}

// --- Report --------------------------------------------------------------------

type ProxyAuditEvent = {
  v?: unknown;
  ts?: string;
  host?: string;
  method?: string;
  path?: string;
  generation?: string;
  suppressed?: number;
};

export type AuditReportHost = {
  host: string;
  requests: number;
  reviewHint?: string;
  command?: string;
};

export type AuditReport = {
  startedAt?: string;
  hosts: AuditReportHost[];
};

// Small built-in heuristic list of host categories worth a second look.
// Review hints, not verdicts: the report never mutates policy.
const AUDIT_REVIEW_HINTS: ReadonlyArray<{ matches: (host: string) => boolean; hint: string }> = [
  {
    matches: (host) => /(^|[.-])(telemetry|tracking|metrics)([.-]|$)/.test(host),
    hint: "telemetry endpoint?",
  },
  {
    matches: (host) => /(^|[.-])(analytics|stats)([.-]|$)/.test(host)
      || /(^|\.)(segment\.(io|com)|mixpanel\.com|amplitude\.com|posthog\.com|statsig\.com)$/.test(host),
    hint: "analytics endpoint?",
  },
  {
    matches: (host) => /(^|\.)(pastebin\.com|paste\.ee|hastebin\.com|dpaste\.org|transfer\.sh|file\.io|gofile\.io|0x0\.st|anonfiles\.com|temp\.sh)$/.test(host),
    hint: "paste/file-sharing service?",
  },
];

export function auditReviewHint(host: string): string | undefined {
  for (const entry of AUDIT_REVIEW_HINTS) {
    if (entry.matches(host)) return entry.hint;
  }
  return undefined;
}

// Parses `proxy-audit: {...}` lines, tolerating unknown fields and skipping
// malformed JSON; logs are untrusted input.
export function extractAuditEvents(logs: string): ProxyAuditEvent[] {
  const events: ProxyAuditEvent[] = [];
  for (const line of logs.split(/\r?\n/)) {
    const start = line.indexOf(AUDIT_EVENT_PREFIX);
    if (start === -1) continue;
    const raw = line.slice(start + AUDIT_EVENT_PREFIX.length).trim();
    if (!raw.startsWith("{")) continue;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) continue;
      events.push(parsed as ProxyAuditEvent);
    } catch {
      // Skip malformed event lines.
    }
  }
  return events;
}

// Aggregates observation events into a per-host report. Every hostname is
// re-validated through normalizeHostname before display so log lines can
// never inject an unverified value into a suggested command.
export function aggregateAuditReport(logs: string): AuditReport {
  const counts = new Map<string, number>();
  let startedAt: string | undefined;
  for (const event of extractAuditEvents(logs)) {
    if (typeof event.host !== "string") continue;
    let host: string;
    try {
      host = normalizeHostname(event.host);
    } catch {
      continue;
    }
    const suppressed = typeof event.suppressed === "number" && Number.isFinite(event.suppressed) && event.suppressed > 0
      ? Math.floor(event.suppressed)
      : undefined;
    counts.set(host, (counts.get(host) ?? 0) + (suppressed ?? 1));
    if (typeof event.ts === "string" && Number.isFinite(Date.parse(event.ts))) {
      if (startedAt === undefined || Date.parse(event.ts) < Date.parse(startedAt)) {
        startedAt = event.ts;
      }
    }
  }

  const hosts: AuditReportHost[] = Array.from(counts.entries())
    .sort(([leftHost, leftCount], [rightHost, rightCount]) => rightCount - leftCount || leftHost.localeCompare(rightHost))
    .map(([host, requests]) => {
      const reviewHint = auditReviewHint(host);
      return {
        host,
        requests,
        ...(reviewHint !== undefined ? { reviewHint } : { command: `runfree host add ${host}` }),
      };
    });

  return {
    ...(startedAt !== undefined ? { startedAt } : {}),
    hosts,
  };
}

export function buildAuditReportLines(report: AuditReport, registry?: Record<string, Service>): string[] {
  if (report.hosts.length === 0) {
    return ["no non-allowlisted hosts observed in recent proxy logs (audit events expire with container logs)"];
  }
  const startedSuffix = report.startedAt !== undefined
    ? ` (audit session started ${report.startedAt.slice(11, 16)} UTC)`
    : "";
  const hostWidth = Math.max(...report.hosts.map((entry) => entry.host.length));
  const countWidth = Math.max(...report.hosts.map((entry) => String(entry.requests).length));
  const lines = [
    `Observed ${report.hosts.length} non-allowlisted ${report.hosts.length === 1 ? "host" : "hosts"}${startedSuffix}:`,
  ];
  for (const entry of report.hosts) {
    const host = sanitizeForTerminal(entry.host);
    const requests = `${String(entry.requests).padStart(countWidth)} ${entry.requests === 1 ? "request " : "requests"}`;
    const suggestion = entry.reviewHint !== undefined
      ? `(review: ${entry.reviewHint})`
      : sanitizeForTerminal(entry.command ?? "");
    lines.push(`  ${host.padEnd(hostWidth)}   ${requests}   ${suggestion}`);
    // Secondary option only: `runfree host add <host>` above stays the primary
    // suggestion; the owning service is named but never auto-applied, with
    // broad-host warnings inlined by serviceSuggestionLines.
    if (entry.command !== undefined) {
      for (const serviceLine of serviceSuggestionLines(entry.host, registry)) {
        lines.push(`      ${sanitizeForTerminal(serviceLine)}`);
      }
    }
  }
  lines.push("Apply none, some, or all. Runfree never applies these automatically.");
  return lines;
}

function auditReport(json: boolean, context: RuntimeContext, io: RuntimeIO): number {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    if (json) {
      console.log(JSON.stringify({ hosts: [] }, null, 2));
      return 0;
    }
    console.log("no running proxy container; nothing to report");
    return 0;
  }
  const logs = io.capture(
    "docker",
    ["logs", "--tail", String(AUDIT_REPORT_LOG_TAIL), proxyId],
    { ...dockerClientEnvOptions(context), timeout: LOG_READ_TIMEOUT_MS },
  );
  if (logs.status !== 0) {
    runfreeLog(`could not read proxy logs: ${logs.stderr.trim() || "docker logs failed"}`);
    return 1;
  }
  const report = aggregateAuditReport(`${logs.stdout}\n${logs.stderr}`);
  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return 0;
  }
  for (const line of buildAuditReportLines(report, combinedServiceRegistry(context.projectRoot, context.env))) console.log(line);
  return 0;
}

// Typed audit intent built by the yargs audit command module.
export type AuditInput = { kind: "status" } | { kind: "off" } | { kind: "report"; json: boolean };

// Typed core for `runfree audit`. The caller asserts Docker availability before
// this runs.
export function auditRuntime(input: AuditInput, context: RuntimeContext, io: RuntimeIO): number {
  switch (input.kind) {
    case "status":
      return auditStatusCommand(context, io);
    case "off":
      return auditOffCommand(context, io);
    case "report":
      return auditReport(input.json, context, io);
  }
}
