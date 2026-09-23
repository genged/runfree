import { describe, expect, test } from "vitest";

import {
  AUDIT_DEFAULT_DURATION_MS,
  AUDIT_MAX_DURATION_MS,
  aggregateAuditReport,
  auditActivationBanner,
  auditReviewHint,
  buildAuditReportLines,
  extractAuditEvents,
  formatAuditStatusLine,
  parseAuditDuration,
  parseUpOptions,
} from "./audit.ts";

const GENERATION = `sha256:${"a".repeat(64)}`;

function auditLine(fields: Record<string, unknown>): string {
  return `proxy-audit: ${JSON.stringify({ v: 1, generation: GENERATION, ...fields })}`;
}

describe("audit duration parsing", () => {
  test("defaults to 60 minutes and accepts minute and hour forms", () => {
    expect(parseAuditDuration(undefined)).toEqual({ ms: AUDIT_DEFAULT_DURATION_MS, clamped: false });
    expect(parseAuditDuration("45m")).toEqual({ ms: 45 * 60_000, clamped: false });
    expect(parseAuditDuration("45")).toEqual({ ms: 45 * 60_000, clamped: false });
    expect(parseAuditDuration("2h")).toEqual({ ms: 2 * 60 * 60_000, clamped: false });
  });

  test("clamps to the 8h maximum and rejects malformed values", () => {
    expect(parseAuditDuration("8h")).toEqual({ ms: AUDIT_MAX_DURATION_MS, clamped: false });
    expect(parseAuditDuration("9h")).toEqual({ ms: AUDIT_MAX_DURATION_MS, clamped: true });
    expect(parseAuditDuration("600m")).toEqual({ ms: AUDIT_MAX_DURATION_MS, clamped: true });
    expect(() => parseAuditDuration("0")).toThrow(/invalid --audit-network duration/);
    expect(() => parseAuditDuration("-5m")).toThrow(/invalid --audit-network duration/);
    expect(() => parseAuditDuration("1d")).toThrow(/invalid --audit-network duration/);
    expect(() => parseAuditDuration("lots")).toThrow(/invalid --audit-network duration/);
  });

  test("up options accept --audit-network with and without a duration", () => {
    expect(parseUpOptions([])).toEqual({});
    expect(parseUpOptions(["--audit-network"])).toEqual({
      auditDurationMs: AUDIT_DEFAULT_DURATION_MS,
      auditClamped: false,
    });
    expect(parseUpOptions(["--audit-network=2h"])).toEqual({
      auditDurationMs: 2 * 60 * 60_000,
      auditClamped: false,
    });
    expect(() => parseUpOptions(["--bogus"])).toThrow(/usage: runfree up/);
  });
});

describe("audit report aggregation", () => {
  test("parses events, counts suppressed summaries, and re-validates hostnames", () => {
    const logs = [
      "proxy: listening on :8080",
      auditLine({ ts: "2026-06-10T12:05:00.000Z", host: "registry.npmjs.org", method: "GET", path: "/react" }),
      auditLine({ ts: "2026-06-10T12:00:00.000Z", host: "registry.npmjs.org", method: "GET", path: "/lodash" }),
      auditLine({ ts: "2026-06-10T12:06:00.000Z", host: "registry.npmjs.org", suppressed: 212 }),
      auditLine({ ts: "2026-06-10T12:07:00.000Z", host: "api.example.com", method: "POST", path: "/v1" }),
      // Hostile log line: the host fails normalizeHostname and never reaches
      // the report or a suggested command.
      auditLine({ ts: "2026-06-10T12:08:00.000Z", host: "evil_host; rm -rf /" }),
      "proxy-audit: not-json {",
      auditLine({ ts: "2026-06-10T12:09:00.000Z", host: "telemetry.example.com", method: "GET", path: "/v1" }),
    ].join("\n");

    expect(extractAuditEvents(logs)).toHaveLength(6);
    const report = aggregateAuditReport(logs);
    expect(report.startedAt).toBe("2026-06-10T12:00:00.000Z");
    expect(report.hosts).toEqual([
      { host: "registry.npmjs.org", requests: 214, command: "runfree host add registry.npmjs.org" },
      { host: "api.example.com", requests: 1, command: "runfree host add api.example.com" },
      { host: "telemetry.example.com", requests: 1, reviewHint: "telemetry endpoint?" },
    ]);
  });

  test("flags telemetry, analytics, and paste-service hosts as review hints, not verdicts", () => {
    expect(auditReviewHint("telemetry.example.com")).toBe("telemetry endpoint?");
    expect(auditReviewHint("tracking.cdn.example.net")).toBe("telemetry endpoint?");
    expect(auditReviewHint("analytics.example.com")).toBe("analytics endpoint?");
    expect(auditReviewHint("api.segment.io")).toBe("analytics endpoint?");
    expect(auditReviewHint("pastebin.com")).toBe("paste/file-sharing service?");
    expect(auditReviewHint("transfer.sh")).toBe("paste/file-sharing service?");
    expect(auditReviewHint("registry.npmjs.org")).toBeUndefined();
    expect(auditReviewHint("api.example.com")).toBeUndefined();
  });

  test("renders the report with suggested commands and never an auto-apply", () => {
    const report = aggregateAuditReport([
      auditLine({ ts: "2026-06-10T12:00:00.000Z", host: "registry.npmjs.org", method: "GET", path: "/react" }),
      auditLine({ ts: "2026-06-10T12:01:00.000Z", host: "telemetry.example.com", method: "GET", path: "/v1" }),
    ].join("\n"));

    const lines = buildAuditReportLines(report);
    expect(lines[0]).toBe("Observed 2 non-allowlisted hosts (audit session started 12:00 UTC):");
    expect(lines[1]).toContain("registry.npmjs.org");
    expect(lines[1]).toContain("runfree host add registry.npmjs.org");
    const telemetryLine = lines.find((line) => line.includes("telemetry.example.com"));
    expect(telemetryLine).toContain("(review: telemetry endpoint?)");
    expect(lines.at(-1)).toBe("Apply none, some, or all. Runfree never applies these automatically.");
  });

  test("a service member host gets a secondary, clearly-labeled service line; the exact host stays primary", () => {
    const report = aggregateAuditReport([
      auditLine({ ts: "2026-06-10T12:00:00.000Z", host: "registry.npmjs.org", method: "GET", path: "/react" }),
      auditLine({ ts: "2026-06-10T12:01:00.000Z", host: "api.example.com", method: "GET", path: "/v1" }),
    ].join("\n"));

    const lines = buildAuditReportLines(report);
    const primaryIndex = lines.findIndex((line) => line.includes("runfree host add registry.npmjs.org"));
    expect(primaryIndex).toBeGreaterThan(0);
    expect(lines[primaryIndex + 1]).toContain('registry.npmjs.org is part of service "node" (2 hosts).');
    expect(lines[primaryIndex + 2]).toContain("runfree service enable node");
    expect(lines[primaryIndex + 2]).toContain("never applied automatically");
    // Hosts outside every service get no service line of their own.
    const otherIndex = lines.findIndex((line) => line.includes("runfree host add api.example.com"));
    expect(lines[otherIndex + 1]).not.toContain("is part of service");
    expect(lines.join("\n")).not.toContain("api.example.com is part of service");
  });

  test("service lines for services with broad hosts inline the broad-host warning", () => {
    const report = aggregateAuditReport([
      auditLine({ ts: "2026-06-10T12:00:00.000Z", host: "api.github.com", method: "GET", path: "/repos" }),
    ].join("\n"));

    const lines = buildAuditReportLines(report).join("\n");
    expect(lines).toContain('api.github.com is part of service "github" (6 hosts, 1 broad).');
    expect(lines).toContain("runfree service enable github");
    expect(lines).toContain("note: objects.githubusercontent.com");
  });

  test("review-hint hosts never get a service suggestion", () => {
    const report = aggregateAuditReport([
      auditLine({ ts: "2026-06-10T12:00:00.000Z", host: "telemetry.example.com", method: "GET", path: "/v1" }),
    ].join("\n"));

    expect(buildAuditReportLines(report).join("\n")).not.toContain("is part of service");
  });

  test("renders an empty report without suggestions", () => {
    expect(buildAuditReportLines(aggregateAuditReport("proxy: listening on :8080"))).toEqual([
      "no non-allowlisted hosts observed in recent proxy logs (audit events expire with container logs)",
    ]);
  });

  test("--json shape: hosts carry requests plus either a command or a review hint", () => {
    const report = aggregateAuditReport([
      auditLine({ ts: "2026-06-10T12:00:00.000Z", host: "cdn.example.net", method: "GET", path: "/asset" }),
    ].join("\n"));
    expect(JSON.parse(JSON.stringify(report))).toEqual({
      startedAt: "2026-06-10T12:00:00.000Z",
      hosts: [{ host: "cdn.example.net", requests: 1, command: "runfree host add cdn.example.net" }],
    });
  });
});

describe("audit status and banner", () => {
  test("status line states ACTIVE with remaining minutes or inactive", () => {
    expect(formatAuditStatusLine(undefined)).toBe("network audit: unknown (proxy not running)");
    expect(formatAuditStatusLine({ active: false })).toBe("network audit: inactive (enforce mode)");
    expect(formatAuditStatusLine({ active: true, expiresInSeconds: 2_580 }))
      .toBe("network audit: ACTIVE, expires in 43m");
  });

  test("activation banner is loud about the exact relaxation and the residual risk", () => {
    const banner = auditActivationBanner(60 * 60_000, "2026-06-10T13:00:00.000Z").join("\n");
    expect(banner).toContain("NETWORK AUDIT MODE ACTIVE");
    expect(banner).toContain("PERMITTED and logged for 1h");
    expect(banner).toContain("exfiltrate workspace data");
    expect(banner).toContain("runfree audit report");
    expect(banner).toContain("runfree audit off");
  });
});
