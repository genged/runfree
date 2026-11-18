import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { setOutputWriterForTest } from "../warnings.ts";
import {
  AUDIT_DEFAULT_DURATION_MS,
  AUDIT_MAX_DURATION_MS,
  aggregateAuditReport,
  auditActivationBanner,
  auditReviewHint,
  auditRuntime,
  buildAuditReportLines,
  enableAuditMode,
  extractAuditEvents,
  formatAuditStatusLine,
  parseAuditDuration,
  parseUpOptions,
  printAuditStatusLine,
  MARKER_STATUS_SCRIPT,
} from "./audit.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

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

describe("the in-container marker status script", () => {
  // The script runs inside the proxy container and cannot import the proxy's
  // `effectiveAuditExpiryMs`, so its copy of the clamp is pinned here to the
  // same formula and the same bound: min(expiresAt, min(enabledAt, now) + 8h).
  test("applies the proxy's own expiry clamp with the shared maximum", () => {
    expect(MARKER_STATUS_SCRIPT).toContain("const maxMs = 8 * 60 * 60 * 1000;");
    expect(8 * 60 * 60 * 1000).toBe(AUDIT_MAX_DURATION_MS);
    expect(MARKER_STATUS_SCRIPT).toContain("Math.min(expiresAtMs, Math.min(enabledAtMs, nowMs) + maxMs)");
    // The same inputs through the script's expression and the proxy formula.
    const clamp = new Function("expiresAtMs", "enabledAtMs", "nowMs", "maxMs", "return Math.min(expiresAtMs, Math.min(enabledAtMs, nowMs) + maxMs);") as
      (expiresAtMs: number, enabledAtMs: number, nowMs: number, maxMs: number) => number;
    const proxyFormula = (enabledAtMs: number, expiresAtMs: number, nowMs: number) =>
      Math.min(expiresAtMs, Math.min(enabledAtMs, nowMs) + AUDIT_MAX_DURATION_MS);
    const now = Date.parse("2026-11-08T12:00:00.000Z");
    for (const [enabledAt, expiresAt] of [
      [now - 60_000, now + 3_600_000],
      [now + 3_600_000, now + 48 * 3_600_000],
      [now - 9 * 3_600_000, now + 3_600_000],
    ]) {
      expect(clamp(expiresAt as number, enabledAt as number, now, AUDIT_MAX_DURATION_MS)).toBe(proxyFormula(enabledAt as number, expiresAt as number, now));
    }
  });
});

// --- Host commands through a fake RuntimeIO --------------------------------

const PROXY_ID = "f".repeat(64);
const MARKER_PATH_LITERAL = JSON.stringify("/run/runfree-proxy-audit/active.json");

type FakeDocker = {
  proxyId?: string;
  exec?: CaptureResult;
  logs?: CaptureResult;
  throwOnCapture?: boolean;
};

const ok = (stdout = "", stderr = ""): CaptureResult => ({ status: 0, stdout, stderr });
const fail = (stderr = ""): CaptureResult => ({ status: 1, stdout: "", stderr });

function fakeIO(docker: FakeDocker): { io: RuntimeIO; calls: string[][] } {
  const calls: string[][] = [];
  const io: RuntimeIO = {
    capture(command, args) {
      if (docker.throwOnCapture) throw new Error("docker unavailable");
      expect(command).toBe("docker");
      calls.push([...args]);
      switch (args[0]) {
        case "ps":
          return ok(docker.proxyId === undefined ? "" : `${docker.proxyId}\n`);
        case "exec":
          return docker.exec ?? ok();
        case "logs":
          return docker.logs ?? ok();
        default:
          throw new Error(`unexpected docker call: ${args.join(" ")}`);
      }
    },
    run: () => { throw new Error("audit commands must not use io.run"); },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => { throw new Error("audit commands must not sync credentials"); },
  };
  return { io, calls };
}

let tempRoot = "";
let printed: string[] = [];
let logged: string[] = [];

function runtimeContext(): RuntimeContext {
  return {
    projectRoot: path.join(tempRoot, "project"),
    project: { config: {}, paths: { stateDir: path.join(tempRoot, "project", ".runfree", "state") } },
    runtimeRoot: path.join(tempRoot, "runtime"),
    // An empty XDG config, so the user service registry never reads the
    // developer's real config.
    env: { PATH: "/bin", XDG_CONFIG_HOME: path.join(tempRoot, "xdg") },
  } as unknown as RuntimeContext;
}

const execCalls = (calls: string[][]) => calls.filter((args) => args[0] === "exec");
const logsCalls = (calls: string[][]) => calls.filter((args) => args[0] === "logs");
function firstCall(calls: string[][], kind: "exec" | "logs"): string[] {
  const call = calls.find((args) => args[0] === kind);
  if (!call) throw new Error(`no docker ${kind} call was recorded`);
  return call;
}
const loggedText = () => logged.join("\n");
const userOf = (argv: string[]) => argv[argv.indexOf("--user") + 1];

beforeEach(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-audit-test-"));
  printed = [];
  logged = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    printed.push(args.map(String).join(" "));
  });
  setOutputWriterForTest((line) => logged.push(line));
});

afterEach(() => {
  vi.restoreAllMocks();
  setOutputWriterForTest(undefined);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

describe("enableAuditMode", () => {
  test("no running proxy: returns 1, says audit mode was not enabled, and never execs", () => {
    const { io, calls } = fakeIO({});
    expect(enableAuditMode(runtimeContext(), io, { auditDurationMs: 60_000 })).toBe(1);
    expect(loggedText()).toContain("no running proxy container; audit mode was not enabled");
    expect(calls.map((args) => args[0])).toEqual(["ps"]);
    // Only running proxies count.
    expect(calls[0]).not.toContain("--all");
    expect(printed).toEqual([]);
  });

  test("success: execs the marker script as root in the proxy and prints the banner with the proxy's expiry", () => {
    const expiresAt = "2026-11-18T13:00:00.000Z";
    const durationMs = 2 * 60 * 60_000;
    const { io, calls } = fakeIO({ proxyId: PROXY_ID, exec: ok(`${JSON.stringify({ v: 1, expiresAt })}\n`) });
    expect(enableAuditMode(runtimeContext(), io, { auditDurationMs: durationMs })).toBe(0);
    const exec = firstCall(calls, "exec");
    expect(userOf(exec)).toBe("0:0");
    expect(exec.indexOf(PROXY_ID)).toBeGreaterThan(exec.indexOf("--user"));
    expect(exec[exec.indexOf("node") + 1]).toBe("-e");
    expect(exec.slice(-2)).toEqual([String(durationMs), "runfree-up"]);
    expect(printed).toEqual(auditActivationBanner(durationMs, expiresAt));
    expect(loggedText()).not.toContain("clamped");
  });

  test("an unset duration requests the 1h default", () => {
    const { io, calls } = fakeIO({ proxyId: PROXY_ID, exec: ok("{}") });
    expect(enableAuditMode(runtimeContext(), io, {})).toBe(0);
    expect(firstCall(calls, "exec").at(-2)).toBe("3600000");
  });

  test("a clamped duration is reported", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec: ok("{}") });
    expect(enableAuditMode(runtimeContext(), io, { auditDurationMs: AUDIT_MAX_DURATION_MS, auditClamped: true })).toBe(0);
    expect(loggedText()).toContain("--audit-network duration clamped to the 8h maximum");
  });

  test("exec failure: returns 1 with the proxy's stderr and prints no banner", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec: fail("invalid audit duration\n") });
    expect(enableAuditMode(runtimeContext(), io, { auditDurationMs: 60_000 })).toBe(1);
    expect(loggedText()).toContain("enabling audit mode failed: invalid audit duration");
    expect(printed).not.toContain("WARNING: NETWORK AUDIT MODE ACTIVE");
    expect(printed).toEqual([]);
  });

  test("exec failure with blank stderr falls back to 'docker exec failed'", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec: fail("  \n") });
    expect(enableAuditMode(runtimeContext(), io, { auditDurationMs: 60_000 })).toBe(1);
    expect(loggedText()).toContain("enabling audit mode failed: docker exec failed");
    expect(printed).toEqual([]);
  });

  test("non-JSON stdout still enables and shows an unknown expiry", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec: ok("not json") });
    expect(enableAuditMode(runtimeContext(), io, { auditDurationMs: 60_000 })).toBe(0);
    expect(printed).toContain("WARNING: NETWORK AUDIT MODE ACTIVE");
    expect(printed.join("\n")).toContain("(until <unknown>, proxy clock)");
  });
});

describe("runfree audit status", () => {
  const UNKNOWN = "network audit: unknown (proxy not running)";

  test("no running proxy: unknown, and no exec", () => {
    const { io, calls } = fakeIO({});
    expect(auditRuntime({ kind: "status" }, runtimeContext(), io)).toBe(0);
    expect(printed).toEqual([UNKNOWN]);
    expect(execCalls(calls)).toEqual([]);
  });

  test.each([
    ["exec fails", fail("boom")],
    ["stdout is not JSON", ok("not json")],
    ["stdout is JSON null", ok("null")],
  ])("%s: unknown", (_label, exec) => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec });
    expect(auditRuntime({ kind: "status" }, runtimeContext(), io)).toBe(0);
    expect(printed).toEqual([UNKNOWN]);
  });

  test("inactive marker: only the inactive line; the status script runs as root", () => {
    const { io, calls } = fakeIO({ proxyId: PROXY_ID, exec: ok('{"active":false}\n') });
    expect(auditRuntime({ kind: "status" }, runtimeContext(), io)).toBe(0);
    expect(printed).toEqual(["network audit: inactive (enforce mode)"]);
    const exec = firstCall(calls, "exec");
    expect(userOf(exec)).toBe("0:0");
    expect(exec).toContain(PROXY_ID);
    expect(exec).toContain(MARKER_STATUS_SCRIPT);
  });

  test("active marker: rounded-up minutes plus the review and disable hints, in order", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec: ok('{"active":true,"expiresInSeconds":61}') });
    expect(auditRuntime({ kind: "status" }, runtimeContext(), io)).toBe(0);
    expect(printed).toEqual([
      "network audit: ACTIVE, expires in 2m",
      "review observed hosts: runfree audit report",
      "disable immediately:   runfree audit off",
    ]);
  });
});

describe("printAuditStatusLine", () => {
  test("prints only the status line for an active marker", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, exec: ok('{"active":true,"expiresInSeconds":2580}') });
    printAuditStatusLine(runtimeContext(), io);
    expect(printed).toEqual(["network audit: ACTIVE, expires in 43m"]);
  });

  test("never throws, and prints nothing, when Docker cannot be inspected", () => {
    const { io } = fakeIO({ throwOnCapture: true });
    expect(() => printAuditStatusLine(runtimeContext(), io)).not.toThrow();
    expect(printed).toEqual([]);
  });
});

describe("runfree audit off", () => {
  test("no running proxy: inactive, returns 0, and no exec", () => {
    const { io, calls } = fakeIO({});
    expect(auditRuntime({ kind: "off" }, runtimeContext(), io)).toBe(0);
    expect(printed).toEqual(["network audit: inactive (proxy not running)"]);
    expect(execCalls(calls)).toEqual([]);
  });

  test("success: removes exactly the fixed marker path as root", () => {
    const { io, calls } = fakeIO({ proxyId: PROXY_ID, exec: ok() });
    expect(auditRuntime({ kind: "off" }, runtimeContext(), io)).toBe(0);
    const exec = firstCall(calls, "exec");
    expect(userOf(exec)).toBe("0:0");
    expect(exec).toContain(PROXY_ID);
    expect(exec.slice(-3)).toEqual(["sh", "-c", "rm -f '/run/runfree-proxy-audit/active.json'"]);
    expect(printed).toEqual([
      "network audit: disabled; enforcement resumes within seconds",
      "the firewall severs in-flight audited connections on its next fast tick",
    ]);
  });

  test("exec failure: returns 1 with the stderr, or 'docker exec failed' when blank", () => {
    const first = fakeIO({ proxyId: PROXY_ID, exec: fail("permission denied\n") });
    expect(auditRuntime({ kind: "off" }, runtimeContext(), first.io)).toBe(1);
    expect(loggedText()).toContain("disabling audit mode failed: permission denied");
    const second = fakeIO({ proxyId: PROXY_ID, exec: fail("") });
    expect(auditRuntime({ kind: "off" }, runtimeContext(), second.io)).toBe(1);
    expect(loggedText()).toContain("disabling audit mode failed: docker exec failed");
    expect(printed).toEqual([]);
  });
});

describe("runfree audit report", () => {
  test("no running proxy: empty JSON or a nothing-to-report line, and no logs read", () => {
    const json = fakeIO({});
    expect(auditRuntime({ kind: "report", json: true }, runtimeContext(), json.io)).toBe(0);
    expect(JSON.parse(printed.join("\n"))).toEqual({ hosts: [] });
    expect(logsCalls(json.calls)).toEqual([]);
    printed = [];
    const text = fakeIO({});
    expect(auditRuntime({ kind: "report", json: false }, runtimeContext(), text.io)).toBe(0);
    expect(printed).toEqual(["no running proxy container; nothing to report"]);
    expect(logsCalls(text.calls)).toEqual([]);
  });

  test("logs failure: returns 1 with the stderr, or 'docker logs failed' when blank", () => {
    const first = fakeIO({ proxyId: PROXY_ID, logs: fail("no such container\n") });
    expect(auditRuntime({ kind: "report", json: true }, runtimeContext(), first.io)).toBe(1);
    expect(loggedText()).toContain("could not read proxy logs: no such container");
    const second = fakeIO({ proxyId: PROXY_ID, logs: fail("") });
    expect(auditRuntime({ kind: "report", json: false }, runtimeContext(), second.io)).toBe(1);
    expect(loggedText()).toContain("could not read proxy logs: docker logs failed");
    expect(printed).toEqual([]);
  });

  const host = "cdn.example.net";
  // Two events on stdout and one on stderr: Docker splits a container's log
  // streams, and the proxy may write audit events to either.
  const splitLogs = () => ok(
    [auditLine({ ts: "2026-06-10T12:01:00.000Z", host }), auditLine({ ts: "2026-06-10T12:02:00.000Z", host })].join("\n"),
    auditLine({ ts: "2026-06-10T12:00:00.000Z", host }),
  );

  test("json: counts audit events from both stdout and stderr of the last 5000 log lines", () => {
    const { io, calls } = fakeIO({ proxyId: PROXY_ID, logs: splitLogs() });
    expect(auditRuntime({ kind: "report", json: true }, runtimeContext(), io)).toBe(0);
    const logs = firstCall(calls, "logs");
    expect(logs[logs.indexOf("--tail") + 1]).toBe("5000");
    expect(logs).toContain(PROXY_ID);
    expect(JSON.parse(printed.join("\n"))).toEqual({
      startedAt: "2026-06-10T12:00:00.000Z",
      hosts: [{ host, requests: 3, command: `runfree host add ${host}` }],
    });
  });

  test("text: prints the observed header and the host add suggestion", () => {
    const { io } = fakeIO({ proxyId: PROXY_ID, logs: splitLogs() });
    expect(auditRuntime({ kind: "report", json: false }, runtimeContext(), io)).toBe(0);
    expect(printed[0]).toBe("Observed 1 non-allowlisted host (audit session started 12:00 UTC):");
    expect(printed[1]).toContain(host);
    expect(printed[1]).toContain("3 requests");
    expect(printed[1]).toContain(`runfree host add ${host}`);
    expect(printed.at(-1)).toBe("Apply none, some, or all. Runfree never applies these automatically.");
  });
});

// --- The in-container scripts, really executed ------------------------------

// The enable script is not exported: take it from the argv the CLI hands to
// `docker exec`, exactly as the proxy container would receive it.
function captureEnableScript(): string {
  const { io, calls } = fakeIO({ proxyId: PROXY_ID, exec: ok("{}") });
  enableAuditMode(runtimeContext(), io, { auditDurationMs: 60_000 });
  printed = [];
  const exec = firstCall(calls, "exec");
  const script = exec[exec.indexOf("-e") + 1];
  if (script === undefined) throw new Error("no node -e script in the exec argv");
  return script;
}

// Points the script's fixed marker path at a temp file; fails loudly if the
// literal path changes or appears more than once.
function withMarkerPath(script: string, markerPath: string): string {
  expect(script.split(MARKER_PATH_LITERAL)).toHaveLength(2);
  return script.replace(MARKER_PATH_LITERAL, JSON.stringify(markerPath));
}

function runNode(script: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(process.execPath, ["-e", script, ...args], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe("the in-container enable script, really executed", () => {
  test.each(["0", "1.5", "abc", String(AUDIT_MAX_DURATION_MS + 1)])("rejects duration %s and writes no marker", (duration) => {
    const markerPath = path.join(tempRoot, "active.json");
    const result = runNode(withMarkerPath(captureEnableScript(), markerPath), [duration, "runfree-up"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("invalid audit duration");
    expect(fs.existsSync(markerPath)).toBe(false);
    expect(fs.existsSync(`${markerPath}.tmp`)).toBe(false);
  });

  test.each([AUDIT_MAX_DURATION_MS, 60_000])("writes a 0644 marker for %i ms atomically and prints it", (duration) => {
    const markerPath = path.join(tempRoot, "active.json");
    const result = runNode(withMarkerPath(captureEnableScript(), markerPath), [String(duration), "runfree-up"]);
    expect(result.status).toBe(0);
    expect(fs.statSync(markerPath).mode & 0o777).toBe(0o644);
    expect(fs.existsSync(`${markerPath}.tmp`)).toBe(false);
    const marker = JSON.parse(fs.readFileSync(markerPath, "utf8")) as Record<string, unknown>;
    expect(JSON.parse(result.stdout)).toEqual(marker);
    expect(marker.v).toBe(1);
    expect(marker.sessionHint).toBe("runfree-up");
    expect(Date.parse(marker.expiresAt as string) - Date.parse(marker.enabledAt as string)).toBe(duration);
  });

  test("defaults the session hint to runfree-cli", () => {
    const markerPath = path.join(tempRoot, "active.json");
    const result = runNode(withMarkerPath(captureEnableScript(), markerPath), ["60000"]);
    expect(result.status).toBe(0);
    expect(JSON.parse(fs.readFileSync(markerPath, "utf8"))).toMatchObject({ sessionHint: "runfree-cli" });
  });
});

describe("the in-container status script, really executed", () => {
  const HOUR = 3_600_000;
  const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
  const markerJson = (fields: Record<string, unknown>) => JSON.stringify({ v: 1, sessionHint: "runfree-up", ...fields });

  function statusFor(marker: string | undefined): Record<string, unknown> {
    const markerPath = path.join(tempRoot, "active.json");
    if (marker !== undefined) fs.writeFileSync(markerPath, marker);
    const result = runNode(withMarkerPath(MARKER_STATUS_SCRIPT, markerPath), []);
    expect(result.status).toBe(0);
    return JSON.parse(result.stdout) as Record<string, unknown>;
  }

  test.each([
    ["a missing marker", () => undefined],
    ["invalid JSON", () => "{not json"],
    ["v: 2", () => markerJson({ v: 2, enabledAt: iso(0), expiresAt: iso(HOUR) })],
    ["a non-string enabledAt", () => markerJson({ enabledAt: Date.now(), expiresAt: iso(HOUR) })],
    ["an unparsable expiresAt", () => markerJson({ enabledAt: iso(0), expiresAt: "soon" })],
    ["an expired marker", () => markerJson({ enabledAt: iso(-2 * HOUR), expiresAt: iso(-1_000) })],
  ])("%s is inactive", (_label, marker) => {
    expect(statusFor(marker())).toEqual({ active: false });
  });

  test("a marker enabled a minute ago, expiring in 1h, is active for about an hour", () => {
    const enabledAt = iso(-60_000);
    const status = statusFor(markerJson({ enabledAt, expiresAt: iso(HOUR) }));
    expect(status).toMatchObject({ active: true, enabledAt });
    expect(status.expiresInSeconds).toBeGreaterThanOrEqual(3_590);
    expect(status.expiresInSeconds).toBeLessThanOrEqual(3_600);
  });

  test("a future enabledAt cannot stretch the window past 8h from now", () => {
    const status = statusFor(markerJson({ enabledAt: iso(HOUR), expiresAt: iso(48 * HOUR) }));
    expect(status.active).toBe(true);
    expect(status.expiresInSeconds).toBeLessThanOrEqual(8 * 3_600);
    expect(status.expiresInSeconds).toBeGreaterThanOrEqual(8 * 3_600 - 10);
  });

  test("a marker enabled 9h ago is inactive even though expiresAt is ahead", () => {
    expect(statusFor(markerJson({ enabledAt: iso(-9 * HOUR), expiresAt: iso(HOUR) }))).toEqual({ active: false });
  });
});
