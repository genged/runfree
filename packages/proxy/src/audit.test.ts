import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "vitest";

import {
  AUDIT_MAX_DURATION_MS,
  createAuditEventEmitter,
  createAuditSpoolWriter,
  effectiveAuditExpiryMs,
  parseAuditMarker,
  readAuditMarkerState,
  validateAuditSpoolLines,
} from "./audit.ts";

const NOW_MS = Date.parse("2026-06-10T12:00:00.000Z");

function marker(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    enabledAt: "2026-06-10T12:00:00.000Z",
    expiresAt: "2026-06-10T13:00:00.000Z",
    sessionHint: "rf-test",
    ...overrides,
  });
}

describe("audit marker parsing", () => {
  test("missing, malformed, wrong-version, and expired markers all yield enforce mode", () => {
    expect(parseAuditMarker(undefined, NOW_MS)).toEqual({ active: false });
    expect(parseAuditMarker("", NOW_MS)).toEqual({ active: false });
    expect(parseAuditMarker("not-json", NOW_MS)).toEqual({ active: false });
    expect(parseAuditMarker("[]", NOW_MS)).toEqual({ active: false });
    expect(parseAuditMarker(marker({ v: 2 }), NOW_MS)).toEqual({ active: false });
    expect(parseAuditMarker(marker({ enabledAt: 42 }), NOW_MS)).toEqual({ active: false });
    expect(parseAuditMarker(marker({ expiresAt: "garbage" }), NOW_MS)).toEqual({ active: false });
    // Expired by the proxy clock.
    expect(parseAuditMarker(marker(), Date.parse("2026-06-10T13:00:00.001Z"))).toEqual({ active: false });
  });

  test("valid markers are active until the effective expiry", () => {
    const state = parseAuditMarker(marker(), NOW_MS + 60_000);
    expect(state).toEqual({
      active: true,
      enabledAtMs: NOW_MS,
      effectiveExpiryMs: Date.parse("2026-06-10T13:00:00.000Z"),
    });
  });

  test("a far-future expiresAt is honored only to enabledAt + MAX_DURATION", () => {
    const state = parseAuditMarker(marker({ expiresAt: "2030-01-01T00:00:00.000Z" }), NOW_MS);
    expect(state).toEqual({
      active: true,
      enabledAtMs: NOW_MS,
      effectiveExpiryMs: NOW_MS + AUDIT_MAX_DURATION_MS,
    });
    expect(parseAuditMarker(marker({ expiresAt: "2030-01-01T00:00:00.000Z" }), NOW_MS + AUDIT_MAX_DURATION_MS))
      .toEqual({ active: false });
  });

  test("a future-dated enabledAt from host clock skew cannot extend the window", () => {
    // enabledAt one hour in the proxy's future: the effective enabledAt is
    // clamped to proxyNow, so the cap is proxyNow + 8h, not skewed + 8h.
    const skewed = marker({
      enabledAt: "2026-06-10T13:00:00.000Z",
      expiresAt: "2030-01-01T00:00:00.000Z",
    });
    const state = parseAuditMarker(skewed, NOW_MS);
    expect(state).toEqual({
      active: true,
      enabledAtMs: Date.parse("2026-06-10T13:00:00.000Z"),
      effectiveExpiryMs: NOW_MS + AUDIT_MAX_DURATION_MS,
    });
  });

  test("effective expiry clamp: min(expiresAt, min(enabledAt, now) + 8h)", () => {
    expect(effectiveAuditExpiryMs(NOW_MS, NOW_MS + 60_000, NOW_MS)).toBe(NOW_MS + 60_000);
    expect(effectiveAuditExpiryMs(NOW_MS, NOW_MS + AUDIT_MAX_DURATION_MS * 2, NOW_MS)).toBe(NOW_MS + AUDIT_MAX_DURATION_MS);
    expect(effectiveAuditExpiryMs(NOW_MS + 3_600_000, NOW_MS + AUDIT_MAX_DURATION_MS * 2, NOW_MS)).toBe(NOW_MS + AUDIT_MAX_DURATION_MS);
  });

  test("readAuditMarkerState treats unreadable files as enforce mode", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-audit-marker-"));
    try {
      expect(readAuditMarkerState(path.join(tmp, "missing.json"), NOW_MS)).toEqual({ active: false });
      const markerPath = path.join(tmp, "active.json");
      fs.writeFileSync(markerPath, marker());
      expect(readAuditMarkerState(markerPath, NOW_MS)).toMatchObject({ active: true });
      fs.writeFileSync(markerPath, "{broken");
      expect(readAuditMarkerState(markerPath, NOW_MS)).toEqual({ active: false });
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("audit spool writer", () => {
  test("writes normalized hostnames only, deduplicates, and respects the size cap", () => {
    const appended: string[] = [];
    const logs: string[] = [];
    const writer = createAuditSpoolWriter({
      path: "/spool",
      appendFile: (_path, data) => appended.push(data),
      log: (line) => logs.push(line),
      maxBytes: 40,
    });

    writer.record("API.Example.COM.");
    writer.record("api.example.com");
    writer.record("bad_host!.example");
    writer.record("second.example");
    expect(appended).toEqual(["api.example.com\n", "second.example\n"]);

    // 16 + 15 = 31 bytes written; the next 15-byte line exceeds the 40-byte cap.
    writer.record("capped0.example");
    expect(appended).toHaveLength(2);
    expect(logs).toContainEqual(expect.stringContaining("spool size cap reached"));

    writer.reset();
    writer.record("api.example.com");
    expect(appended).toEqual(["api.example.com\n", "second.example\n", "api.example.com\n"]);
  });
});

describe("audit spool validation", () => {
  test("rejects oversized lines and lines failing normalizeHostname, counting each", () => {
    const validation = validateAuditSpoolLines([
      "good.example",
      `${"a".repeat(300)}.example`,
      "bad_host!.example",
      " Mixed.Case.Example ",
      "good.example",
      "",
    ]);
    expect(validation.hosts).toEqual(["good.example", "mixed.case.example"]);
    expect(validation.rejectedLines).toBe(2);
  });
});

describe("audit observation events", () => {
  test("emits schema-bounded events with pathname only and no query string", () => {
    const lines: string[] = [];
    const emitter = createAuditEventEmitter({
      log: (line) => lines.push(line),
      now: () => new Date("2026-06-10T12:00:00.000Z"),
    });

    emitter.emit({
      host: "api.example.com",
      method: "GET",
      path: "https://api.example.com/v1/data?secret_param=value#frag",
      generation: `sha256:${"a".repeat(64)}`,
    });

    expect(lines).toHaveLength(1);
    expect(lines[0].startsWith("proxy-audit: ")).toBe(true);
    const event = JSON.parse(lines[0].slice("proxy-audit: ".length)) as Record<string, unknown>;
    expect(event).toEqual({
      v: 1,
      ts: "2026-06-10T12:00:00.000Z",
      host: "api.example.com",
      method: "GET",
      path: "/v1/data",
      generation: `sha256:${"a".repeat(64)}`,
    });
    expect(lines[0]).not.toContain("secret_param");
    expect(lines[0]).not.toContain("frag");
  });

  test("truncates long pathnames and never echoes unparseable hosts", () => {
    const lines: string[] = [];
    const emitter = createAuditEventEmitter({ log: (line) => lines.push(line) });

    emitter.emit({
      host: "api.example.com",
      path: `/${"x".repeat(1000)}`,
      generation: `sha256:${"a".repeat(64)}`,
    });
    const event = JSON.parse(lines[0].slice("proxy-audit: ".length)) as { path: string };
    expect(event.path).toHaveLength(256);

    emitter.emit({ host: "bad_host!.example", generation: `sha256:${"a".repeat(64)}` });
    expect(lines).toHaveLength(1);
  });

  test("coalesces per host with a suppressed summary", () => {
    const lines: string[] = [];
    let nowMs = Date.parse("2026-06-10T12:00:00.000Z");
    const emitter = createAuditEventEmitter({
      log: (line) => lines.push(line),
      now: () => new Date(nowMs),
      maxEventsPerWindow: 2,
      windowMs: 60_000,
    });
    const generation = `sha256:${"a".repeat(64)}`;

    for (let index = 0; index < 5; index += 1) {
      emitter.emit({ host: "api.example.com", method: "GET", path: "/v1", generation });
    }
    emitter.emit({ host: "other.example.com", method: "GET", path: "/v1", generation });
    expect(lines).toHaveLength(3);

    nowMs += 61_000;
    emitter.emit({ host: "api.example.com", method: "GET", path: "/v1", generation });
    const summary = JSON.parse(lines[3].slice("proxy-audit: ".length)) as { suppressed?: number; host: string };
    expect(summary).toMatchObject({ host: "api.example.com", suppressed: 3 });
    expect(lines).toHaveLength(5);
  });
});
