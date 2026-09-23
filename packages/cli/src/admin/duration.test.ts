import { describe, expect, test, vi } from "vitest";

import { formatDurationSeconds, parseDurationSeconds } from "./admin-core.ts";

describe("parseDurationSeconds", () => {
  test("parses each unit, defaulting a bare number to seconds", () => {
    expect(parseDurationSeconds("45", "--ttl")).toBe(45);
    expect(parseDurationSeconds("30s", "--ttl")).toBe(30);
    expect(parseDurationSeconds("18m", "--ttl")).toBe(1080);
    expect(parseDurationSeconds("1h", "--ttl")).toBe(3600);
    expect(parseDurationSeconds("2d", "--ttl")).toBe(2 * 86400);
    expect(parseDurationSeconds("150d", "--ttl")).toBe(150 * 86400);
  });

  test("rejects unknown units and non-positive values", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(() => parseDurationSeconds("150days", "--ttl")).toThrow(/positive duration like 30s, 18m, 1h, or 150d/);
      expect(() => parseDurationSeconds("5w", "--ttl")).toThrow();
      expect(() => parseDurationSeconds("0d", "--ttl")).toThrow();
    } finally {
      spy.mockRestore();
    }
  });
});

describe("formatDurationSeconds", () => {
  test("renders the largest whole unit, preferring days", () => {
    expect(formatDurationSeconds(45)).toBe("45s");
    expect(formatDurationSeconds(90)).toBe("90s");
    expect(formatDurationSeconds(1080)).toBe("18m");
    expect(formatDurationSeconds(3600)).toBe("1h");
    expect(formatDurationSeconds(86400)).toBe("1d");
    expect(formatDurationSeconds(150 * 86400)).toBe("150d");
  });

  test("round-trips with parseDurationSeconds", () => {
    for (const value of ["45s", "18m", "1h", "2d", "150d"]) {
      expect(formatDurationSeconds(parseDurationSeconds(value, "--ttl"))).toBe(value);
    }
  });
});
