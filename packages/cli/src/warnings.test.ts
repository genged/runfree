import { afterEach, expect, test } from "vitest";

import {
  flushWarnings,
  formatRunfreeLog,
  renderOutputEvent,
  setOutputWriterForTest,
  timestampsEnabled,
  warn,
} from "./warnings.ts";

const AT = new Date("2026-06-14T20:01:02.003Z");

afterEach(() => {
  setOutputWriterForTest(undefined);
  flushWarnings();
});

test("formatRunfreeLog prefixes runfree logs with an ISO timestamp", () => {
  expect(formatRunfreeLog("starting runtime", AT)).toBe("2026-06-14T20:01:02.003Z runfree: starting runtime");
});

test("the three severities render distinct prefixes", () => {
  expect(renderOutputEvent({ severity: "info", message: "x" }, { timestamps: false })).toBe("runfree: x");
  expect(renderOutputEvent({ severity: "warning", message: "x" }, { timestamps: false })).toBe("runfree warning: x");
  expect(renderOutputEvent({ severity: "error", message: "x" }, { timestamps: false })).toBe("runfree error: x");
});

test("every line of a multi-line message is attributed: prefix, then continuation indent", () => {
  const rendered = renderOutputEvent(
    { severity: "error", message: "no generation selected\nrun: runfree up\n\ninspect: runfree policy status", at: AT },
    { timestamps: true },
  );
  expect(rendered).toBe([
    "2026-06-14T20:01:02.003Z runfree error: no generation selected",
    "  run: runfree up",
    "",
    "  inspect: runfree policy status",
  ].join("\n"));
});

test("detail renders raw after the message (usage blocks are never prefixed)", () => {
  const rendered = renderOutputEvent(
    { severity: "error", message: "runfree host needs a subcommand", detail: "runfree host\n\nCommands:\n  runfree host add <host>\n" },
    { timestamps: false },
  );
  expect(rendered).toBe("runfree error: runfree host needs a subcommand\n\nrunfree host\n\nCommands:\n  runfree host add <host>");
});

test("timestamps are off on a TTY, on otherwise, and RUNFREE_LOG_TIMESTAMPS overrides both", () => {
  expect(timestampsEnabled({ env: {}, stderrIsTTY: true })).toBe(false);
  expect(timestampsEnabled({ env: {}, stderrIsTTY: false })).toBe(true);
  expect(timestampsEnabled({ env: { RUNFREE_LOG_TIMESTAMPS: "1" }, stderrIsTTY: true })).toBe(true);
  expect(timestampsEnabled({ env: { RUNFREE_LOG_TIMESTAMPS: "0" }, stderrIsTTY: false })).toBe(false);
});

test("a warning captures its timestamp when observed, not when flushed", async () => {
  const lines: string[] = [];
  setOutputWriterForTest((line) => lines.push(line));
  process.env.RUNFREE_LOG_TIMESTAMPS = "1";
  try {
    const before = Date.now();
    warn("observed early");
    await new Promise((resolve) => setTimeout(resolve, 25));
    const flushedAt = Date.now();
    flushWarnings();
    expect(lines).toHaveLength(1);
    const stamp = Date.parse(lines[0].slice(0, "2026-06-14T20:01:02.003Z".length));
    expect(stamp).toBeGreaterThanOrEqual(before);
    expect(stamp).toBeLessThan(flushedAt - 10);
    expect(lines[0]).toContain(" runfree warning: observed early");
  } finally {
    delete process.env.RUNFREE_LOG_TIMESTAMPS;
  }
});

test("flush renders warnings in observation order and empties the buffer", () => {
  const lines: string[] = [];
  setOutputWriterForTest((line) => lines.push(line));
  warn("first");
  warn("second");
  flushWarnings();
  flushWarnings();
  expect(lines.map((line) => line.replace(/^\S+ /, ""))).toEqual(["runfree warning: first", "runfree warning: second"]);
});
