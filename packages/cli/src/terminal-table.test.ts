import { describe, expect, test } from "vitest";

import { formatTerminalTable } from "./terminal-table.ts";

describe("formatTerminalTable", () => {
  test("pads every column to its widest cell and separates columns with two spaces", () => {
    const table = formatTerminalTable({
      columns: [{ label: "SERVICE" }, { label: "STATE" }, { label: "HOSTS" }],
      rows: [
        ["agent-claude", "enabled", 2],
        ["go", "available", 3],
      ],
    });
    expect(table).toBe([
      "SERVICE       STATE      HOSTS",
      "agent-claude  enabled    2",
      "go            available  3",
    ].join("\n"));
  });

  test("header alone is wider than any cell", () => {
    const table = formatTerminalTable({
      columns: [{ label: "REVISION" }, { label: "ID" }],
      rows: [[1, "x"]],
    });
    expect(table).toBe(["REVISION  ID", "1         x"].join("\n"));
  });

  test("renders only the header when there are no rows", () => {
    expect(formatTerminalTable({ columns: [{ label: "A" }, { label: "B" }], rows: [] })).toBe("A  B");
  });

  test("trims trailing padding so lines never end in whitespace", () => {
    const table = formatTerminalTable({ columns: [{ label: "A" }, { label: "LONGER" }], rows: [["a", "b"]] });
    for (const line of table.split("\n")) expect(line).toBe(line.trimEnd());
  });

  test("strips ANSI escapes and control characters before measuring widths", () => {
    const table = formatTerminalTable({
      columns: [{ label: "NAME" }, { label: "X" }],
      rows: [["\x1b[31mred\x1b[0m\x07", "y"]],
    });
    expect(table).toBe(["NAME  X", "red   y"].join("\n"));
  });

  test("treats null and undefined cells as empty and missing cells as empty", () => {
    const table = formatTerminalTable({
      columns: [{ label: "A" }, { label: "B" }, { label: "C" }],
      rows: [[null, undefined], ["x"]],
    });
    expect(table).toBe(["A  B  C", "", "x"].join("\n"));
  });

  test("honors a custom gap", () => {
    expect(formatTerminalTable({ columns: [{ label: "A" }, { label: "B" }], rows: [["1", "2"]], gap: 4 }))
      .toBe(["A    B", "1    2"].join("\n"));
  });
});
