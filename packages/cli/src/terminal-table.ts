const ANSI_CSI_SEQUENCE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const ANSI_OTHER_ESCAPE = /\x1b[@-_]?/g;
const CONTROL_CHARACTERS = /[\x00-\x1f\x7f-\x9f]/g;

export type TerminalTableColumn = {
  label: string;
};

export type TerminalTableOptions = {
  columns: readonly TerminalTableColumn[];
  rows: readonly (readonly unknown[])[];
  gap?: number;
};

function cellText(value: unknown): string {
  return String(value ?? "")
    .replace(ANSI_CSI_SEQUENCE, "")
    .replace(ANSI_OTHER_ESCAPE, "")
    .replace(CONTROL_CHARACTERS, "");
}

export function formatTerminalTable(options: TerminalTableOptions): string {
  const gap = " ".repeat(options.gap ?? 2);
  const rows = [
    options.columns.map((column) => cellText(column.label)),
    ...options.rows.map((row) => options.columns.map((_, index) => cellText(row[index]))),
  ];
  const widths = options.columns.map((_, index) => Math.max(...rows.map((row) => row[index]?.length ?? 0)));
  return rows
    .map((row) => row.map((cell, index) => cell.padEnd(widths[index] ?? 0)).join(gap).trimEnd())
    .join("\n");
}
