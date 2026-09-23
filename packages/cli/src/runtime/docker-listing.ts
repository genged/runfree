import type * as childProcess from "node:child_process";

import { formatTerminalTable } from "../terminal-table.ts";
import { warn } from "../warnings.ts";
import type { RuntimeIO } from "./types.ts";

// Docker `ls`-style listings (`ps`, `network ls`, `volume ls`, `image ls`) read
// through `--format '{{json .}}'`: one self-describing JSON object per line,
// with Docker's formatter field names (`Names`, `Status`, `Image`, `Ports`,
// `Labels`, ...). This replaces tab-joined Go templates, whose splitter could
// not tell a delimiter from a value, and Docker's own `table` format, whose
// column layout differed from every Runfree-rendered table. A line that is not
// a JSON object fails the whole listing closed rather than rendering a
// partially parsed table.

export type DockerListingRow = Record<string, string>;

export type DockerListing = {
  rows: DockerListingRow[];
  status: number;
};

export type DockerListingColumn = {
  label: string;
  value: (row: DockerListingRow) => unknown;
};

export const DOCKER_JSON_FORMAT = "{{json .}}";

export function captureDockerListing(
  io: RuntimeIO,
  args: readonly string[],
  options: childProcess.SpawnSyncOptions,
  label: string,
): DockerListing {
  const result = io.capture("docker", [...args, "--format", DOCKER_JSON_FORMAT], options);
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    warn(`could not list Docker ${label}${detail ? `: ${detail}` : ""}`);
    return { rows: [], status: result.status };
  }
  const rows: DockerListingRow[] = [];
  const lines = result.stdout.split("\n");
  for (const [index, raw] of lines.entries()) {
    const line = raw.trim();
    if (line === "") continue;
    const parsed = parseListingObject(line);
    if (!parsed) {
      warn(`could not parse Docker ${label} listing: line ${index + 1} is not a JSON object`);
      return { rows: [], status: 1 };
    }
    rows.push(parsed);
  }
  return { rows, status: 0 };
}

function parseListingObject(line: string): DockerListingRow | undefined {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const row: DockerListingRow = {};
  for (const [key, field] of Object.entries(value as Record<string, unknown>)) {
    row[key] = field === null || field === undefined ? "" : typeof field === "string" ? field : String(field);
  }
  return row;
}

// `Labels` in a `{{json .}}` listing is Docker's comma-joined `key=value` view.
// Only tokens with an `=` are label pairs; a value that itself contained a comma
// (Compose's config_files, say) leaves stray tokens that no key lookup matches.
export function dockerListingLabel(row: DockerListingRow, key: string): string | undefined {
  const labels = row.Labels;
  if (!labels) return undefined;
  const prefix = `${key}=`;
  for (const token of labels.split(",")) {
    if (token.startsWith(prefix)) return token.slice(prefix.length);
  }
  return undefined;
}

export function renderDockerListing(columns: readonly DockerListingColumn[], rows: readonly DockerListingRow[]): string {
  return formatTerminalTable({
    columns: columns.map((column) => ({ label: column.label })),
    rows: rows.map((row) => columns.map((column) => column.value(row))),
  });
}
