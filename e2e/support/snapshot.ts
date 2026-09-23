import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export type SnapshotSelection = Readonly<{ name: string; path: string }>;

type SnapshotEntry = Readonly<{
  relativePath: string;
  type: "directory" | "file" | "symlink" | "other";
  mode: number;
  sha256?: string;
  target?: string;
}>;

export type OwnedStateSnapshot = Readonly<Record<string, readonly SnapshotEntry[] | "absent">>;

function entryType(stat: fs.Stats): SnapshotEntry["type"] {
  if (stat.isDirectory()) return "directory";
  if (stat.isFile()) return "file";
  if (stat.isSymbolicLink()) return "symlink";
  return "other";
}

function walk(root: string, current: string, entries: SnapshotEntry[]): void {
  const stat = fs.lstatSync(current);
  const type = entryType(stat);
  const relativePath = path.relative(root, current) || ".";
  const base = { relativePath, type, mode: stat.mode & 0o7777 };
  if (type === "file") {
    entries.push(Object.freeze({ ...base, sha256: crypto.createHash("sha256").update(fs.readFileSync(current)).digest("hex") }));
    return;
  }
  if (type === "symlink") {
    entries.push(Object.freeze({ ...base, target: fs.readlinkSync(current) }));
    return;
  }
  entries.push(Object.freeze(base));
  if (type !== "directory") return;
  for (const child of fs.readdirSync(current).sort()) walk(root, path.join(current, child), entries);
}

export function snapshotOwnedState(selections: readonly SnapshotSelection[]): OwnedStateSnapshot {
  if (selections.length === 0) throw new Error("owned-state snapshot requires at least one named selection");
  const names = new Set<string>();
  const snapshot: Record<string, readonly SnapshotEntry[] | "absent"> = {};
  for (const selection of selections) {
    if (!selection.name || names.has(selection.name)) throw new Error(`owned-state snapshot selection name is empty or repeated: ${selection.name}`);
    names.add(selection.name);
    try {
      const entries: SnapshotEntry[] = [];
      walk(selection.path, selection.path, entries);
      snapshot[selection.name] = Object.freeze(entries);
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
      if (code === "ENOENT") snapshot[selection.name] = "absent";
      else throw error;
    }
  }
  return Object.freeze(snapshot);
}

export function assertOwnedStateUnchanged(before: OwnedStateSnapshot, after: OwnedStateSnapshot): void {
  const expected = `${JSON.stringify(before, null, 2)}\n`;
  const actual = `${JSON.stringify(after, null, 2)}\n`;
  if (actual !== expected) throw new Error(`owned state changed\n--- before\n${expected}--- after\n${actual}`);
}
