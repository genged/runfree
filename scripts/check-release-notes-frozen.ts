#!/usr/bin/env node

// Release notes are a promise about bytes that already shipped.
//
// Before publication a notes file is a draft and may change freely. After
// publication it describes a release people have already downloaded, and
// rewriting it silently changes the record of what they got. Corrections belong
// in a later release's notes or in an explicit errata section, both of which are
// additions rather than edits to history.
//
// The gate: for every docs/release-notes/<version>.md whose `v<version>` tag
// exists in this checkout, the working-tree file must be byte-identical to the
// file at that tag.
//
// A checkout without tags cannot check anything, and says so rather than
// reporting a pass. CI checkouts commonly have no tags; that is a coverage
// limit, not a green result.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const notesDir = path.join(repoRoot, "docs/release-notes");

function git(args: readonly string[]): { status: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync("git", args, { cwd: repoRoot, encoding: "utf8", shell: false });
  return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

if (!fs.existsSync(notesDir)) {
  console.log("check-release-notes-frozen: no docs/release-notes directory; nothing to check");
  process.exit(0);
}

const notes = fs
  .readdirSync(notesDir)
  .filter((name) => name.endsWith(".md"))
  .sort();

if (notes.length === 0) {
  console.log("check-release-notes-frozen: no release notes files; nothing to check");
  process.exit(0);
}

const problems: string[] = [];
let checked = 0;
const unpublished: string[] = [];

for (const name of notes) {
  const version = name.replace(/\.md$/, "");
  const tag = `v${version}`;
  const relativePath = path.posix.join("docs/release-notes", name);

  if (git(["rev-parse", "-q", "--verify", `refs/tags/${tag}`]).status !== 0) {
    unpublished.push(`${relativePath} (no ${tag} tag in this checkout)`);
    continue;
  }

  const atTag = git(["show", `${tag}:${relativePath}`]);
  if (atTag.status !== 0) {
    // The notes file was added after the tag. Nothing shipped under it, so
    // there is nothing frozen to compare against.
    unpublished.push(`${relativePath} (not present at ${tag})`);
    continue;
  }

  checked += 1;
  const current = fs.readFileSync(path.join(notesDir, name), "utf8");
  if (current !== atTag.stdout) {
    problems.push(
      `${relativePath} differs from its content at ${tag}. ` +
        "Published release notes are fixed: put the correction in a later release's notes or an errata section.",
    );
  }
}

if (unpublished.length > 0) {
  console.log(`check-release-notes-frozen: not yet published, so not frozen:\n  ${unpublished.join("\n  ")}`);
}

if (problems.length > 0) {
  console.error(`check-release-notes-frozen: ${problems.length} problem(s)`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}

console.log(`check-release-notes-frozen: ${checked} published release note(s) unchanged since their tag`);
