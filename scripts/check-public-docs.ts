#!/usr/bin/env node

// Keeps the public documentation usable from a clone that has nothing else.
//
// Two failures this catches, both of which look fine in the maintainer's
// checkout and are broken for everyone else:
//
//   * A relative link whose target is untracked. It resolves locally because the
//     file is on disk; in a fresh clone it is a 404. Links into `local/` are the
//     common case, since that directory holds maintainer-only records and is
//     never published.
//   * A `#anchor` that no heading produces. An existence-only link check passes
//     these, which is why the 2026-09-14 readiness investigation recorded
//     "did not validate anchors" as a limit of its own check.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

function trackedFiles(...patterns: string[]): string[] {
  const result = childProcess.spawnSync("git", ["ls-files", "-z", "--", ...patterns], {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false,
  });
  if (result.status !== 0) {
    console.error("check-public-docs: git ls-files failed");
    console.error(result.stderr?.trim());
    process.exit(1);
  }
  return (result.stdout ?? "").split("\0").filter((entry) => entry.length > 0);
}

/** GitHub's heading slug: lowercase, drop punctuation, spaces to hyphens. */
function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s+/g, "-");
}

function anchorsOf(markdown: string): Set<string> {
  const anchors = new Set<string>();
  const counts = new Map<string, number>();
  let inFence = false;

  for (const line of markdown.split("\n")) {
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;

    const heading = /^#{1,6}\s+(.*)$/.exec(line);
    if (heading) {
      // Strip inline markup the slug does not see: links, code, emphasis.
      const text = heading[1]
        .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
        .replace(/[`*_]/g, "");
      const base = slug(text);
      const seen = counts.get(base) ?? 0;
      counts.set(base, seen + 1);
      anchors.add(seen === 0 ? base : `${base}-${seen}`);
      continue;
    }

    // Explicit HTML anchors, used by the README's centered header block.
    for (const match of line.matchAll(/(?:id|name)="([^"]+)"/g)) {
      anchors.add(match[1]);
    }
  }
  return anchors;
}

const docs = trackedFiles("*.md", "*.html", "docs/**", ".github/**");
const markdownDocs = docs.filter((file) => file.endsWith(".md"));
const tracked = new Set(trackedFiles());
const anchorCache = new Map<string, Set<string>>();

function anchorsFor(relativePath: string): Set<string> {
  let anchors = anchorCache.get(relativePath);
  if (!anchors) {
    anchors = anchorsOf(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));
    anchorCache.set(relativePath, anchors);
  }
  return anchors;
}

const problems: string[] = [];
let linksChecked = 0;

for (const file of markdownDocs) {
  const source = fs.readFileSync(path.join(repoRoot, file), "utf8");
  const fileDir = path.posix.dirname(file);

  for (const match of source.matchAll(/\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    const target = match[1];
    if (/^(https?:|mailto:|#)/.test(target)) {
      if (target.startsWith("#")) {
        linksChecked += 1;
        const anchor = decodeURIComponent(target.slice(1));
        if (!anchorsFor(file).has(anchor)) {
          problems.push(`${file}: no heading produces the anchor "#${anchor}"`);
        }
      }
      continue;
    }

    linksChecked += 1;
    const [rawPath, rawAnchor] = target.split("#");
    const resolved = path.posix.normalize(path.posix.join(fileDir, rawPath));

    if (resolved.startsWith("local/") || resolved === "local") {
      problems.push(
        `${file}: links to ${target}, which is maintainer-only and never published. ` +
          "Public documentation must work without local/.",
      );
      continue;
    }

    if (!tracked.has(resolved)) {
      const onDisk = fs.existsSync(path.join(repoRoot, resolved));
      problems.push(
        `${file}: links to ${target}, which is ${onDisk ? "not tracked in git" : "missing"}. ` +
          "A fresh clone would get a broken link.",
      );
      continue;
    }

    if (rawAnchor && resolved.endsWith(".md")) {
      const anchor = decodeURIComponent(rawAnchor);
      if (!anchorsFor(resolved).has(anchor)) {
        problems.push(`${file}: links to ${target}, but ${resolved} has no heading with the anchor "#${anchor}"`);
      }
    }
  }
}

if (markdownDocs.length === 0 || linksChecked === 0) {
  console.error("check-public-docs: found no documentation links to check; this gate would pass vacuously");
  process.exit(1);
}

if (problems.length > 0) {
  console.error(`check-public-docs: ${problems.length} problem(s)`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}

console.log(`check-public-docs: ${linksChecked} links across ${markdownDocs.length} documents resolve in a fresh clone`);
