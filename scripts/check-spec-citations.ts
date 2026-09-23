#!/usr/bin/env node

// Active design specs cite repo files, and the tree moves underneath them: a
// renamed module silently turns a spec's evidence into fiction, and the next
// adaptation pass pays for the drift with a hand re-verification. This gate
// does the machine's share (evolution-strategy A4): it parses the file paths a
// spec cites and fails when a citation stops resolving.
//
// Scope, chosen to hold false positives at zero (paths only; symbols are a
// later phase):
// - EVERY active spec's citations are checked. A spec that deliberately
//   narrates an older tree (a rename design citing its pre-rename baseline)
//   opts out explicitly with a `Citation gate: disabled — <reason>` line, so
//   skipping is a recorded decision rather than a silent default. An earlier
//   version gated only specs claiming currency; measured against the corpus
//   that skipped 10 of 12 active specs, including 8 carrying real citations,
//   which is most of what the gate exists to protect.
// - A "verified/adapted against <commit>" currency claim additionally requires
//   the spec to resolve at least one citation: asserting currency while the
//   gate can check nothing is the vacuity this guards against. Specs without
//   such a claim may legitimately carry no repo citations at all, so this
//   cannot fold into a plain resolved-count rule.
// - A citation must be a backticked span rooted at a real repo top-level
//   source directory; `dist/` and `node_modules/` are other packages' layouts,
//   not citable sources. Relative markdown links are always checked.
// - An unresolved path that git never tracked is a planned file, not drift;
//   it is reported but does not fail.
// - Corpus vacuity is one check: zero resolved citations anywhere fails, and
//   "every spec opted out" is that same failure under a more useful name.
//
// The maintainer spec directory is local-only. Public checkouts have no
// `local/specs`, so the gate MUST no-op there (AGENTS.md forbids a public
// dependency on `local/`); it never passes vacuously when specs exist.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const defaultRepoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

const CURRENCY_CLAIM = /(?:erified|dapted)[^\n]{0,80}against[^\n]{0,80}`?[0-9a-f]{7,40}`?/u;
const GATE_OPT_OUT = /Citation gate:\s*disabled/u;
const UNCITABLE_ROOTS = new Set(["dist", "node_modules"]);
const PATHISH = /^[\w@./-]+\/[\w@./{},-]*\.[a-z]{1,10}(?::[\d,-]+)?$/u;

type Options = { repoRoot: string; specsDir: string };

function parseOptions(argv: readonly string[]): Options {
  let repoRoot = defaultRepoRoot;
  let specsDir: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if ((flag === "--repo-root" || flag === "--specs-dir") && value === undefined) {
      console.error(`check-spec-citations: ${flag} requires a value`);
      process.exit(2);
    }
    if (flag === "--repo-root") {
      repoRoot = path.resolve(String(value));
      index += 1;
    } else if (flag === "--specs-dir") {
      specsDir = path.resolve(String(value));
      index += 1;
    } else {
      console.error(`check-spec-citations: unknown argument ${flag}`);
      process.exit(2);
    }
  }
  return { repoRoot, specsDir: specsDir ?? path.join(repoRoot, "local", "specs") };
}

// One level of `{a,b}` alternation, as used by path citations like
// `session-admission-{probe,driver}.ts`. Anything fancier is skipped rather
// than guessed at: a skipped span cannot fail the gate falsely.
function expandBraces(citation: string): string[] | undefined {
  const match = /^([^{}]*)\{([^{}]+)\}([^{}]*)$/u.exec(citation);
  if (!match) return citation.includes("{") || citation.includes("}") ? undefined : [citation];
  return match[2].split(",").map((option) => `${match[1]}${option.trim()}${match[3]}`);
}

/**
 * Roots a citation may be anchored at: top-level directories in the working
 * tree, those tracked at HEAD, and those of any path ever deleted in history.
 *
 * The union is the point. Deriving roots from the current tree alone makes the
 * gate silently blind exactly when it matters most — delete or rename a whole
 * tracked root and every citation beneath it stops looking like a path, so it
 * never reaches the resolve check and the drift goes unreported. HEAD covers a
 * working-tree deletion under review; the history pass covers the same deletion
 * once committed, which is otherwise permanently invisible. Measured at ~0.6s
 * on this repo, which is acceptable for a static gate.
 */
function citableTopLevelDirectories(repoRoot: string): Set<string> {
  const roots = fs.readdirSync(repoRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
  const addFrom = (args: readonly string[], topLevelOnly: boolean): void => {
    const result = childProcess.spawnSync("git", [...args], { cwd: repoRoot, encoding: "utf8", shell: false });
    if (result.status !== 0) return;
    for (const line of result.stdout.split("\n")) {
      const entry = line.trim();
      if (entry === "") continue;
      const name = topLevelOnly ? entry : entry.split("/")[0] as string;
      if (name !== "" && (topLevelOnly || entry.includes("/"))) roots.push(name);
    }
  };
  addFrom(["ls-tree", "HEAD", "--name-only", "-d"], true);
  addFrom(["log", "--diff-filter=D", "--name-only", "--pretty=format:"], false);
  return new Set(roots.filter((name) => !UNCITABLE_ROOTS.has(name)));
}

/**
 * Repo-relative paths cited in backticked spans. A span counts only when it
 * looks like a path (has a directory separator and an extension), is rooted at
 * a citable repo top-level directory, and contains no wildcard. A trailing
 * `:line[-line]` suffix is citation syntax, not path.
 */
function citedRepoPaths(markdown: string, topLevel: ReadonlySet<string>): string[] {
  const cited = new Set<string>();
  for (const span of markdown.matchAll(/`([^`\n]+)`/gu)) {
    const raw = (span[1] as string).trim();
    if (raw.includes("*") || raw.includes(" ") || !PATHISH.test(raw)) continue;
    const withoutLines = raw.replace(/:[\d,-]+$/u, "");
    if (!topLevel.has(withoutLines.split("/")[0] as string)) continue;
    for (const expanded of expandBraces(withoutLines) ?? []) cited.add(expanded);
  }
  return [...cited].sort();
}

/**
 * Relative markdown link targets, resolved against the spec's directory.
 *
 * A target that escapes the repository is not repository evidence: without this
 * check a link like `../../../../etc/hosts` would resolve, satisfy the
 * non-vacuity guards, and let a spec claim currency while nothing in the tree
 * was verified.
 */
function linkedRelativePaths(markdown: string): string[] {
  const linked = new Set<string>();
  for (const link of markdown.matchAll(/\]\(([^()\s]+)\)/gu)) {
    const target = (link[1] as string).split("#")[0] as string;
    if (target === "" || /^[a-z][a-z0-9+.-]*:/iu.test(target) || target.startsWith("/")) continue;
    linked.add(target);
  }
  return [...linked].sort();
}

/** `target: undefined` means the citation points outside the repository. */
type Citation = { kind: "cited" | "linked"; raw: string; target: string | undefined };

/** One spec's citations in report order: backticked repo paths, then links. */
function specCitations(
  markdown: string,
  specPath: string,
  repoRoot: string,
  topLevel: ReadonlySet<string>,
): Citation[] {
  const cited: Citation[] = citedRepoPaths(markdown, topLevel)
    .map((raw) => ({ kind: "cited", raw, target: path.join(repoRoot, raw) }));
  const linked: Citation[] = linkedRelativePaths(markdown).map((raw) => {
    const target = path.resolve(path.dirname(specPath), raw);
    const inRepo = target === repoRoot || target.startsWith(`${repoRoot}${path.sep}`);
    return { kind: "linked", raw, target: inRepo ? target : undefined };
  });
  return [...cited, ...linked];
}

/**
 * The one classification: `resolved` is proof against the current tree,
 * `planned` is reported but not fatal, and a `problem` fails the gate. Only a
 * backticked citation can be planned — a spec does not link forward to a file
 * it has not written, so an unresolved link is always drift.
 */
function classifyCitation(repoRoot: string, citation: Citation): "planned" | "resolved" | { problem: string } {
  if (citation.target === undefined) return { problem: `linked file escapes the repository: ${citation.raw}` };
  if (fs.existsSync(citation.target)) return "resolved";
  if (citation.kind === "linked") return { problem: `linked file does not resolve: ${citation.raw}` };
  return everTracked(repoRoot, citation.raw)
    ? { problem: `cited path no longer resolves: ${citation.raw}` }
    : "planned";
}

function everTracked(repoRoot: string, repoRelative: string): boolean {
  const result = childProcess.spawnSync(
    "git",
    ["log", "-1", "--format=%H", "--", repoRelative],
    { cwd: repoRoot, encoding: "utf8", shell: false },
  );
  return result.status === 0 && result.stdout.trim() !== "";
}

function main(): void {
  const options = parseOptions(process.argv.slice(2));
  if (!fs.existsSync(options.specsDir)) {
    console.log(`check-spec-citations: no ${path.relative(options.repoRoot, options.specsDir) || options.specsDir} in this checkout; nothing to check`);
    return;
  }
  // Active specs only (top-level, date-named): done/ and deprecated/ describe
  // past trees, and the INDEX is a registry whose summaries quote history.
  const specs = fs.readdirSync(options.specsDir)
    .filter((entry) => /^\d{4}-\d{2}-\d{2}-.*\.md$/u.test(entry))
    .sort()
    .map((entry) => path.join(options.specsDir, entry));
  if (specs.length === 0) {
    console.error("check-spec-citations: the specs directory exists but holds no active specs; the gate would pass vacuously");
    process.exit(1);
  }
  const topLevel = citableTopLevelDirectories(options.repoRoot);
  const problems: string[] = [];
  const planned: string[] = [];
  const optedOut: string[] = [];
  let gatedSpecs = 0;
  let citations = 0;
  let resolvedCitations = 0;
  for (const spec of specs) {
    const markdown = fs.readFileSync(spec, "utf8");
    const specLabel = path.relative(options.repoRoot, spec);
    if (GATE_OPT_OUT.test(markdown)) {
      optedOut.push(specLabel);
      continue;
    }
    gatedSpecs += 1;
    const claimsCurrency = CURRENCY_CLAIM.test(markdown);
    let specResolved = 0;
    for (const citation of specCitations(markdown, spec, options.repoRoot, topLevel)) {
      citations += 1;
      const verdict = classifyCitation(options.repoRoot, citation);
      if (verdict === "resolved") {
        specResolved += 1;
        resolvedCitations += 1;
      } else if (verdict === "planned") {
        planned.push(`${specLabel}: never-tracked citation (treated as planned): ${citation.raw}`);
      } else problems.push(`${specLabel}: ${verdict.problem}`);
    }
    // Per-spec vacuity: a spec that claims currency but resolves NO citation is
    // not "passing", it is unchecked. Two ways to land here, both real: only
    // fully-qualified paths rooted at a repo top-level directory are
    // recognized, so a spec written entirely in shorthand
    // (`control/effective.ts`) is skipped; and never-tracked citations are
    // treated as planned files, so a spec citing only future paths verifies
    // nothing about the current tree. Counting resolved citations only means
    // neither shape can assert currency for free.
    if (claimsCurrency && specResolved === 0) {
      problems.push(`${specLabel}: claims tree currency but resolves no citation against the current tree; cite repo-rooted existing paths or drop the currency claim`);
    }
  }
  // Concrete drift first: a real unresolved citation is more actionable than
  // the vacuity fallback, and reporting vacuity instead would hide it.
  if (problems.length > 0) {
    console.error(`check-spec-citations:\n${problems.map((problem) => `  ${problem}`).join("\n")}`);
    process.exit(1);
  }
  // Corpus non-vacuity: gating specs is not the same as checking anything. If
  // the whole corpus resolves nothing — all prose, unrecognized shorthand,
  // planned-only paths, or every spec opted out — the run proves nothing and
  // must not report success. An all-opted-out corpus is the same failure with a
  // more useful name: it resolves nothing BECAUSE nothing was gated.
  if (resolvedCitations === 0) {
    console.error(gatedSpecs === 0
      ? "check-spec-citations: every active spec opted out of the citation gate; it would pass vacuously"
      : `check-spec-citations: ${gatedSpecs} active specs are gated but not one citation resolved; the gate would pass vacuously`);
    process.exit(1);
  }
  for (const line of planned) console.log(`check-spec-citations: ${line}`);
  for (const line of optedOut) console.log(`check-spec-citations: spec opted out of the gate: ${line}`);
  console.log(
    `check-spec-citations: ${citations} citations across ${gatedSpecs} active specs all resolve`
      + ` (${optedOut.length} opted out)`,
  );
}

main();
