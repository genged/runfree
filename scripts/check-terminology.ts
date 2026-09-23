#!/usr/bin/env node

// Generation-family terminology gate (output contract D8; AGENTS.md
// "Generation Families").
//
// User-visible strings must name the generation family — effective policy
// generation, control plane generation, session agent generation, runtime
// generation, ... — never the bare phrase "control generation" or an
// unqualified "a/the/selected/new generation" or a bare `generation:` label,
// because two near-homograph families exist and the bare word reads as the
// wrong one. The check runs over string literals in the emitting modules (the
// same set the remedy parse gate scans) and is part of `make test-static`.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

export const EMITTING_GLOBS = [
  "packages/cli/src",
  "scripts/domain-diagnostics.ts",
  "scripts/services.ts",
  "packages/proxy/src/denial.ts",
];

const EXCLUDED_FILES = [/\.test\.ts$/, /test-harness\.ts$/, /embedded-assets\.generated\.ts$/];

// A family qualifier immediately before "generation" makes the phrase exact.
const FAMILY_QUALIFIERS = [
  "effective policy",
  "control plane",
  "control-plane",
  "session agent",
  "session-agent",
  "runtime",
  "policy",
  "network policy",
  "network-policy",
  "materialization",
  "snapshot",
  "token store",
  "token-store",
  "admission",
  "revocation",
  "lease",
  "candidate",
  "config",
  "checkout",
  "schema-v2",
  "environment",
  "payload",
  "ca",
];

const BARE_PHRASES: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\bcontrol generation\b/i, reason: "bare \"control generation\"; name the family (effective policy generation vs control plane generation)" },
  { pattern: /\b(?:a|the|new|selected|active|current|desired|this|that|no|its|each|every|one|another|latest|previous|same|different)\s+generation\b/i, reason: "unqualified generation; add the family qualifier" },
  { pattern: /(?:^|[\s(])generation:/i, reason: "bare `generation:` label; qualify the family inline" },
];

const STRING_LITERAL = /`((?:[^`\\]|\\.)*)`|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/gs;

export type TerminologyViolation = { text: string; reason: string };

export function findTerminologyViolations(literal: string): TerminologyViolation[] {
  const violations: TerminologyViolation[] = [];
  for (const { pattern, reason } of BARE_PHRASES) {
    const match = pattern.exec(literal);
    if (!match) continue;
    // The qualifier precedes the article-less forms ("selected generation")
    // only when the article itself follows a qualifier, e.g. "session agent
    // selected generation" is still bare; but "the effective policy
    // generation" is fine because the article is not directly before
    // "generation". Only direct adjacency counts, so no extra check here.
    violations.push({ text: match[0], reason });
  }
  // A qualified phrase never trips the label rule ("control plane generation:").
  return violations.filter((violation) => {
    if (!violation.text.endsWith("generation:")) return true;
    const index = literal.indexOf(violation.text);
    const before = literal.slice(Math.max(0, index - 24), index).toLowerCase();
    return !FAMILY_QUALIFIERS.some((qualifier) => before.trimEnd().endsWith(qualifier));
  });
}

function stripComments(source: string): string {
  return source
    .replace(/^[ \t]*\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ""));
}

function listEmittingFiles(): string[] {
  const output = childProcess.spawnSync("git", ["ls-files", "-z", "--", ...EMITTING_GLOBS], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (output.status !== 0) {
    console.error(`check-terminology: git ls-files failed: ${output.stderr}`);
    process.exit(1);
  }
  return output.stdout
    .split("\0")
    .filter((entry) => entry.endsWith(".ts") && !EXCLUDED_FILES.some((pattern) => pattern.test(entry)))
    .sort();
}

export function scanRepository(): string[] {
  const problems: string[] = [];
  const files = listEmittingFiles();
  if (files.length === 0) {
    problems.push("check-terminology: found no emitting modules; the gate would pass vacuously");
    return problems;
  }
  for (const file of files) {
    const source = stripComments(fs.readFileSync(path.join(repoRoot, file), "utf8"));
    for (const literal of source.matchAll(STRING_LITERAL)) {
      const text = literal[1] ?? literal[2] ?? literal[3] ?? "";
      if (!/generation/i.test(text)) continue;
      const line = source.slice(0, literal.index).split("\n").length;
      for (const violation of findTerminologyViolations(text)) {
        problems.push(`${file}:${line}: "${violation.text}" — ${violation.reason}`);
      }
    }
  }
  return problems;
}

const entryPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entryPath === fileURLToPath(import.meta.url)) {
  const problems = scanRepository();
  if (problems.length > 0) {
    console.error("check-terminology: user-visible strings must name the generation family:");
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }
  console.log("check-terminology: ok");
}
