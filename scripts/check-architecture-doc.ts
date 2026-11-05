#!/usr/bin/env node

// Architecture-level gate (docs/writing-docs.md, "Write architecture.md as a
// high-level explanation").
//
// docs/architecture.md explains what each part does, what it trusts, and what
// happens across the lifecycle. Source paths, function and field names,
// environment variables, and exact limits belong to the code, cli.md, and
// security-rules.md, where they are kept accurate. A page that names them
// drifts the next time the code moves, and it buries the idea a reader came
// for. This gate catches the mechanical part of that rule; step-by-step
// algorithms are left to review. Fenced blocks (diagrams, JSON examples) are
// not checked.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

export const ARCHITECTURE_DOC = "docs/architecture.md";

// Each exception is a name the reader needs and cannot get in plain words.
export const ALLOWED_SPANS = new Map<string, string>([
  ["`controlGeneration`", "the Generation Families table maps each family to its serialized key"],
  ["`controlPlaneGenerationDigest`", "the Generation Families table maps each family to its serialized key"],
  ["`RUNFREE_BASE_IMAGE`", "the build argument a project Dockerfile extends"],
]);

const RULES: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /`(?:\.\.\/)?(?:packages|scripts|tests)\/[^`]*`|`[^`\s]*\.(?:ts|tsx|js|cjs|mjs|sh|py)`/g,
    reason: "source path; say what the part does instead",
  },
  { pattern: /`[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*(?:\(\))?`/g, reason: "function, type, or field name; describe the idea in plain words" },
  { pattern: /`[A-Z][A-Z0-9]*_[A-Z0-9_]+`/g, reason: "environment variable or constant; it belongs in cli.md or security-rules.md" },
  {
    pattern: /\b\d+(?:\.\d+)?\s?(?:ms|s|seconds?|minutes?|pids|processes|KiB|MiB|GiB)\b|\buid \d+\b/g,
    reason: "exact limit; it belongs in security-rules.md or cli.md",
  },
];

export type ArchitectureViolation = { line: number; text: string; reason: string };

export function findArchitectureViolations(markdown: string): ArchitectureViolation[] {
  const violations: ArchitectureViolation[] = [];
  let fenced = false;
  markdown.split("\n").forEach((line, index) => {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      return;
    }
    if (fenced) return;
    for (const { pattern, reason } of RULES) {
      for (const match of line.matchAll(pattern)) {
        if (ALLOWED_SPANS.has(match[0])) continue;
        violations.push({ line: index + 1, text: match[0], reason });
      }
    }
  });
  return violations;
}

export function scanRepository(): string[] {
  const file = path.join(repoRoot, ARCHITECTURE_DOC);
  if (!fs.existsSync(file)) return [`check-architecture-doc: ${ARCHITECTURE_DOC} is missing; the gate would pass vacuously`];
  return findArchitectureViolations(fs.readFileSync(file, "utf8")).map(
    (violation) => `${ARCHITECTURE_DOC}:${violation.line}: ${violation.text} — ${violation.reason}`,
  );
}

const entryPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entryPath === fileURLToPath(import.meta.url)) {
  const problems = scanRepository();
  if (problems.length > 0) {
    console.error("check-architecture-doc: architecture.md explains ideas; move code names and limits to cli.md or security-rules.md:");
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }
  console.log("check-architecture-doc: ok");
}
