#!/usr/bin/env node

// `make test-git`: run the Git-dependent test files on every pinned Git.
//
//   tsx scripts/test-git.ts [--git <version>] [--file <test file>]
//
// For each locked version (tests/git-matrix/git-bins.lock.json) it fetches and
// verifies the pinned binary, then runs the files in tests/git-matrix/files.txt
// with RUNFREE_TEST_GIT_VERSION set; the Vitest globalSetup
// (tests/support/pinned-git.ts) puts that Git first on PATH. A lane passes only
// when nothing fails, and a test may skip on one Git and run on another only
// if it declared the newer Git with `needsGit` (tests/support/git-version.ts).
// Skips that hold on every lane (a Linux-only test on macOS) do not depend on
// Git and are only counted.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  compareGitVersions,
  ensurePinnedGit,
  GIT_MATRIX_FILES_PATH,
  GIT_VERSION_ENV,
  NEEDS_GIT_TITLE,
  readGitBinsLock,
  repoRoot,
} from "./git-bins.ts";

type AssertionResult = { fullName: string; title: string; status: string; failureMessages?: string[] };
type JsonReport = { numTotalTests: number; testResults: { name: string; message?: string; assertionResults: AssertionResult[] }[] };

export type LaneSummary = {
  version: string;
  ok: boolean;
  passed: number;
  notApplicable: number;
  /** Skipped without a needsGit requirement; see judgeSkips. */
  skipped: string[];
  /** Every test that ran (passed or failed), by id. */
  ran: string[];
  firstFailure?: string;
};

/** Non-empty, non-comment lines of files.txt. */
export function parseMatrixFiles(text: string): string[] {
  return text.split(/\r?\n/u).map((line) => line.trim()).filter((line) => line !== "" && !line.startsWith("#"));
}

function firstLine(text: string | undefined): string {
  return (text ?? "").split("\n").find((line) => line.trim() !== "")?.trim() ?? "";
}

/** Judges one lane from Vitest's JSON report. */
export function summarizeLane(version: string, report: JsonReport | undefined, exitCode: number | null): LaneSummary {
  if (!report) return failedLane(version, `vitest exited with ${exitCode} and wrote no report`);
  let passed = 0;
  let notApplicable = 0;
  const skipped: string[] = [];
  const ran: string[] = [];
  let firstFailure: string | undefined;
  for (const file of report.testResults) {
    const relative = path.relative(repoRoot, file.name);
    if (file.assertionResults.length === 0 && file.message) firstFailure ??= `${relative}: ${firstLine(file.message)}`;
    for (const result of file.assertionResults) {
      const id = `${relative} > ${result.fullName}`;
      if (result.status === "skipped" || result.status === "pending" || result.status === "todo") {
        const needs = NEEDS_GIT_TITLE.exec(result.title)?.[1];
        if (needs !== undefined && compareGitVersions(version, needs) < 0) notApplicable += 1;
        else if (needs !== undefined) firstFailure ??= `${id}: skipped on Git ${version}, which meets its requirement`;
        else skipped.push(id);
        continue;
      }
      ran.push(id);
      if (result.status === "passed") passed += 1;
      else firstFailure ??= `${id}: ${firstLine(result.failureMessages?.[0])}`;
    }
  }
  if (passed === 0) firstFailure ??= "no test passed";
  if (exitCode !== 0) firstFailure ??= `vitest exited with ${exitCode}`;
  return { version, ok: firstFailure === undefined, passed, notApplicable, skipped, ran, firstFailure };
}

function failedLane(version: string, firstFailure: string): LaneSummary {
  return { version, ok: false, passed: 0, notApplicable: 0, skipped: [], ran: [], firstFailure };
}

/**
 * A test that skips on one Git but runs on another depends on the Git version
 * without declaring it, so a lane could pass by skipping: that fails the lane.
 * A skip on every lane (a platform guard) does not depend on Git.
 */
export function judgeSkips(lanes: readonly LaneSummary[]): LaneSummary[] {
  return lanes.map((lane) => {
    for (const id of lane.skipped) {
      const other = lanes.find((candidate) => candidate.ran.includes(id));
      if (other) {
        return { ...lane, ok: false, firstFailure: lane.firstFailure ?? `${id}: skipped on Git ${lane.version} but ran on Git ${other.version}; declare needsGit` };
      }
    }
    return lane;
  });
}

function runLane(version: string, files: readonly string[]): LaneSummary {
  try {
    ensurePinnedGit({ version });
  } catch (error) {
    return failedLane(version, (error as Error).message);
  }
  const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-test-git-"));
  const reportPath = path.join(reportDir, "report.json");
  try {
    console.log(`\n=== Git ${version}: ${files.length} file(s)`);
    const result = childProcess.spawnSync(
      "pnpm",
      ["exec", "vitest", "run", "--reporter=default", "--reporter=json", `--outputFile.json=${reportPath}`, ...files],
      { cwd: repoRoot, stdio: "inherit", env: { ...process.env, [GIT_VERSION_ENV]: version } },
    );
    const report = fs.existsSync(reportPath) ? (JSON.parse(fs.readFileSync(reportPath, "utf8")) as JsonReport) : undefined;
    return summarizeLane(version, report, result.status);
  } finally {
    fs.rmSync(reportDir, { recursive: true, force: true });
  }
}

export function formatSummary(lanes: readonly LaneSummary[]): string {
  const rows = [
    ["Git", "result", "passed", "n/a", "skipped", "first failure"],
    ...lanes.map((lane) => [
      lane.version,
      lane.ok ? "pass" : "FAIL",
      String(lane.passed),
      String(lane.notApplicable),
      String(lane.skipped.length),
      lane.firstFailure ?? "",
    ]),
  ];
  const widths = [0, 1, 2, 3, 4].map((column) => Math.max(...rows.map((row) => row[column].length)));
  return rows.map((row) => row.map((cell, column) => (column < 5 ? cell.padEnd(widths[column]) : cell)).join("  ").trimEnd()).join("\n");
}

function option(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index < 0) return undefined;
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} needs a value`);
  return value;
}

function main(argv: readonly string[]): number {
  const lock = readGitBinsLock();
  const onlyVersion = option(argv, "--git") || undefined;
  const onlyFile = option(argv, "--file") || undefined;
  if (onlyVersion && !(onlyVersion in lock.versions)) {
    throw new Error(`Git ${onlyVersion} is not in git-bins.lock.json; locked: ${Object.keys(lock.versions).join(", ")}`);
  }
  const files = onlyFile ? [onlyFile] : parseMatrixFiles(fs.readFileSync(GIT_MATRIX_FILES_PATH, "utf8"));
  if (files.length === 0) throw new Error("tests/git-matrix/files.txt lists no test files");
  for (const file of files) {
    if (!fs.existsSync(path.join(repoRoot, file))) throw new Error(`${file} does not exist`);
  }

  const versions = onlyVersion ? [onlyVersion] : Object.keys(lock.versions).sort(compareGitVersions);
  const lanes = judgeSkips(versions.map((version) => runLane(version, files)));
  console.log(`\n${formatSummary(lanes)}`);
  return lanes.every((lane) => lane.ok) ? 0 : 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (error) {
    console.error(`test-git: ${(error as Error).message}`);
    process.exit(2);
  }
}
