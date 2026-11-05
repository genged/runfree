import path from "node:path";

import { describe, expect, test } from "vitest";

import { repoRoot } from "./git-bins.ts";
import { formatSummary, parseMatrixFiles, summarizeLane } from "./test-git.ts";

function report(...results: { title: string; status: string; failureMessages?: string[] }[]) {
  return {
    numTotalTests: results.length,
    testResults: [{
      name: path.join(repoRoot, "scripts", "a.test.ts"),
      assertionResults: results.map((result) => ({ ...result, fullName: result.title })),
    }],
  };
}

test("files.txt parsing drops blanks and comments", () => {
  expect(parseMatrixFiles("# header\n\nscripts/a.test.ts\n  scripts/b.test.ts  \n")).toEqual(["scripts/a.test.ts", "scripts/b.test.ts"]);
});

describe("lane verdict", () => {
  test("passes when every test passes", () => {
    expect(summarizeLane("2.48.0", report({ title: "a", status: "passed" }), 0)).toEqual({
      version: "2.48.0", ok: true, passed: 1, notApplicable: 0, firstFailure: undefined,
    });
  });

  test("counts a skip declared for a newer Git as not applicable", () => {
    const lane = summarizeLane("2.43.0", report(
      { title: "a", status: "passed" },
      { title: "b [needs Git 2.48]", status: "skipped" },
    ), 0);
    expect(lane).toMatchObject({ ok: true, passed: 1, notApplicable: 1 });
  });

  test("fails on a skip without a requirement, so a lane cannot pass by skipping", () => {
    const lane = summarizeLane("2.43.0", report(
      { title: "a", status: "passed" },
      { title: "b", status: "skipped" },
    ), 0);
    expect(lane.ok).toBe(false);
    expect(lane.firstFailure).toContain("b: skipped without a needsGit requirement above 2.43.0");
  });

  test("fails on a declared skip at or above its required version", () => {
    const lane = summarizeLane("2.48.0", report(
      { title: "a", status: "passed" },
      { title: "b [needs Git 2.48]", status: "skipped" },
    ), 0);
    expect(lane.ok).toBe(false);
  });

  test("names the first failure, and fails a lane with no report or no passing test", () => {
    const failed = summarizeLane("2.48.0", report(
      { title: "a", status: "failed", failureMessages: ["\nAssertionError: boom\n  at x"] },
    ), 1);
    expect(failed).toMatchObject({ ok: false, firstFailure: "scripts/a.test.ts > a: AssertionError: boom" });
    expect(summarizeLane("2.48.0", undefined, 1)).toMatchObject({ ok: false, firstFailure: "vitest exited with 1 and wrote no report" });
    expect(summarizeLane("2.48.0", report(), 0)).toMatchObject({ ok: false, firstFailure: "no test passed" });
  });
});

test("the summary table lists every lane", () => {
  const table = formatSummary([
    { version: "2.39.5", ok: true, passed: 450, notApplicable: 8 },
    { version: "2.56.0", ok: false, passed: 457, notApplicable: 0, firstFailure: "x > y: boom" },
  ]);
  expect(table.split("\n")).toEqual([
    "Git     result  passed  n/a  first failure",
    "2.39.5  pass    450     8",
    "2.56.0  FAIL    457     0    x > y: boom",
  ]);
});
