import path from "node:path";

import { describe, expect, test } from "vitest";

import { repoRoot } from "./git-bins.ts";
import { formatSummary, judgeSkips, parseMatrixFiles, summarizeLane } from "./test-git.ts";

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
      version: "2.48.0", ok: true, passed: 1, notApplicable: 0, skipped: [], ran: ["scripts/a.test.ts > a"], firstFailure: undefined,
    });
  });

  test("counts a skip declared for a newer Git as not applicable", () => {
    const lane = summarizeLane("2.43.0", report(
      { title: "a", status: "passed" },
      { title: "b [needs Git 2.48]", status: "skipped" },
    ), 0);
    expect(lane).toMatchObject({ ok: true, passed: 1, notApplicable: 1 });
  });

  test("a skip on every lane, like a platform guard, is counted but does not fail", () => {
    const lanes = judgeSkips(["2.43.0", "2.56.0"].map((version) => summarizeLane(version, report(
      { title: "a", status: "passed" },
      { title: "linux only", status: "skipped" },
    ), 0)));
    expect(lanes.map((lane) => lane.ok)).toEqual([true, true]);
    expect(lanes[0].skipped).toEqual(["scripts/a.test.ts > linux only"]);
  });

  test("fails a lane that skips a test another Git ran, so a lane cannot pass by skipping", () => {
    const lanes = judgeSkips([
      summarizeLane("2.43.0", report({ title: "a", status: "passed" }, { title: "b", status: "skipped" }), 0),
      summarizeLane("2.56.0", report({ title: "a", status: "passed" }, { title: "b", status: "passed" }), 0),
    ]);
    expect(lanes[0].ok).toBe(false);
    expect(lanes[0].firstFailure).toBe("scripts/a.test.ts > b: skipped on Git 2.43.0 but ran on Git 2.56.0; declare needsGit");
    expect(lanes[1].ok).toBe(true);
  });

  test("fails on a declared skip at or above its required version", () => {
    const lane = summarizeLane("2.48.0", report(
      { title: "a", status: "passed" },
      { title: "b [needs Git 2.48]", status: "skipped" },
    ), 0);
    expect(lane.ok).toBe(false);
    expect(lane.firstFailure).toBe("scripts/a.test.ts > b [needs Git 2.48]: skipped on Git 2.48.0, which meets its requirement");
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
    { version: "2.39.5", ok: true, passed: 450, notApplicable: 8, skipped: ["s"], ran: [] },
    { version: "2.56.0", ok: false, passed: 457, notApplicable: 0, skipped: [], ran: [], firstFailure: "x > y: boom" },
  ]);
  expect(table.split("\n")).toEqual([
    "Git     result  passed  n/a  skipped  first failure",
    "2.39.5  pass    450     8    1",
    "2.56.0  FAIL    457     0    0        x > y: boom",
  ]);
});
