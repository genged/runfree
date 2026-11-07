import { describe, expect, it } from "vitest";

import { composeProjectName } from "./docker.ts";
import type { CaptureResult, LiveFixture } from "./fixture.ts";

type Answer = Readonly<{ status: number; stdout: string; stderr?: string }>;

function fakeFixture(answers: readonly Answer[]): { fixture: LiveFixture; calls: string[][] } {
  const calls: string[][] = [];
  const fixture: LiveFixture = Object.freeze({
    projectRoot: "/tmp/fake-project",
    ownerRoot: "/tmp/fake-owner",
    env: {},
    runfree(args: readonly string[]): CaptureResult {
      calls.push([...args]);
      const answer = answers[Math.min(calls.length - 1, answers.length - 1)];
      const stderr = answer.stderr ?? "";
      return Object.freeze({ status: answer.status, stdout: answer.stdout, stderr, output: `${answer.stdout}${stderr}` });
    },
  });
  return { fixture, calls };
}

const ARGV = ["project-id", "--compose-name"];

describe("composeProjectName", () => {
  it("asks the CLI once per fixture and returns the same name", () => {
    const { fixture, calls } = fakeFixture([{ status: 0, stdout: "runfree-abc\n" }]);
    expect(composeProjectName(fixture)).toBe("runfree-abc");
    expect(composeProjectName(fixture)).toBe("runfree-abc");
    expect(calls).toEqual([ARGV]);
  });

  it("asks separately for each fixture", () => {
    const first = fakeFixture([{ status: 0, stdout: "runfree-one\n" }]);
    const second = fakeFixture([{ status: 0, stdout: "runfree-two\n" }]);
    expect(composeProjectName(first.fixture)).toBe("runfree-one");
    expect(composeProjectName(second.fixture)).toBe("runfree-two");
    expect(composeProjectName(first.fixture)).toBe("runfree-one");
    expect(composeProjectName(second.fixture)).toBe("runfree-two");
    expect(first.calls).toEqual([ARGV]);
    expect(second.calls).toEqual([ARGV]);
  });

  it("does not cache a non-zero exit", () => {
    const { fixture, calls } = fakeFixture([
      { status: 1, stdout: "", stderr: "boom" },
      { status: 0, stdout: "runfree-later\n" },
    ]);
    expect(() => composeProjectName(fixture)).toThrow("could not read the Compose project name: boom");
    expect(composeProjectName(fixture)).toBe("runfree-later");
    expect(composeProjectName(fixture)).toBe("runfree-later");
    expect(calls).toEqual([ARGV, ARGV]);
  });

  it("does not cache an empty answer", () => {
    const { fixture, calls } = fakeFixture([
      { status: 0, stdout: "  \n" },
      { status: 0, stdout: "runfree-later\n" },
    ]);
    expect(() => composeProjectName(fixture)).toThrow(/^the Compose project name was empty$/u);
    expect(composeProjectName(fixture)).toBe("runfree-later");
    expect(calls).toEqual([ARGV, ARGV]);
  });
});
