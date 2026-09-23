// Unit coverage for nested failure rendering.
//
// This exists because its absence cost two live cycles: the causal error was
// captured in an `AggregateError` and never printed, so two tranches reported
// only the wrapper's sentence and looked like they were asserting the wrong
// thing when they were not.

import { describe, expect, test } from "vitest";

import { renderFailure } from "./session-admission-failure.ts";

describe("failure rendering", () => {
  test("renders a plain error as its message", () => {
    expect(renderFailure(new Error("plain failure"))).toBe("plain failure");
  });

  test("renders a non-error value", () => {
    expect(renderFailure("not an error")).toBe("not an error");
    expect(renderFailure(undefined)).toBe("undefined");
  });

  test("renders the causes an AggregateError would otherwise hide", () => {
    // The exact shape the matrix produces: the causal failure first, the
    // recovery failure second, under a wrapper sentence.
    const rendered = renderFailure(new AggregateError(
      [
        new Error("Docker internal network contains an unknown participant"),
        new Error("session-container reconciliation refused untrusted-container"),
      ],
      "recovery failed after 3 attempts; durable pending state remains",
    ));

    expect(rendered).toContain("recovery failed after 3 attempts");
    expect(rendered).toContain("cause 1: Docker internal network contains an unknown participant");
    expect(rendered).toContain("cause 2: session-container reconciliation refused untrusted-container");
  });

  test("renders a nested aggregate", () => {
    const rendered = renderFailure(new AggregateError(
      [new AggregateError([new Error("innermost")], "inner wrapper")],
      "outer wrapper",
    ));
    expect(rendered).toContain("outer wrapper");
    expect(rendered).toContain("inner wrapper");
    expect(rendered).toContain("innermost");
  });

  test("renders a plain cause chain", () => {
    const failure = new Error("outer", { cause: new Error("underlying") });
    expect(renderFailure(failure)).toContain("cause: underlying");
  });

  test("bounds runaway nesting instead of recursing forever", () => {
    // A self-referential cause chain must not hang the runner that is trying to
    // explain a failure.
    const looping = new Error("looping");
    Object.defineProperty(looping, "cause", { value: looping });
    expect(renderFailure(looping)).toContain("depth limit reached");
  });
});
