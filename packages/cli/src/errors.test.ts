import { describe, expect, test } from "vitest";

import {
  renderUnexpectedError,
  UNEXPECTED_ERROR_RENDER_LIMITS,
} from "./errors.ts";

describe("unexpected CLI error rendering", () => {
  test("shows AggregateError children and nested causes without child stacks", () => {
    const first = new Error("firewall did not acknowledge generation");
    first.stack = "Error: firewall did not acknowledge generation\n    at hidden-child-stack";
    const cause = new Error("firewall did not acknowledge removal");
    const second = new Error("registry-first revocation did not converge", { cause });
    const error = new AggregateError([first, second], "coordination and compensation failed");
    error.stack = "AggregateError: coordination and compensation failed\n    at top-level-stack";

    const rendered = renderUnexpectedError(error);

    expect(rendered).toContain("AggregateError: coordination and compensation failed");
    expect(rendered).toContain("at top-level-stack");
    expect(rendered).toContain("error[0]:\n    Error: firewall did not acknowledge generation");
    expect(rendered).toContain("error[1]:\n    Error: registry-first revocation did not converge");
    expect(rendered).toContain("cause:\n      Error: firewall did not acknowledge removal");
    expect(rendered).not.toContain("hidden-child-stack");
  });

  test("bounds cycles, depth, node count, messages, and output bytes", () => {
    const cyclic = new Error("cycle");
    cyclic.cause = cyclic;
    expect(renderUnexpectedError(cyclic)).toContain("[cycle: Error: cycle]");

    const deep = new Error("0");
    let cursor = deep;
    for (let index = 1; index < 12; index += 1) {
      const next = new Error(String(index));
      cursor.cause = next;
      cursor = next;
    }
    expect(renderUnexpectedError(deep)).toContain("[depth limit reached]");

    const many = new AggregateError(
      Array.from({ length: 40 }, (_, index) => new Error(`child-${index}`)),
      "many",
    );
    expect(renderUnexpectedError(many)).toContain("[error node limit reached]");

    const long = new Error("x".repeat(UNEXPECTED_ERROR_RENDER_LIMITS.maxOutputBytes * 2));
    const rendered = renderUnexpectedError(long);
    expect(Buffer.byteLength(rendered)).toBeLessThanOrEqual(UNEXPECTED_ERROR_RENDER_LIMITS.maxOutputBytes);
    expect(rendered).toContain("…");
  });

  test("keeps nested causes ahead of a top-level stack that exhausts the byte budget", () => {
    const nested = new Error("actionable nested cause");
    const error = new Error("outer", { cause: nested });
    error.stack = `Error: outer\n${"    at very-long-frame\n".repeat(2_000)}`;

    const rendered = renderUnexpectedError(error);
    expect(rendered).toContain("cause:\n    Error: actionable nested cause");
    expect(Buffer.byteLength(rendered)).toBeLessThanOrEqual(UNEXPECTED_ERROR_RENDER_LIMITS.maxOutputBytes);
    expect(rendered).toContain("[output truncated]");
  });

  test("does not render multiline message continuations as stack frames", () => {
    const hiddenContinuation = `    at ${"x".repeat(UNEXPECTED_ERROR_RENDER_LIMITS.maxMessageCharacters * 2)}`;
    const error = new Error(`first line\n${hiddenContinuation}`);
    error.stack = `${error.name}: ${error.message}\n    at retained-frame`;

    const rendered = renderUnexpectedError(error);

    expect(rendered).toContain("…");
    expect(rendered).toContain("at retained-frame");
    expect(rendered).not.toContain(hiddenContinuation);
  });

  test("bounds intermediate stack traversal before rendering", () => {
    const error = new Error("large stack");
    error.stack = `Error: large stack\n${"    at repeated-frame\n".repeat(100_000)}`;

    const rendered = renderUnexpectedError(error);

    expect(Buffer.byteLength(rendered)).toBeLessThanOrEqual(UNEXPECTED_ERROR_RENDER_LIMITS.maxOutputBytes);
    expect(rendered).toContain("at repeated-frame");
  });

  test("does not inspect non-Error values or arbitrary enumerable properties", () => {
    const error = new Error("safe message") as Error & { credential: string; requestBody: string };
    error.credential = "rf-secret-value";
    error.requestBody = "sensitive request body";

    const rendered = renderUnexpectedError(error);
    expect(rendered).not.toContain("rf-secret-value");
    expect(rendered).not.toContain("sensitive request body");
    expect(renderUnexpectedError({ credential: "another-secret" })).toBe("NonErrorThrown: object");
    expect(renderUnexpectedError("secret string value")).toBe("NonErrorThrown: string");
  });
});
