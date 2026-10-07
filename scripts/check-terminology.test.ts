import { describe, expect, test } from "vitest";

import { findDocumentationViolations, findTerminologyViolations, scanRepository } from "./check-terminology.ts";

describe("generation-family terminology gate", () => {
  test("rejects bare and article-only generation phrases and unqualified labels", () => {
    expect(findTerminologyViolations("no selected control generation")).toHaveLength(1);
    expect(findTerminologyViolations("select a generation from approved controls").map((v) => v.text)).toEqual(["a generation"]);
    expect(findTerminologyViolations("  generation: sha256:abc").map((v) => v.text)).toEqual([" generation:"]);
    expect(findTerminologyViolations("the selected generation")).toHaveLength(1);
    expect(findTerminologyViolations("a compiled effective generation").map((v) => v.text)).toEqual(["effective generation"]);
  });

  test("accepts family-qualified phrases and labels", () => {
    expect(findTerminologyViolations("no effective policy generation is selected")).toEqual([]);
    expect(findTerminologyViolations("  control plane generation: sha256:abc")).toEqual([]);
    expect(findTerminologyViolations("the active control plane generation")).toEqual([]);
    expect(findTerminologyViolations("session-agent generation digest")).toEqual([]);
    expect(findTerminologyViolations("runtime generation manifest is invalid")).toEqual([]);
  });

  test("documentation lines are held to the same rule, except quoted mentions of a term", () => {
    expect(findDocumentationViolations("The proxy consumes the selected generation.").map((v) => v.text)).toEqual(["selected generation"]);
    expect(findDocumentationViolations('the bare phrase "control generation" is retired')).toEqual([]);
    expect(findDocumentationViolations('"retired" wording: the control generation')).toHaveLength(1);
  });

  test("the repository is clean", () => {
    expect(scanRepository()).toEqual([]);
  });
});
