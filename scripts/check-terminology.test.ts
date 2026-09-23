import { describe, expect, test } from "vitest";

import { findTerminologyViolations, scanRepository } from "./check-terminology.ts";

describe("generation-family terminology gate", () => {
  test("rejects bare and article-only generation phrases and unqualified labels", () => {
    expect(findTerminologyViolations("no selected control generation")).toHaveLength(1);
    expect(findTerminologyViolations("select a generation from approved controls").map((v) => v.text)).toEqual(["a generation"]);
    expect(findTerminologyViolations("  generation: sha256:abc").map((v) => v.text)).toEqual([" generation:"]);
    expect(findTerminologyViolations("the selected generation")).toHaveLength(1);
  });

  test("accepts family-qualified phrases and labels", () => {
    expect(findTerminologyViolations("no effective policy generation is selected")).toEqual([]);
    expect(findTerminologyViolations("  control plane generation: sha256:abc")).toEqual([]);
    expect(findTerminologyViolations("the active control plane generation")).toEqual([]);
    expect(findTerminologyViolations("session-agent generation digest")).toEqual([]);
    expect(findTerminologyViolations("runtime generation manifest is invalid")).toEqual([]);
  });

  test("the repository is clean", () => {
    expect(scanRepository()).toEqual([]);
  });
});
