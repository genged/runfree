import fs from "node:fs";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  CORE_LIVE_FILES,
  LIVE_TIER_ENV,
  MIXED_LIVE_FILES,
  liveTierSelected,
  selectedLiveTier,
} from "./tiers.ts";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..", "..");
const CASE = /^\s{2}(test|coreTest|extendedTest)(\.skip)?\(/gmu;

function caseKinds(file: string): string[] {
  const source = fs.readFileSync(path.join(repoRoot, file), "utf8");
  return [...source.matchAll(CASE)].filter((match) => match[2] === undefined).map((match) => match[1]);
}

describe("live runtime tiers", () => {
  test("the tier defaults to all and refuses an unknown value", () => {
    expect(selectedLiveTier({})).toBe("all");
    expect(selectedLiveTier({ [LIVE_TIER_ENV]: "" })).toBe("all");
    expect(selectedLiveTier({ [LIVE_TIER_ENV]: "core" })).toBe("core");
    expect(() => selectedLiveTier({ [LIVE_TIER_ENV]: "Core" })).toThrow(/must be one of core, extended, all/u);
  });

  test.each([
    ["all", true, true],
    ["core", true, false],
    ["extended", false, true],
  ] as const)("tier %s runs core cases: %s, extended cases: %s", (tier, core, extended) => {
    const env = { [LIVE_TIER_ENV]: tier };
    expect(liveTierSelected("core", env)).toBe(core);
    expect(liveTierSelected("extended", env)).toBe(extended);
  });

  test("every listed file exists and is listed once", () => {
    const listed = [...CORE_LIVE_FILES, ...MIXED_LIVE_FILES];
    expect(new Set(listed).size).toBe(listed.length);
    for (const file of listed) expect(fs.existsSync(path.join(repoRoot, file)), file).toBe(true);
  });

  test("a mixed file tags every active case with a tier, and a core file tags none", () => {
    for (const file of MIXED_LIVE_FILES) {
      const kinds = caseKinds(file);
      expect(kinds.length, file).toBeGreaterThan(0);
      expect(kinds.filter((kind) => kind === "test"), `${file} has an untiered case`).toEqual([]);
      expect(kinds, `${file} has no core case`).toContain("coreTest");
      expect(kinds, `${file} has no extended case`).toContain("extendedTest");
    }
    for (const file of CORE_LIVE_FILES) {
      expect(caseKinds(file).filter((kind) => kind !== "test"), `${file} is core-only but tiers a case`).toEqual([]);
    }
  });
});
