import { describe, expect, test } from "vitest";

import { parseGenerationStatusLine, serializeGenerationStatus } from "./proxy-status.ts";

describe("request-proxy generation status", () => {
  test("carries the OAuth state epoch capability through the one-line framing", () => {
    const line = serializeGenerationStatus({
      generation: "g1",
      controlGeneration: "c1",
      policyGeneration: "g1",
      appliedAt: "2026-09-30T00:00:00.000Z",
      oauthStateEpochs: 1,
    }).trim();
    expect(parseGenerationStatusLine(line)).toEqual({
      generation: "g1",
      controlGeneration: "c1",
      policyGeneration: "g1",
      oauthStateEpochs: true,
    });
  });

  test.each([
    ["absent", {}],
    ["true instead of 1", { oauthStateEpochs: true }],
    ["another version", { oauthStateEpochs: 2 }],
  ])("does not claim the capability when the marker is %s", (_label, marker) => {
    const parsed = parseGenerationStatusLine(JSON.stringify({ generation: "g1", ...marker }));
    expect(parsed?.oauthStateEpochs).toBeUndefined();
  });
});
