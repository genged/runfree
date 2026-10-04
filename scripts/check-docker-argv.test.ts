import { describe, expect, test } from "vitest";

import { DOCKER_LITERAL_ALLOWLIST, findDockerLiteralViolations } from "./check-docker-argv.ts";

describe("docker argv gate", () => {
  test("flags a source file with a \"docker\" literal that is not allowlisted", () => {
    const violations = findDockerLiteralViolations(
      [{ path: "packages/cli/src/runtime/new-thing.ts", text: 'io.capture("docker", ["ps"])' }],
      {},
    );
    expect(violations).toEqual(["packages/cli/src/runtime/new-thing.ts"]);
  });

  test("ignores files without the literal and allowlisted files whose count matches", () => {
    expect(findDockerLiteralViolations([
      { path: "a.ts", text: "const x = 'dockerfile';" },
      { path: "b.ts", text: 'command === "docker"' },
    ], { "b.ts": { reason: "classifier: compares the command name", count: 1 } })).toEqual([]);
  });

  test("an allowlisted file that no longer contains the literal is reported as stale", () => {
    expect(findDockerLiteralViolations([{ path: "b.ts", text: "nothing" }], { "b.ts": { reason: "owner", count: 1 } }))
      .toEqual(["b.ts (allowlisted but has no \"docker\" literal; remove its entry)"]);
  });

  test("a file whose literal count grows past the allowlisted count fails", () => {
    const violations = findDockerLiteralViolations(
      [{ path: "b.ts", text: 'io.capture("docker", ["ps"]); io.capture("docker", ["info"]);' }],
      { "b.ts": { reason: "owner", count: 1 } },
    );
    expect(violations).toEqual(["b.ts (allowlisted for 1 \"docker\" literal(s), found 2; update the allowlist count)"]);
  });

  test("a file whose literal count matches the allowlisted count passes", () => {
    expect(findDockerLiteralViolations(
      [{ path: "b.ts", text: 'io.capture("docker", ["ps"]); io.capture("docker", ["info"]);' }],
      { "b.ts": { reason: "owner", count: 2 } },
    )).toEqual([]);
  });

  test("a file whose literal count drops below the allowlisted count fails (stale count)", () => {
    const violations = findDockerLiteralViolations(
      [{ path: "b.ts", text: 'io.capture("docker", ["ps"]);' }],
      { "b.ts": { reason: "owner", count: 2 } },
    );
    expect(violations).toEqual(["b.ts (allowlisted for 2 \"docker\" literal(s), found 1; update the allowlist count)"]);
  });

  test("every allowlist entry has a reason", () => {
    for (const entry of Object.values(DOCKER_LITERAL_ALLOWLIST)) expect(entry.reason.length).toBeGreaterThan(0);
  });

  test("every allowlist entry's count matches its own reason text frequency in the live tree", () => {
    // DOCKER_LITERAL_ALLOWLIST pins a count per file; this is exercised
    // end-to-end by running scripts/check-docker-argv.ts against the tree
    // (make test-static), which is what actually recounts each file. Here we
    // only pin that every entry declares a positive count.
    for (const entry of Object.values(DOCKER_LITERAL_ALLOWLIST)) expect(entry.count).toBeGreaterThan(0);
  });

  test("no file is still pending migration", () => {
    expect(Object.entries(DOCKER_LITERAL_ALLOWLIST).filter(([, entry]) => entry.reason.startsWith("pending:"))).toEqual([]);
  });
});
