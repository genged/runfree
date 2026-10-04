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

  test("ignores files without the literal and allowlisted files", () => {
    expect(findDockerLiteralViolations([
      { path: "a.ts", text: "const x = 'dockerfile';" },
      { path: "b.ts", text: 'command === "docker"' },
    ], { "b.ts": "classifier: compares the command name" })).toEqual([]);
  });

  test("an allowlisted file that no longer contains the literal is reported as stale", () => {
    expect(findDockerLiteralViolations([{ path: "b.ts", text: "nothing" }], { "b.ts": "owner" }))
      .toEqual(["b.ts (allowlisted but has no \"docker\" literal; remove its entry)"]);
  });

  test("every allowlist entry has a reason", () => {
    for (const reason of Object.values(DOCKER_LITERAL_ALLOWLIST)) expect(reason.length).toBeGreaterThan(0);
  });
});
