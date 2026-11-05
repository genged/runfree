import { describe, expect, test } from "vitest";

import { findArchitectureViolations, scanRepository } from "./check-architecture-doc.ts";

function texts(markdown: string): string[] {
  return findArchitectureViolations(markdown).map((violation) => violation.text);
}

describe("architecture-level gate", () => {
  test("rejects source paths, code names, environment variables, and exact limits", () => {
    expect(texts("It runs `packages/proxy/src/host-relay.ts` on the host.")).toEqual(["`packages/proxy/src/host-relay.ts`"]);
    expect(texts("Detection lives in `docker-backend.ts`.")).toEqual(["`docker-backend.ts`"]);
    expect(texts("The CLI lives under `packages/cli/src/`.")).toEqual(["`packages/cli/src/`"]);
    expect(texts("Refused by `validateHostServiceGateway`.")).toEqual(["`validateHostServiceGateway`"]);
    expect(texts("Then `createHostRelay()` starts.")).toEqual(["`createHostRelay()`"]);
    expect(texts("A user's `COMPOSE_PROFILES` never reaches it.")).toEqual(["`COMPOSE_PROFILES`"]);
    expect(texts("as uid 65534, at most 64 pids, with a 250 ms poll and about 2 s")).toEqual([
      "uid 65534",
      "64 pids",
      "250 ms",
      "2 s",
    ]);
  });

  test("accepts plain explanation, user-facing names, and named exceptions", () => {
    expect(texts("The relay runs with no privilege and reads only the effective policy.")).toEqual([]);
    expect(texts("Run `runfree host-service add`, then edit `.runfree/network-policy.json`.")).toEqual([]);
    expect(texts("A `user-*` id, the `ask` default, and `127.0.0.1:<port>`.")).toEqual([]);
    expect(texts("Curated services live in `scripts/services.ts`.")).toEqual(["`scripts/services.ts`"]);
    expect(texts("| Effective policy generation | `controlGeneration` |")).toEqual([]);
    expect(texts("Project Dockerfiles extend `RUNFREE_BASE_IMAGE`.")).toEqual([]);
    expect(texts("Release 2 and version 4 have 3 phases.")).toEqual([]);
  });

  test("skips fenced blocks, which hold diagrams and examples", () => {
    expect(texts("```text\nrequest proxy uid 1001 on :8080\n`host-relay.ts`\n```\nAfter.")).toEqual([]);
    expect(texts("```text\ndiagram\n```\nThen `fooBar` again.")).toEqual(["`fooBar`"]);
  });

  test("reports the line of each violation", () => {
    expect(findArchitectureViolations("one\ntwo `fooBar`\n")).toEqual([
      { line: 2, text: "`fooBar`", reason: "function, type, or field name; describe the idea in plain words" },
    ]);
  });

  test("the repository is clean", () => {
    expect(scanRepository()).toEqual([]);
  });
});
