// The Vitest configuration `make test-mutation` hands to Stryker.
//
// Flat on purpose: Stryker's Vitest runner drives one project, and the
// mutation targets (stryker.config.mjs) are pure modules whose tests need no
// prebuilt bundle, Docker, or repo-mutating serialization. Only the test
// files that exercise those targets are included, so each mutant is judged
// by the tests that can kill it and the run stays within a by-hand budget.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    pool: "forks",
    globals: false,
    testTimeout: 30_000,
    include: [
      "packages/proxy/src/denial*.test.ts",
      "packages/proxy/src/graphql-classify*.test.ts",
      "packages/proxy/src/mcp-classify*.test.ts",
      "packages/proxy/src/approvals*.test.ts",
      "packages/cli/src/runtime/session-admission-pending-reclaim*.test.ts",
      "packages/cli/src/runtime/session-disruption*.test.ts",
      "packages/cli/src/runtime/session-teardown-crash*.test.ts",
    ],
  },
});
