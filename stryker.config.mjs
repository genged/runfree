// Mutation testing, by hand: `make test-mutation`.
//
// Stryker rewrites one expression at a time in the files below and runs the
// tests that cover it; a mutant the tests do not kill is a place where the
// suite asserts less than it seems to. The targets are the modules whose
// defects the implicit-state-machine audit (local/reviews/2026-11-08-...)
// traced to tests that passed without asserting: the terminal-session marks
// and their classifier, the write-approval holds, and the request classifiers.
// Not a gate: the score is recorded in docs/testing.md, and a change to a
// target is expected to re-run this and keep the surviving mutants explained.
/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  // Named explicitly: pnpm's strict layout does not let the default
  // `@stryker-mutator/*` discovery see the runner.
  plugins: ["@stryker-mutator/vitest-runner"],
  testRunner: "vitest",
  vitest: { configFile: "vitest.mutation.config.ts" },
  mutate: [
    "packages/cli/src/runtime/session-teardown-in-flight.ts",
    "packages/cli/src/runtime/session-admission-pending-reclaim.ts",
    "packages/cli/src/runtime/session-disruption.ts",
    "packages/proxy/src/approvals.ts",
    "packages/proxy/src/denial.ts",
    "packages/proxy/src/graphql-classify.ts",
    "packages/proxy/src/mcp-classify.ts",
  ],
  coverageAnalysis: "perTest",
  // No TypeScript checker: the targets are typed strictly already, and the
  // checker would add a dependency and a type-check per mutant.
  disableTypeChecks: true,
  reporters: ["clear-text", "progress", "html", "json"],
  htmlReporter: { fileName: "local/mutation/report.html" },
  jsonReporter: { fileName: "local/mutation/report.json" },
  // The sandbox copies the checkout; everything a mutant run cannot need is
  // left out (the local records, generated assets, live harnesses, and the
  // symlinked agent skills, which the copy cannot follow).
  ignorePatterns: [
    ".agents", ".claude", ".codex", ".pi", ".runfree", ".worktrees", "local", "dist", "docs", "e2e",
    "tests/runtime", "tests/git-matrix", "bin", "scripts/*.test.ts", "**/*.md",
  ],
  tempDirName: ".stryker-tmp",
  cleanTempDir: true,
  concurrency: 4,
  timeoutMS: 60_000,
  thresholds: { high: 80, low: 60, break: null },
};
