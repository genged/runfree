import { defineConfig, type TestProjectConfiguration } from "vitest/config";

import { CORE_LIVE_FILES, MIXED_LIVE_FILES, selectedLiveTier } from "./tests/runtime/live/tiers.ts";

// These files mutate shared repo state (dist/runtime/**, runtime-inputs.lock.json,
// embedded-assets.generated.ts, packages/*/dist), so they must not run while any
// other test file is running. They live in a separate project that runs after the
// parallel group, one file at a time.
const repoMutatingTests = [
  "scripts/build-runtime.test.ts",
  "scripts/update-runtime-input-lock.test.ts",
];

// The installable-cli files spawn the prebuilt CLI bundle 15-26 times each
// from synchronous test bodies. Under Vitest 3 a worker blocked in those
// spawns for over 60s tripped the RPC heartbeat ("Timeout calling
// onTaskUpdate") with every test green; Vitest 4 disables that timeout
// (vitest-dev/vitest#8297), so they run in the parallel group. A capped
// project is not an option: Vitest 4 requires projects with different
// `maxWorkers` to run in different sequence groups, which would serialize
// them after the parallel group instead.

// The one file that spawns the real bin/runfree.js wrapper (node → tsx → full
// CLI, ~1.5s per spawn uncontended and far worse under 12-way CPU
// oversubscription — a single spawn was observed at 24s inside the parallel
// group, brushing the 30s hang backstop). It runs after the parallel group,
// where its handful of spawns take seconds. It does not overlap the
// repo-serial project: each groupOrder is its own sequence group, so
// bin-wrapper (1) finishes before repo-serial (2) starts.
const binWrapperTests = ["scripts/installable-cli-wrapper.test.ts"];

// Live tranches start Docker, take minutes, and must never run inside the
// ordinary suite. The project that owns them exists only when a backend is
// named, so `pnpm test` cannot pick them up even by accident, and they are
// excluded from the parallel project's `**/*.test.ts` glob regardless.
const liveRuntimeTests = ["tests/runtime/**/*.live.test.ts"];
const cliE2eTests = ["e2e/**/*.test.ts"];
const cliE2eLiveTests = ["e2e/**/*.live.test.ts"];
/**
 * How many live files run at once.
 *
 * Refused rather than defaulted when malformed: silently falling back to 3
 * because someone wrote `TEST_RUNTIME_WORKERS=one` would run a loaded host at
 * the setting they were trying to avoid, and the failure that follows is a
 * memory kill many minutes in.
 */
const LIVE_RUNTIME_WORKERS_ENV = "TEST_RUNTIME_WORKERS";
const DEFAULT_LIVE_RUNTIME_WORKERS = 4;
// The core tier is the per-change gate, run on whatever laptop is at hand;
// two files at a time keeps Docker Desktop clear of the memory pressure that
// dropped the daemon mid-run under four (2026-09-25).
const DEFAULT_CORE_LIVE_RUNTIME_WORKERS = 2;

// Which live files the selected tier runs (`tests/runtime/live/tiers.ts`).
// Core: the core files plus the mixed files, whose extended cases skip.
// Extended: every live file except the core-only ones.
const liveRuntimeTier = selectedLiveTier();
const liveRuntimeInclude = liveRuntimeTier === "core"
  ? [...CORE_LIVE_FILES, ...MIXED_LIVE_FILES]
  : liveRuntimeTests;
const liveRuntimeTierExclude: string[] = liveRuntimeTier === "extended" ? [...CORE_LIVE_FILES] : [];

function liveRuntimeWorkers(): number {
  const configured = process.env[LIVE_RUNTIME_WORKERS_ENV];
  if (configured === undefined || configured === "") {
    return liveRuntimeTier === "core" ? DEFAULT_CORE_LIVE_RUNTIME_WORKERS : DEFAULT_LIVE_RUNTIME_WORKERS;
  }
  if (!/^[1-9][0-9]*$/u.test(configured)) {
    throw new Error(`${LIVE_RUNTIME_WORKERS_ENV} must be a positive integer, got ${JSON.stringify(configured)}`);
  }
  return Number(configured);
}

const liveRuntimeBackend = process.env.TEST_RUNTIME_BACKEND;
const liveRuntimeEnabled = liveRuntimeBackend === "docker-desktop" || liveRuntimeBackend === "orbstack";
const cliE2eEnabled = Boolean(process.env.RUNFREE_E2E_ARTIFACT);
const cliE2eLiveEnabled = cliE2eEnabled && liveRuntimeEnabled && Boolean(process.env.RUNFREE_E2E_DOCKER_HOST);

const commonExclude = [
  ...liveRuntimeTests,
  ...cliE2eTests,
  "projects/**",
  // Maintainer-only and gitignored; it has its own local/scripts/vitest.config.ts.
  "local/**",
  ".worktrees/**",
  ".pnpm-store/**",
  "proxy/node_modules/**",
  "packages/**/node_modules/**",
  "node_modules/**",
];

const liveRuntimeProject: TestProjectConfiguration = {
  extends: true,
  test: {
    name: "runtime-live",
    include: liveRuntimeInclude,
    exclude: [...commonExclude.filter((pattern) => !liveRuntimeTests.includes(pattern)), ...liveRuntimeTierExclude],
    // Forks, not threads: a live tranche spawns Docker work and must be
    // killable as a process.
    //
    // Files run four-at-a-time by default. Each file owns a separate Compose
    // project with its own networks and its own project-hash-derived callback
    // port, so concurrent files do not share runtime state; what they share is
    // the daemon. The original one-at-a-time setting cited address-pool
    // exhaustion, but that hazard is *leaked* networks accumulating across runs
    // (`tests/runtime/reclaim-sandbox-runtimes.sh`), not concurrent ones —
    // four files hold twelve networks against Docker's default pools.
    //
    // Four rather than three because the first parallel run (Docker Desktop,
    // 2026-09-21) measured no contention penalty at all: `attached: peer lock
    // observation` took 35,828 ms beside two other live files, against
    // 35,627 ms in the serial run of 2026-09-11, and `preparation across lease
    // expiry` 55,159 ms against 54,074 ms. Wall clock was 606 s for 1,371 s of
    // work. Concurrency is not what these phases are waiting on.
    //
    // The real limits are host memory (a 2026-09-06 run was killed by memory
    // pressure even at one worker) and the ~1-in-1000 chance that two generated
    // project roots hash to the same MCP callback port. Drop to
    // `TEST_RUNTIME_WORKERS=1` on a loaded host; that is the documented escape
    // and the configuration every live run before 2026-09-21 was measured
    // under.
    pool: "forks",
    maxWorkers: liveRuntimeWorkers(),
    isolate: false,
    // A hang backstop far above any healthy tranche, not a budget. The tranches
    // bound their own live work; this only stops a run that has already lost
    // its way from hanging forever.
    testTimeout: 20 * 60_000,
    hookTimeout: 40 * 60_000,
    // Prebuilds the CLI and session-admission runner bundles the fixture and
    // tranches spawn (tests/support/build-live-bundles.ts); without them each
    // of the run's 100+ spawns boots through tsx at ~1.5s.
    globalSetup: ["tests/support/build-live-bundles.ts"],
    sequence: { groupOrder: 3 },
  },
};

const cliE2eProject: TestProjectConfiguration = {
  extends: true,
  test: {
    name: "cli-e2e",
    include: cliE2eTests,
    exclude: [...commonExclude.filter((pattern) => !cliE2eTests.includes(pattern)), ...cliE2eLiveTests],
    setupFiles: ["e2e/support/setup.ts"],
    sequence: { groupOrder: 4 },
  },
};

const cliE2eLiveProject: TestProjectConfiguration = {
  extends: true,
  test: {
    name: "cli-e2e-live",
    include: cliE2eLiveTests,
    exclude: commonExclude.filter((pattern) => !cliE2eTests.includes(pattern)),
    setupFiles: ["e2e/support/setup.ts"],
    pool: "forks",
    maxWorkers: 1,
    isolate: false,
    testTimeout: 40 * 60_000,
    hookTimeout: 40 * 60_000,
    sequence: { groupOrder: 5 },
  },
};

export default defineConfig({
  test: {
    pool: "threads",
    globals: false,
    // Subprocess-spawning tests slow down under parallel worker contention;
    // the timeout is a hang backstop, not a performance budget.
    testTimeout: 30_000,
    ...(cliE2eEnabled ? { reporters: ["default", "./e2e/support/reporter.ts"] } : {}),
    projects: [
      {
        extends: true,
        test: {
          name: "parallel",
          include: ["**/*.test.ts"],
          exclude: [...commonExclude, ...repoMutatingTests, ...binWrapperTests],
          // Prebuilds the CLI and proxy-server bundles the spawn harnesses run
          // (tests/support/prebuilt-entry.ts). Historically the raw tsx spawns
          // took ~1.5s each, and the installable-cli files had to run
          // single-file after the parallel group because those spawns starved
          // their worker RPC heartbeat under CPU oversubscription; prebuilt
          // spawns (~0.2s) removed that cost. The setup is declared per
          // project (not on the inherited root config, which would run it once
          // per project) and builds once per invocation, so another project
          // may declare it too.
          globalSetup: ["tests/support/build-test-bundles.ts"],
          sequence: { groupOrder: 0 },
        },
      },
      {
        extends: true,
        test: {
          name: "bin-wrapper",
          include: binWrapperTests,
          sequence: { groupOrder: 1 },
        },
      },
      {
        extends: true,
        test: {
          name: "repo-serial",
          include: repoMutatingTests,
          maxWorkers: 1,
          isolate: false,
          sequence: { groupOrder: 2 },
        },
      },
      ...(liveRuntimeEnabled ? [liveRuntimeProject] : []),
      ...(cliE2eEnabled ? [cliE2eProject] : []),
      ...(cliE2eLiveEnabled ? [cliE2eLiveProject] : []),
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      reportsDirectory: "coverage",
      include: ["src/**/*.ts", "packages/**/*.ts", "scripts/**/*.ts"],
      exclude: [
        "**/*.test.ts",
        "**/*.test-harness.ts",
        "packages/cli/src/embedded-assets.generated.ts",
        "projects/**",
        ".worktrees/**",
        ".pnpm-store/**",
        "proxy/node_modules/**",
        "packages/**/node_modules/**",
        "packages/**/dist/**",
        "node_modules/**",
      ],
    },
  },
});
