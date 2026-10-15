import { describe, expect, test } from "vitest";

import {
  observeStartupRun,
  redactSecrets,
  summarizeStartupSamples,
  type StartupRunSpec,
  type StartupSample,
} from "./benchmark-startup.ts";

let nextRunId = 0;

/** Spawns a tiny Node `-e` script as the fake child under test, through the real `observeStartupRun` driver. */
function runFakeChild(script: string, overrides: Partial<StartupRunSpec> = {}): Promise<StartupSample> {
  nextRunId += 1;
  return observeStartupRun({
    command: process.execPath,
    args: ["-e", script],
    scenarioId: "test-scenario",
    tree: "test-tree",
    runId: `run-${nextRunId}`,
    timeoutMs: 10_000,
    ...overrides,
  });
}

function minimalSample(overrides: Partial<StartupSample>): StartupSample {
  return {
    tree: "test-tree",
    scenarioId: "test-scenario",
    runId: `fixture-${nextRunId++}`,
    phaseDurationsMs: {},
    wallToHandoffMs: { observed: false, reason: "fixture" },
    normalExitMs: { observed: false, reason: "fixture" },
    outcome: { kind: "success" },
    operationCounts: {},
    environment: {},
    ...overrides,
  };
}

describe("benchmark-startup harness", () => {
  test("retains failed runs and missing readiness", async () => {
    const reached = await runFakeChild('console.log("timing: launch-handoff minted"); process.exitCode = 0;');
    const failedBeforeHandoff = await runFakeChild('process.stderr.write("boom\\n"); process.exitCode = 7;');

    // Both runs come back as samples; a failure is never thrown away.
    expect(reached.outcome).toEqual({ kind: "success" });
    expect(failedBeforeHandoff.outcome).toEqual({ kind: "failure", reason: "exit code 7: boom" });

    // The readiness milestone is absent with a reason, never a zero, for the run that never reached it.
    expect(failedBeforeHandoff.wallToHandoffMs).toEqual({
      observed: false,
      reason: "process did not reach it (failure)",
    });
    // normalExitMs's absent reason reuses the outcome's own reason -- the
    // same event explains both, so there is no second, separately-worded
    // placeholder to drift out of sync with it.
    expect(failedBeforeHandoff.normalExitMs).toEqual({ observed: false, reason: "exit code 7: boom" });
    expect(reached.wallToHandoffMs.observed).toBe(true);

    const summary = summarizeStartupSamples([reached, failedBeforeHandoff]);
    expect(summary.cohorts).toHaveLength(1);
    const [cohort] = summary.cohorts;
    // The failed run is counted, not dropped...
    expect(cohort?.totalRuns).toBe(2);
    expect(cohort?.failures).toBe(1);
    expect(cohort?.outcomeCounts).toEqual({ success: 1, failure: 1 });
    // ...but it never contributes a fabricated zero to the handoff metric: only
    // the one run that actually observed the milestone counts toward it.
    expect(cohort?.metrics.wallToHandoffMs?.count).toBe(1);
    expect(cohort?.metrics.normalExitMs?.count).toBe(1);
  });

  test("does not sum nested spans", () => {
    // `startup-total` nests `token-sync` in the real system (see
    // local/plans/2026-09-25-sub-second-launch-implementation.md). The
    // summarizer must report each self-reported phase under its own name,
    // never derive a combined total by adding them.
    const samples: StartupSample[] = [
      minimalSample({
        runId: "s1",
        phaseDurationsMs: { "startup-total": 1000, "token-sync": 50 },
        wallToHandoffMs: { observed: true, ms: 1000 },
      }),
      minimalSample({
        runId: "s2",
        phaseDurationsMs: { "startup-total": 1100, "token-sync": 60 },
        wallToHandoffMs: { observed: true, ms: 1100 },
      }),
      minimalSample({
        runId: "s3",
        phaseDurationsMs: { "startup-total": 1200, "token-sync": 70 },
        wallToHandoffMs: { observed: true, ms: 1200 },
      }),
    ];

    const summary = summarizeStartupSamples(samples);
    expect(summary.cohorts).toHaveLength(1);
    const metrics = summary.cohorts[0]?.metrics ?? {};

    expect(metrics["phase:startup-total"]?.medianMs).toBe(1100);
    expect(metrics["phase:token-sync"]?.medianMs).toBe(60);
    // Exactly the named phases and the one populated milestone appear: no
    // extra aggregate key (for example a combined "total") was synthesized.
    expect(Object.keys(metrics).sort()).toEqual(["phase:startup-total", "phase:token-sync", "wallToHandoffMs"].sort());
    // The nested phase's own median is nowhere close to the sum of the two.
    expect(metrics["phase:startup-total"]?.medianMs).not.toBe(1100 + 60);
  });

  test("separates invocation from named phases", async () => {
    // The child under-reports its own `startup-total` (1ms) and only prints
    // the handoff marker after a real 200ms sleep. The harness must keep its
    // own parent-observed handoff time distinct from that self-report.
    const script = [
      'console.log("timing: startup-total 1ms");',
      "setTimeout(() => {",
      '  console.log("timing: launch-handoff minted");',
      "  process.exitCode = 0;",
      "}, 200);",
    ].join("\n");
    const sample = await runFakeChild(script);

    expect(sample.phaseDurationsMs["startup-total"]).toBe(1);
    expect(sample.wallToHandoffMs.observed).toBe(true);
    const handoffMs = sample.wallToHandoffMs.observed ? sample.wallToHandoffMs.ms : Number.NaN;
    // The parent's own clock reflects the real wait, not the child's
    // self-report: it must be nowhere near the 1ms the child printed.
    expect(handoffMs).toBeGreaterThanOrEqual(150);
    expect(handoffMs).not.toBe(sample.phaseDurationsMs["startup-total"]);
  }, 15_000);

  test("parses the real output formatter's prefixed, timestamped lines", async () => {
    // Every real `timing:` line is actually emitted through the project's
    // one output formatter (packages/cli/src/runtime/timings.ts calling
    // packages/cli/src/warnings.ts's runfreeLog/emit), which prepends a
    // "runfree:" severity prefix and, on this piped (non-TTY) child, an ISO
    // timestamp -- never a bare "timing: ..." line. This drives that real
    // code (imported by file URL, not re-typed here) so a regression in the
    // harness's parser/handoff-pattern anchoring is caught against the
    // actual format it must match, not a synthetic stand-in for it.
    const timingsUrl = new URL("../packages/cli/src/runtime/timings.ts", import.meta.url).href;
    const script = [
      `import { createRuntimeTimings } from ${JSON.stringify(timingsUrl)};`,
      'const timings = createRuntimeTimings({ RUNFREE_TIMINGS: "1" });',
      'timings.time("token-sync", () => {});',
      'timings.report("launch-handoff", "minted");',
    ].join("\n");

    const sample = await observeStartupRun({
      command: process.execPath,
      args: ["--import", "tsx", "--input-type=module", "-e", script],
      scenarioId: "test-scenario",
      tree: "test-tree",
      runId: `run-${nextRunId++}`,
      timeoutMs: 20_000,
    });

    expect(sample.outcome).toEqual({ kind: "success" });
    expect(sample.wallToHandoffMs.observed).toBe(true);
    expect(typeof sample.phaseDurationsMs["token-sync"]).toBe("number");
    expect(sample.phaseDurationsMs["token-sync"]).toBeGreaterThanOrEqual(0);
  }, 25_000);

  test("redacts a secret that straddles the diagnostic tail boundary", async () => {
    // The harness keeps only the last 2000 characters of captured output
    // for a failure's short diagnostic `reason`. Build a single `op://`
    // reference long enough that this boundary falls well past its 5-char
    // "op://" prefix, with every slash-separated segment short enough
    // (under 32 characters) that the generic opaque-token fallback pattern
    // cannot catch a surviving fragment on its own -- only redacting the
    // whole captured output before any slicing can catch this. (If the
    // order ever regresses to slice-then-redact, the raw, unprefixed
    // fragment would leak into `reason` untouched.)
    const segments = Array.from({ length: 400 }, (_, index) => `segment${index}`);
    const secret = `op://${segments.join("/")}`;
    expect(secret.length).toBeGreaterThan(2010);
    expect(segments.every((segment) => segment.length < 32)).toBe(true);

    const script = `process.stderr.write(${JSON.stringify(`starting up\n${secret}`)}); process.exitCode = 9;`;
    const sample = await runFakeChild(script);

    expect(sample.outcome.kind).toBe("failure");
    const reason = sample.outcome.kind === "failure" ? sample.outcome.reason : "";
    expect(reason).toContain("op://[redacted]");
    expect(reason).not.toMatch(/segment\d+/);
  });

  test("redacts provider identifiers and values", async () => {
    expect(redactSecrets("token=abc123 plain text")).toContain("token=[redacted]");
    expect(redactSecrets("op://Vault/Item/field")).toBe("op://[redacted]");

    const secretLine =
      "failed reading op://PrivateVault/APIKey/credentialvalue for " +
      "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789";
    const sample = await runFakeChild(`process.stderr.write(${JSON.stringify(`${secretLine}\n`)}); process.exitCode = 3;`);

    expect(sample.outcome.kind).toBe("failure");
    const reason = sample.outcome.kind === "failure" ? sample.outcome.reason : "";
    expect(reason).not.toContain("PrivateVault");
    expect(reason).not.toContain("APIKey");
    expect(reason).not.toContain("credentialvalue");
    expect(reason).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
    expect(reason).toContain("[redacted]");
    expect(reason).toContain("exit code 3");
  });
});
