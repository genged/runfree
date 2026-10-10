#!/usr/bin/env node
// Startup measurement harness (T01 of
// local/plans/2026-10-10-startup-top-ten-implementation.md: "Establish
// measurements and inherited-gate ledger"). Later tasks (T02-T15) use this
// harness's sample shape and summarizer to measure before/after each startup
// change; this task only builds the harness. No measurement was run to write
// this file, and this environment has no Docker daemon to run one against.
//
// What this is:
//   - `StartupSample`: one observed run, with named phase durations (parsed
//     from the project's existing `timing: <phase> <detail>` lines — see
//     `tests/runtime/live/launch-timing-support.ts` and
//     `local/scripts/launch-timing-bench.sh`, which use the same format) plus
//     milestones the *parent* observes on its own monotonic clock
//     (`performance.now()`), never a value the child process reports about
//     itself. A missing milestone is `{ observed: false, reason }`, never a
//     zero.
//   - `observeStartupRun`: spawns one command, watches its combined
//     stdout/stderr for configurable milestone patterns (handoff, first
//     useful agent response, first successful MCP exchange), and returns a
//     `StartupSample` once the process exits (or is killed after its
//     timeout). A nonzero exit, a signal, or a timeout still returns a
//     sample — it is never thrown away — with `outcome` recording why and
//     every unreached milestone left absent.
//   - `summarizeStartupSamples`: groups samples by (scenarioId, tree) —
//     never merging samples from different trees into one metric — and
//     reports count, failures, median and empirical nearest-rank p95 per
//     metric, from only the samples that actually observed it. It never
//     sums different named phases into a derived total: a phase that nests
//     others (for example `startup-total` containing `token-sync`) is
//     reported once, under its own name.
//
// What this is not: it does not decide what "useful agent" or "first MCP
// success" means for a given scenario. A caller (a later task's own driver,
// or a maintainer running this by hand) supplies `usefulAgentPattern` /
// `firstMcpSuccessPattern` for its own controlled agent/MCP setup. A shell
// exiting zero proves neither credential correctness nor MCP usefulness, so
// this harness never infers either milestone from the exit code.
//
// Redaction: diagnostic text this harness keeps (a failure's `reason`, and
// any string environment metadata the caller passes in) is passed through
// `redactSecrets`, which scrubs 1Password-style `op://` references, bearer
// tokens, `token=`/`secret=`/`password=`-shaped assignments, and bare
// long opaque tokens. This is a best-effort backstop for diagnostic strings
// built from untrusted child output, not a substitute for keeping real
// credential values out of child argv/env/logs in the first place (see
// AGENTS.md "Project Rules" and this plan's "Global constraints"). This
// harness never retains a run's raw stdout/stderr.
//
// Usage (requires a Docker host; this task did not run it):
//
//   pnpm exec tsx scripts/benchmark-startup.ts run \
//     --scenario-id warm-claude --tree "$(git rev-parse HEAD)" --run-id 1 \
//     --out local/evidence/raw/2026-xx-xx-warm-claude.jsonl \
//     -- scripts/dev-runfree.sh --workspace /path/to/scratch/project claude
//
//   pnpm exec tsx scripts/benchmark-startup.ts summarize \
//     local/evidence/raw/2026-xx-xx-warm-claude.jsonl
//
// `run` appends one JSON Line per invocation to `--out` (creating it if
// needed) and never truncates or rewrites an existing file, so interleaved
// baseline/candidate runs accumulate in one immutable log (this plan's
// "Keep original logs immutable and never overwrite runs").

import childProcess from "node:child_process";
import fs from "node:fs";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

// Order matters: the named shapes run first (so their replacement text, for
// example "token=[redacted]", stays legible), then the opaque-token fallback
// catches a bare secret that slipped past every named shape (a pasted value
// with no recognizable prefix).
const REDACTION_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/op:\/\/[^\s"'<>]+/gi, "op://[redacted]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]"],
  [/\b(token|api[_-]?key|secret|password|authorization)\s*[=:]\s*\S+/gi, "$1=[redacted]"],
  [/\b[A-Za-z0-9_-]{32,}\b/g, "[redacted]"],
];

/**
 * Best-effort scrub of provider identifiers and secret-shaped values from a
 * diagnostic string. See the module header's "Redaction" note for what this
 * is and is not.
 */
export function redactSecrets(text: string): string {
  return REDACTION_PATTERNS.reduce((acc, [pattern, replacement]) => acc.replace(pattern, replacement), text);
}

function redactEnvironment(
  environment: Readonly<Record<string, string | number | boolean>>,
): Record<string, string | number | boolean> {
  const result: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(environment)) {
    result[key] = typeof value === "string" ? redactSecrets(value) : value;
  }
  return result;
}

function lastNonEmptyLine(text: string): string {
  const lines = text.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  return lines.at(-1) ?? "";
}

// ---------------------------------------------------------------------------
// Sample shape
// ---------------------------------------------------------------------------

/** A milestone the parent observed on its own monotonic clock, or an explicit reason it was never observed. Never zero for "missing". */
export type StartupMilestone =
  | { readonly observed: true; readonly ms: number }
  | { readonly observed: false; readonly reason: string };

function milestoneObserved(ms: number): StartupMilestone {
  return { observed: true, ms: Math.round(ms * 100) / 100 };
}

function milestoneAbsent(reason: string): StartupMilestone {
  return { observed: false, reason };
}

export type StartupOutcome =
  | { readonly kind: "success" }
  | { readonly kind: "failure"; readonly reason: string }
  | { readonly kind: "timeout"; readonly reason: string }
  | { readonly kind: "cancelled"; readonly reason: string };

/**
 * One observed run. `phaseDurationsMs` and `operationCounts` come from the
 * child's own self-reported `timing:` lines (see `parseTimingLines`);
 * `wallToHandoffMs`, `wallToUsefulAgentMs`, `wallToFirstMcpSuccessMs`, and
 * `normalExitMs` come only from the parent's monotonic clock at the moment
 * it observed the configured marker or the process exit. The two sources are
 * never reconciled into one number: a child's self-reported phase duration
 * stays exactly as reported, even when it disagrees with how long the parent
 * actually waited.
 */
export interface StartupSample {
  readonly tree: string;
  readonly scenarioId: string;
  readonly runId: string;
  readonly phaseDurationsMs: Readonly<Record<string, number>>;
  readonly wallToHandoffMs: StartupMilestone;
  readonly wallToUsefulAgentMs?: StartupMilestone;
  readonly wallToFirstMcpSuccessMs?: StartupMilestone;
  readonly normalExitMs: StartupMilestone;
  readonly outcome: StartupOutcome;
  readonly operationCounts: Readonly<Record<string, number>>;
  readonly environment: Readonly<Record<string, string | number | boolean>>;
}

// ---------------------------------------------------------------------------
// Self-reported timing-line parsing (`timing: <phase> <detail>`)
// ---------------------------------------------------------------------------

/**
 * Parses the project's existing `timing: <phase> <detail>` convention
 * (`tests/runtime/live/launch-timing-support.ts`, `local/scripts/launch-timing-bench.sh`).
 * A plain `<number>ms` detail is a phase duration; the last line for a given
 * phase name wins (matches the live harness's `milliseconds()` helper), so a
 * phase is never summed against itself. A `<category> count=<n>` detail
 * (the `*-ops` lines) adds into a per phase+category operation count; counts
 * from different phases are kept under different keys and are never added
 * together. This function never produces a key that sums two different
 * phase names.
 */
export function parseTimingLines(
  text: string,
): { phaseDurationsMs: Record<string, number>; operationCounts: Record<string, number> } {
  const phaseDurationsMs: Record<string, number> = {};
  const operationCounts: Record<string, number> = {};
  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\r$/, "").trimEnd();
    const match = /^timing: (\S+) (.*)$/.exec(line);
    if (!match) continue;
    const phase = match[1] as string;
    const detail = match[2] as string;

    const durationMatch = /^([\d.]+)ms$/.exec(detail);
    if (durationMatch) {
      phaseDurationsMs[phase] = Number(durationMatch[1]);
      continue;
    }

    const opsMatch = /^(.+) count=(\d+)(?: total=[\d.]+ms)?$/.exec(detail);
    if (opsMatch) {
      const key = `${phase} ${opsMatch[1]}`;
      operationCounts[key] = (operationCounts[key] ?? 0) + Number(opsMatch[2]);
    }
  }
  return { phaseDurationsMs, operationCounts };
}

// ---------------------------------------------------------------------------
// Invocation -> handoff / exit observation (parent monotonic clock)
// ---------------------------------------------------------------------------

export interface StartupRunSpec {
  readonly command: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly scenarioId: string;
  readonly tree: string;
  readonly runId: string;
  readonly environment?: Readonly<Record<string, string | number | boolean>>;
  /** Matched against each line of combined stdout/stderr as it arrives. Default matches this project's `timing: launch-handoff minted` line. */
  readonly handoffPattern?: RegExp;
  /** Agent first-response marker. Kept separate from readiness: set only by a line this agent itself produced, never inferred from exit code. Omit when the scenario has no agent step. */
  readonly usefulAgentPattern?: RegExp;
  /** First successful MCP round trip marker, from a controlled MCP server/tool with an explicit successful exchange. Omit when the scenario has no MCP step. */
  readonly firstMcpSuccessPattern?: RegExp;
  readonly timeoutMs?: number;
}

const DEFAULT_HANDOFF_PATTERN = /^timing: launch-handoff minted$/;
const DEFAULT_TIMEOUT_MS = 5 * 60_000;
const DIAGNOSTIC_TAIL_CHARS = 2000;

function redactOutcome(outcome: StartupOutcome): StartupOutcome {
  if (outcome.kind === "success") return outcome;
  return { kind: outcome.kind, reason: redactSecrets(outcome.reason) };
}

function outcomeAndNormalExit(
  input: { timedOut: boolean; timeoutMs: number; signal: NodeJS.Signals | null; code: number | null; redactedTail: string },
): { outcome: StartupOutcome; normalExitMs: StartupMilestone } {
  const { timedOut, timeoutMs, signal, code, redactedTail } = input;
  if (timedOut) {
    return {
      outcome: { kind: "timeout", reason: `killed after ${timeoutMs}ms without exiting` },
      normalExitMs: milestoneAbsent("timed out"),
    };
  }
  if (signal !== null) {
    return {
      outcome: { kind: "failure", reason: `terminated by signal ${signal}` },
      normalExitMs: milestoneAbsent(`terminated by signal ${signal}`),
    };
  }
  if (code === 0) {
    return { outcome: { kind: "success" }, normalExitMs: milestoneAbsent("set by caller after measuring exit") };
  }
  const tail = lastNonEmptyLine(redactedTail);
  return {
    outcome: { kind: "failure", reason: `exit code ${code}${tail ? `: ${tail}` : ""}` },
    normalExitMs: milestoneAbsent(`nonzero exit code ${code}`),
  };
}

/**
 * Spawns one command and observes it to exit, using only the parent's own
 * monotonic clock (`performance.now()`) for every timestamp in the returned
 * sample. A nonzero exit, a signal, or a timeout still resolves with a
 * sample — this function never rejects and never discards a run — with
 * `outcome` naming why and every unreached milestone left absent with a
 * reason.
 */
export function observeStartupRun(spec: StartupRunSpec): Promise<StartupSample> {
  return new Promise((resolve) => {
    const handoffPattern = spec.handoffPattern ?? DEFAULT_HANDOFF_PATTERN;
    const timeoutMs = spec.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const startedAt = performance.now();

    let handoffMs: StartupMilestone | undefined;
    let usefulAgentMs: StartupMilestone | undefined;
    let mcpSuccessMs: StartupMilestone | undefined;
    let combinedOutput = "";
    let timedOut = false;
    let settled = false;

    const child = childProcess.spawn(spec.command, spec.args ?? [], {
      cwd: spec.cwd,
      env: spec.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    const onChunk = (chunk: Buffer | string) => {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      combinedOutput += text;
      for (const rawLine of text.split("\n")) {
        const line = rawLine.replace(/\r$/, "");
        if (handoffMs === undefined && handoffPattern.test(line)) handoffMs = milestoneObserved(performance.now() - startedAt);
        if (usefulAgentMs === undefined && spec.usefulAgentPattern?.test(line)) {
          usefulAgentMs = milestoneObserved(performance.now() - startedAt);
        }
        if (mcpSuccessMs === undefined && spec.firstMcpSuccessPattern?.test(line)) {
          mcpSuccessMs = milestoneObserved(performance.now() - startedAt);
        }
      }
    };
    child.stdout?.on("data", onChunk);
    child.stderr?.on("data", onChunk);

    const settle = (result: StartupSample) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const buildSample = (outcome: StartupOutcome, normalExitMs: StartupMilestone, elapsedMs: number): StartupSample => {
      const redactedOutput = redactSecrets(combinedOutput);
      const { phaseDurationsMs, operationCounts } = parseTimingLines(redactedOutput);
      const unreachedReason = `process did not reach it (${outcome.kind})`;
      return {
        tree: spec.tree,
        scenarioId: spec.scenarioId,
        runId: spec.runId,
        phaseDurationsMs: Object.freeze(phaseDurationsMs),
        wallToHandoffMs: handoffMs ?? milestoneAbsent(unreachedReason),
        ...(spec.usefulAgentPattern !== undefined
          ? { wallToUsefulAgentMs: usefulAgentMs ?? milestoneAbsent(unreachedReason) }
          : {}),
        ...(spec.firstMcpSuccessPattern !== undefined
          ? { wallToFirstMcpSuccessMs: mcpSuccessMs ?? milestoneAbsent(unreachedReason) }
          : {}),
        normalExitMs: outcome.kind === "success" ? milestoneObserved(elapsedMs) : normalExitMs,
        outcome: redactOutcome(outcome),
        operationCounts: Object.freeze(operationCounts),
        environment: Object.freeze(redactEnvironment(spec.environment ?? {})),
      };
    };

    child.on("close", (code, signal) => {
      const elapsedMs = performance.now() - startedAt;
      const redactedTail = redactSecrets(combinedOutput.slice(-DIAGNOSTIC_TAIL_CHARS));
      const { outcome, normalExitMs } = outcomeAndNormalExit({ timedOut, timeoutMs, signal, code, redactedTail });
      settle(buildSample(outcome, normalExitMs, elapsedMs));
    });

    child.on("error", (error) => {
      const outcome: StartupOutcome = { kind: "failure", reason: `spawn error: ${error.message}` };
      settle(buildSample(outcome, milestoneAbsent("process failed to start"), performance.now() - startedAt));
    });
  });
}

// ---------------------------------------------------------------------------
// Summarizer
// ---------------------------------------------------------------------------

export interface StartupMetricSummary {
  readonly count: number;
  readonly medianMs: number;
  /** Empirical nearest-rank p95 over `count` samples; exploratory below about 20 samples (see this plan's measurement-noise requirement). */
  readonly p95Ms: number;
  readonly minMs: number;
  readonly maxMs: number;
}

export interface StartupCohortSummary {
  readonly tree: string;
  readonly scenarioId: string;
  readonly totalRuns: number;
  readonly outcomeCounts: Readonly<Record<string, number>>;
  readonly failures: number;
  /** Keyed by milestone field name (for example `wallToHandoffMs`) or `phase:<name>` for a self-reported phase. Never a key that sums two different phases or milestones. */
  readonly metrics: Readonly<Record<string, StartupMetricSummary>>;
}

export interface StartupSummary {
  /** One entry per distinct (scenarioId, tree) pair. A baseline and a candidate tree for the same scenario are always separate cohorts, never merged into one metric. */
  readonly cohorts: readonly StartupCohortSummary[];
}

const MILESTONE_FIELDS = ["wallToHandoffMs", "wallToUsefulAgentMs", "wallToFirstMcpSuccessMs", "normalExitMs"] as const;

function summarizeValues(values: readonly number[]): StartupMetricSummary | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((left, right) => left - right);
  const mid = Math.floor(sorted.length / 2);
  const medianMs = sorted.length % 2 === 1 ? (sorted[mid] as number) : ((sorted[mid - 1] as number) + (sorted[mid] as number)) / 2;
  const p95Ms = sorted[Math.max(0, Math.ceil(0.95 * sorted.length) - 1)] as number;
  return { count: values.length, medianMs, p95Ms, minMs: sorted[0] as number, maxMs: sorted[sorted.length - 1] as number };
}

/**
 * Groups samples by (scenarioId, tree) and reports count, failures, median
 * and empirical nearest-rank p95 per metric, from only the samples that
 * actually observed that metric. Never merges two different trees' samples
 * for the same scenario into one metric, and never derives a metric by
 * summing two different named phases or milestones together.
 */
export function summarizeStartupSamples(samples: readonly StartupSample[]): StartupSummary {
  const cohortsByKey = new Map<string, { tree: string; scenarioId: string; samples: StartupSample[] }>();
  for (const sample of samples) {
    const key = `${sample.scenarioId}\u0000${sample.tree}`;
    const cohort = cohortsByKey.get(key) ?? { tree: sample.tree, scenarioId: sample.scenarioId, samples: [] };
    cohort.samples.push(sample);
    cohortsByKey.set(key, cohort);
  }

  const cohorts: StartupCohortSummary[] = [];
  for (const { tree, scenarioId, samples: cohortSamples } of cohortsByKey.values()) {
    const outcomeCounts: Record<string, number> = {};
    for (const sample of cohortSamples) outcomeCounts[sample.outcome.kind] = (outcomeCounts[sample.outcome.kind] ?? 0) + 1;
    const failures = cohortSamples.length - (outcomeCounts.success ?? 0);

    const metrics: Record<string, StartupMetricSummary> = {};
    for (const field of MILESTONE_FIELDS) {
      const values = cohortSamples
        .map((sample) => sample[field])
        .filter((milestone): milestone is StartupMilestone => milestone !== undefined)
        .filter((milestone): milestone is StartupMilestone & { observed: true } => milestone.observed)
        .map((milestone) => milestone.ms);
      const summary = summarizeValues(values);
      if (summary) metrics[field] = summary;
    }

    const phaseNames = new Set<string>();
    for (const sample of cohortSamples) for (const name of Object.keys(sample.phaseDurationsMs)) phaseNames.add(name);
    for (const name of phaseNames) {
      const values = cohortSamples.map((sample) => sample.phaseDurationsMs[name]).filter((value) => value !== undefined) as number[];
      const summary = summarizeValues(values);
      if (summary) metrics[`phase:${name}`] = summary;
    }

    cohorts.push(
      Object.freeze({
        tree,
        scenarioId,
        totalRuns: cohortSamples.length,
        outcomeCounts: Object.freeze(outcomeCounts),
        failures,
        metrics: Object.freeze(metrics),
      }),
    );
  }

  return Object.freeze({ cohorts });
}

// ---------------------------------------------------------------------------
// CLI (run on a Docker host; this task did not invoke it)
// ---------------------------------------------------------------------------

function printUsage(): void {
  process.stderr.write(
    [
      "usage:",
      "  benchmark-startup run --scenario-id <id> --tree <sha> --run-id <id> --out <file.jsonl>",
      "    [--handoff-pattern <regex-source>] [--useful-agent-pattern <regex-source>]",
      "    [--mcp-success-pattern <regex-source>] [--timeout-ms <n>] -- <command> [args...]",
      "  benchmark-startup summarize <file.jsonl> [<file.jsonl>...]",
      "",
    ].join("\n"),
  );
}

function requireFlag(flags: Map<string, string>, name: string): string {
  const value = flags.get(name);
  if (value === undefined) throw new Error(`missing required --${name}`);
  return value;
}

function parseRunArgs(
  args: readonly string[],
): { flags: Map<string, string>; command: string; commandArgs: string[] } {
  const separator = args.indexOf("--");
  if (separator === -1) throw new Error("run requires -- <command> [args...]");
  const flagArgs = args.slice(0, separator);
  const commandArgs = args.slice(separator + 1);
  if (commandArgs.length === 0) throw new Error("run requires a command after --");

  const flags = new Map<string, string>();
  for (let index = 0; index < flagArgs.length; index += 2) {
    const flag = flagArgs[index];
    const value = flagArgs[index + 1];
    if (!flag?.startsWith("--") || value === undefined) throw new Error(`malformed flag near ${JSON.stringify(flag)}`);
    flags.set(flag.slice(2), value);
  }
  return { flags, command: commandArgs[0] as string, commandArgs: commandArgs.slice(1) };
}

async function runCommand(args: readonly string[]): Promise<void> {
  const { flags, command, commandArgs } = parseRunArgs(args);
  const spec: StartupRunSpec = {
    command,
    args: commandArgs,
    scenarioId: requireFlag(flags, "scenario-id"),
    tree: requireFlag(flags, "tree"),
    runId: requireFlag(flags, "run-id"),
    ...(flags.has("handoff-pattern") ? { handoffPattern: new RegExp(flags.get("handoff-pattern") as string) } : {}),
    ...(flags.has("useful-agent-pattern")
      ? { usefulAgentPattern: new RegExp(flags.get("useful-agent-pattern") as string) }
      : {}),
    ...(flags.has("mcp-success-pattern")
      ? { firstMcpSuccessPattern: new RegExp(flags.get("mcp-success-pattern") as string) }
      : {}),
    ...(flags.has("timeout-ms") ? { timeoutMs: Number(flags.get("timeout-ms")) } : {}),
  };
  const out = requireFlag(flags, "out");
  const sample = await observeStartupRun(spec);
  fs.appendFileSync(out, `${JSON.stringify(sample)}\n`);
  process.stdout.write(`${JSON.stringify(sample, null, 2)}\n`);
}

function summarizeCommand(paths: readonly string[]): void {
  if (paths.length === 0) throw new Error("summarize requires at least one <file.jsonl>");
  const samples: StartupSample[] = [];
  for (const filePath of paths) {
    const text = fs.readFileSync(filePath, "utf8");
    for (const line of text.split("\n")) {
      if (line.trim().length === 0) continue;
      samples.push(JSON.parse(line) as StartupSample);
    }
  }
  process.stdout.write(`${JSON.stringify(summarizeStartupSamples(samples), null, 2)}\n`);
}

async function main(): Promise<void> {
  const [sub, ...rest] = process.argv.slice(2);
  if (sub === "run") {
    await runCommand(rest);
    return;
  }
  if (sub === "summarize") {
    summarizeCommand(rest);
    return;
  }
  printUsage();
  process.exitCode = sub === undefined ? 0 : 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`benchmark-startup: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
