// Opt-in launch-latency instrumentation (design item L0).
//
// `RUNFREE_TIMINGS=1` emits phase durations and JSON timeline spans so before/after
// numbers for every latency optimization come from the same instrument, not
// from forensic reconstruction. Measurement only: when the variable is unset
// the recorder is inert and callers pay a function-call boundary, nothing else.
// Timing lines are diagnostics, never parsed by the runtime, and must not
// carry secrets or container output.

import { AsyncLocalStorage } from "node:async_hooks";

import { runfreeLog } from "../warnings.ts";

export type RuntimeTimings = Readonly<{
  enabled: boolean;
  time<T>(phase: string, fn: () => T): T;
  timeAsync<T>(phase: string, fn: () => Promise<T>): Promise<T>;
  /** Subprocess interval on the host process monotonic clock; no argv or output. */
  operation(category: string, startedAt: number, endedAt: number): void;
  /** Emits a non-duration observation line, e.g. a Docker operation count. */
  report(phase: string, detail: string): void;
}>;

export function runtimeTimingsEnabled(env: NodeJS.ProcessEnv | undefined): boolean {
  return env?.RUNFREE_TIMINGS === "1";
}

export function formatRuntimeTimingLine(phase: string, durationMs: number): string {
  return `timing: ${phase} ${durationMs.toFixed(1)}ms`;
}

const INERT_TIMINGS: RuntimeTimings = Object.freeze({
  enabled: false,
  time: <T>(_phase: string, fn: () => T): T => fn(),
  timeAsync: <T>(_phase: string, fn: () => Promise<T>): Promise<T> => fn(),
  report: () => {},
  operation: () => {},
});

// All recorders in this process share a monotonic clock and span IDs. Async
// context follows the operation that started it, even when another phase
// runs before it settles. Parent IDs describe nesting, not proof dependencies.
// Callers must use static phase names: these strings go straight to stderr.
type TimingScope = Readonly<{ id: number; phase: string }>;
const scope = new AsyncLocalStorage<TimingScope>();
let nextSpanId = 0;

export function createRuntimeTimings(
  env: NodeJS.ProcessEnv | undefined,
  log: (line: string) => void = runfreeLog,
): RuntimeTimings {
  if (!runtimeTimingsEnabled(env)) return INERT_TIMINGS;
  const begin = (phase: string) => ({ id: ++nextSpanId, phase, parentId: scope.getStore()?.id ?? null, startMs: performance.now() });
  const emit = (span: ReturnType<typeof begin>): void => {
    const endMs = performance.now();
    log(formatRuntimeTimingLine(span.phase, endMs - span.startMs));
    log(`timing: timeline ${JSON.stringify({ kind: "phase", pid: process.pid, ...span, endMs })}`);
  };
  return Object.freeze({
    enabled: true,
    time<T>(phase: string, fn: () => T): T {
      const span = begin(phase);
      try {
        return scope.run(span, fn);
      } finally {
        emit(span);
      }
    },
    async timeAsync<T>(phase: string, fn: () => Promise<T>): Promise<T> {
      const span = begin(phase);
      try {
        return await scope.run(span, fn);
      } finally {
        emit(span);
      }
    },
    operation(category: string, startMs: number, endMs: number): void {
      const parent = scope.getStore();
      log(`timing: timeline ${JSON.stringify({
        kind: "operation", pid: process.pid, id: ++nextSpanId,
        parentId: parent?.id ?? null, phase: parent?.phase ?? "unscoped",
        category, startMs, endMs,
      })}`);
    },
    report(phase: string, detail: string): void {
      log(`timing: ${phase} ${detail}`);
    },
  });
}
