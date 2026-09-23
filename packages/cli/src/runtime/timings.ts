// Opt-in launch-latency instrumentation (design item L0).
//
// `RUNFREE_TIMINGS=1` emits one stderr line per lifecycle phase so before/after
// numbers for every latency optimization come from the same instrument, not
// from forensic reconstruction. Measurement only: when the variable is unset
// the recorder is inert and callers pay a function-call boundary, nothing else.
// Timing lines are diagnostics, never parsed by the runtime, and must not
// carry secrets or container output.

import { runfreeLog } from "../warnings.ts";

export type RuntimeTimings = Readonly<{
  enabled: boolean;
  time<T>(phase: string, fn: () => T): T;
  timeAsync<T>(phase: string, fn: () => Promise<T>): Promise<T>;
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
});

export function createRuntimeTimings(
  env: NodeJS.ProcessEnv | undefined,
  log: (line: string) => void = runfreeLog,
): RuntimeTimings {
  if (!runtimeTimingsEnabled(env)) return INERT_TIMINGS;
  const emit = (phase: string, startedAt: number): void => {
    log(formatRuntimeTimingLine(phase, performance.now() - startedAt));
  };
  return Object.freeze({
    enabled: true,
    time<T>(phase: string, fn: () => T): T {
      const startedAt = performance.now();
      try {
        return fn();
      } finally {
        emit(phase, startedAt);
      }
    },
    async timeAsync<T>(phase: string, fn: () => Promise<T>): Promise<T> {
      const startedAt = performance.now();
      try {
        return await fn();
      } finally {
        emit(phase, startedAt);
      }
    },
    report(phase: string, detail: string): void {
      log(`timing: ${phase} ${detail}`);
    },
  });
}
