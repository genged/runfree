import { RuntimeObservationError } from "./observation-failure.ts";
import type { RuntimeIO } from "./types.ts";

export const LIFECYCLE_OPERATION_BUDGET_MS = 90_000;

/** Bounds admitted subprocess work within one held startup/reload lock span. */
export function withLifecycleOperationBudget(io: RuntimeIO, remainingMs: () => number | undefined): RuntimeIO {
  const remaining = (): number | undefined => {
    const value = remainingMs();
    if (value !== undefined && value <= 0) throw new RuntimeObservationError({ kind: "observation-unavailable", subject: "fence",
      expectedIdentity: "project-lifecycle", phase: "startup-validation",
      observation: "lifecycle operation budget ended; session processes were preserved; retry with fresh runtime evidence" });
    return value === undefined ? undefined : Math.max(1, Math.floor(value));
  };
  return { ...io,
    capture(command, args, options = {}) {
      const budget = remaining();
      const result = io.capture(command, args, budget === undefined ? options : { ...options, timeout: Math.min(options.timeout ?? budget, budget) });
      remaining(); return result;
    },
    run(command, args, options = {}) {
      const budget = remaining();
      const result = io.run(command, args, budget === undefined ? options : { ...options, timeout: Math.min(options.timeout ?? budget, budget) });
      remaining(); return result;
    },
  };
}
