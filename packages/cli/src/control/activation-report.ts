// One renderer for the "did the running proxy pick this up?" line every policy
// mutation prints. Callers used to print `activation.kind` and the raw
// generation id, which answered the question in internal vocabulary.

import type { ControlActivationResult } from "./activation.ts";

export const EFFECTIVE_POLICY_SAVED_LINE = "effective policy: saved; applies when the runtime starts";

export function activationReportLine(activation: ControlActivationResult): string {
  switch (activation.kind) {
    case "converged":
      return `effective policy: live now (effective policy generation ${activation.controlGeneration})`;
    case "selected":
      return `${EFFECTIVE_POLICY_SAVED_LINE} (effective policy generation ${activation.controlGeneration})`;
    case "deferred":
      return EFFECTIVE_POLICY_SAVED_LINE;
  }
}
