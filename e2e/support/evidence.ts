import { test } from "vitest";

import {
  EVIDENCE_META_KEY,
  SCENARIO_META_KEY,
  validateScenarioMetadata,
  type ScenarioMetadata,
} from "./evidence-contract.ts";

export {
  validateEvidence,
  validateScenarioMetadata,
  type Evidence,
  type ScenarioMetadata,
} from "./evidence-contract.ts";

export function scenario(
  name: string,
  metadata: ScenarioMetadata,
  handler: () => void | Promise<void>,
  timeout = 30_000,
): void {
  validateScenarioMetadata(metadata);
  test(name, async (context) => {
    context.task.meta[EVIDENCE_META_KEY] = metadata.evidence;
    context.task.meta[SCENARIO_META_KEY] = metadata;
    await handler();
  }, timeout);
}
