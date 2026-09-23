export type Evidence =
  | Readonly<{ kind: "reproduced-user-workflow" }>
  | Readonly<{ kind: "modeled-external-step"; modeledSteps: readonly [string, ...string[]]; proofLimits: string }>
  | Readonly<{ kind: "constructed-recovery-state"; constructedState: string; unproved: string }>
  | Readonly<{ kind: "real-provider-compatibility"; provider: string }>;

export const EVIDENCE_META_KEY = "runfreeEvidence";
export const SCENARIO_META_KEY = "runfreeScenario";

export type ScenarioId = `LH-${number}` | "HARNESS";
export type ScenarioLayer = "P" | "Dp";
export type ScenarioCadence = "pull-request" | "docker-pre-merge";
export type ScenarioImplementationStatus = "Partial" | "Implemented" | "Implemented-failing";

export type ScenarioMetadata = Readonly<{
  scenarioIds: readonly [ScenarioId, ...ScenarioId[]];
  layer: ScenarioLayer;
  cadence: ScenarioCadence;
  implementationStatus: ScenarioImplementationStatus;
  evidence: Evidence;
  ownedStateAreas: readonly string[];
  requiredPrograms: readonly string[];
  cleanup: string;
}>;

declare module "vitest" {
  interface TaskMeta {
    runfreeEvidence?: Evidence;
    runfreeScenario?: ScenarioMetadata;
  }
}

function nonEmptyStrings(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0);
}

export function validateEvidence(value: unknown): Evidence {
  if (!value || typeof value !== "object" || !("kind" in value)) throw new Error("e2e test has no evidence label");
  const evidence = value as Partial<Evidence> & Record<string, unknown>;
  if (evidence.kind === "reproduced-user-workflow") return evidence as Evidence;
  if (evidence.kind === "modeled-external-step") {
    if (!Array.isArray(evidence.modeledSteps) || evidence.modeledSteps.length === 0 || !evidence.modeledSteps.every((step) => typeof step === "string" && step.length > 0)) {
      throw new Error("modeled-external-step evidence must name every modeled step");
    }
    if (typeof evidence.proofLimits !== "string" || evidence.proofLimits.length === 0) {
      throw new Error("modeled-external-step evidence must state its proof limits");
    }
    return evidence as Evidence;
  }
  if (evidence.kind === "constructed-recovery-state") {
    if (typeof evidence.constructedState !== "string" || evidence.constructedState.length === 0) {
      throw new Error("constructed-recovery-state evidence must name the constructed state");
    }
    if (typeof evidence.unproved !== "string" || evidence.unproved.length === 0) {
      throw new Error("constructed-recovery-state evidence must name what remains unproved");
    }
    return evidence as Evidence;
  }
  if (evidence.kind === "real-provider-compatibility") {
    if (typeof evidence.provider !== "string" || evidence.provider.length === 0) {
      throw new Error("real-provider-compatibility evidence must name the provider or runtime");
    }
    return evidence as Evidence;
  }
  throw new Error(`unknown e2e evidence label: ${String(evidence.kind)}`);
}

export function validateScenarioMetadata(value: unknown): ScenarioMetadata {
  if (!value || typeof value !== "object") throw new Error("e2e test has no scenario metadata");
  const metadata = value as Partial<ScenarioMetadata> & Record<string, unknown>;
  if (
    !Array.isArray(metadata.scenarioIds)
    || metadata.scenarioIds.length === 0
    || !metadata.scenarioIds.every((id) => id === "HARNESS" || /^LH-(?:0[1-9]|[12][0-9]|3[0-8])$/u.test(String(id)))
  ) {
    throw new Error("e2e scenario metadata must name one or more valid scenario IDs");
  }
  if (new Set(metadata.scenarioIds).size !== metadata.scenarioIds.length) {
    throw new Error("e2e scenario metadata must not repeat scenario IDs");
  }
  if (metadata.layer !== "P" && metadata.layer !== "Dp") {
    throw new Error("e2e scenario metadata must name physical layer P or Dp");
  }
  if (metadata.cadence !== "pull-request" && metadata.cadence !== "docker-pre-merge") {
    throw new Error("e2e scenario metadata must name its cadence");
  }
  if (!(["Partial", "Implemented", "Implemented-failing"] as const).includes(metadata.implementationStatus as ScenarioImplementationStatus)) {
    throw new Error("e2e scenario metadata must name its implementation status");
  }
  if (!nonEmptyStrings(metadata.ownedStateAreas)) {
    throw new Error("e2e scenario metadata must enumerate its selected owned-state areas");
  }
  if (!nonEmptyStrings(metadata.requiredPrograms)) {
    throw new Error("e2e scenario metadata must enumerate its required programs");
  }
  if (typeof metadata.cleanup !== "string" || metadata.cleanup.length === 0) {
    throw new Error("e2e scenario metadata must state its cleanup contract");
  }
  validateEvidence(metadata.evidence);
  return metadata as ScenarioMetadata;
}
