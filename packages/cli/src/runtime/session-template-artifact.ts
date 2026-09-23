

import {
  composeInterpolationVariables,
  type TopologyDigestJson,
} from "./topology-digest.ts";
import {
  createRuntimeTopologyProjectionArtifactV2,
  runtimeTopologyProjectionArtifactDigestV2,
  type RuntimeTopologyProjectionArtifactV2,
} from "./topology-digest-v2.ts";
import {
  createSessionContainerTemplateFromArtifact,
  sessionContainerTopologyProjectionV2,
  type SessionContainerTemplate,
} from "./session-container-template.ts";
import type { RuntimePlan } from "./plan.ts";
import { strictStableJson, sha256Digest as sha256, exactKeySet as exactKeys, isRecord } from "../strict-primitives.ts";

export const SESSION_TEMPLATE_ARTIFACT_SCHEMA_VERSION = 1 as const;

export type SessionTemplateArtifactV1 = Readonly<{
  schemaVersion: typeof SESSION_TEMPLATE_ARTIFACT_SCHEMA_VERSION;
  projectId: string;
  composeProject: string;
  template: SessionContainerTemplate;
  topologyProjection: RuntimeTopologyProjectionArtifactV2;
}>;

function stableJson(value: unknown): string {
  return strictStableJson(value, "session-template artifact contains a non-finite number");
}




function runtimeTopologyInput(plan: RuntimePlan) {
  const interpolationValues = Object.fromEntries(
    composeInterpolationVariables(plan.renderedCompose).map((name) => [
      name,
      plan.execution.composeEnv[name],
    ]),
  );
  return {
    compose: plan.renderedCompose,
    interpolationValues,
    controlPlane: {
      structure: {} as TopologyDigestJson,
      runtimeSignatures: {},
    },
    sessionTemplate: {
      structure: sessionContainerTopologyProjectionV2(plan.sessionContainerTemplate),
      runtimeSignatures: {},
    },
  };
}

export function createSessionTemplateArtifactV1(plan: RuntimePlan): SessionTemplateArtifactV1 {
  const topologyProjection = createRuntimeTopologyProjectionArtifactV2(
    runtimeTopologyInput(plan),
    "session-template",
  );
  const digest = runtimeTopologyProjectionArtifactDigestV2(topologyProjection);
  if (digest !== plan.generationV2.sessionAgent.sessionTemplateDigest) {
    throw new Error("session-template artifact topology contradicts the planned generation");
  }
  return Object.freeze({
    schemaVersion: SESSION_TEMPLATE_ARTIFACT_SCHEMA_VERSION,
    projectId: plan.projectId,
    composeProject: plan.composeProjectName,
    template: plan.sessionContainerTemplate,
    topologyProjection,
  });
}

export function serializeSessionTemplateArtifactV1(artifact: SessionTemplateArtifactV1): string {
  return `${stableJson(artifact)}\n`;
}

export function sessionTemplateArtifactSha256(source: string | Buffer): string {
  return sha256(source);
}

export function parseSessionTemplateArtifactV1(
  source: string,
  expected: Readonly<{
    projectId: string;
    composeProject: string;
    sessionTemplateDigest: string;
    artifactSha256: string;
  }>,
): SessionTemplateArtifactV1 {
  if (sessionTemplateArtifactSha256(source) !== expected.artifactSha256) {
    throw new Error("session-template artifact hash does not match its materialization");
  }
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error("session-template artifact is malformed");
  }
  if (!isRecord(value)
    || !exactKeys(value, ["schemaVersion", "projectId", "composeProject", "template", "topologyProjection"])
    || value.schemaVersion !== SESSION_TEMPLATE_ARTIFACT_SCHEMA_VERSION
    || value.projectId !== expected.projectId
    || value.composeProject !== expected.composeProject
    || !isRecord(value.topologyProjection)
    || !exactKeys(value.topologyProjection, [
      "schemaVersion",
      "projection",
      "structure",
      "interpolationInputs",
      "runtimeSignatures",
    ])
    || value.topologyProjection.schemaVersion !== 2
    || value.topologyProjection.projection !== "session-template"
    || !Array.isArray(value.topologyProjection.interpolationInputs)
    || !isRecord(value.topologyProjection.runtimeSignatures)) {
    throw new Error("session-template artifact has an invalid contract");
  }
  const template = createSessionContainerTemplateFromArtifact(value.template, {
    projectId: expected.projectId,
    composeProject: expected.composeProject,
  });
  const topologyProjection = value.topologyProjection as RuntimeTopologyProjectionArtifactV2;
  if (stableJson(topologyProjection.structure)
    !== stableJson(sessionContainerTopologyProjectionV2(template))) {
    throw new Error("session-template artifact topology does not describe its template");
  }
  if (runtimeTopologyProjectionArtifactDigestV2(topologyProjection)
    !== expected.sessionTemplateDigest) {
    throw new Error("session-template artifact topology digest does not match its session-agent generation");
  }
  const parsed = Object.freeze({
    schemaVersion: SESSION_TEMPLATE_ARTIFACT_SCHEMA_VERSION,
    projectId: expected.projectId,
    composeProject: expected.composeProject,
    template,
    topologyProjection,
  });
  if (serializeSessionTemplateArtifactV1(parsed) !== source) {
    throw new Error("session-template artifact is not canonical");
  }
  return parsed;
}
