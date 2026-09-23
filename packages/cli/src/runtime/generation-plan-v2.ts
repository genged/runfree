import {
  createControlPlaneGenerationV2,
  createSessionAgentGenerationInputsV2,
  parseRuntimeGenerationTargetV2,
  type RuntimeGenerationTargetV2,
} from "./component-state-v2.ts";
import {
  runtimeTopologyGenerationV2,
  type RuntimeTopologyDigestInputV2,
} from "./topology-digest-v2.ts";

export type RuntimeGenerationPlanInputV2 = {
  projectId: string;
  composeProject: string;
  proxyImageInputDigest: string;
  selectedAgentImageInputDigest: string;
  admissionContractEpoch: number;
  topology: RuntimeTopologyDigestInputV2;
};

/**
 * Computes the desired schema-v2 generation target without materializing or
 * selecting any runtime state.
 */
export function createRuntimeGenerationTargetV2(
  input: RuntimeGenerationPlanInputV2,
): RuntimeGenerationTargetV2 {
  const topology = runtimeTopologyGenerationV2(input.topology);
  const target: RuntimeGenerationTargetV2 = {
    topology,
    controlPlane: createControlPlaneGenerationV2({
      projectId: input.projectId,
      composeProject: input.composeProject,
      proxyImageInputDigest: input.proxyImageInputDigest,
      controlPlaneTopologyDigest: topology.controlPlaneTopologyDigest,
      admissionContractEpoch: input.admissionContractEpoch,
    }),
    sessionAgent: createSessionAgentGenerationInputsV2({
      selectedAgentImageInputDigest: input.selectedAgentImageInputDigest,
      sessionTemplateDigest: topology.sessionTemplateDigest,
      admissionContractEpoch: input.admissionContractEpoch,
    }),
  };
  const parsed = parseRuntimeGenerationTargetV2(target);
  if (!parsed) throw new Error("computed runtime generation target is inconsistent");
  return parsed;
}
