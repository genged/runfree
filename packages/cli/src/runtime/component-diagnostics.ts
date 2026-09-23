import {
  readEffectiveControlPlaneV2,
  readRetainedDesiredSessionAgentV2,
  type RuntimeGenerationTargetV2,
} from "./component-state-v2.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { listSessionContainerRecordsV2 } from "./session-containers.ts";

function comparison(desired: string | number, effective: string | number | undefined, changed: string): string {
  if (effective === undefined) return "unselected";
  return effective === desired ? "unchanged" : changed;
}

function actionLabel(action: string): string {
  if (action === "component-select") return "select session-agent materialization";
  if (action === "blocked-incompatible") return "wait for incompatible sessions to drain";
  return action.replaceAll("-", " ");
}

export function runtimeComponentDiagnosticLines(input: {
  action: string;
  desired: RuntimeGenerationTargetV2;
  stateDir: string;
}): string[] {
  const effective = readEffectiveControlPlaneV2(input.stateDir);
  const desiredSession = readRetainedDesiredSessionAgentV2(input.stateDir);
  const desiredControl = input.desired.controlPlane;
  const effectiveControl = effective?.manifest.generation;
  const desiredAgent = input.desired.sessionAgent;
  const selectedAgent = desiredSession?.manifest.generation;
  return [
    "effective control plane",
    `  control plane generation: ${effectiveControl?.controlPlaneGenerationDigest ?? "unselected"}`,
    `  proxy image input: ${effectiveControl?.proxyImageInputDigest ?? "unselected"}`,
    `  topology: ${effectiveControl?.controlPlaneTopologyDigest ?? "unselected"}`,
    `  admission epoch: ${effectiveControl?.admissionContractEpoch ?? "unselected"}`,
    "desired control plane",
    `  control plane generation: ${desiredControl.controlPlaneGenerationDigest}`,
    `  proxy image input: ${desiredControl.proxyImageInputDigest}  ${comparison(
      desiredControl.proxyImageInputDigest,
      effectiveControl?.proxyImageInputDigest,
      "restart required",
    )}`,
    `  topology: ${desiredControl.controlPlaneTopologyDigest}  ${comparison(
      desiredControl.controlPlaneTopologyDigest,
      effectiveControl?.controlPlaneTopologyDigest,
      "drain required",
    )}`,
    `  admission epoch: ${desiredControl.admissionContractEpoch}  ${comparison(
      desiredControl.admissionContractEpoch,
      effectiveControl?.admissionContractEpoch,
      "drain required",
    )}`,
    "desired session agent",
    `  selected session agent generation: ${selectedAgent?.sessionAgentGenerationDigest ?? "unselected"}`,
    `  target session agent generation:   ${desiredAgent.sessionAgentGenerationDigest}`,
    `  selected image id: ${desiredSession?.manifest.selectedAgentImageId ?? "unselected"}`,
    `  template artifact: ${desiredSession?.selectable === true ? "selectable" : desiredSession ? "retention-only" : "unselected"}`,
    `  target status: ${comparison(
      desiredAgent.sessionAgentGenerationDigest,
      selectedAgent?.sessionAgentGenerationDigest,
      "selection required",
    )}`,
    `upgrade action: ${actionLabel(input.action)}`,
  ];
}

export function runtimeLifecycleStateDiagnosticLines(stateDir: string): string[] {
  const effective = readEffectiveControlPlaneV2(stateDir);
  const desired = readRetainedDesiredSessionAgentV2(stateDir);
  const project = effective?.selection ?? desired?.selection;
  const records = project
    ? listSessionContainerRecordsV2(stateDir, {
        projectId: project.projectId,
        composeProject: project.composeProject,
      })
    : [];
  const rebind = project
    ? readControlPlaneRebindTransaction(stateDir, {
        projectId: project.projectId,
        composeProject: project.composeProject,
      })
    : undefined;
  const groups = new Map<string, number>();
  for (const record of records) {
    const key = `${record.sessionAgentMaterializationDigest}\0${record.selectedAgentImageId}`;
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  const retainedImages = [...new Set(records.map((record) => record.selectedAgentImageId))].sort();
  const nextAction = rebind
    ? "recover the durable control-plane rebind transaction"
    : desired?.selectable === false && records.length > 0
      ? "wait for retention-only sessions to drain before new launch"
      : effective ? "use the selected v2 runtime" : "start the v2 runtime";
  return [
    "runtime lifecycle state",
    "  launch behavior: per-session schema v2",
    `  effective control plane: ${effective?.selection.controlPlaneGenerationDigest ?? "unselected"}`,
    `  desired session agent: ${desired?.selection.sessionAgentGenerationDigest ?? "unselected"}`,
    `  desired materialization: ${desired?.selection.sessionAgentMaterializationDigest ?? "unselected"}`,
    `  desired template: ${desired?.selectable === true ? "selectable" : desired ? "retention-only" : "unselected"}`,
    `  admission epoch: ${effective?.selection.admissionContractEpoch ?? "unselected"}`,
    `  active lifecycle records: ${records.length}`,
    ...[...groups.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([key, count]) => {
      const [materialization, imageId] = key.split("\0");
      return `    ${materialization}  ${imageId}  sessions=${count}`;
    }),
    `  retained session image ids: ${retainedImages.join(", ") || "none"}`,
    `  control-plane rebind: ${rebind?.phase ?? "none"}`,
    `  next safe action: ${nextAction}`,
  ];
}
