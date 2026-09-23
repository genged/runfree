import type {
  ControlPlaneEffectiveSelectionV2,
  ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import type { RuntimeContainer, RuntimeValidationComponents } from "./types.ts";

export type RuntimeRequiredService = "proxy";

const RUNTIME_SERVICES = ["agent", "proxy", "mcp_callback"] as const;
// The per-session runtime's only Compose service is the proxy. `agent` and
// `mcp_callback` remain recognized names so a leftover retired container is
// enumerated and refused as contradictory rather than silently ignored.
const RUNTIME_REQUIRED_SERVICES: readonly RuntimeRequiredService[] = ["proxy"];

type RuntimeCompositionIssue =
  | { kind: "duplicate"; services: readonly RuntimeContainer["service"][] }
  | { kind: "missing"; services: readonly RuntimeRequiredService[] };

// Absence and ambiguity are different failures and deserve different remedies.
//
// A duplicated service is ambiguous evidence: two containers claim to be the
// one agent, and nothing may pick between them, so the only safe answer is to
// refuse and let an operator look. A missing service is not ambiguous — it is
// absence, which the zero-container path already answers by creating the
// runtime. Conflating them made partial loss (say, an agent removed while the
// proxy survives) refuse forever, while total loss recovered.
//
// Duplicates are reported first: a state that is both duplicated and missing is
// still ambiguous, and ambiguity must win.
function runtimeCompositionIssue(containers: readonly RuntimeContainer[]): RuntimeCompositionIssue | undefined {
  const count = (service: RuntimeContainer["service"]): number =>
    containers.filter((container) => container.service === service).length;
  const duplicated = RUNTIME_SERVICES.filter((service) => count(service) > 1);
  if (duplicated.length > 0) return { kind: "duplicate", services: duplicated };
  const missing = RUNTIME_REQUIRED_SERVICES.filter((service) => count(service) === 0);
  if (missing.length > 0) return { kind: "missing", services: missing };
  return undefined;
}

function serviceNoun(services: readonly string[]): string {
  const label = services.length === 1 ? services[0] : `${services.slice(0, -1).join(", ")} and ${services[services.length - 1]}`;
  return `${label} container${services.length === 1 ? "" : "s"}`;
}

function compositionIssueMessage(issue: RuntimeCompositionIssue): string {
  return issue.kind === "duplicate"
    ? `runtime component evidence is duplicated for the ${serviceNoun(issue.services)}`
    : `runtime component evidence is missing the ${serviceNoun(issue.services)}`;
}

const DIGEST = /^sha256:[a-f0-9]{64}$/;

type EvidenceMatch = "effective" | "desired" | "both" | "legacy" | "invalid";

function serviceEvidenceMatch(
  container: RuntimeContainer,
  desired: RuntimeValidationComponents,
  effective: RuntimeValidationComponents,
): EvidenceMatch {
  const service = container.service;
  if (service !== "agent" && service !== "proxy" && service !== "mcp_callback") return "invalid";
  const hasComponentEvidence = container.digestSchemaVersion !== undefined
    || container.agentImageInputDigest !== undefined
    || container.proxyImageInputDigest !== undefined
    || container.topologyDigest !== undefined;
  if (!hasComponentEvidence) return "legacy";
  if (container.digestSchemaVersion !== "1" || !container.topologyDigest || !DIGEST.test(container.topologyDigest)) {
    return "invalid";
  }
  const agentService = service === "agent";
  if (agentService) {
    if (!container.agentImageInputDigest || !DIGEST.test(container.agentImageInputDigest) || container.proxyImageInputDigest) {
      return "invalid";
    }
  } else if (!container.proxyImageInputDigest || !DIGEST.test(container.proxyImageInputDigest) || container.agentImageInputDigest) {
    return "invalid";
  }
  const imageDigest = agentService ? container.agentImageInputDigest : container.proxyImageInputDigest;
  const desiredImage = agentService ? desired.selectedAgentImageInputDigest : desired.proxyImageInputDigest;
  const effectiveImage = agentService ? effective.selectedAgentImageInputDigest : effective.proxyImageInputDigest;
  const matchesDesired = imageDigest === desiredImage && container.topologyDigest === desired.topologyDigest;
  const matchesEffective = imageDigest === effectiveImage && container.topologyDigest === effective.topologyDigest;
  if (matchesDesired && matchesEffective) return "both";
  if (matchesDesired) return "desired";
  if (matchesEffective) return "effective";
  return "invalid";
}

// The two rejections a whole runtime applies to its containers, applied to the
// survivors of a partial one: labels matching neither generation, and labels
// split across both. `legacy` is deliberately neither — unlabelled containers
// predate the digest schema and keep their own one-time recreate path.
/**
 * Why a live runtime cannot be attested, or `undefined` when it can.
 *
 * This is a validation gate, not a lifecycle planner: every kind refuses. The
 * kinds differ only in what an operator should do next, which is why the
 * missing/duplicate split is reported rather than flattened into one string.
 */
export type RuntimeComponentEvidenceIssue = {
  kind: "missing" | "duplicate" | "contradictory";
  message: string;
};

export function effectiveControlPlaneComponentEvidenceIssue(
  containers: readonly RuntimeContainer[],
  effective: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }>,
  identity: { composeProject: string; projectId: string },
): RuntimeComponentEvidenceIssue | undefined {
  const runtimeContainers = containers.filter((container) =>
    container.service === "agent" || container.service === "proxy" || container.service === "mcp_callback"
  );
  const composition = runtimeCompositionIssue(runtimeContainers);
  if (composition?.kind === "duplicate") {
    return { kind: "duplicate", message: compositionIssueMessage(composition) };
  }
  if (runtimeContainers.some((container) => container.service === "agent")) {
    return {
      kind: "contradictory",
      message: "runtime contains a leftover legacy Compose agent outside the schema-v2 control plane",
    };
  }
  if (runtimeContainers.some((container) => container.service === "mcp_callback")) {
    return {
      kind: "contradictory",
      message: "runtime contains a leftover retired mcp_callback relay outside the schema-v2 control plane",
    };
  }
  if (composition) return { kind: "missing", message: compositionIssueMessage(composition) };

  const { selection, manifest } = effective;
  if (selection.projectId !== identity.projectId
    || selection.composeProject !== identity.composeProject
    || manifest.projectId !== identity.projectId
    || manifest.composeProject !== identity.composeProject
    || selection.controlPlaneGenerationDigest !== manifest.generation.controlPlaneGenerationDigest
    || selection.controlPlaneMaterializationDigest !== manifest.controlPlaneMaterializationDigest
    || selection.proxyImageId !== manifest.proxyImageId) {
    return { kind: "contradictory", message: "effective control-plane state is internally contradictory" };
  }

  const proxy = runtimeContainers.find((container) => container.service === "proxy");
  if (!proxy
    || proxy.id !== selection.proxyContainerId
    || proxy.running !== true) {
    return {
      kind: "contradictory",
      message: "runtime container identity contradicts the effective control-plane selection",
    };
  }
  if (!runtimeContainers.every((container) => container.imageRef === manifest.proxyImageRef)) {
    return { kind: "contradictory", message: "runtime container image references contradict the effective control plane" };
  }
  if (!runtimeContainers.every((container) =>
    container.projectId === identity.projectId && container.composeProject === identity.composeProject
  )) {
    return { kind: "contradictory", message: "runtime container project identity contradicts the effective control plane" };
  }
  return undefined;
}

/**
 * Selects the component-evidence check for pre-token-sync validation.
 *
 * A same-generation warm selection pins the live proxy to the durable
 * selection's exact container and image identity — that pinning IS the warm
 * path's authority. A pending control-plane rebind suspends that pinning:
 * the candidate proxy is deliberately a NEW container while the durable
 * selection still names the old one (it flips only at the journal's
 * control-selected phase), so pinning would make every mid-rebind validation
 * refuse its own candidate — a same-generation rebind (stopped proxy,
 * unchanged sources) could then never complete. Candidate container identity
 * is not unpinned, it moves: the rebind coordinator binds the exact candidate
 * container, image, and networks through its own per-phase proof.
 */
export function tokenSyncComponentEvidenceIssue(input: {
  containers: readonly RuntimeContainer[];
  effectiveControlPlane: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }> | undefined;
  pendingControlPlaneRebind: boolean;
  desiredControlPlaneGenerationDigest: string;
  components: RuntimeValidationComponents;
  images: { agent: string; proxy: string };
  identity: { composeProject: string; projectId: string };
}): RuntimeComponentEvidenceIssue | undefined {
  return input.effectiveControlPlane
      && !input.pendingControlPlaneRebind
      && input.effectiveControlPlane.manifest.generation.controlPlaneGenerationDigest
        === input.desiredControlPlaneGenerationDigest
    ? effectiveControlPlaneComponentEvidenceIssue(input.containers, input.effectiveControlPlane, input.identity)
    : runtimeComponentEvidenceIssue(input.containers, input.components, input.images, input.identity);
}

export function runtimeComponentEvidenceIssue(
  containers: readonly RuntimeContainer[],
  expected: RuntimeValidationComponents,
  images?: { agent: string; proxy: string },
  identity?: { composeProject: string; projectId: string },
): RuntimeComponentEvidenceIssue | undefined {
  const runtimeContainers = containers.filter((container) =>
    container.service === "agent" || container.service === "proxy" || container.service === "mcp_callback"
  );
  const composition = runtimeCompositionIssue(runtimeContainers);
  if (composition?.kind === "duplicate") {
    return { kind: "duplicate", message: compositionIssueMessage(composition) };
  }
  if (runtimeContainers.some((container) => container.service === "agent")) {
    return {
      kind: "contradictory",
      message: "runtime contains a leftover legacy Compose agent outside the schema-v2 control plane",
    };
  }
  if (runtimeContainers.some((container) => container.service === "mcp_callback")) {
    return {
      kind: "contradictory",
      message: "runtime contains a leftover retired mcp_callback relay outside the schema-v2 control plane",
    };
  }
  // Contradiction outranks absence for the same reason it does in the planner,
  // and because the remedy this issue names has to be the one that works:
  // `runfree up` repairs a missing container but refuses a contradictory one.
  if (!runtimeContainers.every((container) => serviceEvidenceMatch(container, expected, expected) === "both")) {
    return { kind: "contradictory", message: "runtime component evidence contradicts the active control plane generation" };
  }
  if (images && !runtimeContainers.every((container) => container.imageRef === images.proxy)) {
    return { kind: "contradictory", message: "runtime container image references contradict the active control plane generation" };
  }
  if (identity && !runtimeContainers.every((container) =>
    container.projectId === identity.projectId && container.composeProject === identity.composeProject
  )) {
    return { kind: "contradictory", message: "runtime container project identity contradicts the active control plane generation" };
  }
  // Reported last, so a survivor that contradicts the generation by digest,
  // image reference, or project identity is named as the contradiction it is
  // rather than as the absence beside it. Only the remedy differs, but a
  // remedy that does not work is worse than none.
  if (composition) return { kind: "missing", message: compositionIssueMessage(composition) };
  return undefined;
}
