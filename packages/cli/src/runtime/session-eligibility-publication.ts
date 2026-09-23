import type * as childProcess from "node:child_process";

import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
  type SessionAdmissionEligibility,
  type SessionAdmissionEligibleAgent,
} from "@runfree/runtime-contracts/session-admission";

import { sha256Digest } from "../strict-primitives.ts";
import {
  readPublishedSessionEligibilityV2,
  readRetainedDesiredSessionAgentV2,
  recordPublishedSessionEligibilityV2,
  validDockerStartedAt,
  type ControlPlaneEffectiveSelectionV2,
  type ControlPlaneMaterializationManifestV2,
} from "./component-state-v2.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import { compileAllowedSessionAgentMaterializationsV2 } from "./session-materialization-eligibility.ts";
import type { SessionContainerRecordV2 } from "./session-containers.ts";
import {
  eligibilityPublishCommand,
  executeSessionFileCommand,
  type SessionAdmissionDockerExecutor,
} from "./session-file-publisher.ts";

// One `docker container inspect` of one container; the readiness wait bounds
// the same read at 8 KiB.
const PROXY_INSPECT_MAX_BYTES = 64 * 1024;

/**
 * The exact running incarnation of one proxy container. Read from the same
 * `docker container inspect` shape the firewall readiness wait already uses,
 * and pinned to the expected id and a running state so a stale or foreign
 * answer cannot become a publication receipt.
 */
export function observeProxyStartedAt(
  io: SessionAdmissionDockerExecutor,
  proxyId: string,
  dockerOptions: childProcess.SpawnSyncOptions = {},
): string {
  const inspected = io.capture("docker", ["container", "inspect", proxyId], {
    ...dockerOptions,
    maxBuffer: PROXY_INSPECT_MAX_BYTES,
  });
  let startedAt: unknown;
  try {
    const value: unknown = JSON.parse(inspected.stdout);
    if (inspected.status === 0 && Array.isArray(value) && value.length === 1) {
      const container = value[0] as { Id?: unknown; State?: { Running?: unknown; StartedAt?: unknown } };
      if (container.Id === proxyId && container.State?.Running === true) startedAt = container.State.StartedAt;
    }
  } catch {
    // Falls through to the refusal below: an unparseable answer is no answer.
  }
  if (!validDockerStartedAt(startedAt)) {
    throw new RuntimeObservationError({
      kind: "observation-unavailable",
      subject: "proxy",
      expectedIdentity: proxyId,
      phase: "publish-eligibility",
      observation: "the running proxy start time is unavailable",
    });
  }
  return startedAt;
}

export type SessionEligibilityPublicationInput = Readonly<{
  io: SessionAdmissionDockerExecutor;
  proxyId: string;
  stateDir: string;
  effective: Readonly<{
    selection: ControlPlaneEffectiveSelectionV2;
    manifest: ControlPlaneMaterializationManifestV2;
  }>;
  // Docker's `State.StartedAt` for `proxyId`, from `observeProxyStartedAt`.
  // Part of the publication identity, because an in-place restart keeps the
  // container id but takes `eligibility.json` with it.
  proxyStartedAt: string;
  desired: NonNullable<ReturnType<typeof readRetainedDesiredSessionAgentV2>>;
  records: readonly SessionContainerRecordV2[];
  // Set by a caller that already knows the proxy's session-file directory was
  // recreated (the same-container restart path), so no record may suppress the
  // write. Belt and braces beside `proxyStartedAt`.
  ignorePublicationRecord?: boolean;
  dockerOptions?: childProcess.SpawnSyncOptions;
}>;

export type SessionEligibilityPublication = Readonly<{
  published: boolean;
  eligibility?: SessionAdmissionEligibility;
}>;

function eligibleSessionAgents(
  input: SessionEligibilityPublicationInput,
): readonly SessionAdmissionEligibleAgent[] {
  if (!input.desired.selectable) {
    throw new Error(
      "session eligibility requires the retained current agent template; prepare it with a compatible CLI and retry",
    );
  }
  const { selection } = input.effective;
  // The same allowed set the admission snapshot compiles today: the desired
  // agent materialization widened by every materialization a live lifecycle
  // record still names, so a rolling agent upgrade leaves older sessions
  // admissible until they end.
  const allowed = compileAllowedSessionAgentMaterializationsV2({
    stateDir: input.stateDir,
    expectedProject: { projectId: selection.projectId, composeProject: selection.composeProject },
    effectiveControlPlane: selection,
    records: input.records,
    candidate: input.desired.manifest,
  });
  return [...new Map(allowed.map((materialization) => {
    const agent = {
      sessionAgentGenerationDigest: materialization.generation.sessionAgentGenerationDigest,
      selectedAgentImageId: materialization.selectedAgentImageId,
    };
    return [
      [agent.sessionAgentGenerationDigest, agent.selectedAgentImageId].join("\0"),
      agent,
    ] as const;
  })).values()];
}

/**
 * Publishes the project's session eligibility into the proxy, idempotently.
 *
 * Invariant 9: eligibility is a root-owned proxy file the host publishes, and
 * a proxy holding no eligibility serves nothing. The ordering is
 * widen-before-new-files — this runs before any session file that depends on
 * the widened set — so it is safe to call at every point that could have
 * changed the set, and cheap to call at the points that did not: the exact
 * bytes last published into this exact proxy container are recorded in state,
 * and identical bytes cost no `docker exec` at all.
 */
export function ensureSessionEligibilityPublished(
  input: SessionEligibilityPublicationInput,
): SessionEligibilityPublication {
  const { selection } = input.effective;
  // The eligibility names the selection's control plane, so publishing it into
  // any other container would hand one project's admission to a proxy the
  // selection does not describe.
  if (input.proxyId !== selection.proxyContainerId) {
    throw new Error("session eligibility target is not the proxy the selected control plane names");
  }
  if (!validDockerStartedAt(input.proxyStartedAt)) {
    throw new Error("session eligibility publication requires the running proxy start time");
  }
  const eligibility = createSessionAdmissionEligibility({
    projectId: selection.projectId,
    controlPlaneGenerationDigest: selection.controlPlaneGenerationDigest,
    admissionContractEpoch: selection.admissionContractEpoch,
    agentInternalNetworkId: selection.networkIds.agentInternal,
    allowedSessionAgents: eligibleSessionAgents(input),
  });
  const eligibilitySha256 = sha256Digest(serializeSessionAdmissionEligibility(eligibility));
  const published = input.ignorePublicationRecord
    ? undefined
    : readPublishedSessionEligibilityV2(input.stateDir);
  if (published
    && published.projectId === selection.projectId
    && published.composeProject === selection.composeProject
    // Both halves of the incarnation: a replaced proxy has a different id, and
    // a restarted one keeps the id but recreates the session-file directory
    // empty, so only the start time tells those two apart.
    && published.proxyContainerId === input.proxyId
    && published.proxyStartedAt === input.proxyStartedAt
    && published.eligibilitySha256 === eligibilitySha256) {
    return { published: false, eligibility };
  }
  executeSessionFileCommand(
    input.io,
    eligibilityPublishCommand(input.proxyId, eligibility),
    input.dockerOptions ?? {},
  );
  recordPublishedSessionEligibilityV2(input.stateDir, {
    schemaVersion: 2,
    projectId: selection.projectId,
    composeProject: selection.composeProject,
    proxyContainerId: input.proxyId,
    proxyStartedAt: input.proxyStartedAt,
    eligibilitySha256,
  });
  return { published: true, eligibility };
}
