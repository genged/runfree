import { corroboratedComposeServiceContainerFilters, REBIND_ATTEMPT_LABEL, REBIND_TRANSACTION_LABEL } from "./container-inventory.ts";
import type { ControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import type { DockerNetworkInspect, RuntimeIO } from "./types.ts";
import { observeExactProxy } from "./proxy-containment.ts";
import { RuntimeObservationError } from "./observation-failure.ts";

/** Inspect creation crash windows before any force-recreate, using the journal's marker. */
export function inspectRebindCreation(input: {
  plan: ActiveRuntimePlan;
  io: RuntimeIO;
  transaction: ControlPlaneRebindTransaction;
  assertAuthority(): void;
}): "create" | "recover" | { stoppedProxyId: string } {
  const { plan, io, transaction, assertAuthority } = input;
  const fail = (kind: "observation-unavailable" | "identity-contradiction", observation: string): never => {
    throw new RuntimeObservationError({ kind, subject: "proxy", expectedIdentity: transaction.transactionId,
      phase: transaction.phase, observation });
  };
  const capture = (args: string[]) => {
    assertAuthority();
    const result = io.capture("docker", args, { env: plan.execution.dockerClientEnv, timeout: 1000, maxBuffer: 1024 * 1024 });
    assertAuthority();
    if (result.status !== 0 || result.stderr.trim()) return fail("observation-unavailable", "proxy creation inventory is unavailable; no container was replaced");
    return result.stdout;
  };
  const ids = capture(["ps", "--all", "--quiet", "--no-trunc", ...corroboratedComposeServiceContainerFilters(plan.projectId, plan.composeProjectName, "proxy")])
    .trim().split(/\s+/u).filter(Boolean);
  if (ids.length > 1 || ids.some((id) => !/^[a-f0-9]{64}$/u.test(id))) fail("identity-contradiction", "proxy creation inventory is ambiguous; inspect exact containers before repair");
  const proxy = ids[0] ? observeExactProxy({ proxyId: ids[0], projectId: plan.projectId, composeProject: plan.composeProjectName,
    io, env: plan.execution.dockerClientEnv, assertAuthority }) : undefined;
  const markerMatches = proxy?.Config?.Labels?.[REBIND_TRANSACTION_LABEL] === transaction.transactionId
    && proxy.Config.Labels[REBIND_ATTEMPT_LABEL] === String(transaction.recovery?.candidateAttempt);
  const predecessorMatches = proxy?.Id === transaction.oldControlPlane.proxyContainerId
    && proxy.Image === transaction.oldControlPlane.proxyImageId;
  if (proxy && !markerMatches && !predecessorMatches) {
    fail("identity-contradiction", "unrecorded proxy has no exact creation marker or predecessor identity; automatic adoption and removal refused");
  }
  let networks: DockerNetworkInspect[];
  try { networks = JSON.parse(capture(["network", "inspect", transaction.oldControlPlane.networkIds.agentInternal,
    transaction.oldControlPlane.networkIds.proxyEgress])) as DockerNetworkInspect[]; }
  catch (error) { if (error instanceof RuntimeObservationError) throw error; return fail("observation-unavailable", "retained network inspection is malformed"); }
  if (!Array.isArray(networks) || networks.length !== 2) fail("observation-unavailable", "retained network inspection is incomplete");
  for (const [index, logical] of ["agent_internal", "proxy_egress"].entries()) {
    const network = networks[index];
    const expectedId = index === 0 ? transaction.oldControlPlane.networkIds.agentInternal : transaction.oldControlPlane.networkIds.proxyEgress;
    if (network?.Id !== expectedId || network.Name !== `${plan.composeProjectName}_${logical}`
      || network.Labels?.["com.docker.compose.project"] !== plan.composeProjectName
      || index === 0 && network.Internal !== true || network.EnableIPv6 === true) {
      fail("identity-contradiction", "retained network ownership or isolation changed; restore compatible topology before recovery");
    }
    if (index === 0) {
      for (const [id, endpoint] of Object.entries(network.Containers ?? {})) {
        if (endpoint.IPv4Address?.split("/")[0] === plan.network.proxyIp && id !== proxy?.Id) {
          fail("identity-contradiction", "another container owns the proxy endpoint; no replacement is authorized");
        }
      }
    }
  }
  if (markerMatches) {
    if (proxy?.Image !== transaction.candidateMaterialization.proxyImageId) fail("identity-contradiction", "creation marker names an unapproved proxy image");
    return proxy?.State?.Running === false ? { stoppedProxyId: proxy.Id as string } : "recover";
  }
  return "create";
}

/**
 * Whether a rebind participant's container is gone. Only a successful, clean
 * inventory proves absence; a failed, timed-out or killed call refuses so the
 * participant receipt is preserved.
 */
export function rebindParticipantIsAbsent(input: {
  containerId: string | undefined;
  io: Pick<RuntimeIO, "capture">;
  env?: NodeJS.ProcessEnv;
  assertAuthority(): void;
}): boolean {
  if (!input.containerId) return false;
  input.assertAuthority();
  const found = input.io.capture("docker", ["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${input.containerId}`],
    { env: input.env, timeout: 1000, maxBuffer: 8192 });
  input.assertAuthority();
  if (found.status !== 0 || found.stderr.trim()) throw new RuntimeObservationError({ kind: "observation-unavailable", subject: "session",
    expectedIdentity: input.containerId, phase: "sessions-revalidated", observation: "session departure inventory is unavailable; preserve its participant receipt" });
  return found.stdout.trim() === "";
}
