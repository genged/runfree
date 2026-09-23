import { projectHash } from "../project-identity.ts";
import { corroboratedComposeServiceContainerFilters } from "../runtime/container-inventory.ts";
import { readProxyControlReceipts, dockerClientEnvOptions } from "../runtime/docker.ts";
import { composeProjectName } from "../runtime/env.ts";
import { containExactOwnedProxy } from "../runtime/proxy-containment.ts";
import { tryAcquireProjectLifecycleLockWithRetry } from "../runtime/sessions.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  clearActiveControlSelection,
  clearConvergedPolicyReceipt,
  convergeEffectivePolicyGeneration,
  readActiveControlSelection,
  readActiveEffectiveControl,
  selectEffectivePolicyGeneration,
  type EffectiveConsumerReceipts,
} from "./effective.ts";
import { isControlsNotApprovedError } from "./refusals.ts";
import { usePreparedApprovedPolicyGeneration } from "./workflow.ts";

export type ControlActivationResult =
  | { kind: "deferred"; reason: string }
  | { controlGeneration: string; kind: "selected" }
  | { controlGeneration: string; kind: "converged" };

type ActivationConsumer = {
  probe(): Promise<EffectiveConsumerReceipts>;
  running: boolean;
  stop(): Promise<void>;
};

/**
 * The live proxy container ID, or `undefined` when none is running. Exported so
 * status can qualify a convergence receipt against live state rather than
 * against the generation alone.
 */
export function discoverLiveProxyId(context: RuntimeContext, io: RuntimeIO): string | undefined {
  const composeProject = composeProjectName(context.projectRoot);
  const discovery = io.capture("docker", [
    "ps",
    "-q",
    "--no-trunc",
    ...corroboratedComposeServiceContainerFilters(
      projectHash(context.projectRoot),
      composeProject,
      "proxy",
    ),
  ], { ...dockerClientEnvOptions(context), timeout: 1000, maxBuffer: 8192 });
  if (discovery.status !== 0 || discovery.stderr.trim()) {
    const detail = discovery.stderr.replace(/\s+/g, " ").trim();
    throw new Error(`could not identify the live proxy consumer${detail ? `: ${detail}` : ""}`);
  }
  const ids = discovery.stdout.trim().split(/\s+/).filter(Boolean);
  if (ids.length > 1 || ids.some((id) => !/^[a-f0-9]{64}$/.test(id))) {
    throw new Error("docker returned a malformed or ambiguous live proxy container set");
  }
  return ids[0];
}

function discoverConsumer(context: RuntimeContext, io: RuntimeIO): ActivationConsumer {
  const composeProject = composeProjectName(context.projectRoot);
  const proxyId = discoverLiveProxyId(context, io);
  return {
    running: proxyId !== undefined,
    probe: async () => proxyId ? readProxyControlReceipts(context, io, proxyId) ?? {} : {},
    stop: async () => {
      if (!proxyId) throw new Error("partial policy convergence has no exact proxy identity");
      const lock = await tryAcquireProjectLifecycleLockWithRetry(context);
      if (!lock) throw new Error("partial policy convergence requires fenced proxy containment; runtime safety is unconfirmed");
      try {
        lock.assertHeld();
        const currentProxyId = discoverLiveProxyId(context, io);
        lock.assertHeld();
        if (!currentProxyId) return;
        // A replacement or delayed convergence can finish while containment
        // waits for the lock. Bind the fresh receipt read to this exact ID.
        const freshIo: RuntimeIO = { ...io, capture(command, args, options) {
          lock.assertHeld();
          const result = io.capture(command, args, { ...options, timeout: 1000, maxBuffer: 1024 * 1024 });
          lock.assertHeld();
          return result;
        } };
        const receipts = readProxyControlReceipts(context, freshIo, currentProxyId);
        let selected: ReturnType<typeof readActiveEffectiveControl>;
        try { selected = readActiveEffectiveControl(context.project); }
        catch { /* Corrupt selection cannot prove restored convergence. */ }
        if (discoverLiveProxyId(context, io) !== currentProxyId) {
          throw new Error("proxy changed during fenced containment inspection; safety is unconfirmed; retry policy activation with fresh evidence");
        }
        lock.assertHeld();
        if (selected && receipts?.requestProxy?.controlGeneration === selected.controlGeneration
          && receipts.requestProxy.policyGeneration === selected.policyGeneration
          && receipts.firewall?.controlGeneration === selected.controlGeneration
          && receipts.firewall.policyGeneration === selected.policyGeneration && receipts.firewall.rulesetVerified === true) {
          throw new Error("policy consumers converged before containment; proxy preserved; retry policy activation to record convergence");
        }
        containExactOwnedProxy({ proxyId: currentProxyId, composeProject, projectId: projectHash(context.projectRoot),
          io, env: context.env, assertAuthority: () => lock.assertHeld() });
      } finally { lock.release(); }
    },
  };
}

export async function activateApprovedControlsAfterMutation(
  context: RuntimeContext,
  io: RuntimeIO,
  options: {
    consumer?: ActivationConsumer;
    pollIntervalMs?: number;
    recoverInvalidActive?: boolean;
    timeoutMs?: number;
  } = {},
): Promise<ControlActivationResult> {
  let previous: ReturnType<typeof readActiveControlSelection>;
  try {
    previous = readActiveControlSelection(context.project);
  } catch (error) {
    if (!options.recoverInvalidActive) throw error;
  }
  let generation: Awaited<ReturnType<typeof usePreparedApprovedPolicyGeneration>>;
  try {
    generation = await usePreparedApprovedPolicyGeneration(context, io);
  } catch (error) {
    // Both compile entrypoints raise the same typed refusal when approvals are
    // incomplete (pre-`up`): the desired mutation is already durable, so this
    // is "saved; applies when the runtime starts", never a failure.
    if (isControlsNotApprovedError(error)) {
      return { kind: "deferred", reason: error.message };
    }
    throw error;
  }

  let consumer: ActivationConsumer;
  try {
    consumer = options.consumer ?? discoverConsumer(context, io);
  } catch (error) {
    if (previous) selectEffectivePolicyGeneration(context.project, previous.controlGeneration);
    else clearActiveControlSelection(context.project);
    throw error;
  }
  if (!consumer.running) {
    if (previous?.controlGeneration !== generation.controlGeneration) clearConvergedPolicyReceipt(context.project);
    return { kind: "selected", controlGeneration: generation.controlGeneration };
  }

  const receipt = await convergeEffectivePolicyGeneration(context.project, {
    previous,
    probe: consumer.probe,
    stopRuntime: consumer.stop,
    ...(options.pollIntervalMs === undefined ? {} : { pollIntervalMs: options.pollIntervalMs }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });
  return { kind: "converged", controlGeneration: receipt.controlGeneration };
}
