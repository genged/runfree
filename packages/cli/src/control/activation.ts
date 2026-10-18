import type { SpawnSyncOptions } from "node:child_process";

import { RUNFREE_RUNTIME_COMPONENTS } from "../embedded-assets.generated.ts";
import { projectHash } from "../project-identity.ts";
import { remedy } from "../remedies.ts";
import { createRuntimeAdapters } from "../runtime/adapters.ts";
import { corroboratedComposeServiceContainerFilters } from "../runtime/container-inventory.ts";
import { prepareDependencyOverlayPlan } from "../runtime/dependency-overlays.ts";
import {
  readProxyControlReceipts,
  dockerClientEnvOptions,
  filterValues,
  parseRuntimeContainerInspectRows,
  runtimeContainerInspectFormat,
} from "../runtime/docker.ts";
import { createDockerClient } from "../runtime/docker-client.ts";
import { composeProjectName } from "../runtime/env.ts";
import { createRuntimePlan } from "../runtime/plan.ts";
import { containExactOwnedProxy } from "../runtime/proxy-containment.ts";
import { SESSION_HEARTBEAT_CADENCE_MS } from "../runtime/session-file-heartbeat.ts";
import { tryAcquireProjectLifecycleLockWithRetry } from "../runtime/sessions.ts";
import { planRuntimeUpgradeFromV2State, up, type RuntimeUpgradePlan } from "../runtime/startup.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  clearActiveControlSelection,
  clearConvergedPolicyReceipt,
  convergeEffectivePolicyGeneration,
  readActiveControlSelection,
  readActiveEffectiveControl,
  requireApprovedControls,
  selectEffectivePolicyGeneration,
  type EffectiveConsumerReceipts,
} from "./effective.ts";
import { isControlsNotApprovedError } from "./refusals.ts";
import { usePreparedApprovedPolicyGeneration } from "./workflow.ts";

export type ControlActivationResult =
  | { kind: "deferred"; reason: string }
  // Saved and approved, but not selected: the running proxy is from another
  // Runfree build and cannot be replaced now. Nothing reached the proxy.
  | { kind: "waiting"; reason: string }
  | { controlGeneration: string; kind: "selected" }
  | { controlGeneration: string; kind: "converged" };

type ActivationConsumer = {
  probe(): Promise<EffectiveConsumerReceipts>;
  /**
   * The running proxy container's `io.runfree.proxy-image-input-digest`
   * label; absent when the container carries none.
   */
  proxyImageInputDigest?: string;
  running: boolean;
  stop(): Promise<void>;
};

/**
 * Whether the running proxy is not this CLI's embedded proxy build. A proxy
 * with no identity label is another build: only an exact match is the same.
 */
function proxyFromAnotherBuild(consumer: ActivationConsumer): boolean {
  return consumer.running && consumer.proxyImageInputDigest !== RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest;
}

const REPLACE_THEN_APPLY = `replace the proxy with: ${remedy.up()}, then apply the change with: ${remedy.policyUseApproved()}`;

function proxyBuildMismatchDetail(consumer: ActivationConsumer): string {
  return consumer.proxyImageInputDigest
    ? `the running proxy is from another Runfree build (proxy image input ${consumer.proxyImageInputDigest}, this CLI ships ${RUNFREE_RUNTIME_COMPONENTS.proxyImageInputDigest})`
    : "the running proxy carries no proxy image input label, so it is treated as another Runfree build";
}

/** The upgrade planner's verdict on the running runtime, as `runfree status` computes it. */
function classifyProxyReplacement(context: RuntimeContext, io: RuntimeIO): RuntimeUpgradePlan {
  const desired = createRuntimePlan(
    { ...context, dependencyOverlayPlan: prepareDependencyOverlayPlan(context, io) },
    { dockerSubnets: [], persistNetwork: false },
  );
  return planRuntimeUpgradeFromV2State(desired, context, createRuntimeAdapters(context, io).docker);
}

/**
 * The running proxy's build identity: its container label, read with the same
 * inspection the upgrade classifier reads. The row must name this exact
 * container as this project's proxy, or the identity is not proved.
 */
function readProxyImageInputDigest(context: RuntimeContext, io: RuntimeIO, proxyId: string): string | undefined {
  const inspect = createDockerClient(io, dockerClientEnvOptions(context)).inspect(
    [proxyId],
    { type: "container", format: runtimeContainerInspectFormat() },
    { timeout: 1000, maxBuffer: 8192 },
  );
  if (inspect.status !== 0) {
    const detail = inspect.stderr.replace(/\s+/g, " ").trim();
    throw new Error(`could not inspect the live proxy build identity${detail ? `: ${detail}` : ""}`);
  }
  const rows = parseRuntimeContainerInspectRows(inspect.stdout);
  const row = rows[0];
  if (rows.length !== 1 || !row || row.id !== proxyId || row.service !== "proxy"
    || row.projectId !== projectHash(context.projectRoot) || row.composeProject !== composeProjectName(context.projectRoot)) {
    throw new Error("docker returned a malformed or mismatched live proxy identity");
  }
  return row.proxyImageInputDigest;
}

/**
 * The live proxy container ID, or `undefined` when none is running. Exported so
 * status can qualify a convergence receipt against live state rather than
 * against the generation alone.
 */
export function discoverLiveProxyId(context: RuntimeContext, io: RuntimeIO): string | undefined {
  const composeProject = composeProjectName(context.projectRoot);
  const discovery = createDockerClient(io, dockerClientEnvOptions(context)).listContainers({
    quiet: true,
    noTrunc: true,
    filters: filterValues(corroboratedComposeServiceContainerFilters(
      projectHash(context.projectRoot),
      composeProject,
      "proxy",
    )),
  }, { timeout: 1000, maxBuffer: 8192 });
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

/**
 * The IO for a receipt read under the lifecycle lock: each capture, sync or
 * async, is short and bounded, and needs the lock both before it starts and
 * after it settles.
 */
export function withFencedReceiptRead(io: RuntimeIO, assertHeld: () => void): RuntimeIO {
  const fresh = (options: SpawnSyncOptions | undefined): SpawnSyncOptions => ({ ...options, timeout: 1000, maxBuffer: 1024 * 1024 });
  const { captureAsync } = io;
  return {
    ...io,
    capture(command, args, options) {
      assertHeld();
      const result = io.capture(command, args, fresh(options));
      assertHeld();
      return result;
    },
    ...(captureAsync ? {
      async captureAsync(command: string, args: string[], options?: SpawnSyncOptions) {
        assertHeld();
        const result = await captureAsync.call(io, command, args, fresh(options));
        assertHeld();
        return result;
      },
    } : {}),
  };
}

function discoverConsumer(context: RuntimeContext, io: RuntimeIO): ActivationConsumer {
  const composeProject = composeProjectName(context.projectRoot);
  const proxyId = discoverLiveProxyId(context, io);
  const proxyImageInputDigest = proxyId ? readProxyImageInputDigest(context, io, proxyId) : undefined;
  return {
    running: proxyId !== undefined,
    ...(proxyImageInputDigest ? { proxyImageInputDigest } : {}),
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
        const freshIo = withFencedReceiptRead(io, () => lock.assertHeld());
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

type ActivationOptions = {
  /** Upgrade-planner verdict for a proxy from another build; default as `runfree status` plans it. */
  classifyProxyReplacement?: (context: RuntimeContext, io: RuntimeIO) => RuntimeUpgradePlan;
  consumer?: ActivationConsumer;
  pollIntervalMs?: number;
  /**
   * What to do with a compatible proxy from another build: replace it now
   * (the default), or report `waiting`. A launch passes "wait": it must not
   * nest a runtime start inside its own.
   */
  proxyFromAnotherBuild?: "replace" | "wait";
  recoverInvalidActive?: boolean;
  /**
   * The compatible proxy replacement; default `up` on the selected effective
   * policy generation, which publishes nothing. Returns its exit status.
   */
  replaceProxy?: (context: RuntimeContext, io: RuntimeIO) => Promise<number>;
  timeoutMs?: number;
};

/**
 * The same-build fence. A proxy from another build
 * may misread a policy this CLI publishes, so the policy must not reach it.
 * Runs before publication, because publication writes the active selection
 * that a running proxy polls. Returns `waiting` when the proxy cannot be
 * replaced now; throws when a replacement does not leave this build's proxy.
 */
async function fenceProxyFromAnotherBuild(
  context: RuntimeContext,
  io: RuntimeIO,
  options: ActivationOptions,
): Promise<ControlActivationResult | undefined> {
  const consumer = options.consumer ?? discoverConsumer(context, io);
  if (!proxyFromAnotherBuild(consumer)) return undefined;
  const mismatch = proxyBuildMismatchDetail(consumer);
  const plan = (options.classifyProxyReplacement ?? classifyProxyReplacement)(context, io);
  if (plan.action === "blocked-incompatible") {
    const incompatible = plan.reason === "admission-epoch" ? "admission epoch" : "control-plane topology";
    return {
      kind: "waiting",
      reason: `${mismatch}; active sessions use an incompatible ${incompatible}, so the proxy cannot be replaced while they run; `
        + `wait for the active sessions to drain (${remedy.sessions()} lists them), then apply it with: ${remedy.policyUseApproved()}; `
        + `or recreate the runtime now with: ${remedy.rebuild()}`,
    };
  }
  if (plan.action === "invalid") {
    throw new Error(`${mismatch}; it cannot be replaced: component evidence is invalid: ${plan.reason}; `
      + `the change is saved and was not applied; recreate the runtime with: ${remedy.rebuild()}`);
  }
  if (options.proxyFromAnotherBuild === "wait") {
    return { kind: "waiting", reason: `${mismatch}; ${REPLACE_THEN_APPLY}` };
  }
  const heartbeatSeconds = Math.round(SESSION_HEARTBEAT_CADENCE_MS / 1000);
  console.error(`warning: ${mismatch}; replacing it before the change applies`);
  console.error(`warning: running sessions lose network access for up to one heartbeat (${heartbeatSeconds} s) plus adoption while the proxy is replaced`);
  // The replacement keeps the selected generation: a plain start on an idle
  // runtime would publish the approved one before it replaced the proxy, so
  // the old build would read it, and a failed replacement would leave it
  // selected. Publication waits for the identity check below.
  const status = await (options.replaceProxy
    ?? ((ctx, rio) => up(ctx, rio, false, { keepSelectedPolicyGeneration: true })))(context, io);
  if (status !== 0) {
    throw new Error(`the proxy from another Runfree build was not replaced (status ${status}); the change is saved and was not applied; ${REPLACE_THEN_APPLY}`);
  }
  const replaced = options.consumer ?? discoverConsumer(context, io);
  if (proxyFromAnotherBuild(replaced)) {
    throw new Error(`the proxy replacement left a proxy from another Runfree build running; the change is saved and was not applied; recreate the runtime with: ${remedy.rebuild()}`);
  }
  return undefined;
}

export async function activateApprovedControlsAfterMutation(
  context: RuntimeContext,
  io: RuntimeIO,
  options: ActivationOptions = {},
): Promise<ControlActivationResult> {
  let previous: ReturnType<typeof readActiveControlSelection>;
  try {
    previous = readActiveControlSelection(context.project);
  } catch (error) {
    if (!options.recoverInvalidActive) throw error;
  }
  // Both compile entrypoints raise the same typed refusal when approvals are
  // incomplete (pre-`up`): the desired mutation is already durable, so this
  // is "saved; applies when the runtime starts", never a failure. Checked
  // first so an unapprovable change never inspects or replaces a proxy.
  try {
    requireApprovedControls(context.projectRoot, context.project);
  } catch (error) {
    if (isControlsNotApprovedError(error)) return { kind: "deferred", reason: error.message };
    throw error;
  }
  const fenced = await fenceProxyFromAnotherBuild(context, io, options);
  if (fenced) return fenced;

  let generation: Awaited<ReturnType<typeof usePreparedApprovedPolicyGeneration>>;
  try {
    generation = await usePreparedApprovedPolicyGeneration(context, io);
  } catch (error) {
    if (isControlsNotApprovedError(error)) {
      return { kind: "deferred", reason: error.message };
    }
    throw error;
  }

  const restorePrevious = (): void => {
    if (previous) selectEffectivePolicyGeneration(context.project, previous.controlGeneration);
    else clearActiveControlSelection(context.project);
  };
  let consumer: ActivationConsumer;
  try {
    consumer = options.consumer ?? discoverConsumer(context, io);
  } catch (error) {
    restorePrevious();
    throw error;
  }
  // The fence above holds no lock: a proxy from another build can start
  // between it and publication. Take the selection back rather than converge
  // a proxy that may misread it.
  if (proxyFromAnotherBuild(consumer)) {
    restorePrevious();
    throw new Error(`${proxyBuildMismatchDetail(consumer)}; it started during policy activation, so the previous effective policy generation is restored; the change is saved; retry the command`);
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
