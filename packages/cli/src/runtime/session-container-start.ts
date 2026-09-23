import * as childProcess from "node:child_process";

import {
  assertSessionContainerAttachCommand,
  assertSessionContainerStartAttachCommand,
  executeSessionDockerCommand,
  type SessionDockerCommand,
} from "./session-container-docker.ts";
import {
  assertAttachedSessionContainerControlPlaneRebindV2,
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

declare const sessionContainerForegroundAttachReceiptBrand: unique symbol;
declare const sessionContainerForegroundHandleBrand: unique symbol;

export type SessionContainerForegroundAttachReceipt = Readonly<{
  readonly [sessionContainerForegroundAttachReceiptBrand]: true;
  containerId: string;
  sessionIncarnation: string;
  pid: number;
}>;

export type SessionContainerForegroundCompletion = Readonly<
  | { kind: "exit"; code: number | null; signal: NodeJS.Signals | null }
  | { kind: "error"; error: Error }
>;

export type SessionContainerForegroundHandle = Readonly<{
  readonly [sessionContainerForegroundHandleBrand]: true;
  receipt: SessionContainerForegroundAttachReceipt;
  pid: number;
  containerId: string;
  completion: Promise<SessionContainerForegroundCompletion>;
}>;

export type SessionContainerForegroundChild = {
  readonly pid?: number;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  once(event: "spawn", listener: () => void): SessionContainerForegroundChild;
  once(event: "error", listener: (error: Error) => void): SessionContainerForegroundChild;
  once(
    event: "exit",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): SessionContainerForegroundChild;
  kill(signal: "SIGTERM"): boolean;
};

export type SessionContainerForegroundSpawner = (
  executable: "docker",
  args: readonly string[],
  options: Readonly<{
    shell: false;
    stdio: "inherit";
    env: Readonly<Record<string, string>>;
  }>,
) => SessionContainerForegroundChild;

export type SessionContainerForegroundStartOptions = Readonly<{
  dockerClientEnv: Readonly<Record<string, string>>;
  spawn?: SessionContainerForegroundSpawner;
  spawnTimeoutMs?: number;
}>;

const attachReceiptRecords = new WeakMap<object, SessionContainerRecordV2>();
const foregroundHandles = new WeakMap<object, ForegroundBinding>();

function exactRecordSnapshot(record: SessionContainerRecordV2): SessionContainerRecordV2 {
  const parsed = parseSessionContainerRecordV2(JSON.parse(serializeSessionContainerRecordV2(record)));
  if (!parsed) throw new Error("could not seal the foreground session lifecycle authority");
  return parsed;
}

function defaultSpawner(
  executable: "docker",
  args: readonly string[],
  options: Readonly<{
    shell: false;
    stdio: "inherit";
    env: Readonly<Record<string, string>>;
  }>,
): SessionContainerForegroundChild {
  return childProcess.spawn(executable, [...args], options) as SessionContainerForegroundChild;
}

function exactDockerClientEnvironment(value: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("foreground Docker attach environment is invalid");
  }
  const entries = Object.entries(value);
  if (entries.length > 1_024) throw new Error("foreground Docker attach environment is not bounded");
  let totalBytes = 0;
  for (const [name, entry] of entries) {
    if (name.length === 0 || name.includes("=") || name.includes("\0")
      || typeof entry !== "string" || entry.includes("\0")) {
      throw new Error("foreground Docker attach environment is invalid");
    }
    totalBytes += Buffer.byteLength(name) + Buffer.byteLength(entry) + 1;
  }
  if (totalBytes > 256 * 1024) throw new Error("foreground Docker attach environment is not bounded");
  return Object.freeze(Object.fromEntries(entries));
}

type ForegroundBinding = {
  child: SessionContainerForegroundChild;
  cancelled: boolean;
  outcome?: SessionContainerForegroundCompletion;
};

type AcknowledgedForegroundChild = Readonly<{
  child: SessionContainerForegroundChild;
  pid: number;
  completion: Promise<SessionContainerForegroundCompletion>;
  binding: ForegroundBinding;
}>;

/**
 * Spawns one pinned Docker foreground command and resolves only once the OS
 * has acknowledged the child with an exact host process id.
 *
 * Shared by the start and the re-attach so the two can never diverge on what
 * "the stream is live" means: the same bounded acknowledgement, the same
 * SIGTERM on a timeout or an unusable pid, and the same single-outcome
 * completion that later `error`/`exit` events cannot overwrite. It seals
 * nothing — the lifecycle authority a handle carries is the caller's to bind.
 */
async function acknowledgedForegroundChild(
  command: SessionDockerCommand,
  options: SessionContainerForegroundStartOptions,
): Promise<AcknowledgedForegroundChild> {
  const environment = exactDockerClientEnvironment(options.dockerClientEnv);
  const spawnTimeoutMs = options.spawnTimeoutMs ?? 5_000;
  if (!Number.isSafeInteger(spawnTimeoutMs) || spawnTimeoutMs < 1 || spawnTimeoutMs > 30_000) {
    throw new Error("foreground Docker attach spawn timeout must be between 1 and 30000 milliseconds");
  }
  const spawn = options.spawn ?? defaultSpawner;
  const child = executeSessionDockerCommand(command, (executable, args) => spawn(executable, args, {
    env: environment,
    shell: false,
    stdio: "inherit",
  }));

  let complete: (outcome: SessionContainerForegroundCompletion) => void = () => {};
  const completion = new Promise<SessionContainerForegroundCompletion>((resolve) => {
    complete = resolve;
  });
  let observedOutcome: SessionContainerForegroundCompletion | undefined;
  let binding: ForegroundBinding | undefined;

  const recordOutcome = (outcome: SessionContainerForegroundCompletion): boolean => {
    if (observedOutcome) return false;
    observedOutcome = outcome;
    if (binding) binding.outcome = outcome;
    complete(outcome);
    return true;
  };

  return await new Promise<AcknowledgedForegroundChild>((resolve, reject) => {
    let startSettled = false;
    const timeout = setTimeout(() => {
      if (startSettled) return;
      startSettled = true;
      child.kill("SIGTERM");
      reject(new Error("foreground Docker attach process start acknowledgement timed out"));
    }, spawnTimeoutMs);
    timeout.unref();

    child.once("error", (error) => {
      if (!recordOutcome(Object.freeze({ kind: "error", error }))) return;
      if (!startSettled) {
        startSettled = true;
        clearTimeout(timeout);
        reject(new Error(`foreground Docker attach failed to start: ${error.message}`, { cause: error }));
      }
    });
    child.once("exit", (code, signal) => {
      if (!recordOutcome(Object.freeze({ kind: "exit", code, signal }))) return;
      if (!startSettled) {
        startSettled = true;
        clearTimeout(timeout);
        reject(new Error("foreground Docker attach exited before its process start was acknowledged"));
      }
    });
    child.once("spawn", () => {
      if (startSettled) return;
      if (!Number.isSafeInteger(child.pid) || (child.pid ?? 0) < 1) {
        startSettled = true;
        clearTimeout(timeout);
        child.kill("SIGTERM");
        reject(new Error("foreground Docker attach did not expose an exact host process id"));
        return;
      }
      startSettled = true;
      clearTimeout(timeout);
      binding = { child, cancelled: false, ...(observedOutcome ? { outcome: observedOutcome } : {}) };
      resolve(Object.freeze({ child, pid: child.pid as number, completion, binding }));
    });
  });
}

export async function startSessionContainerForeground(
  command: SessionDockerCommand,
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
  options: SessionContainerForegroundStartOptions,
): Promise<SessionContainerForegroundHandle> {
  assertSessionContainerStartAttachCommand(command, record, expectedProject);
  const recordSnapshot = exactRecordSnapshot(record);
  const started = await acknowledgedForegroundChild(command, options);
  const containerId = recordSnapshot.containerId;
  if (!containerId) {
    started.child.kill("SIGTERM");
    throw new Error("foreground Docker attach lifecycle record has no exact container id");
  }
  const receipt = Object.freeze({
    containerId,
    sessionIncarnation: recordSnapshot.sessionIncarnation,
    pid: started.pid,
  }) as SessionContainerForegroundAttachReceipt;
  attachReceiptRecords.set(receipt, recordSnapshot);
  const handle = Object.freeze({
    receipt,
    pid: started.pid,
    containerId,
    completion: started.completion,
  }) as SessionContainerForegroundHandle;
  foregroundHandles.set(handle, started.binding);
  return handle;
}

/**
 * Replaces the OS child behind a sealed foreground handle after its stream
 * ended without the container ending with it.
 *
 * A `docker start --attach` child can die on its own — a broken pipe, a killed
 * terminal, a signalled CLI — while the agent it was showing keeps running as
 * PID 1 of a container this host has just re-inspected and proved unchanged.
 * Ending such a session would destroy a live process over a lost view of it, so
 * the driver re-attaches instead, and this is the only way to do it.
 *
 * What is replaced is exactly the child: the returned handle carries the same
 * sealed receipt, so the lifecycle authority admission proved — this container,
 * this session incarnation, this argv and TTY contract — is unchanged, and
 * every assertion and adoption that already held the old handle holds the new
 * one. What it refuses, before spawning anything: an unsealed handle, a stream
 * that has not ended (two attaches on one container), a foreground this host
 * already cancelled (teardown's decision, not a lost stream), and any command
 * that is not a sealed attach for this exact identity.
 */
export async function reattachSessionContainerForeground(
  handle: SessionContainerForegroundHandle,
  command: SessionDockerCommand,
  options: SessionContainerForegroundStartOptions,
): Promise<SessionContainerForegroundHandle> {
  const previous = foregroundHandles.get(handle);
  const receiptBinding = attachReceiptRecords.get(handle.receipt);
  if (!previous || !receiptBinding) throw new Error("refusing an unsealed foreground session attach handle");
  if (previous.cancelled) {
    throw new Error("refusing to re-attach a cancelled foreground session attach");
  }
  if (!previous.outcome) {
    throw new Error("refusing to re-attach a foreground session attach that has not ended");
  }
  assertSessionContainerAttachCommand(command, {
    projectId: receiptBinding.projectId,
    composeProject: receiptBinding.composeProject,
    sessionIncarnation: handle.receipt.sessionIncarnation,
    containerId: handle.containerId,
    interactive: receiptBinding.interactive,
  });
  const started = await acknowledgedForegroundChild(command, options);
  const reattached = Object.freeze({
    // The sealed receipt is reused verbatim, including its `pid`: that pid is
    // the original child's and is spent only before the session is attached
    // (the running proof and the activation authority), so it is history by the
    // time any stream can be lost. The handle's own `pid` below is the live one.
    receipt: handle.receipt,
    pid: started.pid,
    containerId: handle.containerId,
    completion: started.completion,
  }) as SessionContainerForegroundHandle;
  foregroundHandles.set(reattached, started.binding);
  return reattached;
}

export function assertSessionContainerForegroundAttachReceipt(
  receipt: SessionContainerForegroundAttachReceipt,
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
): void {
  assertSessionContainerRecordProject(record, expectedProject);
  const binding = attachReceiptRecords.get(receipt);
  if (!binding) throw new Error("refusing an unsealed foreground session attach receipt");
  if (serializeSessionContainerRecordV2(binding) !== serializeSessionContainerRecordV2(record)
    || receipt.containerId !== binding.containerId
    || receipt.sessionIncarnation !== binding.sessionIncarnation
    || !Number.isSafeInteger(receipt.pid)
    || receipt.pid < 1) {
    throw new Error("foreground session attach receipt belongs to a different lifecycle authority");
  }
}

export function assertSessionContainerForegroundHandleIdentity(
  handle: SessionContainerForegroundHandle,
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
): void {
  assertSessionContainerRecordProject(record, expectedProject);
  const handleBinding = foregroundHandles.get(handle);
  const receiptBinding = attachReceiptRecords.get(handle.receipt);
  if (!handleBinding || !receiptBinding) {
    throw new Error("refusing an unsealed foreground session attach handle");
  }
  if (receiptBinding.projectId !== record.projectId
    || receiptBinding.composeProject !== record.composeProject
    || receiptBinding.sessionId !== record.sessionId
    || receiptBinding.sessionIncarnation !== record.sessionIncarnation
    || receiptBinding.sessionPrincipal !== record.sessionPrincipal
    || receiptBinding.containerId !== record.containerId
    || receiptBinding.sourceIp !== record.sourceIp
    || receiptBinding.selectedAgentImageId !== record.selectedAgentImageId
    || receiptBinding.sessionAgentGenerationDigest !== record.sessionAgentGenerationDigest
    || receiptBinding.controlPlaneGenerationDigest !== record.controlPlaneGenerationDigest
    || receiptBinding.admissionContractEpoch !== record.admissionContractEpoch
    || receiptBinding.launchPath !== record.launchPath
    || receiptBinding.launchArgs.length !== record.launchArgs.length
    || receiptBinding.launchArgs.some((entry, index) => entry !== record.launchArgs[index])
    || receiptBinding.interactive !== record.interactive
    || receiptBinding.tty !== record.tty
    || handle.containerId !== record.containerId
    || handle.receipt.sessionIncarnation !== record.sessionIncarnation) {
    throw new Error("foreground session attach handle belongs to a different lifecycle identity");
  }
}

/**
 * Advances the sealed foreground receipt binding across one compatible
 * control-plane rebind. The handle's identity claim — this OS child attaches
 * this exact container for this exact session, argv, and TTY contract — is
 * untouched by a rebind, so only the snapshot's control digest moves, and only
 * after the held-to-rebound pair passes the shared rebind-shape assert. Called
 * by the trusted driver's adoption alone; a no-op when the digest is
 * unchanged (a proxy replacement under the same control generation).
 */
export function adoptSessionContainerForegroundControlPlaneRebind(
  handle: SessionContainerForegroundHandle,
  expectedProject: SessionContainerProjectIdentity,
  held: SessionContainerRecordV2,
  rebound: SessionContainerRecordV2,
): void {
  assertSessionContainerForegroundHandleIdentity(handle, held, expectedProject);
  assertSessionContainerRecordProject(rebound, expectedProject);
  if (rebound.controlPlaneGenerationDigest === held.controlPlaneGenerationDigest) {
    // A retained lease and an unchanged digest leave nothing for a transition
    // to advance, so the exact-record equality is the whole of the proof.
    if (serializeSessionContainerRecordV2(held) !== serializeSessionContainerRecordV2(rebound)) {
      throw new Error("control-plane rebind changed a retained session record it may not touch");
    }
    return;
  }
  assertAttachedSessionContainerControlPlaneRebindV2(held, rebound);
  const receiptBinding = attachReceiptRecords.get(handle.receipt);
  if (!receiptBinding) throw new Error("refusing an unsealed foreground session attach handle");
  attachReceiptRecords.set(handle.receipt, exactRecordSnapshot({
    ...receiptBinding,
    controlPlaneGenerationDigest: rebound.controlPlaneGenerationDigest,
  }));
}

export function cancelSessionContainerForegroundAttach(
  handle: SessionContainerForegroundHandle,
): boolean {
  const binding = foregroundHandles.get(handle);
  if (!binding) throw new Error("refusing an unsealed foreground session attach handle");
  if (binding.cancelled || binding.child.exitCode !== null || binding.child.signalCode !== null) return false;
  binding.cancelled = true;
  return binding.child.kill("SIGTERM");
}

export function currentSessionContainerForegroundCompletion(
  handle: SessionContainerForegroundHandle,
): SessionContainerForegroundCompletion | undefined {
  const binding = foregroundHandles.get(handle);
  if (!binding) throw new Error("refusing an unsealed foreground session attach handle");
  return binding.outcome;
}
