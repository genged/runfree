// The watcher's credential source reader. Host-only: it runs a source's
// provider (`op`, a command source) as an owned, bounded, cancellable child and
// hands back the value, the provider's classified failure, or cancellation.
// It never touches the proxy, receipts or status: the locked pass decides what
// a result means. Values stay in memory and are dropped on every exit.

import childProcess from "node:child_process";

import {
  announceOnePasswordRead,
  commandSourceStep,
  type CredentialReadPlan,
  jwtSigningKeyFromPem,
  onePasswordDocumentArgs,
  onePasswordDocumentStep,
  onePasswordReadArgs,
  onePasswordReadStep,
  type OnePasswordRead,
  PROVIDER_OUTPUT_MAX_BYTES,
  type ProviderExit,
  providerExitThroughTestSeam,
  signJwtWithKey,
  tokenSyncWatchNowMs,
} from "./admin-core.ts";
import { CredentialCancellationError, type CredentialLifetime, settleHostSignals } from "./credential-cancellation.ts";

/** One token's read for this pass: the source configuration as planned, bound to its fingerprint. */
export type CredentialReadInput = Readonly<{
  tokenName: string;
  fingerprint: string;
  plan: CredentialReadPlan;
}>;

export type CredentialReadResult =
  | Readonly<{ kind: "success"; value: string; resolvedAt: number }>
  /** The provider's own verdict, classified exactly as the synchronous resolver classifies it. */
  | Readonly<{ kind: "source-failure"; error: unknown }>
  | Readonly<{ kind: "cancelled" }>;

/**
 * Bounds for an owned provider after the host ends it (cancellation, timeout,
 * output overflow): SIGTERM to its process group, SIGKILL after `graceMs`
 * unless it has already exited and closed its output, then at most `joinMs`
 * for the exit before its output is abandoned.
 */
export type OwnedProviderBounds = Readonly<{ graceMs: number; joinMs: number }>;

export const OWNED_PROVIDER_BOUNDS: OwnedProviderBounds = Object.freeze({ graceMs: 2_000, joinMs: 1_000 });

export type OwnedProviderOptions = Readonly<{
  cwd?: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  maxBytes: number;
}>;

export type OwnedProviderRun =
  | Readonly<{ kind: "exited"; status: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }>
  | Readonly<{ kind: "spawn-error"; message: string }>
  /** Ended by the host; whatever it printed is discarded. */
  | Readonly<{ kind: "timeout" | "overflow" | "cancelled" }>;

/**
 * Runs one provider as the leader of its own process group, which the caller
 * owns: the group is what a cancellation, a timeout or an overflow ends, so a
 * descendant holding the output pipe cannot outlive the bound. A run ended by
 * the host never reports the provider's own result, even one that arrived
 * between the stop and the kill.
 */
export function runOwnedProvider(
  command: string,
  args: readonly string[],
  options: OwnedProviderOptions,
  lifetime: CredentialLifetime,
  bounds: OwnedProviderBounds = OWNED_PROVIDER_BOUNDS,
): Promise<OwnedProviderRun> {
  return lifetime.own(new Promise<OwnedProviderRun>((resolve) => {
    if (lifetime.signal.aborted) {
      resolve({ kind: "cancelled" });
      return;
    }
    let child: childProcess.ChildProcess;
    try {
      child = childProcess.spawn(command, [...args], {
        cwd: options.cwd,
        env: options.env,
        detached: process.platform !== "win32",
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      resolve({ kind: "spawn-error", message: error instanceof Error ? error.message : String(error) });
      return;
    }
    const output = { stdout: { chunks: [] as Buffer[], bytes: 0 }, stderr: { chunks: [] as Buffer[], bytes: 0 } };
    let exit: Readonly<{ status: number | null; signal: NodeJS.Signals | null }> | undefined;
    let spawnError: string | undefined;
    let endedBy: "timeout" | "overflow" | "cancelled" | undefined;
    let settled = false;
    const timers: NodeJS.Timeout[] = [];

    const settle = (): void => {
      if (settled) return;
      settled = true;
      for (const timer of timers) clearTimeout(timer);
      lifetime.signal.removeEventListener("abort", onAbort);
      child.stdout?.destroy();
      child.stderr?.destroy();
      const out = Buffer.concat(output.stdout.chunks).toString("utf8");
      const err = Buffer.concat(output.stderr.chunks).toString("utf8");
      output.stdout.chunks = [];
      output.stderr.chunks = [];
      if (endedBy) resolve({ kind: endedBy });
      else if (spawnError !== undefined) resolve({ kind: "spawn-error", message: spawnError });
      else resolve({ kind: "exited", status: exit?.status ?? null, signal: exit?.signal ?? null, stdout: out, stderr: err });
    };
    const signalGroup = (signal: NodeJS.Signals): void => {
      if (child.pid === undefined) return;
      try {
        process.kill(process.platform === "win32" ? child.pid : -child.pid, signal);
      } catch {
        // The group is already gone.
      }
    };
    const end = (reason: "timeout" | "overflow" | "cancelled"): void => {
      if (settled || endedBy) return;
      endedBy = reason;
      signalGroup("SIGTERM");
      timers.push(setTimeout(() => {
        // Exited with its output closed: the group may be empty and its
        // number reusable, so it is not signalled again.
        if (settled) return;
        signalGroup("SIGKILL");
        timers.push(setTimeout(settle, bounds.joinMs));
      }, bounds.graceMs));
    };
    const onAbort = (): void => end("cancelled");

    const collect = (target: "stdout" | "stderr") => (chunk: Buffer): void => {
      if (endedBy) return;
      const stream = output[target];
      stream.bytes += chunk.length;
      if (stream.bytes > options.maxBytes) {
        end("overflow");
        return;
      }
      stream.chunks.push(chunk);
    };
    child.stdout?.on("data", collect("stdout"));
    child.stderr?.on("data", collect("stderr"));
    child.stdout?.on("error", () => {});
    child.stderr?.on("error", () => {});
    child.on("error", (error) => {
      if (child.pid !== undefined) return;
      spawnError = error.message;
      settle();
    });
    child.on("exit", (status, signal) => {
      exit = { status, signal };
    });
    // `close` follows the exit and the end of every output stream.
    child.on("close", settle);
    timers.push(setTimeout(() => end("timeout"), options.timeoutMs));
    lifetime.signal.addEventListener("abort", onAbort, { once: true });
  }));
}

function cancelled(lifetime: CredentialLifetime): CredentialCancellationError {
  return new CredentialCancellationError(lifetime.stopCause() ?? "lifetime-closed");
}

// One owned provider run, as the shared step classifiers expect it. A run the
// host ended for cancellation throws; a timeout or overflow keeps its usual
// transient/spawn verdict. A provider that ended by a signal the host did not
// send is the provider's own failure, classified as before — unless the
// settle shows the watch was stopped meanwhile.
async function ownedProviderExit(
  command: string,
  args: readonly string[],
  options: OwnedProviderOptions,
  lifetime: CredentialLifetime,
): Promise<ProviderExit> {
  lifetime.assertActive();
  const seamed = providerExitThroughTestSeam(command, args, options);
  if (seamed) return seamed;
  const run = await runOwnedProvider(command, args, options, lifetime);
  switch (run.kind) {
    case "cancelled":
      throw cancelled(lifetime);
    case "timeout":
      return { status: null, signal: null, stdout: "", stderr: "", failure: { kind: "timeout" } };
    case "overflow":
      return { status: null, signal: null, stdout: "", stderr: "", failure: { kind: "spawn", message: `output exceeded ${options.maxBytes} bytes` } };
    case "spawn-error":
      return { status: null, signal: null, stdout: "", stderr: "", failure: { kind: "spawn", message: run.message } };
    case "exited":
      if (run.signal !== null) {
        await settleHostSignals();
        lifetime.assertActive();
      }
      return run;
  }
}

async function readOnePasswordOwned(read: OnePasswordRead, lifetime: CredentialLifetime): Promise<string> {
  announceOnePasswordRead(read);
  const options: OwnedProviderOptions = { env: read.env, timeoutMs: read.timeoutMs, maxBytes: PROVIDER_OUTPUT_MAX_BYTES };
  const readExit = await ownedProviderExit(read.executable, onePasswordReadArgs(read), options, lifetime);
  const step = onePasswordReadStep(read, readExit);
  if (step.kind === "value") return step.value;
  // No fallback once the watch has stopped.
  lifetime.assertActive();
  const documentExit = await ownedProviderExit(read.executable, onePasswordDocumentArgs(step.documentRef), options, lifetime);
  return onePasswordDocumentStep(read, readExit, documentExit);
}

async function executeReadPlan(plan: CredentialReadPlan, lifetime: CredentialLifetime): Promise<string> {
  switch (plan.kind) {
    case "value":
      return plan.value;
    case "failure":
      throw plan.error;
    case "1password":
      return readOnePasswordOwned(plan.read, lifetime);
    case "command": {
      const { invocation } = plan;
      const exit = await ownedProviderExit(invocation.executable, invocation.args, {
        cwd: invocation.cwd,
        env: invocation.env,
        timeoutMs: invocation.timeoutMs,
        maxBytes: PROVIDER_OUTPUT_MAX_BYTES,
      }, lifetime);
      return commandSourceStep(invocation, exit);
    }
    case "jwt": {
      const key = plan.signingKey.kind === "cached"
        ? plan.signingKey.key
        : jwtSigningKeyFromPem(plan.source, await readOnePasswordOwned(plan.signingKey.read, lifetime), plan.options);
      lifetime.assertActive();
      return signJwtWithKey(plan.source, key);
    }
  }
}

/**
 * Reads one credential source for a watcher pass. Success carries the value
 * and the time the read started; a source failure carries the provider's
 * classified error, nothing more; a read the watch's stop overtook is
 * `cancelled`, whatever the provider said.
 */
export async function readCredentialSource(input: CredentialReadInput, lifetime: CredentialLifetime): Promise<CredentialReadResult> {
  const resolvedAt = tokenSyncWatchNowMs();
  try {
    lifetime.assertActive();
    const value = await executeReadPlan(input.plan, lifetime);
    lifetime.assertActive();
    return { kind: "success", value, resolvedAt };
  } catch (error) {
    if (error instanceof CredentialCancellationError || lifetime.stopCause() !== undefined) return { kind: "cancelled" };
    return { kind: "source-failure", error };
  }
}
