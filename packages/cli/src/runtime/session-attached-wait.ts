// The attached wait of one admitted session: the heartbeat loop that keeps its
// session file fresh, and the completion race that decides what the end of the
// foreground stream meant.
//
// Extracted from `InternalBuiltinAdmissionProbeSteps.awaitCompletion` (todo 34)
// without changing behavior. The driver still owns every observation and every
// effect — the sealed beat, the confirming inspection, the re-attach, the
// rebind adoption, the host status stamps — and hands them in as ports. This
// module owns only the order in which they are asked and what each answer
// means, which is the part that was nested several closures deep.
//
// The one rule the whole module keeps: no failing beat, no lost stream, and no
// unconfirmed observation is authority to end the attached process. The loop's
// only power is over this session's file, and the race ends only on a proved
// exit, a proved change, or an ordinary exit status.

import type { SessionFileV1 } from "@runfree/runtime-contracts/session-file";

import { runfreeLog, warn } from "../warnings.ts";
import { cancellableDelay } from "./cancellable-delay.ts";
import type { SessionAdmissionLaunchOutcome } from "./session-admission-probe.ts";
import type {
  SessionContainerForegroundCompletion,
  SessionContainerForegroundHandle,
} from "./session-container-start.ts";
import { nextHeartbeatDelayMs, type HeartbeatOutcome } from "./session-file-heartbeat.ts";

/**
 * Whether a foreground completion is a lost stream rather than the agent's own
 * exit.
 *
 * Two shapes, and only two. A spawn or stream `error` never carried an exit
 * status in the first place, and an exit with a signal but no code is the
 * `docker start --attach` child being killed — neither is news about the
 * process inside the container, which is what the launch's status must report.
 * Every other exit carries the code the agent itself exited with.
 */
export function lostForegroundStream(completion: SessionContainerForegroundCompletion): boolean {
  return completion.kind === "error" || (completion.code === null && completion.signal !== null);
}

/**
 * Whether the last written file's lease had lapsed by the time `next` was
 * inspected. Both times come from the same host clock, so they compare
 * directly. No previous file, or one whose deadline cannot be read, counts as
 * lapsed: the session had no window to be served in.
 */
function leaseLapsedBefore(previousExpiry: string | undefined, next: SessionFileV1): boolean {
  const expiry = previousExpiry === undefined ? Number.NaN : Date.parse(previousExpiry);
  const inspected = Date.parse(next.inspectedAt);
  if (!Number.isFinite(expiry) || !Number.isFinite(inspected)) return true;
  return expiry <= inspected;
}

/**
 * What one confirming inspection says about a lost foreground stream.
 *
 *   reattach  the exact anchored incarnation is still running, and this session
 *             may spend one of its re-attaches on it;
 *   exited    the inspection proved the container's own exit and carries the
 *             status the launch must report;
 *   teardown  the inspection answered, and it is neither of those — a changed
 *             container, or an answer that resolves to no incarnation this
 *             session owns. Handled exactly as this completion is handled
 *             today;
 *   wait      nothing was proved (the observation failed, or the re-attach
 *             limit is reached). Never a verdict about the session: the beat
 *             keeps running and asks again.
 */
export type LostForegroundStreamDecision =
  | Readonly<{ kind: "reattach" }>
  | Readonly<{ kind: "exited"; status: number }>
  | Readonly<{ kind: "teardown"; observation: string }>
  | Readonly<{ kind: "wait"; observation: string }>;

/**
 * How the heartbeat treats a failed rebind adoption.
 *
 *   abort     the renewal lock wait was aborted because the wait is ending;
 *             the loop returns quietly;
 *   preserve  a condition the session outlives (a rebind still in flight, a
 *             lock held past the renewal budget, an unavailable observation):
 *             reported once per gap, and the beat still runs;
 *   fatal     a decision about this session's authority: rethrown, which ends
 *             the renewal loop and therefore the wait.
 */
export type AdoptionFailureClass = "abort" | "preserve" | "fatal";

/** Everything the attached wait asks of the driver that owns the session. */
export type AttachedSessionWaitPorts = Readonly<{
  /** The foreground stream the session was admitted with. */
  foreground: SessionContainerForegroundHandle;
  /** The healthy beat cadence. */
  cadenceMs: number;
  /** One sealed inspect-and-write of this session's file. */
  beat(): Promise<HeartbeatOutcome>;
  /** Adopts a completed compatible rebind if the durable selection changed. */
  adoptDurableSelectionIfChanged(signal: AbortSignal): Promise<void>;
  classifyAdoptionFailure(error: unknown): AdoptionFailureClass;
  /** Best-effort return of the session lock manager to waiting. */
  releaseLockForWait(): void;
  /** Records a written file: the held file and the `served` stamp. */
  onBeatWritten(file: SessionFileV1): void;
  /** Records a failed beat: a `retrying` stamp for the last written file. */
  onBeatRetrying(): void;
  /** The wall deadline of the last file this host wrote, if any. */
  leaseExpiry(): string | undefined;
  /** One confirming inspection of a lost stream. Must never throw. */
  classifyLostStream(): LostForegroundStreamDecision;
  /** Replaces a lost stream with a new attach over the same authority. */
  reattach(current: SessionContainerForegroundHandle): Promise<SessionContainerForegroundHandle>;
  /** This launch's answer for a foreground completion that ended the session. */
  reportCompletion(completion: SessionContainerForegroundCompletion): SessionAdmissionLaunchOutcome;
  /** This launch's answer for an exit the confirming inspection proved. */
  reportInspectedExit(status: number): SessionAdmissionLaunchOutcome;
}>;

type LostStream = {
  readonly lost: SessionContainerForegroundCompletion;
  readonly settled: Promise<LostForegroundStreamDecision>;
  readonly decide: (decision: LostForegroundStreamDecision) => void;
  answered: boolean;
};

/**
 * Holds the session for the life of the attached process, beating its file,
 * and returns the launch outcome.
 *
 * Runs with the lifecycle lock released; the caller reacquires it afterwards
 * for teardown. Always stops the heartbeat before it returns or throws.
 */
export async function waitForAttachedSessionCompletion(
  ports: AttachedSessionWaitPorts,
): Promise<SessionAdmissionLaunchOutcome> {
  let finished = false;
  let wakeRenewal: (() => void) | undefined;
  const renewalLockAcquisition = new AbortController();
  /**
   * The stream this launch is currently attached to.
   *
   * A lost stream is replaced rather than mourned, so the completion this wait
   * races is not fixed for the life of the session.
   */
  let attachedForeground = ports.foreground;
  /**
   * A lost stream whose meaning is not yet known.
   *
   * Present only between a stream ending unconfirmed — the observation failed,
   * or this session has re-attached as often as it may — and the beat that
   * finally answers. While it is present the completion race waits on
   * `settled` instead of on a foreground that has already ended, so nothing
   * spins and nothing is concluded.
   */
  let lostStream: LostStream | undefined;
  const awaitLostStream = (lost: SessionContainerForegroundCompletion, observation: string): void => {
    let decide!: (decision: LostForegroundStreamDecision) => void;
    const settled = new Promise<LostForegroundStreamDecision>((resolve) => { decide = resolve; });
    lostStream = { lost, settled, decide, answered: false };
    // Immediate, not buffered. This is the one state where the terminal goes
    // quiet while the launch keeps waiting, so the person watching it has to be
    // told now — a warning flushed when the command ends would arrive only
    // after they had given up and interrupted it. Every exit from the wait
    // announces itself the same way.
    runfreeLog(`session output stream lost: ${observation}; the agent process is preserved; waiting for the container to be reachable again`);
  };
  /**
   * One beat's share of the confirmation: ask the container again.
   *
   * A beat that proved a mismatch is itself an answer when the inspection could
   * not be read — the shipped judge already decided that this is not the
   * container the session was admitted for (it is gone, or it is different),
   * and waiting for an inspection that will never resolve would hold the launch
   * open over a session that no longer exists.
   */
  const confirmLostStream = (beat: HeartbeatOutcome | undefined): void => {
    const waiting = lostStream;
    if (!waiting || waiting.answered) return;
    const decision = ports.classifyLostStream();
    if (decision.kind === "wait") {
      if (beat?.kind !== "mismatch") return;
      waiting.answered = true;
      waiting.decide({ kind: "teardown", observation: beat.observation });
      return;
    }
    waiting.answered = true;
    waiting.decide(decision);
  };

  /**
   * Renewal: one sealed inspect-and-write per beat, and nothing else.
   *
   * It publishes no snapshot, drains no peer transaction, and mints no lease,
   * and it takes the lifecycle lock only on the one beat that finds a completed
   * compatible rebind to adopt — so an ordinary beat serializes against nothing
   * and cannot be delayed by another launcher's lifecycle operation. That is
   * also why no failing beat may end the session: the loop's only power is over
   * this session's file, and the proxy already stops serving a file that stops
   * being renewed. A beat that cannot observe the container leaves the last
   * file to expire on its own lease; a beat that proves a different container
   * has already had its file deleted by the sealed write itself. Either way the
   * agent process keeps running until it exits, unserved rather than killed.
   */
  const heartbeatLoop = async (): Promise<void> => {
    const cadenceMs = ports.cadenceMs;
    let failures = 0;
    // Whether the last beat failed on a host-side fault rather than on an
    // observation, which is the difference between "this will pass" and "this
    // will not pass without someone acting".
    let faulted = false;
    // Whether the last adoption attempt could not be completed for a reason
    // that ends on its own. Reported once per gap, like every other condition
    // here that is expected to pass.
    let adoptionBlocked = false;
    while (!finished) {
      // Healthy beats run on the cadence; consecutive failures back off from
      // 1 s, doubling to a 30 s cap with jitter. Cancellable because teardown
      // waits on this loop, and an uninterruptible sleep would hold the
      // session's file for a full cadence after its process had already exited.
      const sleep = cancellableDelay(nextHeartbeatDelayMs({ consecutiveFailures: failures, cadenceMs }));
      wakeRenewal = sleep.cancel;
      await sleep.elapsed;
      if (finished) return;
      // Deliberately OUTSIDE the guard below: a refused adoption is a decision
      // about this session's authority, not a beat that failed, and swallowing
      // it as one would keep renewing under a control plane this session no
      // longer holds. An unchanged selection reads two durable fields and takes
      // no lock.
      //
      // Three failures are not that decision, and every one of them means
      // "preserve the process": a rebind still in flight (the journal exists,
      // so adoption refuses until its recovery settles — and a crashed rebinder
      // leaves it there indefinitely), a lifecycle lock held past the renewal
      // wait budget, and a host queue that cannot schedule a renewal. Ending a
      // live agent over any of them would be the wedge this loop must not
      // become. The beat still runs and still writes into the proxy this
      // session holds, which is fail-closed rather than destructive: if the
      // replacement really did happen, that write fails and the file lapses on
      // its own lease. Q5's accepted cost is one cadence plus adoption
      // unserved, never a teardown.
      try {
        await ports.adoptDurableSelectionIfChanged(renewalLockAcquisition.signal);
        adoptionBlocked = false;
      } catch (error) {
        const failureClass = ports.classifyAdoptionFailure(error);
        if (failureClass === "abort") return;
        if (failureClass === "fatal") throw error;
        // The manager retains the lock when the adoption itself threw and has
        // already returned to waiting when acquisition did, so the release is
        // best effort for exactly that reason.
        try { ports.releaseLockForWait(); }
        catch { /* The manager may already be waiting, or the fence was lost. */ }
        // Immediate, not buffered: the session is running unrestored, and the
        // person watching it can act on that now rather than when the command
        // finally ends.
        if (!adoptionBlocked) {
          runfreeLog(`${error instanceof Error ? error.message : String(error)}; the session process remains attached; network restoration is incomplete`);
        }
        adoptionBlocked = true;
      }
      if (finished) return;
      let beat: HeartbeatOutcome | undefined;
      try {
        const outcome = await ports.beat();
        beat = outcome;
        if (outcome.kind === "written") {
          // Only after a gap that actually cost the network: a healthy beat is
          // silent, and so is a gap the previous file's lease outlasted — the
          // proxy kept serving throughout, so there is nothing to restore.
          if ((failures > 0 || faulted) && leaseLapsedBefore(ports.leaseExpiry(), outcome.file)) {
            runfreeLog("session network restored");
          }
          failures = 0;
          faulted = false;
          ports.onBeatWritten(outcome.file);
        } else {
          failures += 1;
          if (outcome.kind === "mismatch") {
            // The beat deleted the file, which is the whole of the authority
            // this source can withdraw. Ending the process is not part of it.
            warn(`${outcome.observation}; session file removed; the process is preserved until it exits`);
          } else if (failures === 1) {
            // Once per outage, not once per beat: an unavailable observation is
            // expected to end, and the loop is already retrying.
            warn(`${outcome.error.message}; session process preserved; heartbeat will retry`);
          }
          ports.onBeatRetrying();
        }
      } catch (error) {
        // `inspectAndWriteSessionFile` answers every post-Docker condition with
        // an outcome and the stamp above never throws, so a throw here is a
        // host-side fault — this driver's own inputs — and nothing about it is
        // expected to end on its own. Ending a live agent over it would be
        // exactly the wedge this loop must not become, so it is swallowed; but
        // a fault that is silently retried until the file lapses would take the
        // session's network away with no signal at all, so unlike a transient
        // outage it is reported on every beat until a write succeeds.
        failures += 1;
        faulted = true;
        const detail = error instanceof Error ? error.message : String(error);
        const expiry = ports.leaseExpiry();
        warn(`session heartbeat is failing on a host-side fault: ${detail}; the session loses network at ${expiry ?? "the end of its current session-file lease"} unless it recovers`);
      }
      // A lost stream this host could not confirm — and a session that has
      // re-attached as often as it may — waits here rather than in a loop of
      // its own: the beat is already the thing that keeps asking the daemon
      // about this container, so the confirmation rides with it and costs one
      // extra inspection only while a stream is actually missing.
      //
      // Invariant: this call sits OUTSIDE the beat's guard above, so it must
      // stay throw-free. `classifyLostStream` answers every condition with a
      // decision and `runfreeLog` writes a line; anything added here that could
      // throw would reject the heartbeat loop and send a live agent to
      // teardown.
      confirmLostStream(beat);
    }
  };
  const renewalLoop = heartbeatLoop();

  /**
   * The completion race.
   *
   * The end of the foreground is not the end of the session: the stream can end
   * while the agent keeps running, and ending the session on that would destroy
   * a live process over a lost view of it. So a lost stream is confirmed by
   * inspection first, and the race is a loop — a re-attach continues it under
   * the new stream, an unconfirmed loss continues it under the beat's
   * confirmation, and only a proved exit, a proved change, or an ordinary exit
   * status leaves it.
   */
  const awaitFileSourceCompletion = async (): Promise<SessionAdmissionLaunchOutcome> => {
    for (;;) {
      const waiting = lostStream;
      const settled = waiting
        ? await Promise.race([
          waiting.settled.then((decision) => ({ kind: "decided" as const, decision, lost: waiting.lost })),
          renewalLoop.then(() => ({ kind: "renewal" as const })),
        ])
        : await Promise.race([
          attachedForeground.completion.then((completion) => ({ kind: "foreground" as const, completion })),
          renewalLoop.then(() => ({ kind: "renewal" as const })),
        ]);
      if (settled.kind === "renewal") {
        throw new Error("session lease renewal stopped before the attached process finished");
      }
      if (settled.kind === "foreground" && !lostForegroundStream(settled.completion)) {
        return ports.reportCompletion(settled.completion);
      }
      const lost = settled.kind === "foreground" ? settled.completion : settled.lost;
      // Whether the person at the terminal was told this session was waiting,
      // and is therefore owed the answer.
      const announced = settled.kind === "decided";
      if (announced) lostStream = undefined;
      const decision = settled.kind === "decided" ? settled.decision : ports.classifyLostStream();
      if (decision.kind === "exited") {
        // The stream is gone and so is the container: the status the launch
        // reports is the one the container actually exited with, never the
        // signal that killed this host's view of it.
        if (announced) runfreeLog(`session container exited with code ${decision.status}`);
        return ports.reportInspectedExit(decision.status);
      }
      if (decision.kind === "teardown") {
        if (announced) runfreeLog(`session output stream cannot be recovered: ${decision.observation}`);
        return ports.reportCompletion(lost);
      }
      if (decision.kind === "wait") {
        awaitLostStream(lost, decision.observation);
        continue;
      }
      try {
        attachedForeground = await ports.reattach(attachedForeground);
        runfreeLog("session output stream ended while the container is still running; re-attached");
      } catch (error) {
        // A re-attach that cannot spawn is this host's failure, not the
        // container's: the process it could not reach is still running, so the
        // beat keeps asking rather than ending it.
        awaitLostStream(lost, error instanceof Error ? error.message : String(error));
      }
    }
  };

  try {
    return await awaitFileSourceCompletion();
  } finally {
    finished = true;
    renewalLockAcquisition.abort();
    wakeRenewal?.();
    await renewalLoop.catch(() => undefined);
  }
}
