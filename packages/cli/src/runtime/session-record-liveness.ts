import {
  compareHostBootId,
  compareHostProcessStart,
  processAlive,
  recordedOnPreviousBoot,
} from "./host-identity.ts";
import type { SessionContainerRecordV2 } from "./session-containers.ts";
import type { SessionHostStatusV1 } from "./session-host-status.ts";

export type SessionRecordOwnerLiveness = "alive" | "dead" | "unknown";

export type SessionRecordLiveness = Readonly<{
  kind: "live" | "stale";
  reason: string;
}>;

/**
 * Whether the host process that opened a record is still running.
 *
 * Ordered so proof outranks the value it would override, the same way
 * `hostSessionProcessAlive` and `removeStaleLifecycleLock` order theirs: a
 * recorded previous boot settles the question without consulting the PID at
 * all, because no process survives a reboot whatever PID it held, and a PID
 * from a previous boot may well be alive again as something unrelated.
 *
 * Returns `unknown` rather than guessing when the record names no usable PID.
 * The legacy predicate answers `true` there because a boolean has nowhere else
 * to go; keeping the third answer prevents advisory expiry from authorizing
 * destruction of a session whose owner may still be running.
 */
export function sessionRecordOwnerLiveness(
  record: Pick<SessionContainerRecordV2, "hostPid" | "hostBootId" | "hostProcessStart">,
  env?: NodeJS.ProcessEnv,
): SessionRecordOwnerLiveness {
  if (recordedOnPreviousBoot(record.hostBootId, env)) return "dead";
  // Guards `processAlive`, not record validity: `process.kill(0, 0)` signals
  // the caller's own process group rather than answering about a process, and
  // a negative PID is a group too. `parseSessionContainerRecordV2` rejects
  // these upstream, so this is unreachable for a record read from disk.
  if (!Number.isInteger(record.hostPid) || record.hostPid <= 0) return "unknown";
  if (!processAlive(record.hostPid)) return "dead";
  const sameBoot = compareHostBootId(record.hostBootId, env) === "match";
  // A live PID is not by itself the same owner. Within one boot the
  // process-start stamp settles it both ways; without a matching boot the stamp
  // describes a different machine-life and cannot be compared at all, leaving a
  // bare PID coincidence — which must not read as proof of life, or a record
  // whose PID happens to be reused holds the registry forever.
  if (sameBoot) {
    const start = compareHostProcessStart(record.hostProcessStart, record.hostPid, env);
    if (start === "mismatch") return "dead";
    if (start === "match") return "alive";
  }
  return "unknown";
}

/**
 * Whether a session must be protected from destructive runtime changes.
 * An advisory stamp can be stale after a failed write, and the durable lease
 * freezes at admission. Neither proves that the owner stopped. Recovery may
 * reclaim the record once process death or a different boot/start is proved.
 */
export function sessionRecordLiveUnderSessionFiles(
  record: Pick<SessionContainerRecordV2, "hostPid" | "hostBootId" | "hostProcessStart">,
  options: Readonly<{ nowEpochMs: number; env?: NodeJS.ProcessEnv; stamp?: SessionHostStatusV1 }>,
): boolean {
  return sessionRecordOwnerLiveness(record, options.env) !== "dead";
}

/** Only positive owner-death evidence authorizes automatic reclamation. */
export function classifySessionRecordLiveness(
  record: SessionContainerRecordV2,
  options: Readonly<{ nowEpochMs: number; env?: NodeJS.ProcessEnv; stamp?: SessionHostStatusV1 }>,
): SessionRecordLiveness {
  const owner = sessionRecordOwnerLiveness(record, options.env);
  if (owner === "dead") {
    return Object.freeze({ kind: "stale", reason: "owning host process is gone" });
  }
  return Object.freeze({
    kind: "live",
    reason: owner === "alive"
      ? "owning host process is running"
      : "owning host process cannot be proved; advisory expiry does not authorize reclamation",
  });
}
