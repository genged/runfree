// Batched host listener observation (startup top-ten F29).
//
// The launch-time host-service warning loop (runtime/startup.ts,
// `refreshHostServicesAtLaunch`) used to run one `lsof -iTCP:<port>` per
// approved host service. This module replaces that with exactly one bounded
// `lsof` observation per launch, covering every TCP listener on the host at
// once, then answers each approved service's owner question from that single
// snapshot. `runfree host-service add`/`admitHostServicePort` and `runfree
// status`/`hostServiceOwnerWarnings` are unchanged: they keep probing one
// port at a time (host-service-port-owner.ts).
//
// The snapshot is a point-in-time, best-effort diagnostic for the warning
// loop only: it never authorizes `admitHostServicePort`'s admission decision,
// and a snapshot read is never retained across launches.

import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { sanitizedHostExecutionEnv } from "./host-path.ts";
import {
  hostServiceWarningLines,
  parseLsofProcessRecords,
  printableCommand,
  LSOF_PATH,
  LSOF_TIMEOUT_MS,
  type HostPortListener,
  type HostPortOwner,
} from "./host-service-port-owner.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";

export type HostListenerSnapshot =
  | { kind: "observed"; byPort: ReadonlyMap<number, readonly HostPortListener[]> }
  | { kind: "unavailable"; reason: string };

// Bounded single observation (F29): one call, this cap, this timeout. An
// explicit cap rather than relying on Node's own default, so the bound is a
// read fact of this module, not an implicit runtime default that could
// silently change. A real overrun fails the whole snapshot closed (the
// underlying spawn's own ENOBUFS handling reports a non-zero `status`; see
// runtime/spawn-status.ts), never a trusted partial read.
export const LSOF_LISTENERS_MAX_BUFFER_BYTES = 1024 * 1024;

// `-nP`: no hostname/port-name resolution. `+c 0`: full process names. No
// `-iTCP:<port>`: every TCP listener on the host, in one call. `-sTCP:LISTEN`:
// listening sockets only. `-Fpcn`: pid, command, and each listen address.
export const LSOF_LISTENERS_ARGS = ["-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN", "-Fpcn"];

type ProbeContext = Pick<RuntimeContext, "env" | "projectRoot">;

const PORT_SUFFIX_RE = /:(\d{1,5})$/u;

function buildSnapshot(stdout: string): HostListenerSnapshot {
  const parsed = parseLsofProcessRecords(stdout);
  if (!Array.isArray(parsed)) return { kind: "unavailable", reason: parsed.reason };
  const byPort = new Map<number, HostPortListener[]>();
  for (const record of parsed) {
    // One process can hold listeners on several ports (and several addresses
    // on the same port); group this record's addresses by their own port
    // before merging into the snapshot, so each port's entry looks exactly
    // like a single-port `lsof -iTCP:<port>` query would have reported it.
    const addressesByPort = new Map<number, string[]>();
    for (const address of record.addresses) {
      const match = PORT_SUFFIX_RE.exec(address);
      if (!match) return { kind: "unavailable", reason: `lsof reported a listen address with no parsable port: ${address}` };
      const port = Number(match[1]);
      const addresses = addressesByPort.get(port) ?? [];
      addresses.push(address);
      addressesByPort.set(port, addresses);
    }
    for (const [port, addresses] of addressesByPort) {
      const listeners = byPort.get(port) ?? [];
      listeners.push({ command: record.command, pid: record.pid, addresses });
      byPort.set(port, listeners);
    }
  }
  return { kind: "observed", byPort };
}

/**
 * One bounded, read-only observation of every TCP listener on the host
 * (macOS only; Docker Desktop for Mac). Replaces a per-port `lsof` call with
 * a single call whose result answers every approved host service's owner
 * question for this launch (`hostPortOwnerFromSnapshot`).
 */
export function probeHostListeners(
  context: ProbeContext,
  io: RuntimeIO,
  platform: NodeJS.Platform = process.platform,
): HostListenerSnapshot {
  if (platform !== "darwin") {
    return { kind: "unavailable", reason: "the host listener check needs macOS (Docker Desktop for Mac)" };
  }
  const result = io.capture(LSOF_PATH, LSOF_LISTENERS_ARGS, {
    encoding: "utf8",
    timeout: LSOF_TIMEOUT_MS,
    maxBuffer: LSOF_LISTENERS_MAX_BUFFER_BYTES,
    env: { ...sanitizedHostExecutionEnv(context.projectRoot, context.env ?? process.env), LC_ALL: "C" },
  });
  // lsof exits 1 both for "no match" and for errors; only a silent exit 1 is
  // an answer (no TCP listener anywhere on the host). Anything on stderr
  // makes the result unknown, never a clean "nothing listens".
  if (result.status === 1 && result.stdout.trim() === "" && result.stderr.trim() === "") {
    return { kind: "observed", byPort: new Map() };
  }
  if (result.status !== 0) {
    const detail = result.timedOut ? "timed out" : `exited with status ${result.status}`;
    const stderr = printableCommand(result.stderr.trim());
    return { kind: "unavailable", reason: `the host listener check (lsof) ${detail}${stderr ? `: ${stderr}` : ""}` };
  }
  return buildSnapshot(result.stdout);
}

/**
 * Answers the single-port owner question (`HostPortOwner`, the same shape
 * `probeHostPortOwner` returns) from a snapshot already taken, with no
 * further `lsof` call. An unavailable snapshot reports its own reason for
 * every port; a port with no listeners in the snapshot is `none`.
 */
export function hostPortOwnerFromSnapshot(snapshot: HostListenerSnapshot, port: number): HostPortOwner {
  if (snapshot.kind === "unavailable") return { kind: "unavailable", reason: snapshot.reason };
  const listeners = snapshot.byPort.get(port);
  if (!listeners || listeners.length === 0) return { kind: "none" };
  const first = listeners[0] as HostPortListener;
  return {
    kind: "listener",
    command: first.command,
    pid: first.pid,
    count: listeners.length,
    commands: listeners.map((entry) => entry.command),
    listeners: listeners as HostPortListener[],
  };
}

/**
 * The launch-time half of the host-service re-check (design "Policy shape",
 * Re-check, SR13): the same warning lines `hostServiceOwnerWarnings` would
 * produce for the same observed owners (shared core,
 * `hostServiceWarningLines`), but answered from one already-taken snapshot
 * instead of one `lsof` call per service (F29).
 */
export function hostServiceOwnerWarningsFromSnapshot(
  snapshot: HostListenerSnapshot,
  services: HostServicesJson,
  recorded: ReadonlyMap<number, string>,
): string[] {
  return hostServiceWarningLines(services, recorded, (port) => hostPortOwnerFromSnapshot(snapshot, port));
}
