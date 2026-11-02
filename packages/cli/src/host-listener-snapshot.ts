// Batched host listener observation (startup top-ten F29).
//
// The launch-time host-service warning loop (runtime/startup.ts,
// `refreshHostServicesAtLaunch`) used to run one listener query per approved
// host service. This module replaces that with exactly one bounded
// observation per launch, covering every TCP listener on the host at once,
// then answers each approved service's owner question from that single
// snapshot. `runfree host-service add`/`admitHostServicePort` and `runfree
// status`/`hostServiceOwnerWarnings` are unchanged: they keep probing one
// port at a time (host-service-port-owner.ts). How the host is read (lsof on
// macOS, /proc on Linux) lives behind `host-listener-probe.ts`.
//
// The snapshot is a point-in-time, best-effort diagnostic for the warning
// loop only: it never authorizes `admitHostServicePort`'s admission decision,
// and a snapshot read is never retained across launches.

import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { hostListenerProbe } from "./host-listener-probe.ts";
import { nodeProcFs, type ProcFs } from "./host-listener-proc.ts";
import {
  hostServiceWarningLines,
  type DockerPublishedPorts,
  type HiddenHostListener,
  type HostPortListener,
  type HostPortOwner,
} from "./host-service-port-owner.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";

export { LSOF_LISTENERS_ARGS, LSOF_LISTENERS_MAX_BUFFER_BYTES } from "./host-listener-lsof.ts";

export type HostListenerSnapshot =
  | {
    kind: "observed";
    byPort: ReadonlyMap<number, readonly HostPortListener[]>;
    /** Linux only: listening sockets no visible process holds, by port. */
    hiddenByPort?: ReadonlyMap<number, readonly HiddenHostListener[]>;
  }
  | { kind: "unavailable"; reason: string };

type ProbeContext = Pick<RuntimeContext, "env" | "projectRoot">;

/**
 * One bounded, read-only observation of every TCP listener on the host.
 * Replaces a per-port query with a single call whose result answers every
 * approved host service's owner question for this launch
 * (`hostPortOwnerFromSnapshot`). `platform` and `procFs` are test seams; the
 * defaults read this host.
 */
export function probeHostListeners(
  context: ProbeContext,
  io: RuntimeIO,
  platform: NodeJS.Platform = process.platform,
  procFs: ProcFs = nodeProcFs,
): HostListenerSnapshot {
  return hostListenerProbe(context, io, platform, procFs).snapshot();
}

/**
 * Answers the single-port owner question (`HostPortOwner`, the same shape
 * `probeHostPortOwner` returns) from a snapshot already taken, with no
 * further host read. An unavailable snapshot reports its own reason for
 * every port; a port with no visible listeners in the snapshot is `none`.
 */
export function hostPortOwnerFromSnapshot(snapshot: HostListenerSnapshot, port: number): HostPortOwner {
  if (snapshot.kind === "unavailable") return { kind: "unavailable", reason: snapshot.reason };
  const listeners = snapshot.byPort.get(port);
  if (!listeners || listeners.length === 0) {
    const hidden = snapshot.hiddenByPort?.get(port) ?? [];
    return hidden.length > 0 ? { kind: "none", hidden: [...hidden] } : { kind: "none" };
  }
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
 * instead of one query per service (F29). `published` is the launch's one
 * `docker ps` read (`readDockerPublishedPorts`), the published-port check on
 * every backend.
 */
export function hostServiceOwnerWarningsFromSnapshot(
  snapshot: HostListenerSnapshot,
  published: DockerPublishedPorts,
  services: HostServicesJson,
  recorded: ReadonlyMap<number, string>,
): string[] {
  return hostServiceWarningLines(services, recorded, (port) => hostPortOwnerFromSnapshot(snapshot, port), published);
}
