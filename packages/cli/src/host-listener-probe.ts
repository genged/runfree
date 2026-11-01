// The host listener check, behind one interface.
//
// Admission, the warnings, the launch snapshot, and the port registry are
// shared on every platform; only how the host's TCP listeners are read
// differs. macOS reads them with lsof (`host-listener-lsof.ts`, today's code),
// Linux from /proc (`host-listener-proc.ts`). Both return the same shapes:
// `HostPortOwner` for one port and `HostListenerSnapshot` for all of them.
// Any other platform is `unavailable`, which admission refuses.

import { lsofListenerSnapshot, lsofPortOwner } from "./host-listener-lsof.ts";
import { nodeProcFs, procListenerSnapshot, procPortOwner, type ProcFs } from "./host-listener-proc.ts";
import type { HostListenerSnapshot } from "./host-listener-snapshot.ts";
import type { HostPortOwner } from "./host-service-port-owner.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";

export type HostListenerProbe = Readonly<{
  /** Who listens on the host's TCP `port` (read-only, bounded). */
  portOwner(port: number): HostPortOwner;
  /** Every TCP listener on the host, in one bounded observation. */
  snapshot(): HostListenerSnapshot;
}>;

export const UNSUPPORTED_PLATFORM_LISTENER_REASON = "the host listener check needs macOS or Linux";

type ProbeContext = Pick<RuntimeContext, "env" | "projectRoot">;

export function hostListenerProbe(
  context: ProbeContext,
  io: RuntimeIO,
  platform: NodeJS.Platform = process.platform,
  procFs: ProcFs = nodeProcFs,
): HostListenerProbe {
  if (platform === "darwin") {
    return Object.freeze({
      portOwner: (port: number) => lsofPortOwner(context, io, port),
      snapshot: () => lsofListenerSnapshot(context, io),
    });
  }
  if (platform === "linux") {
    return Object.freeze({
      portOwner: (port: number) => procPortOwner(port, procFs),
      snapshot: () => procListenerSnapshot(procFs),
    });
  }
  const unavailable = { kind: "unavailable", reason: UNSUPPORTED_PLATFORM_LISTENER_REASON } as const;
  return Object.freeze({ portOwner: () => unavailable, snapshot: () => unavailable });
}
