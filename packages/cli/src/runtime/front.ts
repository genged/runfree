// Cross-cutting runtime front shared by the typed runtime command modules.
//
// The legacy `runRuntime` string dispatcher intercepted `RUNFREE_RUNTIME_DRY_RUN`
// before its switch so every runtime command could be planned without touching
// Docker. The typed command modules call `runtimeDryRun` first to preserve that
// behavior: it prints the same plan JSON (keyed by the command name) and returns
// 0 when dry-run is active, otherwise undefined so the caller runs the real
// side effect. This is not an enforcement boundary — it only short-circuits
// host-side Docker work.

import { prepareDependencyOverlayPlan } from "./dependency-overlays.ts";
import { createRuntimePlan, runtimeDryRunOutput } from "./plan.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

export function runtimeDryRun(context: RuntimeContext, io: RuntimeIO, command: string): number | undefined {
  if (context.env?.RUNFREE_RUNTIME_DRY_RUN !== "1") return undefined;
  // The printed plan includes the materialization path and the topology and
  // generation digests, all derived from the overlay set. Discover it the way
  // startup does — Git ignore/track facts included — or dry run would report a
  // generation the real command will never create.
  const plan = createRuntimePlan(
    { ...context, dependencyOverlayPlan: prepareDependencyOverlayPlan(context, io) },
    { dockerSubnets: [], persistNetwork: false },
  );
  console.log(JSON.stringify(runtimeDryRunOutput(command, plan)));
  return 0;
}
