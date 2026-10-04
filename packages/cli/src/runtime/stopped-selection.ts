import { clearEffectiveControlPlaneV2, readEffectiveControlPlaneSelectionV2 } from "./component-state-v2.ts";
import { readControlPlaneRebindTransaction } from "./control-plane-rebind.ts";
import { peekSessionContainerRecordsV2, type SessionContainerProjectIdentity } from "./session-containers.ts";
import type { DockerClient } from "./docker-client.ts";
import type { CaptureResult } from "./types.ts";

export type StoppedSelectionDeps = Readonly<{
  readSelection: typeof readEffectiveControlPlaneSelectionV2;
  peekRecords: typeof peekSessionContainerRecordsV2;
  readRebind: typeof readControlPlaneRebindTransaction;
  clearSelection: typeof clearEffectiveControlPlaneV2;
  /** One bounded Docker client; any failure or stderr is doubt. */
  docker: Pick<DockerClient, "listContainers" | "listObjects">;
  assertAuthority: () => void;
}>;

/**
 * `retained`: the selection still names live state (a forced stop left
 * sessions on the networks), which the next start rebinds. `unverified`: the
 * state or Docker could not answer, so nothing was proved either way.
 */
export type StoppedSelectionOutcome = "cleared" | "absent" | "retained" | "unverified";

const DEFAULT_DEPS = {
  readSelection: readEffectiveControlPlaneSelectionV2,
  peekRecords: peekSessionContainerRecordsV2,
  readRebind: readControlPlaneRebindTransaction,
  clearSelection: clearEffectiveControlPlaneV2,
} as const;

/**
 * After `runfree stop`'s Compose teardown, removes the effective control-plane
 * selection when Docker proves everything it names is gone.
 *
 * The selection names the proxy container and both network ids. A start that
 * finds a selection but no live proxy takes the compatible rebind, which
 * retains those networks for the sessions still on them. With no sessions,
 * `compose down` removes the networks too, so that rebind can only refuse
 * ("proxy creation inventory is unavailable") on every later start. Clearing
 * the stale selection, as destroy does after its teardown, sends the next start
 * down the ordinary fresh path.
 *
 * Fail-safe in one direction: anything short of proof keeps the selection and
 * leaves the next start exactly as it was. Live state (a lifecycle record, a
 * pending rebind journal, a surviving proxy or network) answers `retained`;
 * doubt (unreadable state, another project's selection, or a Docker read that
 * did not answer cleanly) answers `unverified`.
 */
export function clearStoppedControlPlaneSelection(
  stateDir: string,
  expectedProject: SessionContainerProjectIdentity,
  deps: Pick<StoppedSelectionDeps, "docker" | "assertAuthority"> & Partial<StoppedSelectionDeps>,
): StoppedSelectionOutcome {
  const { readSelection, peekRecords, readRebind, clearSelection, docker, assertAuthority } = { ...DEFAULT_DEPS, ...deps };
  assertAuthority();
  let selection: ReturnType<typeof readSelection>;
  let records: ReturnType<typeof peekRecords>;
  try {
    selection = readSelection(stateDir);
    if (!selection) return "absent";
    if (selection.projectId !== expectedProject.projectId || selection.composeProject !== expectedProject.composeProject) return "unverified";
    records = peekRecords(stateDir, expectedProject);
    if (records.unreadable > 0) return "unverified";
    if (records.records.length > 0) return "retained";
    if (readRebind(stateDir, expectedProject) !== undefined) return "retained";
  } catch {
    return "unverified";
  }
  /** Empty answer: proved absent. Listed: retained. Anything else: no proof. */
  const listing = (result: CaptureResult): "empty" | "listed" | "unverified" => {
    if (result.status !== 0 || result.stderr.trim() !== "") return "unverified";
    return result.stdout.trim() === "" ? "empty" : "listed";
  };
  for (const check of [
    () => docker.listContainers({ all: true, quiet: true, noTrunc: true, filters: [`id=${selection.proxyContainerId}`] }),
    () => docker.listObjects("network", { quiet: true, noTrunc: true, filters: [`id=${selection.networkIds.agentInternal}`] }),
    () => docker.listObjects("network", { quiet: true, noTrunc: true, filters: [`id=${selection.networkIds.proxyEgress}`] }),
  ]) {
    const answer = listing(check());
    if (answer !== "empty") return answer === "listed" ? "retained" : "unverified";
  }
  assertAuthority();
  clearSelection(stateDir);
  assertAuthority();
  return "cleared";
}
