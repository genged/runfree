import * as childProcess from "node:child_process";

import type {
  SessionContainerForegroundSpawner,
} from "./session-container-start.ts";
import { performance } from "node:perf_hooks";

import { subprocessCategory, type OperationHistogram } from "./operation-histogram.ts";
import type { RuntimeIO } from "./types.ts";

export type SessionAdmissionDockerGateway = Readonly<{
  io: RuntimeIO;
  foregroundSpawner: SessionContainerForegroundSpawner;
  dockerOperationCount(): number;
}>;

function defaultForegroundSpawner(
  executable: "docker",
  args: readonly string[],
  options: Parameters<SessionContainerForegroundSpawner>[2],
): ReturnType<SessionContainerForegroundSpawner> {
  return childProcess.spawn(executable, [...args], options) as ReturnType<SessionContainerForegroundSpawner>;
}

/**
 * Counts Docker client operations at the one gateway used by the internal
 * admission driver. Clock reads, durable-state IO, and non-Docker child
 * processes are deliberately outside this metric.
 *
 * With an operation histogram (`RUNFREE_TIMINGS=1`), every counted operation
 * is also recorded under its verb-only category (`subprocessCategory`), so the
 * category counts always sum to `dockerOperationCount()`. The foreground start
 * is recorded for the time its spawn call took, not for the session's
 * lifetime. Categories carry no argv, ids, or env.
 */
export function createSessionAdmissionDockerGateway(input: Readonly<{
  io: RuntimeIO;
  foregroundSpawner?: SessionContainerForegroundSpawner;
  histogram?: OperationHistogram;
}>): SessionAdmissionDockerGateway {
  let operations = 0;
  const count = (): void => {
    if (operations === Number.MAX_SAFE_INTEGER) {
      throw new Error("session admission Docker operation count overflowed");
    }
    operations += 1;
  };
  const histogram = input.histogram;
  const counted = <T>(args: readonly string[], call: () => T): T => {
    count();
    if (!histogram) return call();
    const startedAt = performance.now();
    try {
      return call();
    } finally {
      histogram.record(subprocessCategory("docker", args), performance.now() - startedAt);
    }
  };
  const io: RuntimeIO = {
    ...input.io,
    run(command, args, options) {
      if (command !== "docker") return input.io.run(command, args, options);
      return counted(args, () => input.io.run(command, args, options));
    },
    capture(command, args, options) {
      if (command !== "docker") return input.io.capture(command, args, options);
      return counted(args, () => input.io.capture(command, args, options));
    },
  };
  const spawn = input.foregroundSpawner ?? defaultForegroundSpawner;
  const foregroundSpawner: SessionContainerForegroundSpawner = (executable, args, options) => (
    counted(args, () => spawn(executable, args, options))
  );
  return Object.freeze({
    io,
    foregroundSpawner,
    dockerOperationCount: () => operations,
  });
}
