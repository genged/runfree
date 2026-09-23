import * as childProcess from "node:child_process";

import type {
  SessionContainerForegroundSpawner,
} from "./session-container-start.ts";
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
 */
export function createSessionAdmissionDockerGateway(input: Readonly<{
  io: RuntimeIO;
  foregroundSpawner?: SessionContainerForegroundSpawner;
}>): SessionAdmissionDockerGateway {
  let operations = 0;
  const count = (): void => {
    if (operations === Number.MAX_SAFE_INTEGER) {
      throw new Error("session admission Docker operation count overflowed");
    }
    operations += 1;
  };
  const io: RuntimeIO = {
    ...input.io,
    run(command, args, options) {
      if (command === "docker") count();
      return input.io.run(command, args, options);
    },
    capture(command, args, options) {
      if (command === "docker") count();
      return input.io.capture(command, args, options);
    },
  };
  const spawn = input.foregroundSpawner ?? defaultForegroundSpawner;
  const foregroundSpawner: SessionContainerForegroundSpawner = (executable, args, options) => {
    count();
    return spawn(executable, args, options);
  };
  return Object.freeze({
    io,
    foregroundSpawner,
    dockerOperationCount: () => operations,
  });
}
