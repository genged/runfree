import {
  activeAgentSessions,
} from "./sessions.ts";
import {
  createRuntimeDocker,
  type RuntimeDocker,
} from "./docker.ts";
import type { RuntimeAdminIntent, RuntimeContext, RuntimeIO } from "./types.ts";

export type RuntimeAdapters = {
  admin(intent: RuntimeAdminIntent): Promise<number>;
  docker: RuntimeDocker;
};

export function createRuntimeAdapters(context: RuntimeContext, io: RuntimeIO): RuntimeAdapters {
  return {
    admin: (intent) => io.admin(intent, context),
    docker: createRuntimeDocker(context, io, (project) => activeAgentSessions(project, context, io)),
  };
}
