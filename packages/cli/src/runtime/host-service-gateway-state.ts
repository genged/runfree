// The host-service gateway the root firewall supervisor published (design
// "Approval and CLI", HS8): the pinned address, or the sticky reason it
// withholds one (for example `gateway address changed`, reclaimed by
// `runfree rebuild`). Read through a root exec of the running proxy, as the
// other proxy status reads are. Observation only, shared by `runfree status`
// and the launch's host-service re-check so a withheld gateway is said at
// launch, not only when someone asks for status.

import { parseHostServiceGatewayStatus } from "@runfree/runtime-contracts/proxy-status";

import { ROOT_UID_GID } from "./constants.ts";
import { createDockerClient } from "./docker-client.ts";
import { dockerClientEnvOptions, serviceContainerId } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import { PROXY_HOST_SERVICE_GATEWAY_STATUS_PATH } from "./probes.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

export type HostServiceGatewayState =
  | { kind: "available"; gatewayIp: string }
  | { kind: "unavailable"; reason: string }
  | { kind: "not-running" }
  | { kind: "unknown"; detail: string };

export function readHostServiceGatewayState(context: RuntimeContext, io: RuntimeIO): HostServiceGatewayState {
  const proxyId = serviceContainerId(composeProjectName(context.projectRoot), "proxy", context, io, { runningOnly: true });
  if (!proxyId) return { kind: "not-running" };
  const read = createDockerClient(io, dockerClientEnvOptions(context))
    .exec(proxyId, ["cat", PROXY_HOST_SERVICE_GATEWAY_STATUS_PATH], { user: ROOT_UID_GID });
  if (read.status !== 0) {
    return { kind: "unknown", detail: `reading the proxy's gateway status failed (exit ${read.status})` };
  }
  try {
    const status = parseHostServiceGatewayStatus(read.stdout);
    if (status.gatewayIp !== undefined) return { kind: "available", gatewayIp: status.gatewayIp };
    return { kind: "unavailable", reason: status.unavailableReason ?? "unknown reason" };
  } catch (error) {
    return { kind: "unknown", detail: `the proxy's gateway status is malformed: ${error instanceof Error ? error.message : String(error)}` };
  }
}
