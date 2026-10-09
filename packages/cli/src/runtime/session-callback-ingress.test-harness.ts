// A small in-memory Docker for the session callback ingress tests: it keeps
// the project's containers and answers exactly the calls the callback
// lifecycle makes, recording every argv so tests can assert effects.

import { vi } from "vitest";

import {
  INGRESS_FORWARDER_TEST_IMAGE_ID,
  INGRESS_HOST_NETWORK_TEST_ID,
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  missingContainerResult,
  missingNetworkResult,
} from "./ingress-forwarder.test-harness.ts";
import type { CaptureResult, DockerContainerInspect, RuntimeIO } from "./types.ts";

export const TEST_SESSION_ID = "rf-20260930-abcdef";
export const TEST_SESSION_CONTAINER_ID = "c".repeat(64);
export const TEST_SESSION_IP = "172.30.0.40";
export const TEST_FORWARDER_INTERNAL_IP = "172.30.0.31";

export type FakeDockerOptions = {
  /** Host ports whose `docker run` publication conflicts. */
  conflictingPorts?: Set<number>;
  /** Whether a conflicting run leaves its created container behind. */
  conflictLeavesResidue?: boolean;
  /** A `docker run` failure that is not a publication conflict. */
  runFailure?: string;
  listFailure?: boolean;
  /** A `docker network connect` failure. */
  connectFailure?: string;
  removeFailure?: boolean;
  bridgeStatus?: number;
  /**
   * Host loopback publications shared across fakes (one per project), the
   * way Docker's port bindings are host-global: a `docker run -p` for a port
   * already in the set conflicts, a successful run adds its port, and
   * removing that forwarder frees it.
   */
  publishedPorts?: Set<number>;
  /** Yield to the event loop before each async capture answers, so concurrent callers interleave. */
  asyncYield?: boolean;
};

let nextId = 0;
function fakeContainerId(): string {
  nextId += 1;
  return nextId.toString(16).padStart(64, "a");
}

function ok(stdout = ""): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

export function sessionAgentInspect(input: Readonly<{
  composeProject: string;
  projectId: string;
  containerId?: string;
  sessionId?: string;
  ip?: string;
  running?: boolean;
}>): DockerContainerInspect {
  const containerId = input.containerId ?? TEST_SESSION_CONTAINER_ID;
  return {
    Config: {
      Labels: {
        "io.runfree.project-id": input.projectId,
        "io.runfree.container-role": "session-agent",
        "io.runfree.session-id": input.sessionId ?? TEST_SESSION_ID,
      },
    },
    Id: containerId,
    Name: `/session-${containerId.slice(0, 8)}`,
    State: { Running: input.running ?? true },
    NetworkSettings: {
      Networks: { [`${input.composeProject}_agent_internal`]: { IPAddress: input.ip ?? TEST_SESSION_IP } },
    },
  };
}

export function boundCallbackForwarder(input: Readonly<{
  composeProject: string;
  projectId: string;
  hostPort: string;
  containerId?: string;
  sessionId?: string | null;
  sessionContainerId?: string;
  target?: string;
  running?: boolean;
}>): DockerContainerInspect {
  const base = ingressForwarderInspectFixture({
    composeProject: input.composeProject,
    ...(input.containerId ? { containerId: input.containerId } : {}),
    hostPort: input.hostPort,
    projectId: input.projectId,
    purpose: "mcp-callback",
    target: input.target ?? TEST_SESSION_IP,
  });
  const binding = input.sessionId === null ? [] : [
    `RUNFREE_CALLBACK_SESSION_ID=${input.sessionId ?? TEST_SESSION_ID}`,
    `RUNFREE_CALLBACK_SESSION_CONTAINER=${input.sessionContainerId ?? TEST_SESSION_CONTAINER_ID}`,
  ];
  return {
    ...base,
    Config: { ...base.Config, Env: [...(base.Config?.Env ?? []), ...binding] },
    State: { Running: input.running ?? true },
  };
}

export function createFakeDocker(input: Readonly<{
  projectId: string;
  composeProject: string;
  containers?: DockerContainerInspect[];
  options?: FakeDockerOptions;
}>) {
  const options = input.options ?? {};
  const containers: DockerContainerInspect[] = [...(input.containers ?? [])];
  const captures: string[][] = [];
  const runs: string[][] = [];
  /** Every Docker argv in call order, captured or run, sync or async. */
  const sequence: string[][] = [];
  let hostNetwork = false;
  const byRef = (ref: string) => containers.find((container) => container.Id === ref || container.Name === `/${ref}`);
  const envValue = (args: string[], key: string) => {
    for (let index = 0; index < args.length; index += 1) {
      if (args[index] === "-e" && args[index + 1]?.startsWith(`${key}=`)) return args[index + 1]?.slice(key.length + 1);
    }
    return undefined;
  };

  const answer = (_command: string, rawArgs: readonly string[], _options?: unknown): CaptureResult => {
    const args = [...rawArgs];
    captures.push(args);
    sequence.push(args);
    if (args[0] === "ps") {
      if (options.listFailure) return { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" };
      const filters = args.filter((_, index) => args[index - 1] === "--filter");
      const running = !args.includes("--all");
      const matches = containers.filter((container) => {
        if (running && container.State?.Running !== true) return false;
        return filters.every((filter) => {
          const [, pair] = filter.split("label=");
          if (!pair) return true;
          const [key, value] = pair.split("=");
          return container.Config?.Labels?.[key as string] === value;
        });
      });
      return ok(matches.map((container) => container.Id).join("\n"));
    }
    if (args[0] === "container" && args[1] === "inspect") {
      const refs = args.slice(2);
      const found = refs.map(byRef);
      if (found.some((container) => container === undefined)) return missingContainerResult(refs[found.findIndex((c) => !c)] as string);
      return ok(JSON.stringify(found));
    }
    if (args[0] === "image" && args[1] === "inspect") return ok(`${INGRESS_FORWARDER_TEST_IMAGE_ID}\n`);
    if (args[0] === "network" && args[1] === "inspect") {
      if (!hostNetwork) return missingNetworkResult(args[2] as string);
      const network = ingressHostNetworkInspectFixture(input.projectId);
      const attached = containers.filter((container) => container.Config?.Labels?.["io.runfree.container-role"] === "ingress-forwarder");
      return ok(JSON.stringify([{ ...network, Containers: Object.fromEntries(attached.map((container) => [container.Id, {}])) }]));
    }
    if (args[0] === "network" && args[1] === "create") {
      hostNetwork = true;
      return ok(INGRESS_HOST_NETWORK_TEST_ID);
    }
    if (args[0] === "network" && args[1] === "connect") {
      return options.connectFailure ? { status: 1, stdout: "", stderr: options.connectFailure } : ok();
    }
    if (args[0] === "run") {
      const hostPort = envValue(args, "INGRESS_HOST_PORT") as string;
      if (options.runFailure) return { status: 125, stdout: "", stderr: options.runFailure };
      const created = boundCallbackForwarder({
        composeProject: input.composeProject,
        projectId: input.projectId,
        hostPort,
        containerId: fakeContainerId(),
        sessionId: envValue(args, "RUNFREE_CALLBACK_SESSION_ID") ?? null,
        sessionContainerId: envValue(args, "RUNFREE_CALLBACK_SESSION_CONTAINER") ?? "",
        target: envValue(args, "INGRESS_TARGET") ?? "",
      });
      if (options.conflictingPorts?.has(Number(hostPort)) || options.publishedPorts?.has(Number(hostPort))) {
        if (options.conflictLeavesResidue) containers.push({ ...created, State: { Running: false } });
        return {
          status: 125,
          stdout: "",
          stderr: `docker: Error response from daemon: driver failed programming external connectivity: Bind for 127.0.0.1:${hostPort} failed: port is already allocated.`,
        };
      }
      containers.push(created);
      options.publishedPorts?.add(Number(hostPort));
      return ok(`${created.Id}\n`);
    }
    if (args[0] === "exec") return ok();
    if (args[0] === "container" && args[1] === "rm") {
      if (options.removeFailure) return { status: 1, stdout: "", stderr: "Error response from daemon: removal in progress" };
      const ref = args[args.length - 1] as string;
      const index = containers.findIndex((container) => container.Id === ref || container.Name === `/${ref}`);
      if (index < 0) return missingContainerResult(ref);
      const [gone] = containers.splice(index, 1);
      if (gone?.State?.Running === true) {
        const port = gone.Config?.Env?.find((entry) => entry.startsWith("INGRESS_HOST_PORT="))?.slice("INGRESS_HOST_PORT=".length);
        if (port !== undefined) options.publishedPorts?.delete(Number(port));
      }
      return ok(ref);
    }
    return ok();
  };
  const capture = vi.fn(answer);
  // A separate mock, so a test can tell (and fail) the synchronous path apart
  // from the overlapped one.
  const captureAsync = vi.fn(async (command: string, args: readonly string[], callOptions?: unknown): Promise<CaptureResult> => {
    if (options.asyncYield) await new Promise((resolve) => setImmediate(resolve));
    return answer(command, args, callOptions);
  });
  const run = vi.fn((_command: string, rawArgs: readonly string[]) => {
    runs.push([...rawArgs]);
    sequence.push([...rawArgs]);
    return options.bridgeStatus ?? 0;
  });
  return {
    io: { capture, run, captureAsync } as unknown as RuntimeIO,
    containers,
    captures,
    runs,
    sequence,
    removed: () => captures.filter((args) => args[0] === "container" && args[1] === "rm").map((args) => args[args.length - 1] as string),
    dockerRuns: () => captures.filter((args) => args[0] === "run"),
  };
}
