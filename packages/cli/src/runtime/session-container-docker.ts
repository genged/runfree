import path from "node:path";

import {
  SESSION_CONTAINER_CAPABILITY_DROPS,
  SESSION_CONTAINER_RESTART_POLICY,
  SESSION_CONTAINER_SECURITY_OPTIONS,
  SESSION_CONTAINER_STOP_SIGNAL,
  SESSION_CONTAINER_STOP_SECONDS,
  SESSION_CONTAINER_USER,
  type SessionContainerMount,
} from "./session-container-contract.ts";
import {
  assertSessionContainerCreatePlan,
  type SessionContainerCreatePlan,
} from "./session-container-template.ts";
import {
  assertSessionNamedVolumeProof,
  type SessionNamedVolumeProof,
} from "./session-named-volume-proof.ts";
import {
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  sessionContainerLabels,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

export {
  SESSION_CONTAINER_CAPABILITY_DROPS,
  SESSION_CONTAINER_RESTART_POLICY,
  SESSION_CONTAINER_SECURITY_OPTIONS,
  SESSION_CONTAINER_STOP_SIGNAL,
  SESSION_CONTAINER_STOP_SECONDS,
  SESSION_CONTAINER_USER,
};
export type { SessionContainerCreatePlan, SessionContainerMount };

const DOCKER_OBJECT_ID_PATTERN = /^[a-f0-9]{64}$/;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const FORBIDDEN_AGENT_MOUNT_TARGETS = [
  "/ca/private",
  "/run/runfree-approvals",
  "/run/runfree-proxy-secrets",
  "/run/runfree-sessions",
  "/run/docker.sock",
  "/var/run/docker.sock",
] as const;

declare const validatedSessionDockerCommandBrand: unique symbol;

export type SessionDockerCommand = {
  readonly [validatedSessionDockerCommandBrand]: true;
  executable: "docker";
  args: readonly string[];
  effect:
    | "create-session-container"
    | "inspect-session-container"
    | "start-attach-session-container"
    | "attach-session-container"
    | "inspect-session-network"
    | "disconnect-session-network"
    | "stop-session-container"
    | "remove-session-container";
  exactTarget?: string;
};

export type SessionDockerExecutor<T> = (executable: "docker", args: readonly string[]) => T;

const validatedCommands = new WeakSet<object>();
const createCommandPlans = new WeakMap<object, SessionContainerCreatePlan>();
const startAttachCommandRecords = new WeakMap<object, SessionContainerRecordV2>();
const attachCommandRecords = new WeakMap<object, SessionContainerRecordV2>();

function validatedCommand(
  command: Omit<SessionDockerCommand, typeof validatedSessionDockerCommandBrand>,
): SessionDockerCommand {
  const validated = Object.freeze({ ...command, args: Object.freeze([...command.args]) }) as SessionDockerCommand;
  validatedCommands.add(validated);
  return validated;
}

function validDockerObjectId(value: string, label: string): string {
  if (!DOCKER_OBJECT_ID_PATTERN.test(value)) throw new Error(`${label} must be an exact Docker object id`);
  return value;
}

function requireState(record: SessionContainerRecordV2, states: readonly SessionContainerRecordV2["state"][], operation: string): void {
  if (!states.includes(record.state)) {
    throw new Error(`${operation} is invalid while session-container state is ${record.state}`);
  }
}

function assertRecord(
  record: SessionContainerRecordV2,
  expected: SessionContainerProjectIdentity,
): void {
  if (!parseSessionContainerRecordV2(record)) throw new Error("session-container lifecycle record is invalid");
  assertSessionContainerRecordProject(record, expected);
}

function exactContainerId(record: SessionContainerRecordV2, override?: string): string {
  const selected = override ?? record.containerId;
  if (!selected) throw new Error("session-container lifecycle record has no exact container id");
  validDockerObjectId(selected, "session container id");
  if (record.containerId !== undefined && record.containerId !== selected) {
    throw new Error("session-container operation names a different container id");
  }
  return selected;
}

function normalizeMountTarget(value: string): string {
  if (!value.startsWith("/") || value.includes(",") || CONTROL_CHARACTER_PATTERN.test(value)) {
    throw new Error(`invalid session-container mount target: ${value || "<empty>"}`);
  }
  const normalized = path.posix.normalize(value).replace(/\/+$/u, "") || "/";
  if (normalized !== value) throw new Error(`session-container mount target must be canonical: ${value}`);
  for (const forbidden of FORBIDDEN_AGENT_MOUNT_TARGETS) {
    if (normalized === forbidden || normalized.startsWith(`${forbidden}/`)) {
      throw new Error(`session-container mount target is reserved: ${normalized}`);
    }
  }
  return normalized;
}

function mountArgument(mount: SessionContainerMount): string {
  if (mount.source.length === 0
    || mount.source !== mount.source.trim()
    || mount.source.includes(",")
    || mount.source.includes("${")
    || CONTROL_CHARACTER_PATTERN.test(mount.source)) {
    throw new Error("invalid session-container mount source");
  }
  if (mount.type === "bind" && (mount.source.endsWith("/docker.sock") || mount.source === "docker.sock")) {
    throw new Error("Docker control sockets cannot be mounted into a session container");
  }
  if (mount.type === "bind" && mount.noCopy) {
    throw new Error("session-container bind mounts cannot use volume-nocopy");
  }
  const target = normalizeMountTarget(mount.target);
  return [
    `type=${mount.type}`,
    `src=${mount.source}`,
    `dst=${target}`,
    ...(mount.readOnly ? ["readonly"] : []),
    ...(mount.type === "volume" && mount.noCopy ? ["volume-nocopy"] : []),
  ].join(",");
}

function validatedMountArguments(mounts: readonly SessionContainerMount[]): string[] {
  const targets = new Set<string>();
  const result: string[] = [];
  for (const mount of mounts) {
    const target = normalizeMountTarget(mount.target);
    if (targets.has(target)) throw new Error(`duplicate session-container mount target: ${target}`);
    targets.add(target);
    result.push("--mount", mountArgument(mount));
  }
  return result;
}

function validatedEnvironmentArguments(environment: Readonly<Record<string, string>>): string[] {
  return Object.entries(environment)
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([name, value]) => {
      if (!ENVIRONMENT_NAME_PATTERN.test(name)) {
        throw new Error(`invalid session-container environment name: ${name || "<empty>"}`);
      }
      if (CONTROL_CHARACTER_PATTERN.test(value)) {
        throw new Error(`invalid session-container environment value: ${name}`);
      }
      return ["--env", `${name}=${value}`];
    });
}

export function sessionContainerCreateCommand(
  plan: SessionContainerCreatePlan,
  namedVolumeProof: SessionNamedVolumeProof,
): SessionDockerCommand {
  assertSessionContainerCreatePlan(plan);
  assertSessionNamedVolumeProof(plan, namedVolumeProof);
  assertRecord(plan.record, plan.expectedProject);
  requireState(plan.record, ["allocated"], "session container creation");
  if (plan.record.containerId !== undefined) throw new Error("session container creation already has an exact container id");
  const labels = sessionContainerLabels(plan.record, plan.runfreeVersion);
  const labelArguments = Object.entries(labels).flatMap(([name, value]) => ["--label", `${name}=${value}`]);
  const command = validatedCommand({
    executable: "docker",
    effect: "create-session-container",
    args: [
      "container",
      "create",
      "--name",
      plan.record.containerName,
      "--network",
      plan.effectiveControlPlane.networkIds.agentInternal,
      "--ip",
      plan.record.sourceIp,
      "--user",
      SESSION_CONTAINER_USER,
      "--workdir",
      plan.template.workingDirectory,
      "--restart",
      SESSION_CONTAINER_RESTART_POLICY,
      "--no-healthcheck",
      ...(plan.launch.interactive ? ["--interactive"] : []),
      ...(plan.launch.tty ? ["--tty"] : []),
      ...SESSION_CONTAINER_SECURITY_OPTIONS.flatMap((option) => ["--security-opt", option]),
      ...SESSION_CONTAINER_CAPABILITY_DROPS.flatMap((capability) => ["--cap-drop", capability]),
      "--stop-signal",
      SESSION_CONTAINER_STOP_SIGNAL,
      "--entrypoint",
      plan.launch.path,
      ...labelArguments,
      ...validatedEnvironmentArguments(plan.environment),
      ...validatedMountArguments(plan.mounts),
      plan.record.selectedAgentImageId,
      ...plan.launch.args,
    ],
  });
  createCommandPlans.set(command, plan);
  return command;
}

export function assertSessionContainerCreateCommand(
  command: SessionDockerCommand,
  plan: SessionContainerCreatePlan,
): void {
  assertSessionContainerCreatePlan(plan);
  if (!validatedCommands.has(command)
    || command.effect !== "create-session-container"
    || createCommandPlans.get(command) !== plan) {
    throw new Error("refusing an unsealed or mismatched session container create command");
  }
}

export function parseCreatedSessionContainerId(stdout: string): string {
  const id = stdout.trim();
  return validDockerObjectId(id, "created session container id");
}

export function sessionContainerInspectCommand(
  record: SessionContainerRecordV2,
  expected: SessionContainerProjectIdentity,
  createdContainerId?: string,
): SessionDockerCommand {
  assertRecord(record, expected);
  const containerId = exactContainerId(record, createdContainerId);
  return validatedCommand({
    executable: "docker",
    effect: "inspect-session-container",
    exactTarget: containerId,
    args: ["container", "inspect", containerId],
  });
}

/**
 * Start precedes registration in the admission ladder, so this command is
 * gated only by the durable provisioning-running record: the container holds
 * no authority anywhere until registration and activation, and the single
 * post-start inspection is what activation spends.
 */
export function sessionContainerStartAttachCommand(
  record: SessionContainerRecordV2,
  expected: SessionContainerProjectIdentity,
): SessionDockerCommand {
  assertRecord(record, expected);
  requireState(record, ["provisioning-running"], "foreground session container start");
  const containerId = exactContainerId(record);
  const command = validatedCommand({
    executable: "docker",
    effect: "start-attach-session-container",
    exactTarget: containerId,
    args: [
      "container",
      "start",
      "--attach",
      ...(record.interactive ? ["--interactive"] : []),
      containerId,
    ],
  });
  const recordSnapshot = parseSessionContainerRecordV2(JSON.parse(serializeSessionContainerRecordV2(record)));
  if (!recordSnapshot) throw new Error("could not seal the foreground session lifecycle authority");
  startAttachCommandRecords.set(command, recordSnapshot);
  return command;
}

export function assertSessionContainerStartAttachCommand(
  command: SessionDockerCommand,
  record: SessionContainerRecordV2,
  expected: SessionContainerProjectIdentity,
): void {
  assertRecord(record, expected);
  requireState(record, ["provisioning-running"], "foreground session container start");
  const binding = startAttachCommandRecords.get(command);
  if (!binding || !validatedCommands.has(command) || command.effect !== "start-attach-session-container") {
    throw new Error("refusing an unsealed foreground session start command");
  }
  if (serializeSessionContainerRecordV2(binding) !== serializeSessionContainerRecordV2(record)) {
    throw new Error("foreground session start command belongs to a different lifecycle authority");
  }
}

/**
 * The identity one attach command may name.
 *
 * The re-attach caller holds a sealed foreground handle rather than a durable
 * record — the handle's lifecycle record was sealed at start and the record the
 * command was built from has since advanced to `attached` — so the two are
 * matched on the identity a re-attach may never change: this project, this
 * session incarnation, this container, and the same stdin contract.
 */
export type SessionContainerAttachIdentity = Readonly<{
  projectId: string;
  composeProject: string;
  sessionIncarnation: string;
  containerId: string;
  interactive: boolean;
}>;

/**
 * Re-attaches this host to a session container that is already running.
 *
 * Unlike the start above, this command starts nothing: the container is already
 * the admitted, proved, attached incarnation, and the only thing that ended is
 * this host's view of its output. So the state gate is `attached` — a session
 * that never reached it has no stream to lose — and the argv mirrors the
 * original `container start --attach` in the one way that matters to the person
 * at the terminal: signals are forwarded exactly as they were before the stream
 * was lost (no `--sig-proxy=false`), so Ctrl-C still reaches a non-interactive
 * agent and a re-attach never quietly takes the interrupt away.
 *
 * The one flag is `--no-stdin`: `docker container attach` binds the caller's
 * stdin by default, where `container start --attach` binds it only with
 * `--interactive`, so a session that was never launched interactively must say
 * so explicitly rather than have this host's stdin appear on its input.
 */
export function sessionContainerAttachCommand(
  record: SessionContainerRecordV2,
  expected: SessionContainerProjectIdentity,
): SessionDockerCommand {
  assertRecord(record, expected);
  requireState(record, ["attached"], "foreground session container attach");
  const containerId = exactContainerId(record);
  const command = validatedCommand({
    executable: "docker",
    effect: "attach-session-container",
    exactTarget: containerId,
    args: [
      "container",
      "attach",
      ...(record.interactive ? [] : ["--no-stdin"]),
      containerId,
    ],
  });
  const recordSnapshot = parseSessionContainerRecordV2(JSON.parse(serializeSessionContainerRecordV2(record)));
  if (!recordSnapshot) throw new Error("could not seal the foreground session lifecycle authority");
  attachCommandRecords.set(command, recordSnapshot);
  return command;
}

export function assertSessionContainerAttachCommand(
  command: SessionDockerCommand,
  identity: SessionContainerAttachIdentity,
): void {
  const binding = attachCommandRecords.get(command);
  if (!binding || !validatedCommands.has(command) || command.effect !== "attach-session-container") {
    throw new Error("refusing an unsealed foreground session attach command");
  }
  if (binding.projectId !== identity.projectId
    || binding.composeProject !== identity.composeProject
    || binding.sessionIncarnation !== identity.sessionIncarnation
    || binding.containerId !== identity.containerId
    || binding.interactive !== identity.interactive
    || command.exactTarget !== identity.containerId) {
    throw new Error("foreground session attach command belongs to a different lifecycle identity");
  }
}

export function sessionNetworkInspectCommand(networkId: string): SessionDockerCommand {
  validDockerObjectId(networkId, "session network id");
  return validatedCommand({
    executable: "docker",
    effect: "inspect-session-network",
    exactTarget: networkId,
    args: ["network", "inspect", networkId],
  });
}

/**
 * Judges one `docker container inspect` capture as proof the exact container
 * has already exited (L9). Fail-closed: any parse failure, id mismatch,
 * running/restarting state, or unexpected shape answers false and teardown
 * keeps today's SIGTERM+grace stop path.
 */
export function sessionContainerObservedExited(stdout: string, containerId: string): boolean {
  validDockerObjectId(containerId, "session container id");
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return false;
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) return false;
  const container = parsed[0];
  if (!container || typeof container !== "object") return false;
  const id = Reflect.get(container, "Id");
  if (id !== containerId) return false;
  const state = Reflect.get(container, "State");
  if (!state || typeof state !== "object") return false;
  return Reflect.get(state, "Running") === false && Reflect.get(state, "Restarting") !== true;
}

/**
 * The status the exact pinned container exited with, when one inspection proves
 * both the exit and the status.
 *
 * The same fail-closed judgement as `sessionContainerObservedExited`, plus the
 * status Docker recorded for it. `undefined` means "not proved" and never
 * "exited 0": a running or restarting container, a different container, a
 * missing or out-of-range status, and any parse deviation all answer
 * `undefined`, so no caller can report an exit this inspection did not carry.
 */
export function sessionContainerObservedExitStatus(stdout: string, containerId: string): number | undefined {
  if (!sessionContainerObservedExited(stdout, containerId)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed)) return undefined;
  const container = parsed[0];
  if (!container || typeof container !== "object") return undefined;
  const state = Reflect.get(container, "State");
  if (!state || typeof state !== "object") return undefined;
  const code = Reflect.get(state, "ExitCode");
  if (typeof code !== "number" || !Number.isSafeInteger(code) || code < 0 || code > 255) return undefined;
  return code;
}

export function executeSessionDockerCommand<T>(
  command: SessionDockerCommand,
  executor: SessionDockerExecutor<T>,
): T {
  if (!validatedCommands.has(command)) throw new Error("refusing an unvalidated session Docker command");
  return executor(command.executable, command.args);
}
