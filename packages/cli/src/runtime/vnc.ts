import crypto from "node:crypto";

import { die } from "../errors.ts";
import { resolveAgentExecTarget } from "./agent-exec-target.ts";
import { AGENT_UID_GID } from "./constants.ts";
import { createRuntimeDocker, dockerClientEnvOptions } from "./docker.ts";
import { captureDockerListing, renderDockerListing } from "./docker-listing.ts";
import { composeProjectName, projectHash } from "./env.ts";
import {
  ingressForwarderName,
  listIngressForwarders,
} from "./ingress-forwarder.ts";
import {
  removeValidatedIngressForwarders,
  replaceValidatedIngressForwarder,
} from "./ingress-forwarder-ownership.ts";
import type { RuntimeAdapters } from "./adapters.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";
import { remedy } from "../remedies.ts";

// VNC forwards are ingress forwarders carrying ingress-purpose=vnc, created
// through the shared ingress facility.
const VNC_PURPOSE = "vnc" as const;
const DEFAULT_VNC_PORT = "5901";
const VNC_USAGE = "usage: runfree vnc [start|stop|restart|status] "
  + "[--host-port PORT] [--agent-port PORT] [--display :0] "
  + "[--password PASSWORD | --no-password] [--clipboard] [--no-start-server]";

// Runs inside the agent container; VNC_PORT is validated as numeric before injection.
const LISTENING_SCRIPT = `
if command -v ss >/dev/null 2>&1; then
  ss -ltn
elif command -v netstat >/dev/null 2>&1; then
  netstat -ltn
else
  exit 2
fi | awk '{print $4}' | grep -Eq "[:.]\${VNC_PORT}\$"
`;

// Clipboard exchange with the untrusted display is off unless explicitly enabled.
const X11VNC_SCRIPT = `
set -eu
log="/tmp/x11vnc-\${VNC_PORT}.log"
sel_args="-nosel"
if [ "\${VNC_CLIPBOARD:-0}" = "1" ]; then sel_args=""; fi
if [ -n "\${VNC_PASSWORD:-}" ]; then
  exec x11vnc -display "$VNC_DISPLAY" -rfbport "$VNC_PORT" -forever -shared $sel_args -passwd "$VNC_PASSWORD" -o "$log"
fi
exec x11vnc -display "$VNC_DISPLAY" -rfbport "$VNC_PORT" -forever -shared $sel_args -nopw -o "$log"
`;

export type VncAction = "start" | "stop" | "restart" | "status";

export type VncOptions = {
  action: VncAction;
  hostPort: string;
  hostPortExplicit: boolean;
  agentPort: string;
  display: string;
  password: string;
  clipboard: boolean;
  startServer: boolean;
};

function generatedPassword(): string {
  // x11vnc/RFB passwords only use the first 8 characters.
  return crypto.randomBytes(6).toString("base64url").slice(0, 8);
}

function parsedPort(value: string | undefined, flag: string): string {
  if (!value) die(`${flag} requires a value`);
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
    die(`${flag} must be a port number between 1 and 65535`);
  }
  // Canonical decimal: the host port becomes the ingress forwarder's identity
  // (its name), so equivalent spellings must not name different forwarders.
  return String(Number(value));
}

function validatedDisplay(value: string | undefined): string {
  if (!value || !/^[A-Za-z0-9_.:-]+$/.test(value)) die("--display requires a value like :0");
  return value;
}

export function parseVncArgs(args: string[], env: NodeJS.ProcessEnv = {}): VncOptions {
  const options: VncOptions = {
    action: "start",
    hostPort: DEFAULT_VNC_PORT,
    hostPortExplicit: false,
    agentPort: DEFAULT_VNC_PORT,
    display: ":0",
    password: env.RUNFREE_VNC_PASSWORD ?? generatedPassword(),
    clipboard: false,
    startServer: true,
  };

  let index = 0;
  const first = args[0];
  if (first === "start" || first === "stop" || first === "restart" || first === "status") {
    options.action = first;
    index = 1;
  } else if (first !== undefined && !first.startsWith("--")) {
    die(VNC_USAGE);
  }

  for (; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--host-port":
        options.hostPort = parsedPort(args[index + 1], arg);
        options.hostPortExplicit = true;
        index += 1;
        break;
      case "--agent-port":
        options.agentPort = parsedPort(args[index + 1], arg);
        index += 1;
        break;
      case "--display": {
        options.display = validatedDisplay(args[index + 1]);
        index += 1;
        break;
      }
      case "--password": {
        const value = args[index + 1];
        if (value === undefined) die("--password requires a value");
        options.password = value;
        index += 1;
        break;
      }
      case "--no-password":
        options.password = "";
        break;
      case "--clipboard":
        options.clipboard = true;
        break;
      case "--no-start-server":
        options.startServer = false;
        break;
      default:
        die(`unknown vnc option: ${arg}\n${VNC_USAGE}`);
    }
  }

  return options;
}

// Typed input shape produced by the yargs vnc command module. The grammar
// (action enum, flag names, requiresArg) is validated by yargs; this builder
// re-validates the value shapes (port range, display) exactly as parseVncArgs
// does and applies the same env/default precedence.
export type VncArgs = {
  action?: VncAction;
  "host-port"?: string;
  "agent-port"?: string;
  display?: string;
  password?: string;
  "no-password"?: boolean;
  clipboard?: boolean;
  "no-start-server"?: boolean;
};

export function vncOptionsFromArgs(argv: VncArgs, env: NodeJS.ProcessEnv = {}): VncOptions {
  return {
    action: argv.action ?? "start",
    hostPort: argv["host-port"] !== undefined ? parsedPort(argv["host-port"], "--host-port") : DEFAULT_VNC_PORT,
    hostPortExplicit: argv["host-port"] !== undefined,
    agentPort: argv["agent-port"] !== undefined ? parsedPort(argv["agent-port"], "--agent-port") : DEFAULT_VNC_PORT,
    display: argv.display !== undefined ? validatedDisplay(argv.display) : ":0",
    // --no-password forces an empty password; otherwise an explicit --password,
    // else the env seed, else a generated one (matches parseVncArgs precedence).
    password: argv["no-password"] ? "" : (argv.password ?? env.RUNFREE_VNC_PASSWORD ?? generatedPassword()),
    clipboard: Boolean(argv.clipboard),
    startServer: !argv["no-start-server"],
  };
}

function docker(context: RuntimeContext, io: RuntimeIO, args: string[]): CaptureResult {
  return io.capture("docker", args, dockerClientEnvOptions(context));
}

function networkExists(context: RuntimeContext, io: RuntimeIO, name: string): boolean {
  return docker(context, io, ["network", "inspect", name]).status === 0;
}

type VncTarget = Readonly<{
  /** What `docker exec` addresses to bootstrap x11vnc. */
  execTarget: string;
  /** What the socat forwarder connects to on the internal network. */
  forwardTarget: string;
}>;

/**
 * The container VNC serves, resolved through the one typed answer to "which
 * container is the agent".
 *
 * The resolver returns the one live attached session. Exec addresses its
 * exact container id, and the forwarder targets its fixed
 * internal address — sessions are admitted by source IP, so the address is
 * the identity the admission machinery already binds, where a name would
 * lean on Docker DNS. The resolver's own refusals (a partially legible
 * registry, more than one live session) surface as exact `die` messages.
 */
function resolveVncTarget(
  project: string,
  projectId: string,
  context: RuntimeContext,
  io: RuntimeIO,
): VncTarget {
  let resolved: ReturnType<typeof resolveAgentExecTarget>;
  try {
    resolved = resolveAgentExecTarget(project, createRuntimeDocker(context, io), {
      sessionRegistry: { stateDir: context.project.paths.stateDir, projectId },
    });
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
  if (!resolved) {
    die("no running agent container or live session for this project - try 'runfree up' first");
  }
  return { execTarget: resolved.containerId, forwardTarget: resolved.sourceIp };
}

function agentPortListening(context: RuntimeContext, io: RuntimeIO, agent: string, agentPort: string): boolean {
  return docker(context, io, [
    "exec",
    "-e",
    `VNC_PORT=${agentPort}`,
    agent,
    "sh",
    "-c",
    LISTENING_SCRIPT,
  ]).status === 0;
}

async function ensureAgentVncServer(
  context: RuntimeContext,
  io: RuntimeIO,
  agent: string,
  options: VncOptions,
  delay: (ms: number) => Promise<void>,
): Promise<void> {
  if (agentPortListening(context, io, agent, options.agentPort)) {
    console.log(`x11vnc is already listening in ${agent} on port ${options.agentPort}`);
    return;
  }

  const probe = docker(context, io, ["exec", agent, "sh", "-c", "command -v x11vnc >/dev/null 2>&1"]);
  if (probe.status !== 0) {
    die("x11vnc not found in the agent image; add x11vnc and an X server (for example xvfb) "
      + `to .runfree/image/Dockerfile and run \`${remedy.rebuild()}\``);
  }

  console.log(`starting x11vnc in ${agent} on port ${options.agentPort}`);
  const started = docker(context, io, [
    "exec",
    "-u",
    AGENT_UID_GID,
    "-e",
    `VNC_PORT=${options.agentPort}`,
    "-e",
    `VNC_PASSWORD=${options.password}`,
    "-e",
    `VNC_DISPLAY=${options.display}`,
    "-e",
    `VNC_CLIPBOARD=${options.clipboard ? "1" : "0"}`,
    "-d",
    agent,
    "sh",
    "-c",
    X11VNC_SCRIPT,
  ]);
  if (started.status !== 0) die(started.stderr.trim() || "failed to start x11vnc in the agent container");

  for (let attempt = 0; attempt < 10; attempt += 1) {
    if (agentPortListening(context, io, agent, options.agentPort)) return;
    await delay(500);
  }
  die(`x11vnc did not start on agent port ${options.agentPort}; check /tmp/x11vnc-${options.agentPort}.log in ${agent}`);
}

// This project's VNC forwards: ingress forwarders carrying
// ingress-purpose=vnc, created through the facility.
function newVncForwarders(context: RuntimeContext, io: RuntimeIO, projectId: string): string[] {
  const prefix = ingressForwarderName(projectId, VNC_PURPOSE, "");
  return listIngressForwarders(context, io, projectId).filter((name) => name.startsWith(prefix));
}

// Typed core for `runfree vnc`. Receives validated VncOptions (from parseVncArgs
// or the yargs vncOptionsFromArgs builder) and performs no argument parsing.
export async function vncRuntime(
  options: VncOptions,
  context: RuntimeContext,
  io: RuntimeIO,
  adapters: RuntimeAdapters,
  delay: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
): Promise<number> {
  adapters.docker.assertAvailable();
  const projectId = projectHash(context.projectRoot);
  const project = composeProjectName(context.projectRoot);

  switch (options.action) {
    case "status": {
      const forwarders = newVncForwarders(context, io, projectId);
      if (forwarders.length === 0) {
        console.log("no vnc forward sidecar found");
        return 0;
      }
      const filters = forwarders.flatMap((name) => ["--filter", `name=^/${name}$`]);
      const listing = captureDockerListing(io, ["ps", "-a", ...filters], dockerClientEnvOptions(context), "vnc forwards");
      if (listing.status !== 0) return listing.status;
      if (listing.rows.length === 0) {
        console.log("no vnc forward sidecar found");
        return 0;
      }
      console.log(renderDockerListing([
        { label: "NAME", value: (row) => row.Names },
        { label: "STATUS", value: (row) => row.Status },
        { label: "NETWORKS", value: (row) => row.Networks },
        { label: "PORTS", value: (row) => row.Ports },
      ], listing.rows));
      return 0;
    }
    case "stop": {
      // Stop the forwarder for this port (or all of them). The removal skips a
      // name that is absent, so an empty runtime works.
      const targets = options.hostPortExplicit
        ? [ingressForwarderName(projectId, VNC_PURPOSE, options.hostPort)]
        : newVncForwarders(context, io, projectId);
      for (const name of targets) console.log(`stopping vnc forward: ${name}`);
      const removed = removeValidatedIngressForwarders(context, io, projectId, targets);
      if (removed === 0) console.log("no vnc forward sidecar found");
      return 0;
    }
    case "start":
    case "restart": {
      const target = resolveVncTarget(project, projectId, context, io);
      const internalNetwork = `${project}_agent_internal`;
      if (!networkExists(context, io, internalNetwork)) {
        die(`agent network not found: ${internalNetwork} - try 'runfree up' first`);
      }
      if (options.startServer) {
        await ensureAgentVncServer(context, io, target.execTarget, options, delay);
      }
      // The bridge is the ingress facility's; VNC contributes only the target
      // and ports. `restart` replaces any forwarder on this host port — the
      // facility removes a same-named forwarder before re-creating it.
      replaceValidatedIngressForwarder(context, io, projectId, {
        purpose: VNC_PURPOSE,
        projectId,
        hostPort: options.hostPort,
        target: target.forwardTarget,
        targetPort: options.agentPort,
        internalNetwork,
      });
      console.log(`ready: vnc://127.0.0.1:${options.hostPort}`);
      if (options.password && options.startServer) console.log(`password: ${options.password}`);
      console.log(`TigerVNC: vncviewer 127.0.0.1::${options.hostPort}`);
      return 0;
    }
  }
}
