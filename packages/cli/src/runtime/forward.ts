// `runfree forward` — a generic, hardened host→agent port forward.
//
// VNC is a special case of this: a one-way loopback bridge into the fence.
// `forward` exposes that bridge directly, for previewing a dev server the agent
// is running (a web app on :3000, a docs site, an API under test), with no
// server bootstrap — it resolves the agent/session target and opens an ingress
// forwarder with `ingress-purpose=port`. Every hardening and one-way property is
// the facility's (ingress-forwarder.ts); this module only parses intent,
// resolves the target, and selects/tears down the port-purpose forwarders.
//
// The host-facing network is not a CLI option: the ingress facility derives it
// from the project id so a forward can never be pointed at a shared bridge
// (that hardening is why `runfree vnc`'s `--host-network` has no analogue here).

import { die } from "../errors.ts";
import { resolveAgentExecTarget } from "./agent-exec-target.ts";
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

const FORWARD_USAGE = "usage: runfree forward [<port>] [start|stop|status] "
  + "[--host-port PORT] [--agent-port PORT]";

// The one diagnostic purpose this command owns. VNC and the MCP callback are
// other purposes on the same facility; `forward` selects and tears down only
// its own, so `forward stop` never touches a VNC forward.
const FORWARD_PURPOSE = "port";

export type ForwardAction = "start" | "stop" | "status";

export type ForwardOptions = {
  action: ForwardAction;
  // Undefined addresses nothing specific: valid only for `stop` (all port
  // forwards) and `status` (list). `start` requires both to be resolved.
  hostPort?: string;
  agentPort?: string;
};

const ACTIONS = new Set<string>(["start", "stop", "status"]);

function parsedPort(value: string | undefined, flag: string): string {
  if (!value) die(`${flag} requires a value`);
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
    die(`${flag} must be a port number between 1 and 65535`);
  }
  // Canonical decimal: the port becomes the forwarder's identity (its name and
  // its `-p` binding). Docker reads `03000` as 3000, so a non-canonical
  // spelling would name a forwarder `...-03000` that `forward 3000 stop` could
  // never match — reporting success while the real loopback port stays open.
  return String(Number(value));
}

// Typed input shape produced by the yargs forward command module. yargs
// validates the grammar (action choices, requiresArg); this builder re-validates
// the value shapes (port range) and disambiguates the port/action positionals.
export type ForwardArgs = {
  port?: string;
  action?: ForwardAction;
  "host-port"?: string;
  "agent-port"?: string;
};

export function forwardOptionsFromArgs(argv: ForwardArgs): ForwardOptions {
  let action = argv.action;
  let portArg = argv.port;
  // `runfree forward stop` / `forward status`: with no port, the action keyword
  // lands in the first (port) positional. Recover it rather than parsing "stop"
  // as a port.
  if (portArg !== undefined && ACTIONS.has(portArg)) {
    if (action !== undefined) die(FORWARD_USAGE);
    action = portArg as ForwardAction;
    portArg = undefined;
  }
  const resolvedAction = action ?? "start";
  // --host-port/--agent-port are start-only: a forwarder is identified by its
  // host port (its name), so an agent-only selector cannot target a stop. If it
  // were accepted, `forward stop --agent-port 8080` would leave hostPort
  // undefined and silently widen to stop-all — reject it rather than surprise.
  if (resolvedAction !== "start" && (argv["host-port"] !== undefined || argv["agent-port"] !== undefined)) {
    die(`--host-port and --agent-port are only valid with 'start'\n${FORWARD_USAGE}`);
  }
  const base = portArg !== undefined ? parsedPort(portArg, "<port>") : undefined;
  return {
    action: resolvedAction,
    // The positional publishes 127.0.0.1:<port> → agent:<port>; for start the
    // flags override each side. For stop the positional is the host-port
    // selector (undefined = all); status ignores it and lists everything.
    hostPort: argv["host-port"] !== undefined ? parsedPort(argv["host-port"], "--host-port") : base,
    agentPort: argv["agent-port"] !== undefined ? parsedPort(argv["agent-port"], "--agent-port") : base,
  };
}

function docker(context: RuntimeContext, io: RuntimeIO, args: string[]): CaptureResult {
  return io.capture("docker", args, dockerClientEnvOptions(context));
}

function networkExists(context: RuntimeContext, io: RuntimeIO, name: string): boolean {
  return docker(context, io, ["network", "inspect", name]).status === 0;
}

/**
 * The address the forwarder splices to inside the fence, resolved through the
 * one typed answer to "which container is the agent" (shared with VNC). A live
 * session targets its fixed internal IP, which is the identity admission binds.
 * The resolver's own refusals surface as exact `die` messages.
 */
function resolveForwardTarget(
  project: string,
  projectId: string,
  context: RuntimeContext,
  io: RuntimeIO,
): string {
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
  return resolved.sourceIp;
}

/** This project's open port forwards (ingress-purpose=port only). */
function projectPortForwarders(context: RuntimeContext, io: RuntimeIO, projectId: string): string[] {
  const prefix = `${ingressForwarderName(projectId, FORWARD_PURPOSE, "")}`;
  // ingressForwarderName(..., "") ends with a trailing '-', so this matches
  // exactly runfree-ingress-port-<projectId>-<port> and never a vnc/mcp-callback
  // forwarder.
  return listIngressForwarders(context, io, projectId).filter((name) => name.startsWith(prefix));
}

// Typed core for `runfree forward`. Receives validated ForwardOptions and
// performs no argument parsing.
export function forwardRuntime(
  options: ForwardOptions,
  context: RuntimeContext,
  io: RuntimeIO,
  adapters: RuntimeAdapters,
): number {
  adapters.docker.assertAvailable();
  const projectId = projectHash(context.projectRoot);
  const project = composeProjectName(context.projectRoot);

  switch (options.action) {
    case "status": {
      const forwarders = projectPortForwarders(context, io, projectId);
      if (forwarders.length === 0) {
        console.log("no port forwards open");
        return 0;
      }
      const filters = forwarders.flatMap((name) => ["--filter", `name=^/${name}$`]);
      const listing = captureDockerListing(io, ["ps", "-a", ...filters], dockerClientEnvOptions(context), "port forwards");
      if (listing.status !== 0) return listing.status;
      if (listing.rows.length === 0) {
        console.log("no port forwards open");
        return 0;
      }
      console.log(renderDockerListing([
        { label: "NAME", value: (row) => row.Names },
        { label: "STATUS", value: (row) => row.Status },
        { label: "PORTS", value: (row) => row.Ports },
      ], listing.rows));
      return 0;
    }
    case "stop": {
      const targets = options.hostPort !== undefined
        ? [ingressForwarderName(projectId, FORWARD_PURPOSE, options.hostPort)]
        : projectPortForwarders(context, io, projectId);
      if (targets.length === 0) {
        console.log("no port forwards to stop");
        return 0;
      }
      const removed = removeValidatedIngressForwarders(context, io, projectId, targets);
      if (removed === 0) {
        console.log("no port forwards to stop");
        return 0;
      }
      for (const name of targets) console.log(`forward closed: ${name}`);
      return 0;
    }
    case "start": {
      if (options.hostPort === undefined || options.agentPort === undefined) {
        die(`forward start requires a port\n${FORWARD_USAGE}`);
      }
      const internalNetwork = `${project}_agent_internal`;
      if (!networkExists(context, io, internalNetwork)) {
        die(`agent network not found: ${internalNetwork} - try 'runfree up' first`);
      }
      const target = resolveForwardTarget(project, projectId, context, io);
      const name = replaceValidatedIngressForwarder(context, io, projectId, {
        purpose: FORWARD_PURPOSE,
        projectId,
        hostPort: options.hostPort,
        target,
        targetPort: options.agentPort,
        internalNetwork,
      });
      console.log(`forward open: 127.0.0.1:${options.hostPort} -> agent:${options.agentPort} (${name})`);
      // The splice reaches the agent's network interface, not its loopback, and
      // a failure to connect is otherwise silent (the forward reports success).
      console.log(`  the agent service on :${options.agentPort} must listen on 0.0.0.0 (not only 127.0.0.1) to be reachable`);
      return 0;
    }
  }
}
