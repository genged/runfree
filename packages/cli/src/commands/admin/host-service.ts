// `runfree host-service <add|remove|list>` — approve agent access to a service
// on the Docker Desktop host's loopback (design "Approval and CLI").
//
// Intent layer: yargs validates the grammar (name positional, canonical
// decimal `--port`) and builds a typed mutation. Enforcement is the typed
// desired-policy transaction in `control/host-service-mutation.ts`, which
// re-validates and runs the port admission (static refusals plus the `lsof`
// owner check) before any policy write.
//
// `host` is the exact-host allowlist command; this is a separate root.

import fs from "node:fs";
import path from "node:path";

import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";
import type { ArgumentsCamelCase, Argv } from "yargs";

import { type ProjectInfo, projectControlPaths } from "../../config.ts";
import { activateApprovedControlsAfterMutation, type ControlActivationResult } from "../../control/activation.ts";
import { activationReportLine } from "../../control/activation-report.ts";
import {
  readActiveControlSelection,
  readActiveEffectiveControl,
  readEffectiveHostServices,
} from "../../control/effective.ts";
import {
  mutateDesiredHostService,
  type DesiredHostServiceMutation,
  type DesiredHostServiceScope,
} from "../../control/host-service-mutation.ts";
import { CliError } from "../../errors.ts";
import { type HostPortOwner, probeHostPortOwner } from "../../host-service-port-owner.ts";
import { recordProjectHostServicePorts, repairHostServicePortRegistry } from "../../host-service-registry.ts";
import { runfreeStateRoot } from "../../paths.ts";
import { projectHash } from "../../project-identity.ts";
import { remedy } from "../../remedies.ts";
import { controlPlaneEffectiveSelectionPathV2 } from "../../runtime/component-state-v2.ts";
import { controlPlaneRebindTransactionPath } from "../../runtime/control-plane-rebind.ts";
import { nodeRuntimeIO } from "../../runtime.ts";
import type { RuntimeContext } from "../../runtime/types.ts";
import { formatTerminalTable } from "../../terminal-table.ts";
import type { RunfreeCommandContext } from "../context.ts";
import { withExamples } from "../examples.ts";
import type { CommandHandlerFactory, CommandModule } from "../types.ts";
import { NO_RELOAD_DESCRIBE } from "./no-reload.ts";

type NameArgs = { name: string };
type AddArgs = NameArgs & { port: number; local?: boolean; "no-reload"?: boolean };
type RemoveArgs = NameArgs & { local?: boolean; "no-reload"?: boolean };
type ListArgs = { repair?: boolean };

const CANONICAL_PORT_RE = /^[1-9][0-9]{0,4}$/u;

/** `--port`: canonical decimal (no sign, no leading zero, no exponent), 1-65535. */
export function parseHostServicePortArg(value: unknown): number {
  if (typeof value !== "string" || !CANONICAL_PORT_RE.test(value) || Number(value) > 65535) {
    throw new Error(`--port must be a decimal port from 1 to 65535 without leading zeros, got ${JSON.stringify(value)}`);
  }
  return Number(value);
}

const namePositional = (cmd: Argv): Argv =>
  cmd.positional("name", {
    type: "string",
    demandOption: true,
    describe: "service name; the agent-facing label in <name>.runfree.internal",
  });

const localScopeOption = (cmd: Argv): Argv =>
  cmd.option("local", {
    type: "boolean",
    describe: "Mutate the checkout-local desired policy instead of project policy",
  });

function ownerText(owner: HostPortOwner): string {
  switch (owner.kind) {
    case "listener":
      return `${owner.command} (pid ${owner.pid})`;
    case "none":
      return "no listener";
    case "unavailable":
      return `unknown (${owner.reason})`;
  }
}

/**
 * The ports of the effective policy generation an activation left selected:
 * the one it selected, else whatever is still selected (a deferred
 * activation), else none.
 */
function selectedEffectiveHostServicePorts(runtime: RuntimeContext, activation: ControlActivationResult): number[] {
  const controlGeneration = activation.kind === "deferred"
    ? readActiveControlSelection(runtime.project)?.controlGeneration
    : activation.controlGeneration;
  return controlGeneration === undefined ? [] : readEffectiveHostServices(runtime.project, controlGeneration).ports;
}

/**
 * Whether a project still has a runtime: a live control-plane selection, or
 * the rebind recovery journal that stands in for one mid-rebuild. A completed
 * destroy removes both (and prunes the registry row), while the effective
 * policy generation selection survives it, so repair must not read that alone
 * or it would restore a destroyed project's row. A project that was never
 * launched has no row to protect; its next launch records it.
 */
function projectHasRuntimeSelection(stateDir: string): boolean {
  for (const file of [controlPlaneEffectiveSelectionPathV2(stateDir), controlPlaneRebindTransactionPath(stateDir)]) {
    try {
      if (fs.lstatSync(file).isFile()) return true;
    } catch (error) {
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
    }
  }
  return false;
}

/**
 * The repair reader: one known project's selected effective policy generation,
 * read from host state only. The checkout is never read, so a project whose
 * config moved or broke still contributes the ports its runtime enforces.
 * Throws when that state cannot be read; repair then refuses to write.
 */
export function selectedEffectiveHostServicePortsFromState(
  env: NodeJS.ProcessEnv,
  projectId: string,
): readonly number[] | undefined {
  const stateDir = path.join(runfreeStateRoot(env), "projects", projectId);
  if (!projectHasRuntimeSelection(stateDir)) return undefined;
  // The effective readers need only the state-derived control paths.
  const project = { paths: projectControlPaths(stateDir) } as unknown as ProjectInfo;
  const active = readActiveControlSelection(project);
  if (!active) return undefined;
  return readEffectiveHostServices(project, active.controlGeneration).ports;
}

async function refreshRegistry(
  runtime: RuntimeContext,
  activation: ControlActivationResult,
  owner: { command: string; port: number } | undefined,
): Promise<void> {
  const ports = selectedEffectiveHostServicePorts(runtime, activation);
  const owners = owner && ports.includes(owner.port) ? { [owner.port]: owner.command } : undefined;
  try {
    await recordProjectHostServicePorts(runtime.env ?? process.env, { id: projectHash(runtime.projectRoot), root: runtime.projectRoot }, ports, owners);
  } catch (error) {
    throw new CliError([
      "the policy change is saved, but the host-service port registry was not updated: "
        + `${error instanceof Error ? error.message : String(error)}`,
      `rebuild it with: ${remedy.hostServiceRepair()}`,
    ].join("\n"));
  }
}

async function runMutation(
  context: RunfreeCommandContext,
  scope: DesiredHostServiceScope,
  mutation: DesiredHostServiceMutation,
  reload: boolean,
): Promise<void> {
  const runtime = context.runtimeContext();
  const result = await mutateDesiredHostService(runtime, nodeRuntimeIO, scope, mutation);
  console.log(`scope: ${scope === "local" ? "checkout-local" : "project"}`);
  if (mutation.kind === "add") {
    const owner = result.owner ? ` (${result.owner.command}, pid ${result.owner.pid})` : "";
    console.log(`approved host service ${mutation.name}: 127.0.0.1:${mutation.port}${owner}${result.changed ? "" : " (unchanged)"}`);
    console.log(`agent address: 127.0.0.1:${mutation.port} (relay in new sessions)`);
  } else {
    console.log(`host service ${mutation.name} ${result.changed ? "removed" : "unchanged"}`);
  }
  for (const warning of result.warnings) console.log(`warning: ${warning}`);
  console.log(`updated .runfree/network-policy${scope === "local" ? ".local" : ""}.json`);
  console.log(`approved ${scope} desired policy: ${result.digest.slice(0, 19)}… (approval record id)`);
  if (!reload) {
    console.log("effective policy: unchanged (--no-reload)");
    return;
  }
  const activation = await activateApprovedControlsAfterMutation(runtime, nodeRuntimeIO);
  console.log(activationReportLine(activation));
  await refreshRegistry(
    runtime,
    activation,
    mutation.kind === "add" && result.owner ? { command: result.owner.command, port: mutation.port } : undefined,
  );
}

function listEffective(context: RunfreeCommandContext): void {
  const runtime = context.runtimeContext();
  const effective = readActiveEffectiveControl(runtime.project);
  if (!effective) {
    console.log("no effective policy generation is selected; approved host services apply when the runtime starts");
    return;
  }
  const services: HostServicesJson = effective.policy.hostServices ?? {};
  const names = Object.keys(services).sort();
  if (names.length === 0) {
    console.log("no host services in the effective policy generation");
    return;
  }
  console.log(formatTerminalTable({
    columns: [{ label: "NAME" }, { label: "PORT" }, { label: "OWNER" }],
    rows: names.map((name) => {
      const port = services[name].port;
      return [name, port, ownerText(probeHostPortOwner(runtime, nodeRuntimeIO, port))];
    }),
  }));
}

async function repairRegistry(context: RunfreeCommandContext): Promise<void> {
  let counts: { projects: number; ports: number };
  try {
    counts = await repairHostServicePortRegistry(context.env, (_projectRoot, projectId) =>
      selectedEffectiveHostServicePortsFromState(context.env, projectId));
  } catch (error) {
    // Fails closed (exit non-zero, nothing written) when any known project's
    // ports cannot be read; the message names each one and the reclaim.
    throw new CliError(error instanceof Error ? error.message : String(error));
  }
  console.log(`host-service port registry rebuilt: ${counts.ports} port(s) from ${counts.projects} project(s)`);
}

export const hostServiceCommand: CommandModule = {
  name: "host-service",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "host-service",
      "Approve agent access to a service on the host's loopback",
      (group) => {
        const built = group
          .command(
            "add <name>",
            "Approve a host loopback port for the agent after checking who listens on it",
            (cmd) =>
              localScopeOption(namePositional(cmd))
                .option("port", {
                  type: "string",
                  demandOption: true,
                  requiresArg: true,
                  coerce: parseHostServicePortArg,
                  describe: "Host TCP port on 127.0.0.1 (1-65535); the agent reaches it on the same loopback port",
                })
                .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<AddArgs>) =>
              runMutation(context, argv.local ? "local" : "project", {
                kind: "add",
                name: argv.name,
                port: argv.port,
              }, !argv["no-reload"])),
          )
          .command(
            "remove <name>",
            "Remove an approved host service",
            (cmd) => localScopeOption(namePositional(cmd)).option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<RemoveArgs>) =>
              runMutation(context, argv.local ? "local" : "project", { kind: "remove", name: argv.name }, !argv["no-reload"])),
          )
          .command(
            "list",
            "Print the effective host services and who listens on each port",
            (cmd) => cmd.option("repair", {
              type: "boolean",
              describe: "Rebuild the host-global host-service port registry from every known project",
            }),
            handler((argv: ArgumentsCamelCase<ListArgs>) => (argv.repair ? repairRegistry(context) : listEffective(context))),
          );
        return withExamples(built, "host-service")
          .epilogue(
            "A host service is an exact name and host loopback port. The agent connects to 127.0.0.1:<port> in new sessions; "
              + "a relay carries it through the proxy. The port must have a visible listener that is not Docker Desktop.",
          )
          .demandCommand(1);
      },
      () => {},
    ),
};
