// `runfree service <list|enable|disable|explain|diff|configure|custom add|custom remove>` — curated and user-defined host bundles,
// optionally carrying a credential.
//
// Typed end-to-end: each handler builds a typed intent and calls the shared
// enforcement (which re-validates the service id, credential source, OAuth seed item,
// and policy edits). See the intent-vs-enforcement principle.
//
// `--no-reload` is a literal option name (relies on the global
// `boolean-negation: false`); the installable "literal --no-* flags" regression
// test pins this.

import type { ArgumentsCamelCase, Argv } from "yargs";

import { readAgentEnv, setAgentEnvValues } from "../../admin/admin-core.ts";
import { planServiceParameterUpdate, serviceHostState } from "../../admin/service-policy.ts";
import { createAdminState } from "../../admin/context.ts";
import {
  bindDesiredServiceCredentialSources,
  promptForMissingServiceParameters,
  desiredServiceEntry,
  runAdminAction,
  planDesiredServiceEnable,
  serviceConfigureIntent,
  serviceDefineIntent,
  serviceParameterStatus,
  serviceUndefineIntent,
  credentialSourceSelectionFromArgs,
  type ServiceEnableInput,
} from "../../admin/options.ts";
import { readApprovedNetworkPolicy } from "../../control/approvals.ts";
import { activateApprovedControlsAfterMutation } from "../../control/activation.ts";
import { activationReportLine } from "../../control/activation-report.ts";
import { compileDesiredPolicies } from "../../control/compiler.ts";
import { compareCompiledAuthority } from "../../control/comparator.ts";
import { mutateDesiredService, type DesiredServiceLayer } from "../../control/service-mutation.ts";
import type { DesiredServiceEntry } from "@runfree/runtime-contracts/desired-network-policy";
import { CliError } from "../../errors.ts";
import { formatTerminalTable } from "../../terminal-table.ts";
import { nodeRuntimeIO } from "../../runtime.ts";
import type { RuntimeContext } from "../../runtime/types.ts";
import { combinedServiceRegistry, loadUserServiceCatalog } from "../../user-services.ts";
import { type Service, serviceOriginLabel } from "../../../../../scripts/services.ts";
import type { RunfreeCommandContext } from "../context.ts";
import { withExamples } from "../examples.ts";
import type { CommandHandlerFactory, CommandModule } from "../types.ts";
import { NO_RELOAD_DESCRIBE } from "./no-reload.ts";

const TOKEN_SOURCE_GROUP = "Credential source (choose at most one):";

type IdArgs = { id: string };
type EnableArgs = IdArgs & {
  "from-env"?: string;
  "from-1password"?: string;
  "from-1password-item"?: string;
  "from-source"?: string;
  "from-stdin"?: boolean;
  param?: string[];
  "replace-source"?: boolean;
  "skip-broad"?: boolean;
  "skip-host"?: string[];
  "read-only"?: boolean;
  "allow-write"?: boolean;
  local?: boolean;
  "no-reload"?: boolean;
};
type ListArgs = { all?: boolean };
type DisableArgs = IdArgs & { local?: boolean; "no-reload"?: boolean };
type DiffArgs = { apply?: boolean; "no-reload"?: boolean };
type CustomAddArgs = IdArgs & { "from-file"?: string; replace?: boolean; yes?: boolean };
type ConfigureArgs = IdArgs & { local?: boolean; "no-reload"?: boolean };

// Token-source selection flags shared by credential-bearing service enable.
const tokenSourceOptions = (cmd: Argv): Argv =>
  cmd
    .option("from-env", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Read the token from this host env var" })
    .option("from-1password", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Read the token from a 1Password secret ref (op://...)" })
    .option("from-1password-item", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Seed an OAuth credential from a 1Password item" })
    .option("from-source", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Bind a previously-saved host-owned source" })
    .option("from-stdin", { type: "boolean", group: TOKEN_SOURCE_GROUP, describe: "Read the token from stdin" })
    .option("replace-source", { type: "boolean", describe: "Overwrite an existing credential source for this service" });

const idPositional = (cmd: Argv): Argv =>
  cmd.positional("id", { type: "string", demandOption: true, describe: "service id" });

function approvedDesiredServices(runtime: RuntimeContext) {
  const project = readApprovedNetworkPolicy(runtime.projectRoot, runtime.project, "network-project");
  const local = readApprovedNetworkPolicy(runtime.projectRoot, runtime.project, "network-local");
  if (!project || !local) {
    throw new CliError([
      "approved project and local network controls are required before services can be listed or changed",
      "start the runtime to review and select controls: runfree up",
      "inspect approval state with: runfree policy status",
    ].join("\n"));
  }
  return { project, local, selected: compileDesiredPolicies({ project, local }).selectedServices };
}

export type ServiceListRow = {
  id: string;
  origin: "curated" | "user-defined";
  state: "enabled" | "available";
  layer: DesiredServiceLayer | "-";
  revision: number;
  hosts: number;
};

// Rows for `service list`. Without `all`, only approved (enabled) services are
// listed. With `all`, every curated and user-defined service in the registry is
// listed too; an enabled id whose definition is no longer in the registry is
// still shown from its approved entry so the list never hides live authority.
export function serviceListRows(input: {
  selected: Record<string, DesiredServiceEntry>;
  localServiceIds: ReadonlySet<string>;
  registry: Record<string, Service>;
  all: boolean;
}): ServiceListRow[] {
  const ids = new Set(Object.keys(input.selected));
  if (input.all) for (const id of Object.keys(input.registry)) ids.add(id);
  return [...ids].sort().map((id) => {
    const entry = input.selected[id];
    const origin = serviceOriginLabel(id) as ServiceListRow["origin"];
    if (entry) {
      return {
        id,
        origin,
        state: "enabled",
        layer: input.localServiceIds.has(id) ? "local" : "project",
        revision: entry.revision,
        hosts: entry.resolved.hosts.length,
      };
    }
    const definition = input.registry[id];
    return { id, origin, state: "available", layer: "-", revision: definition.revision, hosts: definition.hosts.length };
  });
}

function listDesiredServices(runtime: RuntimeContext, input: { all: boolean }): void {
  const approved = approvedDesiredServices(runtime);
  const rows = serviceListRows({
    selected: approved.selected,
    localServiceIds: new Set(Object.keys(approved.local.services ?? {})),
    registry: input.all ? combinedServiceRegistry(runtime.projectRoot, runtime.env) : {},
    all: input.all,
  });
  if (rows.length === 0) {
    console.log(input.all ? "no services" : "no approved services; list every known service with: runfree service list --all");
    return;
  }
  console.log(formatServiceListTable(rows, { all: input.all }));
}

export function formatServiceListTable(rows: readonly ServiceListRow[], input: { all: boolean }): string {
  if (input.all) {
    return formatTerminalTable({
      columns: [
        { label: "SERVICE" },
        { label: "ORIGIN" },
        { label: "STATE" },
        { label: "LAYER" },
        { label: "REVISION" },
        { label: "HOSTS" },
      ],
      rows: rows.map((row) => [row.id, row.origin, row.state, row.layer, row.revision, row.hosts]),
    });
  }
  return formatTerminalTable({
    columns: [{ label: "SERVICE" }, { label: "LAYER" }, { label: "REVISION" }, { label: "HOSTS" }],
    rows: rows.map((row) => [row.id, row.layer, row.revision, row.hosts]),
  });
}

function explainDesiredService(runtime: RuntimeContext, idInput: string): void {
  const id = idInput.toLowerCase();
  const approved = approvedDesiredServices(runtime);
  const entry = approved.selected[id];
  if (!entry) throw new CliError(`service is not approved: ${id}`);
  const parameters = entry.resolved.parameters ?? [];
  console.log(JSON.stringify({
    id,
    layer: approved.local.services?.[id] ? "local" : "project",
    definitionDigest: entry.definitionDigest,
    revision: entry.revision,
    selection: entry.selection ?? {},
    resolved: entry.resolved,
    ...(parameters.length > 0 ? { parameterValues: serviceParameterStatus(parameters, readAgentEnv()) } : {}),
  }, null, 2));
}

async function diffDesiredServices(
  runtime: RuntimeContext,
  input: { apply: boolean; reloadProxy: boolean },
): Promise<void> {
  const approved = approvedDesiredServices(runtime);
  const registry = combinedServiceRegistry(runtime.projectRoot, runtime.env);
  const userCatalog = loadUserServiceCatalog(runtime.projectRoot, runtime.env);
  const changes: Array<{ id: string; layer: DesiredServiceLayer; entry: ReturnType<typeof desiredServiceEntry> }> = [];
  const proposed = {
    project: structuredClone(approved.project),
    local: structuredClone(approved.local),
  };
  for (const layer of ["project", "local"] as const) {
    for (const [id, current] of Object.entries(approved[layer].services ?? {}).sort(([left], [right]) => left.localeCompare(right))) {
      const definition = registry[id];
      if (!definition) {
        console.log(`${id} (${layer}): definition unavailable; approved semantics retained`);
        continue;
      }
      const next = desiredServiceEntry(definition, {
        skippedHosts: current.selection?.skippedHosts,
        writeMode: current.selection?.writeMode,
      }, userCatalog.services[id]?.digest);
      if (JSON.stringify(current) === JSON.stringify(next)) {
        console.log(`${id} (${layer}): current`);
        continue;
      }
      console.log(`${id} (${layer}): revision ${current.revision} -> ${next.revision}`);
      console.log(`  definition ${current.definitionDigest} -> ${next.definitionDigest}`);
      console.log(`  before ${JSON.stringify(current.resolved)}`);
      console.log(`  after  ${JSON.stringify(next.resolved)}`);
      changes.push({ id, layer, entry: next });
      proposed[layer].services = { ...(proposed[layer].services ?? {}), [id]: next };
    }
  }
  if (changes.length === 0) return;
  const comparison = compareCompiledAuthority(
    compileDesiredPolicies({ project: approved.project, local: approved.local }),
    compileDesiredPolicies(proposed),
  );
  console.log(`authority: ${comparison.provenReduction ? "proven reduction or equivalent" : "widening or incomparable"}`);
  for (const reason of comparison.reasons) console.log(`  ${reason}`);
  if (!input.apply) {
    console.log("apply with: runfree service diff --apply");
    return;
  }
  // Resolve the complete batch before the first mutation; a missing parameter
  // must not leave earlier services updated and the rest refused.
  const updates = changes.map((change) => ({
    ...change,
    values: planServiceParameterUpdate(registry[change.id]),
  }));
  for (const change of updates) {
    await mutateDesiredService(runtime, nodeRuntimeIO, change.layer, {
      kind: "enable",
      id: change.id,
      entry: change.entry,
    }, serviceHostState(change.id, () => setAgentEnvValues(change.values)));
  }
  if (!input.reloadProxy) {
    console.log("effective policy: unchanged (--no-reload)");
    return;
  }
  const activation = await activateApprovedControlsAfterMutation(runtime, nodeRuntimeIO);
  console.log(activationReportLine(activation));
}

export const serviceCommand: CommandModule = {
  name: "service",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) => {
    const run = (action: () => Promise<void> | void): Promise<number> =>
      runAdminAction(createAdminState(context.adminContext()), action);
    const desiredLayer = (local: boolean | undefined): DesiredServiceLayer => local ? "local" : "project";
    const enableDesired = async (
      runtime: RuntimeContext,
      layer: DesiredServiceLayer,
      intent: ServiceEnableInput,
    ): Promise<void> => {
      // Resolve external inputs first. Bind only after the locked transaction has
      // checked the approved base and compiled the proposed policy.
      const plan = planDesiredServiceEnable(intent);
      let boundSources: string[] = [];
      const result = await mutateDesiredService(runtime, nodeRuntimeIO, layer, {
        kind: "enable",
        id: plan.id,
        entry: plan.entry,
      }, serviceHostState(plan.id, () => {
        boundSources = bindDesiredServiceCredentialSources(plan, intent.replaceSource);
      }));
      console.log(`service ${plan.id}: ${result.changed ? "updated" : "unchanged"} in ${layer} desired policy`);
      console.log(`${layer} digest: ${result.layerDigest}`);
      if (boundSources.length > 0) console.log(`host-owned credential sources: ${boundSources.join(", ")} bound`);
      if (!intent.reloadProxy) {
        console.log("effective policy: unchanged (--no-reload)");
      } else {
        const activation = await activateApprovedControlsAfterMutation(runtime, nodeRuntimeIO);
        console.log(activationReportLine(activation));
      }
    };
    return parser.command(
      "service",
      "Manage curated and user-defined host bundles",
      (service) => {
        const built = service
          .command(
            "list",
            "List enabled services; --all lists every curated and user-defined service",
            (cmd) => cmd.option("all", { type: "boolean", describe: "Include services that are not enabled" }),
            handler((argv: ArgumentsCamelCase<ListArgs>) => {
              return run(() => listDesiredServices(context.runtimeContext(), { all: argv.all === true }));
            }),
          )
          .command(
            "enable <id>",
            "Allow a curated or user-defined service and optionally bind a credential",
            (cmd) =>
              tokenSourceOptions(idPositional(cmd))
                .option("skip-broad", { type: "boolean", describe: "Enable without broad multi-tenant hosts" })
                .option("skip-host", { type: "array", string: true, describe: "Skip a specific service host (repeatable)" })
                .option("read-only", { type: "boolean", describe: "Block writes to the service's hosts (writeAction deny + read-only profile)" })
                .option("allow-write", { type: "boolean", describe: "Let writes flow without approval (writeAction allow)" })
                .option("param", {
                  type: "array",
                  string: true,
                  requiresArg: true,
                  describe: "Supply a declared non-secret service parameter as <key>=<value> (repeatable; see service explain)",
                })
                .option("local", { type: "boolean", describe: "Write the checkout-local desired policy layer" })
                .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<EnableArgs>) => {
              const intent = {
                id: argv.id,
                tokenSource: credentialSourceSelectionFromArgs({
                  env: argv["from-env"],
                  onePassword: argv["from-1password"],
                  source: argv["from-source"],
                  stdin: argv["from-stdin"],
                }),
                fromOnePasswordItem: argv["from-1password-item"],
                ...(argv.param && argv.param.length > 0 ? { parameters: argv.param } : {}),
                replaceSource: Boolean(argv["replace-source"]),
                skipBroad: Boolean(argv["skip-broad"]),
                skipHosts: argv["skip-host"] ?? [],
                readOnly: Boolean(argv["read-only"]),
                allowWrite: Boolean(argv["allow-write"]),
                // `--no-reload` is a literal option (global boolean-negation:false).
                reloadProxy: !argv["no-reload"],
              };
              const layer = desiredLayer(argv.local);
              return run(async () => {
                const runtime = context.runtimeContext();
                const prepared = await promptForMissingServiceParameters(intent, {
                  interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY),
                });
                await enableDesired(runtime, layer, prepared);
              });
            }),
          )
          .command(
            "disable <id>",
            "Remove a service from the selected desired policy layer",
            (cmd) => idPositional(cmd)
              .option("local", { type: "boolean", describe: "Write the checkout-local desired policy layer" })
              .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<DisableArgs>) => {
              const layer = desiredLayer(argv.local);
              return run(async () => {
                const runtime = context.runtimeContext();
                const hostState = serviceHostState(argv.id, () => {});
                const result = await mutateDesiredService(runtime, nodeRuntimeIO, layer, {
                  kind: "disable",
                  id: argv.id,
                }, hostState);
                console.log(`service ${result.id}: disabled in ${layer} desired policy`);
                console.log(`${layer} digest: ${result.layerDigest}`);
                console.log("host-owned credential sources: unchanged");
                const removed = hostState.removedEnvNames;
                if (removed.length > 0) console.log(`host-owned agent env: removed ${removed.join(", ")}`);
                if (argv["no-reload"]) {
                  console.log("effective policy: unchanged (--no-reload)");
                } else {
                  const activation = await activateApprovedControlsAfterMutation(context.runtimeContext(), nodeRuntimeIO);
                  console.log(activationReportLine(activation));
                }
              });
            }),
          )
          .command(
            "explain <id>",
            "Show a service's hosts, credential, origin, and enable state",
            (cmd) => idPositional(cmd),
            handler((argv: ArgumentsCamelCase<IdArgs>) => {
              const intent = { id: argv.id };
              return run(() => explainDesiredService(context.runtimeContext(), intent.id));
            }),
          )
          .command(
            "configure <id>",
            "Guided service setup (TTY only)",
            (cmd) => idPositional(cmd)
              .option("local", { type: "boolean", describe: "Write the checkout-local desired policy layer" })
              .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<ConfigureArgs>) => {
              const intent = { id: argv.id, reloadProxy: !argv["no-reload"] };
              const layer = desiredLayer(argv.local);
              return run(async () => {
                const runtime = context.runtimeContext();
                const approved = readApprovedNetworkPolicy(
                  runtime.projectRoot,
                  runtime.project,
                  layer === "local" ? "network-local" : "network-project",
                );
                await serviceConfigureIntent(intent, {
                  currentEntry: approved?.services?.[argv.id.toLowerCase()],
                  apply: (enableInput) => enableDesired(runtime, layer, enableInput),
                });
              });
            }),
          )
          .command(
            "custom",
            "Manage user-defined service definitions",
            (custom) =>
              custom
                .command(
                  "add <id>",
                  "Create or import a user-defined service",
                  (cmd) =>
                    idPositional(cmd)
                      .option("from-file", { type: "string", requiresArg: true, describe: "Import a strict JSON user-service definition" })
                      .option("replace", { type: "boolean", describe: "Overwrite an existing user-service definition" })
                      .option("yes", { type: "boolean", alias: "y", describe: "Confirm a --from-file import non-interactively" }),
                  handler((argv: ArgumentsCamelCase<CustomAddArgs>) => {
                    const intent = { id: argv.id, fromFile: argv["from-file"], replace: Boolean(argv.replace), yes: Boolean(argv.yes) };
                    return run(() => serviceDefineIntent(intent));
                  }),
                )
                .command(
                  "remove <id>",
                  "Delete a user-defined service definition",
                  (cmd) => idPositional(cmd),
                  handler((argv: ArgumentsCamelCase<IdArgs>) => run(() => serviceUndefineIntent({ id: argv.id }))),
                )
                .demandCommand(1),
            () => {},
          )
          .command(
            "diff",
            "Reconcile recorded service revisions with current service definitions",
            (cmd) =>
              cmd
                .option("apply", { type: "boolean", describe: "Apply the reconciliation instead of only showing it" })
                .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<DiffArgs>) => {
              const intent = { apply: Boolean(argv.apply), reloadProxy: !argv["no-reload"] };
              return run(() => diffDesiredServices(context.runtimeContext(), intent));
            }),
          );
        return withExamples(built, "service")
          .epilogue(
            "Credential-bearing services accept one credential source (--from-env | --from-1password | --from-source | --from-1password-item) and never expose the real token to the agent. User-defined service ids live under user-* and are labeled as not curated by Runfree.",
          )
          .demandCommand(1);
      },
      () => {},
    );
  },
};
