// Top-level yargs command app.
//
// Builds a fresh parser per invocation, registers commands, and awaits
// `parseAsync`. It never reads `process.argv` and never calls `process.exit`;
// control stays in `runCli`. See the spec's "App Runner And Error Contract".

import type { ArgumentsCamelCase, Argv } from "yargs";

import { resolveDefaultAgentName } from "../config.ts";
import { CliError } from "../errors.ts";
import { nodeRuntimeIO, runAgentCommand } from "../runtime.ts";
import { withControlPlaneRebindRefusal } from "../runtime/control-plane-rebind-refusal.ts";
import { runtimeDryRun } from "../runtime/front.ts";
import { normalizeSessionName } from "../runtime/sessions.ts";
import { credentialCommand } from "./admin/credential.ts";
import { doctorCommand, runtimeAdminCommand } from "./admin/diagnostics.ts";
import { hostCommand } from "./admin/host.ts";
import { mcpCommand } from "./admin/mcp.ts";
import { serviceCommand } from "./admin/service.ts";
import { assetsCommand } from "./assets.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { asUsageError } from "./errors.ts";
import { imageCommand } from "./image.ts";
import { initCommand } from "./init.ts";
import { inboxCommand, pasteImageCommand } from "./inbox.ts";
import { projectIdCommand } from "./project-id.ts";
import { policyCommand } from "./policy.ts";
import { controlCommand } from "./control.ts";
import { resumeCommand } from "./resume.ts";
import {
  approvalsCommand,
  approveCommand,
  auditCommand,
  depsCommand,
  destroyCommand,
  forwardCommand,
  gitCommand,
  logsCommand,
  rebuildCommand,
  resourcesCommand,
  runtimeContextWithSessionName,
  sessionsCommand,
  shellCommand,
  statusCommand,
  stopCommand,
  upCommand,
  vncCommand,
} from "./runtime.ts";
import type { CommandHandlerFactory, CommandModule } from "./types.ts";
import { updateCommand } from "./update.ts";
import { versionCommand } from "./version.ts";
import { createBaseParser } from "./yargs-config.ts";

// Commands migrated to the yargs command-spec layer. The default `$0` command
// (registered below) handles everything else.
const COMMAND_MODULES: readonly CommandModule[] = [
  versionCommand,
  projectIdCommand,
  assetsCommand,
  initCommand,
  updateCommand,
  imageCommand,
  policyCommand,
  controlCommand,
  inboxCommand,
  pasteImageCommand,
  upCommand,
  auditCommand,
  approvalsCommand,
  approveCommand,
  depsCommand,
  statusCommand,
  resourcesCommand,
  sessionsCommand,
  resumeCommand,
  stopCommand,
  destroyCommand,
  shellCommand,
  rebuildCommand,
  logsCommand,
  vncCommand,
  forwardCommand,
  gitCommand,
  hostCommand,
  doctorCommand,
  runtimeAdminCommand,
  credentialCommand,
  serviceCommand,
  mcpCommand,
];

function hasHelpFlag(args: readonly string[]): boolean {
  return args.includes("--help") || args.includes("-h");
}

function hasNamedOption(args: readonly string[], names: readonly string[]): boolean {
  return args.some((arg) => names.some((name) => arg === name || arg.startsWith(`${name}=`)));
}

// Handlers never run while rendering help (`--help`/`-h` short-circuits, and a
// bare group trips `.demandCommand` before any handler), so the help parser
// wires no-ops.
const noopHelpHandler: CommandHandlerFactory = (_run) => async () => {};
const noopRunDefault = async (): Promise<number> => 0;

// A parser configured to RENDER native help rather than run: `-h`/`--help` are
// enabled and the `$0 [agent]` default is OMITTED. yargs cannot scope
// `<group> <sub> --help` to a subcommand when a `$0` default command is present
// (yargs #1500), so leaving it out — while registering every real command
// module — gives correctly scoped, comprehensive help at every level.
function createHelpParser(context: RunfreeCommandContext, args: string[]): Argv {
  // `.wrap(null)` keeps option descriptions on one line (no mid-word wrapping at
  // the detected terminal width); the terminal soft-wraps long lines instead.
  let parser = createBaseParser(args).help().alias("help", "h").version(false).wrap(null);
  for (const module of COMMAND_MODULES) {
    parser = module.register(parser, context, noopHelpHandler, noopRunDefault);
  }
  return parser;
}

// The group's own native help (its subcommand listing + examples). Parsing the
// bare group name trips its `.demandCommand(1)`; `getHelp()` is then scoped to
// that group and is the payload we surface.
async function groupHelpText(context: RunfreeCommandContext, name: string): Promise<string> {
  const parser = createHelpParser(context, [name]);
  try {
    await parser.parseAsync();
  } catch {
    // Expected: a bare group fails demandCommand. getHelp() below is the output.
  }
  return parser.getHelp();
}

// The default `$0 [agent]` command handles bare `runfree`, built-in agents, and
// project-configured agent names by resolving the optional `agent` positional
// into a typed runtime intent (default agent | named agent | unknown command).
// It is intentionally not strict about options so trailing agent-specific flags
// (e.g. `claude --resume`) are tolerated rather than rejected — but, exactly as
// the legacy path did, they are NOT forwarded: the agent runs its fixed
// configured command (RUNFREE_AGENT_COMMAND). Only `--quiet`/`--verbose` are
// interpreted by Runfree. Dry-run is honored keyed by the agent name (or
// "default") before any resolution, matching the legacy path.
export async function runAgentCommandWithControlPlaneRebindRefusal(
  context: Parameters<typeof runAgentCommand>[0],
  io: Parameters<typeof runAgentCommand>[1],
  agent: string | undefined,
  options: Parameters<typeof runAgentCommand>[3],
  run: typeof runAgentCommand = runAgentCommand,
): Promise<number> {
  const agentName = agent === undefined || agent === "" || agent === "default"
    ? resolveDefaultAgentName(context.project.config)
    : agent;
  const displayName = agentName === "" ? "The agent" : `${agentName[0]?.toUpperCase()}${agentName.slice(1)}`;
  const outcomeName = agentName === "" ? "the agent" : agentName;
  return withControlPlaneRebindRefusal({
    subject: `${displayName} did not start`,
    final: `${outcomeName} did not start`,
    verbose: options.verbose,
  }, () => run(context, io, agent, options));
}

function registerDefaultCommand(
  parser: Argv,
  context: RunfreeCommandContext,
  handler: CommandHandlerFactory,
): Argv {
  return parser.command(
    "$0 [agent]",
    false,
    (cmd) =>
      cmd
        .positional("agent", { type: "string" })
        .option("quiet", { type: "boolean" })
        .option("session-name", {
          type: "string",
          requiresArg: true,
          coerce: normalizeSessionName,
        })
        .option("use-approved-policy", { type: "boolean" })
        .option("verbose", { type: "boolean", alias: "v" })
        // Opt out of global strict: trailing agent-specific flags/positionals
        // (e.g. `claude --resume`) are tolerated here, not rejected.
        .strict(false),
    handler((argv: ArgumentsCamelCase<{ agent?: string; quiet?: boolean; "session-name"?: string; "use-approved-policy"?: boolean; verbose?: boolean }>) => {
      const rc = runtimeContextWithSessionName(context.runtimeContext(), argv["session-name"]);
      const dry = runtimeDryRun(rc, nodeRuntimeIO, argv.agent ?? "default");
      if (dry !== undefined) return dry;
      return runAgentCommandWithControlPlaneRebindRefusal(rc, nodeRuntimeIO, argv.agent, {
        quiet: Boolean(argv.quiet),
        useApprovedPolicy: Boolean(argv["use-approved-policy"]),
        verbose: Boolean(argv.verbose),
      });
    }),
  );
}

// Names the first token of an emitted `runfree ...` string can take. Used by
// the remedy parse gate: a typed command module, a built-in agent launch, or
// the task-oriented help handled before yargs.
export const EMITTED_COMMAND_ROOTS: readonly string[] = [
  ...COMMAND_MODULES.map((module) => module.name),
  "claude",
  "codex",
  "pi",
  "help",
];

// Parse-only run of the typed command app: every module registered with no-op
// handlers, strict, no `$0 [agent]` default (its tolerant grammar would accept
// any misspelled command as an agent name). Rejects like a real invocation
// would — unknown command, unknown option, missing or extra positional — and
// runs no handler and touches no project state. This is what the remedy parse
// gate (`scripts/emitted-commands.test.ts`) drives.
export async function parseEmittedCommandArgs(context: RunfreeCommandContext, args: string[]): Promise<void> {
  const root = args[0];
  if (root === undefined) throw new CliError("emitted command has no command word");
  if (root === "help") return;
  if (root === "claude" || root === "codex" || root === "pi") return;
  if (!COMMAND_MODULES.some((module) => module.name === root)) {
    throw new CliError(`unknown command: ${root}`);
  }
  // `--help` is handled before yargs and renders for any command prefix.
  if (hasHelpFlag(args.slice(1))) return;
  let parser = createBaseParser(args);
  for (const module of COMMAND_MODULES) {
    parser = module.register(parser, context, noopHelpHandler, noopRunDefault);
  }
  await parser.parseAsync();
}

export async function runCommandApp(
  context: RunfreeCommandContext,
  commandArgs: string[],
  runDefault: () => Promise<number>,
): Promise<number> {
  // Command-specific syntax help for migrated commands is rendered by yargs
  // natively (positionals, options, examples, epilogue) through a dedicated help
  // parser. The typed `$0 [agent]` default does not special-case `--help`; agent
  // flags pass through to the agent (as before).
  const leading = commandArgs[0];
  if (leading === "domain") {
    throw new CliError("`runfree domain` has been removed. Use `runfree host add <host>` for exact-host network policy.");
  }
  if (leading === "source") {
    throw new CliError("`runfree source` has been removed.\nuse: runfree credential source ...");
  }
  if (leading === "token") {
    throw new CliError("`runfree token` has been removed.\nuse: runfree credential ...");
  }
  if (leading === "host" && commandArgs[1] === "add" && hasNamedOption(commandArgs.slice(2), [
    "--token",
    "--from-env",
    "--from-1password",
    "--from-source",
    "--from-stdin",
    "--replace-source",
    "--header",
    "--scheme",
    "--path-prefix",
    "--description",
  ])) {
    throw new CliError("`host add` no longer configures credentials\nrun:\n  runfree host add <host>\n  runfree credential add <name> --host <host> --from-source <source>");
  }
  if (leading === "host" && commandArgs[1] === "remove" && hasNamedOption(commandArgs.slice(2), ["--remove-credential"])) {
    throw new CliError("`host remove --remove-credential` has been removed. Unlink credential destinations explicitly with `runfree credential unlink <name> --host <host>` first.");
  }
  const migrated = leading === undefined ? undefined : COMMAND_MODULES.find((module) => module.name === leading);
  if (migrated) {
    const rest = commandArgs.slice(1);
    if (hasHelpFlag(rest)) {
      // yargs prints the scoped command/group/subcommand help to stdout.
      await createHelpParser(context, commandArgs).parseAsync();
      return 0;
    }
    // A group command needs a subcommand: bare `runfree <group>` is a usage
    // error that shows the group's own commands (not the full reference).
    if (migrated.group && rest.length === 0) {
      // One error line names the problem; the group's usage follows as raw
      // detail. Stdout stays clean for the erroneous invocation.
      throw new CliError(`runfree ${migrated.name} needs a subcommand`, 1, {
        detail: await groupHelpText(context, migrated.name),
      });
    }
  }

  let status = 0;
  let handlerStarted = false;
  const handler: CommandHandlerFactory = (run) => async (argv) => {
    handlerStarted = true;
    const result = await run(argv);
    if (typeof result === "number") status = result;
  };

  let parser = createBaseParser(commandArgs);
  for (const module of COMMAND_MODULES) {
    parser = module.register(parser, context, handler, runDefault);
  }
  parser = registerDefaultCommand(parser, context, handler);

  try {
    await parser.parseAsync();
  } catch (error) {
    // A handler that already started owns its own failure semantics: preserve
    // CliError/AdminExit/handler errors and never reinterpret them as usage
    // errors. Only pre-handler parser/validation failures become usage errors.
    if (handlerStarted) throw error;
    throw asUsageError(error);
  }
  return status;
}
