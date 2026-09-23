// Runtime subcommands on the yargs command layer.
//
// `rebuild`, `logs`, `git`, and `vnc` are typed end-to-end: each handler builds a
// typed input, materializes the RuntimeContext lazily via
// `context.runtimeContext()`, honors the shared `RUNFREE_RUNTIME_DRY_RUN` front,
// and calls the typed runtime core directly — no `runDefault` delegation and no
// string re-parsing. See the intent-vs-enforcement principle and the spec's
// Phase 5 step 3.

import type { ArgumentsCamelCase } from "yargs";

import {
  destroyRuntime,
  logsRuntime,
  nodeRuntimeIO,
  resourcesRuntime,
  sessionsRuntime,
  shellRuntime,
  statusRuntime,
  stopRuntime,
} from "../runtime.ts";
import { createRuntimeAdapters } from "../runtime/adapters.ts";
import {
  type ApprovalsInput,
  type ApproveInput,
  approvalsRuntime,
  approveRuntime,
} from "../runtime/approvals.ts";
import { type AuditInput, auditRuntime, enableAuditMode, parseAuditDuration, type UpOptions } from "../runtime/audit.ts";
import { type DepsInput, depsRuntime } from "../runtime/dependency-overlays.ts";
import { runtimeDryRun } from "../runtime/front.ts";
import { repairWorktreeLinks } from "../runtime/git-layout.ts";
import { normalizeSessionName, renameSessionMetadata } from "../runtime/sessions.ts";
import { withControlPlaneRebindRefusal } from "../runtime/control-plane-rebind-refusal.ts";
import { startRuntime, up } from "../runtime/startup.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { type ForwardArgs, forwardOptionsFromArgs, forwardRuntime } from "../runtime/forward.ts";
import { type VncArgs, vncOptionsFromArgs, vncRuntime } from "../runtime/vnc.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { withExamples } from "./examples.ts";
import type { CommandHandlerFactory, CommandModule } from "./types.ts";

type RebuildArgs = { yes?: boolean; verbose?: boolean };
type LogsArgs = { service: "proxy"; verbose?: boolean };
type UpArgs = { verbose?: boolean; "audit-network"?: string; "use-approved-policy"?: boolean };

export function runtimeContextWithSessionName(
  context: RuntimeContext,
  sessionName: string | undefined,
): RuntimeContext {
  if (sessionName === undefined) return context;
  return {
    ...context,
    env: {
      ...context.env,
      RUNFREE_SESSION_NAME: normalizeSessionName(sessionName),
    },
  };
}

// Start the runtime, then optionally activate network audit mode — the same
// two-step the legacy `runRuntime` `up` case performs. Audit activation is a
// host-only decision applied after the runtime is up.
export async function runUp(
  rc: RuntimeContext,
  options: UpOptions & { useApprovedPolicy?: boolean },
  start: typeof up = up,
): Promise<number> {
  const status = await withControlPlaneRebindRefusal({
    subject: "The runtime did not start",
    final: "the runtime did not start",
    verbose: options.verbose === true,
  }, () => start(rc, nodeRuntimeIO, false, options));
  if (status !== 0 || options.auditDurationMs === undefined) return status;
  return enableAuditMode(rc, nodeRuntimeIO, options);
}

export const upCommand: CommandModule = {
  name: "up",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "up",
      "Start the Docker Compose runtime",
      (cmd) =>
        withExamples(
          cmd
            .option("verbose", { type: "boolean", alias: "v", describe: "Show extra startup diagnostics" })
            // `--audit-network` is valid bare (default window), as
            // `--audit-network=<duration>`, or as the space form
            // `--audit-network <duration>`. The legacy parseUpOptions grammar
            // rejected the space form; the typed yargs grammar accepts it as an
            // intentional improvement — the duration is still validated and clamped
            // to 8h, so no extra capability is granted. parseAuditDuration rejects a
            // malformed value either way.
            .option("audit-network", {
              type: "string",
              describe:
                "Temporarily permit and log non-allowlisted HTTPS hosts (duration like 45m or 2h; bare flag uses the default window)",
            })
            .option("use-approved-policy", {
              type: "boolean",
              describe: "Ignore desired drift and start with the last complete approved control snapshot",
            }),
          "up",
        ).epilogue("Audit mode is clamped to 8h; inspect it with `runfree audit status` or disable it with `runfree audit off`."),
      handler((argv: ArgumentsCamelCase<UpArgs>) => {
        // Parse the audit window before any side effect (asset materialization /
        // policy assertion in runtimeContext) so a malformed --audit-network is a
        // CliError that never touches host state.
        const options: UpOptions & { useApprovedPolicy?: boolean } = {
          verbose: Boolean(argv.verbose),
          useApprovedPolicy: Boolean(argv["use-approved-policy"]),
        };
        if (argv["audit-network"] !== undefined) {
          // "" (bare flag), `=<dur>`, and the space form all surface here as the
          // option's string value; parseAuditDuration maps "" -> default window
          // and validates any explicit duration.
          const duration = parseAuditDuration(argv["audit-network"] || undefined);
          options.auditDurationMs = duration.ms;
          options.auditClamped = duration.clamped;
        }
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "up");
        if (dry !== undefined) return dry;
        return runUp(rc, options);
      }),
    ),
};

// Materialize the runtime context, honor the dry-run front, then assert
// Docker and run the typed approvals core.
async function runApprovals(context: RunfreeCommandContext, input: ApprovalsInput): Promise<number> {
  const rc = context.runtimeContext();
  const dry = runtimeDryRun(rc, nodeRuntimeIO, "approvals");
  if (dry !== undefined) return dry;
  const adapters = createRuntimeAdapters(rc, nodeRuntimeIO);
  adapters.docker.assertAvailable();
  return approvalsRuntime(input, rc, nodeRuntimeIO);
}

type ApprovalsArgs = {
  watch?: boolean;
  "no-bell"?: boolean;
  "clear-deny"?: boolean;
  heartbeat?: boolean;
  "parent-pid"?: number;
};

// Which mode a flag combination means. Exported and named because flag
// precedence here is a decision, not plumbing: `--clear-deny` used to win
// outright and silently discard `--watch`, so an operator clearing the latch in
// order to resume approving was left with no approver attached and the next
// ask-mode write fast-denied — the posture they were undoing. The pair
// composes: clear first (see `approvalsRuntime`), then attach.
export function approvalsInputFromArgs(argv: ApprovalsArgs): ApprovalsInput {
  // Internal mode, spawned by Runfree itself around interactive sessions and
  // never combined with operator flags.
  if (argv.heartbeat) return { kind: "heartbeat", parentPid: argv["parent-pid"] ?? process.ppid };
  if (argv.watch) {
    return { kind: "watch", bell: !argv["no-bell"], ...(argv["clear-deny"] ? { clearDenyFirst: true } : {}) };
  }
  if (argv["clear-deny"]) return { kind: "clear-deny" };
  return { kind: "list" };
}

export const approvalsCommand: CommandModule = {
  name: "approvals",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "approvals",
      "Review and decide writes held for approval",
      (cmd) =>
        withExamples(
          cmd
            .option("watch", { type: "boolean", describe: "Stay attached: print held writes as they arrive and prompt for each" })
            .option("no-bell", { type: "boolean", describe: "Do not ring the terminal bell on a new held write" })
            .option("clear-deny", {
              type: "boolean",
              describe: "Revoke the runtime-wide write deny (and scoped MCP denies) and go back to asking; combine with --watch to clear, then attach",
            })
            // Hidden internal mode: the attached-session approver heartbeat
            // child spawned around interactive sessions.
            .option("heartbeat", { type: "boolean", hidden: true })
            .option("parent-pid", { type: "number", hidden: true }),
          "approvals",
        ).epilogue("Writes to ask-mode hosts pause until approved here or with `runfree approve <id>`. Running --watch registers you as the attached approver. Session-scoped approvals cover the requesting session and expire; `--clear-deny` undoes a \"stop asking\" decision, and with --watch it clears first, then attaches."),
      handler((argv: ArgumentsCamelCase<ApprovalsArgs>) => runApprovals(context, approvalsInputFromArgs(argv))),
    ),
};

export const approveCommand: CommandModule = {
  name: "approve",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "approve <id>",
      "Decide one held write (scriptable, never prompts)",
      (cmd) =>
        withExamples(
          cmd
            .positional("id", { type: "string", demandOption: true, describe: "approval id (any unambiguous prefix)" })
            .option("deny", { type: "boolean", describe: "Deny this request" })
            .option("scope", {
              type: "string",
              requiresArg: true,
              choices: ["request", "session", "deny-session"] as const,
              describe: "Grant scope for an approval (default: this request only)",
            })
            .option("mcp-scope", {
              type: "string",
              requiresArg: true,
              choices: ["tool", "method", "server-tools"] as const,
              describe: "For MCP session decisions, bind scope to one tool, one method, or all server tool calls",
            })
            .option("save-mcp-rule", {
              type: "string",
              requiresArg: true,
              choices: ["tool", "server-tools"] as const,
              describe: "For an MCP tool call, save an allow rule before approving this request",
            })
            .option("ttl", { type: "string", requiresArg: true, describe: "Session-grant duration with --scope session (like 15m, max 8h)" }),
          "approve",
        ).epilogue("The default scope is the narrowest (this request only); wider grants are explicit flags."),
      handler((argv: ArgumentsCamelCase<{ id: string; deny?: boolean; "mcp-scope"?: string; "save-mcp-rule"?: string; scope?: string; ttl?: string }>) => {
        const input: ApproveInput = {
          id: argv.id,
          deny: Boolean(argv.deny),
          mcpScope: argv["mcp-scope"] as ApproveInput["mcpScope"],
          saveMcpRule: argv["save-mcp-rule"] as ApproveInput["saveMcpRule"],
          scope: argv.scope as ApproveInput["scope"],
          ttl: argv.ttl,
        };
        return (async () => {
          const rc = context.runtimeContext();
          const dry = runtimeDryRun(rc, nodeRuntimeIO, "approve");
          if (dry !== undefined) return dry;
          const adapters = createRuntimeAdapters(rc, nodeRuntimeIO);
          adapters.docker.assertAvailable();
          return approveRuntime(input, rc, nodeRuntimeIO);
        })();
      }),
    ),
};

// Materialize the runtime context, honor the dry-run front, then assert Docker
// and run the typed audit core — mirroring the legacy `audit` switch case.
function runAudit(context: RunfreeCommandContext, input: AuditInput): number {
  const rc = context.runtimeContext();
  const dry = runtimeDryRun(rc, nodeRuntimeIO, "audit");
  if (dry !== undefined) return dry;
  const adapters = createRuntimeAdapters(rc, nodeRuntimeIO);
  adapters.docker.assertAvailable();
  return auditRuntime(input, rc, nodeRuntimeIO);
}

export const auditCommand: CommandModule = {
  name: "audit",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "audit <subcommand>",
      "Inspect or disable network audit mode",
      (audit) => {
        const built = audit
          .command("status", "Show audit mode state and expiry", (cmd) => cmd, handler(() => runAudit(context, { kind: "status" })))
          .command("off", "Disable audit mode immediately", (cmd) => cmd, handler(() => runAudit(context, { kind: "off" })))
          .command(
            "report",
            "Summarize non-allowlisted HTTPS hosts observed during audit",
            (cmd) => cmd.option("json", { type: "boolean", describe: "Emit the report as JSON" }),
            handler((argv: ArgumentsCamelCase<{ json?: boolean }>) => runAudit(context, { kind: "report", json: Boolean(argv.json) })),
          );
        return withExamples(built, "audit")
          .epilogue("Audit mode permits and logs non-allowlisted HTTPS; activate it with `runfree up --audit-network[=<duration>]`.")
          .demandCommand(1);
      },
      () => {},
    ),
};

// Materialize the runtime context, honor the dry-run front, then run the typed
// deps core. Mirrors the legacy `deps` switch case (which performs no top-level
// Docker assertion; each subcommand asserts as needed).
async function runDeps(context: RunfreeCommandContext, input: DepsInput): Promise<number> {
  const rc = context.runtimeContext();
  const dry = runtimeDryRun(rc, nodeRuntimeIO, "deps");
  if (dry !== undefined) return dry;
  return depsRuntime(input, rc, nodeRuntimeIO, createRuntimeAdapters(rc, nodeRuntimeIO), startRuntime);
}

export const depsCommand: CommandModule = {
  name: "deps",
  // Not `group: true`: bare `runfree deps` defaults to `plan` rather than being a
  // usage error, so it must reach yargs (where the group default handler runs).
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "deps",
      "Manage dependency overlays",
      (deps) => {
        const built = deps
          .command("plan", "Show the dependency overlay plan", (cmd) => cmd, handler(() => runDeps(context, { kind: "plan" })))
          .command("install", "Install project dependencies into overlay volumes", (cmd) => cmd, handler(() => runDeps(context, { kind: "install" })))
          .command("doctor", "Report dependency overlay drift", (cmd) => cmd, handler(() => runDeps(context, { kind: "doctor" })))
          .command(
            "reset",
            "Remove this project's Runfree dependency volumes",
            (cmd) => cmd.option("force", { type: "boolean", alias: "f", describe: "Skip the confirmation prompt" }),
            handler((argv: ArgumentsCamelCase<{ force?: boolean }>) => runDeps(context, { kind: "reset", force: Boolean(argv.force) })),
          );
        return withExamples(built, "deps").epilogue(
          "Dependency overlays keep installed packages in Docker volumes outside the agent's writable workspace. 'reset' prompts before removing volumes unless --force/-f is given.",
        );
      },
      // Bare `runfree deps` defaults to `plan`; an unknown subcommand is rejected
      // by strictCommands before this runs.
      handler(() => runDeps(context, { kind: "plan" })),
    ),
};

export const rebuildCommand: CommandModule = {
  name: "rebuild",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "rebuild",
      "Rebuild/recreate the Docker Compose runtime",
      (cmd) =>
        withExamples(
          cmd
            .option("yes", { type: "boolean", alias: "y", describe: "Do not prompt before recreating the runtime" })
            .option("verbose", { type: "boolean", alias: "v", describe: "Show extra startup diagnostics" }),
          "rebuild",
        ),
      handler((argv: ArgumentsCamelCase<RebuildArgs>) => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "rebuild");
        if (dry !== undefined) return dry;
        return up(rc, nodeRuntimeIO, true, { assumeYes: Boolean(argv.yes), verbose: Boolean(argv.verbose) });
      }),
    ),
};

export const logsCommand: CommandModule = {
  name: "logs",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "logs <service>",
      "Follow logs for the proxy service",
      (cmd) =>
        withExamples(
          cmd
            .positional("service", { choices: ["proxy"] as const, describe: "service to follow", demandOption: true })
            .option("verbose", { type: "boolean", describe: "Log allowed proxy request metadata" }),
          "logs",
        ),
      handler((argv: ArgumentsCamelCase<LogsArgs>) => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "logs");
        if (dry !== undefined) return dry;
        return logsRuntime(rc, nodeRuntimeIO, { service: argv.service, verbose: Boolean(argv.verbose) });
      }),
    ),
};

export const gitCommand: CommandModule = {
  name: "git",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "git <subcommand>",
      "Git worktree maintenance",
      (cmd) =>
        withExamples(
          cmd.positional("subcommand", {
            choices: ["repair-worktree-links"] as const,
            describe: "git maintenance action",
            demandOption: true,
          }),
          "git",
        ),
      handler(() => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "git");
        if (dry !== undefined) return dry;
        return repairWorktreeLinks(rc, nodeRuntimeIO);
      }),
    ),
};

export const vncCommand: CommandModule = {
  name: "vnc",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "vnc [action]",
      "Manage the loopback VNC forward sidecar",
      (cmd) =>
        withExamples(
          cmd
            .positional("action", { choices: ["start", "stop", "status", "restart"] as const, describe: "vnc action" })
            .option("host-port", { type: "string", requiresArg: true, describe: "Host loopback port to publish (default 5901)" })
            .option("agent-port", { type: "string", requiresArg: true, describe: "Agent x11vnc port to forward to (default 5901)" })
            .option("display", { type: "string", requiresArg: true, describe: "Agent X display to capture (default :0)" })
            .option("password", { type: "string", requiresArg: true, describe: "VNC password (a random one is generated otherwise)" })
            // `no-password` / `no-start-server` are LITERAL option names, not
            // negations of `password` / `start-server`. This relies on the global
            // `boolean-negation: false` parser setting; with negation enabled yargs
            // would read these as `--password=false` etc. and strict parsing would
            // reject the documented flags. Covered by an app.test.ts regression.
            .option("no-password", { type: "boolean", describe: "Start without a password (loopback port is reachable by all local users)" })
            .option("clipboard", { type: "boolean", describe: "Share the clipboard with the untrusted agent display" })
            .option("no-start-server", { type: "boolean", describe: "Do not start x11vnc in the agent; only forward" }),
          "vnc",
        ),
      handler((argv: ArgumentsCamelCase<VncArgs>) => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "vnc");
        if (dry !== undefined) return dry;
        const options = vncOptionsFromArgs(argv, rc.env ?? {});
        return vncRuntime(options, rc, nodeRuntimeIO, createRuntimeAdapters(rc, nodeRuntimeIO));
      }),
    ),
};

export const forwardCommand: CommandModule = {
  name: "forward",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "forward [port] [action]",
      "Open a loopback host→agent port forward",
      (cmd) =>
        withExamples(
          cmd
            .positional("port", { type: "string", describe: "Port to forward (publishes 127.0.0.1:<port> → agent:<port>)" })
            .positional("action", { choices: ["start", "stop", "status"] as const, describe: "forward action (default start)" })
            .option("host-port", { type: "string", requiresArg: true, describe: "Host loopback port to publish (default <port>)" })
            .option("agent-port", { type: "string", requiresArg: true, describe: "Agent port to forward to (default <port>)" }),
          "forward",
        ),
      handler((argv: ArgumentsCamelCase<ForwardArgs>) => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "forward");
        if (dry !== undefined) return dry;
        const options = forwardOptionsFromArgs(argv);
        return forwardRuntime(options, rc, nodeRuntimeIO, createRuntimeAdapters(rc, nodeRuntimeIO));
      }),
    ),
};

// Build a no-option runtime command module: materialize the runtime context,
// honor the dry-run front, then run a typed core. Used by the read-only/teardown
// commands (status/resources/sessions/stop/destroy).
function simpleRuntimeCommand(spec: {
  name: string;
  command: string | string[];
  dryRunKey: string;
  describe: string;
  core: (context: RuntimeContext, io: RuntimeIO) => number | Promise<number>;
}): CommandModule {
  return {
    name: spec.name,
    register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
      parser.command(
        spec.command,
        spec.describe,
        (cmd) => cmd,
        handler(() => {
          const rc = context.runtimeContext();
          const dry = runtimeDryRun(rc, nodeRuntimeIO, spec.dryRunKey);
          if (dry !== undefined) return dry;
          return spec.core(rc, nodeRuntimeIO);
        }),
      ),
  };
}

export const statusCommand: CommandModule = {
  name: "status",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "status",
      "Show the runtime container status",
      (cmd) => cmd.option("verbose", { type: "boolean", alias: "v", describe: "Show the full runtime component and lifecycle diagnosis with untruncated digests" }),
      handler((argv: ArgumentsCamelCase<{ verbose?: boolean }>) => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "status");
        if (dry !== undefined) return dry;
        return statusRuntime(rc, nodeRuntimeIO, { verbose: Boolean(argv.verbose) });
      }),
    ),
};

export const resourcesCommand = simpleRuntimeCommand({
  name: "resources",
  command: "resources",
  dryRunKey: "resources",
  describe: "Show runtime container resource usage",
  core: resourcesRuntime,
});

export const sessionsCommand: CommandModule = {
  name: "sessions",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "sessions",
      "List or rename agent sessions",
      (sessions) =>
        sessions.command(
          "rename <session-id> <name>",
          "Rename one agent session",
          (cmd) =>
            cmd
              .positional("session-id", {
                type: "string",
                demandOption: true,
                describe: "exact Runfree session id",
              })
              .positional("name", {
                type: "string",
                demandOption: true,
                describe: "new display name",
                coerce: normalizeSessionName,
              }),
          handler((argv: ArgumentsCamelCase<{ "session-id": string; name: string }>) => {
            const rc = context.runtimeContext();
            const dry = runtimeDryRun(rc, nodeRuntimeIO, "sessions rename");
            if (dry !== undefined) return dry;
            const renamed = renameSessionMetadata(rc, argv["session-id"], argv.name);
            console.log(`renamed ${renamed.id} to ${renamed.name}`);
            return 0;
          }),
        ),
      handler(() => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "sessions");
        if (dry !== undefined) return dry;
        return sessionsRuntime(rc, nodeRuntimeIO);
      }),
    ),
};

export const stopCommand: CommandModule = {
  name: "stop",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) => parser.command(
    "stop", "Stop this project's runtime",
    (cmd) => cmd.option("force", { type: "boolean", default: false, describe: "Interrupt network access for live sessions" }),
    handler((argv: ArgumentsCamelCase<{ force: boolean }>) => {
      const rc = context.runtimeContext();
      const dry = runtimeDryRun(rc, nodeRuntimeIO, "stop");
      if (dry !== undefined) return dry;
      return stopRuntime(rc, nodeRuntimeIO, { force: argv.force });
    }),
  ),
};

export const destroyCommand: CommandModule = {
  name: "destroy",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "destroy",
      "Destroy this project's runtime",
      (cmd) =>
        cmd
          .option("force", {
            type: "boolean",
            default: false,
            describe: "End live sessions and remove unclaimed project residue",
          })
          .epilogue(
            "Without --force, destroy refuses to end live sessions and only reports containers "
            + "that carry this project's label but that no lifecycle record claims.",
          ),
      handler((argv: ArgumentsCamelCase<{ force: boolean }>) => {
        const rc = context.runtimeContext();
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "destroy");
        if (dry !== undefined) return dry;
        return destroyRuntime(rc, nodeRuntimeIO, { force: argv.force });
      }),
    ),
};

export const shellCommand: CommandModule = {
  name: "shell",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "shell",
      "Open an interactive shell in the agent container",
      (cmd) =>
        cmd
          .option("verbose", { type: "boolean", alias: "v", describe: "Show extra startup diagnostics" })
          .option("session-name", {
            type: "string",
            requiresArg: true,
            describe: "Set the session display name",
            coerce: normalizeSessionName,
          })
          .epilogue("Start the runtime if needed and open an interactive shell in the agent container."),
      handler((argv: ArgumentsCamelCase<{ "session-name"?: string; verbose?: boolean }>) => {
        const rc = runtimeContextWithSessionName(context.runtimeContext(), argv["session-name"]);
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "shell");
        if (dry !== undefined) return dry;
        return shellRuntime(rc, nodeRuntimeIO, { verbose: Boolean(argv.verbose) });
      }),
    ),
};
