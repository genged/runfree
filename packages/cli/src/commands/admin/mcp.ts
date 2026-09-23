// `runfree mcp <list|explain|approve|revoke>` — Runfree import and project-local
// approval of MCP servers.
//
// Typed end-to-end: the yargs module converts argv into a typed intent and calls
// the shared MCP enforcement (which re-validates credential sources, descriptor
// digests, and approval state). See the intent-vs-enforcement principle.

import type { ArgumentsCamelCase, Argv } from "yargs";

import { MCP_AGENT_IDS } from "../../agents.ts";
import { createAdminState } from "../../admin/context.ts";
import {
  type McpApproveInput,
  type McpConfigureInput,
  type McpRulesInput,
  mcpApproveIntent,
  mcpConfigureIntent,
  mcpExplainIntent,
  mcpListIntent,
  mcpRulesIntent,
  mcpRevokeIntent,
  parseMcpAgent,
  parseMcpSource,
  runAdminAction,
  credentialSourceSelectionFromArgs,
} from "../../admin/options.ts";
import { mcpAuthRuntime } from "../../runtime/mcp-auth.ts";
import { nodeRuntimeIO } from "../../runtime.ts";
import type { RunfreeCommandContext } from "../context.ts";
import { withExamples } from "../examples.ts";
import type { CommandHandlerFactory, CommandModule } from "../types.ts";

const TOKEN_SOURCE_GROUP = "Credential source (choose at most one):";

type AgentServerArgs = { agent: string; server: string };
type ConfigureArgs = { agent?: string[]; server?: string };
type ExplainArgs = AgentServerArgs & { source?: string; json?: boolean };
type RulesArgs = AgentServerArgs & { source?: string; tool?: string; write?: "allow" | "ask" | "deny" };
type AuthArgs = AgentServerArgs & { source?: string };
type ApproveArgs = AgentServerArgs & {
  "from-env"?: string;
  "from-1password"?: string;
  "from-source"?: string;
  "from-stdin"?: boolean;
  login?: boolean;
  "replace-source"?: boolean;
};

const agentServerPositionals = (cmd: Argv): Argv =>
  cmd
    .positional("agent", { type: "string", demandOption: true, describe: `Agent ID that owns the server (${MCP_AGENT_IDS.join(" or ")})` })
    .positional("server", { type: "string", demandOption: true, describe: "MCP server name" });

function approveTokenSource(argv: ArgumentsCamelCase<ApproveArgs>): McpApproveInput["tokenSource"] {
  return credentialSourceSelectionFromArgs({
    env: argv["from-env"],
    onePassword: argv["from-1password"],
    source: argv["from-source"],
    stdin: argv["from-stdin"],
  });
}

export const mcpCommand: CommandModule = {
  name: "mcp",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) => {
    const run = (action: () => Promise<void> | void): Promise<number> =>
      runAdminAction(createAdminState(context.adminContext()), action);
    return parser.command(
      "mcp",
      "Import and approve MCP servers",
      (mcp) => {
        // Each handler builds the typed intent FIRST (so a parse/validation
        // failure fails before any admin-state setup or project init), then
        // runs the shared enforcement.
        const built = mcp
          .command(
            "list",
            "Show user, local, and project MCP entries with Runfree decisions",
            (cmd) => cmd.option("json", { type: "boolean", describe: "Emit the entries and decisions as JSON" }),
            handler((argv: ArgumentsCamelCase<{ json?: boolean }>) => {
              const json = Boolean(argv.json);
              return run(() => mcpListIntent({ json }));
            }),
          )
          .command(
            "configure",
            "Configure MCP servers and tool-call rules interactively",
            (cmd) =>
              cmd
                .option("agent", {
                  type: "string",
                  array: true,
                  requiresArg: true,
                  nargs: 1,
                  describe: `Include only this agent ID (repeatable; ${MCP_AGENT_IDS.join(" or ")})`,
                })
                .option("server", { type: "string", requiresArg: true, describe: "Limit to one MCP server name" })
                .epilogue("Non-interactive scripts should use runfree mcp list/approve/rules/auth directly."),
            handler((argv: ArgumentsCamelCase<ConfigureArgs>) => {
              const intent: McpConfigureInput = {
                agents: argv.agent?.map((agent) => parseMcpAgent(agent)),
                server: argv.server,
              };
              return (async () => {
                let result: Awaited<ReturnType<typeof mcpConfigureIntent>> = {};
                const status = await run(async () => {
                  result = await mcpConfigureIntent(intent);
                });
                if (status !== 0 || !result.auth) return status;
                return mcpAuthRuntime(result.auth, context.runtimeContext(), nodeRuntimeIO);
              })();
            }),
          )
          .command(
            "explain <agent> <server>",
            "Show the normalized descriptor and import/approval decision",
            (cmd) =>
              agentServerPositionals(cmd)
                .option("source", { type: "string", requiresArg: true, describe: "Limit to a config source (user | local | project)" })
                .option("json", { type: "boolean", describe: "Emit the descriptor and decision as JSON" }),
            handler((argv: ArgumentsCamelCase<ExplainArgs>) => {
              const intent = {
                agent: parseMcpAgent(argv.agent),
                server: argv.server,
                source: parseMcpSource(argv.source),
                json: Boolean(argv.json),
              };
              return run(() => mcpExplainIntent(intent));
            }),
          )
          .command(
            "approve <agent> <server>",
            "Approve a project-local MCP server and optionally bind a credential",
            (cmd) =>
              agentServerPositionals(cmd)
                .option("from-env", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Read the token from this host env var" })
                .option("from-1password", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Read the token from a 1Password secret ref (op://...)" })
                .option("from-source", { type: "string", requiresArg: true, group: TOKEN_SOURCE_GROUP, describe: "Bind a previously-saved host-owned source" })
                .option("from-stdin", { type: "boolean", group: TOKEN_SOURCE_GROUP, describe: "Read the token from stdin" })
                .option("login", { type: "boolean", describe: "After approval, start the validated runtime and run MCP OAuth login for this server" })
                .option("replace-source", { type: "boolean", describe: "Overwrite an existing credential source for this server" })
                .epilogue("Static headers require a host-owned credential source; the real token never enters the agent."),
            handler((argv: ArgumentsCamelCase<ApproveArgs>) => {
              const intent: McpApproveInput = {
                agent: parseMcpAgent(argv.agent),
                server: argv.server,
                tokenSource: approveTokenSource(argv),
                replaceSource: Boolean(argv["replace-source"]),
              };
              return (async () => {
                const status = await run(() => mcpApproveIntent(intent));
                if (status !== 0 || !argv.login) return status;
                return mcpAuthRuntime({
                  agent: intent.agent,
                  server: intent.server,
                  source: "project",
                }, context.runtimeContext(), nodeRuntimeIO);
              })();
            }),
          )
          .command(
            "auth <agent> <server>",
            "Run agent-native MCP OAuth login inside the validated runtime",
            (cmd) =>
              agentServerPositionals(cmd)
                .option("source", { type: "string", requiresArg: true, describe: "Limit to a config source (user | local | project)" })
                .epilogue("OAuth login runs inside the Runfree agent container after runtime validation; static-header and stdio servers are not auth targets."),
            handler((argv: ArgumentsCamelCase<AuthArgs>) => {
              const intent = {
                agent: parseMcpAgent(argv.agent),
                server: argv.server,
                source: parseMcpSource(argv.source),
              };
              return mcpAuthRuntime(intent, context.runtimeContext(), nodeRuntimeIO);
            }),
          )
          .command(
            "rules <agent> <server>",
            "Show or set MCP tool-call handling rules",
            (cmd) =>
              agentServerPositionals(cmd)
                .option("source", { type: "string", requiresArg: true, describe: "Limit to a config source (user | local | project)" })
                .option("tool", { type: "string", requiresArg: true, describe: "Apply the rule to one MCP tool name instead of all tools" })
                .option("write", {
                  type: "string",
                  requiresArg: true,
                  choices: ["allow", "ask", "deny"] as const,
                  describe: "Set handling for side-effecting MCP tool calls",
                }),
            handler((argv: ArgumentsCamelCase<RulesArgs>) => {
              const intent: McpRulesInput = {
                agent: parseMcpAgent(argv.agent),
                server: argv.server,
                source: parseMcpSource(argv.source),
                tool: argv.tool,
                write: argv.write,
              };
              return run(() => mcpRulesIntent(intent));
            }),
          )
          .command(
            "revoke <agent> <server>",
            "Remove project-local MCP approval",
            (cmd) => agentServerPositionals(cmd),
            handler((argv: ArgumentsCamelCase<AgentServerArgs>) => {
              const intent = { agent: parseMcpAgent(argv.agent), server: argv.server };
              return run(() => mcpRevokeIntent(intent));
            }),
          );
        return withExamples(built, "mcp")
          .epilogue("Project .mcp.json / .codex/config.toml entries are imported only after 'runfree mcp approve'.")
          .demandCommand(1);
      },
      () => {},
    );
  },
};
