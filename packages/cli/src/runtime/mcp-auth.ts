import { resolveAgentCommand } from "../config.ts";
import { die } from "../errors.ts";
import { flushWarnings } from "../warnings.ts";
import { type RuntimeAdapters } from "./adapters.ts";
import { launchConfiguredAgentThroughAdmission } from "./session-public-launch.ts";
import { startSessionMcpCallback, stopSessionMcpCallback } from "./session-mcp-callback.ts";
import {
  mcpApprovalPath,
  mcpInventory,
  mcpRulesPath,
  type McpAgent,
  type McpInventoryEntry,
  type McpSourceScope,
} from "./mcp.ts";
import { startRuntime, type RuntimeStartResult } from "./startup.ts";
import { preparedRuntimeContext } from "./prepared-runtime.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

export type McpAuthInput = {
  agent: McpAgent;
  server: string;
  source?: McpSourceScope;
  verbose?: boolean;
};

export type McpAuthAdapterPlan = {
  command: string[];
  extraOptions: string[];
  session: {
    agentCommand?: string;
    command: string;
  };
};

type McpAuthRuntimeDependencies = {
  adaptersFor?: (context: RuntimeContext, io: RuntimeIO) => RuntimeAdapters;
  launch?: typeof launchConfiguredAgentThroughAdmission;
  start?: typeof startRuntime;
};

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function resolveMcpAuthEntry(input: McpAuthInput, context: RuntimeContext): McpInventoryEntry {
  const inventory = mcpInventory({
    approvalPath: mcpApprovalPath(context.project.paths.stateDir),
    env: context.env ?? process.env,
    projectRoot: context.projectRoot,
    rulesPath: mcpRulesPath(context.project.paths.stateDir),
  });
  const matches = inventory.entries.filter((entry) =>
    entry.agent === input.agent
    && entry.name === input.server
    && (input.source === undefined || entry.source === input.source));
  if (matches.length === 0) {
    die(input.source
      ? `unknown ${input.source} MCP server: ${input.agent} ${input.server}`
      : `unknown MCP server: ${input.agent} ${input.server}`);
  }
  if (matches.length > 1) {
    die(`multiple MCP entries match ${input.agent} ${input.server}; pass --source user, --source local, or --source project`);
  }
  const entry = matches[0];
  if (entry.decision.status === "unsupported" || entry.decision.status === "conflict") {
    die(`cannot authenticate MCP server ${entry.agent} ${entry.name}: ${entry.decision.reason ?? entry.decision.status}`);
  }
  if (entry.source === "project" && entry.decision.status !== "approved") {
    die(`project MCP server must be approved before auth: runfree mcp approve ${entry.agent} ${entry.name}`);
  }
  if (entry.transport === "stdio") {
    die(`no OAuth login is available for stdio MCP server ${entry.agent} ${entry.name}`);
  }
  if (entry.auth === "static") {
    die(`static-header MCP server ${entry.agent} ${entry.name} uses a credential source, not OAuth login`);
  }
  if (entry.auth !== "oauth" && entry.auth !== "public") {
    die(`MCP server ${entry.agent} ${entry.name} is not OAuth-capable`);
  }
  if (!entry.endpoint) {
    die(`MCP server ${entry.agent} ${entry.name} has no HTTP endpoint for OAuth login`);
  }
  return entry;
}

export function mcpAuthAdapterPlan(context: RuntimeContext, input: Pick<McpAuthInput, "agent" | "server">): McpAuthAdapterPlan {
  if (input.agent === "codex") {
    return {
      command: ["codex", "mcp", "login", input.server],
      extraOptions: [],
      session: { command: `mcp auth codex/${input.server}` },
    };
  }

  const agentCommand = resolveAgentCommand(context.project.config, "claude")
    ?? "claude --dangerously-skip-permissions --add-dir /runfree/inbox";
  const reconnect = `/mcp reconnect ${input.server}`;
  const script = [
    "fifo=$(mktemp -u)",
    "mkfifo \"$fifo\"",
    "trap 'rm -f \"$fifo\"' EXIT",
    `printf '%s\\n' ${shellSingleQuote(`If Claude does not open MCP auth, type: ${reconnect}`)} >&2`,
    `{ sleep 1; printf '%s\\n' ${shellSingleQuote(reconnect)}; cat; } > \"$fifo\" &`,
    "exec zsh -c \"$RUNFREE_AGENT_COMMAND\" < \"$fifo\"",
  ].join("; ");
  return {
    command: ["zsh", "-lc", script],
    extraOptions: ["--env", `RUNFREE_AGENT_COMMAND=${agentCommand}`],
    session: { command: `mcp auth claude/${input.server}`, agentCommand },
  };
}

// Per-agent login instructions. Claude Code exposes MCP auth through its
// `/mcp` menu; Codex authenticates through its `codex mcp login` command, so
// telling a Codex session to "type /mcp" sent it the wrong way.
export function mcpAuthInstructionLines(agent: "claude" | "codex", server: string): string[] {
  if (agent === "codex") {
    return [
      `After codex starts, authenticate ${server} by running: codex mcp login ${server}`,
      `(ask codex to run it, or run it from \`runfree shell\`); complete the OAuth login at the URL it prints.`,
    ];
  }
  return [
    `After claude starts, type /mcp and select ${server} to authenticate.`,
    `If the auth flow does not open, type: /mcp reconnect ${server}`,
  ];
}

export async function mcpAuthRuntime(
  input: McpAuthInput,
  context: RuntimeContext,
  io: RuntimeIO,
  deps: McpAuthRuntimeDependencies = {},
): Promise<number> {
  const entry = resolveMcpAuthEntry(input, context);
  const start = deps.start ?? startRuntime;
  const runtime: RuntimeStartResult = await start(context, io, false, { verbose: input.verbose });
  if (runtime.kind === "failed") return runtime.status;
  const activeContext = preparedRuntimeContext(runtime.preparedRuntime);
  flushWarnings();
  const watcher = io.startTokenAutoRefresh?.(activeContext, runtime.tokenResolutionReceipts) ?? { stop: () => {} };
  try {
    // Instruct the operator instead of auto-typing: feeding a reconnect line
    // into the agent's stdin needs a container-side fifo, which is shell syntax
    // the typed direct-launch path deliberately cannot represent. The session
    // launch is the ordinary agent argv plus exact instructions.
    for (const line of mcpAuthInstructionLines(entry.agent, entry.name)) console.log(line);
    // The OAuth callback is a per-session two-hop path: as the session comes up,
    // stand up the mcp-callback forwarder + in-session bridge against its
    // now-known IP; tear the forwarder down once the foreground session ends
    // (its bridge dies with the container).
    try {
      return await (deps.launch ?? launchConfiguredAgentThroughAdmission)({
        preparedRuntime: runtime.preparedRuntime,
        io,
        agentName: entry.agent,
        reprepare: async () => {
          const refreshed = await start(context, io, false, { verbose: input.verbose });
          if (refreshed.kind === "failed") {
            throw new Error(`runtime re-preparation failed with status ${refreshed.status}`);
          }
          return refreshed.preparedRuntime;
        },
        onSessionRunning: async (session) => {
          // The setup warns and reports on its own failures; a broken callback
          // must not fail the launch, so its status is not propagated here.
          await startSessionMcpCallback(activeContext, io, session);
        },
      });
    } finally {
      stopSessionMcpCallback(activeContext, io);
    }
  } finally {
    watcher.stop();
  }
}
