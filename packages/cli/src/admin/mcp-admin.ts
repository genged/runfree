// MCP typed intents + runtime preparation (split from options.ts). Shared MCP
// inventory and policy machinery lives in admin-core.ts.

import fs from "node:fs";
import path from "node:path";
import {
  validateNetworkPolicy,
  type PolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import { confirm as confirmPrompt, isCancel, select, text } from "@clack/prompts";
import { agentChoiceLabel, isMcpAgentId, MCP_AGENT_IDS } from "../agents.ts";
import {
  type McpAgent,
  mcpApprovalPath,
  mcpInventory,
  type McpInventoryEntry,
  mcpOAuthCallbackPort,
  mcpRuleKeyForEntry,
  mcpRulesPath,
  readMcpRules,
  type McpSourceScope,
  prepareMcpRuntime,
  revokeMcpApproval,
  saveMcpApproval,
  writeMcpRules,
} from "../runtime/mcp.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import {
  formatTerminalTable,
} from "../terminal-table.ts";
import {
  childEnv,
  describeSource,
  die,
  ensureStateDirs,
  loadTokenConfig,
  type McpApproveInput,
  type McpConfigureInput,
  type McpExplainInput,
  type McpRulesInput,
  type McpRevokeInput,
  mcpOperationPolicyPath,
  oauthMediationPolicyPath,
  projectRoot,
  saveTokenConfig,
  saveTokenSource,
  stateDir,
  tokenSourceFromSelection,
} from "./admin-core.ts";

export type McpConfigureResult = {
  auth?: {
    agent: McpAgent;
    server: string;
    source?: McpSourceScope;
  };
};

export function mcpListIntent(input: { json: boolean }): void {
  const inventory = mcpInventory({
    projectRoot: projectRoot(),
    env: childEnv(),
    approvalPath: mcpApprovalPath(stateDir()),
    rulesPath: mcpRulesPath(stateDir()),
  });
  if (input.json) {
    console.log(JSON.stringify(inventory, null, 2));
    return;
  }
  console.log(formatTerminalTable({
    columns: [
      { label: "SOURCE" },
      { label: "AGENT" },
      { label: "SERVER" },
      { label: "TRANSPORT" },
      { label: "AUTH" },
      { label: "STATUS" },
      { label: "MCP POLICY" },
      { label: "TARGET" },
    ],
    rows: inventory.entries.map((entry) => [
      entry.source,
      entry.agent,
      entry.name,
      entry.transport,
      entry.auth,
      entry.decision.status,
      entry.mcpPolicy?.summary ?? "-",
      entry.target,
    ]),
  }));
}

export function parseMcpAgent(value: string | undefined): McpAgent {
  if (isMcpAgentId(value)) return value;
  die(`MCP agent must be ${MCP_AGENT_IDS.join(" or ")}`);
}

export function parseMcpSource(value: string | undefined): McpSourceScope | undefined {
  if (value === undefined) return undefined;
  if (value === "user" || value === "local" || value === "project") return value;
  die("--source must be user, local, or project");
}

function findMcpEntry(agent: McpAgent, serverName: string, source?: McpSourceScope): McpInventoryEntry {
  const inventory = mcpInventory({
    projectRoot: projectRoot(),
    env: childEnv(),
    approvalPath: mcpApprovalPath(stateDir()),
    rulesPath: mcpRulesPath(stateDir()),
  });
  const matches = inventory.entries.filter((candidate) => candidate.agent === agent && candidate.name === serverName && (source === undefined || candidate.source === source));
  if (matches.length === 0) {
    die(source ? `unknown ${source} MCP server: ${agent} ${serverName}` : `unknown MCP server: ${agent} ${serverName}`);
  }
  if (matches.length > 1) {
    die(`multiple MCP entries match ${agent} ${serverName}; pass --source user, --source local, or --source project`);
  }
  return matches[0];
}

function interactiveTty(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

export function mcpApproveIntent(input: McpApproveInput): void {
  const { agent, server: serverName } = input;
  const approvalFile = mcpApprovalPath(stateDir());
  const entry = findMcpEntry(agent, serverName, "project");
  if (entry.decision.status === "unsupported") {
    die(`cannot approve unsupported project MCP server: ${entry.decision.reason ?? "unsupported MCP configuration"}`);
  }
  if (entry.decision.status === "conflict") {
    die(`cannot approve project MCP server ${agent} ${serverName}: ${entry.decision.reason ?? "conflict"}`);
  }

  const hasSource = input.tokenSource.kind !== "none";
  if (entry.auth === "static") {
    const bindings = entry.tokenBindings ?? [];
    const configured = loadTokenConfig();
    const missingBindings = bindings.filter((binding) => !configured[binding.tokenName]);
    if (bindings.length > 1 && hasSource) {
      die([
        "static project MCP server has multiple credential bindings; configure each credential source explicitly:",
        ...bindings.map((binding) => `runfree credential set-source ${binding.tokenName} --from-env ${binding.tokenName.toUpperCase().replace(/[^A-Z0-9_]+/g, "_")}_TOKEN`),
      ].join("\n"));
    }
    if (hasSource) {
      const source = tokenSourceFromSelection(input.tokenSource, true);
      if (!source) throw new Error("internal error: required credential source was not parsed");
      for (const binding of bindings) {
        const sourceChanged = saveTokenSource(binding.tokenName, source, { replaceSource: input.replaceSource }).changed;
        console.log(`credential source: ${sourceChanged ? "configured" : "unchanged"} ${binding.tokenName} (${describeSource(source)})`);
      }
    } else if (missingBindings.length > 0) {
      die("static project MCP credentials require --from-env, --from-1password, or --from-source");
    }
  } else if (hasSource) {
    die("--from-* is only valid for static-header project MCP servers");
  }

  const approval = saveMcpApproval(projectRoot(), approvalFile, entry);
  console.log(`approved project MCP server: ${agent} ${serverName}`);
  console.log(`approval: ${approvalFile}`);
  console.log(`digest: ${approval.digest}`);
}

export function mcpExplainIntent(input: McpExplainInput): void {
  const { agent, server: serverName, source, json } = input;
  const entry = findMcpEntry(agent, serverName, source);
  if (json) {
    console.log(JSON.stringify(entry, null, 2));
    return;
  }
  console.log(`source: ${entry.source}`);
  console.log(`agent: ${entry.agent}`);
  console.log(`server: ${entry.name}`);
  if (entry.sourcePath) console.log(`source file: ${entry.sourcePath}`);
  console.log(`transport: ${entry.transport}`);
  console.log(`auth: ${entry.auth}`);
  console.log(`status: ${entry.decision.status}`);
  if (entry.decision.reason) console.log(`reason: ${entry.decision.reason}`);
  console.log(`target: ${entry.target}`);
  if (entry.endpoint) console.log(`endpoint: ${entry.endpoint.host}${entry.endpoint.path}`);
  if (entry.mcpPolicy) {
    console.log(`server id: ${entry.mcpPolicy.operationServerId}`);
    console.log(`MCP tool default: ${entry.mcpPolicy.defaultToolWriteAction ?? "ask"}`);
    for (const [tool, rule] of Object.entries(entry.mcpPolicy.tools).sort(([left], [right]) => left.localeCompare(right))) {
      console.log(`MCP tool rule: ${tool} ${rule.writeAction}`);
    }
    const sourceFlag = ` --source ${entry.source}`;
    console.log(`change: runfree mcp rules ${entry.agent} ${entry.name}${sourceFlag} --write ${entry.mcpPolicy.defaultToolWriteAction ?? "ask"}`);
  }
  if (entry.descriptorDigest) console.log(`digest: ${entry.descriptorDigest}`);
  for (const binding of entry.tokenBindings ?? []) {
    console.log(`credential binding: ${binding.tokenName} -> ${binding.credential.host} ${binding.credential.header} ${binding.credential.scheme}${binding.credential.pathPrefix ? ` ${binding.credential.pathPrefix}` : ""}`);
  }
  if (entry.descriptor) {
    console.log("descriptor:");
    console.log(JSON.stringify(entry.descriptor, null, 2));
  }
  if (entry.source === "project" && (entry.decision.status === "unapproved" || entry.decision.status === "changed")) {
    const staticHint = entry.auth === "static" ? " --from-env <ENV>" : "";
    console.log(`approve: runfree mcp approve ${entry.agent} ${entry.name}${staticHint}`);
  }
  if (entry.source === "project" && entry.decision.status === "approved") {
    console.log(`revoke: runfree mcp revoke ${entry.agent} ${entry.name}`);
  }
}

export function mcpRulesIntent(input: McpRulesInput): void {
  const entry = findMcpEntry(input.agent, input.server, input.source);
  if (entry.decision.status === "unsupported" || entry.decision.status === "conflict") {
    die(`cannot set MCP rules for ${entry.agent} ${entry.name}: ${entry.decision.reason ?? entry.decision.status}`);
  }
  if (entry.source === "project" && entry.decision.status !== "approved") {
    die(`cannot set MCP rules for unapproved project MCP server: runfree mcp approve ${entry.agent} ${entry.name}`);
  }
  if (!entry.endpoint || !entry.mcpPolicy) {
    die("MCP rules apply only to HTTP MCP servers imported through the proxy");
  }
  const key = mcpRuleKeyForEntry(entry);
  if (!key) die("MCP server has no stable rule identity");
  const rulesFile = mcpRulesPath(stateDir());
  const rules = readMcpRules(projectRoot(), rulesFile);
  const current = rules.rules[key] ?? {
    agent: entry.agent,
    identity: key,
    schemaVersion: 1 as const,
    server: entry.name,
    source: entry.source,
    updatedAt: new Date().toISOString(),
  };

  if (input.write !== undefined) {
    const next = {
      ...current,
      updatedAt: new Date().toISOString(),
    };
    if (input.tool) {
      next.tools = { ...(next.tools ?? {}), [input.tool]: { writeAction: input.write } };
    } else {
      next.defaultToolWriteAction = input.write;
    }
    rules.rules[key] = next;
    writeMcpRules(projectRoot(), rulesFile, rules);
  }

  const saved = rules.rules[key];
  console.log(`server: ${entry.agent} ${entry.name} (${entry.source})`);
  console.log(`endpoint: ${entry.endpoint.host}${entry.endpoint.path}`);
  console.log(`server id: ${entry.mcpPolicy.operationServerId}`);
  console.log(`rules: ${rulesFile}`);
  console.log(`MCP tool default: ${saved?.defaultToolWriteAction ?? "ask"}`);
  for (const [tool, rule] of Object.entries(saved?.tools ?? {}).sort(([left], [right]) => left.localeCompare(right))) {
    console.log(`MCP tool rule: ${tool} ${rule.writeAction}`);
  }
}

async function promptTokenSourceForStatic(entry: McpInventoryEntry): Promise<McpApproveInput["tokenSource"] | undefined> {
  const choice = await select({
    message: `Credential source for ${agentChoiceLabel(entry.agent)} / ${entry.name}`,
    options: [
      { value: "env", label: "Host env var" },
      { value: "1password", label: "1Password reference" },
      { value: "source", label: "Named source" },
      { value: "none", label: "Cancel approval" },
    ],
  });
  if (isCancel(choice) || choice === "none") return undefined;
  const answer = await text({
    message: choice === "env"
      ? "Env var name"
      : choice === "1password"
        ? "1Password ref (op://...)"
        : "Source name",
  });
  if (isCancel(answer) || answer.trim() === "") return undefined;
  if (choice === "env") return { kind: "env", env: answer.trim() };
  if (choice === "1password") return { kind: "1password", ref: answer.trim() };
  return { kind: "named", name: answer.trim() };
}

type ConfigureChange = {
  apply: () => Promise<void> | void;
  label: string;
};

export async function mcpConfigureIntent(input: McpConfigureInput): Promise<McpConfigureResult> {
  if (!interactiveTty()) {
    die("runfree mcp configure requires a TTY; use runfree mcp list/approve/rules for scripts");
  }
  const inventory = mcpInventory({
    projectRoot: projectRoot(),
    env: childEnv(),
    approvalPath: mcpApprovalPath(stateDir()),
    rulesPath: mcpRulesPath(stateDir()),
  });
  const selectedAgents = input.agents?.length ? new Set(input.agents) : undefined;
  const entries = inventory.entries.filter((entry) =>
    (selectedAgents === undefined || selectedAgents.has(entry.agent))
    && (input.server === undefined || entry.name === input.server));
  if (entries.length === 0) {
    console.log("Configure MCP servers and tool-call rules");
    console.log("Found 0 MCP servers.");
    console.log(`Add servers in ${MCP_AGENT_IDS.map(agentChoiceLabel).join(" or ")} MCP config, then run: runfree mcp list`);
    return {};
  }

  console.log("Configure MCP servers and tool-call rules");
  console.log(`Found ${entries.length} MCP ${entries.length === 1 ? "server" : "servers"}.`);
  const selectedKey = entries.length === 1
    ? "0"
    : await select({
      message: "Select an MCP server",
      options: entries.map((entry, index) => ({
        value: String(index),
        label: `${agentChoiceLabel(entry.agent)} / ${entry.name} (${entry.source}, ${entry.transport}/${entry.auth}, ${entry.decision.status})`,
      })),
    });
  if (isCancel(selectedKey)) return {};
  const entry = entries[Number(selectedKey)];
  const changes: ConfigureChange[] = [];
  let selectedEntryWillRemain = true;

  if (entry.source === "project") {
    const approvalChoice = await select({
      message: `Project approval for ${agentChoiceLabel(entry.agent)} / ${entry.name}`,
      options: [
        { value: "keep", label: "Keep current approval state" },
        ...(entry.decision.status === "approved"
          ? [{ value: "revoke", label: "Revoke project approval" }]
          : entry.decision.status === "unsupported" || entry.decision.status === "conflict"
            ? []
            : [{ value: "approve", label: "Approve project server" }]),
      ],
    });
    if (isCancel(approvalChoice)) return {};
    if (approvalChoice === "approve") {
      const tokenSource = entry.auth === "static" ? await promptTokenSourceForStatic(entry) : { kind: "none" as const };
      if (!tokenSource) return {};
      changes.push({
        label: `approve project ${entry.agent}/${entry.name}`,
        apply: () => mcpApproveIntent({ agent: entry.agent, server: entry.name, tokenSource, replaceSource: false }),
      });
    } else if (approvalChoice === "revoke") {
      selectedEntryWillRemain = false;
      changes.push({
        label: `revoke project ${entry.agent}/${entry.name}`,
        apply: () => mcpRevokeIntent({ agent: entry.agent, server: entry.name }),
      });
    }
  }

  if (selectedEntryWillRemain && entry.endpoint && entry.mcpPolicy) {
    const policyChoice = await select({
      message: `How should Runfree handle tool calls for ${agentChoiceLabel(entry.agent)} / ${entry.name}?`,
      options: [
        { value: "keep", label: "Keep current tool-call rules" },
        { value: "ask", label: "Ask before tool calls" },
        { value: "allow", label: "Always allow all tool calls (save rule)" },
        { value: "deny", label: "Deny all tool calls" },
        { value: "tool", label: "Configure individual tool name" },
      ],
    });
    if (isCancel(policyChoice)) return {};
    if (policyChoice === "ask" || policyChoice === "allow" || policyChoice === "deny") {
      changes.push({
        label: `set ${entry.agent}/${entry.name} tool calls to ${policyChoice}`,
        apply: () => mcpRulesIntent({ agent: entry.agent, server: entry.name, source: entry.source, write: policyChoice }),
      });
    } else if (policyChoice === "tool") {
      const toolName = await text({ message: "MCP tool name" });
      if (isCancel(toolName) || toolName.trim() === "") return {};
      const toolAction = await select({
        message: `Handling for ${toolName.trim()}`,
        options: [
          { value: "ask", label: "Ask before this tool" },
          { value: "allow", label: "Always allow this tool" },
          { value: "deny", label: "Deny this tool" },
        ],
      });
      if (isCancel(toolAction)) return {};
      changes.push({
        label: `${toolAction} tool "${toolName.trim()}" on ${entry.agent}/${entry.name}`,
        apply: () => mcpRulesIntent({
          agent: entry.agent,
          server: entry.name,
          source: entry.source,
          tool: toolName.trim(),
          write: toolAction,
        }),
      });
    }
  }

  let auth: McpConfigureResult["auth"];
  if (selectedEntryWillRemain && (entry.auth === "oauth" || entry.auth === "public") && entry.transport === "http") {
    const authChoice = await select({
      message: `Authenticate ${agentChoiceLabel(entry.agent)} / ${entry.name} after saving?`,
      options: [
        { value: "no", label: "No" },
        { value: "yes", label: "Yes, run MCP OAuth login" },
      ],
    });
    if (isCancel(authChoice)) return {};
    if (authChoice === "yes") auth = { agent: entry.agent, server: entry.name, source: entry.source };
  } else if (entry.auth === "static") {
    console.log(`static-header server ${entry.agent}/${entry.name} does not need OAuth login`);
  } else if (entry.transport === "stdio") {
    console.log(`stdio server ${entry.agent}/${entry.name} has no OAuth login`);
  }

  console.log("Runfree will save these host-owned MCP settings:");
  if (changes.length === 0) console.log("  no host-owned policy changes");
  for (const change of changes) console.log(`  ${change.label}`);
  if (auth) {
    console.log(`After saving, Runfree will authenticate with: runfree mcp auth ${auth.agent} ${auth.server}${auth.source ? ` --source ${auth.source}` : ""}`);
  }
  console.log("No project files will be modified.");
  const confirmed = await confirmPrompt({ message: "Save these changes?", initialValue: changes.length > 0 || auth !== undefined });
  if (isCancel(confirmed) || confirmed !== true) return {};

  for (const change of changes) await change.apply();
  if (selectedEntryWillRemain) {
    mcpExplainIntent({ agent: entry.agent, server: entry.name, source: entry.source, json: false });
  }
  return auth ? { auth } : {};
}

export function mcpRevokeIntent(input: McpRevokeInput): void {
  const { agent, server: serverName } = input;
  const approvalFile = mcpApprovalPath(stateDir());
  const entry = mcpInventory({ projectRoot: projectRoot(), env: childEnv(), approvalPath: approvalFile })
    .entries.find((candidate) => candidate.source === "project" && candidate.agent === agent && candidate.name === serverName);
  const result = revokeMcpApproval(projectRoot(), approvalFile, agent, serverName);
  if (result.changed) {
    console.log(`revoked project MCP server: ${agent} ${serverName}`);
  } else {
    console.log(`project MCP server was not approved: ${agent} ${serverName}`);
  }
  console.log(`approval: ${approvalFile}`);
  const tokenConfig = loadTokenConfig();
  for (const binding of entry?.tokenBindings ?? []) {
    if (tokenConfig[binding.tokenName]) {
      console.log(`credential source left configured: runfree credential clear-source ${binding.tokenName}`);
    }
  }
}

/**
 * Prepare host-owned MCP projections for a v4 effective control generation.
 * The approved compiled policy is cloned and may only be extended by exact
 * host-owned MCP approvals; desired project files are never read or written by
 * this path.
 */
export function prepareEffectiveRuntimeIntent(input: {
  basePolicy: PolicyJson;
  outputPath: string;
}): void {
  ensureStateDirs();
  const base = validateNetworkPolicy(input.basePolicy);
  const result = prepareMcpRuntime({
    approvalPath: mcpApprovalPath(stateDir()),
    callbackPort: Number.parseInt(childEnv().RUNFREE_MCP_OAUTH_CALLBACK_PORT ?? "", 10) || mcpOAuthCallbackPort(projectRoot()),
    claudeConfigPath: childEnv().RUNFREE_CLAUDE_JSON ?? path.join(stateDir(), "claude.json"),
    claudeMcpConfigPath: childEnv().RUNFREE_CLAUDE_MCP_CONFIG_HOST_PATH ?? path.join(stateDir(), "mounts", "claude-mcp.json"),
    codexDir: childEnv().RUNFREE_CODEX_HOME ?? path.join(stateDir(), "codex"),
    env: childEnv(),
    mcpOperationPolicyPath: mcpOperationPolicyPath(),
    mcpOAuthPolicyPath: oauthMediationPolicyPath(),
    mcpRulesPath: mcpRulesPath(stateDir()),
    policy: structuredClone(base.raw),
    projectRoot: projectRoot(),
    tokenConfig: loadTokenConfig(),
  });
  if (result.tokenConfigChanged) saveTokenConfig(result.tokenConfig);
  const effective = validateNetworkPolicy(result.policy);
  fs.mkdirSync(path.dirname(input.outputPath), { recursive: true, mode: 0o700 });
  atomicReplaceFile(input.outputPath, `${JSON.stringify({
    schemaVersion: 1,
    basePolicyGeneration: base.generation,
    policy: effective.raw,
  }, null, 2)}\n`, 0o600);
}
