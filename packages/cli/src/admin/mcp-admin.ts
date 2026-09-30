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
  mcpOAuthProviderId,
  mcpRuleKeyForEntry,
  mcpRulesPath,
  readMcpRules,
  type McpSourceScope,
  prepareMcpRuntime,
  revokeMcpApproval,
  saveMcpApproval,
  writeMcpRules,
} from "../runtime/mcp.ts";
import {
  boundedEvidence,
  MCP_ENABLED_LIMITS,
  type McpEnabledHost,
  type McpEnabledRecord,
  validateMcpEnabledRecord,
  mcpEnabledPath,
  readMcpEnabled,
  removeMcpEnabledRecords,
  saveMcpEnabledRecord,
} from "../runtime/mcp-enabled.ts";
import { mcpOAuthEpochsPath, mcpOAuthStateEpoch, updateMcpOAuthEpochs } from "../runtime/mcp-oauth-epochs.ts";
import { atomicReplaceFile } from "../safe-fs.ts";
import {
  checkPolicyHostname,
  type DiscoveryDeps,
  discoverMcpOAuthHosts,
  type McpOAuthDiscoveryResult,
} from "./mcp-discovery.ts";
import {
  formatTerminalTable,
} from "../terminal-table.ts";
import {
  childEnv,
  describeSource,
  die,
  ensureStateDirs,
  loadPolicy,
  loadTokenConfig,
  type McpApproveInput,
  type McpConfigureInput,
  type McpEnableInput,
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

type StaticCredentialPlan = {
  // What the review shows.
  lines: string[];
  // Performs the credential source writes. Runs only after the approval.
  apply: () => void;
};

// Validate the credential source for a project entry before any write. Every
// refusal happens here; `apply` only writes.
function planProjectCredentialSource(
  entry: McpInventoryEntry,
  input: Pick<McpApproveInput, "tokenSource" | "replaceSource">,
): StaticCredentialPlan {
  const hasSource = input.tokenSource.kind !== "none";
  if (entry.auth !== "static") {
    if (hasSource) die("--from-* is only valid for static-header project MCP servers");
    return { lines: [], apply: () => {} };
  }
  const bindings = entry.tokenBindings ?? [];
  const configured = loadTokenConfig();
  const missingBindings = bindings.filter((binding) => !configured[binding.tokenName]);
  if (bindings.length > 1 && hasSource) {
    die([
      "static project MCP server has multiple credential bindings; configure each credential source explicitly:",
      ...bindings.map((binding) => `runfree credential set-source ${binding.tokenName} --from-env ${binding.tokenName.toUpperCase().replace(/[^A-Z0-9_]+/g, "_")}_TOKEN`),
    ].join("\n"));
  }
  if (!hasSource) {
    if (missingBindings.length > 0) die("static project MCP credentials require --from-env, --from-1password, or --from-source");
    return {
      lines: bindings.map((binding) => `credential source: keep ${binding.tokenName} (${describeSource(configured[binding.tokenName])})`),
      apply: () => {},
    };
  }
  const source = tokenSourceFromSelection(input.tokenSource, true);
  if (!source) throw new Error("internal error: required credential source was not parsed");
  return {
    lines: bindings.map((binding) => `credential source: ${binding.tokenName} from ${describeSource(source)}`),
    apply: () => {
      for (const binding of bindings) {
        const sourceChanged = saveTokenSource(binding.tokenName, source, { replaceSource: input.replaceSource }).changed;
        console.log(`credential source: ${sourceChanged ? "configured" : "unchanged"} ${binding.tokenName} (${describeSource(source)})`);
      }
    },
  };
}

function assertApprovableProjectEntry(entry: McpInventoryEntry): void {
  if (entry.decision.status === "unsupported" || entry.decision.status === "skipped") {
    die(`cannot approve ${entry.decision.status} project MCP server: ${entry.decision.reason ?? "unsupported MCP configuration"}`);
  }
  if (entry.decision.status === "conflict") {
    die(`cannot approve project MCP server ${entry.agent} ${entry.name}: ${entry.decision.reason ?? "conflict"}`);
  }
}

export function mcpApproveIntent(input: McpApproveInput): void {
  const { agent, server: serverName } = input;
  const approvalFile = mcpApprovalPath(stateDir());
  const entry = findMcpEntry(agent, serverName, "project");
  assertApprovableProjectEntry(entry);
  planProjectCredentialSource(entry, input).apply();

  const approval = saveMcpApproval(projectRoot(), approvalFile, entry);
  console.log(`approved project MCP server: ${agent} ${serverName}`);
  console.log(`approval: ${approvalFile}`);
  console.log(`digest: ${approval.digest}`);
}

export type McpEnableResult = {
  applied: boolean;
  // The OAuth login the command runs next (OAuth-capable servers only).
  login?: { agent: McpAgent; server: string; source: McpSourceScope };
  // The same login as a printable, shell-quoted command.
  loginCommand?: string;
};

// The hosts the current policy allows, when a policy can be read (display only).
function currentPolicyHosts(): string[] {
  try {
    return loadPolicy().raw.hosts;
  } catch {
    return [];
  }
}

export type McpEnableDeps = {
  discovery?: DiscoveryDeps;
  // One yes/no question; defaults to a clack confirm (default No).
  confirm?: (message: string) => Promise<boolean>;
};

type PlannedOAuthHost = McpEnabledHost & { alsoUser?: boolean };

// Render text that came from MCP config or remote metadata: escape anything
// that is not printable ASCII (control, C1, bidi, and other formatting
// characters), so it cannot move the cursor or reorder the review.
export function printable(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, (char) => `\\u{${(char.codePointAt(0) ?? 0).toString(16)}}`);
}

// Quote one shell word for a printed command; plain words stay bare.
function shellWord(value: string): string {
  return /^[A-Za-z0-9._@%+=:,/-]+$/.test(value) ? value : `'${printable(value).replaceAll("'", "'\\''")}'`;
}

function mcpEndpointUrl(entry: McpInventoryEntry): string | undefined {
  const descriptor = entry.descriptor;
  for (const key of ["claudeConfig", "codexConfig"] as const) {
    const config = descriptor?.[key];
    if (config && typeof config === "object" && typeof (config as Record<string, unknown>).url === "string") {
      return (config as Record<string, unknown>).url as string;
    }
  }
  return entry.endpoint ? `https://${entry.endpoint.host}${entry.endpoint.path}` : undefined;
}

function declaredOAuthInputs(entry: McpInventoryEntry): { metadataUrls: string[]; tokenHosts: string[] } {
  const oauthPolicy = entry.descriptor?.oauthPolicy as {
    oauth?: { authServerMetadataUrl?: unknown };
    tokenEndpoints?: Array<{ host?: unknown } | string>;
  } | undefined;
  const metadataUrl = oauthPolicy?.oauth?.authServerMetadataUrl;
  const tokenHosts = (oauthPolicy?.tokenEndpoints ?? []).flatMap((endpoint) => {
    if (typeof endpoint === "string") {
      try {
        return [new URL(endpoint).hostname.toLowerCase()];
      } catch {
        return [];
      }
    }
    return typeof endpoint.host === "string" ? [endpoint.host] : [];
  });
  return { metadataUrls: typeof metadataUrl === "string" ? [metadataUrl] : [], tokenHosts };
}

async function defaultConfirm(message: string): Promise<boolean> {
  const answer = await confirmPrompt({ message, initialValue: false });
  return !isCancel(answer) && answer === true;
}

function hostOriginLabel(host: PlannedOAuthHost): string {
  if (host.origin === "discovered") return "discovered";
  return host.alsoUser ? "--oauth-host, also discovered" : "--oauth-host";
}

/**
 * `runfree mcp enable`: one review and one approval for the MCP approval
 * (project entries), the credential source (static entries), and the OAuth
 * hosts (HTTP OAuth-capable entries). Every refusal happens before the first
 * write, and nothing is written unless the review is accepted (on a terminal)
 * or the command line itself names every change (`--no-discover`).
 *
 * Discovery contacts hosts that MCP config names. For project entries that
 * config is untrusted, so discovery runs only after the person agrees to
 * contact the named endpoint; without a terminal it does not run at all.
 */
export async function mcpEnableIntent(input: McpEnableInput, deps: McpEnableDeps = {}): Promise<McpEnableResult> {
  const { agent, server: serverName } = input;
  const confirm = deps.confirm ?? defaultConfirm;
  const shownName = printable(serverName);
  // 1. Resolve and validate the entry. No network call happens before this.
  const entry = findMcpEntry(agent, serverName, input.source);
  if (entry.decision.status === "unsupported" || entry.decision.status === "skipped" || entry.decision.status === "conflict") {
    die(`cannot enable MCP server ${agent} ${shownName}: ${printable(entry.decision.reason ?? entry.decision.status)}`);
  }
  const isProject = entry.source === "project";
  if (isProject) assertApprovableProjectEntry(entry);
  if (!isProject && input.tokenSource.kind !== "none") {
    die(`--from-* applies to project MCP servers; bind a ${entry.source} server's credential with: runfree credential set-source <name> --from-env <env>`);
  }
  const credential = isProject ? planProjectCredentialSource(entry, input) : { lines: [], apply: () => {} };

  const identity = mcpRuleKeyForEntry(entry);
  const endpointUrl = entry.transport === "http" ? mcpEndpointUrl(entry) : undefined;
  const oauthCapable = entry.transport === "http" && (entry.auth === "oauth" || entry.auth === "public")
    && entry.endpoint !== undefined && identity !== undefined && endpointUrl !== undefined;
  if (input.oauthHosts.length > 0 && !oauthCapable) {
    die("--oauth-host applies only to OAuth-capable HTTP MCP servers");
  }
  const endpointHost = entry.endpoint?.host;

  // 2. User-named hosts: exact, policy-valid, not IP literals.
  const planned = new Map<string, PlannedOAuthHost>();
  const userNotes: string[] = [];
  for (const raw of input.oauthHosts) {
    const checked = checkPolicyHostname(raw);
    if (!checked.ok) die(`--oauth-host ${printable(raw)}: ${checked.reason}`);
    if (checked.host === endpointHost) {
      userNotes.push(`${checked.host} is the MCP endpoint host; it is already allowed with the server`);
      continue;
    }
    planned.set(checked.host, { host: checked.host, origin: "user" });
  }

  // 3. Host-side discovery: only for a resolved, valid, OAuth-capable entry,
  // only on a terminal, and for untrusted project config only after the
  // person agrees to contact the endpoint it names.
  let discovery: McpOAuthDiscoveryResult | undefined;
  if (oauthCapable && input.discover) {
    if (!input.interactive) {
      die([
        `mcp enable discovers OAuth hosts only on a terminal, where you review them before anything is saved`,
        `without a terminal, name the hosts yourself: runfree mcp enable ${agent} ${shellWord(serverName)} --source ${entry.source} --no-discover --oauth-host <host>`,
      ].join("\n"));
    }
    const endpoint = new URL(endpointUrl);
    const declared = declaredOAuthInputs(entry);
    if (isProject) {
      console.log(`Project MCP server ${agent} ${shownName} names the endpoint ${endpoint.origin}.`);
      console.log("To find its OAuth hosts, Runfree fetches OAuth metadata (HTTPS GET, no credentials) from that host and from the authorization servers it names.");
      if (!await confirm(`Contact ${endpoint.hostname} to discover OAuth hosts?`)) {
        console.log("No hosts contacted and no changes saved. To skip discovery, pass --no-discover (with --oauth-host <host> when the login needs other hosts).");
        return { applied: false };
      }
    }
    console.log(`Discovering OAuth hosts from ${endpoint.origin}...`);
    try {
      discovery = await discoverMcpOAuthHosts({
        endpointUrl,
        declaredMetadataUrls: declared.metadataUrls,
        declaredTokenHosts: declared.tokenHosts,
      }, deps.discovery);
    } catch (error) {
      die(`cannot discover OAuth hosts for ${agent} ${shownName}: ${error instanceof Error ? error.message : String(error)}; pass --no-discover with --oauth-host <host> instead`);
    }
    for (const found of discovery.hosts) {
      const existing = planned.get(found.host);
      planned.set(found.host, {
        host: found.host,
        origin: existing ? "user" : "discovered",
        evidence: boundedEvidence(found.evidence),
        ...(existing ? { alsoUser: true } : {}),
      });
    }
  }
  const hosts = [...planned.values()].sort((left, right) => left.host.localeCompare(right.host));
  if (hosts.length > MCP_ENABLED_LIMITS.maxHostsPerRecord) {
    die(`an MCP server can enable at most ${MCP_ENABLED_LIMITS.maxHostsPerRecord} OAuth hosts`);
  }
  const endpoints = discovery?.endpoints ?? [];

  // The record is built and validated before the review, so everything the
  // review shows can be saved: a failure here writes nothing.
  const record: McpEnabledRecord | undefined = oauthCapable && identity && (hosts.length > 0 || endpoints.length > 0)
    ? {
      schemaVersion: 1,
      identity,
      agent,
      source: entry.source,
      server: serverName,
      enabledAt: new Date().toISOString(),
      oauthHosts: hosts.map(({ alsoUser: _alsoUser, ...host }) => host),
      ...(endpoints.length > 0 ? { oauthEndpoints: endpoints.map(({ kind, host, path: endpointPath }) => ({ kind, host, path: endpointPath })) } : {}),
    }
    : undefined;
  if (record && !validateMcpEnabledRecord(record)) {
    die(`cannot enable MCP server ${agent} ${shownName}: the planned OAuth host record is invalid; pass --no-discover with --oauth-host <host> instead`);
  }

  // 4. The one review.
  const enabledFile = mcpEnabledPath(stateDir());
  const previous = readMcpEnabled(projectRoot(), enabledFile, { quiet: true }).file;
  // Hosts the narrowing leaves broad: already allowed by the current policy,
  // or named as `--oauth-host` by another server's record.
  const broadHosts = new Set<string>([...currentPolicyHosts(), ...(endpointHost ? [endpointHost] : [])]);
  for (const other of Object.values(previous.records)) {
    if (other.agent === agent && other.server === serverName && other.source === entry.source) continue;
    for (const host of other.oauthHosts) if (host.origin === "user") broadHosts.add(host.host);
  }
  const previousHosts = Object.values(previous.records)
    .filter((record) => record.agent === agent && record.server === serverName && record.source === entry.source)
    .flatMap((record) => record.oauthHosts.map((host) => host.host));
  const droppedHosts = [...new Set(previousHosts)].filter((host) => !planned.has(host)).sort();
  const login = oauthCapable && (entry.auth === "oauth" || discovery?.oauthDetected === true || hosts.length > 0)
    ? { agent, server: serverName, source: entry.source }
    : undefined;

  console.log(`Enable MCP server: ${agent} ${shownName} (${entry.source}, ${entry.transport}/${entry.auth})`);
  if (endpointUrl) console.log(`  endpoint: ${printable(endpointUrl)}`);
  if (entry.sourcePath) console.log(`  config: ${printable(entry.sourcePath)}`);
  if (entry.descriptorDigest) console.log(`  descriptor: ${entry.descriptorDigest.slice(0, 16)}...`);
  console.log("Changes:");
  if (isProject) {
    console.log(`  approve project MCP server ${agent} ${shownName}${entry.decision.status === "approved" ? " (already approved)" : ""}`);
  }
  for (const line of credential.lines) console.log(`  ${line}`);
  if (endpointHost && entry.transport === "http") console.log(`  allow host ${endpointHost}  [MCP endpoint]`);
  for (const host of hosts) {
    console.log(`  allow host ${host.host}  [OAuth, ${hostOriginLabel(host)}]`);
    for (const evidence of host.evidence ?? []) console.log(`      ${evidence}`);
    const hostEndpoints = endpoints.filter((endpointEntry) => endpointEntry.host === host.host);
    if (host.origin === "discovered" && broadHosts.has(host.host)) {
      console.log("      already allowed by the current policy; its existing rules stay");
    } else if (host.origin === "discovered") {
      console.log(`      limited to GET, HEAD, OPTIONS, and POST on paths starting with /.well-known${hostEndpoints.map((endpointEntry) => `, ${endpointEntry.path}`).join("")}`);
    }
  }
  for (const endpointEntry of endpoints) {
    if (endpointEntry.kind !== "metadata") console.log(`  proxy mediates ${endpointEntry.kind} endpoint https://${endpointEntry.host}${endpointEntry.path}`);
  }
  for (const host of droppedHosts) console.log(`  stop allowing host ${host}  [OAuth, from an earlier enable]`);
  for (const note of userNotes) console.log(`  note: ${note}`);
  if (discovery) {
    console.log("Discovery:");
    for (const contact of discovery.contacted) console.log(`  GET ${contact.url}: ${contact.outcome}`);
    for (const host of discovery.covered) console.log(`  ${host}: already allowed with the server`);
    for (const reason of discovery.rejected) console.log(`  not added: ${printable(reason)}`);
    for (const origin of discovery.authorizationEndpoints) {
      console.log(`  browser sign-in at ${origin} (opened on this computer; not allowlisted)`);
    }
    if (!discovery.oauthDetected) console.log("  no valid OAuth metadata found; add hosts with --oauth-host if the login needs them");
  }
  if (hosts.some((host) => host.origin === "user")) {
    console.log("  --oauth-host hosts are allowed as given (like runfree host add); the proxy mediates tokens there only for endpoints the server's metadata names");
  }
  if (hosts.length > 0) console.log("  OAuth token requests follow this project's write approval setting (default: ask)");
  if (login) console.log(`After saving: OAuth login with: runfree mcp auth ${agent} ${shellWord(serverName)} --source ${entry.source}`);

  // 5. The one approval. Without a terminal, the command line named every
  // change (`--no-discover`), so the command itself is the consent.
  if (input.interactive && !await confirm("Enable this MCP server?")) {
    console.log("No changes saved.");
    return { applied: false };
  }

  // 6. Writes, in order: credential source, approval, OAuth host record. All
  // use the entry reviewed above, never a re-read of the MCP config.
  credential.apply();
  if (isProject) {
    const approvalFile = mcpApprovalPath(stateDir());
    const approval = saveMcpApproval(projectRoot(), approvalFile, entry);
    console.log(`approved project MCP server: ${agent} ${shownName}`);
    console.log(`digest: ${approval.digest}`);
  }
  if (record) {
    const saved = saveMcpEnabledRecord(projectRoot(), enabledFile, record);
    if (saved.droppedInvalid > 0) console.log(`dropped ${saved.droppedInvalid} invalid MCP enable record(s) from ${enabledFile}`);
    console.log(`OAuth hosts: ${hosts.length > 0 ? hosts.map((host) => host.host).join(", ") : "none"}`);
  } else if (oauthCapable) {
    const removed = removeMcpEnabledRecords(projectRoot(), enabledFile, { agent, server: serverName, source: entry.source });
    if (removed.droppedInvalid > 0) console.log(`dropped ${removed.droppedInvalid} invalid MCP enable record(s) from ${enabledFile}`);
    console.log("OAuth hosts: none");
  }
  console.log(`enabled MCP server: ${agent} ${shownName}`);
  return {
    applied: true,
    ...(login ? { login, loginCommand: `runfree mcp auth ${agent} ${shellWord(serverName)} --source ${entry.source}` } : {}),
  };
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
  const identity = mcpRuleKeyForEntry(entry);
  const enabled = identity ? readMcpEnabled(projectRoot(), mcpEnabledPath(stateDir())).file.records[identity] : undefined;
  for (const host of enabled?.oauthHosts ?? []) {
    console.log(`OAuth host: ${host.host} (${host.origin === "user" ? "--oauth-host" : "discovered"}; added by mcp enable)`);
  }
  for (const endpoint of enabled?.oauthEndpoints ?? []) {
    if (endpoint.kind !== "metadata") console.log(`OAuth ${endpoint.kind} endpoint: https://${endpoint.host}${endpoint.path}`);
  }
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
  if (entry.decision.status === "unsupported" || entry.decision.status === "skipped" || entry.decision.status === "conflict") {
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
          : entry.decision.status === "unsupported" || entry.decision.status === "skipped" || entry.decision.status === "conflict"
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
        apply: () => {
          mcpRevokeIntent({ agent: entry.agent, server: entry.name });
        },
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

export type McpRevokeResult = {
  // The proxy OAuth provider whose state this revoke clears, and the new
  // state epoch the next effective policy generation publishes for it.
  oauthProviderId: string;
  oauthStateEpoch: string;
};

export function mcpRevokeIntent(input: McpRevokeInput): McpRevokeResult {
  const { agent, server: serverName } = input;
  const shownName = printable(serverName);
  // The OAuth state clear comes first: if its tombstone cannot be written,
  // revoke fails before it changes anything else. The proxy keys OAuth state
  // by agent and server name, so this covers every source of that name.
  const oauthProviderId = mcpOAuthProviderId(agent, serverName);
  const epochs = updateMcpOAuthEpochs(projectRoot(), mcpOAuthEpochsPath(stateDir()), { revoke: [oauthProviderId] });
  const oauthStateEpoch = mcpOAuthStateEpoch(epochs, oauthProviderId);
  if (epochs.reset === "reclaimed") {
    console.log("the MCP OAuth state epoch store was invalid and was replaced; the proxy clears all MCP OAuth state, so every MCP server needs a new OAuth login");
  }
  console.log(`proxy OAuth state for ${agent} ${shownName}: clear requested`);
  const approvalFile = mcpApprovalPath(stateDir());
  const entry = mcpInventory({ projectRoot: projectRoot(), env: childEnv(), approvalPath: approvalFile })
    .entries.find((candidate) => candidate.source === "project" && candidate.agent === agent && candidate.name === serverName);
  if (input.source === undefined || input.source === "project") {
    const result = revokeMcpApproval(projectRoot(), approvalFile, agent, serverName);
    if (result.changed) {
      console.log(`revoked project MCP server: ${agent} ${shownName}`);
    } else {
      console.log(`project MCP server was not approved: ${agent} ${shownName}`);
    }
    console.log(`approval: ${approvalFile}`);
  }
  // Remove exactly this server's `mcp enable` records. The effective policy
  // projects the union of the remaining records, so a host another server
  // (or desired policy, or a service) still names stays allowed.
  const enabledFile = mcpEnabledPath(stateDir());
  const removed = removeMcpEnabledRecords(projectRoot(), enabledFile, {
    agent,
    server: serverName,
    ...(input.source !== undefined ? { source: input.source } : {}),
  });
  const removedHosts = [...new Set(removed.removed.flatMap((record) => record.oauthHosts.map((host) => host.host)))].sort();
  if (removedHosts.length > 0) console.log(`OAuth hosts no longer allowed for this server: ${removedHosts.join(", ")}`);
  if (removed.droppedInvalid > 0) console.log(`dropped ${removed.droppedInvalid} invalid MCP enable record(s) from ${enabledFile}`);
  const tokenConfig = loadTokenConfig();
  for (const binding of entry?.tokenBindings ?? []) {
    if (tokenConfig[binding.tokenName]) {
      console.log(`credential source left configured: runfree credential clear-source ${binding.tokenName}`);
    }
  }
  return { oauthProviderId, oauthStateEpoch };
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
    mcpEnabledPath: mcpEnabledPath(stateDir()),
    mcpOAuthEpochsPath: mcpOAuthEpochsPath(stateDir()),
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
