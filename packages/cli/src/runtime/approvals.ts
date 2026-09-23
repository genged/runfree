// approvals.ts — host-side approve-on-write commands.
//
// `runfree approvals` (list / --watch) and `runfree approve <id>` resolve
// writes the proxy is holding on `ask` hosts. Pending records are read from
// proxy-owned tmpfs and decision files are written root-owned via root
// `docker exec` — the same trust model as the audit marker: the agent has no
// exec into the proxy and the UID-1001 proxy process cannot mint a decision.

import crypto from "node:crypto";

import { isCancel, select, text } from "@clack/prompts";

import {
  APPROVALS_PROCESS_EPOCH_FILE,
  APPROVAL_CONTROL_FILE_PREFIX,
  APPROVALS_DECISIONS_DIR,
  APPROVALS_PENDING_DIR,
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  WRITE_APPROVAL_GRANT_TTL_MAX_MS,
  formatApprovalDuration,
  isApprovalId,
  parsePendingApprovalRecord,
  parseWriteApprovalsStatus,
  writeApprovalsStatusPath,
  type ApprovalDecisionRecord,
  type PendingApprovalRecord,
  type WriteApprovalGrantSummary,
  type WriteApprovalsStatus,
} from "@runfree/runtime-contracts/write-approvals";
import { suggestableServicesForHost } from "../../../../scripts/services.ts";
import { die } from "../errors.ts";
import { formatTerminalTable } from "../terminal-table.ts";
import { runfreeLog } from "../warnings.ts";
import { ROOT_UID_GID } from "./constants.ts";
import { dockerClientEnvOptions, serviceContainerId } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import {
  mcpApprovalPath,
  mcpInventory,
  mcpRuleKeyForEntry,
  mcpRulesPath,
  readMcpRules,
  writeMcpRules,
  type McpInventoryEntry,
} from "./mcp.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const WATCH_POLL_MS = 1_000;
const WATCH_HEARTBEAT_MS = 10_000;
const CLEAR_CONFIRM_POLL_MS = 300;
const CLEAR_CONFIRM_ATTEMPTS = 15;

// Reads every pending record in one exec; malformed entries are skipped by
// the CLI-side validating parse (tmpfs content is treated as untrusted input).
const READ_PENDING_SCRIPT = `
const fs = require("node:fs");
const dir = ${JSON.stringify(APPROVALS_PENDING_DIR)};
const records = [];
try {
  for (const entry of fs.readdirSync(dir)) {
    if (!entry.endsWith(".json")) continue;
    try { records.push(fs.readFileSync(dir + "/" + entry, "utf8").trim()); } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
} catch (error) { if (error.code !== "ENOENT") throw error; }
console.log(JSON.stringify(records));
`;

// Runs as root inside the proxy container: validates the id shape, refuses to
// overwrite an existing decision (single use), stamps decidedAt from the
// proxy clock, writes atomically with root ownership and mode 0644, and
// opportunistically removes stale leftover decision files.
const WRITE_DECISION_SCRIPT = `
const fs = require("node:fs");
const dir = ${JSON.stringify(APPROVALS_DECISIONS_DIR)};
const record = JSON.parse(process.argv[1]);
if (typeof record.id !== "string" || !/^[0-9a-f]{32}$/.test(record.id)) process.exit(1);
const currentEpoch = fs.readFileSync(${JSON.stringify(`${APPROVALS_PENDING_DIR}/${APPROVALS_PROCESS_EPOCH_FILE}`)}, "utf8").trim();
if (!/^[0-9a-f]{64}$/.test(currentEpoch) || record.processEpoch !== currentEpoch) {
  console.error("proxy restarted; the held request was interrupted; wait for a new request");
  process.exit(1);
}
let pending;
try {
  pending = JSON.parse(fs.readFileSync(${JSON.stringify(APPROVALS_PENDING_DIR)} + "/" + record.id + ".json", "utf8"));
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  console.error("request is no longer pending (expired, cancelled, or already handled)");
  process.exit(3);
}
if (pending.id !== record.id || pending.processEpoch !== currentEpoch) process.exit(1);
if (typeof record.id !== "string" || !/^[0-9a-f]{32}$/.test(record.id)) {
  console.error("invalid approval id");
  process.exit(1);
}
try {
  for (const entry of fs.readdirSync(dir)) {
    if (!entry.endsWith(".json")) continue;
    try {
      const stat = fs.statSync(dir + "/" + entry);
      if (Date.now() - stat.mtimeMs > 60 * 60 * 1000) fs.unlinkSync(dir + "/" + entry);
    } catch {}
  }
} catch {}
const filePath = dir + "/" + record.id + ".json";
if (fs.existsSync(filePath)) {
  console.error("already decided");
  process.exit(2);
}
record.decidedAt = new Date().toISOString();
const tmpPath = filePath + ".tmp";
fs.writeFileSync(tmpPath, JSON.stringify(record) + "\\n", { mode: 0o644 });
fs.renameSync(tmpPath, filePath);
fs.chmodSync(filePath, 0o644);
console.log("ok");
`;

// Runs as root inside the proxy container, exactly like the decision writer:
// a clear is host authority, so it travels the same root-minted, root-owned
// channel as the decision that created the deny. The file name carries a fresh
// host-chosen nonce (so a leftover file can never occupy the path a later
// clear needs) and the record names the proxy's current deny nonce (so the
// proxy can reject a clear aimed at a deny state the operator never saw).
//
// It also retires the control records it superseded. Cleanup belongs to this
// writer: the records are root-owned, so the UID-1001 proxy cannot delete what
// it consumes, and left alone they accumulate one per clear for the life of the
// runtime until the proxy's bounded per-tick scan can no longer reach a fresh
// record — an operator unable to lift a deny, which is the exact failure this
// channel exists to prevent. Unlinking here bounds the directory to a single
// control file instead of tuning the proxy's scan budget around a growing one.
//
// Safe against a concurrent clear: only exact `control-<nonce>.json` names are
// removed — never the `.tmp` a partially written record occupies, never
// decision files, never the heartbeat. If a racing clear removes a record
// before the proxy reads it, the survivor names the same or a newer deny nonce,
// so the revocation still lands or is correctly rejected as stale.
//
// Single use is enforced by the `already issued` check above, which runs before
// this sweep; the `entry === name` guard below is belt-and-braces for the
// narrow window where a concurrent writer creates our own name in between, and
// so that reordering the two blocks cannot quietly turn a repeat into a
// re-mint. It is deliberately unreachable in normal operation.
export const WRITE_CONTROL_SCRIPT = `
const fs = require("node:fs");
const dir = ${JSON.stringify(APPROVALS_DECISIONS_DIR)};
const input = JSON.parse(process.argv[1]);
const processEpoch = fs.readFileSync(${JSON.stringify(`${APPROVALS_PENDING_DIR}/${APPROVALS_PROCESS_EPOCH_FILE}`)}, "utf8").trim();
if (!/^[0-9a-f]{64}$/.test(processEpoch)) process.exit(1);

if (typeof input.denyId !== "string" || !/^[0-9a-f]{32}$/.test(input.denyId)) {
  console.error("invalid deny id");
  process.exit(1);
}
if (typeof input.requestId !== "string" || !/^[0-9a-f]{32}$/.test(input.requestId)) {
  console.error("invalid control request id");
  process.exit(1);
}
const name = ${JSON.stringify(APPROVAL_CONTROL_FILE_PREFIX)} + input.requestId + ".json";
const filePath = dir + "/" + name;
if (fs.existsSync(filePath)) {
  console.error("already issued");
  process.exit(2);
}
try {
  for (const entry of fs.readdirSync(dir)) {
    if (entry === name || !/^control-[0-9a-f]{32}\\.json$/.test(entry)) continue;
    try { fs.unlinkSync(dir + "/" + entry); } catch {}
  }
} catch {}
const record = { v: 1, processEpoch, control: "clear-write-deny", denyId: input.denyId, issuedAt: new Date().toISOString() };
const tmpPath = filePath + ".tmp";
fs.writeFileSync(tmpPath, JSON.stringify(record) + "\\n", { mode: 0o644 });
fs.renameSync(tmpPath, filePath);
fs.chmodSync(filePath, 0o644);
console.log("ok");
`;

const TOUCH_HEARTBEAT_SCRIPT = `
const fs = require("node:fs");
const filePath = ${JSON.stringify(`${APPROVALS_DECISIONS_DIR}/${APPROVALS_WATCHER_HEARTBEAT_FILE}`)};
const epoch = fs.readFileSync(${JSON.stringify(`${APPROVALS_PENDING_DIR}/${APPROVALS_PROCESS_EPOCH_FILE}`)}, "utf8").trim();
if (!/^[0-9a-f]{64}$/.test(epoch)) process.exit(1);
fs.writeFileSync(filePath, epoch, { mode: 0o644 });
`;

export type ApprovalsInput =
  | { kind: "list" }
  // `clearDenyFirst` is `runfree approvals --clear-deny --watch`: revoke, then
  // attach. Clearing in order to resume approving and being left with no
  // approver attached is worse than a no-op — the next ask-mode write
  // fast-denies, which is the state the operator was trying to leave.
  | { kind: "watch"; bell: boolean; clearDenyFirst?: boolean }
  // Revokes the runtime-wide write deny (and any scoped MCP denies) through
  // the root-owned control channel. The counterpart of "stop asking": a
  // decision you cannot undo through the channel that made it is a latch.
  | { kind: "clear-deny" }
  // Hidden: the attached-session approver heartbeat (spawned as a detached
  // child around interactive sessions). Touches the root-owned heartbeat so a
  // human sitting at an attached session gets the full hold window even
  // before opening the approvals tab; exits when the parent session dies.
  | { kind: "heartbeat"; parentPid: number };

export type ApproveInput = {
  id: string;
  deny: boolean;
  mcpScope?: "tool" | "method" | "server-tools";
  saveMcpRule?: "tool" | "server-tools";
  scope?: "request" | "session" | "deny-session";
  ttl?: string;
};

function runningProxyId(context: RuntimeContext, io: RuntimeIO): string | undefined {
  const project = composeProjectName(context.projectRoot);
  return serviceContainerId(project, "proxy", context, io, { runningOnly: true });
}

function execProxyRootNode(context: RuntimeContext, io: RuntimeIO, proxyId: string, script: string, args: string[]): CaptureResult {
  return io.capture(
    "docker",
    ["exec", "--user", ROOT_UID_GID, proxyId, "node", "-e", script, ...args],
    dockerClientEnvOptions(context),
  );
}

function readPendingApprovalsSnapshot(context: RuntimeContext, io: RuntimeIO, proxyId: string): PendingApprovalRecord[] | undefined {
  const result = execProxyRootNode(context, io, proxyId, READ_PENDING_SCRIPT, []);
  if (result.status !== 0) return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(result.stdout.trim());
  } catch {
    return undefined;
  }
  if (!Array.isArray(raw)) return undefined;
  const records: PendingApprovalRecord[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    const record = parsePendingApprovalRecord(entry);
    if (record) records.push(record);
  }
  // Soonest expiry first, matching the picker order.
  return records.sort((left, right) => Date.parse(left.expiresAt) - Date.parse(right.expiresAt));
}

export function readPendingApprovals(context: RuntimeContext, io: RuntimeIO, proxyId: string): PendingApprovalRecord[] {
  return readPendingApprovalsSnapshot(context, io, proxyId) ?? [];
}

export function touchWatcherHeartbeat(context: RuntimeContext, io: RuntimeIO, proxyId: string): boolean {
  return execProxyRootNode(context, io, proxyId, TOUCH_HEARTBEAT_SCRIPT, []).status === 0;
}

// Best-effort read of the proxy's level-triggered approval-state snapshot,
// for `runfree status`. Returns undefined when the proxy is not running or
// the snapshot is unreadable; observation only.
export function readWriteApprovalsStatus(context: RuntimeContext, io: RuntimeIO): WriteApprovalsStatus | undefined {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) return undefined;
  const result = io.capture(
    "docker",
    ["exec", proxyId, "cat", writeApprovalsStatusPath()],
    dockerClientEnvOptions(context),
  );
  if (result.status !== 0) return undefined;
  return parseWriteApprovalsStatus(result.stdout.trim());
}

// Issues one clear-write-deny control record naming `denyId`. The proxy
// applies it only while that nonce is still current, so a clear can never
// silently revoke a deny the operator did not look at.
export function writeClearWriteDeny(
  context: RuntimeContext,
  io: RuntimeIO,
  proxyId: string,
  denyId: string,
): { ok: boolean; message: string } {
  const requestId = crypto.randomBytes(16).toString("hex");
  const result = execProxyRootNode(context, io, proxyId, WRITE_CONTROL_SCRIPT, [JSON.stringify({ denyId, requestId })]);
  if (result.status === 0) return { ok: true, message: "ok" };
  return { ok: false, message: result.stderr.trim() || "docker exec failed" };
}

function writeDecision(
  context: RuntimeContext,
  io: RuntimeIO,
  proxyId: string,
  decision: Omit<ApprovalDecisionRecord, "decidedAt">,
): { ok: boolean; alreadyDecided: boolean; message: string } {
  const result = execProxyRootNode(context, io, proxyId, WRITE_DECISION_SCRIPT, [JSON.stringify(decision)]);
  if (result.status === 0) return { ok: true, alreadyDecided: false, message: "ok" };
  return {
    ok: false,
    alreadyDecided: result.status === 2,
    message: result.stderr.trim() || "docker exec failed",
  };
}

// --- Human-facing language (Tier 2 built-in category table) -----------------

function friendlyTarget(host: string): string {
  const services = suggestableServicesForHost(host);
  return services[0]?.label ?? host;
}

// The category-generic phrase table: always available because the classifier
// already produced the category. Never blocks a prompt; the technical
// descriptor stays on the `what:` line and in structured events.
function mcpServerLabel(record: Pick<PendingApprovalRecord, "host" | "mcp">): string {
  return record.mcp?.server ?? friendlyTarget(record.host);
}

export function actionPhrase(record: Pick<PendingApprovalRecord, "host" | "category" | "path" | "mcp">): string {
  if (record.mcp) {
    const server = mcpServerLabel(record);
    if (record.mcp.method === "tools/call" && record.mcp.tool) {
      return `call the MCP tool "${record.mcp.tool}" on ${server}`;
    }
    if (record.category === "mcp-unknown") {
      return `send an unclassifiable message to the ${server} MCP endpoint`;
    }
    return `send MCP operation "${record.mcp.method}" to ${server}`;
  }
  const target = friendlyTarget(record.host);
  switch (record.category) {
    case "git-push":
      return `push code to ${target}`;
    case "websocket":
      return `open a live connection to ${target} it can keep sending data over`;
    default:
      return `make a change on ${target}`;
  }
}

function relativeSeconds(fromMs: number, toIso: string): number {
  return Math.round((Date.parse(toIso) - fromMs) / 1000);
}

function formatAge(nowMs: number, iso: string): string {
  return `${Math.max(0, Math.round((nowMs - Date.parse(iso)) / 1000))}s`;
}

function formatExpires(nowMs: number, iso: string): string {
  const seconds = relativeSeconds(nowMs, iso);
  return seconds <= 0 ? "expired" : `in ${seconds}s`;
}

function shortId(id: string): string {
  return id.slice(0, 8);
}

export function pendingTableLines(records: PendingApprovalRecord[], nowMs = Date.now()): string[] {
  if (records.length === 0) return ["no writes waiting for approval"];
  const table = formatTerminalTable({
    columns: [{ label: "ID" }, { label: "AGE" }, { label: "EXPIRES" }, { label: "ACTION" }],
    rows: records.map((record) => [
      shortId(record.id),
      formatAge(nowMs, record.heldAt),
      formatExpires(nowMs, record.expiresAt),
      actionPhrase(record).slice(0, 80),
    ]),
  });
  return table.split("\n");
}

export function detailLines(record: PendingApprovalRecord, nowMs = Date.now()): string[] {
  if (record.mcp) {
    const server = mcpServerLabel(record);
    const sourceFlag = `runfree mcp rules ${record.mcp.agent} ${record.mcp.server}`;
    return [
      `  server:  ${server} - ${record.mcp.agent} (${record.host}${record.path})`,
      ...(record.mcp.tool ? [`  tool:    ${record.mcp.tool}`] : []),
      `  action:  ${actionPhrase(record)}`,
      `  what:    ${record.mcp.method} via ${record.method} ${record.path}`,
      ...(record.tokenNames.length > 0 ? [`  token:   ${record.tokenNames.join(", ")} (proxy-managed)`] : []),
      `  expires: ${formatExpires(nowMs, record.expiresAt)} (denied on timeout)`,
      ...(record.mcp.method === "tools/call" && record.mcp.tool
        ? [
          `  rule:    always allow this tool: ${sourceFlag} --tool ${record.mcp.tool} --write allow`,
          `  rule:    allow all tools on this server: ${sourceFlag} --write allow`,
        ]
        : []),
    ];
  }
  return [
    `  service: ${friendlyTarget(record.host)} (${record.host})`,
    `  action:  ${actionPhrase(record)}`,
    `  what:    ${record.method} ${record.path}`,
    ...(record.tokenNames.length > 0 ? [`  token:   ${record.tokenNames.join(", ")} (proxy-managed)`] : []),
    `  expires: ${formatExpires(nowMs, record.expiresAt)} (denied on timeout)`,
  ];
}

function parseTtlDuration(value: string): number {
  const match = /^([1-9][0-9]*)([smh])$/.exec(value.trim());
  if (!match) die(`invalid duration: ${value} (use forms like 5m, 90s, or 1h)`);
  const amount = Number(match[1]);
  const multiplier = match[2] === "h" ? 3_600_000 : match[2] === "m" ? 60_000 : 1_000;
  const ms = amount * multiplier;
  if (ms > WRITE_APPROVAL_GRANT_TTL_MAX_MS) {
    die(`duration too long: ${value} (maximum ${WRITE_APPROVAL_GRANT_TTL_MAX_MS / 3_600_000}h)`);
  }
  return ms;
}


// The proxy honors a session-wide decision only for an authenticated
// per-session principal (`applyDecision`). A typed request-only principal (an
// anonymous utility) gets request-scoped decisions only — offering a session
// scope here would report success for a decision the proxy denies, which is
// the defect this gate closes.
function sessionScopeAvailable(record: PendingApprovalRecord): boolean {
  return record.session !== undefined;
}

function sessionScopeUnavailableReason(record: PendingApprovalRecord): string {
  const label = record.requestOnlyPrincipal?.label ?? "this request";
  return `${label} is a request-only principal; the proxy honors only request-scoped decisions for it`;
}

/** Who a session-scoped decision actually covers, said honestly. */
function subjectNote(_record: PendingApprovalRecord): string {
  return "this session only";
}

function denySessionCoverage(record: PendingApprovalRecord): string {
  return `all writes from this session (${record.session?.name ?? "<unknown>"})`;
}

export function decisionSummary(record: PendingApprovalRecord | undefined, decision: Omit<ApprovalDecisionRecord, "decidedAt">): string[] {
  const phrase = record ? actionPhrase(record) : "the held write";
  if (decision.decision === "deny" && decision.denySession === true) {
    return [
      `denied ${decision.id}: ${phrase}`,
      `  ${record ? denySessionCoverage(record) : "all further writes"} denied without asking until cleared`,
      "  clear it: runfree approvals --clear-deny",
    ];
  }
  if (decision.decision === "deny") {
    return [
      `denied ${decision.id}: ${phrase}`,
      "  the agent sees a blocked-request message; approve a retry from runfree approvals",
    ];
  }
  if (record?.mcp && decision.saveMcpRule) {
    const server = mcpServerLabel(record);
    if (decision.saveMcpRule === "tool" && record.mcp.tool) {
      return [
        `approved ${decision.id}: ${phrase}`,
        `  saved rule: always allow "${record.mcp.tool}" on ${server}`,
        `  change it: runfree mcp rules ${record.mcp.agent} ${record.mcp.server} --tool ${record.mcp.tool} --write ask`,
      ];
    }
    return [
      `approved ${decision.id}: ${phrase}`,
      `  saved rule: always allow all tool calls on ${server}`,
      `  change it: runfree mcp rules ${record.mcp.agent} ${record.mcp.server} --write ask`,
    ];
  }
  if (record?.mcp && decision.scope === "session") {
    const server = mcpServerLabel(record);
    const target = decision.mcpScope === "server-tools"
      ? `all tool calls on ${server}`
      : decision.mcpScope === "method"
        ? `"${record.mcp.method}" on ${server}`
        : record.mcp.tool
          ? `"${record.mcp.tool}" on ${server}`
          : `"${record.mcp.method}" on ${server}`;
    return [
      `approved ${decision.id}: ${phrase}`,
      `  scope: ${target} ${decision.ttlMs !== undefined ? `for ${formatApprovalDuration(decision.ttlMs)}` : "until this session ends"}`,
    ];
  }
  const scopeText = decision.scope === "session"
    ? decision.ttlMs !== undefined
      ? `all writes to this host for ${formatApprovalDuration(decision.ttlMs)}`
      : "all writes to this host until this session ends"
      : "this request only — the held request is being forwarded now";
  return [`approved ${decision.id}: ${phrase}`, `  scope: ${scopeText}`];
}

function mcpRuleEntryForApproval(record: PendingApprovalRecord, context: RuntimeContext): McpInventoryEntry {
  if (!record.mcp || record.mcp.method !== "tools/call" || !record.mcp.tool) {
    die("saved MCP rules are only available for classified MCP tools/call approvals");
  }
  const stateDir = context.project.paths.stateDir;
  const inventory = mcpInventory({
    approvalPath: mcpApprovalPath(stateDir),
    env: context.env ?? process.env,
    projectRoot: context.projectRoot,
    rulesPath: mcpRulesPath(stateDir),
  });
  const matches = inventory.entries.filter((entry) =>
    entry.agent === record.mcp?.agent
    && entry.name === record.mcp.server
    && entry.mcpPolicy !== undefined
    && (record.mcp.serverId === undefined || entry.mcpPolicy.operationServerId === record.mcp.serverId));
  if (matches.length === 0) {
    die(`could not find the MCP server for this approval; inspect it with: runfree mcp explain ${record.mcp.agent} ${record.mcp.server}`);
  }
  if (matches.length > 1) {
    die(`multiple MCP entries match this approval; inspect them with: runfree mcp explain ${record.mcp.agent} ${record.mcp.server} --source <source>`);
  }
  const entry = matches[0];
  if (entry.source === "project" && entry.decision.status !== "approved") {
    die(`cannot save MCP rules for unapproved project MCP server: runfree mcp approve ${entry.agent} ${entry.name}`);
  }
  if (!entry.endpoint || !entry.mcpPolicy) {
    die("saved MCP rules apply only to HTTP MCP servers imported through the proxy");
  }
  return entry;
}

export function saveMcpRuleForApproval(
  record: PendingApprovalRecord,
  saveMcpRule: "tool" | "server-tools",
  context: RuntimeContext,
): void {
  const entry = mcpRuleEntryForApproval(record, context);
  const key = mcpRuleKeyForEntry(entry);
  if (!key) die("MCP server has no stable rule identity");
  const rulesFile = mcpRulesPath(context.project.paths.stateDir);
  const rules = readMcpRules(context.projectRoot, rulesFile);
  const current = rules.rules[key] ?? {
    agent: entry.agent,
    identity: key,
    schemaVersion: 1 as const,
    server: entry.name,
    source: entry.source,
    updatedAt: new Date().toISOString(),
  };
  const next = {
    ...current,
    updatedAt: new Date().toISOString(),
  };
  if (saveMcpRule === "tool") {
    if (!record.mcp?.tool) die("cannot save a per-tool rule for an approval without a tool name");
    next.tools = { ...(next.tools ?? {}), [record.mcp.tool]: { writeAction: "allow" as const } };
  } else {
    next.defaultToolWriteAction = "allow" as const;
  }
  rules.rules[key] = next;
  writeMcpRules(context.projectRoot, rulesFile, rules);
}

async function applyPreDecisionSideEffects(
  context: RuntimeContext,
  io: RuntimeIO,
  record: PendingApprovalRecord,
  decision: Omit<ApprovalDecisionRecord, "decidedAt">,
): Promise<boolean> {
  if (decision.saveMcpRule === undefined) return true;
  try {
    saveMcpRuleForApproval(record, decision.saveMcpRule, context);
  } catch (error) {
    runfreeLog(error instanceof Error ? error.message : String(error));
    return false;
  }
  const prepare = await io.admin({ kind: "prepare" }, context);
  if (prepare !== 0) {
    runfreeLog("saved MCP rule, but runtime policy generation failed; leaving the held request pending");
    return false;
  }
  const converge = await io.admin({ kind: "converge-proxy-policy" }, context);
  if (converge !== 0) {
    runfreeLog("saved MCP rule, but proxy policy reload failed; leaving the held request pending");
    return false;
  }
  return true;
}

function interactiveTty(): boolean {
  return process.stdout.isTTY === true && process.stdin.isTTY === true;
}

// One clack picker round for a pending record. Returns the decision, or
// undefined when the user cancelled (leaves the item pending: ignoring a
// prompt never decides anything).
async function pickDecision(record: PendingApprovalRecord, signal: AbortSignal): Promise<Omit<ApprovalDecisionRecord, "decidedAt"> | undefined> {
  console.log("");
  console.log(record.mcp?.method === "tools/call" && record.mcp.tool
    ? "approve this MCP tool call?"
    : record.mcp
      ? "approve this MCP operation?"
      : "approve this write?");
  console.log("");
  for (const line of detailLines(record)) console.log(line);
  console.log("");
  const sessionScoped = sessionScopeAvailable(record);
  if (!sessionScoped) {
    console.log(`  (${sessionScopeUnavailableReason(record)})`);
  }
  const scopeNote = subjectNote(record);
  const denyScopeNote = record.session !== undefined ? "for this session" : "in this runtime";
  if (record.mcp) {
    const server = mcpServerLabel(record);
    const hasTool = record.mcp.method === "tools/call" && record.mcp.tool;
    const stableMethod = record.mcp.method !== "<unknown>" && !hasTool && record.mcp.method !== "tools/call";
    const mcpChoice = await select({
      signal,
      message: `${shortId(record.id)} — ${actionPhrase(record)}`,
      options: [
        { value: "request", label: hasTool ? "yes — this call only" : stableMethod ? "yes — this operation only" : "yes — this request only" },
        ...(hasTool && sessionScoped
          ? [
            { value: "session-tool", label: `yes — "${record.mcp.tool}" on ${server} for the rest of this session` },
            { value: "session-server-tools", label: `yes — all tool calls on ${server} for the rest of this session` },
          ]
          : []),
        ...(hasTool
          ? [
            { value: "save-tool", label: `yes — always allow "${record.mcp.tool}" on ${server} (save rule)` },
            { value: "save-server-tools", label: `yes — always allow all tool calls on ${server} (save rule)` },
          ]
          : stableMethod && sessionScoped
            ? [{ value: "session-method", label: `yes — "${record.mcp.method}" on ${server} for the rest of this session` }]
            : []),
        { value: "deny", label: hasTool ? "no — deny this call" : stableMethod ? "no — deny this operation" : "no — deny this request" },
        ...(hasTool && sessionScoped
          ? [
            { value: "deny-session-tool", label: `no — deny "${record.mcp.tool}" on ${server} ${denyScopeNote} until cleared` },
            { value: "deny-session-server-tools", label: `no — deny all tool calls on ${server} ${denyScopeNote} until cleared` },
          ]
          : stableMethod && sessionScoped
            ? [{ value: "deny-session-method", label: `no — deny "${record.mcp.method}" on ${server} ${denyScopeNote} until cleared` }]
            : []),
        ...(sessionScoped
          ? [{ value: "deny-session", label: `no — stop asking: deny ${denySessionCoverage(record)} until cleared` }]
          : []),
      ],
    });
    if (isCancel(mcpChoice)) return undefined;
    if (mcpChoice === "deny") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny" };
    if (mcpChoice === "deny-session") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny", denySession: true };
    if (mcpChoice === "deny-session-tool") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny", scope: "session", mcpScope: "tool" };
    if (mcpChoice === "deny-session-server-tools") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny", scope: "session", mcpScope: "server-tools" };
    if (mcpChoice === "deny-session-method") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny", scope: "session", mcpScope: "method" };
    if (mcpChoice === "session-tool") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "session", mcpScope: "tool" };
    if (mcpChoice === "session-server-tools") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "session", mcpScope: "server-tools" };
    if (mcpChoice === "session-method") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "session", mcpScope: "method" };
    if (mcpChoice === "save-tool") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "request", saveMcpRule: "tool" };
    if (mcpChoice === "save-server-tools") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "request", saveMcpRule: "server-tools" };
    return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "request" };
  }
  const target = friendlyTarget(record.host);
  const choice = await select({
    signal,
    message: `${shortId(record.id)} — ${actionPhrase(record)}`,
    options: [
      { value: "request", label: "yes — this request only" },
      ...(sessionScoped
        ? [
          { value: "session", label: `yes — all writes to ${target} for the rest of this session` },
          { value: "ttl", label: `yes — all writes to ${target} for a limited time (${scopeNote})` },
        ]
        : []),
      { value: "deny", label: "no — deny this request" },
      ...(sessionScoped
        ? [{ value: "deny-session", label: `no — stop asking: deny ${denySessionCoverage(record)} until cleared` }]
        : []),
    ],
  });
  if (isCancel(choice)) return undefined;
  if (choice === "deny") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny" };
  if (choice === "deny-session") return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "deny", denySession: true };
  if (choice === "ttl") {
    const duration = await text({
      signal,
      message: "for how long?",
      placeholder: "15m",
      defaultValue: "15m",
    });
    if (isCancel(duration)) return undefined;
    return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: "session", ttlMs: parseTtlDuration(duration || "15m") };
  }
  return { v: 1, id: record.id, processEpoch: record.processEpoch, decision: "approve", scope: choice as "request" | "session" };
}

async function runPickerLoop(context: RuntimeContext, io: RuntimeIO, proxyId: string, remaining?: Set<string>): Promise<string[]> {
  while (true) {
    const pending = readPendingApprovalsSnapshot(context, io, proxyId);
    if (pending === undefined) {
      if (remaining !== undefined) return [...remaining];
      await new Promise((resolve) => setTimeout(resolve, WATCH_POLL_MS));
      continue;
    }
    const record = pending.find((item) => remaining === undefined || remaining.has(item.id));
    if (!record) return [];
    const cancellation = new AbortController();
    const stillPending = () => readPendingApprovalsSnapshot(context, io, proxyId)
      ?.some((current) => current.id === record.id && current.processEpoch === record.processEpoch);
    // The proxy owns hold lifetime. Observe its records, rather than using
    // the host clock or treating an open prompt as authority to extend a hold.
    const poll = setInterval(() => {
      if (stillPending() === false) cancellation.abort();
    }, WATCH_POLL_MS);
    let decision: Omit<ApprovalDecisionRecord, "decidedAt"> | undefined;
    try {
      decision = await pickDecision(record, cancellation.signal);
    } finally {
      clearInterval(poll);
    }
    if (decision === undefined && !cancellation.signal.aborted) {
      remaining?.delete(record.id);
      console.log(`leaving ${shortId(record.id)} pending — ignoring a prompt never decides anything`);
      return [...(remaining ?? [])];
    }
    const current = stillPending();
    if (current === undefined && !cancellation.signal.aborted) {
      console.log(`could not verify approval ${shortId(record.id)}; waiting to retry`);
      if (remaining !== undefined) return [...remaining];
      await new Promise((resolve) => setTimeout(resolve, WATCH_POLL_MS));
      continue;
    }
    remaining?.delete(record.id);
    if (cancellation.signal.aborted || current === false) {
      console.log(`approval ${shortId(record.id)} is no longer pending — waiting for a new request`);
      continue;
    }
    if (decision === undefined) {
      console.log(`leaving ${shortId(record.id)} pending — ignoring a prompt never decides anything`);
      return [...(remaining ?? [])];
    }
    if (!await applyPreDecisionSideEffects(context, io, record, decision)) {
      console.log(`leaving ${shortId(record.id)} pending — saved-rule approval did not complete`);
      return [...(remaining ?? [])];
    }
    const result = writeDecision(context, io, proxyId, decision);
    if (!result.ok) {
      if (result.alreadyDecided) {
        console.log(`approval ${shortId(record.id)} was already decided`);
        continue;
      }
      // A failed exec does not prove the hold ended. Retry after the watcher
      // delay; a fresh snapshot will suppress an actually completed request.
      remaining?.add(record.id);
      console.log(`approval ${shortId(record.id)} could not be decided (${result.message}) — waiting to retry`);
      if (remaining === undefined) {
        await new Promise((resolve) => setTimeout(resolve, WATCH_POLL_MS));
        continue;
      }
      return [...remaining];
    }
    for (const line of decisionSummary(record, decision)) console.log(line);
  }
}

function approvalsPostureLine(pendingCount: number): string {
  return pendingCount > 0
    ? `${pendingCount} held ${pendingCount === 1 ? "write" : "writes"} waiting`
    : "a held write will appear here";
}

// What one grant covers, in the operator's words. A `request` grant is not
// "the held request": it readmits any write matching a bounded shape until it
// is consumed or expires, so it is rendered as the shape it admits.
//
// Exported because `runfree status` renders the same grants: two renderers
// drifted apart once already (status fell back to the bare host and lost the
// tool identity the moment MCP coverage started carrying a host), and a grant
// rendered broader than it is enforced defeats the point of showing it.
export function grantCoverageLabel(grant: WriteApprovalGrantSummary): string {
  const server = grant.mcp?.server ?? "<unknown server>";
  switch (grant.coverage) {
    case "request":
      return `one write: ${grant.method ?? "<unknown method>"} ${grant.path ?? "/"} on ${grant.host ?? "<unknown host>"}`;
    case "host":
      return `all writes to ${grant.host ?? "<unknown host>"}`;
    case "mcp-server-tools":
      return `all tool calls on ${server}`;
    case "mcp-tool":
      return `"${grant.mcp?.tool ?? "<unknown tool>"}" on ${server}`;
    default:
      return `"${grant.mcp?.method ?? "<unknown method>"}" on ${server}`;
  }
}

// Standing authority, positive and negative, in the operator's words. A deny
// that only shows up as "nothing ever gets approved" is the failure mode this
// closes.
export function standingAuthorityLines(status: WriteApprovalsStatus | undefined, nowMs = Date.now()): string[] {
  if (!status) return [];
  const lines: string[] = [];
  for (const grant of status.grants) {
    const remaining = grantRemainingSeconds(status, grant, nowMs);
    if (remaining !== undefined && remaining <= 0) continue;
    const bound = remaining === undefined ? "until cleared" : `${Math.max(1, Math.round(remaining / 60))}m left`;
    const subject = grant.session !== undefined ? `session ${grant.session.name}` : "this request";
    lines.push(`${grant.effect === "allow" ? "allow" : "deny"} grant: ${grantCoverageLabel(grant)} (${bound}, ${subject})`);
  }
  if (status.grants.some((grant) => grant.effect === "deny" && grant.expiresInSeconds === undefined)) {
    lines.push("clear deny grants: runfree approvals --clear-deny");
  }
  return lines;
}

// The snapshot is level-triggered, so `expiresInSeconds` was computed when the
// proxy last published. Age it against `updatedAt` instead of reporting a
// countdown frozen at publish time.
export function grantRemainingSeconds(
  status: Pick<WriteApprovalsStatus, "updatedAt">,
  grant: { expiresInSeconds?: number },
  nowMs = Date.now(),
): number | undefined {
  if (grant.expiresInSeconds === undefined) return undefined;
  const publishedMs = Date.parse(status.updatedAt);
  if (!Number.isFinite(publishedMs)) return grant.expiresInSeconds;
  return grant.expiresInSeconds - Math.max(0, Math.round((nowMs - publishedMs) / 1000));
}

async function approvalsList(context: RuntimeContext, io: RuntimeIO): Promise<number> {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    console.log("no running proxy container — start one with: runfree up");
    return 1;
  }
  const pending = readPendingApprovals(context, io, proxyId);
  console.log(`write approvals: ${approvalsPostureLine(pending.length)}`);
  for (const line of standingAuthorityLines(readWriteApprovalsStatus(context, io))) console.log(line);
  if (pending.length === 0) {
    return 0;
  }
  console.log("");
  for (const line of pendingTableLines(pending)) console.log(line);
  console.log("");
  console.log("approve:  runfree approve <id> [--scope request|session] [--ttl <dur>]");
  console.log("mcp:      runfree approve <id> --scope session --mcp-scope tool|server-tools");
  console.log("save:     runfree approve <id> --save-mcp-rule tool|server-tools");
  console.log("deny:     runfree approve <id> --deny");
  console.log("          session scopes need a session-backed hold; request-only holds accept request scope and --deny");
  console.log("watch:    runfree approvals --watch");
  console.log("clear:    runfree approvals --clear-deny");
  if (interactiveTty()) {
    await runPickerLoop(context, io, proxyId);
  }
  return 0;
}

// Exactly what a clear is about to revoke, itemized. Clearing drops standing
// authority of BOTH signs — a deny shadows any broader allow underneath it, so
// revoking only the deny would readmit the very call the operator narrowed —
// and the operator has to see both halves before it happens.
export function clearPlanLines(status: WriteApprovalsStatus, nowMs = Date.now()): string[] {
  const lines = ["revoking:"];
  for (const grant of status.grants) {
    const remaining = grantRemainingSeconds(status, grant, nowMs);
    if (remaining !== undefined && remaining <= 0) continue;
    lines.push(`  - ${grant.effect} grant: ${grantCoverageLabel(grant)}`);
  }
  lines.push("  writes go back to being held for approval; standing allow grants are dropped too");
  return lines;
}

// Revokes negative write-approval authority through the root-owned control
// channel: the same trust properties as the decision that created it, bound to
// the deny nonce the operator just saw.
export async function approvalsClearDeny(
  context: RuntimeContext,
  io: RuntimeIO,
  options: { confirmPollMs?: number; confirmAttempts?: number } = {},
): Promise<number> {
  const confirmPollMs = options.confirmPollMs ?? CLEAR_CONFIRM_POLL_MS;
  const confirmAttempts = options.confirmAttempts ?? CLEAR_CONFIRM_ATTEMPTS;
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    console.log("no running proxy container — start one with: runfree up");
    return 1;
  }
  const status = readWriteApprovalsStatus(context, io);
  if (!status) {
    runfreeLog("could not read the proxy write-approval state; is the proxy healthy?");
    return 1;
  }
  const denyGrants = status.grants.filter((grant) => grant.effect === "deny");
  if (denyGrants.length === 0) {
    console.log("no write denies are active — writes are already held for approval");
    return 0;
  }
  // Name every decision this revokes. A clear that reports only a count leaves
  // the operator unable to tell which explicit "no" they just took back.
  for (const line of clearPlanLines(status)) console.log(line);
  const result = writeClearWriteDeny(context, io, proxyId, status.denyId);
  if (!result.ok) {
    runfreeLog(`could not issue the clear: ${result.message}`);
    return 1;
  }
  // The proxy applies a clear only while it still names the current deny
  // state, so confirm rather than assume.
  for (let attempt = 0; attempt < confirmAttempts; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, confirmPollMs));
    const next = readWriteApprovalsStatus(context, io);
    if (next && next.grants.every((grant) => grant.effect !== "deny")) {
      console.log("write deny cleared — writes are held for approval again (runfree approvals)");
      return 0;
    }
  }
  runfreeLog("the proxy did not apply the clear (the deny state changed first) — re-run runfree approvals --clear-deny");
  return 1;
}

function nonTtyWatchLine(nowMs: number, state: string, record: PendingApprovalRecord): string {
  const time = new Date(nowMs).toISOString().slice(11, 19);
  return `${time} ${state.padEnd(8)} ${shortId(record.id)} ${actionPhrase(record)} expires ${formatExpires(nowMs, record.expiresAt)}`;
}

async function approvalsWatch(context: RuntimeContext, io: RuntimeIO, bell: boolean): Promise<number> {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    console.log("no running proxy container — start one with: runfree up");
    return 1;
  }
  if (!touchWatcherHeartbeat(context, io, proxyId)) {
    runfreeLog("could not register the approver heartbeat; held writes will fast-deny");
  }
  console.log("watching for held writes (Ctrl+C to leave) — approver heartbeat registered");
  for (const line of standingAuthorityLines(readWriteApprovalsStatus(context, io))) console.log(line);
  const seen = new Set<string>();
  // Keep the watcher attached while a picker (including the duration prompt)
  // waits for input. The outer watch loop cannot refresh it during that wait.
  const heartbeat = setInterval(() => touchWatcherHeartbeat(context, io, proxyId), WATCH_HEARTBEAT_MS);
  let interrupted = false;
  const onInterrupt = () => {
    interrupted = true;
  };
  process.once("SIGINT", onInterrupt);
  try {
    while (!interrupted) {
      const nowMs = Date.now();
      const pending = readPendingApprovals(context, io, proxyId);
      const fresh = pending.filter((record) => !seen.has(record.id));
      for (const record of fresh) {
        seen.add(record.id);
        if (bell) process.stdout.write("");
        console.log(nonTtyWatchLine(nowMs, "held", record));
      }
      if (fresh.length > 0 && interactiveTty()) {
        const retries = await runPickerLoop(context, io, proxyId, new Set(fresh.map((record) => record.id)));
        for (const id of retries) seen.delete(id);
      }
      await new Promise((resolve) => setTimeout(resolve, WATCH_POLL_MS));
    }
  } finally {
    clearInterval(heartbeat);
    process.removeListener("SIGINT", onInterrupt);
  }
  const remaining = readPendingApprovals(context, io, proxyId).length;
  console.log(`leaving watch — ${remaining} ${remaining === 1 ? "write" : "writes"} still pending`);
  return 0;
}

function parentAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function approvalsHeartbeat(context: RuntimeContext, io: RuntimeIO, parentPid: number): Promise<number> {
  while (parentAlive(parentPid)) {
    const proxyId = runningProxyId(context, io);
    if (proxyId) touchWatcherHeartbeat(context, io, proxyId);
    await new Promise((resolve) => setTimeout(resolve, WATCH_HEARTBEAT_MS));
  }
  return 0;
}

export async function approvalsRuntime(input: ApprovalsInput, context: RuntimeContext, io: RuntimeIO): Promise<number> {
  if (input.kind === "watch") {
    if (input.clearDenyFirst) {
      // A failed revocation must not be followed by a watch that looks
      // healthy. The operator would sit attached to a runtime that still
      // denies every write, waiting for prompts that can never arrive, with
      // the failure scrolled off above. "Nothing was denied" is not a failure
      // and returns 0, so that case proceeds to watch: the goal state — no
      // deny, approver attached — is exactly what they asked for.
      const cleared = await approvalsClearDeny(context, io);
      if (cleared !== 0) return cleared;
    }
    return approvalsWatch(context, io, input.bell);
  }
  if (input.kind === "heartbeat") return approvalsHeartbeat(context, io, input.parentPid);
  if (input.kind === "clear-deny") return approvalsClearDeny(context, io);
  return approvalsList(context, io);
}

export async function approveRuntime(input: ApproveInput, context: RuntimeContext, io: RuntimeIO): Promise<number> {
  const proxyId = runningProxyId(context, io);
  if (!proxyId) {
    console.log("no running proxy container — start one with: runfree up");
    return 1;
  }
  const prefix = input.id.toLowerCase();
  if (!/^[0-9a-f]{4,32}$/.test(prefix)) {
    die(`invalid approval id: ${input.id} (use at least 4 hex characters from runfree approvals)`);
  }
  const pending = readPendingApprovals(context, io, proxyId);
  const matches = pending.filter((record) => record.id.startsWith(prefix));
  if (matches.length === 0) {
    runfreeLog(`no pending approval matches ${input.id} — run runfree approvals`);
    return 1;
  }
  if (matches.length > 1) {
    runfreeLog(`ambiguous approval id ${input.id}; matches: ${matches.map((record) => shortId(record.id)).join(", ")}`);
    return 1;
  }
  const record = matches[0];
  if (!isApprovalId(record.id)) {
    runfreeLog("pending approval record carries a malformed id; refusing to decide it");
    return 1;
  }

  // A session-wide decision for a request-only principal is refused by the
  // proxy after the decision file lands, at which point this command has
  // already printed a session-wide success it never had. Refuse here instead,
  // before any decision exists, naming what the operator can still do.
  if ((input.scope === "session" || input.scope === "deny-session") && !sessionScopeAvailable(record)) {
    die(`--scope ${input.scope} is not available for ${shortId(record.id)}: ${sessionScopeUnavailableReason(record)}. `
      + `Use \`runfree approve ${shortId(record.id)}\` for this request only, or \`--deny\` to deny it.`);
  }

  let decision: Omit<ApprovalDecisionRecord, "decidedAt">;
  if (input.deny || input.scope === "deny-session") {
    if (input.saveMcpRule) die("--save-mcp-rule cannot be used with --deny");
    decision = {
      v: 1,
      id: record.id, processEpoch: record.processEpoch,
      decision: "deny",
      ...(input.scope === "deny-session" ? { denySession: true } : {}),
      ...(record.mcp && input.scope === "session" ? { scope: "session" as const, mcpScope: input.mcpScope } : {}),
    };
  } else {
    if (input.ttl && input.scope !== "session") die("--ttl requires --scope session");
    if (input.saveMcpRule && input.scope && input.scope !== "request") die("--save-mcp-rule uses request scope after saving the MCP rule");
    if (input.mcpScope && input.scope !== "session" && !input.saveMcpRule) die("--mcp-scope requires --scope session for approvals");
    if (input.mcpScope && !record.mcp) die("--mcp-scope can only be used for MCP approvals");
    if (input.saveMcpRule && !record.mcp) die("--save-mcp-rule can only be used for MCP approvals");
    decision = {
      v: 1,
      id: record.id, processEpoch: record.processEpoch,
      decision: "approve",
      scope: input.saveMcpRule ? "request" : input.scope ?? "request",
      ...(input.ttl ? { ttlMs: parseTtlDuration(input.ttl) } : {}),
      ...(record.mcp && input.mcpScope ? { mcpScope: input.mcpScope } : {}),
      ...(input.saveMcpRule ? { saveMcpRule: input.saveMcpRule } : {}),
    };
  }

  if (!await applyPreDecisionSideEffects(context, io, record, decision)) return 1;
  const result = writeDecision(context, io, proxyId, decision);
  if (!result.ok) {
    runfreeLog(result.alreadyDecided
      ? `approval ${shortId(record.id)} was already decided`
      : `deciding approval failed: ${result.message}`);
    return 1;
  }
  for (const line of decisionSummary(record, decision)) console.log(line);
  return 0;
}
