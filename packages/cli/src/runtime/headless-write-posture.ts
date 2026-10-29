// The write-posture preflight and the unchecked-authority listing of a
// headless run (headless-run spec §3.5 "Write posture", plan Task 11).
//
// Preflight. A headless session has no approver, so the proxy denies every
// write that resolves to `ask` (`headless-denied`). Before launch, `run`
// lists every way a write can resolve to `ask`, warns in one line, and
// records the list in run.json; it does not refuse (maintainer decision
// 2026-10-29, reversing headless-run spec §7 decision 2). The proxy is the
// enforcement. The preflight reads what the proxy enforces (the active
// effective policy generation, including its MCP operation policy payload)
// and resolves every action with the proxy's own shared resolvers from
// runtime-contracts, never a copy:
//
//   - per allowlisted host, `effectiveWriteAction(policy, host)`;
//   - per MCP server, `effectiveMcpToolAction` for each listed tool and for an
//     unlisted tool (the server default, else the global action);
//   - when any MCP server is configured, the global action unclassified MCP
//     methods use (`mcp-classify.ts`), resolved as `effectiveWriteAction` for
//     a host with no rule (the proxy's `writeApproval ?? DEFAULT_WRITE_ACTION`).
//
// `DEFAULT_WRITE_ACTION` is `ask` (plan C7), so a project with an allowlisted
// host and no write rules warns. Anything the preflight cannot read is named
// in the warning. The proxy picks an MCP rule by endpoint, not by the
// session's agent, so a Codex server's rule applies to a Claude run too; the
// listing keeps every server and names it by endpoint.
//
// Unchecked authority. Host-service tunnels, mediated OAuth exchanges, and
// stdio or loopback MCP servers do not pass write posture
// (`docs/security.md`). `run` allows them (spec §7 decision 6) and lists them,
// names only, in `run.json`.

import fs from "node:fs";
import path from "node:path";

import {
  effectiveMcpToolAction,
  validateMcpOperationPolicy,
  type LoadedMcpOperationPolicy,
} from "@runfree/runtime-contracts/mcp-operation-policy";
import {
  effectiveWriteAction,
  validateNetworkPolicy,
  type LoadedNetworkPolicy,
} from "@runfree/runtime-contracts/network-policy";
import {
  validateOAuthMediationPolicy,
  type LoadedOAuthMediationPolicy,
} from "@runfree/runtime-contracts/oauth-mediation-policy";

import { readActiveEffectiveControl, type EffectivePolicyGeneration } from "../control/effective.ts";
import { parseStrictJson } from "../control/strict-json.ts";
import { sha256Digest } from "../strict-primitives.ts";
import type { HeadlessUncheckedAuthority, HeadlessUncheckedAuthoritySource } from "./headless-run-record.ts";
import { mcpApprovalPath, mcpInventory, mcpRulesPath, type McpInventoryEntry } from "./mcp.ts";
import type { RuntimeContext } from "./types.ts";

const MCP_OPERATION_POLICY_PAYLOAD = "mcp-operation-policy.json";
// A tool name no listed rule can carry (names are non-empty), so the shared
// resolver answers with the server default, else the global action.
const UNLISTED_TOOL = "";
// A host no rule can name, so `effectiveWriteAction` answers with the global
// action: the proxy's `writeApproval ?? DEFAULT_WRITE_ACTION`.
const NO_RULE_HOST = "";

export type HeadlessAskMcpServer = Readonly<{
  serverId: string;
  agent: string;
  name: string;
  /** The endpoint the proxy matches the rule by, for every session (mcp-classify.ts). */
  host: string;
  path: string;
  /** An unlisted tool resolves to `ask` (the server default, else the global action). */
  defaultAsk: boolean;
  /** Listed tools whose own rule resolves to `ask`. */
  askTools: readonly string[];
}>;

export type HeadlessAskExposure = Readonly<{
  /** Hosts with no per-host write rule; their writes use the global action, which is `ask`. */
  defaultAskHosts: readonly string[];
  /** Hosts whose own write rule (direct or a service's) is `ask`. */
  ruleAskHosts: readonly string[];
  askMcp: readonly HeadlessAskMcpServer[];
  /** MCP servers are configured and the global action, which unclassified MCP methods use, is `ask`. */
  globalAskWithMcp: boolean;
  /** Why the enforced policy could not be read. */
  unreadable: readonly string[];
}>;

function errorText(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "unknown error";
}

/** The exposure of one loaded policy pair, resolved with the proxy's shared resolvers. */
export function askExposureOf(controls: Readonly<{ policy: LoadedNetworkPolicy; mcp?: LoadedMcpOperationPolicy }>): HeadlessAskExposure {
  const { policy } = controls;
  const ruled = (host: string): boolean => policy.requests[host]?.writeAction !== undefined;
  const askHosts = policy.allowedHosts.filter((host) => effectiveWriteAction(policy, host) === "ask");
  const globalWriteAction = effectiveWriteAction({ requests: {}, writeApproval: policy.writeApproval }, NO_RULE_HOST);
  const servers = controls.mcp?.servers ?? [];
  const askMcp = servers.flatMap((server): HeadlessAskMcpServer[] => {
    const defaultAsk = effectiveMcpToolAction({ ...server, tools: {} }, UNLISTED_TOOL, globalWriteAction) === "ask";
    const askTools = Object.keys(server.tools).filter((tool) => effectiveMcpToolAction(server, tool, globalWriteAction) === "ask");
    return defaultAsk || askTools.length > 0
      ? [{ serverId: server.id, agent: server.agent, name: server.name, host: server.host, path: server.path, defaultAsk, askTools }]
      : [];
  });
  return {
    defaultAskHosts: askHosts.filter((host) => !ruled(host)),
    ruleAskHosts: askHosts.filter(ruled),
    askMcp,
    globalAskWithMcp: servers.length > 0 && globalWriteAction === "ask",
    unreadable: [],
  };
}

function readGenerationPayload(generation: EffectivePolicyGeneration, name: string, digest: string): unknown {
  const filePath = path.join(generation.proxyDirectory, name);
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.nlink !== 1) throw new Error(`${name} is not a regular single-link generation file`);
  const source = fs.readFileSync(filePath, "utf8");
  if (sha256Digest(source) !== digest) throw new Error(`${name} does not match its manifest digest`);
  return parseStrictJson(source);
}

type EnforcedControls = Readonly<{
  policy: LoadedNetworkPolicy;
  mcp?: LoadedMcpOperationPolicy;
  generation: EffectivePolicyGeneration;
}>;

/** The policy the proxy enforces: the active effective policy generation. Throws when it cannot be read. */
function readEnforcedControls(context: Pick<RuntimeContext, "project">): EnforcedControls {
  const generation = readActiveEffectiveControl(context.project);
  if (!generation) throw new Error("no effective policy generation is selected");
  const policy = validateNetworkPolicy(generation.policy);
  const mcpDigest = generation.proxyManifest.files[MCP_OPERATION_POLICY_PAYLOAD];
  const mcp = mcpDigest === undefined
    ? undefined
    : validateMcpOperationPolicy(readGenerationPayload(generation, MCP_OPERATION_POLICY_PAYLOAD, mcpDigest), MCP_OPERATION_POLICY_PAYLOAD);
  return { policy, generation, ...(mcp ? { mcp } : {}) };
}

/** Every way a write of this project can resolve to `ask` now; unreadable state is named. */
export function headlessAskExposure(context: Pick<RuntimeContext, "project">): HeadlessAskExposure {
  try {
    return askExposureOf(readEnforcedControls(context));
  } catch (error) {
    return { defaultAskHosts: [], ruleAskHosts: [], askMcp: [], globalAskWithMcp: false, unreadable: [`the effective policy could not be read: ${errorText(error)}`] };
  }
}

export function hasAskExposure(exposure: HeadlessAskExposure): boolean {
  return exposure.defaultAskHosts.length > 0
    || exposure.ruleAskHosts.length > 0
    || exposure.askMcp.length > 0
    || exposure.globalAskWithMcp
    || exposure.unreadable.length > 0;
}

function counted(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** The one-line launch warning, or undefined when nothing would ask or the operator accepted denials. */
export function headlessWritePostureWarning(
  exposure: HeadlessAskExposure,
  options: Readonly<{ acceptDeniedWrites: boolean }>,
): string | undefined {
  if (options.acceptDeniedWrites || !hasAskExposure(exposure)) return undefined;
  if (exposure.unreadable.length > 0) {
    return `headless run: the write posture could not be read (${exposure.unreadable.join("; ")}); writes that would ask for approval are denied`;
  }
  const hosts = exposure.defaultAskHosts.length + exposure.ruleAskHosts.length;
  const parts = [
    ...(hosts > 0 ? [counted(hosts, "host", "hosts")] : []),
    ...(exposure.askMcp.length > 0 ? [counted(exposure.askMcp.length, "MCP endpoint", "MCP endpoints")] : []),
    ...(exposure.globalAskWithMcp ? ["unclassified MCP methods"] : []),
  ];
  return `headless run: writes that would ask for approval are denied (${parts.join(", ")}); run.json lists them`;
}

const UNCHECKED_SOURCES: readonly HeadlessUncheckedAuthoritySource[] = ["hostServices", "oauthExchanges", "localMcpServers"];

/** Names of the authority a run allows without write posture; a source left undefined is unreadable. */
export function uncheckedAuthorityOf(
  agent: string,
  sources: Readonly<{ policy?: LoadedNetworkPolicy; oauth?: LoadedOAuthMediationPolicy; mcpEntries?: readonly McpInventoryEntry[] }>,
): HeadlessUncheckedAuthority {
  const sorted = (values: Iterable<string>): string[] => [...new Set(values)].sort();
  const present = {
    hostServices: sources.policy !== undefined,
    oauthExchanges: sources.oauth !== undefined,
    localMcpServers: sources.mcpEntries !== undefined,
  };
  return {
    hostServices: sorted(Object.keys(sources.policy?.hostServices ?? {})),
    oauthExchanges: sorted((sources.oauth?.providers ?? []).map((provider) => provider.providerId)),
    localMcpServers: sorted((sources.mcpEntries ?? [])
      .filter((entry) => entry.agent === agent && entry.target === "generated"
        && (entry.transport === "stdio" || entry.transport === "http-loopback"))
      .map((entry) => `${entry.name} (${entry.transport})`)),
    unreadable: UNCHECKED_SOURCES.filter((source) => !present[source]),
  };
}

/** Lists the unchecked authority of a run of `agent` for `run.json`; never throws. */
export function uncheckedAuthority(context: RuntimeContext, agent: string): HeadlessUncheckedAuthority {
  let policy: LoadedNetworkPolicy | undefined;
  let oauth: LoadedOAuthMediationPolicy | undefined;
  let mcpEntries: McpInventoryEntry[] | undefined;
  try {
    const generation = readActiveEffectiveControl(context.project);
    if (generation) {
      policy = validateNetworkPolicy(generation.policy);
      oauth = validateOAuthMediationPolicy(
        readGenerationPayload(generation, "oauth-mediation-policy.json", generation.proxyManifest.files["oauth-mediation-policy.json"]),
        "oauth-mediation-policy.json",
      );
    }
  } catch {
    // Named as unreadable below.
  }
  try {
    const stateDir = context.project.paths.stateDir;
    mcpEntries = mcpInventory({
      projectRoot: context.projectRoot,
      env: context.env ?? process.env,
      approvalPath: mcpApprovalPath(stateDir),
      rulesPath: mcpRulesPath(stateDir),
    }).entries;
  } catch {
    // Named as unreadable below.
  }
  return uncheckedAuthorityOf(agent, {
    ...(policy ? { policy } : {}),
    ...(oauth ? { oauth } : {}),
    ...(mcpEntries ? { mcpEntries } : {}),
  });
}
