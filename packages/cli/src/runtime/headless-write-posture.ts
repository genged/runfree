// The write-posture preflight and the unchecked-authority listing of a
// headless run (headless-run spec §3.5 "Write posture", plan Task 11).
//
// Preflight. A headless session has no approver, so the proxy denies every
// write that resolves to `ask` (`headless-denied`). Before launch, `run`
// refuses with 65 when any write can resolve to `ask`, unless
// `--accept-denied-writes` was given. The preflight is an early warning only:
// the proxy is the enforcement. It reads what the proxy enforces (the active
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
// host and no write rules refuses: that is spec decision 2, not a defect.
// Anything the preflight cannot read is exposure (fail closed).
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
  /** An unlisted tool resolves to `ask` (the server default, else the global action). */
  defaultAsk: boolean;
  /** Listed tools whose own rule resolves to `ask`. */
  askTools: readonly string[];
}>;

export type HeadlessAskExposure = Readonly<{
  askHosts: readonly string[];
  askMcp: readonly HeadlessAskMcpServer[];
  /** MCP servers are configured and the global action, which unclassified MCP methods use, is `ask`. */
  globalAskWithMcp: boolean;
  /** Why the enforced policy could not be read; any entry is exposure. */
  unreadable: readonly string[];
}>;

export type HeadlessWritePosturePreflight =
  | Readonly<{ kind: "pass"; accepted: boolean; exposure: HeadlessAskExposure }>
  | Readonly<{ kind: "refuse"; status: 65; message: string; exposure: HeadlessAskExposure }>;

function errorText(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "unknown error";
}

/** The exposure of one loaded policy pair, resolved with the proxy's shared resolvers. */
export function askExposureOf(controls: Readonly<{ policy: LoadedNetworkPolicy; mcp?: LoadedMcpOperationPolicy }>): HeadlessAskExposure {
  const { policy } = controls;
  const askHosts = policy.allowedHosts.filter((host) => effectiveWriteAction(policy, host) === "ask");
  const globalWriteAction = effectiveWriteAction({ requests: {}, writeApproval: policy.writeApproval }, NO_RULE_HOST);
  const servers = controls.mcp?.servers ?? [];
  const askMcp = servers.flatMap((server): HeadlessAskMcpServer[] => {
    const defaultAsk = effectiveMcpToolAction({ ...server, tools: {} }, UNLISTED_TOOL, globalWriteAction) === "ask";
    const askTools = Object.keys(server.tools).filter((tool) => effectiveMcpToolAction(server, tool, globalWriteAction) === "ask");
    return defaultAsk || askTools.length > 0
      ? [{ serverId: server.id, agent: server.agent, name: server.name, defaultAsk, askTools }]
      : [];
  });
  return {
    askHosts,
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

/** Every way a write of this project can resolve to `ask` now; unreadable state is exposure. */
export function headlessAskExposure(context: Pick<RuntimeContext, "project">): HeadlessAskExposure {
  try {
    return askExposureOf(readEnforcedControls(context));
  } catch (error) {
    return { askHosts: [], askMcp: [], globalAskWithMcp: false, unreadable: [`the effective policy could not be read: ${errorText(error)}`] };
  }
}

export function hasAskExposure(exposure: HeadlessAskExposure): boolean {
  return exposure.askHosts.length > 0 || exposure.askMcp.length > 0 || exposure.globalAskWithMcp || exposure.unreadable.length > 0;
}

function exposureLines(exposure: HeadlessAskExposure): string[] {
  return [
    ...exposure.unreadable.map((reason) => `  - ${reason}`),
    ...exposure.askHosts.map((host) => `  - host ${host}: writes ask`),
    ...exposure.askMcp.map((server) => {
      const parts = [
        ...(server.defaultAsk ? ["unlisted tools ask"] : []),
        ...(server.askTools.length > 0 ? [`tools ask: ${server.askTools.join(", ")}`] : []),
      ];
      return `  - MCP server ${server.agent} ${server.name}: ${parts.join("; ")}`;
    }),
    ...(exposure.globalAskWithMcp ? ["  - MCP methods that are not classified use the global write action, which is ask"] : []),
  ];
}

/**
 * Refuses (65) when any write can resolve to `ask`, unless the operator
 * accepted denied writes. A pass with exposure is `accepted: true`.
 */
export function headlessWritePosturePreflight(
  exposure: HeadlessAskExposure,
  options: Readonly<{ acceptDeniedWrites: boolean }>,
): HeadlessWritePosturePreflight {
  if (!hasAskExposure(exposure)) return { kind: "pass", accepted: false, exposure };
  if (options.acceptDeniedWrites) return { kind: "pass", accepted: true, exposure };
  return {
    kind: "refuse",
    status: 65,
    exposure,
    message: [
      "refusing a headless run: these writes would ask for approval, and a headless session denies them:",
      ...exposureLines(exposure),
      "Set each to allow or deny with host or MCP write rules, or pass --accept-denied-writes to run and let them be denied.",
    ].join("\n"),
  };
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
