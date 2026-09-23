// denial-summary.ts — session-end summary of proxy denials.
//
// After an agent session ends, the host CLI reads proxy logs since session
// start and prints a deduplicated summary of denied hosts with `runfree
// host add` suggestions. The summary is informational only: it never mutates
// policy, is bounded by a short log-read timeout, and is skipped silently on
// any error so it can never delay or fail session exit.

import fs from "node:fs";

import { validateNetworkPolicy, type PolicyJson } from "@runfree/runtime-contracts/network-policy";

import {
  countBlockedHostDiagnoses,
  diagnoseBlockedHosts,
  sanitizeForTerminal,
  summarizeProtocolDenials,
} from "../../../../scripts/domain-diagnostics.ts";
import { serviceSuggestionLines, type Service } from "../../../../scripts/services.ts";
import { combinedServiceRegistry } from "../user-services.ts";
import { readActiveEffectiveControl } from "../control/effective.ts";
import { dockerClientEnvOptions, serviceContainerId } from "./docker.ts";
import { composeProjectName } from "./env.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const SUMMARY_HOST_LIMIT = 10;
const LOG_READ_TIMEOUT_MS = 3_000;

function requestCountLabel(count: number): string {
  return count === 1 ? "(1 request)" : `(${count} requests)`;
}

// Guard denials raised before any host is known are not blocked hosts and have
// no widening command, so they get their own line rather than being dropped.
function protocolDenialLines(logs: string): string[] {
  const summaries = summarizeProtocolDenials(logs);
  if (summaries.length === 0) return [];
  const total = summaries.reduce((sum, summary) => sum + summary.count, 0);
  return [
    `Runfree also refused ${total} ${total === 1 ? "connection" : "connections"} at the proxy connection guard:`,
    ...summaries.map((summary) => `  ${sanitizeForTerminal(summary.reason)}   ${requestCountLabel(summary.count)}`),
  ];
}

export function buildSessionDenialSummary(logs: string, policy: PolicyJson, limit = SUMMARY_HOST_LIMIT, registry?: Record<string, Service>): string[] {
  const diagnostics = diagnoseBlockedHosts(logs, policy, limit);
  const protocolLines = protocolDenialLines(logs);
  if (diagnostics.length === 0) {
    return protocolLines.length === 0 ? [] : [...protocolLines, "Details: runfree doctor"];
  }

  const hostWidth = Math.max(...diagnostics.map((diagnostic) => diagnostic.host.length));
  const countWidth = Math.max(...diagnostics.map((diagnostic) => requestCountLabel(diagnostic.count).length));

  // The summary is capped; the count is the total, and the cap is stated.
  const total = countBlockedHostDiagnoses(logs);
  const shown = diagnostics.length;
  const lines = [
    `Runfree blocked ${total} ${total === 1 ? "host" : "hosts"} during this session${total > shown ? ` (showing ${shown} of ${total})` : ""}:`,
  ];
  for (const diagnostic of diagnostics) {
    const host = sanitizeForTerminal(diagnostic.host);
    // Shape denials suggest the exact widening command instead of a redundant
    // `runfree host add <host>`; the command is built from re-validated values.
    const remediation = diagnostic.status === "allowlisted"
      ? "now allowed; rerun the failed command"
      : sanitizeForTerminal(diagnostic.command);
    lines.push(`  ${host.padEnd(hostWidth)}   ${requestCountLabel(diagnostic.count).padEnd(countWidth)}   ${remediation}`);
    // Secondary option only: the exact host above stays the primary
    // suggestion; the owning service is named but never auto-applied, with
    // broad-host warnings inlined by serviceSuggestionLines.
    if (diagnostic.status === "missing") {
      if (diagnostic.mcpOAuthIssuer) {
        lines.push(`      OAuth issuer for MCP server ${diagnostic.mcpOAuthIssuer.serverName} (resource ${diagnostic.mcpOAuthIssuer.resourceHost})`);
      }
      for (const serviceLine of serviceSuggestionLines(diagnostic.host, registry)) {
        lines.push(`      ${sanitizeForTerminal(serviceLine)}`);
      }
    }
  }
  lines.push(...protocolLines);
  lines.push("Details: runfree doctor");
  return lines;
}

function readPolicyForSummary(context: RuntimeContext): PolicyJson {
  try {
    if (context.project.config.version >= 4) {
      return readActiveEffectiveControl(context.project)?.policy ?? { hosts: [], tokens: {} };
    }
    const raw: unknown = JSON.parse(fs.readFileSync(context.project.paths.policyPath, "utf8"));
    return validateNetworkPolicy(raw, context.project.paths.policyPath).raw;
  } catch {
    // Without a readable policy, every denied host is reported as missing.
    return { hosts: [], tokens: {} };
  }
}

export function printSessionDenialSummary(
  context: RuntimeContext,
  io: RuntimeIO,
  options: { sinceIso: string; quiet?: boolean },
): void {
  if (options.quiet) return;
  try {
    const project = composeProjectName(context.projectRoot);
    const proxyId = serviceContainerId(project, "proxy", context, io);
    if (!proxyId) return;
    const logs = io.capture(
      "docker",
      ["logs", "--since", options.sinceIso, proxyId],
      { ...dockerClientEnvOptions(context), timeout: LOG_READ_TIMEOUT_MS },
    );
    if (logs.status !== 0) return;
    const lines = buildSessionDenialSummary(`${logs.stdout}\n${logs.stderr}`, readPolicyForSummary(context), SUMMARY_HOST_LIMIT, combinedServiceRegistry(context.projectRoot, context.env));
    for (const line of lines) console.log(line);
  } catch {
    // Never delay or fail session exit because of summary problems.
  }
}
