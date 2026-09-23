// `doctor` typed intent + proxy log diagnosis (split from options.ts). Shared
// docker/proxy machinery lives in admin-core.ts.

import {
  countBlockedHostDiagnoses,
  diagnoseBlockedHosts,
  sanitizeForTerminal,
  summarizeProtocolDenials,
  type ProtocolDenialSummary,
} from "../../../../scripts/domain-diagnostics.ts";
import {
  serviceSuggestionLines,
} from "../../../../scripts/services.ts";
import { projectInfo, resolveAgentCommand } from "../config.ts";
import { RUNFREE_RUNTIME_TARGETS } from "../runtime/mount-target-policy.ts";
import { combinedServiceRegistry } from "../user-services.ts";
import {
  composeProject,
  currentAdminState,
  die,
  dockerAvailable,
  type DoctorInput,
  loadPolicy,
  proxyContainerId,
  runCapture,
} from "./admin-core.ts";

function parseTailOption(value: string | undefined): number {
  if (value === undefined) return 300;
  if (!/^[1-9][0-9]{0,4}$/.test(value)) die("--tail must be a positive integer");
  return Number(value);
}

function readRecentProxyLogs(tail: number): { ok: true; logs: string } | { ok: false; message: string } {
  if (!dockerAvailable()) return { ok: false, message: "docker unavailable" };
  const project = composeProject();
  if (!project) return { ok: false, message: "no agent compose project found; try 'runfree up' first" };
  const id = proxyContainerId(project);
  if (!id) return { ok: false, message: "no proxy container found; try 'runfree up' first" };

  const logs = runCapture("docker", ["logs", "--tail", String(tail), id]);
  if (logs.status !== 0) {
    return { ok: false, message: logs.stderr.trim() || "failed to read proxy logs" };
  }
  return { ok: true, logs: `${logs.stdout}${logs.stderr}` };
}

function claudeInboxGrantWarning(): string | undefined {
  const state = currentAdminState();
  const command = resolveAgentCommand(projectInfo(state.projectRoot, state.env.child).config, "claude");
  if (!command) return undefined;
  const escapedPath = RUNFREE_RUNTIME_TARGETS.inbox.replaceAll("/", "\\/");
  const hasGrant = new RegExp(`(?:^|\\s)--add-dir(?:=|\\s+)["']?${escapedPath}(?:["']?(?:\\s|$))`).test(command);
  if (hasGrant) return undefined;
  return `doctor: agents.claude.command does not grant the Runfree inbox; add --add-dir ${RUNFREE_RUNTIME_TARGETS.inbox}`;
}

// Read-only diagnostic. Takes typed intent and re-validates `--tail` via
// parseTailOption. Driven by the yargs `doctor` command module.
export function doctorIntent(input: DoctorInput): void {
  const postFailure = input.postFailure;
  const tail = parseTailOption(input.tail);
  const policy = loadPolicy();
  const inboxGrantWarning = claudeInboxGrantWarning();
  if (inboxGrantWarning && !postFailure) console.log(inboxGrantWarning);
  const logs = readRecentProxyLogs(tail);

  if (!logs.ok) {
    if (!postFailure) {
      console.log(`doctor: ${logs.message}`);
    }
    return;
  }

  const diagnostics = diagnoseBlockedHosts(logs.logs, policy.raw);
  const state = currentAdminState();
  const registry = combinedServiceRegistry(state.projectRoot, state.env.child);
  // Connection-guard denials have no host and no widening command, so they are
  // reported as their own section rather than being silently dropped.
  const protocolDenials = summarizeProtocolDenials(logs.logs);
  if (diagnostics.length === 0 && protocolDenials.length === 0) {
    if (!postFailure) {
      console.log(`doctor: no blocked proxy hosts found in the last ${tail} proxy log lines`);
    }
    return;
  }
  if (diagnostics.length === 0) {
    printProtocolDenials(protocolDenials, postFailure);
    return;
  }

  console.log(postFailure ? "\nrunfree: proxy allowlist diagnosis" : "Proxy allowlist diagnosis");
  const total = countBlockedHostDiagnoses(logs.logs);
  if (total > diagnostics.length) console.log(`showing the ${diagnostics.length} most recent of ${total} blocked entries`);
  for (const diagnostic of diagnostics) {
    const host = sanitizeForTerminal(diagnostic.host);
    const requests = diagnostic.count === 1 ? "1 request" : `${diagnostic.count} requests`;
    if (diagnostic.status === "request-shape") {
      const method = diagnostic.method ? ` method ${sanitizeForTerminal(diagnostic.method)}` : "";
      console.log(`${host} blocked by request rules (${sanitizeForTerminal(diagnostic.reason ?? "request-shape")}${method}, ${requests})`);
      // The bare `host rules <host>` form only shows the rule; labeling it a
      // fix told the operator that pasting it changes something.
      console.log(`${diagnostic.commandKind === "inspect" ? "inspect rule" : "suggested fix"}: ${diagnostic.command}`);
    } else if (diagnostic.status === "missing") {
      console.log(`${host} is not allowlisted (${requests})`);
      console.log(`suggested fix: ${diagnostic.command}`);
      if (diagnostic.mcpOAuthIssuer) {
        console.log(`context: OAuth issuer for MCP server ${sanitizeForTerminal(diagnostic.mcpOAuthIssuer.serverName)} (resource ${sanitizeForTerminal(diagnostic.mcpOAuthIssuer.resourceHost)})`);
      }
      // Secondary option only: the exact host stays the primary suggestion;
      // a service is named but never auto-applied, with broad-host warnings
      // inlined by serviceSuggestionLines.
      for (const line of serviceSuggestionLines(diagnostic.host, registry)) {
        console.log(`  ${sanitizeForTerminal(line)}`);
      }
    } else {
      console.log(`${host} is already allowlisted in policy (${requests})`);
      console.log(`suggested fix: ${diagnostic.command}`);
    }
  }
  printProtocolDenials(protocolDenials, postFailure);
}

function printProtocolDenials(summaries: ProtocolDenialSummary[], postFailure: boolean | undefined): void {
  if (summaries.length === 0) return;
  console.log(postFailure ? "\nrunfree: proxy connection guard denials" : "Proxy connection guard denials");
  for (const summary of summaries) {
    const requests = summary.count === 1 ? "1 connection" : `${summary.count} connections`;
    console.log(`${sanitizeForTerminal(summary.reason)} (${requests})`);
  }
  console.log("These are refused before any host is known, so there is no allowlist change to make.");
}
