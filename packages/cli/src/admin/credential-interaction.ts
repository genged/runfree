// The "never asks" rule for runs (profiles and unattended credentials spec
// §4.3). A `runfree run` holds an interaction-forbidden hold for its whole
// life, and so does the run's credential watcher (`credential sync --watch
// --unattended`). While it is held, a credential read may start only a
// provider that runfree set up itself and knows cannot ask a person: an env
// source or a 1password connection source. Runfree does not guess from the
// environment: a host OP_SERVICE_ACCOUNT_TOKEN changes nothing here.
//
// Pure apart from the module-level hold counter: the verdict reads only the
// binding and the source registry, never a cache, so a run's answer does not
// depend on timing. admin-core imports this module; it imports only types
// from admin-core (no runtime cycle).

import { remedy } from "../remedies.ts";
import { TokenResolutionError, type TokenResolutionSourceKind } from "../token-resolution.ts";
import type { CredentialOwner, SourceRegistry, TokenSource } from "./admin-core.ts";

// Counted, so nested holders compose and a release is never lost.
let interactionForbiddenHolds = 0;

/** Holds the interaction-forbidden rule until the returned release runs (idempotent). */
export function forbidCredentialInteraction(): () => void {
  interactionForbiddenHolds += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    interactionForbiddenHolds -= 1;
  };
}

/** Whether a run holds the interaction-forbidden rule now. */
export function credentialInteractionForbidden(): boolean {
  return interactionForbiddenHolds > 0;
}

export type MayAskReason = "1password-app" | "command" | "signing-key-1password-app";

export type UnattendedReadVerdict =
  | Readonly<{ kind: "never-asks" }>
  | Readonly<{ kind: "may-ask"; reason: MayAskReason }>;

const NEVER_ASKS: UnattendedReadVerdict = Object.freeze({ kind: "never-asks" });

function mayAsk(reason: MayAskReason): UnattendedReadVerdict {
  return Object.freeze({ kind: "may-ask", reason });
}

/**
 * Whether reading `source` may start a provider that can ask a person. Static:
 * the binding and the registry only. A binding whose read the plan already
 * refuses before any spawn (an unknown source, a connection bound as a value,
 * a bad `via`, a legacy `file`/`cmd` entry) counts as never asking: it fails
 * on its own, with its own message.
 */
export function unattendedReadVerdict(source: TokenSource, registry: SourceRegistry | undefined): UnattendedReadVerdict {
  switch (source.source) {
    case "env":
      return NEVER_ASKS;
    case "1password":
      return source.via === undefined ? mayAsk("1password-app") : NEVER_ASKS;
    case "named": {
      const named = registry?.[source.name];
      if (!named) return NEVER_ASKS;
      if (named.type === "command") return source.via === undefined ? mayAsk("command") : NEVER_ASKS;
      if (named.type === "jwt" || named.type === "google-service-account") {
        return source.via === undefined ? mayAsk("signing-key-1password-app") : NEVER_ASKS;
      }
      return NEVER_ASKS;
    }
    default:
      return NEVER_ASKS;
  }
}

/** The names of the 1password connection sources in `registry`, sorted. */
export function connectionSourceNames(registry: SourceRegistry | undefined): string[] {
  return Object.entries(registry ?? {})
    .filter(([, entry]) => entry.type === "1password")
    .map(([name]) => name)
    .sort();
}

const OP_REF_PLACEHOLDER = "op://<vault>/<item>/<field>";
const CONNECTION_PLACEHOLDER = "<connection>";
const ENV_PLACEHOLDER = "<ENV_VAR>";

function reasonHeadline(tokenName: string, reason: MayAskReason): string {
  switch (reason) {
    case "1password-app":
      return `run refused (65): ${tokenName} uses the 1Password app, which may ask`;
    case "command":
      return `run refused (65): ${tokenName} runs a command source, which runfree cannot keep from asking`;
    case "signing-key-1password-app":
      return `run refused (65): ${tokenName} reads its signing key with the 1Password app, which may ask`;
  }
}

/**
 * The refusal for one binding that may ask: what it uses, and the exact fix.
 * The fix never repeats the binding's own `op://` reference (a service
 * account cannot read a personal vault, and references stay out of messages);
 * it prints placeholders instead.
 */
export function unattendedRefusalLines(input: Readonly<{
  tokenName: string;
  source: TokenSource;
  reason: MayAskReason;
  owner: CredentialOwner | undefined;
  connections: readonly string[];
}>): string[] {
  const { tokenName, source, reason, owner, connections } = input;
  const via = connections.length === 1 ? connections[0] : CONNECTION_PLACEHOLDER;
  const lines = [reasonHeadline(tokenName, reason)];
  if (connections.length === 0) lines.push(`  first: ${remedy.credentialSourceOnePassword(CONNECTION_PLACEHOLDER)}`);
  if (connections.length > 1) lines.push(`  connections: ${connections.join(", ")}`);
  if (owner?.kind === "mcp") {
    // An env source never asks; it is the shortest fix that works for a
    // project MCP server whatever its source was.
    lines.push(`  fix: ${remedy.mcpEnableProjectFromEnvReplace(owner.agent, owner.server, ENV_PLACEHOLDER)}`);
    return lines;
  }
  if (reason === "signing-key-1password-app" && source.source === "named") {
    lines.push(`  fix: ${owner?.kind === "service"
      ? remedy.serviceEnableNamedVia(owner.id, source.name, via)
      : remedy.credentialSetSourceNamedVia(tokenName, source.name, via)}`);
    lines.push("  the key must be in a vault the connection can read");
    return lines;
  }
  lines.push(`  fix: ${owner?.kind === "service"
    ? remedy.serviceEnableOnePasswordVia(owner.id, OP_REF_PLACEHOLDER, via)
    : remedy.credentialSetSourceOnePasswordVia(tokenName, OP_REF_PLACEHOLDER, via)}`);
  if (reason === "command") {
    lines.push(`  or: ${owner?.kind === "service"
      ? remedy.serviceEnableFromEnvReplace(owner.id, ENV_PLACEHOLDER)
      : remedy.credentialSetSourceFromEnvReplace(tokenName, ENV_PLACEHOLDER)}`);
  }
  return lines;
}

/**
 * A read refused because a run holds the rule. Transient on purpose: one
 * project shares one proxy token store with its interactive sessions, so a
 * refusal in a run must never revoke a value they hold. The run still fails
 * its sync and refuses (65).
 */
export class CredentialInteractionForbiddenError extends TokenResolutionError {
  constructor(safeMessage: string, sourceKind: TokenResolutionSourceKind) {
    super({ classification: "transient", sourceKind, code: "interaction-forbidden", safeMessage });
    this.name = "CredentialInteractionForbiddenError";
  }
}
