import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { isReservedRunfreeHostname } from "@runfree/runtime-contracts/host-services";
import {
  isTokenName,
  normalizeHostname,
  normalizePathPrefix,
  type CredentialPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
import { describeCredential } from "../admin/credential-describe.ts";
import type { CredentialFieldsInput } from "../admin/options.ts";
import { CliError } from "../errors.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import type { ControlApprovalSelection } from "./approvals.ts";
import { compileDesiredPolicies } from "./compiler.ts";
import {
  withDesiredPolicyTransaction,
  type DesiredPolicyApprovalSubject,
} from "./desired-policy-transaction.ts";

export type DesiredCredentialMutation =
  | { kind: "add"; name: string; description?: string; credential: CredentialPolicyJson }
  | { kind: "link"; name: string; credential: CredentialPolicyJson }
  | { kind: "unlink"; name: string; host: string; header?: string }
  | { kind: "remove"; name: string };

export type DesiredCredentialMutationResult = {
  changed: boolean;
  name: string;
  projectDigest: string;
  selection: ControlApprovalSelection;
};

function credentialIdentity(credential: CredentialPolicyJson): string {
  return `${credential.host}\0${credential.header.toLowerCase()}`;
}

// Desired policy v3 allows several destinations of one token on one host and
// header, set apart by protocol or path prefix. The CLI's --host/--header
// selector cannot name one of them yet, so a mutation that would have to pick
// one refuses before any policy write rather than act on the first match.
const NO_DESTINATION_SELECTOR = "the CLI cannot yet select one destination of several on the same host and header";

function sameDestination(a: CredentialPolicyJson, b: CredentialPolicyJson): boolean {
  return a.scheme === b.scheme && a.username === b.username && a.pathPrefix === b.pathPrefix && a.protocol === b.protocol;
}

function destinationList(destinations: readonly CredentialPolicyJson[]): string {
  return destinations.map(describeCredential).join("; ");
}

/**
 * Whether `credential` is already one of `name`'s destinations. A destination
 * on the same host and header that differs in scope refuses: adding beside it
 * would need a second destination on that host and header, and doing nothing
 * would report success for a scope that was never written.
 */
function destinationAlreadyLinked(name: string, linked: readonly CredentialPolicyJson[], credential: CredentialPolicyJson): boolean {
  const identity = credentialIdentity(credential);
  const matches = linked.filter((entry) => credentialIdentity(entry) === identity);
  if (matches.length === 0) return false;
  if (matches.some((entry) => sameDestination(entry, credential))) return true;
  const [only] = matches;
  if (matches.length === 1 && only && only.scheme !== credential.scheme) {
    throw new CliError(`${name} is already linked to ${credential.host} ${credential.header} with scheme ${only.scheme}`);
  }
  throw new CliError(`${name} already has a destination for ${credential.host} ${credential.header} with another scope: `
    + `${destinationList(matches)}; requested ${describeCredential(credential)}; ${NO_DESTINATION_SELECTOR}`);
}

function assertNotReservedHost(host: string): void {
  if (isReservedRunfreeHostname(host)) {
    throw new CliError(`${host} uses the reserved runfree.internal suffix`);
  }
}

function normalizeName(name: string): string {
  if (!isTokenName(name)) throw new CliError(`invalid credential name: ${name}`);
  if (name.startsWith("user-")) {
    throw new CliError(`${name} is reserved for a user-defined service; use runfree service enable <id> or runfree service disable <id>`);
  }
  return name;
}

// The CLI's own subset of the contract schemes. `basic` needs a username and
// is reachable only through service definitions, so `--scheme basic` is
// refused here before any policy write even though the contract accepts it.
const CLI_CREDENTIAL_SCHEMES = ["bearer", "raw"] as const;

function isCliCredentialScheme(value: string): value is typeof CLI_CREDENTIAL_SCHEMES[number] {
  return (CLI_CREDENTIAL_SCHEMES as readonly string[]).includes(value);
}

export function desiredCredentialFromFields(fields: CredentialFieldsInput): CredentialPolicyJson {
  if (!fields.host) throw new CliError("credential commands require --host <host>");
  const host = normalizeHostname(fields.host);
  assertNotReservedHost(host);
  const header = fields.header ?? "Authorization";
  if (header.trim() === "") throw new CliError("--header must be non-empty");
  const scheme = fields.scheme ?? "bearer";
  if (!isCliCredentialScheme(scheme)) {
    throw new CliError(`--scheme must be one of: ${CLI_CREDENTIAL_SCHEMES.join(", ")}`);
  }
  return {
    host,
    header,
    scheme,
    ...(fields.pathPrefix === undefined ? {} : { pathPrefix: normalizePathPrefix(fields.pathPrefix) }),
  };
}

// Claude Code login state is Runfree-managed agent state, not a proxy
// credential: proxy tokens are hidden from the agent process and can never
// satisfy Claude Code's login prompt, so binding one to a login host is
// always a misconfiguration. Refuse before the desired policy mutates.
const CLAUDE_CODE_LOGIN_HOSTS = new Set(["api.anthropic.com", "platform.claude.com"]);

function assertNotClaudeCodeAuthProxyCredential(name: string, host: string): void {
  if (!CLAUDE_CODE_LOGIN_HOSTS.has(host)) return;
  throw new CliError(`Claude Code login uses Runfree-managed Claude state, not proxy token ${name} for ${host}

Proxy tokens are hidden from the agent process and cannot satisfy Claude Code's login prompt.`);
}

export function reconcileDesiredCredential(
  current: DesiredNetworkPolicyJson,
  mutation: DesiredCredentialMutation,
): { changed: boolean; name: string; policy: DesiredNetworkPolicyJson } {
  const policy = structuredClone(validateDesiredNetworkPolicy(current));
  const name = normalizeName(mutation.name);
  const before = canonicalDesiredNetworkPolicy(policy);
  policy.tokens ??= {};
  if (mutation.kind === "add" || mutation.kind === "link") {
    assertNotClaudeCodeAuthProxyCredential(name, mutation.credential.host);
  }

  if (mutation.kind === "add") {
    const existing = policy.tokens[name];
    if (!existing) {
      const description = mutation.description ?? `${name} credential`;
      if (description.trim() === "") throw new CliError("--description must be non-empty");
      policy.tokens[name] = { description, credentials: [mutation.credential] };
    } else {
      if (mutation.description !== undefined && mutation.description.trim() === "") {
        throw new CliError("--description must be non-empty");
      }
      if (!destinationAlreadyLinked(name, existing.credentials, mutation.credential)) {
        existing.credentials.push(mutation.credential);
      }
    }
  } else {
    const existing = policy.tokens[name];
    if (!existing) throw new CliError(`unknown project credential: ${name}`);
    if (mutation.kind === "link") {
      const identity = credentialIdentity(mutation.credential);
      // The exact destination already linked is the unchanged no-op, whatever
      // other tokens hold on that host and header; the cross-token refusal
      // below is only for an actual addition.
      if (existing.credentials.some((entry) => credentialIdentity(entry) === identity && sameDestination(entry, mutation.credential))) {
        return { changed: false, name, policy };
      }
      for (const [otherName, token] of Object.entries(policy.tokens)) {
        const linked = token.credentials.find((entry) => credentialIdentity(entry) === identity);
        if (!linked) continue;
        if (otherName !== name) {
          throw new CliError(`${mutation.credential.host} ${mutation.credential.header} is already credentialed by token ${otherName}`);
        }
      }
      if (destinationAlreadyLinked(name, existing.credentials, mutation.credential)) {
        return { changed: false, name, policy };
      }
      existing.credentials.push(mutation.credential);
    } else if (mutation.kind === "unlink") {
      const host = normalizeHostname(mutation.host);
      assertNotReservedHost(host);
      const header = mutation.header ?? "Authorization";
      if (header.trim() === "") throw new CliError("--header must be non-empty");
      const matches = existing.credentials.filter((entry) =>
        entry.host === host && entry.header.toLowerCase() === header.toLowerCase());
      if (matches.length === 0) throw new CliError(`${name} has no destination for ${host} ${header}`);
      if (matches.length > 1) {
        throw new CliError(`${name} has ${matches.length} destinations for ${host} ${header}: ${destinationList(matches)}; `
          + `${NO_DESTINATION_SELECTOR}, so none was unlinked`);
      }
      existing.credentials.splice(existing.credentials.indexOf(matches[0] as CredentialPolicyJson), 1);
    } else {
      delete policy.tokens[name];
    }
  }

  if (Object.keys(policy.tokens).length === 0) delete policy.tokens;
  const validated = validateDesiredNetworkPolicy(policy);
  return {
    changed: canonicalDesiredNetworkPolicy(validated) !== before,
    name,
    policy: validated,
  };
}

// Credentials live only in the project layer, and both refusals name it.
const CREDENTIAL_APPROVAL_SUBJECT: DesiredPolicyApprovalSubject = {
  layer: "project",
  missingBaseSubject: "project desired policy",
  driftSubject: "project desired policy",
};

export async function mutateDesiredCredential(
  context: RuntimeContext,
  io: RuntimeIO,
  mutation: DesiredCredentialMutation,
): Promise<DesiredCredentialMutationResult> {
  return withDesiredPolicyTransaction(context, io, {
    approvalSubject: CREDENTIAL_APPROVAL_SUBJECT,
    writeSubject: "desired credential write",
    transactionNoun: "credential",
    plan: (before) => {
      if ((mutation.kind === "add" || mutation.kind === "link")
        && !before.project.hosts.includes(mutation.credential.host)) {
        throw new CliError(
          `${mutation.credential.host} is not directly allowlisted in project desired policy; add it with: runfree host add ${mutation.credential.host}`,
        );
      }
      const planned = reconcileDesiredCredential(before.project, mutation);
      const compiled = compileDesiredPolicies({ project: planned.policy, local: before.local });
      if (mutation.kind === "add" || mutation.kind === "link") {
        const credential = mutation.credential;
        if (!compiled.policy.hosts.includes(credential.host)) {
          throw new Error(`${credential.host} is not allowlisted in approved desired controls`);
        }
      }
      return planned;
    },
    result: ({ candidate, plan, selection }) => ({
      changed: plan.changed,
      name: plan.name,
      projectDigest: candidate.projectSubject.digest,
      selection,
    }),
  });
}
