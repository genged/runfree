import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import {
  CREDENTIAL_SCHEMES,
  isTokenName,
  normalizeHostname,
  normalizePathPrefix,
  type CredentialPolicyJson,
} from "@runfree/runtime-contracts/network-policy";
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

function normalizeName(name: string): string {
  if (!isTokenName(name)) throw new CliError(`invalid credential name: ${name}`);
  if (name.startsWith("user-")) {
    throw new CliError(`${name} is reserved for a user-defined service; use runfree service enable <id> or runfree service disable <id>`);
  }
  return name;
}

export function desiredCredentialFromFields(fields: CredentialFieldsInput): CredentialPolicyJson {
  if (!fields.host) throw new CliError("credential commands require --host <host>");
  const host = normalizeHostname(fields.host);
  const header = fields.header ?? "Authorization";
  if (header.trim() === "") throw new CliError("--header must be non-empty");
  const scheme = fields.scheme ?? "bearer";
  if (scheme !== "bearer" && scheme !== "raw") {
    throw new CliError(`--scheme must be one of: ${CREDENTIAL_SCHEMES.join(", ")}`);
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
      const identity = credentialIdentity(mutation.credential);
      const linked = existing.credentials.find((entry) => credentialIdentity(entry) === identity);
      if (linked && linked.scheme !== mutation.credential.scheme) {
        throw new CliError(`${name} is already linked to ${mutation.credential.host} ${mutation.credential.header} with scheme ${linked.scheme}`);
      }
      if (!linked) existing.credentials.push(mutation.credential);
    }
  } else {
    const existing = policy.tokens[name];
    if (!existing) throw new CliError(`unknown project credential: ${name}`);
    if (mutation.kind === "link") {
      const identity = credentialIdentity(mutation.credential);
      for (const [otherName, token] of Object.entries(policy.tokens)) {
        const linked = token.credentials.find((entry) => credentialIdentity(entry) === identity);
        if (!linked) continue;
        if (otherName !== name) {
          throw new CliError(`${mutation.credential.host} ${mutation.credential.header} is already credentialed by token ${otherName}`);
        }
        if (linked.scheme !== mutation.credential.scheme) {
          throw new CliError(`${name} is already linked to ${mutation.credential.host} ${mutation.credential.header} with scheme ${linked.scheme}`);
        }
        return { changed: false, name, policy };
      }
      existing.credentials.push(mutation.credential);
    } else if (mutation.kind === "unlink") {
      const host = normalizeHostname(mutation.host);
      const header = mutation.header ?? "Authorization";
      if (header.trim() === "") throw new CliError("--header must be non-empty");
      const index = existing.credentials.findIndex((entry) =>
        entry.host === host && entry.header.toLowerCase() === header.toLowerCase());
      if (index < 0) throw new CliError(`${name} has no destination for ${host} ${header}`);
      existing.credentials.splice(index, 1);
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
