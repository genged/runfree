// Inputs for the gated git provider tranche (`git-https-provider.live.test.ts`).
//
// The tranche runs real git against a real provider, so it needs a dedicated
// private repository and a least-privilege token. It is opt-in: with
// `TEST_RUNTIME_GIT_PROVIDERS` unset it skips and says why. Once the gate names
// a provider, every required input for that provider must be present and
// well-formed, and a missing one fails the run rather than skipping it — a
// recorded "green" provider run that silently skipped a provider would prove
// nothing.
//
// The token is never read from the developer's ambient environment (no
// GH_TOKEN, GITLAB_TOKEN or `gh auth` fallback). The tranche names an existing
// host-side Runfree credential source, copies only that source's command
// definition into the fixture's isolated registry, and binds the provider's
// service token to it, so the value is resolved by the product's own source
// path exactly as a user's would be.
//
// Data and validation only, with no Docker or vitest import, so the unit test
// can prove the gate without a daemon.

import fs from "node:fs";
import path from "node:path";

import { runfreeConfigRoot } from "../../../packages/cli/src/paths.ts";
import { TOKEN_NAME_PATTERN } from "../../../packages/runtime-contracts/src/network-policy.ts";

export const GIT_PROVIDERS_ENV = "TEST_RUNTIME_GIT_PROVIDERS";

export const GIT_PROVIDER_IDS = ["github", "gitlab"] as const;
export type GitProviderId = typeof GIT_PROVIDER_IDS[number];

type ProviderDefinition = Readonly<{
  id: GitProviderId;
  /** The git host, and the service host the git-http credential is bound to. */
  host: string;
  /** The built-in service id, and the name of its token. */
  service: string;
  tokenName: string;
  /** Prefix of the per-provider env inputs, e.g. `TEST_RUNTIME_GITHUB`. */
  envPrefix: string;
  /** Extra `service enable` flags: skip broad multi-tenant hosts the tranche never needs. */
  enableFlags: readonly string[];
  /**
   * Whether the service mediates Git LFS on the host (it has a `git-lfs`
   * mapping). gitlab does not: its batch response hands back a project-wide
   * LFS token, so an LFS batch there is a held write with no credential.
   */
  lfsMediated: boolean;
}>;

const PROVIDERS: Readonly<Record<GitProviderId, ProviderDefinition>> = Object.freeze({
  github: {
    id: "github",
    host: "github.com",
    service: "github",
    tokenName: "github",
    envPrefix: "TEST_RUNTIME_GITHUB",
    enableFlags: ["--skip-broad"],
    lfsMediated: true,
  },
  gitlab: {
    id: "gitlab",
    host: "gitlab.com",
    service: "gitlab",
    tokenName: "gitlab",
    envPrefix: "TEST_RUNTIME_GITLAB",
    enableFlags: [],
    lfsMediated: false,
  },
});

/** A validated repository on a provider host, in the forms the tranche uses. */
export type GitProviderRepository = Readonly<{
  /** `https://<host>/<path>.git`: what the sandbox rewrite must produce. */
  httpsUrl: string;
  /** `git@<host>:<path>.git`: the SSH form put in the workspace remote. */
  sshUrl: string;
  /** `<path>.git`, with no leading slash. */
  path: string;
}>;

export type GitProviderInputs = Readonly<{
  id: GitProviderId;
  host: string;
  service: string;
  tokenName: string;
  enableFlags: readonly string[];
  lfsMediated: boolean;
  /** Env names, for failure messages that tell the operator what to set. */
  envNames: Readonly<{ repo: string; source: string; lfsRepo: string }>;
  repository: GitProviderRepository;
  /** Name of the existing host-side credential source holding the token. */
  source: string;
  /** Optional LFS-enabled repository; L5 skips with a reason when absent. */
  lfsRepository?: GitProviderRepository;
}>;

export type GitProviderSuiteConfig =
  | Readonly<{ kind: "skip"; reason: string }>
  | Readonly<{ kind: "run"; providers: readonly GitProviderInputs[] }>;

const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/u;

/** Parses the gate and per-provider inputs. Throws on any misconfiguration. */
export function gitProviderSuiteConfig(env: NodeJS.ProcessEnv): GitProviderSuiteConfig {
  const gate = env[GIT_PROVIDERS_ENV];
  if (gate === undefined || gate.trim() === "") {
    return Object.freeze({
      kind: "skip",
      reason: `${GIT_PROVIDERS_ENV} is unset; set it to github, gitlab or github,gitlab with the per-provider inputs to run`,
    });
  }
  const requested = gate.split(",").map((value) => value.trim());
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const id of requested) {
    if (!(GIT_PROVIDER_IDS as readonly string[]).includes(id)) {
      problems.push(`${GIT_PROVIDERS_ENV} names unknown provider ${JSON.stringify(id)} (known: ${GIT_PROVIDER_IDS.join(", ")})`);
    } else if (seen.has(id)) {
      problems.push(`${GIT_PROVIDERS_ENV} names ${id} more than once`);
    }
    seen.add(id);
  }
  if (problems.length > 0) throw new Error(problems.join("; "));

  const providers: GitProviderInputs[] = [];
  for (const id of requested as GitProviderId[]) {
    const definition = PROVIDERS[id];
    const envNames = Object.freeze({
      repo: `${definition.envPrefix}_REPO`,
      source: `${definition.envPrefix}_SOURCE`,
      lfsRepo: `${definition.envPrefix}_LFS_REPO`,
    });
    const repoValue = env[envNames.repo];
    const sourceValue = env[envNames.source];
    const lfsValue = env[envNames.lfsRepo];
    let repository: GitProviderRepository | undefined;
    let lfsRepository: GitProviderRepository | undefined;
    if (repoValue === undefined || repoValue.trim() === "") {
      problems.push(`${GIT_PROVIDERS_ENV} names ${id} but ${envNames.repo} is unset`);
    } else {
      try { repository = parseProviderRepository(definition.host, repoValue); } catch (error) {
        problems.push(`${envNames.repo}: ${(error as Error).message}`);
      }
    }
    if (sourceValue === undefined || sourceValue.trim() === "") {
      problems.push(`${GIT_PROVIDERS_ENV} names ${id} but ${envNames.source} is unset`);
    } else if (!TOKEN_NAME_PATTERN.test(sourceValue)) {
      problems.push(`${envNames.source}: ${JSON.stringify(sourceValue)} is not a credential source name`);
    }
    if (lfsValue !== undefined && lfsValue.trim() !== "") {
      try { lfsRepository = parseProviderRepository(definition.host, lfsValue); } catch (error) {
        problems.push(`${envNames.lfsRepo}: ${(error as Error).message}`);
      }
    }
    if (repository && sourceValue && TOKEN_NAME_PATTERN.test(sourceValue)) {
      providers.push(Object.freeze({
        id,
        host: definition.host,
        service: definition.service,
        tokenName: definition.tokenName,
        enableFlags: definition.enableFlags,
        lfsMediated: definition.lfsMediated,
        envNames,
        repository,
        source: sourceValue,
        ...(lfsRepository ? { lfsRepository } : {}),
      }));
    }
  }
  if (problems.length > 0) throw new Error(problems.join("; "));
  return Object.freeze({ kind: "run", providers: Object.freeze(providers) });
}

/**
 * Accepts only `https://<host>/<segment>/<segment>[/...][.git]` with no
 * credentials, port, query or fragment. A token in the URL would bypass the
 * proxy-managed credential the tranche exists to prove.
 */
export function parseProviderRepository(host: string, value: string): GitProviderRepository {
  let url: URL;
  try { url = new URL(value.trim()); } catch { throw new Error(`${JSON.stringify(value)} is not a URL`); }
  if (url.protocol !== "https:") throw new Error(`${JSON.stringify(value)} must be an https:// URL`);
  if (url.hostname !== host) throw new Error(`${JSON.stringify(value)} must be on ${host}`);
  if (url.username || url.password) throw new Error("the repository URL must not carry credentials");
  if (url.port) throw new Error("the repository URL must not name a port");
  if (url.search || url.hash) throw new Error("the repository URL must not carry a query or fragment");
  const segments = url.pathname.replace(/\/+$/u, "").replace(/\.git$/u, "").split("/").slice(1);
  if (segments.length < 2 || !segments.every((segment) => SEGMENT.test(segment) && segment !== "..")) {
    throw new Error(`${JSON.stringify(value)} must name <owner>/<repository>`);
  }
  const repoPath = `${segments.join("/")}.git`;
  return Object.freeze({
    httpsUrl: `https://${host}/${repoPath}`,
    sshUrl: `git@${host}:${repoPath}`,
    path: repoPath,
  });
}

/**
 * The argv of an existing command source in the operator's own host registry
 * (`$XDG_CONFIG_HOME/runfree/sources.json`). Only the definition is read; the
 * token is resolved later by the fixture's CLI through that source. A JWT
 * source is refused: a git token is a plain value.
 */
export function hostCommandSourceArgv(name: string, env: NodeJS.ProcessEnv): readonly string[] {
  const registryPath = path.join(runfreeConfigRoot(env), "sources.json");
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(registryPath, "utf8"));
  } catch (error) {
    throw new Error(`could not read the host credential source registry ${registryPath}: ${(error as Error).message}`);
  }
  const entry = raw !== null && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Record<string, unknown>)[name]
    : undefined;
  if (entry === undefined) {
    throw new Error(`no credential source named ${name} in ${registryPath}; add it with runfree credential source add ${name} -- <command>`);
  }
  const record = entry as { type?: unknown; argv?: unknown };
  if (record.type !== "command") throw new Error(`credential source ${name} is not a command source`);
  if (!Array.isArray(record.argv) || record.argv.length === 0 || !record.argv.every((item) => typeof item === "string")) {
    throw new Error(`credential source ${name} has no command argv`);
  }
  return Object.freeze([...record.argv as string[]]);
}
