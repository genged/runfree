// services.ts — curated, versioned "services": named bundles of exact hostnames
// that a project may allowlist, each OPTIONALLY carrying a credential.
//
// This is the single source of truth behind `runfree service ...`. A service is
// a named host bundle (ecosystem registries, provider APIs, …) that models any
// credential as an optional `credential` block; the only difference between a
// "hosts only" and a "hosts + credential" service is whether that block is set.
//
// Services are trusted CLI definitions. Enabling one writes a complete pinned
// entry to desired network-policy v2: definition digest, revision, selection,
// and resolved host/request/token/OAuth semantics. The host compiler later
// emits the narrow effective proxy policy; runfree.json carries no service
// authority.
//
// Maintenance rules, enforced by scripts/services.test.ts:
// - every host is exact and equals its normalizeHostname form (no wildcards);
// - `revision` must be bumped whenever `hosts` (or `removedHosts`) changes;
// - hosts dropped from a service move to `removedHosts` so `service diff` can
//   propose their removal from project policies;
// - every `broad` (multi-tenant infrastructure) host carries an explanation
//   used for the exfiltration-surface warning;
// - a credential's `credentials[]` hosts must be a subset of the service hosts.

import {
  normalizeHostname,
  normalizePathPrefix,
  validateNetworkPolicy,
  type CredentialPolicyJson,
  type RequestPolicyJson,
} from "@runfree/runtime-contracts/network-policy";

export const RUNFREE_PLACEHOLDER_VALUE = "runfree-placeholder-overwritten-by-proxy";
export const USER_SERVICE_PREFIX = "user-";
export const USER_SERVICE_ID_PATTERN = /^user-[a-z0-9][a-z0-9-]*$/;
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SERVICE_MIGRATION_REQUEST_FIELDS = new Set(["readPathPrefixes", "writePathPrefixes", "gitPush", "graphql"]);

export function isUserServiceId(id: string): boolean {
  return USER_SERVICE_ID_PATTERN.test(id);
}

export function serviceOriginLabel(id: string): string {
  return isUserServiceId(id) ? "user-defined" : "curated";
}

export type ServiceHost = {
  host: string;
  // Broad multi-tenant infrastructure: arbitrary tenants can receive data
  // through this host, making it a documented exfiltration channel.
  broad?: true;
  // Required for broad hosts: the user-facing warning text appended after
  // "note: <host> ".
  explanation?: string;
};

export type DetectRule =
  | { kind: "file"; path: string }
  | { kind: "gitRemoteHost"; host: string };

// Optional credential carried by a service. When present, `service enable`
// links these credentials into proxy token policy and writes placeholder agent
// env names; the real token value is resolved host-side and injected only by
// the proxy. Credential-less services (package registries, APT, etc.) omit it.
export type ServiceCredential = {
  tokenName: string;
  tokenDescription: string;
  // When true, the proxy strips configured inbound credential headers and
  // forwards without injection if no live token is available.
  allowAnonymous?: boolean;
  // Env var names the agent's tools expect; projected into host-owned effective agent env.
  // as inert placeholders only.
  agentEnv: string[];
  // Credential mappings; each `host` must be one of the service's `hosts`.
  credentials: CredentialPolicyJson[];
};

// Maintainer-authored read-only/operation profile, keyed by exact service
// host. `service enable <id> --read-only` (and the write classifier under an
// ask/deny posture generally) expands these per-host refinements into the
// project policy's `requests` section at CLI time; the regular user authors
// nothing. Hosts without an entry still get the tri-state writeAction — they
// just fall back to the generic method-based classifier.
export type ServiceReadOnlyHostProfile = {
  // Non-safe-method endpoints that are actually reads (search, batch-get, RPC
  // reads over POST), so a POST read does not falsely deny/prompt (MED-6).
  readPathPrefixes?: string[];
  // Paths that classify as writes regardless of method.
  writePathPrefixes?: string[];
  // Declares the host as a git-over-HTTPS host: pushes classify as writes and
  // upload-pack fetch negotiation classifies as a read.
  gitPush?: "write";
  // GraphQL endpoints classified by operation type (query => read,
  // mutation/anything-unprovable => write).
  graphql?: { endpoints: string[] };
};

export type ServicePolicyMigration = {
  fromRevision: number;
  toRevision: number;
  requestRuleReplacements?: Array<{
    host: string;
    field: keyof ServiceReadOnlyHostProfile;
    from: unknown;
    to: unknown;
  }>;
  credentialLinksToRemove?: CredentialPolicyJson[];
  agentEnvToRemove?: string[];
};

export type ServiceOAuthSeedField = "refresh_token" | "client_secret";

export type ServiceOAuthCredential = {
  tokenEndpoint: string;
  resourceHost: string;
  resourcePathPrefix?: string;
  seeds: Array<{
    field: ServiceOAuthSeedField;
    envVar: string;
    tokenName: string;
    description: string;
  }>;
};

export const SERVICE_PARAMETER_KEY_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;
export const OAUTH_FIELD_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

// A declared, non-secret input a service needs beside its secrets (an OAuth
// client id, a team or account id, a region). The value is projected into the
// agent env under `envVar` and is never a credential: anything that must stay
// out of the agent container belongs in `credential` or `oauthCredential.seeds`.
// `service enable` resolves every parameter (--param, 1Password item field,
// host env var, the recorded value, a TTY prompt) and refuses before any write
// when one is missing.
export type ServiceParameter = {
  // Stable id used by `--param <key>=<value>`, prompts, and explain output.
  key: string;
  envVar: string;
  description: string;
  // Set when the value is a field of the OAuth token request (client_id).
  oauthField?: string;
  // Optional anchored regex the supplied value must match.
  pattern?: string;
  example?: string;
};

export function serviceParameters(svc: Pick<Service, "parameters">): ServiceParameter[] {
  return svc.parameters ?? [];
}

export type Service = {
  id: string;
  label: string;
  revision: number;
  hosts: ServiceHost[];
  // Hosts shipped by an earlier revision and removed since; `service diff`
  // proposes removing them from project policies.
  removedHosts?: string[];
  detect: DetectRule[];
  explanations: string[];
  // Never offered by init detection, denial feedback, or audit reports;
  // enable explicitly when a project image installs packages at runtime.
  neverAutoSuggest?: true;
  // Functional default used when service enable does not receive an explicit
  // --read-only/--allow-write selection.
  defaultWriteMode?: "allow-write" | "read-only";
  credential?: ServiceCredential;
  oauthCredential?: ServiceOAuthCredential;
  parameters?: ServiceParameter[];
  // Optional per-host read-only profile refinements; see
  // ServiceReadOnlyHostProfile. Keys must be exact service hosts.
  readOnly?: Record<string, ServiceReadOnlyHostProfile>;
  // Exact trusted legacy values that reconciliation may adopt. Project
  // records are descriptive only and cannot expand these removal bounds.
  migrations?: ServicePolicyMigration[];
};

const SKIP_BROAD_HINT = "skip it with --skip-broad if you do not need";

export const SERVICES: Record<string, Service> = {
  "agent-claude": {
    id: "agent-claude",
    label: "Anthropic model provider access",
    revision: 1,
    hosts: [
      { host: "api.anthropic.com" },
      { host: "platform.claude.com" },
    ],
    detect: [],
    explanations: [
      "Anthropic account login and model traffic for supported agents using project-scoped agent state",
      "credential: none; this service does not configure Anthropic API-key injection",
    ],
    neverAutoSuggest: true,
    defaultWriteMode: "allow-write",
  },
  "agent-codex": {
    id: "agent-codex",
    label: "OpenAI model provider access",
    revision: 1,
    hosts: [
      { host: "api.openai.com" },
      { host: "auth.openai.com" },
      { host: "chatgpt.com" },
    ],
    detect: [],
    explanations: [
      "OpenAI account login and model traffic for supported agents using project-scoped agent state",
      "credential: none; this service does not configure OpenAI API-key injection",
    ],
    neverAutoSuggest: true,
    defaultWriteMode: "allow-write",
  },
  node: {
    id: "node",
    label: "Node.js package registries",
    revision: 2,
    hosts: [
      { host: "registry.npmjs.org" },
      { host: "registry.yarnpkg.com" },
    ],
    detect: [
      { kind: "file", path: "package.json" },
      { kind: "file", path: "pnpm-lock.yaml" },
      { kind: "file", path: "package-lock.json" },
      { kind: "file", path: "yarn.lock" },
      { kind: "file", path: "bun.lock" },
      { kind: "file", path: "bun.lockb" },
    ],
    explanations: [
      "npm registry: package metadata and tarballs (npm, pnpm, bun)",
      "yarn registry: registry.yarnpkg.com mirrors registry.npmjs.org for yarn classic",
    ],
    readOnly: {
      "registry.npmjs.org": {
        readPathPrefixes: ["/-/npm/v1/security/advisories/bulk"],
      },
    },
    migrations: [
      {
        fromRevision: 1,
        toRevision: 2,
        requestRuleReplacements: [
          {
            host: "registry.npmjs.org",
            field: "readPathPrefixes",
            from: ["/-/npm/v1/security/"],
            to: ["/-/npm/v1/security/advisories/bulk"],
          },
        ],
      },
    ],
  },
  python: {
    id: "python",
    label: "Python Package Index",
    revision: 1,
    hosts: [
      { host: "pypi.org" },
      { host: "files.pythonhosted.org" },
    ],
    detect: [
      { kind: "file", path: "pyproject.toml" },
      { kind: "file", path: "uv.lock" },
      { kind: "file", path: "poetry.lock" },
      { kind: "file", path: "requirements.txt" },
    ],
    explanations: [
      "PyPI simple API: public HTTPS access",
      "Python package files: public HTTPS access",
      "Private indexes require exact-host allowlisting plus proxy token policy; do not put real index credentials in agent env",
    ],
  },
  rust: {
    id: "rust",
    label: "Rust crates and toolchain",
    revision: 1,
    hosts: [
      { host: "crates.io" },
      { host: "static.crates.io" },
      { host: "index.crates.io" },
      { host: "static.rust-lang.org" },
    ],
    detect: [
      { kind: "file", path: "Cargo.toml" },
      { kind: "file", path: "Cargo.lock" },
    ],
    explanations: [
      "crates.io API and sparse index: index.crates.io",
      "crate downloads: static.crates.io",
      "rustup toolchain components: static.rust-lang.org",
    ],
  },
  go: {
    id: "go",
    label: "Go module mirror",
    revision: 1,
    hosts: [
      { host: "proxy.golang.org" },
      { host: "sum.golang.org" },
      {
        host: "storage.googleapis.com",
        broad: true,
        explanation: "is shared Google Cloud Storage serving buckets for arbitrary tenants. "
          + "Allowing it permits fetching from — and posting to — locations any Google Cloud customer controls. "
          + `The Go module mirror serves some module zips from it; ${SKIP_BROAD_HINT} them.`,
      },
    ],
    detect: [
      { kind: "file", path: "go.mod" },
      { kind: "file", path: "go.sum" },
    ],
    explanations: [
      "Go module mirror: proxy.golang.org",
      "Go checksum database: sum.golang.org",
      "module zip storage: storage.googleapis.com (broad multi-tenant host)",
    ],
  },
  ruby: {
    id: "ruby",
    label: "Ruby gems (RubyGems)",
    revision: 1,
    hosts: [
      { host: "rubygems.org" },
      { host: "index.rubygems.org" },
    ],
    detect: [
      { kind: "file", path: "Gemfile" },
      { kind: "file", path: "Gemfile.lock" },
    ],
    explanations: [
      "RubyGems API and gem downloads: rubygems.org",
      "compact index (Bundler dependency resolution): index.rubygems.org",
    ],
  },
  java: {
    id: "java",
    label: "Java/JVM artifacts (Maven Central + Gradle)",
    revision: 1,
    hosts: [
      { host: "repo1.maven.org" },
      { host: "repo.maven.apache.org" },
      { host: "plugins.gradle.org" },
      { host: "plugins-artifacts.gradle.org" },
      { host: "services.gradle.org" },
    ],
    detect: [
      { kind: "file", path: "pom.xml" },
      { kind: "file", path: "build.gradle" },
      { kind: "file", path: "build.gradle.kts" },
      { kind: "file", path: "settings.gradle" },
      { kind: "file", path: "settings.gradle.kts" },
    ],
    explanations: [
      "Maven Central artifacts: repo1.maven.org and repo.maven.apache.org",
      "Gradle Plugin Portal and its artifact host: plugins.gradle.org, plugins-artifacts.gradle.org",
      "Gradle distributions and version metadata: services.gradle.org",
    ],
  },
  dotnet: {
    id: "dotnet",
    label: ".NET packages (NuGet)",
    revision: 1,
    hosts: [
      { host: "api.nuget.org" },
      { host: "www.nuget.org" },
    ],
    detect: [
      { kind: "file", path: "nuget.config" },
      { kind: "file", path: "packages.config" },
      { kind: "file", path: "global.json" },
    ],
    explanations: [
      "NuGet service index, search, and the flat-container package CDN: api.nuget.org",
      "NuGet gallery web endpoints: www.nuget.org",
    ],
  },
  php: {
    id: "php",
    label: "PHP packages (Composer/Packagist)",
    revision: 1,
    hosts: [
      { host: "packagist.org" },
      { host: "repo.packagist.org" },
    ],
    detect: [
      { kind: "file", path: "composer.json" },
      { kind: "file", path: "composer.lock" },
    ],
    explanations: [
      "Packagist package metadata (Composer 2): packagist.org, repo.packagist.org",
      "package dist zips are served from GitHub (codeload.github.com); enable the github service to fetch them",
    ],
  },
  dart: {
    id: "dart",
    label: "Dart/Flutter packages (pub.dev)",
    revision: 1,
    hosts: [
      { host: "pub.dev" },
      {
        host: "storage.googleapis.com",
        broad: true,
        explanation: "is shared Google Cloud Storage serving buckets for arbitrary tenants. "
          + "Allowing it permits fetching from — and posting to — locations any Google Cloud customer controls. "
          + `pub.dev serves package archives from it; ${SKIP_BROAD_HINT} them.`,
      },
    ],
    detect: [
      { kind: "file", path: "pubspec.yaml" },
      { kind: "file", path: "pubspec.lock" },
    ],
    explanations: [
      "pub.dev package metadata and API: pub.dev",
      "package archive downloads: storage.googleapis.com (broad multi-tenant host)",
    ],
  },
  conda: {
    id: "conda",
    label: "Conda packages (Anaconda)",
    revision: 1,
    hosts: [
      {
        host: "conda.anaconda.org",
        broad: true,
        explanation: "is the multi-tenant Anaconda.org channel host: any user or organization can publish "
          + "a channel at conda.anaconda.org/<channel>. Allowing it permits fetching from — and posting to — "
          + `channels any Anaconda.org user controls. conda resolves community channels through it; ${SKIP_BROAD_HINT} them.`,
      },
      { host: "repo.anaconda.com" },
    ],
    detect: [
      { kind: "file", path: "environment.yml" },
      { kind: "file", path: "environment.yaml" },
    ],
    explanations: [
      "community channels (conda-forge, bioconda, …): conda.anaconda.org (broad multi-tenant host)",
      "Anaconda default channels (pkgs/main, pkgs/r): repo.anaconda.com",
    ],
  },
  terraform: {
    id: "terraform",
    label: "Terraform registry and HashiCorp releases",
    revision: 1,
    hosts: [
      { host: "registry.terraform.io" },
      { host: "releases.hashicorp.com" },
    ],
    detect: [
      { kind: "file", path: ".terraform.lock.hcl" },
    ],
    explanations: [
      "provider and module discovery/metadata: registry.terraform.io",
      "HashiCorp-distributed tool and provider binaries: releases.hashicorp.com",
      "some providers are served from GitHub release assets; enable the github service if a provider download is denied",
    ],
  },
  homebrew: {
    id: "homebrew",
    label: "Homebrew (formulae + bottles)",
    revision: 1,
    hosts: [
      { host: "formulae.brew.sh" },
      {
        host: "ghcr.io",
        broad: true,
        explanation: "is the GitHub Container Registry, a multi-tenant store hosting packages for arbitrary GitHub orgs. "
          + "Allowing it permits pulling from — and pushing to — packages any GitHub user controls. "
          + `Homebrew serves bottle archives from it; ${SKIP_BROAD_HINT} them.`,
      },
    ],
    detect: [
      { kind: "file", path: "Brewfile" },
    ],
    explanations: [
      "formula metadata JSON API: formulae.brew.sh",
      "bottle (prebuilt binary) downloads: ghcr.io (broad multi-tenant host)",
    ],
  },
  github: {
    id: "github",
    label: "GitHub",
    revision: 2,
    hosts: [
      { host: "github.com" },
      { host: "api.github.com" },
      { host: "codeload.github.com" },
      { host: "raw.githubusercontent.com" },
      {
        host: "objects.githubusercontent.com",
        broad: true,
        explanation: "serves release assets and user content for all GitHub users. "
          + "Allowing it permits fetching from — and posting to — locations any GitHub user controls. "
          + `It is required for release-asset downloads; ${SKIP_BROAD_HINT} them.`,
      },
      { host: "avatars.githubusercontent.com" },
    ],
    detect: [
      { kind: "gitRemoteHost", host: "github.com" },
    ],
    explanations: [
      "git over HTTPS and web UI: github.com",
      "REST/GraphQL API: api.github.com",
      "tarball/zipball downloads: codeload.github.com",
      "raw file content: raw.githubusercontent.com",
      "release assets and LFS objects: objects.githubusercontent.com (broad multi-tenant host)",
      "avatar images: avatars.githubusercontent.com",
    ],
    credential: {
      tokenName: "github",
      tokenDescription: "GitHub API token for API and raw content requests",
      allowAnonymous: true,
      agentEnv: ["GH_TOKEN", "GITHUB_TOKEN"],
      credentials: [
        { host: "api.github.com", header: "Authorization", scheme: "bearer" },
        { host: "raw.githubusercontent.com", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      // git fetch/clone negotiation stays a read; pushes classify as writes.
      "github.com": { gitPush: "write" },
      "api.github.com": { graphql: { endpoints: ["/graphql"] } },
    },
  },
  gitlab: {
    id: "gitlab",
    label: "GitLab",
    revision: 1,
    hosts: [
      { host: "gitlab.com" },
    ],
    detect: [
      { kind: "gitRemoteHost", host: "gitlab.com" },
      { kind: "file", path: ".gitlab-ci.yml" },
    ],
    explanations: [
      "git over HTTPS, web UI, REST/GraphQL API, and package registries: gitlab.com (API under /api/)",
      "the GitLab Container Registry (registry.gitlab.com) is a separate broad host; allow it explicitly if you push or pull images",
      "the credential is injected as Authorization: Bearer only on /api/ requests, so it never clobbers git-over-HTTPS auth on gitlab.com",
    ],
    credential: {
      tokenName: "gitlab",
      tokenDescription: "GitLab access token for API and registry requests",
      agentEnv: ["GITLAB_TOKEN", "GL_TOKEN"],
      credentials: [
        { host: "gitlab.com", header: "Authorization", scheme: "bearer", pathPrefix: "/api/" },
      ],
    },
    readOnly: {
      "gitlab.com": { gitPush: "write", graphql: { endpoints: ["/api/graphql"] } },
    },
  },
  bitbucket: {
    id: "bitbucket",
    label: "Bitbucket",
    revision: 1,
    hosts: [
      { host: "bitbucket.org" },
      { host: "api.bitbucket.org" },
    ],
    detect: [
      { kind: "gitRemoteHost", host: "bitbucket.org" },
      { kind: "file", path: "bitbucket-pipelines.yml" },
    ],
    explanations: [
      "git over HTTPS and web UI: bitbucket.org",
      "REST API v2.0: api.bitbucket.org (credential injected as Authorization: Bearer)",
    ],
    credential: {
      tokenName: "bitbucket",
      tokenDescription: "Bitbucket access token for API requests",
      agentEnv: ["BITBUCKET_TOKEN"],
      credentials: [
        { host: "api.bitbucket.org", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "bitbucket.org": { gitPush: "write" },
    },
  },
  "docker-registry": {
    id: "docker-registry",
    label: "Docker Hub registry",
    revision: 1,
    hosts: [
      { host: "registry-1.docker.io" },
      { host: "auth.docker.io" },
      { host: "index.docker.io" },
      {
        host: "production.cloudflare.docker.com",
        broad: true,
        explanation: "is shared CDN infrastructure serving Docker Hub image layers. "
          + "Allowing it permits fetching content staged by any Docker Hub publisher; "
          + `${SKIP_BROAD_HINT} layer downloads through it.`,
      },
    ],
    detect: [
      { kind: "file", path: "Dockerfile" },
      { kind: "file", path: "compose.yaml" },
      { kind: "file", path: "docker-compose.yml" },
    ],
    explanations: [
      "image manifests and blobs: registry-1.docker.io",
      "registry auth tokens: auth.docker.io",
      "legacy registry endpoint: index.docker.io",
      "layer download CDN: production.cloudflare.docker.com (broad multi-tenant host)",
    ],
  },
  "ubuntu-apt": {
    id: "ubuntu-apt",
    label: "Ubuntu APT archives",
    revision: 1,
    hosts: [
      { host: "archive.ubuntu.com" },
      { host: "security.ubuntu.com" },
      { host: "ports.ubuntu.com" },
    ],
    detect: [],
    explanations: [
      "main package archive: archive.ubuntu.com",
      "security updates: security.ubuntu.com",
      "non-amd64 architectures: ports.ubuntu.com",
      "only needed when a project image installs packages at runtime; never auto-suggested",
    ],
    neverAutoSuggest: true,
  },
  "debian-apt": {
    id: "debian-apt",
    label: "Debian APT archives",
    revision: 1,
    hosts: [
      { host: "deb.debian.org" },
      { host: "security.debian.org" },
    ],
    detect: [],
    explanations: [
      "main package archive (Fastly-fronted): deb.debian.org",
      "security updates: security.debian.org",
      "only needed when a project image installs packages at runtime; never auto-suggested",
    ],
    neverAutoSuggest: true,
  },
  "alpine-apk": {
    id: "alpine-apk",
    label: "Alpine apk packages",
    revision: 1,
    hosts: [
      { host: "dl-cdn.alpinelinux.org" },
    ],
    detect: [],
    explanations: [
      "Alpine package index and apk archives: dl-cdn.alpinelinux.org",
      "only needed when a project image installs packages at runtime; never auto-suggested",
    ],
    neverAutoSuggest: true,
  },
  anthropic: {
    id: "anthropic",
    label: "Anthropic",
    revision: 1,
    hosts: [
      { host: "api.anthropic.com" },
    ],
    detect: [],
    explanations: [
      "Anthropic API: x-api-key (raw)",
    ],
    credential: {
      tokenName: "anthropic",
      tokenDescription: "Anthropic API key for API requests",
      agentEnv: ["ANTHROPIC_API_KEY"],
      credentials: [
        { host: "api.anthropic.com", header: "x-api-key", scheme: "raw" },
      ],
    },
    readOnly: {
      // Model inference over POST is a read for read-only purposes: it
      // mutates no Anthropic account state.
      "api.anthropic.com": { readPathPrefixes: ["/v1/messages", "/v1/models"] },
    },
  },
  gemini: {
    id: "gemini",
    label: "Gemini",
    revision: 1,
    hosts: [
      { host: "generativelanguage.googleapis.com" },
    ],
    detect: [],
    explanations: [
      "native Gemini API: x-goog-api-key (raw)",
      "OpenAI-compatible Gemini API: Authorization (bearer), path /v1beta/openai/",
    ],
    credential: {
      tokenName: "gemini",
      tokenDescription: "Gemini API key for native and OpenAI-compatible endpoints",
      agentEnv: ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
      credentials: [
        {
          host: "generativelanguage.googleapis.com",
          header: "Authorization",
          scheme: "bearer",
          pathPrefix: "/v1beta/openai/",
        },
        {
          host: "generativelanguage.googleapis.com",
          header: "x-goog-api-key",
          scheme: "raw",
        },
      ],
    },
    readOnly: {
      "generativelanguage.googleapis.com": { readPathPrefixes: ["/v1beta/models", "/v1beta/openai/chat/completions"] },
    },
  },
  openai: {
    id: "openai",
    label: "OpenAI",
    revision: 1,
    hosts: [
      { host: "api.openai.com" },
    ],
    detect: [],
    explanations: [
      "OpenAI API: Authorization (bearer)",
    ],
    credential: {
      tokenName: "openai",
      tokenDescription: "OpenAI API key for API requests",
      agentEnv: ["OPENAI_API_KEY"],
      credentials: [
        { host: "api.openai.com", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "api.openai.com": { readPathPrefixes: ["/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/v1/models"] },
    },
  },
  mistral: {
    id: "mistral",
    label: "Mistral AI",
    revision: 1,
    hosts: [
      { host: "api.mistral.ai" },
    ],
    detect: [],
    explanations: [
      "Mistral API: Authorization (bearer)",
    ],
    credential: {
      tokenName: "mistral",
      tokenDescription: "Mistral API key for API requests",
      agentEnv: ["MISTRAL_API_KEY"],
      credentials: [
        { host: "api.mistral.ai", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "api.mistral.ai": { readPathPrefixes: ["/v1/chat/completions", "/v1/embeddings", "/v1/models"] },
    },
  },
  groq: {
    id: "groq",
    label: "Groq",
    revision: 1,
    hosts: [
      { host: "api.groq.com" },
    ],
    detect: [],
    explanations: [
      "Groq OpenAI-compatible API: Authorization (bearer), path /openai/v1",
    ],
    credential: {
      tokenName: "groq",
      tokenDescription: "Groq API key for API requests",
      agentEnv: ["GROQ_API_KEY"],
      credentials: [
        { host: "api.groq.com", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "api.groq.com": { readPathPrefixes: ["/openai/v1/chat/completions", "/openai/v1/models"] },
    },
  },
  deepseek: {
    id: "deepseek",
    label: "DeepSeek",
    revision: 1,
    hosts: [
      { host: "api.deepseek.com" },
    ],
    detect: [],
    explanations: [
      "DeepSeek API: Authorization (bearer)",
    ],
    credential: {
      tokenName: "deepseek",
      tokenDescription: "DeepSeek API key for API requests",
      agentEnv: ["DEEPSEEK_API_KEY"],
      credentials: [
        { host: "api.deepseek.com", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "api.deepseek.com": { readPathPrefixes: ["/chat/completions", "/v1/chat/completions", "/models"] },
    },
  },
  xai: {
    id: "xai",
    label: "xAI (Grok)",
    revision: 1,
    hosts: [
      { host: "api.x.ai" },
    ],
    detect: [],
    explanations: [
      "xAI API: Authorization (bearer), path /v1",
    ],
    credential: {
      tokenName: "xai",
      tokenDescription: "xAI API key for API requests",
      agentEnv: ["XAI_API_KEY"],
      credentials: [
        { host: "api.x.ai", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "api.x.ai": { readPathPrefixes: ["/v1/chat/completions", "/v1/messages", "/v1/models"] },
    },
  },
  openrouter: {
    id: "openrouter",
    label: "OpenRouter",
    revision: 1,
    hosts: [
      { host: "openrouter.ai" },
    ],
    detect: [],
    explanations: [
      "OpenRouter API: Authorization (bearer), path /api/v1",
    ],
    credential: {
      tokenName: "openrouter",
      tokenDescription: "OpenRouter API key for API requests",
      agentEnv: ["OPENROUTER_API_KEY"],
      credentials: [
        { host: "openrouter.ai", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "openrouter.ai": { readPathPrefixes: ["/api/v1/chat/completions", "/api/v1/models"] },
    },
  },
  perplexity: {
    id: "perplexity",
    label: "Perplexity",
    revision: 1,
    hosts: [
      { host: "api.perplexity.ai" },
    ],
    detect: [],
    explanations: [
      "Perplexity API: Authorization (bearer)",
    ],
    credential: {
      tokenName: "perplexity",
      tokenDescription: "Perplexity API key for API requests",
      agentEnv: ["PERPLEXITY_API_KEY"],
      credentials: [
        { host: "api.perplexity.ai", header: "Authorization", scheme: "bearer" },
      ],
    },
    readOnly: {
      "api.perplexity.ai": { readPathPrefixes: ["/chat/completions"] },
    },
  },
  elevenlabs: {
    id: "elevenlabs",
    label: "ElevenLabs",
    revision: 1,
    hosts: [
      { host: "api.elevenlabs.io" },
    ],
    detect: [],
    explanations: [
      "ElevenLabs API: xi-api-key (raw)",
    ],
    credential: {
      tokenName: "elevenlabs",
      tokenDescription: "ElevenLabs API key for API requests",
      agentEnv: ["ELEVENLABS_API_KEY"],
      credentials: [
        { host: "api.elevenlabs.io", header: "xi-api-key", scheme: "raw" },
      ],
    },
  },
  "apple-ads": {
    id: "apple-ads",
    label: "Apple Ads (Search Ads) API",
    revision: 2,
    hosts: [
      { host: "api.searchads.apple.com" },
      { host: "appleid.apple.com" },
    ],
    detect: [],
    explanations: [
      "Apple Ads API: OAuth2 client-credentials grant; the agent exchanges a client-secret JWT for 1-hour access tokens",
      "OAuth token endpoint: appleid.apple.com/auth/oauth2/token; Runfree restricts it to POST /auth/oauth2/token for this service",
      "The client-secret JWT seed stays proxy-side; the agent receives a handle for APPLE_ADS_CLIENT_SECRET and only the non-secret APPLE_ADS_CLIENT_ID parameter",
    ],
    // No static credential: Apple has no separate API-key header. The single
    // seed is the client-secret JWT (signable host-side from the EC private key
    // via `source add jwt`, so the key never enters the agent or the proxy).
    oauthCredential: {
      tokenEndpoint: "https://appleid.apple.com/auth/oauth2/token",
      resourceHost: "api.searchads.apple.com",
      seeds: [
        {
          field: "client_secret",
          envVar: "APPLE_ADS_CLIENT_SECRET",
          tokenName: "oauth-apple-ads-client-secret",
          description: "Apple Ads OAuth client-secret JWT seed",
        },
      ],
    },
    parameters: [
      {
        key: "client-id",
        envVar: "APPLE_ADS_CLIENT_ID",
        oauthField: "client_id",
        description: "Apple Ads OAuth client id (SEARCHADS.<uuid>)",
        example: "SEARCHADS.12345678-1234-1234-1234-123456789012",
        pattern: "^SEARCHADS\\.[0-9a-fA-F-]{36}$",
      },
    ],
  },
  "appstore-connect": {
    id: "appstore-connect",
    label: "App Store Connect API",
    revision: 1,
    hosts: [
      { host: "api.appstoreconnect.apple.com" },
    ],
    detect: [],
    explanations: [
      "App Store Connect API: an ES256 JWT presented directly as Authorization: Bearer (no OAuth token exchange)",
      "The JWT is signed host-side from a `runfree credential source add jwt` signer (the .p8 private key stays in the host source), synced into proxy-only tmpfs, and injected by the proxy; the agent never holds the key or the token",
      "Bind the signer with: runfree service enable appstore-connect --from-source <jwt-source>",
    ],
    // Static credential (not OAuth): the value is a short-lived JWT whose source
    // is a `source add jwt` signer. The proxy injects it as Authorization: Bearer
    // and the JWT's ttl drives auto-refresh; nothing reaches the agent but an
    // inert placeholder env var.
    credential: {
      tokenName: "appstore-connect",
      tokenDescription: "App Store Connect API JWT (ES256), injected as Authorization: Bearer",
      agentEnv: ["APP_STORE_CONNECT_TOKEN"],
      credentials: [
        { host: "api.appstoreconnect.apple.com", header: "Authorization", scheme: "bearer" },
      ],
    },
  },
  "google-ads": {
    id: "google-ads",
    label: "Google Ads API",
    revision: 2,
    hosts: [
      { host: "googleads.googleapis.com" },
      { host: "oauth2.googleapis.com" },
    ],
    detect: [],
    explanations: [
      "Google Ads API: OAuth2 access token plus developer-token header",
      "OAuth token endpoint: oauth2.googleapis.com/token; Runfree restricts it to POST /token for this service",
      "OAuth seed secrets stay proxy-side; the agent receives handles for GOOGLE_ADS_REFRESH_TOKEN and GOOGLE_ADS_CLIENT_SECRET",
    ],
    credential: {
      tokenName: "google-ads-developer-token",
      tokenDescription: "Google Ads developer token for API requests",
      agentEnv: ["GOOGLE_ADS_DEVELOPER_TOKEN"],
      credentials: [
        { host: "googleads.googleapis.com", header: "developer-token", scheme: "raw" },
      ],
    },
    oauthCredential: {
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      resourceHost: "googleads.googleapis.com",
      seeds: [
        {
          field: "refresh_token",
          envVar: "GOOGLE_ADS_REFRESH_TOKEN",
          tokenName: "oauth-google-ads-refresh-token",
          description: "Google Ads OAuth refresh token seed",
        },
        {
          field: "client_secret",
          envVar: "GOOGLE_ADS_CLIENT_SECRET",
          tokenName: "oauth-google-ads-client-secret",
          description: "Google Ads OAuth client secret seed",
        },
      ],
    },
    parameters: [
      {
        key: "client-id",
        envVar: "GOOGLE_ADS_CLIENT_ID",
        oauthField: "client_id",
        description: "Google Ads OAuth client id",
        example: "1234567890-abc.apps.googleusercontent.com",
      },
    ],
  },
};

export function service(id: string): Service | undefined {
  return SERVICES[id.toLowerCase()];
}

export function serviceNames(): string[] {
  return Object.keys(SERVICES).sort();
}

function credentialIdentityForValidation(credential: CredentialPolicyJson): string {
  return `${credential.host}\0${credential.header.toLowerCase()}\0${credential.scheme}\0${credential.pathPrefix ?? ""}`;
}

function exactJsonEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reportUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
  issues: string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) issues.push(`${label}.${key} is not a known field`);
  }
}

function currentProfileFieldValue(
  profile: ServiceReadOnlyHostProfile | undefined,
  field: keyof ServiceReadOnlyHostProfile,
): unknown {
  if (field === "graphql" && profile?.graphql) {
    return { endpoints: profile.graphql.endpoints, writeOps: "mutation" };
  }
  return profile?.[field];
}

function validateMigrationRequestValue(
  serviceId: string,
  host: string,
  field: keyof ServiceReadOnlyHostProfile,
  value: unknown,
  label: string,
  issues: string[],
): void {
  try {
    const loaded = validateNetworkPolicy({
      hosts: [host],
      requests: {
        [host]: { [field]: value } as RequestPolicyJson,
      },
    });
    const normalized = (loaded.raw.requests?.[host] as Record<string, unknown> | undefined)?.[field];
    if (!exactJsonEqual(value, normalized)) {
      issues.push(`${serviceId}: ${label}.${field} must use its exact normalized policy value`);
    }
  } catch (error) {
    issues.push(`${serviceId}: ${label}.${field}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export type ServiceDefinitionValidationOptions = {
  origin: "registry" | "user";
  registry?: Record<string, Service>;
};

export function serviceAgentEnvNames(registry: Record<string, Service> = SERVICES): string[] {
  return Object.values(registry)
    .flatMap((svc) => [
      ...(svc.credential?.agentEnv ?? []),
      ...(svc.oauthCredential?.seeds.map((seed) => seed.envVar) ?? []),
      ...serviceParameters(svc).map((parameter) => parameter.envVar),
    ])
    .sort();
}

// Shared registry/user-service invariants. User-definition parsing performs the
// stricter JSON-shape checks first, then calls this over the normalized Service
// object; the maintainer test calls it over the embedded registry so namespace
// and host/credential rules have one implementation.
export function validateServiceDefinition(svc: Service, options: ServiceDefinitionValidationOptions): string[] {
  const issues: string[] = [];
  const origin = options.origin;
  if (origin === "registry" && isUserServiceId(svc.id)) {
    issues.push(`${svc.id}: curated service ids may not use the reserved user- prefix`);
  }
  if (origin === "user" && !isUserServiceId(svc.id)) {
    issues.push(`${svc.id}: user service ids must match ${USER_SERVICE_ID_PATTERN.source}`);
  }
  if (svc.id !== svc.id.toLowerCase()) issues.push(`${svc.id}: service id must be lowercase`);
  if (!Number.isInteger(svc.revision) || svc.revision < 1) issues.push(`${svc.id}: revision must be an integer >= 1`);
  if (typeof svc.label !== "string" || svc.label.trim() === "") issues.push(`${svc.id}: label must be non-empty`);
  if (!Array.isArray(svc.explanations) || svc.explanations.length === 0) issues.push(`${svc.id}: explanations must be non-empty`);
  if (svc.defaultWriteMode !== undefined && svc.defaultWriteMode !== "allow-write" && svc.defaultWriteMode !== "read-only") {
    issues.push(`${svc.id}: defaultWriteMode must be allow-write or read-only`);
  }
  if (origin === "user" && svc.defaultWriteMode !== undefined) {
    issues.push(`${svc.id}: user services may not define defaultWriteMode`);
  }

  const hosts = serviceHostNames(svc);
  if (hosts.length === 0) issues.push(`${svc.id}: hosts must be non-empty`);
  if (new Set(hosts).size !== hosts.length) issues.push(`${svc.id}: hosts must be unique`);
  for (const host of [...hosts, ...(svc.removedHosts ?? [])]) {
    try {
      const normalized = normalizeHostname(host);
      if (normalized !== host) issues.push(`${svc.id}: host ${host} must be stored as ${normalized}`);
    } catch (error) {
      issues.push(`${svc.id}: host ${host}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (host.includes("*")) issues.push(`${svc.id}: host ${host} must not be a wildcard`);
  }
  for (const host of serviceBroadHosts(svc)) {
    if (!host.explanation || host.explanation.trim().length < 20) {
      issues.push(`${svc.id}: broad host ${host.host} requires a non-trivial explanation`);
    }
  }

  if (svc.credential) {
    if (origin === "registry" && svc.credential.tokenName.startsWith(USER_SERVICE_PREFIX)) {
      issues.push(`${svc.id}: curated token names may not use the reserved user- prefix`);
    }
    if (origin === "user" && svc.credential.tokenName !== svc.id) {
      issues.push(`${svc.id}: user service token name must equal the service id`);
    }
    if (svc.credential.allowAnonymous !== undefined && typeof svc.credential.allowAnonymous !== "boolean") {
      issues.push(`${svc.id}: credential.allowAnonymous must be a boolean when present`);
    }
    if (svc.credential.agentEnv.length === 0) issues.push(`${svc.id}: credential.agentEnv must be non-empty`);
    const envSeen = new Set<string>();
    for (const envName of svc.credential.agentEnv) {
      if (!ENV_NAME_PATTERN.test(envName)) issues.push(`${svc.id}: invalid agent env name ${envName}`);
      if (envSeen.has(envName)) issues.push(`${svc.id}: duplicate agent env name ${envName}`);
      envSeen.add(envName);
    }
    const hostSet = new Set(hosts);
    const credentialKeys = new Set<string>();
    for (const credential of svc.credential.credentials) {
      if (!hostSet.has(credential.host)) issues.push(`${svc.id}: credential host ${credential.host} must be a service host`);
      const key = credentialIdentityForValidation(credential);
      if (credentialKeys.has(key)) issues.push(`${svc.id}: duplicate credential mapping for ${credential.host} ${credential.header}`);
      credentialKeys.add(key);
    }
    try {
      validateNetworkPolicy({
        hosts: hosts,
        tokens: {
          [svc.credential.tokenName]: {
            description: svc.credential.tokenDescription,
            ...(typeof svc.credential.allowAnonymous === "boolean"
              ? { allowAnonymous: svc.credential.allowAnonymous }
              : {}),
            credentials: svc.credential.credentials,
          },
        },
      });
    } catch (error) {
      issues.push(`${svc.id}: credential policy invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (svc.oauthCredential) {
    if (origin === "user") issues.push(`${svc.id}: user services may not define oauthCredential`);
    const hostSet = new Set(hosts);
    const endpoint = (() => {
      try {
        return new URL(svc.oauthCredential.tokenEndpoint);
      } catch {
        return undefined;
      }
    })();
    if (!endpoint || endpoint.protocol !== "https:") issues.push(`${svc.id}: oauth tokenEndpoint must be HTTPS`);
    if (endpoint && !hostSet.has(endpoint.hostname)) issues.push(`${svc.id}: oauth tokenEndpoint host must be a service host`);
    if (!hostSet.has(svc.oauthCredential.resourceHost)) issues.push(`${svc.id}: oauth resourceHost must be a service host`);
    for (const seed of svc.oauthCredential.seeds) {
      if (seed.tokenName.startsWith(USER_SERVICE_PREFIX)) issues.push(`${svc.id}: curated OAuth seed token names may not use the reserved user- prefix`);
    }
  }

  const parameterKeys = new Set<string>();
  const parameterEnv = new Set<string>();
  const reservedEnv = new Set([
    ...(svc.credential?.agentEnv ?? []),
    ...(svc.oauthCredential?.seeds ?? []).map((seed) => seed.envVar),
  ]);
  for (const parameter of serviceParameters(svc)) {
    const label = `${svc.id}: parameter ${parameter.key}`;
    if (typeof parameter.key !== "string" || !SERVICE_PARAMETER_KEY_PATTERN.test(parameter.key)) {
      issues.push(`${svc.id}: parameter key ${String(parameter.key)} must match ${SERVICE_PARAMETER_KEY_PATTERN.source}`);
    }
    if (parameterKeys.has(parameter.key)) issues.push(`${svc.id}: duplicate parameter key ${parameter.key}`);
    parameterKeys.add(parameter.key);
    if (typeof parameter.envVar !== "string" || !ENV_NAME_PATTERN.test(parameter.envVar)) {
      issues.push(`${label} has invalid env name ${String(parameter.envVar)}`);
    }
    if (parameterEnv.has(parameter.envVar) || reservedEnv.has(parameter.envVar)) {
      issues.push(`${label} env ${parameter.envVar} collides with another agent env name`);
    }
    parameterEnv.add(parameter.envVar);
    if (typeof parameter.description !== "string" || parameter.description.trim() === "") {
      issues.push(`${label} needs a description`);
    }
    if (parameter.oauthField !== undefined) {
      if (!svc.oauthCredential) issues.push(`${label} sets oauthField without an oauthCredential`);
      if (typeof parameter.oauthField !== "string" || !OAUTH_FIELD_PATTERN.test(parameter.oauthField)) {
        issues.push(`${label} oauthField must match ${OAUTH_FIELD_PATTERN.source}`);
      }
    }
    if (parameter.pattern !== undefined) {
      try {
        new RegExp(parameter.pattern);
      } catch {
        issues.push(`${label} pattern does not compile`);
      }
      if (typeof parameter.pattern !== "string" || !parameter.pattern.startsWith("^") || !parameter.pattern.endsWith("$")) {
        issues.push(`${label} pattern must be anchored with ^ and $`);
      }
    }
    if (parameter.example !== undefined && typeof parameter.example !== "string") issues.push(`${label} example must be a string`);
  }

  if (svc.readOnly) {
    if (origin === "user") issues.push(`${svc.id}: user services may not define readOnly`);
    const hostSet = new Set(hosts);
    for (const [host, profile] of Object.entries(svc.readOnly)) {
      if (!hostSet.has(host)) issues.push(`${svc.id}: readOnly host ${host} must be a service host`);
      for (const prefix of [...(profile.readPathPrefixes ?? []), ...(profile.writePathPrefixes ?? [])]) {
        try {
          const normalized = normalizePathPrefix(prefix);
          if (normalized !== prefix) issues.push(`${svc.id}: readOnly prefix ${prefix} must be normalized`);
        } catch (error) {
          issues.push(`${svc.id}: readOnly prefix ${prefix}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      for (const endpointPath of profile.graphql?.endpoints ?? []) {
        try {
          const normalized = normalizePathPrefix(endpointPath);
          if (normalized !== endpointPath) issues.push(`${svc.id}: GraphQL endpoint ${endpointPath} must be normalized`);
        } catch (error) {
          issues.push(`${svc.id}: GraphQL endpoint ${endpointPath}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
  }

  if (svc.migrations !== undefined && !Array.isArray(svc.migrations)) {
    issues.push(`${svc.id}: migrations must be an array when present`);
  } else if (svc.migrations) {
    if (svc.migrations.length === 0) issues.push(`${svc.id}: migrations must be non-empty when present`);
    if (origin === "user") issues.push(`${svc.id}: user services may not define migrations`);
    const steps = new Set<string>();
    const hostSet = new Set(hosts);
    const credentialHosts = [...hosts, ...(svc.removedHosts ?? [])];
    const currentAgentEnv = new Set([
      ...(svc.credential?.agentEnv ?? []),
      ...(svc.oauthCredential?.seeds.map((seed) => seed.envVar) ?? []),
      ...serviceParameters(svc).map((parameter) => parameter.envVar),
    ]);
    for (const [migrationIndex, migration] of svc.migrations.entries()) {
      const label = `migrations[${migrationIndex}]`;
      if (!isObjectRecord(migration)) {
        issues.push(`${svc.id}: ${label} must be an object`);
        continue;
      }
      reportUnknownKeys(
        migration,
        ["fromRevision", "toRevision", "requestRuleReplacements", "credentialLinksToRemove", "agentEnvToRemove"],
        `${svc.id}: ${label}`,
        issues,
      );
      if (!Number.isInteger(migration.fromRevision) || migration.fromRevision < 1) {
        issues.push(`${svc.id}: ${label}.fromRevision must be an integer >= 1`);
      }
      if (migration.toRevision !== migration.fromRevision + 1) {
        issues.push(`${svc.id}: ${label} must cover adjacent revisions`);
      }
      if (migration.toRevision > svc.revision) {
        issues.push(`${svc.id}: ${label}.toRevision must not exceed service revision ${svc.revision}`);
      }
      const step = `${migration.fromRevision}->${migration.toRevision}`;
      if (steps.has(step)) issues.push(`${svc.id}: duplicate migration step ${step}`);
      steps.add(step);

      const replacements = Array.isArray(migration.requestRuleReplacements)
        ? migration.requestRuleReplacements
        : [];
      if (migration.requestRuleReplacements !== undefined) {
        if (!Array.isArray(migration.requestRuleReplacements)) {
          issues.push(`${svc.id}: ${label}.requestRuleReplacements must be an array when present`);
        } else if (replacements.length === 0) {
          issues.push(`${svc.id}: ${label}.requestRuleReplacements must be non-empty when present`);
        }
      }
      const replacementKeys = new Set<string>();
      for (const [replacementIndex, replacement] of replacements.entries()) {
        const replacementLabel = `${label}.requestRuleReplacements[${replacementIndex}]`;
        if (!isObjectRecord(replacement)) {
          issues.push(`${svc.id}: ${replacementLabel} must be an object`);
          continue;
        }
        reportUnknownKeys(
          replacement,
          ["host", "field", "from", "to"],
          `${svc.id}: ${replacementLabel}`,
          issues,
        );
        if (typeof replacement.host !== "string") {
          issues.push(`${svc.id}: ${replacementLabel}.host must be a string`);
          continue;
        }
        try {
          const normalized = normalizeHostname(replacement.host);
          if (normalized !== replacement.host) {
            issues.push(`${svc.id}: ${replacementLabel}.host must be stored as ${normalized}`);
          }
        } catch (error) {
          issues.push(`${svc.id}: ${replacementLabel}.host: ${error instanceof Error ? error.message : String(error)}`);
        }
        if (!hostSet.has(replacement.host)) {
          issues.push(`${svc.id}: ${replacementLabel}.host must be a current service host`);
        }
        const key = `${replacement.host}\0${replacement.field}`;
        if (replacementKeys.has(key)) issues.push(`${svc.id}: duplicate migration replacement for ${replacement.host}.${replacement.field}`);
        replacementKeys.add(key);
        if (typeof replacement.field !== "string" || !SERVICE_MIGRATION_REQUEST_FIELDS.has(replacement.field)) {
          issues.push(`${svc.id}: ${replacementLabel}.field is not a sanctioned service request field`);
          continue;
        }
        const field = replacement.field as keyof ServiceReadOnlyHostProfile;
        validateMigrationRequestValue(svc.id, replacement.host, field, replacement.from, `${replacementLabel}.from`, issues);
        validateMigrationRequestValue(svc.id, replacement.host, field, replacement.to, `${replacementLabel}.to`, issues);
        if (exactJsonEqual(replacement.from, replacement.to)) {
          issues.push(`${svc.id}: ${replacementLabel} must change the exact value`);
        }
        const current = currentProfileFieldValue(svc.readOnly?.[replacement.host], field);
        if (!exactJsonEqual(replacement.to, current)) {
          issues.push(`${svc.id}: ${replacementLabel}.to must equal the current service profile`);
        }
      }

      const linksToRemove = Array.isArray(migration.credentialLinksToRemove)
        ? migration.credentialLinksToRemove
        : [];
      if (migration.credentialLinksToRemove !== undefined) {
        if (!Array.isArray(migration.credentialLinksToRemove)) {
          issues.push(`${svc.id}: ${label}.credentialLinksToRemove must be an array when present`);
        } else if (linksToRemove.length === 0) {
          issues.push(`${svc.id}: ${label}.credentialLinksToRemove must be non-empty when present`);
        }
      }
      if (linksToRemove.length > 0) {
        try {
          validateNetworkPolicy({
            hosts: credentialHosts,
            tokens: {
              migration: {
                description: "Trusted service migration validation",
                credentials: linksToRemove,
              },
            },
          });
        } catch (error) {
          issues.push(`${svc.id}: ${label}.credentialLinksToRemove: ${error instanceof Error ? error.message : String(error)}`);
        }
        const currentLinks = new Set((svc.credential?.credentials ?? []).map(credentialIdentityForValidation));
        const seenLinks = new Set<string>();
        for (const link of linksToRemove) {
          const key = credentialIdentityForValidation(link);
          if (seenLinks.has(key)) issues.push(`${svc.id}: ${label}.credentialLinksToRemove contains a duplicate mapping`);
          if (currentLinks.has(key)) issues.push(`${svc.id}: ${label}.credentialLinksToRemove contains a current credential mapping`);
          seenLinks.add(key);
        }
      }

      const envToRemove = Array.isArray(migration.agentEnvToRemove)
        ? migration.agentEnvToRemove
        : [];
      if (migration.agentEnvToRemove !== undefined) {
        if (!Array.isArray(migration.agentEnvToRemove)) {
          issues.push(`${svc.id}: ${label}.agentEnvToRemove must be an array when present`);
        } else if (envToRemove.length === 0) {
          issues.push(`${svc.id}: ${label}.agentEnvToRemove must be non-empty when present`);
        }
      }
      const seenEnv = new Set<string>();
      for (const envName of envToRemove) {
        if (typeof envName !== "string" || !ENV_NAME_PATTERN.test(envName)) {
          issues.push(`${svc.id}: ${label}.agentEnvToRemove contains invalid env name ${String(envName)}`);
          continue;
        }
        if (seenEnv.has(envName)) issues.push(`${svc.id}: ${label}.agentEnvToRemove contains duplicate env name ${envName}`);
        if (currentAgentEnv.has(envName)) issues.push(`${svc.id}: ${label}.agentEnvToRemove contains current env name ${envName}`);
        seenEnv.add(envName);
      }

      if (replacements.length === 0 && linksToRemove.length === 0 && envToRemove.length === 0) {
        issues.push(`${svc.id}: ${label} must define at least one exact migration action`);
      }
    }
  }

  return issues;
}

export function serviceHasCredential(svc: Service): svc is Service & { credential: ServiceCredential } {
  return svc.credential !== undefined;
}

export function serviceHasOAuthCredential(svc: Service): svc is Service & { oauthCredential: ServiceOAuthCredential } {
  return svc.oauthCredential !== undefined;
}

export function serviceBroadHosts(svc: Service): ServiceHost[] {
  return svc.hosts.filter((host) => host.broad === true);
}

export function serviceHostNames(svc: Service, options: { skipBroad?: boolean } = {}): string[] {
  return svc.hosts
    .filter((host) => !(options.skipBroad && host.broad === true))
    .map((host) => host.host);
}

export function broadHostWarningLines(hosts: ServiceHost[]): string[] {
  return hosts
    .filter((host) => host.broad === true)
    .map((host) => `note: ${host.host} ${host.explanation ?? "is broad multi-tenant infrastructure."}`);
}

// Services that may be named in automatic suggestions (init detection, denial
// feedback, audit reports) for the given exact host. The lookup is cheap and
// purely local: it scans the embedded registry only.
export function suggestableServicesForHost(
  host: string,
  registry: Record<string, Service> = SERVICES,
): Service[] {
  return Object.values(registry).filter((svc) => svc.neverAutoSuggest !== true
    && svc.hosts.some((serviceHost) => serviceHost.host === host));
}

// Secondary, clearly-labeled service suggestion for blocked/observed-host
// feedback. The single exact host stays the primary suggestion elsewhere; a
// service is only ever named as a follow-up option and is never auto-applied.
// Feedback naming a service with broad hosts inlines the broad-host warning so
// the operator sees the exfiltration-surface note before enabling. For
// credentialed services, a follow-up line notes that a token source also
// attaches the credential.
export function serviceSuggestionLines(
  host: string,
  registry: Record<string, Service> = SERVICES,
): string[] {
  const lines: string[] = [];
  for (const svc of suggestableServicesForHost(host, registry)) {
    const broadHosts = serviceBroadHosts(svc);
    const broadSuffix = broadHosts.length > 0 ? `, ${broadHosts.length} broad` : "";
    const originSuffix = isUserServiceId(svc.id) ? " (user-defined)" : "";
    lines.push(`${host} is part of service "${svc.id}"${originSuffix} (${svc.hosts.length} hosts${broadSuffix}).`);
    lines.push(`runfree service enable ${svc.id}   # allow the whole ecosystem (never applied automatically)`);
    if (serviceHasOAuthCredential(svc)) {
      lines.push(`runfree service enable ${svc.id} --from-1password-item op://...   # also mediate OAuth credentials`);
    } else if (serviceHasCredential(svc)) {
      const envExample = svc.credential.agentEnv[0] ?? `${svc.credential.tokenName.toUpperCase()}_TOKEN`;
      lines.push(`runfree service enable ${svc.id} --from-env ${envExample}   # also inject the ${svc.credential.tokenName} credential`);
    }
    lines.push(...broadHostWarningLines(broadHosts));
  }
  return lines;
}
