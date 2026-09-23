import path from "node:path";

/**
 * Registry for every project-controlled `.runfree` path that Runfree treats as
 * meaningful. Paths not matched here are inert by default. This is an
 * architecture boundary, not a discovery mechanism: production code must not
 * scan `.runfree` looking for additional configuration by convention.
 */
export const PROJECT_RUNFREE_PATHS = {
  root: ".runfree",
  config: ".runfree/runfree.json",
  networkPolicy: ".runfree/network-policy.json",
  networkPolicyLocal: ".runfree/network-policy.local.json",
  image: ".runfree/image",
  legacyDockerfile: ".runfree/Dockerfile",
  agentEnv: ".runfree/config/agent.env",
  gitignore: ".runfree/.gitignore",
  retiredTokenConfig: ".runfree/config/tokens.json",
  retiredSourceConfig: ".runfree/config/sources.json",
  retiredState: ".runfree/state",
  retiredBin: ".runfree/bin",
} as const;

export type ProjectRunfreePathId = keyof typeof PROJECT_RUNFREE_PATHS;
export type ProjectRunfreeApprovalSubject =
  | "image-build"
  | "network-local"
  | "network-project"
  | "runtime-isolation"
  | "sandbox-local"
  | "none";
export type ProjectRunfreeAuthorityClass = "desired-authority" | "sandbox-input" | "presentation-only" | "retired-inert";
export type ProjectRunfreeConsumption = "active" | "scaffold-only" | "inert";

export type ProjectRunfreeConsumer = {
  id: ProjectRunfreePathId;
  path: string;
  match: "exact" | "subtree";
  consumption: ProjectRunfreeConsumption;
  schema: string;
  bounds: string;
  authorityClass: ProjectRunfreeAuthorityClass;
  approvalSubject: ProjectRunfreeApprovalSubject;
  effectiveOutput: string;
  invalidation: string;
  negativeProof: string;
};

export const PROJECT_RUNFREE_CONSUMERS: readonly ProjectRunfreeConsumer[] = [
  {
    id: "root",
    path: PROJECT_RUNFREE_PATHS.root,
    match: "exact",
    consumption: "active",
    schema: "normal directory; descendants are consumed only through another registry entry",
    bounds: "no traversal except through an exact or bounded-subtree entry",
    authorityClass: "sandbox-input",
    approvalSubject: "none",
    effectiveOutput: "writable project control namespace; no nested agent mount",
    invalidation: "root type or identity change invalidates all project-controlled snapshots",
    negativeProof: "a symlinked or non-directory root is rejected before config reads and no descendant is shadow-mounted",
  },
  {
    id: "config",
    path: PROJECT_RUNFREE_PATHS.config,
    match: "exact",
    consumption: "active",
    schema: "runfree config v4 with typed runtime and agent projections; v1-v3 are explicit migration inputs",
    bounds: "regular single-link file; bounded reader is a Phase 2 prerequisite",
    authorityClass: "desired-authority",
    approvalSubject: "runtime-isolation",
    effectiveOutput: "runtime topology, dependency isolation, agent selection, and image-build selection",
    invalidation: "schema/compiler version plus the affected typed projection",
    negativeProof: "unsafe config paths fail before parsing and unknown paths are not consulted",
  },
  {
    id: "networkPolicy",
    path: PROJECT_RUNFREE_PATHS.networkPolicy,
    match: "exact",
    consumption: "active",
    schema: "strict desired network policy v2; legacy policy is explicit migration input only",
    bounds: "regular single-link file; bounded reader is a Phase 2 prerequisite",
    authorityClass: "desired-authority",
    approvalSubject: "network-project",
    effectiveOutput: "current proxy network policy and credential destinations",
    invalidation: "validated policy generation",
    negativeProof: "unsafe or invalid policy fails before proxy reload or credential resolution",
  },
  {
    id: "networkPolicyLocal",
    path: PROJECT_RUNFREE_PATHS.networkPolicyLocal,
    match: "exact",
    consumption: "active",
    schema: "strict desired network policy v2; absent means the canonical empty local overlay",
    bounds: "regular single-link file; no-follow read bounded to 1 MiB before strict parsing",
    authorityClass: "desired-authority",
    approvalSubject: "network-local",
    effectiveOutput: "checkout-local desired network, service, OAuth, environment, and credential-destination overlay",
    invalidation: "canonical network-local subject digest plus compiler identity",
    negativeProof: "unsafe, oversized, duplicate-key, or invalid input fails before candidate publication",
  },
  {
    id: "image",
    path: PROJECT_RUNFREE_PATHS.image,
    match: "subtree",
    consumption: "active",
    schema: "complete selected narrow Docker build-context tree",
    bounds: "normal directories and regular single-link files; numeric tree bounds land in Phase 2",
    authorityClass: "desired-authority",
    approvalSubject: "image-build",
    effectiveOutput: "staged project agent image input",
    invalidation: "normalized build config plus complete staged tree manifest",
    negativeProof: "symlinks, hard links, special files, and context escapes are rejected before docker build",
  },
  {
    id: "legacyDockerfile",
    path: PROJECT_RUNFREE_PATHS.legacyDockerfile,
    match: "exact",
    consumption: "active",
    schema: "legacy explicitly selected wide-context Dockerfile",
    bounds: "regular single-link file inside the selected project context",
    authorityClass: "desired-authority",
    approvalSubject: "image-build",
    effectiveOutput: "wide project agent image input after explicit risk approval",
    invalidation: "normalized build config and Dockerfile digest",
    negativeProof: "unapproved wide context is rejected before docker build",
  },
  {
    id: "agentEnv",
    path: PROJECT_RUNFREE_PATHS.agentEnv,
    match: "exact",
    consumption: "scaffold-only",
    schema: "legacy placeholder-only agent environment; unsupported as a v4 runtime input",
    bounds: "legacy scaffolding/migration only; never opened by ordinary v4 lifecycle, Compose, or attach",
    authorityClass: "retired-inert",
    approvalSubject: "none",
    effectiveOutput: "none in v4; effective agent environment is host-owned immutable state",
    invalidation: "none in v4",
    negativeProof: "project-controlled contents and path replacement cannot affect v4 Compose or attach",
  },
  {
    id: "gitignore",
    path: PROJECT_RUNFREE_PATHS.gitignore,
    match: "exact",
    consumption: "scaffold-only",
    schema: "Git ignore text; never an authorization or integrity input",
    bounds: "regular single-link file",
    authorityClass: "presentation-only",
    approvalSubject: "none",
    effectiveOutput: "Git presentation only",
    invalidation: "none; semantic status must not rely on Git ignore state",
    negativeProof: "editing the file cannot change runtime or approval state",
  },
  {
    id: "retiredTokenConfig",
    path: PROJECT_RUNFREE_PATHS.retiredTokenConfig,
    match: "exact",
    consumption: "inert",
    schema: "retired; no normal parser",
    bounds: "not opened or traversed during normal runtime",
    authorityClass: "retired-inert",
    approvalSubject: "none",
    effectiveOutput: "none; credential sources are host-owned",
    invalidation: "none",
    negativeProof: "presence, malformed contents, and symlink shape cannot change token sync or delete proxy credentials",
  },
  {
    id: "retiredSourceConfig",
    path: PROJECT_RUNFREE_PATHS.retiredSourceConfig,
    match: "exact",
    consumption: "inert",
    schema: "retired; no normal parser",
    bounds: "not opened or traversed during normal runtime",
    authorityClass: "retired-inert",
    approvalSubject: "none",
    effectiveOutput: "none; named source registry is host-owned",
    invalidation: "none",
    negativeProof: "project-local source metadata cannot execute a helper or select a credential source",
  },
  {
    id: "retiredState",
    path: PROJECT_RUNFREE_PATHS.retiredState,
    match: "subtree",
    consumption: "inert",
    schema: "retired; no normal parser",
    bounds: "not scanned or traversed during normal runtime",
    authorityClass: "retired-inert",
    approvalSubject: "none",
    effectiveOutput: "none; runtime, recovery, approval, and auth state are host-owned",
    invalidation: "none",
    negativeProof: "project state cannot become readiness, approval, identity, receipt, or downgrade state",
  },
  {
    id: "retiredBin",
    path: PROJECT_RUNFREE_PATHS.retiredBin,
    match: "subtree",
    consumption: "inert",
    schema: "retired; never executable by Runfree",
    bounds: "not scanned or traversed during normal runtime",
    authorityClass: "retired-inert",
    approvalSubject: "none",
    effectiveOutput: "none",
    invalidation: "none",
    negativeProof: "project helpers are never added to host PATH or automatically executed",
  },
];

export function projectRunfreePath(projectRoot: string, id: ProjectRunfreePathId): string {
  return path.resolve(projectRoot, PROJECT_RUNFREE_PATHS[id]);
}

export function projectRunfreeConsumer(relativePath: string): ProjectRunfreeConsumer | undefined {
  const normalized = relativePath.replaceAll("\\", "/").replace(/^\.\//, "").replace(/\/$/, "");
  return PROJECT_RUNFREE_CONSUMERS.find((consumer) => consumer.match === "exact"
    ? normalized === consumer.path
    : normalized === consumer.path || normalized.startsWith(`${consumer.path}/`));
}
