// The one door for container enumeration filters, and the home of the label
// taxonomy (2026-08-15 container label taxonomy design, Phases 2-3).
//
// A Runfree project's containers come from two creators — Docker Compose for
// the agent/proxy/callback services, and the admission driver for per-session
// containers — and only Compose stamps `com.docker.compose.project`. Every
// enumeration that means "this project's containers" but filters on the
// Compose label silently returns the Compose subset; it does not error, it
// returns a shorter list that reads as success. That shape produced two real
// defects before this module existed. The remedy is that a call site states
// which set it means in typed terms: hand-written label filters outside this
// module are a static-check failure (`make test-static`), so "did you mean
// sessions too?" is a review-time question rather than a production discovery.
//
// Labels select; records authorize; inspection verifies (design principle P1).
// Nothing here verifies anything: these builders narrow candidate sets, and
// every destructive or authority-bearing path keeps acting on record-bound
// container ids or verified inspection exactly as before.

/** One closed vocabulary for what a container is. Diagnostics and selection only. */
export const CONTAINER_ROLE_LABEL = "io.runfree.container-role";
export const REBIND_TRANSACTION_LABEL = "io.runfree.rebind-transaction";
export const REBIND_ATTEMPT_LABEL = "io.runfree.rebind-attempt";
/**
 * Which teardown path owns a container. Descriptive redundancy only: ownership
 * is derived from the lifecycle registry and Compose identity (design P4), and
 * no branch may ever dispatch on this label.
 */
export const LIFECYCLE_OWNER_LABEL = "io.runfree.lifecycle-owner";
/** Marks a container as Runfree-caused. Selection only. */
export const MANAGED_CONTAINER_LABEL = "io.runfree.managed";
/**
 * Which label taxonomy the container was created under. Version skew is a
 * question about the label scheme, not about the release that happened to
 * write it — `io.runfree.version` stays informational and must not be used
 * for this purpose.
 */
export const CONTAINER_LABEL_SCHEMA_LABEL = "io.runfree.label-schema";
export const CONTAINER_LABEL_SCHEMA_VERSION = "1";

export const CONTAINER_ROLES = ["agent", "proxy", "mcp-callback-relay", "session-agent", "ephemeral-helper", "ingress-forwarder"] as const;
export type ContainerRole = typeof CONTAINER_ROLES[number];

export const LIFECYCLE_OWNERS = ["compose", "session", "utility"] as const;
export type LifecycleOwner = typeof LIFECYCLE_OWNERS[number];

/**
 * What a given ephemeral helper is for. Diagnostic only, never a query key and
 * never dispatched on — the same rule as the ingress spec's `ingress-purpose`
 * (cutover decision D-5, 2026-08-17: one role for the one hardened short-lived
 * shape, purposes as diagnostics, `lifecycle-owner=utility` shared with every
 * future host-created, self-torn-down helper).
 */
export const EPHEMERAL_HELPER_PURPOSE_LABEL = "io.runfree.helper-purpose";
// No callback purpose, deliberately: the MCP callback bridge forwards to the
// OAuth'ing agent's own loopback, so it is namespace-bound to that agent's
// container and can never be a helper. Its post-cutover home is the session
// container itself (D23 wiring). `trust-bundle` extracts the selected image's
// system roots for the host-rendered CA bundle (D-4).
export const EPHEMERAL_HELPER_PURPOSES = ["deny-probe", "dependency-prep", "trust-bundle"] as const;
export type EphemeralHelperPurpose = typeof EPHEMERAL_HELPER_PURPOSES[number];
/**
 * A random per-run nonce, recorded in the host-owned helper-run intent before
 * the helper is spawned. Unlike the other helper labels it binds one container
 * to one intent: the residue listing and the removal proof both require it,
 * so neither can reach a helper that another run (a pre-change version, or a
 * concurrent CLI on another state root) created.
 */
export const EPHEMERAL_HELPER_RUN_LABEL = "io.runfree.helper-run";
export const EPHEMERAL_HELPER_RUN_NONCE_PATTERN = /^[a-f0-9]{32}$/u;

const COMPOSE_PROJECT_LABEL = "com.docker.compose.project";
const COMPOSE_SERVICE_LABEL = "com.docker.compose.service";
const PROJECT_ID_LABEL = "io.runfree.project-id";

const PROJECT_ID_PATTERN = /^[0-9a-f]{12}$/;
// Docker Compose's own project-name constraint; the name is env-overridable
// (`RUNFREE_COMPOSE_PROJECT_NAME`), so this must not assume Runfree's default
// `runfree-<hash>` spelling.
const COMPOSE_PROJECT_PATTERN = /^[a-z0-9][a-z0-9_-]*$/;
const COMPOSE_SERVICE_PATTERN = /^[a-z][a-z0-9_]*$/;

function assertProjectId(projectId: string): string {
  if (!PROJECT_ID_PATTERN.test(projectId)) {
    throw new Error(`container enumeration requires an exact project id, not ${projectId || "<empty>"}`);
  }
  return projectId;
}

function assertComposeProject(composeProject: string): string {
  if (!COMPOSE_PROJECT_PATTERN.test(composeProject)) {
    throw new Error(`container enumeration requires an exact Compose project name, not ${composeProject || "<empty>"}`);
  }
  return composeProject;
}

/**
 * The Compose-created services: agent, proxy, and the callback when present.
 * Excludes session containers by construction — they carry no Compose label,
 * deliberately, so no Compose invocation can ever own their teardown.
 */
export function composeProjectContainerFilters(composeProject: string): string[] {
  return ["--filter", `label=${COMPOSE_PROJECT_LABEL}=${assertComposeProject(composeProject)}`];
}

/** One exact Compose service within the Compose set. */
export function composeServiceContainerFilters(composeProject: string, service: string): string[] {
  if (!COMPOSE_SERVICE_PATTERN.test(service)) {
    throw new Error(`container enumeration requires an exact Compose service name, not ${service || "<empty>"}`);
  }
  return [
    ...composeProjectContainerFilters(composeProject),
    "--filter",
    `label=${COMPOSE_SERVICE_LABEL}=${service}`,
  ];
}

/**
 * The Compose set, corroborated by the project-id label both creators stamp.
 * Same subset as `composeProjectContainerFilters`; the extra conjunct keeps a
 * foreign Compose project that happens to reuse the name out of the listing.
 */
export function corroboratedComposeProjectContainerFilters(
  projectId: string,
  composeProject: string,
): string[] {
  return [
    "--filter",
    `label=${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`,
    ...composeProjectContainerFilters(composeProject),
  ];
}

/** One exact Compose service, corroborated by the project-id label. */
export function corroboratedComposeServiceContainerFilters(
  projectId: string,
  composeProject: string,
  service: string,
): string[] {
  return [
    "--filter",
    `label=${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`,
    ...composeServiceContainerFilters(composeProject, service),
  ];
}

/**
 * Everything labelled for this project — Compose services, session containers,
 * and any residue. The union key for discovery, never a sufficient basis for
 * classification: candidates from this set are unverified by definition.
 */
export function wholeProjectContainerFilters(projectId: string): string[] {
  return ["--filter", `label=${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`];
}

/** Compose-owned project networks. Sessions attach to these and create none. */
export function composeProjectNetworkFilters(composeProject: string): string[] {
  return ["--filter", `label=${COMPOSE_PROJECT_LABEL}=${assertComposeProject(composeProject)}`];
}

/** Compose-owned project volumes. */
export function composeProjectVolumeFilters(composeProject: string): string[] {
  return ["--filter", `label=${COMPOSE_PROJECT_LABEL}=${assertComposeProject(composeProject)}`];
}

/**
 * Images labelled for this project. Image labelling itself is out of this
 * taxonomy's scope (the managed-image and image-role labels keep their
 * meaning, built in `images.ts`); this builder only keeps the project-scoped
 * image listing on the same door as every other project-scoped enumeration.
 */
export function projectImageFilters(projectId: string): string[] {
  return ["--filter", `label=${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`];
}

/**
 * The `--label` arguments a new ephemeral helper container carries.
 *
 * Minted here because this module is the taxonomy's home (the same decision
 * the approved ingress-forwarder design records for its own labels). Helpers
 * are `--rm` and self-tearing. The labels select a helper for the destroy
 * residue scan and for exact-id helper reclaim; they never authorize on their
 * own — reclaim also requires the host-owned intent, its run nonce, and a
 * full inspection proof (`ephemeral-helper-residue.ts`).
 */
export function ephemeralHelperLabelArguments(
  projectId: string,
  purpose: EphemeralHelperPurpose,
  runNonce: string,
): string[] {
  if (!EPHEMERAL_HELPER_PURPOSES.includes(purpose)) {
    throw new Error(`unknown ephemeral helper purpose: ${String(purpose)}`);
  }
  return [
    "--label",
    `${MANAGED_CONTAINER_LABEL}=true`,
    "--label",
    `${CONTAINER_ROLE_LABEL}=ephemeral-helper`,
    "--label",
    `${LIFECYCLE_OWNER_LABEL}=utility`,
    "--label",
    `${CONTAINER_LABEL_SCHEMA_LABEL}=${CONTAINER_LABEL_SCHEMA_VERSION}`,
    "--label",
    `${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`,
    "--label",
    `${EPHEMERAL_HELPER_PURPOSE_LABEL}=${purpose}`,
    "--label",
    `${EPHEMERAL_HELPER_RUN_LABEL}=${assertEphemeralHelperRunNonce(runNonce)}`,
  ];
}

function assertEphemeralHelperRunNonce(runNonce: string): string {
  if (!EPHEMERAL_HELPER_RUN_NONCE_PATTERN.test(runNonce)) {
    throw new Error("ephemeral helper run nonce must be 32 lowercase hex characters");
  }
  return runNonce;
}

/** This project's ephemeral helpers — normally none, since helpers are `--rm`. */
export function projectEphemeralHelperFilters(projectId: string): string[] {
  return [
    "--filter",
    `label=${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`,
    "--filter",
    `label=${CONTAINER_ROLE_LABEL}=ephemeral-helper`,
  ];
}

/**
 * One helper run's containers: this project's helpers with the run's purpose
 * and exact nonce. The no-cidfile reclaim lists only this set, so it can never
 * select a helper another run (or a pre-change version) created.
 */
export function ephemeralHelperRunFilters(projectId: string, purpose: EphemeralHelperPurpose, runNonce: string): string[] {
  if (!EPHEMERAL_HELPER_PURPOSES.includes(purpose)) {
    throw new Error(`unknown ephemeral helper purpose: ${String(purpose)}`);
  }
  return [
    ...projectEphemeralHelperFilters(projectId),
    "--filter",
    `label=${EPHEMERAL_HELPER_PURPOSE_LABEL}=${purpose}`,
    "--filter",
    `label=${EPHEMERAL_HELPER_RUN_LABEL}=${assertEphemeralHelperRunNonce(runNonce)}`,
  ];
}

/**
 * What a given ingress forwarder is for. Diagnostic only, never a query key and
 * never dispatched on (ingress spec I1). One hardened socat shape, N purposes:
 * `vnc` (a headed agent UI), `port` (`runfree forward <port>`), `mcp-callback`
 * (the per-session MCP OAuth callback that retires the bespoke Compose relay,
 * cutover option C).
 */
export const INGRESS_PURPOSE_LABEL = "io.runfree.ingress-purpose";
export const INGRESS_PURPOSES = ["vnc", "port", "mcp-callback"] as const;
export type IngressPurpose = typeof INGRESS_PURPOSES[number];

/**
 * The `--label` arguments a new ingress forwarder carries. Minted here for the
 * same reason the ephemeral-helper labels are: this module is the taxonomy's
 * home. Labels are diagnostic and for the residue scan, never authorization —
 * a forwarder is authorized by its live shape check, not this role label
 * (ingress spec, Non-goals).
 */
export function ingressForwarderLabelArguments(projectId: string, purpose: IngressPurpose): string[] {
  if (!INGRESS_PURPOSES.includes(purpose)) {
    throw new Error(`unknown ingress purpose: ${String(purpose)}`);
  }
  return [
    "--label",
    `${MANAGED_CONTAINER_LABEL}=true`,
    "--label",
    `${CONTAINER_ROLE_LABEL}=ingress-forwarder`,
    "--label",
    `${LIFECYCLE_OWNER_LABEL}=utility`,
    "--label",
    `${CONTAINER_LABEL_SCHEMA_LABEL}=${CONTAINER_LABEL_SCHEMA_VERSION}`,
    "--label",
    `${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`,
    "--label",
    `${INGRESS_PURPOSE_LABEL}=${purpose}`,
  ];
}

/** This project's ingress forwarders (by project id + role). */
export function projectIngressForwarderFilters(projectId: string): string[] {
  return [
    "--filter",
    `label=${PROJECT_ID_LABEL}=${assertProjectId(projectId)}`,
    "--filter",
    `label=${CONTAINER_ROLE_LABEL}=ingress-forwarder`,
  ];
}
