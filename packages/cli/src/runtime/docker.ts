import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import type * as childProcess from "node:child_process";
import {
  firewallStatusPath,
  parseGenerationStatusLine,
  requestProxyStatusPath,
  type ParsedGenerationStatus,
} from "@runfree/runtime-contracts/proxy-status";

import { die } from "../errors.ts";
import { resolveRuntimeNetwork } from "../network.ts";
import { projectHash } from "../project-identity.ts";
import { runtimeInputBuildEnvironment } from "../runtime-inputs.ts";
import { warn } from "../warnings.ts";
import { agentBaseImageTag, agentBuildConfig } from "../agent-image.ts";
import {
  composeProjectContainerFilters,
  composeProjectNetworkFilters,
  composeProjectVolumeFilters,
  composeServiceContainerFilters,
  corroboratedComposeProjectContainerFilters,
  projectImageFilters,
  REBIND_TRANSACTION_LABEL,
  REBIND_ATTEMPT_LABEL,
} from "./container-inventory.ts";
import {
  AGENT_IMAGE_INPUT_DIGEST_LABEL,
  PROJECT_ID_LABEL,
  PROXY_IMAGE_INPUT_DIGEST_LABEL,
  RUNTIME_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  ROOT_UID_GID,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  TOPOLOGY_DIGEST_LABEL,
} from "./constants.ts";
import { composeProjectName, composeRuntimeEnvironment, dockerClientEnvironment } from "./env.ts";
import { assertComposeManagedLocalVolume } from "./session-named-volume-proof.ts";
import { createDockerClient } from "./docker-client.ts";
import {
  captureDockerListing,
  type DockerListingColumn,
  type DockerListingRow,
  dockerListingLabel,
  renderDockerListing,
} from "./docker-listing.ts";
import type {
  ActiveAgentSession,
  CaptureResult,
  ComposeContainer,
  DockerNetworkInspect,
  RuntimeContainer,
  RuntimeContext,
  RuntimeIO,
} from "./types.ts";

export type RuntimeDocker = {
  assertAvailable(): void;
  buildImage(args: string[]): number;
  composeContainers(project: string): ComposeContainer[];
  composeDown(project: string): number;
  composeUp(project: string, options?: {
    forceRecreate?: boolean;
    noDeps?: boolean;
    removeOrphans?: boolean;
    services?: string[];
    creationMarker?: { transactionId: string; attempt: number };
  }): number;
  /**
   * Creates one Compose-managed named volume with the exact ownership labels the
   * session named-volume proof requires, idempotently.
   *
   * Compose only creates a declared volume that a started service mounts. The
   * per-session cutover removed the shared `agent` service — the only thing that
   * mounted the session volumes — so `compose up` no longer creates them, yet a
   * session still mounts them and the driver proves they exist with these exact
   * labels before create. This restores that one job the removed service did.
   */
  createComposeManagedVolume(project: string, logicalName: string): number;
  destroyProject(project: string): number;
  followLogs(project: string, service: string): number;
  imageExists(tag: string): boolean;
  /**
   * Inspects one image by exact reference or id.
   *
   * Memoized per adapter instance, keyed by the exact argument string with no
   * ref→id normalization (L5a). Freshness is explicit: pass `fresh: true` at
   * any call site whose claim is temporal — "this reference still resolves to
   * this id NOW" — such as the ref-then-id cross-check pairs and any
   * pre-removal re-check. A cached read would silently satisfy those checks
   * with a stale binding. Image-mutating adapter operations and
   * `clearRuntimeCaches` invalidate the memo.
   */
  inspectImage(tag: string, options?: { fresh?: boolean }): DockerImageInspect | undefined;
  imageRefs(reference: string): string[];
  networkSubnets(): string[];
  pruneImages(filters: string[]): number;
  projectForWorkspace(): string | undefined;
  proxyControlReceipts(project: string): { firewall?: ParsedGenerationStatus; requestProxy?: ParsedGenerationStatus } | undefined;
  activeAgentSessions(project: string): ActiveAgentSession[];
  removeImages(refs: string[]): number;
  removeContainers(ids: string[]): number;
  runtimeContainers(project: string): RuntimeContainer[];
  runningServiceContainerId(project: string, service: string): string | undefined;
  serviceContainerIds(project: string, service: string, options?: { runningOnly?: boolean }): string[];
  serviceContainerId(project: string, service: string): string | undefined;
  /**
   * Whether one exact container (64-hex id) is currently running.
   *
   * For consumers that hold an identity from the lifecycle registry and must
   * not act on a container that has since stopped. Anything but an exact id
   * answers false rather than letting Docker resolve a prefix.
   */
  containerRunning(containerId: string): boolean;
  setProxyVerboseMarker(proxyId: string, markerName: string): void;
  clearProxyVerboseMarker(proxyId: string, markerName: string): void;
  resources(project?: string): number;
  status(project?: string): number;
  tagImage(source: string, target: string): number;
};

export type DockerImageInspect = {
  architecture?: string;
  environment?: Record<string, string>;
  id: string;
  labels: Record<string, string>;
  os?: string;
  onBuild?: string[];
  volumes?: string[];
};

type ActiveAgentSessionsResolver = (project: string) => ActiveAgentSession[];

export function envOptions(env: NodeJS.ProcessEnv | undefined): childProcess.SpawnSyncOptions {
  return env ? { env } : {};
}

export function dockerClientEnvOptions(context: RuntimeContext): childProcess.SpawnSyncOptions {
  return { env: dockerClientEnvironment(context.env) };
}

function runtimeEnvOptions(context: RuntimeContext): childProcess.SpawnSyncOptions {
  const runtimeNetwork = context.network ?? resolveRuntimeNetwork(context.projectRoot, context.project, [], { persist: false });
  return {
    env: {
      ...composeRuntimeEnvironment(context.projectRoot, context.project, context.runtimeRoot, context.env, runtimeNetwork, {
        agentImage: context.agentImage,
        components: context.runtimeComponents,
        gitLayout: context.gitLayoutPlan,
      }),
      ...runtimeInputBuildEnvironment(context.runtimeRoot),
    },
  };
}

/**
 * The daemon a startup is talking to, as its own `docker info` reported it.
 *
 * Read from the one availability check every startup already runs (no extra
 * Docker call). A warm launch binds its warm proof to it: a different daemon,
 * version, or kernel means a different enforcement substrate, and a daemon
 * with live-restore can restart under running containers without changing
 * their `StartedAt`, so it never takes the warm path.
 */
export type DockerDaemonIdentity = Readonly<{
  id: string;
  serverVersion: string;
  kernelVersion: string;
  liveRestoreEnabled: boolean;
}>;

let lastDockerDaemonIdentity: DockerDaemonIdentity | undefined;

export function parseDockerDaemonIdentity(stdout: string): DockerDaemonIdentity | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const value = parsed as Record<string, unknown>;
  const text = (key: string): string | undefined => {
    const field = value[key];
    return typeof field === "string" && field.length > 0 && field.length <= 256 ? field : undefined;
  };
  const id = text("ID");
  const serverVersion = text("ServerVersion");
  const kernelVersion = text("KernelVersion");
  if (!id || !serverVersion || !kernelVersion || typeof value.LiveRestoreEnabled !== "boolean") return undefined;
  return Object.freeze({ id, serverVersion, kernelVersion, liveRestoreEnabled: value.LiveRestoreEnabled });
}

/**
 * Why a `docker info --format '{{json .}}'` that exited 0 still did not reach
 * the daemon, or undefined when it did. Format mode prints what the client has
 * and lists daemon failures in `ServerErrors` instead of failing the command,
 * so the exit status alone does not prove a reachable daemon. Output that is
 * not a JSON object reports no error here; it yields no daemon identity, which
 * keeps every launch off the warm path.
 */
export function dockerInfoServerError(stdout: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const errors = (parsed as Record<string, unknown>).ServerErrors;
  if (errors === undefined || errors === null || (Array.isArray(errors) && errors.length === 0)) return undefined;
  return Array.isArray(errors) ? errors.map(String).join("; ") : "docker info reported server errors";
}

/** The identity the most recent availability check in this process observed, if it parsed. */
export function lastObservedDockerDaemonIdentity(): DockerDaemonIdentity | undefined {
  return lastDockerDaemonIdentity;
}

function dockerAvailable(context: RuntimeContext, io: RuntimeIO): boolean {
  if (!io.commandExists("docker", dockerClientEnvOptions(context))) {
    die("docker not found - install Docker Desktop first");
  }
  lastDockerDaemonIdentity = undefined;
  const info = createDockerClient(io, dockerClientEnvOptions(context)).info("{{json .}}");
  if (info.status !== 0 || dockerInfoServerError(info.stdout) !== undefined) {
    die("docker daemon not running - start Docker Desktop first");
  }
  lastDockerDaemonIdentity = parseDockerDaemonIdentity(info.stdout);
  return true;
}

function firstNonZero(...statuses: number[]): number {
  return statuses.find((status) => status !== 0) ?? 0;
}

// container-inventory.ts's filter builders return interleaved `--filter`/value
// pairs for direct argv splicing; the Docker client's `filters` field wants
// just the values, which it re-flags itself. Fails closed: a caller that feeds
// this a malformed pair or a trailing `--filter` gets a thrown error rather
// than a silently narrowed or widened listing (one caller feeds it into a
// deletion, `removeComposeProjectLeftoverVolumes`).
export function filterValues(flagPairs: readonly string[]): string[] {
  if (flagPairs.length % 2 !== 0) {
    throw new Error(`malformed --filter argv: expected [--filter, value] pairs, got ${flagPairs.length} token(s): ${JSON.stringify(flagPairs)}`);
  }
  const values: string[] = [];
  for (let index = 0; index < flagPairs.length; index += 2) {
    const flag = flagPairs[index];
    const value = flagPairs[index + 1];
    if (flag !== "--filter" || typeof value !== "string") {
      throw new Error(`malformed --filter argv at index ${index}: expected ["--filter", value], got ${JSON.stringify(flagPairs.slice(index, index + 2))}`);
    }
    values.push(value);
  }
  return values;
}

function printResourceSection(title: string, columns: readonly DockerListingColumn[], rows: readonly DockerListingRow[]): void {
  console.log("");
  console.log(title);
  if (rows.length === 0) {
    console.log("none");
    return;
  }
  console.log(renderDockerListing(columns, rows));
}

function dedupeRowsBy(rows: readonly DockerListingRow[], key: (row: DockerListingRow) => string): DockerListingRow[] {
  const deduped = new Map<string, DockerListingRow>();
  for (const row of rows) {
    const name = key(row);
    if (!deduped.has(name)) deduped.set(name, row);
  }
  return Array.from(deduped.values());
}

function imageRef(row: DockerListingRow): string {
  return `${row.Repository ?? ""}:${row.Tag ?? ""}`;
}

// `image ls` rows carry no labels, so the Runfree role and runtime digest come
// from one `image inspect` over the listed refs, read as one JSON label object
// per image and merged into the row as `RunfreeRole` / `RunfreeRuntimeDigest`.
function imageRowsWithLabels(
  context: RuntimeContext,
  io: RuntimeIO,
  query: Readonly<{ filters?: string[]; reference?: string }>,
  label: string,
): { rows: DockerListingRow[]; status: number } {
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const listing = captureDockerListing(client, { type: "image", ...query }, label);
  const refs = listing.rows.map(imageRef).filter((ref) => ref !== ":" && ref !== "<none>:<none>");
  if (listing.status !== 0 || refs.length === 0) return listing;

  const inspect = client.inspect(refs, { type: "image", format: "{{json .Config.Labels}}" });
  if (inspect.status !== 0) {
    const detail = inspect.stderr.trim();
    warn(`could not inspect Docker ${label} labels${detail ? `: ${detail}` : ""}`);
    return { rows: listing.rows, status: inspect.status };
  }

  const labelsByRef = new Map<string, Record<string, unknown>>();
  const lines = inspect.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  for (const [index, ref] of refs.entries()) {
    const line = lines[index];
    if (line === undefined) break;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      parsed = undefined;
    }
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) labelsByRef.set(ref, parsed as Record<string, unknown>);
  }
  return {
    rows: listing.rows.map((row) => {
      const labels = labelsByRef.get(imageRef(row));
      return {
        ...row,
        RunfreeRole: dockerLabelValue(labels?.[RUNFREE_IMAGE_ROLE_LABEL]) ?? "",
        RunfreeRuntimeDigest: dockerLabelValue(labels?.[RUNTIME_DIGEST_LABEL]) ?? "",
      };
    }),
    status: 0,
  };
}

const NAME_DRIVER_SCOPE_COLUMNS: readonly DockerListingColumn[] = [
  { label: "NAME", value: (row) => row.Name },
  { label: "DRIVER", value: (row) => row.Driver },
  { label: "SCOPE", value: (row) => row.Scope },
];

function projectResourceSummary(context: RuntimeContext, io: RuntimeIO, project: string): number {
  const projectId = projectHash(context.projectRoot);
  const dependencyVolumePrefix = `runfree-deps-${projectHash(fs.realpathSync(context.projectRoot))}-`;
  const options = dockerClientEnvOptions(context);
  const client = createDockerClient(io, options);

  const containers = captureDockerListing(client, {
    all: true,
    filters: filterValues(corroboratedComposeProjectContainerFilters(projectId, project)),
  }, "containers");
  const networks = captureDockerListing(client, {
    type: "network",
    filters: filterValues(composeProjectNetworkFilters(project)),
  }, "networks");
  const composeVolumes = captureDockerListing(client, {
    type: "volume",
    filters: filterValues(composeProjectVolumeFilters(project)),
  }, "compose volumes");
  const dependencyVolumes = captureDockerListing(client, {
    type: "volume",
    filters: [`name=${dependencyVolumePrefix}`],
  }, "dependency volumes");
  const projectImages = imageRowsWithLabels(context, io, {
    filters: filterValues(projectImageFilters(projectId)),
  }, "images");
  const baseImages = agentBuildConfig(context.project.config)
    ? imageRowsWithLabels(context, io, { reference: agentBaseImageTag() }, "base images")
    : { rows: [], status: 0 };
  const dependencyVolumeRows = dependencyVolumes.rows
    .filter((row) => (row.Name ?? "").startsWith(dependencyVolumePrefix));

  const volumeRows = dedupeRowsBy([
    ...composeVolumes.rows.map((row) => ({
      ...row,
      RunfreeSource: (row.Name ?? "").startsWith(dependencyVolumePrefix) ? "dependency-overlay" : "compose",
    })),
    ...dependencyVolumeRows.map((row) => ({ ...row, RunfreeSource: "dependency-overlay" })),
  ], (row) => row.Name ?? "");
  const imageRows = dedupeRowsBy([
    ...projectImages.rows,
    ...baseImages.rows,
  ], imageRef);

  console.log(`project: ${project}`);
  console.log(`project id: ${projectId}`);
  printResourceSection("containers", [
    { label: "NAME", value: (row) => row.Names },
    { label: "STATUS", value: (row) => row.Status },
    { label: "IMAGE", value: (row) => row.Image },
    { label: "SERVICE", value: (row) => dockerListingLabel(row, "com.docker.compose.service") ?? "" },
    { label: "RUNTIME DIGEST", value: (row) => dockerListingLabel(row, RUNTIME_DIGEST_LABEL) ?? "" },
  ], containers.rows);
  printResourceSection("networks", NAME_DRIVER_SCOPE_COLUMNS, networks.rows);
  printResourceSection("volumes", [
    ...NAME_DRIVER_SCOPE_COLUMNS,
    { label: "SOURCE", value: (row) => row.RunfreeSource },
  ], volumeRows);
  printResourceSection("images", [
    { label: "IMAGE", value: imageRef },
    { label: "ID", value: (row) => row.ID },
    { label: "CREATED", value: (row) => row.CreatedSince },
    { label: "SIZE", value: (row) => row.Size },
    { label: "ROLE", value: (row) => row.RunfreeRole },
    { label: "RUNTIME DIGEST", value: (row) => row.RunfreeRuntimeDigest },
  ], imageRows);

  return firstNonZero(containers.status, networks.status, composeVolumes.status, dependencyVolumes.status, projectImages.status, baseImages.status);
}

export function containerMissingNetwork(container: ComposeContainer, expectedNetwork: string): boolean {
  return !container.networks.includes(expectedNetwork);
}

const COMPOSE_TEARDOWN_PLACEHOLDER = "runfree-teardown";

/**
 * Supplies a value for every `${VAR:?…}` the runtime compose file marks required
 * but the current env does not provide, for `compose down` only.
 *
 * `docker compose down` parses — and therefore interpolates — the whole compose
 * file, but it removes resources by the `com.docker.compose.project` label,
 * never by these interpolated label values. So a placeholder for a var the
 * torn-down runtime can no longer supply (e.g. a components-derived digest once
 * the runtime generation manifest is unresolved) cannot change what is removed.
 * Without this, a single missing required var aborts teardown and leaks the
 * runtime; deriving the set from the file keeps a future required var from
 * silently reintroducing that failure. `up` is untouched, so its guards stay.
 */
/**
 * Fills a placeholder for every `${VAR:?…}` in the compose source that `baseEnv`
 * does not already provide. Exported for direct testing: missing a required var
 * here re-aborts teardown and leaks the runtime, so the derivation is proven in
 * isolation. Only `:?` (required) forms are defaulted; `:-` (has-default) and
 * present values are left untouched, and the placeholder value is never used to
 * select what `down` removes.
 */
export function applyComposeTeardownDefaults(
  composeSource: string,
  baseEnv: NodeJS.ProcessEnv | undefined,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...baseEnv };
  for (const match of composeSource.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}/gu)) {
    const name = match[1];
    if (!env[name]) env[name] = COMPOSE_TEARDOWN_PLACEHOLDER;
  }
  return env;
}

function composeTeardownEnv(composeFilePath: string, baseEnv: NodeJS.ProcessEnv | undefined): NodeJS.ProcessEnv {
  try {
    return applyComposeTeardownDefaults(fs.readFileSync(composeFilePath, "utf8"), baseEnv);
  } catch {
    return { ...baseEnv };
  }
}

/**
 * Removes the project's volumes that `compose down -v` leaves behind.
 *
 * Session containers mount the dependency-cache volumes, which startup creates
 * with Compose labels (and older sessions also mounted the retired
 * `runfree-commandhistory`). No Compose service uses them, and Compose 5.x
 * `down -v` removes only volumes a service uses, so every destroy left them
 * behind. A volume qualifies only when it carries this
 * project's exact Compose label and the `<project>_` name startup gives it.
 * Removal is never forced: Docker still refuses a volume in use.
 */
export function removeComposeProjectLeftoverVolumes(
  io: Pick<RuntimeIO, "capture">,
  project: string,
  options: childProcess.SpawnSyncOptions,
): number {
  const client = createDockerClient(io, options);
  const listed = client.listObjects("volume", { quiet: true, filters: filterValues(composeProjectVolumeFilters(project)) });
  if (listed.status !== 0) {
    warn(`destroy could not list ${project} volumes: ${listed.stderr.trim().slice(0, 512) || `exit ${listed.status}`}`);
    return listed.status;
  }
  const names = listed.stdout.split("\n").map((line) => line.trim()).filter((name) => name.startsWith(`${project}_`));
  if (names.length === 0) return 0;
  const removed = client.removeVolumes(names);
  if (removed.status !== 0) {
    warn(`destroy could not remove ${project} volumes: ${removed.stderr.trim().slice(0, 512) || `exit ${removed.status}`}`);
  }
  return removed.status;
}

export function createRuntimeDocker(
  context: RuntimeContext,
  io: RuntimeIO,
  activeAgentSessionsForProject: ActiveAgentSessionsResolver = () => [],
): RuntimeDocker {
  const composeContainerCache = new Map<string, ComposeContainer[]>();
  const runtimeContainerCache = new Map<string, RuntimeContainer[]>();
  const serviceContainerIdCache = new Map<string, string | undefined>();
  const imageInspectCache = new Map<string, DockerImageInspect | undefined>();
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const composeFile = (): string => path.join(context.runtimeRoot, "agent", "compose.yaml");
  const composeDir = (): string => path.dirname(composeFile());
  const composeArgs = (project: string, command: string, rest: string[] = []): string[] => [
    "--project-directory",
    composeDir(),
    "-p",
    project,
    "-f",
    composeFile(),
    command,
    ...rest,
  ];
  const composeOptions = (): childProcess.SpawnSyncOptions => ({
    ...runtimeEnvOptions(context),
    cwd: composeDir(),
  });
  const clearRuntimeCaches = (): void => {
    composeContainerCache.clear();
    runtimeContainerCache.clear();
    serviceContainerIdCache.clear();
    imageInspectCache.clear();
  };
  const removeProjectSessionVolumes = (project: string): number =>
    removeComposeProjectLeftoverVolumes(io, project, dockerClientEnvOptions(context));
  const cachedComposeContainers = (project: string): ComposeContainer[] => {
    const cached = composeContainerCache.get(project);
    if (cached) return cached;
    const containers = composeContainers(project, context, io);
    composeContainerCache.set(project, containers);
    return containers;
  };
  const cachedRuntimeContainers = (project: string): RuntimeContainer[] => {
    const cached = runtimeContainerCache.get(project);
    if (cached) return cached;
    const containers = runtimeContainers(project, context, io);
    runtimeContainerCache.set(project, containers);
    return containers;
  };
  const cachedServiceContainerId = (project: string, service: string, options: { runningOnly?: boolean } = {}): string | undefined => {
    const key = `${project}\0${service}\0${options.runningOnly === true ? "running" : "any"}`;
    if (serviceContainerIdCache.has(key)) return serviceContainerIdCache.get(key);
    const id = serviceContainerId(project, service, context, io, options);
    serviceContainerIdCache.set(key, id);
    return id;
  };
  const inspectImageUncached = (tag: string): DockerImageInspect | undefined => {
    const result = client.inspect([tag], { type: "image" });
    if (result.status !== 0) return undefined;
    try {
      const parsed: unknown = JSON.parse(result.stdout);
      if (!Array.isArray(parsed) || parsed.length !== 1) return undefined;
      const image: unknown = parsed[0];
      if (!image || typeof image !== "object") return undefined;
      const id = Reflect.get(image, "Id");
      if (typeof id !== "string" || id.length === 0) return undefined;
      const architecture = Reflect.get(image, "Architecture");
      const os = Reflect.get(image, "Os");
      const config = Reflect.get(image, "Config");
      if (config !== undefined && config !== null && (typeof config !== "object" || Array.isArray(config))) return undefined;
      const rawLabels = config && typeof config === "object" ? Reflect.get(config, "Labels") : undefined;
      if (rawLabels !== undefined && rawLabels !== null && (typeof rawLabels !== "object" || Array.isArray(rawLabels))) {
        return undefined;
      }
      const rawOnBuild = config && typeof config === "object" ? Reflect.get(config, "OnBuild") : undefined;
      if (rawOnBuild !== undefined && rawOnBuild !== null
        && (!Array.isArray(rawOnBuild) || rawOnBuild.some((instruction) => typeof instruction !== "string"))) {
        return undefined;
      }
      const rawVolumes = config && typeof config === "object" ? Reflect.get(config, "Volumes") : undefined;
      if (rawVolumes !== undefined && rawVolumes !== null
        && (typeof rawVolumes !== "object" || Array.isArray(rawVolumes))) return undefined;
      const volumes: string[] = [];
      if (rawVolumes && typeof rawVolumes === "object") {
        for (const [target, declaration] of Object.entries(rawVolumes)) {
          if (!target.startsWith("/")
            || path.posix.normalize(target) !== target
            || (declaration !== null
              && (typeof declaration !== "object" || Array.isArray(declaration)
                || Object.keys(declaration).length !== 0))) return undefined;
          volumes.push(target);
        }
        volumes.sort();
      }
      const rawEnvironment = config && typeof config === "object" ? Reflect.get(config, "Env") : undefined;
      if (rawEnvironment !== undefined && rawEnvironment !== null
        && (!Array.isArray(rawEnvironment) || rawEnvironment.some((entry) => typeof entry !== "string"))) {
        return undefined;
      }
      const environment: Record<string, string> = {};
      for (const entry of (rawEnvironment ?? []) as string[]) {
        const separator = entry.indexOf("=");
        const name = entry.slice(0, separator);
        const value = entry.slice(separator + 1);
        if (separator < 1
          || Object.hasOwn(environment, name)) return undefined;
        environment[name] = value;
      }
      const entries: Array<[string, string]> = [];
      if (rawLabels && typeof rawLabels === "object") {
        for (const [key, value] of Object.entries(rawLabels)) {
          if (typeof value !== "string") return undefined;
          entries.push([key, value]);
        }
      }
      if (typeof architecture !== "string" || architecture.length === 0
        || typeof os !== "string" || os.length === 0) return undefined;
      return {
        architecture,
        id,
        labels: Object.fromEntries(entries),
        os,
        ...(rawEnvironment !== undefined && rawEnvironment !== null ? { environment } : {}),
        ...(Array.isArray(rawOnBuild) ? { onBuild: [...rawOnBuild] as string[] } : {}),
        ...(rawVolumes !== undefined && rawVolumes !== null ? { volumes } : {}),
      };
    } catch {
      return undefined;
    }
  };
  return {
    assertAvailable() {
      dockerAvailable(context, io);
    },
    buildImage(args) {
      const status = client.terminal.build(args);
      imageInspectCache.clear();
      return status;
    },
    composeContainers(project) {
      return cachedComposeContainers(project);
    },
    composeDown(project) {
      const options = composeOptions();
      const status = createDockerClient(io, { ...options, env: composeTeardownEnv(composeFile(), options.env) })
        .terminal.compose(composeArgs(project, "down", ["--remove-orphans"]));
      clearRuntimeCaches();
      return status;
    },
    composeUp(project, options = {}) {
      const args = composeArgs(project, "up", ["-d"]);
      if (options.noDeps) args.push("--no-deps");
      if (options.forceRecreate) args.push("--force-recreate");
      if (options.removeOrphans ?? true) args.push("--remove-orphans");
      args.push(...(options.services ?? []));
      let overrideDirectory: string | undefined;
      try {
        if (options.creationMarker) {
          const { transactionId, attempt } = options.creationMarker;
          if (!/^[a-f0-9]{64}$/u.test(transactionId) || !Number.isSafeInteger(attempt) || attempt < 0
            || options.services?.length !== 1 || options.services[0] !== "proxy") {
            throw new Error("proxy creation requires an exact transaction marker and proxy-only service scope");
          }
          overrideDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-proxy-attempt-"));
          const override = path.join(overrideDirectory, "compose.yaml");
          fs.writeFileSync(override, `services:\n  proxy:\n    labels:\n      ${REBIND_TRANSACTION_LABEL}: '${transactionId}'\n      ${REBIND_ATTEMPT_LABEL}: '${attempt}'\n`, { mode: 0o600, flag: "wx" });
          args.splice(args.indexOf("up"), 0, "-f", override);
        }
        const status = createDockerClient(io, composeOptions()).terminal.compose(args);
        clearRuntimeCaches();
        return status;
      } finally {
        if (overrideDirectory) fs.rmSync(overrideDirectory, { recursive: true });
      }
    },
    createComposeManagedVolume(project, logicalName) {
      // `docker volume create` on an existing volume with matching driver is a
      // no-op that returns 0, so this is idempotent across reruns. It also
      // fails closed on a name that already exists under a non-local driver.
      const name = `${project}_${logicalName}`;
      const created = client.createVolume(name, [
        `com.docker.compose.project=${project}`,
        `com.docker.compose.volume=${logicalName}`,
      ]);
      if (created.status !== 0) return created.status;
      // Create reuses a same-driver volume and does NOT apply the requested
      // labels, so a pre-placed local-driver bind mount (Options set) passes the
      // create above. The dependency-volume ownership step chowns some of these
      // before the per-session named-volume proof runs, so validate the exact
      // shape now and fail closed on anything that is not a plain, correctly
      // labelled, optionless local volume.
      const inspected = client.inspect([name], { type: "volume" });
      if (inspected.status !== 0) {
        warn(`refusing session volume ${name}: inspection failed`);
        return inspected.status;
      }
      try {
        assertComposeManagedLocalVolume(inspected.stdout, { name, logicalName, composeProject: project });
      } catch (error) {
        warn(`refusing session volume ${name}: ${error instanceof Error ? error.message : String(error)}`);
        return 1;
      }
      return 0;
    },
    destroyProject(project) {
      // Compose-owned teardown only. Session containers carry no Compose label
      // and are therefore invisible to `--remove-orphans`; the fenced sequence
      // in `destroy.ts` revokes and removes them by record-bound id around
      // this call, and it is the only production caller.
      const options = composeOptions();
      const status = createDockerClient(io, { ...options, env: composeTeardownEnv(composeFile(), options.env) })
        .terminal.compose(composeArgs(project, "down", ["-v", "--rmi", "local", "--remove-orphans"]));
      clearRuntimeCaches();
      if (status !== 0) return status;
      return removeProjectSessionVolumes(project);
    },
    followLogs(project, service) {
      return createDockerClient(io, composeOptions()).terminal.compose(composeArgs(project, "logs", ["-f", service]));
    },
    imageExists(tag) {
      return client.inspect([tag], { type: "image" }).status === 0;
    },
    inspectImage(tag, options = {}) {
      if (options.fresh === true) return inspectImageUncached(tag);
      if (imageInspectCache.has(tag)) return imageInspectCache.get(tag);
      const image = inspectImageUncached(tag);
      imageInspectCache.set(tag, image);
      return image;
    },
    imageRefs(reference) {
      const result = client.listObjects("image", { format: "{{.Repository}}:{{.Tag}}", reference });
      if (result.status !== 0) {
        const detail = result.stderr.trim();
        warn(`could not list Docker images for cleanup${detail ? `: ${detail}` : ""}`);
        return [];
      }
      return result.stdout.trim().split(/\s+/).filter((ref) => ref && ref !== "<none>:<none>");
    },
    networkSubnets() {
      return dockerNetworkSubnets(context, io);
    },
    pruneImages(filters) {
      const status = client.terminal.pruneImages(filters);
      imageInspectCache.clear();
      return status;
    },
    projectForWorkspace() {
      return composeProject(context, io);
    },
    proxyControlReceipts(project) {
      const proxyId = cachedServiceContainerId(project, "proxy", { runningOnly: true });
      if (!proxyId) return undefined;
      return readProxyControlReceipts(context, io, proxyId);
    },
    activeAgentSessions(project) {
      return activeAgentSessionsForProject(project);
    },
    removeContainers(ids) {
      if (ids.length === 0) return 0;
      const status = client.terminal.removeContainers(ids, { force: true });
      clearRuntimeCaches();
      return status;
    },
    removeImages(refs) {
      if (refs.length === 0) return 0;
      const status = client.terminal.removeImages(refs);
      imageInspectCache.clear();
      return status;
    },
    runtimeContainers(project) {
      return cachedRuntimeContainers(project);
    },
    runningServiceContainerId(project, service) {
      return cachedServiceContainerId(project, service, { runningOnly: true });
    },
    serviceContainerIds(project, service, options = {}) {
      return serviceContainerIds(project, service, context, io, options);
    },
    serviceContainerId(project, service) {
      return cachedServiceContainerId(project, service);
    },
    containerRunning(containerId) {
      if (!/^[a-f0-9]{64}$/u.test(containerId)) return false;
      const result = client.inspect([containerId], { type: "container", format: "{{.State.Running}}" });
      return result.status === 0 && result.stdout.trim() === "true";
    },
    setProxyVerboseMarker(proxyId, markerName) {
      setProxyVerboseMarker(proxyId, markerName, context, io);
    },
    clearProxyVerboseMarker(proxyId, markerName) {
      clearProxyVerboseMarker(proxyId, markerName, context, io);
    },
    resources(project = composeProjectName(context.projectRoot)) {
      return projectResourceSummary(context, io, project);
    },
    status(project = composeProjectName(context.projectRoot)) {
      const listing = captureDockerListing(client, {
        all: true,
        filters: filterValues(corroboratedComposeProjectContainerFilters(projectHash(context.projectRoot), project)),
      }, "containers");
      if (listing.status !== 0) return listing.status;
      if (listing.rows.length === 0) {
        console.log("no containers");
        return 0;
      }
      console.log(renderDockerListing([
        { label: "NAME", value: (row) => row.Names },
        { label: "STATUS", value: (row) => row.Status },
        { label: "IMAGE", value: (row) => row.Image },
      ], listing.rows));
      return 0;
    },
    tagImage(source, target) {
      const status = client.terminal.tagImage(source, target);
      imageInspectCache.clear();
      return status;
    },
  };
}

function dockerInspectFailure(message: string, result: CaptureResult): never {
  const detail = result.stderr.trim();
  die(`${message}${detail ? `: ${detail}` : ""}`);
}

function dockerLabelValue(value: unknown): string | undefined {
  const trimmed = typeof value === "string" ? value.trim() : undefined;
  if (!trimmed || trimmed === "<no value>") return undefined;
  return trimmed;
}

export function runtimeContainerInspectFormat(): string {
  return [
    "{{.Id}}",
    '{{ index .Config.Labels "com.docker.compose.service" }}',
    `{{ index .Config.Labels "${RUNFREE_DIGEST_SCHEMA_LABEL}" }}`,
    `{{ index .Config.Labels "${AGENT_IMAGE_INPUT_DIGEST_LABEL}" }}`,
    `{{ index .Config.Labels "${PROXY_IMAGE_INPUT_DIGEST_LABEL}" }}`,
    `{{ index .Config.Labels "${TOPOLOGY_DIGEST_LABEL}" }}`,
    `{{ index .Config.Labels "${RUNTIME_DIGEST_LABEL}" }}`,
    "{{.Config.Image}}",
    "{{.State.Running}}",
    `{{ index .Config.Labels "${PROJECT_ID_LABEL}" }}`,
    '{{ index .Config.Labels "com.docker.compose.project" }}',
  ].join("\t");
}

export function parseRuntimeContainerInspectRows(output: string): RuntimeContainer[] {
  return output.trim().split(/\n+/).filter(Boolean).map((line) => {
    const fields = line.split("\t");
    if (fields.length === 3) {
      const [id, service, runtimeDigest] = fields;
      return {
        id,
        service: dockerLabelValue(service) ?? "",
        runtimeDigest: dockerLabelValue(runtimeDigest),
      };
    }
    const [
      id,
      service,
      digestSchemaVersion,
      agentImageInputDigest,
      proxyImageInputDigest,
      topologyDigest,
      runtimeDigest,
      imageRef,
      running,
      projectId,
      composeProject,
    ] = fields;
    return {
      id,
      service: dockerLabelValue(service) ?? "",
      digestSchemaVersion: dockerLabelValue(digestSchemaVersion),
      agentImageInputDigest: dockerLabelValue(agentImageInputDigest),
      proxyImageInputDigest: dockerLabelValue(proxyImageInputDigest),
      topologyDigest: dockerLabelValue(topologyDigest),
      runtimeDigest: dockerLabelValue(runtimeDigest),
      imageRef: dockerLabelValue(imageRef),
      projectId: dockerLabelValue(projectId),
      composeProject: dockerLabelValue(composeProject),
      ...(running === "true" ? { running: true } : running === "false" ? { running: false } : {}),
    };
  });
}

// Deliberately the Compose set, not the whole project: the upgrade classifier
// reasons about the agent/proxy/callback composition, and a session container
// appearing here would read as a duplicated participant. Whole-project
// enumeration keys on `io.runfree.project-id` instead (see `destroy.ts`).
function runtimeContainers(project: string, context: RuntimeContext, io: RuntimeIO): RuntimeContainer[] {
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const ps = client.listContainers({ all: true, quiet: true, filters: filterValues(composeProjectContainerFilters(project)) });
  if (ps.status !== 0) dockerInspectFailure("could not inspect Runfree runtime containers", ps);
  const ids = ps.stdout.trim().split(/\s+/).filter(Boolean);
  if (ids.length === 0) return [];

  const inspect = client.inspect(ids, { format: runtimeContainerInspectFormat() });
  if (inspect.status !== 0) dockerInspectFailure("could not inspect Runfree runtime container labels", inspect);
  return parseRuntimeContainerInspectRows(inspect.stdout);
}

function composeContainers(project: string, context: RuntimeContext, io: RuntimeIO): ComposeContainer[] {
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const ps = client.listContainers({ all: true, quiet: true, filters: filterValues(composeProjectContainerFilters(project)) });
  const ids = ps.stdout.trim().split(/\s+/).filter(Boolean);
  if (ps.status !== 0 || ids.length === 0) return [];
  const inspect = client.inspect(ids, { format: "{{.Id}}\t{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}" });
  if (inspect.status !== 0) return ids.map((id) => ({ id, networks: [] }));
  return inspect.stdout.trim().split(/\n+/).filter(Boolean).map((line) => {
    const [id, networkList = ""] = line.split("\t");
    return {
      id,
      networks: networkList.trim().split(/\s+/).filter(Boolean),
    };
  });
}

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

export function parseDockerJson<T>(result: CaptureResult, label: string): T | undefined {
  if (result.status !== 0) {
    const detail = compactDiagnostic(result.stderr);
    warn(`${label} failed${detail ? `: ${detail}` : ""}`);
    return undefined;
  }
  try {
    return JSON.parse(result.stdout) as T;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    warn(`${label} returned invalid JSON: ${detail}`);
    return undefined;
  }
}

function composeProject(context: RuntimeContext, io: RuntimeIO): string | undefined {
  const project = composeProjectName(context.projectRoot);
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const ps = client.listContainers({
    all: true,
    quiet: true,
    filters: filterValues(corroboratedComposeProjectContainerFilters(projectHash(context.projectRoot), project)),
  });
  const agentId = ps.stdout.trim().split(/\s+/).filter(Boolean)[0];
  if (!agentId) return undefined;
  const inspect = client.inspect([agentId], { format: "{{ index .Config.Labels \"com.docker.compose.project\" }}" });
  const inspectedProject = inspect.stdout.trim();
  if (inspect.status !== 0 || inspectedProject === "" || inspectedProject === "<no value>") return undefined;
  return inspectedProject;
}

function composeServiceFilters(project: string, service: string): string[] {
  return composeServiceContainerFilters(project, service);
}

// `--no-trunc` is load-bearing, not cosmetic: `docker ps -q` prints the
// 12-character short ID, and the runtime validation marker, the deny-by-default
// base observation, and effective control-plane selection all bind the exact
// 64-hex Docker container identity. A truncated ID is a prefix, not an
// identity, so it must never enter those proofs.
export function serviceContainerId(
  project: string,
  service: string,
  context: RuntimeContext,
  io: RuntimeIO,
  options: { runningOnly?: boolean } = {},
): string | undefined {
  return serviceContainerIds(project, service, context, io, options)[0];
}

export function serviceContainerIds(
  project: string,
  service: string,
  context: RuntimeContext,
  io: RuntimeIO,
  options: { runningOnly?: boolean } = {},
): string[] {
  const ps = createDockerClient(io, dockerClientEnvOptions(context)).listContainers({
    all: !options.runningOnly,
    quiet: true,
    noTrunc: true,
    filters: filterValues(composeServiceFilters(project, service)),
  });
  if (ps.status !== 0) return [];
  return ps.stdout.trim().split(/\s+/).filter(Boolean);
}

export function serviceContainerName(
  project: string,
  service: string,
  context: RuntimeContext,
  io: RuntimeIO,
  options: { runningOnly?: boolean } = {},
): string | undefined {
  const ps = createDockerClient(io, dockerClientEnvOptions(context)).listContainers({
    all: !options.runningOnly,
    filters: filterValues(composeServiceFilters(project, service)),
    format: "{{.Names}}",
  });
  if (ps.status !== 0) return undefined;
  return ps.stdout.trim().split(/\s+/).filter(Boolean)[0];
}

export function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function setProxyVerboseMarker(proxyId: string, markerName: string, context: RuntimeContext, io: RuntimeIO): void {
  const markerDir = "/run/runfree-proxy-verbose";
  const markerPath = `${markerDir}/${markerName}`;
  const command = `mkdir -p ${shellSingleQuote(markerDir)} && : > ${shellSingleQuote(markerPath)}`;
  const result = createDockerClient(io, dockerClientEnvOptions(context))
    .exec(proxyId, ["sh", "-c", command], { user: ROOT_UID_GID });
  if (result.status !== 0) die(result.stderr.trim() || "failed to enable proxy verbose logs");
}

function clearProxyVerboseMarker(proxyId: string, markerName: string, context: RuntimeContext, io: RuntimeIO): void {
  const markerPath = `/run/runfree-proxy-verbose/${markerName}`;
  createDockerClient(io, dockerClientEnvOptions(context))
    .exec(proxyId, ["sh", "-c", `rm -f ${shellSingleQuote(markerPath)}`], { user: ROOT_UID_GID });
}

function dockerNetworkInspection(context: RuntimeContext, io: RuntimeIO): string {
  const client = createDockerClient(io, dockerClientEnvOptions(context));
  const maxAttempts = 3;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const list = client.listObjects("network", { quiet: true });
    if (list.status !== 0) {
      const detail = list.stderr.trim();
      die(`could not inspect Docker networks${detail ? `: ${detail}` : ""}`);
    }
    const ids = list.stdout.trim().split(/\s+/).filter(Boolean);
    if (ids.length === 0) return "[]";
    const inspect = client.inspect(ids, { type: "network" });
    if (inspect.status === 0) return inspect.stdout;

    const detail = inspect.stderr.trim();
    const onlyMissingListedNetworks = detail.length > 0 && detail.split(/\r?\n/).every((line) => {
      const match = /^Error response from daemon: network (\S+) not found$/u.exec(line.trim());
      return match !== null && ids.includes(match[1]);
    });
    if (!onlyMissingListedNetworks) {
      die(`could not inspect Docker networks${detail ? `: ${detail}` : ""}`);
    }
    // Other projects can remove networks between list and inspect. Discard
    // partial stdout and rediscover all networks, including any newly created
    // ones, before allocating a subnet. Never turn an inspection error into
    // an empty inventory or retry unrelated daemon failures.
    if (attempt === maxAttempts - 1) {
      die(`could not inspect Docker networks after ${maxAttempts} attempts: ${detail}; retry startup after Docker network changes settle`);
    }
  }
  die("could not inspect Docker networks");
}

function dockerNetworkSubnets(context: RuntimeContext, io: RuntimeIO): string[] {
  const inspection = dockerNetworkInspection(context, io);
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspection);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    die(`could not parse Docker network inspection${detail ? `: ${detail}` : ""}`);
  }
  if (!Array.isArray(parsed)) {
    die("could not parse Docker network inspection: expected an array");
  }
  const networks = parsed as DockerNetworkInspect[];
  const project = composeProjectName(context.projectRoot);
  const ownRuntimeNetworks = new Set([`${project}_agent_internal`, `${project}_proxy_egress`]);
  return networks
    .filter((network) => !ownRuntimeNetworks.has(network.Name ?? ""))
    .flatMap((network) => network.IPAM?.Config
      ?.map((config) => config.Subnet)
      .filter((subnet): subnet is string => Boolean(subnet)) ?? []);
}

export function readProxyControlReceipts(context: RuntimeContext, io: RuntimeIO, proxyId: string): { firewall?: ParsedGenerationStatus; requestProxy?: ParsedGenerationStatus } | undefined {
  const script = [firewallStatusPath(), requestProxyStatusPath()]
    .map((file) => `if [ -f ${shellSingleQuote(file)} ]; then cat ${shellSingleQuote(file)}; else printf '{}'; fi; echo`)
    .join("; ");
  const result = createDockerClient(io, dockerClientEnvOptions(context)).exec(proxyId, ["sh", "-c", script]);
  if (result.status !== 0) return undefined;
  const lines = result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length !== 2) return undefined;
  return {
    firewall: parseGenerationStatusLine(lines[0]),
    requestProxy: parseGenerationStatusLine(lines[1]),
  };
}
