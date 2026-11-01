// Topology proof for the Engine host-service relay (`host_relay` Compose
// service, `packages/proxy/src/host-relay.ts`).
//
// On Docker Engine the relay must exist with exactly its hardened shape: the
// proxy image and entrypoint, the host network namespace, a non-root user,
// every capability dropped, no-new-privileges, a read-only root filesystem,
// bounded pids, the managed labels of this runtime's Compose generation, the
// daemon gateway entry the proxy also carries, one read-only mount (the
// effective policy directory), and exactly the runtime addresses the relay
// reads from its environment (above all `RUNFREE_PROXY_EGRESS_IP`, the one
// source it admits). On Docker Desktop, and on any backend without the relay,
// it must be absent. Judged from `docker inspect` of the running container,
// never from the Compose file.

import type { HostServiceRelayMode } from "../docker-backend.ts";
import { HOST_RELAY_COMPOSE_SERVICE } from "../docker-backend.ts";
import type { RuntimeNetwork } from "../network.ts";
import { remedy } from "../remedies.ts";
import { composeServiceContainerFilters } from "./container-inventory.ts";
import type { DockerClient } from "./docker-client.ts";
import type { DockerContainerInspect } from "./types.ts";

export const HOST_RELAY_USER = "65534:65534";
export const HOST_RELAY_COMMAND = ["node", "/app/proxy/host-relay.js"] as const;
export const HOST_RELAY_EFFECTIVE_TARGET = "/app/runfree-effective";
export const HOST_RELAY_MAX_PIDS = 64;
export const HOST_RELAY_ROLE = "host-relay";

/**
 * Labels the relay shares with the proxy of the same Compose generation
 * (compose.yaml). Both come from one `compose up`, so a relay left over from
 * another generation, version, or proxy image does not match.
 */
export const HOST_RELAY_GENERATION_LABELS = [
  "io.runfree.proxy-image-input-digest",
  "io.runfree.topology-digest",
  "io.runfree.version",
] as const;

/**
 * Environment names that change how node or the loader runs the relay. None
 * is set by compose.yaml or the proxy image; a relay carrying one is not the
 * relay this runtime started.
 */
export const HOST_RELAY_FORBIDDEN_ENV = ["NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"] as const;

export type HostRelayNetwork = Pick<RuntimeNetwork, "proxyIp" | "subnet" | "proxyEgressIp" | "proxyEgressSubnet" | "proxyEgressGateway">;

export type HostRelayExpectation = Readonly<{
  mode: HostServiceRelayMode;
  projectId: string;
  composeProject: string;
  /** The proxy container: the relay must run the same image and entrypoint and carry its generation labels. */
  proxy: DockerContainerInspect;
  /** The host's effective proxy directory, mounted read-only. */
  effectiveProxyDir: string;
  /** The exact `ExtraHosts` the proxy carries. */
  extraHosts: readonly string[];
  /** The runtime plan's addresses: the relay's environment must name exactly these. */
  network: HostRelayNetwork;
}>;

/** The exact `RUNFREE_*` environment the relay must carry (compose.yaml `host_relay.environment`). */
export function expectedHostRelayEnvironment(network: HostRelayNetwork): Readonly<Record<string, string>> {
  return {
    RUNFREE_EFFECTIVE_PROXY_ROOT: HOST_RELAY_EFFECTIVE_TARGET,
    RUNFREE_PROXY_IP: network.proxyIp,
    RUNFREE_SUBNET: network.subnet,
    RUNFREE_PROXY_EGRESS_IP: network.proxyEgressIp,
    RUNFREE_PROXY_EGRESS_SUBNET: network.proxyEgressSubnet,
    RUNFREE_PROXY_EGRESS_GATEWAY: network.proxyEgressGateway,
  };
}

const DOCKER_ID = /^[a-f0-9]{64}$/u;

/**
 * Every container of this project's `host_relay` Compose service, stopped or
 * running, by exact id; undefined when the lookup failed or answered anything
 * but exact ids. Never "absent" on a failed lookup: the absence proof on
 * Desktop and the single-relay proof on Engine both depend on it.
 */
export function lookupHostRelayContainerIds(client: Pick<DockerClient, "listContainers">, composeProject: string): string[] | undefined {
  const filters: string[] = [];
  const pairs = composeServiceContainerFilters(composeProject, HOST_RELAY_COMPOSE_SERVICE);
  for (let index = 1; index < pairs.length; index += 2) filters.push(pairs[index] as string);
  const ps = client.listContainers({ all: true, quiet: true, noTrunc: true, filters });
  if (ps.status !== 0) return undefined;
  const ids = ps.stdout.split(/\s+/u).filter(Boolean);
  if (ids.some((id) => !DOCKER_ID.test(id))) return undefined;
  return [...new Set(ids)];
}

function list(value: readonly string[] | null | undefined): string[] {
  return Array.isArray(value) ? [...value] : [];
}

function entrypoint(container: DockerContainerInspect): string[] {
  const value = container.Config?.Entrypoint;
  if (typeof value === "string") return [value];
  return list(value);
}

function sameList(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

/** Issues (each starting "host relay") with the relay's environment, or []. */
function environmentIssues(env: readonly string[] | null | undefined, network: HostRelayNetwork): string[] {
  const issues: string[] = [];
  const expected = expectedHostRelayEnvironment(network);
  const seen = new Map<string, string[]>();
  for (const entry of list(env)) {
    const separator = entry.indexOf("=");
    if (separator < 1) {
      issues.push("host relay environment has a malformed entry");
      continue;
    }
    const name = entry.slice(0, separator);
    const values = seen.get(name) ?? [];
    values.push(entry.slice(separator + 1));
    seen.set(name, values);
  }
  for (const [name, value] of Object.entries(expected)) {
    const values = seen.get(name) ?? [];
    if (values.length === 0) issues.push(`host relay environment is missing ${name}`);
    else if (values.length > 1) issues.push(`host relay environment sets ${name} more than once`);
    else if (values[0] !== value) issues.push(`host relay environment ${name} must be ${value}, not ${values[0]}`);
  }
  for (const name of seen.keys()) {
    if (name.startsWith("RUNFREE_") && !Object.hasOwn(expected, name)) issues.push(`host relay environment must not set ${name}`);
    if ((HOST_RELAY_FORBIDDEN_ENV as readonly string[]).includes(name)) issues.push(`host relay environment must not set ${name}`);
  }
  return issues;
}

/** Issues (each starting "host relay") for the observed relay, or [] when it is exactly right. */
export function hostRelayTopologyIssues(relay: DockerContainerInspect | undefined, expected: HostRelayExpectation): string[] {
  const rebuild = `run \`${remedy.rebuild()}\` to recreate the runtime`;
  if (expected.mode === "none") {
    return relay === undefined
      ? []
      : [`host relay container must not exist where Docker Desktop's host gateway serves host services; ${rebuild}`];
  }
  if (relay === undefined) return [`host relay container is missing on Docker Engine; ${rebuild}`];
  const issues: string[] = [];
  const host = relay.HostConfig ?? {};
  const config = relay.Config ?? {};
  const labels = config.Labels ?? {};
  const proxyLabels = expected.proxy.Config?.Labels ?? {};
  if (relay.State?.Running !== true) issues.push(`host relay container is ${relay.State?.Status ?? "not running"}`);
  if (relay.Image === undefined || relay.Image !== expected.proxy.Image) issues.push("host relay must run the proxy image");
  if (!sameList(entrypoint(relay), entrypoint(expected.proxy))) issues.push("host relay entrypoint must be the proxy image's");
  if (!sameList(list(config.Cmd), HOST_RELAY_COMMAND)) issues.push(`host relay command must be ${HOST_RELAY_COMMAND.join(" ")}`);
  if (config.User !== HOST_RELAY_USER) issues.push(`host relay must run as ${HOST_RELAY_USER}, not ${config.User || "<image default>"}`);
  if (host.NetworkMode !== "host") issues.push("host relay must use the host network namespace");
  if (host.Privileged === true) issues.push("host relay must not be privileged");
  if (list(host.CapAdd).length > 0) issues.push("host relay must add no capability");
  if (!list(host.CapDrop).some((capability) => capability.toUpperCase() === "ALL")) issues.push("host relay must drop ALL capabilities");
  if (host.ReadonlyRootfs !== true) issues.push("host relay must have a read-only root filesystem");
  if (!list(host.SecurityOpt).includes("no-new-privileges:true")) issues.push("host relay must set no-new-privileges");
  if (typeof host.PidsLimit !== "number" || !Number.isInteger(host.PidsLimit) || host.PidsLimit < 1 || host.PidsLimit > HOST_RELAY_MAX_PIDS) {
    issues.push(`host relay pids must be bounded to at most ${HOST_RELAY_MAX_PIDS}`);
  }
  const bindings = Object.values(host.PortBindings ?? {}).filter((binding) => binding !== null && binding !== undefined);
  if (bindings.length > 0) issues.push("host relay must not publish host ports");
  if (!sameList(list(host.ExtraHosts), expected.extraHosts)) {
    issues.push(`host relay ExtraHosts must be exactly ${expected.extraHosts.join(", ")}`);
  }
  if (labels["io.runfree.managed"] !== "true"
    || labels["io.runfree.container-role"] !== HOST_RELAY_ROLE
    || labels["io.runfree.project-id"] !== expected.projectId
    || labels["io.runfree.compose-project"] !== expected.composeProject
    || labels["io.runfree.lifecycle-owner"] !== "compose"
    || labels["io.runfree.label-schema"] !== "1"
    || labels["io.runfree.digest-schema"] !== "1"
    || labels["com.docker.compose.project"] !== expected.composeProject
    || labels["com.docker.compose.service"] !== HOST_RELAY_COMPOSE_SERVICE) {
    issues.push("host relay labels do not name this project's managed host-relay service");
  }
  for (const key of HOST_RELAY_GENERATION_LABELS) {
    const value = labels[key];
    if (typeof value !== "string" || value === "" || value !== proxyLabels[key]) {
      issues.push(`host relay label ${key} must match the proxy's`);
    }
  }
  issues.push(...environmentIssues(config.Env, expected.network));
  const mounts = relay.Mounts ?? [];
  const mount = mounts[0];
  if (mounts.length !== 1 || mount?.Type !== "bind" || mount.Destination !== HOST_RELAY_EFFECTIVE_TARGET
    || mount.RW !== false || mount.Source !== expected.effectiveProxyDir) {
    issues.push(`host relay must mount only the effective policy directory, read-only, at ${HOST_RELAY_EFFECTIVE_TARGET}`);
  }
  return issues;
}

/**
 * The relay proof from a lookup and (when exactly one relay exists) its
 * inspection. A failed lookup, more than one relay, or an inspection that is
 * not the looked-up container fails closed on every backend.
 */
export function hostRelayProofIssues(
  lookup: Readonly<{ ids: readonly string[] | undefined; relay: DockerContainerInspect | undefined }>,
  expected: HostRelayExpectation,
): string[] {
  if (lookup.ids === undefined) return ["host relay lookup failed; the relay's presence or absence is unproven"];
  if (lookup.ids.length > 1) return [`host relay containers must be at most one, found ${lookup.ids.length}`];
  if (lookup.ids.length === 1) {
    if (expected.mode === "none") return hostRelayTopologyIssues({ Id: lookup.ids[0] }, expected);
    if (lookup.relay === undefined) return ["host relay container could not be inspected"];
    if (lookup.relay.Id !== lookup.ids[0]) return ["host relay inspection is not the looked-up container"];
    return hostRelayTopologyIssues(lookup.relay, expected);
  }
  return hostRelayTopologyIssues(undefined, expected);
}
