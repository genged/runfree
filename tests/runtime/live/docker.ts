// Docker helpers shared by the live runtime tranches.
//
// These are deliberately thin: each one runs the real CLI and fails with the
// command's own output rather than a rephrased expectation. A live failure that
// prints only what the test wanted is uninterpretable, and every blind cycle
// here costs a full rebuild.
//
// Nothing in this module derives project identity, image references, or network
// names by recomputing a product rule. Each is asked of the product or of the
// daemon, so a test cannot keep passing after the real derivation changes.

import childProcess from "node:child_process";
import { countObserverDockerCall } from "./timing.ts";

import {
  AGENT_PROJECT_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
} from "../../../packages/cli/src/runtime/constants.ts";
import { describeOutput, type CaptureResult, type LiveFixture } from "./fixture.ts";

const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

export function docker(args: readonly string[]): CaptureResult {
  countObserverDockerCall();
  const result = childProcess.spawnSync("docker", [...args], {
    encoding: "utf8",
    maxBuffer: CAPTURE_MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const stderr = typeof result.stderr === "string" ? result.stderr : "";
  return Object.freeze({ status: result.status ?? 1, stdout, stderr, output: `${stdout}${stderr}` });
}

export function dockerOrThrow(label: string, args: readonly string[]): string {
  const result = docker(args);
  if (result.status !== 0) {
    throw new Error(`${label}: docker ${args.join(" ")} failed: ${describeOutput(result.output)}`);
  }
  return result.stdout.trim();
}

/** Asked of the product: a test that recomputes project identity drifts silently. */
export function composeProjectName(fixture: LiveFixture): string {
  const result = fixture.runfree(["project-id", "--compose-name"]);
  if (result.status !== 0) {
    throw new Error(`could not read the Compose project name: ${describeOutput(result.output)}`);
  }
  const name = result.stdout.trim();
  if (!name) throw new Error("the Compose project name was empty");
  return name;
}

/**
 * Resolves the project's internal network by its Compose labels.
 *
 * Matching on the label pair rather than on a rendered name keeps this correct
 * if Compose changes how it joins project and network names, and keeps it from
 * ever selecting another project's network.
 */
export function internalNetworkId(project: string): string {
  const ids = dockerOrThrow("internal network lookup", [
    "network",
    "ls",
    // Without this, `docker network ls` prints the 12-character short id, while
    // `.NetworkSettings.Networks[].NetworkID` on a container is the full 64-hex
    // form — so every comparison against it silently finds nothing. This is the
    // same truncation defect that reached a live daemon twice in `docker ps -q`
    // lookups, and it presented here identically: "attached to 0 endpoints" on
    // a container that was plainly attached.
    "--no-trunc",
    "--filter",
    `label=com.docker.compose.project=${project}`,
    "--filter",
    "label=com.docker.compose.network=agent_internal",
    "--format",
    "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
  if (ids.length !== 1) {
    throw new Error(`expected exactly one agent_internal network for ${project}, found ${ids.length}`);
  }
  if (!/^[a-f0-9]{64}$/u.test(ids[0])) {
    throw new Error(`agent_internal network id is not the exact 64-hex identity: ${ids[0]}`);
  }
  return ids[0];
}

export function composeServiceContainerId(project: string, service: string): string {
  const ids = dockerOrThrow(`${service} container lookup`, [
    "ps",
    "--no-trunc",
    "--filter",
    `label=com.docker.compose.project=${project}`,
    "--filter",
    `label=com.docker.compose.service=${service}`,
    "--format",
    "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
  if (ids.length !== 1) {
    throw new Error(`expected exactly one running ${service} container for ${project}, found ${ids.length}`);
  }
  // Production reads identity from `.Id` and every strict consumer binds the
  // full 64-hex form. `--no-trunc` above produces it at the source; this refuses
  // anything else rather than letting a short id surface later as an
  // unexplained mismatch, which is exactly how two live defects presented.
  if (!/^[a-f0-9]{64}$/u.test(ids[0])) {
    throw new Error(`${service} container id is not the exact 64-hex identity: ${ids[0]}`);
  }
  return ids[0];
}

export function containerImageRef(containerId: string): string {
  return dockerOrThrow("container image lookup", ["inspect", "-f", "{{.Config.Image}}", containerId]);
}

/**
 * Reads a container's address on one exact network.
 *
 * Keyed by network id rather than by the map's key, because the key is a
 * rendered network name and the id is what every strict consumer binds.
 */
export function containerAddressOnNetwork(containerId: string, networkId: string): string {
  const json = dockerOrThrow("container network settings", [
    "inspect",
    "-f",
    "{{json .NetworkSettings.Networks}}",
    containerId,
  ]);
  const networks = JSON.parse(json) as Record<string, { NetworkID?: string; IPAddress?: string }>;
  const matches = Object.values(networks).filter((entry) => entry.NetworkID === networkId);
  if (matches.length !== 1) {
    throw new Error(`container ${containerId.slice(0, 12)} is attached to ${matches.length} endpoints on that network`);
  }
  const ip = matches[0].IPAddress;
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/u.test(ip)) {
    throw new Error(`container ${containerId.slice(0, 12)} has no IPv4 address on that network`);
  }
  return ip;
}

/**
 * Removes a container the tranche created, tolerating every state.
 *
 * Cleanup must never be the thing that fails a run: a rogue container left on
 * the internal network holds it open, so `runfree destroy` cannot remove the
 * network and the next run meets an exhausted address pool with no explanation.
 */
export function forceRemoveContainer(nameOrId: string): void {
  docker(["rm", "-f", nameOrId]);
}

/**
 * The label every container this module creates carries.
 *
 * Deliberately outside the `io.runfree.` namespace. Session reconciliation
 * treats *any* `io.runfree.*` label as a hint that a container is Runfree's
 * (`session-container-reconciliation.ts`, `managedHint`), so a test container
 * labelled `io.runfree.test` is pulled into the session inventory and correctly
 * refused as an untrusted container — which wedges recovery and makes the test
 * fail for a reason it did not intend to create. Found exactly that way.
 */
export const LIVE_TEST_LABEL = "runfree-livetest";

export type LiveTestContainerOptions = Readonly<{
  name: string;
  image: string;
  networkId: string;
  /** Extra `docker run` arguments placed before the image reference. */
  runArgs?: readonly string[];
  command: readonly string[];
}>;

/**
 * Starts a detached container carrying this tranche's label.
 *
 * Every container this module creates is labelled so a maintainer can find and
 * reclaim leftovers by label alone, without pattern-matching names.
 */
export function startLiveTestContainer(options: LiveTestContainerOptions): string {
  const id = dockerOrThrow(`start ${options.name}`, [
    "run",
    "-d",
    "--name",
    options.name,
    "--label",
    `${LIVE_TEST_LABEL}=session-admission-negative`,
    "--network",
    options.networkId,
    ...(options.runArgs ?? []),
    options.image,
    ...options.command,
  ]);
  return id;
}

export type WaitOptions = Readonly<{
  label: string;
  timeoutMs: number;
  intervalMs?: number;
}>;

/**
 * Polls until a predicate holds, then returns. Bounded and always explains the
 * timeout in terms of what it was waiting for.
 */
export function waitUntil(predicate: () => boolean, options: WaitOptions): void {
  const interval = options.intervalMs ?? 500;
  const deadline = Date.now() + options.timeoutMs;
  let lastFailure: unknown;
  for (;;) {
    try {
      if (predicate()) return;
      lastFailure = undefined;
    } catch (failure) {
      lastFailure = failure;
    }
    if (Date.now() >= deadline) {
      const detail = lastFailure instanceof Error ? `: ${lastFailure.message}` : "";
      throw new Error(`timed out after ${options.timeoutMs}ms waiting for ${options.label}${detail}`);
    }
    // Synchronous sleep: these tranches run in a fork whose Docker calls are
    // synchronous anyway, and an async poll here would interleave with nothing.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, interval);
  }
}

/**
 * The built project agent image, resolved by its daemon labels.
 *
 * The cutover removed the shared `agent` Compose service, so its image is no
 * longer discoverable through a running container. The project agent image is
 * still tagged with the exact role and project-id labels the product sets at
 * build time, so it is asked of the daemon by those — scoped to this project,
 * never recomputing the tag — rather than through a container that no longer
 * exists. A per-session container runs this same image, so a test container
 * built from it still behaves like an admitted session.
 */
export function projectAgentImageId(project: string): string {
  const projectId = project.replace(/^runfree-/u, "");
  const ids = [...new Set(dockerOrThrow("project agent image lookup", [
    "images", "--no-trunc",
    "--filter", `label=${RUNFREE_IMAGE_ROLE_LABEL}=${AGENT_PROJECT_IMAGE_ROLE}`,
    "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`,
    "--format", "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean))];
  if (ids.length !== 1) {
    throw new Error(`expected exactly one project agent image for ${project}, found ${ids.length}`);
  }
  return ids[0];
}
