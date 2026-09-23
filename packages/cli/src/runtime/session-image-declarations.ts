import path from "node:path";

import type { DockerImageInspect } from "./docker.ts";
import type { SessionContainerMount } from "./session-container-contract.ts";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const MAX_DECLARATION_COUNT = 512;
const MAX_ENVIRONMENT_VALUE_BYTES = 32 * 1024;
const MAX_ENVIRONMENT_TOTAL_BYTES = 128 * 1024;
const MAX_MOUNT_TARGET_BYTES = 4 * 1024;

declare const sessionImageDeclarationProofBrand: unique symbol;

export type SessionImageDeclarationProof = Readonly<{
  readonly [sessionImageDeclarationProofBrand]: true;
  version: 1;
  architecture: "amd64" | "arm64";
  os: "linux";
  selectedAgentImageId: string;
  declaredVolumeTargets: readonly string[];
  explicitMounts: readonly SessionContainerMount[];
  mergedEnvironment: Readonly<Record<string, string>>;
}>;

const validatedProofs = new WeakSet<object>();

function sortedUnique(values: readonly string[], label: string): string[] {
  if (!Array.isArray(values) || values.length > MAX_DECLARATION_COUNT) {
    throw new Error(`session image ${label} is not bounded`);
  }
  const sorted = [...values].sort();
  for (const value of sorted) {
    if (typeof value !== "string"
      || !value.startsWith("/")
      || path.posix.normalize(value) !== value
      || Buffer.byteLength(value, "utf8") > MAX_MOUNT_TARGET_BYTES
      || CONTROL_CHARACTER_PATTERN.test(value)) {
      throw new Error(`session image ${label} contains an invalid target`);
    }
  }
  if (sorted.some((value, index) => index > 0 && value === sorted[index - 1])) {
    throw new Error(`session image ${label} contains duplicate targets`);
  }
  return sorted;
}

function exactEnvironment(value: unknown, label: string): Record<string, string> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`session image ${label} is malformed`);
  }
  const entries = Object.entries(value);
  if (entries.length > MAX_DECLARATION_COUNT) throw new Error(`session image ${label} is not bounded`);
  let totalBytes = 0;
  for (const [name, entry] of entries) {
    if (!ENVIRONMENT_NAME_PATTERN.test(name)
      || typeof entry !== "string"
      || CONTROL_CHARACTER_PATTERN.test(entry)
      || Buffer.byteLength(entry, "utf8") > MAX_ENVIRONMENT_VALUE_BYTES) {
      throw new Error(`session image ${label} contains an invalid entry`);
    }
    totalBytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(entry, "utf8") + 1;
  }
  if (totalBytes > MAX_ENVIRONMENT_TOTAL_BYTES) throw new Error(`session image ${label} is not bounded`);
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

function exactMounts(mounts: readonly SessionContainerMount[]): readonly SessionContainerMount[] {
  if (!Array.isArray(mounts)) throw new Error("session image mount plan is malformed");
  const targets = sortedUnique(mounts.map((mount) => mount.target), "mount plan");
  const mountsByTarget = new Map(mounts.map((mount) => [mount.target, mount]));
  return Object.freeze(targets.map((target) => {
    const mount = mountsByTarget.get(target);
    if (!mount
      || (mount.type !== "bind" && mount.type !== "volume")
      || typeof mount.source !== "string"
      || mount.source.length === 0
      || CONTROL_CHARACTER_PATTERN.test(mount.source)
      || typeof mount.readOnly !== "boolean"
      || typeof mount.noCopy !== "boolean") {
      throw new Error("session image mount plan contains an invalid mount");
    }
    return Object.freeze({ ...mount });
  }));
}

function sameMount(left: SessionContainerMount, right: SessionContainerMount): boolean {
  return left.type === right.type
    && left.source === right.source
    && left.target === right.target
    && left.readOnly === right.readOnly
    && left.noCopy === right.noCopy;
}

export function createSessionImageDeclarationProof(input: {
  image: DockerImageInspect;
  selectedAgentImageId: string;
  mounts: readonly SessionContainerMount[];
  environment: Readonly<Record<string, string>>;
}): SessionImageDeclarationProof {
  if (!SHA256_PATTERN.test(input.selectedAgentImageId)
    || input.image.id !== input.selectedAgentImageId) {
    throw new Error("session image declaration proof requires the exact selected image ID");
  }
  if (input.image.os !== "linux"
    || (input.image.architecture !== "amd64" && input.image.architecture !== "arm64")) {
    throw new Error("selected session image platform is unsupported");
  }
  const explicitMounts = exactMounts(input.mounts);
  const declaredVolumeTargets = sortedUnique(input.image.volumes ?? [], "volume declaration");
  const mountsByTarget = new Map(input.mounts.map((mount) => [mount.target, mount]));
  const unaccounted = declaredVolumeTargets.filter((target) => !mountsByTarget.has(target));
  if (unaccounted.length > 0) {
    throw new Error(`selected session image declares unaccounted volumes: ${unaccounted.join(", ")}`);
  }
  const copySeedingTargets = input.mounts
    .filter((mount) => mount.type === "volume" && !mount.noCopy)
    .map((mount) => mount.target)
    .sort();
  if (copySeedingTargets.length > 0) {
    throw new Error(
      `selected session image can seed persistent named volumes without nocopy: ${copySeedingTargets.join(", ")}`,
    );
  }
  const imageEnvironment = exactEnvironment(input.image.environment ?? {}, "environment declaration");
  const explicitEnvironment = exactEnvironment(input.environment, "explicit environment plan");
  const mergedEnvironment = exactEnvironment({
    ...imageEnvironment,
    ...explicitEnvironment,
  }, "merged environment plan");
  const proof = Object.freeze({
    version: 1 as const,
    architecture: input.image.architecture,
    os: input.image.os,
    selectedAgentImageId: input.selectedAgentImageId,
    declaredVolumeTargets: Object.freeze(declaredVolumeTargets),
    explicitMounts,
    mergedEnvironment: Object.freeze(mergedEnvironment),
  }) as SessionImageDeclarationProof;
  validatedProofs.add(proof);
  return proof;
}

export function assertSessionImageDeclarationProof(
  proof: unknown,
  expected: {
    selectedAgentImageId: string;
    mounts: readonly SessionContainerMount[];
    environment: Readonly<Record<string, string>>;
  },
): asserts proof is SessionImageDeclarationProof {
  if (proof === null || typeof proof !== "object" || !validatedProofs.has(proof)) {
    throw new Error("session image declarations were not proven by the canonical preflight");
  }
  const parsed = proof as SessionImageDeclarationProof;
  const expectedMounts = exactMounts(expected.mounts);
  if (parsed.selectedAgentImageId !== expected.selectedAgentImageId
    || parsed.explicitMounts.length !== expectedMounts.length
    || parsed.explicitMounts.some((mount, index) => !sameMount(mount, expectedMounts[index]))) {
    throw new Error("session image declaration proof belongs to a different create plan");
  }
  for (const [name, value] of Object.entries(expected.environment)) {
    if (parsed.mergedEnvironment[name] !== value) {
      throw new Error("session image declaration proof belongs to a different environment plan");
    }
  }
}
