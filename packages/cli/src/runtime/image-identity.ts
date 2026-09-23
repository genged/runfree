import {
  AGENT_BASE_IMAGE_ROLE,
  AGENT_PROJECT_IMAGE_ROLE,
  AGENT_RUNTIME_IMAGE_ROLE,
  PROJECT_ID_LABEL,
  PROXY_RUNTIME_IMAGE_ROLE,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_DIGEST_SCHEMA_VERSION,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_MANAGED_IMAGE_LABEL,
} from "./constants.ts";
import type { RuntimeDocker } from "./docker.ts";

export type ManagedImageRole =
  | typeof AGENT_BASE_IMAGE_ROLE
  | typeof AGENT_PROJECT_IMAGE_ROLE
  | typeof AGENT_RUNTIME_IMAGE_ROLE
  | typeof PROXY_RUNTIME_IMAGE_ROLE;

export type ManagedImageExpectation = {
  inputDigest: string;
  projectId?: string;
  roles: readonly [ManagedImageRole, ...ManagedImageRole[]];
};

export type VerifiedManagedImage = {
  environment?: Record<string, string>;
  id: string;
  labels: Record<string, string>;
  onBuild?: string[];
  tag: string;
  volumes?: string[];
};

const COMPLETE_INPUT_DIGEST = /^sha256:[a-f0-9]{64}$/;
const IMMUTABLE_IMAGE_ID = /^sha256:[a-f0-9]{64}$/;

export function inspectReusableManagedImage(
  docker: Pick<RuntimeDocker, "inspectImage">,
  tag: string,
  expected: ManagedImageExpectation,
  // `fresh` must be set by call sites whose claim is temporal (a ref-then-id
  // cross-check), where the L5a memo would satisfy the check with a stale
  // ref→id binding. Discovery reads may share the memo.
  options: { fresh?: boolean } = {},
): VerifiedManagedImage | undefined {
  if (!COMPLETE_INPUT_DIGEST.test(expected.inputDigest)) return undefined;
  const image = docker.inspectImage(tag, options);
  if (!image || !IMMUTABLE_IMAGE_ID.test(image.id)) return undefined;
  const labels = image.labels;
  if (labels[RUNFREE_MANAGED_IMAGE_LABEL] !== "true") return undefined;
  if (labels[RUNFREE_DIGEST_SCHEMA_LABEL] !== RUNFREE_DIGEST_SCHEMA_VERSION) return undefined;
  if (labels[RUNFREE_IMAGE_INPUT_DIGEST_LABEL] !== expected.inputDigest) return undefined;
  if (!expected.roles.some((role) => labels[RUNFREE_IMAGE_ROLE_LABEL] === role)) return undefined;
  if (expected.projectId !== undefined && labels[PROJECT_ID_LABEL] !== expected.projectId) return undefined;
  return {
    ...(image.environment ? { environment: { ...image.environment } } : {}),
    id: image.id,
    labels,
    ...(image.onBuild ? { onBuild: [...image.onBuild] } : {}),
    tag,
    ...(image.volumes ? { volumes: [...image.volumes] } : {}),
  };
}

export function reusableManagedImage(
  docker: Pick<RuntimeDocker, "inspectImage">,
  tag: string,
  expected: ManagedImageExpectation,
): boolean {
  return inspectReusableManagedImage(docker, tag, expected) !== undefined;
}
