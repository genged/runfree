import shippedLock from "./agent-image-lock.json" with { type: "json" };

/**
 * The published agent base images this CLI may pull instead of building.
 *
 * `agent-image-lock.json` maps a runtime agent image input digest (the
 * `sha256:` digest the local build would label its image with) to the GHCR
 * manifest digest CI published for it. The JSON is bundled into the CLI, so a
 * release can only pull what it shipped with. Only a digest from this lock
 * ever reaches `docker pull`: the pull reference type below is built here and
 * nowhere else, so a tag reference cannot be pulled.
 */
export const AGENT_IMAGE_REPOSITORY = "ghcr.io/genged/runfree-agent";

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;

declare const pinnedAgentImageReference: unique symbol;

/** `ghcr.io/genged/runfree-agent@sha256:<64 hex>`, built only from the lock. */
export type PinnedAgentImageReference = string & { readonly [pinnedAgentImageReference]: true };

export type AgentImageLock = Readonly<{
  repository: typeof AGENT_IMAGE_REPOSITORY;
  images: ReadonlyMap<string, string>;
}>;

export function parseAgentImageLock(value: unknown): AgentImageLock {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("agent image lock must be a JSON object");
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== "images" || keys[1] !== "repository") {
    throw new Error("agent image lock must have exactly the keys repository and images");
  }
  const repository: unknown = Reflect.get(value, "repository");
  if (repository !== AGENT_IMAGE_REPOSITORY) {
    throw new Error(`agent image lock repository must be ${AGENT_IMAGE_REPOSITORY}`);
  }
  const rawImages: unknown = Reflect.get(value, "images");
  if (!rawImages || typeof rawImages !== "object" || Array.isArray(rawImages)) {
    throw new Error("agent image lock images must be an object");
  }
  const images = new Map<string, string>();
  for (const [inputDigest, manifestDigest] of Object.entries(rawImages)) {
    if (!SHA256_DIGEST.test(inputDigest)) {
      throw new Error(`agent image lock has a malformed input digest: ${JSON.stringify(inputDigest)}`);
    }
    if (typeof manifestDigest !== "string" || !SHA256_DIGEST.test(manifestDigest)) {
      throw new Error(`agent image lock has a malformed manifest digest for ${inputDigest}`);
    }
    images.set(inputDigest, manifestDigest);
  }
  return { repository: AGENT_IMAGE_REPOSITORY, images };
}

export function shippedAgentImageLock(): AgentImageLock {
  return parseAgentImageLock(shippedLock);
}

/** The pinned pull reference for one input digest, or undefined when the lock has none. */
export function pinnedAgentImage(lock: AgentImageLock, inputDigest: string): PinnedAgentImageReference | undefined {
  const manifestDigest = lock.images.get(inputDigest);
  if (!manifestDigest) return undefined;
  return `${lock.repository}@${manifestDigest}` as PinnedAgentImageReference;
}
