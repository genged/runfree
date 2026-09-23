import { PROXY_SERVER_GID, PROXY_SERVER_UID } from "@runfree/proxy/firewall/nftables";

export const PROJECT_ID_LABEL = "io.runfree.project-id";
export const RUNFREE_MANAGED_IMAGE_LABEL = "io.runfree.managed";
export const RUNFREE_IMAGE_ROLE_LABEL = "io.runfree.image-role";
export const RUNFREE_DIGEST_SCHEMA_LABEL = "io.runfree.digest-schema";
export const RUNFREE_IMAGE_INPUT_DIGEST_LABEL = "io.runfree.image-input-digest";
export const RUNFREE_DIGEST_SCHEMA_VERSION = "1";
export const AGENT_IMAGE_INPUT_DIGEST_LABEL = "io.runfree.agent-image-input-digest";
export const PROXY_IMAGE_INPUT_DIGEST_LABEL = "io.runfree.proxy-image-input-digest";
export const TOPOLOGY_DIGEST_LABEL = "io.runfree.topology-digest";
/** @deprecated Legacy containers only. */
export const RUNTIME_DIGEST_LABEL = "io.runfree.runtime-digest";
export const RUNFREE_VERSION_LABEL = "io.runfree.version";
export const AGENT_UID_GID = "1000:1000";
export const ROOT_UID_GID = "0:0";
export const PROXY_SERVER_UID_GID = `${PROXY_SERVER_UID}:${PROXY_SERVER_GID}`;
export const RUNTIME_VALIDATION_MARKER_PATH = "/run/runfree-runtime-validation.json";
export const AGENT_BASE_IMAGE_ROLE = "agent-base";
export const AGENT_RUNTIME_IMAGE_ROLE = "agent-runtime";
export const AGENT_PROJECT_IMAGE_ROLE = "agent-project";
export const PROXY_RUNTIME_IMAGE_ROLE = "proxy-runtime";
export const SELECTED_AGENT_IMAGE_LABEL_NAMES = Object.freeze([
  RUNFREE_MANAGED_IMAGE_LABEL,
  RUNFREE_IMAGE_ROLE_LABEL,
  RUNFREE_DIGEST_SCHEMA_LABEL,
  RUNFREE_IMAGE_INPUT_DIGEST_LABEL,
  PROJECT_ID_LABEL,
  RUNFREE_VERSION_LABEL,
] as const);
export const RECENT_SESSION_START_MS = 5 * 60 * 1000;
/** Upper bound for one `docker container inspect` of one proxy container. */
export const PROXY_CONTAINER_INSPECT_MAX_BYTES = 64 * 1024;
