import { proxySessionRegistryDirFromEnv } from "@runfree/runtime-contracts/session-registry";

export type SourceIpSessionIdentityConfig = {
  registryRoot: string;
  projectId: string;
};

/**
 * Source-IP session identity is the only mode, and per-session files are the
 * only admission source.
 *
 * Both proxy processes call this before any privileged side effect — the root
 * entrypoint before nftables setup, the uid-1001 request proxy before its
 * listener binds — so a runtime missing the identity or registry configuration
 * refuses to start instead of falling back to any weaker identity.
 *
 * `RUNFREE_SESSION_ADMISSION_SOURCE` is required and must be `files`. The CLI
 * mints it into every proxy environment it renders, so its absence means this
 * container was created by a pre-cutover CLI for a protocol this image no
 * longer speaks; starting anyway would leave a proxy waiting on pointers
 * nothing advances.
 */
export function assertSourceIpSessionIdentityConfig(
  env: NodeJS.ProcessEnv = process.env,
): SourceIpSessionIdentityConfig {
  const mode = env.RUNFREE_SESSION_IDENTITY_MODE;
  if (mode !== "source-ip-v1") {
    throw new Error(
      `refusing to start: RUNFREE_SESSION_IDENTITY_MODE must be "source-ip-v1", got ${
        mode === undefined ? "<absent>" : JSON.stringify(mode)
      }`,
    );
  }
  const registryRoot = proxySessionRegistryDirFromEnv(env);
  if (registryRoot.trim() === "") {
    throw new Error("refusing to start: session registry directory (RUNFREE_SESSION_REGISTRY_DIR) is empty");
  }
  const projectId = env.RUNFREE_PROJECT_ID;
  if (projectId === undefined || projectId.trim() === "") {
    throw new Error("refusing to start: RUNFREE_PROJECT_ID is required for source-ip session identity");
  }
  assertSessionAdmissionSourceIsFiles(env);
  return { registryRoot, projectId };
}

/**
 * The admission-source half of the refusal above, on its own.
 *
 * The firewall supervisor builds its plan from the environment before the
 * request proxy exists, and must refuse the same spelling for the same reason.
 */
export function assertSessionAdmissionSourceIsFiles(env: NodeJS.ProcessEnv = process.env): void {
  const source = env.RUNFREE_SESSION_ADMISSION_SOURCE;
  if (source !== "files") {
    throw new Error(
      `refusing to start: RUNFREE_SESSION_ADMISSION_SOURCE must be "files", got ${
        source === undefined ? "<absent>" : JSON.stringify(source)
      }`,
    );
  }
}
