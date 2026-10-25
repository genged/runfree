export const SESSION_CONTAINER_STOP_SIGNAL = "SIGTERM";
export const SESSION_CONTAINER_STOP_SECONDS = 10;
/**
 * The Docker client's own bound on one session stop, beyond the grace it asks
 * Docker for. A stop that outlives it is killed and counts as not done
 * (`docs/security.md` "Lifecycle" 2); the teardown that follows repeats it.
 */
export const SESSION_STOP_CLIENT_SLACK_MS = 20_000;
/**
 * The client deadline a headless run gives every synchronous Docker call that
 * carries none of its own (`createHeadlessRuntimeIO`): long enough for a
 * session's graceful stop.
 */
export const SESSION_DOCKER_CALL_TIMEOUT_MS = SESSION_CONTAINER_STOP_SECONDS * 1_000 + SESSION_STOP_CLIENT_SLACK_MS;
export const SESSION_CONTAINER_USER = "1000:1000";
export const SESSION_CONTAINER_RESTART_POLICY = "no";
export const SESSION_CONTAINER_SECURITY_OPTIONS = ["no-new-privileges:true"] as const;
export const SESSION_CONTAINER_CAPABILITY_DROPS = ["NET_ADMIN", "NET_RAW"] as const;

export type SessionContainerMount = Readonly<{
  type: "bind" | "volume";
  source: string;
  target: string;
  readOnly: boolean;
  noCopy: boolean;
}>;
