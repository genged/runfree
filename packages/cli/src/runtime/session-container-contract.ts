export const SESSION_CONTAINER_STOP_SIGNAL = "SIGTERM";
export const SESSION_CONTAINER_STOP_SECONDS = 10;
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
