// How an `op` read logs in. `app`: today's desktop-app read (may ask).
// `connection`: a 1Password service account whose token runfree keeps in the
// macOS login Keychain and hands only to this one `op` child.

import { ConnectionSetupError, type KeychainItem } from "./keychain-login.ts";

export type OnePasswordLogin =
  | Readonly<{ kind: "app" }>
  | Readonly<{ kind: "connection"; sourceName: string; keychain: KeychainItem }>;

export const APP_LOGIN: OnePasswordLogin = Object.freeze({ kind: "app" });

export function loginIdentity(login: OnePasswordLogin): string {
  return login.kind === "app" ? "app" : `connection:${login.keychain.service}:${login.keychain.account}`;
}

const ENV_ALLOWLIST = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"] as const;

export function connectionOpEnv(base: NodeJS.ProcessEnv, token: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ENV_ALLOWLIST) if (base[name] !== undefined) env[name] = base[name];
  env.OP_SERVICE_ACCOUNT_TOKEN = token;
  env.OP_BIOMETRIC_UNLOCK_ENABLED = "false";
  // Without these, `op` still reads the desktop app's settings at start and
  // starts a cache daemon. Under launchd either one makes macOS ask for access
  // to another app's data, on every start, and `op` waits for the answer.
  env.OP_LOAD_DESKTOP_APP_SETTINGS = "false";
  env.OP_CACHE = "false";
  return Object.freeze(env);
}

export function redactLogin(text: string, token: string): string {
  return token === "" ? text : text.split(token).join("[redacted]");
}

export function opWhoamiArgs(): string[] {
  return ["whoami", "--format", "json"];
}

export function opVaultListArgs(): string[] {
  return ["vault", "list", "--format", "json"];
}

export function parseServiceAccountWhoami(stdout: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    parsed = undefined;
  }
  const userType = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as { user_type?: unknown }).user_type : undefined;
  if (userType !== "SERVICE_ACCOUNT") {
    throw new ConnectionSetupError("1Password did not confirm a service account login; only service account tokens can be saved");
  }
}

export function parseVaultNames(stdout: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new ConnectionSetupError("1Password returned an unreadable vault list");
  }
  if (!Array.isArray(parsed)) throw new ConnectionSetupError("1Password returned an unreadable vault list");
  const names = parsed.flatMap((entry) => (entry && typeof entry === "object" && typeof (entry as { name?: unknown }).name === "string" ? [(entry as { name: string }).name] : []));
  if (names.length === 0) throw new ConnectionSetupError("the service account can read no vault");
  return names.sort((left, right) => left.localeCompare(right));
}
