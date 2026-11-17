// The macOS login Keychain adapter for connection-source logins. Pure: it
// builds argv and stdin and classifies exits; admin-core and the owned reader
// run `security` through their existing spawn seams. A read's stdout IS the
// login, so no message here ever quotes stdout or stderr.

import { TokenResolutionError } from "../token-resolution.ts";
import type { ProviderExit } from "./admin-core.ts";

export const KEYCHAIN_SERVICE = "runfree.credential-source";
/** The bounded wait of a run's or a sync's Keychain read only: setup commands never kill `security`. */
export const KEYCHAIN_CALL_TIMEOUT_MS = 10_000;
const SECURITY_PATH = "/usr/bin/security";
const TOKEN_SHAPE = /^ops_[A-Za-z0-9_.+/=-]+$/;
// A login is written on one `security -i` command line, and a line longer
// than the tool's read buffer would be split into a stored prefix and a
// second command. Service account tokens are about 1 KB: 2 KiB of token
// keeps the whole line under 3 KiB, well inside that buffer.
const TOKEN_MAX_BYTES = 2 * 1024;
const WRITE_LINE_MAX_BYTES = 3 * 1024;

export type KeychainItem = Readonly<{ service: string; account: string }>;

/** A refusal before any Keychain or `op` call; fixed text only. */
export class ConnectionSetupError extends Error {}

export function keychainItemForSource(sourceName: string): KeychainItem {
  return Object.freeze({ service: KEYCHAIN_SERVICE, account: sourceName });
}

function testSeam(env: NodeJS.ProcessEnv): boolean {
  return env.RUNFREE_TEST_FAKE_DOCKER === "1";
}

export function keychainExecutable(env: NodeJS.ProcessEnv): string {
  const override = env.RUNFREE_TEST_SECURITY_PATH;
  return testSeam(env) && override ? override : SECURITY_PATH;
}

// Under the test seam, RUNFREE_TEST_KEYCHAIN_PLATFORM names the platform both
// ways, so a test proves the macOS-only refusal on a Mac too.
export function keychainPlatformAvailable(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): boolean {
  const override = testSeam(env) ? env.RUNFREE_TEST_KEYCHAIN_PLATFORM : undefined;
  return (override || platform) === "darwin";
}

export function assertKeychainPlatform(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): void {
  if (!keychainPlatformAvailable(env, platform)) throw new ConnectionSetupError("1password connection sources need the macOS login Keychain");
}

export function assertServiceAccountTokenShape(token: string): void {
  if (Buffer.byteLength(token, "utf8") > TOKEN_MAX_BYTES || !TOKEN_SHAPE.test(token)) {
    throw new ConnectionSetupError("this is not a 1Password service account token (it starts with ops_)");
  }
}

// The lock check before every `security` call on a connection login. A
// `security` call on a locked login Keychain shows the unlock dialog while
// the screen is unlocked, and killing a `security` child that waits on that
// dialog can leave securityd prompting in a loop. So a locked Keychain is
// refused before `security` starts, and `security` runs only when the check
// says unlocked or cannot tell. The check is `SecKeychainGetStatus` on the
// default keychain through the JavaScript-for-Automation bridge: it reads the
// status bits and never asks to unlock. Its child is not `security`, so its
// timeout kill is safe.
export type KeychainLockState = "locked" | "unlocked" | "unknown";
export const KEYCHAIN_LOCK_CHECK_TIMEOUT_MS = 5_000;
const OSASCRIPT_PATH = "/usr/bin/osascript";
const UNLOCK_STATE_STATUS = 1; // kSecUnlockStateStatus
const LOCK_CHECK_SCRIPT = [
  'ObjC.import("Security");',
  "function run() {",
  "  const status = Ref();",
  "  if ($.SecKeychainGetStatus(null, status) !== 0) return \"unknown\";",
  `  return (status[0] & ${UNLOCK_STATE_STATUS}) ? "unlocked" : "locked";`,
  "}",
].join("\n");

/**
 * The lock check's executable, or undefined for no check. Under the test seam
 * the check runs only when RUNFREE_TEST_OSASCRIPT_PATH names a fake; with no
 * fake the state is unknown and nothing starts, so tests never run the real
 * check on a Mac.
 */
export function keychainLockCheckExecutable(env: NodeJS.ProcessEnv): string | undefined {
  if (!testSeam(env)) return OSASCRIPT_PATH;
  return env.RUNFREE_TEST_OSASCRIPT_PATH || undefined;
}

export function keychainLockCheckArgs(): string[] {
  return ["-l", "JavaScript", "-e", LOCK_CHECK_SCRIPT];
}

/** Any answer other than exactly locked or unlocked is unknown. */
export function keychainLockStateFromExit(exit: ProviderExit): KeychainLockState {
  if (exit.failure || exit.status !== 0) return "unknown";
  const answer = exit.stdout.trim();
  return answer === "locked" || answer === "unlocked" ? answer : "unknown";
}

/** A locked login Keychain: the same transient failure as a `security` read that reports it. */
export function keychainLockedError(sourceName: string): TokenResolutionError {
  return keychainError("transient", KEYCHAIN_LOCKED, lockedMessage(sourceName));
}

/** Fixed text for a setup step that found the Keychain locked before `security` ran. */
export const KEYCHAIN_LOCKED_SETUP_MESSAGE = "the macOS login Keychain is locked; unlock it (log in to the Mac) and run the command again";

export const KEYCHAIN_LOCKED = "keychain-locked";

/** The fix for a locked Keychain: a new login would not help. */
export const KEYCHAIN_UNLOCK_FIX = "unlock the macOS login Keychain (log in to the Mac), then run again";

function lockedMessage(sourceName: string): string {
  return `the login for source "${sourceName}" cannot be read (Keychain locked)`;
}

export function keychainReadArgs(item: KeychainItem): string[] {
  return ["find-generic-password", "-s", item.service, "-a", item.account, "-w"];
}

function keychainError(classification: "transient" | "definitive", code: string, safeMessage: string): TokenResolutionError {
  return new TokenResolutionError({ classification, sourceKind: "keychain", code, safeMessage });
}

const ITEM_NOT_FOUND_STATUS = 44; // errSecItemNotFound

export function keychainReadStep(sourceName: string, exit: ProviderExit): string {
  const subject = `the login for source "${sourceName}"`;
  if (exit.failure?.kind === "timeout") throw keychainError("transient", "keychain-timeout", `${subject} cannot be read (the Keychain did not answer)`);
  if (exit.failure) throw keychainError("definitive", "keychain-unavailable", `${subject} cannot be read (security failed to run)`);
  if (exit.status === 0) {
    const token = exit.stdout.replace(/\r?\n$/, "");
    try {
      assertServiceAccountTokenShape(token);
    } catch {
      throw keychainError("definitive", "keychain-login-invalid", `${subject} in the macOS Keychain is not a service account token`);
    }
    return token;
  }
  if (exit.status === ITEM_NOT_FOUND_STATUS || /could not be found/i.test(exit.stderr)) {
    throw keychainError("definitive", "keychain-login-missing", `${subject} is missing from the macOS Keychain`);
  }
  if (/interaction is not allowed|locked/i.test(exit.stderr)) {
    throw keychainError("transient", KEYCHAIN_LOCKED, lockedMessage(sourceName));
  }
  throw keychainError("definitive", "keychain-unreadable", `${subject} cannot be read from the macOS Keychain`);
}

// An add, never an update (-U): an update of an existing item with -T
// changes the item's access list, and macOS asks the user to allow that
// change. A replacement deletes the old item first, then adds.
export function keychainWriteRequest(item: KeychainItem, token: string): Readonly<{ args: string[]; input: string }> {
  assertServiceAccountTokenShape(token);
  const input = `add-generic-password -s ${item.service} -a ${item.account} -l runfree-source-${item.account} -T ${SECURITY_PATH} -w ${token}\n`;
  if (Buffer.byteLength(input, "utf8") > WRITE_LINE_MAX_BYTES) throw new ConnectionSetupError("the login is too long to save in the macOS Keychain");
  return { args: ["-i"], input };
}

/**
 * The read-back after a write: the Keychain must return exactly the login
 * written. Fixed text only; a read's stdout is the login.
 */
export function keychainWriteCheckStep(exit: ProviderExit, token: string): void {
  if (!exit.failure && exit.status === 0 && exit.stdout.replace(/\r?\n$/, "") === token) return;
  throw new ConnectionSetupError("the macOS Keychain did not keep the login as given; run the command again");
}

export function keychainDeleteArgs(item: KeychainItem): string[] {
  return ["delete-generic-password", "-s", item.service, "-a", item.account];
}

export function keychainDeleteStep(exit: ProviderExit): "deleted" | "absent" {
  if (!exit.failure && exit.status === 0) return "deleted";
  if (!exit.failure && exit.status === ITEM_NOT_FOUND_STATUS) return "absent";
  throw new ConnectionSetupError("the macOS Keychain refused to delete the login");
}
