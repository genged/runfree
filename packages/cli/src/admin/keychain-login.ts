// The macOS login Keychain adapter for connection-source logins (profiles and
// unattended credentials spec §4.2, decision 2). Pure: it builds argv and
// stdin and classifies exits; admin-core and the owned reader run `security`
// through their existing spawn seams. A read's stdout IS the login, so no
// message here ever quotes stdout or stderr.

import { TokenResolutionError } from "../token-resolution.ts";
import type { ProviderExit } from "./admin-core.ts";

export const KEYCHAIN_SERVICE = "runfree.credential-source";
export const KEYCHAIN_CALL_TIMEOUT_MS = 10_000;
const SECURITY_PATH = "/usr/bin/security";
const TOKEN_SHAPE = /^ops_[A-Za-z0-9_.+/=-]+$/;
const TOKEN_MAX_BYTES = 8 * 1024;

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

export function assertKeychainPlatform(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): void {
  const effective = testSeam(env) && env.RUNFREE_TEST_KEYCHAIN_PLATFORM === "darwin" ? "darwin" : platform;
  if (effective !== "darwin") throw new ConnectionSetupError("1password connection sources need the macOS login Keychain");
}

export function assertServiceAccountTokenShape(token: string): void {
  if (Buffer.byteLength(token, "utf8") > TOKEN_MAX_BYTES || !TOKEN_SHAPE.test(token)) {
    throw new ConnectionSetupError("this is not a 1Password service account token (it starts with ops_)");
  }
}

export function keychainReadArgs(item: KeychainItem): string[] {
  return ["find-generic-password", "-s", item.service, "-a", item.account, "-w"];
}

function keychainError(classification: "transient" | "definitive", code: string, safeMessage: string): TokenResolutionError {
  return new TokenResolutionError({ classification, sourceKind: "keychain", code, safeMessage });
}

const ITEM_NOT_FOUND_STATUS = 44; // errSecItemNotFound (H1 owed)

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
    throw keychainError("transient", "keychain-locked", `${subject} cannot be read (Keychain locked)`);
  }
  throw keychainError("definitive", "keychain-unreadable", `${subject} cannot be read from the macOS Keychain`);
}

export function keychainWriteRequest(item: KeychainItem, token: string): Readonly<{ args: string[]; input: string }> {
  assertServiceAccountTokenShape(token);
  return {
    args: ["-i"],
    input: `add-generic-password -U -s ${item.service} -a ${item.account} -l runfree-source-${item.account} -T ${SECURITY_PATH} -w ${token}\n`,
  };
}

export function keychainDeleteArgs(item: KeychainItem): string[] {
  return ["delete-generic-password", "-s", item.service, "-a", item.account];
}

export function keychainDeleteStep(exit: ProviderExit): "deleted" | "absent" {
  if (!exit.failure && exit.status === 0) return "deleted";
  if (!exit.failure && exit.status === ITEM_NOT_FOUND_STATUS) return "absent";
  throw new ConnectionSetupError("the macOS Keychain refused to delete the login");
}
