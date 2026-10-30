import { describe, expect, test } from "vitest";

import { TokenResolutionError } from "../token-resolution.ts";
import type { ProviderExit } from "./admin-core.ts";
import {
  assertKeychainPlatform,
  assertServiceAccountTokenShape,
  ConnectionSetupError,
  keychainDeleteArgs,
  keychainDeleteStep,
  keychainExecutable,
  keychainItemForSource,
  keychainReadArgs,
  keychainReadStep,
  keychainWriteRequest,
} from "./keychain-login.ts";

const TOKEN = `ops_${"A".repeat(60)}.sentinel-value`;
const exit = (over: Partial<ProviderExit>): ProviderExit => ({ status: 0, signal: null, stdout: "", stderr: "", ...over });

describe("keychain item naming", () => {
  test("one fixed service, the source name as account", () => {
    expect(keychainItemForSource("automation")).toEqual({ service: "runfree.credential-source", account: "automation" });
  });
});

describe("keychain executable and platform", () => {
  test("always /usr/bin/security outside the test seam, even with an override set", () => {
    expect(keychainExecutable({ RUNFREE_TEST_SECURITY_PATH: "/tmp/fake" })).toBe("/usr/bin/security");
    expect(keychainExecutable({ RUNFREE_TEST_FAKE_DOCKER: "1", RUNFREE_TEST_SECURITY_PATH: "/tmp/fake" })).toBe("/tmp/fake");
  });
  test("refuses off macOS unless the test seam says darwin", () => {
    expect(() => assertKeychainPlatform({}, "linux")).toThrow(ConnectionSetupError);
    expect(() => assertKeychainPlatform({}, "linux")).toThrow("1password connection sources need the macOS login Keychain");
    expect(() => assertKeychainPlatform({ RUNFREE_TEST_FAKE_DOCKER: "1", RUNFREE_TEST_KEYCHAIN_PLATFORM: "darwin" }, "linux")).not.toThrow();
    expect(() => assertKeychainPlatform({ RUNFREE_TEST_KEYCHAIN_PLATFORM: "darwin" }, "linux")).toThrow(ConnectionSetupError);
    expect(() => assertKeychainPlatform({}, "darwin")).not.toThrow();
  });
});

describe("service account token shape", () => {
  test("accepts an ops_ token", () => expect(() => assertServiceAccountTokenShape(TOKEN)).not.toThrow());
  test.each([
    ["empty", ""],
    ["not a service account token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
    ["whitespace would split the -i command", `ops_${"A".repeat(30)} delete-keychain`],
    ["a quote", `ops_${"A".repeat(30)}"`],
    ["a newline", `ops_${"A".repeat(30)}\nadd-generic-password`],
    ["too long", `ops_${"A".repeat(9000)}`],
  ])("refuses %s, and the message never quotes the input", (_label, token) => {
    let message = "";
    try {
      assertServiceAccountTokenShape(token);
    } catch (error) {
      expect(error).toBeInstanceOf(ConnectionSetupError);
      message = (error as Error).message;
    }
    expect(message).toBe("this is not a 1Password service account token (it starts with ops_)");
  });
});

describe("keychain read", () => {
  const item = keychainItemForSource("automation");
  test("argv names the item and asks for the password only", () => {
    expect(keychainReadArgs(item)).toEqual(["find-generic-password", "-s", "runfree.credential-source", "-a", "automation", "-w"]);
  });
  test("a success returns the token without its newline", () => {
    expect(keychainReadStep("automation", exit({ stdout: `${TOKEN}\n` }))).toBe(TOKEN);
  });
  test.each([
    ["missing item (exit 44)", exit({ status: 44, stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." }), "definitive", "keychain-login-missing", 'the login for source "automation" is missing from the macOS Keychain'],
    ["locked keychain", exit({ status: 36, stderr: "security: SecKeychainSearchCopyNext: User interaction is not allowed." }), "transient", "keychain-locked", 'the login for source "automation" cannot be read (Keychain locked)'],
    ["timeout", exit({ status: null, failure: { kind: "timeout" } }), "transient", "keychain-timeout", 'the login for source "automation" cannot be read (the Keychain did not answer)'],
    ["spawn failure", exit({ status: null, failure: { kind: "spawn", message: "ENOENT" } }), "definitive", "keychain-unavailable", 'the login for source "automation" cannot be read (security failed to run)'],
    ["stored value is not a token", exit({ stdout: "hunter2\n" }), "definitive", "keychain-login-invalid", 'the login for source "automation" in the macOS Keychain is not a service account token'],
    ["unknown failure", exit({ status: 1, stderr: `weird ${TOKEN}` }), "definitive", "keychain-unreadable", 'the login for source "automation" cannot be read from the macOS Keychain'],
  ])("%s is classified and never echoes output", (_label, result, classification, code, message) => {
    let caught: unknown;
    try {
      keychainReadStep("automation", result);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(TokenResolutionError);
    const error = caught as TokenResolutionError;
    expect(error.classification).toBe(classification);
    expect(error.sourceKind).toBe("keychain");
    expect(error.code).toBe(code);
    expect(error.message).toBe(message);
    expect(error.message).not.toContain("ops_");
  });
});

describe("keychain write", () => {
  test("the token goes on stdin to security -i, never in argv", () => {
    const request = keychainWriteRequest(keychainItemForSource("automation"), TOKEN);
    expect(request.args).toEqual(["-i"]);
    expect(request.args.join(" ")).not.toContain(TOKEN);
    expect(request.input).toBe(
      `add-generic-password -U -s runfree.credential-source -a automation -l runfree-source-automation -T /usr/bin/security -w ${TOKEN}\n`,
    );
  });
  test("refuses a token of the wrong shape before building a request", () => {
    expect(() => keychainWriteRequest(keychainItemForSource("automation"), "x y")).toThrow(ConnectionSetupError);
  });
});

describe("keychain delete", () => {
  test("argv and outcomes; an absent item counts as done (the reclaim path)", () => {
    expect(keychainDeleteArgs(keychainItemForSource("automation"))).toEqual(["delete-generic-password", "-s", "runfree.credential-source", "-a", "automation"]);
    expect(keychainDeleteStep(exit({}))).toBe("deleted");
    expect(keychainDeleteStep(exit({ status: 44 }))).toBe("absent");
    expect(() => keychainDeleteStep(exit({ status: 36 }))).toThrow("the macOS Keychain refused to delete the login");
  });
});
