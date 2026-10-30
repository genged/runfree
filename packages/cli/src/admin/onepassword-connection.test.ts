import { describe, expect, test } from "vitest";

import { ConnectionSetupError, keychainItemForSource } from "./keychain-login.ts";
import {
  APP_LOGIN,
  connectionOpEnv,
  loginIdentity,
  opVaultListArgs,
  opWhoamiArgs,
  parseServiceAccountWhoami,
  parseVaultNames,
  redactLogin,
} from "./onepassword-connection.ts";

const TOKEN = `ops_${"B".repeat(60)}`;

describe("connection op env", () => {
  test("keeps only the allowlist and adds the token and the app-integration switch", () => {
    const env = connectionOpEnv({
      PATH: "/usr/bin",
      HOME: "/Users/me",
      LANG: "en_US.UTF-8",
      OP_ACCOUNT: "my.1password.com",
      OP_SESSION_abc: "session",
      OP_CONNECT_HOST: "https://connect",
      OP_CONNECT_TOKEN: "connect-token",
      OP_SERVICE_ACCOUNT_TOKEN: "ops_from_the_host_env",
      GITHUB_TOKEN: "ghp_x",
      AWS_SECRET_ACCESS_KEY: "aws",
    }, TOKEN);
    expect(env).toEqual({
      PATH: "/usr/bin",
      HOME: "/Users/me",
      LANG: "en_US.UTF-8",
      OP_SERVICE_ACCOUNT_TOKEN: TOKEN,
      OP_BIOMETRIC_UNLOCK_ENABLED: "false",
    });
    expect(Object.isFrozen(env)).toBe(true);
  });
});

describe("login identity", () => {
  test("app and connection identities never collide", () => {
    expect(loginIdentity(APP_LOGIN)).toBe("app");
    expect(loginIdentity({ kind: "connection", sourceName: "automation", keychain: keychainItemForSource("automation") }))
      .toBe("connection:runfree.credential-source:automation");
  });
});

describe("redaction", () => {
  test("removes every copy of the token", () => {
    expect(redactLogin(`bad token ${TOKEN} (${TOKEN})`, TOKEN)).toBe("bad token [redacted] ([redacted])");
    expect(redactLogin("nothing here", TOKEN)).toBe("nothing here");
  });
});

describe("whoami and vault list", () => {
  test("argv", () => {
    expect(opWhoamiArgs()).toEqual(["whoami", "--format", "json"]);
    expect(opVaultListArgs()).toEqual(["vault", "list", "--format", "json"]);
  });
  test("a service account passes; a person or garbage refuses with fixed text", () => {
    expect(() => parseServiceAccountWhoami(JSON.stringify({ url: "https://x.1password.com", user_type: "SERVICE_ACCOUNT" }))).not.toThrow();
    for (const stdout of [JSON.stringify({ user_type: "HUMAN" }), "not json", "[]"]) {
      expect(() => parseServiceAccountWhoami(stdout)).toThrow(ConnectionSetupError);
      expect(() => parseServiceAccountWhoami(stdout)).toThrow("1Password did not confirm a service account login; only service account tokens can be saved");
    }
  });
  test("vault names, sorted; an empty list refuses", () => {
    expect(parseVaultNames(JSON.stringify([{ id: "1", name: "Automation" }, { id: "2", name: "CI" }]))).toEqual(["Automation", "CI"]);
    expect(() => parseVaultNames("[]")).toThrow("the service account can read no vault");
    expect(() => parseVaultNames("nope")).toThrow("1Password returned an unreadable vault list");
  });
});
