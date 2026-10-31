import { describe, expect, test } from "vitest";

import { isTransientTokenResolutionError } from "../token-resolution.ts";
import {
  connectionSourceNames,
  CredentialInteractionForbiddenError,
  credentialInteractionForbidden,
  forbidCredentialInteraction,
  unattendedReadVerdict,
  unattendedRefusalLines,
} from "./credential-interaction.ts";

const registry = {
  automation: { type: "1password", keychain: { service: "runfree.credential-source", account: "automation" }, createdAt: "x" },
  gh: { type: "command", argv: ["/bin/echo"], displayArgv: ["echo"], createdAt: "x" },
  appstore: { type: "jwt", alg: "ES256", privateKey: { source: "1password", ref: "op://A/k/pem" }, headers: {}, claims: {}, ttlSeconds: 1140, createdAt: "x" },
  gsa: { type: "google-service-account", keyJson: { source: "1password", ref: "op://A/k/json" }, scopes: ["s"], ttlSeconds: 3600, clientEmail: "a@b", createdAt: "x" },
} as const;

describe("the hold", () => {
  test("nested holds compose and releases are idempotent", () => {
    expect(credentialInteractionForbidden()).toBe(false);
    const a = forbidCredentialInteraction();
    const b = forbidCredentialInteraction();
    a();
    a();
    expect(credentialInteractionForbidden()).toBe(true);
    b();
    expect(credentialInteractionForbidden()).toBe(false);
  });
});

describe("verdicts", () => {
  test.each([
    [{ source: "env", env: "X" }, { kind: "never-asks" }],
    [{ source: "1password", ref: "op://A/b/c", via: "automation" }, { kind: "never-asks" }],
    [{ source: "1password", ref: "op://A/b/c" }, { kind: "may-ask", reason: "1password-app" }],
    [{ source: "named", name: "gh" }, { kind: "may-ask", reason: "command" }],
    [{ source: "named", name: "appstore" }, { kind: "may-ask", reason: "signing-key-1password-app" }],
    [{ source: "named", name: "gsa" }, { kind: "may-ask", reason: "signing-key-1password-app" }],
    [{ source: "named", name: "appstore", via: "automation" }, { kind: "never-asks" }],
    [{ source: "named", name: "gsa", via: "automation" }, { kind: "never-asks" }],
    // The plan fails these before any spawn, with their own messages.
    [{ source: "named", name: "missing" }, { kind: "never-asks" }],
    [{ source: "named", name: "automation" }, { kind: "never-asks" }],
    [{ source: "named", name: "gh", via: "automation" }, { kind: "never-asks" }],
    [{ source: "file", path: "/x" }, { kind: "never-asks" }],
    [{ source: "cmd", command: "echo" }, { kind: "never-asks" }],
  ])("%j", (source, verdict) => {
    expect(unattendedReadVerdict(source as never, registry as never)).toEqual(verdict);
  });

  test("a named binding with no readable registry never claims to ask (the plan fails it)", () => {
    expect(unattendedReadVerdict({ source: "named", name: "gh" }, undefined)).toEqual({ kind: "never-asks" });
  });

  test("a host OP_SERVICE_ACCOUNT_TOKEN changes nothing", () => {
    process.env.OP_SERVICE_ACCOUNT_TOKEN = "ops_host";
    try {
      expect(unattendedReadVerdict({ source: "1password", ref: "op://A/b/c" }, registry as never)).toEqual({ kind: "may-ask", reason: "1password-app" });
    } finally {
      delete process.env.OP_SERVICE_ACCOUNT_TOKEN;
    }
  });

  test("connection names come from the registry, sorted", () => {
    expect(connectionSourceNames({ ...registry, zeta: registry.automation } as never)).toEqual(["automation", "zeta"]);
    expect(connectionSourceNames(undefined)).toEqual([]);
  });
});

describe("refusal lines", () => {
  test("one connection: named in the fix", () => {
    expect(unattendedRefusalLines({ tokenName: "github", source: { source: "1password", ref: "op://Private/github/token" }, reason: "1password-app", owner: undefined, connections: ["automation"] })).toEqual([
      "run refused (65): github uses the 1Password app, which may ask",
      "  fix: runfree credential set-source github --from-1password op://<vault>/<item>/<field> --via automation --replace-source",
    ]);
  });

  test("no connection: a placeholder and the first step", () => {
    expect(unattendedRefusalLines({ tokenName: "github", source: { source: "1password", ref: "op://P/g/t" }, reason: "1password-app", owner: undefined, connections: [] })).toEqual([
      "run refused (65): github uses the 1Password app, which may ask",
      "  first: runfree credential source 1password <connection>",
      "  fix: runfree credential set-source github --from-1password op://<vault>/<item>/<field> --via <connection> --replace-source",
    ]);
  });

  test("several connections: a placeholder and the list", () => {
    expect(unattendedRefusalLines({ tokenName: "github", source: { source: "1password", ref: "op://P/g/t" }, reason: "1password-app", owner: undefined, connections: ["a", "b"] })).toEqual([
      "run refused (65): github uses the 1Password app, which may ask",
      "  connections: a, b",
      "  fix: runfree credential set-source github --from-1password op://<vault>/<item>/<field> --via <connection> --replace-source",
    ]);
  });

  test("a command source: the connection fix or an env source", () => {
    expect(unattendedRefusalLines({ tokenName: "stripe", source: { source: "named", name: "gh" }, reason: "command", owner: undefined, connections: ["automation"] })).toEqual([
      "run refused (65): stripe runs a command source, which runfree cannot keep from asking",
      "  fix: runfree credential set-source stripe --from-1password op://<vault>/<item>/<field> --via automation --replace-source",
      "  or: runfree credential set-source stripe --from-env <ENV_VAR> --replace-source",
    ]);
  });

  test("a signing key: rebind the same source through the connection", () => {
    expect(unattendedRefusalLines({ tokenName: "appstore-connect", source: { source: "named", name: "appstore" }, reason: "signing-key-1password-app", owner: undefined, connections: ["automation"] })).toEqual([
      "run refused (65): appstore-connect reads its signing key with the 1Password app, which may ask",
      "  fix: runfree credential set-source appstore-connect --from-source appstore --via automation --replace-source",
      "  the key must be in a vault the connection can read",
    ]);
  });

  test("a service-owned binding is fixed through service enable", () => {
    const owner = { kind: "service", id: "github" } as const;
    expect(unattendedRefusalLines({ tokenName: "github", source: { source: "1password", ref: "op://P/g/t" }, reason: "1password-app", owner, connections: ["automation"] })[1])
      .toBe("  fix: runfree service enable github --from-1password op://<vault>/<item>/<field> --via automation --replace-source");
    expect(unattendedRefusalLines({ tokenName: "github", source: { source: "named", name: "gh" }, reason: "command", owner, connections: ["automation"] })[2])
      .toBe("  or: runfree service enable github --from-env <ENV_VAR> --replace-source");
    expect(unattendedRefusalLines({ tokenName: "apple-ads", source: { source: "named", name: "appstore" }, reason: "signing-key-1password-app", owner: { kind: "service", id: "apple-ads" }, connections: ["automation"] })[1])
      .toBe("  fix: runfree service enable apple-ads --from-source appstore --via automation --replace-source");
  });

  test("an MCP-owned binding is fixed with an env source", () => {
    expect(unattendedRefusalLines({ tokenName: "mcp-claude-github-auth", source: { source: "1password", ref: "op://P/g/t" }, reason: "1password-app", owner: { kind: "mcp", agent: "claude", server: "github" }, connections: ["automation"] })).toEqual([
      "run refused (65): mcp-claude-github-auth uses the 1Password app, which may ask",
      "  fix: runfree mcp enable claude github --source project --from-env <ENV_VAR> --replace-source",
    ]);
  });

  test("the reference itself is never printed", () => {
    const lines = unattendedRefusalLines({ tokenName: "github", source: { source: "1password", ref: "op://Private/secret-item/token" }, reason: "1password-app", owner: undefined, connections: ["automation"] });
    expect(lines.join("\n")).not.toContain("secret-item");
  });
});

test("a rule refusal is transient: it never revokes a held value", () => {
  const error = new CredentialInteractionForbiddenError("x", "1password");
  expect(isTransientTokenResolutionError(error)).toBe(true);
  expect(error.code).toBe("interaction-forbidden");
});
