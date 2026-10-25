import { describe, expect, test } from "vitest";

import { SERVICES } from "../../../../scripts/services.ts";
import type { NamedSource, SourceRegistry } from "./admin-core.ts";
import {
  SEARCH_CONSOLE_HOST,
  SEARCH_CONSOLE_TOKEN,
  searchConsoleBindingScope,
  searchConsoleWarningFor,
  searchConsoleWriteScopeWarning,
  scopesAddWrite,
} from "./search-console-write-guard.ts";

const REMEDY = "runfree host rules searchconsole.googleapis.com --write ask";

const commandRegistry: SourceRegistry = {
  gsc: { type: "command", argv: ["/usr/bin/gcloud"], displayArgv: ["gcloud"], createdAt: "2026-10-25T00:00:00.000Z" },
};

describe("search console write-scope guard (spec §5.1)", () => {
  test("constants match the curated service", () => {
    const service = SERVICES["google-search-console"];
    expect(service?.credential?.tokenName).toBe(SEARCH_CONSOLE_TOKEN);
    expect(service?.credential?.credentials.map((credential) => credential.host)).toEqual([SEARCH_CONSOLE_HOST]);
  });

  test("no binding means no warning in any write action", () => {
    expect(searchConsoleBindingScope(undefined, {})).toBeUndefined();
    for (const writeAction of ["allow", "ask", "deny"] as const) {
      expect(searchConsoleWriteScopeWarning({ writeAction, scope: undefined, sourceLabel: "unconfigured" })).toBeUndefined();
    }
  });

  test("a command, env, or 1Password binding has an unknown scope", () => {
    expect(searchConsoleBindingScope({ source: "named", name: "gsc" }, commandRegistry)).toBe("unknown");
    expect(searchConsoleBindingScope({ source: "env", env: "GSC_TOKEN" }, undefined)).toBe("unknown");
    expect(searchConsoleBindingScope({ source: "1password", ref: "op://Private/gsc/token" }, undefined)).toBe("unknown");
    // A binding to a source missing from the registry cannot prove its scope.
    expect(searchConsoleBindingScope({ source: "named", name: "missing" }, {})).toBe("unknown");
  });

  test("warns only under allow, and names the remedy that restores the prompt", () => {
    expect(searchConsoleWriteScopeWarning({ writeAction: "ask", scope: "unknown", sourceLabel: "source gsc" })).toBeUndefined();
    expect(searchConsoleWriteScopeWarning({ writeAction: "deny", scope: "write", sourceLabel: "source gsc" })).toBeUndefined();
    expect(searchConsoleWriteScopeWarning({ writeAction: "allow", scope: "read-only", sourceLabel: "source gsc" })).toBeUndefined();
    for (const scope of ["unknown", "write"] as const) {
      const warning = searchConsoleWriteScopeWarning({ writeAction: "allow", scope, sourceLabel: "source gsc" });
      expect(warning).toContain(SEARCH_CONSOLE_HOST);
      expect(warning).toContain("source gsc");
      expect(warning).toContain(REMEDY);
      expect(warning).not.toContain("--local");
    }
  });

  test("the remedy names the checkout-local layer when that layer holds the service", () => {
    const warning = searchConsoleWriteScopeWarning({ writeAction: "allow", scope: "unknown", sourceLabel: "source gsc", local: true });
    expect(warning).toContain(`${REMEDY} --local`);
  });

  test("the write action follows the per-host rule, then the policy default", () => {
    const binding = { source: "named", name: "gsc" } as const;
    const allowByHost = { requests: { [SEARCH_CONSOLE_HOST]: { writeAction: "allow" as const } } };
    const allowByDefault = { requests: {}, writeApproval: "allow" as const };
    const hostAskOverDefaultAllow = { requests: { [SEARCH_CONSOLE_HOST]: { writeAction: "ask" as const } }, writeApproval: "allow" as const };
    const defaultPosture = { requests: {} };

    expect(searchConsoleWarningFor({ policy: allowByHost, binding, registry: commandRegistry })).toContain(REMEDY);
    expect(searchConsoleWarningFor({ policy: allowByDefault, binding, registry: commandRegistry })).toContain(REMEDY);
    expect(searchConsoleWarningFor({ policy: hostAskOverDefaultAllow, binding, registry: commandRegistry })).toBeUndefined();
    expect(searchConsoleWarningFor({ policy: defaultPosture, binding, registry: commandRegistry })).toBeUndefined();
    expect(searchConsoleWarningFor({ policy: allowByHost, binding: undefined, registry: undefined })).toBeUndefined();
  });
});

describe("search console write-scope guard: google-service-account scope (spec §5.1, Phase 2)", () => {
  const RO = "https://www.googleapis.com/auth/webmasters.readonly";
  const W = "https://www.googleapis.com/auth/webmasters";
  const binding = { source: "named", name: "gsc" } as const;
  const allowByHost = { requests: { [SEARCH_CONSOLE_HOST]: { writeAction: "allow" as const } } };

  function saSource(scopes: string[]): NamedSource {
    return {
      type: "google-service-account",
      keyJson: { source: "1password", ref: "op://Private/gsc-sa/credential.json" },
      clientEmail: "gsc-reader@my-project-123.iam.gserviceaccount.com",
      scopes,
      ttlSeconds: 3300,
      createdAt: "2026-10-25T00:00:00.000Z",
    };
  }

  test("a service-account source proves its scope from the registry record", () => {
    expect(searchConsoleBindingScope(binding, { gsc: saSource([RO]) })).toBe("read-only");
    expect(searchConsoleBindingScope(binding, { gsc: saSource([W]) })).toBe("write");
    expect(searchConsoleBindingScope(binding, { gsc: saSource([W, RO]) })).toBe("write");
  });

  test("a read-only service-account source is safe under allow; a write scope warns as such", () => {
    expect(searchConsoleWarningFor({ policy: allowByHost, binding, registry: { gsc: saSource([RO]) } })).toBeUndefined();
    const warning = searchConsoleWarningFor({ policy: allowByHost, binding, registry: { gsc: saSource([W, RO]) } });
    expect(warning).toContain("has a Search Console write scope");
    expect(warning).toContain(REMEDY);
  });

  test("scopesAddWrite: only a change that can newly grant webmasters writes", () => {
    expect(scopesAddWrite(undefined, [W])).toBe(true);
    expect(scopesAddWrite(saSource([RO]), [RO, W])).toBe(true);
    expect(scopesAddWrite(saSource([RO, W]), [W])).toBe(false);
    expect(scopesAddWrite(saSource([W]), [RO])).toBe(false);
    // A command source's scope is unknown, so a write scope is new.
    expect(scopesAddWrite(commandRegistry.gsc, [W])).toBe(true);
    for (const previous of [undefined, saSource([RO]), saSource([W]), commandRegistry.gsc]) {
      expect(scopesAddWrite(previous, [RO])).toBe(false);
    }
  });
});
