import { describe, expect, test } from "vitest";

import { SERVICES } from "../../../../scripts/services.ts";
import type { SourceRegistry } from "./admin-core.ts";
import {
  SEARCH_CONSOLE_HOST,
  SEARCH_CONSOLE_TOKEN,
  searchConsoleBindingScope,
  searchConsoleWarningFor,
  searchConsoleWriteScopeWarning,
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
