import { describe, expect, test } from "vitest";

import { describeSource, printableSecretRef } from "./admin-core.ts";
import { namedSourceDisplay } from "./source-policy.ts";

const jwt = { type: "jwt", alg: "ES256", privateKey: { source: "1password", ref: "op://A/k/pem" }, headers: {}, claims: {}, ttlSeconds: 1140, createdAt: "x" } as const;
const gsa = { type: "google-service-account", keyJson: { source: "1password", ref: "op://A/k/json" }, scopes: ["s"], ttlSeconds: 3600, clientEmail: "a@b", createdAt: "x" } as const;

describe("--show-refs", () => {
  test("default output hides every op:// reference", () => {
    expect(describeSource({ source: "1password", ref: "op://A/b/c", via: "automation" })).toBe("1password via automation");
    expect(namedSourceDisplay(jwt as never).join("\n")).not.toContain("op://");
    expect(namedSourceDisplay(gsa as never).join("\n")).not.toContain("op://");
  });

  test("on request, bindings and jwt/GSA sources print their reference", () => {
    expect(describeSource({ source: "1password", ref: "op://A/b/c" }, { showRefs: true })).toBe("1password op://A/b/c");
    expect(describeSource({ source: "1password", ref: "op://A/b/c", via: "automation" }, { showRefs: true })).toBe("1password op://A/b/c via automation");
    expect(namedSourceDisplay(jwt as never, true)).toContain("private key: 1password op://A/k/pem");
    expect(namedSourceDisplay(gsa as never, true)).toContain("key JSON: 1password op://A/k/json");
  });

  test("control bytes and bidi overrides never reach the terminal", () => {
    const hostile = "op://A/\u001b]0;pwned\u0007b/\r\nc\u202e\u2066\u0085\u007f";
    const shown = printableSecretRef(hostile);
    expect(shown).toBe("op://A/?]0;pwned?b/??c????");
    expect(shown).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u);
    const line = describeSource({ source: "1password", ref: hostile }, { showRefs: true });
    expect(line).toBe(`1password ${shown}`);
    expect(namedSourceDisplay({ ...jwt, privateKey: { source: "1password", ref: hostile } } as never, true)).toContain(`private key: 1password ${shown}`);
  });
});
