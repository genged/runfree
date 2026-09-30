import { describe, expect, test } from "vitest";

import { oauthStateClearLine, PROVIDER_ABSENT, type OAuthStateClearEvidence } from "./mcp-oauth-clear.ts";

const EPOCH = "0123456789abcdef0123456789abcdef";
const converged = { kind: "converged" as const, controlGeneration: "sha256:new" };
const status = { generation: "p1", controlGeneration: "sha256:new", policyGeneration: "p1", oauthStateEpochs: true as const };

function line(evidence: OAuthStateClearEvidence): string {
  return oauthStateClearLine({ agent: "claude", server: "linear", expectedEpoch: EPOCH, evidence });
}

describe("mcp revoke OAuth state clear report", () => {
  test("says cleared only when the live proxy applied the generation that publishes the new epoch", () => {
    expect(line({ activation: converged, requestProxy: status, publishedEpoch: EPOCH }))
      .toBe("proxy OAuth state for claude linear: cleared (the proxy applied effective policy generation sha256:new); the next login starts fresh");
  });

  test("a generation that no longer names the server is proof too (the proxy prunes absent providers)", () => {
    expect(line({ activation: converged, requestProxy: status, publishedEpoch: PROVIDER_ABSENT })).toContain(": cleared");
  });

  test.each<[string, OAuthStateClearEvidence]>([
    ["a status for another effective policy generation (same network policy)", {
      activation: converged, requestProxy: { ...status, controlGeneration: "sha256:old" }, publishedEpoch: EPOCH,
    }],
    ["a proxy without the state-epoch marker (older image)", {
      activation: converged, requestProxy: { generation: "p1", controlGeneration: "sha256:new", policyGeneration: "p1" }, publishedEpoch: EPOCH,
    }],
    ["a generation that publishes another epoch", { activation: converged, requestProxy: status, publishedEpoch: "ffffffffffffffffffffffffffffffff" }],
    ["a generation whose provider has no epoch", { activation: converged, requestProxy: status }],
    ["an unreadable proxy status", { activation: converged, publishedEpoch: EPOCH }],
  ])("never says cleared for %s", (_label, evidence) => {
    const text = line(evidence);
    expect(text).not.toContain(": cleared");
    expect(text).toContain("not proven cleared");
  });

  test.each<[string, OAuthStateClearEvidence]>([
    ["no running proxy", { activation: { kind: "selected", controlGeneration: "sha256:new" } }],
    ["controls not yet approved", { activation: { kind: "deferred", reason: "not approved" } }],
  ])("says the clear happens at the next start when there is %s", (_label, evidence) => {
    expect(line(evidence)).toBe("proxy OAuth state for claude linear: not cleared yet; the proxy clears it when it next starts with this project's policy");
  });
});
