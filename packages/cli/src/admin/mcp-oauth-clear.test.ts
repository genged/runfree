import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import {
  gatherOAuthStateClearEvidence,
  oauthStateClearLine,
  PROVIDER_ABSENT,
  type OAuthStateClearEvidence,
} from "./mcp-oauth-clear.ts";

const seams = vi.hoisted(() => ({
  oauthPolicyPath: "",
  verify: vi.fn(),
  discoverLiveProxyId: vi.fn(),
  readProxyControlReceipts: vi.fn(),
}));

vi.mock("../control/effective.ts", () => ({ verifyEffectivePolicyGeneration: seams.verify }));
vi.mock("../control/activation.ts", () => ({ discoverLiveProxyId: seams.discoverLiveProxyId }));
vi.mock("../runtime/docker.ts", () => ({ readProxyControlReceipts: seams.readProxyControlReceipts }));

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

describe("mcp revoke OAuth state clear evidence", () => {
  const PROVIDER = "mcp:claude-linear";
  const context = { project: {} } as unknown as RuntimeContext;
  const io = {} as RuntimeIO;
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-oauth-clear-"));
    seams.oauthPolicyPath = path.join(tmp, "oauth-policy.json");
    seams.verify.mockReset().mockImplementation(() => ({ oauthPolicyPath: seams.oauthPolicyPath }));
    seams.discoverLiveProxyId.mockReset().mockReturnValue("proxy-id");
    seams.readProxyControlReceipts.mockReset().mockReturnValue({ requestProxy: status });
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function writeOAuthPolicy(providers: Record<string, unknown>): void {
    fs.writeFileSync(seams.oauthPolicyPath, JSON.stringify({ providers }));
  }

  const linear = (stateEpoch?: string) => ({
    kind: "mcp",
    resourceHost: "mcp.example.com",
    tokenEndpoints: [{ host: "auth.example.com", path: "/token" }],
    ...(stateEpoch ? { stateEpoch } : {}),
  });

  test("reads the epoch the converged generation publishes and the live proxy's status", () => {
    writeOAuthPolicy({ [PROVIDER]: linear(EPOCH) });
    const evidence = gatherOAuthStateClearEvidence(context, io, converged, PROVIDER);
    expect(seams.verify).toHaveBeenCalledWith(context.project, "sha256:new");
    expect(evidence).toEqual({ activation: converged, requestProxy: status, publishedEpoch: EPOCH });
    expect(line(evidence)).toContain(": cleared");
  });

  test("a generation that no longer names the provider is recorded as absent", () => {
    writeOAuthPolicy({});
    expect(gatherOAuthStateClearEvidence(context, io, converged, PROVIDER).publishedEpoch).toBe(PROVIDER_ABSENT);
  });

  test("a provider without an epoch leaves the epoch unset, never absent", () => {
    writeOAuthPolicy({ [PROVIDER]: linear() });
    const evidence = gatherOAuthStateClearEvidence(context, io, converged, PROVIDER);
    expect(evidence.publishedEpoch).toBeUndefined();
    expect(line(evidence)).toContain("not proven cleared");
  });

  test.each([
    ["an unverifiable generation", () => {
      seams.verify.mockImplementation(() => {
        throw new Error("generation digest mismatch");
      });
    }],
    ["an unreadable OAuth policy", () => {}],
    ["an invalid OAuth policy", () => fs.writeFileSync(seams.oauthPolicyPath, "{\"providers\": {\"mcp:claude-linear\": {}}}")],
  ])("%s leaves only the activation, so nothing is proven", (_label, arrange) => {
    arrange();
    const evidence = gatherOAuthStateClearEvidence(context, io, converged, PROVIDER);
    expect(evidence).toEqual({ activation: converged });
    expect(line(evidence)).toContain("not proven cleared");
    // The live proxy is not consulted once the generation cannot be read.
    expect(seams.readProxyControlReceipts).not.toHaveBeenCalled();
  });

  test.each([
    ["no live proxy", () => seams.discoverLiveProxyId.mockReturnValue(undefined)],
    ["a failing status read", () => seams.readProxyControlReceipts.mockImplementation(() => {
      throw new Error("docker exec failed");
    })],
  ])("%s leaves the proxy status out, so nothing is proven", (_label, arrange) => {
    writeOAuthPolicy({ [PROVIDER]: linear(EPOCH) });
    arrange();
    const evidence = gatherOAuthStateClearEvidence(context, io, converged, PROVIDER);
    expect(evidence).toEqual({ activation: converged, publishedEpoch: EPOCH });
    expect(line(evidence)).toContain("not proven cleared");
  });

  test("an activation that did not converge reads nothing", () => {
    const activation = { kind: "selected" as const, controlGeneration: "sha256:new" };
    expect(gatherOAuthStateClearEvidence(context, io, activation, PROVIDER)).toEqual({ activation });
    expect(seams.verify).not.toHaveBeenCalled();
    expect(seams.discoverLiveProxyId).not.toHaveBeenCalled();
  });
});
