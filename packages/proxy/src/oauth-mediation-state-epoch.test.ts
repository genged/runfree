// `runfree mcp revoke` clears a server's proxy OAuth state by publishing a
// new per-provider state epoch. These tests prove the proxy deletes handles
// and discovered endpoints stamped with another epoch when it activates the
// policy, refuses them at use if a prune was missed, never stores tokens
// from an exchange that began under the old epoch, and fails the activation
// (so it is never acknowledged) when the prune cannot be written.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateOAuthMediationPolicy } from "@runfree/runtime-contracts/oauth-mediation-policy";
import { OAuthMediator } from "./oauth-mediation.ts";

const EPOCH_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EPOCH_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROVIDER = "mcp:claude-linear";

let tmp: string;
let stateDir: string;

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-oauth-epoch-tests-")));
  stateDir = path.join(tmp, "state");
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function policy(stateEpoch?: string, extra: Record<string, unknown> = {}) {
  return validateOAuthMediationPolicy({
    providers: {
      [PROVIDER]: {
        kind: "mcp",
        resourceHost: "mcp.example.test",
        resourcePathPrefix: "/mcp",
        tokenEndpoints: [{ host: "auth.example.test", path: "/oauth/token" }],
        ...(stateEpoch ? { stateEpoch } : {}),
        ...extra,
      },
      "mcp:claude-other": {
        kind: "mcp",
        resourceHost: "other.example.test",
        tokenEndpoints: [{ host: "other.example.test", path: "/token" }],
      },
    },
  });
}

function mediator(stateEpoch?: string): OAuthMediator {
  return new OAuthMediator({ log: () => {}, pairedPolicy: policy(stateEpoch), projectId: "project-under-test", stateDir });
}

function body(value: unknown): { getText(): Promise<string> } {
  return { getText: async () => JSON.stringify(value) };
}

async function login(target: OAuthMediator, id: string, url = "https://auth.example.test/oauth/token", access = "real-access-token"): Promise<{ access: string; refresh: string }> {
  const req = { id, method: "POST", url };
  await target.beforeRequest(req);
  const res = await target.beforeResponse({
    body: body({ access_token: access, refresh_token: `${access}-refresh`, token_type: "Bearer" }),
    statusCode: 200,
  }, req);
  const parsed = JSON.parse(res?.body ?? "{}") as { access_token: string; refresh_token: string };
  return { access: parsed.access_token, refresh: parsed.refresh_token };
}

function stateText(): string {
  return fs.readFileSync(path.join(stateDir, "handles.json"), "utf8");
}

async function useAccess(target: OAuthMediator, handle: string, url = "https://mcp.example.test/mcp") {
  return await target.beforeRequest({ headers: { authorization: `Bearer ${handle}` }, method: "POST", url });
}

describe("OAuth state epoch (mcp revoke clears the proxy OAuth state)", () => {
  test("a new epoch deletes that server's handles and real tokens at activation, and leaves other servers alone", async () => {
    const target = mediator(EPOCH_A);
    const linear = await login(target, "linear");
    const other = await login(target, "other", "https://other.example.test/token", "other-real-token");
    expect(stateText()).toContain("real-access-token");

    target.activatePairedPolicy(policy(EPOCH_B));

    const text = stateText();
    expect(text).not.toContain("real-access-token");
    expect(text).not.toContain(linear.access);
    expect(text).not.toContain(linear.refresh);
    expect(text).toContain("other-real-token");
    expect((await useAccess(target, linear.access))?.response?.body).toContain("unknown OAuth token handle");
    expect((await useAccess(target, other.access, "https://other.example.test/x"))?.headers?.authorization).toBe("Bearer other-real-token");
  });

  test("a refresh handle from before the new epoch is refused before any substitution", async () => {
    const target = mediator(EPOCH_A);
    const { refresh } = await login(target, "linear");
    target.activatePairedPolicy(policy(EPOCH_B));
    const result = await target.beforeRequest({
      body: { getText: async () => `grant_type=refresh_token&refresh_token=${refresh}` },
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    });
    expect(result?.response?.statusCode).toBe(403);
    expect(result?.body ?? "").not.toContain("real-access-token-refresh");
  });

  test("the same epoch keeps the state, and so does a policy without epochs (upgrade path)", async () => {
    const withEpoch = mediator(EPOCH_A);
    const kept = await login(withEpoch, "linear");
    withEpoch.activatePairedPolicy(policy(EPOCH_A));
    expect((await useAccess(withEpoch, kept.access))?.headers?.authorization).toBe("Bearer real-access-token");

    fs.rmSync(stateDir, { recursive: true, force: true });
    const legacy = mediator();
    const legacyHandle = await login(legacy, "legacy");
    legacy.activatePairedPolicy(policy());
    expect((await useAccess(legacy, legacyHandle.access))?.headers?.authorization).toBe("Bearer real-access-token");
  });

  test("a handle stored before epochs existed is deleted when its provider gains an epoch", async () => {
    const legacy = mediator();
    const { access } = await login(legacy, "legacy");
    legacy.activatePairedPolicy(policy(EPOCH_A));
    expect(stateText()).not.toContain("real-access-token");
    expect((await useAccess(legacy, access))?.response?.body).toContain("unknown OAuth token handle");
  });

  test("a handle stamped with another epoch is refused at use even if a prune was missed", async () => {
    const target = mediator(EPOCH_A);
    const { access } = await login(target, "linear");
    // Another proxy process (or a restored volume) wrote state under an old
    // epoch after this activation: the use-time check still refuses it.
    const state = JSON.parse(stateText()) as { handles: Record<string, { stateEpoch?: string }> };
    for (const handle of Object.values(state.handles)) handle.stateEpoch = EPOCH_B;
    fs.writeFileSync(path.join(stateDir, "handles.json"), JSON.stringify(state));
    const result = await useAccess(target, access);
    expect(result?.response?.statusCode).toBe(403);
    expect(result?.headers).toBeUndefined();
  });

  test("an exchange that began under the old epoch is blocked, and its tokens are not stored", async () => {
    const target = mediator(EPOCH_A);
    const req = { id: "in-flight", method: "POST", url: "https://auth.example.test/oauth/token" };
    await target.beforeRequest(req);
    target.activatePairedPolicy(policy(EPOCH_B));
    const res = await target.beforeResponse({
      body: body({ access_token: "late-real-token", token_type: "Bearer" }),
      statusCode: 200,
    }, req);
    expect(res?.body).toContain("blocked by OAuth proxy policy");
    expect(res?.body).not.toContain("late-real-token");
    expect(fs.existsSync(path.join(stateDir, "handles.json")) ? stateText() : "").not.toContain("late-real-token");
  });

  test("a revoke that lands while the response body is still arriving blocks the response and stores nothing", async () => {
    const target = mediator(EPOCH_A);
    const req = { id: "slow-body", method: "POST", url: "https://auth.example.test/oauth/token" };
    await target.beforeRequest(req);
    const res = await target.beforeResponse({
      body: {
        getText: async () => {
          target.activatePairedPolicy(policy(EPOCH_B));
          return JSON.stringify({ access_token: "late-real-token", refresh_token: "late-refresh", token_type: "Bearer" });
        },
      },
      statusCode: 200,
    }, req);
    expect(res?.body).toContain("blocked by OAuth proxy policy");
    expect(res?.body).not.toContain("late-real-token");
    expect(fs.existsSync(path.join(stateDir, "handles.json")) ? stateText() : "").not.toContain("late-");
  });

  test("metadata that arrives after a revoke is recorded under the new epoch only", async () => {
    const target = mediator(EPOCH_A);
    const prm = { method: "GET", url: "https://mcp.example.test/.well-known/oauth-protected-resource/mcp" };
    await target.beforeResponse({
      body: {
        getText: async () => {
          target.activatePairedPolicy(policy(EPOCH_B));
          return JSON.stringify({ authorization_servers: ["https://issuer.example.test"] });
        },
      },
      statusCode: 200,
    }, prm);
    const state = JSON.parse(stateText()) as { discovered: Record<string, { stateEpoch?: string }> };
    expect(state.discovered[PROVIDER].stateEpoch).toBe(EPOCH_B);
  });

  test("an exchange whose server was removed while it was in flight is blocked", async () => {
    const target = mediator(EPOCH_A);
    const req = { id: "in-flight", method: "POST", url: "https://auth.example.test/oauth/token" };
    await target.beforeRequest(req);
    target.activatePairedPolicy(validateOAuthMediationPolicy({ providers: {} }));
    const res = await target.beforeResponse({
      body: body({ access_token: "late-real-token", token_type: "Bearer" }),
      statusCode: 200,
    }, req);
    expect(res?.body).toContain("blocked by OAuth proxy policy");
    expect(res?.body).not.toContain("late-real-token");
  });

  test("discovered issuers and endpoints from the old epoch are deleted and no longer bind", async () => {
    const target = mediator(EPOCH_A);
    const prm = { method: "GET", url: "https://mcp.example.test/.well-known/oauth-protected-resource/mcp" };
    await target.beforeResponse({ body: body({ authorization_servers: ["https://issuer.example.test"] }), statusCode: 200 }, prm);
    const asm = { method: "GET", url: "https://issuer.example.test/.well-known/oauth-authorization-server" };
    await target.beforeResponse({
      body: body({ issuer: "https://issuer.example.test", token_endpoint: "https://issuer.example.test/token" }),
      statusCode: 200,
    }, asm);
    expect(stateText()).toContain("issuer.example.test");
    expect(target.requestNeedsResponseMediation({ url: "https://issuer.example.test/token" })).toBe(true);

    target.activatePairedPolicy(policy(EPOCH_B));

    expect(stateText()).not.toContain("issuer.example.test");
    expect(target.requestNeedsResponseMediation({ url: "https://issuer.example.test/token" })).toBe(false);
    expect(target.issuerDenialContext("issuer.example.test")).toBeUndefined();
  });

  test("discovered state stamped with another epoch is ignored at use even if a prune was missed", async () => {
    const target = mediator(EPOCH_A);
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(path.join(stateDir, "handles.json"), JSON.stringify({
      discovered: { [PROVIDER]: { stateEpoch: EPOCH_B, issuerHosts: ["issuer.example.test"], tokenEndpoints: [{ host: "issuer.example.test", path: "/token" }] } },
    }));
    expect(target.requestNeedsResponseMediation({ url: "https://issuer.example.test/token" })).toBe(false);
    expect(target.issuerDenialContext("issuer.example.test")).toBeUndefined();
  });

  test("a prune that cannot be written fails the activation and keeps the previous policy", async () => {
    const target = mediator(EPOCH_A);
    const { access } = await login(target, "linear");
    // The atomic write's temporary path is taken by a directory.
    fs.mkdirSync(path.join(stateDir, `handles.json.${process.pid}.tmp`));
    expect(() => target.activatePairedPolicy(policy(EPOCH_B))).toThrow();
    // Not acknowledged: the old policy (epoch A) still applies, so the handle
    // keeps working until a later activation succeeds (the reclaim).
    expect((await useAccess(target, access))?.headers?.authorization).toBe("Bearer real-access-token");
    fs.rmdirSync(path.join(stateDir, `handles.json.${process.pid}.tmp`));
    target.activatePairedPolicy(policy(EPOCH_B));
    expect(stateText()).not.toContain("real-access-token");
  });
});

describe("bounds on unattended OAuth exchanges", () => {
  test("a rotated refresh token retires the refresh handle that was swapped for the old one", async () => {
    const target = mediator(EPOCH_A);
    const { refresh } = await login(target, "first");
    const refreshReq = {
      id: "refresh",
      body: { getText: async () => `grant_type=refresh_token&refresh_token=${refresh}` },
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    };
    const swapped = await target.beforeRequest(refreshReq);
    expect(swapped?.body).toContain("refresh_token=real-access-token-refresh");
    const res = await target.beforeResponse({
      body: body({ access_token: "second-access", refresh_token: "second-refresh", token_type: "Bearer" }),
      statusCode: 200,
    }, refreshReq);
    const next = JSON.parse(res?.body ?? "{}") as { refresh_token: string };
    expect(next.refresh_token).toMatch(/^runfree_oauth_refresh_/);
    expect(stateText()).not.toContain("real-access-token-refresh");
    const replay = await target.beforeRequest({ ...refreshReq, id: "replay" });
    expect(replay?.response?.statusCode).toBe(403);
    expect(replay?.response?.body).toContain("unknown OAuth refresh handle");
  });

  test("a refresh without rotation keeps the refresh handle", async () => {
    const target = mediator(EPOCH_A);
    const { refresh } = await login(target, "first");
    const refreshReq = {
      id: "refresh",
      body: { getText: async () => `grant_type=refresh_token&refresh_token=${refresh}` },
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST",
      url: "https://auth.example.test/oauth/token",
    };
    await target.beforeRequest(refreshReq);
    await target.beforeResponse({ body: body({ access_token: "second-access", token_type: "Bearer" }), statusCode: 200 }, refreshReq);
    expect(stateText()).toContain("real-access-token-refresh");
  });

  test("refused requests leave no in-flight entry, so they cannot push out a real exchange", async () => {
    const target = mediator(EPOCH_A);
    const real = { id: "real-exchange", method: "POST", url: "https://auth.example.test/oauth/token" };
    await target.beforeRequest(real);
    for (let index = 0; index < 1100; index += 1) {
      const refused = await target.beforeRequest({
        id: `flood-${index}`,
        body: { getText: async () => `grant_type=refresh_token&refresh_token=runfree_oauth_refresh_${String(index).padStart(32, "x")}` },
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST",
        url: "https://auth.example.test/oauth/token",
      });
      expect(refused?.response?.statusCode).toBe(403);
    }
    // A GET to the token endpoint is never recorded as an exchange at all.
    await target.beforeRequest({ id: "get", method: "GET", url: "https://auth.example.test/oauth/token" });
    // The real exchange is still tracked: a revoke mid-exchange blocks it.
    target.activatePairedPolicy(policy(EPOCH_B));
    const res = await target.beforeResponse({ body: body({ access_token: "late-real-token" }), statusCode: 200 }, real);
    expect(res?.body).toContain("revoked during the exchange");
  });

  test("when 1024 exchanges are in flight, a new one is refused instead of evicting one", async () => {
    const target = mediator(EPOCH_A);
    for (let index = 0; index < 1024; index += 1) {
      await target.beforeRequest({ id: `open-${index}`, method: "POST", url: "https://auth.example.test/oauth/token" });
    }
    const refused = await target.beforeRequest({ id: "one-more", method: "POST", url: "https://auth.example.test/oauth/token" });
    expect(refused?.response?.statusCode).toBe(403);
    expect(refused?.response?.body).toContain("too many OAuth exchanges in flight");
    // The oldest exchange keeps its entry.
    target.activatePairedPolicy(policy(EPOCH_B));
    const res = await target.beforeResponse({ body: body({ access_token: "late" }), statusCode: 200 }, { id: "open-0", method: "POST", url: "https://auth.example.test/oauth/token" });
    expect(res?.body).toContain("revoked during the exchange");
  });

  test("a token response on the mediating rule that nothing mediates any more is blocked, even without an entry", async () => {
    const target = mediator(EPOCH_A);
    target.activatePairedPolicy(validateOAuthMediationPolicy({ providers: {} }));
    const res = await target.beforeResponse({
      body: body({ access_token: "orphan-real-token", token_type: "Bearer" }),
      statusCode: 200,
    }, { id: "no-entry", method: "POST", url: "https://auth.example.test/oauth/token" });
    expect(res?.body).toContain("no longer mediated");
    expect(res?.body).not.toContain("orphan-real-token");
    const formRes = await target.beforeResponse({
      body: { getText: async () => "access_token=orphan-form-token&token_type=bearer" },
      statusCode: 200,
    }, { method: "POST", url: "https://auth.example.test/oauth/token" });
    expect(formRes?.body).not.toContain("orphan-form-token");
  });

  test("a long refresh chain never evicts the registration client secret", async () => {
    let tick = 0;
    const target = new OAuthMediator({
      log: () => {},
      now: () => new Date(Date.UTC(2026, 8, 30, 0, 0, 0, tick++)),
      pairedPolicy: policy(EPOCH_A, { registrationEndpoints: [{ host: "auth.example.test", path: "/oauth/register" }] }),
      projectId: "project-under-test",
      stateDir,
    });
    const registerReq = { id: "register", method: "POST", url: "https://auth.example.test/oauth/register" };
    await target.beforeRequest(registerReq);
    const registered = await target.beforeResponse({ body: body({ client_id: "c", client_secret: "real-client-secret" }), statusCode: 200 }, registerReq);
    const secretHandle = (JSON.parse(registered?.body ?? "{}") as { client_secret: string }).client_secret;
    let { refresh } = await login(target, "first");
    for (let index = 0; index < 300; index += 1) {
      const req = {
        id: `refresh-${index}`,
        body: { getText: async () => `grant_type=refresh_token&refresh_token=${refresh}&client_secret=${secretHandle}` },
        headers: { "content-type": "application/x-www-form-urlencoded" },
        method: "POST",
        url: "https://auth.example.test/oauth/token",
      };
      const swapped = await target.beforeRequest(req);
      expect(swapped?.body, `refresh ${index}`).toContain("client_secret=real-client-secret");
      const res = await target.beforeResponse({
        body: body({ access_token: `access-${index}`, refresh_token: `refresh-${index}`, id_token: `id-${index}`, expires_in: 3600 }),
        statusCode: 200,
      }, req);
      refresh = (JSON.parse(res?.body ?? "{}") as { refresh_token: string }).refresh_token;
    }
    expect(stateText()).toContain("real-client-secret");
  });

  test("each provider keeps at most 256 handles, dropping the oldest", async () => {
    let tick = 0;
    const target = new OAuthMediator({
      log: () => {},
      now: () => new Date(Date.UTC(2026, 8, 30, 0, 0, tick++)),
      pairedPolicy: policy(EPOCH_A),
      projectId: "project-under-test",
      stateDir,
    });
    const first = await login(target, "login-0", undefined, "token-0");
    for (let index = 1; index < 140; index += 1) await login(target, `login-${index}`, undefined, `token-${index}`);
    const state = JSON.parse(stateText()) as { handles: Record<string, { serverName: string }> };
    expect(Object.values(state.handles).filter((token) => token.serverName === PROVIDER)).toHaveLength(256);
    expect(state.handles[first.access]).toBeUndefined();
    expect(stateText()).toContain("token-139");
  });
});
