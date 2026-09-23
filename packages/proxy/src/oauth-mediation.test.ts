import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateOAuthMediationPolicy } from "@runfree/runtime-contracts/oauth-mediation-policy";
import { OAuthMediator } from "./oauth-mediation.ts";

let tmp: string;
const SEEDED_REFRESH_HANDLE = "runfree_oauth_refresh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SEEDED_SECRET_HANDLE = "runfree_oauth_secret_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MISSING_REFRESH_HANDLE = "runfree_oauth_refresh_cccccccccccccccccccccccccccccccc";

function writeJson(filePath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function responseBody(value: unknown): { getText(): Promise<string> } {
  return {
    getText: async () => JSON.stringify(value),
  };
}

beforeEach(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-oauth-mediation-tests-")));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("OAuth mediator service providers", () => {
  test("activates host-loaded paired policy without an independent policy path", async () => {
    const stateDir = path.join(tmp, "state");
    const mediator = new OAuthMediator({
      log: () => {},
      pairedPolicy: validateOAuthMediationPolicy({
        providers: {
          "service:example": {
            kind: "service",
            resourceHost: "api.example.com",
            tokenEndpoints: ["https://auth.example.com/token"],
          },
        },
      }),
      projectId: "project-under-test",
      stateDir,
    });
    const tokenRequest = { id: "paired-token", method: "POST", url: "https://auth.example.com/token" };
    await mediator.beforeRequest(tokenRequest);
    const tokenResponse = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-access-token", token_type: "Bearer" }),
      statusCode: 200,
    }, tokenRequest);
    const accessHandle = (JSON.parse(tokenResponse?.body ?? "{}") as { access_token: string }).access_token;
    expect(accessHandle).toMatch(/^runfree_oauth_access_/);

    mediator.activatePairedPolicy(validateOAuthMediationPolicy({ providers: {} }));
    const resource = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${accessHandle}` },
      method: "GET",
      url: "https://api.example.com/data",
    });

    expect(resource?.response?.statusCode).toBe(403);
    expect(resource?.response?.body).toContain("unknown OAuth token handle");
  });

  test("swaps seeded refresh and client-secret handles from proxy tmpfs and returns only access handles", async () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    const stateDir = path.join(tmp, "state");
    const tokenDir = path.join(tmp, "secrets");
    fs.mkdirSync(tokenDir, { recursive: true });
    fs.writeFileSync(path.join(tokenDir, "oauth-google-ads-refresh-token"), "real-refresh-token\n");
    fs.writeFileSync(path.join(tokenDir, "oauth-google-ads-client-secret"), "real-client-secret\n");
    writeJson(policyPath, {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "googleads.googleapis.com",
          tokenEndpoints: ["https://oauth2.googleapis.com/token"],
          seeds: [
            {
              field: "refresh_token",
              handle: SEEDED_REFRESH_HANDLE,
              secretRef: "oauth-google-ads-refresh-token",
            },
            {
              field: "client_secret",
              handle: SEEDED_SECRET_HANDLE,
              secretRef: "oauth-google-ads-client-secret",
            },
          ],
        },
      },
    });
    const mediator = new OAuthMediator({
      log: () => {},
      policyPath,
      projectId: "project-under-test",
      stateDir,
      tokenDir,
    });

    const request = await mediator.beforeRequest({
      body: { getText: async () => [
        "grant_type=refresh_token",
        `refresh_token=${SEEDED_REFRESH_HANDLE}`,
        `client_secret=${SEEDED_SECRET_HANDLE}`,
      ].join("&") },
      headers: { "content-type": "application/x-www-form-urlencoded" },
      id: "seeded-token",
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
    });

    expect(request?.body).toContain("refresh_token=real-refresh-token");
    expect(request?.body).toContain("client_secret=real-client-secret");
    expect(request?.body).not.toContain("runfree_oauth_");

    const response = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-access-token", expires_in: 3600, token_type: "Bearer" }),
      statusCode: 200,
    }, {
      id: "seeded-token",
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
    });
    const body = JSON.parse(response?.body ?? "{}") as { access_token: string };
    expect(body.access_token).toMatch(/^runfree_oauth_access_/);
    expect(response?.body).not.toContain("real-access-token");

    const resource = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${body.access_token}` },
      method: "GET",
      url: "https://googleads.googleapis.com/v19/customers:list",
    });
    expect(resource?.headers?.authorization).toBe("Bearer real-access-token");
  });

  test("fails closed when a service token response contains long-lived OAuth fields", async () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    writeJson(policyPath, {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "googleads.googleapis.com",
          tokenEndpoints: ["https://oauth2.googleapis.com/token"],
          seeds: [],
        },
      },
    });
    const mediator = new OAuthMediator({
      log: () => {},
      policyPath,
      projectId: "project-under-test",
      stateDir: path.join(tmp, "state"),
      tokenDir: path.join(tmp, "secrets"),
    });
    const req = {
      id: "rotating-token",
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
    };
    await mediator.beforeRequest(req);

    const response = await mediator.beforeResponse({
      body: responseBody({
        access_token: "real-access-token",
        refresh_token: "rotated-refresh-token",
        token_type: "Bearer",
      }),
      statusCode: 200,
    }, req);

    expect(response?.body).toContain("blocked by OAuth proxy policy");
    expect(response?.body).toContain("service OAuth token response contained refresh_token");
    expect(fs.existsSync(path.join(tmp, "state", "handles.json"))).toBe(false);
  });

  test("denies an unavailable seeded secret before forwarding a placeholder value", async () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    writeJson(policyPath, {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "googleads.googleapis.com",
          tokenEndpoints: ["https://oauth2.googleapis.com/token"],
          seeds: [
            {
              field: "refresh_token",
              handle: MISSING_REFRESH_HANDLE,
              secretRef: "oauth-google-ads-refresh-token",
            },
          ],
        },
      },
    });
    const mediator = new OAuthMediator({
      log: () => {},
      policyPath,
      projectId: "project-under-test",
      stateDir: path.join(tmp, "state"),
      tokenDir: path.join(tmp, "secrets"),
    });

    const request = await mediator.beforeRequest({
      body: { getText: async () => `grant_type=refresh_token&refresh_token=${MISSING_REFRESH_HANDLE}` },
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
    });

    expect(request?.response?.statusCode).toBe(403);
    expect(request?.response?.body).toContain("OAuth seed secret unavailable");
    expect(request).not.toHaveProperty("body");
  });

  test("prunes service dynamic access handles when the provider is removed from policy", async () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    const stateDir = path.join(tmp, "state");
    writeJson(policyPath, {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "googleads.googleapis.com",
          tokenEndpoints: ["https://oauth2.googleapis.com/token"],
          seeds: [],
        },
      },
    });
    const mediator = new OAuthMediator({
      log: () => {},
      policyPath,
      projectId: "project-under-test",
      stateDir,
      tokenDir: path.join(tmp, "secrets"),
    });
    const tokenRequest = {
      id: "service-token",
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
    };
    await mediator.beforeRequest(tokenRequest);
    const tokenResponse = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-access-token", token_type: "Bearer" }),
      statusCode: 200,
    }, tokenRequest);
    const tokenBody = JSON.parse(tokenResponse?.body ?? "{}") as { access_token: string };
    expect(tokenBody.access_token).toMatch(/^runfree_oauth_access_/);

    writeJson(policyPath, { providers: {} });
    const future = new Date(Date.now() + 1000);
    fs.utimesSync(policyPath, future, future);

    const resource = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${tokenBody.access_token}` },
      method: "GET",
      url: "https://googleads.googleapis.com/v19/customers:list",
    });
    expect(resource?.response?.statusCode).toBe(403);
    const state = JSON.parse(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")) as { handles?: Record<string, unknown> };
    expect(state.handles ?? {}).toEqual({});
  });

  test("refuses an expired stored access handle instead of injecting its upstream token", async () => {
    const policyPath = path.join(tmp, "oauth-policy.json");
    writeJson(policyPath, {
      providers: {
        "service:google-ads": {
          kind: "service",
          resourceHost: "googleads.googleapis.com",
          tokenEndpoints: ["https://oauth2.googleapis.com/token"],
          seeds: [],
        },
      },
    });
    let now = new Date("2026-01-01T00:00:00.000Z");
    const mediator = new OAuthMediator({
      log: () => {},
      now: () => now,
      policyPath,
      projectId: "project-under-test",
      stateDir: path.join(tmp, "state"),
      tokenDir: path.join(tmp, "secrets"),
    });
    const tokenRequest = {
      id: "expiring-token",
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
    };
    await mediator.beforeRequest(tokenRequest);
    const tokenResponse = await mediator.beforeResponse({
      body: responseBody({ access_token: "real-access-token", expires_in: 3600, token_type: "Bearer" }),
      statusCode: 200,
    }, tokenRequest);
    const accessHandle = (JSON.parse(tokenResponse?.body ?? "{}") as { access_token: string }).access_token;
    expect(accessHandle).toMatch(/^runfree_oauth_access_/);

    now = new Date(now.getTime() + 3_600_000 + 1);
    const resource = await mediator.beforeRequest({
      headers: { authorization: `Bearer ${accessHandle}` },
      method: "GET",
      url: "https://googleads.googleapis.com/v19/customers:list",
    });

    expect(resource?.response?.statusCode).toBe(403);
    expect(resource?.response?.body).toContain("expired OAuth token handle");
    expect(resource?.headers).toBeUndefined();
    expect(JSON.stringify(resource)).not.toContain("real-access-token");
  });

  test("refuses an unreadable handle store instead of restarting it empty", async () => {
    const stateDir = path.join(tmp, "state");
    const stateFile = path.join(stateDir, "handles.json");
    const mediator = new OAuthMediator({
      log: () => {},
      pairedPolicy: validateOAuthMediationPolicy({
        providers: {
          "service:example": {
            kind: "service",
            resourceHost: "api.example.com",
            tokenEndpoints: ["https://auth.example.com/token"],
          },
        },
      }),
      projectId: "project-under-test",
      stateDir,
    });
    // A torn write: the durable store no longer parses, but these bytes still
    // hold the only copy of the stored handles.
    const torn = `{\n  "handles": {\n    "${SEEDED_REFRESH_HANDLE}": {\n      "handle": "${SEEDED_REFRESH_HANDLE}"`;
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(stateFile, torn);

    const tokenRequest = { id: "unreadable-store", method: "POST", url: "https://auth.example.com/token" };
    await expect(mediator.beforeRequest(tokenRequest)).rejects.toThrow(SyntaxError);
    await expect(mediator.beforeResponse({
      body: responseBody({ access_token: "real-access-token", token_type: "Bearer" }),
      statusCode: 200,
    }, tokenRequest)).rejects.toThrow(SyntaxError);

    expect(fs.readFileSync(stateFile, "utf8")).toBe(torn);
    expect(fs.readdirSync(stateDir)).toEqual(["handles.json"]);
  });
});
