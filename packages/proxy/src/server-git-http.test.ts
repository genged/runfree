// Live-proxy tests for git over HTTPS credential mediation (spec T3, T9, T11),
// run against the real server subprocess with the test-only read observer
// (server-observe.test-harness.ts). The git host is github.com-shaped: an
// exact hostname resolved through the resolved-hosts snapshot, so the DNS step
// is an observable file read, with a `git-http` Basic mapping and a `gitPush`
// rule. Every refusal is proven to stop before the resolved-hosts read (DNS),
// before an upstream TCP connection, and before any read of the proxy-only
// secret directory; a positive control proves the observer sees all three on
// an allowed, credentialed request.
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { describe, expect, test } from "vitest";

import {
  APPROVALS_PROCESS_EPOCH_FILE,
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  parsePendingApprovalRecord,
  type PendingApprovalRecord,
} from "@runfree/runtime-contracts/write-approvals";
import { writeResolvedHostsFile } from "./resolved-hosts.ts";
import {
  createUpstreamCertificate,
  httpsViaProxy,
  type ProxyResponse,
  proxyRequestEvents,
  type RunningProxy,
  servers,
  startProxy,
  tmp,
  waitUntil,
  writeJson,
} from "./server.test-harness.ts";

const OWN_UID = String(process.getuid?.() ?? 0);
const GIT_HOST = "github.com";
const REDIRECT_HOST = "codeload.github.com";
const TOKEN = "real-git-proxy-token";
const INJECTED_BASIC = `Basic ${Buffer.from(`x-access-token:${TOKEN}`).toString("base64")}`;
const INFO_REFS = "/owner/repo.git/info/refs?service=git-upload-pack";
const UPLOAD_PACK = "/owner/repo.git/git-upload-pack";
const RECEIVE_PACK = "/owner/repo.git/git-receive-pack";
const RECEIVE_PACK_PROBE = "/owner/repo.git/info/refs?service=git-receive-pack";
const REDIRECTING_INFO_REFS = "/moved/repo.git/info/refs?service=git-upload-pack";

type UpstreamRequest = {
  body: string;
  headers: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
};

type GitUpstream = {
  acceptedConnections: () => number;
  certPath: string;
  port: number;
  requests: UpstreamRequest[];
};

// One HTTPS origin answering for both hostnames (both resolve to 127.0.0.1):
// git and web paths return 200, `/moved/...` redirects to REDIRECT_HOST, and
// `/oauth/token` mints an OAuth token response so the proxy issues real
// handles that the tests can then age, re-home, or misuse.
async function startGitUpstream(): Promise<GitUpstream> {
  const { certPath, keyPath } = createUpstreamCertificate(tmp, {
    commonName: GIT_HOST,
    subjectAltName: `DNS:${GIT_HOST},DNS:${REDIRECT_HOST}`,
  });
  const requests: UpstreamRequest[] = [];
  let acceptedConnections = 0;
  let port = 0;
  const server = https.createServer({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  }, (request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({ body: Buffer.concat(chunks).toString("utf8"), headers: request.headers, method: request.method, url: request.url });
      if (request.url === "/oauth/token" && request.method === "POST") {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({
          access_token: "real-access-token-1",
          refresh_token: "real-refresh-token-1",
          expires_in: 3600,
          token_type: "Bearer",
        }));
        return;
      }
      if (request.url?.startsWith("/moved/")) {
        response.statusCode = 302;
        response.setHeader("location", `https://${REDIRECT_HOST}:${port}${request.url.replace("/moved/", "/owner/")}`);
        response.setHeader("x-upstream-marker", "redirect");
        response.setHeader("content-type", "text/plain");
        response.end("moved\n");
        return;
      }
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ ok: true, url: request.url }));
    });
  });
  servers.add(server);
  server.on("connection", () => {
    acceptedConnections += 1;
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("upstream server did not report a TCP port");
  port = address.port;
  return { acceptedConnections: () => acceptedConnections, certPath, port, requests };
}

type ApprovalDirs = { pendingDir: string; decisionsDir: string };

function approvalDirs(): ApprovalDirs {
  return {
    pendingDir: fs.mkdtempSync(path.join(tmp, "git-approvals-pending-")),
    decisionsDir: fs.mkdtempSync(path.join(tmp, "git-approvals-decisions-")),
  };
}

function gitPolicy(rule: Record<string, unknown>, writeApproval?: "allow" | "ask" | "deny"): unknown {
  return {
    hosts: [GIT_HOST, REDIRECT_HOST],
    tokens: {
      github: {
        description: "GitHub token",
        credentials: [
          { host: GIT_HOST, header: "Authorization", scheme: "basic", username: "x-access-token", protocol: "git-http" },
        ],
      },
    },
    requests: { [GIT_HOST]: rule },
    ...(writeApproval === undefined ? {} : { writeApproval }),
  };
}

const OAUTH_SERVER = {
  resourceHost: GIT_HOST,
  resourcePathPrefix: "/mcp",
  tokenHost: GIT_HOST,
  tokenPath: "/oauth/token",
};

async function startGitProxy(options: {
  approvals?: ApprovalDirs;
  oauth?: boolean;
  rule: Record<string, unknown>;
  writeApproval?: "allow" | "ask" | "deny";
}): Promise<{ oauthStateDir: string; proxy: RunningProxy; upstream: GitUpstream }> {
  const upstream = await startGitUpstream();
  const resolvedHostsPath = path.join(tmp, "resolved-hosts.json");
  writeResolvedHostsFile(resolvedHostsPath, {
    generation: `sha256:${"a".repeat(64)}`,
    hosts: { [GIT_HOST]: ["127.0.0.1"], [REDIRECT_HOST]: ["127.0.0.1"] },
  });
  const oauthStateDir = path.join(tmp, "oauth-state");
  const oauthPolicyPath = path.join(tmp, "oauth-mediation-policy.json");
  if (options.oauth === true) writeJson(oauthPolicyPath, { servers: { sentry: OAUTH_SERVER } });
  if (options.approvals) {
    fs.writeFileSync(path.join(options.approvals.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), "watch-requested");
  }
  const proxy = await startProxy({
    observe: true,
    extraEnv: {
      NODE_EXTRA_CA_CERTS: upstream.certPath,
      PROXY_RESOLVED_HOSTS_PATH: resolvedHostsPath,
      ...(options.oauth === true ? { RUNFREE_OAUTH_POLICY: oauthPolicyPath, RUNFREE_OAUTH_STATE_DIR: oauthStateDir } : {}),
      ...(options.approvals
        ? {
          RUNFREE_APPROVALS_PENDING_DIR: options.approvals.pendingDir,
          RUNFREE_APPROVALS_DECISIONS_DIR: options.approvals.decisionsDir,
          RUNFREE_APPROVALS_DECISION_OWNER_UID: OWN_UID,
          RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "5",
        }
        : {}),
    },
    policy: gitPolicy(options.rule, options.writeApproval),
    secretFiles: { github: `${TOKEN}\n` },
  });
  // Verbose request events carry the per-request credential action.
  fs.writeFileSync(path.join(proxy.verboseDir, "enabled"), "");
  if (options.approvals) {
    // Re-attach with the running proxy's process epoch, as an approver would.
    fs.writeFileSync(
      path.join(options.approvals.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE),
      fs.readFileSync(path.join(options.approvals.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    );
  }
  return { oauthStateDir, proxy, upstream };
}

function viaProxy(proxy: RunningProxy, upstream: GitUpstream, request: {
  body?: string;
  headers?: Record<string, string>;
  host?: string;
  method?: string;
  path: string;
}): Promise<ProxyResponse> {
  return httpsViaProxy({
    proxyPort: proxy.port,
    targetHost: request.host ?? GIT_HOST,
    targetPort: upstream.port,
    path: request.path,
    ...(request.method === undefined ? {} : { method: request.method }),
    ...(request.headers === undefined ? {} : { headers: request.headers }),
    ...(request.body === undefined ? {} : { body: request.body }),
  });
}

function observed(proxy: RunningProxy) {
  const reads = proxy.observedReads;
  if (reads === undefined) throw new Error("proxy was started without observe: true");
  return reads();
}

// A side-effect checkpoint: everything the observer and the upstream have
// seen so far. `expectNothingSince` asserts a refusal added nothing.
function checkpoint(proxy: RunningProxy, upstream: GitUpstream) {
  return { reads: observed(proxy).length, connections: upstream.acceptedConnections(), requests: upstream.requests.length };
}

function expectNothingSince(proxy: RunningProxy, upstream: GitUpstream, mark: ReturnType<typeof checkpoint>, label: string): void {
  expect(observed(proxy).slice(mark.reads), `${label}: secret-dir or resolved-hosts read`).toEqual([]);
  expect(upstream.acceptedConnections(), `${label}: upstream connection`).toBe(mark.connections);
  expect(upstream.requests.length, `${label}: upstream request`).toBe(mark.requests);
}

function secretReadsSince(proxy: RunningProxy, mark: ReturnType<typeof checkpoint>) {
  return observed(proxy).slice(mark.reads).filter((read) => read.kind === "secret");
}

async function waitForPendingRecord(dirs: ApprovalDirs): Promise<PendingApprovalRecord> {
  let record: PendingApprovalRecord | undefined;
  await waitUntil(() => {
    const entries = fs.readdirSync(dirs.pendingDir).filter((entry) => entry.endsWith(".json"));
    if (entries.length === 0) return false;
    record = parsePendingApprovalRecord(fs.readFileSync(path.join(dirs.pendingDir, entries[0]), "utf8"));
    return record !== undefined;
  }, "pending approval record");
  if (!record) throw new Error("pending approval record did not appear");
  return record;
}

// The credential action of the latest admitted request for `pathName`
// (pathname only; request events never log the query).
async function lastCredentialAction(proxy: RunningProxy, pathName: string, previousCount: number): Promise<unknown> {
  const admitted = () => proxyRequestEvents(proxy.output())
    .filter((event) => event.event === "admitted" && event.path === pathName);
  await waitUntil(() => admitted().length > previousCount, `admitted event for ${pathName}`);
  return admitted().at(-1)?.credential_action;
}

function admittedCount(proxy: RunningProxy, pathName: string): number {
  return proxyRequestEvents(proxy.output()).filter((event) => event.event === "admitted" && event.path === pathName).length;
}

describe("proxy server git over HTTPS: refusal ordering (T11)", () => {
  test("positive control: an allowed git read reads resolved-hosts, connects upstream, reads the token and injects Basic", async () => {
    const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write" } });
    const mark = checkpoint(proxy, upstream);

    const response = await viaProxy(proxy, upstream, { path: INFO_REFS, headers: { Authorization: "Basic YWdlbnQ6Zm9yZ2Vk" } });

    expect(response.statusCode).toBe(200);
    const reads = observed(proxy).slice(mark.reads);
    expect(reads).toContainEqual(expect.objectContaining({ kind: "secret", path: path.join(proxy.secretDir, "github") }));
    expect(reads).toContainEqual(expect.objectContaining({ kind: "resolved-hosts" }));
    expect(upstream.acceptedConnections()).toBeGreaterThan(mark.connections);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe(INJECTED_BASIC);
    expect(proxy.output()).toContain(`proxy: injected Authorization for ${GIT_HOST} using github`);
    expect(proxy.output()).not.toContain(TOKEN);
  }, 30_000);

  test("a push denied by gitPush deny or by a deny write posture stops before DNS, connect and token read", async () => {
    for (const [label, rule, reason] of [
      ["gitPush deny", { gitPush: "deny" }, "git-push-denied"],
      ["writeAction deny", { gitPush: "write", writeAction: "deny" }, "write-denied"],
    ] as const) {
      const { proxy, upstream } = await startGitProxy({ rule });
      for (const [requestLabel, method, pathName] of [
        ["receive-pack POST", "POST", RECEIVE_PACK],
        ["receive-pack capability probe", "GET", RECEIVE_PACK_PROBE],
      ] as const) {
        // A deny write posture does not classify the GET probe as a write.
        if (reason === "write-denied" && method === "GET") continue;
        const mark = checkpoint(proxy, upstream);
        const denied = await viaProxy(proxy, upstream, {
          method,
          path: pathName,
          headers: { Authorization: "Basic YWdlbnQ6Zm9yZ2Vk", "content-type": "application/x-git-receive-pack-request" },
          ...(method === "POST" ? { body: "0000" } : {}),
        });
        expect(denied.statusCode, `${label} ${requestLabel}`).toBe(403);
        expect(denied.raw, `${label} ${requestLabel}`).toContain(`x-runfree-blocked: ${reason}`);
        expect(denied.raw, `${label} ${requestLabel}`).not.toContain(TOKEN);
        expectNothingSince(proxy, upstream, mark, `${label} ${requestLabel}`);
      }
      await proxy.stop();
    }
  }, 40_000);

  test("a push held for approval reads nothing and connects nowhere while pending, nor after it times out", async () => {
    const dirs = approvalDirs();
    const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write", writeAction: "ask" }, approvals: dirs });
    const mark = checkpoint(proxy, upstream);

    const responsePromise = viaProxy(proxy, upstream, { method: "POST", path: RECEIVE_PACK, body: "0000" });
    const record = await waitForPendingRecord(dirs);
    expect(record).toMatchObject({ host: GIT_HOST, method: "POST", path: RECEIVE_PACK, tokenNames: ["github"] });
    await proxy.waitForOutput(`proxy-approval-request: {"v":1`);
    // Still pending: no decision was written.
    expect(fs.existsSync(path.join(dirs.pendingDir, `${record.id}.json`))).toBe(true);
    expectNothingSince(proxy, upstream, mark, "pending approval");

    const response = await responsePromise;
    expect(response.statusCode).toBe(403);
    expect(response.raw).toContain("x-runfree-blocked: write-approval-timeout");
    expectNothingSince(proxy, upstream, mark, "timed-out approval");
  }, 30_000);

  test("a rejected push approval stops before DNS, connect and token read", async () => {
    const dirs = approvalDirs();
    const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write", writeAction: "ask" }, approvals: dirs });
    const mark = checkpoint(proxy, upstream);

    const responsePromise = viaProxy(proxy, upstream, { method: "POST", path: RECEIVE_PACK, body: "0000" });
    const record = await waitForPendingRecord(dirs);
    fs.writeFileSync(path.join(dirs.decisionsDir, `${record.id}.json`), `${JSON.stringify({
      v: 1,
      processEpoch: fs.readFileSync(path.join(dirs.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
      id: record.id,
      decidedAt: new Date().toISOString(),
      decision: "deny",
    })}\n`);
    const response = await responsePromise;
    expect(response.statusCode).toBe(403);
    expect(response.raw).not.toContain("write-approval-timeout");
    expect(response.raw).not.toContain(TOKEN);
    expectNothingSince(proxy, upstream, mark, "rejected approval");
  }, 30_000);

  test("a refused OAuth handle on a git path stops before DNS, connect and token read", async () => {
    const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write" }, writeApproval: "allow", oauth: true });
    const mark = checkpoint(proxy, upstream);

    const response = await viaProxy(proxy, upstream, {
      path: INFO_REFS,
      headers: { Authorization: `Bearer runfree_oauth_access_${"f".repeat(32)}` },
    });

    expect(response.statusCode).toBe(403);
    expect(response.body).toContain("unknown OAuth token handle");
    expectNothingSince(proxy, upstream, mark, "refused OAuth handle");
  }, 30_000);
});

type StoredHandle = Record<string, unknown> & { handle: string; type: string };

function readHandles(stateDir: string): { state: Record<string, unknown>; handles: Record<string, StoredHandle> } {
  const state = JSON.parse(fs.readFileSync(path.join(stateDir, "handles.json"), "utf8")) as Record<string, unknown>;
  return { state, handles: (state.handles ?? {}) as Record<string, StoredHandle> };
}

function writeHandles(stateDir: string, state: Record<string, unknown>): void {
  const target = path.join(stateDir, "handles.json");
  const tmpPath = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmpPath, target);
}

describe("proxy server git over HTTPS: agent Authorization and OAuth handles (T3)", () => {
  test("an agent Authorization is replaced with the injected Basic on git paths and stripped with nothing injected on web paths", async () => {
    const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write" }, writeApproval: "allow" });

    for (const [label, method, pathName] of [
      ["info/refs", "GET", INFO_REFS],
      ["upload-pack", "POST", UPLOAD_PACK],
    ] as const) {
      const response = await viaProxy(proxy, upstream, {
        method,
        path: pathName,
        headers: { Authorization: "Bearer agent-supplied-credential" },
        ...(method === "POST" ? { body: "0000" } : {}),
      });
      expect(response.statusCode, label).toBe(200);
      expect(upstream.requests.at(-1)?.headers.authorization, label).toBe(INJECTED_BASIC);
    }

    for (const pathName of ["/owner/repo", "/owner/repo/pulls"]) {
      const mark = checkpoint(proxy, upstream);
      const events = admittedCount(proxy, pathName);
      const response = await viaProxy(proxy, upstream, {
        path: pathName,
        headers: { Authorization: "Bearer agent-supplied-credential" },
      });
      expect(response.statusCode, pathName).toBe(200);
      const forwarded = upstream.requests.at(-1);
      expect(forwarded?.url, pathName).toBe(pathName);
      expect(forwarded?.headers.authorization, pathName).toBeUndefined();
      expect(secretReadsSince(proxy, mark), pathName).toEqual([]);
      expect(await lastCredentialAction(proxy, pathName, events), pathName).toBe("stripped");
    }
    expect(JSON.stringify(upstream.requests.map((request) => request.headers))).not.toContain("agent-supplied-credential");
  }, 30_000);

  test("fabricated, expired, other-project and wrong-resource Bearer handles are refused on a git path before connect", async () => {
    const { oauthStateDir, proxy, upstream } = await startGitProxy({ rule: { gitPush: "write" }, writeApproval: "allow", oauth: true });

    // Mint a real access handle through the mediated token endpoint.
    const minted = await viaProxy(proxy, upstream, {
      method: "POST",
      path: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=authorization-code",
    });
    expect(minted.statusCode).toBe(200);
    const accessHandle = (JSON.parse(minted.body) as { access_token: string }).access_token;
    expect(accessHandle).toMatch(/^runfree_oauth_access_/);

    // The minted handle is valid on its own resource: this is what makes the
    // refusals below about the handle's binding, not about a broken fixture.
    const onResource = await viaProxy(proxy, upstream, { path: "/mcp", headers: { Authorization: `Bearer ${accessHandle}` } });
    expect(onResource.statusCode).toBe(200);
    expect(upstream.requests.at(-1)?.headers.authorization).toBe("Bearer real-access-token-1");

    const { state, handles } = readHandles(oauthStateDir);
    const original = handles[accessHandle];
    expect(original?.type).toBe("access");
    const expiredHandle = `runfree_oauth_access_${"e".repeat(32)}`;
    const otherProjectHandle = `runfree_oauth_access_${"p".repeat(32)}`;
    handles[expiredHandle] = { ...original, handle: expiredHandle, expiresAt: new Date(Date.now() - 60_000).toISOString() };
    handles[otherProjectHandle] = { ...original, handle: otherProjectHandle, projectId: "fedcba987654" };
    writeHandles(oauthStateDir, { ...state, handles });

    for (const [label, handle, reason] of [
      ["fabricated", `runfree_oauth_access_${"f".repeat(32)}`, "unknown OAuth token handle"],
      ["expired", expiredHandle, "expired OAuth token handle"],
      ["other project", otherProjectHandle, "OAuth token handle belongs to another project"],
      ["wrong resource", accessHandle, "OAuth token handle used for the wrong resource"],
    ] as const) {
      for (const [method, pathName] of [["GET", INFO_REFS], ["POST", UPLOAD_PACK]] as const) {
        const mark = checkpoint(proxy, upstream);
        const response = await viaProxy(proxy, upstream, {
          method,
          path: pathName,
          headers: { Authorization: `Bearer ${handle}` },
          ...(method === "POST" ? { body: "0000" } : {}),
        });
        expect(response.statusCode, `${label} ${method}`).toBe(403);
        expect(response.body, `${label} ${method}`).toContain(reason);
        expect(response.raw, `${label} ${method}`).not.toContain(TOKEN);
        expectNothingSince(proxy, upstream, mark, `${label} ${method}`);
      }
    }
  }, 40_000);

  // D-8 (open): a preserved Basic client_secret handle on a git path that is
  // not a token endpoint. This pins the observed behavior; it is not a
  // statement that the behavior is the intended end state.
  // Pinned both with an OAuth provider whose token endpoint is on the same
  // host and with no OAuth provider at all (the usual github.com project).
  test("D-8: a fabricated Basic client_secret handle on a git path is preserved, not injected over, and forwarded unchanged", async () => {
    const handleAuthorization = `Basic ${Buffer.from(`x-access-token:runfree_oauth_secret_${"b".repeat(32)}`).toString("base64")}`;
    for (const oauth of [true, false]) {
      const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write" }, writeApproval: "allow", oauth });
      const mark = checkpoint(proxy, upstream);
      const events = admittedCount(proxy, "/owner/repo.git/info/refs");

      const response = await viaProxy(proxy, upstream, { path: INFO_REFS, headers: { Authorization: handleAuthorization } });

      expect(response.statusCode, `oauth=${oauth}`).toBe(200);
      expect(upstream.requests, `oauth=${oauth}`).toHaveLength(mark.requests + 1);
      expect(upstream.requests.at(-1)?.headers.authorization, `oauth=${oauth}`).toBe(handleAuthorization);
      expect(secretReadsSince(proxy, mark), `oauth=${oauth}`).toEqual([]);
      expect(await lastCredentialAction(proxy, "/owner/repo.git/info/refs", events), `oauth=${oauth}`).toBe("preserved");
      expect(proxy.output(), `oauth=${oauth}`).not.toContain(`proxy: injected Authorization for ${GIT_HOST}`);
      await proxy.stop();
    }
  }, 40_000);
});

describe("proxy server git over HTTPS: cross-host redirect (T9)", () => {
  test("a 302 from a credentialed git request passes through unchanged and the follow-up to an unmapped host carries no Authorization", async () => {
    const { proxy, upstream } = await startGitProxy({ rule: { gitPush: "write" }, writeApproval: "allow" });

    const redirect = await viaProxy(proxy, upstream, { path: REDIRECTING_INFO_REFS });
    const expectedLocation = `https://${REDIRECT_HOST}:${upstream.port}${INFO_REFS}`;
    expect(redirect.statusCode).toBe(302);
    expect(redirect.headers.location).toBe(expectedLocation);
    expect(redirect.headers["x-upstream-marker"]).toBe("redirect");
    expect(redirect.body).toBe("moved\n");
    expect(redirect.raw).not.toContain(TOKEN);
    expect(redirect.raw).not.toContain(INJECTED_BASIC.slice("Basic ".length));
    // The redirecting request itself was a credentialed git request.
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe(INJECTED_BASIC);

    // The client follows the redirect as a new request; nothing carries the
    // injected value to the next host.
    const location = new URL(expectedLocation);
    const mark = checkpoint(proxy, upstream);
    const followed = await viaProxy(proxy, upstream, { host: location.hostname, path: `${location.pathname}${location.search}` });
    expect(followed.statusCode).toBe(200);
    expect(upstream.requests).toHaveLength(2);
    expect(upstream.requests[1].headers.host).toBe(`${REDIRECT_HOST}:${upstream.port}`);
    expect(upstream.requests[1].headers.authorization).toBeUndefined();
    expect(secretReadsSince(proxy, mark)).toEqual([]);
  }, 30_000);
});
