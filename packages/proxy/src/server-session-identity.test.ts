import fs from "node:fs";
import net from "node:net";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  APPROVALS_WATCHER_HEARTBEAT_FILE,
  APPROVALS_PROCESS_EPOCH_FILE,
  parsePendingApprovalRecord,
  type PendingApprovalRecord,
} from "@runfree/runtime-contracts/write-approvals";
import {
  createSessionAdmissionEligibility,
  SESSION_ADMISSION_PROVISIONING_REQUEST,
  serializeSessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  serializeSessionFileV1,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";
import {
  httpsViaProxy,
  httpsRequestOverTunnel,
  openConnectTunnel,
  rawConnectViaProxy,
  parseHttpResponse,
  readUntil,
  startHttpsUpstream,
  replaceFileAtomically,
  startProxy,
  tlsHandshakeOverTunnel,
  tmp,
  waitUntil,
  type RunningProxy,
} from "./server.test-harness.ts";

const OWN_UID = String(process.getuid?.() ?? 0);
const DIGEST = `sha256:${"c".repeat(64)}`;
const KEY_A = "a".repeat(64);
const KEY_B = "b".repeat(64);
const PROJECT_ID = "0123456789ab";

type TestState = {
  decisionsDir: string;
  pendingDir: string;
  registryDir: string;
};

function state(): TestState {
  const root = fs.mkdtempSync(path.join(tmp, "session-identity-"));
  const decisionsDir = path.join(root, "decisions");
  const pendingDir = path.join(root, "pending");
  const registryDir = path.join(root, "registry");
  for (const dir of [decisionsDir, pendingDir]) fs.mkdirSync(dir, { mode: 0o700 });
  fs.mkdirSync(registryDir, { mode: 0o755 });
  fs.mkdirSync(path.join(registryDir, "sessions"), { mode: 0o755 });
  return { decisionsDir, pendingDir, registryDir };
}

function sessionFile(sessionKey: string, overrides: Partial<SessionFileV1> = {}): SessionFileV1 {
  const inspectedAt = new Date(Date.now() - 1_000);
  return {
    v: 1,
    projectId: PROJECT_ID,
    sessionKey,
    sessionId: sessionKey === KEY_A ? "rf-20260805-aaaaaa" : "rf-20260805-bbbbbb",
    sessionIncarnation: sessionKey === KEY_A ? "d".repeat(64) : "e".repeat(64),
    sourceIp: "127.0.0.1",
    containerId: sessionKey === KEY_A ? "f".repeat(64) : "1".repeat(64),
    networkId: "2".repeat(64),
    selectedAgentImageId: DIGEST,
    sessionAgentGenerationDigest: DIGEST,
    controlPlaneGenerationDigest: DIGEST,
    admissionContractEpoch: 1,
    name: sessionKey === KEY_A ? "payments" : "release",
    command: "codex",
    startedAt: new Date(Date.now() - 60_000).toISOString(),
    nonce: sessionKey === KEY_A ? "3".repeat(32) : "4".repeat(32),
    inspectedAt: inspectedAt.toISOString(),
    // Far past any CPU-starved run's wall clock (a 60s horizon has lapsed
    // mid-test under worker starvation), yet under the 5-minute maximum the
    // file validity rule clamps the monotonic bound to.
    aliveUntil: new Date(inspectedAt.getTime() + 240_000).toISOString(),
    ...overrides,
  };
}

function writeEligibility(testState: TestState): void {
  // Atomic like the host publisher: the proxy scans every 100 ms and reads a
  // torn eligibility file as "nothing is admitted", which drops every live
  // context (see replaceFileAtomically).
  replaceFileAtomically(
    path.join(testState.registryDir, "eligibility.json"),
    serializeSessionAdmissionEligibility(createSessionAdmissionEligibility({
      projectId: PROJECT_ID,
      controlPlaneGenerationDigest: DIGEST,
      admissionContractEpoch: 1,
      agentInternalNetworkId: "2".repeat(64),
      allowedSessionAgents: [{
        sessionAgentGenerationDigest: DIGEST,
        selectedAgentImageId: DIGEST,
      }],
    })),
  );
}

/** Replaces the served set with exactly `files`, atomically per file. */
function writeSessionFiles(testState: TestState, files: readonly SessionFileV1[]): void {
  writeEligibility(testState);
  const sessionsDir = path.join(testState.registryDir, "sessions");
  const keep = new Set(files.map((file) => `${file.sessionKey}.json`));
  for (const name of fs.readdirSync(sessionsDir)) {
    if (!keep.has(name)) fs.rmSync(path.join(sessionsDir, name), { force: true });
  }
  // Atomic like the host publisher: the proxy scans this directory every 100ms
  // and must never read a torn file (see replaceFileAtomically).
  for (const file of files) {
    replaceFileAtomically(path.join(sessionsDir, `${file.sessionKey}.json`), serializeSessionFileV1(file));
  }
}

function sourceIdentityEnv(testState: TestState): NodeJS.ProcessEnv {
  return {
    RUNFREE_PROJECT_ID: PROJECT_ID,
    RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
    RUNFREE_SESSION_ADMISSION_SOURCE: "files",
    RUNFREE_SESSION_REGISTRY_DIR: testState.registryDir,
    RUNFREE_SESSION_REGISTRY_OWNER_UID: OWN_UID,
    RUNFREE_APPROVALS_PENDING_DIR: testState.pendingDir,
    RUNFREE_APPROVALS_DECISIONS_DIR: testState.decisionsDir,
    RUNFREE_APPROVALS_DECISION_OWNER_UID: OWN_UID,
    RUNFREE_WRITE_APPROVAL_HOLD_SECONDS: "5",
  };
}

function askPolicy(): unknown {
  return {
    hosts: ["127.0.0.1"],
    tokens: {},
    requests: { "127.0.0.1": { writeAction: "ask" } },
  };
}

function attachWatcher(testState: TestState): void {
  fs.writeFileSync(path.join(testState.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE), fs.existsSync(path.join(testState.pendingDir, APPROVALS_PROCESS_EPOCH_FILE)) ? fs.readFileSync(path.join(testState.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8") : "watch-requested");
}

async function pendingRecord(testState: TestState): Promise<PendingApprovalRecord> {
  let record: PendingApprovalRecord | undefined;
  await waitUntil(() => {
    const name = fs.readdirSync(testState.pendingDir).filter((name) => name.endsWith(".json"))[0];
    if (!name) return false;
    record = parsePendingApprovalRecord(fs.readFileSync(path.join(testState.pendingDir, name), "utf8"));
    return record !== undefined;
  }, "session-attributed pending record");
  if (!record) throw new Error("pending record missing");
  return record;
}

function decide(testState: TestState, id: string, fields: Record<string, unknown>): void {
  fs.writeFileSync(path.join(testState.decisionsDir, `${id}.json`), JSON.stringify({
    v: 1,
    id,
    processEpoch: fs.readFileSync(path.join(testState.pendingDir, APPROVALS_PROCESS_EPOCH_FILE), "utf8"),
    decidedAt: new Date().toISOString(),
    ...fields,
  }));
}

async function startSessionProxy(
  testState: TestState,
  extraEnv: NodeJS.ProcessEnv = {},
  policy: unknown = askPolicy(),
): Promise<RunningProxy> {
  const proxy = await startProxy({ extraEnv: { ...sourceIdentityEnv(testState), ...extraEnv }, policy });
  if (fs.existsSync(path.join(testState.decisionsDir, APPROVALS_WATCHER_HEARTBEAT_FILE))) attachWatcher(testState);
  return proxy;
}

/**
 * Waits for the proxy's 100 ms scan to serve the file tree as written.
 *
 * The host publisher replaces one session file at a time, so a set change is
 * not atomic across sessions: between the delete and the write nothing is
 * served, and a request sent into that window is refused. Every test that
 * rewrites the served set waits here first, using the readiness bytes the
 * session entry itself polls — the one locally answered signal that says
 * "this peer is served right now".
 */
async function waitUntilServed(proxyPort: number, served = true): Promise<void> {
  const expected = served ? 200 : 403;
  const deadline = Date.now() + 8_000;
  let last = "none";
  while (Date.now() < deadline) {
    try {
      const response = await completeRawProxyRequest(proxyPort, SESSION_ADMISSION_PROVISIONING_REQUEST);
      if (response.statusCode === expected) return;
      last = String(response.statusCode);
    } catch (error) {
      last = String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for a ${served ? "served" : "unserved"} session peer (last answer ${last})`);
}

async function openRawProxyRequest(proxyPort: number, request: string): Promise<ReturnType<typeof parseHttpResponse>> {
  const socket = net.connect({ host: "127.0.0.1", port: proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.on("error", () => {});
  socket.write(request);
  try {
    return parseHttpResponse(await readUntil(socket, "\r\n\r\n"));
  } finally {
    socket.destroy();
  }
}

async function completeRawProxyRequest(
  proxyPort: number,
  request: string,
): Promise<ReturnType<typeof parseHttpResponse>> {
  const socket = net.connect({ host: "127.0.0.1", port: proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  const chunks: Buffer[] = [];
  socket.on("data", (chunk: Buffer) => chunks.push(chunk));
  socket.end(request);
  await new Promise<void>((resolve, reject) => {
    socket.once("end", resolve);
    socket.once("error", reject);
  });
  return parseHttpResponse(Buffer.concat(chunks));
}

describe("proxy server startup refusal without source-ip identity config", () => {
  // Negative-before-side-effect (fixes review F1): source-ip-v1 is the only
  // identity mode, and the request proxy must exit non-ready — before its
  // listener binds — when the identity or registry configuration is absent or
  // wrong. There is no fallback mode to fail open into.
  test.each([
    ["identity mode absent", {}, /RUNFREE_SESSION_IDENTITY_MODE must be "source-ip-v1"/],
    [
      "identity mode is the retired runtime-wide mode",
      { RUNFREE_SESSION_IDENTITY_MODE: "runtime-v1", RUNFREE_PROJECT_ID: PROJECT_ID },
      /RUNFREE_SESSION_IDENTITY_MODE must be "source-ip-v1"/,
    ],
    [
      "registry dir configured empty",
      {
        RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
        RUNFREE_SESSION_REGISTRY_DIR: "  ",
        RUNFREE_PROJECT_ID: PROJECT_ID,
      },
      /session registry directory/,
    ],
    [
      "project id absent",
      { RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1", RUNFREE_PROJECT_ID: "" },
      /RUNFREE_PROJECT_ID is required/,
    ],
    [
      "the admission source is absent",
      {
        RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
        RUNFREE_PROJECT_ID: PROJECT_ID,
        RUNFREE_SESSION_REGISTRY_DIR: "/run/runfree-sessions",
      },
      /RUNFREE_SESSION_ADMISSION_SOURCE must be "files", got <absent>/,
    ],
    [
      "the admission source names the retired transaction protocol",
      {
        RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
        RUNFREE_PROJECT_ID: PROJECT_ID,
        RUNFREE_SESSION_REGISTRY_DIR: "/run/runfree-sessions",
        RUNFREE_SESSION_ADMISSION_SOURCE: "generations",
      },
      /RUNFREE_SESSION_ADMISSION_SOURCE must be "files"/,
    ],
  ])("exits before listening when %s", async (_label, extraEnv, message) => {
    let failure: Error | undefined;
    try {
      await startProxy({
        extraEnv: extraEnv as NodeJS.ProcessEnv,
        policy: { hosts: [] },
        provisionSession: false,
      });
    } catch (error) {
      failure = error as Error;
    }
    if (!failure) throw new Error("proxy started despite missing source-ip identity configuration");
    // The harness rejection carries the child's exit and full output: the
    // process died before ever logging a listen line, so no listener existed.
    expect(failure.message).toContain("proxy exited before listening");
    expect(failure.message).toMatch(message);
    expect(failure.message).not.toContain("proxy: listening on");
  }, 20_000);
});

describe("proxy server source-IP session identity", () => {
  test("rejects unregistered and expired peers at CONNECT before policy, approval, or upstream", async () => {
    const testState = state();
    const upstream = await startHttpsUpstream();
    const proxy = await startSessionProxy(testState, { NODE_EXTRA_CA_CERTS: upstream.certPath });
    const unregistered = await rawConnectViaProxy({ authority: "127.0.0.1:443", proxyPort: proxy.port });
    expect(unregistered.statusCode).toBe(403);
    expect(unregistered.body).toContain("unregistered session peer");
    expect(fs.readdirSync(testState.pendingDir).filter((name) => name.endsWith(".json"))).toEqual([]);
    expect(upstream.acceptedConnections()).toBe(0);

    const lapsed = new Date(Date.now() - 10_000);
    writeSessionFiles(testState, [sessionFile(KEY_A, {
      inspectedAt: lapsed.toISOString(),
      aliveUntil: new Date(lapsed.getTime() + 1_000).toISOString(),
    })]);
    // The proxy's 100 ms scan has to observe the rewritten tree before it can
    // report the file as expired rather than as an unreadable registry.
    let expired = await rawConnectViaProxy({ authority: "127.0.0.1:443", proxyPort: proxy.port });
    const deadline = Date.now() + 8_000;
    while (!expired.body.includes("expired") && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
      expired = await rawConnectViaProxy({ authority: "127.0.0.1:443", proxyPort: proxy.port });
    }
    expect(expired.statusCode).toBe(403);
    expect(expired.body).toContain("expired");
    expect(fs.readdirSync(testState.pendingDir).filter((name) => name.endsWith(".json"))).toEqual([]);
    expect(upstream.acceptedConnections()).toBe(0);
  }, 20_000);

  test("answers an active peer's exact readiness request locally with 200 active and no side effects", async () => {
    // Activation-gate design D2: the session entry polls the same readiness
    // bytes until the proxy reports the session active. The answer is local
    // (nothing forwarded, no DNS, no credential, no admission record, no
    // denial event), and only whole-buffer equality reaches it — any other
    // byte from an active peer keeps today's pass-through behavior.
    const testState = state();
    attachWatcher(testState);
    writeSessionFiles(testState, [sessionFile(KEY_A)]);
    const upstream = await startHttpsUpstream();
    const proxy = await startSessionProxy(testState, { NODE_EXTRA_CA_CERTS: upstream.certPath });

    const active = await completeRawProxyRequest(proxy.port, SESSION_ADMISSION_PROVISIONING_REQUEST);
    expect(active.statusCode).toBe(200);
    expect(active.body).toBe("active");
    // Single-request semantics: the guard ends the connection itself.
    expect(active.headers.connection).toBe("close");
    expect(fs.readdirSync(testState.pendingDir).filter((name) => name.endsWith(".json"))).toEqual([]);
    expect(upstream.acceptedConnections()).toBe(0);
    expect(proxy.output()).not.toMatch(/proxy-denial:/);

    // The same bytes plus one header are not the readiness request: an active
    // peer's ordinary absolute-form GET still passes through to the request
    // layer, which refuses it there (plain HTTP is never forwarded) rather
    // than at the guard. Sent full-duplex: the pass-through does not answer a
    // client that half-closes after its head, which the local answer above
    // does not care about.
    const altered = await openRawProxyRequest(proxy.port, SESSION_ADMISSION_PROVISIONING_REQUEST.replace(
      "Connection: close",
      "X-Runfree-Test: extra\r\nConnection: close",
    ));
    expect(altered.statusCode).toBe(403);
    expect(altered.body).not.toBe("active");
    expect(upstream.acceptedConnections()).toBe(0);
    // An unserved peer's 403 is proved by the first test in this block; the
    // compiled probe is run against both states in
    // `scripts/session-entry.test.ts`.
  }, 20_000);

  test("carries the CONNECT peer binding into the held request and isolates IP reuse", async () => {
    const testState = state();
    attachWatcher(testState);
    writeSessionFiles(testState, [sessionFile(KEY_A)]);
    const upstream = await startHttpsUpstream();
    const proxy = await startSessionProxy(testState, { NODE_EXTRA_CA_CERTS: upstream.certPath });
    await waitUntilServed(proxy.port);

    const firstResponse = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/write-a",
      headers: { "X-Runfree-Session-Key": KEY_B },
    });
    const first = await pendingRecord(testState);
    expect(first.session).toMatchObject({ sessionId: "rf-20260805-aaaaaa", name: "payments", command: "codex" });
    expect(first.session).not.toHaveProperty("sessionKey");
    decide(testState, first.id, { decision: "approve", scope: "session" });
    expect((await firstResponse).statusCode).toBe(200);
    expect(upstream.requests[0]?.headers).not.toHaveProperty("x-runfree-session-key");

    // Two observable steps, because a readiness answer cannot tell one served
    // session from another: first prove the address is unserved (KEY_A's file
    // is gone, so its grant is dropped), then prove KEY_B is served.
    writeSessionFiles(testState, []);
    await waitUntilServed(proxy.port, false);
    writeSessionFiles(testState, [sessionFile(KEY_B)]);
    await waitUntilServed(proxy.port);
    attachWatcher(testState);
    const secondResponse = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/write-b",
    });
    const second = await pendingRecord(testState);
    expect(second.session).toMatchObject({ sessionId: "rf-20260805-bbbbbb", name: "release" });
    decide(testState, second.id, { decision: "deny" });
    expect((await secondResponse).statusCode).toBe(403);
  }, 30_000);

  test("the IP fence closes an incomplete CONNECT before acknowledging the new owner", async () => {
    const testState = state();
    writeSessionFiles(testState, [sessionFile(KEY_A)]);
    const upstream = await startHttpsUpstream();
    const proxy = await startSessionProxy(testState);
    await waitUntilServed(proxy.port);
    const socket = net.connect({ host: "127.0.0.1", port: proxy.port });
    socket.on("error", () => {});
    socket.resume();
    await new Promise<void>((resolve) => socket.once("connect", resolve));
    socket.write("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost:");
    const nonce = "7".repeat(32);
    const assignment = { v: 1, sourceIp: "127.0.0.1", sessionKey: KEY_B, nonce, state: "draining" };
    const assignmentPath = path.join(testState.registryDir, "ip-reuse/requests/127.0.0.1.json");
    const ackPath = path.join(testState.registryDir, "ip-reuse/request-proxy/127.0.0.1.json");
    try {
      replaceFileAtomically(assignmentPath, JSON.stringify(assignment));
      await waitUntil(() => fs.existsSync(ackPath), "IP fence acknowledgement");
      expect(fs.readFileSync(ackPath, "utf8")).toBe(`${nonce}\n`);
      await waitUntil(() => socket.destroyed, "incomplete CONNECT closure");
      expect(upstream.acceptedConnections()).toBe(0);
      replaceFileAtomically(assignmentPath, JSON.stringify({ ...assignment, state: "ready" }));
      writeSessionFiles(testState, [sessionFile(KEY_A), sessionFile(KEY_B)]);
      await waitUntilServed(proxy.port);
      expect(socket.destroyed).toBe(true);
      const response = await rawConnectViaProxy({ proxyPort: proxy.port, authority: "127.0.0.1:443" });
      expect(response.statusCode).toBe(200);
    } finally {
      socket.destroy();
    }
  }, 20_000);

  test("a changed session binding closes an already-open idle tunnel before upstream", async () => {
    const testState = state();
    writeSessionFiles(testState, [sessionFile(KEY_A)]);
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: sourceIdentityEnv(testState),
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });
    const tunnel = await openConnectTunnel({ authority: "127.0.0.1:443", proxyPort: proxy.port });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket);
    writeSessionFiles(testState, [sessionFile(KEY_A, {
      selectedAgentImageId: `sha256:${"9".repeat(64)}`,
    })]);
    await waitUntil(() => tlsSocket.destroyed, "revoked session tunnel closure");
    expect(upstream.acceptedConnections()).toBe(0);
  }, 20_000);

  test("an established tunnel survives two valid nonce-only rollovers", async () => {
    const testState = state();
    writeSessionFiles(testState, [sessionFile(KEY_A)]);
    const upstream = await startHttpsUpstream();
    const proxy = await startProxy({
      extraEnv: {
        ...sourceIdentityEnv(testState),
        NODE_EXTRA_CA_CERTS: upstream.certPath,
      },
      policy: { hosts: ["127.0.0.1"], tokens: {}, writeApproval: "allow" },
    });
    const tunnel = await openConnectTunnel({ authority: "127.0.0.1:443", proxyPort: proxy.port });
    expect(tunnel.head.statusCode).toBe(200);
    const tlsSocket = await tlsHandshakeOverTunnel(tunnel.socket);

    for (const nonce of ["5".repeat(32), "6".repeat(32)]) {
      writeSessionFiles(testState, [sessionFile(KEY_A, { nonce })]);
      const refreshResponse = await httpsViaProxy({
        proxyPort: proxy.port,
        targetPort: upstream.port,
        path: `/refresh-${nonce[0]}`,
      });
      expect(refreshResponse.statusCode).toBe(200);
      expect(tlsSocket.destroyed).toBe(false);
    }

    const response = await httpsRequestOverTunnel(tlsSocket, {
      host: "127.0.0.1",
      path: "/after-two-renewals",
      targetPort: upstream.port,
    });
    expect(response.statusCode).toBe(200);
    expect(upstream.requests.at(-1)?.url).toBe("/after-two-renewals");
  }, 20_000);

  test("a session approval grant survives a valid nonce-only rollover", async () => {
    const testState = state();
    attachWatcher(testState);
    writeSessionFiles(testState, [sessionFile(KEY_A)]);
    const upstream = await startHttpsUpstream();
    const proxy = await startSessionProxy(testState, { NODE_EXTRA_CA_CERTS: upstream.certPath });

    const firstResponse = httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/grant-before-renewal",
    });
    const pending = await pendingRecord(testState);
    decide(testState, pending.id, { decision: "approve", scope: "session" });
    expect((await firstResponse).statusCode).toBe(200);
    expect(fs.readdirSync(testState.pendingDir).filter((name) => name.endsWith(".json"))).toEqual([]);

    writeSessionFiles(testState, [sessionFile(KEY_A, { nonce: "7".repeat(32) })]);
    const renewedResponse = await httpsViaProxy({
      proxyPort: proxy.port,
      targetPort: upstream.port,
      method: "POST",
      path: "/grant-after-renewal",
    });

    expect(renewedResponse.statusCode).toBe(200);
    expect(fs.readdirSync(testState.pendingDir).filter((name) => name.endsWith(".json"))).toEqual([]);
  }, 20_000);
});
