// One-step MCP enable tranche (todo 65).
//
// Proves on a real backend that one `runfree mcp enable` command, on a project
// that never enabled this server, makes the proxy admit the MCP endpoint host
// and its OAuth hosts, with no `host add`; that a host `enable` projects from a
// discovery record is narrowed to `/.well-known` and its exact endpoints, so any
// other path is refused before an upstream connection; and that `mcp revoke`
// removes exactly the hosts `enable` added, while a host the user added with
// `host add` and a host another enabled server still names stay allowed.
//
// Todo 78 adds two proofs. A protocol-shaped POST to the exact recorded,
// mediated token endpoint is an OAuth protocol read and passes the ask-default
// write posture with no approver attached, while a non-protocol body there
// still needs approval. A grant POST to any other path on that host, or to an
// `--oauth-host` host with no recorded endpoint, is refused outright as an
// unmediated OAuth request. And `mcp revoke` clears the server's proxy
// OAuth state through its state epoch: a handle seeded into the proxy's OAuth
// volume survives an unrelated policy activation (a stale-epoch one does not),
// a revoke that leaves the server in the policy deletes it, and the revoke
// says "cleared" only because the live proxy confirmed the generation.
//
// The cross-host token endpoint proofs (L1-L4): a token endpoint a record
// places on another host is mediated there and nowhere else on that host; a
// grant POSTed to an `--oauth-host` host is refused as unmediated, before any
// upstream connection, approval hold, or OAuth state write, until the proxy
// has bound an endpoint there; and a cross-host claim whose host becomes a
// credential destination is dropped and its endpoint blocked, until the
// credential is removed.
//
// The client metadata proofs: a token POST whose client_id is a pinned agent
// client metadata URL is a protocol read, any other URL client_id needs
// approval, and the pinned agent binaries carry exactly the pinned URLs.
//
// Discovery itself cannot run here: by design it refuses non-public addresses,
// and every probe host is an unresolvable `.invalid` name (the proxy decision is
// the subject; an admitted request comes back as the proxy's upstream-failure
// 502). The command runs without a terminal, so it uses `--no-discover` with
// named hosts; the discovered-record shape is written directly into host-owned
// state, the way `mcp enable` writes it after a reviewed discovery. Discovery is
// proven by the unit suite (`packages/cli/src/admin/mcp-discovery.test.ts`).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { projectInfo } from "../../../packages/cli/src/config.ts";
import { projectHash } from "../../../packages/cli/src/project-identity.ts";
import { nodeRuntimeIO } from "../../../packages/cli/src/runtime.ts";
import { readPendingApprovals, touchWatcherHeartbeat } from "../../../packages/cli/src/runtime/approvals.ts";
import { type McpEnabledRecord, readMcpEnabled } from "../../../packages/cli/src/runtime/mcp-enabled.ts";
import { CLIENT_ID_METADATA_URLS } from "../../../packages/proxy/src/oauth-protocol-read.ts";
import { APPROVALS_DECISIONS_DIR, APPROVALS_WATCHER_HEARTBEAT_FILE } from "../../../packages/runtime-contracts/src/write-approvals.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  provisionSandboxFixture,
  startStandingSession,
  type StandingSessionHandle,
} from "./fixture.ts";
import {
  admittedToUnresolvableHost,
  curlProbeCommand,
  enableProxyVerboseLogging,
  parseProbeAnswer,
  type ProbeAnswer,
  proxyAdmittedEventCount,
} from "./proxy-answer.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;

/** The HTTP MCP server enabled in one command. */
const ENABLE_SERVER = "enableProbe";
const ENABLE_ENDPOINT_HOST = "runfree-enable-mcp.invalid";
/** Named with --oauth-host; only `enable` allows it. */
const ENABLE_OAUTH_HOST = "runfree-enable-auth.invalid";
/** Also named with --oauth-host, but the user added it first with `host add`. */
const USER_HOST = "runfree-enable-keep.invalid";
/** A second approved server whose record has the discovered, narrowed shape. */
const NARROW_SERVER = "narrowProbe";
const NARROW_ENDPOINT_HOST = "runfree-narrow-mcp.invalid";
const NARROW_IDP_HOST = "runfree-narrow-idp.invalid";
/** L1: a discovered issuer whose token endpoint is on a second host (crossHost). */
const CROSS_SERVER = "crossProbe";
const CROSS_ENDPOINT_HOST = "runfree-cross-mcp.invalid";
const CROSS_IDP_HOST = "runfree-cross-idp.invalid";
const CROSS_TOKEN_HOST = "runfree-cross-token.invalid";
/** L2, L3: an `--oauth-host` (user) host that only its enable record allows. */
const BOUND_SERVER = "boundProbe";
const BOUND_ENDPOINT_HOST = "runfree-bound-mcp.invalid";
const BOUND_AUTH_HOST = "runfree-bound-auth.invalid";
/** L4: a cross-host claim whose host later becomes a credential destination. */
const DROP_SERVER = "dropProbe";
const DROP_ENDPOINT_HOST = "runfree-drop-mcp.invalid";
const DROP_IDP_HOST = "runfree-drop-idp.invalid";
const DROP_TOKEN_HOST = "runfree-drop-token.invalid";
const DROP_CREDENTIAL = "drop-probe";
/** Set by `provisionSandboxFixture` before the fixture snapshots its env. */
const DROP_CREDENTIAL_ENV = "RUNFREE_SANDBOX_STRIP_TOKEN";
const TOKEN_PATH = "/oauth/token";
const METADATA_PATH = "/.well-known/oauth-authorization-server";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the mcp-enable tranche");
  }
  return backend;
}

function sessionExec(id: string, script: string): CaptureResult {
  return docker(["exec", id, "zsh", "-lc", script]);
}

const PROBE_BODY_FILE = "/tmp/runfree-mcp-enable-probe.body";
const PROBE_BODY_MARKER = "runfree-probe-body-follows";

/** One request from the session; `body` is the response body the agent received. */
function probe(
  sessionId: string,
  url: string,
  method?: string,
  request: { body?: string; headers?: readonly string[]; http1?: boolean } = {},
): ProbeAnswer & { detail: string; body: string } {
  const command = curlProbeCommand(url, { maxTimeSeconds: 15, insecure: true, bodyFile: PROBE_BODY_FILE, ...(method ? { method } : {}), ...request });
  const result = sessionExec(sessionId, `rm -f ${PROBE_BODY_FILE}; ${command}; printf '%s\\n' ${PROBE_BODY_MARKER}; cat ${PROBE_BODY_FILE} 2>/dev/null`);
  const at = result.stdout.lastIndexOf(PROBE_BODY_MARKER);
  const headers = at < 0 ? result.stdout : result.stdout.slice(0, at);
  const body = at < 0 ? "" : result.stdout.slice(at + PROBE_BODY_MARKER.length);
  return { ...parseProbeAnswer(headers), detail: describeOutput(result.output), body };
}

const FORM = ["Content-Type: application/x-www-form-urlencoded"];
/** The proxy's denial for an OAuth grant to an endpoint no provider mediates. */
const OAUTH_NOT_MEDIATED = "oauth-endpoint-not-mediated";
const LOGIN_BODY = "grant_type=authorization_code&code=live-probe-code&redirect_uri=http%3A%2F%2Flocalhost%3A33418%2Fcallback&code_verifier=v";
const OAUTH_STATE_FILE = "/run/runfree-oauth/handles.json";
const NARROW_PROVIDER = `mcp:claude-${NARROW_SERVER.toLowerCase()}`;
const CROSS_PROVIDER = `mcp:claude-${CROSS_SERVER.toLowerCase()}`;
const BOUND_PROVIDER = `mcp:claude-${BOUND_SERVER.toLowerCase()}`;
const DROP_PROVIDER = `mcp:claude-${DROP_SERVER.toLowerCase()}`;
const SEEDED_TOKEN = "live-seeded-real-access-token";
const SEEDED_HANDLE = `runfree_oauth_access_${"l".repeat(32)}`;
const STALE_TOKEN = "live-stale-epoch-real-access-token";
const STALE_HANDLE = `runfree_oauth_access_${"s".repeat(32)}`;

function proxyContainerId(fixture: LiveFixture): string {
  return composeServiceContainerId(composeProjectName(fixture), "proxy");
}

function readProxyOAuthState(proxyId: string): string {
  const result = docker(["exec", "--user", "0:0", proxyId, "sh", "-c", `cat ${OAUTH_STATE_FILE} 2>/dev/null || printf '{}'`]);
  expect(result.status, `could not read the proxy OAuth state: ${describeOutput(result.output)}`).toBe(0);
  return result.stdout;
}

type ProxyOAuthState = { handles?: Record<string, unknown>; discovered?: Record<string, unknown> };

/** Writes one handle into the proxy's OAuth volume, as a real login would. */
function seedProxyOAuthHandle(proxyId: string, handle: Record<string, unknown>): void {
  updateProxyOAuthState(proxyId, (state) => {
    state.handles = { ...(state.handles ?? {}), [String(handle.handle)]: handle };
  });
}

/** Replaces the proxy's OAuth state file atomically, owned by the proxy user. */
function updateProxyOAuthState(proxyId: string, change: (state: ProxyOAuthState) => void): void {
  const state = JSON.parse(readProxyOAuthState(proxyId)) as ProxyOAuthState;
  change(state);
  const encoded = Buffer.from(JSON.stringify(state)).toString("base64");
  dockerOrThrow("seed proxy OAuth state", [
    "exec", "--user", "0:0", proxyId, "sh", "-c",
    `printf %s '${encoded}' | base64 -d > ${OAUTH_STATE_FILE}.seed && chown 1001:1001 ${OAUTH_STATE_FILE}.seed && chmod 600 ${OAUTH_STATE_FILE}.seed && mv ${OAUTH_STATE_FILE}.seed ${OAUTH_STATE_FILE}`,
  ]);
}

function runOk(fixture: LiveFixture, args: readonly string[]): CaptureResult {
  const result = fixture.runfree(args);
  expect(result.status, `runfree ${args.join(" ")} failed: ${describeOutput(result.output)}`).toBe(0);
  return result;
}

/** The project state dir, read from the approval path `mcp enable` prints. */
function stateDirFrom(enableOutput: string): string {
  const line = enableOutput.split("\n").find((candidate) => candidate.startsWith("approval: "));
  if (!line) throw new Error(`mcp enable printed no approval path: ${describeOutput(enableOutput)}`);
  return path.dirname(line.slice("approval: ".length).trim());
}

function descriptorDigest(fixture: LiveFixture, server: string): string {
  const explained = runOk(fixture, ["mcp", "explain", "claude", server, "--source", "project", "--json"]);
  const digest = (JSON.parse(explained.stdout) as { descriptorDigest?: unknown }).descriptorDigest;
  if (typeof digest !== "string") throw new Error(`mcp explain gave no descriptor digest: ${describeOutput(explained.output)}`);
  return digest;
}

type Endpoint = { host: string; path: string };
type PreparedOAuthPolicy = {
  blockedEndpoints?: Endpoint[];
  recordOnlyHosts?: string[];
  providers: Record<string, {
    bindingHosts?: string[];
    protocolReadEndpoints?: Array<Endpoint | string>;
    resourceHost: string;
    stateEpoch?: string;
    tokenEndpoints?: Array<Endpoint | string>;
  }>;
};

/** The OAuth mediation policy the MCP projection prepared for the proxy. */
function readPreparedOAuthPolicy(stateDir: string): PreparedOAuthPolicy {
  return JSON.parse(fs.readFileSync(path.join(stateDir, "oauth-mediation-policy.json"), "utf8")) as PreparedOAuthPolicy;
}

/**
 * A reviewed discovery's record for an issuer whose metadata named a token
 * endpoint on another host: the token host carries cross-host provenance.
 * Discovery itself refuses `.invalid` and fixture addresses, so the record is
 * written the way `mcp enable` saves it after the review.
 */
function crossHostRecord(fixture: LiveFixture, server: string, idpHost: string, tokenHost: string): McpEnabledRecord {
  const identity = `project:claude:${server}:${descriptorDigest(fixture, server)}`;
  return {
    schemaVersion: 1,
    identity,
    agent: "claude",
    source: "project",
    server,
    enabledAt: new Date().toISOString(),
    oauthHosts: [
      { host: idpHost, origin: "discovered", evidence: ["live fixture record: issuer"] },
      { host: tokenHost, origin: "discovered", evidence: ["live fixture record: token endpoint on another host"], crossHost: true, crossHostKinds: ["token"] },
    ],
    oauthEndpoints: [
      { kind: "metadata", host: idpHost, path: METADATA_PATH },
      { kind: "token", host: tokenHost, path: TOKEN_PATH },
    ],
  };
}

/** Adds records to the host-owned enable file, keeping what is there. */
function addEnableRecords(fixture: LiveFixture, stateDir: string, records: readonly McpEnabledRecord[]): void {
  const enabledPath = path.join(stateDir, "mcp-enabled.json");
  const current = fs.existsSync(enabledPath)
    ? JSON.parse(fs.readFileSync(enabledPath, "utf8")) as { records?: Record<string, unknown> }
    : {};
  const next = {
    ...current,
    schemaVersion: 1,
    projectHash: projectHash(fixture.projectRoot),
    records: { ...(current.records ?? {}), ...Object.fromEntries(records.map((record) => [record.identity, record])) },
  };
  fs.writeFileSync(enabledPath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  // The same validation every projection runs: an invalid record would grant
  // nothing and these cases would prove nothing.
  const read = readMcpEnabled(fixture.projectRoot, enabledPath, { quiet: true });
  expect(read.invalidRecords, "a hand-written cross-host enable record is invalid").toBe(0);
  for (const record of records) expect(read.file.records[record.identity], `${record.server} record was not read back`).toBeDefined();
}

/** The response carries no OAuth token field and no Runfree handle. */
function expectNoTokenInReply(answer: { body: string; detail: string }, label: string): void {
  expect(answer.body, `${label}: the agent received token material: ${answer.detail}`).not.toMatch(/"(?:access|refresh|id)_token"\s*:|runfree_oauth_/u);
}

/**
 * A WebSocket upgrade request, sent over HTTP/1.1 through the proxy. The URL
 * is https: curl sends the upgrade headers itself, so this needs no curl
 * build with WebSocket support; the proxy routes it by its headers.
 */
function webSocketUpgrade(sessionId: string, url: string): ReturnType<typeof probe> {
  return probe(sessionId, url, undefined, {
    http1: true,
    headers: [
      "Connection: Upgrade",
      "Upgrade: websocket",
      "Sec-WebSocket-Version: 13",
      "Sec-WebSocket-Key: cnVuZnJlZS1saXZlLXByb2Jl",
    ],
  });
}

/** Structured `oauth-endpoint-not-mediated` denial events for `host`, over the whole proxy log. */
function oauthDenialEventCount(fixture: LiveFixture, host: string): number {
  const logs = dockerOrThrow("proxy logs", ["logs", proxyContainerId(fixture)]);
  return logs.split(`"reason":"oauth-endpoint-not-mediated","host":"${host}"`).length - 1;
}

function proxyLogs(fixture: LiveFixture): string {
  return dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyContainerId(fixture)]);
}

/**
 * Attaches an approver (a fresh, root-owned watcher heartbeat), so a write the
 * proxy holds for approval becomes a pending record instead of an immediate
 * denial. `detach` deletes the heartbeat, so later probes see no approver.
 */
function attachApprover(fixture: LiveFixture): Readonly<{ context: Parameters<typeof readPendingApprovals>[0]; detach(): void }> {
  const proxyId = proxyContainerId(fixture);
  const context = {
    projectRoot: fixture.projectRoot,
    project: projectInfo(fixture.projectRoot, fixture.env),
    runtimeRoot: path.join(REPO_ROOT, "dist", "runtime"),
    env: fixture.env,
  };
  expect(touchWatcherHeartbeat(context, nodeRuntimeIO, proxyId), "could not register the current proxy approval epoch").toBe(true);
  return {
    context,
    detach: () => {
      dockerOrThrow("detach the approver", ["exec", "--user", "0:0", proxyId, "rm", "-f", `${APPROVALS_DECISIONS_DIR}/${APPROVALS_WATCHER_HEARTBEAT_FILE}`]);
    },
  };
}

describe("one-step MCP enable and exact revoke", () => {
  let fixture: LiveFixture;
  let stateDir: string;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    const mcpPath = path.join(fixture.projectRoot, ".mcp.json");
    const current = JSON.parse(fs.readFileSync(mcpPath, "utf8")) as { mcpServers: Record<string, unknown> };
    current.mcpServers[ENABLE_SERVER] = { type: "http", url: `https://${ENABLE_ENDPOINT_HOST}/mcp` };
    current.mcpServers[NARROW_SERVER] = { type: "http", url: `https://${NARROW_ENDPOINT_HOST}/mcp` };
    fs.writeFileSync(mcpPath, `${JSON.stringify(current)}\n`);
    const added = runOk(fixture, ["host", "add", USER_HOST]);
    expect(added.stdout, "host add did not converge live").toContain("effective policy: live now");
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  describe("one command enables the server and its OAuth hosts", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;
    let enableOutput: string;

    beforeAll(async () => {
      // The second server: approved (enable with no OAuth hosts writes no
      // record), then given a record in the shape a reviewed discovery writes
      // (discovered origin, exact endpoints).
      const approved = runOk(fixture, ["mcp", "enable", "claude", NARROW_SERVER, "--source", "project", "--no-discover", "--no-login"]);
      stateDir = stateDirFrom(approved.stdout);
      const identity = `project:claude:${NARROW_SERVER}:${descriptorDigest(fixture, NARROW_SERVER)}`;
      const enabledPath = path.join(stateDir, "mcp-enabled.json");
      fs.writeFileSync(enabledPath, `${JSON.stringify({
        schemaVersion: 1,
        projectHash: projectHash(fixture.projectRoot),
        records: {
          [identity]: {
            schemaVersion: 1,
            identity,
            agent: "claude",
            source: "project",
            server: NARROW_SERVER,
            enabledAt: new Date().toISOString(),
            oauthHosts: [{ host: NARROW_IDP_HOST, origin: "discovered", evidence: ["live fixture record"] }],
            oauthEndpoints: [
              { kind: "metadata", host: NARROW_IDP_HOST, path: "/.well-known/oauth-authorization-server" },
              { kind: "token", host: NARROW_IDP_HOST, path: "/oauth/token" },
            ],
          },
        },
      }, null, 2)}\n`, { mode: 0o600 });

      // The one command: approval, endpoint, OAuth hosts, activation.
      const enabled = runOk(fixture, [
        "mcp", "enable", "claude", ENABLE_SERVER, "--source", "project",
        "--no-discover", "--oauth-host", ENABLE_OAUTH_HOST, "--oauth-host", USER_HOST, "--no-login",
      ]);
      enableOutput = enabled.output;
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("the command approved, recorded, and activated in one step", () => {
      expect(enableOutput).toContain(`approved project MCP server: claude ${ENABLE_SERVER}`);
      expect(enableOutput).toContain(`OAuth hosts: ${ENABLE_OAUTH_HOST}, ${USER_HOST}`);
      expect(enableOutput).toContain("effective policy: live now (effective policy generation sha256:");
    }, TEST_TIMEOUT_MS);

    test("the proxy admits the MCP endpoint and the named OAuth host", () => {
      for (const url of [`https://${ENABLE_ENDPOINT_HOST}/mcp`, `https://${ENABLE_OAUTH_HOST}/oauth/token`]) {
        const answer = probe(sessionId, url);
        expect(admittedToUnresolvableHost(answer), `${url} was not admitted: ${answer.detail}`).toBe(true);
      }
    }, TEST_TIMEOUT_MS);

    test("a discovered host is limited to /.well-known and its exact endpoints", () => {
      const metadata = probe(sessionId, `https://${NARROW_IDP_HOST}/.well-known/oauth-authorization-server`);
      expect(admittedToUnresolvableHost(metadata), `metadata GET was not admitted: ${metadata.detail}`).toBe(true);
      const other = probe(sessionId, `https://${NARROW_IDP_HOST}/admin/users`);
      expect(other.blocked, `a path outside the recorded endpoints was not refused: ${other.detail}`).toBe("path-not-allowed");
      const put = probe(sessionId, `https://${NARROW_IDP_HOST}/oauth/token`, "PUT");
      expect(put.blocked, `a method outside the OAuth set was not refused: ${put.detail}`).toBe("method-not-allowed");
    }, TEST_TIMEOUT_MS);

    test("a protocol-shaped POST to the recorded, mediated token endpoint needs no approval; other POSTs need approval or are refused", () => {
      // The fixture keeps the ask default with no approver attached, so a
      // write is refused at once and a read is admitted (502 from the
      // unresolvable upstream).
      const login = probe(sessionId, `https://${NARROW_IDP_HOST}/oauth/token`, "POST", { headers: FORM, body: LOGIN_BODY });
      expect(admittedToUnresolvableHost(login), `the login POST was not admitted as a protocol read: ${login.detail}`).toBe(true);
      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyContainerId(fixture)]);
      expect(logs).toContain(`proxy: oauth protocol-read name=${NARROW_PROVIDER} kind=token`);
      expect(logs).not.toContain("live-probe-code");

      // A pinned agent client metadata URL as the client_id is still a read.
      const metadataLogin = probe(sessionId, `https://${NARROW_IDP_HOST}/oauth/token`, "POST", {
        headers: FORM,
        body: `${LOGIN_BODY}&client_id=${encodeURIComponent("https://claude.ai/oauth/claude-code-client-metadata")}`,
      });
      expect(admittedToUnresolvableHost(metadataLogin), `the metadata-URL login was not admitted as a protocol read: ${metadataLogin.detail}`).toBe(true);

      for (const [label, url, body] of [
        ["another grant", `https://${NARROW_IDP_HOST}/oauth/token`, "grant_type=client_credentials&client_id=x"],
        ["an unpinned client_id URL", `https://${NARROW_IDP_HOST}/oauth/token`, `${LOGIN_BODY}&client_id=${encodeURIComponent("https://runfree-attacker.invalid/chunk")}`],
      ] as const) {
        const answer = probe(sessionId, url, "POST", { headers: FORM, body });
        expect(answer.blocked, `${label} was not held for write approval: ${answer.detail}`).toMatch(/^write-approval/);
      }
      // A grant to an endpoint no provider mediates, on a host only MCP
      // records allow, is refused before write approval: its reply would carry
      // real tokens.
      for (const [label, url] of [
        ["another path on the host", `https://${NARROW_IDP_HOST}/.well-known/oauth-authorization-server`],
        ["an --oauth-host host with no recorded endpoint", `https://${ENABLE_OAUTH_HOST}/oauth/token`],
      ] as const) {
        const answer = probe(sessionId, url, "POST", { headers: FORM, body: LOGIN_BODY });
        expect(answer.blocked, `${label} was not refused as an unmediated OAuth grant: ${answer.detail}`).toBe(OAUTH_NOT_MEDIATED);
      }
    }, TEST_TIMEOUT_MS);
  });

  describe("the pinned agent binaries", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    // The proxy treats a URL client_id as a protocol read only on exact match
    // with CLIENT_ID_METADATA_URLS. A vendor URL change in an agent-tools bump
    // would silently send every login to write approval; this fails instead.
    test("carry exactly the client metadata URLs the proxy accepts", () => {
      const binaries: Record<string, string> = {
        "https://claude.ai/oauth/claude-code-client-metadata": "/opt/runfree-agent-tools/node_modules/@anthropic-ai/claude-code-linux-*/claude",
        "https://chatgpt.com/oauth/codex/client.json": "/opt/runfree-agent-tools/node_modules/@openai/codex-linux-*/vendor/*/bin/codex",
      };
      expect(Object.keys(binaries).sort()).toEqual([...CLIENT_ID_METADATA_URLS].sort());
      for (const [url, pattern] of Object.entries(binaries)) {
        // POSIX sh: an unmatched glob stays literal instead of aborting as in zsh.
        const found = docker(["exec", sessionId, "sh", "-c", `for f in ${pattern}; do [ -f "$f" ] && grep -aFq '${url}' "$f" && exit 0; done; exit 1`]);
        expect(found.status, `${url} not found in ${pattern}: ${describeOutput(found.output)}`).toBe(0);
      }
    }, TEST_TIMEOUT_MS);
  });

  describe("revoke removes exactly the hosts enable added", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;
    let revokeOutput: string;

    beforeAll(async () => {
      const revoked = runOk(fixture, ["mcp", "revoke", "claude", ENABLE_SERVER]);
      revokeOutput = revoked.output;
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("the revoke reports the hosts it removed and converges live", () => {
      expect(revokeOutput).toContain(`OAuth hosts no longer allowed for this server: ${ENABLE_OAUTH_HOST}, ${USER_HOST}`);
      expect(revokeOutput).toContain("effective policy: live now (effective policy generation sha256:");
      expect(revokeOutput).toContain(`proxy OAuth state for claude ${ENABLE_SERVER}: cleared (the proxy applied effective policy generation sha256:`);
    }, TEST_TIMEOUT_MS);

    test("the endpoint and the enable-only OAuth host are refused again", () => {
      for (const host of [ENABLE_ENDPOINT_HOST, ENABLE_OAUTH_HOST]) {
        const answer = probe(sessionId, `https://${host}/`);
        expect(answer.blocked, `${host} is still allowed after revoke: ${answer.detail}`).toBe("host-not-allowlisted");
      }
    }, TEST_TIMEOUT_MS);

    test("the host the user added and the other server's host stay allowed", () => {
      const kept = probe(sessionId, `https://${USER_HOST}/`);
      expect(admittedToUnresolvableHost(kept), `${USER_HOST} (host add) was removed by revoke: ${kept.detail}`).toBe(true);
      const other = probe(sessionId, `https://${NARROW_IDP_HOST}/.well-known/oauth-authorization-server`);
      expect(admittedToUnresolvableHost(other), `${NARROW_IDP_HOST} (another server) was removed by revoke: ${other.detail}`).toBe(true);
    }, TEST_TIMEOUT_MS);
  });

  describe("revoke clears the server's proxy OAuth state through its state epoch", () => {
    type PreparedProvider = { resourceHost: string; resourcePathPrefix?: string; stateEpoch?: string };
    let proxyId: string;
    let revokeOutput: string;
    let afterUnrelatedActivation: string;
    let before: PreparedProvider;
    let after: PreparedProvider | undefined;

    function preparedProvider(): PreparedProvider | undefined {
      const prepared = JSON.parse(fs.readFileSync(path.join(stateDir, "oauth-mediation-policy.json"), "utf8")) as {
        providers: Record<string, PreparedProvider>;
      };
      return prepared.providers[NARROW_PROVIDER];
    }

    function seededHandle(handle: string, token: string, stateEpoch: string | undefined): Record<string, unknown> {
      return {
        createdAt: new Date().toISOString(),
        endpointKind: "token",
        handle,
        projectId: projectHash(fixture.projectRoot),
        resourceHost: before.resourceHost,
        resourcePathPrefix: before.resourcePathPrefix ?? "/",
        serverName: NARROW_PROVIDER,
        ...(stateEpoch ? { stateEpoch } : {}),
        token,
        tokenEndpointHost: NARROW_IDP_HOST,
        tokenEndpointPath: "/oauth/token",
        type: "access",
      };
    }

    beforeAll(() => {
      proxyId = proxyContainerId(fixture);
      // The provider as the prepared OAuth policy publishes it (resource and
      // current state epoch), so only an epoch change can make the handle stale.
      const current = preparedProvider();
      expect(current?.stateEpoch, `the prepared OAuth policy publishes no state epoch for ${NARROW_PROVIDER}`).toMatch(/^[a-f0-9]{32}$/);
      before = current as PreparedProvider;
      seedProxyOAuthHandle(proxyId, seededHandle(SEEDED_HANDLE, SEEDED_TOKEN, before.stateEpoch));
      // A handle from an older epoch of the same, still-published server.
      seedProxyOAuthHandle(proxyId, seededHandle(STALE_HANDLE, STALE_TOKEN, "0".repeat(32)));
      const added = runOk(fixture, ["host", "add", "runfree-enable-unrelated.invalid"]);
      expect(added.stdout, "host add did not converge live").toContain("effective policy: live now");
      afterUnrelatedActivation = readProxyOAuthState(proxyId);
      // `--source user` names no project approval and no enable record of this
      // project server, so the server stays in the policy: the proxy can clear
      // its state only through the new epoch, not because the server is gone.
      revokeOutput = runOk(fixture, ["mcp", "revoke", "claude", NARROW_SERVER, "--source", "user"]).output;
      after = preparedProvider();
    }, PROVISION_TIMEOUT_MS);

    test("an unrelated activation keeps the current-epoch handle and deletes the stale-epoch one", () => {
      expect(afterUnrelatedActivation, "the current-epoch handle was pruned before the revoke").toContain(SEEDED_TOKEN);
      expect(afterUnrelatedActivation, "a handle from another epoch survived an activation").not.toContain(STALE_TOKEN);
    }, TEST_TIMEOUT_MS);

    test("the revoke publishes a new epoch for the still-enabled server, deletes the handle, and proves it", () => {
      expect(after?.stateEpoch, "the revoked server left the policy; the epoch path was not exercised").toMatch(/^[a-f0-9]{32}$/);
      expect(after?.stateEpoch).not.toBe(before.stateEpoch);
      expect(revokeOutput).toContain(`proxy OAuth state for claude ${NARROW_SERVER}: clear requested`);
      expect(revokeOutput).toContain(`proxy OAuth state for claude ${NARROW_SERVER}: cleared (the proxy applied effective policy generation sha256:`);
      const state = readProxyOAuthState(proxyId);
      expect(state).not.toContain(SEEDED_TOKEN);
      expect(state).not.toContain(SEEDED_HANDLE);
    }, TEST_TIMEOUT_MS);
  });

  // Cross-host token endpoints (L1-L4). Every probe host is unresolvable, so
  // no issuer ever answers: a mediated token POST comes back as the proxy's
  // upstream-failure 502 and a refused one as the proxy's own denial. What
  // this proves is the proxy decision and that a refused request never left
  // the proxy (no `admitted` event, no approval hold, no OAuth state write).
  // That a mediated reply reaches the agent as handles only is proven by the
  // proxy suite (`oauth-mediation-cross-host.test.ts`).
  describe("cross-host token endpoints", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;
    let proxyId: string;
    let boundEnableOutput: string;

    beforeAll(async () => {
      const mcpPath = path.join(fixture.projectRoot, ".mcp.json");
      const current = JSON.parse(fs.readFileSync(mcpPath, "utf8")) as { mcpServers: Record<string, unknown> };
      current.mcpServers[CROSS_SERVER] = { type: "http", url: `https://${CROSS_ENDPOINT_HOST}/mcp` };
      current.mcpServers[BOUND_SERVER] = { type: "http", url: `https://${BOUND_ENDPOINT_HOST}/mcp` };
      current.mcpServers[DROP_SERVER] = { type: "http", url: `https://${DROP_ENDPOINT_HOST}/mcp` };
      fs.writeFileSync(mcpPath, `${JSON.stringify(current)}\n`);
      // Approve the two cross-host servers (no OAuth hosts: no record yet),
      // then give each the record a reviewed cross-host discovery writes.
      for (const server of [CROSS_SERVER, DROP_SERVER]) {
        runOk(fixture, ["mcp", "enable", "claude", server, "--source", "project", "--no-discover", "--no-login"]);
      }
      addEnableRecords(fixture, stateDir, [
        crossHostRecord(fixture, CROSS_SERVER, CROSS_IDP_HOST, CROSS_TOKEN_HOST),
        crossHostRecord(fixture, DROP_SERVER, DROP_IDP_HOST, DROP_TOKEN_HOST),
      ]);
      // The `--oauth-host` server, enabled in one command; its activation also
      // projects the hand-written records.
      boundEnableOutput = runOk(fixture, [
        "mcp", "enable", "claude", BOUND_SERVER, "--source", "project",
        "--no-discover", "--oauth-host", BOUND_AUTH_HOST, "--no-login",
      ]).output;
      proxyId = proxyContainerId(fixture);
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("the projection keeps each cross-host claim and binds the --oauth-host", () => {
      expect(boundEnableOutput).toContain("effective policy: live now (effective policy generation sha256:");
      expect(boundEnableOutput, "a hand-written enable record was ignored").not.toContain("ignored an invalid MCP enable record");
      for (const host of [BOUND_AUTH_HOST, CROSS_TOKEN_HOST, DROP_TOKEN_HOST]) {
        expect(boundEnableOutput, `a claim on ${host} was dropped`).not.toMatch(new RegExp(`${host.replaceAll(".", "\\.")}\\S* is not used`, "u"));
      }
      const prepared = readPreparedOAuthPolicy(stateDir);
      for (const [provider, host] of [[CROSS_PROVIDER, CROSS_TOKEN_HOST], [DROP_PROVIDER, DROP_TOKEN_HOST]] as const) {
        expect(prepared.providers[provider]?.tokenEndpoints, `${provider} has no static cross-host token endpoint`).toContainEqual({ host, path: TOKEN_PATH });
        expect(prepared.providers[provider]?.protocolReadEndpoints, `${provider} cross-host endpoint is not a protocol read`).toContainEqual({ host, path: TOKEN_PATH });
      }
      expect(prepared.providers[BOUND_PROVIDER]?.bindingHosts).toEqual([BOUND_AUTH_HOST]);
      expect(prepared.providers[BOUND_PROVIDER]?.tokenEndpoints ?? [], "an --oauth-host endpoint must not be static")
        .not.toContainEqual({ host: BOUND_AUTH_HOST, path: TOKEN_PATH });
      expect(prepared.recordOnlyHosts ?? []).toEqual(expect.arrayContaining([BOUND_AUTH_HOST, CROSS_TOKEN_HOST, DROP_TOKEN_HOST]));
      for (const host of [CROSS_TOKEN_HOST, DROP_TOKEN_HOST]) {
        expect(prepared.blockedEndpoints ?? [], `the claimed endpoint on ${host} is blocked`).not.toContainEqual({ host, path: TOKEN_PATH });
      }
    }, TEST_TIMEOUT_MS);

    test("L1: a token POST to the cross-host token endpoint is mediated; a grant to any other path there is refused", () => {
      const admittedBefore = proxyAdmittedEventCount(proxyId, CROSS_TOKEN_HOST);
      const verbose = enableProxyVerboseLogging(proxyId, "mcp-cross-host-l1");
      let login: ReturnType<typeof probe>;
      let admittedAfterLogin: number;
      let other: ReturnType<typeof probe>;
      try {
        login = probe(sessionId, `https://${CROSS_TOKEN_HOST}${TOKEN_PATH}`, "POST", { headers: FORM, body: LOGIN_BODY });
        admittedAfterLogin = proxyAdmittedEventCount(proxyId, CROSS_TOKEN_HOST);
        other = probe(sessionId, `https://${CROSS_TOKEN_HOST}${METADATA_PATH}`, "POST", { headers: FORM, body: LOGIN_BODY });
      } finally {
        verbose.disable();
      }
      // Mediated: a protocol read of the claiming provider, forwarded upstream.
      expect(admittedToUnresolvableHost(login), `the cross-host token POST was not admitted: ${login.detail}`).toBe(true);
      expect(proxyLogs(fixture)).toContain(`proxy: oauth protocol-read name=${CROSS_PROVIDER} kind=token host=${CROSS_TOKEN_HOST} path=${TOKEN_PATH}`);
      expect(admittedAfterLogin, "the proxy logged no admission for the mediated token POST").toBeGreaterThan(admittedBefore);
      expectNoTokenInReply(login, "cross-host token POST");
      // Only the exact endpoint is mediated: the host is record-only.
      expect(other.blocked, `a grant to another path on the cross-host host was not refused: ${other.detail}`).toBe(OAUTH_NOT_MEDIATED);
      expect(proxyAdmittedEventCount(proxyId, CROSS_TOKEN_HOST), "the refused grant reached the upstream").toBe(admittedAfterLogin);
      expectNoTokenInReply(other, "refused grant");
    }, TEST_TIMEOUT_MS);

    test("L3: a hard-coded token POST to the --oauth-host is refused before any upstream connection, approval hold, or state write", () => {
      const stateBefore = readProxyOAuthState(proxyId);
      const admittedBefore = proxyAdmittedEventCount(proxyId, BOUND_AUTH_HOST);
      const approver = attachApprover(fixture);
      const verbose = enableProxyVerboseLogging(proxyId, "mcp-cross-host-l3");
      let refused: ReturnType<typeof probe>;
      let admittedAfterRefusal: number;
      let pending: ReturnType<typeof readPendingApprovals>;
      let metadata: ReturnType<typeof probe>;
      try {
        // No metadata fetch first: the agent posts a URL it chose itself.
        refused = probe(sessionId, `https://${BOUND_AUTH_HOST}${TOKEN_PATH}`, "POST", { headers: FORM, body: LOGIN_BODY });
        admittedAfterRefusal = proxyAdmittedEventCount(proxyId, BOUND_AUTH_HOST);
        pending = readPendingApprovals(approver.context, nodeRuntimeIO, proxyId).filter((record) => record.host === BOUND_AUTH_HOST);
        // The host itself stays usable: a metadata GET is forwarded.
        metadata = probe(sessionId, `https://${BOUND_AUTH_HOST}${METADATA_PATH}`);
      } finally {
        verbose.disable();
        approver.detach();
      }
      expect(refused.blocked, `the unmediated token POST was not refused: ${refused.detail}`).toBe(OAUTH_NOT_MEDIATED);
      expect(refused.body, "the denial does not name the record-only rule").toContain("Only MCP OAuth settings allow this host");
      expect(proxyLogs(fixture)).toContain(`"reason":"${OAUTH_NOT_MEDIATED}","host":"${BOUND_AUTH_HOST}"`);
      expect(admittedAfterRefusal, "the refused token POST reached the upstream").toBe(admittedBefore);
      expect(pending, "the refused token POST was held for approval").toEqual([]);
      expect(readProxyOAuthState(proxyId), "the refused token POST changed the proxy OAuth state").toBe(stateBefore);
      expectNoTokenInReply(refused, "refused token POST");
      expect(admittedToUnresolvableHost(metadata), `the --oauth-host metadata GET was not admitted: ${metadata.detail}`).toBe(true);
      expect(proxyAdmittedEventCount(proxyId, BOUND_AUTH_HOST), "the proxy logged no admission for the metadata GET").toBeGreaterThan(admittedAfterRefusal);
    }, TEST_TIMEOUT_MS);

    // The proxy cannot read the reply to a WebSocket upgrade (a non-101
    // upstream answer reaches the agent unread), so an upgrade where it
    // guards OAuth is refused before any upstream connection: on a
    // record-only host whatever the path, and on a mediated endpoint.
    test("a WebSocket upgrade to the --oauth-host token path or the cross-host token endpoint is refused; elsewhere it is not", () => {
      const targets = [
        [BOUND_AUTH_HOST, `https://${BOUND_AUTH_HOST}${TOKEN_PATH}?grant_type=refresh_token&refresh_token=x`],
        [CROSS_TOKEN_HOST, `https://${CROSS_TOKEN_HOST}${TOKEN_PATH}`],
      ] as const;
      const stateBefore = readProxyOAuthState(proxyId);
      const before = targets.map(([host]) => ({ admitted: proxyAdmittedEventCount(proxyId, host), denials: oauthDenialEventCount(fixture, host) }));
      const controlDenialsBefore = oauthDenialEventCount(fixture, USER_HOST);
      const verbose = enableProxyVerboseLogging(proxyId, "mcp-cross-host-websocket");
      let answers: Array<ReturnType<typeof probe>>;
      let control: ReturnType<typeof probe>;
      try {
        answers = targets.map(([, url]) => webSocketUpgrade(sessionId, url));
        // Positive control: the same grant-shaped upgrade to a host the user
        // allowed, where the proxy guards no OAuth endpoint.
        control = webSocketUpgrade(sessionId, `https://${USER_HOST}${TOKEN_PATH}?grant_type=refresh_token&refresh_token=x`);
      } finally {
        verbose.disable();
      }
      targets.forEach(([host, url], index) => {
        const answer = answers[index] as ReturnType<typeof probe>;
        expect(answer.code, `${url}: not a 403: ${answer.detail}`).toBe("403");
        expect(answer.blocked, `${url}: not refused as an unmediated OAuth upgrade: ${answer.detail}`).toBe(OAUTH_NOT_MEDIATED);
        expect(oauthDenialEventCount(fixture, host), `${url}: no structured denial event`).toBeGreaterThan(before[index]?.denials ?? 0);
        expect(proxyAdmittedEventCount(proxyId, host), `${url}: the refused upgrade reached the upstream`).toBe(before[index]?.admitted);
        expectNoTokenInReply(answer, `${url} upgrade`);
      });
      expect(readProxyOAuthState(proxyId), "a refused upgrade changed the proxy OAuth state").toBe(stateBefore);
      expect(control.blocked, `the upgrade to ${USER_HOST} was refused as an OAuth upgrade: ${control.detail}`).not.toBe(OAUTH_NOT_MEDIATED);
      expect(oauthDenialEventCount(fixture, USER_HOST)).toBe(controlDenialsBefore);
    }, TEST_TIMEOUT_MS);

    // L2, and the reclaim of L3: the proxy binds an endpoint on a user host
    // when the server's own metadata names it there. The capture cannot run
    // here (no issuer answers), so the discovered endpoint is written into the
    // proxy's OAuth state exactly as the capture records it, under the
    // provider's current state epoch. That the capture refuses an endpoint on
    // an unbound host is proven by the proxy suite.
    test("L2: once the server's metadata has named the endpoint on its --oauth-host, the same token POST is mediated", () => {
      const provider = readPreparedOAuthPolicy(stateDir).providers[BOUND_PROVIDER];
      expect(provider?.stateEpoch, `the prepared OAuth policy publishes no state epoch for ${BOUND_PROVIDER}`).toMatch(/^[a-f0-9]{32}$/u);
      updateProxyOAuthState(proxyId, (state) => {
        state.discovered = {
          ...(state.discovered ?? {}),
          [BOUND_PROVIDER]: { stateEpoch: provider?.stateEpoch, tokenEndpoints: [{ host: BOUND_AUTH_HOST, path: TOKEN_PATH }] },
        };
      });
      // A discovered endpoint is mediated but not a protocol read, so with no
      // approver attached the POST is held for write approval and refused at
      // once. It is no longer refused as unmediated: on a record-only host
      // only a mediating provider lets a grant past that check.
      const login = probe(sessionId, `https://${BOUND_AUTH_HOST}${TOKEN_PATH}`, "POST", { headers: FORM, body: LOGIN_BODY });
      expect(login.blocked, `the bound token POST was not mediated: ${login.detail}`).toMatch(/^write-approval/u);
      expectNoTokenInReply(login, "bound token POST");
      // Binding is per endpoint: another path on the same host is still refused.
      const other = probe(sessionId, `https://${BOUND_AUTH_HOST}/oauth/other-token`, "POST", { headers: FORM, body: LOGIN_BODY });
      expect(other.blocked, `a grant to an unbound path was not refused: ${other.detail}`).toBe(OAUTH_NOT_MEDIATED);
    }, TEST_TIMEOUT_MS);
  });

  describe("L4: a cross-host claim on a host that becomes a credential destination is dropped and blocked", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;
    let proxyId: string;
    let credentialOutput: string;

    beforeAll(async () => {
      // `credential add` takes an already-allowed destination host.
      const added = runOk(fixture, ["host", "add", DROP_TOKEN_HOST]);
      expect(added.stdout, "host add did not converge live").toContain("effective policy: live now");
      credentialOutput = runOk(fixture, [
        "credential", "add", DROP_CREDENTIAL,
        "--host", DROP_TOKEN_HOST, "--header", "Authorization", "--scheme", "bearer",
        "--from-env", DROP_CREDENTIAL_ENV,
      ]).output;
      // `credential add` binds the source but syncs it only at the next
      // converged runtime; until the token reaches the proxy, every request
      // to the destination is refused as missing its token.
      runOk(fixture, ["credential", "sync"]);
      proxyId = proxyContainerId(fixture);
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("the projection drops the claim with a warning and blocks the endpoint", () => {
      expect(credentialOutput).toContain("effective policy: live now (effective policy generation sha256:");
      expect(credentialOutput).toContain(`OAuth host ${DROP_TOKEN_HOST} is not used: ${DROP_TOKEN_HOST} is a credential destination`);
      const prepared = readPreparedOAuthPolicy(stateDir);
      expect(prepared.blockedEndpoints ?? []).toContainEqual({ host: DROP_TOKEN_HOST, path: TOKEN_PATH });
      expect(prepared.providers[DROP_PROVIDER]?.tokenEndpoints ?? []).not.toContainEqual({ host: DROP_TOKEN_HOST, path: TOKEN_PATH });
    }, TEST_TIMEOUT_MS);

    test("the token POST is refused before any upstream connection or state write; other requests to the host pass", () => {
      const stateBefore = readProxyOAuthState(proxyId);
      const admittedBefore = proxyAdmittedEventCount(proxyId, DROP_TOKEN_HOST);
      const verbose = enableProxyVerboseLogging(proxyId, "mcp-cross-host-l4");
      let refused: ReturnType<typeof probe>;
      let admittedAfterRefusal: number;
      let plain: ReturnType<typeof probe>;
      try {
        refused = probe(sessionId, `https://${DROP_TOKEN_HOST}${TOKEN_PATH}`, "POST", { headers: FORM, body: LOGIN_BODY });
        admittedAfterRefusal = proxyAdmittedEventCount(proxyId, DROP_TOKEN_HOST);
        plain = probe(sessionId, `https://${DROP_TOKEN_HOST}/api/status`);
      } finally {
        verbose.disable();
      }
      expect(refused.blocked, `the token POST to the dropped endpoint was not refused: ${refused.detail}`).toBe(OAUTH_NOT_MEDIATED);
      expect(refused.body, "the denial does not name the blocked-endpoint rule").toContain("another use of the host conflicts with that claim");
      expect(admittedAfterRefusal, "the blocked token POST reached the upstream").toBe(admittedBefore);
      expect(readProxyOAuthState(proxyId), "the blocked token POST changed the proxy OAuth state").toBe(stateBefore);
      expectNoTokenInReply(refused, "blocked token POST");
      // The host keeps its own rules: only the endpoint is blocked.
      expect(admittedToUnresolvableHost(plain), `a plain GET to the credential host was not admitted: ${plain.detail}`).toBe(true);
      expect(proxyAdmittedEventCount(proxyId, DROP_TOKEN_HOST)).toBeGreaterThan(admittedAfterRefusal);
    }, TEST_TIMEOUT_MS);
  });

  describe("L4 reclaim: removing the conflicting credential restores the claim", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;
    let removeOutput: string;

    beforeAll(async () => {
      removeOutput = runOk(fixture, ["credential", "remove", DROP_CREDENTIAL]).output;
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("the endpoint is static again and its token POST is a mediated protocol read", () => {
      expect(removeOutput).toContain("effective policy: live now (effective policy generation sha256:");
      const prepared = readPreparedOAuthPolicy(stateDir);
      expect(prepared.blockedEndpoints ?? []).not.toContainEqual({ host: DROP_TOKEN_HOST, path: TOKEN_PATH });
      expect(prepared.providers[DROP_PROVIDER]?.tokenEndpoints).toContainEqual({ host: DROP_TOKEN_HOST, path: TOKEN_PATH });
      const login = probe(sessionId, `https://${DROP_TOKEN_HOST}${TOKEN_PATH}`, "POST", { headers: FORM, body: LOGIN_BODY });
      expect(admittedToUnresolvableHost(login), `the restored token POST was not admitted: ${login.detail}`).toBe(true);
      expect(proxyLogs(fixture)).toContain(`proxy: oauth protocol-read name=${DROP_PROVIDER} kind=token host=${DROP_TOKEN_HOST} path=${TOKEN_PATH}`);
    }, TEST_TIMEOUT_MS);
  });
});
