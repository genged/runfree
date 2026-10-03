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
// write posture with no approver attached, while any other POST on that host,
// a non-protocol body, and a POST to an `--oauth-host` host with no recorded
// endpoint still need approval. And `mcp revoke` clears the server's proxy
// OAuth state through its state epoch: a handle seeded into the proxy's OAuth
// volume survives an unrelated policy activation (a stale-epoch one does not),
// a revoke that leaves the server in the policy deletes it, and the revoke
// says "cleared" only because the live proxy confirmed the generation.
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

import { projectHash } from "../../../packages/cli/src/project-identity.ts";
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
import { admittedToUnresolvableHost, curlProbeCommand, parseProbeAnswer, type ProbeAnswer } from "./proxy-answer.ts";

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

function probe(
  sessionId: string,
  url: string,
  method?: string,
  request: { body?: string; headers?: readonly string[] } = {},
): ProbeAnswer & { detail: string } {
  const result = sessionExec(sessionId, curlProbeCommand(url, { maxTimeSeconds: 15, insecure: true, ...(method ? { method } : {}), ...request }));
  return { ...parseProbeAnswer(result.stdout), detail: describeOutput(result.output) };
}

const FORM = ["Content-Type: application/x-www-form-urlencoded"];
const LOGIN_BODY = "grant_type=authorization_code&code=live-probe-code&redirect_uri=http%3A%2F%2Flocalhost%3A33418%2Fcallback&code_verifier=v";
const OAUTH_STATE_FILE = "/run/runfree-oauth/handles.json";
const NARROW_PROVIDER = `mcp:claude-${NARROW_SERVER.toLowerCase()}`;
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

/** Writes one handle into the proxy's OAuth volume, as a real login would. */
function seedProxyOAuthHandle(proxyId: string, handle: Record<string, unknown>): void {
  const state = JSON.parse(readProxyOAuthState(proxyId)) as { handles?: Record<string, unknown> };
  state.handles = { ...(state.handles ?? {}), [String(handle.handle)]: handle };
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

/** The project state dir, read from the approval path `mcp approve` prints. */
function stateDirFrom(approveOutput: string): string {
  const line = approveOutput.split("\n").find((candidate) => candidate.startsWith("approval: "));
  if (!line) throw new Error(`mcp approve printed no approval path: ${describeOutput(approveOutput)}`);
  return path.dirname(line.slice("approval: ".length).trim());
}

function descriptorDigest(fixture: LiveFixture, server: string): string {
  const explained = runOk(fixture, ["mcp", "explain", "claude", server, "--source", "project", "--json"]);
  const digest = (JSON.parse(explained.stdout) as { descriptorDigest?: unknown }).descriptorDigest;
  if (typeof digest !== "string") throw new Error(`mcp explain gave no descriptor digest: ${describeOutput(explained.output)}`);
  return digest;
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
      // The second server: approved, with a record in the shape a reviewed
      // discovery writes (discovered origin, exact endpoints).
      const approved = runOk(fixture, ["mcp", "approve", "claude", NARROW_SERVER]);
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

    test("a protocol-shaped POST to the recorded, mediated token endpoint needs no approval; other POSTs still do", () => {
      // The fixture keeps the ask default with no approver attached, so a
      // write is refused at once and a read is admitted (502 from the
      // unresolvable upstream).
      const login = probe(sessionId, `https://${NARROW_IDP_HOST}/oauth/token`, "POST", { headers: FORM, body: LOGIN_BODY });
      expect(admittedToUnresolvableHost(login), `the login POST was not admitted as a protocol read: ${login.detail}`).toBe(true);
      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyContainerId(fixture)]);
      expect(logs).toContain(`proxy: oauth protocol-read name=${NARROW_PROVIDER} kind=token`);
      expect(logs).not.toContain("live-probe-code");

      for (const [label, url, body] of [
        ["another grant", `https://${NARROW_IDP_HOST}/oauth/token`, "grant_type=client_credentials&client_id=x"],
        ["another path on the host", `https://${NARROW_IDP_HOST}/.well-known/oauth-authorization-server`, LOGIN_BODY],
        ["an --oauth-host host with no recorded endpoint", `https://${ENABLE_OAUTH_HOST}/oauth/token`, LOGIN_BODY],
      ] as const) {
        const answer = probe(sessionId, url, "POST", { headers: FORM, body });
        expect(answer.blocked, `${label} was not held for write approval: ${answer.detail}`).toMatch(/^write-approval/);
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
});
