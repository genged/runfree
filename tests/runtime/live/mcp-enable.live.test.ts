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
import { docker } from "./docker.ts";
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
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the mcp-enable tranche");
  }
  return backend;
}

function sessionExec(id: string, script: string): CaptureResult {
  return docker(["exec", id, "zsh", "-lc", script]);
}

function probe(sessionId: string, url: string, method?: string): ProbeAnswer & { detail: string } {
  const result = sessionExec(sessionId, curlProbeCommand(url, { maxTimeSeconds: 15, insecure: true, ...(method ? { method } : {}) }));
  return { ...parseProbeAnswer(result.stdout), detail: describeOutput(result.output) };
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
      const stateDir = stateDirFrom(approved.stdout);
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
});
