import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectHash } from "./env.ts";
import {
  INGRESS_HOST_NETWORK_TEST_ID,
  INGRESS_FORWARDER_TEST_IMAGE_ID,
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  missingContainerResult,
  missingNetworkResult,
} from "./ingress-forwarder.test-harness.ts";
import { mcpOAuthCallbackPort } from "./mcp.ts";
import { startSessionMcpCallback, stopSessionMcpCallback } from "./session-mcp-callback.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ROOT = "/workspace/project";
const PROJECT_ID = projectHash(PROJECT_ROOT);
const COMPOSE_PROJECT = `runfree-${PROJECT_ID}`;
const PORT = String(mcpOAuthCallbackPort(PROJECT_ROOT));
const SESSION = { containerId: "session-abc", sourceIp: "172.30.0.40" } as const;
const FORWARDER = `runfree-ingress-mcp-callback-${PROJECT_ID}-${PORT}`;
const FORWARDER_ID = "f".repeat(64);

let tmp: string;

function contextWith(hasServers: boolean): RuntimeContext {
  const policyPath = path.join(tmp, "oauth-mediation-policy.json");
  fs.writeFileSync(policyPath, hasServers ? JSON.stringify({ providers: { p: { kind: "mcp" } } }) : JSON.stringify({ servers: [] }));
  return {
    projectRoot: PROJECT_ROOT,
    project: { config: { version: 3 }, paths: { mcpOAuthPolicyPath: policyPath } },
    env: { RUNFREE_TEST_MCP_CALLBACK_HOST_PROBE: "success" },
  } as unknown as RuntimeContext;
}

function fakeIo() {
  const captures: string[][] = [];
  const runs: string[][] = [];
  let networkCreated = false;
  const capture = vi.fn((_cmd: string, args: string[]) => {
    captures.push(args);
    // Fail the two existence probes so the forwarder creates its network and
    // does not try to remove a stale container; everything else succeeds.
    if (args[0] === "container" && args[1] === "inspect") return missingContainerResult(args[2] as string);
    if (args[0] === "network" && args[1] === "inspect") {
      return networkCreated
        ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
        : missingNetworkResult(args[2] as string);
    }
    if (args[0] === "network" && args[1] === "create") {
      networkCreated = true;
      return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
    }
    if (args[0] === "run") return { status: 0, stdout: `${FORWARDER_ID}\n`, stderr: "" };
    return { status: 0, stdout: "", stderr: "" };
  });
  const run = vi.fn((_cmd: string, args: string[]) => {
    runs.push(args);
    return 0;
  });
  return { io: { capture, run } as unknown as RuntimeIO, captures, runs };
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-cb-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("startSessionMcpCallback", () => {
  test("is a no-op when the OAuth policy has no servers", async () => {
    const { io, captures, runs } = fakeIo();
    expect(await startSessionMcpCallback(contextWith(false), io, SESSION)).toBe(0);
    expect(captures).toHaveLength(0);
    expect(runs).toHaveLength(0);
  });

  test("creates hop 1 targeting the live session IP and hop 2 bound to it", async () => {
    const { io, captures, runs } = fakeIo();
    expect(await startSessionMcpCallback(contextWith(true), io, SESSION)).toBe(0);

    // hop 1: an ingress-forwarder run for the mcp-callback purpose, targeting
    // the session's internal IP and publishing the callback port on loopback.
    const forwarderRun = captures.find((args) => args[0] === "run");
    expect(forwarderRun).toBeDefined();
    expect(forwarderRun).toEqual(expect.arrayContaining([
      "--name",
      FORWARDER,
      "--label",
      "io.runfree.ingress-purpose=mcp-callback",
      "-e",
      `INGRESS_TARGET=${SESSION.sourceIp}`,
      "-p",
      `127.0.0.1:${PORT}:${PORT}`,
    ]));

    // hop 2: a detached bridge exec into the session container, bound to its IP.
    const bridgeExec = runs.find((args) => args[0] === "exec" && args.includes("-d"));
    expect(bridgeExec).toBeDefined();
    expect(bridgeExec).toContain(SESSION.containerId);
    expect(bridgeExec).toContain(SESSION.sourceIp);
    expect(bridgeExec?.join(" ")).toContain("runfree_mcp_callback_bridge");
  });

  test("reports a hop-1 failure without throwing", async () => {
    // An invalid session IP makes startIngressForwarder reject the input.
    const { io } = fakeIo();
    const status = await startSessionMcpCallback(contextWith(true), io, { containerId: "s", sourceIp: "evil; rm" });
    expect(status).toBe(1);
  });
});

describe("stopSessionMcpCallback", () => {
  test("removes the mcp-callback forwarder for this project", () => {
    const candidate = ingressForwarderInspectFixture({
      composeProject: COMPOSE_PROJECT,
      containerId: FORWARDER_ID,
      hostPort: PORT,
      projectId: PROJECT_ID,
      purpose: "mcp-callback",
      target: SESSION.sourceIp,
    });
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "ps") return { status: 0, stdout: "", stderr: "" };
      if (args[0] === "container" && args[1] === "inspect") return { status: 0, stdout: JSON.stringify([candidate]), stderr: "" };
      if (args[0] === "image" && args[1] === "inspect") {
        return { status: 0, stdout: `${INGRESS_FORWARDER_TEST_IMAGE_ID}\n`, stderr: "" };
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" };
      }
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;
    stopSessionMcpCallback({ projectRoot: PROJECT_ROOT } as unknown as RuntimeContext, io);
    const calls = capture.mock.calls.map((c) => (c as unknown as [string, string[]])[1]);
    expect(calls.some((args) => args[0] === "rm" && args.includes(FORWARDER_ID))).toBe(true);
    expect(calls.some((args) => args[0] === "network" && args[1] === "rm" && args[2] === INGRESS_HOST_NETWORK_TEST_ID)).toBe(true);
  });
});
