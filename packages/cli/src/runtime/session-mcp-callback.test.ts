import childProcess from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi, type Mock } from "vitest";

import { CliError } from "../errors.ts";
import { projectHash } from "./env.ts";
import { mcpOAuthCallbackPort } from "./mcp.ts";
import { MCP_CALLBACK_BRIDGE_SOURCE, SESSION_MCP_CALLBACK_PORT_FILE } from "./probes.ts";
import {
  boundCallbackForwarder,
  createFakeDocker,
  TEST_FORWARDER_INTERNAL_IP,
  TEST_SESSION_CONTAINER_ID,
  TEST_SESSION_ID,
  TEST_SESSION_IP,
  type FakeDockerOptions,
} from "./session-callback-ingress.test-harness.ts";
import {
  prepareSessionMcpCallback,
  SESSION_CALLBACK_PORT_ATTEMPTS,
  sessionCallbackPortCandidates,
  sessionMcpCallbackLifecycle,
} from "./session-mcp-callback.ts";
import type { DockerContainerInspect, RuntimeContext } from "./types.ts";

const PROJECT_ROOT = "/workspace/project";
const PROJECT_ID = projectHash(PROJECT_ROOT);
const COMPOSE_PROJECT = `runfree-${PROJECT_ID}`;
const INTERNAL_NETWORK = `${COMPOSE_PROJECT}_agent_internal`;
const LEGACY_PORT = mcpOAuthCallbackPort(PROJECT_ROOT);
const OWNER = Object.freeze({
  sessionId: TEST_SESSION_ID,
  containerId: TEST_SESSION_CONTAINER_ID,
  sourceIp: TEST_SESSION_IP,
  internalNetwork: INTERNAL_NETWORK,
});

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-callback-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function contextWith(hasServers: boolean): RuntimeContext {
  const policyPath = path.join(tmp, "oauth-mediation-policy.json");
  fs.writeFileSync(policyPath, JSON.stringify(hasServers ? { providers: { p: { kind: "mcp" } } } : { servers: [] }));
  return {
    projectRoot: PROJECT_ROOT,
    project: { config: { version: 3 }, paths: { mcpOAuthPolicyPath: policyPath } },
    env: {},
  } as unknown as RuntimeContext;
}

function fake(containers: DockerContainerInspect[] = [], options: FakeDockerOptions = {}) {
  return createFakeDocker({ projectId: PROJECT_ID, composeProject: COMPOSE_PROJECT, containers, options });
}

const allFree = async () => true;
const probeOk = async () => ({ status: 0, stdout: "", stderr: "" });

describe("sessionCallbackPortCandidates", () => {
  test("starts with the legacy project port and stays inside the callback block", () => {
    const candidates = sessionCallbackPortCandidates(PROJECT_ROOT, TEST_SESSION_ID);
    expect(candidates[0]).toBe(LEGACY_PORT);
    expect(candidates).toHaveLength(SESSION_CALLBACK_PORT_ATTEMPTS);
    expect(new Set(candidates).size).toBe(candidates.length);
    expect(candidates.every((port) => port >= 47100 && port <= 48099)).toBe(true);
  });

  test("never offers a port already held, and two sessions try different alternatives", () => {
    const held = new Set([LEGACY_PORT]);
    const first = sessionCallbackPortCandidates(PROJECT_ROOT, TEST_SESSION_ID, held);
    const second = sessionCallbackPortCandidates(PROJECT_ROOT, "rf-20260930-zzzzzz", held);
    expect(first).not.toContain(LEGACY_PORT);
    expect(first).toEqual(sessionCallbackPortCandidates(PROJECT_ROOT, TEST_SESSION_ID, held));
    expect(first).not.toEqual(second);
  });
});

describe("prepareSessionMcpCallback", () => {
  test("creates a forwarder bound to the session, then the peer-only bridge, then proves the path", async () => {
    const docker = fake();
    const endpoint = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
    });

    expect(endpoint.port).toBe(LEGACY_PORT);
    const [run] = docker.dockerRuns();
    expect(run).toEqual(expect.arrayContaining([
      "--name",
      `runfree-ingress-mcp-callback-${PROJECT_ID}-${LEGACY_PORT}`,
      "-p",
      `127.0.0.1:${LEGACY_PORT}:${LEGACY_PORT}`,
      "-e",
      `INGRESS_TARGET=${TEST_SESSION_IP}`,
      `INGRESS_TARGET_PORT=${LEGACY_PORT}`,
      `RUNFREE_CALLBACK_SESSION_ID=${TEST_SESSION_ID}`,
      `RUNFREE_CALLBACK_SESSION_CONTAINER=${TEST_SESSION_CONTAINER_ID}`,
    ]));
    const bridge = docker.runs.find((args) => args[0] === "exec" && args.includes("-d"));
    expect(bridge?.slice(-5)).toEqual([
      TEST_SESSION_IP,
      String(LEGACY_PORT),
      expect.any(String),
      TEST_FORWARDER_INTERNAL_IP,
      SESSION_MCP_CALLBACK_PORT_FILE,
    ]);
    expect(bridge).toContain(TEST_SESSION_CONTAINER_ID);
    expect(docker.removed()).toEqual([]);
  });

  test("leaves a port another session's forwarder holds, and that forwarder, untouched", async () => {
    const peer = boundCallbackForwarder({
      composeProject: COMPOSE_PROJECT,
      projectId: PROJECT_ID,
      hostPort: String(LEGACY_PORT),
      containerId: "b".repeat(64),
      sessionId: "rf-20260930-peer01",
      sessionContainerId: "9".repeat(64),
      target: "172.30.0.41",
    });
    const docker = fake([peer]);
    const endpoint = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
    });

    expect(endpoint.port).not.toBe(LEGACY_PORT);
    expect(docker.dockerRuns().some((args) => args.includes(`127.0.0.1:${LEGACY_PORT}:${LEGACY_PORT}`))).toBe(false);
    expect(docker.removed()).toEqual([]);
    expect(docker.containers).toContain(peer);
  });

  test("skips a port the host already uses without creating anything for it", async () => {
    const docker = fake();
    const endpoint = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: async (port) => port !== LEGACY_PORT,
      probe: probeOk,
    });

    expect(endpoint.port).not.toBe(LEGACY_PORT);
    expect(docker.dockerRuns()).toHaveLength(1);
  });

  test("moves on after a publication conflict and removes the created residue by exact identity", async () => {
    const docker = fake([], { conflictingPorts: new Set([LEGACY_PORT]), conflictLeavesResidue: true });
    const endpoint = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
    });

    expect(endpoint.port).not.toBe(LEGACY_PORT);
    expect(docker.dockerRuns()).toHaveLength(2);
    expect(docker.removed()).toHaveLength(1);
    expect(docker.removed()[0]).toMatch(/^[a-f0-9]{64}$/u);
    expect(docker.containers.filter((container) => container.State?.Running !== true)).toEqual([]);
  });

  test("fails the launch with nothing created when every candidate is busy", async () => {
    const docker = fake();
    const failure = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: async () => false,
      probe: probeOk,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(CliError);
    expect((failure as Error).message).toContain(`no free loopback port among ${SESSION_CALLBACK_PORT_ATTEMPTS} candidates`);
    expect((failure as Error).message).toContain("retry the command");
    expect(docker.dockerRuns()).toEqual([]);
  });

  test("removes its forwarder and fails the launch when the host path does not answer", async () => {
    const docker = fake();
    const failure = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: async () => ({ status: 1, stdout: "", stderr: "ECONNREFUSED" }),
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(CliError);
    expect((failure as Error).message).toContain("did not reach the session (ECONNREFUSED)");
    expect(docker.removed()).toHaveLength(1);
    expect(docker.containers.filter((container) => container.Config?.Labels?.["io.runfree.ingress-purpose"] === "mcp-callback")).toEqual([]);
  });

  test("removes its forwarder when the in-session bridge does not start", async () => {
    const docker = fake([], { bridgeStatus: 1 });
    await expect(prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
    })).rejects.toThrow("the in-session callback bridge did not start");
    expect(docker.removed()).toHaveLength(1);
  });

  test("does not try another port after a failure that is not a publication conflict", async () => {
    const docker = fake([], { runFailure: "Error response from daemon: pull access denied" });
    await expect(prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
    })).rejects.toThrow("pull access denied");
    expect(docker.dockerRuns()).toHaveLength(1);
  });

  test("cuts every setup Docker call off at what is left of its budget, and hands the probe the same deadline", async () => {
    const docker = fake();
    let clock = 5_000;
    const probe = vi.fn(async () => ({ status: 0, stdout: "", stderr: "" }));
    await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe,
      budgetMs: 12_000,
      nowMs: () => (clock += 100),
    });

    const calls = [
      ...(docker.io.capture as Mock).mock.calls,
      ...(docker.io.run as Mock).mock.calls,
    ] as Array<[string, string[], { timeout?: number; killSignal?: string }]>;
    const setupCalls = calls.filter(([, args]) => args[0] !== "rm");
    expect(setupCalls.map(([, args]) => args[0])).toEqual(expect.arrayContaining(["ps", "run", "exec"]));
    for (const [, , options] of setupCalls) {
      expect(options.killSignal).toBe("SIGKILL");
      expect(options.timeout).toBeGreaterThan(0);
      expect(options.timeout).toBeLessThanOrEqual(12_000);
    }
    // The deadline was fixed when the setup started.
    expect(probe).toHaveBeenCalledWith(expect.any(Number), expect.any(String), 5_100 + 12_000, expect.any(Function));
  });

  test("a docker run the budget cuts off still has its forwarder removed by owner binding, and the launch fails", async () => {
    const docker = fake();
    let clock = 0;
    const base = (docker.io.capture as Mock).getMockImplementation() as (command: string, args: string[]) => unknown;
    (docker.io.capture as Mock).mockImplementation((command: string, args: string[], options: { timeout?: number }) => {
      if (args[0] !== "run") return base(command, args);
      // The daemon creates the forwarder, but the CLI is killed at the
      // deadline before it reports the container id.
      base(command, args);
      clock += options.timeout ?? 0;
      return { status: 124, stdout: "", stderr: "" };
    });
    const failure = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
      budgetMs: 12_000,
      nowMs: () => clock,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(CliError);
    expect((failure as Error).message).toContain("retry the command");
    // One try only: a cut-off run is not a publication conflict.
    expect(docker.dockerRuns()).toHaveLength(1);
    expect(docker.removed()).toHaveLength(1);
    expect(docker.containers.filter((container) => container.Config?.Labels?.["io.runfree.ingress-purpose"] === "mcp-callback")).toEqual([]);
    // The removal ran after the budget was spent, so it was not cut off.
    const removal = (docker.io.capture as Mock).mock.calls.find(([, args]) => (args as string[])[0] === "rm");
    expect((removal?.[2] as { killSignal?: string } | undefined)?.killSignal).toBeUndefined();
  });

  test("a spent budget ends the port search before another forwarder is created", async () => {
    const docker = fake();
    let clock = 0;
    const failure = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      // Every port the host already uses, each check slow.
      hostPortFree: async () => {
        clock += 5_000;
        return false;
      },
      probe: probeOk,
      budgetMs: 12_000,
      nowMs: () => clock,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(CliError);
    expect((failure as Error).message).toContain("used its whole 12000 ms budget before a port was reserved");
    expect(docker.dockerRuns()).toEqual([]);
  });

  test.each([
    ["session id", { sessionId: "../x" }],
    ["container id", { containerId: "short" }],
    ["address", { sourceIp: "evil; rm" }],
    ["network", { internalNetwork: "bad network" }],
  ])("refuses an owner with an inexact %s before any Docker call", async (_label, override) => {
    const docker = fake();
    await expect(prepareSessionMcpCallback(contextWith(true), docker.io, { ...OWNER, ...override }, {
      hostPortFree: allFree,
      probe: probeOk,
    })).rejects.toThrow("session callback owner");
    expect(docker.captures).toEqual([]);
  });
});

describe("sessionMcpCallbackLifecycle", () => {
  test("a current-config project without a selected effective generation refuses rather than guessing", () => {
    const context = {
      projectRoot: PROJECT_ROOT,
      project: { config: { version: 4 }, paths: { controlProxyDir: path.join(tmp, "absent-control") } },
      env: {},
    } as unknown as RuntimeContext;
    expect(() => sessionMcpCallbackLifecycle(context, fake().io)).toThrow("selected effective controls are required");
  });

  test("is absent when no OAuth-capable MCP server needs a callback", () => {
    expect(sessionMcpCallbackLifecycle(contextWith(false), fake().io)).toBeUndefined();
    expect(sessionMcpCallbackLifecycle(contextWith(true), fake().io)).toBeDefined();
  });
});

// The bridge source runs as-is: records the port file, then relays only its
// allowed peer's connections and answers the host probe challenge.
describe("in-session callback bridge", () => {
  async function freePort(): Promise<number> {
    return await new Promise((resolve) => {
      const server = net.createServer();
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        const port = typeof address === "object" && address ? address.port : 0;
        server.close(() => resolve(port));
      });
    });
  }

  function startBridge(port: number, allowedPeer: string, portFile: string): childProcess.ChildProcess {
    return childProcess.spawn(process.execPath, ["-e", MCP_CALLBACK_BRIDGE_SOURCE, "127.0.0.1", String(port), "challenge-token", allowedPeer, portFile], {
      stdio: "ignore",
    });
  }

  async function exchange(port: number, payload: string): Promise<string> {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const answer = await new Promise<string | undefined>((resolve) => {
        const socket = net.connect({ host: "127.0.0.1", port });
        let data = "";
        socket.once("connect", () => socket.write(payload));
        socket.on("data", (chunk) => { data += chunk.toString("utf8"); });
        socket.once("error", () => resolve(undefined));
        socket.once("close", () => resolve(data));
        socket.setTimeout(2000, () => socket.destroy());
      });
      if (answer !== undefined) return answer;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error("bridge never accepted a connection");
  }

  test("writes the port file and answers the forwarder's probe", async () => {
    const port = await freePort();
    const portFile = path.join(tmp, "callback-port");
    const bridge = startBridge(port, "127.0.0.1", portFile);
    try {
      expect(await exchange(port, "challenge-token\n")).toBe("challenge-token\n");
      expect(fs.readFileSync(portFile, "utf8")).toBe(`${port}\n`);
      expect(fs.statSync(portFile).mode & 0o777).toBe(0o644);
    } finally {
      bridge.kill();
    }
  });

  test("closes a connection from any address other than its forwarder", async () => {
    const port = await freePort();
    const bridge = startBridge(port, "172.30.0.99", path.join(tmp, "callback-port"));
    try {
      expect(await exchange(port, "challenge-token\n")).toBe("");
    } finally {
      bridge.kill();
    }
  });

  test("replaces a planted symlink at the port file instead of writing through it", async () => {
    const port = await freePort();
    const portFile = path.join(tmp, "callback-port");
    const elsewhere = path.join(tmp, "elsewhere");
    fs.writeFileSync(elsewhere, "untouched");
    fs.symlinkSync(elsewhere, portFile);
    const bridge = startBridge(port, "127.0.0.1", portFile);
    try {
      expect(await exchange(port, "challenge-token\n")).toBe("challenge-token\n");
      expect(fs.lstatSync(portFile).isSymbolicLink()).toBe(false);
      expect(fs.readFileSync(elsewhere, "utf8")).toBe("untouched");
    } finally {
      bridge.kill();
    }
  });
});
