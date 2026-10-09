import childProcess from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi, type Mock } from "vitest";

import { CliError } from "../errors.ts";
import { recordProjectHostServicePorts } from "../host-service-registry.ts";
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
import { SESSION_CALLBACK_COMPLETE_BUDGET_MS, SESSION_CALLBACK_RESERVE_BUDGET_MS } from "./launch-lock-hold.ts";
import {
  completeSessionMcpCallback,
  hostLoopbackPortFree,
  prepareSessionMcpCallback,
  reserveSessionMcpCallback,
  SESSION_CALLBACK_PORT_ATTEMPTS,
  sessionCallbackPortCandidates,
  sessionMcpCallbackLifecycle,
  withSetupDeadline,
} from "./session-mcp-callback.ts";
import type { DockerContainerInspect, RuntimeContext, RuntimeIO } from "./types.ts";

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
  fs.writeFileSync(policyPath, JSON.stringify({ providers: hasServers ? { p: { kind: "mcp" } } : {} }));
  return {
    projectRoot: PROJECT_ROOT,
    project: { config: { version: 3 }, paths: { mcpOAuthPolicyPath: policyPath } },
    // An isolated, empty XDG_STATE_HOME: the default `registeredHostPorts`
    // reader (when a test doesn't inject one) calls `readHostServicePortRegistry`
    // with this env, and it must never resolve to the real host's
    // `~/.local/state/runfree`.
    env: { XDG_STATE_HOME: path.join(tmp, "xdg-state") },
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

describe("hostLoopbackPortFree", () => {
  test("is false while a host process listens on the IPv4 loopback port, and true once it closes", async () => {
    const server = net.createServer();
    const port = await new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        resolve(typeof address === "object" && address ? address.port : 0);
      });
    });
    try {
      expect(await hostLoopbackPortFree(port)).toBe(false);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    expect(await hostLoopbackPortFree(port)).toBe(true);
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
    const bridge = docker.runs.find((args) => args[0] === "exec" && args.includes("--detach"));
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

  test("skips a port an injected host-service registry reader reports as registered (HS7)", async () => {
    const docker = fake();
    const endpoint = await prepareSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      probe: probeOk,
      registeredHostPorts: () => new Set([LEGACY_PORT]),
    });

    expect(endpoint.port).not.toBe(LEGACY_PORT);
    // The 32-attempt budget is unchanged: a registered port is simply one
    // more exclusion, and one forwarder is still created for the chosen port.
    expect(sessionCallbackPortCandidates(PROJECT_ROOT, OWNER.sessionId, new Set([LEGACY_PORT])))
      .toHaveLength(SESSION_CALLBACK_PORT_ATTEMPTS);
    expect(docker.dockerRuns()).toHaveLength(1);
  });

  test("excludes a port the host-global registry reports via the default reader, with no injection", async () => {
    const registryHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-callback-registry-"));
    try {
      const otherRoot = "/workspace/other-project";
      await recordProjectHostServicePorts({ XDG_STATE_HOME: registryHome }, { id: projectHash(otherRoot), root: otherRoot }, [LEGACY_PORT]);
      const ctx = { ...contextWith(true), env: { XDG_STATE_HOME: registryHome } } as unknown as RuntimeContext;
      const docker = fake();

      const endpoint = await prepareSessionMcpCallback(ctx, docker.io, OWNER, {
        hostPortFree: allFree,
        probe: probeOk,
      });

      expect(endpoint.port).not.toBe(LEGACY_PORT);
    } finally {
      fs.rmSync(registryHome, { recursive: true, force: true });
    }
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
      ...(docker.io.captureAsync as unknown as Mock).mock.calls,
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
    (docker.io.captureAsync as unknown as Mock).mockImplementation(async (command: string, args: string[], options: { timeout?: number }) => {
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
    const removal = (docker.io.capture as Mock).mock.calls.find(([, args]) => (args as string[])[0] === "container" && (args as string[])[1] === "rm");
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

describe("reserveSessionMcpCallback and completeSessionMcpCallback", () => {
  const isForwarder = (container: DockerContainerInspect) =>
    container.Config?.Labels?.["io.runfree.ingress-purpose"] === "mcp-callback";
  const indexOf = (sequence: string[][], match: (args: string[]) => boolean) => sequence.findIndex(match);
  const isRun = (args: string[]) => args[0] === "run";
  const isConnect = (args: string[]) => args[0] === "network" && args[1] === "connect";
  const isBridge = (args: string[]) => args[0] === "exec" && args.includes("--detach");

  test("reserve publishes the port and does not attach agent_internal; complete attaches, starts the bridge, and probes", async () => {
    const docker = fake();
    const probe = vi.fn(probeOk);
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, { hostPortFree: allFree, probe });

    expect(reservation.port).toBe(LEGACY_PORT);
    expect(reservation.forwarderName).toBe(`runfree-ingress-mcp-callback-${PROJECT_ID}-${LEGACY_PORT}`);
    expect(reservation.forwarderId).toMatch(/^[a-f0-9]{64}$/u);
    expect(indexOf(docker.sequence, isRun)).toBeGreaterThanOrEqual(0);
    expect(indexOf(docker.sequence, isConnect)).toBe(-1);
    expect(indexOf(docker.sequence, isBridge)).toBe(-1);
    expect(probe).not.toHaveBeenCalled();

    const endpoint = await completeSessionMcpCallback(contextWith(true), docker.io, OWNER, reservation, { hostPortFree: allFree, probe });

    expect(endpoint).toEqual({ port: LEGACY_PORT, forwarderName: reservation.forwarderName });
    const run = indexOf(docker.sequence, isRun);
    const connect = indexOf(docker.sequence, isConnect);
    const bridge = indexOf(docker.sequence, isBridge);
    expect(run).toBeLessThan(connect);
    expect(connect).toBeLessThan(bridge);
    expect(docker.sequence[connect]).toEqual(expect.arrayContaining([INTERNAL_NETWORK, reservation.forwarderId]));
    expect(probe).toHaveBeenCalledOnce();
    expect(docker.removed()).toEqual([]);
  });

  test("reserve uses only async Docker calls", async () => {
    const docker = fake();
    (docker.io.capture as Mock).mockImplementation(() => {
      throw new Error("a synchronous Docker call ran during the reservation");
    });
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, { hostPortFree: allFree, probe: probeOk });

    expect(reservation.port).toBe(LEGACY_PORT);
    expect((docker.io.captureAsync as unknown as Mock).mock.calls.map(([, args]) => (args as string[])[0]))
      .toEqual(expect.arrayContaining(["ps", "run", "exec"]));
  });

  test("two concurrent reservations never share a port", async () => {
    // Two projects (the lifecycle lock serializes one project's admissions)
    // racing for the same first candidate on one host's loopback.
    const otherRoot = "/workspace/other-project";
    const otherId = projectHash(otherRoot);
    const published = new Set<number>();
    const first = fake([], { publishedPorts: published, conflictLeavesResidue: true, asyncYield: true });
    const second = createFakeDocker({
      projectId: otherId,
      composeProject: `runfree-${otherId}`,
      options: { publishedPorts: published, conflictLeavesResidue: true, asyncYield: true },
    });
    const shared = [47_500, 47_501, 47_502];
    const otherOwner = {
      ...OWNER,
      sessionId: "rf-20260930-zzzzzz",
      containerId: "d".repeat(64),
      internalNetwork: `runfree-${otherId}_agent_internal`,
    };
    const otherContext = { ...contextWith(true), projectRoot: otherRoot } as RuntimeContext;

    const [a, b] = await Promise.all([
      reserveSessionMcpCallback(contextWith(true), first.io, OWNER, { hostPortFree: allFree, candidates: () => shared }),
      reserveSessionMcpCallback(otherContext, second.io, otherOwner, { hostPortFree: allFree, candidates: () => shared }),
    ]);

    expect(a.port).not.toBe(b.port);
    expect(new Set([a.port, b.port])).toEqual(new Set([47_500, 47_501]));
    expect([...published].sort()).toEqual([47_500, 47_501]);
    // The loser's conflicting `docker run` residue was removed by exact identity.
    const loser = a.port === 47_500 ? second : first;
    expect(loser.dockerRuns()).toHaveLength(2);
    expect(loser.removed()).toHaveLength(1);
    expect(loser.containers.filter((container) => container.State?.Running !== true)).toEqual([]);
  });

  test("complete removes the reserved forwarder when the connect fails", async () => {
    const docker = fake([], { connectFailure: "Error response from daemon: network not found" });
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, { hostPortFree: allFree });
    const failure = await completeSessionMcpCallback(contextWith(true), docker.io, OWNER, reservation, { probe: probeOk })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(CliError);
    expect((failure as Error).message).toContain("network not found");
    expect((failure as Error).message).toContain("retry the command");
    expect(docker.containers.filter(isForwarder)).toEqual([]);
    expect(indexOf(docker.sequence, isBridge)).toBe(-1);
  });

  test("complete removes the reserved forwarder when the bridge does not start", async () => {
    const docker = fake([], { bridgeStatus: 1 });
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, { hostPortFree: allFree });
    await expect(completeSessionMcpCallback(contextWith(true), docker.io, OWNER, reservation, { probe: probeOk }))
      .rejects.toThrow("the in-session callback bridge did not start");
    expect(docker.removed()).toEqual([reservation.forwarderId]);
    expect(docker.containers.filter(isForwarder)).toEqual([]);
  });

  test("complete refuses a reservation that is not this project's forwarder for its port, and removes the session's route", async () => {
    const docker = fake();
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, { hostPortFree: allFree });
    await expect(completeSessionMcpCallback(contextWith(true), docker.io, OWNER, { ...reservation, port: reservation.port + 1 }, {
      probe: probeOk,
    })).rejects.toThrow("retry the command");
    expect(indexOf(docker.sequence, isConnect)).toBe(-1);
    expect(docker.containers.filter(isForwarder)).toEqual([]);
  });

  test("each phase is cut at its own budget", async () => {
    const docker = fake();
    let clock = 1_000;
    const nowMs = () => (clock += 10);
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: allFree,
      budgetMs: 4_000,
      nowMs,
    });
    const reserveCalls = [...(docker.io.captureAsync as unknown as Mock).mock.calls] as Array<[string, string[], { timeout?: number; killSignal?: string }]>;
    expect(reserveCalls.length).toBeGreaterThan(0);
    for (const [, , options] of reserveCalls) {
      expect(options.killSignal).toBe("SIGKILL");
      expect(options.timeout).toBeGreaterThan(0);
      expect(options.timeout).toBeLessThanOrEqual(4_000);
    }

    clock = 50_000;
    const probe = vi.fn(probeOk);
    await completeSessionMcpCallback(contextWith(true), docker.io, OWNER, reservation, { probe, budgetMs: 3_000, nowMs });
    // The complete phase's deadline is fixed when it starts, from its own budget.
    expect(probe).toHaveBeenCalledWith(reservation.port, expect.any(String), 50_010 + 3_000, expect.any(Function));
    const completeCalls = (docker.io.captureAsync as unknown as Mock).mock.calls.slice(reserveCalls.length) as typeof reserveCalls;
    expect(completeCalls.map(([, args]) => args[0])).toContain("network");
    for (const [, , options] of completeCalls) {
      expect(options.killSignal).toBe("SIGKILL");
      expect(options.timeout).toBeLessThanOrEqual(3_000);
    }
  });

  test("the phases default to their own budgets", async () => {
    const docker = fake();
    const probe = vi.fn(probeOk);
    const nowMs = () => 7_000;
    const reservation = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, { hostPortFree: allFree, nowMs });
    const reserveCalls = (docker.io.captureAsync as unknown as Mock).mock.calls as Array<[string, string[], { timeout?: number }]>;
    expect(reserveCalls.every(([, , options]) => options.timeout === SESSION_CALLBACK_RESERVE_BUDGET_MS)).toBe(true);
    await completeSessionMcpCallback(contextWith(true), docker.io, OWNER, reservation, { probe, nowMs });
    expect(probe).toHaveBeenCalledWith(reservation.port, expect.any(String), 7_000 + SESSION_CALLBACK_COMPLETE_BUDGET_MS, expect.any(Function));
  });

  test("a spent reserve budget ends the port search before a forwarder is created", async () => {
    const docker = fake();
    let clock = 0;
    const failure = await reserveSessionMcpCallback(contextWith(true), docker.io, OWNER, {
      hostPortFree: async () => {
        clock += 5_000;
        return false;
      },
      budgetMs: 12_000,
      nowMs: () => clock,
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(CliError);
    expect((failure as Error).message).toContain("used its whole 12000 ms budget before a port was reserved");
    expect(docker.dockerRuns()).toEqual([]);
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
    const lifecycle = sessionMcpCallbackLifecycle(contextWith(true), fake().io);
    expect(typeof lifecycle?.reserve).toBe("function");
    expect(typeof lifecycle?.complete).toBe("function");
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
        // Only a refused connect means the bridge is not listening yet. A reset
        // after connecting is the bridge closing on us, which is an answer.
        socket.once("error", (error: NodeJS.ErrnoException) => resolve(error.code === "ECONNREFUSED" ? undefined : data));
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

describe("setup deadline IO", () => {
  test("a captureAsync call is cut off with SIGKILL at what is left of the setup budget", async () => {
    let left = 700.6;
    const captureAsync = vi.fn(async () => ({ status: 0, stdout: "", stderr: "" }));
    const io = withSetupDeadline({ capture: vi.fn(), run: vi.fn(), captureAsync } as unknown as RuntimeIO, () => left, 12_000);
    await io.captureAsync?.("docker", ["container", "inspect", "x"], { timeout: 60_000, maxBuffer: 8 });
    expect(captureAsync).toHaveBeenCalledWith("docker", ["container", "inspect", "x"], { timeout: 700, maxBuffer: 8, killSignal: "SIGKILL" });
    left = 0;
    await expect(io.captureAsync?.("docker", ["ps"])).rejects.toThrow("used its whole 12000 ms budget");
    expect(captureAsync).toHaveBeenCalledOnce();
  });

  test("exposes no captureAsync when the inner IO has none", () => {
    const io = withSetupDeadline({ capture: vi.fn(), run: vi.fn() } as unknown as RuntimeIO, () => 1_000, 12_000);
    expect("captureAsync" in io).toBe(false);
  });
});
