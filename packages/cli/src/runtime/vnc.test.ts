import { beforeEach, describe, expect, test, vi } from "vitest";

const SESSION_CONTAINER = "a".repeat(64);
const SESSION_IP = "172.31.90.20";
const targetState = vi.hoisted(() => ({ available: true }));

vi.mock("./agent-exec-target.ts", () => ({
  resolveAgentExecTarget: () => targetState.available ? ({
    kind: "session",
    containerId: SESSION_CONTAINER,
    sessionId: "rf-20260827-abcdef",
    sourceIp: SESSION_IP,
    running: true,
  }) : undefined,
}));

import { createRuntimeAdapters } from "./adapters.ts";
import {
  INGRESS_FORWARDER_IMAGE,
  ingressForwarderName,
  ingressHostNetworkName,
} from "./ingress-forwarder.ts";
import {
  INGRESS_FORWARDER_TEST_IMAGE_ID,
  INGRESS_HOST_NETWORK_TEST_ID,
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  missingContainerResult,
  missingNetworkResult,
} from "./ingress-forwarder.test-harness.ts";
import { parseVncArgs, vncRuntime } from "./vnc.ts";
import { projectHash } from "../project-identity.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ROOT = "/workspace/project";
const PROJECT_ID = projectHash(PROJECT_ROOT);
const COMPOSE_PROJECT = `runfree-${PROJECT_ID}`;
const INTERNAL_NETWORK = `${COMPOSE_PROJECT}_agent_internal`;
const INGRESS_HOST_NETWORK = ingressHostNetworkName(PROJECT_ID);
const NEW_FORWARDER = ingressForwarderName(PROJECT_ID, "vnc", "5901");
const NEW_FORWARDER_ID = "f".repeat(64);
const INGRESS_ROLE_FILTER = "label=io.runfree.container-role=ingress-forwarder";

type Call = { command: string; args: string[] };

function context(): RuntimeContext {
  return {
    projectRoot: PROJECT_ROOT,
    project: {
      config: {},
      paths: {
        stateDir: `${PROJECT_ROOT}/.runfree/state`,
      },
    },
    runtimeRoot: "/runtime",
    env: { PATH: "/bin" },
  } as unknown as RuntimeContext;
}

function ok(stdout = ""): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

function fail(stderr = ""): CaptureResult {
  return { status: 1, stdout: "", stderr };
}

function fakeIo(respond: (args: string[]) => CaptureResult | undefined): { io: RuntimeIO; captures: Call[]; runs: Call[] } {
  const captures: Call[] = [];
  const runs: Call[] = [];
  const io: RuntimeIO = {
    run(command, args) {
      runs.push({ command, args });
      return 0;
    },
    capture(command, args) {
      captures.push({ command, args });
      return respond(args) ?? ok();
    },
    commandExists() {
      return true;
    },
    confirm() {
      return true;
    },
    admin() {
      return Promise.resolve(0);
    },
  };
  return { io, captures, runs };
}

function happyPathResponder(): { respond: (args: string[]) => CaptureResult | undefined; state: { x11vncStarted: boolean } } {
  const state = { x11vncStarted: false };
  let hostNetworkCreated = false;
  const respond = (args: string[]): CaptureResult | undefined => {
    const joined = args.join(" ");
    if (args[0] === "info") return ok();
    if (args[0] === "network" && args[1] === "inspect") {
      if (args[2] === INTERNAL_NETWORK) return ok("[]");
      return hostNetworkCreated
        ? ok(JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]))
        : missingNetworkResult(args[2] as string);
    }
    if (args[0] === "network" && args[1] === "create") {
      hostNetworkCreated = true;
      return ok(INGRESS_HOST_NETWORK_TEST_ID);
    }
    if (args[0] === "network") return ok();
    if (args[0] === "container" && args[1] === "inspect") return missingContainerResult(args[2] as string);
    if (args[0] === "exec") {
      // The facility's socat readiness probe reads /proc/net/tcp in the sidecar;
      // it is always listening in the happy path, independent of x11vnc.
      if (joined.includes("/proc/net/tcp")) return ok();
      if (joined.includes("command -v x11vnc")) return ok();
      if (args.includes("-d")) {
        state.x11vncStarted = true;
        return ok();
      }
      return state.x11vncStarted ? ok() : fail();
    }
    if (args[0] === "run") return ok(`${NEW_FORWARDER_ID}\n`);
    return ok();
  };
  return { respond, state };
}

async function noDelay(): Promise<void> {}

beforeEach(() => {
  targetState.available = true;
});

describe("parseVncArgs", () => {
  test("defaults to start with loopback port 5901 and a random password", () => {
    const options = parseVncArgs([]);
    expect(options.action).toBe("start");
    expect(options.hostPort).toBe("5901");
    expect(options.agentPort).toBe("5901");
    expect(options.password).toMatch(/^[A-Za-z0-9_-]{8}$/);
    expect(options.password).not.toBe(parseVncArgs([]).password);
    expect(options.clipboard).toBe(false);
    expect(options.startServer).toBe(true);
  });

  test("reads the password from the environment", () => {
    const options = parseVncArgs([], { RUNFREE_VNC_PASSWORD: "secret" });
    expect(options.password).toBe("secret");
  });

  test("--no-password clears the password", () => {
    expect(parseVncArgs(["start", "--no-password"]).password).toBe("");
  });

  test("rejects non-numeric and out-of-range ports", () => {
    expect(() => parseVncArgs(["start", "--host-port", "abc"])).toThrow(/port number/);
    expect(() => parseVncArgs(["start", "--host-port", "0"])).toThrow(/port number/);
    expect(() => parseVncArgs(["start", "--agent-port", "70000"])).toThrow(/port number/);
    expect(() => parseVncArgs(["start", "--host-port", "5901; rm -rf /"])).toThrow(/port number/);
  });

  test("rejects unknown actions and options", () => {
    expect(() => parseVncArgs(["frobnicate"])).toThrow(/usage: runfree vnc/);
    expect(() => parseVncArgs(["start", "--bogus"])).toThrow(/unknown vnc option/);
  });

  test("rejects display values with unsafe characters", () => {
    expect(() => parseVncArgs(["start", "--display", ":0 -rawfb"])).toThrow(/--display/);
  });

  test("no longer accepts --host-network (the facility derives the host bridge)", () => {
    expect(() => parseVncArgs(["start", "--host-network", "custom-net"])).toThrow(/unknown vnc option/);
  });
});

describe("vnc start", () => {
  test("publishes a loopback-only forward attached to the agent internal network", async () => {
    const { respond } = happyPathResponder();
    const { io, captures } = fakeIo(respond);
    const ctx = context();
    const status = await vncRuntime(parseVncArgs(["start"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);
    expect(status).toBe(0);

    // VNC now rides the ingress facility: an ingress-forwarder container with
    // ingress-purpose=vnc, generic INGRESS_* env, on the derived host network.
    const run = captures.find((call) => call.args[0] === "run");
    expect(run).toBeDefined();
    expect(run?.args).toContain("--name");
    expect(run?.args).toContain(NEW_FORWARDER);
    expect(run?.args).toContain(`io.runfree.project-id=${PROJECT_ID}`);
    expect(run?.args).toContain("io.runfree.container-role=ingress-forwarder");
    expect(run?.args).toContain("io.runfree.ingress-purpose=vnc");
    expect(run?.args).toContain("io.runfree.lifecycle-owner=utility");
    expect(run?.args).toContain(INGRESS_HOST_NETWORK);
    expect(run?.args).toContain("127.0.0.1:5901:5901");
    expect(run?.args).toContain(`INGRESS_TARGET=${SESSION_IP}`);
    expect(run?.args).toContain("INGRESS_TARGET_PORT=5901");
    expect(run?.args).toContain(INGRESS_FORWARDER_IMAGE);
    expect(run?.args.some((arg) => arg.includes("0.0.0.0"))).toBe(false);

    const connect = captures.find((call) => call.args[0] === "network" && call.args[1] === "connect");
    expect(connect?.args).toEqual(["network", "connect", INTERNAL_NETWORK, NEW_FORWARDER_ID]);
  });

  test("hardens the sidecar and binds the listener away from the agent network", async () => {
    const { respond } = happyPathResponder();
    const { io, captures } = fakeIo(respond);
    const ctx = context();
    await vncRuntime(parseVncArgs(["start"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);

    const run = captures.find((call) => call.args[0] === "run");
    expect(run?.args).toContain("--cap-drop");
    expect(run?.args).toContain("ALL");
    expect(run?.args).toContain("no-new-privileges:true");
    expect(run?.args).toContain("--read-only");
    expect(run?.args).toContain("--pids-limit");
    expect(run?.args).toContain("65534:65534");
    const script = run?.args[run.args.length - 1];
    expect(script).toContain("bind=$(hostname -i)");
  });

  test("starts x11vnc in the agent before forwarding with clipboard disabled by default", async () => {
    const { respond, state } = happyPathResponder();
    const { io, captures } = fakeIo(respond);
    const ctx = context();
    await vncRuntime(parseVncArgs(["start", "--password", "secret"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);

    expect(state.x11vncStarted).toBe(true);
    const started = captures.find((call) => call.args[0] === "exec" && call.args.includes("-d"));
    expect(started?.args).toContain("VNC_PASSWORD=secret");
    expect(started?.args).toContain("VNC_PORT=5901");
    expect(started?.args).toContain("VNC_CLIPBOARD=0");
    expect(started?.args).toContain("-u");
    expect(started?.args).toContain("1000:1000");
    expect(started?.args[started.args.length - 1]).toContain("-nosel");
    const startedIndex = captures.findIndex((call) => call.args[0] === "exec" && call.args.includes("-d"));
    const runIndex = captures.findIndex((call) => call.args[0] === "run");
    expect(startedIndex).toBeGreaterThanOrEqual(0);
    expect(runIndex).toBeGreaterThan(startedIndex);
  });

  test("--clipboard opts in to clipboard exchange", async () => {
    const { respond } = happyPathResponder();
    const { io, captures } = fakeIo(respond);
    const ctx = context();
    await vncRuntime(parseVncArgs(["start", "--clipboard"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);

    const started = captures.find((call) => call.args[0] === "exec" && call.args.includes("-d"));
    expect(started?.args).toContain("VNC_CLIPBOARD=1");
  });

  test("rejects before any side effect when no agent container is running", async () => {
    targetState.available = false;
    const { io, captures } = fakeIo((args) => {
      if (args[0] === "info") return ok();
      if (args[0] === "ps") return ok("");
      return undefined;
    });
    const ctx = context();
    await expect(vncRuntime(parseVncArgs(["start"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay))
      .rejects.toThrow(/no running agent container/);

    expect(captures.some((call) => call.args[0] === "run")).toBe(false);
    expect(captures.some((call) => call.args[0] === "exec")).toBe(false);
    expect(captures.some((call) => call.args[0] === "network" && call.args[1] === "create")).toBe(false);
    expect(captures.some((call) => call.args[0] === "network" && call.args[1] === "connect")).toBe(false);
  });

  test("rejects with image guidance before forwarding when x11vnc is missing", async () => {
    const { io, captures } = fakeIo((args) => {
      if (args[0] === "info") return ok();
      if (args[0] === "network" && args[1] === "inspect" && args[2] === INTERNAL_NETWORK) return ok("[]");
      if (args[0] === "exec") return fail();
      return undefined;
    });
    const ctx = context();
    await expect(vncRuntime(parseVncArgs(["start"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay))
      .rejects.toThrow(/x11vnc not found in the agent image/);

    expect(captures.some((call) => call.args[0] === "run")).toBe(false);
    expect(captures.some((call) => call.args[0] === "network" && call.args[1] === "create")).toBe(false);
  });

  test("--no-start-server skips the x11vnc bootstrap but still opens the forward", async () => {
    const { respond, state } = happyPathResponder();
    const { io, captures } = fakeIo(respond);
    const ctx = context();
    await vncRuntime(parseVncArgs(["start", "--no-start-server"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);

    // No x11vnc bootstrap exec into the agent; the only execs are the facility's
    // socat readiness probe on the sidecar.
    expect(state.x11vncStarted).toBe(false);
    expect(captures.some((call) => call.args[0] === "exec" && call.args.join(" ").includes("x11vnc"))).toBe(false);
    expect(captures.every((call) => call.args[0] !== "exec" || call.args.join(" ").includes("/proc/net/tcp"))).toBe(true);
    expect(captures.some((call) => call.args[0] === "run")).toBe(true);
  });
});

// The facility's ingress-forwarder listing (by role label).
function isIngressList(args: string[]): boolean {
  return args[0] === "ps" && args.includes("-a") && args.includes(INGRESS_ROLE_FILTER);
}

function vncForwarderFixture(name: string) {
  const hostPort = name.split("-").at(-1);
  if (!hostPort || !/^\d+$/u.test(hostPort)) throw new Error(`invalid vnc forwarder fixture: ${name}`);
  return ingressForwarderInspectFixture({
    composeProject: COMPOSE_PROJECT,
    containerId: hostPort.at(-1)?.repeat(64) ?? "f".repeat(64),
    hostPort,
    projectId: PROJECT_ID,
    purpose: "vnc",
    target: SESSION_IP,
  });
}

describe("vnc stop and status", () => {
  test("stop removes new-style ingress forwarders and the derived host network", async () => {
    const forwarders = [ingressForwarderName(PROJECT_ID, "vnc", "5901"), ingressForwarderName(PROJECT_ID, "vnc", "5902")];
    const remaining = new Set(forwarders);
    const candidates = new Map(forwarders.map((name) => [name, vncForwarderFixture(name)]));
    const { io, captures } = fakeIo((args) => {
      if (args[0] === "info") return ok();
      if (isIngressList(args)) return ok(`${[...remaining].join("\n")}\n`);
      if (args[0] === "container" && args[1] === "inspect") {
        const candidate = candidates.get(args[2] as string);
        return candidate && remaining.has(args[2] as string)
          ? ok(JSON.stringify([candidate]))
          : missingContainerResult(args[2] as string);
      }
      if (args[0] === "image" && args[1] === "inspect") return ok(`${INGRESS_FORWARDER_TEST_IMAGE_ID}\n`);
      if (args[0] === "rm") {
        const removed = [...candidates].find(([, candidate]) => candidate.Id === args[2]);
        if (removed) remaining.delete(removed[0]);
        return ok();
      }
      // Only the ingress host network still exists once the forwarders are gone.
      if (args[0] === "network" && args[1] === "inspect") {
        return args[2] === INGRESS_HOST_NETWORK
          ? ok(JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]))
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "rm") return ok();
      return undefined;
    });
    const ctx = context();
    const status = await vncRuntime(parseVncArgs(["stop"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);
    expect(status).toBe(0);

    const removed = captures.filter((call) => call.args[0] === "rm").map((call) => call.args[2]);
    expect(removed).toEqual(expect.arrayContaining(
      forwarders.map((name) => candidates.get(name)?.Id),
    ));
    const networkRm = captures.find((call) => call.args[0] === "network" && call.args[1] === "rm");
    expect(networkRm?.args).toEqual(["network", "rm", INGRESS_HOST_NETWORK_TEST_ID]);
  });

  test("stop --host-port targets the one forwarder for that port", async () => {
    const target = ingressForwarderName(PROJECT_ID, "vnc", "5902");
    const remaining = new Set([target, ingressForwarderName(PROJECT_ID, "vnc", "5901")]);
    const candidates = new Map([...remaining].map((name) => [name, vncForwarderFixture(name)]));
    const { io, captures } = fakeIo((args) => {
      if (args[0] === "info") return ok();
      if (isIngressList(args)) return ok(`${[...remaining].join("\n")}\n`);
      if (args[0] === "container" && args[1] === "inspect") {
        const candidate = candidates.get(args[2] as string);
        return candidate && remaining.has(args[2] as string)
          ? ok(JSON.stringify([candidate]))
          : missingContainerResult(args[2] as string);
      }
      if (args[0] === "image" && args[1] === "inspect") return ok(`${INGRESS_FORWARDER_TEST_IMAGE_ID}\n`);
      if (args[0] === "rm") {
        const removed = [...candidates].find(([, candidate]) => candidate.Id === args[2]);
        if (removed) remaining.delete(removed[0]);
        return ok();
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return ok(JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]));
      }
      return undefined;
    });
    const ctx = context();
    await vncRuntime(parseVncArgs(["stop", "--host-port", "5902"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);

    const removed = captures.filter((call) => call.args[0] === "rm").map((call) => call.args[2]);
    expect(removed).toEqual([candidates.get(target)?.Id]);
  });

  test("status lists this project's vnc ingress forwarders", async () => {
    const forwarder = ingressForwarderName(PROJECT_ID, "vnc", "5901");
    const { io, runs, captures } = fakeIo((args) => {
      if (args[0] === "info") return ok();
      if (isIngressList(args)) return ok(`${forwarder}\n`);
      if (args[0] === "ps" && args.includes("{{json .}}")) {
        return ok(`${JSON.stringify({ Names: forwarder, Status: "Up 1 minute", Networks: "runfree-ingress-host", Ports: "127.0.0.1:5901->5901/tcp" })}\n`);
      }
      return undefined;
    });
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const ctx = context();
      const status = await vncRuntime(parseVncArgs(["status"], ctx.env ?? {}), ctx, io, createRuntimeAdapters(ctx, io), noDelay);
      expect(status).toBe(0);

      const table = captures.find((call) => call.args[0] === "ps" && call.args.includes("{{json .}}"));
      expect(table?.args).toContain(`name=^/${forwarder}$`);
      expect(runs.find((call) => call.args[0] === "ps")).toBeUndefined();
      const output = log.mock.calls.map((call) => call.join(" ")).join("\n");
      expect(output).toBe([
        "NAME                                   STATUS       NETWORKS              PORTS",
        `${forwarder}  Up 1 minute  runfree-ingress-host  127.0.0.1:5901->5901/tcp`,
      ].join("\n"));
    } finally {
      log.mockRestore();
    }
  });
});
