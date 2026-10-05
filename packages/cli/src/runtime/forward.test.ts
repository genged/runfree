import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { recordProjectHostServicePorts } from "../host-service-registry.ts";
import { runfreeStateRoot } from "../paths.ts";
import { projectHash } from "./env.ts";
import { forwardOptionsFromArgs, forwardRuntime } from "./forward.ts";
import {
  INGRESS_FORWARDER_TEST_IMAGE_ID,
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  missingContainerResult,
} from "./ingress-forwarder.test-harness.ts";
import { replaceValidatedIngressForwarder } from "./ingress-forwarder-ownership.ts";
import type { RuntimeAdapters } from "./adapters.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

vi.mock("./ingress-forwarder-ownership.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./ingress-forwarder-ownership.ts")>();
  return { ...actual, replaceValidatedIngressForwarder: vi.fn(actual.replaceValidatedIngressForwarder) };
});

const projectRoot = "/workspace/project";
const projectId = projectHash(projectRoot);
const composeProject = `runfree-${projectId}`;

const context = { projectRoot, project: { paths: { stateDir: "/state" } } } as unknown as RuntimeContext;
const adapters = { docker: { assertAvailable() {} } } as unknown as RuntimeAdapters;

let stateHome: string;

beforeEach(() => {
  stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-forward-registry-"));
  context.env = { XDG_STATE_HOME: stateHome };
  vi.mocked(replaceValidatedIngressForwarder).mockClear();
});

afterEach(() => {
  fs.rmSync(stateHome, { recursive: true, force: true });
});

describe("forwardOptionsFromArgs", () => {
  test("a bare port defaults both sides and starts", () => {
    expect(forwardOptionsFromArgs({ port: "3000" })).toEqual({ action: "start", hostPort: "3000", agentPort: "3000" });
  });

  test("recovers an action keyword parsed into the port positional", () => {
    expect(forwardOptionsFromArgs({ port: "stop" })).toEqual({ action: "stop", hostPort: undefined, agentPort: undefined });
    expect(forwardOptionsFromArgs({ port: "status" })).toEqual({ action: "status", hostPort: undefined, agentPort: undefined });
  });

  test("a port with an explicit action keeps the port on both sides", () => {
    expect(forwardOptionsFromArgs({ port: "3000", action: "stop" })).toEqual({ action: "stop", hostPort: "3000", agentPort: "3000" });
  });

  test("flags override each side of the positional default", () => {
    expect(forwardOptionsFromArgs({ port: "3000", "agent-port": "8080" })).toEqual({ action: "start", hostPort: "3000", agentPort: "8080" });
    expect(forwardOptionsFromArgs({ "host-port": "3000", "agent-port": "8080" })).toEqual({ action: "start", hostPort: "3000", agentPort: "8080" });
  });

  test("canonicalizes a port so equivalent spellings share one forwarder identity", () => {
    expect(forwardOptionsFromArgs({ port: "03000" })).toEqual({ action: "start", hostPort: "3000", agentPort: "3000" });
    expect(forwardOptionsFromArgs({ "host-port": "0080", "agent-port": "3000" })).toEqual({ action: "start", hostPort: "80", agentPort: "3000" });
  });

  test("rejects an out-of-range port and two action keywords", () => {
    expect(() => forwardOptionsFromArgs({ port: "70000" })).toThrow(/port number/u);
    expect(() => forwardOptionsFromArgs({ port: "stop", action: "status" })).toThrow(/usage/u);
  });

  test("rejects start-only selectors on stop/status so an ignored flag cannot widen to stop-all", () => {
    expect(() => forwardOptionsFromArgs({ port: "stop", "agent-port": "8080" })).toThrow(/only valid with 'start'/u);
    expect(() => forwardOptionsFromArgs({ port: "3000", action: "stop", "host-port": "3000" })).toThrow(/only valid with 'start'/u);
    expect(() => forwardOptionsFromArgs({ action: "status", "agent-port": "8080" })).toThrow(/only valid with 'start'/u);
    // start still honors both flags.
    expect(forwardOptionsFromArgs({ "host-port": "3000", "agent-port": "8080" })).toEqual({ action: "start", hostPort: "3000", agentPort: "8080" });
  });
});

const PORT_A = `runfree-ingress-port-${projectId}-3000`;
const PORT_B = `runfree-ingress-port-${projectId}-8080`;
const VNC = `runfree-ingress-vnc-${projectId}-5901`;
const CALLBACK = `runfree-ingress-mcp-callback-${projectId}-47123`;

function fakeIo(names: string[]) {
  const candidates = new Map(names.map((name, index) => {
    const match = /^runfree-ingress-(port|vnc|mcp-callback)-[a-f0-9]{12}-(\d+)$/u.exec(name);
    if (!match) throw new Error(`invalid forwarder fixture name: ${name}`);
    return [name, ingressForwarderInspectFixture({
      composeProject,
      containerId: String(index + 1).repeat(64),
      hostPort: match[2] as string,
      projectId,
      purpose: match[1] as "port" | "vnc" | "mcp-callback",
    })] as const;
  }));
  const run = vi.fn((_cmd: string, _args: string[]) => 0);
  const capture = vi.fn((_cmd: string, args: string[]) => {
    if (args[0] === "ps" && args.includes("{{json .}}")) {
      // The status table: one `{{json .}}` row per `name=^/<name>$` filter.
      const listed = args.filter((arg) => arg.startsWith("name=^/")).map((arg) => arg.slice("name=^/".length, -1));
      const rows = listed.filter((name) => candidates.has(name)).map((name) =>
        JSON.stringify({ Names: name, Status: "Up 5 minutes", Ports: `127.0.0.1:${name.split("-").at(-1)}->8080/tcp` }));
      return { status: 0, stdout: `${rows.join("\n")}\n`, stderr: "" };
    }
    if (args[0] === "ps") return { status: 0, stdout: `${[...candidates.keys()].join("\n")}\n`, stderr: "" };
    if (args[0] === "container" && args[1] === "inspect") {
      const candidate = candidates.get(args[2] as string)
        ?? [...candidates.values()].find((entry) => entry.Id === args[2]);
      return candidate ? { status: 0, stdout: JSON.stringify([candidate]), stderr: "" } : missingContainerResult(args[2] as string);
    }
    if (args[0] === "image" && args[1] === "inspect") {
      return { status: 0, stdout: `${INGRESS_FORWARDER_TEST_IMAGE_ID}\n`, stderr: "" };
    }
    if (args[0] === "container" && args[1] === "rm") {
      const id = args.at(-1);
      const removed = [...candidates.entries()].find(([, candidate]) => candidate.Id === id);
      if (removed) candidates.delete(removed[0]);
      return { status: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "network" && args[1] === "inspect") {
      return { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(projectId)]), stderr: "" };
    }
    return { status: 0, stdout: "", stderr: "" };
  });
  return {
    io: { capture, run } as unknown as RuntimeIO,
    capture,
    ids: new Map([...candidates].map(([name, candidate]) => [name, candidate.Id as string])),
    run,
  };
}

function captureArgs(capture: ReturnType<typeof fakeIo>["capture"]): string[][] {
  return capture.mock.calls.map((c) => (c as unknown as [string, string[]])[1]);
}

describe("forwardRuntime", () => {
  test("status lists only port-purpose forwarders, never vnc or callback", () => {
    const { io, run, capture } = fakeIo([PORT_A, VNC, CALLBACK]);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      expect(forwardRuntime({ action: "status" }, context, io, adapters)).toBe(0);
      const listArgs = captureArgs(capture).find((args) => args[0] === "ps" && args.includes("{{json .}}"));
      expect(listArgs).toEqual(expect.arrayContaining(["--all", "--filter", `name=^/${PORT_A}$`]));
      expect(listArgs?.join(" ")).not.toContain(VNC);
      expect(listArgs?.join(" ")).not.toContain(CALLBACK);
      // Rendered through the shared table, never Docker's own `table` format.
      expect(run).not.toHaveBeenCalled();
      const output = log.mock.calls.map((call) => call.join(" ")).join("\n");
      expect(output).toBe([
        "NAME                                    STATUS        PORTS",
        `${PORT_A}  Up 5 minutes  127.0.0.1:3000->8080/tcp`,
      ].join("\n"));
    } finally {
      log.mockRestore();
    }
  });

  test("status reports nothing open when there are no port forwards", () => {
    const { io, run, capture } = fakeIo([VNC]);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      expect(forwardRuntime({ action: "status" }, context, io, adapters)).toBe(0);
      expect(run).not.toHaveBeenCalled();
      expect(captureArgs(capture).some((args) => args.includes("{{json .}}"))).toBe(false);
      expect(log.mock.calls.flat()).toEqual(["no port forwards open"]);
    } finally {
      log.mockRestore();
    }
  });

  test("stop without a port removes every port forward but leaves vnc alone", () => {
    const { io, capture, ids } = fakeIo([PORT_A, PORT_B, VNC]);
    expect(forwardRuntime({ action: "stop" }, context, io, adapters)).toBe(0);
    const removed = captureArgs(capture).filter((args) => args[0] === "container" && args[1] === "rm").flat();
    expect(removed).toContain(ids.get(PORT_A));
    expect(removed).toContain(ids.get(PORT_B));
    expect(removed).not.toContain(ids.get(VNC));
  });

  test("stop with a port removes exactly that forwarder", () => {
    const { io, capture, ids } = fakeIo([PORT_A, PORT_B]);
    expect(forwardRuntime({ action: "stop", hostPort: "3000" }, context, io, adapters)).toBe(0);
    const removed = captureArgs(capture).filter((args) => args[0] === "container" && args[1] === "rm").flat();
    expect(removed).toContain(ids.get(PORT_A));
    expect(removed).not.toContain(ids.get(PORT_B));
  });

  test("stop refuses a label-and-name lookalike with different image bytes and removes nothing", () => {
    const candidate = {
      ...ingressForwarderInspectFixture({
        composeProject,
        hostPort: "3000",
        projectId,
        purpose: "port",
      }),
      Image: `sha256:${"d".repeat(64)}`,
    };
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "container" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([candidate]), stderr: "" };
      }
      if (args[0] === "image" && args[1] === "inspect") {
        return { status: 0, stdout: `${INGRESS_FORWARDER_TEST_IMAGE_ID}\n`, stderr: "" };
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(projectId)]), stderr: "" };
      }
      if (args[0] === "container" && args[1] === "rm") throw new Error("lookalike must not be removed");
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => forwardRuntime({ action: "stop", hostPort: "3000" }, context, io, adapters))
      .toThrow(/refusing to remove unverified ingress forwarder/u);
    expect(capture.mock.calls.some((call) => (call[1] as string[])[0] === "container" && (call[1] as string[])[1] === "rm")).toBe(false);
  });

  test("start requires a port", () => {
    const { io } = fakeIo([]);
    expect(() => forwardRuntime({ action: "start" }, context, io, adapters)).toThrow(/requires a port/u);
  });

  test("start refuses a port another project registered as a host service, naming its root, before any removal", async () => {
    const otherRoot = "/workspace/other-project";
    const otherProjectId = projectHash(otherRoot);
    await recordProjectHostServicePorts(context.env as NodeJS.ProcessEnv, { id: otherProjectId, root: otherRoot }, [10882]);
    const { io } = fakeIo([PORT_A]);

    expect(() => forwardRuntime({ action: "start", hostPort: "10882", agentPort: "10882" }, context, io, adapters))
      .toThrow(new RegExp(otherRoot.replace(/\//g, "\\/")));
    expect(replaceValidatedIngressForwarder).not.toHaveBeenCalled();
  });

  test("two other projects sharing one host-service port: start on that port is refused naming both, start on an unrelated port is not (R18)", async () => {
    const firstRoot = "/workspace/first-project";
    const secondRoot = "/workspace/second-project";
    const env = context.env as NodeJS.ProcessEnv;
    await recordProjectHostServicePorts(env, { id: projectHash(firstRoot), root: firstRoot }, [10882]);
    await recordProjectHostServicePorts(env, { id: projectHash(secondRoot), root: secondRoot }, [10882]);

    const refused = fakeIo([]);
    let message = "";
    try {
      forwardRuntime({ action: "start", hostPort: "10882", agentPort: "10882" }, context, refused.io, adapters);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain(firstRoot);
    expect(message).toContain(secondRoot);
    expect(replaceValidatedIngressForwarder).not.toHaveBeenCalled();

    // An unrelated port passes the registry check and reaches the next step
    // (target resolution, which has no live session in this fixture).
    const admitted = fakeIo([]);
    expect(() => forwardRuntime({ action: "start", hostPort: "3000", agentPort: "3000" }, context, admitted.io, adapters))
      .toThrow(/no running agent container or live session/u);
  });

  test("start refuses when the host-service port registry is corrupt, with the --repair remedy", () => {
    const registryDir = runfreeStateRoot(context.env as NodeJS.ProcessEnv);
    fs.mkdirSync(registryDir, { recursive: true });
    fs.writeFileSync(path.join(registryDir, "host-service-ports.json"), "{ not json");
    const { io } = fakeIo([]);

    expect(() => forwardRuntime({ action: "start", hostPort: "10882", agentPort: "10882" }, context, io, adapters))
      .toThrow(/runfree host-service list --repair/u);
    expect(replaceValidatedIngressForwarder).not.toHaveBeenCalled();
  });
});
