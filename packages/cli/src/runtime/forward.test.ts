import { describe, expect, test, vi } from "vitest";

import { projectHash } from "./env.ts";
import { forwardOptionsFromArgs, forwardRuntime } from "./forward.ts";
import {
  INGRESS_FORWARDER_TEST_IMAGE_ID,
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  missingContainerResult,
} from "./ingress-forwarder.test-harness.ts";
import type { RuntimeAdapters } from "./adapters.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const projectRoot = "/workspace/project";
const projectId = projectHash(projectRoot);
const composeProject = `runfree-${projectId}`;

const context = { projectRoot, project: { paths: { stateDir: "/state" } } } as unknown as RuntimeContext;
const adapters = { docker: { assertAvailable() {} } } as unknown as RuntimeAdapters;

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
    if (args[0] === "rm") {
      const removed = [...candidates.entries()].find(([, candidate]) => candidate.Id === args[2]);
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
      expect(listArgs).toEqual(expect.arrayContaining(["-a", "--filter", `name=^/${PORT_A}$`]));
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
    const removed = captureArgs(capture).filter((args) => args[0] === "rm").flat();
    expect(removed).toContain(ids.get(PORT_A));
    expect(removed).toContain(ids.get(PORT_B));
    expect(removed).not.toContain(ids.get(VNC));
  });

  test("stop with a port removes exactly that forwarder", () => {
    const { io, capture, ids } = fakeIo([PORT_A, PORT_B]);
    expect(forwardRuntime({ action: "stop", hostPort: "3000" }, context, io, adapters)).toBe(0);
    const removed = captureArgs(capture).filter((args) => args[0] === "rm").flat();
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
      if (args[0] === "rm") throw new Error("lookalike must not be removed");
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => forwardRuntime({ action: "stop", hostPort: "3000" }, context, io, adapters))
      .toThrow(/refusing to remove unverified ingress forwarder/u);
    expect(capture.mock.calls.some((call) => (call[1] as string[])[0] === "rm")).toBe(false);
  });

  test("start requires a port", () => {
    const { io } = fakeIo([]);
    expect(() => forwardRuntime({ action: "start" }, context, io, adapters)).toThrow(/requires a port/u);
  });
});
