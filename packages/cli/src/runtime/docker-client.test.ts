import { describe, expect, test } from "vitest";

import { createDockerClient, type DockerIo } from "./docker-client.ts";
import type { CaptureResult } from "./types.ts";

type Call = { mode: "capture" | "run"; command: string; args: string[]; options: unknown };

function recordingIo(withRun = true): { io: DockerIo; calls: Call[] } {
  const calls: Call[] = [];
  const ok: CaptureResult = { status: 0, stdout: "out", stderr: "" };
  const io: DockerIo = {
    capture: (command, args, options) => {
      calls.push({ mode: "capture", command, args: [...args], options });
      return ok;
    },
    ...(withRun ? { run: (command: string, args: string[], options?: unknown) => {
      calls.push({ mode: "run", command, args: [...args], options });
      return 7;
    } } : {}),
  };
  return { io, calls };
}

const ID = "a".repeat(64);

describe("docker client argv", () => {
  const cases: Array<[string, (c: ReturnType<typeof createDockerClient>) => unknown, string[]]> = [
    ["info", (c) => c.info(), ["info"]],
    ["info json", (c) => c.info("{{json .}}"), ["info", "--format", "{{json .}}"]],
    ["typeless inspect", (c) => c.inspect([ID]), ["inspect", ID]],
    ["typed inspect with format", (c) => c.inspect([ID, "b"], { type: "container", format: "{{.State.Running}}" }),
      ["container", "inspect", "--format", "{{.State.Running}}", ID, "b"]],
    ["network inspect", (c) => c.inspect(["net"], { type: "network" }), ["network", "inspect", "net"]],
    ["container ids", (c) => c.listContainers({ all: true, quiet: true, noTrunc: true, filters: ["label=a=b", "id=x"] }),
      ["ps", "--all", "--quiet", "--no-trunc", "--filter", "label=a=b", "--filter", "id=x"]],
    ["container listing", (c) => c.listContainers({ all: true, filters: ["label=a"], format: "{{json .}}" }),
      ["ps", "--all", "--filter", "label=a", "--format", "{{json .}}"]],
    ["image listing with reference", (c) => c.listObjects("image", { format: "{{.Repository}}:{{.Tag}}", reference: "r" }),
      ["image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "r"]],
    ["network ids", (c) => c.listObjects("network", { quiet: true, noTrunc: true, filters: ["id=n"] }),
      ["network", "ls", "--quiet", "--no-trunc", "--filter", "id=n"]],
    ["logs tail", (c) => c.logs(ID, { tail: 80 }), ["logs", "--tail", "80", ID]],
    ["logs since", (c) => c.logs(ID, { since: "2026-10-03T00:00:00Z" }), ["logs", "--since", "2026-10-03T00:00:00Z", ID]],
    ["exec", (c) => c.exec(ID, ["sh", "-c", "x"], { interactive: true, user: "0:0", env: ["A=1"] }),
      ["exec", "--interactive", "--user", "0:0", "--env", "A=1", ID, "sh", "-c", "x"]],
    ["run keeps flag order", (c) => c.runContainer([["--rm"], ["-i"], ["--network", "n"], ["--cap-drop", "ALL"]], "img@sha256:1", ["true"]),
      ["run", "--rm", "-i", "--network", "n", "--cap-drop", "ALL", "img@sha256:1", "true"]],
    ["run keeps label order", (c) => c.runContainer([["--rm"], ["--label", "a=b"], ["--network", "n"]], "img", ["true"]),
      ["run", "--rm", "--label", "a=b", "--network", "n", "img", "true"]],
    ["rm", (c) => c.removeContainers([ID], { force: true }), ["container", "rm", "--force", ID]],
    ["stop", (c) => c.stopContainers([ID, "b"], 5), ["container", "stop", "--time", "5", ID, "b"]],
    ["start", (c) => c.startContainer(ID), ["container", "start", ID]],
    ["restart", (c) => c.restartContainer(ID), ["container", "restart", ID]],
    ["network create", (c) => c.createNetwork("n", ["a=b", "c=d"]), ["network", "create", "--label", "a=b", "--label", "c=d", "n"]],
    ["network connect", (c) => c.connectNetwork("n", ID), ["network", "connect", "n", ID]],
    ["network rm", (c) => c.removeNetworks(["n"]), ["network", "rm", "n"]],
    ["volume create", (c) => c.createVolume("v", ["a=b"]), ["volume", "create", "--label", "a=b", "v"]],
    ["volume rm", (c) => c.removeVolumes(["v", "w"]), ["volume", "rm", "v", "w"]],
  ];
  for (const [name, call, argv] of cases) {
    test(name, () => {
      const { io, calls } = recordingIo();
      call(createDockerClient(io));
      expect(calls).toEqual([{ mode: "capture", command: "docker", args: argv, options: {} }]);
    });
  }

  const terminalCases: Array<[string, (c: ReturnType<typeof createDockerClient>) => number, string[]]> = [
    ["build", (c) => c.terminal.build(["--tag", "t", "."]), ["build", "--tag", "t", "."]],
    ["compose", (c) => c.terminal.compose(["-p", "p", "up", "-d"]), ["compose", "-p", "p", "up", "-d"]],
    ["detached exec", (c) => c.terminal.exec(ID, ["node", "-e", "x"], { detach: true, user: "1000:1000" }),
      ["exec", "--detach", "--user", "1000:1000", ID, "node", "-e", "x"]],
    ["image prune", (c) => c.terminal.pruneImages(["label=a"]), ["image", "prune", "--force", "--filter", "label=a"]],
    ["image rm", (c) => c.terminal.removeImages(["r"]), ["image", "rm", "r"]],
    ["image tag", (c) => c.terminal.tagImage("s", "t"), ["image", "tag", "s", "t"]],
    ["container rm", (c) => c.terminal.removeContainers([ID], { force: true }), ["container", "rm", "--force", ID]],
    ["volume rm", (c) => c.terminal.removeVolumes(["v"]), ["volume", "rm", "v"]],
  ];
  for (const [name, call, argv] of terminalCases) {
    test(`terminal ${name}`, () => {
      const { io, calls } = recordingIo();
      expect(call(createDockerClient(io))).toBe(7);
      expect(calls).toEqual([{ mode: "run", command: "docker", args: argv, options: {} }]);
    });
  }
});

describe("docker client options", () => {
  test("per-call options are merged over the base options", () => {
    const { io, calls } = recordingIo();
    const env = { PATH: "/bin" };
    createDockerClient(io, { env, timeout: 1000 }).inspect([ID], {}, { timeout: 50, maxBuffer: 8 });
    expect(calls[0]?.options).toEqual({ env, timeout: 50, maxBuffer: 8 });
  });

  test("returns the capture result unchanged", () => {
    const result: CaptureResult = { status: 3, stdout: "a", stderr: "b", timedOut: true };
    const client = createDockerClient({ capture: () => result });
    expect(client.listContainers({ quiet: true })).toBe(result);
  });

  test("a terminal call without a run function fails before spawning", () => {
    const { io, calls } = recordingIo(false);
    expect(() => createDockerClient(io).terminal.build(["."])).toThrow("this Docker client has no terminal runner");
    expect(calls).toEqual([]);
  });
});
