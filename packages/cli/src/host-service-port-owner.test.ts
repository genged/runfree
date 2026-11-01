import type childProcess from "node:child_process";
import os from "node:os";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  admitHostServicePort,
  hostServiceAdmissionEnvironment,
  hostServiceOwnerWarnings,
  parseDockerPublishedPorts,
  parseUnprivilegedPortStart,
  probeHostPortOwner,
  type HostServiceAdmissionEnvironment,
} from "./host-service-port-owner.ts";
import type { CaptureResult, RuntimeIO } from "./runtime/types.ts";
import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";

type CaptureCall = { command: string; args: string[]; options?: childProcess.SpawnSyncOptions };

// Admission first asks which Docker backend it talks to: these macOS cases
// run against Docker Desktop. `calls` records the listener (lsof) calls only;
// `docker ps` (the published-port check) answers `dockerPs`, by default no
// published port.
const DESKTOP_INFO: CaptureResult = {
  status: 0,
  stdout: JSON.stringify({ OperatingSystem: "Docker Desktop", Name: "docker-desktop", KernelVersion: "6.10.14-linuxkit" }),
  stderr: "",
};
const DESKTOP_CONTEXT: CaptureResult = { status: 0, stdout: "\"unix:///Users/me/.docker/run/docker.sock\"\n", stderr: "" };
const NO_PUBLISHED_PORTS: CaptureResult = { status: 0, stdout: "", stderr: "" };

const isDockerPs = (command: string, args: readonly string[]): boolean => command === "docker" && args[0] === "ps";

function fakeIo(result: CaptureResult, dockerPs: CaptureResult = NO_PUBLISHED_PORTS): { io: RuntimeIO; calls: CaptureCall[] } {
  const calls: CaptureCall[] = [];
  const io: RuntimeIO = {
    capture: vi.fn((command: string, args: string[], options?: childProcess.SpawnSyncOptions) => {
      if (command === "docker" && args[0] === "info") return DESKTOP_INFO;
      if (command === "docker" && args[0] === "context") return DESKTOP_CONTEXT;
      if (isDockerPs(command, args)) return dockerPs;
      calls.push({ command, args, options });
      return result;
    }),
    run: () => 0,
    commandExists: () => true,
    confirm: () => false,
    admin: async () => 0,
  };
  return { io, calls };
}

/** Routes each lsof call to the result for the `-iTCP:<port>` it probed; `docker ps` answers `dockerPs`. */
function fakeIoByPort(results: Readonly<Record<number, CaptureResult>>, dockerPs: CaptureResult = NO_PUBLISHED_PORTS): RuntimeIO {
  return {
    capture: vi.fn((command: string, args: string[]) => {
      if (isDockerPs(command, args)) return dockerPs;
      const portArg = args.find((arg) => arg.startsWith("-iTCP:"));
      const port = Number(portArg?.slice("-iTCP:".length));
      return results[port] ?? { status: 1, stdout: "", stderr: "" };
    }),
    run: () => 0,
    commandExists: () => true,
    confirm: () => false,
    admin: async () => 0,
  };
}

const context = {
  projectRoot: "/tmp/runfree-owner-probe-project",
  env: { HOME: os.tmpdir(), PATH: "/usr/bin:/bin", LC_ALL: "de_DE.UTF-8", SECRET_TOKEN: "do-not-pass" },
};

describe("probeHostPortOwner", () => {
  test("parses the first listener's pid, command, and listen addresses from lsof field output", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "darwin")).toEqual({
      kind: "listener",
      command: "idb_companion",
      pid: 4242,
      count: 1,
      commands: ["idb_companion"],
      listeners: [{ command: "idb_companion", pid: 4242, addresses: ["127.0.0.1:10882"] }],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe("/usr/sbin/lsof");
    // `+c 0`: never truncate the process name (the default width is 9).
    expect(calls[0].args).toEqual(["-nP", "+c", "0", "-iTCP:10882", "-sTCP:LISTEN", "-Fpcn"]);
    expect(calls[0].options?.timeout).toBe(5_000);
    // Sanitized host env plus a fixed locale: no inherited secrets or locale.
    expect(calls[0].options?.env).toMatchObject({ LC_ALL: "C", HOME: os.tmpdir() });
    expect(calls[0].options?.env).not.toHaveProperty("SECRET_TOKEN");
  });

  test("takes the first of several listeners and records the count", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn[::1]:10882\nf8\nn127.0.0.1:10882\np5151\ncother\nf9\nn*:10882\n", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "darwin")).toEqual({
      kind: "listener",
      command: "idb_companion",
      pid: 4242,
      count: 2,
      commands: ["idb_companion", "other"],
      listeners: [
        { command: "idb_companion", pid: 4242, addresses: ["[::1]:10882", "127.0.0.1:10882"] },
        { command: "other", pid: 5151, addresses: ["*:10882"] },
      ],
    });
  });

  test("lsof exit 1 with empty output means nothing listens", () => {
    const { io } = fakeIo({ status: 1, stdout: "", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "darwin")).toEqual({ kind: "none" });
  });

  test("lsof exit 1 with stderr is an error, not an empty answer", () => {
    const { io } = fakeIo({ status: 1, stdout: "", stderr: "lsof: WARNING: can't stat() nfs file system" });

    const owner = probeHostPortOwner(context, io, 10882, "darwin");
    expect(owner.kind).toBe("unavailable");
    expect(owner.kind === "unavailable" ? owner.reason : "").toContain("can't stat()");
  });

  test("a timeout is unavailable, never none", () => {
    const { io } = fakeIo({ status: 124, stdout: "", stderr: "", timedOut: true });

    const owner = probeHostPortOwner(context, io, 10882, "darwin");
    expect(owner.kind).toBe("unavailable");
  });

  test("malformed field output is unavailable, never a listener", () => {
    for (const stdout of ["cidb_companion\n", "pnot-a-pid\ncx\n", "p4242\n", "p0\ncx\n", "n127.0.0.1:10882\np1\ncx\n", "p1\ncx\nn\n"]) {
      const { io } = fakeIo({ status: 0, stdout, stderr: "" });
      expect(probeHostPortOwner(context, io, 10882, "darwin").kind, stdout).toBe("unavailable");
    }
  });

  test("replaces control characters in the process name before it reaches a terminal", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncevil\u001b[2Jname\n", stderr: "" });

    const owner = probeHostPortOwner(context, io, 10882, "darwin");
    expect(owner).toMatchObject({ kind: "listener", pid: 4242 });
    expect(owner.kind === "listener" ? owner.command : "").not.toMatch(/[\u0000-\u001f\u007f]/u);
  });

  test("a platform other than macOS or Linux is unavailable without running lsof", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p1\ncx\n", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "win32")).toEqual({
      kind: "unavailable",
      reason: "the host listener check needs macOS or Linux",
    });
    expect(calls).toHaveLength(0);
  });

  test("Linux never runs lsof: it reads /proc", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p1\ncx\n", stderr: "" });

    probeHostPortOwner(context, io, 10882, "linux");
    expect(calls).toHaveLength(0);
  });
});

describe("admitHostServicePort", () => {
  test("a statically refused port is refused without running lsof", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\n", stderr: "" });

    const admission = admitHostServicePort(context, io, 2375, "darwin");
    expect(admission).toMatchObject({ ok: false });
    expect(admission.ok ? "" : admission.reason).toContain("2375");
    expect(calls).toHaveLength(0);
  });

  test("a Docker Desktop owner is refused", () => {
    const { io } = fakeIo({ status: 0, stdout: "p77\nccom.docker.backend\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: false,
      reason: "127.0.0.1:10882 is owned by Docker Desktop (a published container port)",
    });
  });

  test("a truncated Docker Desktop owner name is still refused", () => {
    const { io } = fakeIo({ status: 0, stdout: "p77\nccom.docker.backe\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toMatchObject({ ok: false });
  });

  test("a Docker Desktop listener behind another listener on the same port is refused", () => {
    // macOS lets two sockets share a port, e.g. a user process on [::1] or *
    // and com.docker.backend on 127.0.0.1, which is what the gateway reaches.
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\np77\nccom.docker.backend\nf9\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: false,
      reason: "127.0.0.1:10882 is owned by Docker Desktop (a published container port)",
    });
  });

  test("no listener is refused", () => {
    const { io } = fakeIo({ status: 1, stdout: "", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: false,
      reason: "no process listens on 127.0.0.1:10882",
    });
  });

  test("an lsof error with exit 1 is refused as unavailable, never as no listener", () => {
    const { io } = fakeIo({ status: 1, stdout: "", stderr: "lsof: status error" });

    const admission = admitHostServicePort(context, io, 10882, "darwin");
    expect(admission.ok).toBe(false);
    expect(admission.ok ? "" : admission.reason).toContain("lsof");
    expect(admission.ok ? "" : admission.reason).not.toContain("no process listens");
  });

  test("an unavailable probe is refused with its reason", () => {
    const { io } = fakeIo({ status: 124, stdout: "", stderr: "", timedOut: true });

    const admission = admitHostServicePort(context, io, 10882, "darwin");
    expect(admission.ok).toBe(false);
    expect(admission.ok ? "" : admission.reason).toMatch(/lsof/u);
  });

  test("a visible listener on 127.0.0.1 is admitted and its owner returned", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: true,
      owner: { command: "idb_companion", pid: 4242 },
    });
  });

  test("a wildcard listener (*:P) is admitted (R22)", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn*:10882\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: true,
      owner: { command: "idb_companion", pid: 4242 },
    });
  });

  test("a listener only on [::1] is refused with its address (R22)", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn[::1]:10882\n", stderr: "" });

    const admission = admitHostServicePort(context, io, 10882, "darwin");
    expect(admission.ok).toBe(false);
    expect(admission.ok ? "" : admission.reason).toContain("no visible listener on 127.0.0.1:10882 or *:10882");
    expect(admission.ok ? "" : admission.reason).toContain("[::1]:10882");
    expect(admission.ok ? "" : admission.reason).toContain("bind the service to 127.0.0.1");
  });

  test("a listener only on a LAN address is refused (R22)", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn192.168.1.20:10882\n", stderr: "" });

    const admission = admitHostServicePort(context, io, 10882, "darwin");
    expect(admission.ok ? "" : admission.reason).toContain("192.168.1.20:10882");
  });

  test("the admitted owner is the reachable listener, not the first one", () => {
    const { io } = fakeIo({ status: 0, stdout: "p5151\ncv6_only\nf7\nn[::1]:10882\np4242\ncidb_companion\nf8\nn127.0.0.1:10882\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: true,
      owner: { command: "idb_companion", pid: 4242 },
    });
  });

  test("a reachable listener mixed with a Docker Desktop listener is refused (R22)", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn*:10882\np77\nccom.docker.backend\nf9\nn[::1]:10882\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: false,
      reason: "127.0.0.1:10882 is owned by Docker Desktop (a published container port)",
    });
  });
});

describe("hostServiceOwnerWarnings", () => {
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform") as PropertyDescriptor;
  beforeEach(() => {
    Object.defineProperty(process, "platform", { value: "darwin" });
  });
  afterEach(() => {
    Object.defineProperty(process, "platform", platformDescriptor);
  });

  const idb: HostServicesJson = { idb: { target: "host-loopback", port: 10882 } };

  test("no listener is one warning line", () => {
    const io = fakeIoByPort({ 10882: { status: 1, stdout: "", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map())).toEqual([
      "host service idb (127.0.0.1:10882): no listener",
    ]);
  });

  test("a Docker Desktop owner is one warning line", () => {
    const io = fakeIoByPort({ 10882: { status: 0, stdout: "p77\nccom.docker.backend\n", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map())).toEqual([
      "host service idb (127.0.0.1:10882): owned by Docker Desktop",
    ]);
  });

  test("a listener that differs from the recorded owner is one warning line", () => {
    const io = fakeIoByPort({ 10882: { status: 0, stdout: "p5151\ncother_process\nf7\nn127.0.0.1:10882\n", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map([[10882, "idb_companion"]]))).toEqual([
      "host service idb (127.0.0.1:10882): listener changed to other_process",
    ]);
  });

  test("a listener that matches the recorded owner has no warning", () => {
    const io = fakeIoByPort({ 10882: { status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map([[10882, "idb_companion"]]))).toEqual([]);
  });

  test("a listener only on [::1] is one warning line (R22)", () => {
    const io = fakeIoByPort({ 10882: { status: 0, stdout: "p4242\ncidb_companion\nf7\nn[::1]:10882\n", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map([[10882, "idb_companion"]]))).toEqual([
      "host service idb (127.0.0.1:10882): no visible listener on 127.0.0.1 or * (found: [::1]:10882)",
    ]);
  });

  test("a listener with nothing recorded has no warning", () => {
    const io = fakeIoByPort({ 10882: { status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map())).toEqual([]);
  });

  test("an unavailable probe reports its own reason, never throws", () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    const io = fakeIoByPort({});

    const lines = hostServiceOwnerWarnings(context, io, idb, new Map());
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^host service idb \(127\.0\.0\.1:10882\): .*macOS or Linux/);
  });

  test("no host services means no warnings and no probe", () => {
    const io = fakeIoByPort({});

    expect(hostServiceOwnerWarnings(context, io, {}, new Map())).toEqual([]);
    expect(io.capture).not.toHaveBeenCalled();
  });

  test("names sort, so warnings come out in a stable order", () => {
    const services: HostServicesJson = {
      zed: { target: "host-loopback", port: 10883 },
      alpha: { target: "host-loopback", port: 10882 },
    };
    const io = fakeIoByPort({ 10882: { status: 1, stdout: "", stderr: "" }, 10883: { status: 1, stdout: "", stderr: "" } });

    expect(hostServiceOwnerWarnings(context, io, services, new Map())).toEqual([
      "host service alpha (127.0.0.1:10882): no listener",
      "host service zed (127.0.0.1:10883): no listener",
    ]);
  });

  // Regression (Linux commit 4, C1): on Engine a container that publishes the
  // approved port after `add` holds it through root's docker-proxy, which this
  // user's listener check sees as no visible listener (or, with a visible
  // owner, as an ordinary listener). `docker ps` names it; the listener check
  // alone never did. The status path reads no backend, so Desktop is the same.
  test.each([
    ["no visible listener", { status: 1, stdout: "", stderr: "" }, "host service idb (127.0.0.1:10882): no listener"],
    ["a visible listener", { status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" }, undefined],
    ["a Docker Desktop listener", { status: 0, stdout: "p77\nccom.docker.backend\nf9\nn127.0.0.1:10882\n", stderr: "" },
      "host service idb (127.0.0.1:10882): owned by Docker Desktop"],
  ])("a port docker ps shows published warns as published by a container, beside %s", (_label, lsof, ownerLine) => {
    const io = fakeIoByPort({ 10882: lsof }, { status: 0, stdout: "0.0.0.0:10882->80/tcp, [::]:10882->80/tcp\n", stderr: "" });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map([[10882, "idb_companion"]]))).toEqual([
      "host service idb (127.0.0.1:10882): published by a container (docker ps)",
      ...(ownerLine ? [ownerLine] : []),
    ]);
  });

  test("a failed docker ps is one warning naming the problem, never a throw, and the owner checks still run", () => {
    const io = fakeIoByPort({ 10882: { status: 1, stdout: "", stderr: "" } }, { status: 1, stdout: "", stderr: "daemon down" });

    expect(hostServiceOwnerWarnings(context, io, idb, new Map())).toEqual([
      "host services: container-published ports were not checked: docker ps exited with status 1",
      "host service idb (127.0.0.1:10882): no listener",
    ]);
  });

  test("an unreadable docker ps answer and a throwing docker client both warn once", () => {
    const unreadable = fakeIoByPort({}, { status: 0, stdout: "0.0.0.0:abc->80/tcp\n", stderr: "" });
    expect(hostServiceOwnerWarnings(context, unreadable, idb, new Map())[0])
      .toMatch(/^host services: container-published ports were not checked: docker ps reported an unreadable port binding/u);
    const throwing: RuntimeIO = {
      ...fakeIoByPort({}),
      capture: vi.fn((command: string, args: string[]) => {
        if (isDockerPs(command, args)) throw new Error("spawn docker ENOENT");
        return { status: 1, stdout: "", stderr: "" };
      }),
    };
    expect(hostServiceOwnerWarnings(context, throwing, idb, new Map())[0])
      .toBe("host services: container-published ports were not checked: docker ps failed: spawn docker ENOENT");
  });

  test("one docker ps read per status, however many services are approved (C4)", () => {
    const services: HostServicesJson = Object.fromEntries(Array.from({ length: 5 }, (_unused, index) => [
      `svc${index}`, { target: "host-loopback" as const, port: 10882 + index },
    ]));
    const io = fakeIoByPort({});

    hostServiceOwnerWarnings(context, io, services, new Map());
    const dockerPsCalls = vi.mocked(io.capture).mock.calls.filter(([command, args]) => isDockerPs(command, args));
    expect(dockerPsCalls).toHaveLength(1);
    expect(dockerPsCalls[0]?.[1]).toEqual(["ps", "--no-trunc", "--format", "{{.Ports}}"]);
  });
});

describe("admitHostServicePort backend refusals (C5)", () => {
  const visible = { status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" };
  const engine = (overrides: Partial<HostServiceAdmissionEnvironment> = {}): HostServiceAdmissionEnvironment => ({
    backend: () => ({ kind: "docker-engine" }),
    unprivilegedPortStart: () => 1024,
    dockerPublishedPorts: () => new Set<number>(),
    ...overrides,
  });
  const orbstack = "host services need Docker Desktop or a local Docker Engine on Linux; this daemon (OrbStack) is not Docker Desktop";

  test("an unsupported backend refuses before any listener probe", () => {
    const { io, calls } = fakeIo(visible);
    const admission = admitHostServicePort(context, io, 10882, "darwin", engine({
      backend: () => ({ kind: "unsupported", reason: orbstack }),
    }));
    expect(admission).toEqual({ ok: false, reason: orbstack });
    expect(calls).toHaveLength(0);
  });

  test("the default environment refuses a non-Desktop daemon on macOS with the clear message", () => {
    const calls: string[][] = [];
    const io: RuntimeIO = {
      capture: (command: string, args: string[]) => {
        calls.push([command, ...args]);
        return command === "docker"
          ? { status: 0, stdout: JSON.stringify({ OperatingSystem: "OrbStack", Name: "orbstack", KernelVersion: "6.9" }), stderr: "" }
          : visible;
      },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    };
    const admission = admitHostServicePort(context, io, 10882, "darwin");
    expect(admission.ok ? "" : admission.reason).toContain("host services need Docker Desktop or a local Docker Engine on Linux");
    expect(calls.every(([command]) => command === "docker")).toBe(true);
  });

  test.each([["tcp://10.0.0.5:2376"], ["ssh://me@mac.example"]])(
    "the default environment refuses a remote Docker Desktop (%s) before the listener probe",
    (dockerHost) => {
      const calls: string[][] = [];
      const io: RuntimeIO = {
        capture: (command: string, args: string[]) => {
          calls.push([command, ...args]);
          return command === "docker" && args[0] === "info" ? DESKTOP_INFO : visible;
        },
        run: () => 0,
        commandExists: () => true,
        confirm: () => false,
        admin: async () => 0,
      };
      const admission = admitHostServicePort({ ...context, env: { ...context.env, DOCKER_HOST: dockerHost } }, io, 10882, "darwin");
      expect(admission.ok).toBe(false);
      expect(admission.ok ? "" : admission.reason).toContain("host services need Docker Desktop or a local Docker Engine on Linux");
      expect(admission.ok ? "" : admission.reason).toContain(`${dockerHost} is not a local socket`);
      expect(calls).toEqual([["docker", "info", "--format", "{{json .}}"]]);
    },
  );

  test("Engine refuses a port below ip_unprivileged_port_start, naming the sysctl, before probing", () => {
    const { io, calls } = fakeIo(visible);
    const published = vi.fn(() => new Set<number>());
    const admission = admitHostServicePort(context, io, 80, "darwin", engine({ dockerPublishedPorts: published }));
    expect(admission.ok).toBe(false);
    expect(admission.ok ? "" : admission.reason).toContain("net.ipv4.ip_unprivileged_port_start (1024)");
    expect(published).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  test("Engine admits a low port the sysctl allows", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncweb\nf7\nn127.0.0.1:80\n", stderr: "" });
    expect(admitHostServicePort(context, io, 80, "darwin", engine({ unprivilegedPortStart: () => 0 })))
      .toEqual({ ok: true, owner: { command: "web", pid: 4242 } });
  });

  test("Engine refuses when the sysctl cannot be read", () => {
    const { io } = fakeIo(visible);
    expect(admitHostServicePort(context, io, 10882, "darwin", engine({ unprivilegedPortStart: () => ({ error: "could not read it" }) })))
      .toEqual({ ok: false, reason: "could not read it" });
  });

  // `docker ps` is the published-port check on every supported backend (C2).
  // A visible listener answers the port, so only `docker ps` can refuse it.
  test.each([["docker-engine"], ["docker-desktop"]] as const)("%s refuses a docker-published port before probing", (kind) => {
    const { io, calls } = fakeIo(visible);
    expect(admitHostServicePort(context, io, 10882, "darwin", engine({
      backend: () => ({ kind }),
      dockerPublishedPorts: () => new Set([10882]),
    }))).toEqual({ ok: false, reason: "127.0.0.1:10882 is published by a container (docker ps)" });
    expect(calls).toHaveLength(0);
  });

  test.each([["docker-engine"], ["docker-desktop"]] as const)("%s refuses when docker ps cannot be read (fail closed)", (kind) => {
    const { io, calls } = fakeIo(visible);
    expect(admitHostServicePort(context, io, 10882, "darwin", engine({
      backend: () => ({ kind }),
      dockerPublishedPorts: () => ({ error: "docker ps exited with status 1" }),
    }))).toEqual({ ok: false, reason: "docker ps exited with status 1" });
    expect(calls).toHaveLength(0);
  });

  test.each([["docker-engine"], ["docker-desktop"]] as const)("%s through the default docker ps read: published refuses, a failed read refuses", (kind) => {
    const published = fakeIo(visible, { status: 0, stdout: "127.0.0.1:10882->8080/tcp\n", stderr: "" });
    expect(admitHostServicePort(context, published.io, 10882, "darwin", {
      ...hostServiceAdmissionEnvironment(context, published.io, "darwin"),
      backend: () => ({ kind }),
      unprivilegedPortStart: () => 1024,
    })).toEqual({ ok: false, reason: "127.0.0.1:10882 is published by a container (docker ps)" });
    const failed = fakeIo(visible, { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" });
    expect(admitHostServicePort(context, failed.io, 10882, "darwin", {
      ...hostServiceAdmissionEnvironment(context, failed.io, "darwin"),
      backend: () => ({ kind }),
      unprivilegedPortStart: () => 1024,
    })).toEqual({ ok: false, reason: "docker ps exited with status 1" });
    expect([...published.calls, ...failed.calls]).toHaveLength(0);
  });

  test("Desktop never reads the Engine-only unprivileged port start, and runs docker ps once", () => {
    const { io } = fakeIo(visible);
    const start = vi.fn(() => 1024);
    const published = vi.fn(() => new Set<number>());
    expect(admitHostServicePort(context, io, 10882, "darwin", engine({
      backend: () => ({ kind: "docker-desktop" }),
      unprivilegedPortStart: start,
      dockerPublishedPorts: published,
    }))).toEqual({ ok: true, owner: { command: "idb_companion", pid: 4242 } });
    expect(start).not.toHaveBeenCalled();
    expect(published).toHaveBeenCalledTimes(1);
  });

  test("the default environment on Desktop runs one docker ps before the listener probe", () => {
    const { io } = fakeIo(visible);
    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({ ok: true, owner: { command: "idb_companion", pid: 4242 } });
    const order = vi.mocked(io.capture).mock.calls.map(([command, args]) => (command === "docker" ? `docker ${args[0]}` : command));
    expect(order).toEqual(["docker info", "docker context", "docker ps", "/usr/sbin/lsof"]);
  });
});

describe("parseDockerPublishedPorts", () => {
  test("reads host TCP ports on 127.0.0.1, 0.0.0.0, and ::, including ranges", () => {
    const parsed = parseDockerPublishedPorts([
      "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp",
      "127.0.0.1:9000-9002->9000-9002/tcp",
      ":::7000->7000/tcp",
      "192.168.1.5:6000->6000/tcp, 0.0.0.0:5353->53/udp, 3306/tcp",
      "",
    ].join("\n"));
    expect(parsed instanceof Set ? [...parsed].sort((a, b) => a - b) : parsed).toEqual([7000, 8080, 9000, 9001, 9002]);
  });

  test("an unreadable binding fails the whole read", () => {
    expect(parseDockerPublishedPorts("0.0.0.0:abc->80/tcp")).toMatchObject({ error: expect.any(String) });
    expect(parseDockerPublishedPorts("0.0.0.0:9002-9000->80/tcp")).toMatchObject({ error: expect.any(String) });
  });

  test("the sysctl parser accepts a port number only", () => {
    expect(parseUnprivilegedPortStart("1024\n")).toBe(1024);
    expect(parseUnprivilegedPortStart("0")).toBe(0);
    expect(parseUnprivilegedPortStart("x")).toMatchObject({ error: expect.any(String) });
  });
});
