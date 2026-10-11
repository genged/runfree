import type childProcess from "node:child_process";
import os from "node:os";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { hostServiceOwnerWarnings } from "./host-service-port-owner.ts";
import {
  LSOF_LISTENERS_ARGS,
  LSOF_LISTENERS_MAX_BUFFER_BYTES,
  hostPortOwnerFromSnapshot,
  hostServiceOwnerWarningsFromSnapshot,
  probeHostListeners,
  type HostListenerSnapshot,
} from "./host-listener-snapshot.ts";
import type { CaptureResult, RuntimeIO } from "./runtime/types.ts";

type CaptureCall = { command: string; args: string[]; options?: childProcess.SpawnSyncOptions };

function fakeIo(result: CaptureResult): { io: RuntimeIO; calls: CaptureCall[] } {
  const calls: CaptureCall[] = [];
  const io: RuntimeIO = {
    capture: vi.fn((command: string, args: string[], options?: childProcess.SpawnSyncOptions) => {
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

/** Routes each `lsof -iTCP:<port>` call to the result for that port (the per-port probe's own shape). */
function fakeIoByPort(results: Readonly<Record<number, CaptureResult>>): RuntimeIO {
  return {
    capture: vi.fn((_command: string, args: string[]) => {
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
  projectRoot: "/tmp/runfree-listener-snapshot-project",
  env: { HOME: os.tmpdir(), PATH: "/usr/bin:/bin", LC_ALL: "de_DE.UTF-8", SECRET_TOKEN: "do-not-pass" },
};

describe("probeHostListeners", () => {
  test("a platform other than darwin is unavailable without running lsof", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p1\ncx\nn127.0.0.1:1\n", stderr: "" });

    const snapshot = probeHostListeners(context, io, "linux");
    expect(snapshot).toEqual({ kind: "unavailable", reason: expect.stringContaining("macOS") });
    expect(calls).toHaveLength(0);
  });

  test("runs exactly one lsof call with the exact argv, timeout, cap and sanitized env", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" });

    probeHostListeners(context, io, "darwin");

    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe("/usr/sbin/lsof");
    expect(calls[0].args).toEqual(["-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN", "-Fpcn"]);
    expect(calls[0].args).toEqual(LSOF_LISTENERS_ARGS);
    expect(calls[0].options?.timeout).toBe(5_000);
    expect(calls[0].options?.maxBuffer).toBe(LSOF_LISTENERS_MAX_BUFFER_BYTES);
    expect(LSOF_LISTENERS_MAX_BUFFER_BYTES).toBe(1024 * 1024);
    expect(calls[0].options?.env).toMatchObject({ LC_ALL: "C", HOME: os.tmpdir() });
    expect(calls[0].options?.env).not.toHaveProperty("SECRET_TOKEN");
  });

  test("querying many ports from one snapshot still runs only the one lsof call that produced it", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" });

    const snapshot = probeHostListeners(context, io, "darwin");
    for (let port = 1; port <= 10; port += 1) hostPortOwnerFromSnapshot(snapshot, port);

    expect(calls).toHaveLength(1);
  });

  test("multiple processes sharing one port, and one process owning several ports", () => {
    const { io } = fakeIo({
      status: 0,
      stdout: "p100\ncnginx\nf3\nn127.0.0.1:8080\np200\ncnode\nf4\nn127.0.0.1:8080\nf5\nn127.0.0.1:9090\n",
      stderr: "",
    });

    const snapshot = probeHostListeners(context, io, "darwin") as Extract<HostListenerSnapshot, { kind: "observed" }>;
    expect(snapshot.kind).toBe("observed");
    expect(snapshot.byPort.get(8080)).toEqual([
      { command: "nginx", pid: 100, addresses: ["127.0.0.1:8080"] },
      { command: "node", pid: 200, addresses: ["127.0.0.1:8080"] },
    ]);
    expect(snapshot.byPort.get(9090)).toEqual([
      { command: "node", pid: 200, addresses: ["127.0.0.1:9090"] },
    ]);
  });

  test("multiple addresses for one process on one port (IPv4 loopback and wildcard)", () => {
    const { io } = fakeIo({ status: 0, stdout: "p300\ncidb_companion\nf3\nn127.0.0.1:10882\nf4\nn*:10882\n", stderr: "" });

    const snapshot = probeHostListeners(context, io, "darwin") as Extract<HostListenerSnapshot, { kind: "observed" }>;
    expect(snapshot.byPort.get(10882)).toEqual([
      { command: "idb_companion", pid: 300, addresses: ["127.0.0.1:10882", "*:10882"] },
    ]);
  });

  test("an IPv6-only listener groups under its port", () => {
    const { io } = fakeIo({ status: 0, stdout: "p400\ncv6only\nf3\nn[::1]:12345\n", stderr: "" });

    const snapshot = probeHostListeners(context, io, "darwin") as Extract<HostListenerSnapshot, { kind: "observed" }>;
    expect(snapshot.byPort.get(12345)).toEqual([{ command: "v6only", pid: 400, addresses: ["[::1]:12345"] }]);
  });

  test("Docker Desktop as a non-first owner still appears in its port's listeners", () => {
    const { io } = fakeIo({
      status: 0,
      stdout: "p500\ncidb_companion\nf3\nn*:10882\np77\nccom.docker.backend\nf4\nn[::1]:10882\n",
      stderr: "",
    });

    const snapshot = probeHostListeners(context, io, "darwin") as Extract<HostListenerSnapshot, { kind: "observed" }>;
    expect(snapshot.byPort.get(10882)?.map((listener) => listener.command)).toEqual(["idb_companion", "com.docker.backend"]);
  });

  test("a full (untruncated) command name longer than lsof's own default 9-character cut", () => {
    const longName = "idb_companion_long_name_process";
    const { io } = fakeIo({ status: 0, stdout: `p600\nc${longName}\nf3\nn127.0.0.1:10882\n`, stderr: "" });

    const snapshot = probeHostListeners(context, io, "darwin") as Extract<HostListenerSnapshot, { kind: "observed" }>;
    expect(snapshot.byPort.get(10882)?.[0]?.command).toBe(longName);
  });

  test("a clean no-match (exit 1, empty output) is observed with no listeners anywhere, never unavailable", () => {
    const { io } = fakeIo({ status: 1, stdout: "", stderr: "" });

    expect(probeHostListeners(context, io, "darwin")).toEqual({ kind: "observed", byPort: new Map() });
  });

  test("exit 1 with stderr is unavailable, never a clean no-match", () => {
    const { io } = fakeIo({ status: 1, stdout: "", stderr: "lsof: WARNING: can't stat() nfs file system" });

    const snapshot = probeHostListeners(context, io, "darwin");
    expect(snapshot.kind).toBe("unavailable");
    expect(snapshot.kind === "unavailable" ? snapshot.reason : "").toContain("can't stat()");
  });

  test("a timeout is unavailable", () => {
    const { io } = fakeIo({ status: 124, stdout: "", stderr: "", timedOut: true });

    const snapshot = probeHostListeners(context, io, "darwin");
    expect(snapshot.kind).toBe("unavailable");
    expect(snapshot.kind === "unavailable" ? snapshot.reason : "").toContain("timed out");
  });

  test("an output-cap overrun (non-zero, non-timeout status) is unavailable, and its truncated prefix is never parsed", () => {
    // A real maxBuffer overrun ends the child and reports a non-zero status
    // (runtime/spawn-status.ts); the prefix below looks like a valid record
    // but must never be trusted as one.
    const { io } = fakeIo({ status: 143, stdout: "p700\ncplausible_look", stderr: "", signal: "SIGTERM" });

    const snapshot = probeHostListeners(context, io, "darwin");
    expect(snapshot.kind).toBe("unavailable");
    expect(snapshot.kind === "unavailable" ? snapshot.reason : "").toContain("exited with status 143");
  });

  test("malformed field output is unavailable, never a partial snapshot", () => {
    for (const stdout of ["cidb_companion\n", "pnot-a-pid\ncx\n", "p4242\n", "p0\ncx\n", "n127.0.0.1:10882\np1\ncx\n", "p1\ncx\nn\n"]) {
      const { io } = fakeIo({ status: 0, stdout, stderr: "" });
      expect(probeHostListeners(context, io, "darwin").kind, stdout).toBe("unavailable");
    }
  });

  test("a listen address with no parsable port is unavailable, never silently dropped", () => {
    const { io } = fakeIo({ status: 0, stdout: "p800\ncweird\nf3\nn/var/run/weird.sock\n", stderr: "" });

    const snapshot = probeHostListeners(context, io, "darwin");
    expect(snapshot.kind).toBe("unavailable");
    expect(snapshot.kind === "unavailable" ? snapshot.reason : "").toContain("no parsable port");
  });
});

describe("hostPortOwnerFromSnapshot", () => {
  test("an unavailable snapshot reports its own reason for any port", () => {
    const snapshot: HostListenerSnapshot = { kind: "unavailable", reason: "the host listener check (lsof) timed out" };

    expect(hostPortOwnerFromSnapshot(snapshot, 10882)).toEqual({ kind: "unavailable", reason: "the host listener check (lsof) timed out" });
    expect(hostPortOwnerFromSnapshot(snapshot, 1)).toEqual({ kind: "unavailable", reason: "the host listener check (lsof) timed out" });
  });

  test("a port absent from the snapshot is none", () => {
    const snapshot: HostListenerSnapshot = { kind: "observed", byPort: new Map() };

    expect(hostPortOwnerFromSnapshot(snapshot, 10882)).toEqual({ kind: "none" });
  });

  test("a port with several listeners returns the full owner shape, first listener first", () => {
    const snapshot: HostListenerSnapshot = {
      kind: "observed",
      byPort: new Map([[8080, [
        { command: "nginx", pid: 100, addresses: ["127.0.0.1:8080"] },
        { command: "node", pid: 200, addresses: ["127.0.0.1:8080"] },
      ]]]),
    };

    expect(hostPortOwnerFromSnapshot(snapshot, 8080)).toEqual({
      kind: "listener",
      command: "nginx",
      pid: 100,
      count: 2,
      commands: ["nginx", "node"],
      listeners: [
        { command: "nginx", pid: 100, addresses: ["127.0.0.1:8080"] },
        { command: "node", pid: 200, addresses: ["127.0.0.1:8080"] },
      ],
    });
  });
});

describe("hostServiceOwnerWarningsFromSnapshot matches the per-port probe (F29)", () => {
  // `hostServiceOwnerWarnings` has no platform parameter of its own: it
  // always probes `process.platform`. Stub it to darwin so the per-port side
  // of the comparison actually runs its fake lsof instead of short-circuiting
  // on this (non-macOS) sandbox.
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform") as PropertyDescriptor;
  beforeEach(() => {
    Object.defineProperty(process, "platform", { value: "darwin" });
  });
  afterEach(() => {
    Object.defineProperty(process, "platform", platformDescriptor);
  });

  const services: HostServicesJson = {
    idb: { target: "host-loopback", port: 10882 },
    other: { target: "host-loopback", port: 9090 },
  };
  const recorded = new Map([[10882, "idb_companion"]]);

  // Drives both the existing per-port implementation and the new batched
  // snapshot path through their real code, on the same stable host state, and
  // compares the ordered warning lines (controller ruling: don't re-implement
  // either side of the comparison).
  test("ordered warning lines match the current per-port implementation on the same fixtures", () => {
    const perPortIo = fakeIoByPort({
      10882: { status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" },
      9090: { status: 0, stdout: "p77\nccom.docker.backend\nf9\nn*:9090\n", stderr: "" },
    });
    const perPortLines = hostServiceOwnerWarnings(context, perPortIo, services, recorded);

    const batchedStdout = "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\np77\nccom.docker.backend\nf9\nn*:9090\n";
    const { io: batchedIo } = fakeIo({ status: 0, stdout: batchedStdout, stderr: "" });
    const snapshot = probeHostListeners(context, batchedIo, "darwin");
    const batchedLines = hostServiceOwnerWarningsFromSnapshot(snapshot, services, recorded);

    expect(batchedLines).toEqual(perPortLines);
    expect(batchedLines).toEqual(["host service other (127.0.0.1:9090): owned by Docker Desktop"]);
  });

  test("a clean match against the recorded owner produces no warnings on either path", () => {
    const perPortIo = fakeIoByPort({
      10882: { status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" },
    });
    const idb: HostServicesJson = { idb: services.idb };
    const perPortLines = hostServiceOwnerWarnings(context, perPortIo, idb, recorded);

    const { io: batchedIo } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\nn127.0.0.1:10882\n", stderr: "" });
    const snapshot = probeHostListeners(context, batchedIo, "darwin");
    const batchedLines = hostServiceOwnerWarningsFromSnapshot(snapshot, idb, recorded);

    expect(batchedLines).toEqual([]);
    expect(perPortLines).toEqual([]);
  });

  test("an unavailable probe reports the same reason on both paths, for every service", () => {
    const idb: HostServicesJson = { idb: services.idb };
    const reason = "the host listener check (lsof) timed out";

    const perPortIo = fakeIoByPort({ 10882: { status: 124, stdout: "", stderr: "", timedOut: true } });
    const perPortLines = hostServiceOwnerWarnings(context, perPortIo, idb, new Map());
    const batchedLines = hostServiceOwnerWarningsFromSnapshot({ kind: "unavailable", reason }, idb, new Map());

    expect(batchedLines).toEqual(perPortLines);
    expect(batchedLines).toEqual([`host service idb (127.0.0.1:10882): ${reason}`]);
  });

  test("no host services means no warnings and the snapshot is never consulted", () => {
    expect(hostServiceOwnerWarningsFromSnapshot({ kind: "observed", byPort: new Map() }, {}, new Map())).toEqual([]);
  });
});
