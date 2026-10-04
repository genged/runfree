import type childProcess from "node:child_process";
import os from "node:os";

import { describe, expect, test, vi } from "vitest";

import { admitHostServicePort, probeHostPortOwner } from "./host-service-port-owner.ts";
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

const context = {
  projectRoot: "/tmp/runfree-owner-probe-project",
  env: { HOME: os.tmpdir(), PATH: "/usr/bin:/bin", LC_ALL: "de_DE.UTF-8", SECRET_TOKEN: "do-not-pass" },
};

describe("probeHostPortOwner", () => {
  test("parses the first listener's pid and command from lsof field output", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\n", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "darwin")).toEqual({
      kind: "listener",
      command: "idb_companion",
      pid: 4242,
      count: 1,
      commands: ["idb_companion"],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe("/usr/sbin/lsof");
    // `+c 0`: never truncate the process name (the default width is 9).
    expect(calls[0].args).toEqual(["-nP", "+c", "0", "-iTCP:10882", "-sTCP:LISTEN", "-Fpc"]);
    expect(calls[0].options?.timeout).toBe(5_000);
    // Sanitized host env plus a fixed locale: no inherited secrets or locale.
    expect(calls[0].options?.env).toMatchObject({ LC_ALL: "C", HOME: os.tmpdir() });
    expect(calls[0].options?.env).not.toHaveProperty("SECRET_TOKEN");
  });

  test("takes the first of several listeners and records the count", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\nf7\np5151\ncother\nf9\n", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "darwin")).toEqual({
      kind: "listener",
      command: "idb_companion",
      pid: 4242,
      count: 2,
      commands: ["idb_companion", "other"],
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
    for (const stdout of ["cidb_companion\n", "pnot-a-pid\ncx\n", "p4242\n", "p0\ncx\n"]) {
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

  test("a platform other than darwin is unavailable without running lsof", () => {
    const { io, calls } = fakeIo({ status: 0, stdout: "p1\ncx\n", stderr: "" });

    expect(probeHostPortOwner(context, io, 10882, "linux").kind).toBe("unavailable");
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

  test("a visible listener is admitted and its owner returned", () => {
    const { io } = fakeIo({ status: 0, stdout: "p4242\ncidb_companion\n", stderr: "" });

    expect(admitHostServicePort(context, io, 10882, "darwin")).toEqual({
      ok: true,
      owner: { command: "idb_companion", pid: 4242 },
    });
  });
});
