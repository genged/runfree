import { describe, expect, test } from "vitest";

import type { HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { hostListenerProbe } from "./host-listener-probe.ts";
import { listenAddressText, procListenerSnapshot, procPortOwner, type ProcFs } from "./host-listener-proc.ts";
import { hostServiceOwnerWarningsFromSnapshot } from "./host-listener-snapshot.ts";
import { admitHostServicePort, hostServiceWarningLines, type HostServiceAdmissionEnvironment } from "./host-service-port-owner.ts";
import type { RuntimeIO } from "./runtime/types.ts";

const TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const TCP6_HEADER = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const PORT = 10882; // 0x2A82

function row(local: string, uid: number, inode: number | string, state = "0A"): string {
  return `   0: ${local} 00000000:0000 ${state} 00000000:00000000 00:00000000 00000000 ${uid} 0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

/** An IPv6 row: its remote address is IPv6-width too, as the kernel prints it. */
function row6(local: string, uid: number, inode: number, state = "0A"): string {
  return `   0: ${local} 00000000000000000000000000000000:0000 ${state} 00000000:00000000 00:00000000 00000000 ${uid} 0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

/** `exe` missing reads as EACCES and `cmdline` missing as ENOENT, unless `exited` (both ENOENT). */
type Process = { fds: Record<string, string>; exe?: string; cmdline?: string; comm?: string; hidden?: boolean; exited?: boolean };

/** A fixture /proc: socket tables, and processes with fd links and names. */
function fixtureProc(input: { tcp?: string[]; tcp6?: string[]; processes?: Record<number, Process>; tcpText?: string }): ProcFs {
  const errno = (code: string): Error => Object.assign(new Error(code), { code });
  const processes = input.processes ?? {};
  return {
    readText(filePath) {
      if (filePath === "/proc/net/tcp") return input.tcpText ?? [TCP_HEADER, ...(input.tcp ?? [])].map((line) => `${line}\n`).join("");
      if (filePath === "/proc/net/tcp6") return [TCP6_HEADER, ...(input.tcp6 ?? [])].map((line) => `${line}\n`).join("");
      const match = /^\/proc\/(\d+)\/(cmdline|comm)$/u.exec(filePath);
      const process = match ? processes[Number(match[1])] : undefined;
      const value = process?.[match?.[2] as "cmdline" | "comm"];
      if (value === undefined) throw errno("ENOENT");
      return value;
    },
    listDir(dirPath) {
      if (dirPath === "/proc") return ["self", "net", ...Object.keys(processes)];
      const match = /^\/proc\/(\d+)\/fd$/u.exec(dirPath);
      const process = match ? processes[Number(match[1])] : undefined;
      if (!process) throw errno("ENOENT");
      if (process.hidden) throw errno("EACCES");
      return Object.keys(process.fds);
    },
    readLink(linkPath) {
      const exe = /^\/proc\/(\d+)\/exe$/u.exec(linkPath);
      if (exe) {
        const process = processes[Number(exe[1])];
        if (process?.exited) throw errno("ENOENT");
        const value = process?.exe;
        if (value === undefined) throw errno("EACCES");
        return value;
      }
      const fd = /^\/proc\/(\d+)\/fd\/(\d+)$/u.exec(linkPath);
      const target = fd ? processes[Number(fd[1])]?.fds[fd[2] as string] : undefined;
      if (target === undefined) throw errno("ENOENT");
      return target;
    },
  };
}

const owner = (inode: number | string, extra: Partial<Process> = {}): Process => ({
  fds: { 0: "/dev/null", 3: "anon_inode:[eventpoll]", 7: `socket:[${inode}]` },
  exe: "/usr/local/bin/idb_companion_full_name",
  ...extra,
});

const desktopLess: HostServiceAdmissionEnvironment = {
  backend: () => ({ kind: "docker-engine" }),
  unprivilegedPortStart: () => 1024,
  dockerPublishedPorts: () => new Set(),
};
const noLsof: RuntimeIO = {
  capture: () => {
    throw new Error("the Linux probe must not spawn anything");
  },
  run: () => 0,
  commandExists: () => true,
  confirm: () => false,
  admin: async () => 0,
};
const context = { projectRoot: "/tmp/runfree-proc-probe", env: {} };

/** The shared admission core, reading this fixture /proc through the Linux probe. */
function admit(procFs: ProcFs, environment = desktopLess) {
  return admitHostServicePort(context, noLsof, PORT, "linux", {
    ...environment,
    listenerProbe: hostListenerProbe(context, noLsof, "linux", procFs),
  });
}

describe("Linux /proc listener probe (C2)", () => {
  test("127.0.0.1 listener: owner named by the full exe basename, not the 15-char comm", () => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, 4242)],
      processes: { 4242: owner(4242, { comm: "idb_companion_f" }) },
    });
    expect(procPortOwner(PORT, procFs)).toEqual({
      kind: "listener",
      command: "idb_companion_full_name",
      pid: 4242,
      count: 1,
      commands: ["idb_companion_full_name"],
      listeners: [{ command: "idb_companion_full_name", pid: 4242, addresses: ["127.0.0.1:10882"] }],
    });
    expect(admit(procFs)).toEqual({ ok: true, owner: { command: "idb_companion_full_name", pid: 4242 } });
  });

  test("0.0.0.0 listener is the wildcard *:P and admitted", () => {
    const procFs = fixtureProc({ tcp: [row("00000000:2A82", 1000, 51)], processes: { 51: owner(51, { exe: "/usr/bin/python3.12" }) } });
    expect(procPortOwner(PORT, procFs)).toMatchObject({ kind: "listener", listeners: [{ addresses: ["*:10882"] }] });
    expect(admit(procFs)).toEqual({ ok: true, owner: { command: "python3.12", pid: 51 } });
  });

  test("a tcp6 :: listener counts as wildcard *:P", () => {
    const procFs = fixtureProc({
      tcp6: [row6("00000000000000000000000000000000:2A82", 1000, 61)],
      processes: { 61: owner(61, { exe: "/usr/bin/node" }) },
    });
    expect(procPortOwner(PORT, procFs)).toMatchObject({ kind: "listener", listeners: [{ addresses: ["*:10882"] }] });
    expect(admit(procFs)).toEqual({ ok: true, owner: { command: "node", pid: 61 } });
  });

  test("a ::1-only listener is refused like macOS, with its address", () => {
    const procFs = fixtureProc({
      tcp6: [row6("00000000000000000000000001000000:2A82", 1000, 71)],
      processes: { 71: owner(71) },
    });
    expect(procPortOwner(PORT, procFs)).toMatchObject({ kind: "listener", listeners: [{ addresses: ["[::1]:10882"] }] });
    const admission = admit(procFs);
    expect(admission.ok).toBe(false);
    expect(admission.ok ? "" : admission.reason).toContain("no visible listener on 127.0.0.1:10882 or *:10882 (found: [::1]:10882)");
    expect(admission.ok ? "" : admission.reason).toContain("bind the service to 127.0.0.1");
  });

  test("a LAN-only listener is refused", () => {
    // 192.168.1.20 in host byte order.
    const procFs = fixtureProc({ tcp: [row("1401A8C0:2A82", 1000, 81)], processes: { 81: owner(81) } });
    const admission = admit(procFs);
    expect(admission.ok ? "" : admission.reason).toContain("192.168.1.20:10882");
  });

  test("a socket with no visible pid is no visible listener, and its uid is named", () => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 0, 91)],
      processes: { 91: { ...owner(91), hidden: true }, 300: { fds: { 1: "pipe:[5]" }, exe: "/bin/bash" } },
    });
    expect(procPortOwner(PORT, procFs)).toEqual({ kind: "none", hidden: [{ uid: 0, address: "127.0.0.1:10882" }] });
    expect(admit(procFs)).toEqual({
      ok: false,
      reason: "no visible listener on 127.0.0.1:10882: a socket listens (uid 0 on 127.0.0.1:10882) but its process is not visible to this user",
    });
    const snapshot = procListenerSnapshot(procFs);
    const services: HostServicesJson = { idb: { target: "host-loopback", port: PORT } };
    expect(hostServiceOwnerWarningsFromSnapshot(snapshot, new Set(), services, new Map())).toEqual([
      "host service idb (127.0.0.1:10882): no visible listener (a socket owned by uid 0 on 127.0.0.1:10882)",
    ]);
  });

  test("no socket on the port is none", () => {
    const procFs = fixtureProc({ tcp: [row("0100007F:2A83", 1000, 1)], processes: {} });
    expect(procPortOwner(PORT, procFs)).toEqual({ kind: "none" });
    expect(admit(procFs)).toEqual({ ok: false, reason: "no process listens on 127.0.0.1:10882" });
  });

  test("a non-LISTEN socket on the port is not a listener", () => {
    const procFs = fixtureProc({ tcp: [row("0100007F:2A82", 1000, 5, "01")], processes: { 5: owner(5) } });
    expect(procPortOwner(PORT, procFs)).toEqual({ kind: "none" });
  });

  test.each([
    ["a garbage table", { tcpText: "garbage\n" }],
    ["a truncated row", { tcpText: `${TCP_HEADER}\n   0: 0100007F:2A82 00000000:0000 0A\n` }],
    ["a malformed address", { tcp: [row("0100007:2A82", 1000, 1)] }],
  ])("malformed input is unavailable: %s", (_label, input) => {
    const procFs = fixtureProc(input);
    expect(procPortOwner(PORT, procFs)).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("/proc") });
    expect(procListenerSnapshot(procFs).kind).toBe("unavailable");
    expect(admit(procFs).ok).toBe(false);
  });

  // REVIEW-3 #1: socket inodes are 64-bit. A large inode parses, and owner
  // lookup matches the exact `socket:[<inode>]` link, not a rounded number.
  test.each(["4294967296", "18446744073709551615"])("a 64-bit socket inode %s is matched to its owner exactly", (inode) => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, inode), row("0100007F:1F90", 1000, 4242)],
      processes: { 4242: owner(4242, { exe: "/usr/bin/other" }), 500: owner(inode) },
    });
    expect(procPortOwner(PORT, procFs)).toMatchObject({
      kind: "listener",
      listeners: [{ command: "idb_companion_full_name", pid: 500, addresses: ["127.0.0.1:10882"] }],
    });
    expect(admit(procFs)).toEqual({ ok: true, owner: { command: "idb_companion_full_name", pid: 500 } });
  });

  test("a neighbouring 64-bit inode that differs only past 2^53 is not a match", () => {
    // 9007199254740993 and 9007199254740992 are the same JS number.
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, "9007199254740993")],
      processes: { 500: owner("9007199254740992") },
    });
    expect(procPortOwner(PORT, procFs)).toEqual({ kind: "none", hidden: [{ uid: 1000, address: "127.0.0.1:10882" }] });
  });

  test("a malformed inode fails closed", () => {
    const procFs = fixtureProc({ tcp: [row("0100007F:2A82", 1000, "18446744073709551616")], processes: {} });
    expect(procPortOwner(PORT, procFs)).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("/proc") });
    expect(admit(procFs).ok).toBe(false);
  });

  test("an unexpected read error is unavailable, never none", () => {
    const procFs: ProcFs = {
      ...fixtureProc({ tcp: [row("0100007F:2A82", 1000, 4242)], processes: { 4242: owner(4242) } }),
      listDir: () => {
        throw Object.assign(new Error("EIO"), { code: "EIO" });
      },
    };
    expect(procPortOwner(PORT, procFs).kind).toBe("unavailable");
  });

  test("an oversized table fails closed", () => {
    const procFs: ProcFs = {
      ...fixtureProc({}),
      readText: () => {
        throw Object.assign(new Error("/proc/net/tcp exceeds 16777216 bytes"), { code: "E2BIG" });
      },
    };
    expect(procPortOwner(PORT, procFs).kind).toBe("unavailable");
  });

  // `docker ps` is the published-port check: a container-published port is
  // refused and warned whatever the listener check sees of its host socket
  // (root's proxy process hidden from this user, or a visible one).
  test.each([
    ["a hidden uid-0 socket", fixtureProc({ tcp: [row("00000000:2A82", 0, 11)], processes: { 11: { ...owner(11), hidden: true } } })],
    ["a visible listener", fixtureProc({ tcp: [row("00000000:2A82", 1000, 11)], processes: { 11: owner(11, { exe: "/usr/bin/some-proxy" }) } })],
  ])("a port docker ps shows published is refused and warned as published by a container, beside %s", (_label, procFs) => {
    const published = { ...desktopLess, dockerPublishedPorts: () => new Set([PORT]) };
    expect(admit(procFs, published)).toEqual({ ok: false, reason: "127.0.0.1:10882 is published by a container (docker ps)" });
    const services: HostServicesJson = { idb: { target: "host-loopback", port: PORT } };
    const line = "host service idb (127.0.0.1:10882): published by a container (docker ps)";
    expect(hostServiceWarningLines(services, new Map(), () => procPortOwner(PORT, procFs), new Set([PORT]))[0]).toBe(line);
    expect(hostServiceOwnerWarningsFromSnapshot(procListenerSnapshot(procFs), new Set([PORT]), services, new Map())[0]).toBe(line);
  });

  test("the snapshot groups by process per port, in pid order, like lsof", () => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, 10), row("0100007F:1F90", 1000, 20)],
      tcp6: [row6("00000000000000000000000001000000:2A82", 1000, 30)],
      processes: {
        900: { fds: { 4: "socket:[30]", 5: "socket:[10]" }, exe: "/opt/app/server" },
        800: { fds: { 4: "socket:[20]" }, cmdline: "/usr/bin/devserver\0--port\0" },
      },
    });
    const snapshot = procListenerSnapshot(procFs);
    expect(snapshot.kind).toBe("observed");
    if (snapshot.kind !== "observed") return;
    expect(snapshot.byPort.get(PORT)).toEqual([{ command: "server", pid: 900, addresses: ["127.0.0.1:10882", "[::1]:10882"] }]);
    // No exe link: the first cmdline argument names it.
    expect(snapshot.byPort.get(8080)).toEqual([{ command: "devserver", pid: 800, addresses: ["127.0.0.1:8080"] }]);
  });

  // REVIEW-1 #3: the 15-character comm is never a name. A live holder whose
  // exe and cmdline both fail is not admitted and not mistaken for "nobody".
  test("a live holder named only by comm (exe unreadable, cmdline gone) makes the answer unavailable, not a listener", () => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, 4242)],
      processes: { 4242: { fds: { 7: "socket:[4242]" }, comm: "idb_companion_f" } },
    });
    const result = procPortOwner(PORT, procFs);
    expect(result.kind).toBe("unavailable");
    expect(result.kind === "unavailable" ? result.reason : "").toContain("neither /proc/4242/exe nor /proc/4242/cmdline gives its full name");
    expect(JSON.stringify(result)).not.toContain("idb_companion_f\"");
    expect(admit(procFs).ok).toBe(false);
    expect(procListenerSnapshot(procFs).kind).toBe("unavailable");
  });

  test("an empty cmdline (exe unreadable) is no full name either", () => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, 4242)],
      processes: { 4242: { fds: { 7: "socket:[4242]" }, cmdline: "", comm: "worker" } },
    });
    expect(procPortOwner(PORT, procFs).kind).toBe("unavailable");
  });

  test("a holder that exited mid-walk (exe and cmdline gone) is skipped: the socket shows as no visible listener", () => {
    const procFs = fixtureProc({
      tcp: [row("0100007F:2A82", 1000, 4242)],
      processes: { 4242: { fds: { 7: "socket:[4242]" }, comm: "idb_companion_f", exited: true } },
    });
    expect(procPortOwner(PORT, procFs)).toEqual({ kind: "none", hidden: [{ uid: 1000, address: "127.0.0.1:10882" }] });
  });

  test("addresses use lsof's spelling", () => {
    expect(listenAddressText({ address: "0.0.0.0", port: 1 })).toBe("*:1");
    expect(listenAddressText({ address: "::", port: 1 })).toBe("*:1");
    expect(listenAddressText({ address: "::1", port: 1 })).toBe("[::1]:1");
    expect(listenAddressText({ address: "::ffff:127.0.0.1", port: 1 })).toBe("127.0.0.1:1");
    expect(listenAddressText({ address: "172.17.0.1", port: 1 })).toBe("172.17.0.1:1");
  });

  test("process names are sanitized before they reach a terminal", () => {
    const procFs = fixtureProc({ tcp: [row("0100007F:2A82", 1000, 4242)], processes: { 4242: owner(4242, { exe: "/tmp/evil\u001b[2Jname" }) } });
    const result = procPortOwner(PORT, procFs);
    expect(result.kind === "listener" ? result.command : "").not.toMatch(/[\u0000-\u001f\u007f]/u);
  });
});
