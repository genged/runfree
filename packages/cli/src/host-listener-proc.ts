// The Linux host listener check: `/proc` (behind `host-listener-probe.ts`).
//
// Answers the same question lsof answers on macOS, with no external binary:
//   1. `/proc/net/tcp` and `/proc/net/tcp6` list every LISTEN socket on the
//      host with its address, port, owning uid, and inode;
//   2. each `/proc/<pid>/fd/*` link that reads `socket:[<inode>]` names a
//      process holding one of those sockets. Only the user's own processes
//      (or every process, as root) are readable;
//   3. the process is named by the basename of `/proc/<pid>/exe`, else of
//      its first `cmdline` argument, never the 15-character `comm`.
// A socket no visible process holds (root's, another user's) is not a
// listener: it is reported as hidden, with its uid, and admission refuses it
// as "no visible listener", the same as an unprivileged lsof on macOS.
// Addresses use lsof's spelling: `127.0.0.1:P`, `[::1]:P`, and `*:P` for
// both `0.0.0.0` and `[::]` (a dual-stack IPv6 wildcard also takes IPv4).
//
// Bounded and fail-closed: every read is size-capped, the process and fd
// walks are capped, and any read or parse error other than a process that
// exited or is not ours makes the whole answer `unavailable`.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  parseProcNetTcp,
  PROC_NET_TCP_LISTEN_STATE,
  type ProcNetTcpFamily,
  type ProcNetTcpSocket,
} from "@runfree/runtime-contracts/proc-net-tcp";

import { printableCommand } from "./host-listener-lsof.ts";
import type { HostListenerSnapshot } from "./host-listener-snapshot.ts";
import type { HiddenHostListener, HostPortListener, HostPortOwner } from "./host-service-port-owner.ts";

export const PROC_NET_TCP_MAX_BYTES = 16 * 1024 * 1024;
export const PROC_SMALL_FILE_MAX_BYTES = 64 * 1024;
export const PROC_MAX_PROCESSES = 65_536;
export const PROC_MAX_FD_LINKS = 1_048_576;

/** The `/proc` reads the probe needs; tests substitute fixture text. */
export type ProcFs = Readonly<{
  readText(filePath: string, maxBytes: number): string;
  listDir(dirPath: string): string[];
  readLink(linkPath: string): string;
}>;

function readBounded(filePath: string, maxBytes: number): string {
  const descriptor = fs.openSync(filePath, "r");
  try {
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const chunk = Buffer.alloc(64 * 1024);
      const read = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (read === 0) break;
      total += read;
      if (total > maxBytes) throw Object.assign(new Error(`${filePath} exceeds ${maxBytes} bytes`), { code: "E2BIG" });
      chunks.push(chunk.subarray(0, read));
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

export const nodeProcFs: ProcFs = Object.freeze({
  readText: readBounded,
  listDir: (dirPath: string) => fs.readdirSync(dirPath),
  readLink: (linkPath: string) => fs.readlinkSync(linkPath),
});

const PID_DIR_RE = /^[1-9][0-9]{0,9}$/u;
const FD_RE = /^[0-9]{1,10}$/u;
const SOCKET_LINK_RE = /^socket:\[([0-9]{1,20})\]$/u;
// A process that exited mid-walk, or one this user may not inspect.
const SKIPPABLE_CODES = new Set(["ENOENT", "ESRCH", "EACCES", "EPERM"]);

class ProcUnavailable extends Error {}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function unavailableReason(detail: string): string {
  return `the host listener check (/proc) failed: ${printableCommand(detail)}`;
}

/** lsof's spelling of a listen address, so every probe reports the same text. */
export function listenAddressText(socket: Pick<ProcNetTcpSocket, "address" | "port">): string {
  const { address, port } = socket;
  if (address === "0.0.0.0" || address === "::") return `*:${port}`;
  if (address.startsWith("::ffff:")) return `${address.slice("::ffff:".length)}:${port}`;
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

function listeningSockets(procFs: ProcFs, littleEndian: boolean): ProcNetTcpSocket[] {
  const sockets: ProcNetTcpSocket[] = [];
  for (const [filePath, family] of [["/proc/net/tcp", 4], ["/proc/net/tcp6", 6]] as const satisfies readonly (readonly [string, ProcNetTcpFamily])[]) {
    let text: string;
    try {
      text = procFs.readText(filePath, PROC_NET_TCP_MAX_BYTES);
    } catch (error) {
      // A kernel without IPv6 has no tcp6 table; nothing listens there.
      if (family === 6 && errorCode(error) === "ENOENT") continue;
      throw new ProcUnavailable(`could not read ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
    }
    const parsed = parseProcNetTcp(text, family, littleEndian);
    if (!Array.isArray(parsed)) throw new ProcUnavailable(parsed.error);
    sockets.push(...parsed.filter((socket) => socket.state === PROC_NET_TCP_LISTEN_STATE));
  }
  return sockets;
}

const GONE_CODES = new Set(["ENOENT", "ESRCH"]);

/**
 * The process's full name: the basename of `/proc/<pid>/exe`, else of its
 * first `cmdline` argument. Never the 15-character `comm`, which truncates
 * exactly the names admission and its warnings report. Undefined when the
 * process exited (both sources are gone). A live process holding a listening
 * socket whose full name cannot be read (both sources unreadable or empty)
 * fails the whole observation: a listener that cannot be named is not
 * admitted, and is not mistaken for no listener either.
 */
function processName(procFs: ProcFs, pid: string): string | undefined {
  const base = (value: string): string => path.posix.basename(value.replace(/ \(deleted\)$/u, ""));
  let gone = 0;
  try {
    const exe = base(procFs.readLink(`/proc/${pid}/exe`));
    if (exe !== "") return printableCommand(exe);
  } catch (error) {
    const code = errorCode(error) ?? "";
    if (!SKIPPABLE_CODES.has(code)) throw error;
    if (GONE_CODES.has(code)) gone += 1;
  }
  try {
    const argv0 = base(procFs.readText(`/proc/${pid}/cmdline`, PROC_SMALL_FILE_MAX_BYTES).split("\0")[0] ?? "");
    if (argv0 !== "") return printableCommand(argv0);
  } catch (error) {
    const code = errorCode(error) ?? "";
    if (!SKIPPABLE_CODES.has(code)) throw error;
    if (GONE_CODES.has(code)) gone += 1;
  }
  if (gone === 2) return undefined;
  throw new ProcUnavailable(`process ${pid} holds a listening socket, but neither /proc/${pid}/exe nor /proc/${pid}/cmdline gives its full name`);
}

/** inode -> every visible process holding it (a forked listener has several). */
function socketOwners(procFs: ProcFs, wanted: ReadonlySet<string>): Map<string, Array<{ pid: number; command: string }>> {
  const owners = new Map<string, Array<{ pid: number; command: string }>>();
  if (wanted.size === 0) return owners;
  let entries: string[];
  try {
    entries = procFs.listDir("/proc");
  } catch (error) {
    throw new ProcUnavailable(`could not list /proc: ${error instanceof Error ? error.message : String(error)}`);
  }
  const pids = entries.filter((entry) => PID_DIR_RE.test(entry)).sort((left, right) => Number(left) - Number(right));
  if (pids.length > PROC_MAX_PROCESSES) throw new ProcUnavailable(`more than ${PROC_MAX_PROCESSES} processes`);
  let links = 0;
  for (const pid of pids) {
    let fds: string[];
    try {
      fds = procFs.listDir(`/proc/${pid}/fd`);
    } catch (error) {
      if (SKIPPABLE_CODES.has(errorCode(error) ?? "")) continue;
      throw new ProcUnavailable(`could not list /proc/${pid}/fd: ${error instanceof Error ? error.message : String(error)}`);
    }
    const held = new Set<string>();
    for (const fd of fds) {
      if (!FD_RE.test(fd)) continue;
      links += 1;
      if (links > PROC_MAX_FD_LINKS) throw new ProcUnavailable(`more than ${PROC_MAX_FD_LINKS} open file descriptors`);
      let target: string;
      try {
        target = procFs.readLink(`/proc/${pid}/fd/${fd}`);
      } catch (error) {
        if (SKIPPABLE_CODES.has(errorCode(error) ?? "")) continue;
        throw new ProcUnavailable(`could not read /proc/${pid}/fd/${fd}: ${error instanceof Error ? error.message : String(error)}`);
      }
      const match = SOCKET_LINK_RE.exec(target);
      // Compared as exact decimal text: a 64-bit inode exceeds a number's range.
      const inode = match?.[1];
      if (inode !== undefined && wanted.has(inode)) held.add(inode);
    }
    if (held.size === 0) continue;
    let command: string | undefined;
    try {
      command = processName(procFs, pid);
    } catch (error) {
      throw new ProcUnavailable(`could not name process ${pid}: ${error instanceof Error ? error.message : String(error)}`);
    }
    // The process exited between the fd walk and naming it: its sockets are
    // whatever another holder (or nobody) shows.
    if (command === undefined) continue;
    for (const inode of held) {
      const list = owners.get(inode) ?? [];
      list.push({ pid: Number(pid), command });
      owners.set(inode, list);
    }
  }
  return owners;
}

type ProcObservation = Readonly<{
  byPort: Map<number, HostPortListener[]>;
  hiddenByPort: Map<number, HiddenHostListener[]>;
}>;

function observe(procFs: ProcFs, port: number | undefined, littleEndian: boolean): ProcObservation {
  const sockets = listeningSockets(procFs, littleEndian).filter((socket) => port === undefined || socket.port === port);
  const owners = socketOwners(procFs, new Set(sockets.map((socket) => socket.inode).filter((inode) => inode !== "0")));
  const byPort = new Map<number, HostPortListener[]>();
  const hiddenByPort = new Map<number, HiddenHostListener[]>();
  // Group by process within each port, ordered by pid, as lsof reports them.
  const perPort = new Map<number, Map<number, HostPortListener>>();
  for (const socket of sockets) {
    const address = listenAddressText(socket);
    const holders = socket.inode === "0" ? undefined : owners.get(socket.inode);
    if (!holders || holders.length === 0) {
      const hidden = hiddenByPort.get(socket.port) ?? [];
      if (!hidden.some((entry) => entry.uid === socket.uid && entry.address === address)) hidden.push({ uid: socket.uid, address });
      hiddenByPort.set(socket.port, hidden);
      continue;
    }
    const processes = perPort.get(socket.port) ?? new Map<number, HostPortListener>();
    for (const holder of holders) {
      const listener = processes.get(holder.pid) ?? { command: holder.command, pid: holder.pid, addresses: [] };
      if (!listener.addresses.includes(address)) listener.addresses.push(address);
      processes.set(holder.pid, listener);
    }
    perPort.set(socket.port, processes);
  }
  for (const [listenPort, processes] of perPort) {
    byPort.set(listenPort, [...processes.values()].sort((left, right) => left.pid - right.pid));
  }
  return { byPort, hiddenByPort };
}

const LITTLE_ENDIAN = os.endianness() === "LE";

/** Who listens on the host's TCP `port`, from `/proc`. */
export function procPortOwner(port: number, procFs: ProcFs = nodeProcFs, littleEndian = LITTLE_ENDIAN): HostPortOwner {
  let observation: ProcObservation;
  try {
    observation = observe(procFs, port, littleEndian);
  } catch (error) {
    return { kind: "unavailable", reason: unavailableReason(error instanceof Error ? error.message : String(error)) };
  }
  const listeners = observation.byPort.get(port) ?? [];
  const first = listeners[0];
  if (!first) {
    const hidden = observation.hiddenByPort.get(port) ?? [];
    return hidden.length > 0 ? { kind: "none", hidden } : { kind: "none" };
  }
  return {
    kind: "listener",
    command: first.command,
    pid: first.pid,
    count: listeners.length,
    commands: listeners.map((entry) => entry.command),
    listeners,
  };
}

/** Every TCP listener on the host, from one `/proc` observation (F29). */
export function procListenerSnapshot(procFs: ProcFs = nodeProcFs, littleEndian = LITTLE_ENDIAN): HostListenerSnapshot {
  try {
    const observation = observe(procFs, undefined, littleEndian);
    return observation.hiddenByPort.size > 0
      ? { kind: "observed", byPort: observation.byPort, hiddenByPort: observation.hiddenByPort }
      : { kind: "observed", byPort: observation.byPort };
  } catch (error) {
    return { kind: "unavailable", reason: unavailableReason(error instanceof Error ? error.message : String(error)) };
  }
}
