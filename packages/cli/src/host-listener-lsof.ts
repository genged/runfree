// The macOS host listener check: `lsof` (behind `host-listener-probe.ts`).
//
// lsof runs from its absolute path (no PATH lookup) with the sanitized host
// environment, a fixed locale, and a bound; any failure that is not lsof's
// clean "no match" exit is `unavailable`, which admission refuses (fail
// closed). The probe only reads: it never connects to the port. The single
// port query serves `host-service add` and `status`; the batched one (F29)
// serves the launch-time warning loop.

import { sanitizedHostExecutionEnv } from "./host-path.ts";
import type { HostListenerSnapshot } from "./host-listener-snapshot.ts";
import type { HostPortListener, HostPortOwner } from "./host-service-port-owner.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";

export const LSOF_PATH = "/usr/sbin/lsof";
export const LSOF_TIMEOUT_MS = 5_000;
const PID_RE = /^[1-9][0-9]{0,9}$/u;
const MAX_COMMAND_LENGTH = 256;

// Bounded single observation (F29): one call, this cap, this timeout. An
// explicit cap rather than relying on Node's own default, so the bound is a
// read fact of this module, not an implicit runtime default that could
// silently change. A real overrun fails the whole snapshot closed (the
// underlying spawn's own ENOBUFS handling reports a non-zero `status`; see
// runtime/spawn-status.ts), never a trusted partial read.
export const LSOF_LISTENERS_MAX_BUFFER_BYTES = 1024 * 1024;

// `-nP`: no hostname/port-name resolution. `+c 0`: full process names. No
// `-iTCP:<port>`: every TCP listener on the host, in one call. `-sTCP:LISTEN`:
// listening sockets only. `-Fpcn`: pid, command, and each listen address.
export const LSOF_LISTENERS_ARGS = ["-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN", "-Fpcn"];

type ProbeContext = Pick<RuntimeContext, "env" | "projectRoot">;

const PORT_SUFFIX_RE = /:(\d{1,5})$/u;

// Process names are host data printed to the operator's terminal and stored
// in the registry: replace anything that is not printable ASCII. Shared by
// both lsof call shapes and the Linux /proc probe, so every probe sanitizes
// identically.
export function printableCommand(raw: string): string {
  return raw.slice(0, MAX_COMMAND_LENGTH).replace(/[^\x20-\x7e]/gu, "?");
}

export type LsofProcessRecord = { pid: number; command: string; addresses: string[] };

/**
 * Parses `lsof -Fpcn` field output (`p`id, `c`ommand, `n` listen address per
 * process) into one record per process. Shared by the single-port probe
 * and the batched snapshot (F29): any malformed field anywhere in the output
 * fails the whole parse rather than trusting a partial prefix.
 */
export function parseLsofProcessRecords(stdout: string): LsofProcessRecord[] | { reason: string } {
  const processes: Array<{ pid: number; command?: string; addresses: string[] }> = [];
  for (const line of stdout.split("\n")) {
    if (line === "") continue;
    const field = line[0];
    const value = line.slice(1);
    if (field === "p") {
      if (!PID_RE.test(value)) return { reason: `lsof reported a malformed pid: ${printableCommand(value)}` };
      processes.push({ pid: Number(value), addresses: [] });
    } else if (field === "c") {
      const current = processes.at(-1);
      if (!current || current.command !== undefined || value === "") {
        return { reason: "lsof reported a process name outside a process record" };
      }
      current.command = printableCommand(value);
    } else if (field === "n") {
      const current = processes.at(-1);
      if (!current || value === "") return { reason: "lsof reported a listen address outside a process record" };
      current.addresses.push(printableCommand(value));
    }
    // Other fields (lsof always adds `f` file descriptor records) are ignored.
  }
  if (processes.some((entry) => entry.command === undefined)) {
    return { reason: "lsof reported a listening process without its name" };
  }
  return processes.map((entry) => ({ pid: entry.pid, command: entry.command as string, addresses: entry.addresses }));
}

function parseLsofFields(stdout: string): HostPortOwner {
  const parsed = parseLsofProcessRecords(stdout);
  if (!Array.isArray(parsed)) return { kind: "unavailable", reason: parsed.reason };
  const first = parsed[0];
  if (!first) return { kind: "unavailable", reason: "lsof exited 0 but reported no listening process" };
  return {
    kind: "listener",
    command: first.command,
    pid: first.pid,
    count: parsed.length,
    commands: parsed.map((entry) => entry.command),
    listeners: parsed.map((entry) => ({ command: entry.command, pid: entry.pid, addresses: entry.addresses })),
  };
}

function lsofEnv(context: ProbeContext): NodeJS.ProcessEnv {
  return { ...sanitizedHostExecutionEnv(context.projectRoot, context.env ?? process.env), LC_ALL: "C" };
}

/** Who listens on the host's TCP `port`, from one bounded `lsof` call. */
export function lsofPortOwner(context: ProbeContext, io: RuntimeIO, port: number): HostPortOwner {
  // `+c 0`: the full process name, never lsof's default 9-character cut.
  // `-Fpcn`: pid, command, and each listen address (R22).
  const result = io.capture(LSOF_PATH, ["-nP", "+c", "0", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fpcn"], {
    encoding: "utf8",
    timeout: LSOF_TIMEOUT_MS,
    env: lsofEnv(context),
  });
  // lsof exits 1 both for "no match" and for errors; only a silent exit 1 is
  // an answer. Anything on stderr makes the result unknown, never "none".
  if (result.status === 1 && result.stdout.trim() === "" && result.stderr.trim() === "") return { kind: "none" };
  if (result.status !== 0) {
    const detail = result.timedOut ? "timed out" : `exited with status ${result.status}`;
    const stderr = printableCommand(result.stderr.trim());
    return { kind: "unavailable", reason: `the host listener check (lsof) ${detail}${stderr ? `: ${stderr}` : ""}` };
  }
  return parseLsofFields(result.stdout);
}

function buildSnapshot(stdout: string): HostListenerSnapshot {
  const parsed = parseLsofProcessRecords(stdout);
  if (!Array.isArray(parsed)) return { kind: "unavailable", reason: parsed.reason };
  // Mirrors `parseLsofFields`'s identical guard: lsof's own exit convention
  // with an `-i` search option is 0 only when at least one match is found, so
  // a clean `status === 0` with zero parsed records is itself an anomaly, not
  // a legitimate "nothing listens" answer (that is the `status === 1`,
  // empty-output branch in `lsofListenerSnapshot`). Falling through here would
  // otherwise return the same `{ kind: "observed", byPort: new Map() }` shape
  // as that genuine no-match case, silently suppressing every approved
  // service's warning.
  if (parsed.length === 0) return { kind: "unavailable", reason: "lsof exited 0 but reported no listening process" };
  const byPort = new Map<number, HostPortListener[]>();
  for (const record of parsed) {
    // One process can hold listeners on several ports (and several addresses
    // on the same port); group this record's addresses by their own port
    // before merging into the snapshot, so each port's entry looks exactly
    // like a single-port `lsof -iTCP:<port>` query would have reported it.
    const addressesByPort = new Map<number, string[]>();
    for (const address of record.addresses) {
      const match = PORT_SUFFIX_RE.exec(address);
      if (!match) return { kind: "unavailable", reason: `lsof reported a listen address with no parsable port: ${address}` };
      const port = Number(match[1]);
      const addresses = addressesByPort.get(port) ?? [];
      addresses.push(address);
      addressesByPort.set(port, addresses);
    }
    for (const [port, addresses] of addressesByPort) {
      const listeners = byPort.get(port) ?? [];
      listeners.push({ command: record.command, pid: record.pid, addresses });
      byPort.set(port, listeners);
    }
  }
  return { kind: "observed", byPort };
}

/** Every TCP listener on the host, from one bounded `lsof` call (F29). */
export function lsofListenerSnapshot(context: ProbeContext, io: RuntimeIO): HostListenerSnapshot {
  const result = io.capture(LSOF_PATH, LSOF_LISTENERS_ARGS, {
    encoding: "utf8",
    timeout: LSOF_TIMEOUT_MS,
    maxBuffer: LSOF_LISTENERS_MAX_BUFFER_BYTES,
    env: lsofEnv(context),
  });
  // lsof exits 1 both for "no match" and for errors; only a silent exit 1 is
  // an answer (no TCP listener anywhere on the host). Anything on stderr
  // makes the result unknown, never a clean "nothing listens".
  if (result.status === 1 && result.stdout.trim() === "" && result.stderr.trim() === "") {
    return { kind: "observed", byPort: new Map() };
  }
  if (result.status !== 0) {
    const detail = result.timedOut ? "timed out" : `exited with status ${result.status}`;
    const stderr = printableCommand(result.stderr.trim());
    return { kind: "unavailable", reason: `the host listener check (lsof) ${detail}${stderr ? `: ${stderr}` : ""}` };
  }
  return buildSnapshot(result.stdout);
}
