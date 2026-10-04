// Host-service port admission (design "Policy shape", SR5/SR13).
//
// Before a `runfree host-service add` writes policy, the host checks the port:
//   1. the static refusals shared with policy validation (Docker Engine TCP,
//      runfree's own VNC default and MCP callback block);
//   2. the live owner: `lsof` must show a visible process listening on the
//      host's TCP port. No listener refuses (Docker Desktop answers some ports
//      from its VM, root-owned services are invisible); a `com.docker.*` owner
//      refuses (another container's published port, or Docker Engine TCP).
// The admitted owner (command and pid) is what the operator reviews and what
// the port registry records.
//
// lsof runs from its absolute path (no PATH lookup) with the sanitized host
// environment, a fixed locale, and a bound; any failure that is not lsof's
// clean "no match" exit is `unavailable`, which admission refuses (fail
// closed). The probe only reads: it never connects to the port.

import { refusedHostServicePortReason, type HostServicesJson } from "@runfree/runtime-contracts/host-services";

import { sanitizedHostExecutionEnv } from "./host-path.ts";
import type { RuntimeContext, RuntimeIO } from "./runtime/types.ts";

export type HostPortOwner =
  // `command`/`pid` name the first listener (what the operator reviews);
  // `commands` lists every listening process, so admission can refuse when
  // any of them is Docker Desktop.
  | { kind: "listener"; command: string; pid: number; count: number; commands: string[] }
  | { kind: "none" }
  | { kind: "unavailable"; reason: string };

export type HostServicePortAdmission =
  | { ok: true; owner: { command: string; pid: number } }
  | { ok: false; reason: string };

export const LSOF_PATH = "/usr/sbin/lsof";
const LSOF_TIMEOUT_MS = 5_000;
const PID_RE = /^[1-9][0-9]{0,9}$/u;
const MAX_COMMAND_LENGTH = 256;
const DOCKER_DESKTOP_COMMAND_PREFIX = "com.docker";

type ProbeContext = Pick<RuntimeContext, "env" | "projectRoot">;

// Process names are host data printed to the operator's terminal and stored
// in the registry: replace anything that is not printable ASCII.
function printableCommand(raw: string): string {
  return raw.slice(0, MAX_COMMAND_LENGTH).replace(/[^\x20-\x7e]/gu, "?");
}

function parseLsofFields(stdout: string): HostPortOwner {
  const processes: Array<{ pid: number; command?: string }> = [];
  for (const line of stdout.split("\n")) {
    if (line === "") continue;
    const field = line[0];
    const value = line.slice(1);
    if (field === "p") {
      if (!PID_RE.test(value)) return { kind: "unavailable", reason: `lsof reported a malformed pid: ${printableCommand(value)}` };
      processes.push({ pid: Number(value) });
    } else if (field === "c") {
      const current = processes.at(-1);
      if (!current || current.command !== undefined || value === "") {
        return { kind: "unavailable", reason: "lsof reported a process name outside a process record" };
      }
      current.command = printableCommand(value);
    }
    // Other fields (lsof always adds `f` file descriptor records) are ignored.
  }
  const first = processes[0];
  if (!first) return { kind: "unavailable", reason: "lsof exited 0 but reported no listening process" };
  if (processes.some((entry) => entry.command === undefined)) {
    return { kind: "unavailable", reason: "lsof reported a listening process without its name" };
  }
  return {
    kind: "listener",
    command: first.command as string,
    pid: first.pid,
    count: processes.length,
    commands: processes.map((entry) => entry.command as string),
  };
}

/** Who listens on the host's TCP `port` (macOS only; read-only, bounded). */
export function probeHostPortOwner(
  context: ProbeContext,
  io: RuntimeIO,
  port: number,
  platform: NodeJS.Platform = process.platform,
): HostPortOwner {
  if (platform !== "darwin") {
    return { kind: "unavailable", reason: "the host listener check needs macOS (Docker Desktop for Mac)" };
  }
  // `+c 0`: the full process name, never lsof's default 9-character cut.
  const result = io.capture(LSOF_PATH, ["-nP", "+c", "0", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fpc"], {
    encoding: "utf8",
    timeout: LSOF_TIMEOUT_MS,
    env: { ...sanitizedHostExecutionEnv(context.projectRoot, context.env ?? process.env), LC_ALL: "C" },
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

/** Static refusal first (no probe), then the live owner check. */
export function admitHostServicePort(
  context: ProbeContext,
  io: RuntimeIO,
  port: number,
  platform: NodeJS.Platform = process.platform,
): HostServicePortAdmission {
  const staticReason = refusedHostServicePortReason(port);
  if (staticReason !== undefined) return { ok: false, reason: `port ${port} is refused: ${staticReason}` };
  const owner = probeHostPortOwner(context, io, port, platform);
  if (owner.kind === "none") return { ok: false, reason: `no process listens on 127.0.0.1:${port}` };
  if (owner.kind === "unavailable") return { ok: false, reason: owner.reason };
  // Every listener counts: two sockets can share a port on macOS (a user
  // process on [::1] or *, Docker Desktop on 127.0.0.1, which the gateway
  // reaches), so a non-Docker first listener proves nothing alone.
  if (owner.commands.some((command) => command.startsWith(DOCKER_DESKTOP_COMMAND_PREFIX))) {
    return { ok: false, reason: `127.0.0.1:${port} is owned by Docker Desktop (a published container port)` };
  }
  return { ok: true, owner: { command: owner.command, pid: owner.pid } };
}

/**
 * Live re-check (design "Policy shape", Re-check, SR13): every launch and
 * `runfree status` repeat the owner check for each approved host service, so
 * drift since `add` time (a stopped service, a different process, a port a
 * container now publishes) is never silent. `recorded` is the owner command
 * the port registry has on file for this port, if any; a warning fires only
 * when there is a problem, never on a clean match, and the function never
 * throws — an unavailable probe reports its own reason as the problem.
 */
export function hostServiceOwnerWarnings(
  context: ProbeContext,
  io: RuntimeIO,
  services: HostServicesJson,
  recorded: ReadonlyMap<number, string>,
): string[] {
  const lines: string[] = [];
  for (const [name, entry] of Object.entries(services).sort(([left], [right]) => left.localeCompare(right))) {
    const label = `host service ${name} (127.0.0.1:${entry.port})`;
    const owner = probeHostPortOwner(context, io, entry.port);
    if (owner.kind === "none") {
      lines.push(`${label}: no listener`);
    } else if (owner.kind === "unavailable") {
      lines.push(`${label}: ${owner.reason}`);
    } else if (owner.commands.some((command) => command.startsWith(DOCKER_DESKTOP_COMMAND_PREFIX))) {
      lines.push(`${label}: owned by Docker Desktop`);
    } else {
      const previous = recorded.get(entry.port);
      if (previous !== undefined && previous !== owner.command) {
        lines.push(`${label}: listener changed to ${owner.command}`);
      }
    }
  }
  return lines;
}
