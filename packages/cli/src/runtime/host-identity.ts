// Host boot identity.
//
// A PID is not process identity. Records that outlive a crash — the runtime
// lifecycle lock, the token-store lock, session metadata — are read again after
// a reboot, exactly when PIDs are being reissued from low numbers, so a
// recorded PID can match an unrelated live process and make dead state look
// alive. Stamping the boot the record was written on makes that case decidable:
// a different boot proves the recorded process is gone.
//
// `undefined` means "cannot prove", never "no". Callers must fall back to their
// existing PID-only behavior rather than assuming either answer, so an
// unsupported platform or a failed probe can never delete a live holder's lock.

import { execFileSync } from "node:child_process";
import fs from "node:fs";

// Canonical boot identity: a platform tag plus that platform's per-boot UUID.
// Tagged so values from different platforms can never compare equal, and
// bounded so a corrupt value cannot become an unbounded record.
//
// The shape is deliberately exact rather than permissive. Both sources emit a
// UUID (`/proc/sys/kernel/random/boot_id`, `kern.bootsessionuuid`), so a
// truncated stamp like `linux:8a7f` is provably not an identity — and a
// permissive pattern would accept it, compare it unequal to the real current
// boot, and report a live lock as belonging to a previous one.
const BOOT_ID_RE = /^(?:linux|darwin):[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const PROCESS_START_RE = /^(?:linux:[0-9]+|darwin:[0-9]+)$/;

let cachedPlatformBootId: { value: string | undefined } | undefined;

// This process's own start time, once proved. A process's start never changes,
// so only a successful own-pid probe is cached; other pids stay live questions
// because pids are reused.
let cachedOwnProcessStart: string | undefined;

export function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error instanceof Error && "code" in error && error.code === "EPERM";
  }
}

function readLinuxBootId(): string | undefined {
  try {
    const value = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return value === "" ? undefined : `linux:${value}`;
  } catch {
    return undefined;
  }
}

// Absolute paths only, never a PATH lookup. A shim ahead of the real binary
// could mint an attacker-chosen UUID, but the likelier failure is plain
// correctness: two Runfree processes whose PATHs resolve `sysctl` differently
// would derive different identities for the same boot, and each would read the
// other's live lock as belonging to a previous one and delete it. Identity has
// to be a property of the machine, so it cannot be read through a
// per-process-resolvable name. `/usr/sbin/sysctl` is the base-system location
// on every supported macOS; `/sbin` is the fallback. An exhausted list is
// "cannot prove", which is the pre-existing PID-only behavior.
const DARWIN_SYSCTL_PATHS = ["/usr/sbin/sysctl", "/sbin/sysctl"] as const;

// Deliberately far below `LOCK_PIDLESS_GRACE_MS` (runtime/sessions.ts), not
// coincidentally equal to it. Lock callers resolve boot identity *before*
// creating their lock directory precisely so this spawn cannot sit inside the
// pid-less window, but a probe permitted to run as long as the grace turns any
// future regression of that ordering from a race into a guaranteed steal.
// `host-identity.test.ts` pins the inequality.
export const DARWIN_BOOT_PROBE_TIMEOUT_MS = 250;
export const DARWIN_PROCESS_PROBE_TIMEOUT_MS = 250;

// `kern.bootsessionuuid` is minted once per boot and never changes for its
// lifetime, which is the property this module needs.
//
// `kern.boottime` is deliberately NOT used, despite reading like a boot
// identity: it is the boot instant expressed against the *current* calendar
// clock, so XNU rewrites it whenever the clock is stepped — an NTP correction
// after sleep is the ordinary case, no reboot involved. Deriving identity from
// it would let a routine clock adjustment classify live locks and live sessions
// as belonging to a previous boot, deleting a lock whose owner is still running
// and admitting two holders into the critical section: the exact failure the
// lock exists to prevent.
//
// There is no second-choice *source* here on purpose (the two paths above are
// two locations for one source). When the UUID is unavailable or
// unrecognizable the answer is `undefined` ("cannot prove") and callers keep
// their PID-only behavior. A mutable identity is worse than no identity.
function readDarwinBootSessionUuid(env: NodeJS.ProcessEnv): string | undefined {
  for (const sysctlPath of DARWIN_SYSCTL_PATHS) {
    try {
      const output = execFileSync(sysctlPath, ["-n", "kern.bootsessionuuid"], {
        encoding: "utf8",
        timeout: DARWIN_BOOT_PROBE_TIMEOUT_MS,
        stdio: ["ignore", "pipe", "ignore"],
        env: { ...env, LC_ALL: "C" },
      }).trim();
      if (output !== "") return `darwin:${output}`;
    } catch {
      // Missing at this location, or the probe failed: try the next known one.
    }
  }
  return undefined;
}

// Cached per process and deliberately not keyed on `env`: the boot a machine is
// running is a property of the machine, so a second call that passes a
// different environment must not be able to derive a different answer. `env` is
// only the environment handed to the probe subprocess.
function platformBootId(env: NodeJS.ProcessEnv): string | undefined {
  if (!cachedPlatformBootId) {
    const value = process.platform === "linux"
      ? readLinuxBootId()
      : process.platform === "darwin"
        ? readDarwinBootSessionUuid(env)
        : undefined;
    cachedPlatformBootId = { value: value !== undefined && BOOT_ID_RE.test(value) ? value : undefined };
  }
  return cachedPlatformBootId.value;
}

export function hostBootId(env: NodeJS.ProcessEnv = process.env): string | undefined {
  // Honored only under the fake-docker harness, like the repo's other
  // consequential RUNFREE_TEST_* overrides (see `fakeDockerMsOverride` in
  // admin-core.ts). Boot identity must be a property of the machine, not of one
  // process's environment: two concurrent commands whose environments disagreed
  // would derive different identities for the same boot, and each would read
  // the other's live lock as belonging to a previous one and delete it —
  // admitting two holders into the critical section the lock exists to protect.
  // Outside the harness the override is ignored rather than rejected, because
  // ignoring it yields the correct platform identity and needs no failure path.
  if (env.RUNFREE_TEST_FAKE_DOCKER === "1") {
    const override = env.RUNFREE_TEST_HOST_BOOT_ID?.trim();
    if (override !== undefined && override !== "") {
      return BOOT_ID_RE.test(override) ? override : undefined;
    }
  }
  return platformBootId(env);
}

function readLinuxProcessStart(pid: number): string | undefined {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    // comm is parenthesized and may itself contain spaces or `)`, so field 22
    // cannot be found by splitting the whole record. After the final `)`, the
    // first token is field 3 (state); starttime is therefore token index 19.
    const commandEnd = stat.lastIndexOf(")");
    if (commandEnd < 0) return undefined;
    const fieldsAfterCommand = stat.slice(commandEnd + 1).trim().split(/\s+/);
    const starttime = fieldsAfterCommand[19];
    return starttime && /^[0-9]+$/.test(starttime) ? `linux:${starttime}` : undefined;
  } catch {
    return undefined;
  }
}

const DARWIN_PS_PATHS = ["/bin/ps", "/usr/bin/ps"] as const;

function readDarwinProcessStart(pid: number, env: NodeJS.ProcessEnv): string | undefined {
  for (const psPath of DARWIN_PS_PATHS) {
    try {
      const output = execFileSync(psPath, ["-p", String(pid), "-o", "lstart="], {
        encoding: "utf8",
        timeout: DARWIN_PROCESS_PROBE_TIMEOUT_MS,
        stdio: ["ignore", "pipe", "ignore"],
        env: { ...env, LC_ALL: "C" },
      }).trim();
      if (output === "") continue;
      const epochMs = Date.parse(output);
      if (Number.isFinite(epochMs) && epochMs >= 0) return `darwin:${Math.trunc(epochMs)}`;
    } catch {
      // Missing at this location, the PID exited, or the probe failed.
    }
  }
  return undefined;
}

export function validHostProcessStart(value: unknown): value is string {
  return typeof value === "string" && PROCESS_START_RE.test(value.trim());
}

// Exact identity for one host PID. Like hostBootId, the production result is
// derived only from absolute platform sources. The fake-docker-only override
// makes process-reuse and probe-failure behavior deterministic in tests without
// creating a production environment authority channel.
export function hostProcessStart(
  pid: number = process.pid,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  if (!Number.isInteger(pid) || pid <= 0) return undefined;
  if (env.RUNFREE_TEST_FAKE_DOCKER === "1") {
    const override = env.RUNFREE_TEST_HOST_PROCESS_START?.trim();
    if (override !== undefined && override !== "") {
      return PROCESS_START_RE.test(override) ? override : undefined;
    }
  }
  if (pid === process.pid && cachedOwnProcessStart !== undefined) return cachedOwnProcessStart;
  const value = process.platform === "linux"
    ? readLinuxProcessStart(pid)
    : process.platform === "darwin"
      ? readDarwinProcessStart(pid, env)
      : undefined;
  if (pid === process.pid && value !== undefined) cachedOwnProcessStart = value;
  return value;
}

export function compareHostProcessStart(
  recordedProcessStart: unknown,
  pid: number,
  env: NodeJS.ProcessEnv = process.env,
): "match" | "mismatch" | "unknown" {
  if (!validHostProcessStart(recordedProcessStart)) return "unknown";
  const current = hostProcessStart(pid, env);
  if (current === undefined) return "unknown";
  return recordedProcessStart.trim() === current ? "match" : "mismatch";
}

// True only when the recorded boot is known, the current boot is known, and
// they differ. Every other combination is "cannot prove" and returns false.
export function recordedOnPreviousBoot(
  recordedBootId: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  // Persisted identity is input, not fact, and the session-metadata caller
  // hands over a field of a `JSON.parse` result that `readSessionMetadata`
  // casts without validating: any JSON value can arrive here. A non-string must
  // read as "cannot prove" rather than throw, because the callers are
  // `runfree up`, `rebuild`, and `sessions` — an uncaught TypeError there turns
  // one corrupt record into a CLI that cannot start or inspect the runtime.
  if (typeof recordedBootId !== "string") return false;
  // Both lock callers skip the PID check entirely once this returns true, so a
  // truncated or corrupt stamp must read as "cannot prove" rather than as "some
  // other boot" — otherwise corrupt state deletes a live holder's lock, the one
  // outcome this module promises is impossible.
  const recorded = recordedBootId.trim();
  if (!BOOT_ID_RE.test(recorded)) return false;
  const current = hostBootId(env);
  if (current === undefined) return false;
  // Compared case-insensitively because `BOOT_ID_RE` accepts hex in either
  // case. Two spellings of the same UUID are the same boot, and reading them as
  // different boots is the one outcome this module promises is impossible — it
  // would delete a live holder's lock. Not reachable today (Linux emits
  // lowercase, `kern.bootsessionuuid` uppercase, and a machine has exactly one
  // source), but the failure is latent, silent, and in the dangerous direction,
  // so it is closed at the comparison rather than assumed away.
  return recorded.toLowerCase() !== current.toLowerCase();
}

export function compareHostBootId(
  recordedBootId: unknown,
  env: NodeJS.ProcessEnv = process.env,
): "match" | "mismatch" | "unknown" {
  if (typeof recordedBootId !== "string") return "unknown";
  const recorded = recordedBootId.trim();
  if (!BOOT_ID_RE.test(recorded)) return "unknown";
  const current = hostBootId(env);
  if (current === undefined) return "unknown";
  return recorded.toLowerCase() === current.toLowerCase() ? "match" : "mismatch";
}
