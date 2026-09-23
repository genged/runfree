import path from "node:path";

const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const MAX_LAUNCH_ARGUMENTS = 128;
const MAX_LAUNCH_ARGUMENT_BYTES = 16 * 1024;
const MAX_LAUNCH_TOTAL_BYTES = 64 * 1024;

declare const sessionLaunchTargetBrand: unique symbol;

export type SessionLaunchTarget = Readonly<{
  readonly [sessionLaunchTargetBrand]: true;
  version: 1;
  path: string;
  args: readonly string[];
  interactive: boolean;
  tty: boolean;
}>;

/**
 * The Runfree-owned entry program shipped in the base agent image
 * (`packages/agent-runtime/agent/session-entry.sh`).
 *
 * Every typed launch target minted for a per-session launch names this path
 * and carries the real agent launch as its argv, so the container's first
 * process waits for activation before the agent sends anything. The proof
 * pins `Path`/`Args` to the typed target exactly as before; only the target's
 * content changed.
 */
export const SESSION_ENTRY_PATH = "/usr/local/libexec/runfree/session-entry";

const validatedLaunchTargets = new WeakSet<object>();

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function isBoundedCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string"
    && value.startsWith("/")
    && path.posix.normalize(value) === value
    && !value.endsWith("/")
    && !CONTROL_CHARACTER_PATTERN.test(value)
    && utf8Bytes(value) <= 512;
}

export function createSessionLaunchTarget(input: {
  path: string;
  args: readonly string[];
  interactive: boolean;
  tty: boolean;
}): SessionLaunchTarget {
  if (!isBoundedCanonicalAbsolutePath(input.path)) {
    throw new Error("session launch path must be a bounded canonical absolute path");
  }
  if (!Array.isArray(input.args) || input.args.length > MAX_LAUNCH_ARGUMENTS) {
    throw new Error("session launch argument count is invalid");
  }
  let totalBytes = utf8Bytes(input.path);
  const args = input.args.map((argument) => {
    if (typeof argument !== "string"
      || CONTROL_CHARACTER_PATTERN.test(argument)
      || utf8Bytes(argument) > MAX_LAUNCH_ARGUMENT_BYTES) {
      throw new Error("session launch argument is invalid");
    }
    totalBytes += utf8Bytes(argument);
    return argument;
  });
  if (totalBytes > MAX_LAUNCH_TOTAL_BYTES) throw new Error("session launch argv is too large");
  // The entry execs `args[0]`, so a target that names the entry without a
  // bounded canonical absolute agent path would let the entry search PATH or
  // exec something it was never minted for. Refused here, at the one builder,
  // rather than in the entry script, which is cooperation and not proof.
  if (input.path === SESSION_ENTRY_PATH && !isBoundedCanonicalAbsolutePath(args[0])) {
    throw new Error("session entry launch requires a bounded canonical absolute agent path as its first argument");
  }
  if (typeof input.interactive !== "boolean" || typeof input.tty !== "boolean") {
    throw new Error("session launch terminal contract is invalid");
  }
  if (input.tty && !input.interactive) {
    throw new Error("session launch TTY requires an interactive stdin contract");
  }
  const target = Object.freeze({
    version: 1 as const,
    path: input.path,
    args: Object.freeze([...args]),
    interactive: input.interactive,
    tty: input.tty,
  }) as SessionLaunchTarget;
  validatedLaunchTargets.add(target);
  return target;
}

export function assertSessionLaunchTarget(value: unknown): asserts value is SessionLaunchTarget {
  if (value === null || typeof value !== "object" || !validatedLaunchTargets.has(value)) {
    throw new Error("session launch target was not minted by the canonical launch builder");
  }
}
