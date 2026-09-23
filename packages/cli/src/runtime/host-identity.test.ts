import { expect, test } from "vitest";

import {
  DARWIN_BOOT_PROBE_TIMEOUT_MS,
  DARWIN_PROCESS_PROBE_TIMEOUT_MS,
  compareHostProcessStart,
  hostBootId,
  hostProcessStart,
  recordedOnPreviousBoot,
} from "./host-identity.ts";
import { LOCK_PIDLESS_GRACE_MS } from "./sessions.ts";

const BOOT_A = "linux:11111111-2222-3333-4444-555555555555";
const BOOT_B = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
// One boot in two spellings. The UUID carries hex letters on purpose — a
// digits-only value is case-invariant and would make the comparison test
// vacuous. The `linux:` tag stays lowercase in both because the tag is minted
// by this module and is part of the exact accepted shape; only the UUID may
// legitimately arrive in either case.
const BOOT_MIXED_LOWER = "linux:abcdef01-beef-cafe-dead-0123456789ab";
const BOOT_MIXED_UPPER = `linux:${BOOT_MIXED_LOWER.slice("linux:".length).toUpperCase()}`;

// The boot id override is honored only under the fake-docker harness, so every
// test that pins an identity has to opt into it the same way production callers
// never do.
function harnessEnv(bootId: string): NodeJS.ProcessEnv {
  return { RUNFREE_TEST_FAKE_DOCKER: "1", RUNFREE_TEST_HOST_BOOT_ID: bootId };
}

function processHarnessEnv(processStart: string): NodeJS.ProcessEnv {
  return {
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: BOOT_A,
    RUNFREE_TEST_HOST_PROCESS_START: processStart,
  };
}

test("prefers the test boot id override under the harness", () => {
  expect(hostBootId(harnessEnv(BOOT_A))).toBe(BOOT_A);
});

test("ignores the boot id override outside the fake-docker harness", () => {
  // Identity must be a property of the machine, not of one process's
  // environment: if a stray override applied in production, two concurrent
  // commands would disagree about the current boot and each would delete the
  // other's live lock.
  expect(hostBootId({ RUNFREE_TEST_HOST_BOOT_ID: BOOT_A })).not.toBe(BOOT_A);
  expect(hostBootId({ RUNFREE_TEST_HOST_BOOT_ID: BOOT_A })).toBe(hostBootId({}));
});

test("rejects a malformed boot id override rather than trusting it", () => {
  expect(hostBootId(harnessEnv("boot id with spaces"))).toBeUndefined();
  expect(hostBootId(harnessEnv("x".repeat(200)))).toBeUndefined();
  // Right shape, unknown platform tag: two platforms must never compare equal.
  expect(hostBootId(harnessEnv("plan9:11111111-2222-3333-4444-555555555555"))).toBeUndefined();
});

test("reports a differing boot as a previous boot", () => {
  expect(recordedOnPreviousBoot(BOOT_A, harnessEnv(BOOT_B))).toBe(true);
  // Trailing whitespace survives a round trip through the lock/metadata files.
  expect(recordedOnPreviousBoot(`${BOOT_A}\n`, harnessEnv(BOOT_A))).toBe(false);
  // The `false` above alone cannot distinguish "trimmed and matched" from
  // "rejected as malformed" — both answer false — so it does not actually pin
  // the trim. This does: the same stored-with-newline value must still be
  // *recognized* well enough to be called a previous boot against a different
  // current boot. Drop the trim and this returns false.
  expect(recordedOnPreviousBoot(`${BOOT_A}\n`, harnessEnv(BOOT_B))).toBe(true);
  expect(recordedOnPreviousBoot(`  ${BOOT_A}  `, harnessEnv(BOOT_B))).toBe(true);
});

test("treats two case spellings of one uuid as the same boot", () => {
  // `BOOT_ID_RE` accepts hex in either case, so an exact `!==` would read the
  // same boot as two boots and delete a live holder's lock — the one outcome
  // this module promises is impossible. Only the hex varies here: the platform
  // tag is minted lowercase and stays part of the exact shape, so uppercasing
  // it would be rejected as malformed and prove nothing about the comparison.
  expect(BOOT_MIXED_UPPER).not.toBe(BOOT_MIXED_LOWER);
  expect(recordedOnPreviousBoot(BOOT_MIXED_UPPER, harnessEnv(BOOT_MIXED_LOWER))).toBe(false);
  expect(recordedOnPreviousBoot(BOOT_MIXED_LOWER, harnessEnv(BOOT_MIXED_UPPER))).toBe(false);
  // Case folding must not erase a real difference.
  expect(recordedOnPreviousBoot(BOOT_MIXED_UPPER, harnessEnv(BOOT_B))).toBe(true);
});

test("bounds the darwin boot probe well inside the lock acquisition grace", () => {
  // The probe spawns a process. Callers resolve boot identity before creating
  // their lock directory so it can never run inside the pid-less window, but if
  // that ordering ever regresses, a probe allowed to run as long as the grace
  // turns a contended steal from a race into a certainty. Keep real headroom,
  // not equality.
  expect(DARWIN_BOOT_PROBE_TIMEOUT_MS).toBeLessThan(LOCK_PIDLESS_GRACE_MS / 4);
  expect(DARWIN_PROCESS_PROBE_TIMEOUT_MS).toBeLessThan(LOCK_PIDLESS_GRACE_MS / 4);
});

test("compares a tagged host process start only when both sides are provable", () => {
  expect(hostProcessStart(process.pid, processHarnessEnv("linux:12345"))).toBe("linux:12345");
  expect(compareHostProcessStart("linux:12345", process.pid, processHarnessEnv("linux:12345"))).toBe("match");
  expect(compareHostProcessStart("linux:54321", process.pid, processHarnessEnv("linux:12345"))).toBe("mismatch");
  expect(compareHostProcessStart("corrupt", process.pid, processHarnessEnv("linux:12345"))).toBe("unknown");
  expect(hostProcessStart(process.pid, processHarnessEnv("linux:not-a-number"))).toBeUndefined();
});

test("never claims a previous boot when either side is unknown", () => {
  // Unprovable identity must fall back to the caller's PID-only behavior, so a
  // live holder's lock is never deleted on an unsupported platform.
  expect(recordedOnPreviousBoot(undefined, harnessEnv(BOOT_B))).toBe(false);
  expect(recordedOnPreviousBoot("", harnessEnv(BOOT_B))).toBe(false);
  expect(recordedOnPreviousBoot(BOOT_A, harnessEnv("not a valid id"))).toBe(false);
});

test("treats a corrupt recorded stamp as unprovable, not as another boot", () => {
  // A stamp that survived a torn write or filesystem corruption compares
  // unequal to the current boot but proves nothing. Callers skip the PID check
  // once this returns true, so answering "previous boot" here would delete a
  // lock whose owner is still running.
  const corrupt = ["linux:11111111", "linux:", "11111111-2222-3333-4444-555555555555", "linux:zzzzzzzz-2222-3333-4444-555555555555"];
  for (const recorded of corrupt) {
    expect(recordedOnPreviousBoot(recorded, harnessEnv(BOOT_B))).toBe(false);
  }
});

test("treats a non-string recorded stamp as unprovable instead of throwing", () => {
  // `readSessionMetadata` JSON.parses a host state file and casts it without
  // validating this field, so any JSON value reaches here. The callers are
  // `runfree up`, `rebuild`, and `sessions`, none of which catch: a throw would
  // turn one corrupt session record into a CLI that cannot start or inspect the
  // runtime. Rejection has to happen before `.trim()`, not after.
  const nonStrings: unknown[] = [123, true, null, { bootId: BOOT_A }, [BOOT_A]];
  for (const recorded of nonStrings) {
    expect(recordedOnPreviousBoot(recorded as string | undefined, harnessEnv(BOOT_B))).toBe(false);
  }
});

test.runIf(process.platform === "linux")("reads a stable tagged boot id on linux", () => {
  const first = hostBootId({});
  expect(first).toMatch(/^linux:[0-9a-f-]+$/);
  expect(hostBootId({})).toBe(first);
});

test.runIf(process.platform === "linux")("reads a stable tagged process start on linux", () => {
  const first = hostProcessStart(process.pid, {});
  expect(first).toMatch(/^linux:[0-9]+$/);
  expect(hostProcessStart(process.pid, {})).toBe(first);
});

// The boot session UUID is immutable for the boot. `kern.boottime`, which this
// once used, is rewritten whenever the calendar clock is stepped, so a routine
// NTP correction would have made a live lock look like a previous boot's.
test.runIf(process.platform === "darwin")("reads an immutable tagged boot id on darwin", () => {
  const first = hostBootId({});
  expect(first).toMatch(/^darwin:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/);
  expect(hostBootId({})).toBe(first);
});
