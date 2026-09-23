import { describe, expect, test } from "vitest";

import {
  classifySessionRecordLiveness,
  sessionRecordLiveUnderSessionFiles,
  sessionRecordOwnerLiveness,
} from "./session-record-liveness.ts";
import type { SessionHostStatusV1 } from "./session-host-status.ts";
import { sessionContainerRecordFixture } from "./session-container.test-harness.ts";
import {
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

const BOOT_THIS = "linux:11111111-2222-3333-4444-555555555555";
const BOOT_PREVIOUS = "linux:66666666-7777-8888-9999-aaaaaaaaaaaa";
const PROCESS_THIS = "linux:12345";
const PROCESS_OTHER = "linux:67890";

const NOW_MS = Date.parse("2026-08-14T12:00:00.000Z");

// A PID that cannot be running: above the platform maximum on both supported
// hosts, so `processAlive` answers from the kernel rather than from a guess
// about what happens to be running on the machine executing the suite.
const DEAD_PID = 4_194_305;

// Boot identity is a property of the machine, so the overrides that pin it are
// honored only under the fake-docker harness. See `hostBootId`.
function harnessEnv(bootId: string, processStart?: string): NodeJS.ProcessEnv {
  return {
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: bootId,
    ...(processStart ? { RUNFREE_TEST_HOST_PROCESS_START: processStart } : {}),
  };
}

const LEASE = Object.freeze({
  admittedAt: "2026-08-14T11:55:00.000Z",
  leaseGeneration: "e".repeat(32),
  leaseExpiresAt: "2026-08-14T12:05:00.000Z",
});

// Records are walked through the real transitions rather than shaped by hand,
// so every case is a state the lifecycle can actually produce. Host identity is
// immutable across transitions, so it is set once at allocation.
function attachedRecord(overrides: Partial<SessionContainerRecordV2> = {}): SessionContainerRecordV2 {
  const allocated = sessionContainerRecordFixture({
    containerId: "3".repeat(64),
    overrides: { hostPid: process.pid, hostBootId: BOOT_THIS, hostProcessStart: PROCESS_THIS },
  });
  const attached = transitionProvisioningRunningSessionContainerToAttachedV2(
    transitionBoundAllocatedSessionContainerToProvisioningRunningV2(allocated, LEASE),
  );
  // Overrides land after the transitions, not before: the fixture binds the
  // container while the record is still allocated, so a lease or a later state
  // passed through it cannot bind one — and a defaulted field would swallow a
  // case that deliberately states `undefined`.
  return { ...attached, ...overrides };
}

const record = attachedRecord;

describe("session record ownership", () => {
  test("reads a running owner as alive and a departed one as dead", () => {
    expect(sessionRecordOwnerLiveness(record(), harnessEnv(BOOT_THIS, PROCESS_THIS))).toBe("alive");
    expect(sessionRecordOwnerLiveness(record({ hostPid: DEAD_PID }), harnessEnv(BOOT_THIS, PROCESS_THIS)))
      .toBe("dead");
  });

  test("settles a previous boot without consulting the PID", () => {
    // The PID is this live process, so anything that asked the PID first would
    // answer "alive" — for a record written before a reboot, whose owner
    // provably did not survive it.
    expect(sessionRecordOwnerLiveness(
      record({ hostBootId: BOOT_PREVIOUS }),
      harnessEnv(BOOT_THIS, PROCESS_THIS),
    )).toBe("dead");
  });

  test("rejects a recycled PID within the same boot", () => {
    expect(sessionRecordOwnerLiveness(
      record({ hostProcessStart: PROCESS_OTHER }),
      harnessEnv(BOOT_THIS, PROCESS_THIS),
    )).toBe("dead");
  });

  test("treats a live PID with nothing corroborating it as unknown, not alive", () => {
    // A PID alone is a coincidence away from being an unrelated process. This
    // is also the shape on a host that cannot report process starts, where it
    // is the only evidence available.
    expect(sessionRecordOwnerLiveness(
      record({ hostProcessStart: undefined }),
      harnessEnv(BOOT_THIS, PROCESS_THIS),
    )).toBe("unknown");
    expect(sessionRecordOwnerLiveness(
      record({ hostBootId: undefined }),
      harnessEnv(BOOT_THIS, PROCESS_THIS),
    )).toBe("unknown");
  });

  test("answers unknown rather than signalling a process group", () => {
    // `process.kill(0, 0)` signals the caller's own group and `kill(-1)` every
    // permitted process, so a PID that is not positive must never reach the
    // liveness probe. `parseSessionContainerRecordV2` rejects these upstream,
    // so this is a guard on the probe rather than a record shape to expect.
    for (const hostPid of [0, -1, 1.5]) {
      expect(sessionRecordOwnerLiveness(
        { ...record(), hostPid },
        harnessEnv(BOOT_THIS, PROCESS_THIS),
      )).toBe("unknown");
    }
  });
});

describe("session record liveness", () => {
  test("keeps a record whose owner is running, however little lease remains", () => {
    // Concurrent sessions are the point of per-session admission: another
    // session's record is not residue, and an expired lease under a live owner
    // is a renewal that has not landed yet, not an abandonment.
    expect(classifySessionRecordLiveness(record({
      leaseExpiresAt: new Date(NOW_MS - 60_000).toISOString(),
    }), { nowEpochMs: NOW_MS, env: harnessEnv(BOOT_THIS, PROCESS_THIS) })).toMatchObject({ kind: "live" });
  });

  test("reclaims a killed client's record immediately, without waiting out its lease", () => {
    // The case that wedges the registry today: a client killed while attached
    // leaves a record with a long lease still to run. Waiting for that lease to
    // lapse would leave the project unable to admit a session for the whole
    // window, which is the failure being fixed.
    const liveness = classifySessionRecordLiveness(record({
      state: "attached",
      hostPid: DEAD_PID,
      leaseExpiresAt: new Date(NOW_MS + 5 * 60_000).toISOString(),
    }), { nowEpochMs: NOW_MS, env: harnessEnv(BOOT_THIS, PROCESS_THIS) });

    expect(liveness.kind).toBe("stale");
    expect(liveness.reason).toContain("owning host process is gone");
  });

  test("keeps an unprovable owner even when the frozen lease expires", () => {
    // An uncorroborated PID may still own a live session. The frozen
    // admission lease cannot prove that it stopped.
    const unprovable = { hostProcessStart: undefined } satisfies Partial<SessionContainerRecordV2>;
    const options = { nowEpochMs: NOW_MS, env: harnessEnv(BOOT_THIS, PROCESS_THIS) };

    expect(classifySessionRecordLiveness(record({
      ...unprovable,
      leaseExpiresAt: new Date(NOW_MS - 1).toISOString(),
    }), options)).toMatchObject({ kind: "live" });
    expect(classifySessionRecordLiveness(record({
      ...unprovable,
      leaseExpiresAt: new Date(NOW_MS + 1).toISOString(),
    }), options)).toMatchObject({ kind: "live" });
  });

  test("holds an unprovable record with no usable lease rather than inventing staleness", () => {
    // An allocated record has no lease yet and may be seconds old; its own
    // unbound-created rule covers the case that matters. An unparseable lease
    // is the same unknown and must not read as expiry.
    const options = { nowEpochMs: NOW_MS, env: harnessEnv(BOOT_THIS, PROCESS_THIS) };
    for (const leaseExpiresAt of [undefined, "not-a-timestamp"]) {
      expect(classifySessionRecordLiveness(
        record({ hostProcessStart: undefined, leaseExpiresAt }),
        options,
      )).toMatchObject({ kind: "live" });
    }
  });
});

describe("session record liveness with a host status stamp", () => {
  const options = { nowEpochMs: NOW_MS, env: harnessEnv(BOOT_THIS, PROCESS_THIS) };

  function stamp(aliveUntilMs: number, overrides: Partial<SessionHostStatusV1> = {}): SessionHostStatusV1 {
    return {
      v: 1,
      sessionId: record().sessionId,
      lastHeartbeatAt: new Date(aliveUntilMs - 60_000).toISOString(),
      aliveUntil: new Date(aliveUntilMs).toISOString(),
      served: "served",
      ...overrides,
    };
  }

  test("prefers a live stamp over a frozen admission lease", () => {
    // Under the session-file design the durable record's lease freezes at
    // admission, so a session heartbeating right now carries a long-expired
    // `leaseExpiresAt`. The stamp is what the heartbeat renews.
    const liveness = classifySessionRecordLiveness(
      record({ hostProcessStart: undefined, leaseExpiresAt: new Date(NOW_MS - 60 * 60_000).toISOString() }),
      { ...options, stamp: stamp(NOW_MS + 30_000) },
    );
    expect(liveness.kind).toBe("live");
  });

  test("keeps an unprovable owner when advisory stamp writes stopped", () => {
    const liveness = classifySessionRecordLiveness(
      record({ hostProcessStart: undefined, leaseExpiresAt: new Date(NOW_MS + 60 * 60_000).toISOString() }),
      { ...options, stamp: stamp(NOW_MS - 1) },
    );
    expect(liveness.kind).toBe("live");
  });

  test("keeps ownership ahead of the stamp in both directions", () => {
    // A stamp cannot override owner-death evidence: a dead owner's last stamp must not resurrect it, and a
    // running owner is live before any stamp is consulted.
    expect(classifySessionRecordLiveness(
      record({ hostPid: DEAD_PID }),
      { ...options, stamp: stamp(NOW_MS + 30_000) },
    )).toMatchObject({ kind: "stale" });
    expect(classifySessionRecordLiveness(
      record(),
      { ...options, stamp: stamp(NOW_MS - 60_000) },
    )).toMatchObject({ kind: "live" });
  });

  test("preserves an unknown owner even when the record carries no lease", () => {
    expect(classifySessionRecordLiveness(
      record({ hostProcessStart: undefined, leaseExpiresAt: undefined }),
      { ...options, stamp: stamp(NOW_MS - 1) },
    )).toMatchObject({ kind: "live" });
    expect(classifySessionRecordLiveness(
      record({ hostProcessStart: undefined, leaseExpiresAt: undefined }),
      { ...options, stamp: stamp(NOW_MS + 1) },
    )).toMatchObject({ kind: "live" });
  });
});

// Runtime changes protect an uncertain owner until positive death evidence
// permits reclamation. Advisory status never grants proxy authority.
describe("record liveness under the session-file source", () => {
  const stamp = (aliveUntilMs: number): SessionHostStatusV1 => ({
    v: 1,
    sessionId: record().sessionId,
    lastHeartbeatAt: new Date(aliveUntilMs - 60_000).toISOString(),
    aliveUntil: new Date(aliveUntilMs).toISOString(),
    served: "served",
  });
  const files = (
    record: SessionContainerRecordV2,
    options: { env?: NodeJS.ProcessEnv; stamp?: SessionHostStatusV1 } = {},
  ): boolean => sessionRecordLiveUnderSessionFiles(record, { nowEpochMs: NOW_MS, ...options });

  test("a running owner is live whatever its stamp and its frozen lease say", () => {
    const env = harnessEnv(BOOT_THIS, PROCESS_THIS);
    expect(files(record({ leaseExpiresAt: "2026-08-14T11:00:00.000Z" }), { env })).toBe(true);
    expect(files(record(), { env, stamp: stamp(NOW_MS - 60_000) })).toBe(true);
  });

  test("an unprovable owner blocks destructive runtime changes even without a fresh stamp", () => {
    const env = harnessEnv(BOOT_PREVIOUS);
    const unprovable = record({ hostBootId: undefined, hostProcessStart: undefined });
    expect(files(unprovable, { env, stamp: stamp(NOW_MS + 30_000) })).toBe(true);
    expect(files(unprovable, { env, stamp: stamp(NOW_MS) })).toBe(true);
    // Missing status is not evidence of owner death either.
    expect(files(unprovable, { env })).toBe(true);
  });

  test("a departed owner is not live, however recent its last stamp", () => {
    expect(files(
      record({ hostPid: DEAD_PID }),
      { env: harnessEnv(BOOT_THIS, PROCESS_THIS), stamp: stamp(NOW_MS + 30_000) },
    )).toBe(false);
  });
});
