import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  serializeSessionFileV1,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";
import { afterEach, expect, test, vi } from "vitest";

import { SessionFileRegistry } from "./session-file-registry.ts";

// Toggled by the "throwing scan" test below to exercise `refresh()`'s
// fail-closed wrapping around `scanSessionFiles` without a real I/O fault.
const scanControl = vi.hoisted(() => ({ throwOnScan: false }));

vi.mock("./session-files.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./session-files.ts")>();
  return {
    ...actual,
    scanSessionFiles: (...args: Parameters<typeof actual.scanSessionFiles>) => {
      if (scanControl.throwOnScan) throw new Error("boom");
      return actual.scanSessionFiles(...args);
    },
  };
});

const PROJECT_ID = "abcdef012345";
const NETWORK_ID = "e".repeat(64);
const IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const AGENT_DIGEST = `sha256:${"b".repeat(64)}`;
const CONTROL_DIGEST = `sha256:${"d".repeat(64)}`;
const EPOCH = 3;
const OWNER_UID = process.getuid?.() ?? 0;

const KEY_A = "1".repeat(64);
const KEY_B = "7".repeat(64);
const IP_A = "172.30.194.20";
const IP_B = "172.30.194.21";
const T0 = Date.parse("2026-09-07T07:00:00.000Z");
const MINUTE = 60_000;

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  scanControl.throwOnScan = false;
  vi.restoreAllMocks();
});

function makeRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-file-registry-"));
  roots.push(root);
  fs.chmodSync(root, 0o755);
  fs.mkdirSync(path.join(root, "sessions"), { recursive: true, mode: 0o755 });
  writeEligibility(root);
  return root;
}

function writeEligibility(root: string): void {
  const eligibility = createSessionAdmissionEligibility({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: CONTROL_DIGEST,
    admissionContractEpoch: EPOCH,
    agentInternalNetworkId: NETWORK_ID,
    allowedSessionAgents: [{ selectedAgentImageId: IMAGE_DIGEST, sessionAgentGenerationDigest: AGENT_DIGEST }],
  });
  fs.writeFileSync(path.join(root, "eligibility.json"), serializeSessionAdmissionEligibility(eligibility), {
    mode: 0o644,
  });
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

type FileOverrides = Partial<SessionFileV1> & { inspectedAtMs?: number; aliveForMs?: number };

function makeFile(overrides: FileOverrides = {}): SessionFileV1 {
  const { inspectedAtMs, aliveForMs, ...rest } = overrides;
  const inspectedAt = inspectedAtMs ?? T0;
  return {
    v: 1,
    projectId: PROJECT_ID,
    sessionKey: KEY_A,
    sessionId: "rf-20260907-abc123",
    sessionIncarnation: "2".repeat(64),
    sourceIp: IP_A,
    containerId: "c".repeat(64),
    networkId: NETWORK_ID,
    selectedAgentImageId: IMAGE_DIGEST,
    sessionAgentGenerationDigest: AGENT_DIGEST,
    controlPlaneGenerationDigest: CONTROL_DIGEST,
    admissionContractEpoch: EPOCH,
    name: "claude",
    command: "claude",
    startedAt: "2026-09-07T06:59:00.000Z",
    nonce: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    inspectedAt: iso(inspectedAt),
    aliveUntil: iso(inspectedAt + (aliveForMs ?? MINUTE)),
    ...rest,
  };
}

function writeFile(root: string, file: SessionFileV1): void {
  fs.writeFileSync(path.join(root, "sessions", `${file.sessionKey}.json`), serializeSessionFileV1(file), {
    mode: 0o644,
  });
}

function removeFile(root: string, sessionKey: string): void {
  fs.rmSync(path.join(root, "sessions", `${sessionKey}.json`), { force: true });
}

test("an IP reuse fence clears old authority while preserving other sessions", () => {
  const { root, registry, invalidations } = harness();
  writeFile(root, makeFile());
  writeFile(root, makeFile({ sessionKey: KEY_B, sourceIp: IP_B }));
  registry.refresh();
  expect(registry.lookup(IP_A).kind).toBe("active");
  registry.refresh(new Set([IP_A]));
  expect(registry.lookup(IP_A).kind).toBe("rejected");
  expect(registry.lookup(IP_B).kind).toBe("active");
  expect(invalidations).toEqual([[KEY_A, "removed"]]);
});

test("a delayed old file cannot reclaim a reassigned IP or deny its new owner", () => {
  const { root, registry, invalidations } = harness();
  writeFile(root, makeFile());
  registry.refresh();
  writeFile(root, makeFile({ sessionKey: KEY_B }));
  const assignments = new Map([[IP_A, {
    v: 1 as const, sourceIp: IP_A, sessionKey: KEY_B, nonce: "b".repeat(32), state: "ready" as const,
  }]]);
  registry.refresh(new Set(), assignments);
  expect(registry.lookup(IP_A)).toMatchObject({ kind: "active", session: { sessionKey: KEY_B } });
  expect(invalidations).toEqual([[KEY_A, "removed"]]);
});

type Harness = {
  root: string;
  registry: SessionFileRegistry;
  invalidations: Array<[string, string]>;
  advance: (wallMs: number, monotonicMs: number) => void;
};

function harness(options: { leaseMaxMs?: number } = {}): Harness {
  const root = makeRoot();
  const clocks = { now: T0, monotonic: 10_000 };
  const invalidations: Array<[string, string]> = [];
  const registry = new SessionFileRegistry({
    root,
    projectId: PROJECT_ID,
    ownerUid: OWNER_UID,
    ...(options.leaseMaxMs !== undefined ? { leaseMaxMs: options.leaseMaxMs } : {}),
    now: () => clocks.now,
    monotonicNowMs: () => clocks.monotonic,
    onSessionInvalidated: (sessionKey, reason) => invalidations.push([sessionKey, reason]),
  });
  return {
    root,
    registry,
    invalidations,
    advance: (wallMs, monotonicMs) => {
      clocks.now += wallMs;
      clocks.monotonic += monotonicMs;
    },
  };
}

test("file present ⇒ served; aliveUntil passed on the wall clock ⇒ expired invalidation", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile());

  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(Array.from(registry.servedAddresses())).toEqual([IP_A]);
  const lookup = registry.lookup(IP_A);
  expect(lookup.kind).toBe("active");
  if (lookup.kind !== "active") throw new Error("unreachable");
  expect(lookup.file.sessionKey).toBe(KEY_A);
  expect(lookup.file.sourceIp).toBe(IP_A);
  expect(lookup.session).toEqual({
    kind: "session",
    sessionKey: KEY_A,
    authenticated: true,
    sessionId: "rf-20260907-abc123",
    name: "claude",
    command: "claude",
    startedAt: "2026-09-07T06:59:00.000Z",
  });
  expect(invalidations).toEqual([]);

  // Wall clock passes aliveUntil while the monotonic bound still has room.
  advance(MINUTE + 1_000, 1_000);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(invalidations).toEqual([[KEY_A, "expired"]]);
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "expired" });
  expect(Array.from(registry.servedAddresses())).toEqual([]);
});

test("same nonce rewritten with a later aliveUntil cannot extend the monotonic bound", () => {
  const { root, registry, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // The monotonic clock passes the first observation's bound while the wall
  // clock lags; the same nonce is rewritten with a much later aliveUntil.
  advance(1_000, MINUTE + 1_000);
  writeFile(root, makeFile({ inspectedAtMs: T0 + 1_000, aliveForMs: 5 * MINUTE }));

  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "expired" });
});

test("same nonce, later aliveUntil ⇒ wall bound unchanged", () => {
  const { root, registry, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // The wall clock passes the FIRST observed aliveUntil while the monotonic
  // bound still has room; the same nonce claims a later aliveUntil. The wall
  // term is min(first observed, current), so the replay cannot extend it.
  advance(MINUTE + 30_000, 30_000);
  writeFile(root, makeFile({ inspectedAtMs: T0 + MINUTE + 30_000, aliveForMs: 5 * MINUTE }));

  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "expired" });
});

test("a new nonce with an OLDER inspectedAt is a fresh observation and is served", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile({ inspectedAtMs: T0, aliveForMs: MINUTE }));
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // Host clock stepped backward: the rewrite carries an older inspectedAt but
  // a fresh nonce, so it is a new observation, not a replay.
  advance(1_000, 1_000);
  writeFile(root, makeFile({
    nonce: "f".repeat(32),
    inspectedAtMs: T0 - 30_000,
    aliveForMs: 5 * MINUTE,
  }));

  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(registry.lookup(IP_A).kind).toBe("active");
  // The previous observation had not elapsed on either clock and the stable
  // identity is unchanged, so no context is dropped.
  expect(invalidations).toEqual([]);
});

test("previous nonce expired on either clock, new nonce lands in the same refresh ⇒ expired emitted, then served", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // Only the monotonic clock elapsed (the wall clock still says alive), and a
  // brand new nonce appears in the same refresh gap.
  advance(1_000, MINUTE + 1_000);
  writeFile(root, makeFile({ nonce: "9".repeat(32), inspectedAtMs: T0 + 1_000, aliveForMs: 5 * MINUTE }));

  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(invalidations).toEqual([[KEY_A, "expired"]]);
  expect(registry.lookup(IP_A).kind).toBe("active");
});

test("previous nonce expired on the wall clock, new nonce lands in the same refresh ⇒ expired emitted, then served", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // The other half of "either clock": the previous observation's aliveUntil
  // has passed on the wall clock while its monotonic bound still has room.
  advance(MINUTE + 1_000, 1_000);
  writeFile(root, makeFile({ nonce: "8".repeat(32), inspectedAtMs: T0 + MINUTE + 1_000 }));

  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(invalidations).toEqual([[KEY_A, "expired"]]);
  expect(registry.lookup(IP_A).kind).toBe("active");
});

test("monotonic elapsed beyond min(aliveUntil−now, lease max) ⇒ not served even if the wall clock lags", () => {
  const { root, registry, advance } = harness({ leaseMaxMs: 10_000 });
  writeFile(root, makeFile({ aliveForMs: 5 * MINUTE }));
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // aliveUntil is five minutes out on the wall clock, but the observed bound
  // is capped at the lease maximum.
  advance(1_000, 11_000);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "expired" });
});

test("removal ⇒ 'removed'; rewrite with the same identity preserves; rewrite with a different containerId ⇒ 'replaced'", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // Heartbeat rewrite: new nonce, same stable identity ⇒ nothing is dropped.
  advance(1_000, 1_000);
  writeFile(root, makeFile({ nonce: "b".repeat(32), inspectedAtMs: T0 + 1_000 }));
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(invalidations).toEqual([]);

  // Different container behind the same address ⇒ replaced.
  advance(1_000, 1_000);
  writeFile(root, makeFile({
    nonce: "c".repeat(32),
    containerId: "d".repeat(64),
    inspectedAtMs: T0 + 2_000,
  }));
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(invalidations).toEqual([[KEY_A, "replaced"]]);

  // File deleted ⇒ removed.
  advance(1_000, 1_000);
  removeFile(root, KEY_A);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(invalidations).toEqual([[KEY_A, "replaced"], [KEY_A, "removed"]]);
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "missing" });
});

test("unreadable directory ⇒ every previously served key is invalidated 'removed' and lookup rejects registry-unavailable", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile());
  writeFile(root, makeFile({ sessionKey: KEY_B, sourceIp: IP_B, sessionId: "rf-20260907-bbb222" }));
  expect(registry.refresh()).toEqual({ kind: "ok", served: 2 });

  advance(1_000, 1_000);
  fs.rmSync(path.join(root, "eligibility.json"));
  expect(registry.refresh()).toEqual({ kind: "unreadable" });
  expect(invalidations.map(([key]) => key).sort()).toEqual([KEY_A, KEY_B].sort());
  expect(invalidations.every(([, reason]) => reason === "removed")).toBe(true);
  expect(Array.from(registry.servedAddresses())).toEqual([]);
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "registry-unavailable" });
  expect(registry.lookup(IP_B)).toEqual({ kind: "rejected", reason: "registry-unavailable" });

  // Reclamation: the wedge clears as soon as the state is readable again.
  advance(1_000, 1_000);
  writeEligibility(root);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 2 });
  expect(registry.lookup(IP_A).kind).toBe("active");
});

test("a scan that throws ⇒ every previously served key is invalidated 'removed' and lookup rejects registry-unavailable", () => {
  const { root, registry, invalidations, advance } = harness();
  writeFile(root, makeFile());
  writeFile(root, makeFile({ sessionKey: KEY_B, sourceIp: IP_B, sessionId: "rf-20260907-bbb222" }));
  expect(registry.refresh()).toEqual({ kind: "ok", served: 2 });

  advance(1_000, 1_000);
  scanControl.throwOnScan = true;
  expect(registry.refresh()).toEqual({ kind: "unreadable" });
  expect(invalidations.map(([key]) => key).sort()).toEqual([KEY_A, KEY_B].sort());
  expect(invalidations.every(([, reason]) => reason === "removed")).toBe(true);
  expect(Array.from(registry.servedAddresses())).toEqual([]);
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "registry-unavailable" });
  expect(registry.lookup(IP_B)).toEqual({ kind: "rejected", reason: "registry-unavailable" });

  // Reclamation: the wedge clears as soon as the scan stops throwing.
  advance(1_000, 1_000);
  scanControl.throwOnScan = false;
  expect(registry.refresh()).toEqual({ kind: "ok", served: 2 });
  expect(registry.lookup(IP_A).kind).toBe("active");
});

test("an unreadable scan keeps observations: the monotonic bound continues instead of restarting", () => {
  const { root, registry, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  advance(1_000, 30_000);
  fs.rmSync(path.join(root, "eligibility.json"));
  expect(registry.refresh()).toEqual({ kind: "unreadable" });

  // Readable again with the same bytes. The wall clock still says alive, so
  // the only thing that can withhold the file is the original observation's
  // monotonic bound — which kept running across the unreadable window rather
  // than restarting from a fresh observation.
  advance(1_000, 31_000);
  writeEligibility(root);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "expired" });
});

// Invariant 2's edge: a file the scanner DROPS is not a file that left the
// directory. Between the two refreshes below the file never moves; only the
// eligibility it is judged against does, exactly as it does mid-rebind. If
// pruning keyed on the served set, the second refresh would start a brand new
// observation for the unchanged nonce and hand it a full fresh monotonic
// window.
test("a file dropped as ineligible and eligible again under one nonce keeps its original monotonic bound", () => {
  const { root, registry, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  // Ineligible for one pass: the file is untouched, the eligibility names a
  // different control plane generation digest.
  advance(1_000, 30_000);
  fs.writeFileSync(
    path.join(root, "eligibility.json"),
    serializeSessionAdmissionEligibility(createSessionAdmissionEligibility({
      projectId: PROJECT_ID,
      controlPlaneGenerationDigest: `sha256:${"9".repeat(64)}`,
      admissionContractEpoch: EPOCH,
      agentInternalNetworkId: NETWORK_ID,
      allowedSessionAgents: [{ selectedAgentImageId: IMAGE_DIGEST, sessionAgentGenerationDigest: AGENT_DIGEST }],
    })),
    { mode: 0o644 },
  );
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });

  // Eligible again, same bytes and same nonce. The wall clock still says
  // alive, so the only thing that can withhold it is the FIRST observation's
  // monotonic bound — which must have kept running across the ineligible pass.
  advance(1_000, 31_000);
  writeEligibility(root);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "expired" });
});

// The other half: a file that really did leave the directory must still be
// pruned, so its key starts fresh when a new session writes it again.
test("a file removed from the directory prunes its observation", () => {
  const { root, registry, advance } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  advance(1_000, 30_000);
  removeFile(root, KEY_A);
  expect(registry.refresh()).toEqual({ kind: "ok", served: 0 });

  // Past the first observation's monotonic bound, the same bytes reappear.
  // Because the observation was pruned this is a first observation, not a
  // replay, and it is served.
  advance(1_000, 31_000);
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(registry.lookup(IP_A).kind).toBe("active");
});

test("lookup rejects before the first refresh and rejects an address that is not an exact session IPv4", () => {
  const { root, registry } = harness();
  writeFile(root, makeFile());
  expect(registry.lookup(IP_A)).toEqual({ kind: "rejected", reason: "registry-unavailable" });
  expect(registry.lookup(undefined)).toEqual({ kind: "rejected", reason: "invalid" });
  expect(registry.lookup("172.30.194.020")).toEqual({ kind: "rejected", reason: "invalid" });
});

test("lookup does not touch the filesystem between refreshes", () => {
  const { root, registry } = harness();
  writeFile(root, makeFile());
  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });

  const readdir = vi.spyOn(fs, "readdirSync");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    expect(registry.lookup(IP_A).kind).toBe("active");
    expect(Array.from(registry.servedAddresses())).toEqual([IP_A]);
  }
  expect(readdir).not.toHaveBeenCalled();

  expect(registry.refresh()).toEqual({ kind: "ok", served: 1 });
  expect(readdir).toHaveBeenCalled();
});
