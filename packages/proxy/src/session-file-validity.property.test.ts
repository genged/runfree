import { createSessionAdmissionEligibility } from "@runfree/runtime-contracts/session-admission";
import { type SessionFileV1 } from "@runfree/runtime-contracts/session-file";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import { type SessionFileScan } from "./session-files.ts";
import { servedSessionFiles, type SessionFileObservation } from "./session-file-validity.ts";

// Model-based test of the dual-clock validity rule. The model keeps the
// environment (files on disk, both clocks) and, per session key, the FIRST
// observation of the nonce on disk. The invariants checked after every scan
// are the module's own comments:
//
//   "A replay of the same nonce with a later wall deadline extends neither the
//    wall term nor the first observed monotonic bound."
//   "An unreadable scan serves nothing and prunes nothing."
//   Each served file is within both clocks' bounds.

const T0 = Date.parse("2026-09-07T07:00:00.000Z");
const MONO0 = 10_000;
const LEASE_MAX_MS = 60_000;
const KEYS = ["1".repeat(64), "7".repeat(64), "c".repeat(64)] as const;

const ELIGIBILITY = createSessionAdmissionEligibility({
  projectId: "abcdef012345",
  controlPlaneGenerationDigest: `sha256:${"d".repeat(64)}`,
  admissionContractEpoch: 3,
  agentInternalNetworkId: "e".repeat(64),
  allowedSessionAgents: [{ selectedAgentImageId: `sha256:${"a".repeat(64)}`, sessionAgentGenerationDigest: `sha256:${"b".repeat(64)}` }],
});

type DiskFile = { nonce: string; aliveUntilMs: number };
type FirstObservation = { nonce: string; deadlineMs: number; monoOriginMs: number; durationMs: number };

type Model = {
  wallMs: number;
  monoMs: number;
  nonceSerial: number;
  disk: Map<string, DiskFile>;
  // Every file ever written per key, so an old file can be put back verbatim.
  history: Map<string, DiskFile[]>;
  firstObservations: Map<string, FirstObservation>;
};
type Real = { observations: Map<string, SessionFileObservation> };

function initialModel(): Model {
  return {
    wallMs: T0,
    monoMs: MONO0,
    nonceSerial: 0,
    disk: new Map(),
    history: new Map(),
    firstObservations: new Map(),
  };
}

function sessionFile(sessionKey: string, file: DiskFile): SessionFileV1 {
  return {
    v: 1,
    projectId: "abcdef012345",
    sessionKey,
    sessionId: "rf-20260907-abc123",
    sessionIncarnation: "2".repeat(64),
    sourceIp: `172.30.194.${KEYS.indexOf(sessionKey as (typeof KEYS)[number]) + 20}`,
    containerId: "c".repeat(64),
    networkId: "e".repeat(64),
    selectedAgentImageId: `sha256:${"a".repeat(64)}`,
    sessionAgentGenerationDigest: `sha256:${"b".repeat(64)}`,
    controlPlaneGenerationDigest: `sha256:${"d".repeat(64)}`,
    admissionContractEpoch: 3,
    name: "claude",
    command: "claude",
    startedAt: "2026-09-07T06:59:00.000Z",
    nonce: file.nonce,
    inspectedAt: new Date(T0).toISOString(),
    aliveUntil: new Date(file.aliveUntilMs).toISOString(),
  };
}

// `dropped` keys are on disk but withheld by a scanner rule (ineligible, or a
// duplicate address): in `presentKeys`, not in `files`.
type OkScan = Extract<SessionFileScan, { kind: "ok" }>;

function okScan(model: Model, dropped: ReadonlySet<string>): OkScan {
  const files = new Map<string, SessionFileV1>();
  for (const [key, file] of model.disk) if (!dropped.has(key)) files.set(key, sessionFile(key, file));
  return { kind: "ok", eligibility: ELIGIBILITY, files, dropped: [], presentKeys: new Set(model.disk.keys()) };
}

function writeFile(model: Model, key: string, file: DiskFile): void {
  model.disk.set(key, file);
  model.history.set(key, [...(model.history.get(key) ?? []), file]);
}

function withinBothBounds(observation: FirstObservation, model: Model): boolean {
  return observation.deadlineMs > model.wallMs && model.monoMs - observation.monoOriginMs < observation.durationMs;
}

function snapshot(observations: Map<string, SessionFileObservation>): Array<[string, SessionFileObservation]> {
  return Array.from(observations, ([key, observation]) => [key, { ...observation }]);
}

class WriteFresh implements fc.Command<Model, Real> {
  constructor(readonly key: string, readonly aliveForMs: number) {}
  check(): boolean {
    return true;
  }
  run(model: Model): void {
    model.nonceSerial += 1;
    writeFile(model, this.key, {
      nonce: model.nonceSerial.toString(16).padStart(32, "0"),
      aliveUntilMs: model.wallMs + this.aliveForMs,
    });
  }
  toString(): string {
    return `writeFresh(${this.key.slice(0, 1)}, +${this.aliveForMs})`;
  }
}

// The file's current nonce rewritten with a later wall deadline.
class ReplayLater implements fc.Command<Model, Real> {
  constructor(readonly key: string, readonly laterByMs: number) {}
  check(model: Readonly<Model>): boolean {
    return model.disk.has(this.key);
  }
  run(model: Model): void {
    const current = model.disk.get(this.key) as DiskFile;
    writeFile(model, this.key, { nonce: current.nonce, aliveUntilMs: current.aliveUntilMs + this.laterByMs });
  }
  toString(): string {
    return `replayLater(${this.key.slice(0, 1)}, +${this.laterByMs})`;
  }
}

// An earlier file for the key put back byte for byte.
class RestoreOld implements fc.Command<Model, Real> {
  constructor(readonly key: string, readonly pick: number) {}
  check(model: Readonly<Model>): boolean {
    return (model.history.get(this.key)?.length ?? 0) > 0;
  }
  run(model: Model): void {
    const history = model.history.get(this.key) as DiskFile[];
    model.disk.set(this.key, history[this.pick % history.length]);
  }
  toString(): string {
    return `restoreOld(${this.key.slice(0, 1)}, #${this.pick})`;
  }
}

class Remove implements fc.Command<Model, Real> {
  constructor(readonly key: string) {}
  check(model: Readonly<Model>): boolean {
    return model.disk.has(this.key);
  }
  run(model: Model): void {
    model.disk.delete(this.key);
  }
  toString(): string {
    return `remove(${this.key.slice(0, 1)})`;
  }
}

class AdvanceWall implements fc.Command<Model, Real> {
  constructor(readonly deltaMs: number) {}
  check(): boolean {
    return true;
  }
  run(model: Model): void {
    model.wallMs += this.deltaMs;
  }
  toString(): string {
    return `wall(${this.deltaMs})`;
  }
}

class AdvanceMono implements fc.Command<Model, Real> {
  constructor(readonly deltaMs: number) {}
  check(): boolean {
    return true;
  }
  run(model: Model): void {
    model.monoMs += this.deltaMs;
  }
  toString(): string {
    return `mono(+${this.deltaMs})`;
  }
}

class UnreadableScan implements fc.Command<Model, Real> {
  check(): boolean {
    return true;
  }
  run(model: Model, real: Real): void {
    const before = snapshot(real.observations);
    const result = servedSessionFiles({ kind: "unreadable" }, real.observations, model.wallMs, model.monoMs, LEASE_MAX_MS);
    expect(result.served.size).toBe(0);
    expect(result.expired).toEqual([]);
    expect(snapshot(real.observations)).toEqual(before);
  }
  toString(): string {
    return "unreadableScan";
  }
}

class Scan implements fc.Command<Model, Real> {
  constructor(readonly dropped: ReadonlySet<string>) {}
  check(): boolean {
    return true;
  }
  run(model: Model, real: Real): void {
    const scan = okScan(model, this.dropped);
    const result = servedSessionFiles(scan, real.observations, model.wallMs, model.monoMs, LEASE_MAX_MS);

    const expectedServed: string[] = [];
    const supersededElapsed = new Set<string>();
    for (const [key, file] of model.disk) {
      if (this.dropped.has(key)) continue;
      let first = model.firstObservations.get(key);
      if (!first || first.nonce !== file.nonce) {
        if (first && !withinBothBounds(first, model)) supersededElapsed.add(key);
        first = {
          nonce: file.nonce,
          deadlineMs: file.aliveUntilMs,
          monoOriginMs: model.monoMs,
          durationMs: Math.min(file.aliveUntilMs - model.wallMs, LEASE_MAX_MS),
        };
        model.firstObservations.set(key, first);
      }
      if (file.aliveUntilMs > model.wallMs && withinBothBounds(first, model)) expectedServed.push(key);
    }
    for (const key of Array.from(model.firstObservations.keys())) {
      if (!model.disk.has(key)) model.firstObservations.delete(key);
    }

    // Model and implementation agree on what is served and what is observed.
    expect(Array.from(result.served.keys()).sort()).toEqual(expectedServed.sort());
    expect(Object.fromEntries(real.observations)).toEqual(Object.fromEntries(
      Array.from(model.firstObservations, ([key, first]) => [key, {
        nonce: first.nonce,
        aliveUntilMs: first.deadlineMs,
        observedAtMonotonicMs: first.monoOriginMs,
        observedDurationMs: first.durationMs,
      }]),
    ));

    // Each served file is within both clocks' bounds, measured against the
    // implementation's own observation: the file's deadline, the FIRST
    // observed deadline (a replay cannot raise it), and the first monotonic
    // origin (a replay cannot restart it).
    for (const [key, file] of result.served) {
      const observation = real.observations.get(key) as SessionFileObservation;
      expect(file).toBe(scan.files.get(key));
      expect(observation.nonce).toBe(file.nonce);
      expect(Date.parse(file.aliveUntil)).toBeGreaterThan(model.wallMs);
      expect(observation.aliveUntilMs).toBeGreaterThan(model.wallMs);
      expect(model.monoMs - observation.observedAtMonotonicMs).toBeLessThan(observation.observedDurationMs);
    }

    // Every scanned key that is not served is reported expired, and a served
    // key is reported only when its new nonce superseded an elapsed one.
    const scanned = new Set(scan.files.keys());
    const expired = new Set(result.expired);
    for (const key of scanned) if (!result.served.has(key)) expect(expired.has(key)).toBe(true);
    for (const key of expired) {
      expect(scanned.has(key)).toBe(true);
      if (result.served.has(key)) expect(supersededElapsed.has(key)).toBe(true);
    }
    for (const key of supersededElapsed) expect(expired.has(key)).toBe(true);

    // Pruning follows the directory, not the served set.
    for (const key of real.observations.keys()) expect(model.disk.has(key)).toBe(true);
  }
  toString(): string {
    return `scan(drop=[${Array.from(this.dropped, (key) => key.slice(0, 1)).join(",")}])`;
  }
}

const key = fc.constantFrom(...KEYS);
const replayLater = fc.tuple(key, fc.integer({ min: 1, max: 2 * LEASE_MAX_MS })).map(([k, ms]) => new ReplayLater(k, ms));
const scan = fc.subarray([...KEYS], { maxLength: 1 }).map((dropped) => new Scan(new Set(dropped)));
const commands = fc.commands(
  [
    fc.tuple(key, fc.integer({ min: -5_000, max: 2 * LEASE_MAX_MS })).map(([k, ms]) => new WriteFresh(k, ms)),
    replayLater,
    replayLater,
    fc.tuple(key, fc.nat(8)).map(([k, pick]) => new RestoreOld(k, pick)),
    key.map((k) => new Remove(k)),
    fc.integer({ min: -2 * LEASE_MAX_MS, max: 2 * LEASE_MAX_MS }).map((ms) => new AdvanceWall(ms)),
    fc.nat(2 * LEASE_MAX_MS).map((ms) => new AdvanceMono(ms)),
    fc.constant(new UnreadableScan()),
    // Scans observe state and replays are the guarded event, so both get extra slots.
    scan,
    scan,
    scan,
  ],
  { maxCommands: 60, size: "+2" },
);

describe("servedSessionFiles model", () => {
  it("P7.1: agrees with the dual-clock model and serves only files within both bounds", () => {
    fc.assert(
      fc.property(commands, (sequence) => {
        fc.modelRun(() => ({ model: initialModel(), real: { observations: new Map() } }), sequence);
      }),
      propertyParameters(),
    );
  });

  it("P7.2: an unreadable scan, then a readable scan, restores service", () => {
    fc.assert(
      fc.property(commands, fc.subarray([...KEYS], { maxLength: 1 }), (sequence, droppedKeys) => {
        let model = initialModel();
        let real: Real = { observations: new Map() };
        fc.modelRun(() => {
          model = initialModel();
          real = { observations: new Map() };
          return { model, real };
        }, sequence);
        const dropped = new Set(droppedKeys);
        const before = servedSessionFiles(okScan(model, dropped), real.observations, model.wallMs, model.monoMs, LEASE_MAX_MS);

        const direct = new Map(snapshot(real.observations));
        const directResult = servedSessionFiles(okScan(model, dropped), direct, model.wallMs, model.monoMs, LEASE_MAX_MS);

        servedSessionFiles({ kind: "unreadable" }, real.observations, model.wallMs, model.monoMs, LEASE_MAX_MS);
        const recovered = servedSessionFiles(okScan(model, dropped), real.observations, model.wallMs, model.monoMs, LEASE_MAX_MS);

        expect(Array.from(recovered.served.keys()).sort()).toEqual(Array.from(directResult.served.keys()).sort());
        expect([...recovered.expired].sort()).toEqual([...directResult.expired].sort());
        expect(snapshot(real.observations)).toEqual(snapshot(direct));
        expect(Array.from(recovered.served.keys()).sort()).toEqual(Array.from(before.served.keys()).sort());
      }),
      propertyParameters(),
    );
  });
});
