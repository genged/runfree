import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import { serializeSessionFileV1, type SessionFileV1 } from "@runfree/runtime-contracts/session-file";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { propertyParameters } from "../../../tests/support/property.ts";
import { SessionFileRegistry } from "./session-file-registry.ts";

// Model-based test of the registry over a real temp directory, with both
// clocks injected. Invariants:
//
//   "Fail closed until a refresh proves the state readable: nothing is served
//    before the first loop tick, and an unreadable scan returns to this state."
//   An unreadable scan ends every live context and keeps observations, so the
//   next readable scan restores service without a fresh monotonic bound.
//   Each served address is within both clocks' bounds of its first observation.

const PROJECT_ID = "abcdef012345";
const NETWORK_ID = "e".repeat(64);
const IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const AGENT_DIGEST = `sha256:${"b".repeat(64)}`;
const CONTROL_DIGEST = `sha256:${"d".repeat(64)}`;
const OWNER_UID = process.getuid?.() ?? 0;
const T0 = Date.parse("2026-09-07T07:00:00.000Z");
const LEASE_MAX_MS = 60_000;
const SESSIONS = [
  { key: "1".repeat(64), ip: "172.30.194.20" },
  { key: "7".repeat(64), ip: "172.30.194.21" },
] as const;

type DiskFile = { nonce: string; inspectedAtMs: number; aliveUntilMs: number };
type FirstObservation = { nonce: string; deadlineMs: number; monoOriginMs: number; durationMs: number };

type Model = {
  wallMs: number;
  monoMs: number;
  nonceSerial: number;
  stateReadable: boolean;
  disk: Map<string, DiskFile>;
  // What the registry should hold after its last refresh.
  registryReadable: boolean;
  firstObservations: Map<string, FirstObservation>;
  served: Set<string>;
  expired: Set<string>;
};

type Real = {
  root: string;
  registry: SessionFileRegistry;
  clocks: { wallMs: number; monoMs: number };
  invalidations: Array<[string, string]>;
};

function writeEligibility(root: string): void {
  const eligibility = createSessionAdmissionEligibility({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: CONTROL_DIGEST,
    admissionContractEpoch: 3,
    agentInternalNetworkId: NETWORK_ID,
    allowedSessionAgents: [{ selectedAgentImageId: IMAGE_DIGEST, sessionAgentGenerationDigest: AGENT_DIGEST }],
  });
  fs.writeFileSync(path.join(root, "eligibility.json"), serializeSessionAdmissionEligibility(eligibility), { mode: 0o644 });
}

function setup(): { model: Model; real: Real } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-file-registry-model-"));
  fs.chmodSync(root, 0o755);
  fs.mkdirSync(path.join(root, "sessions"), { mode: 0o755 });
  writeEligibility(root);
  const clocks = { wallMs: T0, monoMs: 10_000 };
  const invalidations: Array<[string, string]> = [];
  const registry = new SessionFileRegistry({
    root,
    projectId: PROJECT_ID,
    ownerUid: OWNER_UID,
    leaseMaxMs: LEASE_MAX_MS,
    now: () => clocks.wallMs,
    monotonicNowMs: () => clocks.monoMs,
    onSessionInvalidated: (sessionKey, reason) => invalidations.push([sessionKey, reason]),
  });
  return {
    model: {
      wallMs: clocks.wallMs,
      monoMs: clocks.monoMs,
      nonceSerial: 0,
      stateReadable: true,
      disk: new Map(),
      registryReadable: false,
      firstObservations: new Map(),
      served: new Set(),
      expired: new Set(),
    },
    real: { root, registry, clocks, invalidations },
  };
}

function sessionFile(session: (typeof SESSIONS)[number], file: DiskFile): SessionFileV1 {
  return {
    v: 1,
    projectId: PROJECT_ID,
    sessionKey: session.key,
    sessionId: "rf-20260907-abc123",
    sessionIncarnation: "2".repeat(64),
    sourceIp: session.ip,
    containerId: "c".repeat(64),
    networkId: NETWORK_ID,
    selectedAgentImageId: IMAGE_DIGEST,
    sessionAgentGenerationDigest: AGENT_DIGEST,
    controlPlaneGenerationDigest: CONTROL_DIGEST,
    admissionContractEpoch: 3,
    name: "claude",
    command: "claude",
    startedAt: "2026-09-07T06:59:00.000Z",
    nonce: file.nonce,
    inspectedAt: new Date(file.inspectedAtMs).toISOString(),
    aliveUntil: new Date(file.aliveUntilMs).toISOString(),
  };
}

function writeFile(model: Model, real: Real, session: (typeof SESSIONS)[number], file: DiskFile): void {
  model.disk.set(session.key, file);
  fs.writeFileSync(
    path.join(real.root, "sessions", `${session.key}.json`),
    serializeSessionFileV1(sessionFile(session, file)),
    { mode: 0o644 },
  );
}

function withinBothBounds(observation: FirstObservation, model: Model): boolean {
  return observation.deadlineMs > model.wallMs && model.monoMs - observation.monoOriginMs < observation.durationMs;
}

// Every command ends here: the registry answers each address as the model says.
function checkLookups(model: Model, real: Real): void {
  for (const session of SESSIONS) {
    const lookup = real.registry.lookup(session.ip);
    if (!model.registryReadable) {
      expect(lookup).toEqual({ kind: "rejected", reason: "registry-unavailable" });
    } else if (model.served.has(session.key)) {
      expect(lookup).toMatchObject({ kind: "active", session: { sessionKey: session.key } });
    } else {
      expect(lookup).toEqual({ kind: "rejected", reason: model.expired.has(session.key) ? "expired" : "missing" });
    }
  }
  expect(Array.from(real.registry.servedAddresses()).sort()).toEqual(
    SESSIONS.filter((session) => model.registryReadable && model.served.has(session.key)).map((session) => session.ip).sort(),
  );
}

abstract class RegistryCommand implements fc.Command<Model, Real> {
  check(_model: Readonly<Model>): boolean {
    return true;
  }
  run(model: Model, real: Real): void {
    this.apply(model, real);
    checkLookups(model, real);
  }
  abstract apply(model: Model, real: Real): void;
  abstract toString(): string;
}

class WriteFresh extends RegistryCommand {
  constructor(readonly index: number, readonly aliveForMs: number) {
    super();
  }
  apply(model: Model, real: Real): void {
    model.nonceSerial += 1;
    writeFile(model, real, SESSIONS[this.index], {
      nonce: model.nonceSerial.toString(16).padStart(32, "0"),
      inspectedAtMs: model.wallMs,
      aliveUntilMs: model.wallMs + this.aliveForMs,
    });
  }
  toString(): string {
    return `writeFresh(${this.index}, +${this.aliveForMs})`;
  }
}

// Same nonce, later deadline; inspectedAt moves with it so the file still parses.
class ReplayLater extends RegistryCommand {
  constructor(readonly index: number, readonly laterByMs: number) {
    super();
  }
  check(model: Readonly<Model>): boolean {
    return model.disk.has(SESSIONS[this.index].key);
  }
  apply(model: Model, real: Real): void {
    const current = model.disk.get(SESSIONS[this.index].key) as DiskFile;
    writeFile(model, real, SESSIONS[this.index], {
      nonce: current.nonce,
      inspectedAtMs: current.inspectedAtMs + this.laterByMs,
      aliveUntilMs: current.aliveUntilMs + this.laterByMs,
    });
  }
  toString(): string {
    return `replayLater(${this.index}, +${this.laterByMs})`;
  }
}

class Remove extends RegistryCommand {
  constructor(readonly index: number) {
    super();
  }
  check(model: Readonly<Model>): boolean {
    return model.disk.has(SESSIONS[this.index].key);
  }
  apply(model: Model, real: Real): void {
    model.disk.delete(SESSIONS[this.index].key);
    fs.rmSync(path.join(real.root, "sessions", `${SESSIONS[this.index].key}.json`));
  }
  toString(): string {
    return `remove(${this.index})`;
  }
}

class SetStateReadable extends RegistryCommand {
  constructor(readonly readable: boolean) {
    super();
  }
  check(model: Readonly<Model>): boolean {
    return model.stateReadable !== this.readable;
  }
  apply(model: Model, real: Real): void {
    model.stateReadable = this.readable;
    if (this.readable) writeEligibility(real.root);
    else fs.rmSync(path.join(real.root, "eligibility.json"));
  }
  toString(): string {
    return this.readable ? "restoreState" : "breakState";
  }
}

class Advance extends RegistryCommand {
  constructor(readonly wallDeltaMs: number, readonly monoDeltaMs: number) {
    super();
  }
  apply(model: Model, real: Real): void {
    model.wallMs += this.wallDeltaMs;
    model.monoMs += this.monoDeltaMs;
    real.clocks.wallMs = model.wallMs;
    real.clocks.monoMs = model.monoMs;
  }
  toString(): string {
    return `advance(wall ${this.wallDeltaMs}, mono +${this.monoDeltaMs})`;
  }
}

class Refresh extends RegistryCommand {
  apply(model: Model, real: Real): void {
    const previouslyServed = new Set(model.served);
    const invalidationsBefore = real.invalidations.length;
    const result = real.registry.refresh();
    const invalidations = real.invalidations.slice(invalidationsBefore).map(([key, reason]) => `${key}:${reason}`).sort();

    if (!model.stateReadable) {
      // Observations are deliberately left alone: the model's first
      // observations carry over to the next readable refresh.
      expect(result).toEqual({ kind: "unreadable" });
      expect(invalidations).toEqual(Array.from(previouslyServed, (key) => `${key}:removed`).sort());
      model.registryReadable = false;
      model.served = new Set();
      model.expired = new Set();
      return;
    }

    const served = new Set<string>();
    const expired = new Set<string>();
    for (const [key, file] of model.disk) {
      let first = model.firstObservations.get(key);
      if (!first || first.nonce !== file.nonce) {
        if (first && !withinBothBounds(first, model)) expired.add(key);
        first = {
          nonce: file.nonce,
          deadlineMs: file.aliveUntilMs,
          monoOriginMs: model.monoMs,
          durationMs: Math.min(file.aliveUntilMs - model.wallMs, LEASE_MAX_MS),
        };
        model.firstObservations.set(key, first);
      }
      if (file.aliveUntilMs > model.wallMs && withinBothBounds(first, model)) served.add(key);
      else expired.add(key);
    }
    for (const key of Array.from(model.firstObservations.keys())) {
      if (!model.disk.has(key)) model.firstObservations.delete(key);
    }

    expect(result).toEqual({ kind: "ok", served: served.size });
    const expectedInvalidations: string[] = [];
    for (const key of previouslyServed) {
      if (expired.has(key)) expectedInvalidations.push(`${key}:expired`);
      else if (!served.has(key)) expectedInvalidations.push(`${key}:removed`);
    }
    expect(invalidations).toEqual(expectedInvalidations.sort());
    model.registryReadable = true;
    model.served = served;
    model.expired = new Set(Array.from(model.disk.keys()).filter((key) => !served.has(key)));
  }
  toString(): string {
    return "refresh";
  }
}

const index = fc.integer({ min: 0, max: SESSIONS.length - 1 });
const replayLater = fc.tuple(index, fc.integer({ min: 1, max: 2 * LEASE_MAX_MS })).map(([i, ms]) => new ReplayLater(i, ms));
const refresh = fc.constant(new Refresh());
const commands = fc.commands(
  [
    fc.tuple(index, fc.integer({ min: 1, max: SESSION_ADMISSION_LEASE_MAX_DURATION_MS })).map(([i, ms]) => new WriteFresh(i, ms)),
    replayLater,
    replayLater,
    index.map((i) => new Remove(i)),
    fc.boolean().map((readable) => new SetStateReadable(readable)),
    fc.integer({ min: -2 * LEASE_MAX_MS, max: 2 * LEASE_MAX_MS }).map((ms) => new Advance(ms, 0)),
    fc.nat(2 * LEASE_MAX_MS).map((ms) => new Advance(0, ms)),
    fc.nat(2 * LEASE_MAX_MS).map((ms) => new Advance(ms, ms)),
    // Refreshes are what observe state, so they get extra slots.
    refresh,
    refresh,
    refresh,
  ],
  { maxCommands: 60, size: "+2" },
);

describe("SessionFileRegistry model", () => {
  it("P7.3: fails closed until a readable refresh and agrees with the dual-clock model", () => {
    fc.assert(
      fc.property(commands, (sequence) => {
        const roots: string[] = [];
        try {
          fc.modelRun(() => {
            const state = setup();
            roots.push(state.real.root);
            checkLookups(state.model, state.real);
            return state;
          }, sequence);
        } finally {
          for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
        }
      }),
      propertyParameters(),
    );
  });
});
