// The warm-empty session state: what a warm handoff launch mints when its
// evidence proves the project holds no session state, and the one-shot seal
// admission consumes before it skips its reconcile.
//
// Real state directory, real lifecycle lock, and the real absence listing;
// only the Docker daemon is a fake, and the warm validation's own seal is
// bypassed so a test can hand it any session-state evidence.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("./warm-proof.ts", () => ({ assertWarmValidation: () => undefined }));

import { sessionRegistryDigest } from "./launch-handoff.ts";
import { SESSION_CONTAINER_ABSENCE_FORMAT } from "./session-container-reconciliation.ts";
import { sessionContainerRecordFixture, SESSION_TEST_PROJECT } from "./session-container.test-harness.ts";
import { sessionContainerRecordsRoot, writeSessionContainerRecordV2 } from "./session-containers.ts";
import { tryAcquireProjectLifecycleLock, type ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";
import {
  consumeWarmEmptySessionState,
  EMPTY_SESSION_REGISTRY_DIGEST,
  isWarmEmptySessionState,
  proveWarmEmptySessionState,
  type WarmEmptySessionState,
} from "./warm-empty-session-state.ts";
import type { WarmValidation } from "./warm-proof.ts";

const PROXY_ID = "7".repeat(64);
const PROXY_STARTED_AT = "2026-10-08T12:00:05.123456789Z";
const SESSION_ROW_ID = "a".repeat(64);
const EXACT_LABEL_COLUMNS = 13;

let tmp: string;
let stateDir: string;
let lock: ProjectLifecycleLock;
let psCalls: string[][];
let psAnswer: CaptureResult;

function io(): RuntimeIO {
  return {
    capture: (_command: string, args: string[]) => {
      if (args[0] === "ps" && args.includes(SESSION_CONTAINER_ABSENCE_FORMAT)) {
        psCalls.push([...args]);
        return psAnswer;
      }
      throw new Error(`unexpected docker call: ${args.join(" ")}`);
    },
  } as unknown as RuntimeIO;
}

function warm(sessionState: WarmValidation["sessionState"] = { kind: "empty" }, proxyStartedAt = PROXY_STARTED_AT): WarmValidation {
  return { proxyStartedAt, sessionState } as unknown as WarmValidation;
}

function prove(overrides: { warm?: WarmValidation; proxyStartedAt?: string; lifecycleLock?: ProjectLifecycleLock } = {}) {
  return proveWarmEmptySessionState({
    warm: overrides.warm ?? warm(),
    io: io(),
    stateDir,
    expectedProject: SESSION_TEST_PROJECT,
    proxyId: PROXY_ID,
    proxyStartedAt: overrides.proxyStartedAt ?? PROXY_STARTED_AT,
    lifecycleLock: overrides.lifecycleLock ?? lock,
    dockerOptions: {},
  });
}

function minted(): WarmEmptySessionState {
  const verdict = prove();
  if (verdict.kind !== "empty") throw new Error(`expected a minted state, got blocked:${verdict.reason}`);
  return verdict.state;
}

function binding(state: WarmEmptySessionState = minted()) {
  return {
    registryDigest: state.registryDigest,
    proxyId: state.proxyId,
    proxyStartedAt: state.proxyStartedAt,
    lockOwnerToken: state.lockOwnerToken,
  };
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-warm-empty-"));
  stateDir = path.join(tmp, "state");
  fs.mkdirSync(stateDir, { recursive: true });
  const context = {
    projectRoot: path.join(tmp, "project"),
    project: { config: {}, paths: { stateDir, sessionsDir: path.join(stateDir, "sessions") } },
    runtimeRoot: path.join(tmp, "runtime"),
    env: {},
  } as unknown as RuntimeContext;
  const acquired = tryAcquireProjectLifecycleLock(context);
  if (!acquired) throw new Error("could not take the test lifecycle lock");
  lock = acquired;
  psCalls = [];
  psAnswer = { status: 0, stdout: "", stderr: "" };
});

afterEach(() => {
  try {
    lock.release();
  } catch {
    // A test released it already.
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("proveWarmEmptySessionState", () => {
  test("mints a frozen state bound to the empty registry, the proxy incarnation, and the held lock", () => {
    const verdict = prove();
    expect(verdict.kind).toBe("empty");
    if (verdict.kind !== "empty") return;
    expect(verdict.state).toEqual({
      kind: "warm-empty",
      registryDigest: EMPTY_SESSION_REGISTRY_DIGEST,
      proxyId: PROXY_ID,
      proxyStartedAt: PROXY_STARTED_AT,
      lockOwnerToken: lock.ownerToken,
    });
    expect(Object.isFrozen(verdict.state)).toBe(true);
    expect(isWarmEmptySessionState(verdict.state)).toBe(true);
    expect(psCalls).toHaveLength(1);
  });

  test("the empty digest is the digest of an empty registry", () => {
    expect(EMPTY_SESSION_REGISTRY_DIGEST).toBe(sessionRegistryDigest(stateDir, SESSION_TEST_PROJECT));
  });

  // The participant reasons come from `internalNetworkSessionStateBlocker`
  // (a helper or other non-ingress participant, a session agent); a warm
  // launch can no longer reach them through a recorded helper, since no record
  // is written beside one, so they are pinned here.
  test.each(["session-files-present", "non-ingress-participant", "session-participant"])(
    "blocked session-state evidence (%s) blocks with its own reason and no listing",
    (reason) => {
      expect(prove({ warm: warm({ kind: "blocked", reason }) })).toEqual({ kind: "blocked", reason });
      expect(psCalls).toHaveLength(0);
    },
  );

  test("a lifecycle record blocks as a non-empty registry", () => {
    writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, sessionContainerRecordFixture());
    expect(prove()).toEqual({ kind: "blocked", reason: "registry-not-empty" });
    expect(psCalls).toHaveLength(0);
  });

  test("a quarantined record blocks", () => {
    // Unreadable bytes: the enumeration moves them into quarantine.
    fs.mkdirSync(sessionContainerRecordsRoot(stateDir), { recursive: true });
    fs.writeFileSync(path.join(sessionContainerRecordsRoot(stateDir), "rf-20261008-abcdef.json"), "{not json\n");
    expect(prove()).toEqual({ kind: "blocked", reason: "quarantined-records" });
    expect(psCalls).toHaveLength(0);
  });

  test("a proxy incarnation other than the one the warm proof observed blocks", () => {
    expect(prove({ warm: warm({ kind: "empty" }, "2026-10-08T12:30:00.000000000Z") }))
      .toEqual({ kind: "blocked", reason: "proxy-incarnation" });
    expect(psCalls).toHaveLength(0);
  });

  test("an unreadable container listing blocks", () => {
    psAnswer = { status: 124, stdout: "", stderr: "timed out" };
    expect(prove()).toEqual({ kind: "blocked", reason: "session-containers-unreadable" });
  });

  test("a container that may be a session blocks", () => {
    psAnswer = {
      status: 0,
      stdout: `${JSON.stringify([
        SESSION_ROW_ID,
        `runfree-${SESSION_TEST_PROJECT.projectId}-session-x`,
        "",
        ...Array.from({ length: EXACT_LABEL_COLUMNS }, () => ""),
      ])}\n`,
      stderr: "",
    };
    expect(prove()).toEqual({ kind: "blocked", reason: "session-containers-present" });
  });

  test("a released lock throws before any observation", () => {
    lock.release();
    expect(() => prove()).toThrow();
    expect(psCalls).toHaveLength(0);
  });
});

describe("consumeWarmEmptySessionState", () => {
  test("consumes a minted state exactly once", () => {
    const state = minted();
    expect(consumeWarmEmptySessionState(state, binding(state))).toBe(true);
    expect(isWarmEmptySessionState(state)).toBe(false);
    expect(consumeWarmEmptySessionState(state, binding(state))).toBe(false);
  });

  test("refuses an object it did not mint, even with equal fields", () => {
    const state = minted();
    const forged: WarmEmptySessionState = Object.freeze({ ...binding(state), kind: "warm-empty" as const });
    expect(isWarmEmptySessionState(forged)).toBe(false);
    expect(consumeWarmEmptySessionState(forged, binding(state))).toBe(false);
    expect(consumeWarmEmptySessionState({ ...state }, binding(state))).toBe(false);
    // The refusals consumed nothing.
    expect(isWarmEmptySessionState(state)).toBe(true);
  });

  test.each([
    ["lockOwnerToken", { lockOwnerToken: "f".repeat(64) }],
    ["registryDigest", { registryDigest: `sha256:${"1".repeat(64)}` }],
    ["proxyStartedAt", { proxyStartedAt: "2026-10-08T12:30:00.000000000Z" }],
    ["proxyId", { proxyId: "9".repeat(64) }],
  ] as const)("refuses a binding with another %s and leaves the state unconsumed", (_field, change) => {
    const state = minted();
    expect(consumeWarmEmptySessionState(state, { ...binding(state), ...change })).toBe(false);
    expect(isWarmEmptySessionState(state)).toBe(true);
    expect(consumeWarmEmptySessionState(state, binding(state))).toBe(true);
  });

  test("refuses values that are not objects", () => {
    const state = minted();
    for (const value of [undefined, null, "warm-empty", 1]) {
      expect(consumeWarmEmptySessionState(value, binding(state))).toBe(false);
      expect(isWarmEmptySessionState(value)).toBe(false);
    }
  });
});
