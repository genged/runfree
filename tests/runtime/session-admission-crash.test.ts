// Unit coverage for the crash runner's command matcher.
//
// A crash point that silently stops matching would make the live tranche
// complete without ever crashing. The runner already fails closed on that (exit
// 3, printing the observed stream), but a live cycle costs a full rebuild, so
// the matching rule is proven here where it costs nothing.

import { describe, expect, test } from "vitest";

import { createSessionAdmissionEligibility } from "@runfree/runtime-contracts/session-admission";
import {
  SESSION_ELIGIBILITY_PATH,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";

import {
  eligibilityPublishCommand,
  sessionFileDeleteCommand,
  sessionFileWriteCommand,
} from "../../packages/cli/src/runtime/session-file-publisher.ts";
import {
  CRASH_POINTS,
  crashPointArmed,
  inspectReportsRunning,
  isCrashPoint,
  isLaunchHoldPoint,
  launchCrashPoints,
  matchesCrashPoint,
  probeCrashPoints,
  sessionFileCommandEffect,
} from "./session-admission-crash.ts";

describe("crash point matching", () => {
  // The exact argv the driver builds, copied from `session-container-docker.ts`
  // so a change there shows up here as a failing expectation rather than as a
  // live crash point that silently stops firing.
  test("matches the driver's real create, inspect, and start commands", () => {
    expect(matchesCrashPoint(
      ["container", "create", "--name", "session", "--network", "net", "--ip", "172.30.0.20"],
      "after-create",
    )).toBe(true);
    expect(matchesCrashPoint(["container", "inspect", "abc123"], "after-running-inspect")).toBe(true);
    expect(matchesCrashPoint(["container", "start", "--attach", "abc123"], "after-start")).toBe(true);
  });

  test("does not match a bare verb appearing as an option value", () => {
    // The failure this rule exists for: once options are stripped, `run --name
    // container create` reads as `container create`. A search-anywhere rule
    // would crash the wrong transition while looking correct.
    expect(matchesCrashPoint(["container", "run", "--name", "create"], "after-create")).toBe(false);
    expect(matchesCrashPoint(["run", "--name", "container", "create"], "after-create")).toBe(false);
  });

  test("matches the driver's revocation commands", () => {
    expect(matchesCrashPoint(["network", "disconnect", "net", "id"], "after-network-disconnect")).toBe(true);
    expect(matchesCrashPoint(["container", "stop", "--time", "5", "id"], "after-container-stop")).toBe(true);
  });

  test("does not match a different subcommand under the same noun", () => {
    expect(matchesCrashPoint(["container", "inspect", "id"], "after-create")).toBe(false);
    expect(matchesCrashPoint(["container", "stop", "--time", "5", "id"], "after-start")).toBe(false);
    expect(matchesCrashPoint(["container", "rm", "id"], "after-container-stop")).toBe(false);
    expect(matchesCrashPoint(["network", "disconnect", "net", "id"], "after-running-inspect")).toBe(false);
    expect(matchesCrashPoint(["network", "inspect", "net"], "after-network-disconnect")).toBe(false);
  });

  test("does not match a truncated path", () => {
    expect(matchesCrashPoint(["container"], "after-create")).toBe(false);
    expect(matchesCrashPoint([], "after-create")).toBe(false);
  });

  test("crash points are recognised by name and nothing else is", () => {
    for (const point of Object.keys(CRASH_POINTS)) expect(isCrashPoint(point)).toBe(true);
  });

  test("arms the post-start inspection point only after a session start was observed", () => {
    // Preflight's whole-inventory reconciliation issues `container inspect`
    // batches whose count depends on the daemon's total container population,
    // so the point that names the single post-start inspection is gated by
    // order rather than by occurrence.
    expect(crashPointArmed("after-running-inspect", false)).toBe(false);
    expect(crashPointArmed("after-running-inspect", true)).toBe(true);
    for (const point of Object.keys(CRASH_POINTS) as (keyof typeof CRASH_POINTS)[]) {
      if (point === "after-running-inspect") continue;
      expect(crashPointArmed(point, false)).toBe(true);
    }
    expect(isCrashPoint("after-everything")).toBe(false);
    expect(isCrashPoint("")).toBe(false);
    // `Object.hasOwn` rather than a prototype-reachable lookup: a points table
    // keyed by "toString" would otherwise report as a valid crash point.
    expect(isCrashPoint("toString")).toBe(false);
  });

});

describe("launch hold point matching", () => {
  // `before-session-file-write` parks a production launch between its running
  // proof and admission. It is armed by the inspect that observed the container
  // running and held at that observation, before the sealed inspect-and-write
  // that grants authority.
  test("accepts every crash point plus the launch-only point", () => {
    for (const point of Object.keys(CRASH_POINTS)) expect(isLaunchHoldPoint(point)).toBe(true);
    expect(isLaunchHoldPoint("before-session-file-write")).toBe(true);
    expect(isLaunchHoldPoint("before-session-file")).toBe(false);
    expect(isLaunchHoldPoint("")).toBe(false);
  });

  test("recognises the running observation only from a single running container", () => {
    expect(inspectReportsRunning(JSON.stringify([{ State: { Running: true, Status: "running" } }]))).toBe(true);
    expect(inspectReportsRunning(JSON.stringify([{ State: { Running: false, Status: "created" } }]))).toBe(false);
    expect(inspectReportsRunning(JSON.stringify([{ State: { Running: true, Status: "restarting" } }]))).toBe(false);
    expect(inspectReportsRunning(JSON.stringify([
      { State: { Running: true, Status: "running" } },
      { State: { Running: true, Status: "running" } },
    ]))).toBe(false);
    expect(inspectReportsRunning(JSON.stringify([]))).toBe(false);
    expect(inspectReportsRunning("not json")).toBe(false);
    expect(inspectReportsRunning(undefined)).toBe(false);
  });

});

describe("per-session file crash points", () => {
  const PROXY_ID = "a".repeat(64);
  const SESSION_KEY = "b".repeat(64);
  const OBJECT_ID = "c".repeat(64);
  const DIGEST = `sha256:${"d".repeat(64)}`;

  // The exact bytes the heartbeat writes, so the argv below is the real one the
  // publisher builds rather than a reconstruction of it.
  const PROJECT_ID = "0123456789ab";
  const sessionFile: SessionFileV1 = {
    v: 1,
    projectId: PROJECT_ID,
    sessionKey: SESSION_KEY,
    sessionId: "rf-20260907-abc123",
    sessionIncarnation: "e".repeat(64),
    sourceIp: "172.30.0.20",
    containerId: OBJECT_ID,
    networkId: OBJECT_ID,
    selectedAgentImageId: DIGEST,
    sessionAgentGenerationDigest: DIGEST,
    controlPlaneGenerationDigest: DIGEST,
    admissionContractEpoch: 1,
    name: "claude",
    command: "runfree claude",
    startedAt: "2026-09-07T00:00:00.000Z",
    nonce: "f".repeat(32),
    inspectedAt: "2026-09-07T00:00:01.000Z",
    aliveUntil: "2026-09-07T00:01:01.000Z",
  };

  const writeArgv = [...sessionFileWriteCommand(PROXY_ID, sessionFile).args];
  const deleteArgv = [...sessionFileDeleteCommand(PROXY_ID, SESSION_KEY).args];
  const eligibilityArgv = [...eligibilityPublishCommand(PROXY_ID, createSessionAdmissionEligibility({
    projectId: PROJECT_ID,
    controlPlaneGenerationDigest: DIGEST,
    admissionContractEpoch: 1,
    agentInternalNetworkId: OBJECT_ID,
    allowedSessionAgents: [{ sessionAgentGenerationDigest: DIGEST, selectedAgentImageId: DIGEST }],
  })).args];

  test("tells the publisher's real write and delete argv apart", () => {
    expect(sessionFileCommandEffect(writeArgv)).toBe("write");
    expect(sessionFileCommandEffect(deleteArgv)).toBe("delete");
    // The eligibility publish shares the write script but names a path outside
    // the sessions directory, so it is neither — a session-file point that
    // matched it would fire during startup, long before any session exists.
    expect(eligibilityArgv).toContain(SESSION_ELIGIBILITY_PATH);
    expect(sessionFileCommandEffect(eligibilityArgv)).toBeUndefined();
    expect(sessionFileCommandEffect(["container", "inspect", OBJECT_ID])).toBeUndefined();
    expect(sessionFileCommandEffect(["exec", "proxy", "cat", "/etc/hosts"])).toBeUndefined();
  });

  test("the file-source points match exactly their own command", () => {
    expect(matchesCrashPoint(writeArgv, "after-session-file-write")).toBe(true);
    expect(matchesCrashPoint(deleteArgv, "after-session-file-write")).toBe(false);
    for (const point of ["after-file-deleted-before-stop", "after-failed-file-delete"] as const) {
      expect(matchesCrashPoint(deleteArgv, point)).toBe(true);
      expect(matchesCrashPoint(writeArgv, point)).toBe(false);
      expect(matchesCrashPoint(eligibilityArgv, point)).toBe(false);
    }
  });

  test("the probe and the launch each select only the points they can reach", () => {
    // The internal probe never activates, so it never writes a session file:
    // a probe run that asked for a file point would exit 3 having tested
    // nothing.
    expect(probeCrashPoints()).toEqual([
      "after-create",
      "after-start",
      "after-running-inspect",
      "after-network-disconnect",
      "after-container-stop",
    ]);
    expect(launchCrashPoints()).toEqual([
      "after-session-file-write",
      "after-file-deleted-before-stop",
      "after-failed-file-delete",
    ]);
  });
});
