import type * as childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  parseSessionFileV1,
  sessionFilePath,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";
import { SESSION_ADMISSION_LEASE_MAX_DURATION_MS } from "@runfree/runtime-contracts/session-registry";

import { sha256Digest } from "../strict-primitives.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import {
  assertSessionContainerNarrowRunningInspect,
  NARROW_LIVENESS_UNREADABLE_INSPECT_MESSAGES,
  type SessionContainerNarrowRunningIdentity,
} from "./session-container-narrow-liveness.ts";
import { SESSION_CONTAINER_INSPECT_MAX_BYTES } from "./session-container-proof.ts";
import {
  inspectAndWriteSessionFile,
  nextHeartbeatDelayMs,
  SESSION_HEARTBEAT_CADENCE_MS,
  type HeartbeatOutcome,
  type SessionFileAnchor,
  type SessionFileDisplay,
  type SessionFileEligibilityBindings,
} from "./session-file-heartbeat.ts";
import {
  sessionContainerCreatePlanFixture,
  sessionContainerInspectJsonFixture,
  SESSION_TEST_DOCKER_STARTED_AT,
  SESSION_TEST_NETWORK_ENDPOINT_ID,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { SessionAdmissionDockerExecutor } from "./session-file-publisher.ts";
import type { CaptureResult } from "./types.ts";

const PROXY_ID = "a".repeat(64);
const CONTAINER_ID = "c".repeat(64);
const NOW = Date.parse("2026-08-08T12:01:00.000Z");
const LEASE_MS = 90_000;
const LEASE = Object.freeze({
  admittedAt: "2026-08-08T12:00:01.000Z",
  leaseGeneration: "e".repeat(32),
  leaseExpiresAt: "2026-08-08T12:05:00.000Z",
});

const plan = sessionContainerCreatePlanFixture({ containerId: CONTAINER_ID });
const NETWORK_ID = plan.effectiveControlPlane.networkIds.agentInternal;
const NETWORK_KEY = `${SESSION_TEST_PROJECT.composeProject}_agent_internal`;
const RUNNING_INSPECT = sessionContainerInspectJsonFixture(plan, { running: true });

const attachedRecord = transitionProvisioningRunningSessionContainerToAttachedV2(
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2(plan.record, LEASE),
);

const ANCHOR: SessionFileAnchor = Object.freeze({
  dockerPid: 4242,
  dockerStartedAt: SESSION_TEST_DOCKER_STARTED_AT,
  networkEndpointId: SESSION_TEST_NETWORK_ENDPOINT_ID,
});

const DISPLAY = Object.freeze({
  name: "payments",
  command: "codex",
  agentCommand: "codex --resume",
  hostTty: "/dev/ttys004",
  hostTermProgram: "iTerm.app",
  startedAt: attachedRecord.createdAt,
});

// The eligibility-matching bindings the caller owns. They are passed separately
// because they must equal the published eligibility file, but they may never
// name an agent, generation, or epoch other than the one this record was
// admitted under.
const BINDINGS = Object.freeze({
  selectedAgentImageId: attachedRecord.selectedAgentImageId,
  sessionAgentGenerationDigest: attachedRecord.sessionAgentGenerationDigest,
  controlPlaneGenerationDigest: attachedRecord.controlPlaneGenerationDigest,
  admissionContractEpoch: attachedRecord.admissionContractEpoch,
});

type Effect = "inspect-session-container" | "write-session-file" | "delete-session-file";
type Call = { effect: Effect; args: string[]; options: Record<string, unknown> };
type Scripted = CaptureResult | readonly CaptureResult[];

const OK: CaptureResult = { status: 0, stdout: "", stderr: "" };

function ok(stdout: string): CaptureResult {
  return { status: 0, stdout, stderr: "" };
}

/**
 * A fake `io.capture` scripted per effect, mirroring the publisher's own test
 * double. The three effects are told apart the way Docker itself would see
 * them: `docker container inspect`, and the sealed `docker exec … node -e`
 * write (which carries the file on stdin) versus delete (which does not).
 */
function scripted(script: Partial<Record<Effect, Scripted>> = {}): {
  io: SessionAdmissionDockerExecutor;
  calls: Call[];
  effects: Effect[];
} {
  const calls: Call[] = [];
  const counts = new Map<Effect, number>();
  return {
    calls,
    get effects() {
      return calls.map((call) => call.effect);
    },
    io: {
      capture: (_command, args, options) => {
        const captured = (options ?? {}) as Record<string, unknown>;
        const effect: Effect = args[0] === "container" && args[1] === "inspect"
          ? "inspect-session-container"
          : captured.input === undefined
            ? "delete-session-file"
            : "write-session-file";
        calls.push({ effect, args: [...args], options: captured });
        const index = counts.get(effect) ?? 0;
        counts.set(effect, index + 1);
        const scriptedResult = script[effect] ?? (effect === "inspect-session-container" ? ok(RUNNING_INSPECT) : OK);
        if (Array.isArray(scriptedResult)) {
          return (scriptedResult[Math.min(index, scriptedResult.length - 1)] ?? OK) as CaptureResult;
        }
        return scriptedResult as CaptureResult;
      },
    },
  };
}

function heartbeat(
  io: SessionAdmissionDockerExecutor,
  overrides: {
    record?: SessionContainerRecordV2;
    anchor?: SessionFileAnchor;
    leaseMs?: number;
    display?: SessionFileDisplay;
    eligibilityBindings?: SessionFileEligibilityBindings;
    nowEpochMs?: () => number;
    dockerOptions?: childProcess.SpawnSyncOptions;
  } = {},
): Promise<HeartbeatOutcome> {
  return inspectAndWriteSessionFile({
    io,
    proxyId: PROXY_ID,
    record: overrides.record ?? attachedRecord,
    anchor: overrides.anchor ?? ANCHOR,
    expectedProject: SESSION_TEST_PROJECT,
    networkId: NETWORK_ID,
    display: overrides.display ?? DISPLAY,
    eligibilityBindings: overrides.eligibilityBindings ?? BINDINGS,
    leaseMs: overrides.leaseMs ?? LEASE_MS,
    nowEpochMs: overrides.nowEpochMs ?? (() => NOW),
    ...(overrides.dockerOptions !== undefined ? { dockerOptions: overrides.dockerOptions } : {}),
  });
}

type InspectDocument = Record<string, unknown> & {
  Id: string;
  State: Record<string, unknown>;
  NetworkSettings: { Networks: Record<string, Record<string, unknown>> };
};

function mutatedInspect(mutate: (document: InspectDocument) => void): string {
  const parsed = JSON.parse(RUNNING_INSPECT) as InspectDocument[];
  const document = parsed[0] as InspectDocument;
  mutate(document);
  return JSON.stringify(parsed);
}

function network(document: InspectDocument): Record<string, unknown> {
  return document.NetworkSettings.Networks[NETWORK_KEY] as Record<string, unknown>;
}

function writtenFile(calls: readonly Call[]): SessionFileV1 {
  const write = calls.find((call) => call.effect === "write-session-file");
  expect(write).toBeDefined();
  const parsed = parseSessionFileV1(String((write as Call).options.input), attachedRecord.sessionPrincipal);
  expect(parsed).toBeDefined();
  return parsed as SessionFileV1;
}

describe("sealed inspect-and-write session file heartbeat", () => {
  test("no write without a same-call inspect: an inspect failure produces no write command", async () => {
    const daemon = scripted({
      "inspect-session-container": { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon\n" },
    });
    const outcome = await heartbeat(daemon.io);
    expect(outcome.kind).toBe("unavailable");
    expect(daemon.effects).toEqual(["inspect-session-container"]);
    const error = (outcome as { kind: "unavailable"; error: RuntimeObservationError }).error;
    expect(error).toBeInstanceOf(RuntimeObservationError);
    expect(error.evidence.kind).toBe("observation-unavailable");
    expect(error.evidence.expectedIdentity).toBe(CONTAINER_ID);
    expect(error.evidence.observation).toContain("Cannot connect to the Docker daemon");

    // A Docker CLI warning beside a zero exit is not a failed observation: the
    // answer is parsed, and a healthy session stays servable.
    const noisy = scripted({
      "inspect-session-container": { status: 0, stdout: RUNNING_INSPECT, stderr: "WARNING: no swap limit support\n" },
    });
    expect((await heartbeat(noisy.io)).kind).toBe("written");
    expect(noisy.effects).toEqual(["inspect-session-container", "write-session-file"]);

    // An io layer that refuses the observation outright is a skipped beat too.
    const refusing: SessionAdmissionDockerExecutor = {
      capture: () => {
        throw new RuntimeObservationError({
          kind: "observation-unavailable",
          subject: "session",
          expectedIdentity: CONTAINER_ID,
          phase: "lifecycle-operation-budget",
          observation: "budget exhausted",
        });
      },
    };
    const refused = await heartbeat(refusing);
    expect(refused.kind).toBe("unavailable");
    expect((refused as { kind: "unavailable"; error: RuntimeObservationError }).error.evidence.observation)
      .toContain("budget exhausted");

    // Anything else from the io layer is a bug, not an outcome.
    const crashing: SessionAdmissionDockerExecutor = {
      capture: () => {
        throw new TypeError("io is broken");
      },
    };
    await expect(heartbeat(crashing)).rejects.toThrow(/io is broken/);
  });

  test("the written file carries the record's sourceIp/containerId/networkId and digests, and aliveUntil − inspectedAt === lease", async () => {
    const run = scripted();
    const outcome = await heartbeat(run.io);
    expect(outcome.kind).toBe("written");
    expect(run.effects).toEqual(["inspect-session-container", "write-session-file"]);

    const inspect = run.calls[0] as Call;
    expect(inspect.args).toEqual(["container", "inspect", CONTAINER_ID]);
    expect(inspect.options.timeout).toBe(5_000);

    const file = writtenFile(run.calls);
    expect(file.sessionKey).toBe(attachedRecord.sessionPrincipal);
    expect(file.sessionId).toBe(attachedRecord.sessionId);
    expect(file.sessionIncarnation).toBe(attachedRecord.sessionIncarnation);
    expect(file.projectId).toBe(attachedRecord.projectId);
    expect(file.sourceIp).toBe(attachedRecord.sourceIp);
    expect(file.containerId).toBe(CONTAINER_ID);
    expect(file.networkId).toBe(NETWORK_ID);
    expect(file.selectedAgentImageId).toBe(BINDINGS.selectedAgentImageId);
    expect(file.sessionAgentGenerationDigest).toBe(BINDINGS.sessionAgentGenerationDigest);
    expect(file.controlPlaneGenerationDigest).toBe(BINDINGS.controlPlaneGenerationDigest);
    expect(file.admissionContractEpoch).toBe(BINDINGS.admissionContractEpoch);
    expect(file.name).toBe(DISPLAY.name);
    expect(file.command).toBe(DISPLAY.command);
    expect(file.agentCommand).toBe(DISPLAY.agentCommand);
    expect(file.hostTty).toBe(DISPLAY.hostTty);
    expect(file.hostTermProgram).toBe(DISPLAY.hostTermProgram);
    expect(file.startedAt).toBe(DISPLAY.startedAt);
    expect(file.nonce).toMatch(/^[a-f0-9]{32}$/);
    expect(file.inspectedAt).toBe(new Date(NOW).toISOString());
    expect(Date.parse(file.aliveUntil) - Date.parse(file.inspectedAt)).toBe(LEASE_MS);
    expect((outcome as { kind: "written"; file: SessionFileV1 }).file).toEqual(file);

    // The write is the sealed publisher command, pinned to this session's path.
    const write = run.calls[1] as Call;
    expect(write.args.slice(0, 5)).toEqual(["exec", "--user", "0:0", "-i", PROXY_ID]);
    expect(write.args).toContain(sessionFilePath(attachedRecord.sessionPrincipal));
  });

  test("the lease defaults to the contract maximum and every write mints a fresh nonce", async () => {
    const first = scripted();
    await inspectAndWriteSessionFile({
      io: first.io,
      proxyId: PROXY_ID,
      record: attachedRecord,
      anchor: ANCHOR,
      expectedProject: SESSION_TEST_PROJECT,
      networkId: NETWORK_ID,
      display: DISPLAY,
      eligibilityBindings: BINDINGS,
      nowEpochMs: () => NOW,
    });
    const defaulted = writtenFile(first.calls);
    expect(Date.parse(defaulted.aliveUntil) - Date.parse(defaulted.inspectedAt))
      .toBe(SESSION_ADMISSION_LEASE_MAX_DURATION_MS);

    const second = scripted();
    await heartbeat(second.io);
    expect(writtenFile(second.calls).nonce).not.toBe(defaulted.nonce);
  });

  test("every inspected field that differs from the anchor/record is a mismatch that deletes and never writes", async () => {
    const cases: ReadonlyArray<readonly [string, (document: InspectDocument) => void, string]> = [
      ["Id", (document) => { document.Id = "1".repeat(64); }, "different session container id"],
      ["Pid", (document) => { document.State.Pid = 4243; }, "Docker process id changed"],
      ["StartedAt", (document) => { document.State.StartedAt = "2026-08-08T13:00:05.123456789Z"; }, "Docker start identity changed"],
      ["IPAddress", (document) => { network(document).IPAddress = "172.31.90.99"; }, "IPv4 address changed"],
      ["NetworkID", (document) => { network(document).NetworkID = "7".repeat(64); }, "network identity changed"],
      ["EndpointID", (document) => { network(document).EndpointID = "f".repeat(64); }, "network endpoint identity changed"],
      ["Running", (document) => { document.State.Running = false; }, "not in exact running state"],
    ];
    for (const [field, mutate, observation] of cases) {
      const run = scripted({ "inspect-session-container": ok(mutatedInspect(mutate)) });
      const outcome = await heartbeat(run.io);
      expect(outcome.kind, field).toBe("mismatch");
      expect((outcome as { kind: "mismatch"; observation: string }).observation, field).toContain(observation);
      expect((outcome as { kind: "mismatch"; deleted: boolean }).deleted, field).toBe(true);
      expect(run.effects, field).toEqual(["inspect-session-container", "delete-session-file"]);
      expect((run.calls[1] as Call).args).toContain(sessionFilePath(attachedRecord.sessionPrincipal));
    }
  });

  test("stderr `No such container: <id>` is a mismatch that deletes the file; a timeout is unavailable with no delete", async () => {
    const absent = scripted({
      "inspect-session-container": { status: 1, stdout: "", stderr: `Error: No such container: ${CONTAINER_ID}\n` },
    });
    const gone = await heartbeat(absent.io);
    expect(gone.kind).toBe("mismatch");
    expect((gone as { kind: "mismatch"; deleted: boolean }).deleted).toBe(true);
    expect(absent.effects).toEqual(["inspect-session-container", "delete-session-file"]);

    // A spawn timeout: no stderr at all, status normalized to 1.
    const timedOut = scripted({ "inspect-session-container": { status: 1, stdout: "", stderr: "" } });
    expect((await heartbeat(timedOut.io)).kind).toBe("unavailable");
    expect(timedOut.effects).toEqual(["inspect-session-container"]);

    // The absence must name this exact container: a nested diagnostic about
    // another id proves nothing about the pinned one.
    const other = scripted({
      "inspect-session-container": {
        status: 1,
        stdout: "",
        stderr: `Error response from daemon: cannot inspect: No such container: ${"9".repeat(64)}\n`,
      },
    });
    expect((await heartbeat(other.io)).kind).toBe("unavailable");
    expect(other.effects).toEqual(["inspect-session-container"]);

    const suffixed = scripted({
      "inspect-session-container": { status: 1, stdout: "", stderr: `Error: No such container: ${CONTAINER_ID}-stale\n` },
    });
    expect((await heartbeat(suffixed.io)).kind).toBe("unavailable");
    expect(suffixed.effects).toEqual(["inspect-session-container"]);
  });

  test("a malformed or truncated inspect answer is unavailable and never deletes", async () => {
    const unreadableNetworks = mutatedInspect((document) => {
      (document as Record<string, unknown>).NetworkSettings = { Networks: null };
    });
    for (const stdout of [
      "{not json",
      "[]",
      `[${RUNNING_INSPECT.slice(1, -1)},${RUNNING_INSPECT.slice(1, -1)}]`,
      unreadableNetworks,
    ]) {
      const run = scripted({ "inspect-session-container": ok(stdout) });
      const outcome = await heartbeat(run.io);
      expect(outcome.kind, stdout.slice(0, 12)).toBe("unavailable");
      expect(run.effects, stdout.slice(0, 12)).toEqual(["inspect-session-container"]);
    }
  });

  // Invariant 4's seam. The heartbeat decides "skip this beat" versus "delete
  // this session's file" by matching the liveness assertion's exact message,
  // so the set it matches on must be exactly the refusals that assertion
  // raises when it learned nothing. Set equality in both directions: a renamed
  // refusal leaves a member nothing throws, and a resolved-field refusal added
  // to the set would turn a real mismatch into a skipped beat.
  test("the unreadable-inspect set is exactly what the liveness assertion throws when it learned nothing", () => {
    const identity: SessionContainerNarrowRunningIdentity = {
      containerId: CONTAINER_ID,
      composeProject: SESSION_TEST_PROJECT.composeProject,
      networkId: NETWORK_ID,
      sourceIp: attachedRecord.sourceIp,
      ...ANCHOR,
    };
    const refusalOf = (source: string, subject = identity): string => {
      try {
        assertSessionContainerNarrowRunningInspect(source, subject);
      } catch (error) {
        return (error as Error).message;
      }
      throw new Error("the narrow liveness assertion did not refuse");
    };
    const unreadable = [
      // Never one inspection of one container.
      refusalOf(" ".repeat(SESSION_CONTAINER_INSPECT_MAX_BYTES + 1)),
      refusalOf("{not json"),
      refusalOf("[]"),
      // This host's own argument is malformed: not evidence about Docker.
      refusalOf(RUNNING_INSPECT, { ...identity, dockerPid: 0 }),
      // An answer whose network block is not even a record.
      refusalOf(mutatedInspect((document) => {
        (document as Record<string, unknown>).NetworkSettings = { Networks: null };
      })),
    ];
    expect(new Set(unreadable)).toEqual(new Set(NARROW_LIVENESS_UNREADABLE_INSPECT_MESSAGES));

    // The complement: every refusal that did resolve a field is a mismatch,
    // and a mismatch deletes.
    const resolved = [
      refusalOf(mutatedInspect((document) => { document.Id = "1".repeat(64); })),
      refusalOf(mutatedInspect((document) => { document.State.Running = false; })),
      refusalOf(mutatedInspect((document) => { document.State.Pid = 4243; })),
      refusalOf(mutatedInspect((document) => { network(document).IPAddress = "172.31.90.99"; })),
      refusalOf(mutatedInspect((document) => { network(document).EndpointID = "f".repeat(64); })),
    ];
    for (const message of resolved) {
      expect(NARROW_LIVENESS_UNREADABLE_INSPECT_MESSAGES.has(message), message).toBe(false);
    }
  });

  test("a second mismatch after the file is already gone does not throw (delete exits 0 on absent)", async () => {
    const run = scripted({ "inspect-session-container": ok(mutatedInspect((document) => { document.State.Pid = 4243; })) });
    const first = await heartbeat(run.io);
    const second = await heartbeat(run.io);
    for (const outcome of [first, second]) {
      expect(outcome.kind).toBe("mismatch");
      expect((outcome as { kind: "mismatch"; deleted: boolean }).deleted).toBe(true);
    }
    expect(run.effects).toEqual([
      "inspect-session-container",
      "delete-session-file",
      "inspect-session-container",
      "delete-session-file",
    ]);

    // A delete that cannot run at all is reported, never thrown.
    const failing = scripted({
      "inspect-session-container": ok(mutatedInspect((document) => { document.State.Pid = 4243; })),
      "delete-session-file": { status: 1, stdout: "", stderr: "unsafe session file\n" },
    });
    const outcome = await heartbeat(failing.io);
    expect(outcome.kind).toBe("mismatch");
    expect((outcome as { kind: "mismatch"; deleted: boolean }).deleted).toBe(false);
    expect(failing.effects).toEqual(["inspect-session-container", "delete-session-file"]);
  });

  test("a write failure is 'unavailable' and leaves nothing to compensate", async () => {
    const run = scripted({ "write-session-file": { status: 1, stdout: "", stderr: "unsafe session file target\n" } });
    const outcome = await heartbeat(run.io);
    expect(outcome.kind).toBe("unavailable");
    const error = (outcome as { kind: "unavailable"; error: RuntimeObservationError }).error;
    expect(error).toBeInstanceOf(RuntimeObservationError);
    expect(error.evidence.kind).toBe("observation-unavailable");
    expect(error.evidence.observation).toContain("unsafe session file target");
    expect(run.effects).toEqual(["inspect-session-container", "write-session-file"]);
  });

  test("refuses a record or lease it may not heartbeat before Docker is reached", async () => {
    const revoking = scripted();
    await expect(heartbeat(revoking.io, { record: { ...attachedRecord, state: "revoking" } })).rejects.toThrow(/revoking/);
    expect(revoking.effects).toEqual([]);

    const overLease = scripted();
    await expect(heartbeat(overLease.io, { leaseMs: SESSION_ADMISSION_LEASE_MAX_DURATION_MS + 1 }))
      .rejects.toThrow(/lease/);
    expect(overLease.effects).toEqual([]);

    const badAnchor = scripted();
    await expect(heartbeat(badAnchor.io, { anchor: { ...ANCHOR, dockerPid: 0 } })).rejects.toThrow(/anchor/);
    expect(badAnchor.effects).toEqual([]);

    // The anchor's StartedAt must satisfy the exact rule the narrow assertion
    // applies to it; otherwise the assertion would refuse this host's own
    // argument after the inspect and that refusal would read as evidence.
    for (const dockerStartedAt of ["", "not-a-timestamp", "0001-01-01T00:00:00Z", "2026-08-08 12:00:05Z"]) {
      const run = scripted();
      await expect(heartbeat(run.io, { anchor: { ...ANCHOR, dockerStartedAt } }), dockerStartedAt)
        .rejects.toThrow(/anchor/);
      expect(run.effects, dockerStartedAt).toEqual([]);
    }

    // Display fields come from the host environment, so contract violations
    // there are refused before an inspection is spent on them.
    const longName = scripted();
    await expect(heartbeat(longName.io, { display: { ...DISPLAY, name: "n".repeat(256) } }))
      .rejects.toThrow(/valid session file/);
    expect(longName.effects).toEqual([]);

    const controlCharacter = scripted();
    await expect(heartbeat(controlCharacter.io, { display: { ...DISPLAY, hostTty: "/dev/tty\u0007" } }))
      .rejects.toThrow(/valid session file/);
    expect(controlCharacter.effects).toEqual([]);

    // Bindings may never name an agent, generation, or epoch other than the
    // one this lifecycle record was admitted under.
    for (const divergent of [
      { ...BINDINGS, selectedAgentImageId: sha256Digest("other-image") },
      { ...BINDINGS, sessionAgentGenerationDigest: sha256Digest("other-generation") },
      { ...BINDINGS, controlPlaneGenerationDigest: sha256Digest("other-control-plane") },
      { ...BINDINGS, admissionContractEpoch: BINDINGS.admissionContractEpoch + 1 },
    ]) {
      const run = scripted();
      await expect(heartbeat(run.io, { eligibilityBindings: divergent })).rejects.toThrow(/bindings/);
      expect(run.effects).toEqual([]);
    }
  });

  test("inspectedAt is read before the inspect, and Docker calls are bounded whatever the caller asks for", async () => {
    // A clock that advances on every capture: an inspectedAt read after the
    // inspection would land 1 s later and shorten nothing about the proof.
    let clock = NOW;
    const run = scripted();
    const advancing: SessionAdmissionDockerExecutor = {
      capture: (command, args, options) => {
        const result = run.io.capture(command, args, options);
        clock += 1_000;
        return result;
      },
    };
    const outcome = await heartbeat(advancing, { nowEpochMs: () => clock, dockerOptions: { timeout: 60_000 } });
    expect(outcome.kind).toBe("written");
    const file = writtenFile(run.calls);
    expect(file.inspectedAt).toBe(new Date(NOW).toISOString());
    expect(Date.parse(file.aliveUntil) - Date.parse(file.inspectedAt)).toBe(LEASE_MS);

    // The sealed bounds: a caller cannot raise either one.
    expect((run.calls[0] as Call).options.timeout).toBe(5_000);
    expect((run.calls[1] as Call).options.timeout).toBe(10_000);

    const defaulted = scripted();
    await heartbeat(defaulted.io);
    expect((defaulted.calls[1] as Call).options.timeout).toBe(10_000);

    // A caller may still tighten it.
    const tightened = scripted();
    await heartbeat(tightened.io, { dockerOptions: { timeout: 2_000 } });
    expect((tightened.calls[1] as Call).options.timeout).toBe(2_000);

    // The delete on a mismatch is bounded the same way.
    const deleting = scripted({
      "inspect-session-container": ok(mutatedInspect((document) => { document.State.Pid = 4243; })),
    });
    await heartbeat(deleting.io, { dockerOptions: { timeout: 60_000 } });
    expect(deleting.effects).toEqual(["inspect-session-container", "delete-session-file"]);
    expect((deleting.calls[1] as Call).options.timeout).toBe(10_000);
  });
});

describe("heartbeat backoff", () => {
  test("backoff: 0→30000, 1→~1000, 2→~2000, 5→~16000, 6+→30000 cap, jitter within ±20 %", () => {
    expect(SESSION_HEARTBEAT_CADENCE_MS).toBe(30_000);
    const centred = (consecutiveFailures: number): number =>
      nextHeartbeatDelayMs({ consecutiveFailures, cadenceMs: SESSION_HEARTBEAT_CADENCE_MS, random: () => 0.5 });

    expect(centred(0)).toBe(30_000);
    expect(centred(1)).toBe(1_000);
    expect(centred(2)).toBe(2_000);
    expect(centred(3)).toBe(4_000);
    expect(centred(4)).toBe(8_000);
    expect(centred(5)).toBe(16_000);
    expect(centred(6)).toBe(30_000);
    expect(centred(40)).toBe(30_000);

    // The cadence itself is never jittered; every backoff step is, inside ±20 %.
    for (const random of [() => 0, () => 1, () => 0.5]) {
      expect(nextHeartbeatDelayMs({ consecutiveFailures: 0, cadenceMs: SESSION_HEARTBEAT_CADENCE_MS, random }))
        .toBe(30_000);
    }
    expect(nextHeartbeatDelayMs({ consecutiveFailures: 3, cadenceMs: SESSION_HEARTBEAT_CADENCE_MS, random: () => 0 }))
      .toBe(3_200);
    expect(nextHeartbeatDelayMs({ consecutiveFailures: 3, cadenceMs: SESSION_HEARTBEAT_CADENCE_MS, random: () => 1 }))
      .toBe(4_800);

    let seen = 0;
    for (let index = 0; index <= 100; index += 1) {
      const delay = nextHeartbeatDelayMs({
        consecutiveFailures: 7,
        cadenceMs: SESSION_HEARTBEAT_CADENCE_MS,
        random: () => index / 100,
      });
      expect(delay).toBeGreaterThanOrEqual(24_000);
      expect(delay).toBeLessThanOrEqual(36_000);
      seen += 1;
    }
    expect(seen).toBe(101);

    // Real randomness stays inside the same envelope.
    for (let index = 0; index < 200; index += 1) {
      const delay = nextHeartbeatDelayMs({ consecutiveFailures: 2, cadenceMs: SESSION_HEARTBEAT_CADENCE_MS });
      expect(delay).toBeGreaterThanOrEqual(1_600);
      expect(delay).toBeLessThanOrEqual(2_400);
    }
  });
});

describe("only the heartbeat mints a session file", () => {
  test("sessionFileWriteCommand is referenced by the publisher that defines it and this heartbeat alone", () => {
    const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const files: string[] = [];
    const walk = (directory: string): void => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory()) walk(entryPath);
        else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) files.push(entryPath);
      }
    };
    walk(sourceRoot);
    expect(files.length).toBeGreaterThan(50);
    const referencing = files
      .filter((file) => /\bsessionFileWriteCommand\b/.test(fs.readFileSync(file, "utf8")))
      .map((file) => path.relative(sourceRoot, file))
      .sort();
    expect(referencing).toEqual([
      "runtime/session-file-heartbeat.ts",
      "runtime/session-file-publisher.ts",
    ]);
  });
});
