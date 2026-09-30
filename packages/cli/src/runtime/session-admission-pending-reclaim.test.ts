// Startup's reclaim of an interrupted session teardown.
//
// The state under test is what a Docker daemon that died under a live session
// leaves: a record its owner stamped terminal, an owner that has since exited,
// a session container and a proxy that Docker stopped. The reclaim may finish
// that teardown only on Docker's own proof, and every negative case here
// asserts the record — the session's address reservation — is still on disk.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";

import {
  publishControlPlaneMaterializationV2,
  selectEffectiveControlPlaneV2,
} from "./component-state-v2.ts";
import {
  reclaimPendingSessionAdmissions,
  type PendingSessionAdmissionReclaimInput,
} from "./session-admission-pending-reclaim.ts";
import {
  controlPlaneMaterializationFixture,
  effectiveControlPlaneFixture,
  SESSION_TEST_PROJECT,
  sessionContainerRecordFixture,
  sessionGenerationFixture,
} from "./session-container.test-harness.ts";
import {
  listSessionContainerRecordsV2,
  writeSessionContainerRecordV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import { readSessionHostStatus, writeSessionHostStatus } from "./session-host-status.ts";
import type { ProjectLifecycleLock } from "./sessions.ts";
import type { CaptureResult } from "./types.ts";

const CONTAINER_ID = "c".repeat(64);
const OTHER_PROXY_ID = "f".repeat(64);
const SELECTION = effectiveControlPlaneFixture({ target: sessionGenerationFixture().target });
const PROXY_ID = SELECTION.proxyContainerId;
const NETWORK_ID = SELECTION.networkIds.agentInternal;

const RECORDED_BOOT = "linux:11111111-1111-4111-8111-111111111111";
const CURRENT_BOOT = "linux:22222222-2222-4222-8222-222222222222";
const OWN_START = "linux:424242";

// Owner liveness is decided by host identity, so each shape is a record plus
// the environment it is judged in.
const OWNERS = {
  // Recorded on a previous boot: no process survives a reboot.
  dead: { overrides: { hostBootId: RECORDED_BOOT }, env: { RUNFREE_TEST_HOST_BOOT_ID: CURRENT_BOOT } },
  // This very process, same boot, same start: provably alive.
  alive: {
    overrides: { hostPid: process.pid, hostBootId: CURRENT_BOOT, hostProcessStart: OWN_START },
    env: { RUNFREE_TEST_HOST_BOOT_ID: CURRENT_BOOT, RUNFREE_TEST_HOST_PROCESS_START: OWN_START },
  },
  // A live PID with no boot identity to compare: cannot be proved either way.
  unknown: { overrides: { hostPid: process.pid }, env: {} },
} as const;

type OwnerShape = keyof typeof OWNERS;

type ContainerAnswer = "absent" | "exited" | "running" | "unavailable" | "foreign";
type ProxyAnswer = "absent" | "exited" | "running" | "unavailable";

const OK: CaptureResult = { status: 0, stdout: "", stderr: "" };
const DAEMON_DOWN: CaptureResult = {
  status: 1,
  stdout: "",
  stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
};

function noSuch(reference: string): CaptureResult {
  return { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${reference}` };
}

function containerInspect(id: string, status: "exited" | "running", labels: Record<string, string>): CaptureResult {
  return {
    status: 0,
    stdout: JSON.stringify([{
      Id: id,
      Name: "/runfree-session",
      Config: { Labels: labels },
      State: { Running: status === "running", Status: status },
    }]),
    stderr: "",
  };
}

const SESSION_LABELS = {
  "io.runfree.project-id": SESSION_TEST_PROJECT.projectId,
  "io.runfree.container-role": "session-agent",
};
const PROXY_LABELS = {
  "io.runfree.project-id": SESSION_TEST_PROJECT.projectId,
  "io.runfree.container-role": "proxy",
  "com.docker.compose.project": SESSION_TEST_PROJECT.composeProject,
  "com.docker.compose.service": "proxy",
};

type Scenario = {
  owner: OwnerShape;
  /** What the session container inspect answers, in order; the last repeats. */
  container: ContainerAnswer[];
  proxy: ProxyAnswer;
  otherRunningProxy?: boolean;
  deleteFails?: boolean;
  removeFails?: boolean;
  bound?: boolean;
  stamped?: boolean;
};

type Harness = {
  stateDir: string;
  record: SessionContainerRecordV2;
  events: string[];
  input: PendingSessionAdmissionReclaimInput;
  records: () => readonly SessionContainerRecordV2[];
};

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-pending-reclaim-"));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

function build(scenario: Scenario): Harness {
  const target = sessionGenerationFixture().target;
  publishControlPlaneMaterializationV2(stateDir, controlPlaneMaterializationFixture({ target }));
  selectEffectiveControlPlaneV2(stateDir, SELECTION);
  const owner = OWNERS[scenario.owner];
  const record = sessionContainerRecordFixture({
    target,
    ...(scenario.bound === false ? {} : { containerId: CONTAINER_ID }),
    overrides: { ...owner.overrides },
  });
  writeSessionContainerRecordV2(stateDir, SESSION_TEST_PROJECT, record);
  if (scenario.stamped !== false) {
    writeSessionHostStatus(stateDir, {
      v: 1,
      sessionId: record.sessionId,
      lastHeartbeatAt: "2026-09-29T20:00:00.000Z",
      aliveUntil: "2026-09-29T20:00:00.000Z",
      served: "unknown",
      terminal: "revoking",
    });
  }

  const events: string[] = [];
  const containerAnswers = [...scenario.container];
  const reference = record.containerId ?? record.containerName;
  const answerContainer = (): CaptureResult => {
    const answer = containerAnswers.length > 1 ? containerAnswers.shift() : containerAnswers[0];
    switch (answer) {
      case "absent": return noSuch(reference);
      case "exited": return containerInspect(CONTAINER_ID, "exited", SESSION_LABELS);
      case "running": return containerInspect(CONTAINER_ID, "running", SESSION_LABELS);
      case "foreign": return containerInspect(CONTAINER_ID, "exited", { "io.runfree.project-id": "ffffffffffff" });
      default: return DAEMON_DOWN;
    }
  };
  const io = {
    capture(command: string, args: string[]): CaptureResult {
      expect(command).toBe("docker");
      if (args[0] === "container" && args[1] === "inspect" && args[2] === reference) {
        events.push("inspect-session");
        return answerContainer();
      }
      if (args[0] === "ps" && args.includes(`id=${PROXY_ID}`)) {
        events.push("inventory-proxy");
        if (scenario.proxy === "unavailable") return DAEMON_DOWN;
        return { ...OK, stdout: scenario.proxy === "absent" ? "" : `${PROXY_ID}\n` };
      }
      if (args[0] === "container" && args[1] === "inspect" && args[2] === PROXY_ID) {
        events.push("inspect-proxy");
        return {
          status: 0,
          stdout: JSON.stringify([{
            Id: PROXY_ID,
            Config: { Labels: PROXY_LABELS },
            State: { Running: scenario.proxy === "running", Status: scenario.proxy === "running" ? "running" : "exited" },
          }]),
          stderr: "",
        };
      }
      if (args[0] === "ps" && args.includes("label=com.docker.compose.service=proxy")) {
        events.push("list-running-proxies");
        const running = [
          ...(scenario.proxy === "running" ? [PROXY_ID] : []),
          ...(scenario.otherRunningProxy ? [OTHER_PROXY_ID] : []),
        ];
        return { ...OK, stdout: running.map((id) => `${id}\n`).join("") };
      }
      if (args[0] === "exec" && args.some((arg) => arg.startsWith(`${SESSION_FILES_DIR}/`))) {
        events.push("delete-session-file");
        return scenario.deleteFails ? DAEMON_DOWN : OK;
      }
      if (args[0] === "network" && args[1] === "disconnect") {
        expect(args.slice(2)).toEqual([NETWORK_ID, CONTAINER_ID]);
        events.push("disconnect");
        return OK;
      }
      if (args[0] === "container" && args[1] === "stop") {
        events.push("stop");
        return OK;
      }
      if (args[0] === "container" && args[1] === "rm") {
        expect(args.at(-1)).toBe(CONTAINER_ID);
        events.push("remove");
        return scenario.removeFails ? DAEMON_DOWN : OK;
      }
      throw new Error(`unexpected docker ${args.join(" ")}`);
    },
  };
  const lifecycleLock: ProjectLifecycleLock = {
    ownerToken: "test-owner",
    assertHeld: () => { events.push("lock"); },
    release: () => undefined,
  };
  return {
    stateDir,
    record,
    events,
    records: () => listSessionContainerRecordsV2(stateDir, SESSION_TEST_PROJECT),
    input: {
      stateDir,
      expectedProject: SESSION_TEST_PROJECT,
      io,
      lifecycleLock,
      env: { RUNFREE_TEST_FAKE_DOCKER: "1", ...owner.env },
      nowEpochMs: Date.parse("2026-09-30T08:00:00.000Z"),
    },
  };
}

function dockerEffects(events: readonly string[]): string[] {
  return events.filter((event) => event !== "lock");
}

describe("the daemon-death residue is reclaimed on Docker's proof", () => {
  test("a stopped proxy and an absent session container: the record is dropped without an exec", () => {
    const harness = build({ owner: "dead", container: ["absent"], proxy: "exited" });

    const result = reclaimPendingSessionAdmissions(harness.input);

    expect(result).toEqual({ kind: "reclaimed", sessionIds: [harness.record.sessionId] });
    expect(harness.records()).toEqual([]);
    expect(readSessionHostStatus(stateDir, harness.record.sessionId)).toBeUndefined();
    // A stopped proxy holds no tmpfs to exec into: the file is proved gone,
    // never deleted.
    expect(harness.events).not.toContain("delete-session-file");
  });

  test("a stopped session container is removed, and absence is proved before the record goes", () => {
    const harness = build({ owner: "dead", container: ["exited", "absent"], proxy: "exited" });
    let recordsWhenAbsenceProved: number | undefined;
    const capture = harness.input.io.capture.bind(harness.input.io);
    const input: PendingSessionAdmissionReclaimInput = {
      ...harness.input,
      io: {
        capture(command, args, options) {
          const answer = capture(command, args, options);
          if (args[1] === "inspect" && args[2] === CONTAINER_ID && answer.status !== 0) {
            recordsWhenAbsenceProved = harness.records().length;
          }
          return answer;
        },
      },
    };

    expect(reclaimPendingSessionAdmissions(input).kind).toBe("reclaimed");

    expect(dockerEffects(harness.events)).toEqual([
      "inspect-session",
      // The pre-check: selected proxy, then every running project proxy.
      "inventory-proxy", "inspect-proxy", "list-running-proxies",
      // Step 1 re-proves the proxy at the step itself.
      "inventory-proxy", "inspect-proxy", "list-running-proxies",
      "disconnect", "stop", "remove",
      // Step 4: absence, proved while the record still exists.
      "inspect-session",
    ]);
    expect(recordsWhenAbsenceProved).toBe(1);
    expect(harness.records()).toEqual([]);
  });

  test("a running selected proxy gets the ordinary file delete first", () => {
    const harness = build({ owner: "dead", container: ["exited", "absent"], proxy: "running" });

    expect(reclaimPendingSessionAdmissions(harness.input).kind).toBe("reclaimed");

    const effects = dockerEffects(harness.events);
    expect(effects.indexOf("delete-session-file")).toBeGreaterThan(-1);
    expect(effects.indexOf("delete-session-file")).toBeLessThan(effects.indexOf("remove"));
    expect(harness.records()).toEqual([]);
  });

  test("a stale allocation that never bound a container is dropped once its name is proved free", () => {
    const harness = build({ owner: "dead", container: ["absent"], proxy: "absent", bound: false, stamped: false });

    expect(reclaimPendingSessionAdmissions(harness.input).kind).toBe("reclaimed");
    expect(harness.records()).toEqual([]);
    expect(harness.events).not.toContain("remove");
  });

  test("nothing pending is nothing to do, and touches no Docker state", () => {
    const harness = build({ owner: "dead", container: ["absent"], proxy: "exited", stamped: false });

    expect(reclaimPendingSessionAdmissions(harness.input)).toEqual({ kind: "none" });
    expect(dockerEffects(harness.events)).toEqual([]);
    expect(harness.records()).toHaveLength(1);
  });
});

describe("no record is dropped before Docker proves it may be", () => {
  test.each<[string, Scenario, string]>([
    ["the session container still runs", { owner: "dead", container: ["running"], proxy: "exited" }, "is still running"],
    ["Docker cannot observe the session container", { owner: "dead", container: ["unavailable"], proxy: "exited" }, "start Docker"],
    ["Docker cannot observe the proxy", { owner: "dead", container: ["absent"], proxy: "unavailable" }, "start Docker"],
    ["another proxy for the project is running", { owner: "dead", container: ["absent"], proxy: "exited", otherRunningProxy: true }, "other than the selected one"],
    ["the container under the record's id is not this project's", { owner: "dead", container: ["foreign"], proxy: "exited" }, "not this project's session container"],
    ["the owner is still running its own teardown", { owner: "alive", container: ["absent"], proxy: "exited" }, "still finishing its teardown"],
    ["the owner cannot be proved gone", { owner: "unknown", container: ["absent"], proxy: "exited" }, "runfree destroy --force"],
    ["the running proxy refuses the file delete", { owner: "dead", container: ["exited"], proxy: "running", deleteFails: true }, "could not be removed from the proxy"],
    ["the container survives its removal", { owner: "dead", container: ["exited"], proxy: "exited" }, "still present after removal"],
    ["Docker goes away before absence is proved", { owner: "dead", container: ["exited", "unavailable"], proxy: "exited" }, "start Docker"],
  ])("refuses when %s", (_name, scenario, reason) => {
    const harness = build(scenario);

    const result = reclaimPendingSessionAdmissions(harness.input);

    expect(result.kind).toBe("refused");
    if (result.kind !== "refused") return;
    expect(result.sessionIds).toEqual([harness.record.sessionId]);
    expect(result.reasons.join("\n")).toContain(reason);
    expect(result.reasons.join("\n")).toContain(harness.record.sessionId);
    // The record is the address reservation: it is exactly what it was.
    expect(harness.records()).toEqual([harness.record]);
    expect(readSessionHostStatus(stateDir, harness.record.sessionId)?.terminal).toBe("revoking");
  });

  test("a refused owner is decided before any Docker call", () => {
    const harness = build({ owner: "alive", container: ["absent"], proxy: "exited" });

    expect(reclaimPendingSessionAdmissions(harness.input).kind).toBe("refused");
    expect(dockerEffects(harness.events)).toEqual([]);
  });

  test("a running session container is refused before any effect", () => {
    const harness = build({ owner: "dead", container: ["running"], proxy: "running" });

    expect(reclaimPendingSessionAdmissions(harness.input).kind).toBe("refused");
    expect(dockerEffects(harness.events)).toEqual(["inspect-session"]);
  });

  test("every remedy it prints is a real command", () => {
    const harness = build({ owner: "unknown", container: ["absent"], proxy: "exited" });

    const result = reclaimPendingSessionAdmissions(harness.input);

    expect(result.kind).toBe("refused");
    if (result.kind !== "refused") return;
    for (const command of result.reasons.join("\n").match(/`runfree [^`]+`/gu) ?? []) {
      expect(["`runfree up`", "`runfree rebuild`", "`runfree destroy --force`", "`runfree sessions`"]).toContain(command);
    }
  });

  test("no lock, no pass", () => {
    const harness = build({ owner: "dead", container: ["absent"], proxy: "exited" });
    const input = {
      ...harness.input,
      lifecycleLock: { ...harness.input.lifecycleLock, assertHeld: () => { throw new Error("lock lost"); } },
    };

    expect(() => reclaimPendingSessionAdmissions(input)).toThrow("lock lost");
    expect(harness.records()).toHaveLength(1);
  });
});
