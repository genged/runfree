// The ordered teardown's proof: the session file goes first, the host record
// goes last, and a delete this host could not perform stops everything after
// it. Every effect is observed as the exact argv Docker would have run, so a
// reordering (or a step that quietly skips its lock assertion) fails here
// rather than in a live tranche.

import { describe, expect, test, vi } from "vitest";

import { SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";

import { RuntimeObservationError } from "./observation-failure.ts";
import { SESSION_CONTAINER_STOP_SECONDS } from "./session-container-contract.ts";
import {
  sessionContainerCreatePlanFixture,
  SESSION_TEST_PROJECT,
} from "./session-container.test-harness.ts";
import {
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2,
  transitionProvisioningRunningSessionContainerToAttachedV2,
  type SessionContainerRecordV2,
} from "./session-containers.ts";
import type { SessionAdmissionDockerExecutor } from "./session-file-publisher.ts";
import {
  proveSessionContainerExited,
  teardownSessionRecord,
  UNCERTAIN_SESSION_COMPLETION,
  type SessionContainerExitProof,
  type SessionFileTeardownInput,
  type SessionTeardownCompletion,
} from "./session-file-teardown.ts";
import type { CaptureResult } from "./types.ts";

const CONTAINER_ID = "c".repeat(64);
const NETWORK_ID = "d".repeat(64);
const PROXY_ID = "e".repeat(64);

const plan = sessionContainerCreatePlanFixture({ containerId: CONTAINER_ID });
// The state teardown actually meets under this source: the record stays
// `attached` until its file is gone, so nothing here may depend on a
// `revoking` transition.
const RECORD = transitionProvisioningRunningSessionContainerToAttachedV2(
  transitionBoundAllocatedSessionContainerToProvisioningRunningV2(plan.record, {
    admittedAt: "2026-08-08T12:00:01.000Z",
    leaseGeneration: "e".repeat(32),
    leaseExpiresAt: "2026-08-08T12:05:00.000Z",
  }),
);
const SESSION_KEY = RECORD.sessionPrincipal;

const OK: CaptureResult = { status: 0, stdout: "", stderr: "" };

type Effect = "delete-session-file" | "list-callback-ingress" | "disconnect" | "stop" | "remove" | "unknown";

/**
 * The effect one captured argv performs.
 *
 * The session-file delete runs as a pinned `docker exec … node -e <script>
 * <path>`, whose argv is thousands of characters of inlined script, so it is
 * recognised by what it targets rather than by its whole text.
 */
function effectOf(args: readonly string[]): Effect {
  if (args[0] === "exec" && args[6] === "-e") {
    return args[8]?.startsWith(`${SESSION_FILES_DIR}/`) ? "delete-session-file" : "unknown";
  }
  if (args[0] === "ps" && args.includes("label=io.runfree.ingress-purpose=mcp-callback")) return "list-callback-ingress";
  if (args[0] === "network" && args[1] === "disconnect") return "disconnect";
  if (args[0] === "container" && args[1] === "stop") return "stop";
  if (args[0] === "container" && args[1] === "rm") return "remove";
  return "unknown";
}

type Harness = Readonly<{
  events: string[];
  argv: string[][];
  effects: () => Effect[];
  input: (overrides?: Partial<SessionFileTeardownInput>) => SessionFileTeardownInput;
  removed: () => number;
}>;

/**
 * One teardown, with every injected helper and every Docker answer recorded in
 * a single ordered event list — the only way to prove that the lock assertion
 * really sits before each step rather than merely being called often enough.
 */
function harness(options: {
  answers?: Partial<Record<Effect, CaptureResult>>;
  record?: SessionContainerRecordV2;
  removeRecord?: () => boolean;
  lock?: () => void;
  completion?: SessionTeardownCompletion;
} = {}): Harness {
  const events: string[] = [];
  const argv: string[][] = [];
  let removals = 0;
  const io: SessionAdmissionDockerExecutor = {
    capture: vi.fn((_executable, args) => {
      const effect = effectOf(args);
      events.push(effect);
      argv.push([...args]);
      return { ...(options.answers?.[effect] ?? OK) };
    }),
  };
  return Object.freeze({
    events,
    argv,
    effects: () => events.filter((event): event is Effect => event !== "lock"
      && event !== "mark-terminal"
      && event !== "clear-stamp"
      && event !== "remove-record"),
    removed: () => removals,
    input: (overrides = {}) => ({
      io,
      proxyId: PROXY_ID,
      record: options.record ?? RECORD,
      expectedProject: SESSION_TEST_PROJECT,
      networkId: NETWORK_ID,
      lock: options.lock ?? (() => { events.push("lock"); }),
      markTerminal: () => { events.push("mark-terminal"); },
      clearStamp: () => { events.push("clear-stamp"); },
      removeRecord: options.removeRecord ?? (() => {
        events.push("remove-record");
        removals += 1;
        return true;
      }),
      completion: () => options.completion ?? UNCERTAIN_SESSION_COMPLETION,
      ...overrides,
    }),
  });
}

describe("ordered session-file teardown", () => {
  test("deletes the file first, then disconnects, stops, and removes, and drops the record last", () => {
    const fixture = harness();

    expect(teardownSessionRecord(fixture.input())).toEqual({ completed: true });

    // Invariant 3, as an ordering: the address the record reserves is released
    // only after the proxy has been told, by the file's absence, that this
    // session may no longer be served.
    expect(fixture.events).toEqual([
      "lock",
      "mark-terminal",
      "lock",
      "delete-session-file",
      "lock",
      "list-callback-ingress",
      "lock",
      "disconnect",
      "lock",
      "stop",
      "lock",
      "remove",
      "lock",
      "remove-record",
      "clear-stamp",
    ]);
    expect(fixture.argv[1]?.slice(0, 2)).toEqual(["ps", "-a"]);
    expect(fixture.argv[2]).toEqual(["network", "disconnect", NETWORK_ID, CONTAINER_ID]);
    expect(fixture.argv[3]).toEqual([
      "container",
      "stop",
      "--time",
      String(SESSION_CONTAINER_STOP_SECONDS),
      CONTAINER_ID,
    ]);
    expect(fixture.argv[4]).toEqual(["container", "rm", "--force", CONTAINER_ID]);
    // The delete names this session's file and nothing else.
    expect(fixture.argv[0]?.[8]).toBe(`${SESSION_FILES_DIR}/${SESSION_KEY}.json`);
    expect(fixture.argv[0]?.[4]).toBe(PROXY_ID);
    expect(fixture.removed()).toBe(1);
  });

  test("a delete this host could not perform stops the sequence and keeps the record", () => {
    const fixture = harness({
      answers: { "delete-session-file": { status: 1, stdout: "", stderr: "Error: No such container: proxy" } },
    });

    const result = teardownSessionRecord(fixture.input());

    expect(result.completed).toBe(false);
    expect(result).toMatchObject({ blockedAt: "delete-session-file" });
    expect((result as { error: unknown }).error).toBeInstanceOf(RuntimeObservationError);
    // Nothing past the delete ran: the container keeps its endpoint and the
    // record keeps the address reserved, because a file this host could not
    // remove may still be serving the session.
    expect(fixture.effects()).toEqual(["delete-session-file"]);
    expect(fixture.events).not.toContain("remove-record");
    expect(fixture.events).not.toContain("clear-stamp");
    expect(fixture.removed()).toBe(0);
  });

  // Startup's reclaim of an interrupted teardown proves the file gone from a
  // stopped or absent proxy instead of exec'ing into it. The proof takes the
  // delete's place in the order, under the same lock assertion, and a proof
  // that fails blocks exactly like a failed delete.
  test("a caller-supplied file removal takes the delete's place in the order", () => {
    const fixture = harness();

    expect(teardownSessionRecord(fixture.input({
      removeSessionFile: () => { fixture.events.push("prove-file-gone"); },
    }))).toEqual({ completed: true });

    expect(fixture.events.slice(0, 4)).toEqual(["lock", "mark-terminal", "lock", "prove-file-gone"]);
    expect(fixture.effects()).not.toContain("delete-session-file");
    expect(fixture.events.at(-2)).toBe("remove-record");
  });

  test("a caller-supplied file removal that throws keeps the record", () => {
    const fixture = harness();
    const refusal = new Error("the selected proxy started during reclaim");

    const result = teardownSessionRecord(fixture.input({
      removeSessionFile: () => { throw refusal; },
    }));

    expect(result).toEqual({ completed: false, blockedAt: "delete-session-file", error: refusal });
    expect(fixture.effects()).toEqual([]);
    expect(fixture.removed()).toBe(0);
  });

  test("a rerun after a blocked delete completes the whole sequence", () => {
    const blocked: CaptureResult = { status: 1, stdout: "", stderr: "proxy exec failed" };
    let attempt = 0;
    const events: string[] = [];
    let removals = 0;
    const io: SessionAdmissionDockerExecutor = {
      capture: vi.fn((_executable, args) => {
        const effect = effectOf(args);
        events.push(effect);
        if (effect !== "delete-session-file") return { ...OK };
        attempt += 1;
        return attempt === 1 ? { ...blocked } : { ...OK };
      }),
    };
    const input: SessionFileTeardownInput = {
      io,
      proxyId: PROXY_ID,
      record: RECORD,
      expectedProject: SESSION_TEST_PROJECT,
      networkId: NETWORK_ID,
      lock: () => {},
      markTerminal: () => {},
      clearStamp: () => { events.push("clear-stamp"); },
      removeRecord: () => { removals += 1; return true; },
      completion: () => UNCERTAIN_SESSION_COMPLETION,
    };

    expect(teardownSessionRecord(input).completed).toBe(false);
    expect(events).toEqual(["delete-session-file"]);
    expect(removals).toBe(0);

    // The reclamation for the refusal above: the same call, once the proxy can
    // be reached again, finishes the steps it was not allowed to start.
    expect(teardownSessionRecord(input)).toEqual({ completed: true });
    expect(events).toEqual([
      "delete-session-file",
      "delete-session-file",
      "list-callback-ingress",
      "disconnect",
      "stop",
      "remove",
      "clear-stamp",
    ]);
    expect(removals).toBe(1);
  });

  test("running the whole sequence twice over objects that are already gone completes both times", () => {
    // The second run's Docker answers: the file is gone (the script exits 0 on
    // an absent path) and the container has been removed.
    const absent = { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${CONTAINER_ID}` };
    const fixture = harness({
      answers: { disconnect: absent, stop: absent, remove: absent },
      removeRecord: () => false,
    });

    expect(teardownSessionRecord(fixture.input())).toEqual({ completed: true });
    expect(teardownSessionRecord(fixture.input())).toEqual({ completed: true });
    expect(fixture.effects()).toEqual([
      "delete-session-file",
      "list-callback-ingress",
      "disconnect",
      "stop",
      "remove",
      "delete-session-file",
      "list-callback-ingress",
      "disconnect",
      "stop",
      "remove",
    ]);
  });

  test("a lock that has been lost stops the sequence at that step, at every one of the seven lock sites", () => {
    // Index n: the (n+1)th lock assertion is the first that fails. The seven
    // sites guard, in order: the terminal stamp, the file delete, the callback
    // ingress removal, the disconnect, the stop, the removal, and the record
    // removal (todo 37 item 1: the stamp and record sites were the two the
    // earlier table did not reach).
    for (const [index, remaining, stamped] of [
      [0, [] as Effect[], false],
      [1, [] as Effect[], true],
      [2, ["delete-session-file"] as Effect[], true],
      [3, ["delete-session-file", "list-callback-ingress"] as Effect[], true],
      [4, ["delete-session-file", "list-callback-ingress", "disconnect"] as Effect[], true],
      [5, ["delete-session-file", "list-callback-ingress", "disconnect", "stop"] as Effect[], true],
      [6, ["delete-session-file", "list-callback-ingress", "disconnect", "stop", "remove"] as Effect[], true],
    ] as const) {
      let calls = 0;
      const fixture = harness({
        lock: () => {
          calls += 1;
          if (calls > index) throw new Error("project lifecycle lock is not held");
        },
      });

      expect(() => teardownSessionRecord(fixture.input())).toThrow("project lifecycle lock is not held");

      expect(fixture.effects()).toEqual(remaining);
      expect(fixture.events.includes("mark-terminal")).toBe(stamped);
      expect(fixture.events).not.toContain("remove-record");
      expect(fixture.events).not.toContain("clear-stamp");
    }
  });

  test("refuses a record this teardown holds no exact authority over, before any effect", () => {
    for (const [overrides, message] of [
      [{ expectedProject: { projectId: "ffffffffffff", composeProject: "runfree-ffffffffffff" } }, "different project"],
      [{ networkId: "not-a-network" }, "exact Docker object id"],
      [{ record: { ...RECORD, containerId: undefined } as SessionContainerRecordV2 }, "exact container id"],
    ] as const) {
      const fixture = harness();

      expect(() => teardownSessionRecord(fixture.input(overrides))).toThrow(message);

      expect(fixture.events).toEqual([]);
    }
  });

  test("tolerates a refused disconnect or stop but never drops the record over a container it could not remove", () => {
    const refused: CaptureResult = { status: 1, stdout: "", stderr: "Error response from daemon: something else" };
    const tolerated = harness({ answers: { disconnect: refused, stop: refused } });

    // The file is already gone, so the session has no authority left whatever
    // the endpoint says, and `rm --force` takes the endpoint with the container.
    expect(teardownSessionRecord(tolerated.input())).toEqual({ completed: true });
    expect(tolerated.removed()).toBe(1);

    const wedged = harness({ answers: { remove: refused } });

    expect(() => teardownSessionRecord(wedged.input())).toThrow("Docker failed to remove");

    expect(wedged.events).not.toContain("remove-record");
    expect(wedged.events).not.toContain("clear-stamp");
    expect(wedged.removed()).toBe(0);
  });

  test("an unprovable callback route stops the sequence before the container and keeps the record", () => {
    // The refusal: the forwarder inventory cannot be read, so a route to this
    // record's address may survive. Nothing past it runs — above all not the
    // record removal that would release the address to a peer.
    const unreadable = harness({
      answers: { "list-callback-ingress": { status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" } },
    });

    expect(() => teardownSessionRecord(unreadable.input())).toThrow("could not list MCP OAuth callback forwarders");
    expect(unreadable.effects()).toEqual(["delete-session-file", "list-callback-ingress"]);
    expect(unreadable.events).not.toContain("remove-record");
    expect(unreadable.removed()).toBe(0);

    // The reclamation: the same call, once Docker answers, finishes the sequence.
    const recovered = harness();
    expect(teardownSessionRecord(recovered.input())).toEqual({ completed: true });
    expect(recovered.removed()).toBe(1);
  });

  test("removes this session's callback forwarder by exact id before the record", () => {
    const forwarderId = "f".repeat(64);
    const events: string[] = [];
    const forwarder = {
      Id: forwarderId,
      Image: `sha256:${"a".repeat(64)}`,
      Name: "/runfree-ingress-mcp-callback-x-47200",
      State: { Running: true },
      Config: {
        Env: [
          "INGRESS_HOST_PORT=47200",
          `INGRESS_TARGET=${RECORD.sourceIp}`,
          "INGRESS_TARGET_PORT=47200",
          `RUNFREE_CALLBACK_SESSION_ID=${RECORD.sessionId}`,
          `RUNFREE_CALLBACK_SESSION_CONTAINER=${CONTAINER_ID}`,
        ],
        Labels: {
          "io.runfree.project-id": SESSION_TEST_PROJECT.projectId,
          "io.runfree.container-role": "ingress-forwarder",
          "io.runfree.ingress-purpose": "mcp-callback",
        },
      },
    };
    const io: SessionAdmissionDockerExecutor = {
      capture: vi.fn((_executable, args) => {
        if (args[0] === "ps") return { status: 0, stdout: `${forwarderId}\n`, stderr: "" };
        if (args[0] === "container" && args[1] === "inspect") return { status: 0, stdout: JSON.stringify([forwarder]), stderr: "" };
        if (args[0] === "image") return { status: 0, stdout: `sha256:${"a".repeat(64)}\n`, stderr: "" };
        if (args[0] === "rm") events.push(`rm:${args[2]}`);
        return { ...OK };
      }),
    };
    const input: SessionFileTeardownInput = {
      io,
      proxyId: PROXY_ID,
      record: RECORD,
      expectedProject: SESSION_TEST_PROJECT,
      networkId: NETWORK_ID,
      lock: () => {},
      markTerminal: () => {},
      clearStamp: () => {},
      removeRecord: () => { events.push("remove-record"); return true; },
      completion: () => UNCERTAIN_SESSION_COMPLETION,
    };

    expect(teardownSessionRecord(input)).toEqual({ completed: true });
    expect(events).toEqual([`rm:${forwarderId}`, "remove-record"]);
  });
});

const STARTED_AT = "2026-08-08T12:00:00.500000000Z";

function exitedInspect(overrides: {
  id?: string;
  running?: boolean;
  restarting?: boolean;
  paused?: boolean;
  status?: string;
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
  restartPolicy?: string;
  extraObject?: boolean;
} = {}): string {
  const container = {
    Id: overrides.id ?? CONTAINER_ID,
    State: {
      Status: overrides.status ?? "exited",
      Running: overrides.running ?? false,
      Paused: overrides.paused ?? false,
      Restarting: overrides.restarting ?? false,
      Pid: 0,
      ExitCode: overrides.exitCode ?? 0,
      StartedAt: overrides.startedAt ?? STARTED_AT,
      FinishedAt: overrides.finishedAt ?? "2026-08-08T12:05:00.000000000Z",
    },
    HostConfig: { RestartPolicy: { Name: overrides.restartPolicy ?? "no", MaximumRetryCount: 0 } },
  };
  return JSON.stringify(overrides.extraObject ? [container, container] : [container]);
}

function exitedCompletion(exitCode = 0): SessionTeardownCompletion {
  const proof = proveSessionContainerExited(exitedInspect({ exitCode }), {
    containerId: CONTAINER_ID,
    startedAt: STARTED_AT,
    exitCode,
  });
  if (!proof) throw new Error("fixture inspection must prove the exit");
  return { kind: "exited", proof };
}

describe("fast teardown after a proved exit (sub-second launch plan Task 8)", () => {
  test("a proved exit deletes the file, removes the callback ingress and then the container, and drops the record last: no disconnect, no stop", () => {
    const fixture = harness({ completion: exitedCompletion() });

    expect(teardownSessionRecord(fixture.input())).toEqual({ completed: true });

    // The callback forwarder outlives the container, so the short path still
    // proves it gone after the file and before the record releases the address.
    expect(fixture.events).toEqual([
      "lock",
      "mark-terminal",
      "lock",
      "delete-session-file",
      "lock",
      "list-callback-ingress",
      "lock",
      "remove",
      "lock",
      "remove-record",
      "clear-stamp",
    ]);
    expect(fixture.argv.at(-1)).toEqual(["container", "rm", "--force", CONTAINER_ID]);
    expect(fixture.removed()).toBe(1);
  });

  test("the proof is refused for every condition it does not meet", () => {
    const expected = { containerId: CONTAINER_ID, startedAt: STARTED_AT, exitCode: 0 };
    expect(proveSessionContainerExited(exitedInspect(), expected)).toBeDefined();
    for (const [label, stdout, want] of [
      ["still running", exitedInspect({ running: true, status: "running" }), expected],
      ["restarting", exitedInspect({ restarting: true }), expected],
      ["paused", exitedInspect({ paused: true }), expected],
      ["created, never ran", exitedInspect({ status: "created" }), expected],
      ["another container", exitedInspect({ id: "f".repeat(64) }), expected],
      ["another incarnation", exitedInspect({ startedAt: "2026-08-08T12:03:00.000000000Z" }), expected],
      ["finished before it started", exitedInspect({ finishedAt: "2026-08-08T11:00:00.000000000Z" }), expected],
      ["a different exit code", exitedInspect({ exitCode: 1 }), expected],
      ["a restart policy", exitedInspect({ restartPolicy: "on-failure" }), expected],
      ["two objects", exitedInspect({ extraObject: true }), expected],
      ["malformed", "{", expected],
      ["an exit code out of range", exitedInspect(), { ...expected, exitCode: 256 }],
    ] as const) {
      expect(proveSessionContainerExited(stdout, want), label).toBeUndefined();
    }
  });

  test("a forged proof, or a proof for another container, keeps the full sequence", () => {
    const forged = { kind: "exited", proof: { containerId: CONTAINER_ID, startedAt: STARTED_AT, exitCode: 0 } as SessionContainerExitProof } as const;
    const other = proveSessionContainerExited(exitedInspect({ id: "f".repeat(64) }), {
      containerId: "f".repeat(64),
      startedAt: STARTED_AT,
      exitCode: 0,
    });
    if (!other) throw new Error("fixture proof for another container");
    for (const completion of [forged, { kind: "exited", proof: other } as const]) {
      const fixture = harness({ completion });
      expect(teardownSessionRecord(fixture.input())).toEqual({ completed: true });
      expect(fixture.effects()).toEqual(["delete-session-file", "list-callback-ingress", "disconnect", "stop", "remove"]);
    }
  });

  test("a delete failure after a proved exit still stops everything before any container effect", () => {
    const fixture = harness({
      completion: exitedCompletion(),
      answers: { "delete-session-file": { status: 1, stdout: "", stderr: "proxy exec failed" } },
    });

    const result = teardownSessionRecord(fixture.input());

    expect(result).toMatchObject({ completed: false, blockedAt: "delete-session-file" });
    expect(fixture.effects()).toEqual(["delete-session-file"]);
    expect(fixture.removed()).toBe(0);
  });

  test("a removal failure after a proved exit keeps the record; an absent container is success", () => {
    const refused = harness({
      completion: exitedCompletion(),
      answers: { remove: { status: 1, stdout: "", stderr: "Error response from daemon: removal in progress" } },
    });
    expect(() => teardownSessionRecord(refused.input())).toThrow("Docker failed to remove");
    expect(refused.events).toContain("mark-terminal");
    expect(refused.events).not.toContain("remove-record");
    expect(refused.events).not.toContain("clear-stamp");

    const absent = harness({
      completion: exitedCompletion(),
      answers: { remove: { status: 1, stdout: "", stderr: `Error response from daemon: No such container: ${CONTAINER_ID}` } },
    });
    expect(teardownSessionRecord(absent.input())).toEqual({ completed: true });
    expect(absent.removed()).toBe(1);
  });

  test("a lost lock on the short path stops it at that step", () => {
    for (const [index, remaining] of [
      [1, [] as Effect[]],
      [2, ["delete-session-file"] as Effect[]],
      [3, ["delete-session-file", "list-callback-ingress"] as Effect[]],
      [4, ["delete-session-file", "list-callback-ingress", "remove"] as Effect[]],
    ] as const) {
      let calls = 0;
      const fixture = harness({
        completion: exitedCompletion(),
        lock: () => {
          calls += 1;
          if (calls > index) throw new Error("project lifecycle lock is not held");
        },
      });
      expect(() => teardownSessionRecord(fixture.input())).toThrow("project lifecycle lock is not held");
      expect(fixture.effects()).toEqual(remaining);
      expect(fixture.events).not.toContain("remove-record");
    }
  });
});
