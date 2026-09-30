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
import { teardownSessionRecord, type SessionFileTeardownInput } from "./session-file-teardown.ts";
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

  test("a lock that has been lost stops the sequence at that step", () => {
    for (const [index, remaining] of [
      [0, [] as Effect[]],
      [1, ["delete-session-file"] as Effect[]],
      [2, ["delete-session-file", "list-callback-ingress"] as Effect[]],
      [3, ["delete-session-file", "list-callback-ingress", "disconnect"] as Effect[]],
      [4, ["delete-session-file", "list-callback-ingress", "disconnect", "stop"] as Effect[]],
    ] as const) {
      let calls = 0;
      const fixture = harness({
        lock: () => {
          calls += 1;
          if (calls > index + 1) throw new Error("project lifecycle lock is not held");
        },
      });

      expect(() => teardownSessionRecord(fixture.input())).toThrow("project lifecycle lock is not held");

      expect(fixture.effects()).toEqual(remaining);
      expect(fixture.events).not.toContain("remove-record");
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
    };

    expect(teardownSessionRecord(input)).toEqual({ completed: true });
    expect(events).toEqual([`rm:${forwarderId}`, "remove-record"]);
  });
});
