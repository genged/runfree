// Ordering proofs for the internal admission kernels.
//
// These are pure sequence tests over a recording double. They exist because the
// kernels encode a security ordering that is invisible in any single step: a
// session that has been granted authority must give it back on every exit path,
// and a failure before provisioning was ever selected must NOT run the paired
// revocation, because there is nothing to revoke and doing so would report a
// teardown that never happened.
//
// The live tranches prove the same orderings against a daemon, at minutes per
// run. These prove them in milliseconds, so a reordering is caught before
// anyone waits for Docker.

import { describe, expect, test } from "vitest";

import {
  runInternalSessionAdmissionLaunch,
  runInternalSessionAdmissionProbe,
  SessionTeardownIncompleteError,
  type SessionAdmissionLaunchOutcome,
  type SessionAdmissionLaunchSteps,
} from "./session-admission-probe.ts";

const REVOCATION_SEQUENCE = ["tearDown"];

const OUTCOME: SessionAdmissionLaunchOutcome = Object.freeze({ status: 0, signal: null });

type Recorder = Readonly<{
  calls: string[];
  steps: SessionAdmissionLaunchSteps;
}>;

/** A steps double that records call order and can fail at a chosen step. */
function recorder(failAt?: string, outcome: SessionAdmissionLaunchOutcome = OUTCOME): Recorder {
  const calls: string[] = [];
  let clock = 0;
  // Separate from the clock on purpose. The probe kernel checks that the Docker
  // operations attributed to its phases account for every operation in the
  // sequence, so a counter that also advanced on unmeasured clock reads would
  // fail that accounting for a reason that has nothing to do with ordering.
  let operations = 0;
  const step = (name: string) => async (): Promise<void> => {
    calls.push(name);
    operations += 1;
    if (name === failAt) throw new Error(`${name} failed`);
  };
  const steps = {
    agent: "claude" as const,
    nowMs: () => (clock += 1),
    dockerOperationCount: () => operations,
    preflight: step("preflight"),
    allocate: step("allocate"),
    createStarted: step("createStarted"),
    proveRunning: step("proveRunning"),
    activate: step("activate"),
    awaitHandoff: step("awaitHandoff"),
    async awaitCompletion(): Promise<SessionAdmissionLaunchOutcome> {
      calls.push("awaitCompletion");
      if (failAt === "awaitCompletion") throw new Error("awaitCompletion failed");
      return outcome;
    },
    cleanupUnadmitted: step("cleanupUnadmitted"),
    tearDown: step("tearDown"),
  } satisfies SessionAdmissionLaunchSteps;
  return { calls, steps };
}

describe("internal session admission launch kernel", () => {
  test("activates only after the running proof, then revokes on the way out", async () => {
    const { calls, steps } = recorder();
    await expect(runInternalSessionAdmissionLaunch(steps)).resolves.toEqual(OUTCOME);

    expect(calls).toEqual([
      "preflight",
      "allocate",
      "createStarted",
      "proveRunning",
      "activate",
      "awaitHandoff",
      "awaitCompletion",
      ...REVOCATION_SEQUENCE,
    ]);
    // The ordering that matters most: nothing is granted before the container
    // has been started and proven, and the attached process only runs after.
    expect(calls.indexOf("activate")).toBeGreaterThan(calls.indexOf("proveRunning"));
    expect(calls.indexOf("awaitCompletion")).toBeGreaterThan(calls.indexOf("activate"));
    // `attached` is reported only after the entry's handoff, still under the
    // lock the grant took, and before the attached wait releases it.
    expect(calls.indexOf("awaitHandoff")).toBe(calls.indexOf("activate") + 1);
    expect(calls.indexOf("awaitCompletion")).toBe(calls.indexOf("awaitHandoff") + 1);
  });

  test("gives authority back when the attached process fails", async () => {
    // The session was activated, so revocation is mandatory regardless of how
    // the process ended.
    const { calls, steps } = recorder("awaitCompletion");
    await expect(runInternalSessionAdmissionLaunch(steps)).rejects.toThrow("awaitCompletion failed");
    expect(calls).toContain("activate");
    expect(calls.slice(calls.indexOf("awaitCompletion") + 1)).toEqual(REVOCATION_SEQUENCE);
  });

  test("gives authority back when activation itself fails", async () => {
    // Activation can fail after selection has already moved, so this must run
    // the paired revocation rather than the unadmitted cleanup.
    const { calls, steps } = recorder("activate");
    await expect(runInternalSessionAdmissionLaunch(steps)).rejects.toThrow("activate failed");
    expect(calls.slice(calls.indexOf("activate") + 1)).toEqual(REVOCATION_SEQUENCE);
    expect(calls).not.toContain("cleanupUnadmitted");
  });

  test("gives authority back when the handoff wait fails, and never waits for completion", async () => {
    // The session file exists by then, so only the ordered teardown (file
    // first) may answer, never the unadmitted cleanup.
    const { calls, steps } = recorder("awaitHandoff");
    await expect(runInternalSessionAdmissionLaunch(steps)).rejects.toThrow("awaitHandoff failed");
    expect(calls.slice(calls.indexOf("awaitHandoff") + 1)).toEqual(REVOCATION_SEQUENCE);
    expect(calls).not.toContain("awaitCompletion");
    expect(calls).not.toContain("cleanupUnadmitted");
  });

  test("uses the unadmitted cleanup before provisioning could have been selected", async () => {
    // Nothing has been published, so the paired revocation would report a
    // teardown that never happened. The container may exist and even be
    // running, but no proxy consumer has ever seen the session.
    const { calls, steps } = recorder("createStarted");
    await expect(runInternalSessionAdmissionLaunch(steps)).rejects.toThrow("createStarted failed");
    expect(calls).toEqual(["preflight", "allocate", "createStarted", "cleanupUnadmitted"]);
    expect(calls).not.toContain("tearDown");
  });

  test("uses the ordered teardown once the running proof could have selected authority", async () => {
    const { calls, steps } = recorder("proveRunning");
    await expect(runInternalSessionAdmissionLaunch(steps)).rejects.toThrow("proveRunning failed");
    expect(calls.slice(calls.indexOf("proveRunning") + 1)).toEqual(REVOCATION_SEQUENCE);
    expect(calls).not.toContain("cleanupUnadmitted");
  });

  test.each([
    ["proveRunning", ["preflight", "allocate", "createStarted", "proveRunning", "cleanupUnadmitted"]],
    ["activate", ["preflight", "allocate", "createStarted", "proveRunning", "activate", "cleanupUnadmitted"]],
  ] as const)(
    "asks the steps whether provisioning could have been selected, and uses unadmitted cleanup at %s when it could not",
    async (failAt, expected) => {
      // The driver answers for itself: until its admitting beat has entered the
      // write that grants authority, a failure has nothing to revoke, and
      // running the ordered teardown would report one that never happened.
      const { calls, steps } = recorder(failAt);
      const unselected = {
        ...steps,
        provisioningMayBeSelected: () => false,
      } satisfies SessionAdmissionLaunchSteps;

      await expect(runInternalSessionAdmissionLaunch(unselected)).rejects.toThrow(`${failAt} failed`);

      expect(calls).toEqual(expected);
      expect(calls).not.toContain("tearDown");
    },
  );

  test("still uses the paired revocation once the steps say the session could be selected", async () => {
    const { calls, steps } = recorder("activate");
    const selected = {
      ...steps,
      provisioningMayBeSelected: () => true,
    } satisfies SessionAdmissionLaunchSteps;

    await expect(runInternalSessionAdmissionLaunch(selected)).rejects.toThrow("activate failed");

    expect(calls.slice(calls.indexOf("activate") + 1)).toEqual(REVOCATION_SEQUENCE);
    expect(calls).not.toContain("cleanupUnadmitted");
  });

  test("does not clean up at all when preflight itself fails", async () => {
    // Preflight failing means no container and no record exist yet.
    const { calls, steps } = recorder("preflight");
    await expect(runInternalSessionAdmissionLaunch(steps)).rejects.toThrow("preflight failed");
    expect(calls).toEqual(["preflight"]);
  });

  test("reports the original failure alongside a failed cleanup", async () => {
    // A cleanup that also fails must not replace the cause; both are needed to
    // understand what the project was left holding.
    const { steps } = recorder("activate");
    const failing = {
      ...steps,
      tearDown: async () => {
        throw new Error("revocation failed");
      },
    } satisfies SessionAdmissionLaunchSteps;
    // Both causes are present, but nested: the cleanup failure is itself an
    // AggregateError, and `String()` on one shows only its own message. Reading
    // it needs the same flattening the live runners do, which is precisely why
    // they had to grow it.
    const failure = await runInternalSessionAdmissionLaunch(failing).catch((error: unknown) => error);
    const flatten = (error: unknown): string[] => (error instanceof AggregateError
      ? [error.message, ...error.errors.flatMap(flatten)]
      : [String(error)]);
    const causes = flatten(failure).join("\n");
    expect(causes).toContain("activate failed");
    expect(causes).toContain("revocation failed");
  });
});

describe("post-completion teardown failures", () => {
  // The 2026-09-29 transcript: a daemon that died under a live session made
  // the owner's teardown and its one retry fail with the same observation, and
  // the launch reported them as `error[0]` and `error[1]` of an "admission
  // probe failed" aggregate. It was one failure, seen twice.
  test("an identical failure on the teardown and its retry is reported once, as an incomplete teardown", async () => {
    const { calls, steps } = recorder();
    const failing = {
      ...steps,
      tearDown: async () => {
        calls.push("tearDown");
        throw new Error("observation-unavailable during delete-session-file: Cannot connect to the Docker daemon");
      },
    } satisfies SessionAdmissionLaunchSteps;

    const failure = await runInternalSessionAdmissionLaunch(failing).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SessionTeardownIncompleteError);
    const aggregate = failure as SessionTeardownIncompleteError;
    expect(aggregate.errors).toHaveLength(1);
    expect(aggregate.message).not.toContain("probe");
    expect(aggregate.message).toContain("runfree up");
    // The retry the ladder has always given the teardown is kept, and there is
    // no third pass.
    expect(calls.filter((call) => call === "tearDown")).toHaveLength(2);
  });

  test("two different teardown failures are both kept", async () => {
    const { steps } = recorder();
    let attempt = 0;
    const failing = {
      ...steps,
      tearDown: async () => {
        attempt += 1;
        throw new Error(`teardown attempt ${attempt} failed`);
      },
    } satisfies SessionAdmissionLaunchSteps;

    const failure = await runInternalSessionAdmissionLaunch(failing).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SessionTeardownIncompleteError);
    expect((failure as SessionTeardownIncompleteError).errors.map(String))
      .toEqual(["Error: teardown attempt 1 failed", "Error: teardown attempt 2 failed"]);
  });

  test("the same sentence over a different cause is not collapsed", async () => {
    const { steps } = recorder();
    let attempt = 0;
    const failing = {
      ...steps,
      tearDown: async () => {
        attempt += 1;
        throw new Error("teardown failed", { cause: new Error(`cause ${attempt}`) });
      },
    } satisfies SessionAdmissionLaunchSteps;

    const failure = await runInternalSessionAdmissionLaunch(failing).catch((error: unknown) => error);

    expect((failure as SessionTeardownIncompleteError).errors).toHaveLength(2);
  });

  test("a retry that completes still reports the first failure", async () => {
    const { steps } = recorder();
    let attempt = 0;
    const flaky = {
      ...steps,
      tearDown: async () => {
        attempt += 1;
        if (attempt === 1) throw new Error("first teardown failed");
      },
    } satisfies SessionAdmissionLaunchSteps;

    await expect(runInternalSessionAdmissionLaunch(flaky)).rejects.toThrow("first teardown failed");
    expect(attempt).toBe(2);
  });

  test("a launch failure paired with an identical cleanup failure is reported once", async () => {
    const { steps } = recorder();
    const failing = {
      ...steps,
      awaitCompletion: async (): Promise<SessionAdmissionLaunchOutcome> => {
        throw new Error("Cannot connect to the Docker daemon");
      },
      tearDown: async () => {
        throw new Error("Cannot connect to the Docker daemon");
      },
    } satisfies SessionAdmissionLaunchSteps;

    const failure = await runInternalSessionAdmissionLaunch(failing).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).message).toBe("session admission launch failed and fail-closed cleanup also failed");
    expect((failure as AggregateError).errors).toHaveLength(1);
  });
});

describe("internal session admission probe kernel", () => {
  test("never activates, and always revokes a successful sequence", async () => {
    // The property that keeps the probe unable to enable a public attach.
    const { calls, steps } = recorder();
    await runInternalSessionAdmissionProbe(steps);
    expect(calls).not.toContain("activate");
    expect(calls).not.toContain("awaitCompletion");
    expect(calls.slice(calls.indexOf("proveRunning") + 1)).toEqual([...REVOCATION_SEQUENCE]);
  });
});
