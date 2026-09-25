import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { nodeRuntimeIO } from "../runtime.ts";
import { withRebindBudgetIO } from "./control-plane-rebind-budget.ts";
import { ephemeralHelperRunArguments, ephemeralHelperTimeoutMs, runEphemeralHelper } from "./ephemeral-helper.ts";
import { EphemeralHelperUnconfirmedError, markHelperRunPending, readHelperMarker, type EphemeralHelperFence } from "./ephemeral-helper-residue.ts";
import { withLifecycleOperationBudget } from "./lifecycle-operation-budget.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const NETWORK_ID = "c".repeat(64);

describe("ephemeral helper run arguments", () => {
  test("mints the exact hardened argv with no network by default", () => {
    const args = ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      capabilities: ["CHOWN"],
      volumes: [{ name: "runfree-x_deps", target: "/workspace/node_modules" }],
      command: ["sh", "-c", "script", "name", "arg"],
    });

    expect(args).toEqual([
      "run",
      "--rm",
      "--pull",
      "never",
      "--label",
      "io.runfree.managed=true",
      "--label",
      "io.runfree.container-role=ephemeral-helper",
      "--label",
      "io.runfree.lifecycle-owner=utility",
      "--label",
      "io.runfree.label-schema=1",
      "--label",
      `io.runfree.project-id=${PROJECT_ID}`,
      "--label",
      "io.runfree.helper-purpose=dependency-prep",
      "--user",
      "0:0",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "CHOWN",
      "--security-opt",
      "no-new-privileges:true",
      "--read-only",
      "--pids-limit",
      "64",
      "--network",
      "none",
      "-v",
      "runfree-x_deps:/workspace/node_modules",
      "runfree-agent:abc",
      "sh",
      "-c",
      "script",
      "name",
      "arg",
    ]);
  });

  test("batched dependency-prep inputs mount every volume in declared order under the same hardening", () => {
    // The L2 batch mounts every volume in ONE run; the hardening argv must be
    // byte-identical to the single-volume shape with only the -v pairs added.
    const args = ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      capabilities: ["CHOWN"],
      volumes: [
        { name: "runfree-x_deps-a", target: "/mnt/runfree-dep-prep/0" },
        { name: "runfree-x_deps-b", target: "/mnt/runfree-dep-prep/1" },
        { name: "runfree-x_store", target: "/mnt/runfree-dep-prep/2" },
      ],
      command: ["sh", "-c", "script"],
    });

    const volumeSpecs = args
      .map((arg, index) => (arg === "-v" ? args[index + 1] : undefined))
      .filter((spec): spec is string => spec !== undefined);
    expect(volumeSpecs).toEqual([
      "runfree-x_deps-a:/mnt/runfree-dep-prep/0",
      "runfree-x_deps-b:/mnt/runfree-dep-prep/1",
      "runfree-x_store:/mnt/runfree-dep-prep/2",
    ]);
    expect(args).toEqual(expect.arrayContaining([
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only", "--pids-limit", "64",
      "--network", "none",
    ]));
  });

  test("places a probe on an exact network with a static address", () => {
    const args = ephemeralHelperRunArguments({
      purpose: "deny-probe",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "1000:1000",
      networkId: NETWORK_ID,
      ip: "172.30.0.19",
      command: ["true"],
    });

    expect(args).toContain(NETWORK_ID);
    expect(args.slice(args.indexOf("--network"))).toEqual(
      expect.arrayContaining(["--network", NETWORK_ID, "--ip", "172.30.0.19"]),
    );
    // No capability sneaks in without being asked for.
    expect(args).not.toContain("--cap-add");
  });

  test.each([
    [{ image: "" }, /exact image reference/u],
    [{ image: "img with space" }, /exact image reference/u],
    [{ networkId: "abc" }, /exact 64-hex network id/u],
    [{ ip: "172.30.0.19" }, /static address requires a network/u],
    // A helper on a network always has a pinned address: never Docker's
    // dynamic pick, which could be a session's address.
    [{ networkId: NETWORK_ID }, /requires a pinned address/u],
    [{ networkId: NETWORK_ID, ip: "not-an-ip" }, /not IPv4/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.019" }, /not IPv4/u],
    // A helper address is only ever one of the reserved block's hosts: never a
    // session-pool address, a fixed role, or the gateway.
    [{ networkId: NETWORK_ID, ip: "172.30.0.20" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.83" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.99" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.10" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.1" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.12" }, /reserved ephemeral-helper block/u],
    [{ volumes: [{ name: "", target: "/x" }] }, /volume name is invalid/u],
    [{ volumes: [{ name: "ok", target: "relative" }] }, /volume target is invalid/u],
    [{ volumes: [{ name: "ok", target: "/x:ro" }] }, /volume target is invalid/u],
    [{ command: [] }, /requires a command/u],
    [{ capabilities: ["SYS_ADMIN" as never] }, /not in the closed set/u],
    [{ projectId: "short" }, /exact project id/u],
    [{ purpose: "exfiltrate" as never }, /unknown ephemeral helper purpose/u],
  ])("refuses invalid input %#", (overrides, message) => {
    expect(() => ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      command: ["true"],
      ...overrides,
    })).toThrow(message);
  });

  test("never pulls: a helper runs only an image that is already local", () => {
    const args = ephemeralHelperRunArguments({
      purpose: "trust-bundle",
      projectId: PROJECT_ID,
      image: `sha256:${"e".repeat(64)}`,
      user: "1000:1000",
      command: ["true"],
    });
    const image = args.indexOf(`sha256:${"e".repeat(64)}`);
    expect(args.slice(0, image)).toEqual(expect.arrayContaining(["--pull", "never"]));
    expect(args.indexOf("--pull")).toBeLessThan(image);
  });
});

type Capture = (command: string, args: string[], options?: Record<string, unknown>) => CaptureResult;

function helperState() {
  const stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-run-")));
  const context = {
    env: { PATH: "/usr/bin" },
    projectRoot: "/p",
    project: { paths: { stateDir } },
  } as unknown as RuntimeContext;
  return {
    stateDir,
    context,
    marker: () => readHelperMarker(stateDir),
    cleanup: () => fs.rmSync(stateDir, { recursive: true, force: true }),
  };
}

const HELPER_ID = "a".repeat(64);

/**
 * The budgeted IO runs only the helper; everything after it must go through
 * the fence's containment IO. `helper` decides what the helper run returns
 * (after optionally "creating" a container that the containment side sees).
 */
function helperHarness(helper: (args: string[], options: Record<string, unknown>, create: () => void) => CaptureResult) {
  const containers = new Set<string>();
  const budgeted: { args: string[]; options: Record<string, unknown> }[] = [];
  const contained: string[][] = [];
  const state = helperState();
  const markerAtSpawn: (ReturnType<typeof readHelperMarker>)[] = [];
  const budgetedCapture: Capture = (_command, args, options = {}) => {
    budgeted.push({ args, options });
    markerAtSpawn.push(readHelperMarker(state.stateDir));
    return helper(args, options, () => { containers.add(HELPER_ID); });
  };
  const containmentCapture: Capture = (_command, args) => {
    contained.push(args);
    if (args[0] === "ps") return { status: 0, stdout: [...containers].map((id) => `${id}\n`).join(""), stderr: "" };
    if (args[0] === "rm") {
      for (const id of args.slice(2)) containers.delete(id);
      return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`unexpected containment call ${args.join(" ")}`);
  };
  const fence: EphemeralHelperFence = {
    lifecycleLock: { assertHeld: () => {} },
    containmentIO: { capture: containmentCapture } as unknown as RuntimeIO,
    stateDir: state.stateDir,
  };
  return {
    ...state,
    containers,
    budgeted,
    contained,
    markerAtSpawn,
    fence,
    io: { capture: budgetedCapture } as unknown as RuntimeIO,
  };
}

const DENY_PROBE_REQUEST = {
  purpose: "deny-probe",
  projectId: PROJECT_ID,
  image: "runfree-agent:abc",
  user: "1000:1000",
  networkId: NETWORK_ID,
  ip: "172.30.0.19",
  command: ["bash", "-c", "true"],
} as const;

const TRUST_BUNDLE_REQUEST = {
  purpose: "trust-bundle",
  projectId: PROJECT_ID,
  image: "runfree-agent:abc",
  user: "1000:1000",
  command: ["cat", "/etc/ssl/certs/ca-certificates.crt"],
} as const;

const TIMED_OUT = { status: 124, stdout: "", stderr: "", timedOut: true, signal: "SIGKILL" as const };

describe("runEphemeralHelper", () => {
  test("refuses without the lifecycle fence before any marker or Docker call", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      expect(() => runEphemeralHelper(harness.context, harness.io, TRUST_BUNDLE_REQUEST, undefined))
        .toThrow(/lifecycle fence/u);
      expect(harness.budgeted).toEqual([]);
      expect(harness.marker()).toBeUndefined();
    } finally {
      harness.cleanup();
    }
  });

  test("pipes stdin, SIGKILLs at the bound, and threads the docker client environment", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      runEphemeralHelper(harness.context, harness.io, { ...TRUST_BUNDLE_REQUEST, command: ["sh", "-s"], stdin: "echo probe" }, harness.fence);
      expect(harness.budgeted).toHaveLength(1);
      const { args, options } = harness.budgeted[0];
      expect(args.slice(0, 2)).toEqual(["run", "--rm"]);
      expect(args).toContain("-i");
      expect(options.input).toBe("echo probe");
      expect(options.killSignal).toBe("SIGKILL");
      expect(options.timeout).toBe(120_000);
      expect(options.env).toEqual(expect.objectContaining({ PATH: "/usr/bin" }));
    } finally {
      harness.cleanup();
    }
  });

  test("the marker is on disk before the helper is spawned", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence);
      expect(harness.markerAtSpawn).toEqual([{ v: 1, writtenAt: expect.any(String) }]);
    } finally {
      harness.cleanup();
    }
  });

  test("a marker another lock span left is swept before the spawn, and a clean exit never clears it unswept", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      // A crashed run's marker, older than the late-create window, and its helper.
      markHelperRunPending(harness.stateDir, { wallClockMs: () => Date.parse("2026-01-01T00:00:00.000Z") });
      harness.containers.add(HELPER_ID);
      runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence);
      expect(harness.contained.map((args) => args[0])).toEqual(["ps", "rm", "ps"]);
      expect(harness.contained[1]).toEqual(["rm", "--force", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
      expect(harness.marker()).toBeUndefined();
    } finally {
      harness.cleanup();
    }
  });

  test("an unconfirmed sweep of a left-behind marker refuses before the spawn", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    const fence: EphemeralHelperFence = {
      ...harness.fence,
      containmentIO: { capture: () => ({ status: 1, stdout: "", stderr: "daemon down" }) } as unknown as RuntimeIO,
    };
    try {
      markHelperRunPending(harness.stateDir, { wallClockMs: () => Date.parse("2026-01-01T00:00:00.000Z") });
      expect(() => runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, fence)).toThrow(EphemeralHelperUnconfirmedError);
      expect(harness.budgeted).toEqual([]);
      expect(harness.marker()).toBeDefined();
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["deny-probe", DENY_PROBE_REQUEST, 30_000],
    ["trust-bundle", TRUST_BUNDLE_REQUEST, 120_000],
    ["dependency-prep", { ...TRUST_BUNDLE_REQUEST, purpose: "dependency-prep", user: "0:0" } as const, 120_000],
  ])("the %s helper's wall-time bound is its purpose default", (_name, request, timeout) => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      runEphemeralHelper(harness.context, harness.io, request, harness.fence);
      expect(harness.budgeted[0].options.timeout).toBe(timeout);
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["5000", "deny-probe", 5_000],
    ["1", "deny-probe", 1_000],
    ["999999", "deny-probe", 30_000],
    ["60000", "trust-bundle", 60_000],
    ["abc", "deny-probe", 30_000],
    ["-5", "deny-probe", 30_000],
    ["1e3", "deny-probe", 30_000],
    ["", "deny-probe", 30_000],
  ])("the test override %j only ever shortens the %s bound, clamped at 1 s", (value, purpose, timeout) => {
    expect(ephemeralHelperTimeoutMs(purpose as "deny-probe" | "trust-bundle", { RUNFREE_TEST_EPHEMERAL_HELPER_TIMEOUT_MS: value })).toBe(timeout);
  });

  test("a clean exit makes no extra Docker call and clears the marker", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "roots", stderr: "" }));
    try {
      expect(runEphemeralHelper(harness.context, harness.io, TRUST_BUNDLE_REQUEST, harness.fence).stdout).toBe("roots");
      expect(harness.contained).toEqual([]);
      expect(harness.marker()).toBeUndefined();
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["an output flood (ENOBUFS)", { status: 125, stdout: "xxxx", stderr: "" }],
    ["a non-zero exit", { status: 3, stdout: "", stderr: "boom" }],
    ["an address already in use", { status: 125, stdout: "", stderr: "Address already in use." }],
  ])("an unclean run whose client exited (%s) is swept through the containment IO and settled", (_name, outcome) => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return outcome;
    });
    try {
      expect(runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence)).toEqual(outcome);
      expect(harness.budgeted).toHaveLength(1);
      expect(harness.contained.map((args) => args[0])).toEqual(["ps", "rm", "ps"]);
      expect(harness.contained[1]).toEqual(["rm", "--force", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
      expect(harness.marker()).toBeUndefined();
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["timed out", TIMED_OUT],
    ["killed by a signal", { status: 137, stdout: "", stderr: "", signal: "SIGKILL" as const }],
    ["status 0 but timed out", { status: 0, stdout: "", stderr: "", timedOut: true }],
  ])("a killed client (%s) is swept and keeps a late-create window open", (_name, outcome) => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return outcome;
    });
    try {
      expect(runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence)).toEqual(outcome);
      expect(harness.contained).toContainEqual(["rm", "--force", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
      expect(harness.marker()?.lateCreateUntil).toBeDefined();
    } finally {
      harness.cleanup();
    }
  });

  test("a budget that ends during the helper still sweeps it, then rethrows the budget error", () => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return TIMED_OUT;
    });
    let remaining = 90_000;
    const budgeted = withLifecycleOperationBudget({
      capture: (command: string, args: string[], options?: Record<string, unknown>) => {
        const result = harness.io.capture(command, args, options);
        remaining = 0;
        return result;
      },
    } as unknown as RuntimeIO, () => remaining);
    try {
      expect(() => runEphemeralHelper(harness.context, budgeted, DENY_PROBE_REQUEST, harness.fence))
        .toThrow(RuntimeObservationError);
      expect(harness.contained).toContainEqual(["rm", "--force", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
    } finally {
      harness.cleanup();
    }
  });

  test("an unconfirmed sweep after a budget failure keeps the budget error as its cause and failure kind", () => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return TIMED_OUT;
    });
    let remaining = 90_000;
    const budgeted = withLifecycleOperationBudget({
      capture: (command: string, args: string[], options?: Record<string, unknown>) => {
        const result = harness.io.capture(command, args, options);
        remaining = 0;
        return result;
      },
    } as unknown as RuntimeIO, () => remaining);
    const fence: EphemeralHelperFence = {
      ...harness.fence,
      containmentIO: {
        capture: (command: string, args: string[], options?: Record<string, unknown>) => (args[0] === "rm"
          ? { status: 124, stdout: "", stderr: "", timedOut: true }
          : harness.fence.containmentIO.capture(command, args, options)),
      } as unknown as RuntimeIO,
    };
    try {
      let caught: unknown;
      try {
        runEphemeralHelper(harness.context, budgeted, DENY_PROBE_REQUEST, fence);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(EphemeralHelperUnconfirmedError);
      const unconfirmed = caught as EphemeralHelperUnconfirmedError;
      expect(unconfirmed.cause).toBeInstanceOf(RuntimeObservationError);
      expect((unconfirmed.cause as RuntimeObservationError).evidence.kind).toBe("observation-unavailable");
      expect(unconfirmed.failureKind).toBe("observation-unavailable");
      expect(unconfirmed.message).toContain("runfree destroy --force");
      expect(unconfirmed.message).toContain("lifecycle operation budget ended");
      expect(harness.marker()).toBeDefined();
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["the lifecycle budget", (io: RuntimeIO, _stateDir: string) => withLifecycleOperationBudget(io, () => 0)],
    ["the rebind allowance", (io: RuntimeIO, stateDir: string) => withRebindBudgetIO(io, stateDir,
      { projectId: PROJECT_ID, composeProject: `runfree-${PROJECT_ID}` }, () => { throw new Error("lock lost"); })],
  ])("%s refusing before the spawn clears the marker with zero Docker calls", (_name, wrap) => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      expect(() => runEphemeralHelper(harness.context, wrap(harness.io, harness.stateDir), DENY_PROBE_REQUEST, harness.fence))
        .toThrow();
      expect(harness.budgeted).toEqual([]);
      expect(harness.contained).toEqual([]);
      expect(harness.marker()).toBeUndefined();
    } finally {
      harness.cleanup();
    }
  });

  test("an invalid request is refused before the marker or any Docker call", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      expect(() => runEphemeralHelper(harness.context, harness.io, { ...TRUST_BUNDLE_REQUEST, command: [] }, harness.fence))
        .toThrow(/requires a command/u);
      expect(harness.budgeted).toEqual([]);
      expect(harness.contained).toEqual([]);
      expect(harness.marker()).toBeUndefined();
    } finally {
      harness.cleanup();
    }
  });

  test("an unconfirmed sweep fails the run with both remedies and keeps the marker", () => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return TIMED_OUT;
    });
    const fence: EphemeralHelperFence = {
      ...harness.fence,
      containmentIO: {
        capture: (command: string, args: string[], options?: Record<string, unknown>) => (args[0] === "rm"
          ? { status: 124, stdout: "", stderr: "", timedOut: true }
          : harness.fence.containmentIO.capture(command, args, options)),
      } as unknown as RuntimeIO,
    };
    try {
      let caught: unknown;
      try {
        runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, fence);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(EphemeralHelperUnconfirmedError);
      expect((caught as Error).message).toContain("runfree up");
      expect((caught as Error).message).toContain("runfree destroy --force");
      expect(harness.marker()).toBeDefined();
    } finally {
      harness.cleanup();
    }
  });
});

describe("the real-process bound", () => {
  // A fake `docker` whose `run` ignores SIGTERM like a wedged client that
  // forwards the signal into a container the untrusted image controls.
  function fakeDockerBin(runBody: string): { dir: string; cleanup: () => void } {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-fake-docker-")));
    fs.writeFileSync(path.join(dir, "docker"), [
      "#!/bin/sh",
      "if [ \"$1\" = run ]; then",
      `  ${runBody}`,
      "fi",
      "exit 0",
      "",
    ].join("\n"), { mode: 0o755 });
    return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
  }

  test("a helper whose client ignores SIGTERM is SIGKILLed at the bound and reclaimed", () => {
    const bin = fakeDockerBin("trap '' TERM; exec sleep 30");
    const state = helperState();
    const context = {
      env: { PATH: `${bin.dir}:/usr/bin:/bin`, RUNFREE_TEST_EPHEMERAL_HELPER_TIMEOUT_MS: "1000" },
      projectRoot: "/p",
      project: { paths: { stateDir: state.stateDir } },
    } as unknown as RuntimeContext;
    try {
      const startedAt = performance.now();
      const result = runEphemeralHelper(context, nodeRuntimeIO, TRUST_BUNDLE_REQUEST, {
        lifecycleLock: { assertHeld: () => {} },
        containmentIO: nodeRuntimeIO,
        stateDir: state.stateDir,
      });
      const elapsed = performance.now() - startedAt;
      expect(elapsed).toBeLessThan(5_000);
      expect(result).toMatchObject({ status: 124, timedOut: true, signal: "SIGKILL" });
      // The fake daemon lists nothing, but the client was killed: its create
      // could still land, so the marker keeps a late-create window for the
      // next lock holder to sweep again.
      expect(state.marker()?.lateCreateUntil).toBeDefined();
    } finally {
      state.cleanup();
      bin.cleanup();
    }
  });

  test("control: the default SIGTERM waits for a client that ignores it (why D-A needs SIGKILL)", () => {
    const bin = fakeDockerBin("trap '' TERM; exec sleep 2");
    try {
      const startedAt = performance.now();
      const result = nodeRuntimeIO.capture("docker", ["run"], { env: { PATH: `${bin.dir}:/usr/bin:/bin` }, timeout: 300 });
      const elapsed = performance.now() - startedAt;
      expect(elapsed).toBeGreaterThan(1_500);
      expect(result).toMatchObject({ timedOut: true });
      expect(result.signal).toBeUndefined();
    } finally {
      bin.cleanup();
    }
  });
});
