import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { nodeRuntimeIO } from "../runtime.ts";
import { withRebindBudgetIO } from "./control-plane-rebind-budget.ts";
import { ephemeralHelperRunArguments, ephemeralHelperTimeoutMs, runEphemeralHelper } from "./ephemeral-helper.ts";
import { EphemeralHelperUnconfirmedError, type EphemeralHelperFence } from "./ephemeral-helper-residue.ts";
import { withLifecycleOperationBudget } from "./lifecycle-operation-budget.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const NETWORK_ID = "c".repeat(64);
const RUN_NONCE = "d".repeat(32);
const CID_FILE = "/state/projects/0123456789ab/helper-runs/run-AbC123/cid";
// What runEphemeralHelper adds to a caller's request: the run's own cidfile
// and nonce, both minted under the host-owned helper-runs directory.
const RUN = { cidFile: CID_FILE, runNonce: RUN_NONCE } as const;

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
      ...RUN,
    });

    expect(args).toEqual([
      "run",
      "--rm",
      "--pull",
      "never",
      "--cidfile",
      CID_FILE,
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
      "--label",
      `io.runfree.helper-run=${RUN_NONCE}`,
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
      ...RUN,
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
      ...RUN,
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
    // The cidfile is the run's exact-id evidence, so it must be the host-owned
    // run directory's own `cid`, never a caller-chosen path.
    [{ cidFile: "relative/helper-runs/run-AbC123/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/run-AbC123/other" }, /cidfile/u],
    [{ cidFile: "/state/not-helper-runs/run-AbC123/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/run-AbC123/../run-XyZ789/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/nope-AbC123/cid" }, /cidfile/u],
    [{ runNonce: "" }, /run nonce/u],
    [{ runNonce: "D".repeat(32) }, /run nonce/u],
    [{ runNonce: "d".repeat(31) }, /run nonce/u],
    [{ projectId: "short" }, /exact project id/u],
    [{ purpose: "exfiltrate" as never }, /unknown ephemeral helper purpose/u],
  ])("refuses invalid input %#", (overrides, message) => {
    expect(() => ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      command: ["true"],
      ...RUN,
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
      ...RUN,
    });
    const image = args.indexOf(`sha256:${"e".repeat(64)}`);
    expect(args.slice(0, image)).toEqual(expect.arrayContaining(["--pull", "never", "--cidfile", CID_FILE]));
    expect(args.indexOf("--cidfile")).toBeLessThan(image);
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
  const runsRoot = path.join(stateDir, "helper-runs");
  return {
    stateDir,
    context,
    runs: () => (fs.existsSync(runsRoot) ? fs.readdirSync(runsRoot) : []),
    cleanup: () => fs.rmSync(stateDir, { recursive: true, force: true }),
  };
}

const HELPER_ID = "a".repeat(64);

function createdHelperInspect(args: string[], status = "running"): Record<string, unknown> {
  const labels: Record<string, string> = {};
  args.forEach((arg, index) => {
    if (args[index - 1] !== "--label") return;
    const [key, ...value] = arg.split("=");
    labels[key] = value.join("=");
  });
  const networkIndex = args.indexOf("--network");
  const network = args[networkIndex + 1];
  const ip = args.includes("--ip") ? args[args.indexOf("--ip") + 1] : undefined;
  const image = args.find((arg) => arg.startsWith("runfree-agent:") || arg.startsWith("sha256:")) as string;
  return {
    Id: HELPER_ID,
    Image: `sha256:${"e".repeat(64)}`,
    Config: { Image: image, Labels: labels },
    HostConfig: { NetworkMode: network },
    State: { Status: status },
    NetworkSettings: {
      Networks: network === "none"
        ? { none: { NetworkID: "f".repeat(64), IPAddress: "" } }
        : { internal: { NetworkID: status === "created" ? "" : network, IPAddress: status === "created" ? "" : ip, IPAMConfig: { IPv4Address: ip } } },
    },
  };
}

/**
 * The budgeted IO runs only the helper; everything after it must go through
 * the fence's containment IO. `helper` decides what the helper run returns
 * (after optionally "creating" a container that the containment side sees).
 */
function helperHarness(helper: (args: string[], options: Record<string, unknown>, create: (status?: string) => void) => CaptureResult) {
  const containers = new Map<string, Record<string, unknown>>();
  const budgeted: { args: string[]; options: Record<string, unknown> }[] = [];
  const contained: string[][] = [];
  const held: string[] = [];
  const budgetedCapture: Capture = (_command, args, options = {}) => {
    budgeted.push({ args, options });
    const cidFile = args[args.indexOf("--cidfile") + 1];
    return helper(args, options, (status = "running") => {
      containers.set(HELPER_ID, createdHelperInspect(args, status));
      fs.writeFileSync(cidFile, HELPER_ID);
    });
  };
  const containmentCapture: Capture = (_command, args) => {
    contained.push(args);
    if (args[0] === "ps") {
      const id = args.find((arg) => arg.startsWith("id="))?.slice(3);
      const ids = id ? (containers.has(id) ? [id] : []) : [...containers.keys()];
      return { status: 0, stdout: ids.map((entry) => `${entry}\n`).join(""), stderr: "" };
    }
    if (args[0] === "container" && args[1] === "inspect") {
      const entry = containers.get(args[2]);
      return entry ? { status: 0, stdout: JSON.stringify([entry]), stderr: "" } : { status: 1, stdout: "[]", stderr: "No such container" };
    }
    if (args[0] === "image") return { status: 0, stdout: `sha256:${"e".repeat(64)}\n`, stderr: "" };
    if (args[0] === "rm") {
      containers.delete(args[2]);
      return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`unexpected containment call ${args.join(" ")}`);
  };
  const state = helperState();
  const fence: EphemeralHelperFence = {
    lifecycleLock: { assertHeld: () => { held.push("held"); } },
    containmentIO: { capture: containmentCapture } as unknown as RuntimeIO,
    stateDir: state.stateDir,
  };
  return {
    ...state,
    containers,
    budgeted,
    contained,
    held,
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

describe("runEphemeralHelper", () => {
  test("refuses without the lifecycle fence before any directory or Docker call", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      expect(() => runEphemeralHelper(harness.context, harness.io, TRUST_BUNDLE_REQUEST, undefined))
        .toThrow(/lifecycle fence/u);
      expect(harness.budgeted).toEqual([]);
      expect(harness.runs()).toEqual([]);
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
      const cidFile = args[args.indexOf("--cidfile") + 1];
      expect(path.dirname(path.dirname(cidFile))).toBe(path.join(harness.stateDir, "helper-runs"));
      expect(options.input).toBe("echo probe");
      expect(options.killSignal).toBe("SIGKILL");
      expect(options.timeout).toBe(120_000);
      expect(options.env).toEqual(expect.objectContaining({ PATH: "/usr/bin" }));
    } finally {
      harness.cleanup();
    }
  });

  test("the intent, with the run nonce, is on disk before the helper is spawned", () => {
    let seen: Record<string, unknown> | undefined;
    const harness = helperHarness((args) => {
      const cidFile = args[args.indexOf("--cidfile") + 1];
      seen = JSON.parse(fs.readFileSync(path.join(path.dirname(cidFile), "intent.json"), "utf8")) as Record<string, unknown>;
      return { status: 0, stdout: "", stderr: "" };
    });
    try {
      runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence);
      const args = harness.budgeted[0].args;
      expect(seen).toMatchObject({
        v: 1, projectId: PROJECT_ID, purpose: "deny-probe", image: "runfree-agent:abc",
        network: NETWORK_ID, ip: "172.30.0.19",
      });
      expect(args).toContain(`io.runfree.helper-run=${seen?.nonce as string}`);
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

  test("a clean exit makes no extra Docker call and removes the run directory", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "roots", stderr: "" }));
    try {
      expect(runEphemeralHelper(harness.context, harness.io, TRUST_BUNDLE_REQUEST, harness.fence).stdout).toBe("roots");
      expect(harness.contained).toEqual([]);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["timed out", { status: 124, stdout: "", stderr: "", timedOut: true, signal: "SIGKILL" as const }],
    ["killed by a signal", { status: 137, stdout: "", stderr: "", signal: "SIGKILL" as const }],
    ["an output flood (ENOBUFS)", { status: 125, stdout: "xxxx", stderr: "" }],
    ["a non-zero exit", { status: 3, stdout: "", stderr: "boom" }],
    ["status 0 but timed out", { status: 0, stdout: "", stderr: "", timedOut: true }],
  ])("an unclean run (%s) is reclaimed by exact id through the containment IO only", (_name, outcome) => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return outcome;
    });
    try {
      const result = runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence);
      expect(result).toEqual(outcome);
      expect(harness.budgeted).toHaveLength(1);
      expect(harness.contained.map((args) => args.slice(0, 2).join(" "))).toEqual([
        "ps --all", "container inspect", "image inspect", "rm -f", "ps --all",
      ]);
      expect(harness.contained[3]).toEqual(["rm", "-f", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test("a start refused for an address in use leaves a created container, which is removed", () => {
    const harness = helperHarness((_args, _options, create) => {
      create("created");
      return {
        status: 125,
        stdout: "",
        stderr: "docker: Error response from daemon: failed to set up container networking: Address already in use.",
      };
    });
    try {
      const result = runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence);
      expect(result.status).toBe(125);
      expect(harness.contained).toContainEqual(["rm", "-f", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test("a killed client with no cidfile yet is reclaimed through the nonce-scoped listing", () => {
    const harness = helperHarness((args) => {
      harness.containers.set(HELPER_ID, createdHelperInspect(args, "created"));
      return { status: 137, stdout: "", stderr: "", signal: "SIGKILL" };
    });
    try {
      runEphemeralHelper(harness.context, harness.io, DENY_PROBE_REQUEST, harness.fence);
      const listing = harness.contained[0];
      expect(listing).toEqual(expect.arrayContaining([expect.stringMatching(/^label=io\.runfree\.helper-run=[a-f0-9]{32}$/u)]));
      expect(harness.contained).toContainEqual(["rm", "-f", HELPER_ID]);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test("a budget that ends during the helper still reclaims it, then rethrows the budget error", () => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return { status: 124, stdout: "", stderr: "", timedOut: true, signal: "SIGKILL" };
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
      expect(harness.contained).toContainEqual(["rm", "-f", HELPER_ID]);
      expect(harness.containers.size).toBe(0);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test.each([
    ["the lifecycle budget", (io: RuntimeIO, _stateDir: string) => withLifecycleOperationBudget(io, () => 0)],
    ["the rebind allowance", (io: RuntimeIO, stateDir: string) => withRebindBudgetIO(io, stateDir,
      { projectId: PROJECT_ID, composeProject: `runfree-${PROJECT_ID}` }, () => { throw new Error("lock lost"); })],
  ])("%s refusing before the spawn clears the run directory with zero Docker calls", (_name, wrap) => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      expect(() => runEphemeralHelper(harness.context, wrap(harness.io, harness.stateDir), DENY_PROBE_REQUEST, harness.fence))
        .toThrow();
      expect(harness.budgeted).toEqual([]);
      expect(harness.contained).toEqual([]);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test("an invalid request is refused after the run directory exists, which is cleared with zero Docker calls", () => {
    const harness = helperHarness(() => ({ status: 0, stdout: "", stderr: "" }));
    try {
      expect(() => runEphemeralHelper(harness.context, harness.io, { ...TRUST_BUNDLE_REQUEST, command: [] }, harness.fence))
        .toThrow(/requires a command/u);
      expect(harness.budgeted).toEqual([]);
      expect(harness.contained).toEqual([]);
      expect(harness.runs()).toEqual([]);
    } finally {
      harness.cleanup();
    }
  });

  test("an unconfirmed reclaim fails the run with both remedies and keeps the directory", () => {
    const harness = helperHarness((_args, _options, create) => {
      create();
      return { status: 124, stdout: "", stderr: "", timedOut: true, signal: "SIGKILL" };
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
      expect(harness.runs()).toHaveLength(1);
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
      // The fake daemon lists nothing for the run, so absence is proven.
      expect(state.runs()).toEqual([]);
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
