import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { defaultConfig } from "../config.ts";
import { RUNFREE_VERSION } from "../embedded-assets.generated.ts";
import { CliError } from "../errors.ts";
import { composeProjectName, projectHash } from "../project-identity.ts";
import { ControlPlaneRebindCandidateMismatchError } from "../runtime/control-plane-rebind-coordinator.ts";
import { runWithRecoveryClaim, scanRecoveryInventory, type RecoveryItem } from "../runtime/recovery.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { runAgentCommand } from "../runtime.ts";
import { runAgentCommandWithControlPlaneRebindRefusal, runCommandApp } from "./app.ts";
import { approvalsInputFromArgs, runUp, runtimeContextWithSessionName } from "./runtime.ts";
import type { PromptApi } from "./resume-prompt.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { projectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../control/candidates.ts";
import { publishEffectivePolicyGeneration } from "../control/effective.ts";
import { mutateDesiredHostService } from "../control/host-service-mutation.ts";
import { controlPlaneEffectiveSelectionPathV2 } from "../runtime/component-state-v2.ts";
import { readHostServicePortRegistry } from "../host-service-registry.ts";
import type { HostPortOwner, HostServicePortAdmission } from "../host-service-port-owner.ts";
import type { ControlActivationResult } from "../control/activation.ts";

// Seams for the host-service command tests: the lsof probe and the activation
// are host/Docker facing, the registry write is spied. Each passes through to
// the real module unless a test arms it.
const hostServiceSeams = vi.hoisted(() => ({
  admit: undefined as undefined | ((port: number) => HostServicePortAdmission),
  probe: undefined as undefined | ((port: number) => HostPortOwner),
  activate: undefined as undefined | (() => Promise<ControlActivationResult>),
  recorded: [] as Array<{ ports: readonly number[]; owners?: Readonly<Record<number, string>> }>,
  recordFails: false,
}));

vi.mock("../host-service-port-owner.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../host-service-port-owner.ts")>();
  return {
    ...actual,
    admitHostServicePort: (...args: Parameters<typeof actual.admitHostServicePort>) =>
      hostServiceSeams.admit ? hostServiceSeams.admit(args[2]) : actual.admitHostServicePort(...args),
    probeHostPortOwner: (...args: Parameters<typeof actual.probeHostPortOwner>) =>
      hostServiceSeams.probe ? hostServiceSeams.probe(args[2]) : actual.probeHostPortOwner(...args),
  };
});

vi.mock("../control/activation.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../control/activation.ts")>();
  return {
    ...actual,
    activateApprovedControlsAfterMutation: (...args: Parameters<typeof actual.activateApprovedControlsAfterMutation>) =>
      hostServiceSeams.activate ? hostServiceSeams.activate() : actual.activateApprovedControlsAfterMutation(...args),
  };
});

vi.mock("../host-service-registry.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../host-service-registry.ts")>();
  return {
    ...actual,
    recordProjectHostServicePorts: (...args: Parameters<typeof actual.recordProjectHostServicePorts>) => {
      hostServiceSeams.recorded.push({ ports: args[2], ...(args[3] ? { owners: args[3] } : {}) });
      if (hostServiceSeams.recordFails) return Promise.reject(new Error("host-service port registry lock is held"));
      return actual.recordProjectHostServicePorts(...args);
    },
  };
});

// Seams for the same-terminal resume tests: `scanCalls` counts every call
// (decision 5 guard — a launch must make none), and `dismissResult`, when
// set, short-circuits `dismissRecoveryItem` to prove `resume.ts`'s own
// message mapping for each of its four results without needing a real claim,
// a real lifecycle-lock contender, or a mid-flight evidence change.
const recoverySeams = vi.hoisted(() => ({
  dismissResult: undefined as undefined | "dismissed" | "claimed" | "changed" | "deferred",
  scanCalls: 0,
}));

vi.mock("../runtime/recovery.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../runtime/recovery.ts")>();
  return {
    ...actual,
    scanRecoveryInventory: (...args: Parameters<typeof actual.scanRecoveryInventory>) => {
      recoverySeams.scanCalls += 1;
      return actual.scanRecoveryInventory(...args);
    },
    dismissRecoveryItem: async (...args: Parameters<typeof actual.dismissRecoveryItem>) =>
      recoverySeams.dismissResult ?? actual.dismissRecoveryItem(...args),
  };
});

// `resumeRecoveryRuntime` is the only thing that starts a runtime/Docker for
// `runfree resume`; counting real calls to it lets a dismiss/refusal test
// prove no runtime ever started, not merely that the test's own assertions
// happened to pass. Passed through unless a test arms `resumeRecoveryRuntime`
// to stand in for the Docker-facing resume.
const runtimeSeams = vi.hoisted(() => ({
  resumeRecoveryRuntimeCalls: 0,
  resumeRecoveryRuntime: undefined as undefined | ((...args: never[]) => Promise<number>),
}));

vi.mock("../runtime.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../runtime.ts")>();
  return {
    ...actual,
    resumeRecoveryRuntime: (...args: Parameters<typeof actual.resumeRecoveryRuntime>) => {
      runtimeSeams.resumeRecoveryRuntimeCalls += 1;
      const stub = runtimeSeams.resumeRecoveryRuntime as undefined | typeof actual.resumeRecoveryRuntime;
      return stub ? stub(...args) : actual.resumeRecoveryRuntime(...args);
    },
  };
});

// `startRuntime` is the Docker boundary inside `runConfiguredAgent`; stubbing
// it (only where a test arms it) lets the decision-5 guard run a real launch
// all the way to a clean, known completion without a Docker daemon.
const startupSeams = vi.hoisted(() => ({
  startRuntime: undefined as undefined | ((...args: unknown[]) => unknown),
}));

vi.mock("../runtime/startup.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../runtime/startup.ts")>();
  return {
    ...actual,
    startRuntime: (...args: Parameters<typeof actual.startRuntime>) =>
      startupSeams.startRuntime ? startupSeams.startRuntime(...args) : actual.startRuntime(...args),
  };
});

const PROJECT_ROOT = "/tmp/runfree-app-test-project";
const tempDirs: string[] = [];

// A context whose lazy accessors throw if used. Pure command tests assert that
// parsing/validation never reaches asset materialization or project reads.
function strictContext(overrides: Partial<RunfreeCommandContext> = {}): RunfreeCommandContext {
  return {
    env: {},
    projectRoot: PROJECT_ROOT,
    commandName: "",
    invocationCwd: "/tmp",
    assets: () => {
      throw new Error("assets() must not be called");
    },
    templatesDir: () => {
      throw new Error("templatesDir() must not be called");
    },
    projectInfo: () => {
      throw new Error("projectInfo() must not be called");
    },
    ensureProject: () => {
      throw new Error("ensureProject() must not be called");
    },
    adminContext: () => {
      throw new Error("adminContext() must not be called");
    },
    sourceAdminContext: () => {
      throw new Error("sourceAdminContext() must not be called");
    },
    runtimeContext: () => {
      throw new Error("runtimeContext() must not be called");
    },
    ...overrides,
  };
}

function captureStdout(): { text: () => string } {
  const lines: string[] = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    lines.push(args.join(" "));
  });
  return { text: () => lines.join("\n") };
}

async function cliRefusal(promise: Promise<number>): Promise<CliError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(CliError);
    return error as CliError;
  }
  throw new Error("expected command refusal");
}

function writeClaudeRecoveryFixture(stateRoot: string, projectRoot: string, name: string): void {
  fs.mkdirSync(projectRoot, { recursive: true });
  const stateDir = path.join(stateRoot, "runfree", "projects", projectHash(projectRoot));
  const registryDir = path.join(stateDir, "claude", "sessions");
  fs.mkdirSync(registryDir, { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, "project.json"),
    `${JSON.stringify({ projectRoot, updatedAt: "2026-08-01T00:00:00.000Z" })}\n`,
  );
  fs.writeFileSync(
    path.join(registryDir, "4242.json"),
    `${JSON.stringify({
      pid: 4242,
      sessionId: "11111111-2222-4333-8444-555555555555",
      cwd: "/workspace",
      startedAt: Date.parse("2026-08-01T00:00:00.000Z"),
      procStart: "98765",
      name,
      status: "idle",
      updatedAt: Date.parse("2026-08-01T00:01:00.000Z"),
    })}\n`,
  );
}

function writeHostRecoveryFixture(
  stateRoot: string,
  projectRoot: string,
  agent: string,
  overrides: { id?: string; recordVersion?: number } = {},
): void {
  fs.mkdirSync(projectRoot, { recursive: true });
  const stateDir = path.join(stateRoot, "runfree", "projects", projectHash(projectRoot));
  const sessionsDir = path.join(stateDir, "sessions");
  fs.mkdirSync(sessionsDir, { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, "project.json"),
    `${JSON.stringify({ projectRoot, updatedAt: "2026-08-01T00:00:00.000Z" })}\n`,
  );
  const id = overrides.id ?? "rf-20260801-c0de01";
  fs.writeFileSync(
    path.join(sessionsDir, `${id}.json`),
    `${JSON.stringify({
      id,
      projectRoot,
      composeProject: composeProjectName(projectRoot),
      command: agent,
      hostPid: 999_999,
      startedAt: "2026-08-01T00:00:00.000Z",
      lastSeenAt: "2026-08-01T00:01:00.000Z",
      endedAt: "2026-08-01T00:02:00.000Z",
      exitStatus: 137,
      outcome: "interrupted",
      ...(overrides.recordVersion !== undefined ? { recordVersion: overrides.recordVersion } : {}),
    })}\n`,
  );
}

// A record-version-2 host fixture whose owner is provably dead (`outcome:
// "interrupted"`), so it is eligible for the same-terminal prompt and picker
// (`eligible`, resume-selection.ts) — unlike `writeHostRecoveryFixture`
// above, which deliberately omits `recordVersion` for the pre-this-release
// fixtures.
function writeHostRecoveryFixtureV2(stateRoot: string, projectRoot: string, overrides: Record<string, unknown> = {}): string {
  fs.mkdirSync(projectRoot, { recursive: true });
  const stateDir = path.join(stateRoot, "runfree", "projects", projectHash(projectRoot));
  const sessionsDir = path.join(stateDir, "sessions");
  fs.mkdirSync(sessionsDir, { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, "project.json"),
    `${JSON.stringify({ projectRoot, updatedAt: "2026-08-01T00:00:00.000Z" })}\n`,
  );
  const id = "rf-20260801-strong01";
  const filePath = path.join(sessionsDir, `${id}.json`);
  fs.writeFileSync(
    filePath,
    `${JSON.stringify({
      id,
      projectRoot,
      composeProject: composeProjectName(projectRoot),
      command: "claude",
      hostPid: 999_999,
      recordVersion: 2,
      startedAt: "2026-08-01T00:00:00.000Z",
      lastSeenAt: "2026-08-01T00:01:00.000Z",
      outcome: "interrupted",
      launchConversationId: "11111111-2222-4333-8444-555555555555",
      ...overrides,
    })}\n`,
  );
  return filePath;
}

// Forces `process.stdin`/`process.stdout`'s `isTTY` for the duration of
// `run`, restoring whatever this test runner actually had — the same
// save/restore shape `runtime/approvals-lifecycle.test.ts` uses.
async function withTty<T>(stdinTty: boolean, stdoutTty: boolean, run: () => Promise<T>): Promise<T> {
  const entries: ReadonlyArray<[NodeJS.ReadStream | NodeJS.WriteStream, boolean]> = [
    [process.stdin, stdinTty],
    [process.stdout, stdoutTty],
  ];
  const descriptors = entries.map(([stream]) => Object.getOwnPropertyDescriptor(stream, "isTTY"));
  for (const [stream, value] of entries) Object.defineProperty(stream, "isTTY", { configurable: true, value });
  try {
    return await run();
  } finally {
    entries.forEach(([stream], index) => {
      const descriptor = descriptors[index];
      if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
      else Reflect.deleteProperty(stream, "isTTY");
    });
  }
}

const PROMPT_CANCEL = Symbol("prompt-cancel");

type RecordedSelectCall = Readonly<{
  message: string;
  options: ReadonlyArray<{ value: unknown; label: string }>;
  initialValue: unknown;
}>;

// A `PromptApi` test double: every `select` call is recorded, then answered
// by `respond` (its own call and a 0-based call index), so a test can drive a
// multi-step prompt (list, then a sub-menu) without touching a terminal.
function fakePromptApi(respond: (call: RecordedSelectCall, index: number) => unknown): PromptApi & { calls: RecordedSelectCall[] } {
  const calls: RecordedSelectCall[] = [];
  return {
    calls,
    select: (async (opts: { message: string; options: ReadonlyArray<{ value: unknown; label: string }>; initialValue?: unknown }) => {
      const call: RecordedSelectCall = { message: opts.message, options: opts.options, initialValue: opts.initialValue };
      calls.push(call);
      return respond(call, calls.length - 1);
    }) as unknown as PromptApi["select"],
    isCancel: ((value: unknown) => value === PROMPT_CANCEL) as unknown as PromptApi["isCancel"],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  recoverySeams.dismissResult = undefined;
  recoverySeams.scanCalls = 0;
  runtimeSeams.resumeRecoveryRuntimeCalls = 0;
  runtimeSeams.resumeRecoveryRuntime = undefined;
  startupSeams.startRuntime = undefined;
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("runCommandApp parser", () => {
  test("runfree claude explains a contradictory rebind and ends with the launch outcome", async () => {
    const context = {
      project: { config: defaultConfig() },
    } as RuntimeContext;
    const refusal = await cliRefusal(runAgentCommandWithControlPlaneRebindRefusal(
      context,
      {} as never,
      "claude",
      { quiet: false, verbose: false },
      async () => { throw new ControlPlaneRebindCandidateMismatchError(); },
    ));

    expect(refusal.status).toBe(1);
    expect(refusal.message).toContain(
      "Claude did not start because Runfree could not safely continue a proxy replacement.",
    );
    expect(refusal.message).toContain(
      "The proxy in the pending rebind journal does not match the proxy that Docker reports.",
    );
    expect(refusal.message.indexOf("runfree sessions")).toBeLessThan(refusal.message.indexOf("runfree rebuild"));
    expect(refusal.message).not.toContain("runfree destroy --force");
    expect(refusal.message).not.toContain("proved candidate control-plane authority");
    expect(refusal.message.endsWith("claude did not start")).toBe(true);
  });

  test("an unnamed default agent keeps a complete launch outcome", async () => {
    const defaults = defaultConfig();
    const context = {
      project: {
        config: {
          ...defaults,
          agents: { ...defaults.agents, default: "" },
        },
      },
    } as RuntimeContext;
    const refusal = await cliRefusal(runAgentCommandWithControlPlaneRebindRefusal(
      context,
      {} as never,
      undefined,
      { quiet: false, verbose: false },
      async () => { throw new ControlPlaneRebindCandidateMismatchError(); },
    ));

    expect(refusal.message).toContain(
      "The agent did not start because Runfree could not safely continue a proxy replacement.",
    );
    expect(refusal.message.endsWith("the agent did not start")).toBe(true);
  });

  test("runfree up explains the same typed refusal in runtime terms", async () => {
    const internal = new ControlPlaneRebindCandidateMismatchError();
    const refusal = await cliRefusal(runUp(
      {} as RuntimeContext,
      {},
      async () => { throw internal; },
    ));

    expect(refusal.status).toBe(1);
    expect(refusal.message).toContain(
      "The runtime did not start because Runfree could not safely continue a proxy replacement.",
    );
    expect(refusal.message.indexOf("runfree sessions")).toBeLessThan(refusal.message.indexOf("runfree rebuild"));
    expect(refusal.message).not.toContain(internal.message);
    expect(refusal.message.endsWith("the runtime did not start")).toBe(true);
  });

  test("the rebind remedy keeps the internal invariant and stack behind --verbose", async () => {
    const internal = new ControlPlaneRebindCandidateMismatchError();
    internal.stack = `${internal.name}: ${internal.message}\n    at exactCandidate (control-plane-rebind-coordinator.ts:147:13)`;
    const refusal = await cliRefusal(runUp(
      {} as RuntimeContext,
      { verbose: true },
      async () => { throw internal; },
    ));

    expect(refusal.message.indexOf("The runtime did not start because")).toBeLessThan(
      refusal.message.indexOf("Internal diagnostic:"),
    );
    expect(refusal.message).toContain(internal.message);
    expect(refusal.message).toContain("at exactCandidate (control-plane-rebind-coordinator.ts:147:13)");
    expect(refusal.message.endsWith("the runtime did not start")).toBe(true);
  });

  test("the rebind remedy does not classify a plain Error by message text", async () => {
    const plain = new Error("proved candidate control-plane authority contradicts the rebind journal");
    await expect(runUp(
      {} as RuntimeContext,
      {},
      async () => { throw plain; },
    )).rejects.toBe(plain);
  });

  test("matches the version command without touching the default dispatcher", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext(), ["version"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toBe(RUNFREE_VERSION);
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("routes a bare invocation to the typed default (agent) command", async () => {
    const runDefault = vi.fn(async () => 7);

    // Bare `runfree` resolves the default agent via the typed `$0` handler, which
    // materializes the runtime context (strictContext throws there); it does not
    // delegate to runDefault.
    await expect(runCommandApp(strictContext(), [], runDefault)).rejects.toThrow(
      "runtimeContext() must not be called",
    );
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("routes a project-configured dynamic agent name to the typed default command", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["my-project-agent"], runDefault)).rejects.toThrow(
      "runtimeContext() must not be called",
    );
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("accepts a validated session display name on default, named-agent, and shell launches", async () => {
    const runDefault = vi.fn(async () => 0);

    for (const args of [
      ["--session-name", "focused work"],
      ["codex", "--session-name", "focused work"],
      ["shell", "--session-name", "focused work"],
    ]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toThrow(
        "runtimeContext() must not be called",
      );
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("rejects invalid launch session names before runtime context materialization", async () => {
    const runDefault = vi.fn(async () => 0);

    for (const args of [
      ["--session-name", "bad\nname"],
      ["codex", "--session-name", "   "],
      ["shell", "--session-name", "bad\u007fname"],
    ]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toBeInstanceOf(CliError);
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("an explicit launch name overrides the environment without mutating the base context", () => {
    const runtimeContext = {
      env: { RUNFREE_SESSION_NAME: "environment name" },
    } as unknown as RuntimeContext;

    const named = runtimeContextWithSessionName(runtimeContext, "  explicit name  ");

    expect(named).not.toBe(runtimeContext);
    expect(named.env?.RUNFREE_SESSION_NAME).toBe("explicit name");
    expect(runtimeContext.env?.RUNFREE_SESSION_NAME).toBe("environment name");
    expect(runtimeContextWithSessionName(runtimeContext, undefined)).toBe(runtimeContext);
  });

  test("routes an unknown command to the typed default rather than failing strict parsing", async () => {
    const runDefault = vi.fn(async () => 3);

    // The non-strict `$0` default accepts an unknown leading token as the agent
    // name; resolution (and the unknown-command error) happens inside the typed
    // handler, after the runtime context — so strictContext throws there.
    await expect(runCommandApp(strictContext(), ["totally-unknown-command"], runDefault)).rejects.toThrow(
      "runtimeContext() must not be called",
    );
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("update is a pure typed command: prints guidance, returns 0, no delegation", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext(), ["update"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("does not replace the running binary yet");
    expect(runDefault).not.toHaveBeenCalled();
    await expect(runCommandApp(strictContext(), ["update", "--bogus"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("resume --list defaults to the current project and remains read-only", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-list-"));
    tempDirs.push(stateRoot);
    const currentProject = path.join(stateRoot, "current-project");
    const otherProject = path.join(stateRoot, "other-project");
    writeClaudeRecoveryFixture(stateRoot, currentProject, "current conversation");
    writeClaudeRecoveryFixture(stateRoot, otherProject, "other conversation");
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext({
      env: { XDG_STATE_HOME: stateRoot },
      projectRoot: currentProject,
    }), ["resume", "--list"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("current conversation");
    expect(out.text()).not.toContain("other conversation");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("resume --all explicitly lists every project and conflicts with --project", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-all-"));
    tempDirs.push(stateRoot);
    const currentProject = path.join(stateRoot, "current-project");
    const otherProject = path.join(stateRoot, "other-project");
    writeClaudeRecoveryFixture(stateRoot, currentProject, "current conversation");
    writeClaudeRecoveryFixture(stateRoot, otherProject, "other conversation");
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);
    const context = strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot: currentProject });

    const status = await runCommandApp(context, ["resume", "--all", "--list"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("current conversation");
    expect(out.text()).toContain("other conversation");
    await expect(
      runCommandApp(context, ["resume", "--all", "--project", otherProject, "--list"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Arguments all and project are mutually exclusive") });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("resume --agent filters recovery evidence by exact agent id", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-agent-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    writeClaudeRecoveryFixture(stateRoot, projectRoot, "Claude recovery");
    writeHostRecoveryFixture(stateRoot, projectRoot, "codex");
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);
    const context = strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot });

    expect(await runCommandApp(context, ["resume", "--agent", "codex", "--list"], runDefault)).toBe(0);

    expect(out.text()).toContain("codex");
    expect(out.text()).not.toContain("Claude recovery");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("repeated resume --agent filters select their union", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-agents-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    writeClaudeRecoveryFixture(stateRoot, projectRoot, "Claude recovery");
    writeHostRecoveryFixture(stateRoot, projectRoot, "codex");
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);
    const context = strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot });

    expect(await runCommandApp(
      context,
      ["resume", "--agent", "claude", "--agent", "codex", "--list"],
      runDefault,
    )).toBe(0);

    expect(out.text()).toContain("Claude recovery");
    expect(out.text()).toContain("codex");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("resume --list strips a bidi override and a zero-width space from an agent-supplied name (review F5)", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-sanitize-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    writeClaudeRecoveryFixture(stateRoot, projectRoot, "safe‮name​here");
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(
      strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot }),
      ["resume", "--list"],
      runDefault,
    );

    expect(status).toBe(0);
    expect(out.text()).toContain("safenamehere");
    expect(out.text()).not.toContain("‮");
    expect(out.text()).not.toContain("​");
  });

  test("resume with no id and no TTY prints the list, same as --list", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-notty-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    writeClaudeRecoveryFixture(stateRoot, projectRoot, "current conversation");
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await withTty(false, false, () =>
      runCommandApp(strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot }), ["resume"], runDefault));

    expect(status).toBe(0);
    expect(out.text()).toContain("current conversation");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("resume --all on a TTY never shows the same-terminal one question", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-all-tty-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    // Eligible (recordVersion 2, provably dead owner) so the picker actually
    // offers it; `--all` must still never ask the one question over it.
    writeHostRecoveryFixtureV2(stateRoot, projectRoot);
    const runDefault = vi.fn(async () => 0);
    const promptApi = fakePromptApi(() => PROMPT_CANCEL);
    const context = strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot, promptApi });

    const status = await withTty(true, true, () => runCommandApp(context, ["resume", "--all"], runDefault));

    expect(status).toBe(0);
    expect(promptApi.calls.length).toBeGreaterThan(0);
    for (const call of promptApi.calls) expect(call.message).not.toContain("Interrupted in this terminal");
    // Spanning more than one project, each row is prefixed with its own
    // project name.
    expect(promptApi.calls[0]?.options[0]?.label.startsWith("current-project")).toBe(true);
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("resume --all shows an unverified, unknown-owner, version-2 row (controller ruling, fix round 1)", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-all-unverified-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    // `hostPid: process.pid` (this very test process: genuinely alive) with
    // no outcome and no recorded boot id/process start makes `hostOwnerState`
    // come out "unknown", never "dead" or "active" — `selectResumeCandidates`
    // (the current-project picker, unchanged) would hide this row entirely,
    // but `--all`/`--project` must still offer it; the live classification in
    // `resumeRecoveryRuntime` decides for real, under the lock.
    writeHostRecoveryFixtureV2(stateRoot, projectRoot, { outcome: undefined, hostPid: process.pid });
    const runDefault = vi.fn(async () => 0);
    const promptApi = fakePromptApi(() => PROMPT_CANCEL);
    const context = strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot, promptApi });

    const status = await withTty(true, true, () => runCommandApp(context, ["resume", "--all"], runDefault));

    expect(status).toBe(0);
    expect(promptApi.calls).toHaveLength(1);
    expect(promptApi.calls[0]?.options).toHaveLength(1);
    expect(promptApi.calls[0]?.options[0]?.label.startsWith("current-project")).toBe(true);
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("a host record without a record version is listed but hidden from the picker (decision 3)", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-resume-recordver-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "current-project");
    writeHostRecoveryFixture(stateRoot, projectRoot, "codex"); // no recordVersion: pre-this-release, hidden
    // A control differing from the hidden row above *only* in recordVersion —
    // same agent, same times, same owner-dead outcome — isolates recordVersion
    // as the one thing that flips visibility, rather than relying only on the
    // Claude row below (which differs in evidenceKind, fields, and source).
    writeHostRecoveryFixture(stateRoot, projectRoot, "codex", { id: "rf-20260801-control1", recordVersion: 2 });
    writeClaudeRecoveryFixture(stateRoot, projectRoot, "eligible conversation"); // always eligible
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const listStatus = await runCommandApp(
      strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot }),
      ["resume", "--list"],
      runDefault,
    );
    expect(listStatus).toBe(0);
    expect(out.text()).toContain("codex");
    expect(out.text()).toContain("eligible conversation");

    const promptApi = fakePromptApi(() => PROMPT_CANCEL);
    const context = strictContext({ env: { XDG_STATE_HOME: stateRoot }, projectRoot, promptApi });

    const status = await withTty(true, true, () => runCommandApp(context, ["resume"], runDefault));

    expect(status).toBe(0);
    expect(promptApi.calls).toHaveLength(1);
    // Exactly two: the Claude row and the recordVersion-2 control. The
    // version-less row never reaches the options at all.
    const labels = (promptApi.calls[0]?.options ?? []).map((option) => option.label);
    expect(labels).toHaveLength(2);
    expect(labels.some((label) => label.includes("eligible conversation"))).toBe(true);
    expect(labels.some((label) => label.includes("codex"))).toBe(true);
    expect(runDefault).not.toHaveBeenCalled();
  });

  describe("choice: dismiss (\"Forget it\")", () => {
    afterEach(() => {
      recoverySeams.dismissResult = undefined;
    });

    function setupDismissProject(prefix: string): { stateRoot: string; projectRoot: string } {
      const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
      tempDirs.push(stateRoot);
      const projectRoot = path.join(stateRoot, "current-project");
      writeClaudeRecoveryFixture(stateRoot, projectRoot, "forgettable conversation");
      fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
      fs.writeFileSync(path.join(projectRoot, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}\n');
      return { stateRoot, projectRoot };
    }

    // The only eligible row is picked, then "forget" at the sub-menu —
    // `contextForRecoveryItem` still reaches `assets()` to build the
    // `RuntimeContext` dismiss needs, so it is stubbed here, not left
    // throwing like `strictContext`'s default.
    function dismissContext(stateRoot: string, projectRoot: string): RunfreeCommandContext {
      let step = 0;
      const promptApi = fakePromptApi((call) => {
        step += 1;
        return step === 1 ? call.options[0]?.value : "forget";
      });
      return strictContext({
        env: { XDG_STATE_HOME: stateRoot },
        projectRoot,
        promptApi,
        assets: () => ({ runtimeDir: "/fake/runtime" }) as unknown as ReturnType<RunfreeCommandContext["assets"]>,
      });
    }

    test("'dismissed' prints the forgotten-session confirmation and exits 0 without starting a runtime", async () => {
      const { stateRoot, projectRoot } = setupDismissProject("runfree-resume-dismiss-ok-");
      recoverySeams.dismissResult = "dismissed";
      const out = captureStdout();
      const runDefault = vi.fn(async () => 0);

      const status = await withTty(true, true, () =>
        runCommandApp(dismissContext(stateRoot, projectRoot), ["resume"], runDefault));

      expect(status).toBe(0);
      expect(out.text()).toContain("forgot the interrupted session from");
      expect(runDefault).not.toHaveBeenCalled();
      // The dismiss branch never starts a runtime: the only function that
      // could is `resumeRecoveryRuntime`, and it was never called.
      expect(runtimeSeams.resumeRecoveryRuntimeCalls).toBe(0);
    });

    test("'claimed' refuses: another terminal is resuming this session", async () => {
      const { stateRoot, projectRoot } = setupDismissProject("runfree-resume-dismiss-claimed-");
      recoverySeams.dismissResult = "claimed";

      const refusal = await cliRefusal(withTty(true, true, () =>
        runCommandApp(dismissContext(stateRoot, projectRoot), ["resume"], vi.fn(async () => 0))));

      expect(refusal.status).toBe(1);
      expect(refusal.message).toBe("another terminal is resuming this session");
      expect(runtimeSeams.resumeRecoveryRuntimeCalls).toBe(0);
    });

    test("'changed' refuses: the session record changed; run runfree resume again", async () => {
      const { stateRoot, projectRoot } = setupDismissProject("runfree-resume-dismiss-changed-");
      recoverySeams.dismissResult = "changed";

      const refusal = await cliRefusal(withTty(true, true, () =>
        runCommandApp(dismissContext(stateRoot, projectRoot), ["resume"], vi.fn(async () => 0))));

      expect(refusal.status).toBe(1);
      expect(refusal.message).toBe("the session record changed; run runfree resume again");
      expect(runtimeSeams.resumeRecoveryRuntimeCalls).toBe(0);
    });

    test("'deferred' refuses: a runtime lifecycle change is in progress; run runfree resume again", async () => {
      const { stateRoot, projectRoot } = setupDismissProject("runfree-resume-dismiss-deferred-");
      recoverySeams.dismissResult = "deferred";

      const refusal = await cliRefusal(withTty(true, true, () =>
        runCommandApp(dismissContext(stateRoot, projectRoot), ["resume"], vi.fn(async () => 0))));

      expect(refusal.status).toBe(1);
      expect(refusal.message).toBe("a runtime lifecycle change is in progress; run runfree resume again");
      expect(runtimeSeams.resumeRecoveryRuntimeCalls).toBe(0);
    });
  });

  describe("bare runfree resume: the one question (resume.ts)", () => {
    const ITERM_ID = "w0t0p0:same-terminal";

    // A strong-match v2 Claude host record: its terminal ids equal the ids
    // `currentTerminal` reads from this test env, so bare `runfree resume`
    // asks the one question about it.
    function setupStrongMatchProject(prefix: string): { stateRoot: string; projectRoot: string; env: NodeJS.ProcessEnv; recordPath: string } {
      const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
      tempDirs.push(stateRoot);
      const projectRoot = path.join(stateRoot, "current-project");
      const recordPath = writeHostRecoveryFixtureV2(stateRoot, projectRoot, {
        terminalIds: { iterm: ITERM_ID },
        termProgram: "iTerm.app",
      });
      fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
      fs.writeFileSync(path.join(projectRoot, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}\n');
      const env = {
        XDG_STATE_HOME: stateRoot,
        TERM_PROGRAM: "iTerm.app",
        ITERM_SESSION_ID: ITERM_ID,
        RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
        RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
      };
      return { stateRoot, projectRoot, env, recordPath };
    }

    function resumeContext(projectRoot: string, env: NodeJS.ProcessEnv, promptApi: PromptApi): RunfreeCommandContext {
      return strictContext({
        env,
        projectRoot,
        promptApi,
        assets: () => ({ runtimeDir: "/fake/runtime" }) as unknown as ReturnType<RunfreeCommandContext["assets"]>,
      });
    }

    test("on a TTY, a strong match asks the one question, and \"Resume it\" reaches resumeRecoveryRuntime with that item", async () => {
      const { projectRoot, env, recordPath } = setupStrongMatchProject("runfree-resume-one-question-");
      const expected = scanRecoveryInventory({ env, projectRoot }).items[0];
      if (!expected) throw new Error("missing recovery fixture");
      runtimeSeams.resumeRecoveryRuntime = vi.fn(async () => 0);
      const promptApi = fakePromptApi(() => "resume");
      const runDefault = vi.fn(async () => 0);

      const status = await withTty(true, true, () =>
        runCommandApp(resumeContext(projectRoot, env, promptApi), ["resume"], runDefault));

      expect(status).toBe(0);
      expect(promptApi.calls).toHaveLength(1);
      expect(promptApi.calls[0]?.message).toContain("Interrupted in this terminal");
      expect(runtimeSeams.resumeRecoveryRuntime).toHaveBeenCalledTimes(1);
      const passed = vi.mocked(runtimeSeams.resumeRecoveryRuntime).mock.calls[0]?.[2] as RecoveryItem | undefined;
      expect(passed?.id).toBe(expected.id);
      expect(passed?.evidencePath).toBe(recordPath);
      expect(passed?.fingerprint).toEqual(expected.fingerprint);
      expect(runDefault).not.toHaveBeenCalled();
    });

    test("stdin a TTY but stdout not: prints the list and asks nothing", async () => {
      const { projectRoot, env } = setupStrongMatchProject("runfree-resume-stdout-notty-");
      runtimeSeams.resumeRecoveryRuntime = vi.fn(async () => 0);
      const promptApi = fakePromptApi(() => "resume");
      const out = captureStdout();

      const status = await withTty(true, false, () =>
        runCommandApp(resumeContext(projectRoot, env, promptApi), ["resume"], vi.fn(async () => 0)));

      expect(status).toBe(0);
      expect(promptApi.calls).toHaveLength(0);
      expect(out.text()).toContain("claude");
      expect(out.text()).toContain("11111111-2222-4333-8444-555555555555");
      expect(runtimeSeams.resumeRecoveryRuntime).not.toHaveBeenCalled();
    });

    test("decision 6: a resume that ends non-zero keeps the record, and the next runfree resume asks the same one question", async () => {
      const { projectRoot, env, recordPath } = setupStrongMatchProject("runfree-resume-nonzero-");
      // The real claim and consumption path around a resumed session that
      // ended non-zero (no `supersededByNewRecord`): only the Docker-facing
      // session itself is replaced.
      runtimeSeams.resumeRecoveryRuntime = vi.fn(async (context: RuntimeContext, _io: RuntimeIO, item: RecoveryItem) => {
        const result = await runWithRecoveryClaim(context, item, () => 137);
        return result?.status ?? 1;
      });
      const firstPrompt = fakePromptApi(() => "resume");

      const status = await withTty(true, true, () =>
        runCommandApp(resumeContext(projectRoot, env, firstPrompt), ["resume"], vi.fn(async () => 0)));

      expect(status).toBe(137);
      expect(fs.existsSync(recordPath)).toBe(true);
      const secondPrompt = fakePromptApi(() => PROMPT_CANCEL);
      vi.spyOn(console, "log").mockImplementation(() => {});

      const second = await withTty(true, true, () =>
        runCommandApp(resumeContext(projectRoot, env, secondPrompt), ["resume"], vi.fn(async () => 0)));

      expect(second).toBe(0);
      expect(secondPrompt.calls).toHaveLength(1);
      expect(secondPrompt.calls[0]?.message).toContain("Interrupted in this terminal");
      expect(secondPrompt.calls[0]?.message).toBe(firstPrompt.calls[0]?.message);
      expect(secondPrompt.calls[0]?.options.map((option) => option.value)).toEqual(["resume", "not-now", "forget"]);
    });
  });

  test("runfree claude refuses before the approval gate, scanning nothing, when the checkout binding is corrupted (decision 5)", async () => {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-claude-decision5-"));
    tempDirs.push(projectRoot);
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-claude-decision5-state-"));
    tempDirs.push(stateRoot);
    fs.mkdirSync(path.join(projectRoot, ".runfree"));
    fs.writeFileSync(path.join(projectRoot, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}');
    const env = {
      XDG_STATE_HOME: stateRoot,
      XDG_CONFIG_HOME: path.join(stateRoot, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const context = {
      projectRoot,
      project: projectInfo(projectRoot, env),
      runtimeRoot: path.join(projectRoot, "runtime"),
      env,
    } as RuntimeContext;
    // A record that, if the launch ever scanned for it, would be a strong
    // match and a one-question candidate — proving the launch path never
    // reaches it, not merely that no such record happened to exist.
    writeHostRecoveryFixtureV2(stateRoot, projectRoot, {
      terminalIds: { iterm: "same-terminal" },
      termProgram: "iTerm.app",
      hostTty: "/dev/ttys004",
    });

    // Approve, then corrupt the checkout binding: `requireUsableApprovalSelection`
    // refuses before Docker, before any claim, and — per decision 5 — before
    // any recovery scan. Same reachability proof `launch-approval-gate.test.ts`
    // uses for the start funnel and for `runfree resume`.
    const candidate = captureDesiredPolicyCandidate(projectRoot, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(projectRoot, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(projectRoot, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(projectRoot, context.project, "interactive");
    const approvalsPath = context.project.paths.controlApprovalsPath;
    const stored = JSON.parse(fs.readFileSync(approvalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
    stored.checkoutBinding.rootInode = "999999999";
    fs.writeFileSync(approvalsPath, `${JSON.stringify(stored, null, 2)}\n`);

    const io = {
      capture: () => ({ status: 1, stdout: "", stderr: "" }),
      run: () => 0,
      commandExists: () => true,
      confirm: () => { throw new Error("a non-interactive refusal must not confirm"); },
      isInteractive: () => false,
      admin: async () => 0,
    } as unknown as RuntimeIO;
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});

    await withTty(true, true, async () => {
      await expect(runAgentCommand(context, io, "claude", { quiet: false, verbose: false })).rejects.toThrow(
        "require exact approval before startup",
      );
    });

    expect(recoverySeams.scanCalls).toBe(0);
  });

  // Controller ruling (fix round 1): a refusal that stops the launch early
  // proves nothing by itself — stopping early is exactly when a scan is also
  // structurally unreachable. This test instead lets the launch run past the
  // approval gate and the operational-service review (approvals genuinely
  // approved, the review genuinely allowed to enable `agent-claude`) into
  // `startRuntime` — the Docker boundary, stubbed to a known failed status —
  // and still asserts zero `scanRecoveryInventory` calls. It does not reach
  // the session itself: everything after `startRuntime` is out of scope.
  test("runfree claude never scans on the launch path through the approval gate and service review into startRuntime (decision 5)", async () => {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-claude-decision5-full-"));
    tempDirs.push(projectRoot);
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-claude-decision5-full-state-"));
    tempDirs.push(stateRoot);
    fs.mkdirSync(path.join(projectRoot, ".runfree"));
    fs.writeFileSync(path.join(projectRoot, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}');
    const env = {
      XDG_STATE_HOME: stateRoot,
      XDG_CONFIG_HOME: path.join(stateRoot, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const context = {
      projectRoot,
      project: projectInfo(projectRoot, env),
      runtimeRoot: path.join(projectRoot, "runtime"),
      env,
    } as RuntimeContext;
    // Bait, as above: a record that would be a strong, one-question
    // candidate if the launch ever scanned for it.
    writeHostRecoveryFixtureV2(stateRoot, projectRoot, {
      terminalIds: { iterm: "same-terminal" },
      termProgram: "iTerm.app",
      hostTty: "/dev/ttys004",
    });

    // Genuinely approved, matching this checkout (no corruption this time):
    // the approval gate passes, so the launch continues past it.
    const candidate = captureDesiredPolicyCandidate(projectRoot, context.project.paths.controlCandidatesDir);
    approveNetworkCandidate(projectRoot, context.project, candidate, "network-project", "interactive");
    approveNetworkCandidate(projectRoot, context.project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(projectRoot, context.project, "interactive");

    // `startRuntime` is the Docker boundary; stub it to a known, clean
    // "failed" result so `runConfiguredAgent` returns normally right after
    // it, instead of needing a real Docker daemon.
    startupSeams.startRuntime = vi.fn(async () => ({ kind: "failed", fastPath: false, status: 7 }));

    const io = {
      capture: () => ({ status: 1, stdout: "", stderr: "" }),
      run: () => 0,
      commandExists: () => true,
      // The operational-service review finds `agent-claude` unselected by
      // this minimal policy and asks to enable it; answering yes and
      // stubbing the admin call lets that review complete without touching
      // Docker or the project's real policy file.
      confirm: () => true,
      isInteractive: () => true,
      admin: async () => 0,
    } as unknown as RuntimeIO;
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});

    const status = await withTty(true, true, () =>
      runAgentCommand(context, io, "claude", { quiet: false, verbose: false }));

    // `startRuntime`'s own stubbed status, proving the real launch logic ran
    // all the way to it rather than failing earlier for an unrelated reason.
    expect(status).toBe(7);
    expect(startupSeams.startRuntime).toHaveBeenCalled();
    expect(recoverySeams.scanCalls).toBe(0);
  });

  test("init ensures the project (reaches the typed handler); unknown flags reject first", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["init", "--bogus"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    // Valid `init` reaches project setup (strictContext throws there), proving the
    // typed module runs without delegating to runDefault.
    await expect(runCommandApp(strictContext(), ["init", "--yes"], runDefault)).rejects.toThrow(
      "ensureProject() must not be called",
    );
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("the typed default rejects unknown flags and extra positionals before any runtime work", async () => {
    const runDefault = vi.fn(async () => 0);

    // The agent never receives trailing flags, so accepting one would silently
    // drop it (`claude --resume` starting a fresh session, `--version` starting
    // the runtime). strictContext throws if the runtime context is reached, so a
    // CliError here proves the refusal came first.
    const cases: Array<[string[], string, string | undefined]> = [
      [["--version"], "Unknown argument: version", "use: runfree version"],
      [["claude", "--resume"], "Unknown argument: resume", "use: runfree resume"],
      [["claude", "--resume=abc"], "Unknown argument: resume", "use: runfree resume"],
      [["codex", "--bogus"], "Unknown argument: bogus", undefined],
      [["claude", "extra"], "Unknown argument: extra", undefined],
    ];
    for (const [args, reason, hint] of cases) {
      const error = await runCommandApp(strictContext(), args, runDefault).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect(error, args.join(" ")).toBeInstanceOf(CliError);
      expect((error as CliError).message).toContain(reason);
      if (hint) expect((error as CliError).message).toContain(hint);
      else expect((error as CliError).message).not.toContain("use:");
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("a migrated command's unknown flag gets no default-command hint", async () => {
    await expect(runCommandApp(strictContext(), ["status", "--resume"], vi.fn(async () => 0))).rejects.toMatchObject({
      message: expect.not.stringContaining("use: runfree resume"),
    });
  });

  test("the typed default interprets --quiet and --verbose", async () => {
    const runDefault = vi.fn(async () => 0);

    for (const args of [["--quiet"], ["--verbose"], ["-v", "claude"], ["claude", "--quiet"]]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toThrow(
        "runtimeContext() must not be called",
      );
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("rejects unknown options on a migrated command before its handler runs", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["version", "--bad"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bad"),
    });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("rejects extra positionals on a migrated command", async () => {
    await expect(runCommandApp(strictContext(), ["version", "extra"], vi.fn(async () => 0))).rejects.toBeInstanceOf(
      CliError,
    );
  });

  test("rejects an implicit negated flag because boolean-negation is off", async () => {
    await expect(
      runCommandApp(strictContext(), ["project-id", "--no-compose-name"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: no-compose-name") });
  });

  test("reads a boolean flag and never materializes assets for project-id", async () => {
    const out = captureStdout();

    const plain = await runCommandApp(strictContext(), ["project-id"], vi.fn(async () => 0));
    expect(plain).toBe(0);
    expect(out.text()).toBe(projectHash(PROJECT_ROOT));
  });

  test("project-id --compose-name prints the compose project name", async () => {
    const out = captureStdout();

    await runCommandApp(strictContext(), ["project-id", "--compose-name"], vi.fn(async () => 0));

    expect(out.text()).toBe(composeProjectName(PROJECT_ROOT));
  });

  test("validates an enum positional before the handler materializes assets", async () => {
    const runDefault = vi.fn(async () => 0);

    // `assets` handler calls context.assets(); strictContext throws there. A
    // CliError (not the assets() Error) proves validation happened first.
    await expect(runCommandApp(strictContext(), ["assets", "bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("requires the assets subcommand positional", async () => {
    await expect(runCommandApp(strictContext(), ["assets"], vi.fn(async () => 0))).rejects.toBeInstanceOf(CliError);
  });

  test("rejects --workspace after a migrated command (pre-command global only)", async () => {
    await expect(
      runCommandApp(strictContext(), ["project-id", "--workspace", "/elsewhere"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: workspace") });
  });

  test("renders command-specific help without running the handler or the default", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext(), ["version", "--help"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("runfree version");
    expect(out.text()).toContain("Print the Runfree version");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("propagates an async handler rejection without printing yargs help text", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);
    // The typed `$0 [agent]` handler runs and throws (here via runtimeContext);
    // a started handler's CliError must propagate as-is, never reinterpreted as a
    // usage error and never printing yargs help.
    const context = strictContext({
      runtimeContext: () => {
        throw new CliError("handler boom", 2);
      },
    });

    await expect(runCommandApp(context, ["claude"], runDefault)).rejects.toMatchObject({
      message: "handler boom",
      status: 2,
    });
    expect(out.text()).toBe("");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

describe("group + leaf command parsing (Phase 2)", () => {
  test("bare group command is a usage error showing the group's own commands", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["image"], runDefault)).rejects.toMatchObject({
      message: "runfree image needs a subcommand",
      detail: expect.stringContaining("runfree image init"),
    });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("group --help prints the group's native help (positionals + examples) without running a handler", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext(), ["image", "--help"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("runfree image init");
    expect(out.text()).toContain("runfree image approve-context");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("group rejects an invalid subcommand before any context/side-effect access", async () => {
    // strictContext throws a plain Error from assets()/projectInfo(); a CliError
    // proves the choice was rejected during parsing, before the handler ran.
    await expect(runCommandApp(strictContext(), ["image", "bogus"], vi.fn(async () => 0))).rejects.toBeInstanceOf(
      CliError,
    );
  });

  test("group subcommand rejects unknown flags before any context/side-effect access", async () => {
    await expect(
      runCommandApp(strictContext(), ["image", "init", "--bogus"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
  });

  test("inbox is a strict group and rejects invalid input before touching project state", async () => {
    await expect(runCommandApp(strictContext(), ["inbox"], vi.fn(async () => 0))).rejects.toMatchObject({
      message: "runfree inbox needs a subcommand",
      detail: expect.stringContaining("runfree inbox paste"),
    });
    await expect(
      runCommandApp(strictContext(), ["inbox", "paste", "--bogus"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
    await expect(
      runCommandApp(strictContext(), ["inbox", "clean", "--copy"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: copy") });
  });

  test("deprecated paste-image dispatches to inbox paste with clean stdout", async () => {
    const stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-inbox-command-")));
    tempDirs.push(stateDir);
    const source = path.join(stateDir, "source.png");
    fs.writeFileSync(source, Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]));
    const out = captureStdout();
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => errors.push(args.join(" ")));
    const context = strictContext({
      env: {
        RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source,
        RUNFREE_TEST_INBOX_RANDOM: "a8f3",
      },
      projectInfo: () => ({ paths: { inboxDir: path.join(stateDir, "inbox") } }) as never,
    });

    expect(await runCommandApp(context, ["paste-image"], vi.fn(async () => 0))).toBe(0);

    expect(out.text()).toMatch(/^\/runfree\/inbox\/clip-.*-a8f3\.png$/);
    expect(errors).toEqual(["warning: `runfree paste-image` is deprecated; use `runfree inbox paste`"]);
  });

  test("leaf command rejects conflicting flags before any context/side-effect access", async () => {
    await expect(
      runCommandApp(strictContext(), ["paste-image", "--copy", "--clean"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("mutually exclusive") });
  });

  test("leaf command rejects unknown flags", async () => {
    await expect(
      runCommandApp(strictContext(), ["paste-image", "--bogus"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
  });

  test("leaf command --help prints usage without running the handler", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext(), ["paste-image", "--help"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("runfree paste-image");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("-h short form prints usage anywhere it can be appended (group, leaf)", async () => {
    // The Help Contract reserves -h/--help "anywhere it can be appended". Cover
    // the short form, which --help-only tests miss.
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    expect(await runCommandApp(strictContext(), ["service", "-h"], runDefault)).toBe(0);
    expect(out.text()).toContain("runfree service enable");
    expect(await runCommandApp(strictContext(), ["version", "-h"], runDefault)).toBe(0);
    expect(out.text()).toContain("runfree version");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("group <sub> --help / -h renders that subcommand's own native help (third guaranteed form)", async () => {
    // `runfree <group> <sub> --help` and its -h form are guaranteed by the Help
    // Contract; native yargs help scopes to the subcommand (its own positionals
    // and options), not just the group.
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    expect(await runCommandApp(strictContext(), ["service", "enable", "--help"], runDefault)).toBe(0);
    expect(out.text()).toContain("--param");
    expect(await runCommandApp(strictContext(), ["service", "enable", "-h"], runDefault)).toBe(0);
    expect(await runCommandApp(strictContext(), ["credential", "set-source", "--help"], runDefault)).toBe(0);
    expect(out.text()).toContain("runfree service enable <id>");
    expect(out.text()).toContain("runfree credential set-source <name>");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

describe("runtime commands (typed: rebuild/logs/git; shim: vnc)", () => {
  // rebuild/logs/git are typed end-to-end: a parse rejection is a CliError
  // before enforcement; valid input reaches the typed runtime core via
  // context.runtimeContext() (strictContext throws there) without delegating to
  // runDefault.
  test("rebuild: valid input reaches the runtime core, no delegation", async () => {
    const runDefault = vi.fn(async () => 5);

    await expect(
      runCommandApp(strictContext(), ["rebuild", "--yes", "--verbose"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("rebuild rejects unknown flags before enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["rebuild", "--bogus"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("up: valid input (incl. --audit-network forms) reaches the core, no delegation", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["up"], runDefault)).rejects.toThrow(
      "runtimeContext() must not be called",
    );
    // bare --audit-network (default window) and --audit-network=<dur> both parse.
    await expect(
      runCommandApp(strictContext(), ["up", "--verbose", "--audit-network"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["up", "--audit-network=2h"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    // The space form `--audit-network 2h` is accepted by the typed yargs grammar
    // (an intentional improvement over the legacy parseUpOptions, which rejected
    // it); the duration is still validated and reaches the core.
    await expect(
      runCommandApp(strictContext(), ["up", "--audit-network", "2h"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("up rejects unknown flags and malformed durations before any side effect", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["up", "--bogus"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    // A malformed --audit-network duration is parsed before runtimeContext(), so
    // it is a CliError that never materializes assets or asserts policy.
    await expect(
      runCommandApp(strictContext(), ["up", "--audit-network=nope"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("invalid --audit-network duration") });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("audit: subcommands reach the core; bad input rejects before enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["audit"], runDefault)).rejects.toMatchObject({
      message: "runfree audit needs a subcommand",
      detail: expect.stringContaining("runfree audit status"),
    });
    await expect(runCommandApp(strictContext(), ["audit", "bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["audit", "report", "--bogus"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
    expect(runDefault).not.toHaveBeenCalled();

    for (const args of [["audit", "status"], ["audit", "off"], ["audit", "report", "--json"]]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toThrow(
        "runtimeContext() must not be called",
      );
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("approve: MCP flags parse before runtime enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(
      runCommandApp(strictContext(), ["approve", "abcd", "--mcp-scope", "bogus"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["approve", "abcd", "--save-mcp-rule", "bogus"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["approve", "abcd", "--scope", "session", "--mcp-scope", "server-tools"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["approve", "abcd", "--save-mcp-rule", "tool"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("deps: bare defaults to plan; subcommands reach the core; bad input rejects", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["deps", "bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    // Per-subcommand strict: --force is only valid on `reset`.
    await expect(runCommandApp(strictContext(), ["deps", "plan", "--force"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: force"),
    });
    await expect(runCommandApp(strictContext(), ["deps", "reset", "--bad"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bad"),
    });
    // Every deps subcommand is per-subcommand strict.
    for (const sub of ["plan", "install", "doctor"]) {
      await expect(runCommandApp(strictContext(), ["deps", sub, "--typo"], runDefault)).rejects.toMatchObject({
        message: expect.stringContaining("Unknown argument: typo"),
      });
    }
    expect(runDefault).not.toHaveBeenCalled();

    // Bare `deps` (defaults to plan), explicit subcommands, and `reset --force`
    // all reach the typed core without delegating.
    for (const args of [["deps"], ["deps", "plan"], ["deps", "install"], ["deps", "doctor"], ["deps", "reset", "--force"]]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toThrow(
        "runtimeContext() must not be called",
      );
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("simple runtime commands reach the core", async () => {
    const runDefault = vi.fn(async () => 0);

    for (const args of [
      ["status"],
      ["resources"],
      ["sessions"],
      ["stop"],
      ["destroy"],
      ["shell"],
      ["shell", "--verbose"],
    ]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toThrow(
        "runtimeContext() must not be called",
      );
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("simple runtime commands reject unknown flags/positionals before enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["status", "--bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    await expect(runCommandApp(strictContext(), ["status", "extra"], runDefault)).rejects.toBeInstanceOf(CliError);
    await expect(runCommandApp(strictContext(), ["shell", "--bogus"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("sessions rename replaces only the host-owned display name", async () => {
    const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-rename-command-"));
    tempDirs.push(stateRoot);
    const projectRoot = path.join(stateRoot, "project");
    const sessionId = "rf-20260801-c0de01";
    writeHostRecoveryFixture(stateRoot, projectRoot, "codex");
    const stateDir = path.join(stateRoot, "runfree", "projects", projectHash(projectRoot));
    const sessionsDir = path.join(stateDir, "sessions");
    const sessionPath = path.join(sessionsDir, `${sessionId}.json`);
    const before = {
      ...(JSON.parse(fs.readFileSync(sessionPath, "utf8")) as Record<string, unknown>),
      name: "old name",
      hostInbox: path.join(stateDir, "inbox"),
      containerInbox: "/runfree/inbox",
    };
    fs.writeFileSync(sessionPath, `${JSON.stringify(before)}\n`);
    const runtimeContext = {
      projectRoot,
      project: {
        config: {},
        paths: {
          inboxDir: path.join(stateDir, "inbox"),
          sessionsDir,
        },
      },
      runtimeRoot: path.join(stateRoot, "runtime"),
      env: {},
    } as unknown as RuntimeContext;
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(
      strictContext({ projectRoot, runtimeContext: () => runtimeContext }),
      ["sessions", "rename", sessionId, "  payments refactor  "],
      runDefault,
    );

    expect(status).toBe(0);
    expect(out.text()).toBe(`renamed ${sessionId} to payments refactor`);
    const after = JSON.parse(fs.readFileSync(sessionPath, "utf8")) as Record<string, unknown>;
    expect(after).toEqual({ ...before, name: "payments refactor" });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("sessions rename validates its complete intent before host-state access", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(
      runCommandApp(strictContext(), ["sessions", "rename", "rf-20260801-c0de01", "bad\nname"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["sessions", "rename", "rf-20260801-c0de01"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("logs requires a valid service positional before reaching the core", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["logs"], runDefault)).rejects.toMatchObject({
      message: "runfree logs needs a subcommand",
      detail: expect.stringContaining("runfree logs <service>"),
    });
    await expect(runCommandApp(strictContext(), ["logs", "bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    expect(runDefault).not.toHaveBeenCalled();

    await expect(
      runCommandApp(strictContext(), ["logs", "proxy", "--verbose"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("vnc strictly validates its options before reaching the core", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["vnc", "--bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    expect(runDefault).not.toHaveBeenCalled();

    await expect(
      runCommandApp(strictContext(), ["vnc", "start", "--host-port", "5901"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("vnc accepts literal --no-* flags (boolean-negation is off)", async () => {
    // `--no-password` / `--no-start-server` must parse as their own option
    // names, not as negations of `password` / `start-server`. Guards the
    // dependence on the global `boolean-negation: false` parser setting: a
    // parse failure would reject these before the runtime core; instead they
    // reach the typed core (runtimeContext sentinel) without delegating.
    const runDefault = vi.fn(async () => 0);

    await expect(
      runCommandApp(strictContext(), ["vnc", "--no-password"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["vnc", "start", "--no-start-server"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("git requires a valid subcommand before reaching the core", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["git"], runDefault)).rejects.toMatchObject({
      message: "runfree git needs a subcommand",
      detail: expect.stringContaining("repair-worktree-links"),
    });
    await expect(runCommandApp(strictContext(), ["git", "bogus"], runDefault)).rejects.toBeInstanceOf(CliError);
    expect(runDefault).not.toHaveBeenCalled();

    await expect(
      runCommandApp(strictContext(), ["git", "repair-worktree-links"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("runtime command --help prints usage without delegating", async () => {
    const out = captureStdout();
    const runDefault = vi.fn(async () => 0);

    const status = await runCommandApp(strictContext(), ["vnc", "--help"], runDefault);

    expect(status).toBe(0);
    expect(out.text()).toContain("runfree vnc");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

describe("admin host command (Phase 4)", () => {
  // strictContext.adminContext() throws a plain Error; a CliError therefore
  // proves yargs rejected the input during parsing, before the handler reached
  // the admin state / enforcement (no policy mutation possible).
  test("bare host shows the group's own usage as a usage error", async () => {
    const runDefault = vi.fn(async () => 0);

    const usage = await cliRefusal(runCommandApp(strictContext(), ["host"], runDefault));
    expect(usage.message).toBe("runfree host needs a subcommand");
    expect(usage.detail).toContain("runfree host add");
    // A bare group prints only its own usage, never another group's or the full admin reference.
    expect(usage.detail).not.toContain("runfree credential add");
    expect(usage.detail).not.toContain("runfree service enable");
    expect(usage.detail).not.toContain("runfree mcp list");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("host --help prints usage without touching admin state", async () => {
    const out = captureStdout();

    const status = await runCommandApp(strictContext(), ["host", "--help"], vi.fn(async () => 0));

    expect(status).toBe(0);
    expect(out.text()).toContain("Commands:");
    expect(out.text()).toContain("runfree host add");
  });

  test("host rejects unknown subcommands and flags before enforcement", async () => {
    await expect(runCommandApp(strictContext(), ["host", "bogus"], vi.fn(async () => 0))).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(runCommandApp(strictContext(), ["host", "add"], vi.fn(async () => 0))).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(
      runCommandApp(strictContext(), ["host", "add", "example.org", "--bogus"], vi.fn(async () => 0)),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
    await expect(
      runCommandApp(strictContext(), ["host", "remove", "example.org", "--bad"], vi.fn(async () => 0)),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("domain command is removed instead of acting as an alias", async () => {
    const runDefault = vi.fn(async () => 0);

    const refusal = await cliRefusal(runCommandApp(strictContext(), ["domain"], runDefault));
    expect(refusal.message).toContain("`runfree domain` has been removed");
    expect(refusal.message).toContain("runfree host add");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

describe("admin host-service command", () => {
  afterEach(() => {
    hostServiceSeams.admit = undefined;
    hostServiceSeams.probe = undefined;
    hostServiceSeams.activate = undefined;
    hostServiceSeams.recorded = [];
    hostServiceSeams.recordFails = false;
  });

  test("bare host-service shows the group's own usage as a usage error", async () => {
    const runDefault = vi.fn(async () => 0);

    const usage = await cliRefusal(runCommandApp(strictContext(), ["host-service"], runDefault));
    expect(usage.message).toBe("runfree host-service needs a subcommand");
    expect(usage.detail).toContain("runfree host-service add");
    expect(usage.detail).not.toContain("runfree host add");
    expect(usage.detail).not.toContain("runfree credential add");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("host-service --help prints usage without touching project state", async () => {
    const out = captureStdout();

    const status = await runCommandApp(strictContext(), ["host-service", "--help"], vi.fn(async () => 0));

    expect(status).toBe(0);
    expect(out.text()).toContain("Commands:");
    expect(out.text()).toContain("runfree host-service add");
  });

  test("rejects unknown subcommands and flags before enforcement", async () => {
    for (const args of [
      ["host-service", "bogus"],
      ["host-service", "add"],
      ["host-service", "add", "idb"],
      ["host-service", "add", "idb", "--port"],
      ["host-service", "add", "idb", "--port", "10882", "--bogus"],
      ["host-service", "remove"],
      ["host-service", "remove", "idb", "--port", "10882"],
      ["host-service", "list", "--bad"],
    ]) {
      await expect(runCommandApp(strictContext(), args, vi.fn(async () => 0)), args.join(" ")).rejects.toBeInstanceOf(CliError);
    }
  });

  test("--port must be canonical decimal from 1 to 65535, refused at parse", async () => {
    for (const port of ["010", "70000", "0", "-1", "1e3", "0x2a", "10882.0", "65536", " 10882", "abc"]) {
      await expect(
        runCommandApp(strictContext(), ["host-service", "add", "idb", "--port", port], vi.fn(async () => 0)),
        port,
      ).rejects.toBeInstanceOf(CliError);
    }
    await expect(
      runCommandApp(strictContext(), ["host-service", "add", "idb", "--port", "10882", "--port", "10883"], vi.fn(async () => 0)),
    ).rejects.toBeInstanceOf(CliError);
    for (const port of ["1", "10882", "65535"]) {
      await expect(
        runCommandApp(strictContext(), ["host-service", "add", "idb", "--port", port, "--no-reload"], vi.fn(async () => 0)),
      ).rejects.toThrow("runtimeContext() must not be called");
    }
  });

  describe("against a project", () => {
    let root: string;
    let stateHome: string;
    let env: NodeJS.ProcessEnv;

    function projectContext(): RunfreeCommandContext {
      return strictContext({
        env,
        projectRoot: root,
        runtimeContext: () => ({ projectRoot: root, project: projectInfo(root, env), runtimeRoot: path.join(root, "runtime"), env }),
      });
    }

    function publish(): string {
      const project = projectInfo(root, env);
      approveRuntimeIsolationControl(root, project, "interactive");
      return publishEffectivePolicyGeneration(root, project, { runtimeNetwork: { subnet: "172.30.1.0/24" } }).controlGeneration;
    }

    beforeEach(() => {
      root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-app-host-service-"));
      stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-app-host-service-state-"));
      tempDirs.push(root, stateHome);
      fs.mkdirSync(path.join(root, ".runfree"));
      fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), '{"version":2,"hosts":["example.com"]}\n');
      env = {
        XDG_STATE_HOME: stateHome,
        XDG_CONFIG_HOME: path.join(stateHome, "config"),
        RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
        RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
      };
      const project = projectInfo(root, env);
      const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
      approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
      approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
      hostServiceSeams.admit = () => ({ ok: true, owner: { command: "idb_companion", pid: 4242 } });
    });

    test("add prints the reviewed owner and the agent address", async () => {
      const out = captureStdout();

      const status = await runCommandApp(projectContext(), ["host-service", "add", "idb", "--port", "10882", "--no-reload"], vi.fn(async () => 0));

      expect(status).toBe(0);
      expect(out.text()).toContain("approved host service idb: 127.0.0.1:10882 (idb_companion, pid 4242)");
      expect(out.text()).toContain("agent address: 127.0.0.1:10882 (relay in new sessions)");
      expect(out.text()).toContain("effective policy: unchanged (--no-reload)");
      // --no-reload selects nothing, so nothing new is effective to record.
      expect(hostServiceSeams.recorded).toEqual([]);
    });

    test("an admission refusal exits non-zero before the policy write", async () => {
      hostServiceSeams.admit = (port) => ({ ok: false, reason: `no process listens on 127.0.0.1:${port}` });
      const before = fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8");

      const refusal = await cliRefusal(runCommandApp(projectContext(), ["host-service", "add", "idb", "--port", "10882"], vi.fn(async () => 0)));

      expect(refusal.message).toContain("no process listens on 127.0.0.1:10882");
      expect(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8")).toBe(before);
      expect(hostServiceSeams.recorded).toEqual([]);
    });

    test("add with reload records the new effective ports and the owner in the registry", async () => {
      hostServiceSeams.activate = async () => ({ kind: "selected", controlGeneration: publish() });
      captureStdout();

      await runCommandApp(projectContext(), ["host-service", "add", "idb", "--port", "10882"], vi.fn(async () => 0));

      expect(hostServiceSeams.recorded).toEqual([{ ports: [10882], owners: { 10882: "idb_companion" } }]);
      const registry = readHostServicePortRegistry(env);
      expect(registry.ok && registry.owners.get(10882)?.[0]).toMatchObject({
        projectId: projectHash(root),
        projectRoot: root,
        command: "idb_companion",
      });

      // remove with reload prunes the port from the registry.
      await runCommandApp(projectContext(), ["host-service", "remove", "idb"], vi.fn(async () => 0));
      expect(hostServiceSeams.recorded.at(-1)).toEqual({ ports: [] });
      const pruned = readHostServicePortRegistry(env);
      expect(pruned.ok && pruned.owners.has(10882)).toBe(false);
    });

    test("a registry write failure after the policy applied exits non-zero with the repair remedy", async () => {
      hostServiceSeams.activate = async () => ({ kind: "selected", controlGeneration: publish() });
      hostServiceSeams.recordFails = true;
      captureStdout();

      const refusal = await cliRefusal(runCommandApp(projectContext(), ["host-service", "add", "idb", "--port", "10882"], vi.fn(async () => 0)));

      expect(refusal.message).toContain("the policy change is saved, but the host-service port registry was not updated");
      expect(refusal.message).toContain("host-service port registry lock is held");
      expect(refusal.message).toContain("rebuild it with: runfree host-service list --repair");
      // The policy change itself stays applied.
      expect(JSON.parse(fs.readFileSync(path.join(root, ".runfree", "network-policy.json"), "utf8"))).toMatchObject({
        hostServices: { idb: { target: "host-loopback", port: 10882 } },
      });
      expect(hostServiceSeams.recorded).toEqual([{ ports: [10882], owners: { 10882: "idb_companion" } }]);
    });

    test("list prints one row per effective service with its current owner", async () => {
      const runtime = projectContext().runtimeContext();
      await mutateDesiredHostService(runtime, {} as never, "project", { kind: "add", name: "idb", port: 10882 }, {
        admit: () => ({ ok: true, owner: { command: "idb_companion", pid: 4242 } }),
      });
      await mutateDesiredHostService(runtime, {} as never, "project", { kind: "add", name: "sim", port: 10883 }, {
        admit: () => ({ ok: true, owner: { command: "sim", pid: 1 } }),
      });
      publish();
      hostServiceSeams.probe = (port) => port === 10882
        ? { kind: "listener", command: "idb_companion", pid: 4242, count: 1, commands: ["idb_companion"], listeners: [{ command: "idb_companion", pid: 4242, addresses: ["127.0.0.1:10882"] }] }
        : { kind: "none" };
      const out = captureStdout();

      expect(await runCommandApp(projectContext(), ["host-service", "list"], vi.fn(async () => 0))).toBe(0);

      const lines = out.text().split("\n");
      expect(lines[0]).toMatch(/^NAME\s+PORT\s+OWNER$/u);
      expect(lines[1]).toMatch(/^idb\s+10882\s+idb_companion \(pid 4242\)$/u);
      expect(lines[2]).toMatch(/^sim\s+10883\s+no listener$/u);
      expect(lines).toHaveLength(3);
    });

    /** A live control-plane selection: what a running (not destroyed) project has. */
    function markRuntimeLive(stateRoot: string): string {
      const selection = controlPlaneEffectiveSelectionPathV2(path.join(stateRoot, "projects", projectHash(root)));
      fs.mkdirSync(path.dirname(selection), { recursive: true });
      fs.writeFileSync(selection, "{}\n");
      return selection;
    }

    async function repairSetup(): Promise<string> {
      await mutateDesiredHostService(projectContext().runtimeContext(), {} as never, "project", { kind: "add", name: "idb", port: 10882 }, {
        admit: () => ({ ok: true, owner: { command: "idb_companion", pid: 4242 } }),
      });
      publish();
      const stateRoot = path.join(stateHome, "runfree");
      fs.writeFileSync(
        path.join(stateRoot, "projects", projectHash(root), "project.json"),
        `${JSON.stringify({ projectRoot: root, updatedAt: "2026-10-04T00:00:00.000Z" })}\n`,
      );
      fs.writeFileSync(path.join(stateRoot, "host-service-ports.json"), "{corrupt");
      return stateRoot;
    }

    test("list --repair does not restore the row of a destroyed project (no control-plane selection)", async () => {
      await repairSetup();
      const out = captureStdout();

      const status = await runCommandApp(strictContext({ env }), ["host-service", "list", "--repair"], vi.fn(async () => 0));

      expect(status).toBe(0);
      expect(out.text()).toContain("host-service port registry rebuilt: 0 port(s) from 0 project(s)");
      const registry = readHostServicePortRegistry(env);
      expect(registry.ok && registry.owners.has(10882)).toBe(false);
    });

    test("list --repair refuses to write and exits non-zero when a live project's ports cannot be read, then recovers", async () => {
      const stateRoot = await repairSetup();
      markRuntimeLive(stateRoot);
      const project = projectInfo(root, env);
      const activePath = path.join(project.paths.controlProxyDir, "active.json");
      const activeBytes = fs.readFileSync(activePath, "utf8");
      fs.chmodSync(activePath, 0o600);
      fs.writeFileSync(activePath, "{not json");

      await expect(runCommandApp(strictContext({ env }), ["host-service", "list", "--repair"], vi.fn(async () => 0)))
        .rejects.toThrow(new RegExp(`host-service port registry was not rebuilt[\\s\\S]*${root.replace(/[/.]/g, "\\$&")}[\\s\\S]*runfree host-service list --repair`, "u"));
      // Nothing written: the corrupt file is untouched and still refuses.
      expect(fs.readFileSync(path.join(stateRoot, "host-service-ports.json"), "utf8")).toBe("{corrupt");

      // Reclaim: the project's state is readable again.
      fs.writeFileSync(activePath, activeBytes);
      const out = captureStdout();
      expect(await runCommandApp(strictContext({ env }), ["host-service", "list", "--repair"], vi.fn(async () => 0))).toBe(0);
      expect(out.text()).toContain("host-service port registry rebuilt: 1 port(s) from 1 project(s)");
    });

    test("list --repair rebuilds a corrupt registry from each project's selected effective policy generation", async () => {
      await mutateDesiredHostService(projectContext().runtimeContext(), {} as never, "project", { kind: "add", name: "idb", port: 10882 }, {
        admit: () => ({ ok: true, owner: { command: "idb_companion", pid: 4242 } }),
      });
      publish();
      const stateRoot = path.join(stateHome, "runfree");
      fs.writeFileSync(
        path.join(stateRoot, "projects", projectHash(root), "project.json"),
        `${JSON.stringify({ projectRoot: root, updatedAt: "2026-10-04T00:00:00.000Z" })}\n`,
      );
      markRuntimeLive(stateRoot);
      fs.writeFileSync(path.join(stateRoot, "host-service-ports.json"), "{corrupt");
      expect(readHostServicePortRegistry(env).ok).toBe(false);
      const out = captureStdout();

      // The reclaim is host-global: it never needs this checkout's project context.
      const status = await runCommandApp(strictContext({ env }), ["host-service", "list", "--repair"], vi.fn(async () => 0));

      expect(status).toBe(0);
      expect(out.text()).toContain("host-service port registry rebuilt: 1 port(s) from 1 project(s)");
      const registry = readHostServicePortRegistry(env);
      expect(registry.ok && registry.owners.get(10882)?.[0]).toMatchObject({ projectId: projectHash(root), projectRoot: root });
    });
  });
});

describe("admin diagnostics commands (Phase 4)", () => {
  test("doctor and runtime reload-policy reject unknown flags before admin state", async () => {
    await expect(runCommandApp(strictContext(), ["doctor", "--bogus"], vi.fn(async () => 0))).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    await expect(
      runCommandApp(strictContext(), ["runtime", "reload-policy", "--bogus"], vi.fn(async () => 0)),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("runtime reload-policy reaches admin enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["runtime", "reload-policy"], runDefault)).rejects.toThrow(
      "adminContext() must not be called",
    );
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("doctor --help prints usage without touching admin state", async () => {
    const out = captureStdout();

    const status = await runCommandApp(strictContext(), ["doctor", "--help"], vi.fn(async () => 0));

    expect(status).toBe(0);
    expect(out.text()).toContain("runfree doctor");
    expect(out.text()).toContain("--post-failure");
  });
});

describe("admin credential source command (typed)", () => {
  test("credential source strictly validates list/show/remove before enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["credential", "source"], runDefault)).rejects.toBeInstanceOf(CliError);
    await expect(runCommandApp(strictContext(), ["credential", "source", "list", "extra"], runDefault)).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["credential", "source", "show", "github-cli", "--bad"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bad") });
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("credential source add preserves strict pre-separator parsing and verbatim argv", async () => {
    const runDefault = vi.fn(async () => 0);
    await expect(
      runCommandApp(strictContext(), ["credential", "source", "add", "github-cli", "--bogus", "--", "gh"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
    await expect(
      runCommandApp(strictContext(), ["credential", "source", "add", "github-cli", "typo", "--", "gh"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("unexpected credential source add argument before --: typo") });
    await expect(
      runCommandApp(strictContext(), ["credential", "source", "add", "github-cli", "--ttl", "1h", "--", "gh"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("unknown option: --ttl") });
    await expect(
      runCommandApp(strictContext(), ["credential", "source", "add", "github-cli", "--replace-source", "--", "gh", "auth", "--token"], runDefault),
    ).rejects.toThrow("sourceAdminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["credential", "source", "add", "jwt", "appstore", "--alg", "ES256", "--private-key-from-1password", "op://x", "--claim", "iss=ID", "--ttl", "19m"], runDefault),
    ).rejects.toThrow("sourceAdminContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

describe("admin service command (typed)", () => {
  // service is typed end-to-end: reject -> CliError before enforcement; valid ->
  // reaches enforcement (adminContext sentinel); no runDefault delegation.
  test("service rejects unknown subcommands/flags before enforcement", async () => {
    const runDefault = vi.fn(async () => 0);

    const usage = await cliRefusal(runCommandApp(strictContext(), ["service"], runDefault));
    expect(usage.message).toBe("runfree service needs a subcommand");
    expect(usage.detail).toContain("runfree service enable");
    // A bare group prints only its own usage, never another group's or the full admin reference.
    expect(usage.detail).not.toContain("runfree mcp list");
    expect(usage.detail).not.toContain("runfree host add");
    await expect(runCommandApp(strictContext(), ["service", "list", "--bogus"], runDefault)).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(runCommandApp(strictContext(), ["service", "list", "extra"], runDefault)).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(
      runCommandApp(strictContext(), ["service", "enable", "node", "--bogus"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
    // A stray extra positional on a side-effecting leaf command is rejected
    // (global .strict() covers positionals, not just options).
    await expect(
      runCommandApp(strictContext(), ["service", "disable", "node", "typo"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: typo") });
    // Conflicting credential sources are caught building the typed selection.
    await expect(
      runCommandApp(strictContext(), ["service", "enable", "github", "--from-env", "A", "--from-source", "B"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("choose only one credential source") });
    // --param needs a value; a bare flag is a parser error, not an enforcement one.
    await expect(
      runCommandApp(strictContext(), ["service", "enable", "apple-ads", "--param"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Not enough arguments following: param") });
    await expect(runCommandApp(strictContext(), ["service", "define", "user-demo"], runDefault)).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(runCommandApp(strictContext(), ["service", "undefine", "user-demo"], runDefault)).rejects.toBeInstanceOf(
      CliError,
    );
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("service: valid grammar reaches enforcement, no delegation", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(
      runCommandApp(strictContext(), ["service", "enable", "github", "--from-env", "A", "--no-reload"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(
        strictContext(),
        ["service", "enable", "apple-ads", "--from-source", "apple", "--param", "client-id=SEARCHADS.x", "--param", "APPLE_ADS_CLIENT_ID=y"],
        runDefault,
      ),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(runCommandApp(strictContext(), ["service", "list"], runDefault)).rejects.toThrow(
      "adminContext() must not be called",
    );
    await expect(runCommandApp(strictContext(), ["service", "list", "--all"], runDefault)).rejects.toThrow(
      "adminContext() must not be called",
    );
    await expect(runCommandApp(strictContext(), ["service", "diff", "--apply"], runDefault)).rejects.toThrow(
      "adminContext() must not be called",
    );
    await expect(
      runCommandApp(strictContext(), ["service", "custom", "add", "user-demo", "--from-file", "./service.json", "--yes"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["service", "custom", "remove", "user-demo"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

describe("admin credential/host/mcp commands", () => {
  test("credential: typed lifecycle, conflict rejection, and removed-command guidance", async () => {
    const runDefault = vi.fn(async () => 0);

    const usage = await cliRefusal(runCommandApp(strictContext(), ["credential"], runDefault));
    expect(usage.message).toBe("runfree credential needs a subcommand");
    expect(usage.detail).toContain("runfree credential add");
    expect(usage.detail).toContain("runfree credential source add");
    // A bare group prints only its own usage, never another group's or the full admin reference.
    expect(usage.detail).not.toContain("runfree service enable");
    expect(usage.detail).not.toContain("runfree mcp list");
    await expect(runCommandApp(strictContext(), ["token"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("runfree credential"),
    });
    await expect(runCommandApp(strictContext(), ["source"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("runfree credential source"),
    });
    await expect(
      runCommandApp(strictContext(), ["credential", "sync", "--watch", "--bogus"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("Unknown argument: bogus") });
    await expect(
      runCommandApp(strictContext(), ["credential", "set-source", "gh", "--from-env", "A", "--from-source", "B"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("choose only one credential source") });
    expect(runDefault).not.toHaveBeenCalled();

    for (const args of [
      ["credential", "add", "gh", "--host", "x", "--no-reload"],
      ["credential", "link", "gh", "--host", "x"],
      ["credential", "unlink", "gh", "--host", "x"],
      ["credential", "remove", "gh", "--no-reload"],
      ["credential", "status", "gh"],
      ["credential", "sync", "-v"],
    ]) {
      await expect(runCommandApp(strictContext(), args, runDefault)).rejects.toThrow("adminContext() must not be called");
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  // host add/rules are typed end-to-end: reject before enforcement; valid
  // input reaches the desired-policy transaction; no delegation.
  test("host: typed intent, repeatable flags, conflict caught, no delegation", async () => {
    const runDefault = vi.fn(async () => 0);

    await expect(runCommandApp(strictContext(), ["host"], runDefault)).rejects.toBeInstanceOf(CliError);
    await expect(runCommandApp(strictContext(), ["host", "add", "x.example", "--bogus"], runDefault)).rejects.toMatchObject({
      message: expect.stringContaining("Unknown argument: bogus"),
    });
    await expect(
      runCommandApp(strictContext(), ["host", "add", "x.example", "--from-env", "A"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("host add` no longer configures credentials") });
    expect(runDefault).not.toHaveBeenCalled();

    await expect(
      runCommandApp(
        strictContext(),
        ["host", "add", "api.example.com", "--method", "GET", "--method", "HEAD", "--request-path-prefix", "/v1/", "--no-reload"],
        runDefault,
      ),
    ).rejects.toThrow("runtimeContext() must not be called");
    await expect(
      runCommandApp(
        strictContext(),
        ["host", "rules", "api.example.com", "--method", "GET", "--method", "POST", "--write", "ask", "--no-reload"],
        runDefault,
      ),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  // mcp is typed end-to-end: handlers build a typed intent and call enforcement
  // via context.adminContext() (strictContext throws there). A CliError proves a
  // parse rejection before enforcement; the adminContext sentinel proves valid
  // input reached enforcement without delegating to runDefault.
  test("mcp: typed intent, rejects bad input before enforcement, no delegation", async () => {
    const runDefault = vi.fn(async () => 0);

    const usage = await cliRefusal(runCommandApp(strictContext(), ["mcp"], runDefault));
    expect(usage.message).toBe("runfree mcp needs a subcommand");
    expect(usage.detail).toContain("runfree mcp list");
    expect(usage.detail).toContain("runfree mcp enable");
    expect(usage.detail).not.toContain("runfree mcp approve");
    // A bare group prints only its own usage, never another group's or the full admin reference.
    expect(usage.detail).not.toContain("runfree credential source add");
    expect(usage.detail).not.toContain("runfree credential add");
    expect(usage.detail).not.toContain("runfree service enable");
    await expect(runCommandApp(strictContext(), ["mcp", "enable", "claude"], runDefault)).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(
      runCommandApp(strictContext(), ["mcp", "revoke", "claude", "srv", "--bogus"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["mcp", "rules", "claude", "srv", "--write", "maybe"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["mcp", "auth", "bogusagent", "srv"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("MCP agent must be claude or codex") });
    await expect(
      runCommandApp(strictContext(), ["mcp", "auth", "claude", "srv", "--source", "elsewhere"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("--source must be user, local, or project") });
    await expect(
      runCommandApp(strictContext(), ["mcp", "configure", "--agent", "bogusagent"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("MCP agent must be claude or codex") });
    // Invalid agent is re-validated in the command module before enforcement.
    await expect(
      runCommandApp(strictContext(), ["mcp", "enable", "bogusagent", "srv"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("MCP agent must be claude or codex") });
    await expect(
      runCommandApp(strictContext(), ["mcp", "enable", "claude", "srv", "--source", "elsewhere"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("--source must be user, local, or project") });
    // Conflicting credential sources are caught building the typed selection.
    await expect(
      runCommandApp(strictContext(), ["mcp", "enable", "claude", "srv", "--from-env", "X", "--from-source", "Y"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("choose only one credential source") });
    await expect(
      runCommandApp(strictContext(), ["mcp", "enable", "claude", "srv", "--oauth-host"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    await expect(
      runCommandApp(strictContext(), ["mcp", "revoke", "claude", "srv", "--source", "elsewhere"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("--source must be user, local, or project") });

    // Valid input parses and reaches enforcement (admin state), not runDefault.
    await expect(
      runCommandApp(strictContext(), ["mcp", "configure", "--agent", "codex", "--server", "srv"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(
        strictContext(),
        ["mcp", "configure", "--agent", "claude", "--agent", "codex", "--server", "srv"],
        runDefault,
      ),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "enable", "claude", "srv", "--source", "project", "--from-env", "X"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "rules", "claude", "srv", "--source", "user", "--tool", "query", "--write", "allow"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "auth", "claude", "srv", "--source", "user"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    await expect(
      runCommandApp(
        strictContext(),
        ["mcp", "enable", "claude", "srv", "--no-discover", "--oauth-host", "auth.example.com", "--oauth-host", "id.example.com"],
        runDefault,
      ),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "revoke", "claude", "srv", "--source", "project"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  // `runfree mcp approve` was removed outright; `mcp enable` replaces it. No
  // alias may parse, with or without arguments.
  test("mcp approve is an unknown command", async () => {
    const runDefault = vi.fn(async () => 0);
    for (const argv of [["mcp", "approve"], ["mcp", "approve", "claude", "srv"], ["mcp", "approve", "claude", "srv", "--from-env", "X"]]) {
      const refusal = await cliRefusal(runCommandApp(strictContext(), argv, runDefault));
      expect(refusal.message).toMatch(/^Unknown arguments?: (?:.*, )?approve(?:,|$)/);
    }
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("mcp enable reaches runtime activation only after the approval is saved", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-mcp-login-command-"));
    tempDirs.push(tmp);
    const projectRoot = path.join(tmp, "project");
    const templatesDir = path.join(tmp, "templates");
    const stateDir = path.join(tmp, "state");
    const home = path.join(tmp, "home");
    fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
    fs.mkdirSync(templatesDir, { recursive: true });
    fs.writeFileSync(path.join(templatesDir, "runfree.json"), `${JSON.stringify({ version: 3 })}\n`);
    fs.writeFileSync(path.join(templatesDir, "network-policy.json"), `${JSON.stringify({ hosts: [] })}\n`);
    fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), [
      "[mcp_servers.repo_tools]",
      'url = "https://repo-tools.example.com/mcp"',
      "",
    ].join("\n"));
    const env = {
      HOME: home,
      CODEX_HOME: path.join(home, ".codex"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: stateDir,
    };
    const runDefault = vi.fn(async () => 0);
    const context = strictContext({
      env,
      projectRoot,
      templatesDir: () => templatesDir,
      assets: () => ({
        currentDir: templatesDir,
        dataDir: path.join(tmp, "data"),
        manifest: { files: {}, modes: {}, version: "test" },
        runtimeDir: templatesDir,
        version: "test",
        versionDir: templatesDir,
      }),
      adminContext: () => ({
        env,
        packageRoot: templatesDir,
        projectRoot,
        stateDir,
      }),
      runtimeContext: () => {
        throw new Error("runtimeContext() called after approval");
      },
    });

    await expect(
      runCommandApp(context, ["mcp", "enable", "codex", "repo_tools", "--source", "project", "--no-discover"], runDefault),
    ).rejects.toThrow("runtimeContext() called after approval");
    const approvals = JSON.parse(fs.readFileSync(path.join(stateDir, "approved-mcp.json"), "utf8")) as unknown;
    expect(JSON.stringify(approvals)).toContain("repo_tools");
    expect(runDefault).not.toHaveBeenCalled();
  });
});

// Flag precedence for `runfree approvals` is a decision, not plumbing:
// `--clear-deny` once won outright and silently discarded `--watch`, leaving an
// operator who cleared the latch to resume approving with no approver attached.
describe("approvals flag precedence", () => {
  test("--clear-deny and --watch compose instead of one winning", () => {
    expect(approvalsInputFromArgs({ "clear-deny": true, watch: true }))
      .toEqual({ kind: "watch", bell: true, clearDenyFirst: true });
    expect(approvalsInputFromArgs({ "clear-deny": true, watch: true, "no-bell": true }))
      .toEqual({ kind: "watch", bell: false, clearDenyFirst: true });
  });

  test("each flag alone keeps its own mode", () => {
    expect(approvalsInputFromArgs({})).toEqual({ kind: "list" });
    expect(approvalsInputFromArgs({ watch: true })).toEqual({ kind: "watch", bell: true });
    expect(approvalsInputFromArgs({ "clear-deny": true })).toEqual({ kind: "clear-deny" });
  });

  test("the internal heartbeat mode still outranks operator flags", () => {
    // Runfree spawns this itself around interactive sessions; it is hidden and
    // never combined with --watch or --clear-deny by a human.
    expect(approvalsInputFromArgs({ heartbeat: true, "parent-pid": 4242, watch: true, "clear-deny": true }))
      .toEqual({ kind: "heartbeat", parentPid: 4242 });
  });

  test("the parser accepts the combination rather than rejecting it", async () => {
    const context = strictContext({
      runtimeContext: () => {
        throw new Error("reached the approvals runtime");
      },
    });
    await expect(runCommandApp(context, ["approvals", "--clear-deny", "--watch"], async () => 0))
      .rejects.toThrow("reached the approvals runtime");
  });
});

// T8: `basic` is in the shared contract scheme list, but it needs a username
// and is reachable only through service definitions. The CLI checks its own
// subset and refuses before the desired-policy transaction writes anything.
describe("credential --scheme basic", () => {
  test("credential add and link refuse --scheme basic before any policy or state write", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-credential-basic-"));
    tempDirs.push(tmp);
    const projectRoot = path.join(tmp, "project");
    const stateDir = path.join(tmp, "state");
    fs.mkdirSync(path.join(projectRoot, ".runfree"), { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
    const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
    fs.writeFileSync(policyPath, `${JSON.stringify({ version: 2, hosts: ["api.example.com"] })}\n`);
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(policyPath, past, past);
    const env = {
      HOME: path.join(tmp, "home"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      XDG_CONFIG_HOME: path.join(tmp, "config"),
      XDG_STATE_HOME: stateDir,
    };
    const context = strictContext({
      env,
      projectRoot,
      adminContext: () => ({ env, packageRoot: tmp, projectRoot, stateDir }),
      runtimeContext: () => ({ projectRoot, project: projectInfo(projectRoot, env), runtimeRoot: projectRoot, env }),
    });
    const before = { bytes: fs.readFileSync(policyPath, "utf8"), mtimeMs: fs.statSync(policyPath).mtimeMs };
    const runDefault = vi.fn(async () => 0);

    for (const argv of [
      ["credential", "add", "gh", "--host", "api.example.com", "--scheme", "basic", "--no-reload"],
      ["credential", "link", "gh", "--host", "api.example.com", "--scheme", "basic", "--no-reload"],
    ]) {
      await expect(runCommandApp(context, argv, runDefault), argv.join(" "))
        .rejects.toThrow("--scheme must be one of: bearer, raw");
    }

    expect(fs.readFileSync(policyPath, "utf8")).toBe(before.bytes);
    expect(fs.statSync(policyPath).mtimeMs).toBe(before.mtimeMs);
    expect(fs.readdirSync(stateDir, { recursive: true })).toEqual([]);
    expect(runDefault).not.toHaveBeenCalled();
  });
});
