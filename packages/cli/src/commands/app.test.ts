import { afterEach, describe, expect, test, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { defaultConfig } from "../config.ts";
import { RUNFREE_VERSION } from "../embedded-assets.generated.ts";
import { CliError } from "../errors.ts";
import { composeProjectName, projectHash } from "../project-identity.ts";
import { ControlPlaneRebindCandidateMismatchError } from "../runtime/control-plane-rebind-coordinator.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { runAgentCommandWithControlPlaneRebindRefusal, runCommandApp } from "./app.ts";
import { approvalsInputFromArgs, runUp, runtimeContextWithSessionName } from "./runtime.ts";
import type { RunfreeCommandContext } from "./context.ts";

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

function writeHostRecoveryFixture(stateRoot: string, projectRoot: string, agent: string): void {
  fs.mkdirSync(projectRoot, { recursive: true });
  const stateDir = path.join(stateRoot, "runfree", "projects", projectHash(projectRoot));
  const sessionsDir = path.join(stateDir, "sessions");
  fs.mkdirSync(sessionsDir, { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, "project.json"),
    `${JSON.stringify({ projectRoot, updatedAt: "2026-08-01T00:00:00.000Z" })}\n`,
  );
  const id = "rf-20260801-c0de01";
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
    })}\n`,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
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

  test("the typed default tolerates agent-specific flags (non-strict $0)", async () => {
    const runDefault = vi.fn(async () => 0);

    // Built-in/configured agent names route through the non-strict `$0 [agent]`
    // default, which tolerates trailing agent-specific flags (e.g.
    // `claude --resume`) instead of rejecting them, and reaches the typed runtime
    // core. The flags are not forwarded to the agent — the agent runs its fixed
    // configured RUNFREE_AGENT_COMMAND, exactly as the legacy path did; this only
    // asserts they are accepted, not rejected.
    await expect(runCommandApp(strictContext(), ["claude", "--resume"], runDefault)).rejects.toThrow(
      "runtimeContext() must not be called",
    );
    expect(runDefault).not.toHaveBeenCalled();
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
    expect(usage.detail).toContain("runfree mcp approve");
    // A bare group prints only its own usage, never another group's or the full admin reference.
    expect(usage.detail).not.toContain("runfree credential source add");
    expect(usage.detail).not.toContain("runfree credential add");
    expect(usage.detail).not.toContain("runfree service enable");
    await expect(runCommandApp(strictContext(), ["mcp", "approve", "claude"], runDefault)).rejects.toBeInstanceOf(
      CliError,
    );
    await expect(
      runCommandApp(strictContext(), ["mcp", "revoke", "claude", "srv", "--bogus"], runDefault),
    ).rejects.toBeInstanceOf(CliError);
    // Invalid agent is re-validated in the command module before enforcement.
    await expect(
      runCommandApp(strictContext(), ["mcp", "approve", "bogusagent", "srv"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("MCP agent must be claude or codex") });
    // Conflicting credential sources are caught building the typed selection.
    await expect(
      runCommandApp(strictContext(), ["mcp", "approve", "claude", "srv", "--from-env", "X", "--from-source", "Y"], runDefault),
    ).rejects.toMatchObject({ message: expect.stringContaining("choose only one credential source") });
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
      runCommandApp(strictContext(), ["mcp", "approve", "claude", "srv", "--from-env", "X"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "approve", "claude", "srv", "--login"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "rules", "claude", "srv", "--source", "user", "--tool", "query", "--write", "allow"], runDefault),
    ).rejects.toThrow("adminContext() must not be called");
    await expect(
      runCommandApp(strictContext(), ["mcp", "auth", "claude", "srv", "--source", "user"], runDefault),
    ).rejects.toThrow("runtimeContext() must not be called");
    expect(runDefault).not.toHaveBeenCalled();
  });

  test("mcp approve --login hands off to runtime auth only after approval succeeds", async () => {
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
      runCommandApp(context, ["mcp", "approve", "codex", "repo_tools", "--login"], runDefault),
    ).rejects.toThrow("runtimeContext() called after approval");
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
