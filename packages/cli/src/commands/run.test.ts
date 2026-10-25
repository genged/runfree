import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

import { CliError } from "../errors.ts";
import { remedy } from "../remedies.ts";
import { ControlPlaneRebindCandidateMismatchError } from "../runtime/control-plane-rebind-coordinator.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import { runCommandApp } from "./app.ts";
import type { RunfreeCommandContext } from "./context.ts";

// The orchestrator is the Docker boundary of `run`; the command tests prove
// what reaches it (typed options) and that nothing does on a usage error.
const seams = vi.hoisted(() => ({
  calls: [] as unknown[][],
  result: (async () => 0) as (...args: unknown[]) => Promise<number>,
}));

vi.mock("../runtime/headless-run.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../runtime/headless-run.ts")>();
  return {
    ...actual,
    runHeadlessAgent: (...args: unknown[]) => {
      seams.calls.push(args);
      return seams.result(...args);
    },
  };
});

const tempDirs: string[] = [];

afterEach(() => {
  seams.calls.length = 0;
  seams.result = async () => 0;
  vi.restoreAllMocks();
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-run-command-"));
  tempDirs.push(dir);
  return dir;
}

// Every lazy accessor throws: a usage error must be refused before the
// handler reads the project, materializes assets, or reaches the runtime.
function strictContext(invocationCwd: string, overrides: Partial<RunfreeCommandContext> = {}): RunfreeCommandContext {
  const refuse = (name: string) => () => {
    throw new Error(`${name}() must not be called`);
  };
  return {
    env: {},
    projectRoot: path.join(invocationCwd, "project"),
    commandName: "run",
    invocationCwd,
    assets: refuse("assets"),
    templatesDir: refuse("templatesDir"),
    projectInfo: refuse("projectInfo"),
    ensureProject: refuse("ensureProject"),
    adminContext: refuse("adminContext"),
    sourceAdminContext: refuse("sourceAdminContext"),
    runtimeContext: refuse("runtimeContext"),
    ...overrides,
  };
}

function runtimeContextStub(env: NodeJS.ProcessEnv = {}): RuntimeContext {
  return { projectRoot: "/tmp/project", env } as unknown as RuntimeContext;
}

async function refusal(promise: Promise<number>): Promise<CliError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(CliError);
    return error as CliError;
  }
  throw new Error("expected a refusal");
}

const neverDelegate = async (): Promise<number> => {
  throw new Error("runDefault must not be called");
};

describe("runfree run", () => {
  test("usage errors exit 64 before any project, asset, or runtime work", async () => {
    const cwd = tempDir();
    fs.writeFileSync(path.join(cwd, "task.md"), "do the thing\n");
    const cases: Array<[string[], RegExp]> = [
      [["run"], /Not enough non-option arguments/],
      [["run", "claude"], /Missing required argument: prompt-file/],
      [["run", "claude", "--prompt-file"], /prompt-file/],
      [["run", "claude", "--prompt-file", "task.md", "--bogus"], /Unknown argument: bogus/],
      [["run", "claude", "--prompt-file", "task.md", "extra"], /Unknown argument: extra/],
      // Nothing is passed through to the agent (D-3), not even after `--`.
      [["run", "claude", "--prompt-file", "task.md", "--", "--dangerously-skip-permissions"], /Unknown argument/],
      [["run", "shell", "--prompt-file", "task.md"], /Invalid values/],
      [["run", "nobody", "--prompt-file", "task.md"], /Invalid values/],
      // Codex and Pi have no headless mode yet (plan Task 15).
      [["run", "codex", "--prompt-file", "task.md"], /Invalid values/],
      [["run", "pi", "--prompt-file", "task.md"], /Invalid values/],
      [["run", "claude", "--prompt-file", "task.md", "--timeout", "soon"], /--timeout/],
      [["run", "claude", "--prompt-file", "task.md", "--timeout", "0"], /--timeout/],
      [["run", "claude", "--prompt-file", "task.md", "--timeout", "25h"], /--timeout must be at most 24h/],
      [["run", "claude", "--prompt-file", "task.md", "--no-accept-denied-writes"], /Unknown argument/],
    ];
    for (const [args, reason] of cases) {
      const error = await refusal(runCommandApp(strictContext(cwd), args, neverDelegate));
      expect(error.status, args.join(" ")).toBe(64);
      expect(error.message, args.join(" ")).toMatch(reason);
    }
    expect(seams.calls).toEqual([]);
  });

  test("a missing or invalid prompt file exits 64 before the runtime context is built", async () => {
    const cwd = tempDir();
    fs.mkdirSync(path.join(cwd, "a-directory"));
    fs.writeFileSync(path.join(cwd, "real.md"), "x");
    fs.symlinkSync(path.join(cwd, "real.md"), path.join(cwd, "link.md"));
    fs.writeFileSync(path.join(cwd, "huge.md"), Buffer.alloc(1024 * 1024 + 1, 0x61));
    const cases: Array<[string, RegExp]> = [
      ["missing.md", /the prompt file could not be read/],
      ["a-directory", /not a regular file/],
      ["link.md", /must not be a symlink/],
      ["huge.md", /larger than 1048576 bytes/],
    ];
    for (const [file, reason] of cases) {
      const error = await refusal(runCommandApp(strictContext(cwd), ["run", "claude", "--prompt-file", file], neverDelegate));
      expect(error.status, file).toBe(64);
      expect(error.message, file).toMatch(reason);
    }
    expect(seams.calls).toEqual([]);
  });

  test("the handler passes typed options to the orchestrator and returns its exit code", async () => {
    const cwd = tempDir();
    fs.writeFileSync(path.join(cwd, "task.md"), "do the thing\n");
    const rc = runtimeContextStub();
    seams.result = async () => 68;
    const status = await runCommandApp(
      strictContext(cwd, { runtimeContext: () => rc }),
      ["run", "claude", "--prompt-file", "task.md", "--timeout", "30m", "--accept-denied-writes", "--verbose"],
      neverDelegate,
    );
    expect(status).toBe(68);
    expect(seams.calls).toHaveLength(1);
    const [passedContext, , agent, options] = seams.calls[0] ?? [];
    expect(passedContext).toBe(rc);
    expect(agent).toBe("claude");
    // The prompt path resolves against the invocation directory, not the
    // `--workspace` project.
    expect(options).toEqual({
      promptFile: path.join(cwd, "task.md"),
      timeoutMs: 30 * 60 * 1000,
      acceptDeniedWrites: true,
      verbose: true,
    });
  });

  test("without optional flags no timeout is set and denied writes are not accepted", async () => {
    const cwd = tempDir();
    const prompt = path.join(cwd, "task.md");
    fs.writeFileSync(prompt, "do the thing\n");
    const status = await runCommandApp(
      strictContext(cwd, { runtimeContext: () => runtimeContextStub() }),
      ["run", "claude", "--prompt-file", prompt],
      neverDelegate,
    );
    expect(status).toBe(0);
    expect(seams.calls[0]?.[3]).toEqual({ promptFile: prompt, acceptDeniedWrites: false, verbose: false });
  });

  test("an orchestrator failure is not reinterpreted as a usage error", async () => {
    const cwd = tempDir();
    fs.writeFileSync(path.join(cwd, "task.md"), "x");
    seams.result = async () => {
      throw new CliError("handler refusal", 3);
    };
    const error = await refusal(runCommandApp(
      strictContext(cwd, { runtimeContext: () => runtimeContextStub() }),
      ["run", "claude", "--prompt-file", "task.md"],
      neverDelegate,
    ));
    expect(error.status).toBe(3);
  });

  test("a contradictory control-plane rebind is refused with 65", async () => {
    const cwd = tempDir();
    fs.writeFileSync(path.join(cwd, "task.md"), "x");
    seams.result = async () => {
      throw new ControlPlaneRebindCandidateMismatchError();
    };
    const error = await refusal(runCommandApp(
      strictContext(cwd, { runtimeContext: () => runtimeContextStub() }),
      ["run", "claude", "--prompt-file", "task.md"],
      neverDelegate,
    ));
    expect(error.status).toBe(65);
    expect(error.message).toContain("could not safely continue a proxy replacement");
    expect(error.message.split("\n").at(-1)).toBe("the headless run did not start");
  });

  test("dry run prints the plan without reaching the orchestrator", async () => {
    const cwd = tempDir();
    fs.writeFileSync(path.join(cwd, "task.md"), "x");
    const front = await import("../runtime/front.ts");
    const dry = vi.spyOn(front, "runtimeDryRun").mockReturnValue(0);
    const status = await runCommandApp(
      strictContext(cwd, { runtimeContext: () => runtimeContextStub({ RUNFREE_RUNTIME_DRY_RUN: "1" }) }),
      ["run", "claude", "--prompt-file", "task.md"],
      neverDelegate,
    );
    expect(status).toBe(0);
    expect(dry).toHaveBeenCalledWith(expect.anything(), expect.anything(), "run");
    expect(seams.calls).toEqual([]);
  });

  test("other commands keep exit 1 for usage errors", async () => {
    const cwd = tempDir();
    for (const args of [["version", "--bad"], ["claude", "--prompt-file", "task.md"], ["status", "extra"]]) {
      const error = await refusal(runCommandApp(strictContext(cwd), args, neverDelegate));
      expect(error.status, args.join(" ")).toBe(1);
    }
  });

  test("run --help renders the command's native help", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(args.join(" "));
    });
    const status = await runCommandApp(strictContext(tempDir()), ["run", "--help"], neverDelegate);
    expect(status).toBe(0);
    const help = lines.join("\n");
    expect(help).toContain("runfree run <agent>");
    expect(help).toContain("--prompt-file");
    expect(help).toContain("--timeout");
    expect(help).toContain("--accept-denied-writes");
    expect(help).toContain("runfree run claude --prompt-file task.md");
  });

  test("the accept-denied-writes remedy repeats the run and quotes a prompt path for the shell", () => {
    expect(remedy.runAcceptDeniedWrites("claude", "/tmp/task.md", { timeout: "1800s" }))
      .toBe("runfree run claude --prompt-file /tmp/task.md --timeout 1800s --accept-denied-writes");
    expect(remedy.runAcceptDeniedWrites("claude", "/tmp/my task's.md"))
      .toBe("runfree run claude --prompt-file '/tmp/my task'\\''s.md' --accept-denied-writes");
    expect(remedy.runAcceptDeniedWrites("claude", "/tmp/a\nb.md")).toBe("runfree run claude --prompt-file '/tmp/a?b.md' --accept-denied-writes");
  });
});
