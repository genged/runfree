// `runfree credential ...` driven through the real command tree: argv parsing,
// the admin action wrapper, desired-policy mutation and host-owned source
// files all run for real against a temp project and home. Docker is either
// absent from PATH or a logging stub that prints nothing (runtime not running).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, type MockInstance, test, vi } from "vitest";

import { projectInfo } from "../../config.ts";
import { approveNetworkCandidate, readControlApprovalSelection } from "../../control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../../control/candidates.ts";
import { CliError } from "../../errors.ts";
import type { RuntimeContext } from "../../runtime/types.ts";
import { flushWarnings, setOutputWriterForTest } from "../../warnings.ts";
import { runCommandApp } from "../app.ts";
import type { RunfreeCommandContext } from "../context.ts";

type World = {
  root: string;
  projectRoot: string;
  home: string;
  bin: string;
  env: NodeJS.ProcessEnv;
  runtime: RuntimeContext;
  context: RunfreeCommandContext;
  policyFile: string;
  tokensFile: string;
  sourcesFile: string;
  effectivePolicyFile: string;
  dockerLog: string;
};

type Outcome = { status?: number; error?: unknown; out: string[]; err: string[] };

const GITHUB_DESTINATION = { host: "api.github.com", header: "Authorization", scheme: "bearer" };
const LEGACY_EFFECTIVE_POLICY = {
  hosts: ["api.github.com"],
  tokens: { github: { description: "GH", credentials: [GITHUB_DESTINATION] } },
};

let world: World;
let errLines: string[];
let logSpy: MockInstance<typeof console.log>;
const ttyDescriptors = {
  stdin: Object.getOwnPropertyDescriptor(process.stdin, "isTTY"),
  stdout: Object.getOwnPropertyDescriptor(process.stdout, "isTTY"),
};

function restoreTty(stream: NodeJS.ReadStream | NodeJS.WriteStream, descriptor: PropertyDescriptor | undefined): void {
  if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
  else delete (stream as { isTTY?: boolean }).isTTY;
}

// `approvePolicy` seeds an approved project and local desired policy; the
// source router never reads desired policy, so its tests skip that cost.
function createWorld(approvePolicy: boolean): World {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-credential-command-")));
  const projectRoot = path.join(root, "project");
  const home = path.join(root, "home");
  const bin = path.join(root, "bin");
  for (const dir of [projectRoot, home, bin]) fs.mkdirSync(dir, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    HOME: home,
    PATH: bin,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_LOG_TIMESTAMPS: "0",
    RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
    RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
  };
  const policyFile = path.join(projectRoot, ".runfree", "network-policy.json");
  fs.mkdirSync(path.dirname(policyFile), { recursive: true });
  fs.writeFileSync(policyFile, `${JSON.stringify({ version: 2, hosts: ["api.github.com"] }, null, 2)}\n`);
  const runtime = {
    projectRoot,
    project: projectInfo(projectRoot, env),
    runtimeRoot: path.join(root, "runtime"),
    env,
  } as unknown as RuntimeContext;
  for (const layer of approvePolicy ? (["network-project", "network-local"] as const) : []) {
    const candidate = captureDesiredPolicyCandidate(projectRoot, runtime.project.paths.controlCandidatesDir);
    approveNetworkCandidate(projectRoot, runtime.project, candidate, layer, "interactive");
  }
  const tokensFile = path.join(home, ".config", "runfree", "tokens.json");
  const effectivePolicyFile = path.join(root, "effective-policy.json");
  const members: Record<string, unknown> = {
    env,
    projectRoot,
    commandName: "credential",
    invocationCwd: projectRoot,
    runtimeContext: () => runtime,
    sourceAdminContext: () => ({ projectRoot, packageRoot: root, env }),
    adminContext: () => ({
      projectRoot,
      packageRoot: root,
      env,
      tokenConfigPath: tokensFile,
      stateDir: path.join(root, "state"),
      policyPath: effectivePolicyFile,
      policyAccess: "effective-read-only",
    }),
  };
  const context = new Proxy(members, {
    get(target, key) {
      if (typeof key === "string" && !(key in target)) {
        return () => {
          throw new Error(`context.${key}() must not be called`);
        };
      }
      return target[key as string];
    },
  }) as unknown as RunfreeCommandContext;
  return {
    root,
    projectRoot,
    home,
    bin,
    env,
    runtime,
    context,
    policyFile,
    tokensFile,
    sourcesFile: path.join(home, ".config", "runfree", "sources.json"),
    effectivePolicyFile,
    dockerLog: path.join(root, "docker.log"),
  };
}

// Docker that is installed but reports nothing: no runtime containers.
function installStubDocker(): void {
  writeExecutable("docker", `#!/bin/sh\nprintf '%s\\n' "$*" >> '${world.dockerLog}'\nexit 0\n`);
}

function writeExecutable(name: string, body: string): void {
  const file = path.join(world.bin, name);
  fs.writeFileSync(file, body);
  fs.chmodSync(file, 0o755);
}

function writeEffectivePolicy(): void {
  fs.writeFileSync(world.effectivePolicyFile, `${JSON.stringify(LEGACY_EFFECTIVE_POLICY)}\n`);
}

function readJson(file: string): unknown {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readBytes(file: string): Buffer | undefined {
  return fs.existsSync(file) ? fs.readFileSync(file) : undefined;
}

function tokens(): Record<string, unknown> {
  return (readJson(world.policyFile) as { tokens?: Record<string, unknown> }).tokens ?? {};
}

async function cli(...args: string[]): Promise<Outcome> {
  logSpy.mockClear();
  errLines.length = 0;
  const outcome: Outcome = { out: [], err: [] };
  try {
    outcome.status = await runCommandApp(world.context, ["credential", ...args], async () => 0);
  } catch (error) {
    outcome.error = error;
  }
  flushWarnings();
  outcome.out = logSpy.mock.calls.map((call) => call.map(String).join(" "));
  outcome.err = errLines.join("\n").split("\n").map((line) => line.replace(/^\S+ (?=runfree )/, ""));
  return outcome;
}

async function expectCliError(args: string[], message: string): Promise<Outcome> {
  const outcome = await cli(...args);
  expect(outcome.error).toBeInstanceOf(CliError);
  expect((outcome.error as Error).message).toBe(message);
  return outcome;
}

const ADD_GITHUB = ["add", "github", "--host", "api.github.com", "--description", "GH", "--from-env", "GH_X", "--no-reload"];

async function addGithub(): Promise<void> {
  const outcome = await cli(...ADD_GITHUB);
  expect(outcome.status, outcome.err.join("\n")).toBe(0);
}

beforeEach((ctx) => {
  world = createWorld(ctx.task.suite?.name !== "credential source router");
  errLines = [];
  setOutputWriterForTest((line) => errLines.push(line));
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true, writable: true });
  Object.defineProperty(process.stdout, "isTTY", { value: false, configurable: true, writable: true });
  world.env.GH_X = "gh-secret-value";
});

afterEach(() => {
  flushWarnings();
  setOutputWriterForTest(undefined);
  vi.restoreAllMocks();
  restoreTty(process.stdin, ttyDescriptors.stdin);
  restoreTty(process.stdout, ttyDescriptors.stdout);
  fs.rmSync(world.root, { recursive: true, force: true });
});

describe("credential policy commands", () => {
  test("add writes the destination and binding, approves it, and skips reload with --no-reload", async () => {
    const outcome = await cli(...ADD_GITHUB);
    expect(outcome.status).toBe(0);
    expect(outcome.out).toHaveLength(4);
    expect(outcome.out[0]).toBe("credential github: updated in project desired policy");
    expect(outcome.out[1]).toMatch(/^approved project desired policy: sha256:[0-9a-f]{12}… \(approval record id\)$/);
    expect(outcome.out.slice(2)).toEqual([
      "host-owned source: bound; sync on next converged runtime",
      "effective policy: unchanged (--no-reload)",
    ]);
    expect(tokens()).toEqual({ github: { description: "GH", credentials: [GITHUB_DESTINATION] } });
    expect((readJson(world.tokensFile) as Record<string, unknown>).github).toEqual({ source: "env", env: "GH_X" });
  });

  test("add without --no-reload saves effective policy for the next start, and no source flag leaves the source unchanged", async () => {
    const outcome = await cli("add", "github", "--host", "api.github.com", "--description", "GH");
    expect(outcome.status, outcome.err.join("\n")).toBe(0);
    expect(outcome.out).toContain("host-owned source: unchanged");
    expect(outcome.out.at(-1)).toBe("effective policy: saved; applies when the runtime starts");
    expect(fs.existsSync(world.tokensFile)).toBe(false);
  });

  test("link appends a destination and unlink removes only that one; the binding is untouched", async () => {
    await addGithub();
    const binding = readBytes(world.tokensFile);
    const linked = await cli("link", "github", "--host", "api.github.com", "--header", "X-Api-Key", "--scheme", "raw", "--no-reload");
    expect(linked.status, linked.err.join("\n")).toBe(0);
    expect(linked.out[0]).toBe("credential github: updated in project desired policy");
    expect(tokens()).toEqual({
      github: {
        description: "GH",
        credentials: [GITHUB_DESTINATION, { host: "api.github.com", header: "X-Api-Key", scheme: "raw" }],
      },
    });
    const unlinked = await cli("unlink", "github", "--host", "api.github.com", "--header", "X-Api-Key", "--no-reload");
    expect(unlinked.status, unlinked.err.join("\n")).toBe(0);
    expect(tokens()).toEqual({ github: { description: "GH", credentials: [GITHUB_DESTINATION] } });
    expect(readBytes(world.tokensFile)).toEqual(binding);
  });

  test("link to a host that is not allowlisted is refused and leaves the policy file unchanged", async () => {
    await addGithub();
    const before = readBytes(world.policyFile);
    await expectCliError(
      ["link", "github", "--host", "example.com", "--no-reload"],
      "example.com is not directly allowlisted in project desired policy; add it with: runfree host add example.com",
    );
    expect(readBytes(world.policyFile)).toEqual(before);
  });

  test("remove refuses before changing desired policy when Docker is unavailable", async () => {
    await addGithub();
    const policyBefore = readBytes(world.policyFile);
    const tokensBefore = readBytes(world.tokensFile);
    const selectionBefore = readControlApprovalSelection(world.projectRoot, world.runtime.project);
    const outcome = await cli("remove", "github", "--no-reload");
    expect(outcome.status).toBe(1);
    expect(outcome.err).toEqual([
      "runfree error: github was not removed: cannot verify credential revocation while proxy state is docker-unavailable",
      "  the credential is still bound and still injected",
      "  restore Docker access and retry",
    ]);
    expect(outcome.out.some((line) => line.includes("updated"))).toBe(false);
    expect(readBytes(world.policyFile)).toEqual(policyBefore);
    expect(readBytes(world.tokensFile)).toEqual(tokensBefore);
    expect(readControlApprovalSelection(world.projectRoot, world.runtime.project)).toEqual(selectionBefore);
  });

  test("remove with a stopped runtime revokes first, then drops the policy entry and binding; a repeat is refused", async () => {
    await addGithub();
    installStubDocker();
    const outcome = await cli("remove", "github", "--no-reload");
    expect(outcome.status, outcome.err.join("\n")).toBe(0);
    expect(outcome.out[0]).toBe("host/proxy credential state: removed");
    expect(outcome.out[1]).toBe("credential github: updated in project desired policy");
    expect(tokens()).not.toHaveProperty("github");
    expect(readJson(world.tokensFile)).not.toHaveProperty("github");
    const dockerCalls = fs.readFileSync(world.dockerLog, "utf8").split("\n").filter(Boolean);
    expect(dockerCalls.length).toBeGreaterThan(0);
    expect(dockerCalls.some((line) => /(^| )exec( |$)/.test(line))).toBe(false);

    const again = await expectCliError(["remove", "github", "--no-reload"], "unknown project credential: github");
    expect(again.out).toEqual(["host/proxy credential state: not-present"]);
  });

  test("add refuses a name reserved for user-defined services and writes nothing", async () => {
    const policyBefore = readBytes(world.policyFile);
    await expectCliError(
      ["add", "user-x", "--host", "api.github.com", "--description", "x", "--no-reload"],
      "user-x is reserved for a user-defined service; use runfree service enable <id> or runfree service disable <id>",
    );
    expect(readBytes(world.policyFile)).toEqual(policyBefore);
    expect(fs.existsSync(world.tokensFile)).toBe(false);
  });
});

describe("credential source binding and status", () => {
  beforeEach(async () => {
    installStubDocker();
    writeExecutable("mytok", "#!/bin/sh\necho token\n");
    await addGithub();
    writeEffectivePolicy();
  });

  test("status reports the env source, then the named command source after set-source --replace-source", async () => {
    for (const args of [["status"], ["status", "github"]]) {
      const outcome = await cli(...args);
      expect(outcome.status, outcome.err.join("\n")).toBe(0);
      expect(outcome.out).toContain("github: configured");
      expect(outcome.out.map((line) => line.trim())).toContain("source: env GH_X");
    }

    expect((await cli("source", "add", "c1", "--", "mytok", "a")).status).toBe(0);
    const refused = await cli("set-source", "github", "--from-source", "c1", "--no-sync");
    expect(refused.status).toBe(1);
    expect(refused.err).toEqual(["runfree error: github credential source is already env GH_X; pass --replace-source to change it"]);
    expect((readJson(world.tokensFile) as Record<string, unknown>).github).toEqual({ source: "env", env: "GH_X" });

    const replaced = await cli("set-source", "github", "--from-source", "c1", "--no-sync", "--replace-source");
    expect(replaced.status, replaced.err.join("\n")).toBe(0);
    expect(replaced.out.map((line) => line.trim())).toContain("proxy sync: skipped");
    expect((readJson(world.tokensFile) as Record<string, unknown>).github).toEqual({ source: "named", name: "c1" });

    const status = await cli("status", "github");
    expect(status.status, status.err.join("\n")).toBe(0);
    const trimmed = status.out.map((line) => line.trim());
    expect(trimmed).toContain("source: source c1");
    expect(trimmed).toContain("runfree run: refused (runs a command source)");
  });

  test("clear-source drops the binding and reports no proxy-held value", async () => {
    const outcome = await cli("clear-source", "github");
    expect(outcome.status, outcome.err.join("\n")).toBe(0);
    const trimmed = outcome.out.map((line) => line.trim());
    expect(trimmed).toContain("github credential source cleared");
    expect(trimmed).toContain("proxy-held value: none held (proxy not-running)");
    expect(readJson(world.tokensFile)).toEqual({});
  });

  test("sync refuses without a selected effective generation", async () => {
    const outcome = await cli("sync");
    expect(outcome.status).toBe(1);
    expect(outcome.err[0]).toBe("runfree error: credential resolution requires a selected effective policy generation with complete convergence");
  });
});

describe("credential source router", () => {
  test.each([
    [["jwt", "j1", "--scope", "x"], "unknown option: --scope"],
    [["jwt", "j1", "extra"], "unexpected credential source add argument: extra"],
    [["jwt", "j1", "--", "echo"], "unexpected tokens after -- in credential source add jwt: echo"],
    [["google-service-account", "g1", "--alg", "ES256"], "unknown option: --alg"],
    [["google-service-account", "g1", "--claim", "a=b"], "unknown option: --claim"],
    [["google-service-account", "g1", "extra"], "unexpected credential source add argument: extra"],
    [["google-service-account", "g1", "--", "echo"], "unexpected tokens after -- in credential source add google-service-account: echo"],
    [["c1", "--ttl", "5m", "--", "echo", "hi"], "unknown option: --ttl"],
    [["c1", "--alg", "ES256", "--", "echo", "hi"], "unknown option: --alg"],
    [["c1", "--scope", "s", "--", "echo", "hi"], "unknown option: --scope"],
    [["c1", "c2", "--", "echo"], "unexpected credential source add argument before --: c2"],
  ])("source add %j is refused with %j and saves nothing", async (args, message) => {
    await expectCliError(["source", "add", ...args], message);
    expect(fs.existsSync(world.sourcesFile)).toBe(false);
  });

  test("command source add, list, show, duplicate refusal and remove", async () => {
    writeExecutable("mytok", "#!/bin/sh\necho token\n");
    const added = await cli("source", "add", "c1", "--", "mytok", "a");
    expect(added.status, added.err.join("\n")).toBe(0);
    const addedText = added.out.map((line) => line.trim());
    expect(addedText).toContain("c1 source configured");
    expect(addedText).toContain("type: command");
    expect(addedText).toContain("command: mytok a");
    // The router refusals assert this file stays absent; prove it is the real path.
    expect(fs.existsSync(world.sourcesFile)).toBe(true);

    const passthrough = await cli("source", "add", "c2", "--", "mytok", "--alg", "x");
    expect(passthrough.status, passthrough.err.join("\n")).toBe(0);
    expect(passthrough.out.map((line) => line.trim())).toContain("command: mytok --alg x");

    const list = await cli("source", "list");
    expect(list.status).toBe(0);
    expect(list.out.join("\n")).toMatch(/\bc1\b/);

    const shown = await cli("source", "show", "c1");
    expect(shown.status).toBe(0);
    expect(shown.out.map((line) => line.trim())).toContain("c1: configured");

    const sourcesBefore = readBytes(world.sourcesFile);
    const duplicate = await cli("source", "add", "c1", "--", "mytok", "b");
    expect(duplicate.status).toBe(1);
    expect(duplicate.err).toEqual(["runfree error: c1 source is already configured; pass --replace-source to change it"]);
    expect(readBytes(world.sourcesFile)).toEqual(sourcesBefore);

    const removed = await cli("source", "remove", "c1");
    expect(removed.status, removed.err.join("\n")).toBe(0);
    expect(removed.out.map((line) => line.trim())).toContain("c1 source removed");
    expect((await cli("source", "list")).out.join("\n")).not.toMatch(/\bc1\b/);
  });

  test.each([["1password"], ["login"]])("source %s --token-stdin refuses more than 16 KiB of stdin", async (subcommand) => {
    const realRead = fs.readFileSync;
    vi.spyOn(fs, "readFileSync").mockImplementation(((file: fs.PathOrFileDescriptor, options?: unknown) =>
      file === 0 ? Buffer.alloc(16 * 1024 + 1, 0x61) : realRead(file, options as never)) as typeof fs.readFileSync);
    await expectCliError(["source", subcommand, "op1", "--token-stdin"], "--token-stdin input is larger than 16 KiB");
    expect(fs.existsSync(world.sourcesFile)).toBe(false);
  });
});
