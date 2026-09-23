// Host fixture for live runtime tranches that run under Vitest.
//
// This is the TypeScript port of the project setup at the top of
// `tests/runtime/sandbox.sh`, reduced to what a tranche actually needs rather
// than what the cumulative sandbox happens to have built by the time it gets
// there. It provisions a throwaway project root and a throwaway XDG owner root,
// drives the two exact startup approvals through the same typed host commands a
// maintainer would run by hand, and starts the runtime.
//
// It deliberately does NOT reproduce the sandbox's firewall/proxy/audit/token
// fixtures, its custom recovery Dockerfile, or its multi-branch MCP history.
// Those exist for other tranches. A tranche that needs one should add it here
// behind an explicit option so the cost stays attributable.

import { startLivePhase } from "./timing.ts";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { cliEntryArgv, sessionAdmissionCrashEntryArgv } from "../../support/prebuilt-entry.ts";
import { liveRunToken } from "./run-token.ts";

const CAPTURE_MAX_BYTES = 1024 * 1024;
// Generated project roots are `<prefix><run token>.<random>`. The run token is
// what lets the leak guard below tell a sibling fixture from an earlier run's
// residue; `reclaim-sandbox-runtimes.sh` still matches on the prefix alone.
const SANDBOX_PROJECT_PREFIX = "runfree-runtime-sandbox-project.";
const SANDBOX_OWNER_PREFIX = "runfree-runtime-sandbox-owned.";
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/gu;

// The same signature `tests/runtime/reclaim-sandbox-runtimes.sh` uses: a
// container mounting a generated sandbox project directory. A real project's
// runtime never carries it, so this can never count a maintainer's own work.
const SANDBOX_MOUNT_SIGNATURE = SANDBOX_PROJECT_PREFIX;

export type LiveRuntimeBackend = "docker-desktop" | "orbstack";

export type CaptureResult = Readonly<{
  status: number;
  stdout: string;
  stderr: string;
  output: string;
}>;

export type LiveFixture = Readonly<{
  projectRoot: string;
  ownerRoot: string;
  env: NodeJS.ProcessEnv;
  runfree(args: readonly string[]): CaptureResult;
}>;

export type ProvisionLiveFixtureOptions = Readonly<{
  repoRoot: string;
  /** Extra host commands run against the project before its first startup. */
  configure?: (fixture: LiveFixture) => void;
  /** Retains the host project and XDG roots when provisioning itself fails. */
  keepHostStateOnFailure?: boolean;
}>;

function capture(command: string, args: readonly string[], options: childProcess.SpawnSyncOptions): CaptureResult {
  const result = childProcess.spawnSync(command, [...args], {
    encoding: "utf8",
    maxBuffer: CAPTURE_MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.error) throw result.error;
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const stderr = typeof result.stderr === "string" ? result.stderr : "";
  return Object.freeze({ status: result.status ?? 1, stdout, stderr, output: `${stdout}${stderr}` });
}

/**
 * Bounded single-line rendering of live output for a failure message. A live
 * failure that prints only its expectation is uninterpretable, and an unbounded
 * one buries the cause it is meant to explain. Control characters collapse to
 * spaces so a multi-line body cannot smear or corrupt the diagnostic.
 *
 * An over-long body keeps both ends. Startup output is Compose build and
 * container progress first and the refusal last, so a head-only cut kept the
 * build log and dropped the one line that named the cause.
 */
export function describeOutput(value: string, limit = 1600): string {
  const compact = value.replace(CONTROL_CHARACTERS, " ").replace(/ {2,}/gu, " ").trim();
  if (!compact) return "<empty>";
  if (compact.length <= limit) return compact;
  const tail = Math.floor((limit * 3) / 4);
  const head = limit - tail;
  return `${compact.slice(0, head)} … ${compact.slice(compact.length - tail)}`;
}

function assertDockerReachable(): void {
  const info = capture("docker", ["info"], {});
  if (info.status !== 0) {
    throw new Error(`docker daemon is not reachable: ${describeOutput(info.output)}`);
  }
}

/**
 * Whether a running container's mounts make it a sandbox runtime leaked by an
 * *earlier* run, as opposed to a sibling of the run asking.
 *
 * Split out from the daemon query so the classification is provable without a
 * daemon. Both halves are load-bearing and fail in opposite directions: drop
 * the signature test and a maintainer's own project counts as a leak; drop the
 * token test and, under more than one worker, every fixture after the first
 * refuses because its siblings are up.
 */
export function isLeakedSandboxRuntime(mountsJson: string, runToken: string): boolean {
  if (!mountsJson.includes(SANDBOX_MOUNT_SIGNATURE)) return false;
  return !mountsJson.includes(`${SANDBOX_MOUNT_SIGNATURE}${runToken}.`);
}

/**
 * Live runtimes left behind by earlier runs hold their Docker networks and
 * their MCP OAuth callback port. Both have already broken later runs: address
 * pools exhausted at network creation, and a callback port collision at Compose
 * start. Neither names its cause, and both arrive many minutes into a run that
 * was never going to pass, so this refuses up front instead of warning.
 *
 * Scoped to other runs' tokens, not to "any sandbox container", because the
 * live project runs files in parallel: a sibling file's runtime is expected to
 * be up while this one provisions. See `run-token.ts`.
 */
function assertNoLeakedSandboxRuntimes(): void {
  const running = capture("docker", ["ps", "-q"], {});
  if (running.status !== 0) {
    throw new Error(`could not list Docker containers: ${describeOutput(running.output)}`);
  }
  const runToken = liveRunToken();
  const leaked: string[] = [];
  for (const containerId of running.stdout.split("\n").map((line) => line.trim()).filter(Boolean)) {
    const mounts = capture("docker", ["inspect", "-f", "{{json .Mounts}}", containerId], {});
    if (mounts.status === 0 && isLeakedSandboxRuntime(mounts.stdout, runToken)) leaked.push(containerId);
  }
  if (leaked.length > 0) {
    throw new Error(
      `${leaked.length} container(s) from earlier live runs are still running; they hold Docker networks and the MCP callback port. Reclaim them with: make reclaim-runtime-sandbox-apply`,
    );
  }
}

export function assertLiveRuntimePreconditions(): void {
  assertDockerReachable();
  assertNoLeakedSandboxRuntimes();
}

function canonicalTempDir(prefix: string): string {
  const created = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  // macOS `mktemp`/`os.tmpdir()` commonly return a lexical `/var/folders/...`
  // path while the filesystem canonicalizes the same directory as
  // `/private/var/folders/...`. Production Git-layout planning canonicalizes
  // with `fs.realpathSync`, and `sessionMounts` requires byte-for-byte equality
  // between the project root and the Git-layout root, so the fixture has to use
  // the same function rather than `path.resolve`.
  return fs.realpathSync(created);
}

const CONTROL_APPROVAL_SUBJECTS = ["network-local", "network-project", "runtime-isolation"] as const;
const CONTROL_APPROVAL_PATTERN = /^runfree control approve ([a-z-]+) --subject-digest (sha256:[a-f0-9]{64})$/u;

type ControlApproval = Readonly<{ subject: string; digest: string }>;

/**
 * Parses the exact approval commands out of a fail-closed startup refusal.
 *
 * Output is parsed strictly and never evaluated as shell: each approval is
 * rebuilt as explicit argv from a fully anchored pattern, the subject set must
 * be exactly the expected three, and each digest must be a full sha256.
 */
export function parseExactControlApprovals(output: string): readonly ControlApproval[] {
  const approvals: ControlApproval[] = [];
  for (const line of output.split("\n")) {
    const match = CONTROL_APPROVAL_PATTERN.exec(line.trim());
    if (match) approvals.push(Object.freeze({ subject: match[1], digest: match[2] }));
  }
  if (approvals.length !== CONTROL_APPROVAL_SUBJECTS.length) {
    throw new Error(
      `control approval named ${approvals.length} exact subjects, expected ${CONTROL_APPROVAL_SUBJECTS.length}: ${describeOutput(output)}`,
    );
  }
  const named = [...approvals].map((approval) => approval.subject).sort().join(" ");
  const expected = [...CONTROL_APPROVAL_SUBJECTS].sort().join(" ");
  if (named !== expected) {
    throw new Error(`control approval demanded an unexpected subject set: ${named}`);
  }
  return Object.freeze(approvals);
}

/**
 * Runs a startup command, approving each exact subject the product refuses on.
 *
 * This does not disable either gate. It proves each one fires — startup must
 * fail closed and name its exact subject — and then approves those exact
 * digests. Removing an assertion here would silently convert a proof into a
 * bypass, so both refusals are required, not tolerated.
 */
function startWithExactApprovals(fixture: LiveFixture, args: readonly string[]): void {
  const desiredControls = fixture.runfree(args);
  if (desiredControls.status === 0) {
    throw new Error("startup required no control approval; the generated fixture must start unapproved");
  }
  if (!desiredControls.output.includes("desired controls require exact approval before startup")) {
    throw new Error(`startup did not fail closed on desired controls: ${describeOutput(desiredControls.output)}`);
  }
  // The refusal also prints `runfree policy use-approved`. Do not run it here:
  // activation is deferred while no proxy runtime is live, and `policy
  // use-approved` turns a deferred activation into an error. The next startup
  // selects the approved generation itself.
  for (const approval of parseExactControlApprovals(desiredControls.output)) {
    const approved = fixture.runfree(["control", "approve", approval.subject, "--subject-digest", approval.digest]);
    if (approved.status !== 0) {
      throw new Error(`could not approve control subject ${approval.subject}: ${describeOutput(approved.output)}`);
    }
  }

  const buildInput = fixture.runfree(args);
  if (buildInput.status === 0) {
    throw new Error("startup required no build approval; the generated fixture stages an unapproved image context");
  }
  if (!buildInput.output.includes("exact pre-sandbox Docker build approval is required")) {
    throw new Error(`startup did not fail closed on the staged agent build input: ${describeOutput(buildInput.output)}`);
  }
  // `image approve-context` approves whatever is currently staged under
  // `.runfree/image`. Everything staged there was written by this fixture,
  // which is what makes an unattended approval legitimate; a real project
  // reviews the staged files at the interactive prompt instead.
  const approvedBuild = fixture.runfree(["image", "approve-context"]);
  if (approvedBuild.status !== 0) {
    throw new Error(`could not approve the exact staged agent build input: ${describeOutput(approvedBuild.output)}`);
  }
  if (!/approved exact agent build input: sha256:[a-f0-9]{64}$/mu.test(approvedBuild.output)) {
    throw new Error(`image approval did not report an exact staged input digest: ${describeOutput(approvedBuild.output)}`);
  }
  // `approve-context` prints the same content the interactive prompt shows;
  // the listing header carries the file count (directories are counted apart).
  if (!/^Staged files \([1-9][0-9]*(?:, [1-9][0-9]* directories)?\):$/mu.test(approvedBuild.output)) {
    throw new Error(`image approval listed no staged files: ${describeOutput(approvedBuild.output)}`);
  }

  const started = fixture.runfree(args);
  if (started.status !== 0) {
    throw new Error(`runtime startup failed after exact approvals: ${describeOutput(started.output)}`);
  }
}

function git(projectRoot: string, args: readonly string[]): void {
  const result = capture("git", ["-C", projectRoot, ...args], {});
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${describeOutput(result.output)}`);
  }
}

export function provisionLiveFixture(options: ProvisionLiveFixtureOptions): LiveFixture {
  assertLiveRuntimePreconditions();

  const runToken = liveRunToken();
  const projectRoot = canonicalTempDir(`${SANDBOX_PROJECT_PREFIX}${runToken}.`);
  const ownerRoot = canonicalTempDir(`${SANDBOX_OWNER_PREFIX}${runToken}.`);
  const env = Object.freeze({
    ...process.env,
    // All three host roots the CLI derives from XDG. The config root holds the
    // host-owned credential source registry and per-project token configs;
    // without isolating it, a tranche's `credential source add` lands in the
    // maintainer's real registry and the next fixture finds it "already
    // configured".
    XDG_CONFIG_HOME: path.join(ownerRoot, "xdg-config"),
    XDG_DATA_HOME: path.join(ownerRoot, "xdg-data"),
    XDG_STATE_HOME: path.join(ownerRoot, "xdg-state"),
  });
  const fixture: LiveFixture = Object.freeze({
    projectRoot,
    ownerRoot,
    env,
    runfree(args: readonly string[]): CaptureResult {
      // The source-backed CLI: the prebuilt bundle when the live globalSetup
      // built one, else `node --import tsx`. The two env values are what
      // `bin/runfree.js` sets for an invocation from the repo root, so the
      // CLI resolves its package root and invocation cwd exactly as the
      // wrapper would; `--workspace` names the project either way.
      const finishPhase = startLivePhase(`fixture: runfree ${args.slice(0, 2).join(" ")}`);
      try {
        return capture(process.execPath, [...cliEntryArgv(), "--workspace", projectRoot, ...args], {
          cwd: options.repoRoot,
          env: { ...env, RUNFREE_INVOCATION_CWD: options.repoRoot, RUNFREE_PROJECT_ROOT: options.repoRoot },
        });
      } finally { finishPhase(); }
    },
  });

  // Provisioning owns its own failure cleanup. A caller can only tear down a
  // fixture it received, so a failure between the first Compose resource and
  // the successful return would otherwise leak exactly the containers and
  // networks whose accumulation breaks later runs.
  try {
    fs.writeFileSync(
      path.join(projectRoot, "package.json"),
      `${JSON.stringify({ name: "runfree-runtime-live", private: true, packageManager: "pnpm@10" })}\n`,
    );

    for (const args of [["init"], ["image", "init"]]) {
      const result = fixture.runfree(args);
      if (result.status !== 0) {
        throw new Error(`runfree ${args.join(" ")} failed: ${describeOutput(result.output)}`);
      }
    }

    // Session mounts require a Git layout whose host root is exactly this
    // project root, so the fixture needs a real repository with one commit.
    git(projectRoot, ["init", "-b", "main"]);
    git(projectRoot, ["config", "user.name", "Runfree Runtime Test"]);
    git(projectRoot, ["config", "user.email", "runtime-test@runfree.invalid"]);
    git(projectRoot, ["add", "package.json"]);
    git(projectRoot, ["commit", "-m", "initial live fixture"]);

    options.configure?.(fixture);
    startWithExactApprovals(fixture, ["up"]);
    return fixture;
  } catch (failure) {
    try {
      destroyLiveFixture(fixture, { keepHostState: options.keepHostStateOnFailure });
    } catch (cleanupFailure) {
      throw new AggregateError(
        [failure, cleanupFailure],
        "live fixture provisioning failed and its cleanup also failed; reclaim with make reclaim-runtime-sandbox-apply",
      );
    }
    throw failure;
  }
}

export type DestroyLiveFixtureOptions = Readonly<{
  /**
   * Keeps the host project and XDG roots for reproduction. The Compose runtime
   * is destroyed either way: keeping it holds three Docker networks and the MCP
   * callback port, and enough kept runs exhaust the daemon's predefined address
   * pools so that later runs fail for a reason unrelated to the code under
   * test. Reproduction needs the host state, not the containers, and `runfree
   * up` recreates the runtime from the kept state.
   */
  keepHostState?: boolean;
  report?: (message: string) => void;
}>;

export function destroyLiveFixture(fixture: LiveFixture, options: DestroyLiveFixtureOptions = {}): void {
  const report = options.report ?? ((message: string) => process.stderr.write(`${message}\n`));
  const destroyed = fixture.runfree(["destroy"]);
  if (destroyed.status !== 0) {
    report(
      `runtime-live: destroy failed; reclaim with make reclaim-runtime-sandbox-apply: ${describeOutput(destroyed.output)}`,
    );
  }
  if (options.keepHostState) {
    report(`runtime-live: keeping project at ${fixture.projectRoot}`);
    report(
      `runtime-live: reproduce with XDG_DATA_HOME=${fixture.env.XDG_DATA_HOME} XDG_STATE_HOME=${fixture.env.XDG_STATE_HOME} ./bin/runfree.js --workspace ${fixture.projectRoot} up`,
    );
    return;
  }
  // Only ever removes directories this module created under the system temp
  // directory, under its own generated prefixes.
  for (const root of [fixture.projectRoot, fixture.ownerRoot]) {
    if (!path.basename(root).startsWith("runfree-runtime-sandbox-")) {
      throw new Error(`refusing to remove an unexpected live fixture root: ${root}`);
    }
    // Docker Desktop on macOS guards a bind-mounted host directory with a
    // `deny delete` ACL and leaves it behind when the container is removed
    // abruptly (a killed launch, a forced removal). The owner cannot rmdir
    // such a directory, so an otherwise complete teardown would fail on the
    // project's mounted `.codex`; clearing every ACL first keeps the removal
    // scoped to this fixture's own root.
    if (process.platform === "darwin") capture("chmod", ["-RN", root], {});
    fs.rmSync(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Sandbox layer: the seeded project the ported security tranches run against.
//
// `provisionLiveFixture` above reproduces the minimal project preamble (init,
// image init, a one-commit Git repo, and the two fail-closed startup
// approvals). This layer adds the rest of the retired sandbox.sh project setup
// — the seeded allowlist and credential, the enabled agent services, the
// project MCP/Codex files and their branch history, and a project agent image
// — and the standing-session primitive the ported tranches use to `docker
// exec` into a live per-session agent.
//
// Two deliberate departures from the bash fixture, both consequences of the
// D23 per-session cutover:
//
//   1. The default agent is the built-in `claude`, not a custom `pathProbe`.
//      Per-session launch refuses custom agents (cutover decision D-3), so the
//      custom-default-agent probe has no per-session analog; `managed-launch`
//      asserts the refusal instead. The `runfree-path-probe` binary is gone.
//
//   2. There is no shared long-lived `agent` container to `docker exec` into,
//      and no recovery-dispatch toggle recording argv inside it. Instead the
//      project image replaces the pinned Claude launcher's real target with a
//      stand-in that records the managed argv to a workspace-bind-mounted file
//      and then stays up (`exec sleep`, in effect). A launched `claude`
//      session therefore both proves the managed argv and holds open a
//      container the tranches can inspect. What runs inside the container is
//      not what these tranches prove; the stand-in is named as such here.

import { SESSION_CONTAINER_LABELS } from "../../../packages/cli/src/runtime/session-containers.ts";
import { SESSION_ADMISSION_ROOT } from "../../../packages/runtime-contracts/src/session-admission.ts";
import {
  SESSION_ELIGIBILITY_PATH,
  SESSION_FILES_DIR,
} from "../../../packages/runtime-contracts/src/session-file.ts";
import {
  CRASH_PRECONDITION_EXIT,
  HELD_STATE_FILE,
  type HeldSessionState,
} from "../session-admission-crash.ts";
import { docker } from "./docker.ts";

/** The one built-in the Phase-1 tranches launch; the sandbox's default was `pathProbe`. */
export const SANDBOX_PROBE_AGENT = "claude" as const;

/**
 * Where the project image's Claude stand-in records the managed launch argv,
 * relative to the project root (bind-mounted at `/workspace` in the session).
 *
 * A workspace path rather than container-local `/tmp`: per-session containers
 * are ephemeral, so the argv the sandbox read back with `docker exec ... tail
 * /tmp/...` would vanish with the container. The bind mount keeps it on the
 * host, where a tranche reads it after the session has even been revoked.
 */
export const MANAGED_ARGV_DIRNAME = ".runfree-managed-argv";
export const MANAGED_CLAUDE_ARGV_RELATIVE_PATH = path.join(MANAGED_ARGV_DIRNAME, "claude.jsonl");
/**
 * Presence of this file (bind-mounted) tells the Claude stand-in to stay up
 * instead of recording-and-exiting. A standing session creates it before launch
 * so the container holds open for `docker exec`; a one-shot launch (`mcp auth`,
 * a D-3 refusal) runs with it absent so the command completes on its own.
 */
export const MANAGED_HOLD_RELATIVE_PATH = path.join(MANAGED_ARGV_DIRNAME, "hold");
/** The same paths as the container sees them. */
export const MANAGED_CLAUDE_ARGV_CONTAINER_PATH = "/workspace/.runfree-managed-argv/claude.jsonl";
export const MANAGED_HOLD_CONTAINER_PATH = "/workspace/.runfree-managed-argv/hold";

// Never a real token and never reaches the agent: the audit-mode credential
// strip proof needs a *configured* credential header name to exist so the union
// strip does not return early on an empty set. A resolvable host-env value keeps
// the credential from denying its host during startup convergence.
const STRIP_TOKEN_ENV = "RUNFREE_SANDBOX_STRIP_TOKEN";
const STRIP_TOKEN_VALUE = "sandbox-not-a-real-token";

/**
 * The Node stand-in that replaces the pinned Claude launcher's real target.
 *
 * `claude-runfree.sh` (the base image's `/usr/local/bin/claude`) prepends the
 * strict Runfree MCP flags and execs `claude-real`; this file becomes that
 * `claude-real`. It records exactly the argv `claude-real` receives — which is
 * the managed argv under test — to the workspace bind mount, then stays alive so
 * the launched session holds a container open. `--resume` ends promptly, so a
 * resumed foreground process can complete, mirroring the shared long-lived stub.
 */
const MANAGED_CLAUDE_REAL_SCRIPT = `#!/usr/bin/env node
// Live-fixture Claude stand-in. Not a production artifact: it records the
// managed launch argv to a workspace-bind-mounted file and then either stays up
// (so a held per-session container remains inspectable) or exits (so a one-shot
// launch completes). It proves the launch argv, not the agent runtime.
"use strict";
const fs = require("node:fs");
const args = process.argv.slice(2);
try {
  fs.mkdirSync("/workspace/${MANAGED_ARGV_DIRNAME}", { recursive: true });
  fs.appendFileSync("${MANAGED_CLAUDE_ARGV_CONTAINER_PATH}", JSON.stringify(args) + "\\n");
} catch (error) {
  process.stderr.write("managed-claude-real: could not record argv: " + String(error) + "\\n");
}
if (args.includes("--resume")) {
  // Mirrors the long-lived stub's resume branch: end promptly so a resumed
  // foreground process can complete.
  setTimeout(() => process.exit(0), 45000);
} else if (fs.existsSync("${MANAGED_HOLD_CONTAINER_PATH}")) {
  // Held: keep the event loop alive without spinning; the host ends the session
  // with \`docker kill\`.
  setInterval(() => {}, 1 << 30);
} else {
  process.exit(0);
}
`;

const MANAGED_CLAUDE_REAL_FILENAME = "managed-claude-real.js";

/**
 * The Dockerfile stanza appended to `runfree image init`'s default.
 *
 * Replaces the pinned Claude launcher's real target with the recorder stand-in
 * and installs a setuid copy of `id` so the capability tranche can prove a
 * setuid binary still runs as uid 1000. Root for the build steps; `USER agent`
 * at the end to match the default scaffold (the session's uid is set by the
 * driver at create time regardless).
 */
const MANAGED_IMAGE_DOCKERFILE_STANZA = [
  "",
  "USER root",
  "RUN mv /usr/local/libexec/runfree/claude-real /usr/local/libexec/runfree/claude-real-pinned \\",
  " && install -m 4755 /usr/bin/id /usr/local/bin/runfree-setuid-id",
  `COPY ${MANAGED_CLAUDE_REAL_FILENAME} /usr/local/libexec/runfree/claude-real`,
  "RUN chmod 0755 /usr/local/libexec/runfree/claude-real",
  "USER agent",
  "",
].join("\n");

const HOST_MCP_JSON = `${JSON.stringify({ mcpServers: { hostSentinel: { url: "https://host-mcp.invalid/mcp" } } })}\n`;
const BRANCH_MCP_JSON = `${JSON.stringify({ mcpServers: { branchSentinel: { url: "https://branch-mcp.invalid/mcp" } } })}\n`;
const CODEX_CONFIG_TOML = '[mcp_servers.host_sentinel]\nurl = "https://host-codex.invalid/mcp"\n';

function runOrThrow(fixture: LiveFixture, args: readonly string[]): void {
  const result = fixture.runfree(args);
  if (result.status !== 0) {
    throw new Error(`runfree ${args.join(" ")} failed: ${describeOutput(result.output)}`);
  }
}

/**
 * Reproduces sandbox.sh's project preamble on a `provisionLiveFixture` project.
 *
 * Runs after `provisionLiveFixture`'s own `git init -b main` + package.json
 * commit and before the first `up`, so the seeded policy is desired project
 * input at startup and the project image is what the runtime builds.
 */
export function configureSandboxProject(fixture: LiveFixture): void {
  const projectRoot = fixture.projectRoot;

  // Seed the exact hosts later tranches read back and rule on; `runfree init`
  // writes a deny-all policy and no starter allowlist. `example.net` is a
  // project-only reference for the empty-allowlist tranche: it must not also be a
  // user-scope MCP/service host (which survive an emptied project policy), and an
  // IANA reserved-example domain never is, unlike api.github.com on a developer's
  // own machine.
  for (const host of ["api.github.com", "github.com", "raw.githubusercontent.com", "example.net"]) {
    runOrThrow(fixture, ["host", "add", host, "--no-reload"]);
  }
  // A configured credential header name must exist for the audit-mode strip
  // proof; the value is resolved from the host env at token sync, never here.
  runOrThrow(fixture, [
    "credential", "add", "sandbox-strip-probe",
    "--host", "raw.githubusercontent.com",
    "--header", "Authorization", "--scheme", "bearer",
    "--from-env", STRIP_TOKEN_ENV, "--no-reload",
  ]);
  // Built-in launches refuse to start until their operational service is
  // enabled; both are `credential: none`, so this binds no token source.
  runOrThrow(fixture, ["service", "enable", "agent-claude", "--no-reload"]);
  runOrThrow(fixture, ["service", "enable", "agent-codex", "--no-reload"]);

  fs.writeFileSync(path.join(projectRoot, ".mcp.json"), HOST_MCP_JSON);
  fs.mkdirSync(path.join(projectRoot, ".codex"), { recursive: true });
  fs.writeFileSync(path.join(projectRoot, ".codex", "config.toml"), CODEX_CONFIG_TOML);
  // The legacy nested-image inbox mountpoint; startup must remove it safely
  // before creating the replacement `/runfree/inbox` mount.
  fs.mkdirSync(path.join(projectRoot, ".runfree-images"), { recursive: true });

  const imageDir = path.join(projectRoot, ".runfree", "image");
  fs.writeFileSync(path.join(imageDir, MANAGED_CLAUDE_REAL_FILENAME), MANAGED_CLAUDE_REAL_SCRIPT, { mode: 0o755 });
  fs.appendFileSync(path.join(imageDir, "Dockerfile"), MANAGED_IMAGE_DOCKERFILE_STANZA);

  // Branch history for the MCP branch-checkout proof: `main` carries the host
  // sentinel, `mcp-update` a different one, `no-mcp` none at all.
  git(projectRoot, ["add", ".mcp.json"]);
  git(projectRoot, ["commit", "-m", "add project MCP config"]);
  git(projectRoot, ["checkout", "-b", "mcp-update"]);
  fs.writeFileSync(path.join(projectRoot, ".mcp.json"), BRANCH_MCP_JSON);
  git(projectRoot, ["commit", "-am", "update project MCP config"]);
  git(projectRoot, ["checkout", "-b", "no-mcp", "main"]);
  git(projectRoot, ["rm", ".mcp.json"]);
  git(projectRoot, ["commit", "-m", "remove project MCP config"]);
  git(projectRoot, ["checkout", "main"]);
}

/**
 * Provisions the shared sandbox fixture: a fully seeded project with the
 * recorder/long-lived project image, started through the fail-closed approvals.
 *
 * Sets the strip-credential's host env in this process so the seeded credential
 * resolves during startup convergence; `provisionLiveFixture` snapshots
 * `process.env` into the fixture env.
 */
export function provisionSandboxFixture(repoRoot: string): LiveFixture {
  process.env[STRIP_TOKEN_ENV] = STRIP_TOKEN_VALUE;
  return provisionLiveFixture({ repoRoot, configure: configureSandboxProject });
}

// ---------------------------------------------------------------------------
// Standing session: a launched built-in `claude` held open for `docker exec`.
// ---------------------------------------------------------------------------

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
/** Admission to attached is seconds on a healthy daemon; the bound is for a cold one. */
const ATTACHED_WAIT_TIMEOUT_MS = 180_000;

export type StandingSession = Readonly<{
  /** The 64-hex id of the running per-session agent container to exec into. */
  containerId: string;
  /** The session's source IP; its authority in the paired consumers. */
  sourceIp: string;
  sessionId: string;
}>;

export type StandingSessionHandle = Readonly<{
  session: StandingSession;
  /** Ends only this session and waits for its owner's teardown. */
  stop: () => Promise<void>;
  /** Ends this session and verifies an empty project. For a group, use
   * releaseStandingSessions so live peers are stopped before the global check.
   */
  release: () => Promise<void>;
}>;

/** Stop every owner before checking global emptiness. Continue through failures
 * so one broken teardown cannot leave its peers running or hide its error.
 */
export async function releaseStandingSessions(
  handles: readonly Pick<StandingSessionHandle, "stop">[],
  verifyEmpty: () => Promise<void>,
): Promise<void> {
  const failures: unknown[] = [];
  for (const handle of [...handles].reverse()) {
    try { await handle.stop(); } catch (error) { failures.push(error); }
  }
  try { await verifyEmpty(); } catch (error) { failures.push(error); }
  if (failures.length) throw new AggregateError(failures, "standing session cleanup failed");
}

/**
 * Launches a built-in `claude` session through the production admission path and
 * holds it attached, returning the running container to inspect.
 *
 * Uses the crash runner's `--launch --hold-dir` mode — the only caller of the
 * production `launchBuiltin` in the repo — which publishes the first attached
 * observation to a hold directory and then runs to completion when the session
 * ends. The recorder/long-lived project image keeps the launched process up, so
 * the session reaches and stays attached.
 */
export async function startStandingSession(
  fixture: LiveFixture,
  options: Readonly<{
    /**
     * Launch beside already-attached sessions instead of requiring a clean
     * project. Release concurrent handles together with releaseStandingSessions.
     */
    allowExistingSessions?: boolean;
  }> = {},
): Promise<StandingSessionHandle> {
  const holdDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-standing-session."));
  // The stand-in stays up only while this bind-mounted file exists; create it
  // before launch so `claude-real` sees it and holds the container open.
  const holdMarker = path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH);
  fs.mkdirSync(path.dirname(holdMarker), { recursive: true });
  fs.writeFileSync(holdMarker, "");
  const child = childProcess.spawn(
    process.execPath,
    [
      ...sessionAdmissionCrashEntryArgv(),
      "--workspace", fixture.projectRoot,
      "--agent", SANDBOX_PROBE_AGENT,
      "--launch", "--hold-dir", holdDir,
      ...(options.allowExistingSessions ? ["--allow-existing-sessions"] : []),
    ],
    { cwd: REPO_ROOT, env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
  );

  let output = "";
  const collect = (chunk: Buffer | string): void => {
    output += String(chunk);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);

  let exited: Readonly<{ status: number | null }> | undefined;
  const completion = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status) => {
      exited = Object.freeze({ status });
      resolve();
    });
  });

  const statePath = path.join(holdDir, HELD_STATE_FILE);
  const deadline = Date.now() + ATTACHED_WAIT_TIMEOUT_MS;
  while (!fs.existsSync(statePath)) {
    if (exited) {
      const detail = exited.status === CRASH_PRECONDITION_EXIT
        ? "the project was not clean before the launch, so an earlier case failed to converge"
        : "the launch ended before any session was observed attached";
      throw new Error(`${detail}: ${describeOutput(output, 4000)}`);
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`no session reached attached: ${describeOutput(output, 4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  const held = JSON.parse(fs.readFileSync(statePath, "utf8")) as HeldSessionState;
  const record = held.records[0];
  if (!record) throw new Error(`the launch observed no attached record: ${JSON.stringify(held)}`);
  if (!record.containerId) throw new Error(`the attached record names no container: ${JSON.stringify(record)}`);
  const session: StandingSession = Object.freeze({
    containerId: record.containerId,
    sourceIp: record.sourceIp,
    sessionId: record.sessionId,
  });

  const stop = async (): Promise<void> => {
    // Remove the hold marker first so any subsequent one-shot launch records and
    // exits rather than staying up. Existing stand-ins read it only at startup;
    // their intervals keep running until their own containers are stopped.
    fs.rmSync(holdMarker, { force: true });
    try {
      const killed = docker(["kill", session.containerId]);
      if (killed.status !== 0) throw new Error(`could not stop standing session: ${describeOutput(killed.output)}`);
      await completion;
    } finally { fs.rmSync(holdDir, { recursive: true, force: true }); }
  };
  return Object.freeze({ session, stop, release: () => releaseStandingSessions([{ stop }], () => forceCleanSessions(fixture)) });
}

export function assertCleanSessionReport(status: number | null, output: string): void {
  const line = output.split("\n").find((candidate) => candidate.startsWith('{"v":1,"kind":"runfree-session-admission-crash-report"'));
  if (status !== 0 || !line) throw new Error(`session cleanup failed: ${describeOutput(output)}`);
  const report = JSON.parse(line);
  if (!report.lifecycleRegistryEmpty || report.residualContainers !== 0 || report.records?.length !== 0 || report.harnessReset) {
    throw new Error(`test left session residue; harness repair was required: ${describeOutput(line)}`);
  }
}

/** Verifies empty state, repairing failed cases for isolation and reporting
 * the repair as a failure. A successful case never needs a destructive reset.
 */
export async function forceCleanSessions(fixture: LiveFixture): Promise<void> {
  const finishPhase = startLivePhase("fixture: verify session cleanup");
  try {
    await new Promise<void>((resolve, reject) => {
      const child = childProcess.spawn(
        process.execPath,
        [...sessionAdmissionCrashEntryArgv(), "--workspace", fixture.projectRoot, "--agent", SANDBOX_PROBE_AGENT, "--force-clean"],
        { cwd: REPO_ROOT, env: fixture.env, stdio: ["ignore", "pipe", "pipe"] },
      );
      let output = "";
      child.stdout.on("data", (chunk) => { output = (output + String(chunk)).slice(-CAPTURE_MAX_BYTES); });
      child.stderr.on("data", (chunk) => { output = (output + String(chunk)).slice(-CAPTURE_MAX_BYTES); });
      child.once("error", reject);
      child.once("close", (status) => {
        try {
          assertCleanSessionReport(status, output);
          resolve();
        } catch (error) { reject(error); }
      });
    });
  } finally { finishPhase(); }
}

/**
 * The running per-session agent containers for a project, by role label.
 *
 * Per-session containers are resolved by `io.runfree.container-role=session-agent`
 * scoped to the Compose project, never by `com.docker.compose.service=agent` —
 * the cutover removed the shared `agent` service. `run` is injectable so the
 * resolver can be fault-injected without a daemon.
 */
export function sessionAgentContainerIds(
  project: string,
  run: (args: readonly string[]) => CaptureResult = docker,
): readonly string[] {
  const result = run([
    "ps", "--no-trunc",
    "--filter", `label=com.docker.compose.project=${project}`,
    "--filter", `label=${SESSION_CONTAINER_LABELS.role}=session-agent`,
    "--format", "{{.ID}}",
  ]);
  if (result.status !== 0) {
    throw new Error(`could not list session-agent containers for ${project}: ${describeOutput(result.output)}`);
  }
  return result.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
}

/**
 * Resolves the single running session-agent container id, or throws.
 *
 * The load-bearing failure mode is "no session": a probe that ran `docker exec`
 * against an empty id would exec into the daemon's default and pass vacuously.
 * This refuses anything but exactly one 64-hex id.
 */
export function resolveStandingSessionContainer(
  project: string,
  run: (args: readonly string[]) => CaptureResult = docker,
): string {
  const ids = sessionAgentContainerIds(project, run);
  if (ids.length !== 1) {
    throw new Error(`expected exactly one running session-agent container for ${project}, found ${ids.length}`);
  }
  if (!/^[a-f0-9]{64}$/u.test(ids[0])) {
    throw new Error(`session-agent container id is not the exact 64-hex identity: ${ids[0]}`);
  }
  return ids[0];
}

/** The IPv4 members of one proxy-owned nftables set, or throws (never silently empty). */
export function ownedNftSetIps(
  proxyId: string,
  setName: string,
  run: (args: readonly string[]) => CaptureResult = docker,
): readonly string[] {
  const json = run(["exec", "--user", "0:0", proxyId, "nft", "-j", "list", "set", "inet", "runfree_proxy", setName]);
  if (json.status !== 0) throw new Error(`could not read the ${setName} set: ${describeOutput(json.output)}`);
  const parsed = JSON.parse(json.stdout) as { nftables?: { set?: { elem?: unknown[] } }[] };
  const set = (parsed.nftables ?? []).map((statement) => statement.set).find(Boolean);
  const ips: string[] = [];
  for (const element of set?.elem ?? []) {
    if (typeof element === "string") ips.push(element);
    else if (element && typeof element === "object") {
      const value = (element as { val?: unknown; elem?: { val?: unknown } }).val
        ?? (element as { elem?: { val?: unknown } }).elem?.val;
      if (typeof value === "string") ips.push(value);
    }
  }
  return ips;
}

/**
 * The admitted IPs that no currently-resolved host explains.
 *
 * The teardown/empty/restore checks assert this is empty rather than pinning
 * exact set equality: the proxy's DNS refresh legitimately rotates resolved
 * addresses, and approved MCP hosts survive an emptied project policy, so brittle
 * equality was both machine- and time-dependent. The precise invariant is that
 * every IP the enforce allowlist still admits is one the proxy currently
 * resolves; an unexplained addition or a stale leftover fails.
 */
export function unexplainedAdmittedIps(
  admittedIps: readonly string[],
  resolvedHostsSnapshot: string,
): readonly string[] {
  return admittedIps.filter((ip) => !resolvedHostsSnapshot.includes(`"${ip}"`));
}

// ---------------------------------------------------------------------------
// Which admission source a live run actually exercised.
//
// Every interesting assertion below is about state a session has whatever put
// it there — a session container, an address in the kernel set, an empty
// registry — so a run whose proxy was somehow started without the per-session
// file source would keep passing while proving nothing about it. These helpers
// make the source itself an assertion at every point the tranches already
// assert authority.
//
// Everything is read from the proxy container and the kernel, never from host
// modules that took part in writing it.
// ---------------------------------------------------------------------------

/** The env key the runtime plan mints into every proxy it starts. */
export const PROXY_SESSION_ADMISSION_SOURCE_ENV = "RUNFREE_SESSION_ADMISSION_SOURCE";

/**
 * One `lstat` of one path inside the proxy, as the evidence reader reports it.
 * `present: false` is an absent path; anything else is the daemon's own answer.
 */
export type ProxyPathEvidence = Readonly<{
  present: boolean;
  uid?: number;
  nlink?: number;
  /** Permission bits as octal digits, e.g. `"644"`. */
  mode?: string;
  file?: boolean;
  symlink?: boolean;
}>;

export type SessionFileEvidence = Readonly<{
  sessionsDir: ProxyPathEvidence;
  eligibility: ProxyPathEvidence;
  files: readonly Readonly<{ name: string; stat: ProxyPathEvidence; content: string | null }>[];
}>;

// Pure observation, run in the proxy's own Node: `lstat` of the two pinned
// paths plus every entry of the sessions directory, and the bytes of each
// session file. It re-implements no product rule — the point is to see what the
// filesystem holds, which is what the proxy's readers see. Written as one exec
// so a tranche that calls this on every authority assertion pays one Docker
// round trip rather than six.
const SESSION_FILE_EVIDENCE_SCRIPT = `
const fs = require("node:fs");
const path = require("node:path");
const sessionsDir = ${JSON.stringify(SESSION_FILES_DIR)};
function entry(target) {
  try {
    const stat = fs.lstatSync(target);
    return {
      present: true,
      uid: stat.uid,
      nlink: stat.nlink,
      mode: (stat.mode & 0o7777).toString(8),
      file: stat.isFile(),
      symlink: stat.isSymbolicLink(),
    };
  } catch (error) {
    if (error && error.code === "ENOENT") return { present: false };
    throw error;
  }
}
let names = [];
try { names = fs.readdirSync(sessionsDir).sort(); }
catch (error) { if (!error || error.code !== "ENOENT") throw error; }
const files = [];
for (const name of names) {
  // Only what the proxy's own reader considers a session file. A heartbeat
  // mid-write leaves a \`.runfree-<pid>-<hex>.tmp\` beside the real one for the
  // few milliseconds before its rename, and reporting that as a session file
  // would make every assertion here intermittently wrong about a directory the
  // proxy reads exactly this way.
  if (!name.endsWith(".json")) continue;
  const target = path.join(sessionsDir, name);
  let content = null;
  try { content = fs.readFileSync(target, "utf8"); } catch {}
  files.push({ name: name, stat: entry(target), content: content });
}
process.stdout.write(JSON.stringify({
  sessionsDir: entry(sessionsDir),
  eligibility: entry(${JSON.stringify(SESSION_ELIGIBILITY_PATH)}),
  files: files,
}) + "\\n");
`;

/** What the session-admission root currently holds, read from inside the proxy. */
export function readSessionFileEvidence(
  proxyId: string,
  run: (args: readonly string[]) => CaptureResult = docker,
): SessionFileEvidence {
  const result = run(["exec", "--user", "0:0", proxyId, "node", "-e", SESSION_FILE_EVIDENCE_SCRIPT]);
  if (result.status !== 0) {
    throw new Error(`could not read ${SESSION_ADMISSION_ROOT} from the proxy: ${describeOutput(result.output)}`);
  }
  return JSON.parse(result.stdout) as SessionFileEvidence;
}

/** The proxy's own environment, as the daemon reports it. */
export function proxyEnvironment(
  proxyId: string,
  run: (args: readonly string[]) => CaptureResult = docker,
): readonly string[] {
  const result = run(["inspect", "-f", "{{json .Config.Env}}", proxyId]);
  if (result.status !== 0) {
    throw new Error(`could not read the proxy environment: ${describeOutput(result.output)}`);
  }
  return JSON.parse(result.stdout.trim()) as string[];
}

function sortedUnique(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}

function requireExactOwnedFile(
  evidence: ProxyPathEvidence,
  subject: string,
  context: string,
): void {
  if (!evidence.present) throw new Error(`${context}: ${subject} does not exist in the proxy`);
  if (evidence.file !== true || evidence.symlink === true) {
    throw new Error(`${context}: ${subject} is not a plain regular file`);
  }
  if (evidence.uid !== 0) throw new Error(`${context}: ${subject} is owned by uid ${evidence.uid}, not root`);
  if (evidence.nlink !== 1) throw new Error(`${context}: ${subject} carries ${evidence.nlink} links, not exactly one`);
  if (evidence.mode !== "644") throw new Error(`${context}: ${subject} is mode ${evidence.mode}, not 644`);
}

/**
 * Asserts this runtime is admitting sessions through per-session files, and
 * that the files it holds are exactly the ones the given records claim.
 *
 * The four things that together mean "sessions are served, and by exactly
 * these files":
 *
 *   1. the proxy was started with `RUNFREE_SESSION_ADMISSION_SOURCE=files`;
 *   2. `eligibility.json` exists as a root-owned 0644 regular file (F8) — a
 *      proxy holding no eligibility serves nothing;
 *   3. `sessions/` holds exactly one such file per live record, each named by
 *      its own session key and carrying the record's source IP; and
 *   4. the kernel's `session_ipv4` set enforces exactly the file addresses.
 *
 * Throws rather than using `expect`, so it can be called from fixture-level
 * helpers as well as from a test body; every message names the project root so
 * a failure is reproducible without re-deriving it.
 */
export function assertFilesPathExercised(
  fixture: LiveFixture,
  proxyId: string,
  recordSourceIps: readonly string[],
  label: string,
): void {
  const context = `${label} (files path, project ${fixture.projectRoot})`;
  const environment = proxyEnvironment(proxyId);
  if (!environment.includes(`${PROXY_SESSION_ADMISSION_SOURCE_ENV}=files`)) {
    throw new Error(
      `${context}: the proxy does not carry ${PROXY_SESSION_ADMISSION_SOURCE_ENV}=files, so this run is not on the files path`,
    );
  }
  const evidence = readSessionFileEvidence(proxyId);
  requireExactOwnedFile(evidence.eligibility, "eligibility.json", context);

  const expected = sortedUnique(recordSourceIps);
  const observed: string[] = [];
  for (const file of evidence.files) {
    requireExactOwnedFile(file.stat, `sessions/${file.name}`, context);
    const key = file.name.endsWith(".json") ? file.name.slice(0, file.name.length - 5) : undefined;
    if (key === undefined || !/^[a-f0-9]{64}$/u.test(key)) {
      throw new Error(`${context}: sessions/${file.name} is not named by a session key`);
    }
    if (file.content === null) throw new Error(`${context}: sessions/${file.name} could not be read`);
    const parsed = JSON.parse(file.content) as { sessionKey?: unknown; sourceIp?: unknown };
    if (parsed.sessionKey !== key) {
      throw new Error(`${context}: sessions/${file.name} claims session key ${String(parsed.sessionKey)}`);
    }
    if (typeof parsed.sourceIp !== "string") {
      throw new Error(`${context}: sessions/${file.name} names no source IP`);
    }
    observed.push(parsed.sourceIp);
  }
  const served = sortedUnique(observed);
  if (served.join(",") !== expected.join(",")) {
    throw new Error(
      `${context}: the proxy holds session files for [${served.join(", ")}], expected exactly [${expected.join(", ")}]`,
    );
  }
  const enforced = sortedUnique(ownedNftSetIps(proxyId, "session_ipv4"));
  if (enforced.join(",") !== served.join(",")) {
    throw new Error(
      `${context}: the kernel session set enforces [${enforced.join(", ")}] while the session files name [${served.join(", ")}]`,
    );
  }
}

export type PublishedSessionEligibility = Readonly<{
  projectId: string;
  controlPlaneGenerationDigest: string;
  admissionContractEpoch: number;
  agentInternalNetworkId: string;
  allowedSessionAgents: readonly Readonly<{
    sessionAgentGenerationDigest: string;
    selectedAgentImageId: string;
  }>[];
}>;

/** The published session eligibility, parsed, as the proxy currently holds it. */
export function readPublishedSessionEligibility(proxyId: string): PublishedSessionEligibility {
  const result = docker(["exec", "--user", "0:0", proxyId, "cat", SESSION_ELIGIBILITY_PATH]);
  if (result.status !== 0) {
    throw new Error(`could not read ${SESSION_ELIGIBILITY_PATH}: ${describeOutput(result.output)}`);
  }
  return JSON.parse(result.stdout) as PublishedSessionEligibility;
}
