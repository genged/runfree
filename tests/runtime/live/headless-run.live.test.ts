// Live headless run tranche (`runfree run`, headless-run spec §5 "Live").
//
// Proves on the real backend what the unit and proxy-unit suites can only
// model:
//
//   - a run with no TTY completes, returns the agent's own code, and keeps
//     the host-only run record; its container differs from an interactive
//     one only in `Tty` and `OpenStdin` (mounts, capabilities, security
//     options, session firewall membership, and CA material equal), and its
//     session file carries `launchMode: "headless"` at the current admission
//     contract epoch;
//   - with `runfree approvals --watch` attached and an interactive session
//     live, the run session's `ask` write is denied at once and counted,
//     while the interactive session's write is held;
//   - a rule changed to `ask` during a run gives `headless-denied` and 68;
//   - an `ask` rule at launch does not refuse: the run starts, warns once,
//     records the host under run.json `askExposure`, its write is denied as
//     `headless-denied`, and it exits 68;
//   - a pending approval is refused with 65 before any session container is
//     created;
//   - after a timeout whose teardown was not confirmed, the next run gets 66
//     until the container is gone, and a normal timeout leaves no session
//     file, container, prompt file, or lock.
//
// The agent is a stand-in, not a model. The project image keeps the
// fixture's interactive Claude recorder (`configureStandingSessionImage`) and
// puts a dispatcher in front of it: argv carrying `-p` (the headless flag
// Runfree mints, `agents.ts`) runs the headless stub, anything else runs the
// recorder. The stub reads its stdin (the prompt, through the session
// entry's `--stdin-file`), takes its instructions from that prompt as JSON,
// records what it saw to the workspace bind mount, and prints one Claude
// `stream-json` success `result` line. What it does inside the container is
// not the subject; the host lifecycle, the proxy decision, and the run's exit
// code are.
//
// Write probes target a reserved `.invalid` host (`proxy-answer.ts`), so
// every answer is the proxy's own decision and no upstream is involved.
//
// Tiers (`tiers.ts`): the trust-boundary cases are core; the lock and
// teardown lifecycle is extended. Every case sets up and restores its own
// rule state, so a skipped case never leaves state for the next one.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { APPROVAL_HEADLESS_DENIED_EVENT_PREFIX } from "../../../packages/runtime-contracts/src/write-approvals.ts";
import { projectInfo } from "../../../packages/cli/src/config.ts";
import { nodeRuntimeIO } from "../../../packages/cli/src/runtime.ts";
import { readPendingApprovals } from "../../../packages/cli/src/runtime/approvals.ts";
import { RUNTIME_ADMISSION_CONTRACT_EPOCH } from "../../../packages/cli/src/runtime/component-state-v2.ts";
import { HEADLESS_RUN_LOCK_DIRNAME } from "../../../packages/cli/src/runtime/headless-run-lock.ts";
import type { HeadlessRunJson } from "../../../packages/cli/src/runtime/headless-run-record.ts";
import { SESSION_CONTAINER_LABELS } from "../../../packages/cli/src/runtime/session-containers.ts";
import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  assertFilesPathExercised,
  configureStandingSessionImage,
  describeOutput,
  destroyLiveFixture,
  forceCleanSessions,
  type LiveFixture,
  requireLiveRuntimeBackend,
  type LiveRuntimeBackend,
  provisionLiveFixture,
  readPublishedSessionEligibility,
  readSessionFileEvidence,
  sessionAgentContainerIds,
  startStandingSession,
  type StandingSessionHandle,
} from "./fixture.ts";
import { parseProbeAnswer } from "./proxy-answer.ts";
import { liveTierSelected } from "./tiers.ts";

const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
/** A run's startup through `attached` on a warm runtime is seconds; the bound is for a cold daemon. */
const RUN_READY_TIMEOUT_MS = 180_000;
/** A run that was told to finish: its drain, teardown, and record. */
const RUN_FINISH_TIMEOUT_MS = 180_000;
/** A refused or skipped run never reaches Docker create; it should end in seconds. */
const RUN_REFUSAL_TIMEOUT_MS = 120_000;
/**
 * A headless denial is synthesized by the proxy without waiting for an
 * approver. A held write waits for a decision or the approval timeout, so a
 * bound well below that timeout tells the two apart.
 */
const HEADLESS_DENIAL_BOUND_MS = 15_000;

/** The write probe host. Every case starts and ends with it at `writeAction=allow`. */
const WRITE_HOST = "runfree-headless-write.invalid";

/** Where the stub records what it saw, relative to the project root (`/workspace` in the session). */
const STUB_DIRNAME = ".runfree-headless";
const STUB_CONTAINER_ROOT = `/workspace/${STUB_DIRNAME}`;
const STUB_FILENAME = "headless-claude-stub.js";
const DISPATCH_FILENAME = "headless-claude-dispatch.sh";
const PROMPT_PATH_PATTERN = /^\/runfree\/inbox\/run-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\.prompt$/u;
const INBOX_PROMPT_PATTERN = /^run-.*\.prompt$/u;
const PROXY_CA_CERT_PATH = "/etc/proxy-ca/proxy-ca.crt";

function requiredBackend(): LiveRuntimeBackend {
  return requireLiveRuntimeBackend("the headless-run tranche");
}

// ---------------------------------------------------------------------------
// The headless agent stand-in.
// ---------------------------------------------------------------------------

/**
 * What a prompt tells the stub to do. The prompt is the run's only input
 * the stub sees, so it is also the per-case script.
 */
type StubDirective = Readonly<{
  /** Names the stub's record directory, `<project>/.runfree-headless/<tag>/`. */
  tag: string;
  /** Stay up after `ready` until `<tag>/release` exists. */
  hold?: boolean;
  /** Ignore SIGTERM and SIGINT, so only a kill or removal ends the container. */
  ignoreSignals?: boolean;
  /** Send one `POST` to this URL (no retry) after any hold, and record the answer. */
  post?: string;
  /** The stub's exit code, after it prints its success `result` line. */
  exitCode?: number;
}>;

/**
 * Live-fixture Claude headless stand-in. Not a production artifact.
 *
 * Synchronous throughout (`Atomics.wait` as its sleep), so it never yields to
 * the event loop: a SIGTERM with a listener installed is then never acted on,
 * which is how `ignoreSignals` keeps the container up.
 */
const HEADLESS_STUB_SCRIPT = `#!/usr/bin/env node
// Live-fixture Claude headless stand-in. Not a production artifact: it records
// its argv, stdin, and terminal state to the workspace bind mount, follows
// the JSON instructions in its prompt, and prints one stream-json result line.
"use strict";
const fs = require("node:fs");
const os = require("node:os");
const tty = require("node:tty");
const { spawnSync } = require("node:child_process");
const args = process.argv.slice(2);
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
let input = Buffer.alloc(0);
try { input = fs.readFileSync(0); } catch (error) { process.stderr.write("headless stub: no stdin: " + String(error) + "\\n"); }
let directive = {};
try { directive = JSON.parse(input.toString("utf8")); } catch { directive = {}; }
const tag = typeof directive.tag === "string" && /^[a-z0-9-]{1,40}$/.test(directive.tag) ? directive.tag : "untagged";
const dir = "${STUB_CONTAINER_ROOT}/" + tag;
fs.mkdirSync(dir, { recursive: true });
const record = (name, contents) => {
  fs.writeFileSync(dir + "/" + name + ".tmp", contents);
  fs.renameSync(dir + "/" + name + ".tmp", dir + "/" + name);
};
if (directive.ignoreSignals === true) {
  process.on("SIGTERM", () => {});
  process.on("SIGINT", () => {});
}
record("argv.json", JSON.stringify(args));
record("stdin", input);
record("terminal.json", JSON.stringify({ stdinTty: tty.isatty(0), stdoutTty: tty.isatty(1), stderrTty: tty.isatty(2) }));
record("ready", os.hostname() + "\\n");
if (directive.hold === true) {
  let waited = 0;
  while (!fs.existsSync(dir + "/release")) {
    if (waited > 20 * 60 * 1000) { process.stderr.write("headless stub was not released\\n"); process.exit(124); }
    sleep(100);
    waited += 100;
  }
}
if (typeof directive.post === "string") {
  const started = Date.now();
  const curl = spawnSync("curl", ["-sS", "--max-time", "120", "-X", "POST", "--data-raw", "{}",
    "-D", dir + "/post-headers", "-o", "/dev/null", "-w", "%{http_code}", directive.post], { encoding: "utf8" });
  record("post.json", JSON.stringify({ code: String(curl.stdout || "000").trim(), elapsedMs: Date.now() - started, stderr: String(curl.stderr || "") }));
}
const exitCode = Number.isSafeInteger(directive.exitCode) ? directive.exitCode : 0;
fs.writeSync(1, JSON.stringify({ type: "system", subtype: "init", session_id: "live-stub" }) + "\\n");
fs.writeSync(1, JSON.stringify({ type: "result", subtype: "success", is_error: false, result: "live headless stub finished " + tag }) + "\\n");
process.exit(exitCode);
`;

/**
 * Replaces `claude-real` (the target of the pinned `claude-runfree.sh`
 * launcher) with a dispatcher: the headless argv goes to the stub, every
 * other argv to the fixture's interactive recorder, unchanged.
 */
const DISPATCH_SCRIPT = `#!/bin/sh
# Live-fixture dispatcher. Not a production artifact.
for a in "$@"; do
  if [ "$a" = "-p" ]; then exec /usr/local/libexec/runfree/headless-claude-stub "$@"; fi
done
exec /usr/local/libexec/runfree/claude-real-interactive "$@"
`;

function stageHeadlessAgentStub(fixture: LiveFixture): void {
  const imageDir = path.join(fixture.projectRoot, ".runfree", "image");
  fs.writeFileSync(path.join(imageDir, STUB_FILENAME), HEADLESS_STUB_SCRIPT, { mode: 0o755 });
  fs.writeFileSync(path.join(imageDir, DISPATCH_FILENAME), DISPATCH_SCRIPT, { mode: 0o755 });
  fs.appendFileSync(path.join(imageDir, "Dockerfile"), [
    "",
    "USER root",
    "RUN mv /usr/local/libexec/runfree/claude-real /usr/local/libexec/runfree/claude-real-interactive",
    `COPY ${DISPATCH_FILENAME} /usr/local/libexec/runfree/claude-real`,
    `COPY ${STUB_FILENAME} /usr/local/libexec/runfree/headless-claude-stub`,
    "RUN chmod 0755 /usr/local/libexec/runfree/claude-real /usr/local/libexec/runfree/headless-claude-stub",
    "USER agent",
    "",
  ].join("\n"));
}

function runOrThrow(fixture: LiveFixture, args: readonly string[]): string {
  const result = fixture.runfree(args);
  if (result.status !== 0) throw new Error(`runfree ${args.join(" ")} failed: ${describeOutput(result.output)}`);
  return result.output;
}

function configureHeadlessProject(fixture: LiveFixture): void {
  configureStandingSessionImage(fixture);
  stageHeadlessAgentStub(fixture);
  // `allow` from the start: the write-posture preflight refuses a run while
  // any allowlisted host resolves to `ask` (the default), so every case that
  // needs `ask` sets it and restores `allow`.
  runOrThrow(fixture, ["host", "add", WRITE_HOST, "--no-reload"]);
  runOrThrow(fixture, ["host", "rules", WRITE_HOST, "--write", "allow", "--no-reload"]);
}

function stubDir(fixture: LiveFixture, tag: string): string {
  return path.join(fixture.projectRoot, STUB_DIRNAME, tag);
}

function readStubFile(fixture: LiveFixture, tag: string, name: string): string {
  return fs.readFileSync(path.join(stubDir(fixture, tag), name), "utf8");
}

function releaseStub(fixture: LiveFixture, tag: string): void {
  fs.mkdirSync(stubDir(fixture, tag), { recursive: true });
  fs.writeFileSync(path.join(stubDir(fixture, tag), "release"), "");
}

type StubPost = Readonly<{ code: string; blocked?: string; elapsedMs: number; stderr: string }>;

function readStubPost(fixture: LiveFixture, tag: string): StubPost {
  const post = JSON.parse(readStubFile(fixture, tag, "post.json")) as { code: string; elapsedMs: number; stderr: string };
  let headers = "";
  try { headers = readStubFile(fixture, tag, "post-headers"); } catch { headers = ""; }
  const answer = parseProbeAnswer(headers, post.code);
  return { ...post, ...(answer.blocked !== undefined ? { blocked: answer.blocked } : {}) };
}

// ---------------------------------------------------------------------------
// Running `runfree run` without a TTY.
// ---------------------------------------------------------------------------

type RunOutcome = Readonly<{ status: number | null; signal: NodeJS.Signals | null; stdout: string; output: string }>;

type StartedRun = Readonly<{
  child: childProcess.ChildProcess;
  completion: Promise<RunOutcome>;
  /** The outcome if the run has already ended. */
  ended: () => RunOutcome | undefined;
}>;

function writePrompt(fixture: LiveFixture, directive: StubDirective): string {
  const dir = path.join(fixture.ownerRoot, "prompts");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, `${directive.tag}.json`);
  fs.writeFileSync(file, `${JSON.stringify(directive)}\n`, { mode: 0o600 });
  return file;
}

/**
 * Starts `runfree run claude` the way a scheduler does: every standard
 * stream a pipe or closed, so there is no TTY anywhere. `env` adds to the
 * fixture's own environment (the unconfirmed-teardown case puts a Docker
 * shim first on `PATH`).
 */
function startRun(
  fixture: LiveFixture,
  promptFile: string,
  flags: readonly string[] = [],
  env: NodeJS.ProcessEnv = {},
): StartedRun {
  const child = childProcess.spawn(
    process.execPath,
    [...cliEntryArgv(), "--workspace", fixture.projectRoot, "run", "claude", "--prompt-file", promptFile, ...flags],
    {
      cwd: REPO_ROOT,
      env: { ...fixture.env, RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let output = "";
  child.stdout?.on("data", (chunk) => { stdout += String(chunk); output += String(chunk); });
  child.stderr?.on("data", (chunk) => { output += String(chunk); });
  let outcome: RunOutcome | undefined;
  const completion = new Promise<RunOutcome>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status, signal) => {
      outcome = Object.freeze({ status, signal, stdout, output });
      resolve(outcome);
    });
  });
  return Object.freeze({ child, completion, ended: () => outcome });
}

async function finishRun(run: StartedRun, timeoutMs: number, label: string): Promise<RunOutcome> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      run.child.kill("SIGKILL");
      reject(new Error(`${label}: the run did not end within ${timeoutMs} ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([run.completion, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Ends a run a failed case left behind, so the next case starts clean. */
async function abandonRun(run: StartedRun | undefined, fixture: LiveFixture, tag: string): Promise<void> {
  if (!run || run.ended()) return;
  releaseStub(fixture, tag);
  try {
    await finishRun(run, RUN_FINISH_TIMEOUT_MS, `abandoned ${tag} run`);
  } catch {
    // finishRun has already SIGKILLed it; forceCleanSessions reports residue.
  }
}

async function waitFor<T>(probe: () => T | undefined, timeoutMs: number, label: string, run?: StartedRun): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = probe();
    if (value !== undefined) return value;
    const ended = run?.ended();
    if (ended) throw new Error(`${label}: the run ended first (status ${ended.status}): ${describeOutput(ended.output, 4000)}`);
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

async function waitForStubReady(fixture: LiveFixture, tag: string, run: StartedRun): Promise<string> {
  const ready = path.join(stubDir(fixture, tag), "ready");
  return await waitFor(() => (fs.existsSync(ready) ? fs.readFileSync(ready, "utf8").trim() : undefined),
    RUN_READY_TIMEOUT_MS, `the ${tag} run's agent to start`, run);
}

function runRecordDir(outcome: RunOutcome): string {
  const match = /^run record: (.+)$/mu.exec(outcome.stdout);
  if (!match) throw new Error(`the run printed no record path: ${describeOutput(outcome.output, 4000)}`);
  return match[1].trim();
}

function readRunJson(outcome: RunOutcome): HeadlessRunJson {
  return JSON.parse(fs.readFileSync(path.join(runRecordDir(outcome), "run.json"), "utf8")) as HeadlessRunJson;
}

// ---------------------------------------------------------------------------
// Observation.
// ---------------------------------------------------------------------------

type ProjectPaths = Readonly<{ stateDir: string; inboxDir: string }>;

function projectPaths(fixture: LiveFixture): ProjectPaths {
  const { stateDir, inboxDir } = projectInfo(fixture.projectRoot, fixture.env).paths;
  return { stateDir, inboxDir };
}

function inboxPrompts(paths: ProjectPaths): string[] {
  try {
    return fs.readdirSync(paths.inboxDir).filter((name) => INBOX_PROMPT_PATTERN.test(name));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

function runLockPresent(paths: ProjectPaths): boolean {
  return fs.existsSync(path.join(paths.stateDir, HEADLESS_RUN_LOCK_DIRNAME));
}

/** Every session-agent container of the project, running or not. */
function allSessionAgentContainers(project: string): string[] {
  return dockerOrThrow("session-agent listing", [
    "ps", "-a", "--no-trunc",
    "--filter", `label=${SESSION_CONTAINER_LABELS.composeProject}=${project}`,
    "--filter", `label=${SESSION_CONTAINER_LABELS.role}=session-agent`,
    "--format", "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
}

/**
 * Session-agent `create` events for the project in a closed window. Asked of
 * the daemon rather than inferred from the absence of a container: a
 * container created and removed inside the window still shows here.
 */
function sessionContainerCreates(project: string, sinceSeconds: number, untilSeconds: number): string[] {
  return dockerOrThrow("session-agent create events", [
    "events",
    "--since", String(sinceSeconds),
    "--until", String(untilSeconds),
    "--filter", "type=container",
    "--filter", "event=create",
    "--filter", `label=${SESSION_CONTAINER_LABELS.composeProject}=${project}`,
    "--filter", `label=${SESSION_CONTAINER_LABELS.role}=session-agent`,
    "--format", "{{.Actor.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function containerExists(id: string): boolean {
  const inspected = docker(["container", "inspect", "--format", "{{.Id}}", id]);
  if (inspected.status === 0) return true;
  if (/no such (container|object)/iu.test(inspected.output)) return false;
  throw new Error(`could not tell whether container ${id} exists: ${describeOutput(inspected.output)}`);
}

type ContainerInspect = Readonly<{
  Id: string;
  Name: string;
  Config: Readonly<{
    Tty: boolean;
    OpenStdin: boolean;
    Cmd: readonly string[] | null;
    Labels: Readonly<Record<string, string>> | null;
    [key: string]: unknown;
  }>;
  HostConfig: Readonly<Record<string, unknown>>;
  Mounts: readonly Readonly<{ Destination: string }>[] | null;
  NetworkSettings: Readonly<{ Networks: Readonly<Record<string, Readonly<{ IPAddress: string }>>> }>;
}>;

function inspectContainer(id: string): ContainerInspect {
  const parsed = JSON.parse(dockerOrThrow("container inspect", ["container", "inspect", id])) as ContainerInspect[];
  if (parsed.length !== 1) throw new Error(`container inspect ${id} returned ${parsed.length} entries`);
  return parsed[0];
}

function containerSourceIp(inspect: ContainerInspect): string {
  const addresses = Object.values(inspect.NetworkSettings.Networks).map((network) => network.IPAddress).filter(Boolean);
  if (addresses.length !== 1) throw new Error(`${inspect.Id} has ${addresses.length} network addresses, expected 1`);
  return addresses[0];
}

/**
 * The container's isolation as Docker reports it, with this session's own
 * identity replaced by placeholders: everything but the stdin and TTY
 * shape, which the caller compares on its own, and the argv, which differs
 * by design (headless flags and the entry's `--stdin-file`).
 *
 * Identity is replaced by value rather than by dropping fields, so a mount
 * source, label, or environment entry that differs for any other reason
 * still fails the comparison.
 */
function isolationView(inspect: ContainerInspect): string {
  const labels = inspect.Config.Labels ?? {};
  const identity: Array<[string, string]> = [
    [inspect.Id, "<container-id>"],
    [inspect.Name.replace(/^\//u, ""), "<container-name>"],
    [labels[SESSION_CONTAINER_LABELS.sessionIncarnation] ?? "", "<session-incarnation>"],
    [labels[SESSION_CONTAINER_LABELS.sessionId] ?? "", "<session-id>"],
    [containerSourceIp(inspect), "<source-ip>"],
  ];
  const {
    Tty: _tty,
    OpenStdin: _openStdin,
    // Derived from OpenStdin by the Docker CLI (`create -i` attaches stdin).
    AttachStdin: _attachStdin,
    StdinOnce: _stdinOnce,
    Cmd: _cmd,
    Hostname: _hostname,
    ...config
  } = inspect.Config;
  const view = {
    config: { ...config, Env: [...((config.Env as string[] | undefined) ?? [])].sort() },
    hostConfig: inspect.HostConfig,
    mounts: [...(inspect.Mounts ?? [])].sort((left, right) => left.Destination.localeCompare(right.Destination)),
    networks: Object.keys(inspect.NetworkSettings.Networks).sort(),
  };
  let text = JSON.stringify(view, null, 2);
  for (const [value, placeholder] of identity) {
    if (value !== "") text = text.split(value).join(placeholder);
  }
  return text;
}

function proxyCaDigest(containerId: string): string {
  const digest = dockerOrThrow("proxy CA digest", ["exec", containerId, "sh", "-c",
    `sha256sum ${PROXY_CA_CERT_PATH} | cut -d' ' -f1; if [ -e /etc/proxy-ca/proxy-ca.key ]; then echo private-key-present; else echo no-private-key; fi`]);
  return digest;
}

type SessionFileFacts = Readonly<{ launchMode?: unknown; admissionContractEpoch?: unknown; keys: readonly string[] }>;

/** The proxy-held session file of one container, by its exact id. */
function sessionFileOf(proxyId: string, containerId: string): SessionFileFacts {
  const evidence = readSessionFileEvidence(proxyId);
  for (const file of evidence.files) {
    if (file.content === null) continue;
    const parsed = JSON.parse(file.content) as Record<string, unknown>;
    if (parsed.containerId === containerId) {
      return { launchMode: parsed.launchMode, admissionContractEpoch: parsed.admissionContractEpoch, keys: Object.keys(parsed).sort() };
    }
  }
  throw new Error(`the proxy holds no session file for ${containerId}`);
}

function setWriteAction(fixture: LiveFixture, action: "allow" | "ask"): void {
  const output = runOrThrow(fixture, ["host", "rules", WRITE_HOST, "--write", action]);
  if (!output.includes("effective policy: live now (effective policy generation sha256:")) {
    throw new Error(`host rules ${WRITE_HOST} --write ${action} did not converge live: ${describeOutput(output)}`);
  }
}

/** `runfree approvals --watch` attached, non-TTY: it prints one `held` line per pending write. */
type Watcher = Readonly<{ output: () => string; stop: () => Promise<void> }>;

async function startApprovalsWatcher(fixture: LiveFixture): Promise<Watcher> {
  const child = childProcess.spawn(
    process.execPath,
    [...cliEntryArgv(), "--workspace", fixture.projectRoot, "approvals", "--watch", "--no-bell"],
    {
      cwd: REPO_ROOT,
      env: { ...fixture.env, RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  let closed = false;
  child.stdout?.on("data", (chunk) => { output += String(chunk); });
  child.stderr?.on("data", (chunk) => { output += String(chunk); });
  const completion = new Promise<void>((resolve) => child.once("close", () => { closed = true; resolve(); }));
  await waitFor(() => {
    if (closed) throw new Error(`the approvals watcher exited: ${describeOutput(output)}`);
    return output.includes("approver heartbeat registered") ? true : undefined;
  }, 60_000, "the approvals watcher to attach");
  return {
    output: () => output,
    stop: async () => {
      if (closed) return;
      child.kill("SIGINT");
      const timer = setTimeout(() => child.kill("SIGKILL"), 15_000);
      await completion;
      clearTimeout(timer);
    },
  };
}

function heldLines(watcherOutput: string): string[] {
  return watcherOutput.split("\n").filter((line) => /^\d{2}:\d{2}:\d{2} held /u.test(line));
}

// ---------------------------------------------------------------------------
// The tranche.
// ---------------------------------------------------------------------------

describe("headless runs (runfree run) on the real backend", () => {
  let fixture: LiveFixture;
  let project: string;
  let proxyId: string;
  let paths: ProjectPaths;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, isolateHostHome: true, configure: configureHeadlessProject });
    project = composeProjectName(fixture);
    proxyId = composeServiceContainerId(project, "proxy");
    paths = projectPaths(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  coreTest("a run without a TTY returns the agent's code and keeps its record, in a container that differs from an interactive one only in Tty and OpenStdin", async () => {
    const tag = "parity";
    let standing: StandingSessionHandle | undefined;
    let run: StartedRun | undefined;
    try {
      standing = await startStandingSession(fixture);
      const interactiveId = standing.session.containerId;
      const promptFile = writePrompt(fixture, { tag, hold: true });
      run = startRun(fixture, promptFile);
      await waitForStubReady(fixture, tag, run);

      const runIds = sessionAgentContainerIds(project).filter((id) => id !== interactiveId);
      expect(runIds, "expected exactly one run container beside the interactive session").toHaveLength(1);
      const runId = runIds[0];
      const interactive = inspectContainer(interactiveId);
      const headless = inspectContainer(runId);

      // The only intended difference: no TTY and no open stdin.
      expect({ tty: interactive.Config.Tty, openStdin: interactive.Config.OpenStdin }, "interactive stdin/TTY shape")
        .toEqual({ tty: true, openStdin: true });
      expect({ tty: headless.Config.Tty, openStdin: headless.Config.OpenStdin }, "headless stdin/TTY shape")
        .toEqual({ tty: false, openStdin: false });
      // Mounts, capabilities, security options, user, image, entry, labels,
      // environment, and networks are equal once identity is replaced.
      expect(isolationView(headless), "the run container's isolation differs from the interactive container's")
        .toBe(isolationView(interactive));
      // The argv differs by design only: the entry's prompt file, then the
      // same agent path.
      const headlessCmd = headless.Config.Cmd ?? [];
      const interactiveCmd = interactive.Config.Cmd ?? [];
      expect(headlessCmd[0], "the run's entry argv starts with --stdin-file").toBe("--stdin-file");
      expect(headlessCmd[1] ?? "", "the run's prompt path is one inbox run file").toMatch(PROMPT_PATH_PATTERN);
      expect(headlessCmd[2], "the run launches the same agent path").toBe(interactiveCmd[0]);

      // CA material: the same public proxy CA, and no private key, in both.
      expect(proxyCaDigest(runId), "the run container's proxy CA material").toBe(proxyCaDigest(interactiveId));
      expect(proxyCaDigest(runId), "the run container sees the proxy CA private key").toMatch(/no-private-key$/u);

      // Firewall: both sessions are served by their own files and admitted in
      // the kernel's session set, exactly as two interactive sessions are.
      assertFilesPathExercised(fixture, proxyId, [containerSourceIp(interactive), containerSourceIp(headless)], "interactive beside headless");
      // The mark the proxy enforces on, at the current admission contract
      // epoch; otherwise the two session files carry the same keys.
      const interactiveFile = sessionFileOf(proxyId, interactiveId);
      const headlessFile = sessionFileOf(proxyId, runId);
      expect(interactiveFile.launchMode, "interactive session file launchMode").toBe("interactive");
      expect(headlessFile.launchMode, "headless session file launchMode").toBe("headless");
      expect(headlessFile.admissionContractEpoch, "headless session file epoch").toBe(RUNTIME_ADMISSION_CONTRACT_EPOCH);
      expect(readPublishedSessionEligibility(proxyId).admissionContractEpoch, "published eligibility epoch")
        .toBe(RUNTIME_ADMISSION_CONTRACT_EPOCH);
      expect(headlessFile.keys.filter((key) => key !== "hostTty" && key !== "hostTermProgram"), "session file keys")
        .toEqual(interactiveFile.keys.filter((key) => key !== "hostTty" && key !== "hostTermProgram"));
      expect(headlessFile.keys, "a headless session records no host terminal").not.toContain("hostTty");

      // The prompt is in the inbox while the run is live.
      expect(inboxPrompts(paths), "the run's prompt file is in the inbox while it runs")
        .toEqual([path.basename(headlessCmd[1] ?? "")]);

      releaseStub(fixture, tag);
      const outcome = await finishRun(run, RUN_FINISH_TIMEOUT_MS, "parity run");
      expect(outcome.status, `the parity run did not exit 0: ${describeOutput(outcome.output, 4000)}`).toBe(0);
      expect(outcome.stdout, "the run printed the agent's final message").toContain(`live headless stub finished ${tag}`);

      // What the agent saw: no terminal, the exact prompt on stdin, and
      // Runfree's headless argv with no prompt text in it (D-3).
      expect(JSON.parse(readStubFile(fixture, tag, "terminal.json")), "the agent saw a terminal")
        .toEqual({ stdinTty: false, stdoutTty: false, stderrTty: false });
      expect(readStubFile(fixture, tag, "stdin"), "the agent's stdin is not the prompt file")
        .toBe(fs.readFileSync(promptFile, "utf8"));
      const argv = JSON.parse(readStubFile(fixture, tag, "argv.json")) as string[];
      for (const flag of ["-p", "--output-format", "stream-json", "--verbose", "--session-id"]) {
        expect(argv, `the headless argv lacks ${flag}`).toContain(flag);
      }
      expect(argv.join(" "), "the prompt reached the agent's argv").not.toContain(`"tag":"${tag}"`);

      // The host record: success, the agent's status, a confirmed teardown,
      // the exact container, no denials, and drained streams.
      const record = runRecordDir(outcome);
      const recorded = readRunJson(outcome);
      expect(path.relative(fixture.projectRoot, record).startsWith(".."), "the run record is inside the project").toBe(true);
      expect(recorded, "run.json").toMatchObject({
        outcome: "success",
        exitCode: 0,
        agentStatus: 0,
        teardown: "confirmed",
        containerId: runId,
        sessionId: headless.Config.Labels?.[SESSION_CONTAINER_LABELS.sessionId],
        headlessDenials: 0,
        streamsDrained: true,
      });
      expect(fs.readFileSync(path.join(record, "result.md"), "utf8"), "result.md").toContain(`live headless stub finished ${tag}`);
      expect(fs.readFileSync(path.join(record, "transcript.jsonl"), "utf8"), "transcript.jsonl").toContain('"type":"result"');
      expect(containerExists(runId), "the run's container outlived the run").toBe(false);
      expect(inboxPrompts(paths), "the run's prompt file outlived the run").toEqual([]);
      expect(runLockPresent(paths), "the run lock outlived a confirmed run").toBe(false);

      // The agent's own failure code is the run's exit code.
      const failTag = "agent-code";
      const failed = await finishRun(startRun(fixture, writePrompt(fixture, { tag: failTag, exitCode: 7 })), RUN_FINISH_TIMEOUT_MS + RUN_READY_TIMEOUT_MS, "agent-code run");
      expect(failed.status, `the run did not return the agent's code: ${describeOutput(failed.output, 4000)}`).toBe(7);
      expect(readRunJson(failed), "agent-code run.json").toMatchObject({ outcome: "failed", exitCode: 7, agentStatus: 7, teardown: "confirmed" });
    } finally {
      await abandonRun(run, fixture, tag);
      if (standing) await standing.stop();
      await forceCleanSessions(fixture);
    }
  }, TEST_TIMEOUT_MS);

  coreTest("with a watcher attached and an interactive session live, the run's ask write is denied at once and counted while the interactive write is held", async () => {
    const tag = "watcher";
    let standing: StandingSessionHandle | undefined;
    let watcher: Watcher | undefined;
    let run: StartedRun | undefined;
    const context = {
      projectRoot: fixture.projectRoot,
      project: projectInfo(fixture.projectRoot, fixture.env),
      runtimeRoot: path.join(REPO_ROOT, "dist", "runtime"),
      env: fixture.env,
    };
    const pendingFor = (requestPath: string) => readPendingApprovals(context, nodeRuntimeIO, proxyId)
      .filter((record) => record.host === WRITE_HOST && record.method === "POST" && record.path === requestPath);
    try {
      setWriteAction(fixture, "ask");
      standing = await startStandingSession(fixture);
      const interactiveId = standing.session.containerId;
      watcher = await startApprovalsWatcher(fixture);

      // The interactive write: held for the attached approver.
      dockerOrThrow("start the interactive held write", ["exec", "-d", interactiveId, "sh", "-c",
        `curl -sS --max-time 300 -X POST --data-raw '{}' -o /dev/null -w '%{http_code}' https://${WRITE_HOST}/interactive > /tmp/headless-live-interactive.code 2>&1`]);
      const activeWatcher = watcher;
      await waitFor(() => (heldLines(activeWatcher.output()).length > 0 && pendingFor("/interactive").length === 1 ? true : undefined),
        60_000, "the interactive write to be held and shown to the watcher");

      // The run's write: denied at once, never held, and counted.
      run = startRun(fixture, writePrompt(fixture, { tag, post: `https://${WRITE_HOST}/headless` }), ["--accept-denied-writes"]);
      const outcome = await finishRun(run, RUN_READY_TIMEOUT_MS + RUN_FINISH_TIMEOUT_MS, "watcher run");
      expect(outcome.status, `--accept-denied-writes keeps a denied run at 0: ${describeOutput(outcome.output, 4000)}`).toBe(0);
      const post = readStubPost(fixture, tag);
      expect(post.code, `the run's write was not refused: ${post.stderr}`).toBe("403");
      expect(post.blocked, "the run's write was not refused as headless-denied").toBe("write-approval-headless-denied");
      expect(post.elapsedMs, "the run's write waited instead of being denied at once").toBeLessThan(HEADLESS_DENIAL_BOUND_MS);
      const recorded = readRunJson(outcome);
      expect(recorded, "watcher run.json").toMatchObject({ outcome: "success", exitCode: 0, headlessDenials: 1, acceptDeniedWrites: true });
      expect(outcome.stdout, "the summary does not warn about the denial").toContain("1 write was denied (headless)");
      expect(pendingFor("/headless"), "the run's write created a pending approval").toEqual([]);
      const logs = dockerOrThrow("proxy logs", ["logs", "--since", recorded.startedAt, proxyId]);
      expect(logs.split("\n").some((line) => line.startsWith(APPROVAL_HEADLESS_DENIED_EVENT_PREFIX)
        && line.includes(`"sessionId":"${recorded.sessionId}"`)), "the proxy logged no headless-denied event for the run session").toBe(true);

      // The interactive write is still held, and the watcher saw only it.
      expect(pendingFor("/interactive"), "the interactive write stopped being held").toHaveLength(1);
      expect(docker(["exec", interactiveId, "test", "-s", "/tmp/headless-live-interactive.code"]).status,
        "the interactive write was answered while it should be held").not.toBe(0);
      expect(heldLines(watcher.output()), "the watcher saw a write other than the interactive one").toHaveLength(1);

      const held = pendingFor("/interactive")[0];
      const decided = fixture.runfree(["approve", held.id, "--deny"]);
      expect(decided.output, "approve --deny did not decide the held write").toContain(`denied ${held.id}`);
    } finally {
      await abandonRun(run, fixture, tag);
      if (watcher) await watcher.stop();
      if (standing) await standing.stop();
      setWriteAction(fixture, "allow");
      await forceCleanSessions(fixture);
    }
  }, TEST_TIMEOUT_MS);

  coreTest("a rule changed to ask during a run gives headless-denied and exit 68", async () => {
    const tag = "rule-change";
    let run: StartedRun | undefined;
    try {
      run = startRun(fixture, writePrompt(fixture, { tag, hold: true, post: `https://${WRITE_HOST}/rule-change` }));
      await waitForStubReady(fixture, tag, run);
      // The preflight passed under `allow`; the proxy is the enforcement.
      setWriteAction(fixture, "ask");
      releaseStub(fixture, tag);
      const outcome = await finishRun(run, RUN_FINISH_TIMEOUT_MS, "rule-change run");
      expect(outcome.status, `a denied write without --accept-denied-writes did not exit 68: ${describeOutput(outcome.output, 4000)}`).toBe(68);
      const post = readStubPost(fixture, tag);
      expect(post.code, `the write after the rule change was not refused: ${post.stderr}`).toBe("403");
      expect(post.blocked, "the write after the rule change was not refused as headless-denied").toBe("write-approval-headless-denied");
      expect(readRunJson(outcome), "rule-change run.json").toMatchObject({
        outcome: "success",
        exitCode: 68,
        agentStatus: 0,
        headlessDenials: 1,
        acceptDeniedWrites: false,
        teardown: "confirmed",
      });
    } finally {
      await abandonRun(run, fixture, tag);
      setWriteAction(fixture, "allow");
      await forceCleanSessions(fixture);
    }
  }, TEST_TIMEOUT_MS);

  coreTest("an ask rule at launch warns, runs, records the exposure, and exits 68", async () => {
    const tag = "ask-at-launch";
    let run: StartedRun | undefined;
    try {
      setWriteAction(fixture, "ask");
      run = startRun(fixture, writePrompt(fixture, { tag, post: `https://${WRITE_HOST}/ask-at-launch` }));
      const outcome = await finishRun(run, RUN_READY_TIMEOUT_MS + RUN_FINISH_TIMEOUT_MS, "ask-at-launch run");
      expect(outcome.status, `an ask rule at launch did not exit 68: ${describeOutput(outcome.output, 4000)}`).toBe(68);
      const warnings = outcome.output.split("\n").filter((line) => line.includes("headless run: writes that would ask for approval are denied"));
      expect(warnings, `the posture warning is not printed once: ${describeOutput(outcome.output, 4000)}`).toHaveLength(1);
      expect(outcome.output, "the run was refused").not.toContain("refusing a headless run");
      const post = readStubPost(fixture, tag);
      expect(post.code, `the write was not refused: ${post.stderr}`).toBe("403");
      expect(post.blocked, "the write was not refused as headless-denied").toBe("write-approval-headless-denied");
      const recorded = readRunJson(outcome);
      expect(recorded, "ask-at-launch run.json").toMatchObject({
        outcome: "success",
        exitCode: 68,
        headlessDenials: 1,
        acceptDeniedWrites: false,
        teardown: "confirmed",
      });
      expect(recorded.askExposure?.ruleAskHosts, "run.json askExposure").toContain(WRITE_HOST);
    } finally {
      await abandonRun(run, fixture, tag);
      setWriteAction(fixture, "allow");
      await forceCleanSessions(fixture);
    }
  }, TEST_TIMEOUT_MS);

  coreTest("a pending approval is refused with 65 before any session container is created", async () => {
    const tag = "pending-approval";
    // An unapproved change to the staged project image: the exact build
    // approval an interactive launch would ask for. Restoring the exact bytes
    // is the reclaim (the approval is of the content digest).
    const dockerfile = path.join(fixture.projectRoot, ".runfree", "image", "Dockerfile");
    const approved = fs.readFileSync(dockerfile);
    const since = nowSeconds() - 2;
    try {
      fs.appendFileSync(dockerfile, "\n# headless live tranche: an unapproved change\n");
      const outcome = await finishRun(startRun(fixture, writePrompt(fixture, { tag })), RUN_REFUSAL_TIMEOUT_MS, "pending-approval run");
      expect(outcome.status, `a pending approval did not refuse with 65: ${describeOutput(outcome.output, 4000)}`).toBe(65);
      expect(outcome.output, "the refusal does not name the approval").toMatch(/approv/iu);
      expect(sessionContainerCreates(project, since, nowSeconds()), "a session container was created before the refusal").toEqual([]);
      expect(fs.existsSync(stubDir(fixture, tag)), "the agent ran despite the refusal").toBe(false);
      const recorded = readRunJson(outcome);
      expect(recorded, "pending-approval run.json").toMatchObject({ outcome: "refused", exitCode: 65, agentStatus: null });
      expect(recorded.containerId, "a refused run names a container").toBeUndefined();
      expect(inboxPrompts(paths), "a refused run left its prompt in the inbox").toEqual([]);
      expect(runLockPresent(paths), "a refused run kept the run lock").toBe(false);
    } finally {
      fs.writeFileSync(dockerfile, approved);
    }
    await forceCleanSessions(fixture);
  }, TEST_TIMEOUT_MS);

  // An older proxy (admission contract epoch 4) is not something any live
  // fixture can stand up: the runtime builds its proxy image from this
  // checkout only, and no tranche pins or builds a previous release's proxy.
  // Building one would mean a second runtime asset build from an older ref,
  // which is new mechanism. The refusal itself is the strict-key parser
  // (`parseSessionFileV1` refuses an unknown key, unit-proven with the epoch
  // bump in plan Task 2); the parity case above proves live that the files
  // the current proxy serves carry `launchMode` at the current epoch.
  test.todo("a proxy at admission contract epoch 4 refuses a session file that carries launchMode (no fixture runs an older proxy image)");

  extendedTest("after a timeout with an unconfirmed teardown the next run gets 66 until the container is gone; a normal timeout leaves nothing behind", async () => {
    // A Docker shim first on PATH for one run only: once its marker exists it
    // refuses every stop, kill, and remove, so the run's stop routine cannot
    // confirm the teardown. Everything else reaches the real Docker CLI.
    const shimDir = path.join(fixture.ownerRoot, "docker-shim");
    const refuseMarker = path.join(shimDir, "refuse-teardown");
    const realDocker = childProcess.execFileSync("sh", ["-c", "command -v docker"], { encoding: "utf8" }).trim();
    expect(realDocker, "no docker on PATH").not.toBe("");
    fs.mkdirSync(shimDir, { recursive: true, mode: 0o700 });
    const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    fs.writeFileSync(path.join(shimDir, "docker"), [
      "#!/bin/sh",
      "# Live-fixture Docker shim. Not a production artifact.",
      `if [ -e ${quote(refuseMarker)} ]; then`,
      '  sub="$1"; [ "$1" = "container" ] && sub="$2"',
      '  case "$sub" in stop|kill|rm) echo "live shim: teardown refused" >&2; exit 1 ;; esac',
      "fi",
      `exec ${quote(realDocker)} "$@"`,
      "",
    ].join("\n"), { mode: 0o755 });
    const shimEnv = { PATH: `${shimDir}${path.delimiter}${fixture.env.PATH ?? process.env.PATH ?? ""}` };

    const stuckTag = "unconfirmed";
    let stuck: StartedRun | undefined;
    let stuckContainer: string | undefined;
    let normal: StartedRun | undefined;
    try {
      // 1. A run whose container ignores signals and whose stop is refused.
      stuck = startRun(fixture, writePrompt(fixture, { tag: stuckTag, hold: true, ignoreSignals: true }), ["--timeout", "240s"], shimEnv);
      await waitForStubReady(fixture, stuckTag, stuck);
      fs.writeFileSync(refuseMarker, "");
      const stuckOutcome = await finishRun(stuck, 240_000 + RUN_FINISH_TIMEOUT_MS, "unconfirmed-teardown run");
      expect(stuckOutcome.status, `a timed-out run did not exit 67: ${describeOutput(stuckOutcome.output, 4000)}`).toBe(67);
      const stuckRecord = readRunJson(stuckOutcome);
      expect(stuckRecord, "unconfirmed run.json").toMatchObject({ outcome: "timeout", exitCode: 67, teardown: "unconfirmed" });
      stuckContainer = stuckRecord.containerId;
      expect(stuckContainer, "the unconfirmed run names no container").toMatch(/^[a-f0-9]{64}$/u);
      expect(containerExists(stuckContainer as string), "the shim did not keep the container").toBe(true);
      expect(runLockPresent(paths), "an unconfirmed teardown released the run lock").toBe(true);
      expect(stuckOutcome.stdout, "the summary does not warn about the kept lock").toContain("the run lock is kept until it is gone");

      // 2. The next run is skipped (66) and touches no Docker create while
      //    the container exists; asked twice, so it is not a one-off.
      for (const attempt of [1, 2]) {
        const since = nowSeconds() - 2;
        const skipped = await finishRun(startRun(fixture, writePrompt(fixture, { tag: `skipped-${attempt}` })), RUN_REFUSAL_TIMEOUT_MS, `skipped run ${attempt}`);
        expect(skipped.status, `a run beside a kept lock did not exit 66: ${describeOutput(skipped.output, 4000)}`).toBe(66);
        expect(readRunJson(skipped), `skipped run ${attempt} run.json`).toMatchObject({ outcome: "skipped", exitCode: 66, teardown: "not-started" });
        expect(sessionContainerCreates(project, since, nowSeconds()), "a skipped run created a session container").toEqual([]);
        expect(containerExists(stuckContainer as string), "the kept container vanished").toBe(true);
      }

      // 3. The reclaim: the container is gone, so the next run takes the lock.
      fs.rmSync(refuseMarker, { force: true });
      dockerOrThrow("remove the unconfirmed run's container", ["rm", "-f", stuckContainer as string]);
      expect(containerExists(stuckContainer as string), "the unconfirmed run's container is still present").toBe(false);
      stuckContainer = undefined;

      // 4. A normal timeout: confirmed teardown, and nothing left behind.
      const normalTag = "normal-timeout";
      normal = startRun(fixture, writePrompt(fixture, { tag: normalTag, hold: true }), ["--timeout", "90s"]);
      await waitForStubReady(fixture, normalTag, normal);
      expect(inboxPrompts(paths), "the normal run's prompt is not in the inbox while it runs").toHaveLength(1);
      expect(runLockPresent(paths), "the normal run does not hold the run lock").toBe(true);
      const normalOutcome = await finishRun(normal, 90_000 + RUN_FINISH_TIMEOUT_MS, "normal-timeout run");
      expect(normalOutcome.status, `a timed-out run did not exit 67: ${describeOutput(normalOutcome.output, 4000)}`).toBe(67);
      const normalRecord = readRunJson(normalOutcome);
      expect(normalRecord, "normal-timeout run.json").toMatchObject({ outcome: "timeout", exitCode: 67, teardown: "confirmed" });
      expect(readSessionFileEvidence(proxyId).files, "a session file outlived the timed-out run").toEqual([]);
      expect(allSessionAgentContainers(project), "a session container outlived the timed-out run").toEqual([]);
      expect(inboxPrompts(paths), "a prompt file outlived the timed-out run").toEqual([]);
      expect(runLockPresent(paths), "the run lock outlived a confirmed timeout").toBe(false);
    } finally {
      fs.rmSync(refuseMarker, { force: true });
      await abandonRun(stuck, fixture, stuckTag);
      await abandonRun(normal, fixture, "normal-timeout");
      if (stuckContainer) docker(["rm", "-f", stuckContainer]);
      await forceCleanSessions(fixture);
    }
  }, TEST_TIMEOUT_MS);
});
