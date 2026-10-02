// Live proof for agent session containers run under Docker's init, and for the
// launch reporting `attached` only after the session entry hands off (the
// 2026-09-30 agent container init design).
//
// What the unit tests cannot show, because it is the kernel's and the daemon's
// behavior rather than the host's:
//
//   - `docker stop` of a live agent ends it at once (exit 143) instead of
//     waiting out the stop timeout for a PID 1 that drops SIGTERM;
//   - Ctrl-C reaches the agent through the init, both as a TTY byte and as a
//     signal the daemon delivers;
//   - the session entry still gives up with exit 111 when it is never served;
//   - the handoff wait: a launch reports `attached` only once the entry has
//     exec'd the agent, and a proxy lost inside that window is recovered after
//     it, with the agent still starting.
//
// The project image slows the readiness probe: once the real probe answers
// `active`, the wrapper sleeps before returning, so the entry execs the agent
// a fixed few seconds after the grant instead of well under a second. That
// makes "attached before the handoff" observable rather than a race the test
// would usually lose, and it stays inside the launch's 10 s handoff ceiling.
//
// Process state is read from the daemon (`docker container top`, `inspect`),
// never by exec into the untrusted container, except where a case needs a
// terminal of its own.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import { parseSessionContainerTopHandoff } from "../../../packages/cli/src/runtime/session-container-docker.ts";
import { SESSION_ENTRY_PATH } from "../../../packages/cli/src/runtime/session-launch.ts";
import { stageLongLivedAgentBinary } from "./agent-stub.ts";
import {
  FAST_HEARTBEAT_ENV,
  PROVISION_TIMEOUT_MS,
  REPO_ROOT,
  TEST_TIMEOUT_MS,
  awaitAgentStarted,
  containerExitState,
  parseLaunchReport,
  pollUntil,
  requiredBackend,
  servedSourceIps,
  startAttachedLaunch,
  startHeldLaunch,
  startRunfree,
  type LaunchRun,
} from "./attached-support.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  forceCleanSessions,
  provisionLiveFixture,
  type LiveFixture,
} from "./fixture.ts";

/**
 * How long the staged probe holds a successful answer before returning it —
 * the minimum gap between the grant and the entry's exec. Below the launch's
 * 10 s handoff ceiling with room for a slow daemon.
 */
const SLOW_PROBE_HOLD_S = 6;
/** "Well under" Docker's 10 s stop timeout: an init that forwards SIGTERM. */
const FAST_STOP_BOUND_MS = 5_000;
/** The entry's own bound (60 s) plus a margin for a slow daemon. */
const ENTRY_GIVE_UP_WAIT_MS = 90_000;
const SIGTERM_EXIT = 143;
const SIGINT_EXIT = 130;
const ENTRY_TIMEOUT_EXIT = 111;

/**
 * Wraps the base image's readiness probe so a successful poll is held before
 * it is returned.
 *
 * The entry resolves the probe next to itself, so replacing the file in place
 * keeps the stock entry, which is the one under test. A failed poll returns at
 * once, so the entry's own give-up bound is unchanged.
 */
function stageSlowReadinessProbe(fixture: LiveFixture): void {
  const imageDir = path.join(fixture.projectRoot, ".runfree", "image");
  fs.writeFileSync(
    path.join(imageDir, "slow-session-ready-probe.sh"),
    [
      "#!/bin/sh",
      "# Live-fixture probe wrapper. Not a production artifact.",
      '/usr/local/libexec/runfree/session-ready-probe-real "$@"',
      "status=$?",
      `if [ "$status" -eq 0 ]; then sleep ${SLOW_PROBE_HOLD_S}; fi`,
      'exit "$status"',
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  fs.appendFileSync(path.join(imageDir, "Dockerfile"), [
    "",
    "USER root",
    "RUN mv /usr/local/libexec/runfree/session-ready-probe /usr/local/libexec/runfree/session-ready-probe-real",
    "COPY slow-session-ready-probe.sh /usr/local/libexec/runfree/session-ready-probe",
    "RUN chmod 0755 /usr/local/libexec/runfree/session-ready-probe",
    "USER agent",
    "",
  ].join("\n"));
}

function configureInitProject(fixture: LiveFixture): void {
  stageLongLivedAgentBinary(fixture);
  stageSlowReadinessProbe(fixture);
}

/**
 * The in-container pid of the one child of PID 1 (Docker's init): the entry,
 * then the agent. A `docker exec` process has parent 0 in the container's
 * namespace, so it is never counted.
 */
function initChildArgv(containerId: string): readonly string[] {
  const listed = docker([
    "exec", "--user", "1000:1000", containerId, "sh", "-c",
    'for d in /proc/[0-9]*; do [ "$(awk \'/^PPid:/ { print $2 }\' "$d/status" 2>/dev/null)" = 1 ] && echo "${d#/proc/}"; done; true',
  ]);
  const pids = listed.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  if (listed.status !== 0 || pids.length !== 1) {
    throw new Error(`expected exactly one child of the session init: ${describeOutput(listed.output)}`);
  }
  const cmdline = dockerOrThrow("read the init child's argv", [
    "exec", "--user", "1000:1000", containerId, "cat", `/proc/${pids[0]}/cmdline`,
  ]);
  return cmdline.split("\0").filter(Boolean);
}

/** The daemon's handoff answer for one session container, the product's own read. */
function handoffOf(containerId: string): string {
  const [pid, init] = dockerOrThrow("inspect the session anchor", [
    "inspect", "-f", "{{.State.Pid}} {{json .HostConfig.Init}}", containerId,
  ]).trim().split(/\s+/u);
  const top = dockerOrThrow("list the session processes", ["container", "top", containerId, "-o", "pid,ppid,args"]);
  return parseSessionContainerTopHandoff(top, { anchorPid: Number(pid), init: init === "true" });
}

function attachedContainerId(run: LaunchRun): string {
  const record = run.attached.records.find((candidate) => candidate.state === "attached");
  if (!record?.containerId) throw new Error(`no attached record names a container: ${JSON.stringify(run.attached)}`);
  return record.containerId;
}

/** Waits for a stopped session's launch to finish its own teardown. */
async function launchEnded(run: Readonly<{ completion: LaunchRun["completion"] }>): Promise<Readonly<{ status: number | null; output: string }>> {
  return await run.completion;
}

/**
 * Sends Ctrl-C as a terminal byte: `docker attach` under a pseudo-terminal of
 * its own (`script`), so the byte reaches the container's TTY and its line
 * discipline turns it into SIGINT for the foreground process group — the agent,
 * which Docker's init made that group.
 */
async function sendTerminalInterrupt(containerId: string): Promise<void> {
  const argv = process.platform === "darwin"
    ? ["-q", "/dev/null", "docker", "attach", containerId]
    : ["-q", "-f", "-c", `docker attach ${containerId}`, "/dev/null"];
  // A byte typed before `docker attach` has connected and put its terminal in
  // raw mode is the attach client's own Ctrl-C and never reaches the session,
  // so a slow daemon gets fresh attaches until the agent stops, within a bound.
  for (let attempt = 1; attempt <= 4 && containerExitState(containerId).running; attempt += 1) {
    const child = childProcess.spawn("script", argv, { stdio: ["pipe", "ignore", "ignore"] });
    await new Promise((resolve) => setTimeout(resolve, 1_500 * attempt));
    child.stdin?.write("\u0003");
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    child.kill("SIGKILL");
  }
}

describe("agent session containers run under Docker's init", () => {
  requiredBackend();
  let fixture: LiveFixture;
  let project: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: configureInitProject });
    project = composeProjectName(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  afterEach(async () => {
    if (!fixture) return;
    await forceCleanSessions(fixture);
  });

  test("the launch reports attached only after the entry has handed off to the agent", async () => {
    const run = await startAttachedLaunch(fixture);
    const containerId = attachedContainerId(run);
    try {
      // With every probe delayed, a report taken at the grant would find the
      // entry still polling; the handoff-gated report finds the agent.
      const warnings = run.output().split("\n").filter((line) => line.includes("warning")).join("\n");
      expect(handoffOf(containerId), `the entry had not handed off when the launch reported attached; launch warnings: ${describeOutput(warnings, 3000)}`)
        .toBe("handed-off");
      // The same fact read independently of the product's parser: the init's
      // child is no longer the entry.
      expect(initChildArgv(containerId).slice(0, 2), "the init's child still runs the entry")
        .not.toContain(SESSION_ENTRY_PATH);
      expect(run.output(), "the handoff was observed, not assumed at the ceiling").not.toContain("did not hand off");
      expect(dockerOrThrow("inspect Init", ["inspect", "-f", "{{json .HostConfig.Init}}", containerId]).trim())
        .toBe("true");
    } finally {
      docker(["kill", containerId]);
      await launchEnded(run);
    }
  }, TEST_TIMEOUT_MS);

  test("docker stop ends a live agent well inside the stop timeout, with exit 143", async () => {
    const run = await startAttachedLaunch(fixture);
    const containerId = attachedContainerId(run);
    await awaitAgentStarted(containerId, "stop latency");

    const started = Date.now();
    const stopped = docker(["stop", "--time", "10", containerId]);
    const elapsedMs = Date.now() - started;

    expect(stopped.status, `docker stop failed: ${describeOutput(stopped.output)}`).toBe(0);
    expect(elapsedMs, "a live agent under the init should stop without the SIGKILL wait").toBeLessThan(FAST_STOP_BOUND_MS);
    expect(containerExitState(containerId).exitCode, "the init reports the agent's SIGTERM").toBe(SIGTERM_EXIT);
    const ended = await launchEnded(run);
    expect(parseLaunchReport(ended).outcome?.status ?? null, "the launch reports the container's exit").toBe(SIGTERM_EXIT);
  }, TEST_TIMEOUT_MS);

  test("Ctrl-C delivered by the daemon (no terminal) stops the agent", async () => {
    const run = await startAttachedLaunch(fixture);
    const containerId = attachedContainerId(run);
    await awaitAgentStarted(containerId, "signal Ctrl-C");

    // The daemon signals PID 1 — what `docker start --attach` does for a
    // non-TTY session and what `docker kill -s INT` does here. A PID 1 agent
    // without a handler used to drop it; the init forwards it.
    dockerOrThrow("send SIGINT through the daemon", ["kill", "--signal", "SIGINT", containerId]);
    await pollUntil(() => !containerExitState(containerId).running, 10_000, "the agent to stop on SIGINT");
    expect(containerExitState(containerId).exitCode).toBe(SIGINT_EXIT);
    await launchEnded(run);
  }, TEST_TIMEOUT_MS);

  // macOS's BSD `script` refuses a non-terminal stdin ("tcgetattr/ioctl:
  // Operation not supported on socket"), and Node's pipes are sockets there, so
  // no byte is ever typed. Typing one on macOS needs a pseudo-terminal
  // dependency, which is still undecided; the daemon-delivered SIGINT case
  // above proves the init's forwarding on every host.
  test.skipIf(process.platform === "darwin")("Ctrl-C typed at the session's terminal stops the agent", async () => {
    const run = await startAttachedLaunch(fixture);
    const containerId = attachedContainerId(run);
    await awaitAgentStarted(containerId, "terminal Ctrl-C");

    const tty = dockerOrThrow("inspect the session TTY", ["inspect", "-f", "{{.Config.Tty}} {{.Config.OpenStdin}}", containerId]).trim();
    await sendTerminalInterrupt(containerId);

    await pollUntil(() => !containerExitState(containerId).running, 10_000, `the agent to stop on a typed Ctrl-C (Tty OpenStdin: ${tty})`);
    expect(containerExitState(containerId).exitCode).toBe(SIGINT_EXIT);
    await launchEnded(run);
  }, TEST_TIMEOUT_MS);

  test("the session entry still gives up with exit 111 when the session is never served", async () => {
    // Held before the session file is written: the entry polls a proxy that
    // never serves it and gives up at its own bound.
    const held = await startHeldLaunch(fixture, "before-session-file-write");
    const record = held.held.records[0];
    if (!record?.containerId) throw new Error(`the held launch names no container: ${JSON.stringify(held.held)}`);
    try {
      await pollUntil(
        () => !containerExitState(record.containerId as string).running,
        ENTRY_GIVE_UP_WAIT_MS,
        "the entry to give up",
      );
      expect(containerExitState(record.containerId).exitCode).toBe(ENTRY_TIMEOUT_EXIT);
    } finally {
      held.release();
    }
    // The hold parks the host inside the running proof's own inspect, so the
    // resumed launch finds that proof older than its bound and refuses it; it
    // can never report the entry's exit as its outcome. What it must do is fail
    // closed: never attached, and nothing left behind.
    const ended = await held.completion;
    const report = parseLaunchReport(ended);
    expect(report.attached, `the never-served launch reported attached: ${describeOutput(ended.output, 3000)}`).toBeNull();
    expect(report.failure, describeOutput(ended.output, 3000)).toBeDefined();
    expect(report.after.records).toEqual([]);
    expect(report.after.residualContainers).toBe(0);
  }, TEST_TIMEOUT_MS);

  test("a lifecycle command started inside the handoff window runs only after the handoff", async () => {
    const proxyId = composeServiceContainerId(project, "proxy");
    const launch = startAttachedLaunch(fixture);
    // The grant: the proxy serves the new session's file. The held probe keeps
    // the entry from exec'ing the agent for several seconds after that.
    await pollUntil(() => servedSourceIps(proxyId).length === 1, 180_000, "the session file to be served");
    const upStarted = Date.now();
    const up = startRunfree(fixture, ["up"]);
    // Sample the handoff from the test's side while `up` waits for the lock.
    // Bounded: an entry that never hands off fails the assertion below rather
    // than spinning until the test timeout.
    let handedOffAt: number | undefined;
    let containerId: string | undefined;
    const samplerDeadline = upStarted + 120_000;
    const sampler = (async () => {
      while (handedOffAt === undefined && Date.now() < samplerDeadline) {
        const ids = dockerOrThrow("list session containers", [
          "ps", "-q", "--no-trunc", "--filter", "label=io.runfree.session-id",
          "--filter", `label=io.runfree.compose-project=${project}`,
        ]).trim().split("\n").filter(Boolean);
        if (ids.length === 1) {
          containerId = ids[0];
          if (handoffOf(ids[0] as string) === "handed-off") handedOffAt = Date.now();
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    })();
    const upDone = await up.completion;
    const upFinishedAt = Date.now();
    await sampler;
    expect(upDone.status, `up failed: ${describeOutput(upDone.output, 4000)}`).toBe(0);
    // Without the handoff wait, `up` takes the lock at once and a warm `up`
    // finishes inside the held window; with it, `up` cannot finish before the
    // entry has handed off.
    expect(handedOffAt, "the entry never handed off").toBeDefined();
    expect(upFinishedAt, "up finished before the entry handed off").toBeGreaterThanOrEqual(handedOffAt as number);
    expect(upFinishedAt - upStarted, "up waited out the held window").toBeGreaterThanOrEqual((SLOW_PROBE_HOLD_S - 1) * 1_000);
    const run = await launch;
    try {
      expect(run.output(), "the handoff was observed, not assumed at the ceiling").not.toContain("did not hand off");
    } finally {
      if (containerId) docker(["kill", containerId]);
      await launchEnded(run);
    }
  }, TEST_TIMEOUT_MS);

  // Availability, not discrimination: once the proxy is gone the entry cannot
  // hand off, so the launch reaches its handoff ceiling (or the entry's held
  // probe was already past the proxy) and releases the lock; the recovery then
  // restores the proxy and the heartbeat refills the file inside the entry's
  // own 60 s bound. The case above is the one that tells the handoff wait
  // apart from the old grant-time release.
  test("a proxy lost between the grant and the handoff is recovered after it, and the agent still starts", async () => {
    const proxyBefore = composeServiceContainerId(project, "proxy");
    const run = startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    // The grant: the proxy serves the new session's file. The slowed probe
    // keeps the entry gated for seconds after that.
    await pollUntil(() => servedSourceIps(proxyBefore).length === 1, 180_000, "the session file to be served");
    dockerOrThrow("stop the proxy inside the handoff window", ["stop", "--time", "2", proxyBefore]);
    // The recovery needs the lifecycle lock the launch holds until its handoff
    // (or its ceiling), so it runs after that window instead of inside it.
    const recovery = await startRunfree(fixture, ["up"]).completion;
    expect(recovery.status, `recovery failed: ${describeOutput(recovery.output, 4000)}`).toBe(0);

    const launched = await run;
    const containerId = attachedContainerId(launched);
    try {
      await awaitAgentStarted(containerId, "the session across the recovery");
      expect(containerExitState(containerId).running, "the session survived the lost proxy").toBe(true);
      expect(launched.output()).not.toContain("giving up");
    } finally {
      docker(["kill", containerId]);
      await launchEnded(launched);
    }
  }, TEST_TIMEOUT_MS);
});
