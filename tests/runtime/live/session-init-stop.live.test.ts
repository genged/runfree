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
// The project image slows the readiness probe (every poll sleeps first), which
// widens the window between the grant and the entry's exec from well under a
// second to seconds. That makes "attached before the handoff" observable,
// rather than a race the test would usually lose.
//
// Process state is read from the daemon (`docker container top`, `inspect`),
// never by exec into the untrusted container, except where a case needs a
// terminal of its own.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";

import { parseSessionContainerTopHandoff } from "../../../packages/cli/src/runtime/session-container-docker.ts";
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

/** How long each readiness poll of the staged image waits before probing. */
const SLOW_PROBE_DELAY_S = 3;
/** "Well under" Docker's 10 s stop timeout: an init that forwards SIGTERM. */
const FAST_STOP_BOUND_MS = 5_000;
/** The entry's own bound (60 s) plus a margin for a slow daemon. */
const ENTRY_GIVE_UP_WAIT_MS = 90_000;
const SIGTERM_EXIT = 143;
const SIGINT_EXIT = 130;
const ENTRY_TIMEOUT_EXIT = 111;

/**
 * Wraps the base image's readiness probe so each poll sleeps first.
 *
 * The entry resolves the probe next to itself, so replacing the file in place
 * keeps the stock entry, which is the one under test.
 */
function stageSlowReadinessProbe(fixture: LiveFixture): void {
  const imageDir = path.join(fixture.projectRoot, ".runfree", "image");
  fs.writeFileSync(
    path.join(imageDir, "slow-session-ready-probe.sh"),
    `#!/bin/sh\n# Live-fixture probe wrapper. Not a production artifact.\nsleep ${SLOW_PROBE_DELAY_S}\nexec /usr/local/libexec/runfree/session-ready-probe-real "$@"\n`,
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

/** The daemon's handoff answer for one session container, the product's own read. */
function handoffOf(containerId: string): string {
  const [pid, init] = dockerOrThrow("inspect the session anchor", [
    "inspect", "-f", "{{.State.Pid}} {{.HostConfig.Init}}", containerId,
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
  const child = childProcess.spawn("script", argv, { stdio: ["pipe", "ignore", "ignore"] });
  await new Promise((resolve) => setTimeout(resolve, 1_500));
  child.stdin?.write("\u0003");
  await new Promise((resolve) => setTimeout(resolve, 1_500));
  child.kill("SIGKILL");
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
      expect(handoffOf(containerId), "the entry had not handed off when the launch reported attached")
        .toBe("handed-off");
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

  test("Ctrl-C typed at the session's terminal stops the agent", async () => {
    const run = await startAttachedLaunch(fixture);
    const containerId = attachedContainerId(run);
    await awaitAgentStarted(containerId, "terminal Ctrl-C");

    await sendTerminalInterrupt(containerId);

    await pollUntil(() => !containerExitState(containerId).running, 10_000, "the agent to stop on a typed Ctrl-C");
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
    const ended = await held.completion;
    expect(parseLaunchReport(ended).outcome?.status ?? null, "the entry's exit is the launch outcome").toBe(ENTRY_TIMEOUT_EXIT);
  }, TEST_TIMEOUT_MS);

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
