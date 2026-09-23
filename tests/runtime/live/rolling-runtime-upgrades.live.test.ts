// Live public-launch proof for rolling session materializations.
//
// This tranche keeps three real direct sessions attached while it changes a
// session-template input and then the project agent image. Docker inspection,
// not host planner output, proves coexistence, proxy stability, image retention,
// cleanup after the final reference, and the absence of a Compose agent.

import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import { startLivePhase } from "./timing.ts";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { stageLongLivedAgentBinary } from "./agent-stub.ts";
import {
  composeProjectName,
  composeServiceContainerId,
  docker,
  dockerOrThrow,
  forceRemoveContainer,
} from "./docker.ts";
import {
  assertFilesPathExercised,
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  readPublishedSessionEligibility,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 20 * 60_000;
const SESSION_WAIT_TIMEOUT_MS = 180_000;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for rolling runtime proof");
  }
  return backend;
}

type RunningSession = Readonly<{
  child: childProcess.ChildProcess;
  completion: Promise<Readonly<{ status: number | null; output: string }>>;
  containerId: string;
  labels: Readonly<Record<string, string>>;
  processIdentity: string;
}>;

function directSessionIds(projectId: string): readonly string[] {
  return dockerOrThrow("direct session listing", [
    "ps", "--no-trunc",
    "--filter", `label=io.runfree.project-id=${projectId}`,
    "--filter", "label=io.runfree.container-role=session-agent",
    "--format", "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean).sort();
}

// A container visible in `docker ps` is only the start of admission: the
// launch still registers with the proxy (a durable admission transaction is
// pending during that convergence), proves the running shape, and activates
// the lifecycle record to `attached`. A concurrent runfree invocation that
// reads component evidence during the transaction window refuses fail-closed,
// so "attached" here must mean the admitted record, not the running container.
function sessionRecordAttached(fixture: LiveFixture, projectId: string, containerId: string): boolean {
  const stateDir = path.join(
    fixture.env.XDG_STATE_HOME as string, "runfree", "projects", projectId,
  );
  const transactionPath = path.join(
    stateDir, "runtime", "v2", "session-admission-transactions", `${projectId}.json`,
  );
  if (fs.existsSync(transactionPath)) return false;
  const registryDir = path.join(stateDir, "runtime", "v2", "session-containers");
  let entries: string[];
  try {
    entries = fs.readdirSync(registryDir);
  } catch {
    return false;
  }
  for (const entry of entries) {
    let record: { containerId?: unknown; state?: unknown };
    try {
      record = JSON.parse(fs.readFileSync(path.join(registryDir, entry), "utf8"));
    } catch {
      continue;
    }
    if (record.containerId === containerId) return record.state === "attached";
  }
  return false;
}

async function startAttachedSession(
  fixture: LiveFixture,
  projectId: string,
  existing: ReadonlySet<string>,
): Promise<RunningSession> {
  const finishPhase = startLivePhase("rolling: public launch through attachment");
  const child = childProcess.spawn(
    process.execPath,
    [...cliEntryArgv(), "--workspace", fixture.projectRoot, "claude"],
    { cwd: REPO_ROOT, env: { ...fixture.env, RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT }, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout?.on("data", (chunk) => { output += String(chunk); });
  child.stderr?.on("data", (chunk) => { output += String(chunk); });
  let exited: Readonly<{ status: number | null; output: string }> | undefined;
  const completion = new Promise<Readonly<{ status: number | null; output: string }>>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (status) => {
      exited = Object.freeze({ status, output });
      resolve(exited);
    });
  });
  const deadline = Date.now() + SESSION_WAIT_TIMEOUT_MS;
  let containerId: string | undefined;
  let admitted = false;
  while (!containerId || !admitted) {
    if (exited) throw new Error(`public launch ended before attachment: ${describeOutput(exited.output, 4000)}`);
    if (!containerId) {
      const added = directSessionIds(projectId).filter((id) => !existing.has(id));
      if (added.length > 1) throw new Error(`public launch created ${added.length} new session containers`);
      containerId = added[0];
    }
    if (containerId) {
      admitted = sessionRecordAttached(fixture, projectId, containerId);
      if (admitted) break;
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      throw new Error(`public launch did not attach before the deadline: ${describeOutput(output, 4000)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const labels = JSON.parse(dockerOrThrow("session labels", [
    "inspect", "-f", "{{json .Config.Labels}}", containerId,
  ])) as Record<string, string>;
  const processIdentity = dockerOrThrow("session process identity", [
    "inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", containerId,
  ]);
  finishPhase();
  return Object.freeze({ child, completion, containerId, labels: Object.freeze(labels), processIdentity });
}

async function endSession(session: RunningSession): Promise<void> {
  const stopped = docker(["stop", "--time", "1", session.containerId]);
  if (stopped.status !== 0 && !/No such container/u.test(stopped.output)) {
    throw new Error(`could not stop session ${session.containerId.slice(0, 12)}: ${describeOutput(stopped.output)}`);
  }
  const completed = await Promise.race([
    session.completion,
    new Promise<never>((_resolve, reject) => setTimeout(
      () => reject(new Error(`session launch ${session.containerId.slice(0, 12)} did not finish teardown`)),
      SESSION_WAIT_TIMEOUT_MS,
    )),
  ]);
  if (completed.status === null) {
    throw new Error(`session launch ${session.containerId.slice(0, 12)} ended without an exit status`);
  }
}

function sessionRecordByContainerId(
  stateDir: string,
  containerId: string,
): Readonly<{ controlPlaneGenerationDigest: string; leaseGeneration: string; sourceIp: string; state: string }> {
  const registryDir = path.join(stateDir, "runtime", "v2", "session-containers");
  for (const entry of fs.readdirSync(registryDir)) {
    const record = JSON.parse(fs.readFileSync(path.join(registryDir, entry), "utf8")) as {
      containerId?: string;
      controlPlaneGenerationDigest: string;
      leaseGeneration: string;
      sourceIp: string;
      state: string;
    };
    if (record.containerId === containerId) return record;
  }
  throw new Error(`no lifecycle record for session container ${containerId.slice(0, 12)}`);
}

function materializationPath(stateDir: string, digest: string): string {
  return path.join(
    stateDir,
    "runtime", "v2", "session-agent", "materializations",
    digest.replace(/^sha256:/u, "sha256-"),
  );
}

function configureRollingFixture(fixture: LiveFixture): void {
  stageLongLivedAgentBinary(fixture);
  const enabled = fixture.runfree(["service", "enable", "agent-claude", "--no-reload"]);
  if (enabled.status !== 0) {
    throw new Error(`could not enable Claude operational access: ${describeOutput(enabled.output)}`);
  }
}

describe("per-session rolling runtime upgrades", () => {
  const backend = requiredBackend();
  let fixture: LiveFixture;
  const sessions: RunningSession[] = [];

  beforeAll(() => {
    fixture = provisionLiveFixture({
      repoRoot: REPO_ROOT,
      configure: configureRollingFixture,
      keepHostStateOnFailure: process.env.TEST_RUNTIME_KEEP_PROJECT === "1",
    });
  }, PROVISION_TIMEOUT_MS);

  afterAll(async () => {
    for (const session of sessions) {
      forceRemoveContainer(session.containerId);
      if (session.child.exitCode === null) session.child.kill("SIGKILL");
    }
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  test(`rolls templates and agent images without replacing live sessions on ${backend}`, async () => {
    const projectId = fixture.runfree(["project-id"]).stdout.trim();
    expect(projectId).toMatch(/^[a-f0-9]{12}$/u);
    const project = composeProjectName(fixture);
    const proxyId = composeServiceContainerId(project, "proxy");
    const stateDir = path.join(fixture.env.XDG_STATE_HOME as string, "runfree", "projects", projectId);
    const desiredPath = path.join(stateDir, "runtime", "v2", "session-agent", "desired.json");
    const initialDesired = JSON.parse(fs.readFileSync(desiredPath, "utf8")) as {
      sessionAgentMaterializationDigest: string;
      sessionAgentGenerationDigest: string;
      selectedAgentImageId: string;
    };

    const first = await startAttachedSession(fixture, projectId, new Set());
    sessions.push(first);
    expect(first.labels["io.runfree.session-agent-materialization-digest"])
      .toBe(initialDesired.sessionAgentMaterializationDigest);
    expect(first.labels["io.runfree.selected-agent-image-id"]).toBe(initialDesired.selectedAgentImageId);

    fs.writeFileSync(
      path.join(fixture.projectRoot, "package.json"),
      `${JSON.stringify({ name: "runfree-runtime-live", private: true, packageManager: "npm@10" })}\n`,
    );
    const second = await startAttachedSession(fixture, projectId, new Set(directSessionIds(projectId)));
    sessions.push(second);
    const templateDesired = JSON.parse(fs.readFileSync(desiredPath, "utf8")) as typeof initialDesired;
    expect(templateDesired.sessionAgentMaterializationDigest)
      .not.toBe(initialDesired.sessionAgentMaterializationDigest);
    expect(templateDesired.sessionAgentGenerationDigest)
      .not.toBe(initialDesired.sessionAgentGenerationDigest);
    expect(templateDesired.selectedAgentImageId).toBe(initialDesired.selectedAgentImageId);
    expect(second.labels["io.runfree.session-agent-materialization-digest"])
      .toBe(templateDesired.sessionAgentMaterializationDigest);
    expect(dockerOrThrow("proxy identity after template roll", ["inspect", "-f", "{{.Id}}", proxyId]))
      .toBe(proxyId);

    const dockerfile = path.join(fixture.projectRoot, ".runfree", "image", "Dockerfile");
    fs.appendFileSync(dockerfile, "\nENV RUNFREE_ROLLING_IMAGE_PROOF=1\n");
    const approved = fixture.runfree(["image", "approve-context"]);
    expect(approved.status, describeOutput(approved.output)).toBe(0);
    const third = await startAttachedSession(fixture, projectId, new Set(directSessionIds(projectId)));
    sessions.push(third);
    const imageDesired = JSON.parse(fs.readFileSync(desiredPath, "utf8")) as typeof initialDesired;
    expect(imageDesired.selectedAgentImageId).not.toBe(templateDesired.selectedAgentImageId);
    expect(third.labels["io.runfree.selected-agent-image-id"]).toBe(imageDesired.selectedAgentImageId);
    expect(directSessionIds(projectId)).toHaveLength(3);
    for (const session of [first, second, third]) {
      expect(dockerOrThrow("stable session process", [
        "inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", session.containerId,
      ])).toBe(session.processIdentity);
    }

    // "Coexistence" is a property of the published eligibility: it is the whole
    // of what the proxy will serve, so a rolling upgrade that narrowed it to
    // the newest materialization would cut the two older sessions off at their
    // next heartbeat. The widened set — one entry per materialization a live
    // record still names — is what keeps them eligible, and all three addresses
    // being served is the consequence.
    {
      const eligibility = readPublishedSessionEligibility(proxyId);
      const allowed = eligibility.allowedSessionAgents.map((agent) => (
        `${agent.sessionAgentGenerationDigest} ${agent.selectedAgentImageId}`
      ));
      for (const [label, desired] of [
        ["the first session's original materialization", initialDesired],
        ["the second session's rolled template", templateDesired],
        ["the third session's rolled image", imageDesired],
      ] as const) {
        expect(
          allowed,
          `the published eligibility no longer admits ${label}, so a live session would lapse at its next heartbeat`,
        ).toContain(`${desired.sessionAgentGenerationDigest} ${desired.selectedAgentImageId}`);
      }
      const addresses = [first, second, third]
        .map((session) => sessionRecordByContainerId(stateDir, session.containerId).sourceIp)
        .sort();
      assertFilesPathExercised(fixture, proxyId, addresses, "after the rolling image upgrade");
    }

    const composeAgents = dockerOrThrow("Compose agent absence", [
      "ps", "-a", "--no-trunc",
      "--filter", `label=com.docker.compose.project=${project}`,
      "--filter", "label=com.docker.compose.service=agent",
      "--format", "{{.ID}}",
    ]);
    expect(composeAgents).toBe("");

    await endSession(first);
    sessions.splice(sessions.indexOf(first), 1);
    const afterFirst = fixture.runfree(["up"]);
    expect(afterFirst.status, describeOutput(afterFirst.output, 4000)).toBe(0);
    expect(fs.existsSync(materializationPath(stateDir, initialDesired.sessionAgentMaterializationDigest))).toBe(false);
    expect(docker(["image", "inspect", templateDesired.selectedAgentImageId]).status).toBe(0);

    await endSession(second);
    sessions.splice(sessions.indexOf(second), 1);
    const afterSecond = fixture.runfree(["up"]);
    expect(afterSecond.status, describeOutput(afterSecond.output, 4000)).toBe(0);
    expect(fs.existsSync(materializationPath(stateDir, templateDesired.sessionAgentMaterializationDigest))).toBe(false);
    expect(docker(["image", "inspect", templateDesired.selectedAgentImageId]).status).not.toBe(0);
    expect(docker(["image", "inspect", imageDesired.selectedAgentImageId]).status).toBe(0);

    const thirdBeforeRestart = dockerOrThrow("third session before proxy restart", [
      "inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", third.containerId,
    ]);
    const beforeGuard = dockerOrThrow("proxy before disruption guards", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]);
    for (const command of [["stop"], ["runtime", "reload-policy"]]) {
      const refused = fixture.runfree(command);
      expect(refused.status, describeOutput(refused.output, 4000)).not.toBe(0);
      expect(refused.output).toContain("--force");
      expect(dockerOrThrow("guard preserved proxy process", ["inspect", "-f", "{{.State.StartedAt}}", proxyId])).toBe(beforeGuard);
    }
    const forcedReload = fixture.runfree(["runtime", "reload-policy", "--force"]);
    expect(forcedReload.status, describeOutput(forcedReload.output, 4000)).toBe(0);
    expect(forcedReload.output).toContain("remembered denials reset");
    expect(composeServiceContainerId(project, "proxy")).toBe(proxyId);
    expect(dockerOrThrow("forced reload preserved owner", ["inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", third.containerId])).toBe(thirdBeforeRestart);
    const finishRestart = startLivePhase("rolling: Docker proxy restart");
    dockerOrThrow("proxy restart with active session", ["restart", proxyId]);
    finishRestart();
    const recovered = fixture.runfree(["up"]);
    expect(recovered.status, describeOutput(recovered.output, 4000)).toBe(0);
    expect(dockerOrThrow("third session after proxy restart", [
      "inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", third.containerId,
    ])).toBe(thirdBeforeRestart);

    // A compatible proxy replacement under live sessions is the session
    // independence tranche's subject (`session-independence.live.test.ts`),
    // which proves it per session for eight at once; this tranche's subject is
    // the rolling materializations, so it ends here.
    await endSession(third);
    sessions.splice(sessions.indexOf(third), 1);
    // Client-side teardown converged: the record is gone before any other
    // runfree invocation could reclaim it.
    expect(() => sessionRecordByContainerId(stateDir, third.containerId))
      .toThrow("no lifecycle record");
    const afterThird = fixture.runfree(["up"]);
    expect(afterThird.status, describeOutput(afterThird.output, 4000)).toBe(0);
    expect(fs.existsSync(materializationPath(stateDir, imageDesired.sessionAgentMaterializationDigest))).toBe(true);
  }, TEST_TIMEOUT_MS);
});
