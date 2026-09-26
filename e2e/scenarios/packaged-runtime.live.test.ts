import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { assertExit, assertOutputContains, assertOutputExcludes } from "../support/assertions.ts";
import { describeCommandResult, type CommandResult } from "../support/command.ts";
import { scenario } from "../support/evidence.ts";
import { withWorld, type E2EWorld } from "../support/world.ts";

const COMMAND_TIMEOUT_MS = 10 * 60_000;
const STARTUP_TIMEOUT_MS = 30 * 60_000;
const SCENARIO_TIMEOUT_MS = 40 * 60_000;
// The refusal is one multi-line message; the shared formatter indents its
// continuation lines under the attributed first line, so the anchor tolerates
// that indent and nothing else before the command.
const APPROVAL_PATTERN = /^ *runfree control approve ([a-z-]+) --subject-digest (sha256:[a-f0-9]{64})$/gmu;
const SESSION_WAIT_TIMEOUT_MS = 90_000;

type DesiredSessionSelection = Readonly<{
  sessionAgentGenerationDigest: string;
  sessionAgentMaterializationDigest: string;
  selectedAgentImageId: string;
}>;

function requiredDockerHost(): string {
  const dockerHost = process.env.RUNFREE_E2E_DOCKER_HOST?.trim();
  if (!dockerHost) throw new Error("RUNFREE_E2E_DOCKER_HOST is required for packaged runtime e2e");
  return dockerHost;
}

function resultText(result: CommandResult): string {
  return `${result.stdout}${result.stderr}`;
}

async function runDocker(world: E2EWorld, args: readonly string[]): Promise<CommandResult> {
  return world.runExternal("docker", args, { timeoutMs: COMMAND_TIMEOUT_MS });
}

async function git(world: E2EWorld, args: readonly string[]): Promise<void> {
  const result = await world.runExternal("git", ["-C", world.projectRoot, ...args]);
  if (result.outcome.kind !== "exit" || result.outcome.exitCode !== 0) {
    throw new Error(`git ${args.join(" ")} failed\n${describeCommandResult(result)}`);
  }
}

async function waitForSessionContainer(world: E2EWorld, projectId: string): Promise<string> {
  const deadline = Date.now() + SESSION_WAIT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const listed = await runDocker(world, [
      "ps", "--no-trunc",
      "--filter", `label=io.runfree.project-id=${projectId}`,
      "--filter", "label=io.runfree.container-role=session-agent",
      "--format", "{{.ID}}",
    ]);
    assertExit(listed, 0);
    const ids = listed.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
    if (ids.length === 1) return ids[0];
    if (ids.length > 1) throw new Error(`rolling launch created ${ids.length} session containers`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("rolling launch did not publish one running session container before the deadline");
}

describe("packaged executable against a real Docker runtime", () => {
  scenario("startup, warm session-template rolling selection, reuse, and destroy complete end to end", {
    scenarioIds: ["LH-11", "LH-12", "LH-20"],
    layer: "Dp",
    cadence: "docker-pre-merge",
    implementationStatus: "Partial",
    evidence: {
      kind: "real-provider-compatibility",
      provider: `Docker (${process.env.TEST_RUNTIME_BACKEND ?? "unspecified backend"})`,
    },
    ownedStateAreas: ["project", "XDG config", "XDG data", "XDG state", "Docker project resources"],
    requiredPrograms: ["packaged Runfree executable", "Docker CLI", "Git", "POSIX shell"],
    cleanup: "Force-destroy the exact project runtime, repeat destroy, and prove no project-labeled containers remain.",
  }, async () => {
    await withWorld({ dockerHost: requiredDockerHost() }, async (world) => {
      let runtimeMayExist = false;
      let failure: unknown;
      let projectId = "";
      try {
        fs.writeFileSync(
          path.join(world.projectRoot, "package.json"),
          `${JSON.stringify({ name: "runfree-packaged-e2e", private: true, packageManager: "pnpm@10" })}\n`,
        );
        assertExit(await world.runfree(["init"]), 0);
        assertExit(await world.runfree(["image", "init"]), 0);

        const dockerfile = path.join(world.projectRoot, ".runfree", "image", "Dockerfile");
        fs.appendFileSync(dockerfile, [
          "",
          "USER root",
          "RUN mv /usr/local/libexec/runfree/claude-real /usr/local/libexec/runfree/claude-real-pinned \\",
          " && printf '%s\\n' '#!/bin/sh' 'printf \"%s\\n\" \"$@\" > /workspace/.runfree-e2e-agent-argv' 'if [ -f /workspace/.runfree-e2e-hold ]; then while [ ! -f /workspace/.runfree-e2e-release ]; do sleep 0.1; done; fi' > /usr/local/libexec/runfree/claude-real \\",
          " && chmod 0755 /usr/local/libexec/runfree/claude-real",
          "USER agent",
          "",
        ].join("\n"));

        await git(world, ["init", "-b", "main"]);
        await git(world, ["config", "user.name", "Runfree Packaged E2E"]);
        await git(world, ["config", "user.email", "packaged-e2e@runfree.invalid"]);
        await git(world, ["add", "package.json"]);
        await git(world, ["commit", "-m", "initial packaged e2e fixture"]);

        const service = await world.runfree(["service", "enable", "agent-claude", "--no-reload"], { timeoutMs: COMMAND_TIMEOUT_MS });
        assertExit(service, 0);

        const authorityRefusal = await world.runfree(["up"], { timeoutMs: COMMAND_TIMEOUT_MS });
        assertExit(authorityRefusal, 1);
        assertOutputContains(authorityRefusal, "desired controls require exact approval before startup");
        const approvals = [...resultText(authorityRefusal).matchAll(APPROVAL_PATTERN)]
          .map((match) => ({ subject: match[1], digest: match[2] }));
        expect(approvals.map((approval) => approval.subject).sort()).toEqual(["network-local", "network-project", "runtime-isolation"]);
        for (const approval of approvals) {
          assertExit(await world.runfree([
            "control", "approve", approval.subject, "--subject-digest", approval.digest,
          ], { timeoutMs: COMMAND_TIMEOUT_MS }), 0);
        }

        const buildRefusal = await world.runfree(["up"], { timeoutMs: COMMAND_TIMEOUT_MS });
        assertExit(buildRefusal, 1);
        assertOutputContains(buildRefusal, "exact pre-sandbox Docker build approval is required");
        const imageApproval = await world.runfree(["image", "approve-context"], { timeoutMs: COMMAND_TIMEOUT_MS });
        assertExit(imageApproval, 0);
        expect(resultText(imageApproval)).toMatch(/approved exact agent build input: sha256:[a-f0-9]{64}/u);

        runtimeMayExist = true;
        const started = await world.runfree(["up"], { timeoutMs: STARTUP_TIMEOUT_MS });
        assertExit(started, 0);
        // Progress lines, including "runtime startup complete", print only with
        // --verbose (output contract P6). The non-verbose user path prints one
        // start line; exit 0 plus the exact proxy inventory below is the proof
        // that startup completed.
        assertOutputContains(started, "runfree: starting runtime");

        const projectIdResult = await world.runfree(["project-id"]);
        assertExit(projectIdResult, 0);
        projectId = projectIdResult.stdout.trim();
        const proxyList = await runDocker(world, [
          "ps", "--no-trunc",
          "--filter", `label=io.runfree.project-id=${projectId}`,
          "--filter", "label=io.runfree.container-role=proxy",
          "--format", "{{.ID}}",
        ]);
        assertExit(proxyList, 0);
        const proxyIds = proxyList.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
        expect(proxyIds).toHaveLength(1);
        const proxyId = proxyIds[0];
        const projectStateDir = path.join(world.stateHome, "runfree", "projects", projectId);
        const desiredSelectionPath = path.join(projectStateDir, "runtime", "v2", "session-agent", "desired.json");
        const controlSelectionPath = path.join(projectStateDir, "runtime", "v2", "control-plane", "effective.json");
        const initialDesiredBytes = fs.readFileSync(desiredSelectionPath, "utf8");
        const initialDesired = JSON.parse(initialDesiredBytes) as DesiredSessionSelection;
        const initialControlBytes = fs.readFileSync(controlSelectionPath, "utf8");

        const inspection = await runDocker(world, [
          "inspect", "-f",
          "{{.State.Status}}|{{index .Config.Labels \"io.runfree.container-role\"}}|{{json .NetworkSettings.Networks}}",
          proxyId,
        ]);
        assertExit(inspection, 0);
        const [status, role, networkJson] = inspection.stdout.trim().split("|", 3);
        expect(status).toBe("running");
        expect(role).toBe("proxy");
        expect(Object.keys(JSON.parse(networkJson) as Record<string, unknown>).sort()).toEqual([
          `runfree-${projectId}_agent_internal`,
          `runfree-${projectId}_proxy_egress`,
        ]);

        const launched = await world.runfree(["claude"], { timeoutMs: STARTUP_TIMEOUT_MS });
        assertExit(launched, 0);
        const agentArgv = fs.readFileSync(path.join(world.projectRoot, ".runfree-e2e-agent-argv"), "utf8").split("\n").filter(Boolean);
        expect(agentArgv).toContain("--strict-mcp-config");
        expect(agentArgv).toContain("--mcp-config");
        expect(agentArgv).toContain("/runfree/mcp/claude.json");
        expect(agentArgv).toContain("--add-dir");
        expect(agentArgv).toContain("/runfree/inbox");

        // Change only a session-template owner. Dependency overlay mounts and
        // environment change, while control-plane inputs and the proxy image do
        // not. Hold the stub session so Docker can be inspected independently.
        fs.writeFileSync(
          path.join(world.projectRoot, "package.json"),
          `${JSON.stringify({ name: "runfree-packaged-e2e", private: true, packageManager: "npm@10" })}\n`,
        );
        const holdPath = path.join(world.projectRoot, ".runfree-e2e-hold");
        const releasePath = path.join(world.projectRoot, ".runfree-e2e-release");
        fs.rmSync(releasePath, { force: true });
        fs.writeFileSync(holdPath, "hold\n");
        const rollingLaunch = world.runfree(["claude"], { timeoutMs: STARTUP_TIMEOUT_MS });
        let rollingResult: CommandResult;
        try {
          const sessionId = await waitForSessionContainer(world, projectId);
          const selectedBytes = fs.readFileSync(desiredSelectionPath, "utf8");
          const selected = JSON.parse(selectedBytes) as DesiredSessionSelection;
          expect(selected.sessionAgentMaterializationDigest)
            .not.toBe(initialDesired.sessionAgentMaterializationDigest);
          expect(selected.sessionAgentGenerationDigest)
            .not.toBe(initialDesired.sessionAgentGenerationDigest);
          expect(selected.selectedAgentImageId).toBe(initialDesired.selectedAgentImageId);
          expect(fs.readFileSync(controlSelectionPath, "utf8")).toBe(initialControlBytes);

          const sessionInspection = await runDocker(world, [
            "inspect", "-f",
            "{{json .Config.Labels}}|{{.Image}}|{{json .NetworkSettings.Networks}}",
            sessionId,
          ]);
          assertExit(sessionInspection, 0);
          const [labelsJson, imageId, sessionNetworksJson] = sessionInspection.stdout.trim().split("|", 3);
          const labels = JSON.parse(labelsJson) as Record<string, string>;
          expect(labels["io.runfree.container-role"]).toBe("session-agent");
          expect(labels["io.runfree.session-agent-materialization-digest"])
            .toBe(selected.sessionAgentMaterializationDigest);
          expect(labels["io.runfree.session-agent-generation-digest"])
            .toBe(selected.sessionAgentGenerationDigest);
          expect(labels["io.runfree.selected-agent-image-id"]).toBe(selected.selectedAgentImageId);
          expect(imageId).toBe(selected.selectedAgentImageId);
          expect(Object.keys(JSON.parse(sessionNetworksJson) as Record<string, unknown>))
            .toEqual([`runfree-${projectId}_agent_internal`]);

          const composeAgent = await runDocker(world, [
            "ps", "-a", "--no-trunc",
            "--filter", `label=com.docker.compose.project=runfree-${projectId}`,
            "--filter", "label=com.docker.compose.service=agent",
            "--format", "{{.ID}}",
          ]);
          assertExit(composeAgent, 0);
          expect(composeAgent.stdout.trim()).toBe("");
        } finally {
          fs.writeFileSync(releasePath, "release\n");
          fs.rmSync(holdPath, { force: true });
          rollingResult = await rollingLaunch;
          fs.rmSync(releasePath, { force: true });
        }
        assertExit(rollingResult, 0);
        assertOutputExcludes(rollingResult, "runfree rebuild");
        expect((await runDocker(world, [
          "ps", "--no-trunc",
          "--filter", `label=io.runfree.project-id=${projectId}`,
          "--filter", "label=io.runfree.container-role=proxy",
          "--format", "{{.ID}}",
        ])).stdout.trim()).toBe(proxyId);

        const secondUp = await world.runfree(["up"], { timeoutMs: STARTUP_TIMEOUT_MS });
        assertExit(secondUp, 0);
        const proxyListAfter = await runDocker(world, [
          "ps", "--no-trunc",
          "--filter", `label=io.runfree.project-id=${projectId}`,
          "--filter", "label=io.runfree.container-role=proxy",
          "--format", "{{.ID}}",
        ]);
        assertExit(proxyListAfter, 0);
        expect(proxyListAfter.stdout.trim()).toBe(proxyId);

        const stableDesiredBytes = fs.readFileSync(desiredSelectionPath, "utf8");
        const unchangedLaunch = await world.runfree(["claude"], { timeoutMs: STARTUP_TIMEOUT_MS });
        assertExit(unchangedLaunch, 0);
        expect(fs.readFileSync(desiredSelectionPath, "utf8")).toBe(stableDesiredBytes);
        expect(fs.readFileSync(controlSelectionPath, "utf8")).toBe(initialControlBytes);
      } catch (error) {
        failure = error;
      } finally {
        if (runtimeMayExist) {
          const destroyed = await world.runfree(["destroy", "--force"], { timeoutMs: STARTUP_TIMEOUT_MS });
          if (destroyed.outcome.kind !== "exit" || destroyed.outcome.exitCode !== 0) {
            world.preserve();
            const cleanupFailure = new Error(`packaged runtime cleanup failed; world preserved\n${describeCommandResult(destroyed)}`);
            failure = failure ? new AggregateError([failure, cleanupFailure], "scenario and cleanup both failed") : cleanupFailure;
          } else {
            const secondDestroy = await world.runfree(["destroy", "--force"], { timeoutMs: COMMAND_TIMEOUT_MS });
            if (secondDestroy.outcome.kind !== "exit" || secondDestroy.outcome.exitCode !== 0) {
              const cleanupFailure = new Error(`second destroy did not converge\n${describeCommandResult(secondDestroy)}`);
              failure = failure ? new AggregateError([failure, cleanupFailure], "scenario and null cleanup run both failed") : cleanupFailure;
            }
            const remaining = await runDocker(world, [
              "ps", "-a", "--no-trunc",
              "--filter", `label=io.runfree.project-id=${projectId}`,
              "--format", "{{.ID}}",
            ]);
            if (remaining.outcome.kind !== "exit" || remaining.outcome.exitCode !== 0 || remaining.stdout.trim() !== "") {
              const cleanupFailure = new Error(`destroy left project containers behind\n${describeCommandResult(remaining)}`);
              failure = failure ? new AggregateError([failure, cleanupFailure], "scenario and runtime absence proof both failed") : cleanupFailure;
            }
          }
        }
      }
      if (failure) throw failure;
    });
  }, SCENARIO_TIMEOUT_MS);
});
