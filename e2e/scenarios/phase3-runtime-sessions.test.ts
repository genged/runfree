import fs from "node:fs";
import path from "node:path";

import { describe, expect } from "vitest";

import { artifactPath } from "../support/artifact.ts";
import { assertExit, assertOutputContains, assertOutputExcludes } from "../support/assertions.ts";
import { scenario } from "../support/evidence.ts";
import { assertOwnedStateUnchanged, snapshotOwnedState } from "../support/snapshot.ts";
import { withWorld, type E2EWorld } from "../support/world.ts";

type RecoveryInventoryItem = Readonly<{
  id: string;
  project?: string;
  projectName: string;
  agent: string;
  state: string;
  evidence: string;
  conversationId?: string;
  conversationName?: string;
  updatedAt?: string;
}>;

type RecoveryInventory = Readonly<{
  items: readonly RecoveryInventoryItem[];
  truncated: boolean;
  invalidFiles: number;
}>;

const packagedCleanup = "Remove the disposable projects, constructed recovery evidence, home, and XDG roots after the test.";

const recoveryMetadata = {
  scenarioIds: ["LH-19"],
  layer: "P",
  cadence: "pull-request",
  implementationStatus: "Partial",
  evidence: {
    kind: "constructed-recovery-state",
    constructedState: "Host session and agent registry files model interrupted, malformed, linked, and oversized recovery evidence.",
    unproved: "These fixtures do not prove crash-time evidence creation, live Docker classification, claim concurrency, resume execution, or evidence consumption.",
  },
  ownedStateAreas: ["projects", "home", "XDG config", "XDG data", "XDG state", "XDG cache", "Docker invocation log"],
  requiredPrograms: ["packaged Runfree executable"],
  cleanup: packagedCleanup,
} as const;

const CURRENT_CLAUDE_SESSION = "11111111-2222-4333-8444-555555555555";
const OTHER_CLAUDE_SESSION = "22222222-3333-4444-8555-666666666666";

function writeJson(filePath: string, value: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function installUnavailableDocker(world: E2EWorld): void {
  fs.writeFileSync(path.join(world.fakeBin, "docker"), [
    "#!/bin/sh",
    "printf '%s\\n' \"$*\" >> \"$RUNFREE_E2E_DOCKER_LOG\"",
    "printf 'Docker is unavailable in this e2e world\\n' >&2",
    "exit 97",
    "",
  ].join("\n"), { mode: 0o755 });
}

async function packagedProjectId(world: E2EWorld, projectRoot: string): Promise<string> {
  const result = projectRoot === world.projectRoot
    ? await world.runfree(["project-id"])
    : await world.runExternal(artifactPath(), ["--workspace", projectRoot, "project-id"]);
  assertExit(result, 0);
  expect(result.stdout.trim()).toMatch(/^[0-9a-f]{12}$/u);
  return result.stdout.trim();
}

function projectStateDir(world: E2EWorld, projectId: string): string {
  return path.join(world.stateHome, "runfree", "projects", projectId);
}

function writeProjectPointer(stateDir: string, projectRoot: string): void {
  writeJson(path.join(stateDir, "project.json"), {
    projectRoot,
    updatedAt: "2026-08-25T00:00:00.000Z",
  });
}

function writeClaudeEvidence(input: {
  stateDir: string;
  pid: number;
  sessionId: string;
  name: string;
  updatedAt?: string;
}): string {
  const updatedAt = input.updatedAt ?? "2026-08-25T00:02:00.000Z";
  const filePath = path.join(input.stateDir, "claude", "sessions", `${input.pid}.json`);
  writeJson(filePath, {
    pid: input.pid,
    sessionId: input.sessionId,
    cwd: "/workspace",
    startedAt: Date.parse("2026-08-25T00:00:00.000Z"),
    procStart: String(input.pid * 10),
    name: input.name,
    status: "idle",
    updatedAt: Date.parse(updatedAt),
  });
  return filePath;
}

function writeHostEvidence(input: {
  stateDir: string;
  projectRoot: string;
  projectId: string;
  id: string;
  agent: string;
  updatedAt?: string;
  resumeConversationId?: string;
}): string {
  const updatedAt = input.updatedAt ?? "2026-08-25T00:03:00.000Z";
  const filePath = path.join(input.stateDir, "sessions", `${input.id}.json`);
  writeJson(filePath, {
    id: input.id,
    projectRoot: input.projectRoot,
    composeProject: `runfree-${input.projectId}`,
    command: input.agent,
    hostPid: 999_999,
    startedAt: "2026-08-25T00:00:00.000Z",
    lastSeenAt: updatedAt,
    endedAt: updatedAt,
    exitStatus: 137,
    outcome: "interrupted",
    ...(input.resumeConversationId === undefined ? {} : { resumeConversationId: input.resumeConversationId }),
  });
  return filePath;
}

function inventory(stdout: string): RecoveryInventory {
  return JSON.parse(stdout) as RecoveryInventory;
}

function ownedSelections(world: E2EWorld, otherProjectRoot?: string) {
  return [
    { name: "current project", path: world.projectRoot },
    ...(otherProjectRoot ? [{ name: "other project", path: otherProjectRoot }] : []),
    { name: "home", path: world.home },
    { name: "config", path: world.configHome },
    { name: "data", path: world.dataHome },
    { name: "state", path: world.stateHome },
    { name: "cache", path: world.cacheHome },
    { name: "fake programs", path: world.fakeBin },
    { name: "Docker invocation log", path: world.dockerLog },
  ] as const;
}

describe("packaged runtime session recovery", () => {
  scenario("offline inventory is read-only and applies explicit project and agent scope", recoveryMetadata, async () => {
    await withWorld({}, async (world) => {
      installUnavailableDocker(world);
      const otherProjectRoot = path.join(world.root, "other-project");
      fs.mkdirSync(otherProjectRoot, { mode: 0o700 });
      const currentProjectId = await packagedProjectId(world, world.projectRoot);
      const otherProjectId = await packagedProjectId(world, otherProjectRoot);
      const currentStateDir = projectStateDir(world, currentProjectId);
      const otherStateDir = projectStateDir(world, otherProjectId);
      writeProjectPointer(currentStateDir, world.projectRoot);
      writeProjectPointer(otherStateDir, otherProjectRoot);

      writeClaudeEvidence({
        stateDir: currentStateDir,
        pid: 4_242,
        sessionId: CURRENT_CLAUDE_SESSION,
        name: "current Claude conversation",
      });
      writeHostEvidence({
        stateDir: currentStateDir,
        projectRoot: world.projectRoot,
        projectId: currentProjectId,
        id: "rf-20260825-c0de01",
        agent: "codex",
      });
      writeClaudeEvidence({
        stateDir: otherStateDir,
        pid: 4_343,
        sessionId: OTHER_CLAUDE_SESSION,
        name: "other Claude conversation",
      });
      writeHostEvidence({
        stateDir: otherStateDir,
        projectRoot: otherProjectRoot,
        projectId: otherProjectId,
        id: "rf-20260825-0a1b2c",
        agent: "pi",
      });
      writeHostEvidence({
        stateDir: otherStateDir,
        projectRoot: otherProjectRoot,
        projectId: otherProjectId,
        id: "rf-20260825-0d1e2f",
        agent: "unknown-agent",
      });

      const unavailableProbe = await world.runExternal("docker", ["info"]);
      assertExit(unavailableProbe, 97);
      fs.writeFileSync(world.dockerLog, "", { mode: 0o600 });
      const selections = ownedSelections(world, otherProjectRoot);
      const before = snapshotOwnedState(selections);

      const listed = await world.runfree(["resume", "--list"]);
      assertExit(listed, 0);
      assertOutputContains(listed, "current Claude conversation");
      assertOutputContains(listed, "codex");
      assertOutputExcludes(listed, "other Claude conversation");
      assertOutputExcludes(listed, "unknown-agent");

      const currentJson = await world.runfree(["resume", "--json"]);
      assertExit(currentJson, 0);
      expect(currentJson.stderr).toBe("");
      expect(inventory(currentJson.stdout)).toMatchObject({
        truncated: false,
        invalidFiles: 0,
        items: expect.arrayContaining([
          expect.objectContaining({ project: world.projectRoot, agent: "claude", conversationId: CURRENT_CLAUDE_SESSION }),
          expect.objectContaining({ project: world.projectRoot, agent: "codex", evidence: "host" }),
        ]),
      });
      expect(inventory(currentJson.stdout).items).toHaveLength(2);

      const allJson = await world.runfree(["resume", "--all", "--json"]);
      assertExit(allJson, 0);
      expect(inventory(allJson.stdout).items.map((item) => item.agent).sort())
        .toEqual(["claude", "claude", "codex", "pi", "unknown-agent"]);

      const otherJson = await world.runfree(["resume", "--project", otherProjectRoot, "--json"]);
      assertExit(otherJson, 0);
      expect(inventory(otherJson.stdout).items.map((item) => item.agent).sort())
        .toEqual(["claude", "pi", "unknown-agent"]);
      expect(inventory(otherJson.stdout).items.every((item) => item.project === otherProjectRoot)).toBe(true);

      const selectedAgents = await world.runfree([
        "resume", "--all", "--agent", "claude", "--agent", "pi", "--json",
      ]);
      assertExit(selectedAgents, 0);
      expect(inventory(selectedAgents.stdout).items.map((item) => item.agent).sort())
        .toEqual(["claude", "claude", "pi"]);

      assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      expect(fs.readFileSync(world.dockerLog, "utf8")).toBe("");
    });
  }, 60_000);

  scenario("offline inventory rejects unsafe registry files and omits an unsafe exact conversation", recoveryMetadata, async () => {
    await withWorld({}, async (world) => {
      installUnavailableDocker(world);
      const projectId = await packagedProjectId(world, world.projectRoot);
      const stateDir = projectStateDir(world, projectId);
      const registryDir = path.join(stateDir, "claude", "sessions");
      const sessionsDir = path.join(stateDir, "sessions");
      writeProjectPointer(stateDir, world.projectRoot);

      writeClaudeEvidence({
        stateDir,
        pid: 4_242,
        sessionId: CURRENT_CLAUDE_SESSION,
        name: "safe conversation",
      });
      writeHostEvidence({
        stateDir,
        projectRoot: world.projectRoot,
        projectId,
        id: "rf-20260825-c0de01",
        agent: "codex",
        resumeConversationId: OTHER_CLAUDE_SESSION,
      });
      writeHostEvidence({
        stateDir,
        projectRoot: world.projectRoot,
        projectId,
        id: "rf-20260825-c0de02",
        agent: "codex",
        updatedAt: "2026-08-25T00:04:00.000Z",
        resumeConversationId: "../../tmp/argv-injection",
      });

      const outsideEvidence = path.join(world.home, "outside-registry.json");
      writeJson(outsideEvidence, {
        pid: 5_151,
        sessionId: "33333333-4444-4555-8666-777777777777",
        cwd: "/workspace",
        startedAt: Date.parse("2026-08-25T00:00:00.000Z"),
        procStart: "51510",
        updatedAt: Date.parse("2026-08-25T00:01:00.000Z"),
      });
      fs.symlinkSync(outsideEvidence, path.join(registryDir, "5151.json"));

      const hardLinked = writeClaudeEvidence({
        stateDir,
        pid: 5_152,
        sessionId: "44444444-5555-4666-8777-888888888888",
        name: "hard-linked evidence",
      });
      fs.linkSync(hardLinked, path.join(registryDir, "5153.json"));
      fs.writeFileSync(path.join(registryDir, "5154.json"), "x".repeat((64 * 1024) + 1), { mode: 0o600 });
      writeJson(path.join(registryDir, "5155.json"), {
        pid: 5_155,
        sessionId: "$(touch /tmp/unsafe-recovery-id)",
        cwd: "/workspace",
        startedAt: Date.parse("2026-08-25T00:00:00.000Z"),
        procStart: "51550",
        updatedAt: Date.parse("2026-08-25T00:01:00.000Z"),
      });
      fs.writeFileSync(path.join(sessionsDir, "rf-20260825-badbad.json"), "{not json\n", { mode: 0o600 });

      const unavailableProbe = await world.runExternal("docker", ["info"]);
      assertExit(unavailableProbe, 97);
      fs.writeFileSync(world.dockerLog, "", { mode: 0o600 });
      const selections = ownedSelections(world);
      const before = snapshotOwnedState(selections);

      const result = await world.runfree(["resume", "--json"]);
      assertExit(result, 0);
      expect(result.stderr).toBe("");
      const parsed = inventory(result.stdout);
      expect(parsed.truncated).toBe(false);
      expect(parsed.invalidFiles).toBeGreaterThanOrEqual(6);
      expect(parsed.items).toHaveLength(3);
      expect(parsed.items.map((item) => item.agent).sort()).toEqual(["claude", "codex", "codex"]);
      expect(parsed.items).toContainEqual(expect.objectContaining({
        agent: "codex",
        conversationId: OTHER_CLAUDE_SESSION,
      }));
      expect(parsed.items).toContainEqual(expect.objectContaining({
        agent: "codex",
        updatedAt: "2026-08-25T00:04:00.000Z",
      }));
      const unsafeConversation = parsed.items.find((item) => item.updatedAt === "2026-08-25T00:04:00.000Z");
      expect(unsafeConversation?.conversationId).toBeUndefined();
      assertOutputExcludes(result, "../../tmp/argv-injection");
      assertOutputExcludes(result, "unsafe-recovery-id");
      assertOutputExcludes(result, "hard-linked evidence");

      const listed = await world.runfree(["resume", "--list"]);
      assertExit(listed, 0);
      assertOutputContains(listed, "safe conversation");
      assertOutputExcludes(listed, "argv-injection");
      assertOutputExcludes(listed, "hard-linked evidence");

      assertOwnedStateUnchanged(before, snapshotOwnedState(selections));
      expect(fs.readFileSync(world.dockerLog, "utf8")).toBe("");
    });
  }, 60_000);
});
