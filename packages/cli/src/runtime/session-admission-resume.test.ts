import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createRuntimeDocker: vi.fn(),
  createDriver: vi.fn(),
  launchBuiltin: vi.fn(),
}));

vi.mock("./docker.ts", async (importOriginal) => ({
  ...await importOriginal<object>(),
  createRuntimeDocker: mocks.createRuntimeDocker,
}));
vi.mock("./session-admission-driver.ts", () => ({
  createInternalSessionAdmissionDriver: mocks.createDriver,
}));
vi.mock("./prepared-runtime.ts", () => ({
  preparedRuntimeContext: (prepared: { context: unknown }) => prepared.context,
  StalePreparedRuntimeError: class StalePreparedRuntimeError extends Error {},
}));

import { defaultConfig } from "../config.ts";
import { composeProjectName, projectHash } from "../project-identity.ts";
import { scanRecoveryInventory, type RecoveryItem } from "./recovery.ts";
import { resumeInterruptedSessionThroughAdmission } from "./session-admission-resume.ts";
import { tryAcquireProjectLifecycleLock } from "./sessions.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const BOOT = "linux:11111111-2222-3333-4444-555555555555";
const PROCESS_START = "linux:12345";
const CLAUDE_SESSION = "11111111-2222-4333-8444-555555555555";

let tmp: string;
let projectRoot: string;
let stateDir: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  vi.clearAllMocks();
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-resume-"));
  projectRoot = path.join(tmp, "project");
  fs.mkdirSync(projectRoot, { recursive: true });
  env = {
    XDG_STATE_HOME: path.join(tmp, "xdg-state"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: BOOT,
    RUNFREE_TEST_HOST_PROCESS_START: PROCESS_START,
  };
  stateDir = path.join(env.XDG_STATE_HOME as string, "runfree", "projects", projectHash(projectRoot));
  fs.mkdirSync(path.join(stateDir, "sessions"), { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, "project.json"),
    `${JSON.stringify({ projectRoot, updatedAt: "2026-07-31T00:00:00.000Z" })}\n`,
    { mode: 0o600 },
  );
  mocks.createRuntimeDocker.mockReturnValue({
    activeAgentSessions: () => [],
    runningServiceContainerId: () => undefined,
  });
  mocks.launchBuiltin.mockResolvedValue({ status: 0, signal: null });
  mocks.createDriver.mockImplementation((input: { sessionLockManager: { lock: { assertHeld(): void } } }) => {
    input.sessionLockManager.lock.assertHeld();
    return { launchBuiltin: mocks.launchBuiltin };
  });
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function claudeEvidence(overrides: Record<string, unknown> = {}): string {
  const dir = path.join(stateDir, "claude", "sessions");
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, "4242.json");
  fs.writeFileSync(filePath, `${JSON.stringify({
    pid: 4242,
    sessionId: CLAUDE_SESSION,
    cwd: "/workspace",
    startedAt: Date.parse("2026-07-31T00:00:00.000Z"),
    procStart: "98765",
    name: "fix recovery",
    status: "idle",
    updatedAt: Date.parse("2026-07-31T00:02:00.000Z"),
    ...overrides,
  })}\n`, { mode: 0o600 });
  return filePath;
}

function hostEvidence(id = "rf-20260731-abcdef", overrides: Record<string, unknown> = {}): string {
  const filePath = path.join(stateDir, "sessions", `${id}.json`);
  fs.writeFileSync(filePath, `${JSON.stringify({
    id,
    projectRoot,
    composeProject: composeProjectName(projectRoot),
    command: "claude",
    hostPid: process.pid,
    hostBootId: BOOT,
    hostProcessStart: PROCESS_START,
    startedAt: "2026-07-31T00:00:00.000Z",
    lastSeenAt: "2026-07-31T00:01:00.000Z",
    outcome: "interrupted",
    exitStatus: 137,
    endedAt: "2026-07-31T00:02:00.000Z",
    ...overrides,
  })}\n`, { mode: 0o600 });
  return filePath;
}

function runtimeContext(): RuntimeContext {
  const policyPath = path.join(projectRoot, ".runfree", "network-policy.json");
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  if (!fs.existsSync(policyPath)) {
    fs.writeFileSync(policyPath, `${JSON.stringify({ hosts: [], requests: {}, tokens: {} })}\n`);
  }
  return {
    projectRoot,
    project: {
      config: { ...defaultConfig(), version: 3 },
      paths: { stateDir, sessionsDir: path.join(stateDir, "sessions"), policyPath },
    },
    runtimeRoot: path.join(tmp, "runtime"),
    env,
  } as unknown as RuntimeContext;
}

function firstItem(): RecoveryItem {
  const item = scanRecoveryInventory({ env }).items[0];
  if (!item) throw new Error("missing recovery item fixture");
  return item;
}

const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

function preparedRuntime(context = runtimeContext()) {
  return Object.freeze({ version: 1, context }) as never;
}

describe("resume through session admission", () => {
  test("launches the exact conversation as a new lifecycle session and consumes the claimed evidence", async () => {
    claudeEvidence();
    const context = runtimeContext();
    const item = firstItem();

    const result = await resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item });

    expect(result).toEqual({ status: 0, consumed: true });
    expect(mocks.launchBuiltin).toHaveBeenCalledWith("claude", {
      resume: { conversationId: CLAUDE_SESSION },
    });
    const driverInput = mocks.createDriver.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(driverInput.sessionLockManager).toBeDefined();
    expect(driverInput).not.toHaveProperty("lifecycleLock");
    expect(driverInput).not.toHaveProperty("lifecycleLockLease");
    // Consumption is a host-owned fingerprint marker plus the project-agent
    // epoch; the agent-writable registry entry itself is never unlinked.
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-consumed")).sort()).toEqual([
      "agent-claude.json",
      `${item.id}.json`,
    ]);
    expect(fs.existsSync(path.join(stateDir, "claude", "sessions", "4242.json"))).toBe(true);
  });

  test("retries a transient lifecycle-lock collision before launching the resume", async () => {
    claudeEvidence();
    const context = runtimeContext();
    const held = tryAcquireProjectLifecycleLock(context);
    expect(held).toBeDefined();
    const releaseTimer = setTimeout(() => held?.release(), 25);

    try {
      const result = await resumeInterruptedSessionThroughAdmission({
        preparedRuntime: preparedRuntime(context),
        io,
        item: firstItem(),
      });

      expect(result).toEqual({ status: 0, consumed: true });
      expect(mocks.launchBuiltin).toHaveBeenCalledTimes(1);
    } finally {
      clearTimeout(releaseTimer);
      held?.release();
    }
  });

  test("a failed launch leaves the evidence retryable and releases the claim", async () => {
    claudeEvidence();
    const context = runtimeContext();
    mocks.launchBuiltin.mockResolvedValueOnce({ status: 137, signal: null });

    const first = await resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item: firstItem() });
    expect(first).toEqual({ status: 137, consumed: false });
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-consumed"))).toBe(false);

    const second = await resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item: firstItem() });
    expect(second).toEqual({ status: 0, consumed: true });
    expect(mocks.launchBuiltin).toHaveBeenCalledTimes(2);
  });

  test("a signal death maps to a nonzero status and does not consume evidence", async () => {
    claudeEvidence();
    mocks.launchBuiltin.mockResolvedValueOnce({ status: null, signal: "SIGKILL" });

    const result = await resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(), io, item: firstItem() });

    expect(result).toEqual({ status: 1, consumed: false });
  });

  test("refuses a custom resume command before any claim or launch", async () => {
    hostEvidence(undefined, { command: "codex", agentCommand: "codex --custom" });
    const context = runtimeContext();
    context.project.config.agents.codex = { command: "codex --custom", resumeCommand: "codex custom-resume" };

    await expect(resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item: firstItem() }))
      .rejects.toThrow("custom resume command");
    expect(mocks.launchBuiltin).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(stateDir, "sessions", "recovery-claims"))).toBe(false);
  });

  test("refuses the Claude picker while a live claude session record exists", async () => {
    hostEvidence();
    const context = runtimeContext();
    const projectId = projectHash(projectRoot);
    const recordsRoot = path.join(stateDir, "runtime", "v2", "session-containers");
    fs.mkdirSync(recordsRoot, { recursive: true });
    const sessionId = "rf-20260731-zz1111";
    fs.writeFileSync(path.join(recordsRoot, `${sessionId}.json`), `${JSON.stringify({
      schemaVersion: 4,
      projectId,
      composeProject: `runfree-${projectId}`,
      sessionId,
      sessionIncarnation: "1".repeat(64),
      sessionPrincipal: "2".repeat(64),
      displayName: "Claude Code session",
      command: "claude",
      launchPath: "/usr/local/bin/claude",
      launchArgs: ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
      interactive: true,
      tty: true,
      state: "attached",
      containerName: `runfree-${projectId}-session-${sessionId}`,
      containerId: "3".repeat(64),
      sourceIp: "172.31.90.20",
      selectedAgentImageRef: "runfree/agent-project:test",
      selectedAgentImageId: `sha256:${"a".repeat(64)}`,
      sessionAgentMaterializationDigest: `sha256:${"b".repeat(64)}`,
      selectedAgentImageInputDigest: `sha256:${"c".repeat(64)}`,
      sessionTemplateDigest: `sha256:${"d".repeat(64)}`,
      sessionAgentGenerationDigest: `sha256:${"e".repeat(64)}`,
      controlPlaneGenerationDigest: `sha256:${"f".repeat(64)}`,
      admissionContractEpoch: 3,
      hostPid: process.pid,
      hostBootId: BOOT,
      hostProcessStart: PROCESS_START,
      createdAt: "2026-07-31T00:00:00.000Z",
      admittedAt: "2026-07-31T00:00:10.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-07-31T00:05:10.000Z",
    })}\n`);

    await expect(resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item: firstItem() }))
      .rejects.toThrow("Claude resume picker");
    expect(mocks.launchBuiltin).not.toHaveBeenCalled();
  });

  test("a stale claude record does not block the admission picker: its residue is reclaimed by the launch itself", async () => {
    hostEvidence();
    const context = runtimeContext();
    const projectId = projectHash(projectRoot);
    const recordsRoot = path.join(stateDir, "runtime", "v2", "session-containers");
    fs.mkdirSync(recordsRoot, { recursive: true });
    const sessionId = "rf-20260731-zz2222";
    fs.writeFileSync(path.join(recordsRoot, `${sessionId}.json`), `${JSON.stringify({
      schemaVersion: 4,
      projectId,
      composeProject: `runfree-${projectId}`,
      sessionId,
      sessionIncarnation: "1".repeat(64),
      sessionPrincipal: "2".repeat(64),
      displayName: "Claude Code session",
      command: "claude",
      launchPath: "/usr/local/bin/claude",
      launchArgs: ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
      interactive: true,
      tty: true,
      state: "attached",
      containerName: `runfree-${projectId}-session-${sessionId}`,
      containerId: "3".repeat(64),
      sourceIp: "172.31.90.20",
      selectedAgentImageRef: "runfree/agent-project:test",
      selectedAgentImageId: `sha256:${"a".repeat(64)}`,
      sessionAgentMaterializationDigest: `sha256:${"b".repeat(64)}`,
      selectedAgentImageInputDigest: `sha256:${"c".repeat(64)}`,
      sessionTemplateDigest: `sha256:${"d".repeat(64)}`,
      sessionAgentGenerationDigest: `sha256:${"e".repeat(64)}`,
      controlPlaneGenerationDigest: `sha256:${"f".repeat(64)}`,
      admissionContractEpoch: 3,
      hostPid: process.pid,
      // A previous boot: the owning host process is provably gone, so this is
      // reclaimable residue, not a live session.
      hostBootId: "linux:99999999-8888-7777-6666-555555555555",
      hostProcessStart: PROCESS_START,
      createdAt: "2026-07-31T00:00:00.000Z",
      admittedAt: "2026-07-31T00:00:10.000Z",
      leaseGeneration: "4".repeat(32),
      leaseExpiresAt: "2026-07-31T00:05:10.000Z",
    })}\n`);

    const result = await resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item: firstItem() });

    expect(result.status).toBe(0);
    expect(mocks.launchBuiltin).toHaveBeenCalledTimes(1);
  });

  test("re-validates under the claim and refuses an item that went active after the pre-claim guard", async () => {
    hostEvidence();
    const context = runtimeContext();
    const item = firstItem();
    const activeSession = {
      sessionId: item.sourceId,
      command: "claude --resume",
      containerTty: "pts/0",
      name: "Claude session",
      processCount: 1,
    };
    // Interrupted at the pre-claim guard, live by the time the under-lock
    // recheck runs — the window a fresh launch can occupy while no exclusion
    // is held.
    const activeAgentSessions = vi.fn()
      .mockReturnValueOnce([])
      .mockReturnValue([activeSession]);
    mocks.createRuntimeDocker.mockReturnValue({
      activeAgentSessions,
      runningServiceContainerId: () => undefined,
    });

    await expect(resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item }))
      .rejects.toThrow("became active before the resume launch");
    expect(mocks.launchBuiltin).not.toHaveBeenCalled();
    // The claim was taken for the recheck and released on the failure.
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-claims"))).toEqual([]);
  });

  test("legacy shared-agent recovery evidence refuses when interruption is not provable", async () => {
    claudeEvidence();
    const context = runtimeContext();
    mocks.createRuntimeDocker.mockReturnValue({
      activeAgentSessions: () => [],
      // Explicit pre-cutover evidence remains unverified while its shared
      // agent container is still running and cannot be probed.
      runningServiceContainerId: () => "agent-id",
    });

    await expect(resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(context), io, item: firstItem() }))
      .rejects.toThrow("requires proven interruption");
    expect(mocks.launchBuiltin).not.toHaveBeenCalled();
  });

  test("refuses a non-built-in agent before any Docker or claim effect", async () => {
    hostEvidence(undefined, { command: "custom-agent" });

    await expect(resumeInterruptedSessionThroughAdmission({ preparedRuntime: preparedRuntime(), io, item: firstItem() }))
      .rejects.toThrow("only built-in agents");
    expect(mocks.createDriver).not.toHaveBeenCalled();
  });
});
