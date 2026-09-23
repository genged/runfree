import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { defaultConfig } from "../config.ts";
import { composeProjectName, projectHash } from "../project-identity.ts";
import {
  acquireRecoveryClaim,
  buildResumeLaunchPlan,
  classifyRecoveryItemLive,
  consumeRecoveryEvidence,
  formatRecoveryInventory,
  liveClaudeSessionBlocksPicker,
  RECOVERY_LIMITS,
  recoveryInventoryJson,
  runWithRecoveryClaim,
  scanRecoveryInventory,
  sessionContainerRecoveryLiveInputs,
  writeProjectRecoveryPointer,
  type RecoveryItem,
} from "./recovery.ts";
import type { SessionContainerRecordV2 } from "./session-containers.ts";
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
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-recovery-"));
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
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

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
    ...overrides,
  })}\n`, { mode: 0o600 });
  return filePath;
}

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
      paths: {
        stateDir,
        sessionsDir: path.join(stateDir, "sessions"),
        policyPath,
        controlProxyDir: path.join(stateDir, "control", "proxy"),
      },
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

describe("bounded offline recovery inventory", () => {
  test("unions host and Claude evidence without Docker and emits stable machine ids", () => {
    hostEvidence();
    claudeEvidence();

    const first = scanRecoveryInventory({ env });
    const second = scanRecoveryInventory({ env });

    expect(first.items).toHaveLength(2);
    expect(first.items.map((item) => item.id)).toEqual(second.items.map((item) => item.id));
    expect(first.items.every((item) => item.state === "active" || item.state === "unverified")).toBe(true);
    expect(JSON.parse(recoveryInventoryJson(first))).toMatchObject({ truncated: false, invalidFiles: 0 });
  });

  test("skips symlinks, hard links, oversized files, malformed schemas, and unsafe conversation ids", () => {
    const valid = claudeEvidence();
    fs.symlinkSync(valid, path.join(path.dirname(valid), "4243.json"));
    fs.linkSync(valid, path.join(path.dirname(valid), "4244.json"));
    fs.writeFileSync(path.join(path.dirname(valid), "4245.json"), "x".repeat(70 * 1024));
    fs.writeFileSync(path.join(path.dirname(valid), "4246.json"), JSON.stringify({ sessionId: "$(touch /tmp/no)" }));

    const inventory = scanRecoveryInventory({ env });

    // The hard link makes both names unsafe; no registry entry survives.
    expect(inventory.items).toEqual([]);
    expect(inventory.invalidFiles).toBeGreaterThanOrEqual(4);
  });

  test("rejects a symlinked agent-writable registry directory ancestor", () => {
    claudeEvidence();
    const claudeDir = path.join(stateDir, "claude");
    const outside = path.join(tmp, "outside-claude-state");
    fs.renameSync(claudeDir, outside);
    fs.symlinkSync(outside, claudeDir, "dir");

    expect(scanRecoveryInventory({ env }).items).toEqual([]);
  });

  test("sanitizes agent-controlled names in text output", () => {
    claudeEvidence({ name: "safe\u001b[2J\nFAKE PROMPT" });

    const output = formatRecoveryInventory(scanRecoveryInventory({ env }));

    expect(output).toContain("safeFAKE PROMPT");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\nFAKE PROMPT");
  });

  test("invalid project mappings are listable but never actionable", () => {
    hostEvidence();
    fs.writeFileSync(
      path.join(stateDir, "project.json"),
      `${JSON.stringify({ projectRoot: path.join(tmp, "other"), updatedAt: "2026-07-31T00:00:00.000Z" })}\n`,
    );

    expect(firstItem()).toMatchObject({ state: "unrecoverable", reason: expect.stringContaining("mapping") });
  });

  test("stops before reading past the per-kind file budget and reports truncation", () => {
    // Exercise the boundary with real files without thousands of synchronous
    // writes, secure reads, and unlinks competing with the parallel suite.
    const originalLimit = RECOVERY_LIMITS.maxFilesPerKindPerProject;
    Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: 2 });
    const open = vi.spyOn(fs, "openSync");
    try {
      const files = [hostEvidence("rf-20260731-000000"), hostEvidence("rf-20260731-000001")];
      const atLimit = scanRecoveryInventory({ env });
      expect(atLimit.items).toHaveLength(2);
      expect(atLimit.truncated).toBe(false);
      files.push(hostEvidence("rf-20260731-000002"));
      claudeEvidence();
      open.mockClear();

      const inventory = scanRecoveryInventory({ env });
      const hostItems = inventory.items.filter((item) => item.evidenceKind === "host");

      expect(hostItems).toHaveLength(2);
      expect(inventory.items.filter((item) => item.evidenceKind === "claude")).toHaveLength(1);
      expect(inventory.truncated).toBe(true);
      // The excess file must never be opened, even if its result is discarded.
      expect(open.mock.calls.map(([file]) => file).filter((file) => files.includes(String(file))).sort())
        .toEqual(hostItems.map((item) => item.evidencePath).sort());
    } finally {
      open.mockRestore();
      Object.assign(RECOVERY_LIMITS, { maxFilesPerKindPerProject: originalLimit });
    }
  });
});

describe("live classification and launch plans", () => {
  test("requires a successful container-session probe before host evidence becomes interrupted", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();
    const io = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      agentContainerId: "agent-id",
    }).state).toBe("unverified");
    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [{
        sessionId: item.sourceId,
        command: "Claude",
        containerTty: "pts/0",
        name: "Claude recovery",
        processCount: 1,
      }],
    }).state).toBe("active");
  });

  test("a live PID with incomplete identity remains unverified even when no container is running", () => {
    hostEvidence(undefined, { hostProcessStart: undefined });
    const item = firstItem();

    expect(classifyRecoveryItemLive(
      item,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    )).toMatchObject({ state: "unverified", reason: expect.stringContaining("identity") });
  });

  test("a stopped or absent agent container makes valid Claude registry evidence interrupted", () => {
    claudeEvidence();
    const item = firstItem();
    const classified = classifyRecoveryItemLive(
      item,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    );

    expect(classified.state).toBe("interrupted");
  });

  test("a killed host client never makes its still-running container session resumable", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();
    fs.mkdirSync(path.join(context.runtimeRoot, "agent"), { recursive: true });
    fs.writeFileSync(path.join(context.runtimeRoot, "agent", "inspect-active-sessions.sh"), "probe");
    const io = {
      capture: () => ({
        status: 0,
        stdout: `123\tpts/0\t${item.sourceId}\tclaude --resume\n`,
        stderr: "",
      }),
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      agentContainerId: "agent-id",
    }).state).toBe("active");
  });

  test("builds descriptor-owned argv and never interpolates the conversation id into shell source", () => {
    claudeEvidence();
    const item = firstItem();
    const plan = buildResumeLaunchPlan(runtimeContext(), item);

    expect(plan).toMatchObject({ precision: "exact", env: {} });
    expect(plan?.argv).toEqual([
      "claude",
      "--dangerously-skip-permissions",
      "--add-dir",
      "/runfree/inbox",
      "--resume",
      CLAUDE_SESSION,
    ]);
    expect(plan?.argv.at(-1)).toBe(item.conversationId);
  });

  test("preserves the managed Claude inbox grant in picker-based recovery", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });

    expect(buildResumeLaunchPlan(runtimeContext(), firstItem())).toMatchObject({
      precision: "picker",
      argv: [
        "claude",
        "--dangerously-skip-permissions",
        "--add-dir",
        "/runfree/inbox",
        "--resume",
      ],
    });
  });

  test("recognizes the previous built-in Claude command as managed", () => {
    claudeEvidence();
    const context = runtimeContext();
    context.project.config.agents.claude = { command: "claude --dangerously-skip-permissions" };

    expect(buildResumeLaunchPlan(context, firstItem())).toMatchObject({
      precision: "exact",
      argv: expect.arrayContaining(["--add-dir", "/runfree/inbox", "--resume", CLAUDE_SESSION]),
    });
  });

  test("requires an explicit resumeCommand for a customized built-in command", () => {
    hostEvidence(undefined, { command: "codex", agentCommand: "codex --custom" });
    const item = firstItem();
    const context = runtimeContext();
    context.project.config.agents.codex = { command: "codex --custom" };

    expect(buildResumeLaunchPlan(context, item)).toBeUndefined();

    context.project.config.agents.codex = { command: "codex --custom", resumeCommand: "codex custom-resume" };
    expect(buildResumeLaunchPlan(context, item)).toMatchObject({
      argv: ["zsh", "-c", "exec zsh -c \"$RUNFREE_RESUME_COMMAND\""],
      env: { RUNFREE_RESUME_COMMAND: "codex custom-resume" },
    });
  });
});

function sessionRecord(overrides: Partial<SessionContainerRecordV2> = {}): SessionContainerRecordV2 {
  const projectId = projectHash(projectRoot);
  const sessionId = (overrides.sessionId as string | undefined) ?? "rf-20260731-abcdef";
  return {
    schemaVersion: 4,
    projectId,
    composeProject: `runfree-${projectId}`,
    sessionId,
    sessionIncarnation: "1".repeat(64),
    sessionPrincipal: "2".repeat(64),
    displayName: "Claude Code resume",
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
    ...overrides,
  } as SessionContainerRecordV2;
}

describe("per-session lifecycle registry classification", () => {
  const failingIo = { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO;

  test("a live lifecycle record makes its host evidence active without probing any container", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const io = {
      capture: () => {
        throw new Error("classification must not exec into a session container");
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(firstItem(), runtimeContext(), io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("active");
  });

  test("a stale lifecycle record proves interruption where the legacy probe could not", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const stale = sessionRecord({ hostBootId: "linux:99999999-8888-7777-6666-555555555555" });

    // Without the registry decision this item would be unverified: the shared
    // agent inspector asset is absent, so the legacy probe answers "unknown".
    expect(classifyRecoveryItemLive(firstItem(), runtimeContext(), failingIo, {
      activeSessions: [],
      agentContainerId: "agent-id",
      sessionContainers: { records: [stale], unreadable: false },
    }).state).toBe("interrupted");
  });

  test("session-world evidence with no surviving record is interrupted, and unverified when the registry is partial", () => {
    hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
      sessionContainerName: `runfree-${projectHash(projectRoot)}-session-rf-20260731-abcdef`,
    });
    const item = firstItem();
    const context = runtimeContext();

    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      agentContainerId: "agent-id",
      sessionContainers: { records: [], unreadable: false },
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      sessionContainers: { records: [], unreadable: true },
    })).toMatchObject({ state: "unverified", reason: expect.stringContaining("registry") });
  });

  test("a revoking record is teardown in progress while its owner lives, interrupted once the owner is gone", () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();

    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord({ state: "revoking" })], unreadable: false },
    })).toMatchObject({ state: "unverified", reason: expect.stringContaining("teardown") });
    expect(classifyRecoveryItemLive(item, context, failingIo, {
      activeSessions: [],
      sessionContainers: {
        records: [sessionRecord({ state: "revoking", hostBootId: "linux:99999999-8888-7777-6666-555555555555" })],
        unreadable: false,
      },
    }).state).toBe("interrupted");
  });

  test("Claude registry evidence is probed inside record-bound claude session containers", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const containerId = "3".repeat(64);
    const io = {
      capture: (_command: string, args: string[]) => {
        if (args[0] === "inspect") {
          expect(args.at(-1)).toBe(containerId);
          return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        }
        expect(args).toContain(containerId);
        return { status: 0, stdout: "98765", stderr: "" };
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("active");
  });

  test("Claude registry evidence with a dead pid in every candidate container is interrupted, and a partial registry is not", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const io = {
      capture: (_command: string, args: string[]) => {
        if (args[0] === "inspect") return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        return { status: 2, stdout: "", stderr: "" };
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: true },
    }).state).toBe("unverified");
  });

  test("a record whose container Docker confirms absent is decisively gone, not indecisive", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    // The residue a crash between container removal and record deletion
    // leaves: a stale record naming a container the daemon no longer knows.
    const absentIo = {
      capture: () => ({ status: 1, stdout: "", stderr: `Error: No such object: ${"3".repeat(64)}` }),
    } as unknown as RuntimeIO;
    const daemonDownIo = {
      capture: () => ({ status: 1, stdout: "", stderr: "Cannot connect to the Docker daemon" }),
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(item, context, absentIo, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("interrupted");
    expect(classifyRecoveryItemLive(item, context, daemonDownIo, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }).state).toBe("unverified");
  });

  test("resume lineage on crashed resume evidence yields an exact item; a corrupted value degrades to picker", () => {
    hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
      resumeConversationId: CLAUDE_SESSION,
    });
    const context = runtimeContext();
    const exact = firstItem();
    expect(exact.conversationId).toBe(CLAUDE_SESSION);
    expect(buildResumeLaunchPlan(context, exact)).toMatchObject({
      precision: "exact",
      argv: expect.arrayContaining(["--resume", CLAUDE_SESSION]),
    });

    hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
      resumeConversationId: "../../etc/passwd",
    });
    const degraded = firstItem();
    expect(degraded.conversationId).toBeUndefined();
    expect(buildResumeLaunchPlan(context, degraded)).toMatchObject({ precision: "picker" });
  });

  test("one classification pass spends a bounded probe budget and degrades to unverified when it runs out", () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const records = Array.from({ length: 20 }, (_, index) => sessionRecord({
      sessionId: `rf-20260731-c${String(index).padStart(5, "0")}`,
      containerId: index.toString(16).padStart(64, "0"),
    }));
    let captures = 0;
    const io = {
      capture: (_command: string, args: string[]) => {
        captures += 1;
        if (args[0] === "inspect") return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        return { status: 2, stdout: "", stderr: "" };
      },
    } as unknown as RuntimeIO;

    const classified = classifyRecoveryItemLive(item, context, io, {
      activeSessions: [],
      sessionContainers: { records, unreadable: false },
    });

    // 20 candidates want 40 captures; the pass budget refuses the tail, and a
    // refused probe proves nothing — so the item is unverified, not guessed
    // interrupted from a partial sweep.
    expect(captures).toBe(32);
    expect(classified.state).toBe("unverified");
  });

  test("one pass inspects each candidate container once, however many items name it", () => {
    claudeEvidence();
    const secondRegistry = path.join(stateDir, "claude", "sessions", "4343.json");
    fs.writeFileSync(secondRegistry, `${JSON.stringify({
      pid: 4343,
      sessionId: "22222222-3333-4444-8555-666666666666",
      cwd: "/workspace",
      startedAt: Date.parse("2026-07-31T00:00:00.000Z"),
      procStart: "13579",
      updatedAt: Date.parse("2026-07-31T00:02:00.000Z"),
    })}\n`, { mode: 0o600 });
    const context = runtimeContext();
    const items = scanRecoveryInventory({ env }).items;
    expect(items).toHaveLength(2);
    let inspects = 0;
    const io = {
      capture: (_command: string, args: string[]) => {
        if (args[0] === "inspect") {
          inspects += 1;
          return { status: 0, stdout: "true\t2026-07-31T00:00:30.000000000Z", stderr: "" };
        }
        return { status: 2, stdout: "", stderr: "" };
      },
    } as unknown as RuntimeIO;
    const live = {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    };

    for (const item of items) classifyRecoveryItemLive(item, context, io, live);

    expect(inspects).toBe(1);
  });

  test("a codex session container is never a Claude probe candidate", () => {
    claudeEvidence();
    const codexRecord = sessionRecord({
      command: "codex",
      launchPath: "/usr/local/bin/codex",
      launchArgs: ["--dangerously-bypass-approvals-and-sandbox"],
    });
    const io = {
      capture: () => {
        throw new Error("no candidate container should be probed");
      },
    } as unknown as RuntimeIO;

    expect(classifyRecoveryItemLive(firstItem(), runtimeContext(), io, {
      activeSessions: [],
      sessionContainers: { records: [codexRecord], unreadable: false },
    }).state).toBe("interrupted");
  });

  test("the Claude picker is blocked by live and stale claude records and by a partial registry", () => {
    const context = runtimeContext();
    const stale = sessionRecord({ hostBootId: "linux:99999999-8888-7777-6666-555555555555" });

    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    })).toBe(true);
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [], unreadable: true },
    })).toBe(true);
    // A dead host owner is not proof the container died with it: the ordinary
    // attached-crash residue is a stale record whose claude still runs, so by
    // default it blocks exactly like a live one.
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [stale], unreadable: false },
    })).toBe(true);
    // Only a caller whose launch reclaims residue first may ignore stale
    // records — and even it must still be blocked by a live one.
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [stale], unreadable: false },
    }, { staleRecordsReclaimedBeforeLaunch: true })).toBe(false);
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord()], unreadable: false },
    }, { staleRecordsReclaimedBeforeLaunch: true })).toBe(true);
    expect(liveClaudeSessionBlocksPicker(context, {
      activeSessions: [],
      sessionContainers: { records: [sessionRecord({ state: "revoking" })], unreadable: false },
    })).toBe(false);
  });

  test("a symlinked records root reads as an unprovable registry, not an empty one", () => {
    const context = runtimeContext();
    const runtimeV2 = path.join(stateDir, "runtime", "v2");
    fs.mkdirSync(runtimeV2, { recursive: true });
    const outside = path.join(tmp, "outside-records");
    fs.mkdirSync(outside, { recursive: true });
    fs.symlinkSync(outside, path.join(runtimeV2, "session-containers"), "dir");

    const inputs = sessionContainerRecoveryLiveInputs(context);

    expect(inputs.unreadable).toBe(true);
    expect(inputs.records).toEqual([]);
  });

  test("building the registry inputs is strictly read-only, even over an unreadable record", () => {
    const context = runtimeContext();
    const recordsRoot = path.join(stateDir, "runtime", "v2", "session-containers");
    fs.mkdirSync(recordsRoot, { recursive: true });
    const record = sessionRecord();
    fs.writeFileSync(path.join(recordsRoot, `${record.sessionId}.json`), `${JSON.stringify(record)}\n`);
    fs.writeFileSync(path.join(recordsRoot, "rf-20260731-zz9999.json"), "not json");

    const inputs = sessionContainerRecoveryLiveInputs(context);

    expect(inputs.unreadable).toBe(true);
    expect(inputs.records.map((entry) => entry.sessionId)).toEqual([record.sessionId]);
    // The corrupted record stays exactly where it was: no quarantine, no unlink.
    expect(fs.readFileSync(path.join(recordsRoot, "rf-20260731-zz9999.json"), "utf8")).toBe("not json");
    expect(fs.existsSync(path.join(stateDir, "runtime", "v2", "session-containers-quarantine"))).toBe(false);
  });
});

describe("transactional claims and evidence consumption", () => {
  test("only one selector can claim an item", async () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    const item = firstItem();
    const context = runtimeContext();

    const first = await acquireRecoveryClaim(context, item);
    const second = await acquireRecoveryClaim(context, item);

    expect(first).toBeDefined();
    expect(second).toBeUndefined();
    expect(fs.existsSync(first?.path ?? "")).toBe(true);
    first?.release();
    expect(fs.existsSync(first?.path ?? "")).toBe(false);
  });

  test("a selector waiting on the lifecycle lock cannot claim Claude evidence consumed meanwhile", async () => {
    claudeEvidence();
    const item = firstItem();
    const context = runtimeContext();
    const held = tryAcquireProjectLifecycleLock(context);
    expect(held).toBeDefined();
    let actionCalls = 0;

    try {
      const waiting = runWithRecoveryClaim(context, item, () => {
        actionCalls += 1;
        return 0;
      });
      expect(consumeRecoveryEvidence(item)).toBe(true);
      held?.release();

      await expect(waiting).resolves.toBeUndefined();
      expect(actionCalls).toBe(0);
    } finally {
      held?.release();
    }
  });

  test("serializes host and registry representations at the project-agent scope", async () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    claudeEvidence();
    const items = scanRecoveryInventory({ env }).items;
    const host = items.find((item) => item.evidenceKind === "host");
    const registry = items.find((item) => item.evidenceKind === "claude");
    if (!host || !registry) throw new Error("missing paired recovery fixtures");

    const first = await acquireRecoveryClaim(runtimeContext(), host);
    expect(first).toBeDefined();
    expect(await acquireRecoveryClaim(runtimeContext(), registry)).toBeUndefined();
    first?.release();
    expect(await acquireRecoveryClaim(runtimeContext(), registry)).toBeDefined();
  });

  test("never unlinks evidence replaced after the claim", async () => {
    const evidencePath = hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    const item = firstItem();
    const claim = await acquireRecoveryClaim(runtimeContext(), item);
    const replacement = `${evidencePath}.replacement`;
    fs.writeFileSync(replacement, fs.readFileSync(evidencePath));
    fs.renameSync(replacement, evidencePath);

    expect(consumeRecoveryEvidence(item)).toBe(false);
    expect(fs.existsSync(evidencePath)).toBe(true);
    claim?.release();
  });

  test("failed and thrown resume actions release the claim but keep retryable evidence", async () => {
    const evidencePath = hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    const item = firstItem();
    const context = runtimeContext();

    await expect(runWithRecoveryClaim(context, item, () => 17)).resolves.toEqual({ status: 17, consumed: false });
    expect(fs.existsSync(evidencePath)).toBe(true);
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-claims"))).toEqual([]);

    await expect(runWithRecoveryClaim(context, item, () => {
      throw new Error("startup failed");
    })).rejects.toThrow("startup failed");
    expect(fs.existsSync(evidencePath)).toBe(true);
    expect(fs.readdirSync(path.join(stateDir, "sessions", "recovery-claims"))).toEqual([]);
  });

  test("status zero consumes exactly the claimed evidence", async () => {
    const evidencePath = hostEvidence(undefined, {
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2026-07-31T00:02:00.000Z",
    });
    const item = firstItem();

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({
      status: 0,
      consumed: true,
    });
    expect(fs.existsSync(evidencePath)).toBe(false);
  });

  test("Claude consumption leaves agent state untouched and hides only the exact fingerprint", async () => {
    const evidencePath = claudeEvidence();
    const item = firstItem();

    await expect(runWithRecoveryClaim(runtimeContext(), item, () => 0)).resolves.toEqual({
      status: 0,
      consumed: true,
    });
    expect(fs.existsSync(evidencePath)).toBe(true);
    expect(scanRecoveryInventory({ env }).items).toEqual([]);

    const replacement = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    replacement.name = "new registry generation";
    fs.writeFileSync(evidencePath, `${JSON.stringify(replacement)}\n`);
    expect(scanRecoveryInventory({ env }).items).toHaveLength(1);
  });

  test("an exact Claude recovery leaves older host-only fallback evidence non-actionable", async () => {
    hostEvidence(undefined, { outcome: "interrupted", exitStatus: 137, endedAt: "2026-07-31T00:02:00.000Z" });
    claudeEvidence();
    const exact = scanRecoveryInventory({ env }).items.find((item) => item.evidenceKind === "claude");
    if (!exact) throw new Error("missing exact Claude recovery fixture");
    await runWithRecoveryClaim(runtimeContext(), exact, () => 0);

    const host = scanRecoveryInventory({ env }).items.find((item) => item.evidenceKind === "host");
    if (!host) throw new Error("missing host recovery fixture");
    expect(classifyRecoveryItemLive(
      host,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    )).toMatchObject({ state: "unverified", reason: expect.stringContaining("exact Claude recovery") });
  });

  test("host evidence updated after the exact-recovery epoch remains actionable", async () => {
    claudeEvidence();
    const exact = firstItem();
    await runWithRecoveryClaim(runtimeContext(), exact, () => 0);
    hostEvidence("rf-20260731-overlap", {
      startedAt: "2026-07-31T00:00:00.000Z",
      lastSeenAt: "2026-07-31T00:01:00.000Z",
      outcome: "interrupted",
      exitStatus: 137,
      endedAt: "2100-07-31T00:02:00.000Z",
    });
    const host = firstItem();

    expect(classifyRecoveryItemLive(
      host,
      runtimeContext(),
      { capture: () => ({ status: 1, stdout: "", stderr: "" }) } as unknown as RuntimeIO,
      { activeSessions: [] },
    ).state).toBe("interrupted");
  });

  test("refuses recovery pointer publication without a selected effective control", () => {
    // Negative-before-side-effect: recovery state publication requires the
    // selected effective control's policy to validate first; with no selection
    // at all it must fail closed and write nothing.
    const context = runtimeContext();
    const pointerPath = path.join(stateDir, "project.json");
    fs.rmSync(pointerPath);

    expect(() => writeProjectRecoveryPointer(context)).toThrow("selected effective controls are required");
    expect(fs.existsSync(pointerPath)).toBe(false);
  });
});
