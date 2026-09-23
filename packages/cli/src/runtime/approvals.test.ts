import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import { APPROVALS_DECISIONS_DIR, APPROVALS_PENDING_DIR, APPROVALS_PROCESS_EPOCH_FILE } from "@runfree/runtime-contracts/write-approvals";
import type { ApprovalDecisionRecord, PendingApprovalRecord } from "@runfree/runtime-contracts/write-approvals";
import { projectInfo } from "../config.ts";
import {
  actionPhrase,
  approvalsClearDeny,
  approvalsRuntime,
  approveRuntime,
  clearPlanLines,
  grantCoverageLabel,
  decisionSummary,
  detailLines,
  pendingTableLines,
  saveMcpRuleForApproval,
  standingAuthorityLines,
  WRITE_CONTROL_SCRIPT,
} from "./approvals.ts";
import { printWriteApprovalStatusLine } from "../runtime.ts";
import { ROOT_UID_GID } from "./constants.ts";
import { mcpRulesPath, readMcpRules } from "./mcp.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function mcpToolRecord(): PendingApprovalRecord {
  return {
    v: 1,
    id: "0123456789abcdef0123456789abcdef",
    host: "mcp.posthog.com",
    method: "POST",
    path: "/mcp",
    category: "mcp-tool",
    tokenNames: ["POSTHOG_MCP"],
    mcp: {
      agent: "codex",
      serverId: "codex:user:posthog",
      server: "posthog",
      method: "tools/call",
      tool: "create_feature_flag",
    },
    generation: "sha256:policy;mcp=sha256:mcp",
    heldAt: "2026-07-08T22:00:00.000Z",
    expiresAt: "2026-07-08T22:02:00.000Z",
  };
}

function tempMcpContext(): RuntimeContext {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approval-rules-"));
  tempDirs.push(tmp);
  const projectRoot = path.join(tmp, "project");
  const codexHome = path.join(tmp, "home", ".codex");
  fs.mkdirSync(projectRoot, { recursive: true });
  fs.mkdirSync(codexHome, { recursive: true });
  fs.writeFileSync(path.join(codexHome, "config.toml"), [
    "[mcp_servers.posthog]",
    'url = "https://mcp.posthog.com/mcp"',
    "",
  ].join("\n"));
  const env = {
    HOME: path.join(tmp, "home"),
    CODEX_HOME: codexHome,
    XDG_CONFIG_HOME: path.join(tmp, "config"),
    XDG_STATE_HOME: path.join(tmp, "state"),
  };
  const project = projectInfo(projectRoot, env);
  expect(project.paths.stateDir).toContain(tmp);
  return {
    projectRoot,
    project,
    runtimeRoot: path.join(tmp, "runtime"),
    env,
  };
}

function captureResult(status: number, stdout = "", stderr = ""): CaptureResult {
  return { status, stdout, stderr };
}

function approvalIo(record: PendingApprovalRecord, adminStatus: Partial<Record<"prepare" | "converge-proxy-policy", number>> = {}): RuntimeIO & {
  decisions: ApprovalDecisionRecord[];
  events: string[];
} {
  const events: string[] = [];
  const decisions: ApprovalDecisionRecord[] = [];
  return {
    decisions,
    events,
    admin: async (intent) => {
      events.push(intent.kind);
      return adminStatus[intent.kind as "prepare" | "converge-proxy-policy"] ?? 0;
    },
    capture: (_command, args) => {
      if (args[0] === "ps") return captureResult(0, "proxy-id\n");
      if (args[0] === "exec" && args.includes("node") && args.includes("-e")) {
        const maybeDecision = args.at(-1);
        if (typeof maybeDecision === "string" && maybeDecision.startsWith("{")) {
          events.push("write-decision");
          decisions.push({ ...(JSON.parse(maybeDecision) as Omit<ApprovalDecisionRecord, "decidedAt">), decidedAt: "2026-07-09T00:00:00.000Z" });
          return captureResult(0, "ok\n");
        }
        return captureResult(0, `${JSON.stringify([JSON.stringify(record)])}\n`);
      }
      return captureResult(1, "", `unexpected docker args: ${args.join(" ")}`);
    },
    commandExists: () => true,
    confirm: () => false,
    run: () => 0,
  };
}

describe("approval rendering", () => {
  test("renders MCP tool calls as semantic MCP operations", () => {
    const record = mcpToolRecord();

    expect(actionPhrase(record)).toBe('call the MCP tool "create_feature_flag" on posthog');
    expect(pendingTableLines([record], Date.parse("2026-07-08T22:00:04.000Z")).join("\n")).toContain(
      'call the MCP tool "create_feature_flag" on posthog',
    );
    expect(detailLines(record, Date.parse("2026-07-08T22:00:04.000Z"))).toEqual([
      "  server:  posthog - codex (mcp.posthog.com/mcp)",
      '  tool:    create_feature_flag',
      '  action:  call the MCP tool "create_feature_flag" on posthog',
      "  what:    tools/call via POST /mcp",
      "  token:   POSTHOG_MCP (proxy-managed)",
      "  expires: in 116s (denied on timeout)",
      "  rule:    always allow this tool: runfree mcp rules codex posthog --tool create_feature_flag --write allow",
      "  rule:    allow all tools on this server: runfree mcp rules codex posthog --write allow",
    ]);
  });

  test("summarizes MCP session and saved-rule decisions with MCP scope", () => {
    const record = mcpToolRecord();
    const sessionDecision: Omit<ApprovalDecisionRecord, "decidedAt"> = {
      v: 1,
      id: record.id,
      decision: "approve",
      scope: "session",
      mcpScope: "tool",
    };
    const savedRuleDecision: Omit<ApprovalDecisionRecord, "decidedAt"> = {
      v: 1,
      id: record.id,
      decision: "approve",
      scope: "request",
      saveMcpRule: "tool",
    };

    // The session is the authority subject; the internal key stays out of the
    // operator-facing summary.
    expect(decisionSummary(record, sessionDecision)).toEqual([
      'approved 0123456789abcdef0123456789abcdef: call the MCP tool "create_feature_flag" on posthog',
      '  scope: "create_feature_flag" on posthog until this session ends',
    ]);
    expect(decisionSummary(record, savedRuleDecision)).toEqual([
      'approved 0123456789abcdef0123456789abcdef: call the MCP tool "create_feature_flag" on posthog',
      '  saved rule: always allow "create_feature_flag" on posthog',
      "  change it: runfree mcp rules codex posthog --tool create_feature_flag --write ask",
    ]);
  });

  test("persists saved MCP tool and server rules in host-owned state", () => {
    const context = tempMcpContext();
    const record = mcpToolRecord();

    saveMcpRuleForApproval(record, "tool", context);
    saveMcpRuleForApproval(record, "server-tools", context);

    const rules = Object.values(readMcpRules(context.projectRoot, mcpRulesPath(context.project.paths.stateDir)).rules);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({
      agent: "codex",
      defaultToolWriteAction: "allow",
      server: "posthog",
      source: "user",
      tools: {
        create_feature_flag: { writeAction: "allow" },
      },
    });
  });

  test("saved-rule approval regenerates and reloads policy before deciding the held request", async () => {
    const context = tempMcpContext();
    const io = approvalIo(mcpToolRecord());

    await expect(approveRuntime({
      deny: false,
      id: "01234567",
      saveMcpRule: "tool",
    }, context, io)).resolves.toBe(0);

    expect(io.events).toEqual(["prepare", "converge-proxy-policy", "write-decision"]);
    expect(io.decisions).toMatchObject([{ decision: "approve", id: mcpToolRecord().id, saveMcpRule: "tool", scope: "request" }]);
    const rules = Object.values(readMcpRules(context.projectRoot, mcpRulesPath(context.project.paths.stateDir)).rules);
    expect(rules[0]).toMatchObject({
      tools: {
        create_feature_flag: { writeAction: "allow" },
      },
    });
  });

  test("saved-rule approval leaves the request pending when policy regeneration or reload fails", async () => {
    for (const [failedStep, expectedEvents] of [
      ["prepare", ["prepare"]],
      ["converge-proxy-policy", ["prepare", "converge-proxy-policy"]],
    ] as const) {
      const context = tempMcpContext();
      const io = approvalIo(mcpToolRecord(), { [failedStep]: 1 });

      await expect(approveRuntime({
        deny: false,
        id: "01234567",
        saveMcpRule: "server-tools",
      }, context, io)).resolves.toBe(1);

      expect(io.events).toEqual(expectedEvents);
      expect(io.decisions).toEqual([]);
    }
  });

  test("refuses session-wide scopes for a request-only principal before any decision is written", async () => {
    // The proxy would refuse the decision after the file landed, at which point
    // the CLI had already printed a session-wide success it never had — the
    // recorded cutover defect. The refusal now happens first, names the
    // principal, and leaves nothing decided.
    const requestOnly: PendingApprovalRecord = {
      ...mcpToolRecord(),
      mcp: undefined,
      requestOnlyPrincipal: { kind: "anonymous-utility", label: "the utility forwarder" },
    };
    // A record with no session and no typed principal (a shape the proxy no
    // longer produces) gets the same refusal: only a session-backed hold may
    // receive a session-wide decision.
    const sessionless: PendingApprovalRecord = { ...mcpToolRecord(), mcp: undefined };
    for (const record of [requestOnly, sessionless]) {
      for (const scope of ["deny-session", "session"] as const) {
        const io = approvalIo(record);
        await expect(approveRuntime({ deny: false, id: "01234567", scope }, tempMcpContext(), io))
          .rejects.toThrow(/request-only principal.*request-scoped decisions/su);
        expect(io.decisions).toEqual([]);
      }
    }
  });

  test("host-scope summaries state the session subject and the real duration", () => {
    const record: PendingApprovalRecord = {
      ...mcpToolRecord(),
      host: "api.github.com",
      category: "method",
      mcp: undefined,
      session: GRANT_SESSION,
    };
    expect(decisionSummary(record, { v: 1, id: record.id, decision: "approve", scope: "session" })).toEqual([
      `approved ${record.id}: make a change on GitHub`,
      "  scope: all writes to this host until this session ends",
    ]);
  });

  test("deny-session summaries for a session-backed hold name that session, not the runtime", () => {
    // Under source-ip identity a session-wide deny latches exactly one
    // session; claiming runtime coverage here was the recorded cutover defect
    // (CLI success message for authority the proxy never granted that way).
    const record: PendingApprovalRecord = {
      ...mcpToolRecord(),
      host: "api.github.com",
      category: "method",
      mcp: undefined,
      session: {
        sessionId: "rf-20260817-abcdef",
        name: "payments",
        command: "claude",
        startedAt: "2026-08-17T00:00:00.000Z",
      },
    };
    expect(decisionSummary(record, { v: 1, id: record.id, decision: "deny", denySession: true })).toEqual([
      `denied ${record.id}: make a change on GitHub`,
      "  all writes from this session (payments) denied without asking until cleared",
      "  clear it: runfree approvals --clear-deny",
    ]);
  });
});

const DENY_NONCE = "a".repeat(32);

const GRANT_SESSION = {
  sessionId: "rf-20260817-abcdef",
  name: "payments",
  command: "claude",
  startedAt: "2026-08-17T00:00:00.000Z",
};

function statusJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    held: 0,
    denyId: DENY_NONCE,
    grants: [],
    updatedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  });
}

// Entering watch mode is observed by the approver-heartbeat exec, which is the
// first thing `approvalsWatch` does. Throwing a sentinel there ends the
// otherwise-infinite watch loop deterministically, with no signals.
const WATCH_ENTERED = "watch-entered-sentinel";

function clearDenyIo(statuses: readonly (string | undefined)[], options: { trapWatch?: boolean } = {}): RuntimeIO & {
  controls: Array<Record<string, unknown>>;
  execUsers: string[];
  heartbeats: number;
} {
  const controls: Array<Record<string, unknown>> = [];
  const execUsers: string[] = [];
  const counters = { heartbeats: 0 };
  let statusIndex = 0;
  return {
    controls,
    execUsers,
    get heartbeats() {
      return counters.heartbeats;
    },
    admin: async () => 0,
    capture: (_command, args) => {
      if (args[0] === "ps") return captureResult(0, "proxy-id\n");
      if (args.some((arg) => typeof arg === "string" && arg.includes("watcher-heartbeat"))) {
        counters.heartbeats += 1;
        if (options.trapWatch) throw new Error(WATCH_ENTERED);
        return captureResult(0, "");
      }
      if (args[0] === "exec" && args.includes("cat")) {
        const raw = statuses[Math.min(statusIndex, statuses.length - 1)];
        statusIndex += 1;
        return raw === undefined ? captureResult(1, "") : captureResult(0, `${raw}\n`);
      }
      if (args[0] === "exec" && args.includes("node")) {
        const payload = args.at(-1);
        if (typeof payload === "string" && payload.startsWith("{")) {
          const userIndex = args.indexOf("--user");
          execUsers.push(userIndex >= 0 ? args[userIndex + 1] : "<no --user>");
          controls.push(JSON.parse(payload) as Record<string, unknown>);
          return captureResult(0, "ok\n");
        }
      }
      return captureResult(1, "", `unexpected docker args: ${args.join(" ")}`);
    },
    commandExists: () => true,
    confirm: () => false,
    run: () => 0,
  };
}

// Defect B: the session-wide deny had no clear path at all. It gets the same
// host-owned, root-minted channel as the decision that created it.
describe("clearing standing write denies", () => {
  const fast = { confirmPollMs: 1, confirmAttempts: 3 };

  test("itemizes what it is about to revoke, including the allow grants a deny was shadowing", () => {
    const status = {
      held: 0,
      denyId: DENY_NONCE,
      grants: [
        { effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "mcp-tool" as const, host: "mcp.posthog.com", mcp: { agent: "codex" as const, server: "posthog", method: "tools/call", tool: "delete_flag" }, session: GRANT_SESSION },
        { effect: "allow" as const, scope: "session" as const, subject: "session" as const, coverage: "mcp-server-tools" as const, host: "mcp.posthog.com", mcp: { agent: "codex" as const, server: "posthog", method: "tools/call" }, expiresInSeconds: 3_600, session: GRANT_SESSION },
        { effect: "allow" as const, scope: "request" as const, subject: "request" as const, coverage: "request" as const, host: "api.github.com", method: "POST", path: "/repos/o/r/issues", expiresInSeconds: 300 },
      ],
      updatedAt: "2026-07-27T00:00:00.000Z",
    };

    expect(clearPlanLines(status, Date.parse("2026-07-27T00:00:00.000Z"))).toEqual([
      "revoking:",
      '  - deny grant: "delete_flag" on posthog',
      "  - allow grant: all tool calls on posthog",
      "  - allow grant: one write: POST /repos/o/r/issues on api.github.com",
      "  writes go back to being held for approval; standing allow grants are dropped too",
    ]);
  });

  test("issues a root-minted control record naming the current deny nonce, then confirms", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo([
      statusJson({ grants: [{ effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "*", session: GRANT_SESSION }] }),
      statusJson(),
    ]);

    await expect(approvalsClearDeny(context, io, fast)).resolves.toBe(0);
    expect(io.controls).toHaveLength(1);
    expect(io.controls[0]).toMatchObject({ denyId: DENY_NONCE });
    expect(io.controls[0].requestId).toMatch(/^[0-9a-f]{32}$/);
    // Same channel as a decision file: written by root docker exec, never by
    // the uid-1001 proxy and never by the agent.
    expect(io.execUsers).toEqual([ROOT_UID_GID]);
  });

  test("clears scoped MCP deny grants through the same control record", async () => {
    const context = tempMcpContext();
    const denyGrant = {
      effect: "deny",
      scope: "session",
      subject: "session",
      coverage: "mcp-tool",
      mcp: { agent: "codex", server: "posthog", method: "tools/call", tool: "delete_flag" },
      session: GRANT_SESSION,
    };
    const io = clearDenyIo([statusJson({ grants: [denyGrant] }), statusJson()]);

    await expect(approvalsClearDeny(context, io, fast)).resolves.toBe(0);
    expect(io.controls).toHaveLength(1);
  });

  test("writes no control record when nothing is denied", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo([statusJson({
      grants: [{ effect: "allow", scope: "session", subject: "session", coverage: "host", host: "api.github.com", expiresInSeconds: 600, session: GRANT_SESSION }],
    })]);

    await expect(approvalsClearDeny(context, io, fast)).resolves.toBe(0);
    expect(io.controls).toEqual([]);
  });

  test("refuses to mint a control record when the proxy state is unreadable or malformed", async () => {
    const context = tempMcpContext();
    for (const raw of ["{ not json", JSON.stringify({ held: 0, grants: [], updatedAt: "x" }), undefined]) {
      const io = clearDenyIo([raw]);
      await expect(approvalsClearDeny(context, io, fast)).resolves.toBe(1);
      // Rejected before the sensitive side effect: no control file exists to
      // race a later, legitimate clear.
      expect(io.controls).toEqual([]);
    }
  });

  test("reports failure when the proxy did not apply the clear", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo([statusJson({ grants: [{ effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "*", session: GRANT_SESSION }] })]);

    await expect(approvalsClearDeny(context, io, fast)).resolves.toBe(1);
    expect(io.controls).toHaveLength(1);
  });
});

// P3-2: the flags used to race, and `--clear-deny` won silently. Clearing the
// latch specifically in order to resume approving, and being left with no
// attached approver, drops the operator back into fast-denial — the state they
// were undoing.
describe("--clear-deny composed with --watch", () => {
  const watchInput = { kind: "watch", bell: false, clearDenyFirst: true } as const;

  test("clears first, then attaches as the approver", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo([
      statusJson({ grants: [{ effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "*", session: GRANT_SESSION }] }),
      statusJson(),
    ], { trapWatch: true });

    await expect(approvalsRuntime(watchInput, context, io)).rejects.toThrow(WATCH_ENTERED);
    // Order matters: the revocation completed before the watcher attached.
    expect(io.controls).toHaveLength(1);
    expect(io.controls[0]).toMatchObject({ denyId: DENY_NONCE });
    expect(io.heartbeats).toBe(1);
  });

  test("nothing to clear still proceeds to watch", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo([statusJson()], { trapWatch: true });

    // "No denies are active" is the goal state, not a failure: the operator
    // asked to end up unblocked and attached, and they are.
    await expect(approvalsRuntime(watchInput, context, io)).rejects.toThrow(WATCH_ENTERED);
    expect(io.controls).toEqual([]);
    expect(io.heartbeats).toBe(1);
  });

  test("a failed clear stops before attaching, rather than watching a runtime that still denies", async () => {
    const context = tempMcpContext();
    // The proxy never applies the clear: status keeps reporting the deny.
    const io = clearDenyIo([statusJson({ grants: [{ effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "*", session: GRANT_SESSION }] })], { trapWatch: true });

    await expect(approvalsRuntime(watchInput, context, io)).resolves.toBe(1);
    // No approver attached: watching here would show a healthy-looking prompt
    // loop for a runtime where every write is still denied.
    expect(io.heartbeats).toBe(0);
  });

  test("an unreadable proxy state stops before attaching", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo(["{ not json"], { trapWatch: true });

    await expect(approvalsRuntime(watchInput, context, io)).resolves.toBe(1);
    expect(io.controls).toEqual([]);
    expect(io.heartbeats).toBe(0);
  });

  test("--watch alone never touches the control channel", async () => {
    const context = tempMcpContext();
    const io = clearDenyIo([statusJson()], { trapWatch: true });

    await expect(approvalsRuntime({ kind: "watch", bell: false }, context, io)).rejects.toThrow(WATCH_ENTERED);
    expect(io.controls).toEqual([]);
  });
});

// The two surfaces that render grants must not drift: `runfree status` once
// reduced every grant to `grant.host`, which silently erased the tool identity
// of a deny and made a one-request grant read as host-wide the moment MCP
// coverage started carrying a host.
describe("status line and approvals list share one coverage renderer", () => {
  const GRANTS = [
    { effect: "allow" as const, scope: "request" as const, subject: "request" as const, coverage: "request" as const, host: "api.github.com", method: "POST", path: "/repos/o/r/issues", expiresInSeconds: 300 },
    { effect: "allow" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "api.github.com", expiresInSeconds: 3_600, session: GRANT_SESSION },
    { effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "mcp-tool" as const, host: "mcp.posthog.com", mcp: { agent: "codex" as const, server: "posthog", method: "tools/call", tool: "delete_flag" }, session: GRANT_SESSION },
    { effect: "allow" as const, scope: "session" as const, subject: "session" as const, coverage: "mcp-server-tools" as const, host: "mcp.posthog.com", mcp: { agent: "codex" as const, server: "posthog", method: "tools/call" }, expiresInSeconds: 3_600, session: GRANT_SESSION },
    { effect: "allow" as const, scope: "session" as const, subject: "session" as const, coverage: "mcp-method" as const, host: "mcp.posthog.com", mcp: { agent: "claude" as const, server: "posthog", method: "resources/subscribe" }, expiresInSeconds: 900, session: GRANT_SESSION },
  ];

  test("every coverage kind renders its own identity, not its bare host", () => {
    expect(GRANTS.map(grantCoverageLabel)).toEqual([
      "one write: POST /repos/o/r/issues on api.github.com",
      "all writes to api.github.com",
      '"delete_flag" on posthog',
      "all tool calls on posthog",
      '"resources/subscribe" on posthog',
    ]);
  });

  test("runfree status renders grants through the same labels", () => {
    const context = tempMcpContext();
    fs.mkdirSync(path.dirname(context.project.paths.policyPath), { recursive: true });
    fs.writeFileSync(context.project.paths.policyPath, JSON.stringify({ hosts: ["api.github.com", "mcp.posthog.com"] }));
    // Fresh snapshot: bounded grants are aged against `updatedAt`, so a stale
    // one would legitimately render nothing.
    const io = clearDenyIo([statusJson({ grants: GRANTS, updatedAt: new Date().toISOString() })]);
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(args.join(" "));
    });
    try {
      printWriteApprovalStatusLine(context, io);
    } finally {
      spy.mockRestore();
    }

    const status = lines.join("\n");
    expect(status).toContain("one write: POST /repos/o/r/issues on api.github.com");
    expect(status).toContain('"delete_flag" on posthog');
    expect(status).toContain("all tool calls on posthog");
    // The regression: a denied tool must never be reported as its whole host.
    expect(status).not.toContain("deny grant (mcp.posthog.com,");
  });
});

// P2-2, at the ownership boundary: the proxy cannot delete root-owned files,
// so the root writer that mints control records is what keeps the directory
// from growing until the proxy's bounded per-tick scan can no longer reach a
// fresh one. This runs the real script text against a temp directory.
describe("control-record writer cleanup", () => {
  function runControlScript(dir: string, input: Record<string, unknown>): { status: number; stderr: string } {
    const epochPath = path.join(dir, "epoch");
    if (!fs.existsSync(epochPath)) fs.writeFileSync(epochPath, "a".repeat(64));
    const script = WRITE_CONTROL_SCRIPT.replace(JSON.stringify(APPROVALS_DECISIONS_DIR), JSON.stringify(dir))
      .replace(JSON.stringify(`${APPROVALS_PENDING_DIR}/${APPROVALS_PROCESS_EPOCH_FILE}`), JSON.stringify(epochPath));
    try {
      execFileSync("node", ["-e", script, JSON.stringify(input)], { encoding: "utf8" });
      return { status: 0, stderr: "" };
    } catch (error) {
      const failure = error as { status?: number; stderr?: string };
      return { status: failure.status ?? 1, stderr: failure.stderr ?? "" };
    }
  }

  function decisionsDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-control-"));
    tempDirs.push(dir);
    fs.writeFileSync(path.join(dir, "epoch"), "a".repeat(64));
    return dir;
  }

  const nonce = (seed: number) => seed.toString(16).padStart(32, "0");

  test("retires superseded control records and nothing else", () => {
    const dir = decisionsDir();
    const survivors = ["watcher-heartbeat", `${nonce(9)}.json`, `control-${nonce(7)}.json.tmp`, "notes.txt"];
    for (const name of [...survivors, `control-${nonce(1)}.json`, `control-${nonce(2)}.json`, `control-${nonce(3)}.json`]) {
      fs.writeFileSync(path.join(dir, name), "existing\n");
    }

    expect(runControlScript(dir, { denyId: nonce(42), requestId: nonce(4) }).status).toBe(0);

    // Exactly one control record remains: the new one.
    expect(fs.readdirSync(dir).filter((name) => /^control-[0-9a-f]{32}\.json$/.test(name)))
      .toEqual([`control-${nonce(4)}.json`]);
    // Decision files, the watcher heartbeat, a partially written record's .tmp,
    // and unrelated names are never touched by the cleanup.
    for (const name of survivors) expect(fs.existsSync(path.join(dir, name))).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(dir, `control-${nonce(4)}.json`), "utf8")))
      .toMatchObject({ v: 1, control: "clear-write-deny", denyId: nonce(42) });
  });

  test("cleanup does not defeat the single-use check for a repeated request id", () => {
    const dir = decisionsDir();
    expect(runControlScript(dir, { denyId: nonce(42), requestId: nonce(5) }).status).toBe(0);
    // The record being written is excluded from the sweep, so a repeat still
    // fails instead of silently re-minting itself.
    const repeat = runControlScript(dir, { denyId: nonce(42), requestId: nonce(5) });
    expect(repeat.status).toBe(2);
    expect(repeat.stderr).toContain("already issued");
    expect(fs.existsSync(path.join(dir, `control-${nonce(5)}.json`))).toBe(true);
  });

  test("a malformed nonce is rejected before anything is unlinked or written", () => {
    const dir = decisionsDir();
    fs.writeFileSync(path.join(dir, `control-${nonce(1)}.json`), "existing\n");

    expect(runControlScript(dir, { denyId: "not-a-nonce", requestId: nonce(6) }).status).toBe(1);
    expect(runControlScript(dir, { denyId: nonce(42), requestId: "../escape" }).status).toBe(1);

    expect(fs.readdirSync(dir).sort()).toEqual([`control-${nonce(1)}.json`, "epoch"]);
  });
});

describe("standing authority rendering", () => {
  test("names each grant's session subject, the clear command, and both grant signs", () => {
    const status = {
      held: 0,
      denyId: DENY_NONCE,
      grants: [
        { effect: "allow" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "api.github.com", expiresInSeconds: 1_800, session: GRANT_SESSION },
        { effect: "deny" as const, scope: "session" as const, subject: "session" as const, coverage: "mcp-tool" as const, mcp: { agent: "codex" as const, server: "posthog", method: "tools/call", tool: "delete_flag" }, session: GRANT_SESSION },
      ],
      updatedAt: "2026-07-27T00:00:00.000Z",
    };

    expect(standingAuthorityLines(status, Date.parse("2026-07-27T00:00:00.000Z"))).toEqual([
      "allow grant: all writes to api.github.com (30m left, session payments)",
      'deny grant: "delete_flag" on posthog (until cleared, session payments)',
      "clear deny grants: runfree approvals --clear-deny",
    ]);
  });

  test("ages a published countdown instead of reporting it frozen, and hides grants that already lapsed", () => {
    const status = {
      held: 0,
      denyId: DENY_NONCE,
      grants: [
        { effect: "allow" as const, scope: "session" as const, subject: "session" as const, coverage: "host" as const, host: "api.github.com", expiresInSeconds: 600, session: GRANT_SESSION },
      ],
      updatedAt: "2026-07-27T00:00:00.000Z",
    };

    expect(standingAuthorityLines(status, Date.parse("2026-07-27T00:05:00.000Z"))).toEqual([
      "allow grant: all writes to api.github.com (5m left, session payments)",
    ]);
    expect(standingAuthorityLines(status, Date.parse("2026-07-27T00:20:00.000Z"))).toEqual([]);
  });
});
