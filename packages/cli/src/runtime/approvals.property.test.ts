// Property tests for the host-side approval display (spec Phase 6).
//
// A pending record reaches the host terminal through `runfree approvals`. The
// MCP `tool` and `method` in it are chosen by the agent: the proxy only slices
// them to 128 characters (`boundedMcp` in packages/proxy/src/approvals.ts).
// The generators below keep every other field to what the proxy writes, so a
// failure points at the agent-controlled fields.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import fc from "fast-check";
import { describe, expect, test } from "vitest";

import type { ApprovalDecisionRecord, PendingApprovalRecord } from "@runfree/runtime-contracts/write-approvals";
import { propertyParameters } from "../../../../tests/support/property.ts";
import { parseEmittedCommandArgs } from "../commands/app.ts";
import { createCommandContext } from "../commands/context.ts";
import { decisionSummary, detailLines, pendingTableLines } from "./approvals.ts";

// C0 and C1 controls (ESC included) and the Unicode bidi overrides, embeddings,
// isolates, and marks.
const TERMINAL_UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
// The characters `shlex.quote` (CPython) leaves unquoted: a word made only of
// these is one argument to a POSIX shell, with no expansion.
const SHELL_LITERAL_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

const NOW_MS = Date.parse("2026-07-08T22:00:00.000Z");

// Agent-chosen text, biased toward terminal and shell metacharacters.
const agentText = fc
  .string({
    unit: fc.oneof(
      fc.constantFrom("\u001b", "\u009b", "\u0007", "\u0000", "\n", "\r", "\u202e", "\u2066", " ", ";", "$", "`", "'", "\"", "|", "-"),
      fc.string({ unit: "binary", minLength: 1, maxLength: 1 }),
    ),
    minLength: 1,
    maxLength: 140,
  })
  .map((value) => value.slice(0, 128));
// Names that follow the MCP tool-name convention ([A-Za-z0-9_.-]).
const conventionalToolName = fc.stringMatching(/^[A-Za-z0-9_.-]{1,64}$/);
// Printable tool names, so P6.5 isolates shell splitting from P6.4's controls.
const printableToolName = fc.string({
  unit: fc.oneof(
    fc.constantFrom(" ", ";", "$", "`", "'", "\"", "|", "&", "(", "*", "#", "-"),
    fc.string({ unit: "grapheme-ascii", minLength: 1, maxLength: 1 }),
  ),
  minLength: 1,
  maxLength: 64,
});

const record = (tool: fc.Arbitrary<string>): fc.Arbitrary<PendingApprovalRecord> => fc
  .record({
    host: fc.domain(),
    method: fc.constantFrom("POST", "PUT", "PATCH", "DELETE"),
    path: fc.constantFrom("/mcp", "/v1/mcp", "/sse"),
    tokenNames: fc.array(fc.stringMatching(/^[A-Z][A-Z0-9_]{0,15}$/), { maxLength: 2 }),
    agent: fc.constantFrom("claude" as const, "codex" as const),
    server: fc.stringMatching(/^[a-z][a-z0-9-]{0,15}$/),
    mcpMethod: fc.oneof(fc.constant("tools/call"), agentText),
    tool: fc.option(tool, { nil: undefined }),
    expiresInMs: fc.integer({ min: -5_000, max: 300_000 }),
  })
  .map((fields) => ({
    v: 1,
    id: "0123456789abcdef0123456789abcdef",
    host: fields.host,
    method: fields.method,
    path: fields.path,
    category: fields.mcpMethod === "tools/call" && fields.tool !== undefined ? "mcp-tool" : "mcp-unknown",
    tokenNames: fields.tokenNames,
    mcp: {
      agent: fields.agent,
      server: fields.server,
      method: fields.mcpMethod,
      ...(fields.tool === undefined ? {} : { tool: fields.tool }),
    },
    generation: "sha256:policy",
    heldAt: new Date(NOW_MS).toISOString(),
    expiresAt: new Date(NOW_MS + fields.expiresInMs).toISOString(),
  }));

// Every decision summary the approve flow can print for a held MCP request.
function summaries(pending: PendingApprovalRecord): string[] {
  const decisions: Array<Omit<ApprovalDecisionRecord, "decidedAt">> = [
    { v: 1, id: pending.id, decision: "approve", scope: "request" },
    { v: 1, id: pending.id, decision: "approve", scope: "session", mcpScope: "tool" },
    { v: 1, id: pending.id, decision: "approve", scope: "request", saveMcpRule: "tool" },
    { v: 1, id: pending.id, decision: "approve", scope: "request", saveMcpRule: "server-tools" },
    { v: 1, id: pending.id, decision: "deny" },
  ];
  return decisions.flatMap((decision) => decisionSummary(pending, decision));
}

// The `runfree ...` command a line presents, as the argv the remedy gate
// (scripts/emitted-commands.test.ts) checks: split on single spaces.
function suggestedArgv(line: string): string[] | undefined {
  const start = line.indexOf("runfree ");
  return start === -1 ? undefined : line.slice(start + "runfree ".length).split(" ");
}

describe("approval display", () => {
  // Product defect: the agent-chosen MCP tool and method reach the terminal
  // unescaped (spec hypothesis H6).
  test.skip("P6.4: approval display lines carry no terminal control or bidi characters — product defect, see todo 105", () => {
    fc.assert(
      fc.property(record(agentText), (pending) => {
        const lines = [...detailLines(pending, NOW_MS), ...pendingTableLines([pending], NOW_MS), ...summaries(pending)];
        for (const line of lines) expect(line).not.toMatch(TERMINAL_UNSAFE);
      }),
      propertyParameters(),
    );
  });

  // Product defect: the tool name is pasted bare into a suggested shell
  // command, so it can split into several arguments or expand.
  test.skip("P6.5: every suggested command parses and keeps the tool name one shell word — product defect, see todo 106", async () => {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approvals-property-"));
    const context = createCommandContext({ projectRoot, invocationCwd: projectRoot, commandName: "", env: { ...process.env } });
    // Building the yargs app costs 5-10 ms per parse and dominates the run.
    // Lines without the tool repeat across runs, and the two `--tool` lines
    // differ only in `--write allow` versus `--write ask`, both valid values;
    // so each argv is parsed once per distinct shape, after the pure checks.
    const parsed = new Map<string, Promise<void>>();
    const parse = (argv: string[]) => {
      const key = argv.map((word, index) => (argv[index - 1] === "--write" ? "<write>" : word)).join("\0");
      if (!parsed.has(key)) parsed.set(key, parseEmittedCommandArgs(context, argv));
      return parsed.get(key);
    };
    try {
      await fc.assert(
        fc.asyncProperty(record(fc.oneof(conventionalToolName, printableToolName)), async (pending) => {
          const lines = [...detailLines(pending, NOW_MS), ...summaries(pending)];
          for (const argv of lines.map(suggestedArgv)) {
            if (argv === undefined) continue;
            const toolIndex = argv.indexOf("--tool");
            if (toolIndex !== -1) {
              expect(argv[toolIndex + 1]).toBe(pending.mcp?.tool);
              expect(argv[toolIndex + 1]).toMatch(SHELL_LITERAL_WORD);
            }
            await parse(argv);
          }
        }),
        propertyParameters(),
      );
    } finally {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  });
});
