import { describe, expect, test } from "vitest";

import type { EvidenceFingerprint, RecoveryItem } from "./recovery.ts";
import {
  formatResumeRow,
  sanitizeAgentText,
  selectResumeCandidates,
  type CurrentTerminal,
  type ResumeRow,
} from "./resume-selection.ts";

const NOW = new Date("2026-10-07T14:08:00.000Z");

const FINGERPRINT: EvidenceFingerprint = {
  dev: 1,
  ino: 1,
  size: 10,
  mtimeMs: 0,
  schemaId: "host-session-v1",
  sha256: "a".repeat(64),
};

const CURRENT: CurrentTerminal = { ids: { iterm: "iterm-1" }, tty: "/dev/ttys004", termProgram: "iTerm.app", bootId: "boot-1" };
const STRONG_TERMINAL = { ids: { iterm: "iterm-1" }, tty: "/dev/ttys004", termProgram: "iTerm.app", bootId: "boot-1" };
const OTHER_TERMINAL = { ids: { iterm: "iterm-9" }, tty: "/dev/ttys099", termProgram: "iTerm.app", bootId: "boot-1" };
const WEAK_TERMINAL = { ids: {}, tty: "/dev/ttys004", termProgram: "iTerm.app" };

let counter = 0;

function hostItem(overrides: Partial<RecoveryItem> = {}): RecoveryItem {
  counter += 1;
  return {
    id: `rfr-item-${counter}`,
    projectId: "aaaaaaaaaaaa",
    projectName: "demo",
    stateDir: "/state/demo",
    state: "interrupted",
    evidenceKind: "host",
    evidencePath: `/state/demo/sessions/rf-20261006-abc${counter}.json`,
    fingerprint: FINGERPRINT,
    sourceId: `rf-20261006-abc${counter}`,
    agent: "claude",
    conversationSource: "host-chosen",
    recordVersion: 2,
    ownerState: "dead",
    startedAt: "2026-10-07T14:00:00.000Z",
    updatedAt: "2026-10-07T14:02:00.000Z",
    terminal: STRONG_TERMINAL,
    ...overrides,
  };
}

function claudeItem(overrides: Partial<RecoveryItem> = {}): RecoveryItem {
  counter += 1;
  return {
    id: `rfr-claude-${counter}`,
    projectId: "aaaaaaaaaaaa",
    projectName: "demo",
    stateDir: "/state/demo",
    state: "unverified",
    evidenceKind: "claude",
    evidencePath: `/state/demo/claude/sessions/${counter}.json`,
    fingerprint: FINGERPRINT,
    sourceId: `claude-${counter}`,
    agent: "claude",
    conversationSource: "claude-reported",
    startedAt: "2026-10-07T14:01:00.000Z",
    updatedAt: "2026-10-07T14:01:00.000Z",
    ...overrides,
  };
}

describe("selectResumeCandidates", () => {
  test("one eligible Claude host row with a strong match asks the one question", () => {
    const item = hostItem();
    const result = selectResumeCandidates({ items: [item], current: CURRENT, now: NOW });
    expect(result.kind).toBe("one-question");
    if (result.kind !== "one-question") throw new Error("unreachable");
    expect(result.row.item.id).toBe(item.id);
    expect(result.row.match).toBe("strong");
    expect(result.row.source).toBe("host");
  });

  test("the same row with only a weak match shows the picker, first, as the default", () => {
    const item = hostItem({ terminal: WEAK_TERMINAL });
    const result = selectResumeCandidates({ items: [item], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.rows).toHaveLength(1);
    expect(result.rows.at(0)?.item.id).toBe(item.id);
    expect(result.rows.at(0)?.match).toBe("weak");
    expect(result.defaultItemId).toBe(item.id);
  });

  test("two strong-match rows show the picker, not the one question", () => {
    const a = hostItem();
    const b = hostItem();
    const result = selectResumeCandidates({ items: [a, b], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
  });

  test("a Codex host row with a strong match never asks the one question (decision 4)", () => {
    const codex = hostItem({ agent: "codex" });
    const result = selectResumeCandidates({ items: [codex], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.defaultItemId).toBe(codex.id);
  });

  test("a codex-match row is never the default, even alongside a Codex host row", () => {
    const codexHost = hostItem({ agent: "codex", terminal: OTHER_TERMINAL });
    const codexMatch = hostItem({
      agent: "codex",
      conversationSource: "codex-match",
      codexMatchOf: codexHost.id,
      codexMatchTabs: 1,
      updatedAt: "2026-10-07T14:07:00.000Z",
    });
    const result = selectResumeCandidates({ items: [codexHost, codexMatch], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    const codexMatchRow = result.rows.find((row) => row.item.id === codexMatch.id);
    expect(codexMatchRow?.source).toBe("codex-match");
    expect(codexMatchRow?.match).toBe("none");
    expect(result.defaultItemId).toBe(codexHost.id);
  });

  test("decision 1: a newer Claude-reported conversation for the same agent forces the picker", () => {
    const host = hostItem();
    const claude = claudeItem({ startedAt: "2026-10-07T14:05:00.000Z" });
    const result = selectResumeCandidates({ items: [host, claude], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.defaultItemId).toBe(host.id);
    const claudeRow = result.rows.find((row) => row.item.id === claude.id);
    expect(claudeRow?.source).toBe("claude-reported");
    expect(claudeRow?.note).toBe("Claude reported");
  });

  test("hides records that are claimed, unprovable, active-owned, unrecoverable, or pre-dating the record version", () => {
    const items = [
      hostItem({ recordVersion: undefined }),
      hostItem({ state: "claimed" }),
      hostItem({ claimUnprovable: "owner identity unknown" }),
      hostItem({ ownerState: "active" }),
      hostItem({ state: "unrecoverable" }),
    ];
    const result = selectResumeCandidates({ items, current: CURRENT, now: NOW });
    expect(result).toEqual({ kind: "none" });
  });

  test("orders strong, then weak, then the rest newest first, and never defaults to an agent-sourced row", () => {
    const strong = hostItem({ agent: "codex", updatedAt: "2026-10-07T13:00:00.000Z" });
    const weak = hostItem({ agent: "codex", terminal: WEAK_TERMINAL, updatedAt: "2026-10-07T13:30:00.000Z" });
    const olderOther = hostItem({ agent: "codex", terminal: OTHER_TERMINAL, updatedAt: "2026-10-07T12:00:00.000Z" });
    const newerOther = hostItem({ agent: "codex", terminal: OTHER_TERMINAL, updatedAt: "2026-10-07T13:45:00.000Z" });
    const result = selectResumeCandidates({ items: [olderOther, weak, newerOther, strong], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.rows.map((row) => row.item.id)).toEqual([strong.id, weak.id, newerOther.id, olderOther.id]);
    expect(result.defaultItemId).toBe(strong.id);
  });

  test("with only agent-sourced rows, the default cursor is undefined even though one sorts first", () => {
    const newerClaude = claudeItem({ startedAt: "2026-10-07T14:06:00.000Z", updatedAt: "2026-10-07T14:06:00.000Z" });
    const olderClaude = claudeItem({ startedAt: "2026-10-07T14:01:00.000Z", updatedAt: "2026-10-07T14:01:00.000Z" });
    const result = selectResumeCandidates({ items: [olderClaude, newerClaude], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.rows.map((row) => row.item.id)).toEqual([newerClaude.id, olderClaude.id]);
    expect(result.defaultItemId).toBeUndefined();
  });

  test("formats time as the locale's HH:MM and ago relative to now", () => {
    const item = hostItem({ updatedAt: "2026-10-07T14:02:00.000Z" });
    const result = selectResumeCandidates({ items: [item], current: CURRENT, now: NOW });
    expect(result.kind).toBe("one-question");
    if (result.kind !== "one-question") throw new Error("unreachable");
    const expectedTime = new Date("2026-10-07T14:02:00.000Z").toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    expect(result.row.time).toBe(expectedTime);
    expect(result.row.ago).toBe("6 min ago"); // NOW is 14:08Z, updatedAt is 14:02Z
  });

  test("a resume-lineage host row with a strong match also asks the one question", () => {
    const item = hostItem({ conversationSource: "resume-lineage" });
    const result = selectResumeCandidates({ items: [item], current: CURRENT, now: NOW });
    expect(result.kind).toBe("one-question");
    if (result.kind !== "one-question") throw new Error("unreachable");
    expect(result.row.item.id).toBe(item.id);
  });

  test("fails closed to the picker when startedAt cannot be parsed", () => {
    const item = hostItem({ startedAt: undefined });
    const result = selectResumeCandidates({ items: [item], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.defaultItemId).toBe(item.id);
  });

  test("a codex-match note says 'Codex match' for one tab and 'matches N tabs' for several", () => {
    const base = hostItem({ agent: "codex" });
    const single = hostItem({ agent: "codex", conversationSource: "codex-match", codexMatchOf: base.id, codexMatchTabs: 1 });
    const several = hostItem({ agent: "codex", conversationSource: "codex-match", codexMatchOf: base.id, codexMatchTabs: 3 });
    const result = selectResumeCandidates({ items: [single, several], current: CURRENT, now: NOW });
    expect(result.kind).toBe("picker");
    if (result.kind !== "picker") throw new Error("unreachable");
    expect(result.rows.find((row) => row.item.id === single.id)?.note).toBe("Codex match");
    expect(result.rows.find((row) => row.item.id === several.id)?.note).toBe("matches 3 tabs");
  });
});

describe("sanitizeAgentText", () => {
  test("strips ANSI, then Cf/Zl/Zp characters left over from sanitizeForTerminal", () => {
    // U+202E (Cf, right-to-left override), U+200B (Cf, zero-width space),
    // U+2028 (Zl, line separator), and a real ANSI color escape.
    expect(sanitizeAgentText("a‮b​c d\u001b[31me", 80)).toBe("abcde");
  });

  test("cuts the result to max", () => {
    expect(sanitizeAgentText("x".repeat(100), 10)).toBe("x".repeat(10));
  });

  test("replaces embedded double quotes so a name cannot forge a closing quote and the host fields after it", () => {
    const spoof = 'x"  claude  14:02  ttys004 · this terminal  "y';
    const sanitized = sanitizeAgentText(spoof, 200);
    expect(sanitized.includes('"')).toBe(false);
    const row: ResumeRow = {
      item: hostItem(),
      match: "strong",
      source: "host",
      time: "09:15",
      ago: "1 min ago",
      agent: "claude",
      terminal: "ttys007 (Terminal)",
      name: sanitized,
    };
    const formatted = formatResumeRow(row);
    expect(formatted.split('"')).toHaveLength(3); // exactly two '"' characters, both the real wrapper
  });

  test("collapses whitespace runs so a name cannot fake the two-space column gaps", () => {
    expect(sanitizeAgentText("a   b    c", 80)).toBe("a b c");
  });
});

describe("formatResumeRow", () => {
  const baseRow: ResumeRow = {
    item: hostItem(),
    match: "strong",
    source: "host",
    time: "14:02",
    ago: "6 min ago",
    agent: "claude",
    terminal: "ttys004 · this terminal",
    name: "refactor proxy",
  };

  test("puts the quoted name apart from the fixed-width host fields", () => {
    expect(formatResumeRow(baseRow)).toBe('"refactor proxy"  claude  14:02  ttys004 · this terminal');
  });

  test("a name that echoes host-field text cannot shift the real host columns", () => {
    const decoy: ResumeRow = { ...baseRow, name: "14:02 this terminal", time: "09:15", terminal: "ttys007 (Terminal)" };
    expect(formatResumeRow(decoy)).toBe('"14:02 this terminal"  claude  09:15  ttys007 (Terminal)');
  });

  test("renders without a name when the row has none", () => {
    const noName: ResumeRow = { ...baseRow, name: undefined };
    expect(formatResumeRow(noName)).toBe("claude  14:02  ttys004 · this terminal");
  });

  test("appends a note for agent-sourced rows", () => {
    const reported: ResumeRow = { ...baseRow, name: undefined, note: "Claude reported" };
    expect(formatResumeRow(reported)).toBe("claude  14:02  ttys004 · this terminal  (Claude reported)");
  });
});
