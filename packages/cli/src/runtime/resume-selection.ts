// Pure selection of what `runfree resume` asks (spec section 3, "Prompt and
// picker"): nothing here touches the filesystem, Docker, or any clock other
// than the `now` passed in. The scan and this selection both run offline,
// before runtime preparation and before any lifecycle lock, claim, or
// container side effect.
//
// `RecoveryItem` is imported type-only on purpose: a later task adds the
// reverse value import (`sanitizeAgentText` into `recovery.ts`), and a value
// import here would make that a runtime cycle.
import path from "node:path";

import type { RecoveryItem } from "./recovery.ts";
import { matchTerminal, type TerminalIdentity, type TerminalMatch } from "./terminal-identity.ts";
import { sanitizeForTerminal } from "../../../../scripts/domain-diagnostics.ts";

export type CurrentTerminal = Readonly<{ ids: TerminalIdentity; tty?: string; termProgram?: string; bootId?: string }>;

export type ResumeRow = Readonly<{
  item: RecoveryItem;
  match: TerminalMatch;
  source: "host" | "claude-reported" | "codex-match";
  time: string; // host field: "14:02"
  ago: string; // host field: "6 min ago"
  agent: string; // host field
  terminal: string; // host field: "ttys004 (iTerm)" plus " · this terminal" when strong
  name?: string; // agent-supplied, sanitized, shown quoted
  note?: string; // "Codex match", "Claude reported", "matches 2 tabs"
}>;

export type ResumeSelection =
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "one-question"; row: ResumeRow }>
  | Readonly<{ kind: "picker"; rows: readonly ResumeRow[]; defaultItemId: string | undefined }>;

const NAME_MAX = 80;
const AGENT_MAX = 24;
const TERMINAL_PART_MAX = 40;

// Direction overrides, zero-width characters, and line/paragraph separators
// (spec section 3, "Sanitizer") — stripped on top of `sanitizeForTerminal`'s
// C0/C1 controls and ANSI sequences, so an agent-supplied name cannot hide
// characters or break a terminal line.
const FORMAT_OR_SEPARATOR = /[\p{Cf}\p{Zl}\p{Zp}]/gu;

// A `"` would let an agent-supplied name close `formatResumeRow`'s quoting
// early; a run of plain spaces/tabs would let it fake the two-space column
// gaps the host fields are joined with. Both are neutralized here, after
// the existing strips and before the length cut, so the quoted name can
// never be mistaken for (or bleed into) the host fields that follow it.
const DOUBLE_QUOTE = /"/g;
const WHITESPACE_RUN = /[ \t]+/g;

export function sanitizeAgentText(value: string, max: number): string {
  return sanitizeForTerminal(value)
    .replace(FORMAT_OR_SEPARATOR, "")
    .replace(DOUBLE_QUOTE, "'")
    .replace(WHITESPACE_RUN, " ")
    .slice(0, max);
}

// Whether a record is a candidate at all, independent of ranking (spec
// decisions 3 and 9). Hidden rows never appear in the one question or the
// picker; `runfree resume --list` still lists them elsewhere.
function eligible(item: RecoveryItem): boolean {
  if (item.state === "claimed" || item.state === "unrecoverable" || item.state === "active") return false;
  if (item.claimUnprovable) return false;
  if (item.evidenceKind === "claude") return true; // claude-reported rows
  if (item.recordVersion !== 2) return false; // decision 3: no record version means an older Runfree
  return item.ownerState === "dead";
}

// Codex-match rows are `RecoveryItem`s copied from their host item, so they
// carry the host's own `conversationSource` unless it is itself
// "codex-match" — check that first, then the Claude registry, and default
// to a plain host row.
function sourceOf(item: RecoveryItem): "host" | "claude-reported" | "codex-match" {
  if (item.conversationSource === "codex-match") return "codex-match";
  if (item.evidenceKind === "claude") return "claude-reported";
  return "host";
}

// Only a host row can ever match the current terminal. Codex-match rows
// carry the host's `terminal` field but must never count toward a strong
// match or sort as one (decision 4); Claude-registry rows have no terminal
// of their own at all.
function matchOf(item: RecoveryItem, source: "host" | "claude-reported" | "codex-match", current: CurrentTerminal): TerminalMatch {
  if (source !== "host" || !item.terminal) return "none";
  return matchTerminal(current, item.terminal);
}

function noteOf(item: RecoveryItem, source: "host" | "claude-reported" | "codex-match"): string | undefined {
  if (source === "codex-match") {
    const tabs = item.codexMatchTabs;
    return tabs !== undefined && tabs > 1 ? `matches ${tabs} tabs` : "Codex match";
  }
  if (source === "claude-reported") return "Claude reported";
  return undefined;
}

function terminalOf(item: RecoveryItem, match: TerminalMatch): string {
  const tty = item.terminal?.tty;
  const termProgram = item.terminal?.termProgram;
  const base = tty
    ? path.posix.basename(tty)
    : (item.terminalHint ? sanitizeForTerminal(item.terminalHint).slice(0, TERMINAL_PART_MAX) : "-");
  const withProgram = tty && termProgram ? `${base} (${sanitizeForTerminal(termProgram).slice(0, TERMINAL_PART_MAX)})` : base;
  return match === "strong" ? `${withProgram} · this terminal` : withProgram;
}

function timestampOf(item: RecoveryItem): number {
  const value = item.updatedAt ?? item.startedAt;
  const parsed = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function timeOf(ms: number): string {
  return Number.isFinite(ms) ? new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "-";
}

function agoOf(ms: number, now: Date): string {
  if (!Number.isFinite(ms)) return "-";
  const deltaMs = Math.max(0, now.getTime() - ms);
  const minutes = Math.round(deltaMs / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.round(hours / 24);
  return `${days} d ago`;
}

function nameOf(item: RecoveryItem): string | undefined {
  if (item.conversationName === undefined) return undefined;
  const sanitized = sanitizeAgentText(item.conversationName, NAME_MAX);
  return sanitized.length > 0 ? sanitized : undefined;
}

function buildRow(item: RecoveryItem, current: CurrentTerminal, now: Date): ResumeRow {
  const source = sourceOf(item);
  const match = matchOf(item, source, current);
  const ms = timestampOf(item);
  return {
    item,
    match,
    source,
    time: timeOf(ms),
    ago: agoOf(ms, now),
    agent: sanitizeForTerminal(item.agent).slice(0, AGENT_MAX),
    terminal: terminalOf(item, match),
    name: nameOf(item),
    note: noteOf(item, source),
  };
}

const MATCH_RANK: Record<TerminalMatch, number> = { strong: 0, weak: 1, none: 2 };

// Strong, then weak, then the rest newest first (spec section 3, "Order").
function compareRows(a: ResumeRow, b: ResumeRow): number {
  const rank = MATCH_RANK[a.match] - MATCH_RANK[b.match];
  if (rank !== 0) return rank;
  const bt = timestampOf(b.item);
  const at = timestampOf(a.item);
  return (Number.isFinite(bt) ? bt : -Infinity) - (Number.isFinite(at) ? at : -Infinity);
}

const ONE_QUESTION_AGENTS = new Set(["claude", "pi"]);

function oneQuestionAllowed(row: ResumeRow, rows: readonly ResumeRow[]): boolean {
  const item = row.item;
  if (row.match !== "strong" || row.source !== "host") return false;
  if (!ONE_QUESTION_AGENTS.has(item.agent)) return false;
  if (item.conversationSource !== "host-chosen" && item.conversationSource !== "resume-lineage") return false;
  const started = Date.parse(item.startedAt ?? "");
  // Fail closed: an unparsable startedAt can't be compared against another
  // row's, so show the picker instead of guessing it's the newest.
  if (Number.isNaN(started)) return false;
  // Decision 1: a newer Claude-reported conversation means /clear or /resume
  // may have moved this tab to another conversation.
  return !rows.some((other) => other.source === "claude-reported"
    && other.item.agent === item.agent
    && Date.parse(other.item.startedAt ?? "") > started);
}

export function selectResumeCandidates(input: Readonly<{
  items: readonly RecoveryItem[];
  current: CurrentTerminal;
  now: Date;
}>): ResumeSelection {
  const rows = input.items.filter(eligible).map((item) => buildRow(item, input.current, input.now)).sort(compareRows);
  if (rows.length === 0) return { kind: "none" };

  const strongRows = rows.filter((row) => row.match === "strong");
  const onlyStrongRow = strongRows.length === 1 ? strongRows.at(0) : undefined;
  if (onlyStrongRow && oneQuestionAllowed(onlyStrongRow, rows)) {
    return { kind: "one-question", row: onlyStrongRow };
  }

  const defaultItemId = rows.find((row) => row.source === "host")?.item.id;
  return { kind: "picker", rows, defaultItemId };
}

// Host fields (agent, time, terminal) are built first as a fixed, self
// contained block, independent of the agent-supplied name; the quoted name
// is then placed apart from it. A name whose content echoes real host-field
// text (spec section 3, "Labels") cannot shift that block, because it is
// never reparsed into the host fields — only concatenated beside them.
export function formatResumeRow(row: ResumeRow): string {
  const hostFields = [row.agent, row.time, row.terminal].join("  ");
  const namePart = row.name !== undefined ? `"${row.name}"  ` : "";
  const noteSuffix = row.note !== undefined ? `  (${row.note})` : "";
  return `${namePart}${hostFields}${noteSuffix}`;
}
