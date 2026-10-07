// What `runfree resume` asks in a terminal (spec section 3, "Prompt and
// picker"; section 5, "After the choice"). `selectResumeCandidates`
// (resume-selection.ts) decides *what* to ask offline; this module owns only
// *how* it is asked — the clack prompts themselves — and the three outcomes
// `resume.ts` acts on. Nothing here touches the filesystem, Docker, or a
// lifecycle lock: the claim and consumption happen after the choice, in
// `recovery.ts`, under the lock.

import { isCancel, select } from "@clack/prompts";

import type { RecoveryItem } from "../runtime/recovery.ts";
import { captureHostTty } from "../runtime/sessions.ts";
import { hostBootId } from "../runtime/host-identity.ts";
import { captureTerminalIdentity } from "../runtime/terminal-identity.ts";
import { formatResumeRow, type CurrentTerminal, type ResumeRow, type ResumeSelection } from "../runtime/resume-selection.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";

export type ResumePromptChoice =
  | Readonly<{ kind: "resume"; item: RecoveryItem }>
  | Readonly<{ kind: "dismiss"; item: RecoveryItem }>
  | Readonly<{ kind: "cancel" }>;

export type PromptApi = Readonly<{ select: typeof select; isCancel: typeof isCancel }>;

const DEFAULT_PROMPT_API: PromptApi = { select, isCancel };

// Builds the current terminal's identity for matching against host-sourced
// recovery rows (spec section 1, "Terminal identity"). `captureHostTty` needs
// a `RuntimeContext` only to reach `context.env` (`sessions.ts`); the cast is
// safe because nothing else of the context is read on that path.
export function currentTerminal(context: Readonly<{ env?: NodeJS.ProcessEnv }>, io: RuntimeIO): CurrentTerminal {
  const env = context.env ?? process.env;
  return {
    ids: captureTerminalIdentity(env),
    tty: captureHostTty({ env } as RuntimeContext, io),
    termProgram: env.TERM_PROGRAM,
    bootId: hostBootId(env),
  };
}

function oneQuestionMessage(row: ResumeRow): string {
  const name = row.name !== undefined ? `"${row.name}" — ${row.agent}` : row.agent;
  return `Interrupted in this terminal (${row.time}, ${row.ago}):\n${name}`;
}

async function askOneQuestion(row: ResumeRow, api: PromptApi): Promise<ResumePromptChoice> {
  const choice = await api.select({
    message: oneQuestionMessage(row),
    options: [
      { value: "resume", label: "Resume it" },
      { value: "not-now", label: "Not now" },
      { value: "forget", label: "Forget it (don't ask again)" },
    ],
    initialValue: "resume",
  });
  if (api.isCancel(choice)) return { kind: "cancel" };
  if (choice === "resume") return { kind: "resume", item: row.item };
  if (choice === "forget") return { kind: "dismiss", item: row.item };
  // "not-now": ask again next time (spec section 5) — same as cancel.
  return { kind: "cancel" };
}

// Choosing a row opens a second question ("Resume it / Forget it / Back");
// "Back" returns to this same list with the cursor on the row just chosen,
// not reset to the original default (spec section 3, "Picker").
async function askPicker(
  rows: readonly ResumeRow[],
  defaultItemId: string | undefined,
  api: PromptApi,
): Promise<ResumePromptChoice> {
  let cursor = defaultItemId;
  while (true) {
    const chosen = await api.select({
      message: "Resume which interrupted session?",
      options: rows.map((row) => ({ value: row.item.id, label: formatResumeRow(row) })),
      initialValue: cursor,
    });
    if (api.isCancel(chosen)) return { kind: "cancel" };
    const row = rows.find((candidate) => candidate.item.id === chosen);
    if (!row) return { kind: "cancel" };
    cursor = row.item.id;
    const sub = await api.select({
      message: formatResumeRow(row),
      options: [
        { value: "resume", label: "Resume it" },
        { value: "forget", label: "Forget it" },
        { value: "back", label: "Back" },
      ],
      initialValue: "resume",
    });
    if (api.isCancel(sub)) return { kind: "cancel" };
    if (sub === "resume") return { kind: "resume", item: row.item };
    if (sub === "forget") return { kind: "dismiss", item: row.item };
    // "back": loop, re-showing the list with the cursor on the same row.
  }
}

export async function promptResumeSelection(
  selection: ResumeSelection,
  api: PromptApi = DEFAULT_PROMPT_API,
): Promise<ResumePromptChoice> {
  if (selection.kind === "none") return { kind: "cancel" };
  if (selection.kind === "one-question") return askOneQuestion(selection.row, api);
  return askPicker(selection.rows, selection.defaultItemId, api);
}
