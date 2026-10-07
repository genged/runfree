import { describe, expect, test } from "vitest";

import type { EvidenceFingerprint, RecoveryItem } from "../runtime/recovery.ts";
import type { ResumeRow } from "../runtime/resume-selection.ts";
import type { RuntimeIO } from "../runtime/types.ts";
import { currentTerminal, promptResumeSelection, type PromptApi } from "./resume-prompt.ts";

const CANCEL = Symbol("cancel");

const FINGERPRINT: EvidenceFingerprint = {
  dev: 1,
  ino: 1,
  size: 10,
  mtimeMs: 0,
  schemaId: "host-session-v1",
  sha256: "a".repeat(64),
};

let counter = 0;

function item(overrides: Partial<RecoveryItem> = {}): RecoveryItem {
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
    ...overrides,
  };
}

function row(overrides: Partial<ResumeRow> = {}): ResumeRow {
  return {
    item: item(),
    match: "strong",
    source: "host",
    time: "14:02",
    ago: "6 min ago",
    agent: "claude",
    terminal: "ttys004 · this terminal",
    name: "refactor proxy denial messages",
    ...overrides,
  };
}

type SelectCall = Readonly<{
  message: string;
  options: ReadonlyArray<{ value: unknown; label: string }>;
  initialValue: unknown;
}>;

type SelectOpts = Readonly<{
  message: string;
  options: ReadonlyArray<{ value: unknown; label: string }>;
  initialValue?: unknown;
}>;

// A queue-driven fake of `@clack/prompts`' `select`/`isCancel`: each call to
// `select` records what it was asked and returns the next queued response
// (or the cancel sentinel). Nothing here touches a terminal.
function fakePromptApi(responses: readonly unknown[]): PromptApi & { calls: SelectCall[] } {
  const calls: SelectCall[] = [];
  let next = 0;
  return {
    calls,
    select: (async (opts: SelectOpts) => {
      calls.push({ message: opts.message, options: opts.options, initialValue: opts.initialValue });
      const response = responses[next];
      next += 1;
      return response;
    }) as unknown as PromptApi["select"],
    isCancel: ((value: unknown) => value === CANCEL) as unknown as PromptApi["isCancel"],
  };
}

describe("promptResumeSelection: one question", () => {
  test("asks with the host-fact message, Resume it / Not now / Forget it in order, defaulting to Resume it", async () => {
    const theRow = row();
    const api = fakePromptApi(["resume"]);

    const choice = await promptResumeSelection({ kind: "one-question", row: theRow }, api);

    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.message).toBe('Interrupted in this terminal (14:02, 6 min ago):\n"refactor proxy denial messages" — claude');
    expect(api.calls[0]?.options.map((option) => [option.value, option.label])).toEqual([
      ["resume", "Resume it"],
      ["not-now", "Not now"],
      ["forget", "Forget it (don't ask again)"],
    ]);
    expect(api.calls[0]?.initialValue).toBe("resume");
    expect(choice).toEqual({ kind: "resume", item: theRow.item });
  });

  test("Not now asks again next time (cancel)", async () => {
    const theRow = row();
    const choice = await promptResumeSelection({ kind: "one-question", row: theRow }, fakePromptApi(["not-now"]));
    expect(choice).toEqual({ kind: "cancel" });
  });

  test("Forget it dismisses the row", async () => {
    const theRow = row();
    const choice = await promptResumeSelection({ kind: "one-question", row: theRow }, fakePromptApi(["forget"]));
    expect(choice).toEqual({ kind: "dismiss", item: theRow.item });
  });

  test("Ctrl-C cancels", async () => {
    const theRow = row();
    const choice = await promptResumeSelection({ kind: "one-question", row: theRow }, fakePromptApi([CANCEL]));
    expect(choice).toEqual({ kind: "cancel" });
  });
});

describe("promptResumeSelection: picker", () => {
  function twoRows(): [ResumeRow, ResumeRow] {
    return [row({ name: "fix init wizard notes" }), row({ name: "release packaging", agent: "codex" })];
  }

  test("lists rows in order, labelled with formatResumeRow, defaulting to defaultItemId", async () => {
    const [first, second] = twoRows();
    const api = fakePromptApi([first.item.id, "back", first.item.id, "resume"]);

    await promptResumeSelection({ kind: "picker", rows: [first, second], defaultItemId: second.item.id }, api);

    const listCall = api.calls[0];
    expect(listCall?.message).toBe("Resume which interrupted session?");
    expect(listCall?.options.map((option) => option.value)).toEqual([first.item.id, second.item.id]);
    expect(listCall?.options[0]?.label).toContain("fix init wizard notes");
    expect(listCall?.options[1]?.label).toContain("release packaging");
    expect(listCall?.initialValue).toBe(second.item.id);
  });

  test("choosing a row opens Resume it / Forget it / Back, defaulting to Resume it", async () => {
    const [first, second] = twoRows();
    const api = fakePromptApi([first.item.id, "resume"]);

    const choice = await promptResumeSelection({ kind: "picker", rows: [first, second], defaultItemId: second.item.id }, api);

    const subCall = api.calls[1];
    expect(subCall?.options.map((option) => [option.value, option.label])).toEqual([
      ["resume", "Resume it"],
      ["forget", "Forget it"],
      ["back", "Back"],
    ]);
    expect(subCall?.initialValue).toBe("resume");
    expect(choice).toEqual({ kind: "resume", item: first.item });
  });

  test("Forget it in the sub-menu dismisses the chosen row", async () => {
    const [first, second] = twoRows();
    const api = fakePromptApi([second.item.id, "forget"]);

    const choice = await promptResumeSelection({ kind: "picker", rows: [first, second], defaultItemId: first.item.id }, api);

    expect(choice).toEqual({ kind: "dismiss", item: second.item });
  });

  test("Back returns to the list with the cursor on the same row", async () => {
    const [first, second] = twoRows();
    // Choose the non-default row, then Back, then resume that same row.
    const api = fakePromptApi([second.item.id, "back", second.item.id, "resume"]);

    const choice = await promptResumeSelection({ kind: "picker", rows: [first, second], defaultItemId: first.item.id }, api);

    expect(api.calls).toHaveLength(4);
    // The second list call's cursor is the row just backed out of, not the
    // original `defaultItemId`.
    expect(api.calls[2]?.initialValue).toBe(second.item.id);
    expect(choice).toEqual({ kind: "resume", item: second.item });
  });

  test("Ctrl-C at the list cancels", async () => {
    const [first, second] = twoRows();
    const choice = await promptResumeSelection({ kind: "picker", rows: [first, second], defaultItemId: first.item.id }, fakePromptApi([CANCEL]));
    expect(choice).toEqual({ kind: "cancel" });
  });

  test("Ctrl-C at the sub-menu cancels", async () => {
    const [first, second] = twoRows();
    const api = fakePromptApi([first.item.id, CANCEL]);
    const choice = await promptResumeSelection({ kind: "picker", rows: [first, second], defaultItemId: first.item.id }, api);
    expect(choice).toEqual({ kind: "cancel" });
  });
});

describe("promptResumeSelection: none", () => {
  test("asks nothing and cancels", async () => {
    const api = fakePromptApi([]);
    const choice = await promptResumeSelection({ kind: "none" }, api);
    expect(api.calls).toHaveLength(0);
    expect(choice).toEqual({ kind: "cancel" });
  });
});

describe("currentTerminal", () => {
  test("wires terminal identity, TERM_PROGRAM, and boot id from the environment", () => {
    const descriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: false });
    try {
      const env = {
        TERM_PROGRAM: "iTerm.app",
        ITERM_SESSION_ID: "w0t0p0:ABC",
        RUNFREE_TEST_FAKE_DOCKER: "1",
        RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      };
      // Without a TTY, `captureHostTty` must never shell out.
      const io = { capture: () => { throw new Error("must not probe tty without a TTY"); } } as unknown as RuntimeIO;

      const result = currentTerminal({ env }, io);

      expect(result.ids).toEqual({ iterm: "w0t0p0:ABC" });
      expect(result.termProgram).toBe("iTerm.app");
      expect(result.bootId).toBe("linux:11111111-2222-3333-4444-555555555555");
      expect(result.tty).toBeUndefined();
    } finally {
      if (descriptor) Object.defineProperty(process.stdin, "isTTY", descriptor);
      else Reflect.deleteProperty(process.stdin, "isTTY");
    }
  });
});
