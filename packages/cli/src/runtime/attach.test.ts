import { expect, test } from "vitest";

import {
  INTERACTIVE_TERMINAL_RESTORE_SEQUENCE,
  restoreInteractiveTerminalControlModes,
} from "./attach.ts";

test("interactive terminal restore disables mouse and paste modes", () => {
  const writes: string[] = [];

  restoreInteractiveTerminalControlModes({
    isTTY: true,
    write: (chunk) => writes.push(chunk),
  });

  expect(writes).toEqual([INTERACTIVE_TERMINAL_RESTORE_SEQUENCE]);
  expect(writes[0]).toContain("\x1b[?1000l");
  expect(writes[0]).toContain("\x1b[?1003l");
  expect(writes[0]).toContain("\x1b[?1006l");
  expect(writes[0]).toContain("\x1b[?2004l");
  expect(writes[0]).toContain("\x1b[?25h");
});

test("interactive terminal restore skips non-TTY output", () => {
  const writes: string[] = [];

  restoreInteractiveTerminalControlModes({
    isTTY: false,
    write: (chunk) => writes.push(chunk),
  });

  expect(writes).toEqual([]);
});
