// The process-wide headless terminal mode (headless-run spec §3.3).
//
// A `runfree run` must never prompt and never treat the host's own TTYs as a
// person at the keyboard: a tmux pane or a CI runner with a PTY has them. Most
// prompts already go through `RuntimeIO`, which `createHeadlessRuntimeIO`
// replaces; the rest read `process.stdin.isTTY`/`process.stdout.isTTY`
// directly, and every such read on the `run` path asks here instead, so one
// switch covers both.
//
// The mode only ever narrows: while it is held every reader answers
// "not interactive", and outside it each reader answers exactly as it did
// before this module existed.

import type { RuntimeIO } from "./runtime/types.ts";

type TtyStream = Readonly<{ isTTY?: boolean }>;

// Counted, so nested holders compose and a release is never lost.
let headlessHolds = 0;

/** Holds the headless mode until the returned release runs (idempotent). */
export function enterHeadlessTerminalMode(): () => void {
  headlessHolds += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    headlessHolds -= 1;
  };
}

/** Whether a headless run holds the mode now. */
export function headlessTerminalModeActive(): boolean {
  return headlessHolds > 0;
}

/** Whether `stream` is a terminal a person may be at: never while headless. */
export function hostStreamIsTty(stream: TtyStream): boolean {
  return !headlessTerminalModeActive() && stream.isTTY === true;
}

/** Whether host stdin and stdout are both terminals a person may be at. */
export function hostTerminalInteractive(
  streams: Readonly<{ stdin: TtyStream; stdout: TtyStream }> = process,
): boolean {
  return hostStreamIsTty(streams.stdin) && hostStreamIsTty(streams.stdout);
}

/** Whether host stdout is a terminal a person may be watching. */
export function hostStdoutIsTty(stream: TtyStream = process.stdout): boolean {
  return hostStreamIsTty(stream);
}

/**
 * The runtime IO a headless run uses for its whole life: it never asks
 * (`confirm` answers no, the Pi chooser offers nothing) and is never
 * interactive; everything else is the base IO's. `captureAsync` is present
 * exactly when the base has one (`RuntimeIO.captureAsync`).
 */
export function createHeadlessRuntimeIO(base: RuntimeIO): RuntimeIO {
  return {
    ...base,
    confirm: () => false,
    choosePiProvider: () => undefined,
    isInteractive: () => false,
  };
}
