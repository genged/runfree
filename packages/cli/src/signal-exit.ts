// The CLI's signal exit, in its own module so a process that is not the CLI
// entry (a test harness bundle) can install exactly the same handlers without
// importing `cli.ts`, whose entry check would start the CLI inside a bundle.

// Exit codes for a signal-terminated run (contract D3): the conventional
// 128+signal values, so a wrapper can tell an interrupt from a refusal.
export const SIGNAL_EXIT_CODES = Object.freeze({ SIGINT: 130, SIGTERM: 143 });

type SignalName = keyof typeof SIGNAL_EXIT_CODES;

// A long-lived credential watch must unwind through its locks and join its
// providers before the process ends, so while a deferral is held the
// handlers below only flush and restore; the watch observes the signal itself
// and exits once its work has settled. Counted, so nested holders compose.
let exitDeferrals = 0;

/** Hold the signal exit until the returned release runs (idempotent). */
export function deferSignalExit(): () => void {
  exitDeferrals += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    exitDeferrals -= 1;
  };
}

export type SignalExitHooks = {
  flush: () => void;
  restore: () => void;
  exit: (code: number) => void;
};

// Install one-shot SIGINT/SIGTERM handlers that flush buffered warnings,
// restore the terminal, and exit 130/143 (unless a deferral is held). `once` means a second signal takes
// the default action (immediate exit) without re-running the handlers, and
// restoration is idempotent so a signal during a prompt or a half-initialized
// command is safe. The flush is best-effort synchronous.
export function installSignalExit(
  hooks: SignalExitHooks,
  target: Pick<NodeJS.Process, "once"> = process,
): void {
  for (const signal of Object.keys(SIGNAL_EXIT_CODES) as SignalName[]) {
    target.once(signal, () => {
      try {
        hooks.flush();
      } catch {
        // Best effort: never let a failed flush block terminal restoration.
      }
      try {
        hooks.restore();
      } catch {
        // Same: exit regardless.
      }
      if (exitDeferrals > 0) return;
      hooks.exit(SIGNAL_EXIT_CODES[signal]);
    });
  }
}
