// The CLI's signal exit, in its own module so a process that is not the CLI
// entry (a test harness bundle) can install exactly the same handlers without
// importing `cli.ts`, whose entry check would start the CLI inside a bundle.

// Exit codes for a signal-terminated run (contract D3): the conventional
// 128+signal values, so a wrapper can tell an interrupt from a refusal.
export const SIGNAL_EXIT_CODES = Object.freeze({ SIGINT: 130, SIGTERM: 143 });

type SignalName = keyof typeof SIGNAL_EXIT_CODES;

export type SignalExitHooks = {
  flush: () => void;
  restore: () => void;
  exit: (code: number) => void;
};

// Install one-shot SIGINT/SIGTERM handlers that flush buffered warnings,
// restore the terminal, and exit 130/143. `once` means a second signal takes
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
      hooks.exit(SIGNAL_EXIT_CODES[signal]);
    });
  }
}
