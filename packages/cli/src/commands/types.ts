// Shared types for the command layer. Kept separate from `app.ts` so command
// modules can import these types without a value-import cycle.

import type { Argv } from "yargs";

import type { RunfreeCommandContext } from "./context.ts";

// Each command registers its handler through this factory. The factory records
// that a handler started (so the runner can tell parser failures apart from
// handler failures) and captures the handler's exit status.
// The wrapped `run` may return a numeric exit status or nothing; the runner
// only acts on a numeric result. `unknown` keeps both shapes (and async
// variants) assignable without a confusing `void` union.
export type CommandHandlerFactory = <A>(
  run: (argv: A) => unknown,
) => (argv: A) => Promise<void>;

// A migrated command module. `register` defines the command's yargs parsing,
// handler, and — via `.describe()`/`.option({describe})`/`.positional()`/
// `.group()`/`.example()`/`.epilogue()` — its documentation. `--help`/`-h` is
// rendered natively by yargs from that builder metadata (the command spec is the
// single source of truth; see that spec principle). No hand-written usage string.
//
// `group: true` marks a command that requires a subcommand (e.g. `image`,
// `vnc`). For groups, a bare `runfree <name>` prints the group's native help as
// a usage error (a subcommand is required); for leaf commands, a bare invocation
// runs the handler. Either kind renders native help on `--help`/`-h`.
// `runDefault` is a no-delegation guard, not active wiring: every command is now
// a typed module that resolves and runs its own intent, so no module calls it.
// The app threads it through (and `cli.ts` passes a throwing sentinel) only so an
// accidental future delegation fails loudly instead of silently reviving the
// removed legacy/runtime dispatcher; tests assert it is never invoked.
export type CommandModule = {
  name: string;
  group?: boolean;
  register(
    parser: Argv,
    context: RunfreeCommandContext,
    handler: CommandHandlerFactory,
    runDefault: () => Promise<number>,
  ): Argv;
};
