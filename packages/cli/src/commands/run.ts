// `runfree run <agent> --prompt-file <file>`: one headless agent turn
// (headless-run spec §3, plan Task 14).
//
// The module only parses and checks usage; `runHeadlessAgent` is the run.
// Every usage problem exits 64 before any project, asset, or Docker work:
// yargs refusals (the app maps them to 64 for this command, plan C4), the
// agent choice (built-in agents with a headless mode only), the timeout
// bound, and the prompt file, which is checked here before the runtime
// context is built and read again by the orchestrator. Nothing is passed
// through to the agent: Runfree mints its argv (D-3).

import path from "node:path";

import type { ArgumentsCamelCase } from "yargs";

import { parseDurationSeconds } from "../admin/admin-core.ts";
import { CliError } from "../errors.ts";
import { nodeRuntimeIO } from "../runtime.ts";
import { withControlPlaneRebindRefusal } from "../runtime/control-plane-rebind-refusal.ts";
import { runtimeDryRun } from "../runtime/front.ts";
import { HeadlessPromptFileError, readPromptFileBounded } from "../runtime/headless-prompt.ts";
import { HEADLESS_RUN_EXIT, headlessAgentIds, runHeadlessAgent } from "../runtime/headless-run.ts";
import type { RuntimeContext } from "../runtime/types.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { withExamples } from "./examples.ts";
import type { CommandHandlerFactory, CommandModule } from "./types.ts";

/** The `--timeout` bound: one second to one day. */
export const RUN_TIMEOUT_MAX_SECONDS = 24 * 60 * 60;

type RunArgs = {
  agent: string;
  "prompt-file": string;
  timeout?: number;
  "accept-denied-writes": boolean;
  verbose?: boolean;
};

function parseRunTimeout(value: string): number {
  const seconds = parseDurationSeconds(value, "--timeout");
  if (seconds > RUN_TIMEOUT_MAX_SECONDS) throw new CliError("--timeout must be at most 24h", HEADLESS_RUN_EXIT.usage);
  return seconds;
}

export const runCommand: CommandModule = {
  name: "run",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "run <agent>",
      "Run one headless agent turn with a prompt file, for schedulers",
      (cmd) =>
        withExamples(
          cmd
            .positional("agent", {
              type: "string",
              choices: headlessAgentIds(),
              describe: "Built-in agent to run",
            })
            .option("prompt-file", {
              type: "string",
              requiresArg: true,
              demandOption: true,
              describe: "Prompt file given to the agent as stdin (regular file, at most 1 MiB)",
            })
            .option("timeout", {
              type: "string",
              requiresArg: true,
              describe: "Stop the run after this long, like 30m or 2h (at most 24h); exits 67",
              coerce: parseRunTimeout,
            })
            .option("accept-denied-writes", {
              type: "boolean",
              default: false,
              describe: "Exit 0 even if the proxy denied writes that would ask for approval (otherwise 68)",
            })
            .option("verbose", { type: "boolean", alias: "v", describe: "Show extra startup diagnostics" })
            // Strict mode does not see words after `--`; yargs keeps them in
            // `_` after the command word. The agent's argv is Runfree's (D-3).
            .check((argv) => {
              const extra = argv._.slice(1);
              if (extra.length > 0) {
                throw new CliError(`Unknown argument: ${extra.join(" ")} (nothing is passed to the agent)`, HEADLESS_RUN_EXIT.usage);
              }
              return true;
            })
            .epilogue(
              "The run never prompts and never holds a write for approval. "
                + "Exit codes: 0 success, 1-63 the agent failed or the result is unverified, 64 usage, "
                + "65 refused before launch (an approval, service review, or credential source), 66 another run holds the project lock, 67 timeout or signal, "
                + "68 success but writes were denied without --accept-denied-writes. "
                + "The run record is kept in Runfree state under runs/<run-id>/, never in the project.",
            ),
          "run",
        ),
      handler(async (argv: ArgumentsCamelCase<RunArgs>) => {
        // Resolved against where runfree was invoked, not `--workspace`.
        const promptFile = path.resolve(context.invocationCwd, argv["prompt-file"]);
        try {
          readPromptFileBounded(promptFile);
        } catch (error) {
          if (error instanceof HeadlessPromptFileError) throw new CliError(error.message, HEADLESS_RUN_EXIT.usage);
          throw error;
        }
        let rc: RuntimeContext;
        try {
          rc = context.runtimeContext();
        } catch (error) {
          // An invalid project config or network policy refuses before the launch.
          throw new CliError(
            `${error instanceof Error ? error.message : String(error)}\nthe headless run did not start`,
            HEADLESS_RUN_EXIT.refused,
          );
        }
        const dry = runtimeDryRun(rc, nodeRuntimeIO, "run");
        if (dry !== undefined) return dry;
        const verbose = Boolean(argv.verbose);
        return withControlPlaneRebindRefusal({
          subject: "The headless run did not start",
          final: "the headless run did not start",
          verbose,
          status: HEADLESS_RUN_EXIT.refused,
        }, () => runHeadlessAgent(rc, nodeRuntimeIO, argv.agent, {
          promptFile,
          ...(argv.timeout !== undefined ? { timeoutMs: argv.timeout * 1000 } : {}),
          acceptDeniedWrites: argv["accept-denied-writes"],
          verbose,
        }));
      }),
    ),
};
