// Shared yargs parser settings for the Runfree command app.
//
// The parser is strict, non-exiting, and keeps Runfree's custom top-level help
// and version behavior. See the spec's "Yargs Configuration" section.
//
// `.strict()` makes unknown commands, unknown options, AND extra positionals
// fail consistently across every command (so e.g. `service disable <id> typo`
// is rejected, not silently ignored). The single exception is the tolerant
// `$0 [agent]` default, which opts back out with `.strict(false)` in its own
// builder so trailing agent-specific flags/positionals (e.g. `claude --resume`)
// are accepted rather than rejected.

import yargs from "yargs";
import type { Argv } from "yargs";

export const RUNFREE_PARSER_CONFIGURATION = {
  "camel-case-expansion": false,
  "boolean-negation": false,
  "dot-notation": false,
  "duplicate-arguments-array": true,
  "parse-numbers": false,
  "parse-positional-numbers": false,
  "strip-aliased": true,
  "strip-dashed": false,
  "unknown-options-as-args": false,
} as const;

// Build a fresh parser per invocation. Callers pass the already-extracted
// command args (global `--workspace` is handled before this point), so the
// parser never reads `process.argv` directly.
export function createBaseParser(args: string[]): Argv {
  return yargs(args)
    .scriptName("runfree")
    .parserConfiguration(RUNFREE_PARSER_CONFIGURATION)
    // `--verbose` is accepted everywhere: `main()` prints stack traces for
    // unexpected errors only behind it, so no command may reject it. Commands
    // that give it a meaning re-declare it with a description.
    .option("verbose", { type: "boolean", hidden: true })
    .strict()
    .recommendCommands()
    .demandCommand()
    .help(false)
    .version(false)
    .exitProcess(false)
    .showHelpOnFail(false)
    .fail(false);
}
