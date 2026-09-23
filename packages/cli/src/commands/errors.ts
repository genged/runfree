// Normalize yargs parser failures into existing Runfree error behavior.
//
// The app runner distinguishes two failure classes (see the spec's "App Runner
// And Error Contract"):
//
//   - Parser/validation failures (unknown option, bad enum, missing/extra
//     positional) happen before any handler runs. These map to a `CliError`
//     so they print with the same stderr shape and exit status as the existing
//     usage failures.
//
//   - Handler failures happen after parsing succeeded. These propagate
//     unchanged so `CliError`/`AdminExit`/handler errors keep their status and
//     so yargs never prints generic command help over a real failure.

import { CliError } from "../errors.ts";

// Convert a parser/validation failure thrown by yargs into a usage CliError.
export function asUsageError(error: unknown): CliError {
  if (error instanceof CliError) return error;
  const message = error instanceof Error ? error.message : String(error);
  return new CliError(message.trim());
}
