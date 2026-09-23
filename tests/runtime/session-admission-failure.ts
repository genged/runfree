// Failure rendering for the internal admission runners.
//
// Both runners wrap a causal failure and its recovery failure in an
// `AggregateError`, but `Error.message` on an aggregate is only the wrapper's
// own sentence — the causes live in `.errors` and were never printed. So a live
// run that failed on, say, an unknown network participant reported only
// "recovery failed after 3 attempts; durable pending state remains", and the
// thing that actually went wrong was invisible.
//
// Observed exactly that way: two tranches could not see their own cause, and
// the assertions that named it looked wrong when they were right.
//
// This is the same lesson as `describe_output` in the shell fixture — the cause
// was present the whole time and simply not rendered.

const MAX_DEPTH = 8;

export function renderFailure(error: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) return "<nested failure depth limit reached>";
  if (!(error instanceof Error)) return String(error);

  const lines = [error.message];
  const causes = error instanceof AggregateError && Array.isArray(error.errors) ? error.errors : [];
  for (const [index, cause] of causes.entries()) {
    const rendered = renderFailure(cause, depth + 1);
    // Indented and numbered so a nested aggregate stays readable in a terminal
    // and in a Vitest assertion message, both of which collapse structure.
    for (const [lineIndex, line] of rendered.split("\n").entries()) {
      lines.push(`${"  ".repeat(depth + 1)}${lineIndex === 0 ? `cause ${index + 1}: ` : "  "}${line}`);
    }
  }
  if (causes.length === 0 && error.cause !== undefined) {
    lines.push(`${"  ".repeat(depth + 1)}cause: ${renderFailure(error.cause, depth + 1)}`);
  }
  return lines.join("\n");
}
