import { CliError, renderUnexpectedError, UNEXPECTED_ERROR_RENDER_LIMITS } from "../errors.ts";
import { remedy } from "../remedies.ts";
import { ControlPlaneRebindCandidateMismatchError } from "./control-plane-rebind-coordinator.ts";

export type ControlPlaneRebindRefusalOutcome = Readonly<{
  final: string;
  subject: string;
  verbose: boolean;
}>;

function controlPlaneRebindRefusal(
  error: ControlPlaneRebindCandidateMismatchError,
  outcome: ControlPlaneRebindRefusalOutcome,
): CliError {
  const lines = [
    `${outcome.subject} because Runfree could not safely continue a proxy replacement.`,
    "The proxy in the pending rebind journal does not match the proxy that Docker reports.",
    `Inspect work that a rebuild can stop: ${remedy.sessions()}`,
    `Recreate this project's runtime: ${remedy.rebuild()}`,
  ];
  if (outcome.verbose) {
    lines.push(
      "Internal diagnostic:",
      renderUnexpectedError(error, UNEXPECTED_ERROR_RENDER_LIMITS, { stack: true }),
    );
  }
  lines.push(outcome.final);
  return Object.assign(new CliError(lines.join("\n"), 1), { cause: error });
}

export async function withControlPlaneRebindRefusal<T>(
  outcome: ControlPlaneRebindRefusalOutcome,
  action: () => Promise<T>,
): Promise<T> {
  try {
    return await action();
  } catch (error) {
    if (!(error instanceof ControlPlaneRebindCandidateMismatchError)) throw error;
    throw controlPlaneRebindRefusal(error, outcome);
  }
}
