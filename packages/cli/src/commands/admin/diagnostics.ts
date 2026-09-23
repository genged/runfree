// `runfree doctor` and `runfree runtime reload-policy` — operational,
// parser-light admin commands. doctor is read-only (diagnose blocked hosts);
// runtime reload-policy reloads policy and syncs tokens. Both run within the
// admin state; the parser validates before either touches the proxy.

import type { ArgumentsCamelCase } from "yargs";

import { createAdminState } from "../../admin/context.ts";
import { doctorIntent, reloadProxy, runAdminAction } from "../../admin/options.ts";
import type { RunfreeCommandContext } from "../context.ts";
import { withExamples } from "../examples.ts";
import type { CommandHandlerFactory, CommandModule } from "../types.ts";
import { startRuntime } from "../../runtime/startup.ts";
import { nodeRuntimeIO } from "../../runtime.ts";
import { readControlPlaneRebindTransaction } from "../../runtime/control-plane-rebind.ts";
import { projectHash, composeProjectName } from "../../runtime/env.ts";

type DoctorArgs = { "post-failure"?: boolean; tail?: string };

function adminRun(context: RunfreeCommandContext, action: () => Promise<void> | void): Promise<number> {
  return runAdminAction(createAdminState(context.adminContext()), action);
}

export const doctorCommand: CommandModule = {
  name: "doctor",
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "doctor",
      "Diagnose blocked proxy hosts",
      (cmd) =>
        withExamples(
          cmd
            .option("post-failure", { type: "boolean", describe: "Quiet output for end-of-session hooks" })
            .option("tail", { type: "string", requiresArg: true, describe: "Proxy log lines to scan" }),
          "doctor",
        ).epilogue(
          "Reads recent proxy denial events and suggests exact 'runfree host add/rules' commands. This command only reads; it never changes policy.",
        ),
      handler((argv: ArgumentsCamelCase<DoctorArgs>) =>
        adminRun(context, () => doctorIntent({ postFailure: Boolean(argv["post-failure"]), tail: argv.tail })),
      ),
    ),
};

export const runtimeAdminCommand: CommandModule = {
  name: "runtime",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "runtime",
      "Runtime maintenance",
      (runtime) => {
        const built = runtime.command(
          "reload-policy",
          "Reload runtime policy and sync credentials",
          (cmd) => cmd.option("force", { type: "boolean", default: false, describe: "Authorize proxy restart while sessions are live" })
            .epilogue("Restart the proxy, reload policy, and re-sync proxy-managed tokens. Live sessions require --force."),
          handler((argv: ArgumentsCamelCase<{ force: boolean }>) => adminRun(context, () => reloadProxy({ force: argv.force }))),
        );
        built.command("recover", "Resume the pending compatible proxy replacement",
          (cmd) => cmd.option("retry", { type: "boolean", default: false, describe: "Grant this transaction a new 120-second, two-creation allowance" }),
          handler(async (argv: ArgumentsCamelCase<{ retry: boolean }>) => {
            const runtimeContext = context.runtimeContext();
            const transaction = readControlPlaneRebindTransaction(runtimeContext.project.paths.stateDir,
              { projectId: projectHash(runtimeContext.projectRoot), composeProject: composeProjectName(runtimeContext.projectRoot) });
            if (!transaction) throw new Error("no proxy replacement is pending; use runfree up to prove the current runtime");
            return (await startRuntime(runtimeContext, nodeRuntimeIO, false, { useApprovedPolicy: true, recoveryRetry: argv.retry })).status;
          }));
        return withExamples(built, "runtime").demandCommand(1);
      },
      () => {},
    ),
};
