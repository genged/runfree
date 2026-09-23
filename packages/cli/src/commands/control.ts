// Exact non-interactive approval for one typed desired-control subject.

import type { ArgumentsCamelCase } from "yargs";

import { nodeRuntimeIO } from "../runtime.ts";
import {
  approveImageBuild,
  approveNetworkControl,
  approveRuntimeIsolation,
} from "../control/workflow.ts";
import type { ControlSubjectType } from "../control/subjects.ts";
import type { CommandModule } from "./types.ts";

type ControlApproveArgs = {
  subject: ControlSubjectType;
  "subject-digest": string;
};

export const controlCommand: CommandModule = {
  name: "control",
  group: true,
  register: (parser, context, handler) =>
    parser.command(
      "control",
      "Approve an exact desired-control subject",
      (control) => control
        .command(
          "approve <subject>",
          "Approve one subject by its exact full digest",
          (cmd) => cmd
            .positional("subject", {
              choices: ["network-project", "network-local", "runtime-isolation", "image-build"] as const,
              demandOption: true,
              describe: "control subject type",
            })
            .option("subject-digest", {
              type: "string",
              requiresArg: true,
              demandOption: true,
              describe: "Exact full digest of this subject",
            }),
          handler(async (argv: ArgumentsCamelCase<ControlApproveArgs>) => {
            const runtime = context.runtimeContext();
            const digest = argv["subject-digest"];
            let approvedDigest: string | undefined;
            if (argv.subject === "network-project" || argv.subject === "network-local") {
              const selection = await approveNetworkControl(runtime, nodeRuntimeIO, argv.subject, {
                expectedDigest: digest,
                mechanism: "digest-command",
              });
              approvedDigest = selection.subjects[argv.subject]?.digest;
            } else if (argv.subject === "runtime-isolation") {
              const selection = await approveRuntimeIsolation(runtime, nodeRuntimeIO, {
                expectedDigest: digest,
                mechanism: "digest-command",
              });
              approvedDigest = selection.subjects[argv.subject]?.digest;
            } else {
              const selection = await approveImageBuild(runtime, nodeRuntimeIO, { expectedDigest: digest });
              approvedDigest = selection.subjects[argv.subject]?.digest;
            }
            console.log(`approved ${argv.subject}: ${approvedDigest}`);
          }),
        )
        .demandCommand(1),
      () => {},
    ),
};
