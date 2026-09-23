// `runfree project-id [--compose-name]` — pure command.
//
// project-id is a pure function of the resolved project path; it needs no
// materialized assets, Docker, or initialized project, so its handler never
// touches `context.assets()` or `context.projectInfo()`.

import type { ArgumentsCamelCase } from "yargs";

import { composeProjectName, projectHash } from "../project-identity.ts";
import type { CommandModule } from "./types.ts";

type ProjectIdArgs = {
  "compose-name": boolean;
};

export const projectIdCommand: CommandModule = {
  name: "project-id",
  register: (parser, context, handler) =>
    parser.command(
      "project-id",
      "Print this project's Runfree id",
      (cmd) =>
        cmd
          .option("compose-name", {
            type: "boolean",
            default: false,
            describe: "Print the Docker Compose project name (runfree-<id>)",
          }),
      handler((argv: ArgumentsCamelCase<ProjectIdArgs>) => {
        console.log(
          argv["compose-name"]
            ? composeProjectName(context.projectRoot)
            : projectHash(context.projectRoot),
        );
      }),
    ),
};
