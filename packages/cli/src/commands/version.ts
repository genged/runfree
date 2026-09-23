// `runfree version` — pure command. No project state, no asset materialization.

import { RUNFREE_VERSION } from "../embedded-assets.generated.ts";
import type { CommandModule } from "./types.ts";

export const versionCommand: CommandModule = {
  name: "version",
  register: (parser, _context, handler) =>
    parser.command(
      "version",
      "Print the Runfree version",
      (cmd) => cmd,
      handler(() => {
        console.log(RUNFREE_VERSION);
      }),
    ),
};
