// `runfree update` — placeholder that explains Runfree does not self-update yet.
//
// Typed command module: the grammar is validated by yargs (no options) and the
// handler prints the same guidance the legacy dispatcher did. It performs no
// project or runtime side effects.

import type { RunfreeCommandContext } from "./context.ts";
import type { CommandHandlerFactory, CommandModule } from "./types.ts";

export const updateCommand: CommandModule = {
  name: "update",
  register: (parser, _context: RunfreeCommandContext, handler: CommandHandlerFactory) =>
    parser.command(
      "update",
      "Explain how to update the Runfree binary",
      (cmd) =>
        cmd.epilogue(
          "Runfree does not replace the running binary yet. Install the latest release with " +
            "the same method you used for this binary; your project .runfree files are left unchanged.",
        ),
      handler(() => {
        console.log("runfree update does not replace the running binary yet");
        console.log("install the latest release with the same method you used for this binary");
        console.log("project .runfree files were not changed");
        return 0;
      }),
    ),
};
