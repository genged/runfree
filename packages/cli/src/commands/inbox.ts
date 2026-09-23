// `runfree inbox <paste|clean>` and the deprecated `runfree paste-image`
// compatibility leaf. The group keeps host-triggered clipboard import and
// cleanup typed and validates flags before touching either clipboard or state.

import type { ArgumentsCamelCase } from "yargs";

import {
  cleanupInbox,
  ensureInbox,
  importImageFromClipboard,
  tryCopyTextToHostClipboard,
} from "../inbox.ts";
import type { RunfreeCommandContext } from "./context.ts";
import { withExamples } from "./examples.ts";
import type { CommandModule } from "./types.ts";

type InboxPasteArgs = { copy?: boolean };
type InboxCleanArgs = { all?: boolean };
type PasteImageArgs = { clean?: boolean; copy?: boolean };

function pasteInboxImage(context: RunfreeCommandContext, copy: boolean): void {
  const project = context.projectInfo();
  const imported = importImageFromClipboard({
    env: context.env,
    hostInbox: project.paths.inboxDir,
  });
  console.log(imported.containerPath);
  if (!copy) return;
  const copyError = tryCopyTextToHostClipboard(imported.containerPath, context.env);
  if (copyError) console.error(`warning: image imported at ${imported.containerPath}; copy failed: ${copyError}`);
}

function cleanInbox(context: RunfreeCommandContext, all: boolean): void {
  const hostInbox = context.projectInfo().paths.inboxDir;
  ensureInbox(hostInbox);
  const removed = cleanupInbox(hostInbox, new Date(), { all });
  console.log(`removed ${removed.length} inbox file(s)`);
}

export const inboxCommand: CommandModule = {
  name: "inbox",
  group: true,
  register: (parser, context, handler) =>
    parser.command(
      "inbox <subcommand>",
      "Import and manage files in the Runfree inbox",
      (inbox) => {
        const built = inbox
          .command(
            "paste",
            "Import a macOS clipboard image",
            (cmd) => cmd.option("copy", {
              type: "boolean",
              describe: "Copy the imported image's container path to the host clipboard",
            }),
            handler((argv: ArgumentsCamelCase<InboxPasteArgs>) => pasteInboxImage(context, Boolean(argv.copy))),
          )
          .command(
            "clean",
            "Remove imported inbox files",
            (cmd) => cmd.option("all", {
              type: "boolean",
              describe: "Remove every Runfree-minted inbox file instead of only files older than 24 hours",
            }),
            handler((argv: ArgumentsCamelCase<InboxCleanArgs>) => cleanInbox(context, Boolean(argv.all))),
          );
        return withExamples(built, "inbox")
          .epilogue("The inbox is mounted read-only at /runfree/inbox inside the agent container.")
          .demandCommand(1);
      },
      () => {},
    ),
};

export const pasteImageCommand: CommandModule = {
  name: "paste-image",
  register: (parser, context, handler) =>
    parser.command(
      "paste-image",
      false,
      (cmd) =>
        cmd
          .option("copy", {
            type: "boolean",
            describe: "Copy the imported image's container path to the host clipboard",
          })
          .option("clean", {
            type: "boolean",
            describe: "Remove imported images older than 24 hours (cannot combine with --copy)",
          })
          .conflicts("copy", "clean"),
      handler((argv: ArgumentsCamelCase<PasteImageArgs>) => {
        console.error("warning: `runfree paste-image` is deprecated; use `runfree inbox paste`");
        if (argv.clean) {
          cleanInbox(context, false);
          return;
        }
        pasteInboxImage(context, Boolean(argv.copy));
      }),
    ),
};
