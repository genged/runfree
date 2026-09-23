// `runfree assets <status|clean>` — manage the embedded runtime asset cache.
//
// These commands already materialized assets before this migration, so keeping
// `context.assets()` here preserves behavior (it installs/refreshes the current
// version before reporting status or pruning old versions).

import type { ArgumentsCamelCase } from "yargs";

import { cleanOldAssetVersions } from "../assets.ts";
import type { CommandModule } from "./types.ts";

type AssetsArgs = {
  subcommand: "status" | "clean";
};

export const assetsCommand: CommandModule = {
  name: "assets",
  register: (parser, context, handler) =>
    parser.command(
      "assets <subcommand>",
      "Inspect or clean embedded runtime assets",
      (cmd) =>
        cmd
          .positional("subcommand", {
            choices: ["status", "clean"] as const,
            describe: "asset action",
            demandOption: true,
          })
          .epilogue(
            "status  Show the installed embedded runtime asset version and location\n" +
              "clean   Remove embedded runtime asset versions other than the current one",
          ),
      handler((argv: ArgumentsCamelCase<AssetsArgs>) => {
        const assets = context.assets();
        if (argv.subcommand === "status") {
          console.log(`version: ${assets.version}`);
          console.log(`current: ${assets.currentDir}`);
          return;
        }
        const removed = cleanOldAssetVersions(context.env);
        console.log(
          removed.length === 0
            ? "no old asset versions to clean"
            : `removed asset versions: ${removed.join(", ")}`,
        );
      }),
    ),
};
