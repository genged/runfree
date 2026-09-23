// `runfree credential ...` — canonical low-level credential policy, source
// binding, runtime sync, and host-owned named-source surface.

import type { ArgumentsCamelCase, Argv } from "yargs";

import { createAdminState } from "../../admin/context.ts";
import {
  bindDesiredCredentialSource,
  type CredentialFieldsInput,
  credentialClearSourceIntent,
  credentialSetSourceIntent,
  credentialSourceSelectionFromArgs,
  credentialStatus,
  credentialSyncIntent,
  runAdminAction,
  revokeDesiredCredentialState,
  sourceAddCommandIntent,
  sourceAddJwtIntent,
  sourceList,
  sourceRemoveIntent,
  sourceShowIntent,
} from "../../admin/options.ts";
import { activateApprovedControlsAfterMutation } from "../../control/activation.ts";
import { activationReportLine } from "../../control/activation-report.ts";
import {
  desiredCredentialFromFields,
  mutateDesiredCredential,
  type DesiredCredentialMutation,
} from "../../control/credential-mutation.ts";
import { CliError } from "../../errors.ts";
import { nodeRuntimeIO } from "../../runtime.ts";
import type { RuntimeContext } from "../../runtime/types.ts";
import type { RunfreeCommandContext } from "../context.ts";
import { withExamples } from "../examples.ts";
import type { CommandHandlerFactory, CommandModule } from "../types.ts";
import { NO_RELOAD_DESCRIBE } from "./no-reload.ts";

const SOURCE_GROUP = "Credential source (choose at most one):";
const POLICY_GROUP = "Credential destination:";
const JWT_SOURCE_GROUP = "JWT source (credential source add jwt ...):";

type NameArgs = { name: string };
type CredentialArgs = {
  host?: string;
  header?: string;
  scheme?: string;
  "path-prefix"?: string;
};
type SourceArgs = {
  "from-env"?: string;
  "from-1password"?: string;
  "from-source"?: string;
  "from-stdin"?: boolean;
  "refresh-every"?: string;
  "replace-source"?: boolean;
  "no-sync"?: boolean;
};
type AddArgs = NameArgs & CredentialArgs & SourceArgs & { description?: string; "no-reload"?: boolean };
type LinkArgs = NameArgs & CredentialArgs & { "no-reload"?: boolean };
type UnlinkArgs = NameArgs & { host: string; header?: string; "no-reload"?: boolean };
type RemoveArgs = NameArgs & { "no-reload"?: boolean };
type SetSourceArgs = NameArgs & SourceArgs;
type StatusArgs = { name?: string };
type SyncArgs = {
  verbose?: boolean;
  watch?: boolean;
  quiet?: boolean;
  "delay-first-sync"?: boolean;
  "no-cache-source-secrets"?: boolean;
};
type SourceAddArgs = {
  args?: string[];
  "replace-source"?: boolean;
  alg?: string | string[];
  "private-key-from-1password"?: string | string[];
  ttl?: string | string[];
  claim?: string[];
  header?: string[];
  "--"?: string[];
};

const namePositional = (cmd: Argv): Argv =>
  cmd.positional("name", { type: "string", demandOption: true, describe: "credential name" });

const destinationOptions = (cmd: Argv): Argv =>
  cmd
    .option("host", { type: "string", requiresArg: true, demandOption: true, group: POLICY_GROUP, describe: "Already-allowlisted destination host" })
    .option("header", { type: "string", requiresArg: true, group: POLICY_GROUP, describe: "Header to inject (default Authorization)" })
    .option("scheme", { type: "string", requiresArg: true, group: POLICY_GROUP, describe: "Credential scheme (bearer | raw)" })
    .option("path-prefix", { type: "string", requiresArg: true, group: POLICY_GROUP, describe: "Restrict injection to this path prefix" })
    .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE });

function credentialFields(argv: CredentialArgs): CredentialFieldsInput {
  return {
    host: argv.host,
    header: argv.header,
    scheme: argv.scheme,
    pathPrefix: argv["path-prefix"],
  };
}

// Source-binding flags. `credential add` binds the source without a proxy sync
// (the value reaches the proxy on the next converged runtime), so it takes
// these without `--no-sync`; only `set-source` syncs and can skip it.
const sourceBindingOptions = (cmd: Argv): Argv =>
  cmd
    .option("from-env", { type: "string", requiresArg: true, group: SOURCE_GROUP, describe: "Resolve from this host environment variable" })
    .option("from-1password", { type: "string", requiresArg: true, group: SOURCE_GROUP, describe: "Resolve from a 1Password ref (op://...)" })
    .option("from-source", { type: "string", requiresArg: true, group: SOURCE_GROUP, describe: "Bind a saved host-owned named source" })
    .option("from-stdin", { type: "boolean", group: SOURCE_GROUP, describe: "Read from stdin (plaintext storage remains disabled)" })
    .option("refresh-every", { type: "string", requiresArg: true, describe: "Re-resolve on this interval (e.g. 15m)" })
    .option("replace-source", { type: "boolean", describe: "Replace an existing source binding" });

const sourceOptions = (cmd: Argv): Argv =>
  sourceBindingOptions(cmd)
    .option("no-sync", { type: "boolean", describe: "Do not sync the proxy after binding the source" });

function sourceIntent(argv: SourceArgs) {
  return {
    tokenSource: credentialSourceSelectionFromArgs({
      env: argv["from-env"],
      onePassword: argv["from-1password"],
      source: argv["from-source"],
      stdin: argv["from-stdin"],
    }),
    refreshEvery: argv["refresh-every"],
    replaceSource: Boolean(argv["replace-source"]),
    sync: !argv["no-sync"],
  };
}

const sourceNamePositional = (cmd: Argv): Argv =>
  cmd.positional("name", { type: "string", demandOption: true, describe: "named source" });

const sourceAddBuilder = (cmd: Argv): Argv =>
  cmd
    .parserConfiguration({ "populate--": true })
    .positional("args", { type: "string", array: true, describe: "<name> -- <command> | jwt <name> [jwt options]" })
    .option("replace-source", { type: "boolean", describe: "Overwrite an existing source" })
    .option("alg", { type: "string", requiresArg: true, group: JWT_SOURCE_GROUP, describe: "JWT signing algorithm (e.g. ES256)" })
    .option("private-key-from-1password", { type: "string", requiresArg: true, group: JWT_SOURCE_GROUP, describe: "JWT private-key 1Password ref" })
    .option("ttl", { type: "string", requiresArg: true, group: JWT_SOURCE_GROUP, describe: "JWT lifetime (e.g. 19m)" })
    .option("claim", { type: "string", array: true, requiresArg: true, nargs: 1, group: JWT_SOURCE_GROUP, describe: "JWT claim key=value (repeatable)" })
    .option("header", { type: "string", array: true, requiresArg: true, nargs: 1, group: JWT_SOURCE_GROUP, describe: "JWT header key=value (repeatable)" });

const JWT_ONLY_FLAGS: ReadonlyArray<readonly [keyof SourceAddArgs, string]> = [
  ["alg", "--alg"],
  ["private-key-from-1password", "--private-key-from-1password"],
  ["ttl", "--ttl"],
  ["claim", "--claim"],
  ["header", "--header"],
];

export const credentialCommand: CommandModule = {
  name: "credential",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) => {
    const run = (action: () => Promise<void> | void): Promise<number> =>
      runAdminAction(createAdminState(context.adminContext()), action);
    const runSource = (action: () => Promise<void> | void): Promise<number> =>
      runAdminAction(createAdminState(context.sourceAdminContext()), action);
    const mutateDesired = async (
      runtime: RuntimeContext,
      mutation: DesiredCredentialMutation,
      reloadProxy: boolean,
      afterMutation?: () => void,
    ): Promise<void> => {
      const result = await mutateDesiredCredential(runtime, nodeRuntimeIO, mutation);
      console.log(`credential ${result.name}: ${result.changed ? "updated" : "unchanged"} in project desired policy`);
      console.log(`approved project desired policy: ${result.projectDigest.slice(0, 19)}… (approval record id)`);
      afterMutation?.();
      if (!reloadProxy) {
        console.log("effective policy: unchanged (--no-reload)");
        return;
      }
      const activation = await activateApprovedControlsAfterMutation(runtime, nodeRuntimeIO);
      console.log(activationReportLine(activation));
    };

    return parser.command(
      "credential",
      "Manage proxy-held credentials, destinations, and host-owned sources",
      (credential) => {
        const built = credential
          .command(
            "add <name>",
            "Create or ensure a credential destination on an already-allowlisted host",
            (cmd) => sourceBindingOptions(destinationOptions(namePositional(cmd))).option("description", {
              type: "string",
              requiresArg: true,
              describe: "Public description stored in project policy",
            }),
            handler((argv: ArgumentsCamelCase<AddArgs>) => {
              const intent = {
                name: argv.name,
                credential: credentialFields(argv),
                description: argv.description,
                reloadProxy: !argv["no-reload"],
                ...sourceIntent(argv),
              };
              return run(async () => {
                const runtime = context.runtimeContext();
                await mutateDesired(runtime, {
                  kind: "add",
                  name: intent.name,
                  description: intent.description,
                  credential: desiredCredentialFromFields(intent.credential),
                }, intent.reloadProxy, () => {
                  const sourceBound = bindDesiredCredentialSource(intent);
                  console.log(`host-owned source: ${sourceBound ? "bound; sync on next converged runtime" : "unchanged"}`);
                });
              });
            }),
          )
          .command(
            "link <name>",
            "Add a destination to an existing credential",
            (cmd) => destinationOptions(namePositional(cmd)),
            handler((argv: ArgumentsCamelCase<LinkArgs>) => run(() => {
              const intent = {
                name: argv.name,
                credential: credentialFields(argv),
                reloadProxy: !argv["no-reload"],
              };
              const runtime = context.runtimeContext();
              return mutateDesired(runtime, {
                kind: "link",
                name: intent.name,
                credential: desiredCredentialFromFields(intent.credential),
              }, intent.reloadProxy);
            })),
          )
          .command(
            "unlink <name>",
            "Remove one credential destination without changing its host or source",
            (cmd) => namePositional(cmd)
              .option("host", { type: "string", requiresArg: true, demandOption: true, describe: "Destination host" })
              .option("header", { type: "string", requiresArg: true, describe: "Destination header (default Authorization)" })
              .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<UnlinkArgs>) => run(() => {
              const intent = {
                name: argv.name,
                host: argv.host,
                header: argv.header,
                reloadProxy: !argv["no-reload"],
              };
              const runtime = context.runtimeContext();
              return mutateDesired(runtime, { kind: "unlink", name: intent.name, host: intent.host, header: intent.header }, intent.reloadProxy);
            })),
          )
          .command(
            "remove <name>",
            "Remove a manually managed credential, its source binding, and proxy value",
            (cmd) => namePositional(cmd).option("no-reload", { type: "boolean", describe: `${NO_RELOAD_DESCRIBE}; the proxy-held value is still revoked` }),
            handler((argv: ArgumentsCamelCase<RemoveArgs>) => run(async () => {
              const intent = { name: argv.name, reloadProxy: !argv["no-reload"] };
              const runtime = context.runtimeContext();
              const revoked = revokeDesiredCredentialState(intent.name);
              console.log(`host/proxy credential state: ${revoked}`);
              await mutateDesired(runtime, { kind: "remove", name: intent.name }, intent.reloadProxy);
            })),
          )
          .command(
            "set-source <name>",
            "Bind a host-owned value source to an existing credential",
            (cmd) => sourceOptions(namePositional(cmd)),
            handler((argv: ArgumentsCamelCase<SetSourceArgs>) => {
              const intent = { name: argv.name, ...sourceIntent(argv) };
              return run(() => credentialSetSourceIntent(intent));
            }),
          )
          .command(
            "clear-source <name>",
            "Remove a credential source binding and its proxy-held value",
            (cmd) => namePositional(cmd),
            handler((argv: ArgumentsCamelCase<NameArgs>) => run(() => credentialClearSourceIntent({ name: argv.name }))),
          )
          .command(
            "status [name]",
            "Show credential destinations, ownership, sources, and sync status",
            (cmd) => cmd.positional("name", { type: "string", describe: "optional credential name" }),
            handler((argv: ArgumentsCamelCase<StatusArgs>) => run(() => credentialStatus({ name: argv.name }))),
          )
          .command(
            "sync",
            "Resolve credential sources and reconcile proxy-only values",
            (cmd) => cmd
              .option("verbose", { type: "boolean", alias: "v", describe: "Print per-credential resolution details" })
              .option("watch", { type: "boolean", describe: "Keep running and re-sync as sources become due" })
              .option("quiet", { type: "boolean", describe: "Suppress non-error watch output" })
              .option("delay-first-sync", { type: "boolean", describe: "Wait until the first source is due" })
              .option("no-cache-source-secrets", { type: "boolean", describe: "Disable memory-only source-secret caching" }),
            handler((argv: ArgumentsCamelCase<SyncArgs>) => run(() => credentialSyncIntent({
              verbose: Boolean(argv.verbose),
              watch: Boolean(argv.watch),
              quiet: Boolean(argv.quiet),
              delayFirstSync: Boolean(argv["delay-first-sync"]),
              cacheSourceSecrets: !argv["no-cache-source-secrets"],
            }))),
          )
          .command(
            "source",
            "Manage reusable host-owned command and JWT sources",
            (source) => source
              .command(
                "add [args..]",
                "Add a host-owned command or JWT source",
                sourceAddBuilder,
                handler((argv: ArgumentsCamelCase<SourceAddArgs>) => {
                  const positionals = argv.args ?? [];
                  if (positionals[0] === "jwt") {
                    if (positionals.length > 2) throw new CliError(`unexpected credential source add argument: ${positionals[2]}`);
                    const afterSeparator = argv["--"] ?? [];
                    if (afterSeparator.length > 0) throw new CliError(`unexpected tokens after -- in credential source add jwt: ${afterSeparator[0]}`);
                    return runSource(() => sourceAddJwtIntent({
                      name: positionals[1],
                      replaceSource: Boolean(argv["replace-source"]),
                      alg: argv.alg,
                      privateKeyRef: argv["private-key-from-1password"],
                      ttl: argv.ttl,
                      claims: argv.claim ?? [],
                      headers: argv.header ?? [],
                    }));
                  }
                  if (positionals.length > 1) throw new CliError(`unexpected credential source add argument before --: ${positionals[1]}`);
                  for (const [key, flag] of JWT_ONLY_FLAGS) {
                    if (argv[key] !== undefined) throw new CliError(`unknown option: ${flag}`);
                  }
                  return runSource(() => sourceAddCommandIntent({
                    name: positionals[0],
                    replaceSource: Boolean(argv["replace-source"]),
                    command: argv["--"] ?? [],
                  }));
                }),
              )
              .command("list", "List host-owned named sources", (cmd) => cmd, handler(() => runSource(() => sourceList())))
              .command(
                "show <name>",
                "Show source metadata without resolving it",
                sourceNamePositional,
                handler((argv: ArgumentsCamelCase<NameArgs>) => runSource(() => sourceShowIntent({ name: argv.name }))),
              )
              .command(
                "remove <name>",
                "Remove an unused host-owned named source",
                sourceNamePositional,
                handler((argv: ArgumentsCamelCase<NameArgs>) => runSource(() => sourceRemoveIntent({ name: argv.name }))),
              )
              .epilogue("Everything after 'credential source add <name> --' is host command argv and is not parsed by Runfree.")
              .demandCommand(1),
            () => {},
          );
        return withExamples(built, "credential")
          .epilogue("Network access is separate: allow a host first with 'runfree host add <host>'. Real values stay host/proxy-side and never enter the agent.")
          .demandCommand(1);
      },
      () => {},
    );
  },
};
