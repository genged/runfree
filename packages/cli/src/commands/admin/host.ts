// `runfree host <add|remove|list|explain|rules>` — manage exact-host network
// access and request rules only. Credential destinations are managed by the
// separate `runfree credential` command family.
//
// Intent layer: yargs validates each subcommand's grammar and converts argv into
// a typed intent. Execution defers to the shared admin enforcement (which
// re-validates the host and mutates policy) run inside the admin state. See the
// spec's "Intent And Enforcement Are Separate" principle.

import type { ArgumentsCamelCase, Argv } from "yargs";

import { describeRequestRules } from "../../admin/admin-core.ts";
import { createAdminState } from "../../admin/context.ts";
import {
  type RequestRuleInput,
  domainExplainIntent as hostExplainIntent,
  domainList as hostList,
  runAdminAction,
} from "../../admin/options.ts";
import {
  mutateDesiredHost,
  readDesiredHostRules,
  type DesiredHostMutation,
  type DesiredHostScope,
} from "../../control/local-host-mutation.ts";
import { activateApprovedControlsAfterMutation } from "../../control/activation.ts";
import { activationReportLine } from "../../control/activation-report.ts";
import { nodeRuntimeIO } from "../../runtime.ts";
import type { RunfreeCommandContext } from "../context.ts";
import { withExamples } from "../examples.ts";
import type { CommandHandlerFactory, CommandModule } from "../types.ts";
import { NO_RELOAD_DESCRIBE } from "./no-reload.ts";

const REQUEST_RULES_GROUP = "Request rules:";

type HostArgs = { host: string };
type RequestRuleArgs = {
  method?: string[];
  "request-path-prefix"?: string[];
  "read-only"?: boolean;
  "deny-git-push"?: boolean;
};
type AddArgs = HostArgs & RequestRuleArgs & { local?: boolean; "no-reload"?: boolean };
type RemoveArgs = HostArgs & { local?: boolean; "no-reload"?: boolean };
type RulesArgs = HostArgs & RequestRuleArgs & { clear?: boolean; local?: boolean; write?: string; "no-reload"?: boolean };

const hostPositional = (cmd: Argv): Argv =>
  cmd.positional("host", { type: "string", demandOption: true, describe: "exact hostname" });

const requestRuleOptions = (cmd: Argv): Argv =>
  cmd
    .option("method", {
      type: "string",
      array: true,
      requiresArg: true,
      group: REQUEST_RULES_GROUP,
      describe: "Allow only these methods (repeatable)",
    })
    .option("request-path-prefix", {
      type: "string",
      array: true,
      requiresArg: true,
      group: REQUEST_RULES_GROUP,
      describe: "Limit which request paths are permitted (repeatable)",
    })
    .option("read-only", {
      type: "boolean",
      group: REQUEST_RULES_GROUP,
      describe: "Shorthand for --method GET --method HEAD --method OPTIONS",
    })
    .option("deny-git-push", {
      type: "boolean",
      group: REQUEST_RULES_GROUP,
      describe: "Block git push to this host",
    });

const localScopeOption = (cmd: Argv): Argv =>
  cmd.option("local", {
    type: "boolean",
    describe: "Mutate the checkout-local desired policy instead of project policy",
  });

function requestRuleFromArgs(argv: RequestRuleArgs): RequestRuleInput | undefined {
  const rule = {
    readOnly: Boolean(argv["read-only"]),
    methods: argv.method ?? [],
    pathPrefixes: argv["request-path-prefix"] ?? [],
    denyGitPush: Boolean(argv["deny-git-push"]),
  };
  return rule.readOnly || rule.methods.length > 0 || rule.pathPrefixes.length > 0 || rule.denyGitPush
    ? rule
    : undefined;
}

export const hostCommand: CommandModule = {
  name: "host",
  group: true,
  register: (parser, context: RunfreeCommandContext, handler: CommandHandlerFactory) => {
    const run = (action: () => Promise<void> | void): Promise<number> =>
      runAdminAction(createAdminState(context.adminContext()), action);
    const runMutation = async (
      scope: DesiredHostScope,
      mutation: DesiredHostMutation,
      reload: boolean,
    ): Promise<void> => {
      const runtime = context.runtimeContext();
      const result = await mutateDesiredHost(runtime, nodeRuntimeIO, scope, mutation);
      console.log(`scope: ${scope === "local" ? "checkout-local" : "project"}`);
      console.log(`${result.host} ${result.changed ? "updated" : "unchanged"}`);
      for (const warning of result.warnings) console.log(`warning: ${warning}`);
      console.log(`updated .runfree/network-policy${scope === "local" ? ".local" : ""}.json`);
      console.log(`approved ${scope} desired policy: ${result.digest.slice(0, 19)}… (approval record id)`);
      if (!reload) {
        console.log("effective policy: unchanged (--no-reload)");
        return;
      }
      const activation = await activateApprovedControlsAfterMutation(runtime, nodeRuntimeIO);
      console.log(activationReportLine(activation));
    };
    const showRules = async (scope: DesiredHostScope, host: string): Promise<void> => {
      const result = await readDesiredHostRules(context.runtimeContext(), nodeRuntimeIO, scope, host);
      console.log(`scope: ${scope === "local" ? "checkout-local" : "project"}`);
      console.log(`${result.host}: ${describeRequestRules(result.rule)}`);
    };
    return parser.command(
      "host",
      "Manage the exact-host network allowlist",
      (host) => {
        const built = host
          .command(
            "add <host>",
            "Allow an exact host and optionally restrict its requests",
            (cmd) => localScopeOption(requestRuleOptions(hostPositional(cmd))).option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<AddArgs>) => runMutation(
              argv.local ? "local" : "project",
              {
                kind: "add",
                host: argv.host,
                requestRule: requestRuleFromArgs(argv),
              },
              !argv["no-reload"],
            )),
          )
          .command(
            "remove <host>",
            "Remove a host from the allowlist",
            (cmd) => localScopeOption(hostPositional(cmd)).option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<RemoveArgs>) =>
              runMutation(
                argv.local ? "local" : "project",
                { kind: "remove", host: argv.host },
                !argv["no-reload"],
              )),
          )
          .command(
            "list",
            "Print allowlisted hosts",
            (cmd) => cmd,
            handler(() => run(() => hostList())),
          )
          .command(
            "explain <host>",
            "Show a host's allowlist status, credentials, and request rules",
            (cmd) => hostPositional(cmd),
            handler((argv: ArgumentsCamelCase<HostArgs>) => run(() => hostExplainIntent({ host: argv.host }))),
          )
          .command(
            "rules <host>",
            "Show or change a host's request rules",
            (cmd) =>
              localScopeOption(requestRuleOptions(hostPositional(cmd)))
                .option("clear", { type: "boolean", describe: "Remove the host's request rules" })
                .option("write", {
                  type: "string",
                  requiresArg: true,
                  choices: ["allow", "ask", "deny"] as const,
                  describe: "Set the action for the write class of requests to this host",
                })
                .option("no-reload", { type: "boolean", describe: NO_RELOAD_DESCRIBE }),
            handler((argv: ArgumentsCamelCase<RulesArgs>) => {
              const scope = argv.local ? "local" : "project";
              const requestRule = requestRuleFromArgs(argv);
              if (!argv.clear && argv.write === undefined && requestRule === undefined) {
                return showRules(scope, argv.host);
              }
              return runMutation(scope, {
                  kind: "rules",
                  host: argv.host,
                  clear: Boolean(argv.clear),
                  write: argv.write as "allow" | "ask" | "deny" | undefined,
                  requestRule,
                }, !argv["no-reload"]);
            }),
          );
        return withExamples(built, "host")
          .epilogue("Hosts are exact hostnames; there are no wildcards. The allowlist is the proxy egress boundary.")
          .demandCommand(1);
      },
      () => {},
    );
  },
};
