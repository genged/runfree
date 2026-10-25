// `runfree host <add|remove|list|explain|rules>` — manage exact-host network
// access and request rules only. Credential destinations are managed by the
// separate `runfree credential` command family.
//
// Intent layer: yargs validates each subcommand's grammar and converts argv into
// a typed intent. Execution defers to the shared admin enforcement (which
// re-validates the host and mutates policy) run inside the admin state. See the
// spec's "Intent And Enforcement Are Separate" principle.

import type { RequestPolicyJson } from "@runfree/runtime-contracts/network-policy";
import type { ArgumentsCamelCase, Argv } from "yargs";

import { describeRequestRules } from "../../admin/admin-core.ts";
import { createAdminState } from "../../admin/context.ts";
import { SEARCH_CONSOLE_HOST, searchConsoleWarningForApprovedPolicy } from "../../admin/search-console-write-guard.ts";
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
  type DesiredHostRulesResult,
  type DesiredHostScope,
  type HostRuleOwnerLabel,
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
type RulesArgs = HostArgs & RequestRuleArgs & {
  clear?: boolean;
  local?: boolean;
  service?: string;
  write?: string;
  "no-reload"?: boolean;
};

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

// `owner: service github (project)`, `owner: direct (checkout-local)`, or
// `owner: none` when the host has no request rule.
function ownerLine(owner: HostRuleOwnerLabel, layer: DesiredHostScope | undefined): string {
  const where = layer === undefined ? "" : ` (${layer === "local" ? "checkout-local" : "project"})`;
  if (owner === "none") return "owner: none";
  if (owner === "direct") return `owner: direct${where}`;
  return `owner: service ${owner.slice("service:".length)}${where}`;
}

// Only the fields a rule sets, for the `service rule:` and `your setting:`
// lines: `gitPush=deny writeAction=ask`, or `none`. `describeRequestRules`
// spells out defaults instead, which would hide which layer set what.
export function describeRuleFields(full: RequestPolicyJson | undefined): string {
  if (!full) return "none";
  const fields = [
    ...(full.methods !== undefined ? [`methods=${full.methods.join(",")}`] : []),
    ...(full.pathPrefixes !== undefined ? [`pathPrefixes=${full.pathPrefixes.join(",")}`] : []),
    ...(full.gitPush !== undefined ? [`gitPush=${full.gitPush}`] : []),
    ...(full.writeAction !== undefined ? [`writeAction=${full.writeAction}`] : []),
    ...(full.readPathPrefixes !== undefined ? [`readPathPrefixes=${full.readPathPrefixes.join(",")}`] : []),
    ...(full.writePathPrefixes !== undefined ? [`writePathPrefixes=${full.writePathPrefixes.join(",")}`] : []),
    ...(full.graphql !== undefined ? [`graphql=${full.graphql.endpoints.join(",")}`] : []),
  ];
  return fields.length === 0 ? "none" : fields.join(" ");
}

/** The `host rules <host>` show text (spec §4.10). Line 2 is pinned by live tests. */
export function hostRulesShowLines(result: DesiredHostRulesResult): string[] {
  const lines = [
    `scope: ${result.scope === "local" ? "checkout-local" : "project"}`,
    `${result.host}: ${describeRequestRules(result.enforced)}`,
    ownerLine(result.owner, result.ownerLayer),
  ];
  if (result.owner.startsWith("service:")) {
    lines.push(`  service rule: ${describeRuleFields(result.serviceRule)}`);
    lines.push(`  your setting: ${describeRuleFields(result.userSetting)}`);
  }
  return lines;
}

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
    ): Promise<number> => {
      const runtime = context.runtimeContext();
      let exitStatus = 0;
      const result = await mutateDesiredHost(runtime, nodeRuntimeIO, scope, mutation);
      console.log(`scope: ${scope === "local" ? "checkout-local" : "project"}`);
      console.log(`${result.host} ${result.changed ? "updated" : "unchanged"}`);
      for (const notice of result.notices) console.log(notice);
      if (mutation.kind === "rules" || (mutation.kind === "add" && mutation.requestRule !== undefined)) {
        console.log(ownerLine(result.owner, result.ownerLayer));
        console.log(`before: ${describeRequestRules(result.before)}`);
        console.log(`after: ${describeRequestRules(result.after)}`);
      }
      for (const warning of result.warnings) console.log(`warning: ${warning}`);
      if (result.host === SEARCH_CONSOLE_HOST) {
        // Spec §5.1: the binding lives in host credential config, read only
        // inside an admin action and after the policy lock is released. A
        // config read failure renders and becomes the exit status; the
        // mutation above already stands, so the command still reports it.
        exitStatus = await run(() => {
          const writeScopeWarning = searchConsoleWarningForApprovedPolicy(runtime);
          if (writeScopeWarning) console.log(`warning: ${writeScopeWarning}`);
        });
      }
      console.log(`updated .runfree/network-policy${scope === "local" ? ".local" : ""}.json`);
      console.log(`approved ${scope} desired policy: ${result.digest.slice(0, 19)}… (approval record id)`);
      if (!reload) {
        console.log("effective policy: unchanged (--no-reload)");
        return exitStatus;
      }
      const activation = await activateApprovedControlsAfterMutation(runtime, nodeRuntimeIO);
      console.log(activationReportLine(activation));
      return exitStatus;
    };
    const showRules = async (scope: DesiredHostScope, host: string, service: string | undefined): Promise<void> => {
      const result = await readDesiredHostRules(context.runtimeContext(), nodeRuntimeIO, scope, host, service);
      for (const line of hostRulesShowLines(result)) console.log(line);
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
                .option("service", {
                  type: "string",
                  requiresArg: true,
                  describe: "Name the service that owns the rule when several services provide the host",
                })
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
                return showRules(scope, argv.host, argv.service);
              }
              return runMutation(scope, {
                  kind: "rules",
                  host: argv.host,
                  clear: Boolean(argv.clear),
                  write: argv.write as "allow" | "ask" | "deny" | undefined,
                  requestRule,
                  ...(argv.service === undefined ? {} : { service: argv.service }),
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
