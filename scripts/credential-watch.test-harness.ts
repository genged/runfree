// Real-subprocess harness for the credential watcher cancellation tests in
// scripts/admin-token-policy.test.ts (F08: a watcher cancelled by its session's
// exit must not read as a definitive provider failure and revoke a credential).
//
// One file, two roles, chosen by argv:
//
// - `parent <config>` stands in for the session CLI process. In `runtime` mode
//   it starts the watcher through the production `nodeRuntimeIO`
//   (`startTokenAutoRefresh`) and, on `stop`, runs the production stop
//   protocol: close the lifetime pipe, then SIGTERM the watcher's process
//   group. In `plan` mode it spawns the production spawn plan itself so a test
//   can close the pipe without a signal (a crashed parent, or a recycled
//   parent PID) or close it before the watcher has started.
// - Any other argv is the watcher: the production self-invocation re-runs
//   this file with `--workspace <root> credential sync --watch ...`. It
//   installs the CLI's own signal handlers and runs the production
//   `credentialSyncIntent` in an admin state built like the in-process tests'
//   (`runAdmin`), so the provider is a real `op` executable reached through a
//   real `spawnSync`, and signals are real signals.
//
// Commands for the parent arrive one per line on stdin; it reports
// `parent-ready <watcher-pid>` on stdout once the watcher has been spawned.
// The watcher writes `<config>.done` when a bounded test watch returns.

import childProcess from "node:child_process";
import fs from "node:fs";
import readline from "node:readline";

import { installSignalExit } from "../packages/cli/src/cli.ts";
import type { ProjectInfo } from "../packages/cli/src/config.ts";
import { createAdminState } from "../packages/cli/src/admin/context.ts";
import { credentialSyncIntent, runAdminAction } from "../packages/cli/src/admin/options.ts";
import type { TokenResolutionReceipt } from "../packages/cli/src/token-resolution.ts";
import { buildTokenAutoRefreshSpawnPlan, nodeRuntimeIO, type RuntimeContext } from "../packages/cli/src/runtime.ts";
import { flushWarnings } from "../packages/cli/src/warnings.ts";

export type CredentialWatchHarnessConfig = {
  projectRoot: string;
  stateDir: string;
  runtimeRoot: string;
  project: ProjectInfo;
  policyAccess?: "effective-read-only";
  validatedRuntime?: RuntimeContext["validatedRuntime"];
  /** `runtime`: production start/stop; `plan`: the spawn plan with test-chosen lifetime handling. */
  launch: "runtime" | "plan";
  initialSourceTruth: boolean;
  receipts?: TokenResolutionReceipt[];
  /** Plan mode only: the PID the watcher probes as its parent. */
  parentPid?: number;
  /** Plan mode only: close the lifetime pipe right after the spawn. */
  closePipeAtSpawn?: boolean;
};

export const CREDENTIAL_WATCH_HARNESS_CONFIG_ENV = "RUNFREE_CREDENTIAL_WATCH_HARNESS_CONFIG";

function readConfig(configPath: string): CredentialWatchHarnessConfig {
  return JSON.parse(fs.readFileSync(configPath, "utf8")) as CredentialWatchHarnessConfig;
}

function runtimeContext(config: CredentialWatchHarnessConfig): RuntimeContext {
  return {
    projectRoot: config.projectRoot,
    project: config.project,
    runtimeRoot: config.runtimeRoot,
    env: process.env,
  };
}

async function runWatcher(argv: readonly string[]): Promise<void> {
  const configPath = process.env[CREDENTIAL_WATCH_HARNESS_CONFIG_ENV];
  if (!configPath) throw new Error("watcher harness: missing config path");
  const config = readConfig(configPath);
  // The same handlers `main()` installs: a signal exits 130/143, but its JS
  // handler only runs when the event loop next turns.
  installSignalExit({ flush: flushWarnings, restore: () => {}, exit: (code) => process.exit(code) });
  const status = await runAdminAction(createAdminState({
    env: process.env,
    packageRoot: config.projectRoot,
    projectRoot: config.projectRoot,
    runtimeContext: runtimeContext(config),
    stateDir: config.stateDir,
    ...(config.policyAccess ? { policyAccess: config.policyAccess } : {}),
    ...(config.validatedRuntime ? { validatedRuntime: config.validatedRuntime } : {}),
  }), () => credentialSyncIntent({
    verbose: false,
    watch: true,
    quiet: argv.includes("--quiet"),
    delayFirstSync: argv.includes("--delay-first-sync"),
    cacheSourceSecrets: true,
    initialSourceTruth: argv.includes("--initial-source-truth"),
  }));
  process.exitCode = status;
  // A bounded test watch returned (`RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS`).
  // The process itself stays up while the lifetime pipe is open, as the
  // production watcher does, so tests wait for this marker instead.
  fs.writeFileSync(`${configPath}.done`, `${status}\n`);
}

function runParent(configPath: string): void {
  const config = readConfig(configPath);
  process.env[CREDENTIAL_WATCH_HARNESS_CONFIG_ENV] = configPath;
  const context = runtimeContext(config);
  const commands = new Map<string, () => void>();
  if (config.launch === "runtime") {
    const start = nodeRuntimeIO.startTokenAutoRefresh;
    if (!start) throw new Error("parent harness: the node runtime IO has no watcher starter");
    const before = new Set(childPids());
    const handle = start(context, config.receipts ?? [], { initialSourceTruth: config.initialSourceTruth });
    const watcherPid = childPids().find((pid) => !before.has(pid));
    commands.set("stop", () => {
      handle.stop();
      process.stdout.write("stopped\n", () => process.exit(0));
    });
    process.stdout.write(`parent-ready ${watcherPid ?? 0}\n`);
  } else {
    const plan = buildTokenAutoRefreshSpawnPlan({
      base: { command: process.execPath, args: [...process.execArgv, process.argv[1] as string] },
      context,
      parentPid: config.parentPid ?? process.pid,
      receipts: config.receipts,
      initialSourceTruth: config.initialSourceTruth,
    });
    const child = childProcess.spawn(plan.command, plan.args, plan.options);
    child.on("error", () => {});
    const lifetime = child.stdio[plan.lifetimeFd];
    lifetime?.on("error", () => {});
    if (plan.receiptFd !== undefined && plan.receiptPayload !== undefined) {
      const receiptStream = child.stdio[plan.receiptFd];
      receiptStream?.on("error", () => {});
      (receiptStream as NodeJS.WritableStream | null)?.end(plan.receiptPayload);
    }
    const closePipe = () => lifetime?.destroy();
    if (config.closePipeAtSpawn) closePipe();
    commands.set("close-pipe", () => {
      closePipe();
      process.stdout.write("pipe-closed\n");
    });
    process.stdout.write(`parent-ready ${child.pid ?? 0}\n`);
  }
  // A crash: no `finally`, no stop protocol; the kernel closes the pipe.
  commands.set("crash", () => process.kill(process.pid, "SIGKILL"));
  commands.set("exit", () => process.exit(0));
  const lines = readline.createInterface({ input: process.stdin });
  lines.on("line", (line) => commands.get(line.trim())?.());
}

// Direct children of this process (the listing `ps` itself excluded), from
// `ps` (portable across Linux and macOS).
function childPids(): number[] {
  const listing = childProcess.spawnSync("ps", ["-A", "-o", "pid=", "-o", "ppid="], { encoding: "utf8" });
  return listing.stdout.split("\n").flatMap((line) => {
    const [pid, ppid] = line.trim().split(/\s+/).map(Number);
    return ppid === process.pid && pid !== listing.pid && Number.isInteger(pid) ? [pid] : [];
  });
}

const args = process.argv.slice(2);
if (args[0] === "parent" && args[1]) {
  runParent(args[1]);
} else {
  await runWatcher(args);
}
