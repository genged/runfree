// Real-subprocess harness for the credential watcher cancellation tests in
// scripts/admin-token-policy.test.ts (F08: a watcher cancelled by its session's
// exit must not read as a definitive provider failure and revoke a credential)
// and for the watcher stop-protocol tests in packages/cli/src/runtime.test.ts.
//
// One file, three roles, chosen by argv and environment:
//
// - `parent <config>` stands in for the session CLI process. In `runtime` mode
//   it starts the watcher through the production `nodeRuntimeIO`
//   (`startTokenAutoRefresh`) and, on `stop`, runs the production stop
//   protocol (`TokenAutoRefreshHandle.stop`). In `plan` mode it spawns the
//   production spawn plan itself so a test can close the pipe without a signal
//   (a crashed parent, or a recycled parent PID) or close it before the watcher
//   has started.
// - Any other argv is a `credential sync` run: the production self-invocation
//   re-runs this file with `--workspace <root> credential sync --watch ...`,
//   and a test may run it directly without `--watch` (a foreground one-shot
//   sync). It installs the CLI's own signal handlers and runs the production
//   `credentialSyncIntent` in an admin state built like the in-process tests'
//   (`runAdmin`), so a provider is a real executable reached through a real
//   `spawnSync`, and signals are real signals.
// - With `RUNFREE_CREDENTIAL_WATCH_HARNESS_PROBE=<dir>` the self-invoked
//   watcher is a stop-protocol probe instead: it records which signals it and
//   a child in its own process group receive, and whether the lifetime pipe
//   was already closed when its signal arrived.
//
// Commands for the parent arrive one per line on stdin; it reports
// `parent-ready` on stdout once the watcher has been spawned. The watcher
// writes its PID to `<config>.pid` before anything else, and `<config>.done`
// when a bounded test watch returns: tests wait on these files, never on a
// process listing.

import childProcess from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import readline from "node:readline";

import { installSignalExit } from "../packages/cli/src/signal-exit.ts";
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
export const CREDENTIAL_WATCH_HARNESS_PROBE_ENV = "RUNFREE_CREDENTIAL_WATCH_HARNESS_PROBE";

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

function requiredConfigPath(): string {
  const configPath = process.env[CREDENTIAL_WATCH_HARNESS_CONFIG_ENV];
  if (!configPath) throw new Error("credential watch harness: missing config path");
  return configPath;
}

async function runCredentialSync(argv: readonly string[]): Promise<void> {
  const configPath = requiredConfigPath();
  fs.writeFileSync(`${configPath}.pid`, `${process.pid}\n`);
  const config = readConfig(configPath);
  // The same handlers `main()` installs: a signal exits 130/143, but its JS
  // handler only runs when the event loop next turns.
  installSignalExit({ flush: flushWarnings, restore: () => {}, exit: (code) => process.exit(code) });
  const watch = argv.includes("--watch");
  const status = await runAdminAction(createAdminState({
    env: process.env,
    packageRoot: config.projectRoot,
    projectRoot: config.projectRoot,
    runtimeContext: runtimeContext(config),
    stateDir: config.stateDir,
  }), () => credentialSyncIntent({
    verbose: false,
    watch,
    quiet: argv.includes("--quiet"),
    delayFirstSync: argv.includes("--delay-first-sync"),
    cacheSourceSecrets: true,
    initialSourceTruth: argv.includes("--initial-source-truth"),
  }));
  process.exitCode = status;
  // A bounded test watch (`RUNFREE_TEST_TOKEN_SYNC_WATCH_ITERATIONS`) or a
  // one-shot sync returned. A watch process stays up while its lifetime pipe
  // is open, as the production watcher does, so tests wait for this marker.
  fs.writeFileSync(`${configPath}.done`, `${status}\n`);
}

// The stop-protocol probe. It holds the lifetime pipe the way the watcher
// does (a socket, so the process can exit while the parent
// keeps the pipe), never exits on its own signal, and starts one child in its
// own process group that records any SIGTERM it receives.
function runStopProbe(probeDir: string): void {
  const configPath = requiredConfigPath();
  const record = (line: string) => fs.appendFileSync(path.join(probeDir, "events.log"), `${line}\n`);
  const fd = Number(process.env.RUNFREE_TOKEN_SYNC_LIFETIME_FD);
  const lifetime = new net.Socket({ fd, readable: true, writable: false });
  lifetime.on("error", () => {});
  lifetime.resume();
  const pipeState = (): string => {
    try {
      return fs.readSync(fd, Buffer.alloc(1), 0, 1, null) === 0 ? "closed" : "data";
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "EAGAIN" ? "open" : "closed";
    }
  };
  process.on("SIGTERM", () => record(`watcher-sigterm pipe-${pipeState()}`));
  const child = childProcess.spawn("/bin/sh", ["-c", `trap 'echo group-member-sigterm >> "$0"; exit 0' TERM; echo group-member-ready >> "$0"; while :; do sleep 0.1; done`, path.join(probeDir, "events.log")], { stdio: "ignore" });
  child.on("error", () => {});
  fs.writeFileSync(`${configPath}.pid`, `${process.pid}\n`);
  // Ends itself well after any test has read its events.
  setTimeout(() => {
    child.kill("SIGKILL");
    process.exit(0);
  }, 20_000);
}

function runParent(configPath: string): void {
  const config = readConfig(configPath);
  process.env[CREDENTIAL_WATCH_HARNESS_CONFIG_ENV] = configPath;
  const context = runtimeContext(config);
  const commands = new Map<string, () => void>();
  if (config.launch === "runtime") {
    const start = nodeRuntimeIO.startTokenAutoRefresh;
    if (!start) throw new Error("parent harness: the node runtime IO has no watcher starter");
    const handle = start(context, config.receipts ?? [], { initialSourceTruth: config.initialSourceTruth });
    commands.set("stop", () => {
      handle.stop();
      process.stdout.write("stopped\n", () => process.exit(0));
    });
    // The session CLI's own ending: stop, then simply return, so the process
    // exits only once nothing it still references keeps its event loop alive.
    commands.set("stop-and-return", () => {
      handle.stop();
      lines.close();
      process.stdin.destroy();
    });
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
  }
  // A crash: no `finally`, no stop protocol; the kernel closes the pipe.
  commands.set("crash", () => process.kill(process.pid, "SIGKILL"));
  commands.set("exit", () => process.exit(0));
  process.stdout.write("parent-ready\n");
  const lines = readline.createInterface({ input: process.stdin });
  lines.on("line", (line) => commands.get(line.trim())?.());
}

const args = process.argv.slice(2);
const probeDir = process.env[CREDENTIAL_WATCH_HARNESS_PROBE_ENV];
if (args[0] === "parent" && args[1]) {
  runParent(args[1]);
} else if (probeDir) {
  runStopProbe(probeDir);
} else {
  await runCredentialSync(args);
}
