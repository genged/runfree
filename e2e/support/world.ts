import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { artifactPath } from "./artifact.ts";
import { describeCommandResult, runCommand, type CommandResult } from "./command.ts";

const WORLD_PREFIX = "runfree-cli-e2e-";
const BASE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
const LIVE_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const TREE_LIMIT = 160;

export type WorldPathFlavor = "baseline" | "spaces" | "non-ascii";

export type RunfreeOptions = Readonly<{
  cwd?: string;
  env?: Readonly<Record<string, string | undefined>>;
  timeoutMs?: number;
  termGraceMs?: number;
  umask?: string;
  stdin?: string;
}>;

export type E2EWorld = Readonly<{
  baseRoot: string;
  root: string;
  projectRoot: string;
  home: string;
  configHome: string;
  dataHome: string;
  stateHome: string;
  cacheHome: string;
  fakeBin: string;
  dockerLog: string;
  env: NodeJS.ProcessEnv;
  runfree(args: readonly string[], options?: RunfreeOptions): Promise<CommandResult>;
  runExternal(executable: string, args: readonly string[], options?: Omit<RunfreeOptions, "umask">): Promise<CommandResult>;
  installEmptyDockerInventory(): void;
  preserve(): void;
  isPreserved(): boolean;
  describe(): string;
  cleanup(): void;
}>;

export type CreateWorldOptions = Readonly<{
  pathFlavor?: WorldPathFlavor;
  dockerHost?: string;
}>;

function flavorDirectory(flavor: WorldPathFlavor): string {
  if (flavor === "spaces") return "world with spaces";
  if (flavor === "non-ascii") return "world-שלום";
  return "world";
}

function childEnv(base: NodeJS.ProcessEnv, extra: Readonly<Record<string, string | undefined>> = {}): NodeJS.ProcessEnv {
  const merged = { ...base };
  for (const [name, value] of Object.entries(extra)) {
    if (value === undefined) delete merged[name];
    else merged[name] = value;
  }
  return merged;
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function describeTree(root: string): string {
  const lines: string[] = [];
  const walk = (current: string): void => {
    if (lines.length >= TREE_LIMIT) return;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      lines.push(`${path.relative(root, current) || "."} <unreadable: ${String(error)}>`);
      return;
    }
    const relative = path.relative(root, current) || ".";
    const kind = stat.isDirectory() ? "dir" : stat.isFile() ? "file" : stat.isSymbolicLink() ? `link -> ${fs.readlinkSync(current)}` : "other";
    lines.push(`${(stat.mode & 0o7777).toString(8).padStart(4, "0")} ${kind} ${relative}`);
    if (!stat.isDirectory()) return;
    for (const child of fs.readdirSync(current).sort()) {
      if (lines.length >= TREE_LIMIT) return;
      walk(path.join(current, child));
    }
  };
  walk(root);
  if (lines.length >= TREE_LIMIT) lines.push(`<tree truncated after ${TREE_LIMIT} entries>`);
  return lines.join("\n");
}

export function createWorld(options: CreateWorldOptions = {}): E2EWorld {
  const baseRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), WORLD_PREFIX)));
  const root = path.join(baseRoot, flavorDirectory(options.pathFlavor ?? "baseline"));
  const projectRoot = path.join(root, "project");
  const home = path.join(root, "home");
  const configHome = path.join(root, "xdg-config");
  const dataHome = path.join(root, "xdg-data");
  const stateHome = path.join(root, "xdg-state");
  const cacheHome = path.join(root, "xdg-cache");
  const fakeBin = path.join(root, "fake-bin");
  const dockerLog = path.join(root, "docker-invocations.log");
  const gitConfig = path.join(root, "gitconfig");
  for (const directory of [projectRoot, home, configHome, dataHome, stateHome, cacheHome, fakeBin]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(gitConfig, "", { mode: 0o600 });
  fs.writeFileSync(dockerLog, "", { mode: 0o600 });

  const env: NodeJS.ProcessEnv = Object.freeze({
    HOME: home,
    XDG_CONFIG_HOME: configHome,
    XDG_DATA_HOME: dataHome,
    XDG_STATE_HOME: stateHome,
    XDG_CACHE_HOME: cacheHome,
    PATH: `${fakeBin}:${options.dockerHost ? LIVE_PATH : BASE_PATH}`,
    LC_ALL: "C",
    LANG: "C",
    TZ: "UTC",
    TERM: "dumb",
    NO_COLOR: "1",
    GIT_CONFIG_GLOBAL: gitConfig,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    RUNFREE_E2E_DOCKER_LOG: dockerLog,
    ...(options.dockerHost ? { DOCKER_HOST: options.dockerHost } : {}),
  });
  let preserved = false;

  const runfree = async (args: readonly string[], runOptions: RunfreeOptions = {}): Promise<CommandResult> => {
    const artifact = artifactPath();
    const productArgs = ["--workspace", projectRoot, ...args];
    const command = [artifact, ...productArgs];
    if (runOptions.umask) {
      return runCommand({
        executable: "/bin/sh",
        args: ["-c", "umask \"$1\"; shift; exec \"$@\"", "runfree-e2e-umask", runOptions.umask, artifact, ...productArgs],
        cwd: runOptions.cwd ?? root,
        env: childEnv(env, runOptions.env),
        displayCommand: command,
        timeoutMs: runOptions.timeoutMs,
        termGraceMs: runOptions.termGraceMs,
        stdin: runOptions.stdin,
      });
    }
    return runCommand({
      executable: artifact,
      args: productArgs,
      cwd: runOptions.cwd ?? root,
      env: childEnv(env, runOptions.env),
      displayCommand: command,
      timeoutMs: runOptions.timeoutMs,
      termGraceMs: runOptions.termGraceMs,
      stdin: runOptions.stdin,
    });
  };

  const runExternal = (
    executable: string,
    args: readonly string[],
    runOptions: Omit<RunfreeOptions, "umask"> = {},
  ): Promise<CommandResult> => runCommand({
    executable,
    args,
    cwd: runOptions.cwd ?? root,
    env: childEnv(env, runOptions.env),
    timeoutMs: runOptions.timeoutMs,
    termGraceMs: runOptions.termGraceMs,
    stdin: runOptions.stdin,
  });

  return Object.freeze({
    baseRoot,
    root,
    projectRoot,
    home,
    configHome,
    dataHome,
    stateHome,
    cacheHome,
    fakeBin,
    dockerLog,
    env,
    runfree,
    runExternal,
    installEmptyDockerInventory(): void {
      const docker = path.join(fakeBin, "docker");
      fs.writeFileSync(docker, [
        "#!/bin/sh",
        `printf '%s\\n' \"$*\" >> ${shellSingleQuote(dockerLog)}`,
        "case \"${1:-}\" in",
        "  info|ps) exit 0 ;;",
        "  network)",
        "    case \"${2:-}\" in",
        "      ls) exit 0 ;;",
        "    esac",
        "    ;;",
        "  *) printf 'e2e docker model does not implement: %s\\n' \"$*\" >&2; exit 97 ;;",
        "esac",
        "",
      ].join("\n"), { mode: 0o755 });
    },
    preserve(): void {
      preserved = true;
    },
    isPreserved(): boolean {
      return preserved;
    },
    describe(): string {
      return `world: ${root}\n${describeTree(root)}`;
    },
    cleanup(): void {
      if (preserved || process.env.KEEP_TMP === "1") {
        process.stderr.write(`runfree e2e: kept world at ${root}\n`);
        return;
      }
      if (!path.basename(baseRoot).startsWith(WORLD_PREFIX)) {
        throw new Error(`refusing to remove unexpected e2e world root: ${baseRoot}`);
      }
      fs.rmSync(baseRoot, { recursive: true, force: true });
    },
  });
}

export async function withWorld<T>(
  options: CreateWorldOptions,
  handler: (world: E2EWorld) => T | Promise<T>,
): Promise<T> {
  const world = createWorld(options);
  try {
    return await handler(world);
  } catch (error) {
    const detail = error instanceof Error ? error.stack ?? error.message : String(error);
    throw new Error(`${detail}\n${world.describe()}`);
  } finally {
    world.cleanup();
  }
}

export function assertSuccessfulCommand(result: CommandResult, label: string): void {
  if (result.outcome.kind !== "exit" || result.outcome.exitCode !== 0) {
    throw new Error(`${label} failed\n${describeCommandResult(result)}`);
  }
}
