import type * as childProcess from "node:child_process";

import type { CaptureResult, RuntimeIO } from "./types.ts";

/*
 * The one place non-session `docker` command lines are built. The sealed
 * session commands (`SessionDockerCommand`, session-container-docker.ts and
 * the other session-* builders with an `effect`) are the other owner and are
 * not built here. Every method returns exactly what the injected IO returns,
 * so budget wrappers, the operation histogram, and the admin deadline runner
 * see each call as before. Parsing stays with the caller.
 *
 * Migration table (old hand-written argv -> client call):
 *
 *   info [--format F]                         info(F?)
 *   inspect R…  / container|image|network|volume inspect [--format F] R…
 *                                             inspect([R…], { type?, format? })
 *   ps|container ls [-a|--all] [-q|--quiet] [--no-trunc] [--filter X]… [--format {{.ID}}]
 *                                             listContainers({ all, quiet: true, noTrunc, filters })
 *   ps … --format F (any other template)      listContainers({ …, format: F })
 *   image|network|volume ls [-q] [--no-trunc] [--filter X]… [--format F] [REF]
 *                                             listObjects(type, { quiet, noTrunc, filters, format, reference })
 *   logs --tail N ID / logs --since T ID      logs(ID, { tail: N }) / logs(ID, { since: T })
 *   exec [-i] [--user U|-u U] [-e E]… ID CMD… exec(ID, [CMD…], { interactive, user, env })
 *   exec -d … (via io.run)                    terminal.exec(ID, [CMD…], { detach: true, … })
 *   run FLAGS… IMAGE CMD… (incl. --label L…)  runContainer([[flag], [flag, value]…], IMAGE, [CMD…])
 *   rm [-f] ID… / container rm [--force] ID…  removeContainers([ID…], { force })
 *   rm -f ID… (via io.run)                    terminal.removeContainers([ID…], { force: true })
 *   stop|container stop --time N ID…          stopContainers([ID…], N)
 *   start ID / restart ID                     startContainer(ID) / restartContainer(ID)
 *   network create --label L… NAME            createNetwork(NAME, [L…])
 *   network connect NET ID                    connectNetwork(NET, ID)
 *   network rm ID…                            removeNetworks([ID…])
 *   volume create --label L… NAME             createVolume(NAME, [L…])
 *   volume rm NAME… (captured / via io.run)   removeVolumes([…]) / terminal.removeVolumes([…])
 *   build ARGS… (via io.run)                  terminal.build([ARGS…])
 *   compose ARGS… (via io.run)                terminal.compose([ARGS…])
 *   image prune -f --filter X… (via io.run)   terminal.pruneImages([X…])
 *   image rm R… / image tag S T (via io.run)  terminal.removeImages([R…]) / terminal.tagImage(S, T)
 *
 * `{{ .State.Running }}` is written `{{.State.Running}}`; Docker prints the
 * same output for both.
 */

/** Per-call spawn options, merged over the client's base options. */
export type DockerCallOptions = Readonly<Pick<childProcess.SpawnSyncOptions, "timeout" | "maxBuffer" | "input" | "killSignal">>;

/** The IO the client runs on: `RuntimeIO`'s shape, or any wrapper of it. `run` is needed only for `terminal.*`. */
export type DockerIo = Readonly<{
  capture: RuntimeIO["capture"];
  run?: RuntimeIO["run"];
}>;

export type DockerObjectType = "container" | "image" | "network" | "volume";

export type DockerListQuery = Readonly<{
  all?: boolean;
  quiet?: boolean;
  noTrunc?: boolean;
  filters?: readonly string[];
  format?: string;
}>;

export type DockerExecOptions = Readonly<{
  detach?: boolean;
  interactive?: boolean;
  user?: string;
  env?: readonly string[];
}>;

type DockerRunValueFlag =
  | "--name" | "--network" | "--ip" | "--user" | "--entrypoint" | "--pids-limit" | "--pull"
  | "--cap-add" | "--cap-drop" | "--security-opt" | "--label" | "-e" | "-p" | "-v";

/** One `docker run` flag, in the caller's order. */
export type DockerRunFlag =
  | readonly ["--rm"]
  | readonly ["-d"]
  | readonly ["-i"]
  | readonly ["--read-only"]
  | readonly [DockerRunValueFlag, string];

/**
 * Turns a flat `--label`/value argv stream (as container-inventory.ts's
 * label builders produce, and as `network create`/`volume create` splice
 * directly) into `DockerRunFlag` tuples for `runContainer`, in the same
 * order. Fails closed on a malformed stream rather than silently dropping
 * or reordering a label.
 */
export function labelRunFlags(flagPairs: readonly string[]): readonly DockerRunFlag[] {
  if (flagPairs.length % 2 !== 0) {
    throw new Error(`malformed --label argv: expected [--label, value] pairs, got ${flagPairs.length} token(s): ${JSON.stringify(flagPairs)}`);
  }
  const flags: DockerRunFlag[] = [];
  for (let index = 0; index < flagPairs.length; index += 2) {
    const flag = flagPairs[index];
    const value = flagPairs[index + 1];
    if (flag !== "--label" || typeof value !== "string") {
      throw new Error(`malformed --label argv at index ${index}: expected ["--label", value], got ${JSON.stringify(flagPairs.slice(index, index + 2))}`);
    }
    flags.push(["--label", value]);
  }
  return flags;
}

export type DockerClient = Readonly<{
  info(format?: string, options?: DockerCallOptions): CaptureResult;
  inspect(refs: readonly string[], query?: Readonly<{ type?: DockerObjectType; format?: string }>, options?: DockerCallOptions): CaptureResult;
  listContainers(query: DockerListQuery, options?: DockerCallOptions): CaptureResult;
  listObjects(type: Exclude<DockerObjectType, "container">, query: DockerListQuery & Readonly<{ reference?: string }>, options?: DockerCallOptions): CaptureResult;
  logs(containerId: string, query: Readonly<{ tail?: number; since?: string }>, options?: DockerCallOptions): CaptureResult;
  exec(containerId: string, command: readonly string[], exec?: DockerExecOptions, options?: DockerCallOptions): CaptureResult;
  runContainer(flags: readonly DockerRunFlag[], image: string, command?: readonly string[], options?: DockerCallOptions): CaptureResult;
  removeContainers(ids: readonly string[], query?: Readonly<{ force?: boolean }>, options?: DockerCallOptions): CaptureResult;
  stopContainers(ids: readonly string[], timeSeconds: number, options?: DockerCallOptions): CaptureResult;
  startContainer(id: string, options?: DockerCallOptions): CaptureResult;
  restartContainer(id: string, options?: DockerCallOptions): CaptureResult;
  createNetwork(name: string, labels: readonly string[], options?: DockerCallOptions): CaptureResult;
  connectNetwork(network: string, containerId: string, options?: DockerCallOptions): CaptureResult;
  removeNetworks(ids: readonly string[], options?: DockerCallOptions): CaptureResult;
  createVolume(name: string, labels: readonly string[], options?: DockerCallOptions): CaptureResult;
  removeVolumes(names: readonly string[], options?: DockerCallOptions): CaptureResult;
  /** Operations whose output goes to the user's terminal; each returns the exit status. */
  terminal: Readonly<{
    build(args: readonly string[], options?: DockerCallOptions): number;
    compose(args: readonly string[], options?: DockerCallOptions): number;
    exec(containerId: string, command: readonly string[], exec?: DockerExecOptions, options?: DockerCallOptions): number;
    pruneImages(filters: readonly string[], options?: DockerCallOptions): number;
    removeImages(refs: readonly string[], options?: DockerCallOptions): number;
    tagImage(source: string, target: string, options?: DockerCallOptions): number;
    removeContainers(ids: readonly string[], query?: Readonly<{ force?: boolean }>, options?: DockerCallOptions): number;
    removeVolumes(names: readonly string[], options?: DockerCallOptions): number;
  }>;
}>;

const filterArgs = (filters: readonly string[] = []): string[] => filters.flatMap((filter) => ["--filter", filter]);
const labelArgs = (labels: readonly string[]): string[] => labels.flatMap((label) => ["--label", label]);

function listArgs(query: DockerListQuery): string[] {
  return [
    ...(query.all ? ["--all"] : []),
    ...(query.quiet ? ["--quiet"] : []),
    ...(query.noTrunc ? ["--no-trunc"] : []),
    ...filterArgs(query.filters),
    ...(query.format !== undefined ? ["--format", query.format] : []),
  ];
}

function execArgs(containerId: string, command: readonly string[], exec: DockerExecOptions = {}): string[] {
  return [
    "exec",
    ...(exec.detach ? ["--detach"] : []),
    ...(exec.interactive ? ["--interactive"] : []),
    ...(exec.user !== undefined ? ["--user", exec.user] : []),
    ...(exec.env ?? []).flatMap((entry) => ["--env", entry]),
    containerId,
    ...command,
  ];
}

const removeArgs = (ids: readonly string[], force?: boolean): string[] => ["container", "rm", ...(force ? ["--force"] : []), ...ids];

export function createDockerClient(io: DockerIo, base: childProcess.SpawnSyncOptions = {}): DockerClient {
  const capture = (args: string[], options: DockerCallOptions = {}): CaptureResult => io.capture("docker", args, { ...base, ...options });
  const run = (args: string[], options: DockerCallOptions = {}): number => {
    if (!io.run) throw new Error("this Docker client has no terminal runner");
    return io.run("docker", args, { ...base, ...options });
  };
  return Object.freeze({
    info: (format, options) => capture(["info", ...(format !== undefined ? ["--format", format] : [])], options),
    inspect: (refs, query = {}, options) => capture([
      ...(query.type ? [query.type, "inspect"] : ["inspect"]),
      ...(query.format !== undefined ? ["--format", query.format] : []),
      ...refs,
    ], options),
    listContainers: (query, options) => capture(["ps", ...listArgs(query)], options),
    listObjects: (type, query, options) => capture([type, "ls", ...listArgs(query), ...(query.reference !== undefined ? [query.reference] : [])], options),
    logs: (containerId, query, options) => capture([
      "logs",
      ...(query.tail !== undefined ? ["--tail", String(query.tail)] : []),
      ...(query.since !== undefined ? ["--since", query.since] : []),
      containerId,
    ], options),
    exec: (containerId, command, exec, options) => capture(execArgs(containerId, command, exec), options),
    runContainer: (flags, image, command = [], options) => capture(["run", ...flags.flatMap((flag) => [...flag]), image, ...command], options),
    removeContainers: (ids, query = {}, options) => capture(removeArgs(ids, query.force), options),
    stopContainers: (ids, timeSeconds, options) => capture(["container", "stop", "--time", String(timeSeconds), ...ids], options),
    startContainer: (id, options) => capture(["container", "start", id], options),
    restartContainer: (id, options) => capture(["container", "restart", id], options),
    createNetwork: (name, labels, options) => capture(["network", "create", ...labelArgs(labels), name], options),
    connectNetwork: (network, containerId, options) => capture(["network", "connect", network, containerId], options),
    removeNetworks: (ids, options) => capture(["network", "rm", ...ids], options),
    createVolume: (name, labels, options) => capture(["volume", "create", ...labelArgs(labels), name], options),
    removeVolumes: (names, options) => capture(["volume", "rm", ...names], options),
    terminal: Object.freeze({
      build: (args: readonly string[], options?: DockerCallOptions) => run(["build", ...args], options),
      compose: (args: readonly string[], options?: DockerCallOptions) => run(["compose", ...args], options),
      exec: (containerId: string, command: readonly string[], exec?: DockerExecOptions, options?: DockerCallOptions) => run(execArgs(containerId, command, exec), options),
      pruneImages: (filters: readonly string[], options?: DockerCallOptions) => run(["image", "prune", "--force", ...filterArgs(filters)], options),
      removeImages: (refs: readonly string[], options?: DockerCallOptions) => run(["image", "rm", ...refs], options),
      tagImage: (source: string, target: string, options?: DockerCallOptions) => run(["image", "tag", source, target], options),
      removeContainers: (ids: readonly string[], query?: Readonly<{ force?: boolean }>, options?: DockerCallOptions) => run(removeArgs(ids, query?.force), options),
      removeVolumes: (names: readonly string[], options?: DockerCallOptions) => run(["volume", "rm", ...names], options),
    }),
  });
}
