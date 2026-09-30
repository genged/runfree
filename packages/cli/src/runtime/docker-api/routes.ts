/**
 * The fixed allowlist of `docker` argv shapes the Engine API transport may
 * answer. Matching is exact, token by token: an unknown flag, a flag in a
 * form the table does not list (`-f` for `--format`, `--flag=value`), an
 * extra argument, or an object reference outside its strict character set
 * leaves the argv on the Docker CLI. Every route is either a read or the
 * non-TTY exec the proxy and agent helpers use; nothing here creates,
 * starts, stops, removes, or reconfigures a Docker object.
 *
 * References only ever become one URL path segment (or, for images, a path
 * the daemon's `{name:.*}` route reads), and only after they match a
 * character set that needs no escaping — so no argv value can add a path
 * segment, a query parameter, or reach a different endpoint.
 */

export type InspectObject = "container" | "image" | "network" | "volume";

/** The exact `--format` templates whose Go output the transport reproduces. */
export type InspectTemplate = "raw" | "id" | "state-running";

export type DockerApiRoute =
  | { kind: "inspect"; object: InspectObject; refs: readonly string[]; template: InspectTemplate }
  | { kind: "ps"; all: boolean; noTrunc: boolean; filters: Readonly<Record<string, readonly string[]>> }
  | { kind: "exec"; user?: string; interactive: boolean; containerId: string; cmd: readonly string[] };

// Docker's own container/network/volume name rule, bounded.
const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$/;
// Image references and ids: registry/path:tag@digest characters only.
const IMAGE_REF_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:/@-]{0,511}$/;
const EXACT_ID_PATTERN = /^[a-f0-9]{64}$/;
const USER_PATTERN = /^[0-9]{1,10}(?::[0-9]{1,10})?$/;
const PS_FILTER_KEYS = new Set(["label", "name", "id", "network"]);
// Label/name/id/network filter values: printable, no leading/trailing space
// (the CLI trims; an untrimmed value stays on the CLI rather than risk a
// different filter).
// eslint-disable-next-line no-control-regex
const FILTER_VALUE_PATTERN = /^[^\s\u0000-\u001f\u007f](?:[^\u0000-\u001f\u007f]{0,510}[^\s\u0000-\u001f\u007f])?$/u;

function validImageRef(ref: string): boolean {
  if (!IMAGE_REF_PATTERN.test(ref)) return false;
  return !ref.split("/").some((segment) => segment === "" || segment === "." || segment === "..");
}

function refsValid(object: InspectObject, refs: readonly string[]): boolean {
  if (refs.length === 0 || refs.length > 256) return false;
  return refs.every((ref) => object === "image" ? validImageRef(ref) : NAME_PATTERN.test(ref));
}

function inspectRoute(object: InspectObject, rest: readonly string[], allowed: readonly InspectTemplate[]): DockerApiRoute | undefined {
  let template: InspectTemplate = "raw";
  let refs = rest;
  if (rest[0] === "--format") {
    const format = rest[1];
    if (format === "{{.Id}}") template = "id";
    else if (format === "{{.State.Running}}") template = "state-running";
    else return undefined;
    refs = rest.slice(2);
  }
  if (!allowed.includes(template)) return undefined;
  if (refs.some((ref) => ref.startsWith("-"))) return undefined;
  if (!refsValid(object, refs)) return undefined;
  return { kind: "inspect", object, refs: [...refs], template };
}

function psRoute(rest: readonly string[]): DockerApiRoute | undefined {
  let all = false;
  let quiet = false;
  let noTrunc = false;
  const filters: Record<string, string[]> = {};
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    switch (token) {
      case "-a":
      case "--all":
        all = true;
        break;
      case "-q":
      case "--quiet":
        quiet = true;
        break;
      case "-aq":
      case "-qa":
        all = true;
        quiet = true;
        break;
      case "--no-trunc":
        noTrunc = true;
        break;
      case "--filter": {
        const value = rest[index + 1];
        index += 1;
        if (value === undefined) return undefined;
        const separator = value.indexOf("=");
        if (separator <= 0) return undefined;
        const key = value.slice(0, separator);
        const filterValue = value.slice(separator + 1);
        if (!PS_FILTER_KEYS.has(key) || !FILTER_VALUE_PATTERN.test(filterValue)) return undefined;
        filters[key] = [...(filters[key] ?? []), filterValue];
        break;
      }
      default:
        return undefined;
    }
  }
  // Only quiet listings: their output is the id column alone. Every other
  // listing is a client-side Go template the transport does not reproduce.
  if (!quiet) return undefined;
  return { kind: "ps", all, noTrunc, filters };
}

function execRoute(rest: readonly string[], hasInput: boolean): DockerApiRoute | undefined {
  let user: string | undefined;
  let interactive = false;
  let index = 0;
  while (index < rest.length && rest[index].startsWith("-")) {
    const token = rest[index];
    if (token === "--user" && user === undefined) {
      const value = rest[index + 1];
      if (value === undefined || !USER_PATTERN.test(value)) return undefined;
      user = value;
      index += 2;
    } else if ((token === "-i" || token === "--interactive") && !interactive) {
      interactive = true;
      index += 1;
    } else {
      return undefined;
    }
  }
  const containerId = rest[index];
  if (containerId === undefined || !EXACT_ID_PATTERN.test(containerId)) return undefined;
  const cmd = rest.slice(index + 1);
  if (cmd.length === 0 || cmd.length > 4096) return undefined;
  // Input without `-i` is dropped by the CLI; keep that mismatch on the CLI.
  if (hasInput && !interactive) return undefined;
  return { kind: "exec", ...(user !== undefined ? { user } : {}), interactive, containerId, cmd: [...cmd] };
}

/** The route for `args`, or undefined when the argv must stay on the Docker CLI. */
export function matchDockerApiRoute(args: readonly string[], options: { hasInput: boolean }): DockerApiRoute | undefined {
  // execve cannot carry NUL; the CLI path throws for it and so must stay the path.
  if (args.some((arg) => typeof arg !== "string" || arg.includes("\u0000"))) return undefined;
  const [first, second] = args;
  if (options.hasInput && first !== "exec") return undefined;
  if (first === "container" && second === "inspect") return inspectRoute("container", args.slice(2), ["raw", "id", "state-running"]);
  // Type-less inspect tries containers first (cli/command/system inspect);
  // any miss is answered by the CLI's full type search.
  if (first === "inspect") return inspectRoute("container", args.slice(1), ["raw", "state-running"]);
  if (first === "image" && second === "inspect") return inspectRoute("image", args.slice(2), ["raw", "id"]);
  if (first === "network" && second === "inspect") return inspectRoute("network", args.slice(2), ["raw"]);
  if (first === "volume" && second === "inspect") return inspectRoute("volume", args.slice(2), ["raw"]);
  if (first === "ps") return psRoute(args.slice(1));
  if (first === "container" && second === "ls") return psRoute(args.slice(2));
  if (first === "exec") return execRoute(args.slice(1), options.hasInput);
  return undefined;
}
