// Live equivalence proof for the Engine API transport
// (packages/cli/src/runtime/docker-api/): for every routed argv shape, the
// same argv run through the real Docker CLI and through the transport must
// give byte-equal stdout and stderr and the same status, on the real daemon
// the CLI resolves. The unit suite proves the transport against a fake
// Engine API; only this file proves the fake's recorded shapes and the CLI's
// formatting agree with a real daemon and a real CLI.
//
// Every case also asserts the transport actually answered (routed), so a
// silent fallback to the CLI cannot make the comparison vacuous. A missing
// object must stay on the CLI (the transport hands every miss to the CLI so
// the CLI prints its own not-found text).
//
// The objects are the provisioned runtime's own: the proxy container, its
// image, the project's networks and volumes, and exec into the proxy as
// root with and without stdin. One case runs the product CLI (the prebuilt
// bundle the fixture uses) with RUNFREE_TIMINGS=1 and reads its
// docker-transport count, so a silent fallback in the shipped path shows.

import childProcess from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { createDockerApiCapture, type DockerApiCapture } from "../../../packages/cli/src/runtime/docker-api/transport.ts";
import { composeProjectName, composeServiceContainerId, dockerOrThrow } from "./docker.ts";
import { cliEntryArgv } from "../../support/prebuilt-entry.ts";
import { describeOutput, destroyLiveFixture, type LiveFixture, type LiveRuntimeBackend, provisionSandboxFixture } from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 5 * 60_000;
const MAX_BUFFER = 8 * 1024 * 1024;
const CALL_TIMEOUT_MS = 30_000;
const MISSING_ID = "f".repeat(64);

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the docker transport equivalence tranche");
  }
  return backend;
}

type Answer = { status: number; stdout: string; stderr: string };

// `pnpm exec` prepends a relative `./node_modules/.bin` to PATH, and the
// transport treats a relative PATH entry as doubt about which `docker` the CLI
// path would run, so every call would stay on the CLI and fail the routed
// assertion. The proof runs with PATH's absolute entries only.
function absoluteSearchPath(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return { ...env, PATH: (env.PATH ?? "").split(":").filter((dir) => path.isAbsolute(dir)).join(":") };
}

const SPAWN_ENV = absoluteSearchPath(process.env);

function viaCli(args: readonly string[], input?: string): Answer {
  const result = childProcess.spawnSync("docker", [...args], {
    encoding: "utf8",
    env: SPAWN_ENV,
    maxBuffer: MAX_BUFFER,
    timeout: CALL_TIMEOUT_MS,
    ...(input !== undefined ? { input } : {}),
  });
  if (result.error) throw result.error;
  return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

let fixture: LiveFixture;
let transport: DockerApiCapture;
let proxyId: string;
let proxyImageId: string;
let networkNames: string[];
let volumeNames: string[];
let versions: string;

// The daemon emits a container's `Mounts` in a different order on each
// request, so two raw inspects through the CLI itself differ byte for byte.
// Raw container inspects compare byte length (a reorder keeps it) and the
// parsed objects with `Mounts` sorted; every other byte is still compared.
function withSortedMounts(stdout: string): unknown {
  const parsed = JSON.parse(stdout) as Array<Record<string, unknown>>;
  return parsed.map((entry) => Array.isArray(entry.Mounts)
    ? { ...entry, Mounts: [...entry.Mounts].sort((a, b) => String(a.Destination).localeCompare(String(b.Destination))) }
    : entry);
}

function assertEquivalent(args: readonly string[], input?: string, options: { unorderedMounts?: boolean } = {}): Answer {
  const cli = viaCli(args, input);
  const outcome = transport("docker", args, {
    env: SPAWN_ENV,
    maxBuffer: MAX_BUFFER,
    timeout: CALL_TIMEOUT_MS,
    ...(input !== undefined ? { input } : {}),
  });
  const label = `docker ${args.slice(0, 4).join(" ")}… (${versions})`;
  expect(outcome.routed, `${label} was not answered by the transport`).toBe(true);
  if (!outcome.routed) return cli;
  expect(outcome.result.status, `${label}: CLI stderr ${describeOutput(cli.stderr)}`).toBe(cli.status);
  if (options.unorderedMounts && cli.status === 0) {
    expect(Buffer.byteLength(outcome.result.stdout), `${label} stdout length`).toBe(Buffer.byteLength(cli.stdout));
    expect(withSortedMounts(outcome.result.stdout), `${label} stdout`).toEqual(withSortedMounts(cli.stdout));
  } else {
    expect(outcome.result.stdout, `${label} stdout`).toBe(cli.stdout);
  }
  expect(outcome.result.stderr, `${label} stderr`).toBe(cli.stderr);
  return cli;
}

beforeAll(() => {
  requiredBackend();
  fixture = provisionSandboxFixture(REPO_ROOT);
  const project = composeProjectName(fixture);
  proxyId = composeServiceContainerId(project, "proxy");
  proxyImageId = dockerOrThrow("proxy image id", ["container", "inspect", "--format", "{{.Image}}", proxyId]);
  networkNames = dockerOrThrow("project networks", ["network", "ls", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.Name}}"])
    .split("\n").filter(Boolean);
  volumeNames = dockerOrThrow("project volumes", ["volume", "ls", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.Name}}"])
    .split("\n").filter(Boolean);
  versions = dockerOrThrow("docker versions", ["version", "--format", "client API {{.Client.APIVersion}}, server API {{.Server.APIVersion}}"]);
  transport = createDockerApiCapture({ controlEnv: { ...SPAWN_ENV, RUNFREE_DOCKER_TRANSPORT: "api" } });
}, PROVISION_TIMEOUT_MS);

afterAll(() => {
  if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
}, PROVISION_TIMEOUT_MS);

describe("docker Engine API transport matches the Docker CLI on real Docker", () => {
  test("container and type-less inspect, raw and templated", () => {
    expect(networkNames.length).toBeGreaterThan(0);
    assertEquivalent(["container", "inspect", proxyId], undefined, { unorderedMounts: true });
    assertEquivalent(["container", "inspect", proxyId, proxyId], undefined, { unorderedMounts: true });
    assertEquivalent(["inspect", proxyId], undefined, { unorderedMounts: true });
    assertEquivalent(["container", "inspect", "--format", "{{.Id}}", proxyId]);
    assertEquivalent(["container", "inspect", "--format", "{{.State.Running}}", proxyId]);
    assertEquivalent(["inspect", "--format", "{{.State.Running}}", proxyId]);
  }, TEST_TIMEOUT_MS);

  test("image, network, and volume inspect", () => {
    assertEquivalent(["image", "inspect", proxyImageId]);
    assertEquivalent(["image", "inspect", "--format", "{{.Id}}", proxyImageId]);
    assertEquivalent(["network", "inspect", ...networkNames]);
    if (volumeNames.length > 0) assertEquivalent(["volume", "inspect", ...volumeNames]);
  }, TEST_TIMEOUT_MS);

  test("quiet container listings with filters, truncated and not", () => {
    const project = composeProjectName(fixture);
    assertEquivalent(["ps", "-aq", "--no-trunc", "--filter", `label=com.docker.compose.project=${project}`]);
    assertEquivalent(["ps", "-q", "--filter", `label=com.docker.compose.project=${project}`, "--filter", "label=com.docker.compose.service=proxy"]);
    assertEquivalent(["ps", "--all", "--quiet", "--no-trunc", "--filter", `id=${proxyId}`]);
    assertEquivalent(["container", "ls", "-q", "--no-trunc", "--filter", `name=${project}`]);
    assertEquivalent(["ps", "-aq", "--filter", `label=runfree.equivalence.none=${MISSING_ID}`]);
  }, TEST_TIMEOUT_MS);

  test("exec as root with stdin, without stdin, with stderr and a non-zero exit", () => {
    const echo = assertEquivalent(["exec", "--user", "0:0", "-i", proxyId, "node", "-e",
      "let s='';process.stdin.on('data',(c)=>s+=c).on('end',()=>{process.stdout.write(s.toUpperCase());process.stderr.write('n='+s.length+'\\n');})"],
      "session payload é\n".repeat(64));
    expect(echo.stdout).toContain("SESSION PAYLOAD");
    assertEquivalent(["exec", proxyId, "sh", "-c", "printf 'out\\n'; printf 'err\\n' >&2; exit 7"]);
    assertEquivalent(["exec", "--user", "0:0", proxyId, "cat", "/etc/hostname"]);
    assertEquivalent(["exec", "--user", "0:0", proxyId, "sh", "-c", "head -c 300000 /dev/zero | tr '\\0' x"]);
  }, TEST_TIMEOUT_MS);

  test("a missing object stays on the CLI, which prints its own not-found text", () => {
    for (const args of [["container", "inspect", MISSING_ID], ["inspect", MISSING_ID], ["exec", MISSING_ID, "true"]]) {
      const outcome = transport("docker", args, { env: SPAWN_ENV, timeout: CALL_TIMEOUT_MS });
      expect(outcome.routed, `docker ${args.join(" ")}`).toBe(false);
    }
  }, TEST_TIMEOUT_MS);

  test("the product CLI routes calls by default: api and unset route, cli routes none", () => {
    const warmUp = (extra: NodeJS.ProcessEnv) => childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", fixture.projectRoot, "up"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...absoluteSearchPath(fixture.env), RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT, RUNFREE_TIMINGS: "1", ...extra },
      maxBuffer: MAX_BUFFER,
      timeout: TEST_TIMEOUT_MS,
    });
    const counts = (stderr: string) => {
      const match = /timing: docker-transport routed=(\d+) cli=(\d+)/u.exec(stderr);
      if (!match) throw new Error(`no docker-transport timing line: ${describeOutput(stderr)}`);
      return { routed: Number(match[1]), cli: Number(match[2]) };
    };
    const on = warmUp({ RUNFREE_DOCKER_TRANSPORT: "api" });
    expect(on.status, describeOutput(`${on.stdout}${on.stderr}`)).toBe(0);
    expect(counts(on.stderr).routed).toBeGreaterThan(0);
    const off = warmUp({ RUNFREE_DOCKER_TRANSPORT: "cli" });
    expect(off.status, describeOutput(`${off.stdout}${off.stderr}`)).toBe(0);
    expect(counts(off.stderr).routed).toBe(0);
    const { RUNFREE_DOCKER_TRANSPORT: _unset, ...defaultEnv } = fixture.env;
    const unset = childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", fixture.projectRoot, "up"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...absoluteSearchPath(defaultEnv), RUNFREE_INVOCATION_CWD: REPO_ROOT, RUNFREE_PROJECT_ROOT: REPO_ROOT, RUNFREE_TIMINGS: "1" },
      maxBuffer: MAX_BUFFER,
      timeout: TEST_TIMEOUT_MS,
    });
    expect(unset.status, describeOutput(`${unset.stdout}${unset.stderr}`)).toBe(0);
    expect(counts(unset.stderr).routed).toBeGreaterThan(0);
  }, TEST_TIMEOUT_MS);

  test("the kill switch keeps every call on the CLI", () => {
    const off = createDockerApiCapture({ controlEnv: { ...process.env, RUNFREE_DOCKER_TRANSPORT: "cli" } });
    expect(off("docker", ["container", "inspect", proxyId], { env: SPAWN_ENV })).toEqual({ routed: false });
  }, TEST_TIMEOUT_MS);
});
