// The pinned-tool --session-id contract (same-terminal session resume, task
// 4). Tasks 2-3 made every Claude and Pi launch pass `--session-id <uuid>`;
// this gate proves the exact pinned tool binaries still accept it the way
// the launch and resume paths assume: the flag is accepted, Claude starts
// writing its transcript under that id before any network use, a resume
// alongside --session-id is refused with the tool's own message, and Pi
// accepts the flag and refuses the same combination with its own message. A
// tool update that silently changed any of this would otherwise surface only
// as a broken resume in a real session.
//
// Security review F1 (2026-10-06): third-party agent-tool code never runs on
// the host. The host only ever runs `npm ci --ignore-scripts` (download, no
// package code executes). Every `npm rebuild` and every `claude`/`pi`
// invocation this module causes runs inside a throwaway container with
// `--network none --cap-drop ALL --security-opt no-new-privileges --user
// 1000:1000`, no environment inherited from the host, and no mount beyond the
// one caller-named directory. There is no host-side runner function here;
// no Docker CLI is a hard failure (`spawnDocker`'s ENOENT message), never a
// silent skip.

import childProcess from "node:child_process";
import { randomUUID } from "node:crypto";

/**
 * POSIX sh, run inside a throwaway container as `sh -c SCRIPT sh <uuid>`, so
 * `$1` is the uuid. Prints one `<case>=ok` or `<case>=missing` line per
 * contract case. No `-e`: every case still runs and reports even after an
 * earlier one fails, so a single bad run still names every failing case
 * rather than stopping at the first.
 *
 * Review F6: the script's own `run()` wrapper is the only place `env -i`
 * appears, so every claude/pi invocation shares the same scrubbed
 * environment and placeholder credential — a regressed refusal elsewhere in
 * the script still cannot reach a real API or an update check.
 */
export const AGENT_SESSION_ID_CONTRACT_SCRIPT = `
set -u
U="$1"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/home" "$T/work" "$T/pi"
cd "$T/work" || exit 2
run() {
  env -i "PATH=$PATH" "HOME=$T/home" "CLAUDE_CONFIG_DIR=$T/home/.claude" \\
    ANTHROPIC_API_KEY=placeholder ANTHROPIC_BASE_URL=http://127.0.0.1:9 DISABLE_AUTOUPDATER=1 \\
    "PI_CODING_AGENT_DIR=$T/pi" PI_SKIP_VERSION_CHECK=1 PI_TELEMETRY=0 "$@"
}
# Claude: the flag is accepted and the transcript is created with the given id
# before any network use (verified offline 2026-10-06 on 2.1.280).
run claude --session-id "$U" -p contract-probe >"$T/claude.out" 2>&1 &
pid=$!
i=0
while [ "$i" -lt 200 ]; do
  if ls "$T/home/.claude/projects/"*/"$U.jsonl" >/dev/null 2>&1; then echo "claude-transcript=ok"; break; fi
  i=$((i + 1)); sleep 0.1
done
[ "$i" -lt 200 ] || echo "claude-transcript=missing"
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
run claude --session-id "$U" --resume "$U" -p x >"$T/c2" 2>&1
grep -q -- "--session-id can only be used" "$T/c2" && echo "claude-resume-refused=ok" || echo "claude-resume-refused=missing"
# Pi: the flag is accepted and names the id. Pi writes no session without a model.
run pi --session-id "$U" -p contract-probe >"$T/pi.out" 2>&1
grep -q "creating a new session with that id" "$T/pi.out" && grep -q "$U" "$T/pi.out" && echo "pi-session-id=ok" || echo "pi-session-id=missing"
run pi --session-id "$U" --resume -p x >"$T/p2" 2>&1
grep -q -- "--session-id cannot be combined" "$T/p2" && echo "pi-resume-refused=ok" || echo "pi-resume-refused=missing"
`;

/**
 * `node:22-bookworm-slim`, pinned by digest (review F1: never an unpinned
 * tag). This is the OCI image index digest (covers linux/amd64, linux/arm64,
 * and the other published platforms under this tag), resolved 2026-10-06 from
 * the official Docker Library's own `docker-library/repo-info` generator —
 * which republishes the registry's `docker-content-digest` for every
 * official tag — because this environment's own egress policy does not admit
 * the Docker Hub registry hosts themselves (auth.docker.io,
 * registry-1.docker.io, hub.docker.com all refused; registry.npmjs.org and
 * *.githubusercontent.com are reachable). The pinned tag's `NODE_VERSION` at
 * that digest is 22.23.3, which satisfies Pi's >= 22.19 requirement.
 */
export const CONTRACT_NODE_IMAGE =
  "node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392";

export type ContractRunner = (script: string, uuid: string) => { status: number; stdout: string; stderr: string };

const REQUIRED_CONTRACT_LINES = [
  "claude-transcript=ok",
  "claude-resume-refused=ok",
  "pi-session-id=ok",
  "pi-resume-refused=ok",
] as const;

const MAX_REPORTED_OUTPUT = 4000;

/** Mints a uuid, runs the script, and requires exactly the four contract lines above. */
export function assertAgentSessionIdContract(run: ContractRunner): void {
  const uuid = randomUUID();
  const { status, stdout, stderr } = run(AGENT_SESSION_ID_CONTRACT_SCRIPT, uuid);
  const output = `${stdout}${stderr}`;
  const missing = REQUIRED_CONTRACT_LINES.filter((line) => !output.includes(line));
  if (status === 0 && missing.length === 0) return;
  const reason = missing.length > 0 ? `missing ${missing.join(", ")}` : `exit ${status}`;
  throw new Error(`--session-id contract failed (${reason}):\n${output.slice(0, MAX_REPORTED_OUTPUT)}`);
}

const CONTAINER_FLAGS = [
  "run", "--rm", "--network", "none", "--cap-drop", "ALL",
  "--security-opt", "no-new-privileges", "--user", "1000:1000", "--entrypoint", "sh",
] as const;

// Only these name the Docker connection itself; nothing else from the host
// environment (credentials, proxy variables, tokens) reaches the `docker` CLI
// invocation, let alone the throwaway container it starts.
const DOCKER_HOST_ENV_KEYS = ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"] as const;

function dockerHostEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const picked: NodeJS.ProcessEnv = {};
  for (const key of DOCKER_HOST_ENV_KEYS) {
    const value = env[key];
    if (value !== undefined) picked[key] = value;
  }
  return picked;
}

type ContractSpawnResult = { status: number; stdout: string; stderr: string };

function spawnDocker(args: readonly string[]): ContractSpawnResult {
  const result = childProcess.spawnSync("docker", args, {
    env: { PATH: process.env.PATH ?? "", ...dockerHostEnv(process.env) },
    encoding: "utf8",
    timeout: 180_000,
  });
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        "the --session-id contract needs Docker; run make test-runtime-core on a Docker host, or pass --no-contract",
      );
    }
    throw result.error;
  }
  return {
    status: result.status ?? 1,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

/** Live gate: the real agent image, whose tools were rebuilt with --network=none at build time. */
export function imageContractRunner(image: string): ContractRunner {
  return (script, uuid) => spawnDocker([...CONTAINER_FLAGS, image, "-c", script, "sh", uuid]);
}

/** Update gate: rebuild (runs install scripts) and probe inside a throwaway container. */
export function lockedToolsContractRunner(toolsDir: string): ContractRunner {
  return (script, uuid) => spawnDocker([
    ...CONTAINER_FLAGS,
    "-e", "HOME=/tmp",
    "-v", `${toolsDir}:/opt/t`,
    CONTRACT_NODE_IMAGE,
    "-c",
    `npm rebuild --prefix /opt/t --omit=dev >/dev/null 2>&1 || exit 3; PATH=/opt/t/node_modules/.bin:$PATH; ${script}`,
    "sh",
    uuid,
  ]);
}
