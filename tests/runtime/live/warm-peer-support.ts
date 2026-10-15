// Shared live support for warm launches beside live peer sessions.
//
// A warm launch beside peers is judged by `warm-peer-proof.ts` under the held
// lifecycle lock. The tranches that prove it live need the same three pieces:
// peers that stay up beside the launch under test, requests sampled from
// those peers for the whole time the launch runs (their service must never
// drop), and a Docker shim that changes the world at an exact point inside
// the launch (after its peer judgement, before the effect the case is about).
// Kept here once so the copies in four tranches cannot drift apart.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { startRunfree, type AsyncCliRun } from "./attached-support.ts";
import { docker } from "./docker.ts";
import { describeOutput, MANAGED_HELD_RELATIVE_PATH, MANAGED_HOLD_RELATIVE_PATH, type LiveFixture } from "./fixture.ts";
import { milliseconds, sessionContainers, timing } from "./launch-timing-support.ts";
import { answeredByUpstream, curlProbeCommand, parseProbeAnswer } from "./proxy-answer.ts";

/** How long a held peer may take to reach a running session container. */
export const HELD_PEER_START_TIMEOUT_MS = 180_000;

export type HeldPeer = Readonly<{ container: string; run: AsyncCliRun }>;

async function waitFor<T>(probe: () => T | undefined, timeoutMs: number, label: string): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = probe();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/**
 * Starts `count` `claude` sessions on a fixture whose Claude stand-in honors
 * the managed hold marker, one at a time, each held up by that marker. The
 * marker is left in place; a caller that then launches a one-shot session
 * removes it first. That is safe only once every peer's stand-in has read the
 * marker: it reads it once, at its own start, which comes after the session
 * entry and so after the container is already running. Each peer therefore
 * counts as started only when its stand-in has acknowledged the hold.
 */
export async function startHeldPeers(
  fixture: LiveFixture,
  count: number,
  extraEnv: NodeJS.ProcessEnv = {},
): Promise<HeldPeer[]> {
  const holdMarker = path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH);
  fs.mkdirSync(path.dirname(holdMarker), { recursive: true });
  fs.writeFileSync(holdMarker, "");
  const peers: HeldPeer[] = [];
  for (let index = 0; index < count; index += 1) {
    const before = new Set(sessionContainers(fixture));
    const run = startRunfree(fixture, ["claude"], extraEnv);
    let exited = false;
    void run.completion.then(() => { exited = true; }, () => { exited = true; });
    const container = await waitFor(() => {
      if (exited) throw new Error(`held peer ${index} ended before its session started`);
      const id = sessionContainers(fixture).find((candidate) => !before.has(candidate));
      if (!id) return undefined;
      const state = docker(["inspect", "-f", "{{.State.Running}}", id]);
      return state.status === 0 && state.stdout.trim() === "true" ? id : undefined;
    }, HELD_PEER_START_TIMEOUT_MS, `held peer ${index}`);
    await waitFor(() => {
      if (exited) throw new Error(`held peer ${index} ended before its stand-in acknowledged the hold`);
      return heldAcknowledged(fixture, container) ? true : undefined;
    }, HELD_PEER_START_TIMEOUT_MS, `held peer ${index}'s hold acknowledgement`);
    peers.push(Object.freeze({ container, run }));
  }
  return peers;
}

export type HeldLaunches = Readonly<{ runs: readonly AsyncCliRun[]; containers: readonly string[] }>;

/**
 * Starts `count` held `claude` launches at the same moment, so they contend
 * for the lifecycle lock, and waits until each has a running session whose
 * stand-in acknowledged the hold. Held rather than one-shot: a one-shot
 * session can end while a concurrent launch is still starting beside it, and
 * that launch's restore step then meets a stopped peer container (a separate,
 * known gap). Which container belongs to which launch is not tracked; end
 * them together with `endHeldLaunches`.
 */
export async function startConcurrentHeldLaunches(
  fixture: LiveFixture,
  count: number,
  extraEnv: NodeJS.ProcessEnv = {},
): Promise<HeldLaunches> {
  const holdMarker = path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH);
  fs.mkdirSync(path.dirname(holdMarker), { recursive: true });
  fs.writeFileSync(holdMarker, "");
  const before = new Set(sessionContainers(fixture));
  const runs = Array.from({ length: count }, () => startRunfree(fixture, ["claude"], extraEnv));
  const exited = runs.map(() => false);
  runs.forEach((run, index) => {
    void run.completion.then(() => { exited[index] = true; }, () => { exited[index] = true; });
  });
  const containers = await waitFor(() => {
    const ended = exited.findIndex(Boolean);
    if (ended !== -1) throw new Error(`concurrent held launch ${ended} ended before its session was held`);
    const held = sessionContainers(fixture).filter((id) => !before.has(id) && heldAcknowledged(fixture, id));
    return held.length >= count ? held : undefined;
  }, HELD_PEER_START_TIMEOUT_MS, `${count} concurrent held launches`);
  return Object.freeze({ runs: Object.freeze(runs), containers: Object.freeze(containers) });
}

/** Ends concurrent held launches the ordinary way and returns each launch's result, in start order. */
export async function endHeldLaunches(
  launches: HeldLaunches,
): Promise<ReadonlyArray<Readonly<{ status: number | null; output: string }>>> {
  for (const container of launches.containers) docker(["kill", container]);
  return Promise.all(launches.runs.map((run) => run.completion));
}

/** Whether the stand-in in `container` saw the hold marker and is staying up. */
function heldAcknowledged(fixture: LiveFixture, container: string): boolean {
  let acknowledged: string;
  try {
    acknowledged = fs.readFileSync(path.join(fixture.projectRoot, MANAGED_HELD_RELATIVE_PATH), "utf8");
  } catch {
    return false;
  }
  // A container's default hostname is its short (12-character) id.
  const hostname = container.slice(0, 12);
  return acknowledged.split("\n").some((line) => line.trim() === hostname);
}

/** Ends held peers the ordinary way (their agent dies) and waits for their owners to exit. */
export async function endHeldPeers(peers: readonly HeldPeer[]): Promise<void> {
  for (const peer of peers) docker(["kill", peer.container]);
  await Promise.allSettled(peers.map((peer) => peer.run.completion));
}

/** Removes the managed hold marker so the next `claude` launch is one-shot. */
export function releaseHoldMarker(fixture: LiveFixture): void {
  fs.rmSync(path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH), { force: true });
}

export type PeerRequestSample = Readonly<{ container: string; answered: boolean; detail: string }>;

export type PeerRequestSampler = Readonly<{
  /** Stops sampling after the round in flight and returns every sample. */
  stop: () => Promise<readonly PeerRequestSample[]>;
}>;

function dockerAsync(args: readonly string[], timeoutMs: number): Promise<Readonly<{ status: number; output: string }>> {
  return new Promise((resolve) => {
    childProcess.execFile("docker", [...args], { encoding: "utf8", timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
      const status = error ? (typeof error.code === "number" ? error.code : 1) : 0;
      resolve(Object.freeze({ status, output: `${stdout}${stderr}` }));
    });
  });
}

/**
 * Sends one request from every peer, round after round, until stopped,
 * without blocking the event loop the launch under test reports through. A
 * sample is answered only when the upstream answered it through the proxy:
 * a proxy denial, a dropped connection, or a timeout is a lost request.
 */
export function samplePeerRequests(containers: readonly string[], url: string, intervalMs = 500): PeerRequestSampler {
  let stopped = false;
  const samples: PeerRequestSample[] = [];
  const loop = (async () => {
    while (!stopped) {
      const round = await Promise.all(containers.map(async (container) => {
        const result = await dockerAsync(["exec", container, "zsh", "-lc", curlProbeCommand(url, { maxTimeSeconds: 15 })], 30_000);
        const answer = parseProbeAnswer(result.output);
        return Object.freeze({ container, answered: answeredByUpstream(answer), detail: describeOutput(result.output, 400) });
      }));
      samples.push(...round);
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  })();
  return Object.freeze({
    stop: async () => {
      stopped = true;
      await loop;
      return samples;
    },
  });
}

/**
 * A `docker` on PATH that, once armed, runs one shell side effect the first
 * time it sees a matching argument, then forwards the command unchanged.
 *
 * `armOn` and `fireOn` are `case` patterns over single arguments. Arming is
 * what orders the side effect inside a launch: the warm proof's root batch
 * (whose script argument names `RUNFREE_FIREWALL_SECTION`) runs before the
 * peer judgement, so a side effect armed on it and fired on a later argument
 * lands after the stable observation it is meant to postdate. Nothing is
 * faked: every command, the fired one included, reaches the daemon. The side
 * effect runs in the shim's shell, where `$real_docker` names the real client.
 */
export function createDockerSideEffectShim(
  fixture: LiveFixture,
  options: Readonly<{ armOn: string; fireOn: string; sideEffect: string }>,
): Readonly<{ env: NodeJS.ProcessEnv; fired: () => boolean; dispose: () => void }> {
  for (const pattern of [options.armOn, options.fireOn]) {
    if (!/^[A-Za-z0-9_.*{}-]+$/u.test(pattern)) throw new Error(`unsafe Docker shim pattern: ${pattern}`);
  }
  const realDocker = childProcess
    .execFileSync("sh", ["-c", "command -v docker"], { env: fixture.env, encoding: "utf8" })
    .trim();
  if (!path.isAbsolute(realDocker)) throw new Error("the Docker side-effect shim requires an absolute Docker executable");
  const bin = fs.mkdtempSync(path.join(fixture.ownerRoot, "docker-side-effect."));
  const quote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
  const armedPath = path.join(bin, "armed");
  const firedPath = path.join(bin, "fired");
  fs.writeFileSync(
    path.join(bin, "docker"),
    `#!/bin/sh
# Live-fixture Docker shim. Not a production artifact: it runs one side effect
# at an ordered point inside a real launch and forwards every command.
armed=${quote(armedPath)}
fired=${quote(firedPath)}
real_docker=${quote(realDocker)}
if [ ! -f "$fired" ]; then
  for runfree_argument in "$@"; do
    case "$runfree_argument" in
      ${options.armOn}) : > "$armed" ;;
    esac
  done
  if [ -f "$armed" ]; then
    for runfree_argument in "$@"; do
      case "$runfree_argument" in
        ${options.fireOn})
          : > "$fired"
          ${options.sideEffect}
          break
          ;;
      esac
    done
  fi
fi
exec "$real_docker" "$@"
`,
    { mode: 0o755 },
  );
  return Object.freeze({
    env: { PATH: `${bin}${path.delimiter}${fixture.env.PATH ?? ""}` },
    fired: () => fs.existsSync(firedPath),
    dispose: () => fs.rmSync(bin, { recursive: true, force: true }),
  });
}

/**
 * One launch's startup phases, separated the way the peer-scaling report
 * records them: validation, reconcile and restore, the lifecycle lock's hold,
 * the handoff and admission preflight, the wait for the agent to be useful,
 * and the exit path.
 */
export function warmPeerLaunchPhases(output: string): Readonly<Record<string, number | string | undefined>> {
  const lockHold = timing(output, "session-admission")
    .map((detail) => /^lifecycle-lock-hold-ms=(\d+)$/u.exec(detail)?.[1])
    .find((value) => value !== undefined);
  return Object.freeze({
    warmProof: timing(output, "validation:warm-proof").at(-1),
    warmPeer: timing(output, "validation:warm-peer").at(-1),
    warmProofCheckMs: milliseconds(output, "validation:warm-proof-check"),
    warmPeerCheckMs: milliseconds(output, "validation:warm-peer-check"),
    fullValidationMs: milliseconds(output, "runtime-validation"),
    reconcileMs: milliseconds(output, "startup:reconcile-sessions"),
    restore: timing(output, "startup:restore-sessions").at(-1),
    lockHoldMs: lockHold === undefined ? undefined : Number(lockHold),
    handoff: timing(output, "launch-handoff").at(-1),
    preflightMs: milliseconds(output, "admission:preflight"),
    awaitHandoffMs: milliseconds(output, "admission:await-handoff"),
    startupTotalMs: milliseconds(output, "startup-total"),
    teardownPath: timing(output, "teardown-path").at(-1),
  });
}
