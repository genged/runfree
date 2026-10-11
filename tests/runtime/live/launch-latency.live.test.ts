// Live proof for the sub-second launch plan, Phase B (Tasks 2–6, 8).
//
// Each case launches the recording Claude stand-in one-shot (its hold marker
// absent, so it records its argv and exits 0) with `RUNFREE_TIMINGS=1`, and
// reads the timing lines the CLI prints. The assertions are about which path a
// launch took, never about a time budget, except the optional latency gate:
//
//   - a warm launch after a full validation matches its warm proof, skips the
//     full runtime validation, the image cleanup inventory, and the separate
//     IP-assignment read, and is admitted under the lock startup handed off;
//   - `runfree up` always validates fully and rewrites the warm proof;
//   - an in-place `docker restart` of the proxy is a warm-proof mismatch, and
//     the launch still succeeds on the full path;
//   - a firewall changed inside the running proxy (same container, same
//     start time) is a warm-proof mismatch, full validation refuses it and
//     contains the proxy, and the next launch reclaims the warm path;
//   - a normal numeric exit takes the short teardown (spec open decision 3:
//     the exited container's inspection proves it stopped before removal),
//     and the session container is gone afterwards;
//   - one session's exit while its credential watcher is mid-read stops that
//     read without touching the shared proxy credential: a peer session's
//     value, status, watcher, and requests to the credential's host carry on
//     (credential watcher cancellation).
//
// The latency gate runs `LAUNCH_LATENCY_RUNS` (default 5) warm launches and
// writes their timings to `LAUNCH_LATENCY_REPORT` when set. With
// `LAUNCH_LATENCY_P95_MS` set it also asserts the nearest-rank p95 of the
// in-CLI `startup-total` plus admission phases; the plan's gates (Gate B:
// p50 about 1.8–2.0 s through the dev wrapper; Gate E/F: p95 <= 1.0 s) are
// recorded by the benchmark script, not hard-coded here.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { startRunfree } from "./attached-support.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type LiveFixture,
  type LiveRuntimeBackend,
  forceCleanSessions,
  MANAGED_HOLD_RELATIVE_PATH,
  provisionSandboxFixture,
} from "./fixture.ts";
import {
  launchClaudeTimed,
  milliseconds,
  runfreeTimed,
  sessionContainers,
  timing,
} from "./launch-timing-support.ts";
import { answeredByUpstream, curlProbeCommand, parseProbeAnswer } from "./proxy-answer.ts";
import { liveTierSelected } from "./tiers.ts";

// The fast paths are part of the trust boundary's proof (a warm launch must
// never skip what a changed runtime needs), so those cases are core; the
// latency gate is a measurement and is extended.
const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the launch latency tranche");
  }
  return backend;
}

// The sandbox fixture's seeded credential and its host environment source.
const SHARED_CREDENTIAL = "sandbox-strip-probe";
const SHARED_CREDENTIAL_ENV = "RUNFREE_SANDBOX_STRIP_TOKEN";
const SHARED_CREDENTIAL_HOST = "raw.githubusercontent.com";
const PEER_PROBE_SOURCE = "live-peer-probe";
const PEER_PROBE_WAIT_MS = 120_000;
// The watcher's provider bound (TERM, 2 s grace, KILL, 1 s join), with margin.
const CANCELLATION_BOUND_MS = 8_000;

async function waitUntil<T>(probe: () => T | undefined, timeoutMs: number, label: string): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = probe();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${label}`);
}

function processGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch {
    return true;
  }
}

// A host command source that answers with a fixed placeholder, except that a
// read by a credential watcher hangs while the hang file exists, unless that
// watcher is the one named in the skip file (the peer's). It records every
// watcher read as `<event> <watcher pid> <provider pid>`.
function writePeerProbeProvider(dir: string): string {
  const script = path.join(dir, "provider.sh");
  fs.writeFileSync(script, [
    "#!/bin/sh",
    `dir='${dir}'`,
    "case \"$(ps -o args= -p \"$PPID\" 2>/dev/null)\" in",
    "  *'credential sync --watch'*)",
    "    echo \"watch-start $PPID $$\" >> \"$dir/reads\"",
    "    if [ -f \"$dir/hang\" ] && [ \"$PPID\" != \"$(cat \"$dir/skip\" 2>/dev/null)\" ]; then",
    "      echo \"watch-hang $PPID $$\" >> \"$dir/reads\"",
    "      while :; do sleep 1; done",
    "    fi",
    "    echo \"watch-done $PPID $$\" >> \"$dir/reads\" ;;",
    "esac",
    "printf '%s\\n' 'live-peer-placeholder-not-a-token'",
    "",
  ].join("\n"), { mode: 0o755 });
  return script;
}

function peerProbeReads(dir: string): Array<Readonly<{ event: string; watcher: number; provider: number }>> {
  const file = path.join(dir, "reads");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => {
    const [event, watcher, provider] = line.split(" ");
    return { event: event as string, watcher: Number(watcher), provider: Number(provider) };
  });
}

function nearestRankP95(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(0.95 * sorted.length) - 1)] as number;
}

describe("launch latency: sub-second launch plan Phase B", () => {
  let fixture: LiveFixture;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    fs.rmSync(path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH), { force: true });
    // Two launches: the first may still build or select, the second leaves a
    // full validation's warm proof and a completed cleanup stamp behind.
    launchClaudeTimed(fixture);
    launchClaudeTimed(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  coreTest("a warm launch takes the warm proof, the held-lock handoff, and the short exit", () => {
    const warm = launchClaudeTimed(fixture);
    const output = warm.output;
    expect(timing(output, "validation:warm-proof"), describeOutput(output)).toContain("match");
    // The full validation's phases did not run.
    expect(milliseconds(output, "runtime-validation")).toBeUndefined();
    expect(milliseconds(output, "validation:topology")).toBeUndefined();
    expect(timing(output, "image-cleanup")).toContain("skipped inputs-unchanged");
    expect(timing(output, "launch-handoff")).toContain("minted");
    // Admission's Docker work before the agent is fully categorized.
    const before = timing(output, "session-admission")
      .map((detail) => /^docker-operations-before-agent=(\d+)$/.exec(detail)?.[1])
      .find((value) => value !== undefined);
    const categorized = timing(output, "admission-ops")
      .reduce((sum, detail) => sum + Number(/ count=(\d+) /.exec(detail)?.[1] ?? Number.NaN), 0);
    expect(Number(before)).toBe(categorized);
    // Spec open decision 3: the exited container's inspection proved it
    // stopped, so the teardown skipped the disconnect and the stop.
    expect(timing(output, "teardown-path")).toContain("exited");
    expect(sessionContainers(fixture)).toEqual([]);
  }, TEST_TIMEOUT_MS);

  coreTest("a warm launch with no session state skips the startup reconcile", () => {
    // The previous case already left the project with no session file, no
    // lifecycle record and no session container, so this launch's own
    // evidence proves the empty state the skip depends on.
    const warm = launchClaudeTimed(fixture);
    const output = warm.output;
    expect(timing(output, "startup:warm-empty"), describeOutput(output)).toContain("empty");
    expect(timing(output, "startup:reconcile-sessions"), describeOutput(output)).toContain("skipped warm-empty");
    expect(timing(output, "launch-handoff"), describeOutput(output)).toContain("minted");
  }, TEST_TIMEOUT_MS);

  coreTest("runfree up always validates fully, and the next launch is warm again", () => {
    const up = runfreeTimed(fixture, ["up"]);
    expect(up.status, describeOutput(up.output)).toBe(0);
    expect(milliseconds(up.output, "validation:topology"), describeOutput(up.output)).toBeGreaterThan(0);
    expect(timing(up.output, "validation:warm-proof")).toContain("recorded");
    const warm = launchClaudeTimed(fixture);
    expect(timing(warm.output, "validation:warm-proof"), describeOutput(warm.output)).toContain("match");
  }, TEST_TIMEOUT_MS);

  coreTest("an in-place proxy restart is a warm-proof mismatch, and the launch validates fully", () => {
    const project = composeProjectName(fixture);
    const proxyId = composeServiceContainerId(project, "proxy");
    dockerOrThrow("restart the proxy in place", ["restart", proxyId]);
    const restarted = launchClaudeTimed(fixture);
    const verdicts = timing(restarted.output, "validation:warm-proof");
    expect(verdicts.some((verdict) => verdict.startsWith("mismatch:")), describeOutput(restarted.output)).toBe(true);
    expect(milliseconds(restarted.output, "validation:topology")).toBeGreaterThan(0);
    // And the one after it is warm on the new incarnation.
    const warm = launchClaudeTimed(fixture);
    expect(timing(warm.output, "validation:warm-proof"), describeOutput(warm.output)).toContain("match");
  }, TEST_TIMEOUT_MS);

  coreTest("a firewall changed inside the running proxy is never a warm launch, and containment reclaims the warm path", () => {
    const project = composeProjectName(fixture);
    const proxyId = composeServiceContainerId(project, "proxy");
    // Same proxy container and start time: only the in-proxy ruleset moved.
    dockerOrThrow("add a chain to the proxy's table",
      ["exec", "--privileged", "--user", "0:0", proxyId, "nft", "add", "chain", "inet", "runfree_proxy", "runfree_warm_drift"]);
    const drifted = runfreeTimed(fixture, ["claude"]);
    const verdicts = timing(drifted.output, "validation:warm-proof");
    expect(verdicts, describeOutput(drifted.output)).not.toContain("match");
    expect(verdicts.some((verdict) => verdict.startsWith("mismatch:")), describeOutput(drifted.output)).toBe(true);
    // Full validation refuses the drifted ruleset and contains the proxy; the
    // drifted chain goes with the stopped proxy's network namespace.
    expect(drifted.status, describeOutput(drifted.output)).not.toBe(0);
    expect(dockerOrThrow("contained proxy state", ["inspect", "-f", "{{.State.Running}}", proxyId])).toBe("false");
    // Reclaim: the next launch recovers the stopped proxy through the
    // compatible rebind, which records no warm proof; the launch after it
    // validates fully and records one; the one after that is warm.
    launchClaudeTimed(fixture);
    const recorded = launchClaudeTimed(fixture);
    expect(timing(recorded.output, "validation:warm-proof"), describeOutput(recorded.output)).toContain("recorded");
    const warm = launchClaudeTimed(fixture);
    expect(timing(warm.output, "validation:warm-proof"), describeOutput(warm.output)).toContain("match");
  }, TEST_TIMEOUT_MS);

  extendedTest("latency gate: warm launches, measured in the CLI", () => {
    const runs = Number(process.env.LAUNCH_LATENCY_RUNS ?? "5");
    expect(Number.isSafeInteger(runs) && runs > 0).toBe(true);
    const samples: Array<Record<string, number | string | undefined>> = [];
    for (let index = 0; index < runs; index += 1) {
      const startedAt = performance.now();
      const launched = launchClaudeTimed(fixture);
      const wallMs = performance.now() - startedAt;
      const admission = ["admission:preflight", "admission:allocate", "admission:create-started", "admission:prove-running", "admission:activate", "admission:await-handoff"]
        .reduce((sum, phase) => sum + (milliseconds(launched.output, phase) ?? 0), 0);
      samples.push({
        wallMs,
        startupTotalMs: milliseconds(launched.output, "startup-total"),
        admissionMs: admission,
        warmProof: timing(launched.output, "validation:warm-proof").at(-1),
        handoff: timing(launched.output, "launch-handoff").at(-1),
        teardownPath: timing(launched.output, "teardown-path").at(-1),
      });
    }
    const report = process.env.LAUNCH_LATENCY_REPORT;
    if (report) fs.writeFileSync(report, `${JSON.stringify({ runs, samples }, null, 2)}\n`);
    for (const sample of samples) {
      expect(sample.warmProof).toBe("match");
      expect(sample.handoff).toBe("minted");
    }
    const bound = process.env.LAUNCH_LATENCY_P95_MS;
    if (bound !== undefined) {
      const overhead = samples.map((sample) => Number(sample.startupTotalMs ?? Number.NaN) + Number(sample.admissionMs));
      expect(nearestRankP95(overhead)).toBeLessThanOrEqual(Number(bound));
    }
  }, TEST_TIMEOUT_MS);

  // Last: it rebinds the shared credential's source for its duration, which
  // would turn the warm launches above into source re-reads.
  // No live fixture echoes a credentialed request's headers (the sandbox's
  // credential points at raw.githubusercontent.com, which does not), so the
  // peer's injected header itself is not observed: the case proves the value
  // the proxy injects is unchanged and that the peer's requests to that
  // destination are still admitted and answered upstream.
  coreTest("one session exits mid-read while a peer's held credential and its requests to the credential's host carry on", async () => {
    const providerDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-live-peer-probe.")));
    const provider = writePeerProbeProvider(providerDir);
    const holdMarker = path.join(fixture.projectRoot, MANAGED_HOLD_RELATIVE_PATH);
    const proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");
    const heldValueDigest = (): string => dockerOrThrow("digest the shared proxy credential",
      ["exec", "--user", "0:0", proxyId, "sha256sum", `/run/runfree-proxy-secrets/${SHARED_CREDENTIAL}`]);
    const runs: Array<ReturnType<typeof startRunfree>> = [];
    try {
      for (const args of [
        ["credential", "source", "add", PEER_PROBE_SOURCE, "--", provider],
        ["credential", "set-source", SHARED_CREDENTIAL, "--from-source", PEER_PROBE_SOURCE, "--refresh-every", "10s", "--replace-source"],
      ]) {
        const result = fixture.runfree(args);
        expect(result.status, describeOutput(result.output)).toBe(0);
      }
      fs.mkdirSync(path.dirname(holdMarker), { recursive: true });
      fs.writeFileSync(holdMarker, "");

      // The peer: attached, and its watcher has completed a read.
      const idle = new Set(sessionContainers(fixture));
      const peer = startRunfree(fixture, ["claude"]);
      runs.push(peer);
      const peerContainer = await waitUntil(() => sessionContainers(fixture).find((id) => !idle.has(id)), PEER_PROBE_WAIT_MS, "the peer session");
      const peerWatcher = (await waitUntil(() => peerProbeReads(providerDir).find((read) => read.event === "watch-done"), PEER_PROBE_WAIT_MS, "the peer watcher's first read")).watcher;
      fs.writeFileSync(path.join(providerDir, "skip"), String(peerWatcher));
      fs.writeFileSync(path.join(providerDir, "hang"), "");
      const digestBefore = heldValueDigest();

      // The exiting session: its watcher's read hangs until the session ends.
      const exiting = startRunfree(fixture, ["claude"]);
      runs.push(exiting);
      const exitingContainer = await waitUntil(() => sessionContainers(fixture).find((id) => !idle.has(id) && id !== peerContainer), PEER_PROBE_WAIT_MS, "the exiting session");
      const hung = await waitUntil(() => peerProbeReads(providerDir).find((read) => read.event === "watch-hang" && read.watcher !== peerWatcher), PEER_PROBE_WAIT_MS, "the exiting watcher's read");
      const peerReadsBefore = peerProbeReads(providerDir).filter((read) => read.event === "watch-done" && read.watcher === peerWatcher).length;
      dockerOrThrow("end the exiting session", ["kill", exitingContainer]);
      await exiting.completion;
      const stopped = Date.now();
      await waitUntil(() => processGone(hung.provider) && processGone(hung.watcher) ? true : undefined, CANCELLATION_BOUND_MS, "the exiting watcher and its read to end");
      expect(Date.now() - stopped).toBeLessThan(CANCELLATION_BOUND_MS);

      // The shared value is the one the peer's requests carry: unchanged,
      // still `ok`, and the peer's watcher reads it again on schedule.
      expect(heldValueDigest()).toBe(digestBefore);
      const status = fixture.runfree(["credential", "status", SHARED_CREDENTIAL]);
      expect(status.output, describeOutput(status.output)).toContain("last sync: ok");
      expect(dockerOrThrow("peer state", ["inspect", "-f", "{{.State.Running}}", peerContainer])).toBe("true");
      const request = docker(["exec", peerContainer, "zsh", "-lc",
        curlProbeCommand(`https://${SHARED_CREDENTIAL_HOST}/`, { maxTimeSeconds: 15, retries: 3 })]);
      expect(answeredByUpstream(parseProbeAnswer(request.stdout)), `the peer's request after the exit: ${describeOutput(request.output)}`).toBe(true);
      await waitUntil(() => peerProbeReads(providerDir).filter((read) => read.event === "watch-done" && read.watcher === peerWatcher).length > peerReadsBefore ? true : undefined,
        PEER_PROBE_WAIT_MS, "the peer watcher's next read");
      expect(heldValueDigest()).toBe(digestBefore);
    } finally {
      fs.rmSync(path.join(providerDir, "hang"), { force: true });
      fs.rmSync(holdMarker, { force: true });
      for (const id of sessionContainers(fixture)) docker(["kill", id]);
      await Promise.allSettled(runs.map((run) => run.completion));
      fixture.runfree(["credential", "set-source", SHARED_CREDENTIAL, "--from-env", SHARED_CREDENTIAL_ENV, "--replace-source"]);
      fixture.runfree(["credential", "source", "remove", PEER_PROBE_SOURCE]);
      fs.rmSync(providerDir, { recursive: true, force: true });
      await forceCleanSessions(fixture);
    }
  }, TEST_TIMEOUT_MS);
});
