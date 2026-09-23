// Session-independence live tranche: a compatible proxy replacement preserves
// and restores live sessions.
//
// Split from the attached tranche, whose header describes the shared setup.
// This file owns the replacement-recovery family: sessions carried across a
// compatible replacement (whose candidate's allowed destination IPs change
// between the checks), recovery from a failed candidate proof, and the terminal
// refusal when the recovery allowance is exhausted.

import { startLivePhase } from "./timing.ts";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";
import { runfreeStateRoot } from "../../../packages/cli/src/paths.ts";
import {
  REBIND_RECOVERY_BUDGET_MS,
  REBIND_RECOVERY_CREATIONS,
} from "../../../packages/cli/src/runtime/control-plane-rebind-recovery.ts";
import { controlPlaneRebindTransactionPath } from "../../../packages/cli/src/runtime/control-plane-rebind.ts";
import {
  composeProjectName,
  composeServiceContainerId,
  docker,
  dockerOrThrow,
  forceRemoveContainer,
  waitUntil,
} from "./docker.ts";
import {
  forceCleanSessions as forceClean,
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  type LiveFixture,
} from "./fixture.ts";
import {
  CONSUMER_CONVERGENCE_TIMEOUT_MS,
  PROVISION_TIMEOUT_MS,
  REPO_ROOT,
  TEST_TIMEOUT_MS,
  awaitAgentStarted,
  clearFirstRequestResult,
  configureAttachedProject,
  enforcedSessionSetIps,
  firewallSetIpsThroughProductCommand,
  parseLaunchReport,
  pollUntil,
  readDurableSessionRecord,
  requiredBackend,
  servedAliveUntil,
  servedSessionFiles,
  servedSessionKey,
  servedSourceIps,
  startAttachedLaunch,
  startRunfree,
  type LaunchRun,
} from "./attached-support.ts";
// ---------------------------------------------------------------------------
// Session-independence live acceptance: the replacement cases.
//
// The parent spec's acceptance is the union of its children's. Two criteria
// are covered here; five are not, and this header records why rather than
// letting a reader infer coverage from a file name.
//
// Covered:
//   L5/T6  a compatible proxy replacement beside many attached sessions
//          preserves every session's process and restores every session's
//          service, without relaunching any of them.
//   L6(b)  a candidate whose valid allowed destination IPs changed between the
//          checks is still the same candidate and still succeeds, while a real
//          identity change refuses. (T7's "two valid dumps differ only in
//          allowed IPs", driven live rather than from a stub, inside the L5
//          case: the allowlist changes just before its replacement.)
//
// NOT covered here, and not simulated:
//   L3(b)  "a proved boundary violation executes containment". Removing the
//          proxy does not prove one: the exact-proxy inventory then reads the
//          proxy as absent (`packages/cli/src/runtime/proxy-containment.ts:28`),
//          startup classifies an ordinary compatible restart, and containment
//          never runs. A live identity contradiction needs a container that
//          answers the proxy's exact id with another identity, which Docker
//          does not let a test produce. `proxy-containment.test.ts` covers the
//          classification; the recovery half is the proof-failure case below.
//   L6(a)  "delayed initialization" needs the firewall's init to be held past
//          the CA wait. No product lever exposes that, and a test that merely
//          recreates with an existing CA would assert the easy half and imply
//          the race was proved.
//   L3(a)  "transient warm-runtime observation failure" needs a Docker
//          observation to fail once and then succeed. Nothing injects that.
//   L7     "force candidate DNS failure" needs the candidate's resolution to
//          fail during the rebind. Nothing injects that either.
//   L8/T11 bounded DNS diagnostics on timeout/nonzero. The bounding and the
//          solo-retry rule are implemented (`runtime/probes.ts`), but with no
//          way to force a nonzero DNS outcome the assertion would pass because
//          nothing failed, which is not proof of a bound.
//
// Closing the last four needs a fault-injection surface in the rebind and probe
// paths. That is a product change to security-sensitive code and a maintainer
// decision, not something a test file should introduce on its own.
// ---------------------------------------------------------------------------

/**
 * Sessions carried across the replacement. The spec words this as "dozens"; the
 * gate runs eight.
 *
 * At 24 the case cost ~196 s, nearly all of it ramping and tearing down
 * sessions rather than exercising the replacement. What the restoration
 * allowance (Q5) bounds is the *restoration* — every live session re-served by
 * the new proxy inside one allowance, with no relaunch — and that is a
 * per-session proof the case makes individually, so it holds at eight exactly
 * as it held at 24. Raise it via `RUNFREE_LIVE_REPLACEMENT_SESSIONS` to re-run
 * the literal scale proof.
 */
const REPLACEMENT_SURVIVOR_SESSIONS = Number(process.env.RUNFREE_LIVE_REPLACEMENT_SESSIONS ?? 8);
const REPLACEMENT_SURVIVOR_LAUNCH_WORKERS = 4;
/** Long enough that no session's lease lapses while the replacement runs. */
const REPLACEMENT_SURVIVOR_LEASE_ENV = {
  RUNFREE_SESSION_INTERNAL_LEASE_DURATION_MS: "120000",
  RUNFREE_SESSION_HEARTBEAT_CADENCE_MS: "5000",
} as const;
/** The restoration allowance (Q5): one project-wide allowance, at most two proxy creations. */
const RESTORATION_ALLOWANCE_MS = 120_000;
const SURVIVOR_TEARDOWN_BATCH = 4;
const SURVIVOR_TEARDOWN_BATCH_TIMEOUT_MS = 120_000;
/** Not seeded by the sandbox fixture, so it cannot be allowlisted sideways. */
const ALLOWED_IP_CHANGE_HOST = "example.org";

type ProcessIdentity = Readonly<{ id: string; pid: string; startedAt: string }>;

/** Container identity as a triple, so a silent restart cannot read as survival. */
function processIdentity(containerId: string): ProcessIdentity {
  const inspected = dockerOrThrow(`process identity of ${containerId}`, [
    "inspect", "-f", "{{.Id}}\t{{.State.Pid}}\t{{.State.StartedAt}}", containerId,
  ]);
  const [id, pid, startedAt] = inspected.trim().split("\t");
  if (!id || !pid || !startedAt) throw new Error(`malformed identity inspection: ${inspected}`);
  return Object.freeze({ id, pid, startedAt });
}

function assertProcessSurvived(before: ProcessIdentity, label: string): void {
  const after = processIdentity(before.id);
  expect(after.id, `${label}: container was replaced`).toBe(before.id);
  expect(after.pid, `${label}: process was restarted (pid moved)`).toBe(before.pid);
  expect(after.startedAt, `${label}: container restarted`).toBe(before.startedAt);
}

/** The control plane generation the host has currently selected. */
function selectedControlPlaneDigest(fixture: LiveFixture, project: string): string {
  const projectId = project.replace(/^runfree-/u, "");
  const effective = path.join(
    runfreeStateRoot(fixture.env), "projects", projectId, "runtime", "v2", "control-plane", "effective.json",
  );
  const parsed = JSON.parse(fs.readFileSync(effective, "utf8")) as { controlPlaneGenerationDigest?: unknown };
  if (typeof parsed.controlPlaneGenerationDigest !== "string") {
    throw new Error(`no selected control plane generation in ${effective}`);
  }
  return parsed.controlPlaneGenerationDigest;
}

/**
 * Heartbeat cadence for the two recovery cases, with the lease left alone.
 *
 * These cases hold the proxy down for longer than a replacement does — a
 * failed startup, a candidate removal and a second startup, or three refusals
 * and an operator remedy — so `REPLACEMENT_SURVIVOR_LEASE_ENV`'s shortened 120000 ms lease would
 * be working against them. Nothing renews a record's lease anyway; it freezes
 * at admission (`packages/cli/src/runtime/startup.ts:1693`), so the contract
 * maximum the driver mints by default is strictly the safer value here and the
 * env is deliberately absent. The cadence is shortened for the opposite
 * reason: it is what decides how quickly a preserved session republishes its
 * file once a proxy exists again.
 */
const REBIND_RECOVERY_SESSION_ENV = { RUNFREE_SESSION_HEARTBEAT_CADENCE_MS: "5000" } as const;

/**
 * The durable rebind journal for this project, as read-only evidence.
 *
 * These cases assert against the journal the product wrote; they never
 * construct one. A hand-built journal would have to satisfy an exact-key
 * parser (`packages/cli/src/runtime/control-plane-rebind-recovery.ts:41`) and
 * would then be proving this file's copy of the schema rather than the
 * product's own recovery. The coupling that remains is read-only, so a renamed
 * field fails these assertions loudly instead of passing on a stale copy.
 */
type RebindJournalView = Readonly<{
  phase?: string;
  candidateControlPlane?: Readonly<{ proxyContainerId?: string }>;
  recovery?: Readonly<{ allowance?: Readonly<{ number?: number; creations?: number; exhausted?: boolean }> }>;
}>;

/** The journal, or undefined when no replacement is pending. Path asked of the product. */
function readRebindJournal(fixture: LiveFixture, project: string): RebindJournalView | undefined {
  const projectId = project.replace(/^runfree-/u, "");
  const file = controlPlaneRebindTransactionPath(
    path.join(runfreeStateRoot(fixture.env), "projects", projectId),
  );
  if (!fs.existsSync(file)) return undefined;
  return JSON.parse(fs.readFileSync(file, "utf8")) as RebindJournalView;
}

/**
 * The project's proxy containers, stopped ones included.
 *
 * `composeServiceContainerId` answers only about running containers and
 * refuses anything but exactly one, which is the right shape for every case
 * that expects a live proxy. These two cases deliberately run with no proxy
 * serving — one has removed the candidate, the other has refused to create
 * any — so they need the inventory rather than the identity, and they need the
 * stopped predecessor to be visible in it.
 */
function proxyContainerIds(project: string, options: Readonly<{ includeStopped?: boolean }> = {}): readonly string[] {
  return dockerOrThrow("proxy container inventory", [
    "ps",
    ...(options.includeStopped ? ["--all"] : []),
    "--no-trunc",
    "--filter",
    `label=com.docker.compose.project=${project}`,
    "--filter",
    "label=com.docker.compose.service=proxy",
    "--format",
    "{{.ID}}",
  ]).split("\n").map((line) => line.trim()).filter(Boolean);
}

/** `sh` `case` globs the shim below will interpolate unquoted, bounded to what cannot escape the arm. */
const DOCKER_SHIM_PATTERN = /^[A-Za-z0-9*./_-]+$/u;

type DockerRefusalShim = Readonly<{
  /** Hand this to the ONE startup under test; nothing else ever sees it. */
  env: NodeJS.ProcessEnv;
  /** The full argv the shim refused, or undefined when it never fired. */
  refusedArgv: () => string | undefined;
  dispose: () => void;
}>;

/**
 * A `docker` on PATH that refuses one command and forwards every other.
 *
 * The CLI resolves `docker` by name, and `dockerClientEnvironment` forwards `PATH` to
 * every Docker invocation the runtime makes — Compose, exec and inspect alike
 * (`packages/cli/src/runtime/env.ts:24`, `:44`). The wrapper is therefore
 * visible to exactly the one startup it is handed to: not to the session
 * heartbeats, which are host processes already running under the unshimmed
 * PATH, and not to this file's own `docker(...)` reads.
 *
 * Nothing is faked. Forwarded commands reach the daemon unchanged and return
 * the daemon's own answer; the refused one is not run at all, which is exactly
 * the observation failure the product classifies and handles
 * (`packages/cli/src/runtime/startup.ts:647`). A shim that answered a probe
 * with invented output would be proving the shim instead of the runtime.
 *
 * `armOn` makes the refusal ordered: it stays inert until the shim has seen —
 * and forwarded — a command matching that pattern. That is what lets a case
 * refuse a command which may also exist earlier in a startup without resting
 * on an assumption about when it is first issued.
 */
function createDockerRefusalShim(
  fixture: LiveFixture,
  options: Readonly<{ refuse: string; armOn?: string; reason: string }>,
): DockerRefusalShim {
  for (const pattern of [options.refuse, ...(options.armOn ? [options.armOn] : [])]) {
    if (!DOCKER_SHIM_PATTERN.test(pattern)) throw new Error(`unsafe Docker shim pattern: ${pattern}`);
  }
  const realDocker = childProcess
    .execFileSync("sh", ["-c", "command -v docker"], { env: fixture.env, encoding: "utf8" })
    .trim();
  if (!path.isAbsolute(realDocker)) throw new Error("the Docker refusal shim requires an absolute Docker executable");
  const bin = fs.mkdtempSync(path.join(fixture.ownerRoot, "docker-refusal."));
  const refusedPath = path.join(bin, "refused");
  const armedPath = options.armOn ? path.join(bin, "armed") : "";
  const quote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
  const arming = options.armOn
    ? `for runfree_argument in "$@"; do
  case "$runfree_argument" in
    ${options.armOn}) : > "$armed" ;;
  esac
done
`
    : "";
  fs.writeFileSync(
    path.join(bin, "docker"),
    `#!/bin/sh
# Live-fixture Docker shim. Not a production artifact: it refuses one command
# so a real startup failure can be observed, and forwards everything else.
armed=${quote(armedPath)}
if [ -z "$armed" ] || [ -f "$armed" ]; then
  for runfree_argument in "$@"; do
    case "$runfree_argument" in
      ${options.refuse})
        printf '%s\\n' "$*" > ${quote(refusedPath)}
        printf '%s\\n' ${quote(options.reason)} >&2
        exit 1
        ;;
    esac
  done
fi
${arming}exec ${quote(realDocker)} "$@"
`,
    { mode: 0o755 },
  );
  return Object.freeze({
    env: { PATH: `${bin}${path.delimiter}${fixture.env.PATH ?? ""}` },
    refusedArgv: () => (fs.existsSync(refusedPath) ? fs.readFileSync(refusedPath, "utf8").trim() : undefined),
    dispose: () => fs.rmSync(bin, { recursive: true, force: true }),
  });
}

describe("session independence: a compatible replacement preserves and restores live sessions", () => {
  requiredBackend();
  let fixture: LiveFixture;
  let project: string;

  /**
   * The proxy serving this project right now, resolved per use.
   *
   * These cases replace the proxy on purpose, so a container id captured once
   * in `beforeAll` is stale for every case after the first: it addresses a
   * removed container and every consumer read fails with "No such container".
   * The compose service name is the stable identity here; the container id is
   * not, and treating it as one is exactly what the replacement invalidates.
   */
  function currentProxyId(): string {
    return composeServiceContainerId(project, "proxy");
  }

  /**
   * Waits for a recovered proxy to serve both preserved peers.
   *
   * The peers' own output is the diagnosis when this times out: each logs why
   * its heartbeat could not adopt the new proxy. The proxy's served files and
   * the durable selection are appended so the failure also says which side
   * the restoration stopped on.
   */
  async function awaitPeersServed(
    proxyId: string,
    peerIps: readonly string[],
    label: string,
    peers: readonly Readonly<{ label: string; run: LaunchRun }>[],
  ): Promise<void> {
    try {
      await pollUntil(
        () => servedSourceIps(proxyId).length === peerIps.length,
        RESTORATION_ALLOWANCE_MS,
        label,
        peers.map((peer) => ({ label: `the ${peer.label} peer launch`, completion: peer.run.completion, output: peer.run.output })),
      );
    } catch (error) {
      const state = (read: () => unknown): string => {
        try { return JSON.stringify(read()); } catch (cause) { return `<unreadable: ${String(cause)}>`; }
      };
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}`
          + `; served files: ${state(() => servedSessionFiles(proxyId))}`
          + `; selected proxy ${state(currentProxyId)} (expected ${JSON.stringify(proxyId)})`
          + `; selected control plane generation ${state(() => selectedControlPlaneDigest(fixture, project))}`
          + `; rebind journal ${state(() => readRebindJournal(fixture, project) ?? null)}`,
        { cause: error },
      );
    }
  }

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: configureAttachedProject });
    project = composeProjectName(fixture);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  afterEach(async () => {
    if (!fixture) return;
    await forceClean(fixture);
    clearFirstRequestResult(fixture);
  });

  /** Both consumers, read from the proxy itself, agreeing on exactly these IPs. */
  function assertConsumersAdmitExactly(proxy: string, expectedIps: readonly string[], label: string): void {
    const expected = [...expectedIps].sort().join(",");
    waitUntil(
      () => servedSourceIps(proxy).join(",") === expected
        && [...enforcedSessionSetIps(proxy)].sort().join(",") === expected,
      { label: `${label}: files and kernel membership to converge`, timeoutMs: CONSUMER_CONVERGENCE_TIMEOUT_MS, intervalMs: 250 },
    );
    // The same kernel set through the product's own sealed read, so this is not
    // a lookalike of the host's convergence proof but that proof's own command.
    expect([...firewallSetIpsThroughProductCommand(proxy)].sort().join(","), `${label}: product-command read disagrees`).toBe(expected);
  }

  /**
   * Forces the compatible-rebind classification and drives it to completion.
   *
   * Stopping the proxy leaves the control generation untouched with no live
   * proxy, which is exactly `restart-compatible-proxy`; the next `up` must
   * replace the container, re-prove and rebind every retained session, and
   * finish token sync without touching a session container.
   */
  function forceCompatibleReplacement(label: string): Readonly<{ newProxyId: string; elapsedMs: number }> {
    const before = currentProxyId();
    dockerOrThrow(`stop the proxy for ${label}`, ["stop", "--time", "2", before]);
    const started = Date.now();
    const rebound = fixture.runfree(["up"]);
    const elapsedMs = Date.now() - started;
    expect(rebound.status, `${label}: the rebind did not complete: ${describeOutput(rebound.output, 4000)}`).toBe(0);
    const newProxyId = composeServiceContainerId(project, "proxy");
    expect(newProxyId, `${label}: the proxy container was not replaced`).not.toBe(before);
    return Object.freeze({ newProxyId, elapsedMs });
  }

  test("every attached session survives a compatible proxy replacement and is re-served without relaunch", async () => {
    // Sessions survive a compatible replacement (T6/L5). The guarantee is per
    // session, so every assertion below is per
    // session: a running-container count or one successful request cannot
    // establish it, and the spec says so explicitly.
    assertConsumersAdmitExactly(currentProxyId(), [], "before the replacement case");

    type Watched = Readonly<{ sessionId: string; ip: string; identity: ProcessIdentity; key: string }>;
    const watched: Watched[] = [];
    const runs: LaunchRun[] = [];
    let finishPhase = startLivePhase(`attached: replacement-survivor ${REPLACEMENT_SURVIVOR_SESSIONS}-session ramp`);
    let killed = false;
    // A launch that has exited has relaunched or lost its session.
    let exitedRuns = 0;
    try {
      let started = 0;
      let rampFailed = false;
      const worker = async (): Promise<void> => {
        try {
          while (!rampFailed && started < REPLACEMENT_SURVIVOR_SESSIONS) {
            started += 1;
            const run = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: REPLACEMENT_SURVIVOR_LEASE_ENV });
            runs.push(run);
            void run.completion.then(() => { exitedRuns += 1; }, () => { exitedRuns += 1; });
            for (const record of run.attached.records) {
              if (watched.some((session) => session.sessionId === record.sessionId)) continue;
              expect(record.containerId, `attached record ${record.sessionId} names no container`).toBeTruthy();
              watched.push(Object.freeze({
                sessionId: record.sessionId,
                ip: record.sourceIp,
                identity: processIdentity(String(record.containerId)),
                key: servedSessionKey(currentProxyId(), record.sourceIp),
              }));
              await awaitAgentStarted(String(record.containerId), `session ${record.sessionId}`);
            }
          }
        } catch (error) {
          rampFailed = true;
          throw error;
        }
      };
      const ramp = await Promise.allSettled(Array.from({ length: REPLACEMENT_SURVIVOR_LAUNCH_WORKERS }, () => worker()));
      finishPhase();
      const failures = ramp.filter((result) => result.status === "rejected");
      if (failures.length) throw new AggregateError(failures.map((r) => r.reason), `the ${REPLACEMENT_SURVIVOR_SESSIONS}-session ramp failed`);
      expect(watched.length, "the ramp did not attach every launched session").toBe(REPLACEMENT_SURVIVOR_SESSIONS);
      assertConsumersAdmitExactly(currentProxyId(), watched.map((session) => session.ip), "every session attached");

      const generationBefore = selectedControlPlaneDigest(fixture, project);

      // Changed allowed destination IPs (L6(b)/T7). Candidate identity must
      // exclude observation provenance: two valid firewall dumps that differ
      // only in allowed destination IPs are the same candidate. Changing the
      // allowlist changes the firewall's allowed destination IPs while leaving
      // container, image, network, control plane, contract, proof schema and
      // epoch identical, so the replacement below must still accept the
      // candidate — and step 4's unchanged generation still holds, because a
      // live policy change advances only the effective policy generation.
      const added = fixture.runfree(["host", "add", ALLOWED_IP_CHANGE_HOST]);
      expect(added.status, `could not add ${ALLOWED_IP_CHANGE_HOST}: ${describeOutput(added.output, 4000)}`).toBe(0);

      finishPhase = startLivePhase(`attached: replacement beside ${REPLACEMENT_SURVIVOR_SESSIONS} sessions`);
      const { newProxyId, elapsedMs } = forceCompatibleReplacement("the replacement beside live sessions");
      finishPhase();

      // 1. Every session's process survived. Not a count: each identity triple.
      for (const session of watched) {
        assertProcessSurvived(session.identity, `session ${session.sessionId} across the replacement`);
      }

      // 2. Every session is served again, by the REPLACEMENT proxy. Its tmpfs
      //    starts empty, so a file there can only be one the surviving client's
      //    own heartbeat wrote after adopting the rebound selection.
      finishPhase = startLivePhase("attached: restoration of every session");
      await pollUntil(
        () => servedSourceIps(newProxyId).length === watched.length,
        RESTORATION_ALLOWANCE_MS,
        `all ${REPLACEMENT_SURVIVOR_SESSIONS} sessions to be served by the replacement proxy`,
      );
      assertConsumersAdmitExactly(newProxyId, watched.map((session) => session.ip), "after the replacement");
      finishPhase();

      // 3. Restored, not stale: each address' file must be a NEW one, and its
      //    window must still be advancing under the session's own heartbeat.
      //    Every baseline is read first and all sessions are awaited together:
      //    the heartbeats run concurrently, so one cadence renews them all.
      const baselines = watched.map((session) => ({ session, before: servedAliveUntil(newProxyId, session.ip) }));
      await pollUntil(
        () => {
          const files = servedSessionFiles(newProxyId);
          return baselines.every(({ session, before }) => {
            const aliveUntil = files.find((file) => file.sourceIp === session.ip)?.aliveUntil;
            return aliveUntil !== undefined && aliveUntil > before;
          });
        },
        RESTORATION_ALLOWANCE_MS,
        `every session to renew against the replacement proxy`,
      );

      // 4. The control plane generation is UNCHANGED, and every record is still
      //    attached under it.
      //
      //    This is what "compatible" means: stopping the proxy with no input
      //    change classifies `restart-compatible-proxy`, which replaces the
      //    container within the same control plane generation. An earlier
      //    draft asserted the generation moved; the first live run reported
      //    both digests equal and was right to. A generation that moved here
      //    would mean this case exercised something other than the compatible
      //    replacement it claims, so pin it rather than delete it.
      const generationAfter = selectedControlPlaneDigest(fixture, project);
      expect(generationAfter, "a compatible replacement must not churn the control plane generation").toBe(generationBefore);
      for (const session of watched) {
        const record = readDurableSessionRecord(fixture, project, session.sessionId);
        expect(record?.state, `session ${session.sessionId} is no longer attached after the replacement`).toBe("attached");
      }

      // 5. The restoration allowance (Q5). Recorded, and asserted: a replacement that took longer
      //    than the allowance did not meet the availability contract.
      expect(elapsedMs, `the replacement exceeded the ${RESTORATION_ALLOWANCE_MS}ms restoration allowance`).toBeLessThanOrEqual(RESTORATION_ALLOWANCE_MS);

      // 6. No session was relaunched to achieve any of the above.
      expect(exitedRuns, "a launch runner exited during the replacement, so its session was relaunched rather than preserved").toBe(0);

      finishPhase = startLivePhase("attached: replacement-survivor teardown");
      for (let index = 0; index < watched.length; index += SURVIVOR_TEARDOWN_BATCH) {
        const batch = watched.slice(index, index + SURVIVOR_TEARDOWN_BATCH);
        docker(["kill", ...batch.map((session) => session.identity.id)]);
        await pollUntil(
          () => batch.every((session) => readDurableSessionRecord(fixture, project, session.sessionId) === undefined),
          SURVIVOR_TEARDOWN_BATCH_TIMEOUT_MS,
          `sessions ${batch.map((session) => session.sessionId).join(", ")} to finish tearing down`,
        );
      }
      killed = true;
      const reports = (await Promise.all(runs.map((run) => run.completion))).map((c) => parseLaunchReport(c));
      for (const report of reports) {
        expect(report.failure, `a session failed during teardown: ${report.failure}`).toBeUndefined();
      }
      assertConsumersAdmitExactly(newProxyId, [], "after every session ended");
      finishPhase();
    } finally {
      finishPhase();
      if (!killed && watched.length > 0) docker(["kill", ...watched.map((session) => session.identity.id)]);
      await Promise.all(runs.map((run) => run.completion.catch(() => undefined)));
    }
  }, TEST_TIMEOUT_MS);

  test("a candidate whose proof fails and whose container is then removed is recovered by a plain up", async () => {
    // A candidate whose proof fails, whose container is then removed, and which
    // a plain `up` recovers (T9) — in full, and the one criterion in this
    // family with no unit
    // substitute: the candidate failure has to travel through real startup
    // integration and the real durable journal, so a stubbed rejection cannot
    // satisfy it.
    //
    // How the failure is produced, and why each step is the one it is:
    //
    //   1. stopping the proxy classifies `restart-compatible-proxy`, exactly as
    //      `forceCompatibleReplacement` above documents;
    //   2. a `docker` shim on that startup's own PATH refuses ONE command — the
    //      proxy's `nft` owned-table inspection
    //      (`packages/cli/src/runtime/probes.ts:461`) — which the candidate's
    //      topology validation issues only after Compose has created the
    //      candidate container. The shim arms itself on the creation-marker
    //      override Compose is handed for that one call
    //      (`packages/cli/src/runtime/docker.ts:532`), so the refusal cannot
    //      fire earlier in the startup than the creation it must follow;
    //   3. a refused probe is not a PROVED boundary violation, so the failure
    //      classifies `observation-unavailable` and containment does not run
    //      (`packages/cli/src/runtime/startup.ts:644`). The candidate container
    //      therefore survives its own failed proof, charged to the allowance
    //      but unrecorded by the journal;
    //   4. the coordinator retries the transaction twice more inside the same
    //      `up` (`control-plane-rebind-coordinator.ts:825`), re-proving that
    //      same candidate rather than creating another, and then parks the
    //      journal at `prepared` with exactly one creation spent.
    //
    // The case then removes that candidate — the state the recovery design's
    // claim ledger records as able to wedge recovery — and proves a PLAIN
    // `runfree up` gets out of it with both peers intact.
    //
    // Chosen over killing the CLI mid-rebind, the other way to park a journal:
    // a kill has to land inside a window whose width is a property of the host,
    // and this was written where Docker is unavailable. Chosen over building
    // the parked journal by hand, which would assert this file's copy of an
    // exact-key schema rather than the product's recovery.
    //
    // What breaks it: a topology validation that no longer issues a bare `nft`
    // argv (the refusal never fires and the startup succeeds — asserted), a
    // startup that contains the proxy on an unavailable observation (no
    // candidate is left to remove — asserted), or a recovery slower than the
    // shared allowance, which is REBIND_RECOVERY_BUDGET_MS from the first
    // rebind and is named in the recovery failure message below.
    assertConsumersAdmitExactly(currentProxyId(), [], "proof-failure recovery: before the parked-journal case");
    const originalProxyId = currentProxyId();
    expect(readRebindJournal(fixture, project), "proof-failure recovery: a rebind journal was already pending before this case ran").toBeUndefined();

    const shim = createDockerRefusalShim(fixture, {
      refuse: "nft",
      armOn: "*runfree-proxy-attempt-*",
      reason: "live-fixture proof-failure shim: refusing the candidate proxy's nftables inspection",
    });
    const first = await startAttachedLaunch(fixture, { extraEnv: REBIND_RECOVERY_SESSION_ENV });
    const [firstRecord] = first.attached.records;
    expect(firstRecord, "proof-failure recovery: the first launch observed no attached record").toBeDefined();
    expect(firstRecord.containerId, "proof-failure recovery: the first attached record names no container").toBeTruthy();
    const firstIdentity = processIdentity(String(firstRecord.containerId));
    // A launch that has exited has relaunched or lost its session; the
    // replacement-survivor case
    // can only report that a completion promise exists, which cannot fail.
    let firstExited = false;
    let secondExited = false;
    void first.completion.then(() => { firstExited = true; }, () => { firstExited = true; });

    let second: LaunchRun | undefined;
    let secondIdentity: ProcessIdentity | undefined;
    let ended = false;
    try {
      second = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: REBIND_RECOVERY_SESSION_ENV });
      void second.completion.then(() => { secondExited = true; }, () => { secondExited = true; });
      const [secondRecord] = second.attached.records;
      expect(secondRecord, "proof-failure recovery: the second launch observed no new attached record").toBeDefined();
      expect(secondRecord.containerId, "proof-failure recovery: the second attached record names no container").toBeTruthy();
      expect(secondRecord.sessionId, "proof-failure recovery: the two launches reused one session id").not.toBe(firstRecord.sessionId);
      expect(secondRecord.sourceIp, "proof-failure recovery: the two launches reused one source IP").not.toBe(firstRecord.sourceIp);
      secondIdentity = processIdentity(String(secondRecord.containerId));
      const peerIps = [firstRecord.sourceIp, secondRecord.sourceIp];
      assertConsumersAdmitExactly(originalProxyId, peerIps, "proof-failure recovery: while both peers are attached");
      // Live sessions, not just recorded ones: each agent is running before the
      // proxy goes away (see awaitAgentStarted).
      await awaitAgentStarted(String(firstRecord.containerId), "proof-failure recovery: the first peer");
      await awaitAgentStarted(String(secondRecord.containerId), "proof-failure recovery: the second peer");

      // 1. The rebind fails inside real startup validation.
      dockerOrThrow("proof-failure recovery: stop the proxy to classify the compatible replacement", ["stop", "--time", "2", originalProxyId]);
      const rebindStartedAt = Date.now();
      let finishPhase = startLivePhase("attached: candidate proof failure");
      const failed = await startRunfree(fixture, ["up"], shim.env).completion;
      finishPhase();
      expect(
        failed.status,
        `proof-failure recovery: the startup succeeded although the candidate's nftables inspection was refused: ${describeOutput(failed.output, 6000)}`,
      ).not.toBe(0);
      expect(
        shim.refusedArgv(),
        "proof-failure recovery: no nftables inspection was refused, so the candidate never reached the proof this case fails"
          + ` (see packages/cli/src/runtime/probes.ts:461): ${describeOutput(failed.output, 6000)}`,
      ).toBeDefined();

      // 2. The journal is parked at the creation phase, one creation is spent,
      //    and no candidate was recorded — the proof never produced one.
      const parked = readRebindJournal(fixture, project);
      expect(parked, `proof-failure recovery: the failed startup left no rebind journal: ${describeOutput(failed.output, 6000)}`).toBeDefined();
      expect(parked?.phase, "proof-failure recovery: the journal did not park at the candidate-creation phase").toBe("prepared");
      expect(parked?.candidateControlPlane, "proof-failure recovery: the journal recorded a candidate although its proof failed").toBeUndefined();
      expect(parked?.recovery?.allowance?.creations, "proof-failure recovery: the failed proof did not charge exactly one creation").toBe(1);
      expect(parked?.recovery?.allowance?.exhausted, "proof-failure recovery: a single failed proof exhausted the whole allowance").toBe(false);

      // 3. The candidate container outlived its failed proof, unrecorded.
      const inventory = proxyContainerIds(project, { includeStopped: true });
      expect(inventory.length, `proof-failure recovery: expected exactly one unrecorded candidate proxy container, found ${inventory.length}`).toBe(1);
      const candidateProxyId = inventory[0];
      expect(candidateProxyId, "proof-failure recovery: Compose did not replace the proxy container before the proof failed").not.toBe(originalProxyId);

      // 4. Neither session was touched by the failure.
      assertProcessSurvived(firstIdentity, "proof-failure recovery: the first peer across the failed rebind");
      assertProcessSurvived(secondIdentity, "proof-failure recovery: the second peer across the failed rebind");

      // 5. Remove the candidate: a charged creation whose container is gone.
      forceRemoveContainer(candidateProxyId);
      expect(
        docker(["container", "inspect", candidateProxyId]).status,
        "proof-failure recovery: the candidate is still inspectable, so the parked journal's candidate was not removed",
      ).not.toBe(0);
      expect(proxyContainerIds(project, { includeStopped: true }), "proof-failure recovery: a proxy container survived the candidate removal").toEqual([]);

      // 6. A PLAIN `runfree up` — no retry flag, no operator argument — recovers.
      finishPhase = startLivePhase("attached: recovery through a plain up");
      const recovered = fixture.runfree(["up"]);
      finishPhase();
      const elapsedMs = Date.now() - rebindStartedAt;
      expect(
        recovered.status,
        `proof-failure recovery: the plain recovery failed ${elapsedMs}ms after the rebind began; the shared allowance is`
          + ` ${REBIND_RECOVERY_BUDGET_MS}ms and at most ${REBIND_RECOVERY_CREATIONS} creations, so check whether it ran out`
          + ` rather than refused for another reason: ${describeOutput(recovered.output, 6000)}`,
      ).toBe(0);
      expect(readRebindJournal(fixture, project), "proof-failure recovery: recovery completed without discarding the journal").toBeUndefined();
      const recoveredProxyId = currentProxyId();
      expect(recoveredProxyId, "proof-failure recovery: recovery adopted the removed candidate rather than creating a proxy").not.toBe(candidateProxyId);
      expect(recoveredProxyId, "proof-failure recovery: recovery reused the original proxy container").not.toBe(originalProxyId);

      // 7. Both peers, per session: same process, served again, never relaunched.
      assertProcessSurvived(firstIdentity, "proof-failure recovery: the first peer across recovery");
      assertProcessSurvived(secondIdentity, "proof-failure recovery: the second peer across recovery");
      await awaitPeersServed(
        recoveredProxyId,
        peerIps,
        "proof-failure recovery: both peers to be served by the recovered proxy",
        [{ label: "first", run: first }, { label: "second", run: second }],
      );
      assertConsumersAdmitExactly(recoveredProxyId, peerIps, "proof-failure recovery: after recovery");
      for (const record of [firstRecord, secondRecord]) {
        expect(
          readDurableSessionRecord(fixture, project, record.sessionId)?.state,
          `proof-failure recovery: session ${record.sessionId} is no longer attached after recovery`,
        ).toBe("attached");
      }
      expect(firstExited, "proof-failure recovery: the first peer's launch exited, so its session was relaunched rather than preserved").toBe(false);
      expect(secondExited, "proof-failure recovery: the second peer's launch exited, so its session was relaunched rather than preserved").toBe(false);

      // 8. Teardown runs through the recovered proxy, leaving both consumers empty.
      docker(["kill", firstIdentity.id, secondIdentity.id]);
      for (const peer of [{ label: "first", run: first }, { label: "second", run: second }]) {
        const report = parseLaunchReport(await peer.run.completion);
        expect(report.failure, `proof-failure recovery: the ${peer.label} peer failed during teardown: ${report.failure}`).toBeUndefined();
      }
      ended = true;
      assertConsumersAdmitExactly(recoveredProxyId, [], "proof-failure recovery: after both peers ended");
    } finally {
      shim.dispose();
      // Never leave a parked journal for the cases after this one: while a
      // journal exists every later `up` — the afterEach cleanup's own included
      // — classifies `restart-compatible-proxy`
      // (`packages/cli/src/runtime/upgrade-plan-v2.ts:107`). Best effort and
      // unasserted: the case above has already decided its own verdict.
      if (readRebindJournal(fixture, project)) fixture.runfree(["runtime", "recover", "--retry"]);
      if (!ended) {
        docker(["kill", firstIdentity.id, ...(secondIdentity ? [secondIdentity.id] : [])]);
        await Promise.all([first.completion.catch(() => undefined), second?.completion.catch(() => undefined)]);
      }
    }
  }, TEST_TIMEOUT_MS);

  test("an exhausted recovery allowance refuses, preserves both sessions and its journal, and is reclaimed only by an explicit retry", async () => {
    // An exhausted recovery allowance refuses terminally (T6), live and beside
    // live sessions. The allowance is
    // one project-wide budget: REBIND_RECOVERY_BUDGET_MS and at most
    // REBIND_RECOVERY_CREATIONS proxy creations
    // (`packages/cli/src/runtime/control-plane-rebind-recovery.ts:4`).
    //
    // It is exhausted here by two failed CREATIONS rather than by waiting out
    // the deadline, which would add two minutes of wall clock for the same
    // terminal state. The lever is a `docker` shim that refuses exactly the one
    // Compose invocation carrying a creation-marker override, written into a
    // `runfree-proxy-attempt-` directory for that call and no other
    // (`packages/cli/src/runtime/docker.ts:532`).
    //
    // Both creations are spent inside a single `up`, which is a property of the
    // coordinator rather than a shortcut: it retries a failed rebind twice more
    // in the same process (`control-plane-rebind-coordinator.ts:825`); each
    // retry finds a charged creation with no container, restarts the candidate
    // attempt and charges the next one (`:637`, `:651`); and the third finds
    // creations already at the limit and refuses (`:552`). The deadline is the
    // backstop, not the mechanism — on a host slow enough to reach it first the
    // journal still ends exhausted, so only the creation count below would
    // move, and its failure message says so.
    assertConsumersAdmitExactly(currentProxyId(), [], "exhausted allowance: before the terminal-refusal case");
    const originalProxyId = currentProxyId();
    expect(readRebindJournal(fixture, project), "exhausted allowance: a rebind journal was already pending before this case ran").toBeUndefined();

    const shim = createDockerRefusalShim(fixture, {
      refuse: "*runfree-proxy-attempt-*",
      reason: "live-fixture exhausted-allowance shim: refusing the marked candidate proxy creation",
    });
    const first = await startAttachedLaunch(fixture, { extraEnv: REBIND_RECOVERY_SESSION_ENV });
    const [firstRecord] = first.attached.records;
    expect(firstRecord, "exhausted allowance: the first launch observed no attached record").toBeDefined();
    expect(firstRecord.containerId, "exhausted allowance: the first attached record names no container").toBeTruthy();
    const firstIdentity = processIdentity(String(firstRecord.containerId));

    let second: LaunchRun | undefined;
    let secondIdentity: ProcessIdentity | undefined;
    let ended = false;
    try {
      second = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: REBIND_RECOVERY_SESSION_ENV });
      const [secondRecord] = second.attached.records;
      expect(secondRecord, "exhausted allowance: the second launch observed no new attached record").toBeDefined();
      expect(secondRecord.containerId, "exhausted allowance: the second attached record names no container").toBeTruthy();
      expect(secondRecord.sessionId, "exhausted allowance: the two launches reused one session id").not.toBe(firstRecord.sessionId);
      expect(secondRecord.sourceIp, "exhausted allowance: the two launches reused one source IP").not.toBe(firstRecord.sourceIp);
      secondIdentity = processIdentity(String(secondRecord.containerId));
      const peerIps = [firstRecord.sourceIp, secondRecord.sourceIp];
      assertConsumersAdmitExactly(originalProxyId, peerIps, "exhausted allowance: while both peers are attached");
      // Live sessions, not just recorded ones: each agent is running before the
      // proxy goes away (see awaitAgentStarted).
      await awaitAgentStarted(String(firstRecord.containerId), "exhausted allowance: the first peer");
      await awaitAgentStarted(String(secondRecord.containerId), "exhausted allowance: the second peer");

      // 1. Every candidate creation is refused, so the allowance runs out.
      dockerOrThrow("exhausted allowance: stop the proxy to classify the compatible replacement", ["stop", "--time", "2", originalProxyId]);
      const finishPhase = startLivePhase("attached: recovery allowance exhaustion");
      const refused = await startRunfree(fixture, ["up"], shim.env).completion;
      finishPhase();
      expect(
        refused.status,
        `exhausted allowance: the startup succeeded although every candidate creation was refused: ${describeOutput(refused.output, 6000)}`,
      ).not.toBe(0);
      expect(
        shim.refusedArgv(),
        "exhausted allowance: no creation-marked Compose call was refused, so the allowance was not spent on creations"
          + ` (see packages/cli/src/runtime/docker.ts:532): ${describeOutput(refused.output, 6000)}`,
      ).toBeDefined();
      // The operator-facing half of the refusal: `RebindRecoveryExhaustedError`
      // names the remedy (`control-plane-rebind-recovery.ts:96`) and startup
      // reports its message (`startup.ts:1568`).
      expect(refused.output, "exhausted allowance: the refusal did not report that the automatic allowance ended").toContain("automatic allowance ended");
      expect(refused.output, "exhausted allowance: the refusal did not name the explicit retry as its remedy").toContain("runfree runtime recover --retry");

      // 2. The journal is preserved and records the exhaustion.
      const exhausted = readRebindJournal(fixture, project);
      expect(exhausted, `exhausted allowance: the refused startup left no rebind journal: ${describeOutput(refused.output, 6000)}`).toBeDefined();
      expect(exhausted?.recovery?.allowance?.exhausted, "exhausted allowance: the allowance was not recorded exhausted").toBe(true);
      expect(
        exhausted?.recovery?.allowance?.creations,
        "exhausted allowance: the allowance did not spend both creations; a lower count means the 120s deadline ended it before the"
          + " second creation, which is the backstop rather than the lever this case intends",
      ).toBe(REBIND_RECOVERY_CREATIONS);
      // No creation ever succeeded, so the stopped predecessor is still the
      // project's only proxy container.
      expect(
        proxyContainerIds(project, { includeStopped: true }),
        "exhausted allowance: a proxy container was created although every marked creation was refused",
      ).toEqual([originalProxyId]);

      // 3. Terminal refusal preserves sessions; it does not drain them.
      assertProcessSurvived(firstIdentity, "exhausted allowance: the first peer across the terminal refusal");
      assertProcessSurvived(secondIdentity, "exhausted allowance: the second peer across the terminal refusal");

      // 4. A second PLAIN `up` must refuse again and must not hand out a new
      //    allowance. The shim is gone, so the durable allowance is the only
      //    thing left that can refuse.
      const repeated = fixture.runfree(["up"]);
      expect(
        repeated.status,
        `exhausted allowance: a plain up succeeded after the allowance was exhausted: ${describeOutput(repeated.output, 6000)}`,
      ).not.toBe(0);
      expect(
        repeated.output,
        "exhausted allowance: the repeated plain up refused for some reason other than the exhausted allowance",
      ).toContain("automatic allowance ended");
      const stillExhausted = readRebindJournal(fixture, project);
      expect(stillExhausted, "exhausted allowance: the repeated refusal discarded the journal").toBeDefined();
      expect(stillExhausted?.recovery?.allowance?.exhausted, "exhausted allowance: a plain up cleared the exhausted flag").toBe(true);
      expect(
        stillExhausted?.recovery?.allowance?.number,
        "exhausted allowance: a plain up granted a new allowance, which only an explicit retry may do",
      ).toBe(exhausted?.recovery?.allowance?.number);
      expect(stillExhausted?.recovery?.allowance?.creations, "exhausted allowance: a plain up refunded a spent creation").toBe(REBIND_RECOVERY_CREATIONS);
      assertProcessSurvived(firstIdentity, "exhausted allowance: the first peer across the repeated refusal");
      assertProcessSurvived(secondIdentity, "exhausted allowance: the second peer across the repeated refusal");

      // 5. The operator's remedy is the path that reclaims the wedge, and it
      //    must restore service to BOTH peers, in both consumers.
      const retried = fixture.runfree(["runtime", "recover", "--retry"]);
      expect(retried.status, `exhausted allowance: the explicit retry did not restore the runtime: ${describeOutput(retried.output, 6000)}`).toBe(0);
      expect(readRebindJournal(fixture, project), "exhausted allowance: the explicit retry completed without discarding the journal").toBeUndefined();
      const restoredProxyId = currentProxyId();
      expect(restoredProxyId, "exhausted allowance: the explicit retry reused the refused predecessor container").not.toBe(originalProxyId);
      assertProcessSurvived(firstIdentity, "exhausted allowance: the first peer across the explicit retry");
      assertProcessSurvived(secondIdentity, "exhausted allowance: the second peer across the explicit retry");
      await awaitPeersServed(
        restoredProxyId,
        peerIps,
        "exhausted allowance: both peers to be served after the explicit retry",
        [{ label: "first", run: first }, { label: "second", run: second }],
      );
      assertConsumersAdmitExactly(restoredProxyId, peerIps, "exhausted allowance: after the explicit retry");
      for (const record of [firstRecord, secondRecord]) {
        expect(
          readDurableSessionRecord(fixture, project, record.sessionId)?.state,
          `exhausted allowance: session ${record.sessionId} is no longer attached after the explicit retry`,
        ).toBe("attached");
      }

      docker(["kill", firstIdentity.id, secondIdentity.id]);
      for (const peer of [{ label: "first", run: first }, { label: "second", run: second }]) {
        const report = parseLaunchReport(await peer.run.completion);
        expect(report.failure, `exhausted allowance: the ${peer.label} peer failed during teardown: ${report.failure}`).toBeUndefined();
      }
      ended = true;
      assertConsumersAdmitExactly(restoredProxyId, [], "exhausted allowance: after both peers ended");
    } finally {
      shim.dispose();
      // Same contract as the case above: a journal left parked here would
      // reclassify every later startup in this describe.
      if (readRebindJournal(fixture, project)) fixture.runfree(["runtime", "recover", "--retry"]);
      if (!ended) {
        docker(["kill", firstIdentity.id, ...(secondIdentity ? [secondIdentity.id] : [])]);
        await Promise.all([first.completion.catch(() => undefined), second?.completion.catch(() => undefined)]);
      }
    }
  }, TEST_TIMEOUT_MS);
});
