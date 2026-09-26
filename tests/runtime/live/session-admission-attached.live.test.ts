// Attached-authority live tranche for per-session admission.
//
// The nominal tranche proves the sequence completes without ever activating;
// the crash tranche activates only to kill the host. This file is the first
// live proof of the attached state itself — the state a session spends nearly
// all its life in — and of the two claims activation makes:
//
//   1. an attached session's authority is exactly its source IP, present in
//      both paired consumers (the request-proxy's selected bindings and the
//      firewall's enforced nftables set), and nothing else is admitted; and
//   2. drift after the running proof — the case the drift tranche recorded as
//      owed because only lease renewal can see it — ends the session's
//      authority without ending its process; owner exit performs cleanup.
//
// Consumer state is read back from the proxy container itself, not from the
// host modules that wrote it: `cat` of the selection pointers and the selected
// immutable bindings, and `nft` for the enforced set. The taxonomy's
// declarative-config lesson applies — the daemon and the ruleset are the
// evidence, the renderer is not.
//
// The launched "agent" is the first-request stub (`agent-stub.ts`): a
// long-lived stand-in that sends one real request to an allowlisted host the
// moment it starts and records the answer. That first request is the
// activation-gate design's positive live proof (T5): behind the session entry
// it lands after activation and the proxy forwards it, where the real CLI used
// to be answered 403 and exit. The host is reserved and never resolves, so the
// proof depends on no public service. What runs inside the container beyond that is not
// what this tranche proves; the stub stays up so the attached window can be
// read. The gate's reclaim proof (T7) lives here too, because only the
// production launch activates.

import { startSessionSampler } from "./session-sampler.ts";
import { startLivePhase } from "./timing.ts";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";
import { projectInfo } from "../../../packages/cli/src/config.ts";
import { nodeRuntimeIO } from "../../../packages/cli/src/runtime.ts";
import { readPendingApprovals, touchWatcherHeartbeat } from "../../../packages/cli/src/runtime/approvals.ts";
import { CONTAINER_ROLE_LABEL } from "../../../packages/cli/src/runtime/container-inventory.ts";
import { PROJECT_ID_LABEL } from "../../../packages/cli/src/runtime/constants.ts";
import { tryAcquireProjectLifecycleLock } from "../../../packages/cli/src/runtime/sessions.ts";
import type { PendingApprovalRecord } from "../../../packages/runtime-contracts/src/write-approvals.ts";
import { FIRST_REQUEST_HOST } from "./agent-stub.ts";
import { admittedToUnresolvableHost, enableProxyVerboseLogging, proxyAdmittedEventCount } from "./proxy-answer.ts";
import {
  composeProjectName,
  composeServiceContainerId,
  containerAddressOnNetwork,
  docker,
  dockerOrThrow,
  internalNetworkId,
  waitUntil,
} from "./docker.ts";
import {
  assertFilesPathExercised,
  forceCleanSessions as forceClean,
  describeOutput,
  destroyLiveFixture,
  provisionLiveFixture,
  readSessionFileEvidence,
  type LiveFixture,
} from "./fixture.ts";
import {
  CONSUMER_CONVERGENCE_TIMEOUT_MS,
  ELIGIBILITY_REPUBLISH_TIMEOUT_MS,
  FAST_HEARTBEAT_ENV,
  FORWARD_PROBE_PORT,
  HELD_WRITE_TIMEOUT_MS,
  PEER_LOCK_HEARTBEAT_WINDOW_MS,
  PEER_LOCK_LEASE_ENV,
  PEER_LOCK_LEASE_MS,
  PROVISION_TIMEOUT_MS,
  RENEWAL_RESTORE_TIMEOUT_MS,
  REPO_ROOT,
  SESSION_REFILL_TIMEOUT_MS,
  SESSION_TEARDOWN_TIMEOUT_MS,
  TEST_TIMEOUT_MS,
  clearFirstRequestResult,
  configureAttachedProject,
  containerExitState,
  enforcedSessionSetIps,
  firewallSetIpsThroughProductCommand,
  firstRequestAnswer,
  firstRequestResult,
  parseLaunchReport,
  pollUntil,
  requiredBackend,
  servedAliveUntil,
  servedSessionFiles,
  servedSessionKey,
  servedSourceIps,
  startAttachedLaunch,
  startHeldLaunch,
  startHeldWrite,
  type HeldLaunch,
  type LaunchRun,
} from "./attached-support.ts";
import { liveTierSelected } from "./tiers.ts";

// This file holds cases of both live tiers (see `tiers.ts`): the exact
// authority of attached sessions is core; lifecycle recovery around it is
// extended.
const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

describe("attached per-session authority is exact and drift after the proof fails closed", () => {
  // Called for its validation, not its value, exactly as the sibling describes
  // below do: this tranche drives launches directly and no longer runs an
  // admission slice that would need the backend name.
  requiredBackend();
  let fixture: LiveFixture;
  let project: string;
  let proxyId: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: configureAttachedProject });
    project = composeProjectName(fixture);
    proxyId = composeServiceContainerId(project, "proxy");
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

  /**
   * Asserts exactly who this runtime admits, through whichever mechanism it is
   * actually admitting them (review fix F10).
   *
   * Every case below opens with this on an empty expectation and repeats it as
   * sessions come and go, so it is also where the admission source itself is
   * proven: the proxy must show `RUNFREE_SESSION_ADMISSION_SOURCE=files`, one
   * root-owned 0644 session file per live session, and a published eligibility.
   * Without that, a run whose source never reached the proxy would pass every
   * assertion in this file while proving nothing.
   */
  function assertSessionAuthorityExactly(expectedIps: readonly string[], label: string): void {
    const expected = [...expectedIps].sort();
    waitUntil(() => (
      servedSourceIps(proxyId).join(",") === expected.join(",")
        && [...enforcedSessionSetIps(proxyId)].sort().join(",") === expected.join(",")
    ), {
      label: `${label}: the session files and the kernel set to converge on [${expected.join(", ")}]`,
      timeoutMs: CONSUMER_CONVERGENCE_TIMEOUT_MS,
      intervalMs: 250,
    });
    assertFilesPathExercised(fixture, proxyId, expectedIps, label);
  }

  coreTest("an attached session's authority is exactly its source IP in both consumers, and ending it clears both", async () => {
    // The empty precondition is asserted, not assumed: without it, "exactly
    // this session" below could pass while a leftover admission from an
    // earlier case was also enforced.
    assertSessionAuthorityExactly([], "before any session");

    const admittedBefore = proxyAdmittedEventCount(proxyId, FIRST_REQUEST_HOST);
    // The first request is sent the moment the agent starts, so the proxy's
    // `admitted` event logging must already be on when the launch begins.
    const verbose = enableProxyVerboseLogging(proxyId, "attached-first-request");
    let launch: LaunchRun;
    try {
      launch = await startAttachedLaunch(fixture);
      await firstRequestResult(fixture);
    } finally {
      verbose.disable();
    }
    const [record] = launch.attached.records;
    expect(record, `the launch observed no attached record: ${JSON.stringify(launch.attached)}`).toBeDefined();
    expect(record.state).toBe("attached");
    expect(record.sourceIp).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/u);
    expect(record.containerId, "the attached record names no container to end").toBeTruthy();

    try {
      assertSessionAuthorityExactly([record.sourceIp], "while attached");
      // T5 (activation-gate design): the stub's very first request — sent
      // the moment the agent process started, with no retry — was admitted
      // and forwarded by the proxy. Without the session entry the agent's
      // first request lands before activation and the proxy refuses it 403
      // with `x-runfree-blocked`. The host never resolves, so a forwarded
      // request comes back as the proxy's upstream-failure 502.
      const first = firstRequestAnswer(fixture, await firstRequestResult(fixture));
      expect(first.blocked, `the proxy refused the agent's first request at start: ${first.detail}`).toBeUndefined();
      expect(admittedToUnresolvableHost(first), `the agent's first request was not forwarded: ${first.detail}`).toBe(true);
      expect(
        proxyAdmittedEventCount(proxyId, FIRST_REQUEST_HOST),
        "the proxy logged no admission for the agent's first request",
      ).toBeGreaterThan(admittedBefore);
    } finally {
      // The session must end even when a readback assertion throws, or its
      // admitted source IP and container survive into the next case.
      docker(["kill", String(record.containerId)]);
    }

    const report = parseLaunchReport(await launch.completion);
    // The stub was killed from outside, so the attach completes non-zero; what
    // must not happen is the launch surfacing a failure of its own, which
    // would mean revocation ran as compensation rather than as completion.
    expect(report.failure, `the launch failed rather than completing: ${report.failure}`).toBeUndefined();
    expect(report.outcome, "the launch reported no completion outcome").toBeDefined();
    expect(report.outcome?.status, "ending the container read as a clean agent exit").not.toBe(0);

    expect(report.after.lifecycleRegistryEmpty, "a completed session left a lifecycle record").toBe(true);
    expect(report.after.residualContainers, "a completed session left a session container").toBe(0);
    assertSessionAuthorityExactly([], "after revocation");

    const inspected = docker(["container", "inspect", String(record.containerId)]);
    expect(inspected.status, "the revoked session container still exists").not.toBe(0);
  }, TEST_TIMEOUT_MS);

  coreTest("two concurrent sessions are served exactly by their own addresses, and each teardown clears only its own authority", async () => {
    // One session pair, carrying what were three separate cases: concurrent
    // attachment with distinct identities, the served set read through both
    // consumers, and the ordered owner-exit teardown. They differed only in
    // which readback they took of the same two-session state, and each paid its
    // own ~20 s launches for it. Merged, nothing is dropped: every assertion
    // below appeared in one of the three.
    //
    // The teardown is ordered deliberately — second, then first — because the
    // claim is that ending one session clears *only* its own authority. A
    // simultaneous teardown could not tell "cleared exactly one" from "cleared
    // both".
    assertSessionAuthorityExactly([], "before the two-session case");

    const first = await startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    const [firstRecord] = first.attached.records;
    expect(firstRecord, "the first launch observed no attached record").toBeDefined();
    expect(firstRecord.containerId, "the first attached record names no container").toBeTruthy();

    let second: LaunchRun | undefined;
    let secondEnded = false;
    let firstEnded = false;
    try {
      second = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: FAST_HEARTBEAT_ENV });
      const [secondRecord] = second.attached.records;
      expect(secondRecord, "the second launch observed no new attached record").toBeDefined();
      expect(secondRecord.containerId, "the second attached record names no container").toBeTruthy();
      expect(secondRecord.sessionId, "concurrent launches reused one session id").not.toBe(firstRecord.sessionId);
      expect(secondRecord.sourceIp, "concurrent launches reused one source IP").not.toBe(firstRecord.sourceIp);
      const expected = [firstRecord.sourceIp, secondRecord.sourceIp].sort();

      // Convergence first, then the direct reads: the sealed write returns
      // before the firewall's own 100 ms loop has added the address, so a
      // kernel read taken here without waiting can legitimately be one loop
      // behind the files it is being compared against.
      assertSessionAuthorityExactly(expected, "while two sessions are served");
      // Read through the product's own two reads: the served set (what the
      // request proxy resolves a principal from) and the firewall set command
      // the host's convergence proof uses.
      const served = servedSessionFiles(proxyId);
      expect(served.map((entry) => String(entry.sourceIp)).sort(), "the proxy does not hold exactly the two sessions").toEqual(expected);
      expect(new Set(served.map((entry) => String(entry.sessionKey))).size, "the two sessions share one session key").toBe(2);
      for (const entry of served) {
        expect(entry.malformed, `session file ${String(entry.name)} is malformed`).toBeUndefined();
        expect(entry.eligible, `session file ${String(entry.sessionKey)} is not eligible`).toBe(true);
        expect(entry.wallActive, `session file ${String(entry.sessionKey)} is already expired`).toBe(true);
      }
      expect(firewallSetIpsThroughProductCommand(proxyId), "the kernel set does not enforce exactly the two served addresses").toEqual(expected);

      docker(["kill", String(secondRecord.containerId)]);
      const secondReport = parseLaunchReport(await second.completion);
      secondEnded = true;
      expect(secondReport.failure, `the second launch failed during teardown: ${secondReport.failure}`).toBeUndefined();
      expect(
        secondReport.after.records.map((record) => record.sessionId),
        "ending the second session removed the first session's lifecycle record",
      ).toContain(firstRecord.sessionId);
      assertSessionAuthorityExactly([firstRecord.sourceIp], "after one of the two ended");
      expect(servedSourceIps(proxyId), "ending one session took the other's file with it").toEqual([firstRecord.sourceIp]);
      expect(firewallSetIpsThroughProductCommand(proxyId), "ending one session took the other's kernel element with it").toEqual([firstRecord.sourceIp]);

      // The file IS the authority under this source, so "both consumers
      // cleared" is exactly this pair: the proxy holds no file to resolve a
      // principal from, and the kernel admits no packet from the address. Read
      // separately rather than through the shared helper alone, because the
      // ordered teardown claims the file goes first and the container after it
      // — a teardown that stopped the container while leaving the file
      // published would still leave an empty kernel set once the endpoint went
      // away.
      docker(["kill", String(firstRecord.containerId)]);
      const firstReport = parseLaunchReport(await first.completion);
      firstEnded = true;
      expect(firstReport.failure, `the first launch failed during teardown: ${firstReport.failure}`).toBeUndefined();
      expect(firstReport.after.lifecycleRegistryEmpty, "the served pair left a lifecycle record").toBe(true);
      expect(firstReport.after.residualContainers, "the served pair left a session container").toBe(0);
      assertSessionAuthorityExactly([], "after both served sessions ended");
      expect(servedSessionFiles(proxyId), "owner exit left a session file published").toEqual([]);
      expect(firewallSetIpsThroughProductCommand(proxyId), "owner exit left a kernel element").toEqual([]);
      for (const [label, record] of [["first", firstRecord], ["second", secondRecord]] as const) {
        expect(
          docker(["container", "inspect", String(record.containerId)]).status,
          `the ended ${label} session container still exists`,
        ).not.toBe(0);
      }
    } finally {
      const secondRecord = second?.attached.records[0];
      if (secondRecord?.containerId && !secondEnded) {
        docker(["kill", String(secondRecord.containerId)]);
        await second?.completion.catch(() => undefined);
      }
      if (!firstEnded) {
        docker(["kill", String(firstRecord.containerId)]);
        await first.completion.catch(() => undefined);
      }
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("a dead owner's session file, container, and record are reclaimed by the next launch", async () => {
    // The residue an ordinary kill leaves under this source: nobody deletes the
    // file, nobody removes the record, and the container keeps running, because
    // the process that would have done all three is gone. The reclamation is
    // the next launch's own reconcile, which runs before it allocates.
    assertSessionAuthorityExactly([], "before the dead-owner case");

    const abandoned = await startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    const [deadRecord] = abandoned.attached.records;
    expect(deadRecord, "the abandoned launch observed no attached record").toBeDefined();
    expect(deadRecord.containerId, "the abandoned record names no container").toBeTruthy();
    const deadContainer = String(deadRecord.containerId);

    let next: LaunchRun | undefined;
    let nextEnded = false;
    try {
      assertSessionAuthorityExactly([deadRecord.sourceIp], "while the soon-to-be-abandoned session is served");
      await abandoned.killOwner();

      // Vacuity guard: without residue there is nothing to reclaim, and the
      // case below would pass against a project that had already cleaned up.
      expect(servedSourceIps(proxyId), "the dead owner's session file was cleaned up by something").toEqual([deadRecord.sourceIp]);
      expect(containerExitState(deadContainer).running, "the dead owner's container stopped on its own").toBe(true);

      next = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: FAST_HEARTBEAT_ENV });
      const [liveRecord] = next.attached.records;
      expect(liveRecord, "the reclaiming launch observed no attached record").toBeDefined();
      expect(liveRecord.sessionId, "the reclaiming launch reused the dead session's identity").not.toBe(deadRecord.sessionId);
      assertSessionAuthorityExactly([liveRecord.sourceIp], "after the next launch reclaimed the dead owner");
      expect(
        docker(["container", "inspect", deadContainer]).status,
        "the dead owner's session container survived the next launch's reconcile",
      ).not.toBe(0);

      docker(["kill", String(liveRecord.containerId)]);
      const report = parseLaunchReport(await next.completion);
      nextEnded = true;
      expect(report.failure, `the reclaiming launch failed during teardown: ${report.failure}`).toBeUndefined();
      expect(report.after.lifecycleRegistryEmpty, "the reclaiming launch left a lifecycle record").toBe(true);
      assertSessionAuthorityExactly([], "after the reclaimed project ended");
    } finally {
      const liveRecord = next?.attached.records[0];
      if (liveRecord?.containerId && !nextEnded) {
        docker(["kill", String(liveRecord.containerId)]);
        await next?.completion.catch(() => undefined);
      }
      docker(["container", "rm", "--force", deadContainer]);
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("a peer holding the lifecycle lock past the session-file lease neither gaps the heartbeat nor needs an operator", async () => {
    // The L1 incident, run forward under the source that answers it. The same
    // choreography as the generation-path case above — A served, a peer parked
    // after creation and before start, holding the project lifecycle
    // lock past A's whole lease — and the opposite outcome: the heartbeat takes
    // no lock, so there is no gap to recover from and nothing for an operator
    // to do. Proven by A's address never leaving the kernel set across a window
    // longer than its lease, and by A's own file window advancing inside it.
    assertSessionAuthorityExactly([], "before the held-lock heartbeat case");

    const peerLockEnv = { ...PEER_LOCK_LEASE_ENV, ...FAST_HEARTBEAT_ENV } as const;
    const attached = await startAttachedLaunch(fixture, { extraEnv: peerLockEnv });
    const [aRecord] = attached.attached.records;
    expect(aRecord, "the attached launch observed no record").toBeDefined();
    expect(aRecord.containerId, "the attached record names no container").toBeTruthy();
    const aIp = aRecord.sourceIp;
    const aContainer = String(aRecord.containerId);

    let held: HeldLaunch | undefined;
    let heldReleased = false;
    let bContainer: string | undefined;
    let bCompleted = false;
    let attachedEnded = false;
    try {
      assertSessionAuthorityExactly([aIp], "while A is served, before the peer takes the lock");
      const windowBefore = servedAliveUntil(proxyId, aIp);

      // Hold before start: a lease-sized wait inside a running inspection exhausts the
      // proof deadline and the entry gate's activation timeout. Neither timer
      // measures the property here: A must renew while a peer owns the lock.
      held = await startHeldLaunch(fixture, "after-create", {
        allowExistingSessions: true,
        extraEnv: peerLockEnv,
      });
      const bRecord = held.held.records.find((record) => record.sessionId !== aRecord.sessionId);
      expect(bRecord, "the parked peer allocated no session record").toBeDefined();
      // The create command has returned, but its ID has not yet been bound to
      // the record. Ask Docker for the container carrying this exact session.
      bContainer = dockerOrThrow("parked peer container lookup", [
        "ps", "--all", "--no-trunc",
        "--filter", `label=${PROJECT_ID_LABEL}=${project.replace(/^runfree-/u, "")}`,
        "--filter", `label=io.runfree.session-id=${bRecord?.sessionId}`,
        "--format", "{{.ID}}",
      ]).trim();
      expect(bContainer, "the parked peer did not create exactly one container").toMatch(/^[a-f0-9]{64}$/u);
      expect(containerExitState(String(bContainer)).running, "the held peer started before release").toBe(false);
      assertSessionAuthorityExactly([aIp], "while the unstarted peer holds the lifecycle lock");
      const lockContext = {
        projectRoot: fixture.projectRoot,
        project: projectInfo(fixture.projectRoot, fixture.env),
        runtimeRoot: path.join(REPO_ROOT, "dist", "runtime"),
        env: fixture.env,
      };
      const assertLockContended = (): void => {
        const acquired = tryAcquireProjectLifecycleLock(lockContext);
        acquired?.release();
        expect(acquired, "the parked peer is not holding the lifecycle lock").toBeUndefined();
      };
      assertLockContended();

      const sampler = await startSessionSampler(proxyId);
      const nonces = sampler.watch(aIp, PEER_LOCK_LEASE_MS);
      const finishPhase = startLivePhase("attached: peer lock observation");
      try {
        const sampleDeadline = sampler.check().elapsedMs + PEER_LOCK_HEARTBEAT_WINDOW_MS;
        while (sampler.check().elapsedMs < sampleDeadline) {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        expect(nonces.size, "A did not renew while its peer held the lock").toBeGreaterThanOrEqual(2);
      } finally {
        await sampler.stop();
        finishPhase();
      }
      const windowAfter = servedAliveUntil(proxyId, aIp);
      expect(Date.parse(windowAfter), "A's served window never advanced").toBeGreaterThan(Date.parse(windowBefore));
      // A's container was never touched, and no operator action was involved.
      const aRunning = docker(["container", "inspect", "--format", "{{.State.Running}}", aContainer]);
      expect(aRunning.status, `A's container could not be inspected: ${describeOutput(aRunning.output)}`).toBe(0);
      expect(aRunning.stdout.trim(), "the peer's lock-hold stopped A's container").toBe("true");

      assertLockContended();
      held.release();
      heldReleased = true;
      // The peer completes its own admission beside A; both are then served.
      // Watched rather than merely waited on: everything this poll is waiting
      // for happens inside the peer launch, so a peer that failed or is stuck
      // has the only account of why the second file never appeared.
      await pollUntil(
        () => servedSourceIps(proxyId).length === 2,
        RENEWAL_RESTORE_TIMEOUT_MS,
        "the released peer to be served beside A",
        { label: "the released peer launch", completion: held.completion, output: held.output },
      );
      const bIp = servedSourceIps(proxyId).find((ip) => ip !== aIp);
      expect(bIp, "the released peer was never served").toBeTruthy();
      assertSessionAuthorityExactly([aIp, String(bIp)], "after the peer was released");

      docker(["kill", String(bContainer)]);
      const bReport = parseLaunchReport(await held.completion);
      bCompleted = true;
      expect(bReport.failure, `the peer launch reported a failure: ${bReport.failure}`).toBeUndefined();
      assertSessionAuthorityExactly([aIp], "after the peer ended, A alone is served");

      docker(["kill", aContainer]);
      const aReport = parseLaunchReport(await attached.completion);
      attachedEnded = true;
      expect(aReport.failure, `A failed during teardown: ${aReport.failure}`).toBeUndefined();
      expect(aReport.after.lifecycleRegistryEmpty, "A's teardown left a lifecycle record").toBe(true);
      assertSessionAuthorityExactly([], "after both sessions ended");
    } finally {
      if (held && !heldReleased) held.release();
      if (bContainer && !bCompleted) {
        docker(["kill", String(bContainer)]);
        await held?.completion.catch(() => undefined);
      }
      if (!attachedEnded) {
        docker(["kill", aContainer]);
        await attached.completion.catch(() => undefined);
      }
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("a forced policy reload republishes eligibility and refills the served set", async () => {
    // A proxy holding no eligibility serves nothing (invariant 9), so a policy
    // restart that took the eligibility file with it would silently strand every
    // live session. The claim is that it does not: eligibility is republished,
    // and the sessions are served again inside the heartbeat's own window,
    // without the operator doing anything and without the session process being
    // replaced.
    assertSessionAuthorityExactly([], "before the forced reload case");

    const attached = await startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    const [aRecord] = attached.attached.records;
    expect(aRecord, "the attached launch observed no record").toBeDefined();
    expect(aRecord.containerId, "the attached record names no container").toBeTruthy();
    const aIp = aRecord.sourceIp;
    const aContainer = String(aRecord.containerId);
    let ended = false;
    try {
      assertSessionAuthorityExactly([aIp], "while A is served, before the forced reload");
      const processBefore = dockerOrThrow(
        "A before the forced reload",
        ["inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", aContainer],
      );
      const proxyStartedBefore = dockerOrThrow(
        "proxy before the forced reload",
        ["inspect", "-f", "{{.State.StartedAt}}", proxyId],
      );

      const refused = fixture.runfree(["runtime", "reload-policy"]);
      expect(refused.status, describeOutput(refused.output, 4000)).not.toBe(0);
      expect(refused.output).toContain("--force");

      const forced = fixture.runfree(["runtime", "reload-policy", "--force"]);
      expect(forced.status, `forced reload failed: ${describeOutput(forced.output, 4000)}`).toBe(0);
      expect(composeServiceContainerId(project, "proxy"), "the forced reload replaced the proxy container").toBe(proxyId);
      // The premise of the whole case: this reload restarts the same container
      // in place, and the proxy entrypoint recreates the session-file directory
      // and removes `eligibility.json` on every start (see
      // `PublishedSessionEligibilityV2` in `component-state-v2.ts`). An
      // unchanged start time would mean nothing was ever lost, and the
      // republish below would be asserting a file that never went away.
      const proxyStartedAfter = dockerOrThrow(
        "proxy after the forced reload",
        ["inspect", "-f", "{{.State.StartedAt}}", proxyId],
      );
      expect(
        Date.parse(proxyStartedAfter),
        "the forced reload did not restart the proxy, so it took no session state with it",
      ).toBeGreaterThan(Date.parse(proxyStartedBefore));
      expect(
        dockerOrThrow("A after the forced reload", ["inspect", "-f", "{{.State.Pid}}|{{.State.StartedAt}}", aContainer]),
        "the forced reload restarted A's container",
      ).toBe(processBefore);

      await pollUntil(
        () => readSessionFileEvidence(proxyId).eligibility.present,
        ELIGIBILITY_REPUBLISH_TIMEOUT_MS,
        "the session eligibility to be republished after the forced reload",
      );
      await pollUntil(
        () => servedSourceIps(proxyId).includes(aIp) && enforcedSessionSetIps(proxyId).includes(aIp),
        SESSION_REFILL_TIMEOUT_MS,
        "A's session file and kernel element to be refilled after the forced reload",
      );
      assertSessionAuthorityExactly([aIp], "after the forced reload refilled the served set");

      docker(["kill", aContainer]);
      const report = parseLaunchReport(await attached.completion);
      ended = true;
      expect(report.failure, `A failed during teardown: ${report.failure}`).toBeUndefined();
      expect(report.after.lifecycleRegistryEmpty, "A's teardown left a lifecycle record").toBe(true);
      assertSessionAuthorityExactly([], "after A ended");
    } finally {
      if (!ended) {
        docker(["kill", aContainer]);
        await attached.completion.catch(() => undefined);
      }
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("an ingress forwarder on the internal network is never served, and a launch beside it is", async () => {
    // The MCP callback, VNC, and `runfree forward` all open the same hardened
    // ingress forwarder onto the project's internal network, so a container
    // that is emphatically not a session shares the session address space. Two
    // things must hold at once: the forwarder is never served (no file, no
    // kernel element), and a launch concurrent with it still gets an address of
    // its own — the allocator excludes every address the network baseline
    // already holds, forwarder included.
    assertSessionAuthorityExactly([], "before the ingress forwarder case");

    const first = await startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    const [firstRecord] = first.attached.records;
    expect(firstRecord, "the first launch observed no attached record").toBeDefined();
    expect(firstRecord.containerId, "the first attached record names no container").toBeTruthy();

    let forwardOpened = false;
    let second: LaunchRun | undefined;
    let secondEnded = false;
    let firstEnded = false;
    try {
      // Marked before the status is judged: a `forward start` that created the
      // container and then failed would otherwise leave it holding the internal
      // network open, which is what breaks the *next* run rather than this one.
      forwardOpened = true;
      const opened = fixture.runfree(["forward", String(FORWARD_PROBE_PORT), "start"]);
      expect(opened.status, `runfree forward start failed: ${describeOutput(opened.output, 4000)}`).toBe(0);

      const forwarderIds = dockerOrThrow("ingress forwarder lookup", [
        "ps", "--no-trunc",
        "--filter", `label=${PROJECT_ID_LABEL}=${project.replace(/^runfree-/u, "")}`,
        "--filter", `label=${CONTAINER_ROLE_LABEL}=ingress-forwarder`,
        "--format", "{{.ID}}",
      ]).split("\n").map((line) => line.trim()).filter(Boolean);
      expect(forwarderIds, "runfree forward opened no ingress forwarder container").toHaveLength(1);
      const forwarderIp = containerAddressOnNetwork(forwarderIds[0], internalNetworkId(project));

      second = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: FAST_HEARTBEAT_ENV });
      const [secondRecord] = second.attached.records;
      expect(secondRecord, "the concurrent launch observed no attached record").toBeDefined();
      expect(
        [firstRecord.sourceIp, secondRecord.sourceIp],
        "a session was allocated the forwarder's address",
      ).not.toContain(forwarderIp);
      const expected = [firstRecord.sourceIp, secondRecord.sourceIp].sort();
      assertSessionAuthorityExactly(expected, "while an ingress forwarder shares the internal network");
      expect(servedSourceIps(proxyId), "the forwarder is served as if it were a session").toEqual(expected);
      expect(firewallSetIpsThroughProductCommand(proxyId), "the forwarder's address is admitted by the kernel set").toEqual(expected);

      docker(["kill", String(secondRecord.containerId)]);
      await second.completion.catch(() => undefined);
      secondEnded = true;
      docker(["kill", String(firstRecord.containerId)]);
      const report = parseLaunchReport(await first.completion);
      firstEnded = true;
      expect(report.failure, `the first launch failed during teardown: ${report.failure}`).toBeUndefined();
      assertSessionAuthorityExactly([], "after both sessions beside the forwarder ended");
    } finally {
      const secondRecord = second?.attached.records[0];
      if (secondRecord?.containerId && !secondEnded) {
        docker(["kill", String(secondRecord.containerId)]);
        await second?.completion.catch(() => undefined);
      }
      if (!firstEnded) {
        docker(["kill", String(firstRecord.containerId)]);
        await first.completion.catch(() => undefined);
      }
      // The forwarder holds the internal network open, so it must go even when
      // an assertion above threw.
      if (forwardOpened) fixture.runfree(["forward", String(FORWARD_PROBE_PORT), "stop"]);
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("an owner exiting while another launch is admitting leaves exactly the arriving session served", async () => {
    // Teardown and admission both take the project lifecycle lock, and under
    // this source teardown is one indivisible file-first sequence. Racing them
    // is what a real project does all day — one terminal closes while another
    // opens — and the invariant is that the two sessions never share a verdict:
    // the leaving session's file and record go, the arriving session's stay.
    assertSessionAuthorityExactly([], "before the owner-exit race");

    const leaving = await startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    const [leavingRecord] = leaving.attached.records;
    expect(leavingRecord, "the leaving launch observed no attached record").toBeDefined();
    expect(leavingRecord.containerId, "the leaving record names no container").toBeTruthy();

    let arriving: LaunchRun | undefined;
    let arrivingEnded = false;
    let leavingEnded = false;
    try {
      assertSessionAuthorityExactly([leavingRecord.sourceIp], "before the race");
      // Read while the leaving session is the only one served, because its
      // address stops identifying it the moment it leaves: the allocator hands
      // out the lowest free host, so an arriving session that allocates after
      // the leaving record is gone legitimately receives the same address. The
      // key does not move between sessions, so it is what "the leaving
      // session's file" means for the rest of this case.
      const leavingKey = servedSessionKey(proxyId, leavingRecord.sourceIp);

      // Deliberately not awaited: the arriving launch is admitting while the
      // leaving owner is tearing down.
      const arrivingLaunch = startAttachedLaunch(fixture, {
        allowExistingSessions: true,
        extraEnv: FAST_HEARTBEAT_ENV,
      });
      docker(["kill", String(leavingRecord.containerId)]);
      arriving = await arrivingLaunch;
      const [arrivedRecord] = arriving.attached.records;
      expect(arrivedRecord, "the arriving launch observed no attached record").toBeDefined();
      expect(arrivedRecord.sessionId, "the arriving launch reused the leaving session's identity").not.toBe(leavingRecord.sessionId);

      const leavingReport = parseLaunchReport(await leaving.completion);
      leavingEnded = true;
      expect(leavingReport.failure, `the leaving owner failed during teardown: ${leavingReport.failure}`).toBeUndefined();
      await pollUntil(
        () => !servedSessionFiles(proxyId).some((entry) => entry.sessionKey === leavingKey),
        SESSION_TEARDOWN_TIMEOUT_MS,
        "the leaving session's file to be removed",
      );
      assertSessionAuthorityExactly([arrivedRecord.sourceIp], "after the leaving owner exited beside the arriving launch");
      // The address alone would not settle this: if the arriving session took
      // the leaving one's address, an exact-authority assertion on that
      // address is equally satisfied by the leaving session's own file
      // outliving its teardown. The key says which session the surviving file
      // belongs to.
      expect(
        servedSessionFiles(proxyId).map((entry) => String(entry.sessionKey)),
        "the file served at the arriving session's address is the leaving session's",
      ).not.toContain(leavingKey);

      docker(["kill", String(arrivedRecord.containerId)]);
      const arrivingReport = parseLaunchReport(await arriving.completion);
      arrivingEnded = true;
      expect(arrivingReport.failure, `the arriving launch failed during teardown: ${arrivingReport.failure}`).toBeUndefined();
      expect(arrivingReport.after.lifecycleRegistryEmpty, "the race left a lifecycle record").toBe(true);
      assertSessionAuthorityExactly([], "after the raced pair ended");
    } finally {
      const arrivedRecord = arriving?.attached.records[0];
      if (arrivedRecord?.containerId && !arrivingEnded) {
        docker(["kill", String(arrivedRecord.containerId)]);
        await arriving?.completion.catch(() => undefined);
      }
      if (!leavingEnded) {
        docker(["kill", String(leavingRecord.containerId)]);
        await leaving.completion.catch(() => undefined);
      }
    }
  }, TEST_TIMEOUT_MS);

  coreTest("a write grant issued to one session is not honoured for another session's address", async () => {
    // The live suites prove admission-set separation between sessions; this
    // proves session-scoped approval-grant separation. Two sessions are served; A's identical write is approved
    // with `--scope session`; B's is then held on its own, under its own
    // session identity, rather than being carried by A's grant.
    assertSessionAuthorityExactly([], "before the grant-separation case");

    const first = await startAttachedLaunch(fixture, { extraEnv: FAST_HEARTBEAT_ENV });
    const [firstRecord] = first.attached.records;
    expect(firstRecord, "the first launch observed no attached record").toBeDefined();
    expect(firstRecord.containerId, "the first attached record names no container").toBeTruthy();

    let second: LaunchRun | undefined;
    let secondEnded = false;
    let firstEnded = false;
    try {
      second = await startAttachedLaunch(fixture, { allowExistingSessions: true, extraEnv: FAST_HEARTBEAT_ENV });
      const [secondRecord] = second.attached.records;
      expect(secondRecord, "the second launch observed no attached record").toBeDefined();
      expect(secondRecord.containerId, "the second attached record names no container").toBeTruthy();
      assertSessionAuthorityExactly(
        [firstRecord.sourceIp, secondRecord.sourceIp].sort(),
        "while both grant-separation sessions are served",
      );

      const approvalContext = {
        projectRoot: fixture.projectRoot,
        project: projectInfo(fixture.projectRoot, fixture.env),
        runtimeRoot: path.join(REPO_ROOT, "dist", "runtime"),
        env: fixture.env,
      };
      const heartbeat = (): void => {
        expect(
          touchWatcherHeartbeat(approvalContext, nodeRuntimeIO, proxyId),
          "could not register the current proxy approval epoch",
        ).toBe(true);
      };
      const pendingWrites = (): readonly PendingApprovalRecord[] =>
        readPendingApprovals(approvalContext, nodeRuntimeIO, proxyId)
          .filter((record) => record.host === FIRST_REQUEST_HOST && record.method === "POST");
      heartbeat();

      // A's write is held under the ask default, and approved for A's session.
      startHeldWrite(String(firstRecord.containerId), "a");
      let firstPending: readonly PendingApprovalRecord[] = [];
      await pollUntil(() => {
        heartbeat();
        firstPending = pendingWrites();
        return firstPending.length === 1;
      }, HELD_WRITE_TIMEOUT_MS, "A's write to be held for approval");
      const firstHold = firstPending[0];
      expect(firstHold.session?.sessionId, "A's held write names no session subject").toBeTruthy();

      const approved = fixture.runfree(["approve", firstHold.id, "--scope", "session"]);
      expect(approved.status, `approve --scope session failed: ${describeOutput(approved.output, 4000)}`).toBe(0);
      await pollUntil(() => {
        heartbeat();
        return pendingWrites().every((record) => record.id !== firstHold.id);
      }, HELD_WRITE_TIMEOUT_MS, "A's approved write to be released");

      // B's identical write must be held on its own rather than admitted by
      // A's standing grant. Same host, method, path and category — the only
      // thing that differs is the session it comes from.
      startHeldWrite(String(secondRecord.containerId), "b");
      let secondPending: readonly PendingApprovalRecord[] = [];
      await pollUntil(() => {
        heartbeat();
        secondPending = pendingWrites();
        return secondPending.length === 1;
      }, HELD_WRITE_TIMEOUT_MS, "B's identical write to be held despite A's session grant");
      const secondHold = secondPending[0];
      expect(secondHold.id, "B's write was answered by A's own held request").not.toBe(firstHold.id);
      expect(
        secondHold.session?.sessionId,
        "B's held write carries A's session subject, so the grant was not session-scoped",
      ).not.toBe(firstHold.session?.sessionId);

      const denied = fixture.runfree(["approve", secondHold.id, "--deny"]);
      expect(denied.status, `approve --deny failed: ${describeOutput(denied.output, 4000)}`).toBe(0);
      expect(denied.output, "approve --deny did not decide B's held write").toContain(`denied ${secondHold.id}`);

      docker(["kill", String(secondRecord.containerId)]);
      await second.completion.catch(() => undefined);
      secondEnded = true;
      docker(["kill", String(firstRecord.containerId)]);
      const report = parseLaunchReport(await first.completion);
      firstEnded = true;
      expect(report.failure, `the grant-separation launch failed during teardown: ${report.failure}`).toBeUndefined();
      assertSessionAuthorityExactly([], "after the grant-separation sessions ended");
    } finally {
      const secondRecord = second?.attached.records[0];
      if (secondRecord?.containerId && !secondEnded) {
        docker(["kill", String(secondRecord.containerId)]);
        await second?.completion.catch(() => undefined);
      }
      if (!firstEnded) {
        docker(["kill", String(firstRecord.containerId)]);
        await first.completion.catch(() => undefined);
      }
    }
  }, TEST_TIMEOUT_MS);

  // Recorded, not silently absent. A session file carries an absolute
  // `aliveUntil`, and the proxy compares it against the clock of the VM its
  // container runs in. A guest clock that lags the host's would therefore keep
  // serving a file the host considers expired, for as long as the lag. The
  // fixture drives Docker Desktop and OrbStack through the ordinary client and
  // has no way to step the VM's clock (the daemon's own time is not a
  // per-container setting, and moving the host clock under a running run would
  // invalidate every other timing assertion in this file), so the case has no
  // live proof and is named here as untested rather than left out.
  test.skip("a guest clock lagging the host's does not extend a session file's served window (untested: the live fixture cannot shift the VM clock)", () => {
    throw new Error("unreachable: recorded as untested");
  });

  // No closing admission slice here, unlike the crash and entry-gate tranches.
  // Those two close with one because their damage — six crashes, a replaced
  // session entry — could plausibly leave a runtime that reconciles cleanly and
  // no longer admits. This tranche's last substantive case is the write-grant
  // refusal, and it reaches its refusal only by successfully admitting two
  // sessions first, so "the runtime still admits" is already its precondition.
  // A separate closing slice re-proved that at the cost of another launch.
});
