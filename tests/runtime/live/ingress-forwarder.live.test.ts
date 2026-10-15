// Ingress-forwarder live tranche: `runfree forward`, `runfree vnc`, and the
// per-session MCP OAuth callback, proved on a real daemon.
//
// Every forwarder claim is read back from `docker inspect` of the forwarder,
// the ingress host network's own labels, `/proc` inside the session, and real
// host round trips — never from Runfree's render (the taxonomy's
// declarative-config lesson). Launches go through the public CLI; see
// `ingress-support.ts` for why the crash harness's `--launch` is not enough.
//
// Spec gates covered (ingress forwarder tooling design, "Test and proof
// gates"; the maintainer's 2026-09-30 callback and recovery decisions):
//
//   core  `runfree forward` publishes 127.0.0.1:<port> only (PortBindings and
//         NetworkSettings.Ports), reaches an agent listener, carries the
//         hardened shape (CapDrop ALL, read-only rootfs, 65534:65534, no
//         mounts, exactly the ingress host network plus agent_internal), and
//         `forward <port> stop` removes it.
//   core  One-way: from inside the session, the forwarder's agent_internal
//         address refuses the forwarded port, while host→listener works.
//   core  A project with no OAuth-capable MCP server gets no mcp-callback
//         forwarder, no callback port file, and no bridge.
//   core  Two concurrent `runfree claude` sessions, each with the whole
//         callback two-hop (exact forwarder name/env/publication, the
//         in-session port file and bridge, a host GET reaching the session's
//         loopback listener with path and query intact, and the forwarder gone
//         when the session ends): two ports, two forwarders; a peer session
//         cannot reach the other's bridge or forwarder; ending one removes
//         only its own forwarder.
//   core  The callback is set up before the agent runs: the agent stub's very
//         first instruction already sees the port file naming this session's
//         forwarder port, and that forwarder started no later than the stub's
//         record of it.
//   core  Two launches started at the same moment get distinct callback ports
//         and each a working two-hop path.
//   core  `runfree shell` and `runfree mcp auth` ride the same lifecycle.
//   ext   `runfree vnc` end to end: server bootstrap (RFB banner through the
//         forward), loopback publication, ingress labels, clipboard off by
//         default, `vnc stop`. Skipped with the probed reason when the agent
//         image has no x11vnc/X display; this tranche installs nothing.
//   ext   Recovery (a): the owner of an eligible session is SIGKILLed; the next
//         launch's reconciliation removes the dead session's forwarder, and no
//         forwarder carrying the dead identity ever targets the new session.
//   ext   Recovery (a'): the dead owner's session container has also
//         stopped, so warm-launch topology validation meets the dead route
//         first; startup reclaims it and the next launch succeeds.
//   ext   A forwarder removed at each callback setup step (its start; its
//         agent_internal connect), from a `docker events` watcher, fails the
//         launch with the callback refusal and leaves no forwarder, session
//         container, or registry record; the next launch gets a two-hop path.
//         At the connect point the session is mildly CPU-throttled from its
//         create, so the removal lands before the bridge and probe; a launch
//         that attaches anyway fails the case at once.
//   ext   A launcher SIGKILLed at its forwarder's start leaves that forwarder,
//         its session container, and its lifecycle record behind; the next
//         launch succeeds and all three are reclaimed.
//   ext   Recovery (b): a compatible proxy replacement leaves a live callback
//         forwarder and a port forward in place, loopback-only and reaching.
//   core  A warm launch beside a live peer that owns a callback forwarder and
//         is the target of a recorded port forward takes the warm peer path;
//         once that peer ends, the forward left aimed at its address sends the
//         next launch to the full validation.
//   core  `runfree stop` and `runfree destroy` each remove a port forward
//         (destroy also takes the host network).
//   ext   Lock-hold budget: a warm launch that took the held-lock handoff,
//         whose session's callback bridge is throttled to a sliver of a CPU,
//         never makes a `destroy --force` started meanwhile give up on the
//         lifecycle lock. It brings the runtime back first and is the file's
//         last case.
//
// Contract points marked "contract: session MCP OAuth callback decisions
// 2026-09-30" pin the per-launch callback being implemented alongside this
// file: a forwarder per launch (not per `mcp auth` only), its
// RUNFREE_CALLBACK_SESSION_* identity env, the in-session port file, a bridge
// that accepts only the forwarder, and reconciliation of a dead owner's
// forwarder. They are written against that contract, not the code at HEAD.
//
// NOT covered here:
//   - The unit gates (label minting, validator mutations, inventory-only
//     enumeration, VNC legacy-label tolerance, teardown ordering); those are
//     `packages/cli/src/runtime/*.test.ts`.
//   - A real OAuth provider or a real agent CLI callback server: the in-session
//     listener stands in for the CLI's loopback server, and the MCP server's
//     host is reserved (`.invalid`), so no token is ever minted.
//   - A browser: the host GET is the browser's redirect request.
//   - VNC on the stock base image, which ships no x11vnc (the case reports
//     that as a skip, not a pass).

import { afterAll, afterEach, beforeAll, describe, expect, test } from "vitest";
import { CONTAINER_ROLE_LABEL, INGRESS_PURPOSE_LABEL } from "../../../packages/cli/src/runtime/container-inventory.ts";
import { PROJECT_ID_LABEL } from "../../../packages/cli/src/runtime/constants.ts";
import { SESSION_CONTAINER_LABELS } from "../../../packages/cli/src/runtime/session-containers.ts";
import {
  PROVISION_TIMEOUT_MS,
  REPO_ROOT,
  TEST_TIMEOUT_MS,
  pollUntil,
  requiredBackend,
  servedSourceIps,
} from "./attached-support.ts";
import {
  composeProjectName,
  composeServiceContainerId,
  containerAddressOnNetwork,
  docker,
  dockerOrThrow,
  internalNetworkId,
} from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  forceCleanSessions as forceClean,
  provisionLiveFixture,
  type LiveFixture,
} from "./fixture.ts";
import {
  CALLBACK_BRIDGE_MARKER,
  CALLBACK_FORWARDER_TIMEOUT_MS,
  CALLBACK_PORT_FILE,
  CALLBACK_REQUEST_PATH,
  MCP_FIXTURE_SERVER,
  allCallbackForwarders,
  allSessionContainers,
  awaitExitUnlessAttached,
  awaitHostReach,
  awaitStartObservation,
  callbackForwardersForSession,
  configureIngressProject,
  containerEnv,
  daemonNow,
  dockerTimestampNs,
  forceRemoveProjectForwarders,
  freeLoopbackPort,
  hostTcpBanner,
  inspectContainer,
  listenerLog,
  loopbackOnlyPublication,
  projectIngressForwarders,
  projectIngressHostNetworks,
  publishedBindings,
  sessionFile,
  sessionListenerOwner,
  sessionProcessArgv,
  peekSessionRegistryRecords,
  sessionRegistryRecords,
  sessionTcpProbe,
  spawnCli,
  startCliSession,
  startSessionListener,
  upWithExactApprovals,
  watchDockerEvents,
  type CallbackForwarder,
  type CliLaunch,
  type ContainerInspect,
  type DockerEvent,
  type SessionListener,
  type SpawnedCli,
} from "./ingress-support.ts";
import { liveTierSelected } from "./tiers.ts";
import { milliseconds, timing } from "./launch-timing-support.ts";
import { LAUNCH_LOCK_HOLD_BUDGET_MS } from "../../../packages/cli/src/runtime/launch-lock-hold.ts";

// Mixed file (see `tiers.ts`): loopback publication, the one-way refusal, the
// callback two-hop and peer refusal, and teardown are trust-boundary proofs;
// VNC and the two recovery cases are extended.
const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

/**
 * The session's CPU share at the agent_internal-connect kill point: slow
 * enough that the bridge start outlasts a `docker rm -f`, far above the
 * lock-hold case's 0.01 so the bridge is not starved into its own timeout.
 */
const CONNECT_POINT_SESSION_CPUS = 0.1;
/** Bound for a dead owner's forwarder to be reconciled away once a new launch runs. */
const RECONCILE_TIMEOUT_MS = 90_000;
/** Bound for a preserved session to be re-served after the compatible replacement. */
const RESTORATION_TIMEOUT_MS = 120_000;
/** Shortened heartbeat for the replacement case so the preserved session republishes promptly. */
const REBIND_SESSION_ENV = { RUNFREE_SESSION_HEARTBEAT_CADENCE_MS: "5000" } as const;

describe("ingress forwarders are loopback-only, one-way, per-session, and torn down", () => {
  requiredBackend();
  let fixture: LiveFixture;
  let project: string;
  let projectId: string;
  let internalNetworkName: string;
  let mcpEligible = false;
  let runtimeDestroyed = false;
  const launches: CliLaunch[] = [];

  beforeAll(() => {
    // An isolated HOME: a maintainer's user-scope HTTP MCP server needs no
    // approval, so it would make every session here callback eligible and
    // void the negative case's precondition.
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: configureIngressProject, isolateHostHome: true });
    project = composeProjectName(fixture);
    projectId = project.replace(/^runfree-/u, "");
    internalNetworkName = `${project}_agent_internal`;
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  afterEach(async () => {
    if (!fixture) return;
    // Sessions first: a forwarder removed under a live session would be
    // re-reported by that session's own teardown as a failure it did not cause.
    const endings = launches.splice(0).filter((launch) => !launch.exited()).map((launch) => launch.end().catch(() => undefined));
    await Promise.all(endings);
    if (!runtimeDestroyed) await forceClean(fixture);
    // Every case asserts its own forwarder teardown; this only keeps a failed
    // case's residue from holding a loopback port or agent_internal open.
    forceRemoveProjectForwarders(projectId);
  }, PROVISION_TIMEOUT_MS);

  async function launch(
    args: readonly string[],
    label: string,
    extraEnv?: NodeJS.ProcessEnv,
    options: Readonly<{ byOwnerPid?: boolean }> = {},
  ): Promise<CliLaunch> {
    const started = await startCliSession(fixture, project, args, { label, extraEnv, byOwnerPid: options.byOwnerPid });
    launches.push(started);
    return started;
  }

  /**
   * Makes the project's runtime MCP OAuth policy carry a server, the way a
   * user does: enable the project's public HTTP MCP server, then start.
   * Without a terminal, enable needs --no-discover; it saves the approval and
   * selects the approved controls before the runtime starts.
   */
  function ensureMcpOAuthEligible(): void {
    if (mcpEligible) return;
    const approved = fixture.runfree(["mcp", "enable", "claude", MCP_FIXTURE_SERVER, "--source", "project", "--no-discover", "--no-login"]);
    expect(approved.status, `mcp enable failed: ${describeOutput(approved.output, 4000)}`).toBe(0);
    upWithExactApprovals(fixture);
    mcpEligible = true;
  }

  function inspectOrThrow(nameOrId: string, label: string): ContainerInspect {
    const inspect = inspectContainer(nameOrId);
    if (!inspect) throw new Error(`${label}: ${nameOrId} does not exist`);
    return inspect;
  }

  function assertGone(nameOrId: string, label: string): void {
    expect(inspectContainer(nameOrId), `${label}: ${nameOrId} still exists`).toBeUndefined();
  }

  /** Loopback-only publication of exactly one port, in both of Docker's maps. */
  function assertLoopbackOnly(inspect: ContainerInspect, port: string, label: string): void {
    const expected = loopbackOnlyPublication(port);
    expect(publishedBindings(inspect.HostConfig?.PortBindings), `${label}: HostConfig.PortBindings`).toEqual(expected);
    expect(publishedBindings(inspect.NetworkSettings?.Ports), `${label}: NetworkSettings.Ports`).toEqual(expected);
  }

  /**
   * The hardened shape, read back from the daemon. The second network is
   * identified by the labels the facility minted on it, not by its name.
   */
  function assertHardenedForwarder(inspect: ContainerInspect, label: string): void {
    const capDrop = inspect.HostConfig?.CapDrop ?? [];
    expect(capDrop.some((cap) => /^(?:CAP_)?ALL$/iu.test(cap)), `${label}: CapDrop ${JSON.stringify(capDrop)}`).toBe(true);
    expect(inspect.HostConfig?.CapAdd ?? [], `${label}: CapAdd`).toEqual([]);
    expect(inspect.HostConfig?.Privileged, `${label}: privileged`).toBe(false);
    expect(inspect.HostConfig?.ReadonlyRootfs, `${label}: read-only rootfs`).toBe(true);
    expect(inspect.HostConfig?.SecurityOpt ?? [], `${label}: security options`).toContain("no-new-privileges:true");
    expect(inspect.Config?.User, `${label}: user`).toBe("65534:65534");
    expect(inspect.Mounts ?? [], `${label}: mounts`).toEqual([]);
    expect(inspect.HostConfig?.Binds ?? [], `${label}: binds`).toEqual([]);

    const networks = Object.keys(inspect.NetworkSettings?.Networks ?? {}).sort();
    expect(networks, `${label}: networks`).toHaveLength(2);
    expect(networks, `${label}: networks`).toContain(internalNetworkName);
    const hostNetwork = networks.find((name) => name !== internalNetworkName) ?? "";
    expect(inspect.HostConfig?.NetworkMode, `${label}: primary network`).toBe(hostNetwork);
    const labels = JSON.parse(dockerOrThrow(`${label}: host network labels`, [
      "network", "inspect", "-f", "{{json .Labels}}", hostNetwork,
    ])) as Record<string, string>;
    expect(labels["io.runfree.network-role"], `${label}: host network role`).toBe("ingress-host");
    expect(labels[PROJECT_ID_LABEL], `${label}: host network project`).toBe(projectId);
    expect(projectIngressHostNetworks(projectId), `${label}: host network inventory`).toEqual([hostNetwork]);
  }

  function forwarderInternalIp(forwarderId: string): string {
    return containerAddressOnNetwork(forwarderId, internalNetworkId(project));
  }

  /** Waits for exactly one callback forwarder carrying this session's identity. */
  async function awaitCallbackForwarder(run: CliLaunch): Promise<CallbackForwarder> {
    let found: readonly CallbackForwarder[] = [];
    await pollUntil(
      () => {
        found = callbackForwardersForSession(projectId, run.session.sessionId);
        return found.length > 0;
      },
      CALLBACK_FORWARDER_TIMEOUT_MS,
      `${run.label}'s mcp-callback forwarder`,
      { label: run.label, completion: run.completion, output: run.output },
    );
    expect(found, `${run.label}: more than one callback forwarder names this session`).toHaveLength(1);
    return found[0];
  }

  type TwoHop = Readonly<{ forwarder: CallbackForwarder; listener: SessionListener }>;

  /**
   * The whole per-session callback contract for one live session, then a host
   * round trip through both hops. Contract: session MCP OAuth callback
   * decisions 2026-09-30.
   */
  async function assertCallbackTwoHop(run: CliLaunch): Promise<TwoHop> {
    const { session } = run;
    const forwarder = await awaitCallbackForwarder(run);
    const port = forwarder.port;
    expect(port, `${run.label}: callback port`).toMatch(/^[1-9]\d{0,4}$/u);
    expect(forwarder.name, `${run.label}: forwarder name`).toBe(`runfree-ingress-mcp-callback-${projectId}-${port}`);
    expect(forwarder.env.RUNFREE_CALLBACK_SESSION_ID, `${run.label}: session id env`).toBe(session.sessionId);
    expect(forwarder.env.RUNFREE_CALLBACK_SESSION_CONTAINER, `${run.label}: session container env`).toBe(session.containerId);
    expect(forwarder.env.RUNFREE_CALLBACK_SESSION_CONTAINER, `${run.label}: session container env`).toMatch(/^[a-f0-9]{64}$/u);
    expect(forwarder.env.INGRESS_TARGET, `${run.label}: target`).toBe(session.ip);
    expect(forwarder.env.INGRESS_TARGET_PORT, `${run.label}: target port`).toBe(port);
    expect(forwarder.env.INGRESS_HOST_PORT, `${run.label}: host port`).toBe(port);

    const inspect = inspectOrThrow(forwarder.id, run.label);
    expect(inspect.State?.Running, `${run.label}: forwarder running`).toBe(true);
    expect(inspect.Config?.Labels?.[CONTAINER_ROLE_LABEL], `${run.label}: role label`).toBe("ingress-forwarder");
    expect(inspect.Config?.Labels?.[INGRESS_PURPOSE_LABEL], `${run.label}: purpose label`).toBe("mcp-callback");
    assertLoopbackOnly(inspect, port, run.label);
    assertHardenedForwarder(inspect, run.label);

    expect(sessionFile(session.containerId, CALLBACK_PORT_FILE)?.trim(), `${run.label}: ${CALLBACK_PORT_FILE}`).toBe(port);
    const bridge = sessionListenerOwner(session.containerId, session.ip, port, CALLBACK_BRIDGE_MARKER);
    expect(bridge.pids.length, `${run.label}: no in-session bridge process`).toBeGreaterThan(0);
    expect(bridge.listening, `${run.label}: nothing listens on ${session.ip}:${port}`).toBe(true);
    expect(bridge.owned, `${run.label}: the ${session.ip}:${port} listener is not the bridge's`).not.toBe(false);

    // The CLI's callback server binds the session's own loopback; this
    // listener stands in for it, so only the bridge can reach it.
    const listener = await startSessionListener(session.containerId, "127.0.0.1", port, "callback");
    const reached = await awaitHostReach(port, CALLBACK_REQUEST_PATH, listener, `${run.label} two-hop callback`);
    expect(reached.status, `${run.label}: callback status`).toBe(200);
    expect(reached.body, `${run.label}: path and query did not arrive byte for byte`).toBe(`${listener.marker}\n${CALLBACK_REQUEST_PATH}`);
    return Object.freeze({ forwarder, listener });
  }

  async function endAndAssertCallbackGone(run: CliLaunch, forwarder: CallbackForwarder): Promise<void> {
    await run.end();
    // Checked the moment the owner exits: the forwarder's removal is part of
    // the session's own teardown, not something a later sweep may finish.
    assertGone(forwarder.id, `${run.label} after its session ended`);
    expect(callbackForwardersForSession(projectId, run.session.sessionId), `${run.label}: a forwarder still names the ended session`).toEqual([]);
  }

  // -------------------------------------------------------------------------
  // runfree forward
  // -------------------------------------------------------------------------

  coreTest("runfree forward publishes 127.0.0.1 only, reaches the agent listener, is hardened, and forward stop removes it", async () => {
    const run = await launch(["claude"], "forward session");
    const port = await freeLoopbackPort();
    const listener = await startSessionListener(run.session.containerId, "0.0.0.0", port, "forward");

    const opened = fixture.runfree(["forward", port]);
    expect(opened.status, `runfree forward failed: ${describeOutput(opened.output, 4000)}`).toBe(0);
    const name = `runfree-ingress-port-${projectId}-${port}`;
    const inspect = inspectOrThrow(name, "port forward");
    expect(inspect.State?.Running, "the port forward is not running").toBe(true);
    expect(inspect.Config?.Labels?.[CONTAINER_ROLE_LABEL]).toBe("ingress-forwarder");
    expect(inspect.Config?.Labels?.[INGRESS_PURPOSE_LABEL]).toBe("port");
    expect(containerEnv(inspect).INGRESS_TARGET, "the forward does not target the live session").toBe(run.session.ip);
    assertLoopbackOnly(inspect, port, "port forward");
    assertHardenedForwarder(inspect, "port forward");

    const reached = await awaitHostReach(port, "/forward-probe", listener, "port forward");
    expect(reached.body).toBe(`${listener.marker}\n/forward-probe`);

    const stopped = fixture.runfree(["forward", port, "stop"]);
    expect(stopped.status, `runfree forward stop failed: ${describeOutput(stopped.output, 4000)}`).toBe(0);
    assertGone(inspect.Id, "port forward after forward stop");
    await run.end();
  }, TEST_TIMEOUT_MS);

  coreTest("the forward is one-way: the session cannot connect to the forwarder's agent_internal listener", async () => {
    const run = await launch(["claude"], "one-way session");
    const port = await freeLoopbackPort();
    const listener = await startSessionListener(run.session.containerId, "0.0.0.0", port, "oneway");
    const opened = fixture.runfree(["forward", port]);
    expect(opened.status, `runfree forward failed: ${describeOutput(opened.output, 4000)}`).toBe(0);
    const forwarder = inspectOrThrow(`runfree-ingress-port-${projectId}-${port}`, "one-way forward");

    // Host → forwarder → listener works, so the forward is really live.
    await awaitHostReach(port, "/host-side", listener, "one-way forward");
    // The probe itself can connect from inside the session (positive control),
    // so the refusal below is the forwarder's, not a broken probe.
    const self = sessionTcpProbe(run.session.containerId, run.session.ip, port, "/self");
    expect(self.connected && self.data.includes(listener.marker), `the in-session probe cannot reach its own listener: ${JSON.stringify(self)}`).toBe(true);

    // Agent → forwarder: socat bound the host-facing interface before
    // agent_internal existed, so nothing listens on the internal address.
    const internalIp = forwarderInternalIp(forwarder.Id);
    const reverse = sessionTcpProbe(run.session.containerId, internalIp, port, "/agent-side");
    expect(reverse.connected, `the session connected to the forwarder at ${internalIp}:${port}: ${JSON.stringify(reverse)}`).toBe(false);
    expect(listenerLog(run.session.containerId, listener), "an agent-side connection reached the listener through the forwarder").not.toContain("/agent-side");

    const stopped = fixture.runfree(["forward", port, "stop"]);
    expect(stopped.status, `runfree forward stop failed: ${describeOutput(stopped.output, 4000)}`).toBe(0);
    assertGone(forwarder.Id, "one-way forward after forward stop");
    await run.end();
  }, TEST_TIMEOUT_MS);

  // -------------------------------------------------------------------------
  // Per-session MCP OAuth callback
  // -------------------------------------------------------------------------

  coreTest("a project with no OAuth-capable MCP server gets no mcp-callback forwarder", async () => {
    // Ordering guard: this is the only case that needs the unapproved project.
    expect(mcpEligible, "the negative case ran after the project was made MCP OAuth eligible").toBe(false);
    const run = await launch(["claude"], "ineligible session");
    // No settle window is needed below: an eligible launch's forwarder exists
    // before its agent's first instruction ("the port file and the forwarder
    // exist before the agent's first instruction" proves it), so an attached
    // ineligible session has already passed the point where one would exist.
    // What the agent itself saw at start agrees.
    const observed = await awaitStartObservation(inspectOrThrow(run.session.containerId, run.label), run.label);
    expect(observed.content, "an ineligible session's agent saw a callback port file at start").toBe("absent");
    expect(projectIngressForwarders(projectId, "mcp-callback"), "an ineligible launch minted a callback forwarder").toEqual([]);
    expect(sessionFile(run.session.containerId, CALLBACK_PORT_FILE), "an ineligible session has a callback port file").toBeUndefined();
    expect(sessionProcessArgv(run.session.containerId, CALLBACK_BRIDGE_MARKER), "an ineligible session runs a callback bridge").toEqual([]);
    await run.end();
    expect(projectIngressForwarders(projectId, "mcp-callback")).toEqual([]);
  }, TEST_TIMEOUT_MS);

  // The single-session two-hop is not a case of its own: each session below
  // runs the whole `assertCallbackTwoHop` contract and `endAndAssertCallbackGone`.
  coreTest("concurrent sessions get distinct callback ports, cannot reach each other's callback, and end independently", async () => {
    ensureMcpOAuthEligible();
    const first = await launch(["claude"], "first session");
    const a = await assertCallbackTwoHop(first);
    const second = await launch(["claude"], "second session");
    const b = await assertCallbackTwoHop(second);

    expect(b.forwarder.port, "two live sessions share one callback port").not.toBe(a.forwarder.port);
    expect(b.forwarder.id).not.toBe(a.forwarder.id);
    expect(second.session.ip).not.toBe(first.session.ip);

    // Peer → A's bridge: the bridge accepts only its forwarder, so the peer's
    // request must never arrive at A's loopback listener.
    const peerPath = `/peer-${Math.random().toString(36).slice(2, 10)}`;
    const toBridge = sessionTcpProbe(second.session.containerId, first.session.ip, a.forwarder.port, peerPath);
    expect(toBridge.data, `the peer got A's callback listener's answer: ${JSON.stringify(toBridge)}`).not.toContain(a.listener.marker);
    expect(listenerLog(first.session.containerId, a.listener), "a peer session's request reached A's callback listener").not.toContain(peerPath);
    // Peer → A's forwarder on agent_internal: the one-way bind refuses it.
    const toForwarder = sessionTcpProbe(second.session.containerId, forwarderInternalIp(a.forwarder.id), a.forwarder.port, peerPath);
    expect(toForwarder.connected, `the peer connected to A's forwarder: ${JSON.stringify(toForwarder)}`).toBe(false);

    await endAndAssertCallbackGone(second, b.forwarder);
    const survivor = inspectOrThrow(a.forwarder.id, "A's forwarder after B ended");
    expect(survivor.State?.Running, "ending B stopped A's forwarder").toBe(true);
    assertLoopbackOnly(survivor, a.forwarder.port, "A's forwarder after B ended");
    await awaitHostReach(a.forwarder.port, "/callback/after-peer-ended", a.listener, "A after B ended");

    await endAndAssertCallbackGone(first, a.forwarder);
  }, TEST_TIMEOUT_MS);

  coreTest("the port file and the forwarder exist before the agent's first instruction", async () => {
    ensureMcpOAuthEligible();
    // The record is container-local, so no earlier session's record can
    // stand in for this launch's: the container is new.
    const run = await launch(["claude"], "first-instruction session");
    const session = inspectOrThrow(run.session.containerId, run.label);
    // Read once, at attach, never polled: a forwarder that only appeared later
    // would be a setup that finished after the handoff.
    const forwarders = callbackForwardersForSession(projectId, run.session.sessionId);
    expect(forwarders, `${run.label}: callback forwarders naming the session at attach`).toHaveLength(1);
    const [forwarder] = forwarders;

    const observed = await awaitStartObservation(session, run.label);
    expect(observed.content, `${run.label}: what the agent's first instruction found at ${CALLBACK_PORT_FILE}`).toBe(forwarder.port);
    const startedAt = inspectOrThrow(forwarder.id, run.label).State?.StartedAt ?? "";
    expect(
      dockerTimestampNs(startedAt) <= observed.mtimeNs,
      `${run.label}: the forwarder started at ${startedAt}, after the agent's record (mtime ${observed.mtimeNs} ns)`,
    ).toBe(true);

    // The same forwarder carries the whole two-hop path, and leaves with the session.
    const hop = await assertCallbackTwoHop(run);
    expect(hop.forwarder.id, `${run.label}: the two-hop forwarder is not the one present at attach`).toBe(forwarder.id);
    await endAndAssertCallbackGone(run, hop.forwarder);
  }, TEST_TIMEOUT_MS);

  coreTest("two launches started at the same moment get distinct callback ports", async () => {
    ensureMcpOAuthEligible();
    // Precondition: neither launch can find a port already taken by residue.
    expect(projectIngressForwarders(projectId, "mcp-callback"), "a callback forwarder exists before the launches").toEqual([]);
    // Both spawned in the same tick, neither awaited before the other starts.
    // Each finds its own session by its lifecycle record's host pid.
    const settled = await Promise.allSettled([
      launch(["claude"], "simultaneous launch A", undefined, { byOwnerPid: true }),
      launch(["claude"], "simultaneous launch B", undefined, { byOwnerPid: true }),
    ]);
    const rejected = settled.find((result): result is PromiseRejectedResult => result.status === "rejected");
    if (rejected) throw rejected.reason;
    const [first, second] = settled.map((result) => (result as PromiseFulfilledResult<CliLaunch>).value);
    expect(second.session.containerId, "both launches resolved to one session").not.toBe(first.session.containerId);

    const a = await assertCallbackTwoHop(first);
    const b = await assertCallbackTwoHop(second);
    expect(b.forwarder.port, "two simultaneous launches share one callback port").not.toBe(a.forwarder.port);
    expect(b.forwarder.id).not.toBe(a.forwarder.id);
    expect(allCallbackForwarders(projectId).map((forwarder) => forwarder.id).sort(), "callback forwarders beyond the two launches'")
      .toEqual([a.forwarder.id, b.forwarder.id].sort());

    await endAndAssertCallbackGone(first, a.forwarder);
    await endAndAssertCallbackGone(second, b.forwarder);
  }, TEST_TIMEOUT_MS);

  coreTest("runfree shell gets its own two-hop callback with the same lifecycle", async () => {
    ensureMcpOAuthEligible();
    const run = await launch(["shell"], "shell session");
    const { forwarder } = await assertCallbackTwoHop(run);
    await endAndAssertCallbackGone(run, forwarder);
  }, TEST_TIMEOUT_MS);

  coreTest("runfree mcp auth rides the same per-session callback lifecycle", async () => {
    ensureMcpOAuthEligible();
    const run = await launch(["mcp", "auth", "claude", MCP_FIXTURE_SERVER], "mcp auth session");
    const { forwarder } = await assertCallbackTwoHop(run);
    await endAndAssertCallbackGone(run, forwarder);
  }, TEST_TIMEOUT_MS);

  // -------------------------------------------------------------------------
  // VNC (extended)
  // -------------------------------------------------------------------------

  extendedTest("runfree vnc bootstraps the server, publishes loopback only with ingress labels, keeps clipboard off, and vnc stop removes it", async (context) => {
    const run = await launch(["claude"], "vnc session");
    const { containerId } = run.session;
    // Probe the image, install nothing: the stock agent image ships no
    // x11vnc, and a project that wants VNC adds it to .runfree/image.
    const hasX11vnc = docker(["exec", containerId, "sh", "-c", "command -v x11vnc"]).status === 0;
    if (!hasX11vnc) {
      await run.end();
      context.skip("the agent image has no x11vnc (docs/cli.md: the image must provide x11vnc and an X display); nothing is installed here");
    }
    let hasDisplay = docker(["exec", containerId, "test", "-S", "/tmp/.X11-unix/X0"]).status === 0;
    if (!hasDisplay && docker(["exec", containerId, "sh", "-c", "command -v Xvfb"]).status === 0) {
      dockerOrThrow("start Xvfb", ["exec", "-d", containerId, "Xvfb", ":0", "-nolisten", "tcp"]);
      for (let attempt = 0; attempt < 40 && !hasDisplay; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 250));
        hasDisplay = docker(["exec", containerId, "test", "-S", "/tmp/.X11-unix/X0"]).status === 0;
      }
    }
    if (!hasDisplay) {
      await run.end();
      context.skip("the agent image has x11vnc but no X display on :0 and no Xvfb to start one; nothing is installed here");
    }

    const port = await freeLoopbackPort();
    const started = fixture.runfree(["vnc", "--host-port", port]);
    expect(started.status, `runfree vnc failed: ${describeOutput(started.output, 4000)}`).toBe(0);
    expect(started.output).toContain(`ready: vnc://127.0.0.1:${port}`);

    const name = `runfree-ingress-vnc-${projectId}-${port}`;
    const inspect = inspectOrThrow(name, "vnc forward");
    expect(inspect.Config?.Labels?.[CONTAINER_ROLE_LABEL], "vnc sidecar role label").toBe("ingress-forwarder");
    expect(inspect.Config?.Labels?.[INGRESS_PURPOSE_LABEL], "vnc sidecar purpose label").toBe("vnc");
    expect(containerEnv(inspect).INGRESS_TARGET).toBe(run.session.ip);
    assertLoopbackOnly(inspect, port, "vnc forward");
    assertHardenedForwarder(inspect, "vnc forward");

    // Server bootstrap end to end: the RFB greeting crosses the forward.
    expect(await hostTcpBanner(port, 12), "no RFB greeting through the vnc forward").toMatch(/^RFB \d{3}\.\d{3}\n$/u);
    // Clipboard off by default: x11vnc runs with -nosel (runtime/vnc.ts).
    const servers = sessionProcessArgv(containerId, "x11vnc").filter((argv) => argv[0]?.endsWith("x11vnc"));
    expect(servers, "no x11vnc process in the session").toHaveLength(1);
    expect(servers[0], "x11vnc runs with clipboard exchange enabled").toContain("-nosel");

    const stopped = fixture.runfree(["vnc", "stop", "--host-port", port]);
    expect(stopped.status, `runfree vnc stop failed: ${describeOutput(stopped.output, 4000)}`).toBe(0);
    assertGone(inspect.Id, "vnc forward after vnc stop");
    await run.end();
  }, TEST_TIMEOUT_MS);

  // -------------------------------------------------------------------------
  // Recovery (extended)
  // -------------------------------------------------------------------------

  extendedTest("an eligible session's dead owner leaves a forwarder that the next launch reconciles away, never aimed at the new session", async () => {
    ensureMcpOAuthEligible();
    const dead = await launch(["claude"], "owner-death session");
    const { forwarder: deadForwarder } = await assertCallbackTwoHop(dead);
    await dead.killOwner();
    // The owner is gone without teardown; its forwarder is residue now.
    expect(inspectContainer(deadForwarder.id), "the forwarder vanished with its owner, so nothing is left to reconcile").toBeDefined();

    const next = await launch(["claude"], "launch after owner death");
    /** No forwarder minted for the dead session may target the new session's address. Contract: 2026-09-30. */
    const assertNeverAimedAtNext = (): void => {
      for (const candidate of allCallbackForwarders(projectId)) {
        if (candidate.env.INGRESS_TARGET !== next.session.ip) continue;
        expect(candidate.env.RUNFREE_CALLBACK_SESSION_ID, `forwarder ${candidate.name} targets the new session's ${next.session.ip} with another identity`)
          .toBe(next.session.sessionId);
      }
    };
    await pollUntil(
      () => {
        assertNeverAimedAtNext();
        return inspectContainer(deadForwarder.id) === undefined;
      },
      RECONCILE_TIMEOUT_MS,
      "the dead owner's callback forwarder to be reconciled away",
      { label: next.label, completion: next.completion, output: next.output },
    );
    expect(callbackForwardersForSession(projectId, dead.session.sessionId), "a forwarder still names the dead session").toEqual([]);
    const { forwarder } = await assertCallbackTwoHop(next);
    assertNeverAimedAtNext();
    await endAndAssertCallbackGone(next, forwarder);
  }, TEST_TIMEOUT_MS);

  extendedTest("a dead owner whose session container has also stopped does not wedge the next launch", async () => {
    // The warm-launch topology validation meets the dead route before
    // admission does: its forwarder now targets a stopped container. Startup
    // must reclaim it under the lock and launch, not refuse every later launch.
    ensureMcpOAuthEligible();
    const dead = await launch(["claude"], "stopped-owner session");
    const { forwarder: deadForwarder } = await assertCallbackTwoHop(dead);
    await dead.killOwner();
    const stopped = docker(["container", "stop", "--time", "1", dead.session.containerId]);
    expect(stopped.status, `docker stop of the dead session failed: ${stopped.stderr}`).toBe(0);
    expect(inspectContainer(deadForwarder.id), "the forwarder vanished before the next launch").toBeDefined();

    const next = await launch(["claude"], "launch after a stopped dead session");
    expect(inspectContainer(deadForwarder.id), "the dead route survived the next launch").toBeUndefined();
    const { forwarder } = await assertCallbackTwoHop(next);
    await endAndAssertCallbackGone(next, forwarder);
  }, TEST_TIMEOUT_MS);

  /**
   * The events every callback-setup kill point is chosen from: container
   * create and start, and network connect. Docker ANDs different filter keys,
   * so a label filter would drop every network event; the project and role
   * are matched on the event's own attributes instead.
   */
  const CALLBACK_SETUP_EVENT_FILTERS = ["type=container", "type=network", "event=create", "event=start", "event=connect"] as const;

  function eventAttributes(event: DockerEvent): Readonly<Record<string, string>> {
    return event.Actor?.Attributes ?? {};
  }

  /** A container event for this project's mcp-callback forwarder (container events carry the labels). */
  function isCallbackForwarderEvent(event: DockerEvent): boolean {
    const attributes = eventAttributes(event);
    return event.Type === "container"
      && attributes[PROJECT_ID_LABEL] === projectId
      && attributes[CONTAINER_ROLE_LABEL] === "ingress-forwarder"
      && attributes[INGRESS_PURPOSE_LABEL] === "mcp-callback";
  }

  /** A container event for one of this project's session agents. */
  function isSessionAgentEvent(event: DockerEvent): boolean {
    const attributes = eventAttributes(event);
    return event.Type === "container"
      && attributes[SESSION_CONTAINER_LABELS.composeProject] === project
      && attributes[SESSION_CONTAINER_LABELS.role] === "session-agent";
  }

  function escapeRegExp(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  }

  /**
   * The callback refusal carrying only an inner detail a removed forwarder
   * yields at `point` (`session-mcp-callback.ts`, `ingress-forwarder.ts`).
   *
   * Forwarder start: readiness sees the container gone (`did not begin
   * listening`); or readiness won and the agent_internal connect meets the
   * removal (`No such container`, or Docker's `is marked for removal` while
   * the forced removal is in flight); or the connect won too and the address
   * read finds no forwarder (`has no exact … address`).
   *
   * agent_internal connect: the connect has returned, so the address read
   * finds no forwarder; or the read won and the host probe through the
   * removed forwarder fails (`did not reach the session`). The bridge start
   * is not forwarder-dependent, so its failure is not accepted.
   */
  function removalCausedFailure(point: "forwarder start" | "agent_internal connect", forwarderName: string): RegExp {
    expect(forwarderName, "the removed forwarder's start event carried no name").toMatch(new RegExp(`^runfree-ingress-mcp-callback-${escapeRegExp(projectId)}-\\d+$`, "u"));
    const name = escapeRegExp(forwarderName);
    const noAddress = `MCP OAuth callback forwarder ${name} has no exact \\S+ address`;
    const details = point === "forwarder start"
      ? [
        `ingress forwarder ${name} did not begin listening on 127\\.0\\.0\\.1:\\d+`,
        "(?:Error response from daemon: )?No such container",
        "(?:Error response from daemon: )?[Cc]ontainer \\S+ is marked for removal",
        noAddress,
      ]
      : [noAddress, "http://127\\.0\\.0\\.1:\\d+ did not reach the session"];
    return new RegExp(`the MCP OAuth callback for this session could not be set up: (?:${details.join("|")})`, "u");
  }

  /** No callback forwarder, session container, or lifecycle record: the state a residue claim is measured from. */
  function assertNoSessionResidue(label: string): void {
    expect(projectIngressForwarders(projectId, "mcp-callback"), `${label}: callback forwarders`).toEqual([]);
    expect(allSessionContainers(project), `${label}: session containers`).toEqual([]);
    expect(sessionRegistryRecords(fixture, project), `${label}: lifecycle registry`).toEqual([]);
  }

  extendedTest("a forwarder killed at each setup step fails the launch with no residue, and the next launch reclaims", async () => {
    ensureMcpOAuthEligible();
    const internalId = internalNetworkId(project);
    // Reservation: the forwarder's `docker run -p` has just started it.
    // Completion: it has just joined agent_internal; the bridge and the host
    // probe have not run yet.
    //
    // The second iteration's empty-residue precondition directly follows the
    // first's `end()`. That holds without polling: the owner's teardown
    // (`teardownSessionRecord`, run inline by the admission driver before the
    // CLI returns) removes the session container and then the lifecycle
    // record, and a blocked step leaves the residue a failure should report.
    for (const point of ["forwarder start", "agent_internal connect"] as const) {
      const label = `forwarder removed at its ${point}`;
      // Precondition: everything asserted absent below is absent before the
      // launch, so only this launch could have left it.
      assertNoSessionResidue(`${label}, before the launch`);

      /** Forwarder id to its container name, from the start events. */
      const forwarders = new Map<string, string>();
      const sessionContainers = new Set<string>();
      let throttled: Readonly<{ id: string; status: number; output: string }> | undefined;
      let removed: Readonly<{ id: string; name: string; status: number; output: string }> | undefined;
      const remove = (id: string): void => {
        const result = docker(["rm", "-f", id]);
        removed = Object.freeze({ id, name: forwarders.get(id) ?? "", status: result.status, output: result.output });
      };
      const watcher = watchDockerEvents(daemonNow(), CALLBACK_SETUP_EVENT_FILTERS, (event) => {
        const id = event.Actor?.ID ?? "";
        if (isSessionAgentEvent(event)) {
          sessionContainers.add(id);
          // After connect the launch still has to start the in-session bridge
          // and probe through it before it can attach. A mild throttle on the
          // session, applied at create (as the lock-hold case does), makes
          // the bridge's `node` start take far longer than the `docker rm -f`
          // below, so the removal reliably lands first. Mild, so the
          // removal, not the bridge's own budget, is what fails the launch.
          if (point === "agent_internal connect" && event.Action === "create" && !throttled) {
            const result = docker(["update", "--cpus", String(CONNECT_POINT_SESSION_CPUS), id]);
            throttled = Object.freeze({ id, status: result.status, output: result.output });
          }
        }
        if (isCallbackForwarderEvent(event) && event.Action === "start") {
          forwarders.set(id, eventAttributes(event).name ?? "");
          if (point === "forwarder start" && !removed) remove(id);
          return;
        }
        const connected = eventAttributes(event).container ?? "";
        if (event.Type === "network" && event.Action === "connect" && id === internalId && forwarders.has(connected)) {
          if (point === "agent_internal connect" && !removed) remove(connected);
        }
      });
      let failed: Awaited<SpawnedCli["completion"]>;
      try {
        failed = await awaitExitUnlessAttached(fixture, project, spawnCli(fixture, ["claude"]), label);
      } finally {
        await watcher.stop();
      }

      expect(watcher.handlerError(), `${label}: the event watcher failed`).toBeUndefined();
      if (point === "agent_internal connect") {
        expect(throttled, `${label}: the session container was never throttled`).toBeDefined();
        expect(throttled?.status, `${label}: docker update --cpus failed: ${describeOutput(throttled?.output ?? "")}`).toBe(0);
      }
      expect(removed, `${label}: the kill point never came: ${describeOutput(failed.output, 4000)}`).toBeDefined();
      const killed = removed as NonNullable<typeof removed>;
      expect(killed.status, `${label}: docker rm -f ${killed.id} failed: ${describeOutput(killed.output)}`).toBe(0);
      expect(failed.status, `${label}: the launch succeeded without its forwarder: ${describeOutput(failed.output, 4000)}`).not.toBe(0);
      // The callback refusal wraps every setup failure alike, a spent budget
      // included, so the inner detail is what attributes this one to the
      // removal. Each point accepts only the details a removed forwarder can
      // produce there, and none that a spent budget produces.
      expect(failed.output, `${label}: the callback setup ran out of budget instead`).not.toMatch(/used its whole|budget ended/u);
      expect(
        removalCausedFailure(point, killed.name).test(failed.output),
        `${label}: the launch did not fail on the removed forwarder: ${describeOutput(failed.output, 4000)}`,
      ).toBe(true);
      // The launch reached its session container, so "no session container
      // remains" is a claim about one that existed.
      expect(sessionContainers.size, `${label}: the launch never created a session container`).toBeGreaterThan(0);
      for (const id of sessionContainers) assertGone(id, `${label}: the failed launch's session container`);
      assertNoSessionResidue(`${label}, after the failed launch`);

      const next = await launch(["claude"], `launch after a ${label}`);
      const { forwarder } = await assertCallbackTwoHop(next);
      expect(forwarder.id, `${label}: the removed forwarder came back`).not.toBe(killed.id);
      await endAndAssertCallbackGone(next, forwarder);
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("a launcher killed during callback setup leaves residue the next launch reclaims", async () => {
    ensureMcpOAuthEligible();
    assertNoSessionResidue("before the launch");
    let deadForwarderId: string | undefined;
    const deadSessionContainers = new Set<string>();
    const dead = spawnCli(fixture, ["claude"]);
    try {
      const watcher = watchDockerEvents(daemonNow(), CALLBACK_SETUP_EVENT_FILTERS, (event) => {
        // Created before the reservation starts, so seen before the kill.
        if (isSessionAgentEvent(event) && event.Action === "create") deadSessionContainers.add(event.Actor?.ID ?? "");
        if (deadForwarderId || !isCallbackForwarderEvent(event) || event.Action !== "start") return;
        deadForwarderId = event.Actor?.ID ?? "";
        // At once, from the handler: the launch must die mid-setup.
        dead.child.kill("SIGKILL");
      });
      try {
        await pollUntil(
          () => deadForwarderId !== undefined,
          CALLBACK_FORWARDER_TIMEOUT_MS,
          "the launch's callback forwarder to start",
          { label: "killed launcher", completion: dead.completion, output: dead.output },
        );
      } finally {
        await watcher.stop();
      }
      expect(watcher.handlerError(), "the event watcher failed").toBeUndefined();
      await dead.killOwner();
      const residue = deadForwarderId as string;
      expect(residue, "the forwarder start event carried no container id").toMatch(/^[a-f0-9]{64}$/u);
      // Precondition: the residue exists, so its removal below is the next
      // launch's reclamation, not the dead launch's own cleanup.
      expect(inspectContainer(residue), "the killed launcher's forwarder was already gone").toBeDefined();
      expect(deadSessionContainers.size, "the killed launcher never created its session container").toBe(1);
      const deadRecords = (): readonly string[] => peekSessionRegistryRecords(fixture, project)
        .filter((record) => record.hostPid === dead.pid).map((record) => record.sessionId);
      expect(deadRecords(), "the killed launcher left no lifecycle record").toHaveLength(1);

      // The dead launch's session container may still be starting, so the
      // next session is found by its own lifecycle record.
      const next = await launch(["claude"], "launch after a killed launcher", undefined, { byOwnerPid: true });
      const { forwarder } = await assertCallbackTwoHop(next);
      expect(forwarder.id, "the next launch adopted the dead launcher's forwarder").not.toBe(residue);
      await pollUntil(
        () => inspectContainer(residue) === undefined,
        RECONCILE_TIMEOUT_MS,
        "the killed launcher's callback forwarder to be reclaimed",
        { label: next.label, completion: next.completion, output: next.output },
      );
      // The rest of the dead launch's residue goes the same way: its session
      // container and its lifecycle record.
      await pollUntil(
        () => [...deadSessionContainers].every((id) => inspectContainer(id) === undefined) && deadRecords().length === 0,
        RECONCILE_TIMEOUT_MS,
        "the killed launcher's session container and lifecycle record to be reclaimed",
        { label: next.label, completion: next.completion, output: next.output },
      );
      expect(allCallbackForwarders(projectId).map((candidate) => candidate.id), "a stale callback forwarder remains")
        .toEqual([forwarder.id]);
      await endAndAssertCallbackGone(next, forwarder);
    } finally {
      // Cleanup only: the Docker children the kill left behind.
      dead.killGroup();
      await dead.completion.catch(() => undefined);
    }
  }, TEST_TIMEOUT_MS);

  extendedTest("a compatible proxy replacement keeps the callback forwarder and a port forward in place and reaching", async () => {
    ensureMcpOAuthEligible();
    const run = await launch(["claude"], "rebind session", REBIND_SESSION_ENV);
    const { forwarder: callback, listener: callbackListener } = await assertCallbackTwoHop(run);
    const port = await freeLoopbackPort();
    const forwardListener = await startSessionListener(run.session.containerId, "0.0.0.0", port, "rebind-forward");
    const opened = fixture.runfree(["forward", port]);
    expect(opened.status, `runfree forward failed: ${describeOutput(opened.output, 4000)}`).toBe(0);
    const portForward = inspectOrThrow(`runfree-ingress-port-${projectId}-${port}`, "rebind port forward");
    await awaitHostReach(port, "/before-rebind", forwardListener, "port forward before the replacement");

    // The same lever session-independence uses: a stopped proxy with the
    // control plane untouched is `restart-compatible-proxy`, and `up` must
    // replace it without touching the session.
    const before = composeServiceContainerId(project, "proxy");
    dockerOrThrow("stop the proxy", ["stop", "--time", "2", before]);
    const rebound = fixture.runfree(["up"]);
    expect(rebound.status, `the compatible replacement failed: ${describeOutput(rebound.output, 4000)}`).toBe(0);
    const after = composeServiceContainerId(project, "proxy");
    expect(after, "the proxy was not replaced").not.toBe(before);
    await pollUntil(
      () => servedSourceIps(after).includes(run.session.ip),
      RESTORATION_TIMEOUT_MS,
      "the preserved session to be served by the new proxy",
      { label: run.label, completion: run.completion, output: run.output },
    );

    for (const [id, forwardedPort, label] of [
      [callback.id, callback.port, "callback forwarder after the replacement"],
      [portForward.Id, port, "port forward after the replacement"],
    ] as const) {
      const inspect = inspectOrThrow(id, label);
      expect(inspect.State?.Running, `${label} is not running`).toBe(true);
      assertLoopbackOnly(inspect, forwardedPort, label);
    }
    expect(containerEnv(inspectOrThrow(callback.id, "callback")).INGRESS_TARGET).toBe(run.session.ip);
    const callbackReach = await awaitHostReach(callback.port, CALLBACK_REQUEST_PATH, callbackListener, "callback after the replacement");
    expect(callbackReach.body).toBe(`${callbackListener.marker}\n${CALLBACK_REQUEST_PATH}`);
    await awaitHostReach(port, "/after-rebind", forwardListener, "port forward after the replacement");

    const stopped = fixture.runfree(["forward", port, "stop"]);
    expect(stopped.status, `runfree forward stop failed: ${describeOutput(stopped.output, 4000)}`).toBe(0);
    assertGone(portForward.Id, "port forward after forward stop");
    await endAndAssertCallbackGone(run, callback);
  }, TEST_TIMEOUT_MS);

  // -------------------------------------------------------------------------
  // Runtime teardown. Only the lock-hold case below runs after destroy, and it
  // brings the runtime back itself.
  // -------------------------------------------------------------------------

  /** Opens a port forward to a session, then ends the session, leaving the forward behind. */
  async function forwardThatOutlivesItsSession(label: string): Promise<string> {
    const run = await launch(["claude"], label);
    const port = await freeLoopbackPort();
    const opened = fixture.runfree(["forward", port]);
    expect(opened.status, `runfree forward failed: ${describeOutput(opened.output, 4000)}`).toBe(0);
    const forwarder = inspectOrThrow(`runfree-ingress-port-${projectId}-${port}`, label);
    await run.end();
    // Precondition, not the claim: a port forward is the operator's hole and
    // outlives the session it was opened against until something closes it.
    expect(inspectContainer(forwarder.Id), `${label}: the forward was already gone before the runtime command`).toBeDefined();
    return forwarder.Id;
  }

  // The warm record binds `vnc`/`port` forwarders by id, address, endpoint,
  // purpose, and target, and binds no callback forwarder: those belong to a
  // session and are proved fresh with it. A forward is opened against the
  // peer, so the next launch (its fixed participants changed) validates fully
  // and records it; the launch after that is judged beside the peer.
  coreTest("a warm launch beside a peer with its callback forwarder and a recorded port forward to it takes the warm peer path", async () => {
    ensureMcpOAuthEligible();
    const peer = await launch(["claude"], "warm peer");
    await awaitCallbackForwarder(peer);
    const port = await freeLoopbackPort();
    const opened = fixture.runfree(["forward", port]);
    expect(opened.status, `runfree forward failed: ${describeOutput(opened.output, 4000)}`).toBe(0);
    try {
      const forward = inspectOrThrow(`runfree-ingress-port-${projectId}-${port}`, "peer forward");
      expect(containerEnv(forward).INGRESS_TARGET, "the forward does not target the peer").toBe(peer.session.ip);
      const recording = await launch(["claude"], "recording launch", { RUNFREE_TIMINGS: "1" });
      expect(timing(recording.output(), "validation:warm-proof"), describeOutput(recording.output(), 4000))
        .toContain("recorded");
      const judged = await launch(["claude"], "judged launch", { RUNFREE_TIMINGS: "1" });
      expect(timing(judged.output(), "validation:warm-peer"), describeOutput(judged.output(), 4000)).toContain("match");
      expect(milliseconds(judged.output(), "runtime-validation")).toBeUndefined();
      expect(timing(judged.output(), "startup:restore-sessions")).toContain("skipped warm-peer");
      await assertCallbackTwoHop(judged);

      // The forward outlives its target: beside the remaining peers it is
      // aimed at a session address no peer holds, so it is not accounted for
      // and the next launch validates fully.
      await peer.end();
      expect(inspectContainer(forward.Id), "the forward was gone before the stale-target launch").toBeDefined();
      const stale = await launch(["claude"], "stale-target launch", { RUNFREE_TIMINGS: "1" });
      expect(timing(stale.output(), "validation:warm-peer"), describeOutput(stale.output(), 4000))
        .toContain("miss:ingress-target-unaccounted");
      expect(milliseconds(stale.output(), "runtime-validation"), describeOutput(stale.output(), 4000)).toBeGreaterThan(0);
    } finally {
      fixture.runfree(["forward", port, "stop"]);
    }
  }, TEST_TIMEOUT_MS);

  coreTest("runfree stop removes an open port forward", async () => {
    const forwarderId = await forwardThatOutlivesItsSession("stop session");
    const stopped = fixture.runfree(["stop"]);
    expect(stopped.status, `runfree stop failed: ${describeOutput(stopped.output, 4000)}`).toBe(0);
    assertGone(forwarderId, "port forward after runfree stop");
    expect(projectIngressForwarders(projectId), "runfree stop left an ingress forwarder").toEqual([]);
    upWithExactApprovals(fixture);
  }, TEST_TIMEOUT_MS);

  coreTest("runfree destroy removes an open port forward and the ingress host network", async () => {
    const forwarderId = await forwardThatOutlivesItsSession("destroy session");
    runtimeDestroyed = true;
    const destroyed = fixture.runfree(["destroy"]);
    expect(destroyed.status, `runfree destroy failed: ${describeOutput(destroyed.output, 4000)}`).toBe(0);
    assertGone(forwarderId, "port forward after runfree destroy");
    expect(projectIngressForwarders(projectId), "runfree destroy left an ingress forwarder").toEqual([]);
    expect(projectIngressHostNetworks(projectId), "runfree destroy left the ingress host network").toEqual([]);
    expect(
      docker(["ps", "-a", "--filter", `label=${PROJECT_ID_LABEL}=${projectId}`, "--format", "{{.Names}}"]).stdout.trim(),
      "runfree destroy left project containers",
    ).toBe("");
  }, TEST_TIMEOUT_MS);

  // -------------------------------------------------------------------------
  // Lock-hold budget (extended). Runs after the destroy case: it brings the
  // runtime back, and ends by destroying it again.
  // -------------------------------------------------------------------------

  /** Brings the runtime back after a destroy, approving each exact subject startup names. */
  function upAfterDestroy(): void {
    for (let round = 0; round < 3; round += 1) {
      const up = fixture.runfree(["up"]);
      if (up.status === 0) return;
      if (up.output.includes("desired controls require exact approval before startup")) {
        upWithExactApprovals(fixture);
        return;
      }
      if (up.output.includes("exact pre-sandbox Docker build approval is required")) {
        const approved = fixture.runfree(["image", "approve-context"]);
        expect(approved.status, `image approve-context failed: ${describeOutput(approved.output, 4000)}`).toBe(0);
        continue;
      }
      throw new Error(`runfree up after destroy failed: ${describeOutput(up.output, 4000)}`);
    }
    throw new Error("runfree up after destroy did not converge in three rounds");
  }

  extendedTest("a handed-off launch with a slow callback bridge never makes a concurrent destroy give up on the lifecycle lock", async () => {
    // Todo: launch-lock-hold budget (cross-lane review finding 1). A warm launch
    // hands startup's lifecycle lock to admission, which then sets up the
    // session's MCP OAuth callback under the same hold. The session container
    // is throttled to a sliver of one CPU as soon as it runs, so the bridge's
    // `node` and the host probe are slow. A destroy started meanwhile waits
    // for the lock for up to 60 s; the launch's one continuous hold must end
    // inside that, whether the callback setup finishes or runs out its budget.
    upAfterDestroy();
    runtimeDestroyed = false;
    mcpEligible = false;
    ensureMcpOAuthEligible();
    // A first launch after `up` settles the warm-proof record the next one matches.
    const warm = await launch(["claude"], "warm-up session");
    await warm.end();

    // Every session-agent container, created or running: the throttle must
    // land before the callback setup, so it is applied as soon as `docker
    // create` has returned, not once the container runs.
    const sessionContainers = (): readonly string[] => allSessionContainers(project);
    const before = new Set(sessionContainers());
    const launched = spawnCli(fixture, ["claude"], { RUNFREE_TIMINGS: "1" });
    let launchExited = false;
    void launched.completion.then(() => { launchExited = true; }, () => { launchExited = true; });
    let sessionContainerId: string | undefined;
    const deadline = Date.now() + 120_000;
    // A launch that exits before creating its session fails here at once, not
    // after the whole deadline.
    while (!sessionContainerId && !launchExited && Date.now() < deadline) {
      sessionContainerId = sessionContainers().find((id) => !before.has(id));
      if (!sessionContainerId) await new Promise((resolve) => setTimeout(resolve, 25));
    }
    expect(sessionContainerId, `no session container appeared: ${describeOutput(launched.output(), 4000)}`).toBeDefined();
    const throttled = docker(["update", "--cpus", "0.01", sessionContainerId as string]);
    expect(throttled.status, `docker update --cpus failed: ${throttled.stderr}`).toBe(0);

    const destroyed = spawnCli(fixture, ["destroy", "--force"]);
    runtimeDestroyed = true;
    const destroy = await destroyed.completion;
    const launchResult = await Promise.race([
      launched.completion,
      new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), 60_000)),
    ]);
    if (!launchResult) launched.child.kill("SIGKILL");
    const launchOutput = launched.output();

    expect(launchOutput, "the measured launch did not take the held-lock handoff").toMatch(/timing: launch-handoff minted/u);
    expect(destroy.output, `destroy gave up waiting for the lifecycle lock: ${describeOutput(destroy.output, 4000)}`)
      .not.toContain("lifecycle change is in progress");
    expect(destroy.status, `destroy --force failed: ${describeOutput(destroy.output, 4000)}`).toBe(0);
    // The launch either attached, and reported the one continuous hold it
    // ended, or its callback setup ran out of budget and it failed. Either
    // way the hold stayed inside the budget plus the round-trip allowance.
    const hold = /timing: session-admission lifecycle-lock-hold-ms=(\d+)/u.exec(launchOutput);
    if (hold) {
      expect(Number(hold[1]), `the launch held the lifecycle lock too long: ${describeOutput(launchOutput, 4000)}`)
        .toBeLessThanOrEqual(LAUNCH_LOCK_HOLD_BUDGET_MS + 10_000);
    } else {
      expect(launchOutput, `the launch neither attached nor failed its callback setup: ${describeOutput(launchOutput, 4000)}`)
        .toContain("the MCP OAuth callback for this session could not be set up");
    }
    // Nothing the launch or its callback created survives the destroy.
    expect(sessionContainers(), "a session container survived destroy --force").toEqual([]);
    expect(projectIngressForwarders(projectId), "a callback forwarder survived destroy --force").toEqual([]);
  }, TEST_TIMEOUT_MS);
});
