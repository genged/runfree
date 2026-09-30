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
//   core  Callback two-hop in an ordinary `runfree claude` session: exact
//         forwarder name/env/publication, the in-session port file and bridge,
//         a host GET reaching the session's loopback listener with path and
//         query intact, and the forwarder gone when the session ends.
//   core  Two concurrent sessions: two ports, two forwarders; a peer session
//         cannot reach the other's bridge or forwarder; ending one removes
//         only its own forwarder.
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
//   ext   Recovery (b): a compatible proxy replacement leaves a live callback
//         forwarder and a port forward in place, loopback-only and reaching.
//   core  `runfree stop` and `runfree destroy` each remove a port forward
//         (destroy is the file's last case and also takes the host network).
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
  awaitHostReach,
  callbackForwardersForSession,
  configureIngressProject,
  containerEnv,
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
  sessionTcpProbe,
  startCliSession,
  startSessionListener,
  upWithExactApprovals,
  type CallbackForwarder,
  type CliLaunch,
  type ContainerInspect,
  type SessionListener,
} from "./ingress-support.ts";
import { liveTierSelected } from "./tiers.ts";

// Mixed file (see `tiers.ts`): loopback publication, the one-way refusal, the
// callback two-hop and peer refusal, and teardown are trust-boundary proofs;
// VNC and the two recovery cases are extended.
const coreTest = liveTierSelected("core") ? test : test.skip;
const extendedTest = liveTierSelected("extended") ? test : test.skip;

/** How long the negative case watches a launch for a callback forwarder that must never appear. */
const NO_CALLBACK_SETTLE_MS = 10_000;
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
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT, configure: configureIngressProject });
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

  async function launch(args: readonly string[], label: string, extraEnv?: NodeJS.ProcessEnv): Promise<CliLaunch> {
    const started = await startCliSession(fixture, project, args, { label, extraEnv });
    launches.push(started);
    return started;
  }

  /**
   * Makes the project's runtime MCP OAuth policy carry a server, the way a
   * user does: approve the project's public HTTP MCP server, then start.
   */
  function ensureMcpOAuthEligible(): void {
    if (mcpEligible) return;
    const approved = fixture.runfree(["mcp", "approve", "claude", MCP_FIXTURE_SERVER]);
    expect(approved.status, `mcp approve failed: ${describeOutput(approved.output, 4000)}`).toBe(0);
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
    const deadline = Date.now() + NO_CALLBACK_SETTLE_MS;
    while (Date.now() < deadline) {
      expect(projectIngressForwarders(projectId, "mcp-callback"), "an ineligible launch minted a callback forwarder").toEqual([]);
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    expect(sessionFile(run.session.containerId, CALLBACK_PORT_FILE), "an ineligible session has a callback port file").toBeUndefined();
    expect(sessionProcessArgv(run.session.containerId, CALLBACK_BRIDGE_MARKER), "an ineligible session runs a callback bridge").toEqual([]);
    await run.end();
    expect(projectIngressForwarders(projectId, "mcp-callback")).toEqual([]);
  }, TEST_TIMEOUT_MS);

  coreTest("an ordinary runfree claude session gets its own two-hop callback, removed when the session ends", async () => {
    ensureMcpOAuthEligible();
    const run = await launch(["claude"], "claude session");
    const { forwarder } = await assertCallbackTwoHop(run);
    await endAndAssertCallbackGone(run, forwarder);
  }, TEST_TIMEOUT_MS);

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
  // Runtime teardown. Destroy is last: nothing after it has a runtime.
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
});
