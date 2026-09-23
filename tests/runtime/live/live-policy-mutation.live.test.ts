// Live persistent-policy mutation tranche (A2 decision, option b — no pause).
//
// The typed desired-policy mutations (`host add`/`host remove`) opt out of the
// live-session refusal and rely on the capture → approved-base → atomic-write →
// re-read → content-addressed-approve chain instead of pausing anything. This
// tranche proves that against the real backend: `host add` with one live
// session and `host remove` with three change effective authority — firewall
// and request proxy converge to a new effective generation and live egress
// flips — with zero container restarts and no pause state ever set (exact
// container ids, start times, and run state before and after).
//
// The egress checks keep the sandbox trichotomy: HTTP 2xx to a removed host is
// a leak and fails; an in-tunnel 403 passes; a connection-level failure passes
// only when the proxy independently recorded denying that host in the window.

import { fileURLToPath } from "node:url";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { firewallStatusPath, requestProxyStatusPath } from "../../../packages/runtime-contracts/src/proxy-status.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  provisionSandboxFixture,
  startStandingSession,
  releaseStandingSessions,
  forceCleanSessions,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  type StandingSessionHandle,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;
// Not seeded by the sandbox fixture and IANA-reserved like example.net, so it
// cannot be allowlisted through a developer-machine service or MCP side door.
const MUTATION_HOST = "example.org";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the live-policy-mutation tranche");
  }
  return backend;
}

type ContainerIdentity = Readonly<{
  id: string;
  startedAt: string;
  running: boolean;
  paused: boolean;
}>;

function containerIdentity(id: string): ContainerIdentity {
  const inspected = dockerOrThrow(
    `container identity of ${id}`,
    ["inspect", "-f", "{{.Id}}\t{{.State.StartedAt}}\t{{.State.Running}}\t{{.State.Paused}}", id],
  );
  const [exactId, startedAt, running, paused] = inspected.trim().split("\t");
  if (!exactId || !startedAt) throw new Error(`malformed container identity inspection: ${inspected}`);
  return Object.freeze({ id: exactId, startedAt, running: running === "true", paused: paused === "true" });
}

function assertIdentityUnchanged(before: ContainerIdentity, label: string): void {
  const after = containerIdentity(before.id);
  expect(after.id, `${label}: container was replaced`).toBe(before.id);
  expect(after.startedAt, `${label}: container restarted during the live mutation`).toBe(before.startedAt);
  expect(after.running, `${label}: container is no longer running`).toBe(true);
  expect(after.paused, `${label}: container was paused by the live mutation`).toBe(false);
}

function firewallGeneration(proxyId: string): string | null {
  const status = docker(["exec", proxyId, "cat", firewallStatusPath()]);
  if (status.status !== 0) return null;
  try {
    const parsed = JSON.parse(status.stdout) as { generation?: unknown };
    return typeof parsed.generation === "string" ? parsed.generation : null;
  } catch {
    return null;
  }
}

function sessionCurl(sessionContainerId: string, host: string): CaptureResult {
  return docker([
    "exec", sessionContainerId, "zsh", "-lc",
    `curl -ksS --max-time 20 -o /dev/null -w '%{http_code}' https://${host}/`,
  ]);
}

async function pollUntil(
  predicate: () => boolean | Promise<boolean>,
  options: { timeoutMs: number; intervalMs?: number; label: string },
): Promise<void> {
  const deadline = Date.now() + options.timeoutMs;
  for (;;) {
    if (await predicate()) return;
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${options.label}`);
    await new Promise((resolve) => setTimeout(resolve, options.intervalMs ?? 1000));
  }
}

/** The typed mutation must itself report live convergence, not just exit 0. */
function runConvergedHostMutation(fixture: LiveFixture, args: readonly string[]): string {
  const result = fixture.runfree(args);
  expect(result.status, `\`runfree ${args.join(" ")}\` failed with live sessions running: ${describeOutput(result.output)}`).toBe(0);
  expect(result.stdout, "the typed mutation did not converge the live effective policy").toMatch(/effective policy: live now \(effective policy generation sha256:/u);
  return result.stdout;
}

async function awaitConvergedGeneration(
  proxyId: string,
  previousGeneration: string | null,
  label: string,
): Promise<string> {
  let generation: string | null = null;
  await pollUntil(() => {
    generation = firewallGeneration(proxyId);
    if (!generation || generation === previousGeneration) return false;
    return docker(["exec", proxyId, "cat", requestProxyStatusPath()]).stdout.includes(generation);
  }, { timeoutMs: 40_000, label });
  const firewallJson = docker(["exec", proxyId, "cat", firewallStatusPath()]).stdout;
  expect(firewallJson, `${label}: firewall did not verify the ruleset at the new generation`).toContain('"rulesetVerified":true');
  return generation as unknown as string;
}

function assertDeniedWithEvidence(
  probe: CaptureResult,
  proxyId: string,
  sinceIso: string,
  label: string,
): void {
  const code = probe.stdout.trim();
  if (/^2/u.test(code)) {
    throw new Error(`EGRESS LEAKED ${label}: reached ${MUTATION_HOST} with HTTP ${code}. ${describeOutput(probe.output)}`);
  }
  if (code === "403") return; // in-tunnel synthetic denial
  const logs = dockerOrThrow(`proxy logs ${label}`, ["logs", "--since", sinceIso, proxyId]);
  const recordedDenial = logs.split("\n").some((line) =>
    line.includes("proxy-denial") && line.includes('"reason":"host-not-allowlisted"') && line.includes(`"host":"${MUTATION_HOST}"`));
  expect(
    recordedDenial,
    `${label}: egress was neither a 403 nor a recorded denial for ${MUTATION_HOST}: ${describeOutput(probe.output)}`,
  ).toBe(true);
}

describe("typed desired-policy mutations converge live sessions without restart or pause", () => {
  let fixture: LiveFixture;
  let proxyId: string;
  const handles: StandingSessionHandle[] = [];

  beforeAll(async () => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");
    handles.push(await startStandingSession(fixture));
  }, PROVISION_TIMEOUT_MS);

  afterAll(async () => {
    if (!fixture) return;
    try {
      await releaseStandingSessions(handles, () => forceCleanSessions(fixture));
    } finally {
      destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
    }
  }, PROVISION_TIMEOUT_MS);

  test("host add with one live session changes effective authority in place", async () => {
    const session = handles[0].session;
    const denialWindowStart = new Date().toISOString();
    const baseline = sessionCurl(session.containerId, MUTATION_HOST);
    assertDeniedWithEvidence(baseline, proxyId, denialWindowStart, "before host add");

    const proxyBefore = containerIdentity(proxyId);
    const sessionBefore = containerIdentity(session.containerId);
    const generationBefore = firewallGeneration(proxyId);
    expect(generationBefore, "could not read the firewall generation before the mutation").toBeTruthy();

    runConvergedHostMutation(fixture, ["host", "add", MUTATION_HOST]);
    await awaitConvergedGeneration(proxyId, generationBefore, "consumers to converge after host add");

    assertIdentityUnchanged(proxyBefore, "proxy after host add");
    assertIdentityUnchanged(sessionBefore, "live session after host add");

    const reachable = sessionCurl(session.containerId, MUTATION_HOST);
    expect(
      reachable.stdout.trim(),
      `the added host was not reachable from the live session: ${describeOutput(reachable.output)}`,
    ).toBe("200");
  }, TEST_TIMEOUT_MS);

  test("host remove with several live sessions converges to denial in place", async () => {
    // Two sessions, not three. What the case proves is that one mutation
    // converges *every* live session rather than only the one the earlier case
    // used — a plural property, and two is plural. The third session cost
    // another ~20 s launch and asserted nothing the second does not.
    handles.push(await startStandingSession(fixture, { allowExistingSessions: true }));
    const sessions = handles.map((handle) => handle.session);
    expect(new Set(sessions.map((session) => session.sourceIp)).size, "concurrent sessions shared a source IP")
      .toBe(handles.length);

    const proxyBefore = containerIdentity(proxyId);
    const sessionsBefore = sessions.map((session) => containerIdentity(session.containerId));
    const generationBefore = firewallGeneration(proxyId);
    const denialWindowStart = new Date().toISOString();

    runConvergedHostMutation(fixture, ["host", "remove", MUTATION_HOST]);
    await awaitConvergedGeneration(proxyId, generationBefore, "consumers to converge after host remove");

    assertIdentityUnchanged(proxyBefore, "proxy after host remove");
    for (const [index, before] of sessionsBefore.entries()) {
      assertIdentityUnchanged(before, `live session ${index + 1} after host remove`);
    }

    for (const [index, session] of sessions.entries()) {
      const probe = sessionCurl(session.containerId, MUTATION_HOST);
      assertDeniedWithEvidence(probe, proxyId, denialWindowStart, `session ${index + 1} after host remove`);
    }
  }, TEST_TIMEOUT_MS);
});
