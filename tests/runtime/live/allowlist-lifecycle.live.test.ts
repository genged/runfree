// Empty-allowlist lifecycle tranche, ported from `tests/runtime/sandbox.sh`.
//
// The regression this is named after: `runfree host remove` on the last host
// produced a valid policy that bricked proxy startup ("no safe IPv4 addresses
// resolved for allowlisted hosts"), so a legitimate CLI operation could leave
// the runtime unbootable. This proves the real backend end to end: an
// agent-authored empty edit is inert until approved, the approved empty policy
// converges to a fully enforced deny-all with no restart, a proxy restart with
// an empty allowlist reaches readiness with no egress leak, and restoring the
// policy repopulates the allowlist.
//
// Choreography: `policy approve`/`use-approved` quiesce (they take the project
// lifecycle lock), so they run while no session is up; the behavioral egress
// checks run inside a held session. State flows between suites through the
// on-disk desired policy and the module-level `emptyGeneration`.
//
// The egress-leak check keeps the sandbox's trichotomy: an HTTP 2xx is a leak
// and fails; an in-tunnel 403 passes; a connection-level failure passes only
// when the proxy independently recorded denying this host after the restart.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { firewallStatusPath, requestProxyStatusPath } from "../../../packages/runtime-contracts/src/proxy-status.ts";
import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  ownedNftSetIps,
  provisionSandboxFixture,
  startStandingSession,
  unexplainedAdmittedIps,
  type StandingSessionHandle,
} from "./fixture.ts";
import { answeredByUpstream, curlProbeCommand, parseProbeAnswer } from "./proxy-answer.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;
// A project-only host (see the fixture seed): it must be denied once the project
// policy is emptied, which a user-scope MCP/service host would not be.
const REFERENCE_HOST = "example.net";
const REFERENCE_PATH = "/";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the allowlist-lifecycle tranche");
  }
  return backend;
}

function sessionExec(id: string, script: string): CaptureResult {
  return docker(["exec", id, "zsh", "-lc", script]);
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

function proxyStartedAt(proxyId: string): string {
  return dockerOrThrow("proxy start time", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]);
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

/** The enforce resolved-hosts snapshot, or a sentinel if the proxy has none. */
function resolvedHostsSnapshot(proxyId: string): string {
  const read = docker(["exec", "--user", "0:0", proxyId, "sh", "-c",
    'cat /run/runfree-resolved-hosts.json 2>/dev/null || echo "<snapshot-absent>"']);
  if (read.status !== 0 || read.stdout.trim() === "") {
    throw new Error(`could not read the resolved-hosts snapshot: ${describeOutput(read.output)}`);
  }
  return read.stdout;
}

/** Rename-based desired-policy write, matching safeReplaceProjectFile. */
function writeProjectPolicy(fixture: LiveFixture, contents: string): void {
  const file = path.join(fixture.projectRoot, ".runfree", "network-policy.json");
  const staged = `${file}.livetest-tmp`;
  fs.writeFileSync(staged, `${contents}\n`, { mode: 0o600 });
  fs.renameSync(staged, file);
}

/** Approves and selects the current desired project policy (quiesces; no session). */
function approveDesiredProjectPolicy(fixture: LiveFixture): void {
  const diff = fixture.runfree(["policy", "diff", "--project", "--json"]);
  if (diff.status !== 0) throw new Error(`policy diff failed: ${describeOutput(diff.output)}`);
  const entries = JSON.parse(diff.stdout) as { scope?: string; desiredDigest?: string }[];
  const digest = entries.find((entry) => entry.scope === "project")?.desiredDigest;
  if (typeof digest !== "string") throw new Error(`could not resolve the desired project policy digest: ${describeOutput(diff.output)}`);
  const approve = fixture.runfree(["policy", "approve", "--project", "--subject-digest", digest]);
  if (approve.status !== 0) throw new Error(`policy approve failed: ${describeOutput(approve.output)}`);
  const use = fixture.runfree(["policy", "use-approved"]);
  if (use.status !== 0) throw new Error(`policy use-approved failed: ${describeOutput(use.output)}`);
}

function assertAllowlistFullyExplained(proxyId: string, label: string): void {
  const admitted = ownedNftSetIps(proxyId, "allowed_ipv4");
  const snapshot = resolvedHostsSnapshot(proxyId);
  const unexplained = unexplainedAdmittedIps(admitted, snapshot);
  expect(unexplained, `${label}: allowed_ipv4 admits IPs no resolved host explains: ${unexplained.join(", ")}`).toEqual([]);
}

describe("empty allowlist is a fully enforced deny-all, not a startup failure", () => {
  let fixture: LiveFixture;
  let proxyId: string;
  let policyBackup: string;
  let preEmptyGeneration: string | null = null;
  let emptyGeneration: string | null = null;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");
    policyBackup = fs.readFileSync(path.join(fixture.projectRoot, ".runfree", "network-policy.json"), "utf8");
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  describe("an agent-authored empty edit is inert before exact approval", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("emptying the desired policy does not change live enforcement until approved", () => {
      // Reachability is end to end (the upstream itself answered), so it
      // proves the live firewall set as well as the proxy policy.
      const baseline = sessionExec(sessionId,
        curlProbeCommand(`https://${REFERENCE_HOST}${REFERENCE_PATH}`, { maxTimeSeconds: 15, retries: 3 }));
      expect(
        answeredByUpstream(parseProbeAnswer(baseline.stdout)),
        `baseline: ${REFERENCE_HOST} was not reachable before emptying: ${describeOutput(baseline.output)}`,
      ).toBe(true);

      preEmptyGeneration = firewallGeneration(proxyId);
      expect(preEmptyGeneration, "could not read the firewall generation before emptying").toBeTruthy();

      writeProjectPolicy(fixture, '{"version":2,"hosts":[]}');
      // The desired edit is inert: the live firewall generation must not change,
      // and egress must still work, until an exact approval selects a new one.
      // A brief settle for the proxy's desired-policy poll.
      const start = Date.now();
      while (Date.now() - start < 2000) { /* settle */ }
      expect(firewallGeneration(proxyId), "an unapproved desired policy changed the live firewall generation").toBe(preEmptyGeneration);
      const stillReachable = sessionExec(sessionId,
        curlProbeCommand(`https://${REFERENCE_HOST}${REFERENCE_PATH}`, { maxTimeSeconds: 15, retries: 2 }));
      expect(
        answeredByUpstream(parseProbeAnswer(stillReachable.stdout)),
        `an unapproved desired edit changed live egress: ${describeOutput(stillReachable.output)}`,
      ).toBe(true);
    }, TEST_TIMEOUT_MS);
  });

  describe("the approved empty policy converges to enforced deny-all with no restart", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      const startedAtBefore = proxyStartedAt(proxyId);
      approveDesiredProjectPolicy(fixture);
      await pollUntil(() => {
        emptyGeneration = firewallGeneration(proxyId);
        const requestJson = docker(["exec", proxyId, "cat", requestProxyStatusPath()]).stdout;
        return Boolean(emptyGeneration) && emptyGeneration !== preEmptyGeneration
          && requestJson.includes(String(emptyGeneration));
      }, { timeoutMs: 40_000, label: "the firewall to converge to the empty generation" });

      const firewallJson = docker(["exec", proxyId, "cat", firewallStatusPath()]).stdout;
      expect(firewallJson, "firewall did not verify the ruleset at the empty generation").toContain('"rulesetVerified":true');
      const allowedSet = dockerOrThrow("allowed_ipv4 set", ["exec", "--user", "0:0", proxyId, "nft", "list", "set", "inet", "runfree_proxy", "allowed_ipv4"]);
      expect(allowedSet, "allowed_ipv4 stopped existing under the empty policy").toContain("set allowed_ipv4");
      expect(resolvedHostsSnapshot(proxyId), "resolved-host snapshot did not drop the policy host under the empty policy").not.toContain(REFERENCE_HOST);
      assertAllowlistFullyExplained(proxyId, "empty policy");
      expect(proxyStartedAt(proxyId), "proxy restarted while converging to the empty policy").toBe(startedAtBefore);

      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("a previously reachable host is denied under the empty policy", () => {
      const probe = sessionExec(sessionId,
        `curl -ksS --max-time 15 -o /dev/null -w '%{http_code}' https://${REFERENCE_HOST}${REFERENCE_PATH}`);
      expect(probe.stdout, `previously reachable host was not denied under the empty policy: ${describeOutput(probe.output)}`).toContain("403");
    }, TEST_TIMEOUT_MS);
  });

  describe("a proxy restart with an empty allowlist reaches readiness with no egress leak", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;
    let restartStartedAt: string;

    beforeAll(async () => {
      docker(["restart", proxyId]);
      restartStartedAt = proxyStartedAt(proxyId);
      // Restart-safe readiness: request-proxy.json lives on a tmpfs Docker
      // recreates empty on restart, so its reappearance with a generation cannot
      // be a stale pre-restart line.
      await pollUntil(
        () => docker(["exec", proxyId, "cat", requestProxyStatusPath()]).stdout.includes('"generation":"sha256:'),
        { timeoutMs: 120_000, label: "the request proxy to become ready after an empty-policy restart" },
      );
      await pollUntil(
        () => docker(["exec", proxyId, "cat", firewallStatusPath()]).stdout.includes('"rulesetVerified":true'),
        { timeoutMs: 30_000, label: "the firewall to verify the ruleset after restart" },
      );
      const firewallJson = docker(["exec", proxyId, "cat", firewallStatusPath()]).stdout;
      expect(firewallJson, "firewall did not report the empty generation after restart").toContain(String(emptyGeneration));
      const allowedSet = dockerOrThrow("allowed_ipv4 set", ["exec", "--user", "0:0", proxyId, "nft", "list", "set", "inet", "runfree_proxy", "allowed_ipv4"]);
      expect(allowedSet, "allowed_ipv4 did not exist after an empty-policy restart").toContain("set allowed_ipv4");
      assertAllowlistFullyExplained(proxyId, "after empty-policy restart");

      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("agent egress is denied after the empty-policy restart (no leak)", () => {
      const probe = sessionExec(sessionId, `
        curl_err="$(mktemp)"
        http_code="$(curl -ksS --max-time 20 -o /dev/null -w '%{http_code}' https://${REFERENCE_HOST}${REFERENCE_PATH} 2>"$curl_err")"
        printf 'http_code=%s\\n' "$http_code"
        rm -f "$curl_err"
      `);
      const code = /http_code=([0-9]*)/u.exec(probe.stdout)?.[1] ?? "";
      // Only output produced after the restart, so a pre-restart denial cannot
      // corroborate a post-restart failure.
      const logs = dockerOrThrow("post-restart proxy logs", ["logs", "--since", restartStartedAt, proxyId]);
      const recordedDenial = logs.split("\n").some((line) =>
        line.includes("proxy-denial") && line.includes('"reason":"host-not-allowlisted"') && line.includes(`"host":"${REFERENCE_HOST}"`));

      if (/^2/u.test(code)) {
        throw new Error(`EGRESS LEAKED after an empty-policy restart: reached ${REFERENCE_HOST} with HTTP ${code}. ${describeOutput(probe.output)}`);
      }
      if (code === "403") return; // in-tunnel synthetic denial
      // A connection-level failure counts only when the proxy recorded denying
      // this host after the restart.
      expect(recordedDenial, `egress after the empty-policy restart was neither a 403 nor a recorded denial for ${REFERENCE_HOST}: ${describeOutput(probe.output)}`).toBe(true);
    }, TEST_TIMEOUT_MS);
  });

  describe("restoring the project policy repopulates the allowlist", () => {
    beforeAll(() => {
      writeProjectPolicy(fixture, policyBackup.trimEnd());
      approveDesiredProjectPolicy(fixture);
    }, PROVISION_TIMEOUT_MS);

    test("the firewall allowlist recovers after restoring the policy", async () => {
      // Firewall-layer proof rather than an HTTP round trip: the restart above
      // wiped the proxy-managed token tmpfs, so upstream status would now depend
      // on credential state rather than allowlist state.
      await pollUntil(() => {
        const generation = firewallGeneration(proxyId);
        return Boolean(generation) && generation !== emptyGeneration;
      }, { timeoutMs: 40_000, label: "the firewall to converge back to the restored policy" });
      await pollUntil(() => {
        const allowedSet = docker(["exec", "--user", "0:0", proxyId, "nft", "list", "set", "inet", "runfree_proxy", "allowed_ipv4"]).stdout;
        const snapshot = docker(["exec", "--user", "0:0", proxyId, "cat", "/run/runfree-resolved-hosts.json"]).stdout;
        return allowedSet.includes("elements") && snapshot.includes(REFERENCE_HOST);
      }, { timeoutMs: 40_000, label: "the allowlist to repopulate after restoring the policy" });
    }, TEST_TIMEOUT_MS);
  });
});
