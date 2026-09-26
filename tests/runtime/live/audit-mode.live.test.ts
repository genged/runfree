// Network audit-mode tranche, ported from `tests/runtime/sandbox.sh`.
//
// Proves the observe-don't-enforce mode: host-only activation, the uid-1001
// proxy cannot write the marker, a non-allowlisted public host is observed and
// permitted (but never added to the enforce allowlist), non-HTTPS stays
// rejected, hostnames resolving to private addresses stay unreachable (the SSRF
// guard), configured credential headers are stripped toward audited hosts,
// teardown severs an in-flight upload, and enforcement resumes afterwards.
//
// Choreography: activation is `runfree up --audit-network`, which is a startup
// path and takes the project lifecycle lock, so it runs before any session.
// `audit status/report/off` do not quiesce, so the behavioral probes and the
// teardown-severance run inside one held session admitted under audit mode. The
// teardown test runs last because it disables audit for the rest of the suite.
//
// Named stand-ins: `example.com`/`httpbin.org` exercise the audit observe path
// on real public hosts; `127.0.0.1.nip.io` resolves to loopback to exercise the
// SSRF guard, not real reachability; `sandbox-forged-token` is never a real
// credential.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  provisionSandboxFixture,
  startStandingSession,
  type StandingSessionHandle,
} from "./fixture.ts";
import { answeredByUpstream, curlProbeCommand, parseProbeAnswer } from "./proxy-answer.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;
const AUDITED_HOST = "example.com";
const PRIVATE_AUDITED_HOST = "127.0.0.1.nip.io";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the audit-mode tranche");
  }
  return backend;
}

function sessionExec(id: string, script: string): CaptureResult {
  return docker(["exec", id, "zsh", "-lc", script]);
}

/** The IPv4 members of one owned nftables set, or throws (never silently empty). */
function auditSetIps(proxyId: string, setName: string): readonly string[] {
  const json = docker(["exec", "--user", "0:0", proxyId, "nft", "-j", "list", "set", "inet", "runfree_proxy", setName]);
  if (json.status !== 0) throw new Error(`could not read the ${setName} set: ${describeOutput(json.output)}`);
  const parsed = JSON.parse(json.stdout) as { nftables?: { set?: { elem?: unknown[] } }[] };
  const set = (parsed.nftables ?? []).map((statement) => statement.set).find(Boolean);
  const ips: string[] = [];
  for (const element of set?.elem ?? []) {
    if (typeof element === "string") ips.push(element);
    else if (element && typeof element === "object") {
      const value = (element as { val?: unknown; elem?: { val?: unknown } }).val
        ?? (element as { elem?: { val?: unknown } }).elem?.val;
      if (typeof value === "string") ips.push(value);
    }
  }
  return ips;
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

describe("network audit mode observes without enforcing", () => {
  let fixture: LiveFixture;
  let proxyId: string;
  let standing: StandingSessionHandle;
  let sessionId: string;

  beforeAll(async () => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");

    // Host-only activation, before any session (it takes the lifecycle lock).
    const activate = fixture.runfree(["up", "--audit-network=10m"]);
    expect(activate.output, "audit activation banner is not loud").toContain("NETWORK AUDIT MODE ACTIVE");
    expect(activate.output, "audit activation does not name the disable command").toContain("runfree audit off");
    expect(fixture.runfree(["audit", "status"]).output, "audit status is not ACTIVE").toContain("network audit: ACTIVE, expires in");
    expect(fixture.runfree(["status"]).output, "runfree status does not show audit ACTIVE").toContain("network audit: ACTIVE");

    standing = await startStandingSession(fixture);
    sessionId = standing.session.containerId;
  }, PROVISION_TIMEOUT_MS);

  afterAll(async () => {
    fixture?.runfree(["audit", "off"]);
    if (standing) await standing.release();
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  test("the uid-1001 proxy server cannot write the audit marker", () => {
    const write = docker(["exec", "--user", "1001:1001", proxyId, "sh", "-c", 'echo "{}" > /run/runfree-proxy-audit/active.json']);
    expect(write.status, "uid-1001 overwrote the audit marker").not.toBe(0);
    expect(write.output, "audit marker write not denied for the proxy server uid").toContain("Permission denied");
    const create = docker(["exec", "--user", "1001:1001", proxyId, "sh", "-c", "touch /run/runfree-proxy-audit/uid1001-probe"]);
    expect(create.status, "uid-1001 created a file in the audit marker dir").not.toBe(0);
  }, TEST_TIMEOUT_MS);

  test("a non-allowlisted public host is observed and permitted, but never enters the enforce allowlist", async () => {
    // The upstream itself must answer (any answer counts, see
    // `proxy-answer.ts`): that is what proves audit_ipv4 let the proxy out.
    await pollUntil(
      () => answeredByUpstream(parseProbeAnswer(sessionExec(sessionId, curlProbeCommand(`https://${AUDITED_HOST}/`, { maxTimeSeconds: 10 })).stdout)),
      { timeoutMs: 40_000, label: `${AUDITED_HOST} to become reachable under audit` },
    );
    const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "600", proxyId]);
    expect(logs, "structured proxy-audit event missing").toContain("proxy-audit: ");
    expect(logs, "audit event does not name the host").toContain(`"host":"${AUDITED_HOST}"`);

    let auditIps: readonly string[] = [];
    await pollUntil(() => { auditIps = auditSetIps(proxyId, "audit_ipv4"); return auditIps.length > 0; },
      { timeoutMs: 25_000, label: "audit_ipv4 to gain members after an audited request" });
    const allowedSet = dockerOrThrow("allowed_ipv4 set", ["exec", "--user", "0:0", proxyId, "nft", "list", "set", "inet", "runfree_proxy", "allowed_ipv4"]);
    for (const ip of auditIps) {
      expect(allowedSet, `audited IP ${ip} leaked into allowed_ipv4`).not.toContain(ip);
    }
    const enforceSnapshot = dockerOrThrow("enforce snapshot", ["exec", "--user", "0:0", proxyId, "cat", "/run/runfree-resolved-hosts.json"]);
    expect(enforceSnapshot, "audited host present in the enforce resolved-hosts snapshot").not.toContain(AUDITED_HOST);
  }, TEST_TIMEOUT_MS);

  test("non-HTTPS ports stay rejected during audit", () => {
    const proxyIp = dockerOrThrow("proxy internal address", [
      "inspect", "-f", `{{with index .NetworkSettings.Networks "${composeProjectName(fixture)}_agent_internal"}}{{.IPAddress}}{{end}}`, proxyId,
    ]);
    const probe = docker(["exec", sessionId, "sh", "-lc",
      `printf 'CONNECT ${AUDITED_HOST}:80 HTTP/1.1\\r\\nHost: ${AUDITED_HOST}:80\\r\\n\\r\\n' | nc -w 3 ${proxyIp} 8080`]);
    expect(probe.output, "non-443 CONNECT was not rejected during audit").toContain("403");
  }, TEST_TIMEOUT_MS);

  test("a host resolving to a private address stays unreachable (SSRF guard)", async () => {
    const probe = sessionExec(sessionId,
      `curl -sS --max-time 15 -o /tmp/audit-private-body.out -w '%{http_code}' https://${PRIVATE_AUDITED_HOST}/ ; echo " status=$?"`);
    const body = docker(["exec", sessionId, "cat", "/tmp/audit-private-body.out"]).stdout;
    // A transport failure is fine; the only acceptable HTTP completion is the
    // proxy's own 502 from the guarded lookup (ENOTFOUND before any private dial).
    if (/^200/u.test(probe.stdout)) {
      throw new Error(`audited private-resolving host was reachable: ${describeOutput(probe.output)} body=${describeOutput(body)}`);
    }
    expect(auditSetIps(proxyId, "audit_ipv4"), "loopback answer entered audit_ipv4").not.toContain("127.0.0.1");

    // The supervisor classifies and rejects on its async tick, possibly after
    // curl already saw the guarded 502; poll the logs for the rejection.
    await pollUntil(() => {
      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "800", proxyId]);
      return logs.includes("audit rejected unsafe DNS answer")
        || logs.includes("audit host has no safe IPv4 answers")
        || logs.includes(`audit DNS lookup failed host=${PRIVATE_AUDITED_HOST}`);
    }, { timeoutMs: 25_000, label: "the supervisor to record rejecting the private-resolving host" });
    expect(auditSetIps(proxyId, "audit_ipv4"), "loopback answer entered audit_ipv4 after classification").not.toContain("127.0.0.1");
  }, TEST_TIMEOUT_MS);

  test("configured credential headers are stripped toward audited hosts", () => {
    // Precondition: the managed header name must be in the effective policy, or
    // the union strip returns early and the probe could not fail.
    const status = fixture.runfree(["credential", "status", "sandbox-strip-probe"]);
    expect(status.output, "the strip-proof credential is not configured").toContain("sandbox-strip-probe: configured");
    expect(status.output, "no managed Authorization destination exists")
      .toContain("raw.githubusercontent.com -> Authorization (bearer)");

    // A public header-echo is required (audit permits only public hosts); tolerate
    // third-party outages, since the union strip is also covered by unit tests. A
    // reachable echo that leaks the forged token still fails.
    let strip: CaptureResult | undefined;
    for (const url of ["https://httpbin.org/headers", "https://postman-echo.com/get"]) {
      const probe = sessionExec(sessionId, `curl -sS --max-time 10 -H 'Authorization: Bearer sandbox-forged-token' ${url}`);
      if (probe.stdout.includes('"headers"')) { strip = probe; break; }
    }
    if (strip) {
      expect(strip.stdout, "forged Authorization header reached upstream").not.toContain("sandbox-forged-token");
    } else {
      console.warn("audit-mode: header-echo services unavailable; skipping the upstream strip echo (covered by unit tests)");
    }
  }, TEST_TIMEOUT_MS);

  test("audit report lists observed hosts with suggested commands", () => {
    const report = fixture.runfree(["audit", "report"]);
    expect(report.output, "audit report does not name the observed host").toContain(AUDITED_HOST);
    expect(report.output, "audit report does not suggest the host add command").toContain(`runfree host add ${AUDITED_HOST}`);
    expect(report.output, "audit report does not disclaim auto-apply").toContain("Runfree never applies these automatically.");
  }, TEST_TIMEOUT_MS);

  test("teardown severs an in-flight upload and enforcement resumes afterwards", async () => {
    // This test disables audit; it runs last. A slow streaming upload to a public
    // host observed under audit; `audit off` must sever it within a tick, not let
    // it run to its --max-time.
    const startedAtBefore = dockerOrThrow("proxy start time", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]);
    sessionExec(sessionId, "rm -f /tmp/audit-upload-exit /tmp/audit-upload-out");
    docker(["exec", "-d", sessionId, "zsh", "-lc",
      "curl -sS --max-time 120 -o /tmp/audit-upload-out -T - https://httpbin.org/put < <(for i in $(seq 1 90); do head -c 1024 /dev/zero | tr '\\0' 'x'; sleep 1; done); echo $? > /tmp/audit-upload-exit"]);
    const uploadStartedAt = Date.now();

    // Wait until an audited egress connection to the upload host is established.
    await pollUntil(() => auditSetIps(proxyId, "audit_ipv4").length > 0,
      { timeoutMs: 30_000, label: "an audited egress destination before teardown" });

    const off = fixture.runfree(["audit", "off"]);
    expect(off.output, "audit off did not disable the marker").toContain("network audit: disabled");

    await pollUntil(() => auditSetIps(proxyId, "audit_ipv4").length === 0,
      { timeoutMs: 20_000, label: "audit_ipv4 to flush on the fast teardown tick" });

    await pollUntil(() => docker(["exec", sessionId, "cat", "/tmp/audit-upload-exit"]).stdout.trim() !== "",
      { timeoutMs: 60_000, label: "the in-flight upload to be severed" });
    const uploadExit = docker(["exec", sessionId, "cat", "/tmp/audit-upload-exit"]).stdout.trim();
    expect(uploadExit, "in-flight audited upload completed after teardown").not.toBe("0");
    expect((Date.now() - uploadStartedAt) / 1000, "audited upload was not severed promptly").toBeLessThan(85);
    expect(dockerOrThrow("proxy start time", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]),
      "the proxy restarted during audit teardown; severance must not come from a container restart").toBe(startedAtBefore);

    // Enforcement resumes: the next request to the previously-audited host is
    // denied at the guard, and the host is gone from the enforce snapshot.
    const post = sessionExec(sessionId, `curl -ksS --max-time 10 -o /dev/null -w '%{http_code}' https://${AUDITED_HOST}/`);
    expect(post.stdout, "audited host still reachable after audit off").toContain("403");
    const enforceSnapshot = dockerOrThrow("enforce snapshot", ["exec", "--user", "0:0", proxyId, "cat", "/run/runfree-resolved-hosts.json"]);
    expect(enforceSnapshot, "audited host present in enforce snapshot after teardown").not.toContain(AUDITED_HOST);
    expect(fixture.runfree(["audit", "status"]).output, "audit status not inactive after off").toContain("network audit: inactive");
  }, TEST_TIMEOUT_MS);
});
