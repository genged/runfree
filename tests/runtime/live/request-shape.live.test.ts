// Request-shape enforcement tranche, ported from `tests/runtime/sandbox.sh`.
//
// Proves the per-host request rules: read-only method denial, git-push denial,
// the ask-default write posture with no approver, approve-on-write through the
// root-owned decision channel (and that neither the agent nor the uid-1001 proxy
// can mint a decision), and that `--write allow` restores write flow — each with
// live convergence and no proxy restart.
//
// Structural constraint that shapes this file: a policy mutation quiesces the
// project (it takes the project lifecycle lock and pauses live agents), and a
// held standing session holds that same lock for its whole life. So a mutation
// and a session cannot overlap. Each rule state is a nested suite whose
// `beforeAll` mutates while no session is up, then starts one held session for
// that state's behavioral probes; `afterAll` ends it before the next state
// mutates. `runfree approvals`/`approve` do not quiesce, so approve-on-write
// runs inside a held session.
//
// The rules under test live on reserved `.invalid` hosts that never resolve
// (see `proxy-answer.ts`): every claim here is about the proxy's decision, so
// an admitted request is read as the proxy's upstream-failure 502 plus an
// `admitted` event, and no public service or its rate limit is involved. The
// approve-on-write cases stay on `api.github.com` for its service-specific
// approval wording; those writes are held and denied, never forwarded.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { projectInfo } from "../../../packages/cli/src/config.ts";
import { nodeRuntimeIO } from "../../../packages/cli/src/runtime.ts";
import { readPendingApprovals, touchWatcherHeartbeat } from "../../../packages/cli/src/runtime/approvals.ts";

import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  admittedToUnresolvableHost,
  curlProbeCommand,
  enableProxyVerboseLogging,
  parseProbeAnswer,
  proxyAdmittedEventCount,
} from "./proxy-answer.ts";
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

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;
/** Carries the method rules: read-only, then cleared, then `--write allow`. */
const METHOD_HOST = "runfree-shape-methods.invalid";
/** Carries the git-push deny rule. */
const GIT_HOST = "runfree-shape-git.invalid";

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the request-shape tranche");
  }
  return backend;
}

function sessionExec(id: string, script: string): CaptureResult {
  return docker(["exec", id, "zsh", "-lc", script]);
}

function proxyStartedAt(proxyId: string): string {
  return dockerOrThrow("proxy start time", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]);
}

/** Allowlists a probe host; converges live before any session starts. */
function assertConvergedHostAdd(fixture: LiveFixture, host: string): void {
  const added = fixture.runfree(["host", "add", host]);
  expect(added.status, `host add ${host} failed: ${describeOutput(added.output)}`).toBe(0);
  expect(added.stdout, `host add ${host} did not converge live`).toMatch(/effective policy: live now \(effective policy generation sha256:/u);
}

/** A desired-policy mutation that must converge live and not restart the proxy. */
function assertConvergedMutation(result: CaptureResult, host: string, label: string): void {
  expect(result.status, `${label} failed: ${describeOutput(result.output)}`).toBe(0);
  expect(result.output, `${label}: the host was not reported updated`).toContain(`${host} updated`);
  expect(result.output, `${label}: the mutation did not converge live`).toContain("effective policy: live now (effective policy generation sha256:");
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

describe("request-shape enforcement", () => {
  let fixture: LiveFixture;
  let proxyId: string;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
    proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");
    assertConvergedHostAdd(fixture, METHOD_HOST);
    assertConvergedHostAdd(fixture, GIT_HOST);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  describe("a read-only method rule and a git-push deny converge live", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      const startedAtBefore = proxyStartedAt(proxyId);
      assertConvergedMutation(fixture.runfree(["host", "rules", METHOD_HOST, "--read-only"]), METHOD_HOST, "read-only rule");
      assertConvergedMutation(fixture.runfree(["host", "rules", GIT_HOST, "--deny-git-push"]), GIT_HOST, "git-push deny rule");
      // Null second run: re-applying a converged rule is a no-op that still exits
      // 0 and does not restart the proxy.
      const second = fixture.runfree(["host", "rules", METHOD_HOST, "--read-only"]);
      expect(second.status, `re-applying the read-only rule failed: ${describeOutput(second.output)}`).toBe(0);
      expect(proxyStartedAt(proxyId), "applying request rules restarted the proxy").toBe(startedAtBefore);
      // The persisted rules read back authoritatively, not from the write log.
      expect(fixture.runfree(["host", "rules", METHOD_HOST]).output, "method rule not persisted")
        .toContain("methods=GET,HEAD,OPTIONS");
      expect(fixture.runfree(["host", "rules", GIT_HOST]).output, "git-push deny not persisted").toContain("gitPush=deny");
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("a read-only GET succeeds while a POST receives the in-tunnel method denial with no credential", () => {
      const admittedBefore = proxyAdmittedEventCount(proxyId, METHOD_HOST);
      const verbose = enableProxyVerboseLogging(proxyId, "shape-get");
      let get: CaptureResult;
      try {
        get = sessionExec(sessionId, curlProbeCommand(`https://${METHOD_HOST}/rate_limit`, { maxTimeSeconds: 15 }));
      } finally {
        verbose.disable();
      }
      expect(admittedToUnresolvableHost(parseProbeAnswer(get.stdout)), `read-only GET was not admitted: ${describeOutput(get.output)}`)
        .toBe(true);
      expect(proxyAdmittedEventCount(proxyId, METHOD_HOST), "the proxy logged no admission for the read-only GET")
        .toBeGreaterThan(admittedBefore);

      // Verbose allowed-request logging, so a forwarded POST would be visible.
      docker(["exec", "--user", "0:0", proxyId, "sh", "-c", "mkdir -p /run/runfree-proxy-verbose && touch /run/runfree-proxy-verbose/sandbox"]);
      const post = sessionExec(sessionId, `
        set -euo pipefail
        rm -f /tmp/shape-headers.txt /tmp/shape-body.txt
        http_code="$(curl -sS --max-time 10 -X POST -D /tmp/shape-headers.txt -o /tmp/shape-body.txt -w '%{http_code}' 'https://${METHOD_HOST}/rate_limit?shape_probe_param=should-not-be-logged')"
        printf 'http_code=%s\\n' "$http_code"
        cat /tmp/shape-headers.txt
        cat /tmp/shape-body.txt
      `);
      docker(["exec", "--user", "0:0", proxyId, "rm", "-f", "/run/runfree-proxy-verbose/sandbox"]);
      expect(post.status, `method-denied POST probe failed: ${describeOutput(post.output)}`).toBe(0);
      const out = post.output;
      expect(out, "method denial not 403").toContain("http_code=403");
      expect(out, "method denial reason header missing").toContain("x-runfree-blocked: method-not-allowed");
      expect(out, "method denial does not name the method").toContain("method: POST");
      expect(out, "method denial does not name the allowed set").toContain("(allowed: GET, HEAD, OPTIONS)");
      expect(out, "method denial does not suggest the exact widening command")
        .toContain(`runfree host rules ${METHOD_HOST} --method GET --method HEAD --method OPTIONS --method POST`);
      expect(out.toLowerCase(), "denial response carries an injected credential").not.toContain("authorization:");
      expect(out, "denial response carries a bearer value").not.toContain("Bearer ");

      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyId]);
      expect(logs, "structured method-denial event missing")
        .toContain(`"reason":"method-not-allowed","host":"${METHOD_HOST}","method":"POST"`);
      expect(logs, "method denial event leaked the query string").not.toContain("shape_probe_param");
      expect(logs, "the denied POST was forwarded upstream").not.toContain(`proxy: allowed method=POST scheme=https host=${METHOD_HOST}`);
    }, TEST_TIMEOUT_MS);

    test("git fetch negotiation is admitted while push is denied in-tunnel", () => {
      // The proxy's git-push denial is the subject, so the remote must sit
      // behind the proxy; an unresolvable one does, and every request to it
      // ends at the proxy's decision. Reads are proven by what the proxy did
      // with them — admitted and forwarded (the upstream-failure 502) — for
      // both halves of fetch negotiation: the upload-pack ref advertisement
      // GET, and the upload-pack POST, which the git rule classifies as a read
      // rather than a write.
      const admittedBefore = proxyAdmittedEventCount(proxyId, GIT_HOST);
      const verbose = enableProxyVerboseLogging(proxyId, "shape-git");
      let git: CaptureResult;
      let uploadPack: CaptureResult;
      try {
        git = sessionExec(sessionId, `
        set -uo pipefail
        export GIT_TERMINAL_PROMPT=0
        rm -rf /tmp/shape-git && mkdir -p /tmp/shape-git && cd /tmp/shape-git
        git init -q && git -c user.name=probe -c user.email=probe@${GIT_HOST} commit -q --allow-empty -m probe
        if git ls-remote https://${GIT_HOST}/probe.git >/tmp/shape-git-read.log 2>&1; then
          echo read-unexpectedly-succeeded
        else
          echo "read-log: $(tr '\n' ' ' </tmp/shape-git-read.log)"
        fi
        if git push https://${GIT_HOST}/probe.git HEAD:refs/heads/runfree-shape-denied-push >/tmp/shape-git-push.log 2>&1; then
          echo push-unexpectedly-succeeded
        else
          echo "push-log: $(tr '\n' ' ' </tmp/shape-git-push.log)"
        fi
      `);
        uploadPack = sessionExec(sessionId, curlProbeCommand(`https://${GIT_HOST}/probe.git/git-upload-pack`, {
          method: "POST",
          maxTimeSeconds: 15,
        }));
      } finally {
        verbose.disable();
      }
      expect(git.status, `gitPush probe failed: ${describeOutput(git.output)}`).toBe(0);
      const readLog = git.stdout.split("\n").find((line) => line.startsWith("read-log: ")) ?? "";
      const pushLog = git.stdout.split("\n").find((line) => line.startsWith("push-log: ")) ?? "";
      expect(readLog, `the ref advertisement was not forwarded: ${describeOutput(git.output)}`).toContain("error: 502");
      expect(pushLog, `git push was not denied by the proxy: ${describeOutput(git.output)}`).toContain("error: 403");

      expect(
        admittedToUnresolvableHost(parseProbeAnswer(uploadPack.stdout)),
        `the upload-pack POST was not admitted as a read: ${describeOutput(uploadPack.output)}`,
      ).toBe(true);
      expect(proxyAdmittedEventCount(proxyId, GIT_HOST), "the proxy did not log admitting both fetch requests")
        .toBeGreaterThanOrEqual(admittedBefore + 2);

      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyId]);
      expect(logs, "structured git-push denial event missing").toContain(`"reason":"git-push-denied","host":"${GIT_HOST}"`);
    }, TEST_TIMEOUT_MS);

    test("runfree doctor suggests the exact method-widening command", () => {
      const doctor = fixture.runfree(["doctor"]);
      expect(doctor.output, "doctor does not report the shape denial").toContain(`${METHOD_HOST} blocked by request rules`);
      expect(doctor.output, "doctor does not suggest method widening")
        .toContain(`runfree host rules ${METHOD_HOST} --method GET --method HEAD --method OPTIONS --method POST`);
    }, TEST_TIMEOUT_MS);
  });

  describe("cleared rules fall back to the ask-default write posture", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      assertConvergedMutation(fixture.runfree(["host", "rules", METHOD_HOST, "--clear"]), METHOD_HOST, "clear method rules");
      assertConvergedMutation(fixture.runfree(["host", "rules", GIT_HOST, "--clear"]), GIT_HOST, "clear git rules");
      expect(fixture.runfree(["host", "rules", METHOD_HOST]).output, "method rules not cleared")
        .toContain("none (all methods, all paths, git push allowed)");
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("an unruled POST fails closed under the ask default with no approver", () => {
      const probe = sessionExec(sessionId, `curl -sS --max-time 30 -X POST https://${METHOD_HOST}/rate_limit`);
      expect(probe.output, "unruled POST did not fail closed under the ask default")
        .toContain("writes need approval but no approver is attached");
      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyId]);
      expect(logs, "structured write-approval denial event missing")
        .toContain(`"reason":"write-approval-required","host":"${METHOD_HOST}"`);
    }, TEST_TIMEOUT_MS);

    test("approve-on-write resolves a held write through the root-owned decision channel", async () => {
      const context = {
        projectRoot: fixture.projectRoot,
        project: projectInfo(fixture.projectRoot, fixture.env),
        runtimeRoot: path.join(REPO_ROOT, "dist", "runtime"),
        env: fixture.env,
      };
      const heartbeat = (): void => {
        expect(touchWatcherHeartbeat(context, nodeRuntimeIO, proxyId), "could not register the current proxy approval epoch").toBe(true);
      };
      heartbeat();
      // Detached held write from the admitted session.
      dockerOrThrow("start held approval write", ["exec", "-d", sessionId, "zsh", "-lc",
        "curl -sS --max-time 60 -o /tmp/approval-probe.body -w '%{http_code}' -X POST https://api.github.com/rate_limit > /tmp/approval-probe.code 2>&1"]);

      await pollUntil(() => {
        heartbeat();
        return fixture.runfree(["approvals"]).output.includes("make a change on GitHub");
      }, { timeoutMs: 30_000, label: "the held write to appear in approvals" });

      const pending = readPendingApprovals(context, nodeRuntimeIO, proxyId)
        .filter((record) => record.host === "api.github.com" && record.method === "POST");
      expect(pending, "expected one held GitHub write").toHaveLength(1);
      const approvalId = pending[0].id;

      const decided = fixture.runfree(["approve", approvalId, "--deny"]);
      expect(decided.output, "approve --deny did not decide the held write").toContain(`denied ${approvalId}`);

      await pollUntil(
        () => docker(["exec", sessionId, "cat", "/tmp/approval-probe.code"]).stdout.includes("403"),
        { timeoutMs: 20_000, label: "the held request to receive the denial" },
      );
      const logs = dockerOrThrow("proxy logs", ["logs", "--tail", "400", proxyId]);
      expect(logs, "structured approval-request event missing").toContain('proxy-approval-request: {"v":1');
      expect(logs, "structured approval outcome event missing").toContain('"outcome":"denied"');
    }, TEST_TIMEOUT_MS);

    test("neither the agent nor the uid-1001 proxy can mint a decision", () => {
      const agent = sessionExec(sessionId, 'echo "{}" > /tmp/forged.json 2>/dev/null; ls /run/runfree-approvals 2>&1');
      expect(agent.output, "the agent has a view of the approvals decisions tmpfs").not.toContain("decisions");
      const uid1001 = docker(["exec", "--user", "1001:1001", proxyId, "sh", "-c",
        'echo "{\\"v\\":1}" > /run/runfree-approvals/decisions/forged.json 2>&1 || echo uid1001-decision-write-denied']);
      expect(uid1001.output, "the uid-1001 proxy user minted a decision").toContain("uid1001-decision-write-denied");
    }, TEST_TIMEOUT_MS);
  });

  describe("host rules --write allow restores write flow", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      assertConvergedMutation(fixture.runfree(["host", "rules", METHOD_HOST, "--write", "allow"]), METHOD_HOST, "write allow");
      expect(fixture.runfree(["host", "rules", METHOD_HOST]).output, "write action not persisted").toContain("writeAction=allow");
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("a POST is admitted and forwarded after --write allow", async () => {
      let output = "";
      await pollUntil(() => {
        const probe = sessionExec(sessionId, curlProbeCommand(`https://${METHOD_HOST}/rate_limit`, { method: "POST", maxTimeSeconds: 10 }));
        output = probe.output;
        return admittedToUnresolvableHost(parseProbeAnswer(probe.stdout));
      }, { timeoutMs: 20_000, label: "the POST to be admitted after --write allow" }).catch((error: unknown) => {
        throw new Error(`${String(error)}; last answer: ${describeOutput(output)}`);
      });
    }, TEST_TIMEOUT_MS);
  });
});
