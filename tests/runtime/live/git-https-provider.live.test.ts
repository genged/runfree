// Gated git provider tranche: git over HTTPS credential mediation against a
// real provider (L1–L3, L5, L6). Extended tier; it is not in CORE_LIVE_FILES.
//
// Opt-in. Without the gate every case skips and says why. With the gate set,
// a missing or malformed input FAILS the run instead of skipping, so a
// recorded provider run cannot be green without having run.
//
//   TEST_RUNTIME_GIT_PROVIDERS   comma list of providers: github, gitlab
//
// Per provider (<P> is GITHUB or GITLAB), required once the gate names it:
//
//   TEST_RUNTIME_<P>_REPO      https URL of a dedicated PRIVATE repository on
//                              github.com / gitlab.com, e.g.
//                              https://github.com/<owner>/<repo>.git. The run
//                              pushes and then deletes one scratch branch
//                              named runfree-live-<time>-<random>.
//   TEST_RUNTIME_<P>_SOURCE    name of an existing host-side Runfree credential
//                              source (`runfree credential source add <name> --
//                              <command>`, in $XDG_CONFIG_HOME/runfree, default
//                              ~/.config/runfree) whose command prints a
//                              least-privilege token for that repository only:
//                              read and write contents, nothing else. For
//                              GitHub, a fine-grained token scoped to the one
//                              repository with Contents read/write; for
//                              GitLab, a project access token with
//                              read_repository and write_repository.
//
// Optional per provider:
//
//   TEST_RUNTIME_<P>_LFS_REPO  https URL of a private repository on the same
//                              provider that holds at least one committed Git
//                              LFS object. Without it, L5 skips with that
//                              reason. It is a separate input because LFS is a
//                              per-repository opt-in and a pointer file must
//                              already exist to prove an authorized download;
//                              the main repository stays free of LFS. The
//                              agent image ships no git-lfs client, so L5
//                              sends the batch requests git-lfs sends, with
//                              curl, and never follows the returned object
//                              hrefs (their storage hosts are provider-owned
//                              and outside the service bundle). The batch
//                              request is the part Runfree classifies.
//
// Never read: GH_TOKEN, GITHUB_TOKEN, GITLAB_TOKEN, `gh auth token`, or any
// other ambient credential. Only the named source's command definition is
// copied into the fixture's isolated registry (`git-provider-config.ts`); the
// fixture CLI then resolves the token through that source.
//
// Example:
//
//   TEST_RUNTIME_BACKEND=docker-desktop \
//   TEST_RUNTIME_GIT_PROVIDERS=github,gitlab \
//   TEST_RUNTIME_GITHUB_REPO=https://github.com/<owner>/<repo>.git \
//   TEST_RUNTIME_GITHUB_SOURCE=<source> \
//   TEST_RUNTIME_GITLAB_REPO=https://gitlab.com/<group>/<repo>.git \
//   TEST_RUNTIME_GITLAB_SOURCE=<source> \
//   pnpm exec vitest run --project runtime-live tests/runtime/live/git-https-provider.live.test.ts
//
// Shape (per provider, one fixture): the provider's service is enabled with no
// credential source, so the first held session proves a private fetch fails
// cleanly with no prompt (L2 negative). The token is then bound and a second
// session proves the SSH remote resolves over HTTPS with an injected
// credential (L1), a private clone (L2), LFS batch classification (L5), and an
// approved push plus its cleanup (L3). Last, `--deny-git-push` is applied and a
// third session proves the push is denied by the proxy (L3). GitLab running the
// same cases is L6. A policy or credential mutation quiesces the project, so
// each state's mutation runs in `beforeAll` with no session up, as in
// `request-shape.live.test.ts`.

import childProcess from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { projectInfo } from "../../../packages/cli/src/config.ts";
import { nodeRuntimeIO } from "../../../packages/cli/src/runtime.ts";
import { readPendingApprovals, touchWatcherHeartbeat } from "../../../packages/cli/src/runtime/approvals.ts";

import { composeProjectName, composeServiceContainerId, docker, dockerOrThrow } from "./docker.ts";
import {
  configureStandingSessionImage,
  describeOutput,
  destroyLiveFixture,
  type CaptureResult,
  type LiveFixture,
  provisionLiveFixture,
  startStandingSession,
  type StandingSessionHandle,
} from "./fixture.ts";
import {
  type GitProviderInputs,
  type GitProviderRepository,
  gitProviderSuiteConfig,
  hostCommandSourceArgv,
} from "./git-provider-config.ts";
import { answeredByUpstream, enableProxyVerboseLogging, parseProbeAnswer } from "./proxy-answer.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 12 * 60_000;
/** Bound on any one git command inside the session; a prompt would hang until it. */
const GIT_COMMAND_TIMEOUT_SECONDS = 120;
/** Bound on a held write waiting for this tranche to decide it. */
const APPROVAL_WAIT_MS = 3 * 60_000;
/** Git with no prompt, no askpass, and no credential helper: only the proxy can authenticate. */
const NO_PROMPT_GIT = "env GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= git -c credential.helper=";
const LFS_MEDIA_TYPE = "application/vnd.git-lfs+json";

function requireDockerDesktopBackend(): void {
  if (process.env.TEST_RUNTIME_BACKEND !== "docker-desktop") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop for the git provider tranche");
  }
}

function sessionExec(containerId: string, script: string): CaptureResult {
  return docker(["exec", containerId, "zsh", "-lc", script]);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function runOrThrow(fixture: LiveFixture, args: readonly string[]): CaptureResult {
  const result = fixture.runfree(args);
  if (result.status !== 0) throw new Error(`runfree ${args.join(" ")} failed: ${describeOutput(result.output, 4000)}`);
  return result;
}

function hostGit(projectRoot: string, args: readonly string[]): void {
  const result = childProcess.spawnSync("git", ["-C", projectRoot, ...args], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${describeOutput(String(result.stderr ?? ""))}`);
}

function proxyLogs(proxyId: string): string {
  const logs = docker(["logs", proxyId]);
  if (logs.status !== 0) throw new Error(`proxy logs failed: ${describeOutput(logs.output)}`);
  return logs.output;
}

function countOccurrences(text: string, needle: string): number {
  return text.split(needle).length - 1;
}

/** The proxy's own line for a git-http injection on this provider's host. */
function injectedLine(provider: GitProviderInputs): string {
  return `proxy: injected Authorization for ${provider.host} using ${provider.tokenName}`;
}

function scratchBranch(): string {
  return `runfree-live-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

type ApprovalRun = Readonly<{
  exitCode: number;
  log: string;
  /** Ids this tranche decided, in order; empty means nothing was ever held. */
  decided: readonly string[];
}>;

/**
 * Runs `script` detached in the session with an approver attached, deciding
 * every write it holds on `host` whose path contains `pathPart`, until the
 * script exits. The same root-owned decision channel `request-shape` uses:
 * the watcher heartbeat registers the approver, `readPendingApprovals` reads
 * the held records, and `runfree approve` decides them.
 */
async function runDecidingHeldWrites(input: Readonly<{
  fixture: LiveFixture;
  proxyId: string;
  sessionId: string;
  label: string;
  script: string;
  host: string;
  pathPart: string;
  decision: "approve" | "deny";
}>): Promise<ApprovalRun> {
  const { fixture, proxyId, sessionId } = input;
  const context = {
    projectRoot: fixture.projectRoot,
    project: projectInfo(fixture.projectRoot, fixture.env),
    runtimeRoot: path.join(REPO_ROOT, "dist", "runtime"),
    env: fixture.env,
  };
  const heartbeat = (): void => {
    if (!touchWatcherHeartbeat(context, nodeRuntimeIO, proxyId)) {
      throw new Error(`${input.label}: could not register the current proxy approval epoch`);
    }
  };
  const tag = `${input.label.replaceAll(/[^a-z0-9]+/giu, "-")}-${crypto.randomBytes(3).toString("hex")}`;
  const logFile = `/tmp/rf-${tag}.log`;
  const codeFile = `/tmp/rf-${tag}.code`;
  heartbeat();
  dockerOrThrow(`start ${input.label}`, ["exec", "-d", sessionId, "zsh", "-lc",
    `{ ${input.script} ; } > ${logFile} 2>&1; echo $? > ${codeFile}`]);

  const decided: string[] = [];
  const deadline = Date.now() + APPROVAL_WAIT_MS;
  for (;;) {
    heartbeat();
    const pending = readPendingApprovals(context, nodeRuntimeIO, proxyId)
      .filter((record) => record.host === input.host && record.method === "POST" && record.path.includes(input.pathPart))
      .filter((record) => !decided.includes(record.id));
    for (const record of pending) {
      const args = input.decision === "approve" ? ["approve", record.id] : ["approve", record.id, "--deny"];
      const result = fixture.runfree(args);
      const expected = `${input.decision === "approve" ? "approved" : "denied"} ${record.id}`;
      if (!result.output.includes(expected)) {
        throw new Error(`${input.label}: runfree ${args.join(" ")} did not decide the held write: ${describeOutput(result.output)}`);
      }
      decided.push(record.id);
    }
    const code = docker(["exec", sessionId, "cat", codeFile]);
    if (code.status === 0 && /^\d+$/u.test(code.stdout.trim())) {
      const log = docker(["exec", sessionId, "cat", logFile]).output;
      return Object.freeze({ exitCode: Number(code.stdout.trim()), log, decided: Object.freeze(decided) });
    }
    if (Date.now() >= deadline) {
      const log = docker(["exec", sessionId, "cat", logFile]).output;
      throw new Error(`${input.label}: did not finish within ${APPROVAL_WAIT_MS} ms (decided ${decided.length}): ${describeOutput(log)}`);
    }
    await sleep(1000);
  }
}

/** Clones `repository` read-only into the session, returning the clone path. */
function cloneInSession(sessionId: string, repository: GitProviderRepository, dir: string): CaptureResult {
  return sessionExec(sessionId, `
    set -uo pipefail
    rm -rf ${dir}
    timeout ${GIT_COMMAND_TIMEOUT_SECONDS} ${NO_PROMPT_GIT} clone --quiet --depth 1 --no-tags ${shellQuote(repository.httpsUrl)} ${dir}
  `);
}

function pushScript(dir: string, refspec: string): string {
  return [
    `cd ${dir}`,
    `timeout ${GIT_COMMAND_TIMEOUT_SECONDS} ${NO_PROMPT_GIT} push origin ${shellQuote(refspec)}`,
  ].join(" && ");
}

function lfsBatchScript(repository: GitProviderRepository, body: string, out: string): string {
  const url = `${repository.httpsUrl}/info/lfs/objects/batch`;
  return [
    `curl -sS --max-time 60 -X POST`,
    `-H ${shellQuote(`Accept: ${LFS_MEDIA_TYPE}`)}`,
    `-H ${shellQuote(`Content-Type: ${LFS_MEDIA_TYPE}`)}`,
    `--data-raw ${shellQuote(body)}`,
    `-D - -o ${out} -w '\\nrunfree-probe-http-code=%{http_code}\\n'`,
    shellQuote(url),
  ].join(" ");
}

function lfsBatchBody(operation: "download" | "upload", oid: string, size: number): string {
  return JSON.stringify({ operation, transfers: ["basic"], objects: [{ oid, size }] });
}

function defineProviderSuite(provider: GitProviderInputs): void {
  describe(`git over HTTPS against ${provider.id} (${provider.repository.httpsUrl})`, () => {
    let fixture: LiveFixture;
    let proxyId: string;

    beforeAll(() => {
      requireDockerDesktopBackend();
      // Read before any Docker work so a bad source name fails in seconds.
      const sourceArgv = hostCommandSourceArgv(provider.source, process.env);
      fixture = provisionLiveFixture({
        repoRoot: REPO_ROOT,
        configure: (configured) => {
          configureStandingSessionImage(configured);
          // No credential source yet: the first state proves the anonymous
          // failure. Both services allow anonymous forwarding.
          runOrThrow(configured, ["service", "enable", provider.service, ...provider.enableFlags, "--no-reload"]);
          runOrThrow(configured, ["credential", "source", "add", provider.source, "--", ...sourceArgv]);
          hostGit(configured.projectRoot, ["remote", "add", "origin", provider.repository.sshUrl]);
        },
      });
      proxyId = composeServiceContainerId(composeProjectName(fixture), "proxy");
    }, PROVISION_TIMEOUT_MS);

    afterAll(() => {
      if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
    }, PROVISION_TIMEOUT_MS);

    describe("with no credential bound", () => {
      let standing: StandingSessionHandle;
      let sessionId: string;

      beforeAll(async () => {
        standing = await startStandingSession(fixture);
        sessionId = standing.session.containerId;
      }, PROVISION_TIMEOUT_MS);

      afterAll(async () => {
        if (standing) await standing.release();
      }, PROVISION_TIMEOUT_MS);

      test("L2: a private fetch fails cleanly, with no prompt and no injected credential", () => {
        const injectedBefore = countOccurrences(proxyLogs(proxyId), injectedLine(provider));
        const started = Date.now();
        const probe = sessionExec(sessionId, `
          cd /workspace
          timeout ${GIT_COMMAND_TIMEOUT_SECONDS} ${NO_PROMPT_GIT} ls-remote origin
          printf '\\nexit=%s\\n' "$?"
        `);
        const elapsedMs = Date.now() - started;
        const exit = /\nexit=(\d+)\n/u.exec(probe.stdout)?.[1];
        expect(exit, `the probe did not report git's exit: ${describeOutput(probe.output)}`).toBeDefined();
        expect(exit, `git hung until the ${GIT_COMMAND_TIMEOUT_SECONDS} s bound, as an interactive prompt would`).not.toBe("124");
        expect(exit, `an anonymous private fetch succeeded: ${describeOutput(probe.output)}`).not.toBe("0");
        expect(elapsedMs, "the anonymous failure was not prompt").toBeLessThan(GIT_COMMAND_TIMEOUT_SECONDS * 1000);
        expect(probe.output, "the failure did not come from the provider's refusal")
          .toMatch(/terminal prompts disabled|Authentication failed|could not read Username|not found|HTTP Basic: Access denied/iu);
        expect(countOccurrences(proxyLogs(proxyId), injectedLine(provider)), "a credential was injected with none bound")
          .toBe(injectedBefore);
      }, TEST_TIMEOUT_MS);
    });

    describe("with the token bound under the default ask write posture", () => {
      let standing: StandingSessionHandle;
      let sessionId: string;

      beforeAll(async () => {
        runOrThrow(fixture, ["credential", "set-source", provider.tokenName, "--from-source", provider.source]);
        const status = fixture.runfree(["credential", "status", provider.tokenName]);
        expect(status.output, `the bound token did not sync: ${describeOutput(status.output)}`).toContain("last sync: ok");
        standing = await startStandingSession(fixture);
        sessionId = standing.session.containerId;
      }, PROVISION_TIMEOUT_MS);

      afterAll(async () => {
        if (standing) await standing.release();
      }, PROVISION_TIMEOUT_MS);

      test("L1: the SSH remote resolves to HTTPS and ls-remote succeeds through the proxy with an injected credential", () => {
        const injectedBefore = countOccurrences(proxyLogs(proxyId), injectedLine(provider));
        const probe = sessionExec(sessionId, `
          set -euo pipefail
          cd /workspace
          printf 'container-git: %s\\n' "$(git --version)"
          printf 'get-url: %s\\n' "$(git ls-remote --get-url origin)"
          timeout ${GIT_COMMAND_TIMEOUT_SECONDS} ${NO_PROMPT_GIT} ls-remote origin
        `);
        expect(probe.status, `ls-remote over the rewritten remote failed: ${describeOutput(probe.output)}`).toBe(0);
        const version = /^container-git: (.+)$/mu.exec(probe.stdout)?.[1] ?? "";
        expect(version).toMatch(/^git version \d+\.\d+/u);
        console.log(`git provider ${provider.id}: container ${version}`);
        expect(probe.stdout, "the SSH remote was not rewritten to HTTPS").toContain(`get-url: ${provider.repository.httpsUrl}\n`);
        expect(probe.stdout, "ls-remote listed no refs").toMatch(/^[0-9a-f]{40}\t(?:HEAD|refs\/)/mu);
        expect(countOccurrences(proxyLogs(proxyId), injectedLine(provider)), `the proxy did not log "${injectedLine(provider)}"`)
          .toBeGreaterThan(injectedBefore);
      }, TEST_TIMEOUT_MS);

      test("L2: a private clone succeeds with the source bound", () => {
        const clone = cloneInSession(sessionId, provider.repository, "/tmp/rf-l2-clone");
        expect(clone.status, `private clone failed: ${describeOutput(clone.output)}`).toBe(0);
        const head = sessionExec(sessionId, "git -C /tmp/rf-l2-clone rev-parse --verify --quiet HEAD || echo empty-repository");
        expect(head.status, describeOutput(head.output)).toBe(0);
      }, TEST_TIMEOUT_MS);

      test.skipIf(!provider.lfsRepository)(
        `L5: an LFS batch download is a read and an LFS batch upload waits for approval${provider.lfsRepository ? "" : ` (skipped: ${provider.envNames.lfsRepo} is unset)`}`,
        async () => {
          const lfs = provider.lfsRepository;
          if (!lfs) return;
          // A committed pointer gives a real oid, so the download answer proves
          // an authorized lookup of an object that exists.
          const clone = sessionExec(sessionId, `
            set -euo pipefail
            rm -rf /tmp/rf-l5-clone
            timeout ${GIT_COMMAND_TIMEOUT_SECONDS} ${NO_PROMPT_GIT} clone --quiet --depth 1 --no-tags ${shellQuote(lfs.httpsUrl)} /tmp/rf-l5-clone
            cd /tmp/rf-l5-clone
            pointer="$(git grep -l -I '^version https://git-lfs.github.com/spec/v1' HEAD -- | head -n 1 | sed 's/^HEAD://')"
            test -n "$pointer"
            cat "$pointer"
          `);
          expect(clone.status, `no LFS pointer in ${provider.envNames.lfsRepo}: ${describeOutput(clone.output)}`).toBe(0);
          const oid = /^oid sha256:([0-9a-f]{64})$/mu.exec(clone.stdout)?.[1];
          const size = Number(/^size (\d+)$/mu.exec(clone.stdout)?.[1]);
          expect(oid, `could not parse the LFS pointer: ${describeOutput(clone.stdout)}`).toBeDefined();

          const download = await runDecidingHeldWrites({
            fixture, proxyId, sessionId,
            label: `${provider.id} lfs download`,
            script: lfsBatchScript(lfs, lfsBatchBody("download", oid as string, size), "/tmp/rf-l5-download.json")
              + " && cat /tmp/rf-l5-download.json",
            host: provider.host,
            pathPart: "/info/lfs/objects/batch",
            // Any held download would be a failure; denying it keeps that loud.
            decision: "deny",
          });
          expect(download.decided, "an LFS download batch request waited for write approval").toEqual([]);
          expect(download.exitCode, `the LFS download batch request failed: ${describeOutput(download.log)}`).toBe(0);
          const answer = parseProbeAnswer(download.log);
          expect(answeredByUpstream(answer) && answer.code === "200", `the provider did not answer the download batch: ${describeOutput(download.log)}`)
            .toBe(true);
          expect(download.log, "the download batch answer offered no download action").toMatch(/"download"\s*:/u);

          const uploadOid = crypto.randomBytes(32).toString("hex");
          const upload = await runDecidingHeldWrites({
            fixture, proxyId, sessionId,
            label: `${provider.id} lfs upload`,
            script: lfsBatchScript(lfs, lfsBatchBody("upload", uploadOid, 1), "/tmp/rf-l5-upload.json"),
            host: provider.host,
            pathPart: "/info/lfs/objects/batch",
            // Denied, so nothing reaches the provider and nothing is uploaded.
            decision: "deny",
          });
          expect(upload.decided, "the LFS upload batch request was not held for approval").toHaveLength(1);
          const denied = parseProbeAnswer(upload.log);
          expect(denied.code, `the denied upload batch was not refused by the proxy: ${describeOutput(upload.log)}`).toBe("403");
          expect(denied.blocked, "the upload refusal did not come from the proxy").toBeDefined();
        },
        TEST_TIMEOUT_MS,
      );

      test("L3: a push waits for approval and an approved push succeeds; the scratch branch is then deleted", async () => {
        const dir = "/tmp/rf-l3-clone";
        const clone = cloneInSession(sessionId, provider.repository, dir);
        expect(clone.status, `clone before push failed: ${describeOutput(clone.output)}`).toBe(0);
        const commit = sessionExec(sessionId,
          `git -C ${dir} -c user.name=runfree-live -c user.email=runfree-live@runfree.invalid commit --quiet --allow-empty -m 'runfree live provider probe'`);
        expect(commit.status, `scratch commit failed: ${describeOutput(commit.output)}`).toBe(0);

        const branch = scratchBranch();
        let pushed = false;
        let failure: unknown;
        try {
          const push = await runDecidingHeldWrites({
            fixture, proxyId, sessionId,
            label: `${provider.id} push`,
            script: pushScript(dir, `HEAD:refs/heads/${branch}`),
            host: provider.host,
            pathPart: "/git-receive-pack",
            decision: "approve",
          });
          pushed = push.exitCode === 0;
          expect(push.decided.length, `the push was never held for approval: ${describeOutput(push.log)}`).toBeGreaterThanOrEqual(1);
          expect(push.exitCode, `the approved push failed: ${describeOutput(push.log)}`).toBe(0);
          const remote = sessionExec(sessionId,
            `timeout ${GIT_COMMAND_TIMEOUT_SECONDS} ${NO_PROMPT_GIT} -C ${dir} ls-remote origin ${shellQuote(`refs/heads/${branch}`)}`);
          expect(remote.stdout, `the pushed branch is not on the provider: ${describeOutput(remote.output)}`).toContain(`refs/heads/${branch}`);
        } catch (error) {
          failure = error;
        }
        // Best effort, also through an approved push. Attempted even after a
        // failed push: the push may have landed before its result was lost.
        const cleanup = await runDecidingHeldWrites({
          fixture, proxyId, sessionId,
          label: `${provider.id} delete scratch branch`,
          script: pushScript(dir, `:refs/heads/${branch}`),
          host: provider.host,
          pathPart: "/git-receive-pack",
          decision: "approve",
        }).catch((error: unknown) => ({ exitCode: -1, log: String(error), decided: [] as readonly string[] }));
        if (cleanup.exitCode !== 0) {
          const message = `could not delete scratch branch ${branch} from ${provider.repository.httpsUrl}; delete it by hand: ${describeOutput(cleanup.log)}`;
          if (pushed && failure === undefined) failure = new Error(message);
          else console.warn(message);
        }
        if (failure !== undefined) throw failure;
      }, TEST_TIMEOUT_MS);
    });

    describe("with --deny-git-push on the provider host", () => {
      let standing: StandingSessionHandle;
      let sessionId: string;

      beforeAll(async () => {
        const rule = runOrThrow(fixture, ["host", "rules", provider.host, "--deny-git-push"]);
        expect(rule.output, `the git-push deny did not converge live: ${describeOutput(rule.output)}`)
          .toContain("effective policy: live now (effective policy generation sha256:");
        expect(fixture.runfree(["host", "rules", provider.host]).output, "git-push deny not persisted").toContain("gitPush=deny");
        standing = await startStandingSession(fixture);
        sessionId = standing.session.containerId;
      }, PROVISION_TIMEOUT_MS);

      afterAll(async () => {
        if (standing) await standing.release();
      }, PROVISION_TIMEOUT_MS);

      test("L3: a push is denied by the proxy with git-push-denied, with no credential injected and nothing forwarded", async () => {
        const dir = "/tmp/rf-l3-deny-clone";
        const clone = cloneInSession(sessionId, provider.repository, dir);
        expect(clone.status, `clone under the git-push deny failed: ${describeOutput(clone.output)}`).toBe(0);
        const commit = sessionExec(sessionId,
          `git -C ${dir} -c user.name=runfree-live -c user.email=runfree-live@runfree.invalid commit --quiet --allow-empty -m 'runfree live denied push'`);
        expect(commit.status, describeOutput(commit.output)).toBe(0);

        const injectedBefore = countOccurrences(proxyLogs(proxyId), injectedLine(provider));
        const verbose = enableProxyVerboseLogging(proxyId, `git-provider-deny-${provider.id}`);
        let push: ApprovalRun;
        try {
          // An approver is attached and would approve, so a push that reached
          // the ask path instead of the deny rule could still succeed.
          push = await runDecidingHeldWrites({
            fixture, proxyId, sessionId,
            label: `${provider.id} denied push`,
            script: pushScript(dir, `HEAD:refs/heads/${scratchBranch()}`),
            host: provider.host,
            pathPart: "/git-receive-pack",
            decision: "approve",
          });
        } finally {
          verbose.disable();
        }
        expect(push.exitCode, `a push under --deny-git-push succeeded: ${describeOutput(push.log)}`).not.toBe(0);
        expect(push.decided, "a push under --deny-git-push was held for approval instead of denied").toEqual([]);
        expect(push.log, `git did not see the proxy's 403: ${describeOutput(push.log)}`).toContain("403");
        const logs = proxyLogs(proxyId);
        expect(logs, "structured git-push denial event missing").toContain(`"reason":"git-push-denied","host":"${provider.host}"`);
        expect(logs, "the receive-pack POST was forwarded upstream")
          .not.toContain(`proxy: allowed method=POST scheme=https host=${provider.host} path=/${provider.repository.path}/git-receive-pack`);
        expect(countOccurrences(logs, injectedLine(provider)), "a credential was injected into a denied push").toBe(injectedBefore);
      }, TEST_TIMEOUT_MS);
    });
  });
}

let suiteConfig: ReturnType<typeof gitProviderSuiteConfig> | undefined;
let suiteConfigError: unknown;
try {
  suiteConfig = gitProviderSuiteConfig(process.env);
} catch (error) {
  suiteConfigError = error;
}

if (suiteConfigError !== undefined) {
  describe("git over HTTPS provider tranche", () => {
    test("the gated provider inputs are complete", () => {
      throw suiteConfigError;
    });
  });
} else if (suiteConfig?.kind === "skip") {
  describe.skip(`git over HTTPS provider tranche (skipped: ${suiteConfig.reason})`, () => {
    test("L1-L3, L5, L6 against a real provider", () => {});
  });
} else if (suiteConfig?.kind === "run") {
  for (const provider of suiteConfig.providers) defineProviderSuite(provider);
}
