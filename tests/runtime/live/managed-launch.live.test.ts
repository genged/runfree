// Managed built-in launch tranche, ported from `tests/runtime/sandbox.sh`.
//
// Proves the properties of launching a built-in agent through per-session
// admission: the launch reaches the pinned Claude CLI with exactly the strict
// Runfree MCP argv, `mcp auth` uses that same adapter, a customized agent is
// refused with the exact D-3 guidance before any Docker effect, the session can
// author desired control input but never sees a trusted `agent.env`, the inbox
// is delivered read-only from outside the project, and the project MCP file is
// visible and survives branch changes without startup recreating it.
//
// The exec-based probes inspect a held session. One-shot launches (`mcp auth`,
// the D-3 refusal) run after it ends, with the stand-in's hold marker removed
// so they can record their argv and exit.
//
// The launched Claude is the recording/long-lived stand-in (see
// `fixture.ts`): it records the argv it receives to a workspace file and
// stays up while held, so the same launch both proves the managed argv and holds
// the container open. It proves the launch argv, not the agent runtime.

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { docker, waitUntil } from "./docker.ts";
import {
  describeOutput,
  destroyLiveFixture,
  type CaptureResult,
  type LiveFixture,
  type LiveRuntimeBackend,
  MANAGED_CLAUDE_ARGV_RELATIVE_PATH,
  provisionSandboxFixture,
  startStandingSession,
  type StandingSessionHandle,
} from "./fixture.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RUNFREE_BIN = path.join(REPO_ROOT, "bin", "runfree.js");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 10 * 60_000;
const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the managed launch tranche");
  }
  return backend;
}

/** Runs the source CLI with extra env (for probes that need test-only env vars). */
function runfreeWithEnv(fixture: LiveFixture, args: readonly string[], extraEnv: NodeJS.ProcessEnv): CaptureResult {
  const result = childProcess.spawnSync(process.execPath, [RUNFREE_BIN, "--workspace", fixture.projectRoot, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...fixture.env, ...extraEnv },
    maxBuffer: CAPTURE_MAX_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const stderr = typeof result.stderr === "string" ? result.stderr : "";
  return Object.freeze({ status: result.status ?? 1, stdout, stderr, output: `${stdout}${stderr}` });
}

/** `docker exec` a login-shell script in the session, returning its capture. */
function sessionExec(containerId: string, script: string): CaptureResult {
  return docker(["exec", containerId, "zsh", "-lc", script]);
}

/** The last argv the recording Claude stand-in captured, from the workspace file. */
function lastRecordedClaudeArgv(fixture: LiveFixture): readonly string[] {
  const file = path.join(fixture.projectRoot, MANAGED_CLAUDE_ARGV_RELATIVE_PATH);
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  const last = lines.at(-1);
  if (!last) throw new Error(`no managed Claude argv was recorded in ${file}`);
  return JSON.parse(last) as readonly string[];
}

/**
 * Asserts the argv carries exactly one strict Runfree MCP config and add-dir.
 *
 * This is the whole managed-launch contract: the pinned CLI is reached with the
 * exact flags Runfree injects and nothing doubled.
 */
function assertStrictManagedClaudeArgv(argv: readonly string[], label: string): void {
  const count = (flag: string): number => argv.filter((argument) => argument === flag).length;
  expect(count("--mcp-config"), `${label}: exactly one --mcp-config`).toBe(1);
  expect(count("--strict-mcp-config"), `${label}: exactly one --strict-mcp-config`).toBe(1);
  expect(count("--add-dir"), `${label}: exactly one --add-dir`).toBe(1);
  expect(argv[argv.indexOf("--mcp-config") + 1], `${label}: --mcp-config names the Runfree config`)
    .toBe("/runfree/mcp/claude.json");
  expect(argv[argv.indexOf("--add-dir") + 1], `${label}: --add-dir names the inbox`).toBe("/runfree/inbox");
}

describe("managed built-in launch", () => {
  let fixture: LiveFixture;

  beforeAll(() => {
    requiredBackend();
    fixture = provisionSandboxFixture(REPO_ROOT);
  }, PROVISION_TIMEOUT_MS);

  afterAll(() => {
    if (fixture) destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  }, PROVISION_TIMEOUT_MS);

  describe("with a held standing session", () => {
    let standing: StandingSessionHandle;
    let sessionId: string;

    beforeAll(async () => {
      standing = await startStandingSession(fixture);
      sessionId = standing.session.containerId;
    }, PROVISION_TIMEOUT_MS);

    afterAll(async () => {
      if (standing) await standing.release();
    }, PROVISION_TIMEOUT_MS);

    test("the built-in launch reaches the pinned CLI with strict MCP argv", () => {
      // Attached records host publication. The entry gate and managed launcher
      // still have to run before the stand-in can record the received argv.
      waitUntil(() => {
        assertStrictManagedClaudeArgv(lastRecordedClaudeArgv(fixture), "held session launch");
        return true;
      }, { label: "the managed Claude launch to record strict MCP argv", timeoutMs: 30_000 });
    }, TEST_TIMEOUT_MS);

    test("the session sees the real project MCP file and a strict, read-only Claude config", () => {
      const hostMcpSha = sha256(path.join(fixture.projectRoot, ".mcp.json"));
      const probe = sessionExec(sessionId, `
        set -euo pipefail
        step() { printf 'mcp-visibility probe failed: %s\\n' "$1" >&2; exit 1; }
        node -e 'const c=require("node:crypto"),f=require("node:fs");process.stdout.write(c.createHash("sha256").update(f.readFileSync("/workspace/.mcp.json")).digest("hex"))' > /tmp/agent-mcp-sha
        test -f /workspace/.mcp.json || step "project MCP file is not visible"
        grep -q hostSentinel /workspace/.mcp.json || step "project MCP file lost its host sentinel"
        test -f /runfree/mcp/claude.json || step "the strict Runfree Claude config is not mounted"
        test "$(findmnt -T /runfree/mcp/claude.json -n -o TARGET)" = /runfree/mcp/claude.json || step "the Claude config is not its own mount"
        findmnt -T /runfree/mcp/claude.json -n -o OPTIONS | grep -Eq '(^|,)ro(,|$)' || step "the Claude config mount is not read-only"
        ! grep -q hostSentinel /runfree/mcp/claude.json || step "the strict Claude config leaked the project MCP server"
        ! (printf '{}\\n' > /runfree/mcp/claude.json) 2>/tmp/mcp-write.err || step "the strict Claude config is writable"
        grep -Eiq 'read-only file system|permission denied' /tmp/mcp-write.err || step "writing the Claude config failed for the wrong reason"
        test -d /workspace/.codex || step "the project .codex dir is not visible"
        test ! -e /workspace/.codex/config.toml || step "the host .codex/config.toml is not masked"
        test -z "$(find /workspace/.codex -mindepth 1 -print -quit)" || step "the .codex mount is not empty"
        cat /tmp/agent-mcp-sha
      `);
      expect(probe.status, `mcp visibility probe failed: ${describeOutput(probe.output)}`).toBe(0);
      expect(probe.stdout.trim(), "the session's project MCP bytes differ from the host file").toBe(hostMcpSha);
    }, TEST_TIMEOUT_MS);

    test("the session can author desired control input but sees no trusted agent-env file", () => {
      const probe = sessionExec(sessionId, `
        set -euo pipefail
        step() { printf 'desired-input probe failed: %s\\n' "$1" >&2; exit 1; }
        test -d /workspace/.runfree || step "/workspace/.runfree is not a directory"
        test -f /workspace/.runfree/network-policy.json || step "the desired network policy is not visible"
        test -f /workspace/.runfree/runfree.json || step "the project config is not visible"
        test ! -e /workspace/.runfree/config/agent.env || step "a trusted agent-env file is visible inside the project"
        grep -q api.github.com /workspace/.runfree/network-policy.json || step "the desired policy lost the seeded api.github.com host"
        grep -q github.com /workspace/.runfree/network-policy.json || step "the desired policy lost the seeded github.com host"
        cp /workspace/.runfree/network-policy.json /tmp/desired-policy.backup || step "could not read the desired network policy"
        printf '%s\\n' '{"version":2,"hosts":[]}' > /workspace/.runfree/network-policy.json || step "the desired network policy is not writable by the agent"
        grep -q '"version":2' /workspace/.runfree/network-policy.json || step "the agent write to the desired policy did not land"
        cp /tmp/desired-policy.backup /workspace/.runfree/network-policy.json || step "could not restore the desired network policy"
      `);
      expect(probe.status, `desired-input probe failed: ${describeOutput(probe.output)}`).toBe(0);
    }, TEST_TIMEOUT_MS);

    test("a session-planted Codex config symlink cannot redirect either host writer", () => {
      const outside = path.join(fixture.ownerRoot, "codex-config-outside-sentinel.toml");
      fs.writeFileSync(outside, "outside = true\n", { mode: 0o640 });
      const outsideMode = fs.statSync(outside).mode & 0o777;
      const planted = sessionExec(sessionId, `
        set -euo pipefail
        rm -f /home/agent/.codex/config.toml
        ln -s ${JSON.stringify(outside)} /home/agent/.codex/config.toml
        test -L /home/agent/.codex/config.toml
      `);
      expect(planted.status, `could not plant the Codex config symlink: ${describeOutput(planted.output)}`).toBe(0);

      const refused = fixture.runfree(["up", "--use-approved-policy"]);
      expect(refused.status, `up failed after the safe Codex refusal: ${describeOutput(refused.output)}`).toBe(0);
      expect(refused.output).toContain("Codex config update skipped");
      expect(refused.output).toContain("remove only this config.toml entry");
      expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
      expect(fs.statSync(outside).mode & 0o777).toBe(outsideMode);
      const stillLinked = sessionExec(sessionId, "test -L /home/agent/.codex/config.toml");
      expect(stillLinked.status, `the unsafe entry did not remain available for recovery: ${describeOutput(stillLinked.output)}`).toBe(0);

      const removed = sessionExec(sessionId, "rm -f /home/agent/.codex/config.toml");
      expect(removed.status, `could not remove only the unsafe entry: ${describeOutput(removed.output)}`).toBe(0);
      const retried = fixture.runfree(["up", "--use-approved-policy"]);
      expect(retried.status, `up did not recover after removing the unsafe entry: ${describeOutput(retried.output)}`).toBe(0);
      const recovered = sessionExec(sessionId, `
        set -euo pipefail
        test -f /home/agent/.codex/config.toml
        test ! -L /home/agent/.codex/config.toml
        grep -q '^cli_auth_credentials_store = "file"$' /home/agent/.codex/config.toml
        test -z "$(find /home/agent/.codex -maxdepth 1 -name '.config.toml.runfree-*.tmp' -print -quit)"
      `);
      expect(recovered.status, `Codex config recovery was incomplete: ${describeOutput(recovered.output)}`).toBe(0);
      expect(fs.readFileSync(outside, "utf8")).toBe("outside = true\n");
    }, TEST_TIMEOUT_MS);

    test("the inbox is delivered read-only from outside the project, and paste bytes round-trip", () => {
      // Host cleanliness and read-only boundary, proven inside the session.
      expect(
        fs.existsSync(path.join(fixture.projectRoot, ".runfree-images")),
        "the legacy .runfree-images mountpoint remains in the host project",
      ).toBe(false);
      const gitStatus = sessionExec(sessionId, "git -C /workspace status --porcelain");
      expect(gitStatus.output, "agent git status includes the legacy inbox").not.toContain(".runfree-images");

      const boundary = sessionExec(sessionId, `
        set -euo pipefail
        step() { printf 'inbox boundary probe failed: %s\\n' "$1" >&2; exit 1; }
        test "$RUNFREE_INBOX_CONTAINER_DIR" = /runfree/inbox || step "RUNFREE_INBOX_CONTAINER_DIR is not the fixed path"
        test "$(findmnt -T /runfree/inbox -n -o TARGET)" = /runfree/inbox || step "the inbox is not its own mount"
        findmnt -T /runfree/inbox -n -o OPTIONS | grep -Eq '(^|,)ro(,|$)' || step "the inbox mount is not read-only"
        test ! -e /workspace/.runfree-images || step "the legacy inbox mountpoint remains inside the session"
        ! touch /runfree/inbox/probe 2>/tmp/inbox-write.err || step "the inbox accepted a write"
        grep -Eiq 'read-only file system|permission denied' /tmp/inbox-write.err || step "the inbox write failed for the wrong reason"
      `);
      expect(boundary.status, `inbox boundary probe failed: ${describeOutput(boundary.output)}`).toBe(0);

      // A pasted image lands at the fixed container path with byte-identical
      // content — proof the read-only inbox actually delivers host bytes.
      const source = path.join(fixture.ownerRoot, "inbox-source.png");
      fs.writeFileSync(source, Buffer.from("\x89PNG\r\n\x1a\nrunfree-inbox-live-proof", "latin1"));
      const paste = runfreeWithEnv(fixture, ["inbox", "paste"], {
        RUNFREE_TEST_CLIPBOARD_IMAGE_PATH: source,
        RUNFREE_TEST_INBOX_RANDOM: "a8f3",
      });
      expect(paste.status, `inbox paste failed: ${describeOutput(paste.output)}`).toBe(0);
      const inboxPath = paste.stdout.trim();
      expect(inboxPath, "inbox paste did not print the fixed container path")
        .toMatch(/^\/runfree\/inbox\/clip-\d{4}-\d{2}-\d{2}-\d{6}-a8f3\.png$/u);
      const hostSha = sha256(source);
      const agentSha = sessionExec(sessionId, `node -e 'const c=require("node:crypto"),f=require("node:fs");process.stdout.write(c.createHash("sha256").update(f.readFileSync("${inboxPath}")).digest("hex"))'`);
      expect(agentSha.status, `could not read the pasted inbox image: ${describeOutput(agentSha.output)}`).toBe(0);
      expect(agentSha.stdout.trim(), "the session inbox bytes differ from the imported host bytes").toBe(hostSha);
    }, TEST_TIMEOUT_MS);
  });

  describe("one-shot launches (no standing session)", () => {
    test("mcp auth uses the same managed Claude adapter and strict MCP argv", () => {
      const approved = fixture.runfree(["mcp", "approve", "claude", "hostSentinel"]);
      expect(approved.status, `mcp approve failed: ${describeOutput(approved.output)}`).toBe(0);
      // Truncate first so the recorded line is unambiguously this launch's.
      fs.writeFileSync(path.join(fixture.projectRoot, MANAGED_CLAUDE_ARGV_RELATIVE_PATH), "");
      // The real Claude has no credentials and exits non-zero; the launch's exit
      // status is not the claim, its recorded argv is (matching the sandbox).
      fixture.runfree(["mcp", "auth", "claude", "hostSentinel", "--source", "project"]);
      assertStrictManagedClaudeArgv(lastRecordedClaudeArgv(fixture), "mcp auth launch");
    }, TEST_TIMEOUT_MS);

    test("a customized agent is refused before any Docker effect with the exact D-3 guidance", () => {
      // Register a configured, non-built-in agent and invoke it by name. The
      // refusal needs no session and cannot leave residue.
      //
      // This comment used to claim the refusal fired "before the lifecycle lock
      // or any Docker command". That was wrong until 2026-09-21: the check sat
      // inside the launch, after `startRuntime`, so the CLI built the whole
      // runtime before reporting that custom agents are unsupported — this case
      // took 18.1 s in the 2026-09-21 live run. It is true now, and the
      // ordering is what `runtime.test.ts` pins by asserting the refusal issues
      // no Docker command at all; wall-clock here is too noisy to assert on.
      const configPath = path.join(fixture.projectRoot, ".runfree", "runfree.json");
      const original = fs.readFileSync(configPath, "utf8");
      const config = JSON.parse(original) as { agents?: Record<string, unknown> };
      config.agents = { ...(config.agents ?? {}), customTool: { command: "some-custom-tool" } };
      fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
      try {
        const refused = fixture.runfree(["customTool"]);
        // The product's own code for an unhandled refusal is 1 — never a shell
        // signal code. Assert that and the recovery command token, not the prose.
        expect(refused.status, `custom-agent launch exit code: ${describeOutput(refused.output)}`).toBe(1);
        expect(refused.output, "the refusal does not name the built-in-only rule")
          .toContain("per-session launch supports only the built-in agents");
        expect(refused.output, "the refusal does not point at the `runfree shell` escape hatch")
          .toContain("runfree shell");
      } finally {
        fs.writeFileSync(configPath, original);
      }
    }, TEST_TIMEOUT_MS);

    test("a project MCP branch change is not blocked and startup does not recreate a removed file", () => {
      const mcpPath = path.join(fixture.projectRoot, ".mcp.json");
      git(fixture.projectRoot, ["checkout", "no-mcp"]);
      expect(fs.existsSync(mcpPath), "the no-mcp branch still has a project MCP file").toBe(false);
      const up = fixture.runfree(["up"]);
      expect(up.status, `runfree up failed on the no-mcp branch: ${describeOutput(up.output)}`).toBe(0);
      expect(fs.existsSync(mcpPath), "runtime startup recreated a removed project MCP file").toBe(false);
      git(fixture.projectRoot, ["checkout", "main"]);
      expect(fs.existsSync(mcpPath), "the main branch lost its project MCP file").toBe(true);
    }, TEST_TIMEOUT_MS);
  });
});

function sha256(file: string): string {
  return childProcess.spawnSync(process.execPath, [
    "-e",
    'const c=require("node:crypto"),f=require("node:fs");process.stdout.write(c.createHash("sha256").update(f.readFileSync(process.argv[1])).digest("hex"))',
    file,
  ], { encoding: "utf8" }).stdout ?? "";
}

function git(projectRoot: string, args: readonly string[]): void {
  const result = childProcess.spawnSync("git", ["-C", projectRoot, ...args], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${describeOutput(String(result.stderr ?? ""))}`);
  }
}
