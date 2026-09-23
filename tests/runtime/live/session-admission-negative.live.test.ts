// Negative live tranche for per-session admission.
//
// The nominal tranche proves the happy path: a session is allocated, created
// and started, registered as provisioning, proven running by the one post-start
// inspection, and revoked. This file proves the refusals — that the machinery
// fails closed when the environment is wrong, and that the controls it depends
// on are load-bearing rather than incidental.
//
// Every test here follows the same shape, because a live assertion that cannot
// fail is worse than no assertion and this repository has already shipped four
// of those:
//
//   1. establish the bad condition,
//   2. prove the product refuses,
//   3. remove the bad condition and prove the product accepts.
//
// Step 3 is what makes step 2 mean anything. Without it, a refusal for an
// unrelated reason reads as a pass.
//
// Scope note: this file covers the refusals reachable without a public session
// launch. Launch-path behavior is proven live by the attached, crash, and
// drift tranches through the production admission launch. Session grant
// separation still has no live proof anywhere (docs/security.md carries the
// same caveat); it is not stubbed here, because a skipped test that looks like
// coverage is the same failure mode as a vacuous one.

import path from "node:path";
import { spawn } from "node:child_process";
import { sessionIpAssignmentReadCommand, sessionIpReuseFenceCommand } from "../../../packages/cli/src/runtime/session-file-publisher.ts";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import {
  destroyLiveFixture,
  describeOutput,
  provisionLiveFixture,
  type LiveFixture,
  type LiveRuntimeBackend,
} from "./fixture.ts";
import {
  composeProjectName,
  composeServiceContainerId,
  projectAgentImageId,
  containerAddressOnNetwork,
  docker,
  dockerOrThrow,
  forceRemoveContainer,
  internalNetworkId,
  LIVE_TEST_LABEL,
  startLiveTestContainer,
  waitUntil,
} from "./docker.ts";
import { runNominalAdmissionSlice } from "./session-admission-slice.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROVISION_TIMEOUT_MS = 30 * 60_000;
const TEST_TIMEOUT_MS = 15 * 60_000;
const PROXY_READY_TIMEOUT_MS = 120_000;

// One agent is enough for every refusal here: the refusals are properties of
// admission, not of which built-in launches, so running all three would triple
// the probes for the same proof.
const PROBE_AGENT = "claude" as const;

// The two load-bearing *success* probes rotate the agent instead of repeating
// `claude`. The retired nominal tranche paid a fixture and three launches to
// admit, prove and revoke one session per built-in; what it proved per agent is
// exactly what a successful slice proves, so rotating the agent across probes
// this tranche already runs keeps all three built-ins covered for free.
// Positional, not random: a rotation a run cannot reproduce is not evidence.
const RECOVERY_PROBE_AGENT = "codex" as const;
const RESTART_PROBE_AGENT = "pi" as const;

function requiredBackend(): LiveRuntimeBackend {
  const backend = process.env.TEST_RUNTIME_BACKEND;
  if (backend !== "docker-desktop" && backend !== "orbstack") {
    throw new Error("TEST_RUNTIME_BACKEND must be docker-desktop or orbstack for the negative admission tranche");
  }
  return backend;
}

describe("per-session admission refuses and its controls are load-bearing", () => {
  const backend = requiredBackend();
  let fixture: LiveFixture;
  let project: string;
  let networkId: string;
  let proxyId: string;
  let agentImage: string;

  beforeAll(() => {
    fixture = provisionLiveFixture({ repoRoot: REPO_ROOT });
    project = composeProjectName(fixture);
    networkId = internalNetworkId(project);
    proxyId = composeServiceContainerId(project, "proxy");
    // A test container that must behave like a session uses the same project
    // agent image the runtime built, resolved by its daemon labels.
    agentImage = projectAgentImageId(project);
  }, PROVISION_TIMEOUT_MS);

  // No explicit hook timeout: the `runtime-live` project sets `hookTimeout` to
  // 40 minutes, which is already above the 30-minute bound the other tranches
  // pass here. Adding one would tighten the backstop, not extend it.
  afterAll(() => {
    if (!fixture) return;
    destroyLiveFixture(fixture, { keepHostState: process.env.TEST_RUNTIME_KEEP_PROJECT === "1" });
  });

  test("IP reuse drains queued Linux connections and a timed-out fence can be retried", async () => {
    const serverPid = dockerOrThrow("find request proxy", ["exec", "--user", "0:0", proxyId, "node", "-e", `
      const fs = require("node:fs");
      const pids = fs.readdirSync("/proc").filter((pid) => {
        if (!/^[0-9]+$/.test(pid)) return false;
        try { return /^Uid:\\s+1001\\s/m.test(fs.readFileSync("/proc/" + pid + "/status", "utf8"))
          && fs.readFileSync("/proc/" + pid + "/cmdline", "utf8").includes("/app/proxy/server.js"); }
        catch { return false; }
      });
      if (pids.length !== 1) throw new Error("request proxy identity is ambiguous");
      process.stdout.write(pids[0]);
    `]);
    const signal = (name: string) => dockerOrThrow(`request proxy ${name}`, ["exec", "--user", "0:0", proxyId, "node", "-e", "process.kill(Number(process.argv[1]), process.argv[2])", serverPid, name]);
    const connections = (address: string) => dockerOrThrow("inspect queued TCP", [
      "exec", "--user", "0:0", proxyId, "ss", "-H", "-n", "-4", "-t", "state", "connected", "exclude", "time-wait", "dst", address, "sport", "=", ":8080",
    ]);
    const readAssignment = () => dockerOrThrow("read fence precondition", sessionIpAssignmentReadCommand(proxyId, "127.0.0.1").args);
    const command = sessionIpReuseFenceCommand(proxyId, "127.0.0.1", "a".repeat(64), readAssignment());
    const clientPidPath = "/tmp/runfree-ip-fence-live-client.pid";
    let stopped = false;
    let fenceProcess: ReturnType<typeof spawn> | undefined;
    try {
      signal("SIGSTOP");
      stopped = true;
      dockerOrThrow("queue old and unrelated connections", ["exec", "-d", "--user", "0:0", proxyId, "node", "-e", `
        const fs = require("node:fs");
        const net = require("node:net");
        fs.writeFileSync(${JSON.stringify(clientPidPath)}, String(process.pid));
        for (const localAddress of ["127.0.0.1", "127.0.0.2"]) {
          const socket = net.connect({ host: "127.0.0.1", port: 8080, localAddress });
          socket.on("error", () => {});
          socket.on("connect", () => socket.write("CONNECT example.com:443 HTTP/1.1\\r\\nHost:"));
        }
      `]);
      try {
        waitUntil(() => connections("127.0.0.1") !== "" && connections("127.0.0.2") !== "", {
          label: "queued sockets from both addresses", timeoutMs: 10_000,
        });
      } catch (error) {
        throw new Error(`${error}\n${dockerOrThrow("dump sockets", ["exec", proxyId, "ss", "-H", "-n", "-t", "-a"])}`);
      }
      fenceProcess = spawn("docker", [...command.args], { stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      fenceProcess.stderr?.on("data", (chunk) => { stderr += chunk; });
      const finished = new Promise<number | null>((resolve, reject) => {
        fenceProcess?.once("error", reject);
        fenceProcess?.once("close", resolve);
      });
      // Some Linux versions cannot destroy unaccepted sockets with ss -K.
      // Either way, the stopped consumer cannot acknowledge retirement, so
      // the host must refuse and retain its fence until a later retry.
      waitUntil(() => docker(["exec", proxyId, "test", "-f", "/run/runfree-sessions/ip-reuse/requests/127.0.0.1.json"]).status === 0, {
        label: "executor owns the assignment", timeoutMs: 10_000,
      });
      expect(docker(["exec", "--user", "0:0", proxyId, "flock", "--nonblock", "/run/runfree-sessions/ip-reuse", "true"]).status).toBe(1);
      expect(await finished).toBe(1);
      expect(docker(["exec", "--user", "0:0", proxyId, "flock", "--nonblock", "/run/runfree-sessions/ip-reuse", "true"]).status).toBe(0);
      expect(stderr).toContain("retry the launch");
      expect(connections("127.0.0.2"), "the IP fence preserves the other address").not.toBe("");
      const assignment = () => JSON.parse(dockerOrThrow("read IP assignment", ["exec", "--user", "0:0", proxyId, "cat", "/run/runfree-sessions/ip-reuse/requests/127.0.0.1.json"]));
      expect(assignment().state).toBe("draining");
      signal("SIGCONT");
      stopped = false;
      const retried = docker(sessionIpReuseFenceCommand(proxyId, "127.0.0.1", "a".repeat(64), readAssignment()).args);
      expect(retried.status, retried.output).toBe(0);
      expect(assignment()).toMatchObject({ state: "ready", sessionKey: "a".repeat(64) });
      expect(connections("127.0.0.1")).toBe("");
      expect(connections("127.0.0.2"), "the unrelated connection survives retry").not.toBe("");
      const current = assignment();
      const delayed = docker(command.args);
      expect(delayed.status).toBe(1);
      expect(delayed.output).toContain("IP assignment changed");
      expect(assignment()).toEqual(current);
    } finally {
      if (stopped) signal("SIGCONT");
      if (fenceProcess?.exitCode === null) fenceProcess.kill();
      docker(["exec", "--user", "0:0", proxyId, "node", "-e", `
        const fs = require("node:fs");
        try { process.kill(Number(fs.readFileSync(${JSON.stringify(clientPidPath)}, "utf8"))); } catch {}
        fs.rmSync(${JSON.stringify(clientPidPath)}, { force: true });
      `]);
    }
  }, TEST_TIMEOUT_MS);

  test("an unadmitted container on the internal network fails admission closed", () => {
    const rogue = "runfree-negative-unknown-participant";
    forceRemoveContainer(rogue);
    try {
      startLiveTestContainer({
        name: rogue,
        image: agentImage,
        networkId,
        command: ["sleep", "3600"],
      });

      const refused = runNominalAdmissionSlice({ fixture, backend, agent: PROBE_AGENT, expect: "failure" });

      // Two refusals can legitimately catch this, and which one fires depends on
      // where the container is noticed first:
      //
      //   - reconciliation, as `untrusted-container: container lacks exact
      //     Runfree session identity proof` — a container in the project's own
      //     inventory that carries no session identity; and
      //   - the network baseline, as `Docker internal network contains an
      //     unknown participant`.
      //
      // Observed live: the reconciliation path fires first, because a container
      // running this project's selected agent image on its internal network is
      // already in scope for the project inventory before the baseline is
      // consulted. Accepting either keeps the assertion about *this* control
      // without pinning which layer notices, while still being far narrower
      // than "the probe failed".
      expect(
        refused.output.toLowerCase(),
        `admission failed, but not on the unadmitted container: ${describeOutput(refused.output, 4000)}`,
      ).toMatch(/untrusted-container|unknown participant/u);
    } finally {
      forceRemoveContainer(rogue);
    }

    // Load-bearing half: a probe must now pass. Without this, any unrelated
    // failure above would read as a successful refusal. Runs as `codex` so the
    // built-in is admitted, proved and revoked somewhere in the suite.
    runNominalAdmissionSlice({ fixture, backend, agent: RECOVERY_PROBE_AGENT, expect: "success" });
  }, TEST_TIMEOUT_MS);

  test("dropping NET_ADMIN is what prevents a container claiming another address", () => {
    // Session containers are created with NET_ADMIN and NET_RAW dropped. The
    // property that matters is that a container cannot give itself a second
    // address on the shared network and speak as another session.
    //
    // This is proven with `ip addr add`, which needs NET_ADMIN, rather than with
    // forged packets: the agent image ships iproute2, so the attempt uses a tool
    // that is actually present, and the mutation below shows the capability drop
    // is the thing stopping it.
    const constrained = "runfree-negative-cap-constrained";
    const mutated = "runfree-negative-cap-mutated";
    const claimedAddress = "172.30.0.240/16";
    const claim = ["ip", "addr", "add", claimedAddress, "dev", "eth0"];

    for (const name of [constrained, mutated]) forceRemoveContainer(name);
    try {
      startLiveTestContainer({
        name: constrained,
        image: agentImage,
        networkId,
        runArgs: ["--cap-drop", "NET_ADMIN", "--cap-drop", "NET_RAW", "--user", "0:0"],
        command: ["sleep", "600"],
      });
      // Run as root inside the container deliberately: root without NET_ADMIN
      // must still fail. Testing this as an unprivileged user would prove only
      // that the user is unprivileged, which is a weaker and different claim.
      const denied = docker(["exec", constrained, ...claim]);
      expect(denied.status, `claiming ${claimedAddress} succeeded without NET_ADMIN: ${describeOutput(denied.output)}`)
        .not.toBe(0);

      startLiveTestContainer({
        name: mutated,
        image: agentImage,
        networkId,
        runArgs: ["--cap-add", "NET_ADMIN", "--user", "0:0"],
        command: ["sleep", "600"],
      });
      const allowed = docker(["exec", mutated, ...claim]);
      // The mutation. If this also fails, the test above proved nothing about
      // capabilities — something else was refusing the command — and the
      // constrained assertion must not be trusted.
      expect(
        allowed.status,
        `restoring NET_ADMIN did not make the address claim succeed, so the constrained case proves nothing about capabilities: ${describeOutput(allowed.output)}`,
      ).toBe(0);
    } finally {
      for (const name of [constrained, mutated]) forceRemoveContainer(name);
    }
  }, TEST_TIMEOUT_MS);

  test("the daemon refuses a second container starting on an address in use", () => {
    // Production does not depend on create-time IP reservation: the host
    // registry allocates addresses and Docker's static IP enforces rather than
    // arbitrates. What must hold is that two containers cannot hold the same
    // address at once, and Docker only decides that at start.
    const competitor = "runfree-negative-address-conflict";
    // The proxy persistently holds an address on the internal network, so it is
    // the stand-in for "an address already in use" now that there is no shared
    // agent; a competitor claiming it must be refused at start.
    const occupied = containerAddressOnNetwork(proxyId, networkId);

    forceRemoveContainer(competitor);
    try {
      // Create is expected to succeed — the endpoint does not exist until
      // start, so there is nothing to conflict with yet.
      const created = docker([
        "create",
        "--name",
        competitor,
        "--label",
        `${LIVE_TEST_LABEL}=session-admission-negative`,
        "--network",
        networkId,
        "--ip",
        occupied,
        agentImage,
        "sleep",
        "600",
      ]);
      expect(created.status, `could not create the competing container: ${describeOutput(created.output)}`).toBe(0);

      const started = docker(["start", competitor]);
      expect(
        started.status,
        `a second container started on ${occupied}, which the proxy already holds: ${describeOutput(started.output)}`,
      ).not.toBe(0);
    } finally {
      forceRemoveContainer(competitor);
    }
  }, TEST_TIMEOUT_MS);

  test("admission still converges after the proxy restarts", () => {
    const startedAtBefore = dockerOrThrow("proxy start time", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]);

    dockerOrThrow("proxy restart", ["restart", proxyId]);

    waitUntil(
      () => {
        const startedAtAfter = dockerOrThrow("proxy start time", ["inspect", "-f", "{{.State.StartedAt}}", proxyId]);
        if (startedAtAfter === startedAtBefore) return false;
        const running = dockerOrThrow("proxy state", ["inspect", "-f", "{{.State.Running}}", proxyId]);
        if (running !== "true") return false;
        // Readiness is asked of the product rather than inferred from logs.
        // Docker retains log output across a restart, so a log-based wait can
        // match the previous boot and return immediately — a stale-log race this
        // suite has already been burned by once.
        return fixture.runfree(["status"]).status === 0;
      },
      { label: "the proxy to restart and report ready", timeoutMs: PROXY_READY_TIMEOUT_MS },
    );

    // The claim under test: a restarted proxy reconciles to a state that still
    // admits a fresh session. A proxy that came back holding stale session
    // authority, or one that came back unable to converge at all, fails here.
    // Runs as `pi` so the third built-in is admitted, proved and revoked too.
    runNominalAdmissionSlice({ fixture, backend, agent: RESTART_PROBE_AGENT, expect: "success" });
  }, TEST_TIMEOUT_MS);
});
