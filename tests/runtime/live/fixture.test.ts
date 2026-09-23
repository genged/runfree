// Fault-injection self-tests for the sandbox fixture's load-bearing helpers.
//
// These run in the ordinary (non-Docker) suite: the standing-session container
// resolver is the thing every ported `docker exec` probe trusts to name a real
// container, so a resolver that returned an empty id on "no session" would let
// every probe exec into the daemon's default and pass vacuously. The resolver
// takes an injectable command runner precisely so this can prove it fails
// closed without a live daemon.

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { afterEach, describe, expect, test } from "vitest";
import { resumeStub } from "./agent-stub.ts";
import { parseSessionSample, SESSION_SAMPLE_SCRIPT, SessionObservation } from "./session-sampler.ts";

import type { CaptureResult } from "./fixture.ts";
import { LIVE_RUN_ID_ENV, liveRunToken, newLiveRunToken } from "./run-token.ts";
import {
  describeOutput,
  assertCleanSessionReport,
  isLeakedSandboxRuntime,
  releaseStandingSessions,
  resolveStandingSessionContainer,
  sessionAgentContainerIds,
  unexplainedAdmittedIps,
} from "./fixture.ts";

function stubRun(stdout: string, status = 0): (args: readonly string[]) => CaptureResult {
  return () => Object.freeze({ status, stdout, stderr: "", output: stdout });
}

const PROJECT = "runfree-0123456789ab";
const EXACT_ID = "a".repeat(64);

describe("standing-session container resolver fails closed", () => {
  test("no running session-agent container throws rather than returning an empty id", () => {
    expect(() => resolveStandingSessionContainer(PROJECT, stubRun("\n"))).toThrow(/found 0/u);
  });

  test("more than one session-agent container throws", () => {
    expect(() => resolveStandingSessionContainer(PROJECT, stubRun(`${EXACT_ID}\n${"b".repeat(64)}\n`)))
      .toThrow(/found 2/u);
  });

  test("a truncated (short) id is refused, never used as an exec target", () => {
    expect(() => resolveStandingSessionContainer(PROJECT, stubRun("abc123\n"))).toThrow(/exact 64-hex/u);
  });

  test("exactly one 64-hex id resolves", () => {
    expect(resolveStandingSessionContainer(PROJECT, stubRun(`${EXACT_ID}\n`))).toBe(EXACT_ID);
  });

  test("a non-zero docker exit is surfaced, not read as zero containers", () => {
    expect(() => sessionAgentContainerIds(PROJECT, stubRun("boom", 1))).toThrow(/could not list session-agent/u);
  });
});

describe("the admitted-IP explanation invariant fails on an unexplained IP", () => {
  test("an IP no resolved host explains is reported", () => {
    expect(unexplainedAdmittedIps(["1.2.3.4"], '{"hosts":{"api.github.com":["5.6.7.8"]}}')).toEqual(["1.2.3.4"]);
  });

  test("an IP a resolved host explains is not reported", () => {
    expect(unexplainedAdmittedIps(["5.6.7.8"], '{"hosts":{"api.github.com":["5.6.7.8"]}}')).toEqual([]);
  });

  test("an empty admitted set is trivially fully explained", () => {
    expect(unexplainedAdmittedIps([], "<snapshot-absent>")).toEqual([]);
  });
});

describe("describeOutput keeps the end of an over-long body", () => {
  test("a long startup log keeps its head and the refusal at its tail", () => {
    const refusal = "runfree: proxy firewall readiness timed out";
    const body = `${"#4 CACHED Container starting\n".repeat(200)}${refusal}\n`;
    const rendered = describeOutput(body, 400);
    expect(rendered.length).toBeLessThanOrEqual(403);
    expect(rendered.startsWith("#4 CACHED Container starting")).toBe(true);
    expect(rendered.endsWith(refusal)).toBe(true);
    expect(rendered).toContain(" … ");
  });

  test("a body within the limit is rendered whole", () => {
    expect(describeOutput("one\ntwo  three\n", 400)).toBe("one two three");
    expect(describeOutput("\n\n")).toBe("<empty>");
  });
});

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});
function temporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "live-harness-selftest."));
  roots.push(root);
  return root;
}
async function eventually(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error("harness condition did not arrive");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
const sampleFile = { sourceIp: "172.30.0.20", nonce: "initial", inspectedAt: "2099-01-01T00:00:00Z", aliveUntil: "2099-01-01T00:00:30Z" };
const kernelSet = { nftables: [{ set: { family: "inet", table: "runfree_proxy", name: "session_ipv4", elem: [sampleFile.sourceIp] } }] };

test("group cleanup stops every session before checking the project's authority", async () => {
  const live = new Set(["a", "b", "c"]);
  let verified = false;
  await releaseStandingSessions([...live].map((id) => ({ async stop() { live.delete(id); } })), async () => {
    expect([...live]).toEqual([]);
    verified = true;
  });
  expect(verified).toBe(true);
});

test("a failed session stop still releases its peers and reports both stop and cleanup failures", async () => {
  const live = new Set(["a", "b"]);
  let checked = false;
  const stopFailure = new Error("owner teardown failed");
  const cleanupFailure = new Error("repair required");
  const result = releaseStandingSessions([
    { async stop() { live.delete("a"); } },
    { async stop() { throw stopFailure; } },
  ], async () => {
    expect([...live]).toEqual(["b"]);
    checked = true;
    throw cleanupFailure;
  });
  await expect(result).rejects.toMatchObject({ errors: [stopFailure, cleanupFailure] });
  expect(checked).toBe(true);
});

test("the persistent sampler reads changed files and kernel output, and exits on input EOF", async () => {
  const root = temporaryRoot();
  const directory = path.join(root, "sessions");
  fs.mkdirSync(directory);
  const file = path.join(directory, "session.json");
  fs.writeFileSync(file, JSON.stringify(sampleFile));
  const nft = path.join(root, "nft");
  fs.writeFileSync(nft, `#!/bin/sh\ncat '${root}/kernel.json'\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(root, "kernel.json"), JSON.stringify(kernelSet));
  const child = childProcess.spawn(process.execPath, ["-e", SESSION_SAMPLE_SCRIPT,
    JSON.stringify({ directory, nft, intervalMs: 20, timeoutMs: 5000 }),
  ], { stdio: ["pipe", "pipe", "pipe"] });
  const closed = once(child, "close");
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  try {
    await eventually(() => output.includes("\n"));
    const first = parseSessionSample(output.split("\n")[0]);
    expect(first.ips).toEqual([sampleFile.sourceIp]);
    expect(first.files).toEqual([sampleFile]);
    fs.writeFileSync(path.join(directory, "next.tmp"), JSON.stringify({ ...sampleFile, nonce: "renewed" }));
    fs.renameSync(path.join(directory, "next.tmp"), file);
    await eventually(() => output.includes('"renewed"'));
    child.stdin.end();
    expect((await closed)[0]).toBe(0);
  } finally { child.kill("SIGKILL"); await closed; }
});

test("renewal observation rejects authority loss, malformed kernel evidence, and missed samples", () => {
  const observation = new SessionObservation(100);
  const sample = parseSessionSample(JSON.stringify({ elapsedMs: 1, files: [sampleFile], nft: kernelSet }));
  observation.accept(sample);
  const nonces = observation.watch(sampleFile.sourceIp);
  observation.accept({ ...sample, elapsedMs: 20 });
  observation.accept({ ...sample, elapsedMs: 30 });
  expect([...nonces]).toEqual(["initial"]);
  observation.accept({ ...sample, elapsedMs: 40, files: [{ ...sampleFile, nonce: "renewed" }] });
  expect([...nonces]).toEqual(["initial", "renewed"]);
  observation.accept({ ...sample, elapsedMs: 60, ips: [] });
  observation.accept({ ...sample, elapsedMs: 80 });
  expect(() => observation.check()).toThrow(/lost file or kernel authority/u);
  const missingFile = new SessionObservation();
  missingFile.watch(sampleFile.sourceIp);
  missingFile.accept({ ...sample, files: [] });
  expect(() => missingFile.check()).toThrow(/lost file or kernel authority/u);
  const gap = new SessionObservation(100);
  gap.accept(sample);
  gap.accept({ ...sample, elapsedMs: 200 });
  expect(() => gap.check()).toThrow(/observation gap/u);
  const ignoredLeaseOverride = new SessionObservation();
  ignoredLeaseOverride.watch(sampleFile.sourceIp, 10_000);
  ignoredLeaseOverride.accept(sample);
  expect(() => ignoredLeaseOverride.check()).toThrow(/short lease/u);
  expect(() => parseSessionSample(JSON.stringify({ elapsedMs: 1, files: [], nft: { nftables: [] } })))
    .toThrow(/exact session kernel set/u);
  expect(() => parseSessionSample(JSON.stringify({ elapsedMs: 1, files: [{}], nft: kernelSet })))
    .toThrow(/malformed session file/u);
});

test("a repaired, missing, or failed cleanup report cannot pass as product convergence", () => {
  const report = { v: 1, kind: "runfree-session-admission-crash-report", records: [], residualContainers: 0, lifecycleRegistryEmpty: true };
  expect(() => assertCleanSessionReport(0, JSON.stringify(report))).not.toThrow();
  expect(() => assertCleanSessionReport(0, JSON.stringify({ ...report, harnessReset: true }))).toThrow(/repair/u);
  expect(() => assertCleanSessionReport(0, JSON.stringify({ ...report, residualContainers: 1 }))).toThrow(/residue/u);
  expect(() => assertCleanSessionReport(0, "")).toThrow(/cleanup failed/u);
  expect(() => assertCleanSessionReport(1, JSON.stringify(report))).toThrow(/cleanup failed/u);
});

test("the persistent reader fails on unreadable evidence and a failed kernel command", () => {
  const root = temporaryRoot();
  const file = path.join(root, "session.json");
  fs.writeFileSync(file, "broken JSON");
  const config = { directory: root, nft: path.join(root, "nft"), intervalMs: 20, timeoutMs: 1000 };
  const run = () => childProcess.spawnSync(process.execPath, ["-e", SESSION_SAMPLE_SCRIPT, JSON.stringify(config)], {
    encoding: "utf8", input: "", timeout: 2000,
  });
  const brokenFile = run();
  expect(brokenFile.status).toBe(1);
  expect(brokenFile.stdout).toBe("");
  fs.writeFileSync(file, JSON.stringify(sampleFile));
  fs.writeFileSync(config.nft, "#!/bin/sh\nexit 7\n", { mode: 0o755 });
  const brokenKernel = run();
  expect(brokenKernel.status).toBe(1);
  expect(brokenKernel.stdout).toBe("");
});

test("resume remains running until released, then exits normally only for typed resume argv", async () => {
  const directory = path.join(temporaryRoot(), "resume ' with spaces");
  const script = `${resumeStub(directory)}\nexit 19\n`;
  expect(childProcess.spawnSync("sh", ["-c", script, "stub", "--other"]).status).toBe(19);
  const child = childProcess.spawn("sh", ["-c", script, "stub", "--resume", "conversation"], { stdio: "ignore" });
  const closed = once(child, "close");
  try {
    await eventually(() => fs.existsSync(path.join(directory, "ready")));
    expect(child.exitCode).toBeNull();
    fs.writeFileSync(path.join(directory, "release"), "");
    expect((await closed)[0]).toBe(0);
  } finally { child.kill("SIGKILL"); await closed; }
});

describe("leaked-runtime classification separates siblings from earlier runs", () => {
  // The live project runs files in parallel, so the guard that refuses to
  // provision beside a leaked sandbox runtime must not refuse beside a sibling
  // file's live one. Both directions are proven here because both have a
  // failure mode: too strict and a parallel run cannot start at all; too loose
  // and an earlier run's residue silently holds the networks and the MCP
  // callback port that the next run then fails on, minutes in, with no cause
  // named.
  const TOKEN = "0123456789ab";
  const OTHER = "ba9876543210";
  const mounts = (source: string): string => JSON.stringify([{ Type: "bind", Source: source, Destination: "/workspace" }]);

  test("a container from this run is not a leak", () => {
    expect(isLeakedSandboxRuntime(mounts(`/tmp/runfree-runtime-sandbox-project.${TOKEN}.XkP2q1/repo`), TOKEN)).toBe(false);
  });

  test("a container from another run is a leak", () => {
    expect(isLeakedSandboxRuntime(mounts(`/tmp/runfree-runtime-sandbox-project.${OTHER}.XkP2q1/repo`), TOKEN)).toBe(true);
  });

  test("a maintainer's own project is never a leak", () => {
    expect(isLeakedSandboxRuntime(mounts("/Users/mg/code/runfree"), TOKEN)).toBe(false);
    expect(isLeakedSandboxRuntime(JSON.stringify([]), TOKEN)).toBe(false);
  });

  test("a token that is a prefix of another does not read as this run's", () => {
    // Without the trailing separator in the match, run `0123456789ab` would
    // claim every container of a run whose token merely started with it.
    const longer = `${TOKEN}cd`;
    expect(isLeakedSandboxRuntime(mounts(`/tmp/runfree-runtime-sandbox-project.${longer}.XkP2q1/repo`), TOKEN)).toBe(true);
  });
});

describe("live run token", () => {
  afterEach(() => { delete process.env[LIVE_RUN_ID_ENV]; });

  test("an inherited token is used verbatim, so every worker agrees", () => {
    process.env[LIVE_RUN_ID_ENV] = "abcdef012345";
    expect(liveRunToken()).toBe("abcdef012345");
  });

  test("a malformed token is refused rather than normalized", () => {
    process.env[LIVE_RUN_ID_ENV] = "../escape";
    expect(() => liveRunToken()).toThrow(/12 lowercase hex characters/u);
  });

  test("a fresh token matches the pattern the guard matches on", () => {
    expect(newLiveRunToken()).toMatch(/^[0-9a-f]{12}$/u);
    expect(newLiveRunToken()).not.toBe(newLiveRunToken());
  });

  test("without an inherited token the process keeps one stable token", () => {
    expect(liveRunToken()).toBe(liveRunToken());
  });
});
