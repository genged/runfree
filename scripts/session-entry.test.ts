// Unit proof for the agent image's session entry and readiness probe
// (activation-gate design D1; test plan T3 and T4).
//
// Both programs are run as shipped — the POSIX entry script and the probe as
// `tsc` compiles it from `packages/agent-runtime/src`, copied into a temporary
// libexec directory the way the Dockerfile installs them. The probe is
// compiled here with the same project build `pnpm build:runtime` uses, so the
// bytes under test are the shipped ones, not a test-only bundle.
//
// Two oracles, deliberately:
//   - the real request proxy (the proxy test harness), which is the only
//     authority on what the readiness request is answered in each session
//     state, so the probe's classification is proven against it rather than
//     against a transcript of what the proxy is believed to send;
//   - a scripted loopback fake, for the entry's own loop behavior, which needs
//     answer sequences (unreachable, then active) and timing the real proxy
//     cannot be made to produce on cue.
// The probe's fixed proxy port is overridden through its test seam; the
// session environment never renders that name, so a real session always
// probes the proxy port.
//
// Children are spawned asynchronously: the fakes and the proxy harness live in
// this worker's event loop, and a synchronous spawn would block them.

import childProcess from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";

import { BASE_AGENT_ENVIRONMENT } from "../packages/cli/src/runtime/agent-env.ts";
import {
  harnessSessionFile,
  startProxy,
  writeHarnessSessionFiles,
} from "../packages/proxy/src/server.test-harness.ts";
import { SESSION_ADMISSION_PROVISIONING_REQUEST } from "../packages/runtime-contracts/src/session-admission.ts";

const AGENT_PACKAGE = path.resolve("packages/agent-runtime");
const ENTRY_SOURCE = path.join(AGENT_PACKAGE, "agent", "session-entry.sh");
const PROBE_SOURCE = path.join(AGENT_PACKAGE, "dist", "session-ready-probe.cjs");
const RELAY_SOURCE = path.join(AGENT_PACKAGE, "dist", "host-service-relay.cjs");

type ProbeModule = Readonly<{
  EXIT_ACTIVE: number;
  EXIT_REFUSED: number;
  EXIT_UNEXPECTED: number;
  EXIT_UNREACHABLE: number;
  EXIT_USAGE: number;
  PROXY_PORT: number;
  READINESS_REQUEST: string;
  ATTEMPT_CONNECT_TIMEOUT_MS: number;
  RETRY_PAUSE_MS: number;
  TOTAL_TIMEOUT_MS: number;
  probeUntilActive: (options: Readonly<{
    host: string;
    port: number;
    connect?: (options: Readonly<{ host: string; port: number; family: 4 }>) => net.Socket;
  }>) => Promise<number>;
}>;

let probeModule: ProbeModule;

beforeAll(() => {
  // Same compiler and project the runtime build runs; incremental, so a warm
  // tree costs well under a second. The repo-serial build test cleans these
  // outputs, but it runs after the parallel group this file belongs to.
  const build = childProcess.spawnSync("pnpm", ["exec", "tsc", "-b", "packages/agent-runtime"], {
    cwd: path.resolve("."),
    encoding: "utf8",
  });
  if (build.error) throw build.error;
  if (build.status !== 0) throw new Error(`agent-runtime build failed: ${build.stdout}${build.stderr}`);
  probeModule = createRequire(import.meta.url)(PROBE_SOURCE) as ProbeModule;
}, 60_000);

// Scripted answers for the entry's loop tests. Their shape mirrors the proxy's
// answers only loosely on purpose: what the real proxy sends is proven below
// against the real proxy, and these exist to sequence the entry through
// states, not to specify the proxy.
const ACTIVE_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nactive";
const REFUSED_RESPONSE = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 7\r\n\r\nblocked";

type FakeProxy = Readonly<{
  port: number;
  /** Every request head the fake proxy received, in order. */
  requests: readonly string[];
  connections: () => number;
  close: () => Promise<void>;
}>;

type Run = Readonly<{
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  pid: number | undefined;
}>;

/**
 * A loopback stand-in for the request proxy's guard: answers each connection
 * with the next scripted response (the last one repeats) after reading a
 * whole request head, and records exactly the bytes it was sent.
 */
async function startFakeProxy(responses: readonly string[]): Promise<FakeProxy> {
  const requests: string[] = [];
  let connections = 0;
  const server = net.createServer((socket) => {
    connections += 1;
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (!buffered.includes("\r\n\r\n")) return;
      requests.push(buffered.toString("latin1"));
      const response = responses[Math.min(requests.length - 1, responses.length - 1)];
      socket.end(response, "latin1");
    });
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("fake proxy did not bind a TCP port");
  return Object.freeze({
    port: address.port,
    requests,
    connections: () => connections,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  });
}

async function unusedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("could not reserve a port");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

function run(
  executable: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  options: Readonly<{ timeoutMs?: number; onSpawn?: (child: childProcess.ChildProcess) => void }> = {},
): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(executable, [...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += String(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += String(chunk);
    });
    const killer = setTimeout(() => child.kill("SIGKILL"), options.timeoutMs ?? 20_000);
    child.once("error", (error) => {
      clearTimeout(killer);
      reject(error);
    });
    child.once("close", (status, signal) => {
      clearTimeout(killer);
      resolve(Object.freeze({ status, signal, stdout, stderr, pid: child.pid }));
    });
    options.onSpawn?.(child);
  });
}

let tmp: string;
let libexecDir: string;
let entryPath: string;
let probePath: string;
let relayPath: string;
let fakeAgentPath: string;
let argvPath: string;
let proxies: FakeProxy[];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-entry-"));
  libexecDir = path.join(tmp, "usr", "local", "libexec", "runfree");
  fs.mkdirSync(libexecDir, { recursive: true });
  entryPath = path.join(libexecDir, "session-entry");
  probePath = path.join(libexecDir, "session-ready-probe");
  relayPath = path.join(libexecDir, "host-service-relay");
  fs.copyFileSync(ENTRY_SOURCE, entryPath);
  fs.copyFileSync(PROBE_SOURCE, probePath);
  fs.copyFileSync(RELAY_SOURCE, relayPath);
  fs.chmodSync(entryPath, 0o755);
  fs.chmodSync(probePath, 0o755);
  fs.chmodSync(relayPath, 0o755);
  argvPath = path.join(tmp, "argv.json");
  fakeAgentPath = path.join(tmp, "fake-agent");
  fs.writeFileSync(fakeAgentPath, [
    "#!/usr/bin/env node",
    'const fs = require("node:fs");',
    "fs.writeFileSync(process.env.RUNFREE_TEST_ARGV_PATH, JSON.stringify({",
    "  argv: process.argv.slice(2),",
    "  pid: process.pid,",
    "}));",
    // A test proving the relay survives past the exec needs a window where
    // the exec'd process is still alive but has already recorded its argv;
    // zero (the default) exits as fast as before.
    "const holdMs = Number(process.env.RUNFREE_TEST_HOLD_MS || 0);",
    "setTimeout(() => process.exit(Number(process.env.RUNFREE_TEST_EXIT_STATUS || 0)), holdMs);",
    "",
  ].join("\n"), { mode: 0o755 });
  proxies = [];
});

afterEach(async () => {
  for (const proxy of proxies) await proxy.close();
  // A host-service relay started by the entry outlives a normal exec (that is
  // the point of it), so a test that starts one leaves it running as an
  // orphan once the fake agent exits. Every process this test spawned ran
  // under this test's own tmp dir (the entry, probe, and relay binaries are
  // all copied there), so sweeping `/proc` for that path is scoped to this
  // test alone and safe to run unconditionally.
  try {
    const ps = childProcess.spawnSync("ps", ["-eo", "pid,args"], { encoding: "utf8" });
    for (const line of ps.stdout.split("\n")) {
      if (!line.includes(tmp)) continue;
      const pid = Number(line.trim().split(/\s+/)[0]);
      if (Number.isInteger(pid)) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    }
  } catch {
    // `ps` unavailable: nothing more we can do here.
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

async function fakeProxy(responses: readonly string[]): Promise<FakeProxy> {
  const proxy = await startFakeProxy(responses);
  proxies.push(proxy);
  return proxy;
}

function entryEnv(port: number, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    PROXY_IP: "127.0.0.1",
    RUNFREE_SESSION_READY_PROBE_PORT: String(port),
    RUNFREE_TEST_ARGV_PATH: argvPath,
    ...extra,
  };
}

function runEntry(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  options: Readonly<{ onSpawn?: (child: childProcess.ChildProcess) => void }> = {},
): Promise<Run> {
  return run(entryPath, args, env, options);
}

function runProbe(env: NodeJS.ProcessEnv): Promise<Run> {
  return run(probePath, [], { PATH: process.env.PATH, ...env }, { timeoutMs: 10_000 });
}

/** Runs the compiled probe against a proxy port until it returns `expected` or the attempts run out. */
async function probeUntil(port: number, expected: number, attempts = 40): Promise<Run> {
  let last = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(port) });
  for (let attempt = 1; attempt < attempts && last.status !== expected; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    last = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(port) });
  }
  return last;
}

function recordedAgentRun(): { argv: string[]; pid: number } {
  return JSON.parse(fs.readFileSync(argvPath, "utf8")) as { argv: string[]; pid: number };
}

/** One attempt: whether a loopback TCP connection to `port` succeeds right now. */
async function isListening(port: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
  });
}

/** Polls `127.0.0.1:port` until a connection succeeds or the bound elapses. */
async function waitForConnect(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await isListening(port)) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/** Polls `127.0.0.1:port` until every connection is refused or the bound elapses. */
async function waitForRefusal(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (!(await isListening(port))) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/**
 * The one `ps` line for a process whose argv names this test's own copy of
 * the relay binary (`relayPath`, inside this test's own tmp dir), if any is
 * running. Matching on that exact absolute path, rather than the bare
 * `host-service-relay` substring, keeps this from also matching unrelated
 * processes whose command line happens to mention this test file's own name
 * (`scripts/host-service-relay.test.ts`, e.g. the test runner's own argv).
 */
function relayProcessLine(): string | undefined {
  const ps = childProcess.spawnSync("ps", ["-eo", "pid,ppid,args"], { encoding: "utf8" });
  return ps.stdout.split("\n").find((line) => line.includes(relayPath));
}

/**
 * The relay is designed to survive the entry's own exec (that is the point
 * of it), and it inherits the entry's stdout/stderr pipes (nothing redirects
 * them in `session-entry.sh`, only the relay's stdin). A background child
 * that still holds those pipes open keeps a spawned `ChildProcess`'s `close`
 * event from ever firing, even once the tracked process itself has long
 * since exited — proven against a minimal repro before relying on it here.
 * A test that has already observed what it needs from a still-running relay
 * must kill it before awaiting a `run()`-based promise, or that promise
 * would hang until the relay exits on its own, which (by design) it never
 * does.
 */
function killRelayProcess(): void {
  const relayLine = relayProcessLine();
  if (relayLine === undefined) return;
  const pid = Number(relayLine.trim().split(/\s+/)[0]);
  if (!Number.isInteger(pid)) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Already gone.
  }
}

describe("session readiness probe against the real request proxy", () => {
  test("embeds the admission readiness request byte for byte (contract pin, T3)", () => {
    // The agent image carries no contracts package, so the probe embeds the
    // bytes. Drift here would make the entry time out on every launch.
    expect(probeModule.READINESS_REQUEST).toBe(SESSION_ADMISSION_PROVISIONING_REQUEST);
  });

  test("probes the port the session environment routes the agent's own traffic to", () => {
    // The pinned agent environment names the proxy port in every proxy URL;
    // the probe must knock on the same door.
    const match = /:(\d+)$/.exec(BASE_AGENT_ENVIRONMENT.HTTPS_PROXY);
    expect(match).not.toBeNull();
    expect(probeModule.PROXY_PORT).toBe(Number(match?.[1]));
  });

  test("reads active and refused from the proxy's own answers", async () => {
    // The harness serves one session file for 127.0.0.1; the file tree is then
    // rewritten and the proxy's 100 ms reconcile picks the change up.
    const proxy = await startProxy({ policy: { hosts: [] } });
    const registryDir = proxy.sessionRegistryDir;
    if (!registryDir) throw new Error("the harness did not provision a session registry");

    const active = await probeUntil(proxy.port, probeModule.EXIT_ACTIVE);
    expect(active.status, active.stderr).toBe(probeModule.EXIT_ACTIVE);
    // The answer was local: no denial was emitted for a served poll, so
    // nothing the probe sent reached policy.
    expect(proxy.output()).not.toMatch(/proxy-denial:/);

    const lapsed = new Date(Date.now() - 10_000);
    writeHarnessSessionFiles(registryDir, [harnessSessionFile({
      inspectedAt: lapsed.toISOString(),
      aliveUntil: new Date(lapsed.getTime() + 1_000).toISOString(),
    })]);
    const refused = await probeUntil(proxy.port, probeModule.EXIT_REFUSED);
    expect(refused.status, refused.stderr).toBe(probeModule.EXIT_REFUSED);
    // The refusal is the guard's source-IP identity check, not a policy
    // denial further in.
    await proxy.waitForOutput(/proxy-denial: [^\n]*"reason":"unregistered-session-peer"/);
  }, 30_000);

  test("sends exactly the readiness bytes, once, on one connection", async () => {
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(proxy.port) });

    expect(result.status, result.stderr).toBe(probeModule.EXIT_ACTIVE);
    expect(proxy.requests).toEqual([SESSION_ADMISSION_PROVISIONING_REQUEST]);
    expect(proxy.connections()).toBe(1);
  });

  test("does not read a 200 without the active body, an unrelated status, or a non-HTTP answer as active", async () => {
    // Only the proxy's active answer may release the agent. Anything else
    // that is not one of the proxy's other answers is "not yet" as well.
    // Each run retries until its whole budget is spent, so the three run at
    // once rather than one after another.
    const cases = [
      ["a 200 without the active body", ACTIVE_RESPONSE.replace("active", "actual")],
      ["an unrelated status", "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"],
      ["a non-HTTP answer", "not http\r\n\r\n"],
    ] as const;
    const results = await Promise.all(cases.map(async ([label, response]) => {
      const proxy = await fakeProxy([response]);
      return { label, result: await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(proxy.port) }) };
    }));
    for (const { label, result } of results) {
      expect(result.status, `${label}: ${result.stderr}`).toBe(probeModule.EXIT_UNEXPECTED);
    }
  });

  test("retries a refusal inside one run and exits active on the next connection", async () => {
    // Between the firewall admitting the address and the request proxy
    // serving the file the answer is a 403: the two consumers reconcile
    // independently. One run must not end on it.
    const proxy = await fakeProxy([REFUSED_RESPONSE, ACTIVE_RESPONSE]);
    const result = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(proxy.port) });

    expect(result.status, result.stderr).toBe(probeModule.EXIT_ACTIVE);
    expect(proxy.requests).toEqual([SESSION_ADMISSION_PROVISIONING_REQUEST, SESSION_ADMISSION_PROVISIONING_REQUEST]);
    expect(proxy.connections()).toBe(2);
  });

  test("a dropped SYN costs one short attempt, not a 1 s connect timeout (launch plan Task 7)", async () => {
    // The firewall drops a not-yet-admitted session's SYN without an RST, and
    // Linux retransmits it only after a 1 s RTO. A socket that never connects
    // models that attempt; the next attempt reaches the served proxy.
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    let calls = 0;
    const startedAt = performance.now();
    const code = await probeModule.probeUntilActive({
      host: "127.0.0.1",
      port: proxy.port,
      connect: (options) => {
        calls += 1;
        return calls === 1 ? new net.Socket() : net.connect(options);
      },
    });
    const elapsed = performance.now() - startedAt;

    expect(code).toBe(probeModule.EXIT_ACTIVE);
    expect(calls).toBe(2);
    expect(elapsed).toBeGreaterThanOrEqual(probeModule.ATTEMPT_CONNECT_TIMEOUT_MS - 5);
    // One short attempt, one pause, and the served answer: well under the old
    // single attempt's 1 s connect timeout.
    expect(elapsed).toBeLessThan(900);
    expect(proxy.requests).toEqual([SESSION_ADMISSION_PROVISIONING_REQUEST]);
  });

  test("a run that is never answered spends exactly its one total budget", async () => {
    // Every attempt dropped: the run ends on its whole-run budget, not per
    // attempt, so the entry's stop and timeout arithmetic still sees a
    // bounded child.
    let calls = 0;
    const startedAt = performance.now();
    const code = await probeModule.probeUntilActive({
      host: "127.0.0.1",
      port: 9,
      connect: () => {
        calls += 1;
        return new net.Socket();
      },
    });
    const elapsed = performance.now() - startedAt;

    expect(code).toBe(probeModule.EXIT_UNREACHABLE);
    expect(elapsed).toBeGreaterThanOrEqual(probeModule.TOTAL_TIMEOUT_MS - 25);
    expect(elapsed).toBeLessThan(probeModule.TOTAL_TIMEOUT_MS + 700);
    // Short attempts, one after another, until the budget ran out.
    expect(calls).toBeGreaterThanOrEqual(
      Math.floor(probeModule.TOTAL_TIMEOUT_MS / (probeModule.ATTEMPT_CONNECT_TIMEOUT_MS + probeModule.RETRY_PAUSE_MS)),
    );
  });

  test("a failed or cut-short attempt does not replace the proxy's last answer", async () => {
    // A loaded host can time out an attempt, and the run's budget can cut the
    // final one short; the run still reports what the proxy last said.
    const answered = await fakeProxy(["HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"]);
    const stalled = new Set<net.Socket>();
    const stallServer = net.createServer((socket) => {
      stalled.add(socket);
      socket.on("data", () => {});
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve) => stallServer.listen(0, "127.0.0.1", resolve));
    const stallAddress = stallServer.address();
    if (stallAddress === null || typeof stallAddress === "string") throw new Error("stall server did not bind");
    let calls = 0;
    try {
      const code = await probeModule.probeUntilActive({
        host: "127.0.0.1",
        port: answered.port,
        connect: (options) => {
          calls += 1;
          return net.connect(calls === 1 ? options : { ...options, port: stallAddress.port });
        },
      });
      expect(code).toBe(probeModule.EXIT_UNEXPECTED);
      expect(calls).toBe(2);
    } finally {
      for (const socket of stalled) socket.destroy();
      await new Promise<void>((resolve) => stallServer.close(() => resolve()));
    }
  });

  test("a refusal that never clears ends the run refused, every connection sending only the readiness bytes", async () => {
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    const result = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(proxy.port) });

    expect(result.status, result.stderr).toBe(probeModule.EXIT_REFUSED);
    expect(proxy.requests.length).toBeGreaterThan(1);
    expect(new Set(proxy.requests)).toEqual(new Set([SESSION_ADMISSION_PROVISIONING_REQUEST]));
    expect(proxy.connections()).toBe(proxy.requests.length);
  });

  test("exits unreachable when the proxy port is closed", async () => {
    const port = await unusedPort();
    const result = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(port) });
    expect(result.status, result.stderr).toBe(probeModule.EXIT_UNREACHABLE);
  });

  test("exits unreachable on a stalled proxy within its total timeout", async () => {
    // Accepts and reads the request but never answers. The sockets are
    // tracked so cleanup can destroy them: a server socket with unread data
    // never emits `end`, and `server.close()` would wait on it forever.
    const stalled = new Set<net.Socket>();
    const server = net.createServer((socket) => {
      stalled.add(socket);
      socket.on("data", () => {});
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("stall server did not bind");
    try {
      const startedAt = Date.now();
      const result = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(address.port) });
      expect(result.status, result.stderr).toBe(probeModule.EXIT_UNREACHABLE);
      // One run's budget, plus the Node start of the probe process.
      expect(Date.now() - startedAt).toBeLessThan(probeModule.TOTAL_TIMEOUT_MS + 2_000);
    } finally {
      for (const socket of stalled) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test.each([
    ["unset", undefined],
    ["a hostname", "proxy.runfree.invalid"],
    ["an IPv6 literal", "::1"],
    ["an out-of-range octet", "127.0.0.256"],
    ["a URL", "http://127.0.0.1:8080"],
  ])("refuses before connecting when PROXY_IP is %s", async (_label, value) => {
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runProbe({
      ...(value === undefined ? {} : { PROXY_IP: value }),
      RUNFREE_SESSION_READY_PROBE_PORT: String(proxy.port),
    });

    expect(result.status).toBe(probeModule.EXIT_USAGE);
    expect(result.stderr).toContain("PROXY_IP must be an IPv4 literal");
    expect(proxy.connections()).toBe(0);
  });
});

describe("session entry", () => {
  test("polls through unserved answers and execs the agent once the session is active (T4)", async () => {
    const proxy = await fakeProxy([REFUSED_RESPONSE, REFUSED_RESPONSE, REFUSED_RESPONSE, ACTIVE_RESPONSE]);
    const result = await runEntry([fakeAgentPath, "--flag", "value with spaces"], entryEnv(proxy.port));

    expect(result.status, result.stderr).toBe(0);
    const recorded = recordedAgentRun();
    expect(recorded.argv).toEqual(["--flag", "value with spaces"]);
    // `exec`: the agent replaced the entry rather than running as its child.
    expect(recorded.pid).toBe(result.pid);
    expect(proxy.requests).toHaveLength(4);
    expect(new Set(proxy.requests)).toEqual(new Set([SESSION_ADMISSION_PROVISIONING_REQUEST]));
  });

  test("passes the agent's own exit status through after exec, printing nothing on the fast path", async () => {
    // An immediately active proxy ends the loop on its first poll, before the
    // waiting notice is ever considered, so silence here is deterministic
    // regardless of how slowly the polls themselves run.
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_TEST_EXIT_STATUS: "23" }));
    expect(result.status, result.stderr).toBe(23);
    expect(result.stderr).toBe("");
  });

  test("starts the next probe run within a few tens of milliseconds of the last (launch plan Task 7)", async () => {
    // A probe stand-in that records when it ran and fails at once, so the only
    // thing between two runs is the entry's own loop and pause. The median gap
    // is well under the old 250 ms pause even on a loaded host.
    const runsPath = path.join(tmp, "probe-runs");
    fs.writeFileSync(probePath, `#!/bin/sh\ndate +%s%N >> "${runsPath}"\nexit 4\n`, { mode: 0o755 });
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    // Whole seconds in the entry: a 2 s bound runs it for 1-2 s, dozens of runs.
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "2000" }));

    expect(result.status, result.stderr).toBe(111);
    const stamps = fs.readFileSync(runsPath, "utf8").split("\n").filter(Boolean).map((line) => Number(BigInt(line) / 1_000_000n));
    expect(stamps.length).toBeGreaterThan(5);
    const gaps = stamps.slice(1).map((stamp, index) => stamp - stamps[index]).sort((left, right) => left - right);
    const median = gaps[Math.floor(gaps.length / 2)];
    expect(median).toBeLessThan(200);
  });

  test("prints the waiting notice once after two seconds, then exits 111 naming the bound", async () => {
    // One run past the notice: each probe run against a refusal spends its
    // 2 s budget, so the notice prints after the first run and the bound ends
    // the second. The fast path's silence is proven above.
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    const startedAt = Date.now();
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "3500" }));

    expect(result.status, result.stderr).toBe(111);
    expect(Date.now() - startedAt).toBeLessThan(10_000);
    expect(result.stderr.split("\n").filter((line) => line === "runfree: waiting for session admission")).toHaveLength(1);
    expect(result.stderr).toContain("not activated within 3500 ms");
    expect(result.stderr).toContain("RUNFREE_SESSION_ENTRY_TIMEOUT_MS");
    expect(fs.existsSync(argvPath)).toBe(false);
    expect(proxy.requests.length).toBeGreaterThanOrEqual(2);
  });

  test("keeps polling across an unreachable proxy within the bound", async () => {
    // Registration precedes reachability: before the firewall admits the
    // session's address the probe cannot connect at all. That must read as
    // "not yet", not as a failure.
    const port = await unusedPort();
    const result = await runEntry([fakeAgentPath], entryEnv(port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "1200" }));
    expect(result.status, result.stderr).toBe(111);
    expect(fs.existsSync(argvPath)).toBe(false);
  });

  test.each([
    ["TERM", "SIGTERM", 143],
    ["INT", "SIGINT", 130],
  ] as const)("exits promptly with %s while waiting", async (_label, signal, code) => {
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    let signalledAt = 0;
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port), {
      onSpawn: (child) => {
        // Let the entry reach its poll loop before signalling.
        const started = Date.now();
        const tick = () => {
          if (proxy.requests.length === 0 && Date.now() - started < 5_000) {
            setTimeout(tick, 25);
            return;
          }
          signalledAt = Date.now();
          child.kill(signal);
        };
        tick();
      },
    });

    expect(proxy.requests.length).toBeGreaterThan(0);
    expect({ status: result.status, signal: result.signal }).toEqual({ status: code, signal: null });
    expect(Date.now() - signalledAt).toBeLessThan(1_500);
    expect(fs.existsSync(argvPath)).toBe(false);
  });

  test.each([
    ["no argv", []],
    ["a relative agent path", ["fake-agent"]],
  ])("refuses %s before probing", async (_label, args) => {
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runEntry(args, entryEnv(proxy.port));

    expect(result.status).toBe(64);
    expect(result.stderr).toContain("runfree: session entry");
    expect(proxy.connections()).toBe(0);
  });

  test.each(["abc", "0", "-5", "1.5"])("refuses the host-rendered bound %j before probing", async (bound) => {
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: bound }));

    expect(result.status).toBe(64);
    expect(result.stderr).toContain("RUNFREE_SESSION_ENTRY_TIMEOUT_MS must be a positive integer");
    expect(proxy.connections()).toBe(0);
  });

  test("falls back to the default bound when the variable is absent or empty", async () => {
    // `${VAR:-default}`: absent and empty both select the default, which is
    // what a host that renders no bound should get rather than a refusal.
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "" }));
    expect(result.status, result.stderr).toBe(0);
    expect(recordedAgentRun().argv).toEqual([]);
  });
});

describe("session entry: host-service relay (T6)", () => {
  test("the relay listens before the probe reports active", async () => {
    const relayPort = await unusedPort();
    let releaseActive: (() => void) | undefined;
    const activeGate = new Promise<void>((resolve) => {
      releaseActive = resolve;
    });
    // A proxy that only answers the readiness request once released, so the
    // probe stays in its "not yet" loop for as long as the test needs.
    const server = net.createServer((socket) => {
      let buffered = Buffer.alloc(0);
      socket.on("data", (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        if (!buffered.includes("\r\n\r\n")) return;
        void activeGate.then(() => socket.end(ACTIVE_RESPONSE, "latin1"));
      });
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as net.AddressInfo;

    const resultPromise = runEntry([fakeAgentPath], entryEnv(address.port, { RUNFREE_HOST_SERVICES: `svc:${relayPort}` }));
    try {
      expect(await waitForConnect(relayPort, 2_000)).toBe(true);
      // The entry is still waiting: the proxy has not been allowed to answer
      // active yet, so the agent has not been exec'd.
      expect(fs.existsSync(argvPath)).toBe(false);
    } finally {
      releaseActive?.();
    }
    // The relay survives the exec by design (that is the point of it), and
    // it inherits the entry's stdout/stderr pipes, so the spawned process's
    // `close` event (what `runEntry` awaits) would otherwise never fire.
    // Everything this test needs was already observed above.
    killRelayProcess();
    const result = await resultPromise;
    expect(result.status, result.stderr).toBe(0);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("after exec: the agent PID is unchanged, the relay is still listening, and the relay's parent is the agent PID", async () => {
    const relayPort = await unusedPort();
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const runPromise = runEntry([fakeAgentPath], entryEnv(proxy.port, {
      RUNFREE_HOST_SERVICES: `svc:${relayPort}`,
      // A window after exec, while the agent (same PID as the entry) is still
      // alive, to sample process state before it exits.
      RUNFREE_TEST_HOLD_MS: "600",
    }));

    const deadline = Date.now() + 5_000;
    while (!fs.existsSync(argvPath) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(fs.existsSync(argvPath)).toBe(true);
    const agentPid = recordedAgentRun().pid;

    expect(await isListening(relayPort)).toBe(true);

    const relayLine = relayProcessLine();
    expect(relayLine, "no host-service-relay process found").toBeDefined();
    const match = /^\s*(\d+)\s+(\d+)/.exec(relayLine ?? "");
    expect(match).not.toBeNull();
    expect(Number(match?.[2])).toBe(agentPid);

    // Everything this test needs was already observed above; see the comment
    // on `killRelayProcess`.
    killRelayProcess();
    const result = await runPromise;
    expect(result.status, result.stderr).toBe(0);
    expect(result.pid).toBe(agentPid);
  });

  test("execs the agent normally, with unchanged exit status and timing, when the relay binary is missing", async () => {
    fs.rmSync(relayPath, { force: true });
    const relayPort = await unusedPort();
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const startedAt = Date.now();
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_HOST_SERVICES: `svc:${relayPort}` }));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(Date.now() - startedAt).toBeLessThan(2_000);
    expect(recordedAgentRun().pid).toBe(result.pid);
  });

  test.each([
    ["TERM", "SIGTERM", 143],
    ["INT", "SIGINT", 130],
  ] as const)("the relay is gone within 1.5s when %s arrives while waiting", async (_label, signal, code) => {
    const relayPort = await unusedPort();
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    let signalledAt = 0;
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_HOST_SERVICES: `svc:${relayPort}` }), {
      onSpawn: (child) => {
        const started = Date.now();
        const tick = async (): Promise<void> => {
          const relayUp = await isListening(relayPort);
          if ((proxy.requests.length === 0 || !relayUp) && Date.now() - started < 5_000) {
            setTimeout(tick, 25);
            return;
          }
          signalledAt = Date.now();
          child.kill(signal);
        };
        void tick();
      },
    });

    expect({ status: result.status, signal: result.signal }).toEqual({ status: code, signal: null });
    expect(signalledAt).toBeGreaterThan(0);
    const goneWithinBound = await waitForRefusal(relayPort, Math.max(0, signalledAt + 1_500 - Date.now()));
    expect(goneWithinBound, "the relay was still listening 1.5s after the signal").toBe(true);
  });

  test("starts no relay process when RUNFREE_HOST_SERVICES is unset", async () => {
    const proxy = await fakeProxy([ACTIVE_RESPONSE]);
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port));
    expect(result.status, result.stderr).toBe(0);
    expect(relayProcessLine()).toBeUndefined();
  });

  test("the relay's argv never names the session-entry path", async () => {
    const relayPort = await unusedPort();
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    const runPromise = runEntry([fakeAgentPath], entryEnv(proxy.port, {
      RUNFREE_HOST_SERVICES: `svc:${relayPort}`,
      RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "1500",
    }));

    expect(await waitForConnect(relayPort, 1_000)).toBe(true);
    const relayLine = relayProcessLine();
    expect(relayLine, "no host-service-relay process found").toBeDefined();
    // The brief's own check: the relay's argv never names the session-entry
    // path. (This test's tmp dir is itself named `runfree-session-entry-*`,
    // so a bare `"session-entry"` substring check would false-positive on
    // that; the exact entry path is the precise, correct check.)
    expect(relayLine).not.toContain(entryPath);

    // The entry's own timeout exit (111) does not kill the relay (only
    // `on_term`/`on_int` do, per `session-entry.sh`), so nothing else would
    // ever let the spawned process's `close` event fire.
    killRelayProcess();
    await runPromise;
  }, 10_000);
});
