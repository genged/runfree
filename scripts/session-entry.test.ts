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

type ProbeModule = Readonly<{
  EXIT_ACTIVE: number;
  EXIT_REFUSED: number;
  EXIT_UNEXPECTED: number;
  EXIT_UNREACHABLE: number;
  EXIT_USAGE: number;
  PROXY_PORT: number;
  READINESS_REQUEST: string;
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
let fakeAgentPath: string;
let argvPath: string;
let proxies: FakeProxy[];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-entry-"));
  libexecDir = path.join(tmp, "usr", "local", "libexec", "runfree");
  fs.mkdirSync(libexecDir, { recursive: true });
  entryPath = path.join(libexecDir, "session-entry");
  probePath = path.join(libexecDir, "session-ready-probe");
  fs.copyFileSync(ENTRY_SOURCE, entryPath);
  fs.copyFileSync(PROBE_SOURCE, probePath);
  fs.chmodSync(entryPath, 0o755);
  fs.chmodSync(probePath, 0o755);
  argvPath = path.join(tmp, "argv.json");
  fakeAgentPath = path.join(tmp, "fake-agent");
  fs.writeFileSync(fakeAgentPath, [
    "#!/usr/bin/env node",
    'const fs = require("node:fs");',
    "fs.writeFileSync(process.env.RUNFREE_TEST_ARGV_PATH, JSON.stringify({",
    "  argv: process.argv.slice(2),",
    "  pid: process.pid,",
    "}));",
    "process.exit(Number(process.env.RUNFREE_TEST_EXIT_STATUS || 0));",
    "",
  ].join("\n"), { mode: 0o755 });
  proxies = [];
});

afterEach(async () => {
  for (const proxy of proxies) await proxy.close();
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

  test.each([
    ["a 200 without the active body", ACTIVE_RESPONSE.replace("active", "actual")],
    ["an unrelated status", "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"],
    ["a non-HTTP answer", "not http\r\n\r\n"],
  ])("does not read %s as active", async (_label, response) => {
    // Only the proxy's active answer may release the agent. Anything else
    // that is not one of the proxy's other answers is "not yet" as well.
    const proxy = await fakeProxy([response]);
    const result = await runProbe({ PROXY_IP: "127.0.0.1", RUNFREE_SESSION_READY_PROBE_PORT: String(proxy.port) });
    expect(result.status, result.stderr).toBe(probeModule.EXIT_UNEXPECTED);
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
      expect(Date.now() - startedAt).toBeLessThan(5_000);
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

  test("exits 111 naming the bound when the session never becomes active", async () => {
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    const startedAt = Date.now();
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "1500" }));

    expect(result.status, result.stderr).toBe(111);
    expect(Date.now() - startedAt).toBeLessThan(6_000);
    expect(result.stderr).toContain("not activated within 1500 ms");
    expect(result.stderr).toContain("RUNFREE_SESSION_ENTRY_TIMEOUT_MS");
    expect(fs.existsSync(argvPath)).toBe(false);
    expect(proxy.requests.length).toBeGreaterThanOrEqual(2);
  });

  test("prints the waiting notice once after two seconds and nothing on the fast path", async () => {
    const proxy = await fakeProxy([REFUSED_RESPONSE]);
    const result = await runEntry([fakeAgentPath], entryEnv(proxy.port, { RUNFREE_SESSION_ENTRY_TIMEOUT_MS: "3500" }));

    expect(result.status, result.stderr).toBe(111);
    expect(result.stderr.split("\n").filter((line) => line === "runfree: waiting for session admission")).toHaveLength(1);
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
