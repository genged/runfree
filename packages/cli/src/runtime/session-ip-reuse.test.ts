import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test } from "vitest";
import { SESSION_IP_REUSE_DIR } from "@runfree/runtime-contracts/session-file";
import { SessionIpAssignments } from "../../../proxy/src/session-ip-reuse.ts";
import { sessionIpAssignmentReadCommand, sessionIpReuseFenceCommand } from "./session-file-publisher.ts";

const roots: string[] = [];
const uid = process.getuid?.() ?? 0;
const IP = "172.31.90.20";
const KEY = "b".repeat(64);

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-ip-reuse-"));
  roots.push(root);
  const directory = path.join(root, "ip-reuse");
  for (const name of ["requests", "firewall", "request-proxy"]) fs.mkdirSync(path.join(directory, name), { recursive: true, mode: 0o755 });
  const request = path.join(directory, "requests", `${IP}.json`);
  return { root, directory, request };
}

async function fence(f: ReturnType<typeof fixture>, options: { respond?: boolean; kernelResidue?: boolean; expectedDigest?: string; umask?: number } = {}) {
  const read = sessionIpAssignmentReadCommand("a".repeat(64), IP);
  const readScript = read.args[7].replaceAll(SESSION_IP_REUSE_DIR, f.directory).replace("const ownerUid = 0;", `const ownerUid = ${uid};`);
  const before = spawnSync(process.execPath, ["-e", readScript, f.directory, IP], { encoding: "utf8" });
  expect(before.status, before.stderr).toBe(0);
  const expectedDigest = options.expectedDigest ?? before.stdout;
  const command = sessionIpReuseFenceCommand("a".repeat(64), IP, KEY, expectedDigest);
  const kernelLog = path.join(f.root, "kernel-effects.jsonl");
  // Execute the exact sealed publisher. Substitute only container paths, UIDs,
  // the test timeout, and the kernel command boundary; consumers are real.
  const sourceScript = command.args[command.args.indexOf("-e") + 1]
    .replaceAll(SESSION_IP_REUSE_DIR, f.directory)
    .replace("const ownerUid = 0;", `const ownerUid = ${uid};`)
    .replace("const requestProxyUid = 1001;", `const requestProxyUid = ${uid};`)
    .replace("performance.now() + 20000", "performance.now() + 2000")
    .replace('const { execFileSync } = require("node:child_process");', `const execFileSync = (name, args) => {
      fs.appendFileSync(${JSON.stringify(kernelLog)}, JSON.stringify({ name, args }) + "\\n");
      return args.includes("-H") && ${options.kernelResidue === true} ? "ESTAB old connection" : "";
    };`);
  const script = `process.umask(${options.umask ?? 0o022});\n${sourceScript}`;
  const rootConsumer = new SessionIpAssignments(f.root, uid);
  const proxyConsumer = new SessionIpAssignments(f.root, uid);
  const observedNonces = new Set<string>();
  const child = spawn(process.execPath, ["-e", script, f.directory, IP, KEY, expectedDigest], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const timer = setInterval(() => {
    for (const entry of rootConsumer.read()?.values() ?? []) {
      if (entry.state !== "draining") continue;
      observedNonces.add(entry.nonce);
      if (options.respond === false) continue;
      rootConsumer.acknowledge("firewall", entry);
      proxyConsumer.acknowledge("request-proxy", entry);
    }
  }, 10);
  try {
    const status = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    return { status, stderr, observedNonces, kernelLog };
  } finally {
    clearInterval(timer);
    if (child.exitCode === null) child.kill();
  }
}

test("the publisher drains TCP between fresh acknowledgements and retains the new IP owner", async () => {
  const f = fixture();
  const result = await fence(f);
  expect(result.status, result.stderr).toBe(0);
  expect(result.observedNonces.size).toBe(2);
  expect(JSON.parse(fs.readFileSync(f.request, "utf8"))).toMatchObject({ sourceIp: IP, sessionKey: KEY, state: "ready" });
  const effects = fs.readFileSync(result.kernelLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  expect(effects).toHaveLength(2);
  expect(effects[0].args).toContain("-K");
  expect(effects[1].args).toContain("-H");
  expect(effects.every((effect) => effect.args.includes(IP) && effect.args.includes(":8080"))).toBe(true);
});

test("old acknowledgements cannot release a fence, and a retry reclaims it", async () => {
  const f = fixture();
  for (const consumer of ["firewall", "request-proxy"]) {
    fs.writeFileSync(path.join(f.directory, consumer, `${IP}.json`), `${"f".repeat(32)}\n`);
  }
  const refused = await fence(f, { respond: false });
  expect(refused.status).toBe(1);
  expect(refused.stderr).toContain("retry the launch");
  expect(fs.existsSync(refused.kernelLog)).toBe(false);
  expect(JSON.parse(fs.readFileSync(f.request, "utf8")).state).toBe("draining");
  const retried = await fence(f);
  expect(retried.status, retried.stderr).toBe(0);
  expect(JSON.parse(fs.readFileSync(f.request, "utf8")).state).toBe("ready");
});

test("a successful ss kill with remaining kernel sockets refuses IP assignment", async () => {
  const f = fixture();
  const result = await fence(f, { kernelResidue: true });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("old TCP connections remain");
  expect(result.observedNonces.size).toBe(1);
  expect(JSON.parse(fs.readFileSync(f.request, "utf8")).state).toBe("draining");
});

test("unsafe or malformed assignment state cannot become an empty served set", () => {
  const f = fixture();
  const consumer = new SessionIpAssignments(f.root, uid);
  fs.writeFileSync(f.request, "malformed");
  expect(consumer.read()).toBeUndefined();
  fs.unlinkSync(f.request);
  fs.symlinkSync(path.join(f.root, "outside"), f.request);
  expect(consumer.read()).toBeUndefined();
});


test("a delayed executor cannot replace an assignment that advanced since its host read", async () => {
  const f = fixture();
  const current = JSON.stringify({ v: 1, sourceIp: IP, sessionKey: "c".repeat(64), nonce: "d".repeat(32), state: "ready" });
  fs.writeFileSync(f.request, current);
  const result = await fence(f, { expectedDigest: "-" });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("IP assignment changed; retry the launch");
  expect(fs.readFileSync(f.request, "utf8")).toBe(current);
  expect(fs.existsSync(result.kernelLog)).toBe(false);
});

test("assignments remain readable to the request proxy under a restrictive umask", async () => {
  const f = fixture();
  const result = await fence(f, { umask: 0o077 });
  expect(result.status, result.stderr).toBe(0);
  expect(fs.statSync(f.request).mode & 0o777).toBe(0o644);
});

test("the IP reuse fence refuses any address outside the session pool before a command exists", () => {
  // C8: the fence is sealed and executed only from the returned command, so a
  // throw here means no docker exec and no proxy-side write can happen.
  for (const sourceIp of [
    "172.31.90.19",
    "172.31.90.13",
    "172.31.90.16",
    "172.31.90.11",
    "172.31.90.1",
    "172.31.90.84",
    "172.31.90.255",
  ]) {
    expect(() => sessionIpReuseFenceCommand("a".repeat(64), sourceIp, KEY, "-"), sourceIp)
      .toThrow(/outside the session address pool/);
  }
  for (const sourceIp of ["172.31.90.20", "172.31.90.83"]) {
    expect(sessionIpReuseFenceCommand("a".repeat(64), sourceIp, KEY, "-").effect).toBe("fence-session-ip");
  }
});
