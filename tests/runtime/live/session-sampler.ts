// Read-only live observation. One Docker exec keeps daemon polling out of the
// workload whose renewal deadlines we measure. No production verdict is used.
import childProcess from "node:child_process";
import { SESSION_FILES_DIR } from "@runfree/runtime-contracts/session-file";

export const SESSION_SAMPLE_SCRIPT = `
const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");
const config = JSON.parse(process.argv[1]);
const started = performance.now();
let stopping = false;
process.stdin.resume();
process.stdin.on("end", () => { stopping = true; });
async function main() {
  while (!stopping) {
    if (performance.now() - started > config.timeoutMs) throw new Error("sampler lifetime exceeded");
    const files = [];
    for (const name of fs.readdirSync(config.directory).sort()) {
      if (!name.endsWith(".json")) continue;
      try { files.push(JSON.parse(fs.readFileSync(path.join(config.directory, name), "utf8"))); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    const nft = JSON.parse(cp.execFileSync(config.nft, ["-j", "list", "set", "inet", "runfree_proxy", "session_ipv4"], {
      encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024,
    }));
    process.stdout.write(JSON.stringify({ elapsedMs: performance.now() - started, files, nft }) + "\\n");
    await new Promise(resolve => setTimeout(resolve, config.intervalMs));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
`;

type FileObservation = Readonly<{ sourceIp: string; nonce: string; inspectedAt: string; aliveUntil: string }>;
export type SessionSample = Readonly<{
  elapsedMs: number;
  files: readonly FileObservation[];
  ips: readonly string[];
}>;

export function parseSessionSample(line: string): SessionSample {
  const raw = JSON.parse(line);
  if (!Number.isFinite(raw.elapsedMs) || !Array.isArray(raw.files) || !Array.isArray(raw.nft?.nftables)) {
    throw new Error("malformed session sample");
  }
  const sets = raw.nft.nftables.filter((entry: { set?: unknown }) => entry.set);
  if (sets.length !== 1 || sets[0].set.name !== "session_ipv4"
    || sets[0].set.family !== "inet" || sets[0].set.table !== "runfree_proxy") {
    throw new Error("sample does not contain the exact session kernel set");
  }
  const ips = (sets[0].set.elem ?? []).map((element: unknown) => {
    const value = typeof element === "string" ? element : (element as { elem?: unknown })?.elem;
    if (typeof value !== "string") throw new Error("malformed session kernel element");
    return value;
  });
  for (const file of raw.files) {
    if (typeof file.sourceIp !== "string" || typeof file.nonce !== "string"
      || !Number.isFinite(Date.parse(file.inspectedAt)) || !Number.isFinite(Date.parse(file.aliveUntil))) {
      throw new Error("malformed session file in sample");
    }
  }
  return { elapsedMs: raw.elapsedMs, files: raw.files, ips };
}

export class SessionObservation {
  private last: SessionSample | undefined;
  private failure: Error | undefined;
  private readonly watched = new Map<string, Set<string>>();
  private readonly leaseBounds = new Map<string, number>();

  constructor(private readonly maxGapMs = 5000) {}

  accept(sample: SessionSample): void {
    if (this.last && (sample.elapsedMs <= this.last.elapsedMs || sample.elapsedMs - this.last.elapsedMs > this.maxGapMs)) {
      this.failure ??= new Error("session observation gap exceeded its bound; renewal continuity is unproved");
    }
    this.last = sample;
    for (const [ip, nonces] of this.watched) {
      const file = sample.files.find((entry) => entry.sourceIp === ip);
      if (!sample.ips.includes(ip) || !file) this.failure ??= new Error(`session ${ip} lost file or kernel authority`);
      if (file) {
        nonces.add(file.nonce);
        const bound = this.leaseBounds.get(ip);
        const leaseMs = Date.parse(file.aliveUntil) - Date.parse(file.inspectedAt);
        if (bound !== undefined && (leaseMs <= 0 || leaseMs > bound)) {
          this.failure ??= new Error(`session ${ip} did not use the requested short lease; expiry coverage is unproved`);
        }
      }
    }
  }

  watch(ip: string, maxLeaseMs?: number): Set<string> {
    const nonces = this.watched.get(ip) ?? new Set<string>();
    this.watched.set(ip, nonces);
    if (maxLeaseMs !== undefined) this.leaseBounds.set(ip, maxLeaseMs);
    return nonces;
  }

  check(): SessionSample {
    if (this.failure) throw this.failure;
    if (!this.last) throw new Error("no session observations received");
    return this.last;
  }
}

export async function startSessionSampler(proxyId: string, intervalMs = 500) {
  const child = childProcess.spawn("docker", [
    "exec", "--interactive", "--user", "0:0", proxyId, "node", "-e", SESSION_SAMPLE_SCRIPT,
    JSON.stringify({ directory: SESSION_FILES_DIR, nft: "nft", intervalMs, timeoutMs: 15 * 60_000 }),
  ], { stdio: ["pipe", "pipe", "pipe"] });
  const observation = new SessionObservation();
  let pending = "";
  let stderr = "";
  let failure: Error | undefined;
  let receivedAt = 0;
  let stopping = false;
  child.stdout.on("data", (chunk: Buffer) => {
    pending += String(chunk);
    if (pending.length > 1024 * 1024) failure ??= new Error("session sample exceeds output bound");
    while (pending.includes("\n") && !failure) {
      const end = pending.indexOf("\n");
      const line = pending.slice(0, end);
      pending = pending.slice(end + 1);
      try {
        observation.accept(parseSessionSample(line));
        receivedAt = Date.now();
      } catch (error) { failure = error as Error; }
    }
    if (failure) pending = "";
  });
  child.stderr.on("data", (chunk: Buffer) => { stderr = (stderr + String(chunk)).slice(-4000); });
  child.stdin.on("error", (error) => { failure ??= error; });
  const completion = new Promise<void>((resolve) => {
    child.once("error", (error) => { failure ??= error; resolve(); });
    child.once("close", (status) => {
      if (status !== 0 || !stopping) failure ??= new Error(`session sampler exited ${status}: ${stderr}`);
      resolve();
    });
  });
  const stop = async (): Promise<void> => {
    stopping = true;
    child.stdin.end();
    const timeout = setTimeout(() => {
      failure ??= new Error("session sampler did not stop");
      child.kill("SIGKILL");
    }, 6000);
    await completion;
    clearTimeout(timeout);
    if (failure) throw failure;
    observation.check();
  };
  try {
    const deadline = Date.now() + 15_000;
    while (receivedAt === 0) {
      if (failure) throw failure;
      if (Date.now() >= deadline) throw new Error(`session sampler produced no observations: ${stderr}`);
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  } catch (error) {
    await stop().catch(() => undefined);
    throw error;
  }
  return {
    watch: (ip: string, maxLeaseMs?: number) => observation.watch(ip, maxLeaseMs),
    check(): SessionSample {
      if (failure) throw failure;
      if (Date.now() - receivedAt > 5000) throw new Error("session sampler stopped delivering observations");
      return observation.check();
    },
    stop,
  };
}
