import fs from "node:fs";
import { SESSION_IP_REUSE_DIR } from "@runfree/runtime-contracts/session-file";
import path from "node:path";
import { spawn, spawnSync, type ChildProcess, type SpawnSyncReturns } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  auditMarkerPathFromEnv,
  auditSpoolPathFromEnv,
} from "./audit.js";
import {
  buildFirewallPlan,
  createFirewallController,
  PROXY_SERVER_GID,
  PROXY_SERVER_UID,
  type FirewallController,
} from "./firewall/index.js";
import { loadProxyPolicy } from "./policy.js";
import { assertSourceIpSessionIdentityConfig } from "./session-identity-config.js";
import {
  effectiveProxyRootFromEnv,
  loadEffectiveProxyControl,
} from "@runfree/runtime-contracts/effective-control";
import {
  DEFAULT_PROXY_STATUS_DIR,
  firewallStatusPath,
  requestProxyStatusDir,
} from "@runfree/runtime-contracts/proxy-status";
import { approvalsDecisionsDirFromEnv, approvalsPendingDirFromEnv } from "@runfree/runtime-contracts/write-approvals";
import { SESSION_ADMISSION_ROOT } from "@runfree/runtime-contracts/session-admission";
import {
  SESSION_ELIGIBILITY_PATH,
  SESSION_FILES_DIR,
} from "@runfree/runtime-contracts/session-file";

const FIREWALL_READY_PATH = "/tmp/firewall-initialized";
const SERVER_UID = PROXY_SERVER_UID;
const SERVER_GID = PROXY_SERVER_GID;
// Read at call time (not module load) so the startup-refusal test can prove
// the identity gate runs before this, the first filesystem side effect.
function oauthStateDir(): string {
  return process.env.RUNFREE_OAUTH_STATE_DIR ?? process.env.RUNFREE_MCP_OAUTH_STATE_DIR ?? "/run/runfree-oauth";
}
const NET_ADMIN_BIT = 12n;
const NET_RAW_BIT = 13n;

type ServerLaunchCommand = {
  command: string;
  args: string[];
  options: { shell: false };
};

type ServerDeniedCommandProbe = {
  command: string;
  args: string[];
  cleanup?: string[];
};

type ServerDeniedCommandResult = Pick<SpawnSyncReturns<string>, "status" | "signal" | "stdout" | "stderr" | "error">;

type ServerDeniedCommandRunner = (probe: ServerDeniedCommandProbe) => ServerDeniedCommandResult;

type RefreshableFirewallController = Pick<FirewallController, "refreshPolicyAndIps">;
type SessionAdmissionReconciliationController = Pick<FirewallController, "reconcileSessionAdmission">;

type FirewallRefreshScheduler = {
  tick(): Promise<void>;
  start(): ReturnType<typeof setInterval>;
  stop(): void;
};

type FirewallRefreshSchedulerInput = {
  controller: RefreshableFirewallController;
  policyIntervalMs: number;
  dnsIntervalMs: number;
  nowMs?: () => number;
  log?: (line: string) => void;
};

type SessionAdmissionScheduler = {
  tick(): Promise<void>;
  start(): ReturnType<typeof setInterval>;
  stop(): void;
};

type SessionAdmissionSchedulerInput = {
  controller: SessionAdmissionReconciliationController;
  intervalMs?: number;
  log?: (line: string) => void;
};

export function serverLaunchCommand(): ServerLaunchCommand {
  return {
    command: "setpriv",
    args: [
      ...serverPrivilegeDropArgs(),
      "node",
      "/app/proxy/server.js",
    ],
    options: { shell: false },
  };
}

function serverPrivilegeDropArgs(): string[] {
  return [
    `--reuid=${SERVER_UID}`,
    `--regid=${SERVER_GID}`,
    "--clear-groups",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--bounding-set=-net_admin,-net_raw",
    "--no-new-privs",
  ];
}

// mkdir + re-asserted ownership and mode on every start, so a tampered or
// stale tmpfs entry cannot survive a restart.
function ensureOwnedDir(dir: string, uid: number, gid: number, mode: number): void {
  fs.mkdirSync(dir, { recursive: true, mode });
  fs.chownSync(dir, uid, gid);
  fs.chmodSync(dir, mode);
}

function clearTemporaryStateDirectory(dir: string): void {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir)) fs.rmSync(path.join(dir, entry), { recursive: true, force: true });
}

export function ensureProxyOwnedStateDirs(): void {
  const serverUid = Number(SERVER_UID);
  const serverGid = Number(SERVER_GID);
  ensureOwnedDir(oauthStateDir(), serverUid, serverGid, 0o700);

  // Audit marker dir: root-owned and never writable by the UID-1001 proxy
  // server. The marker is the host-only enablement switch for network audit
  // mode; if the agent-facing server process could write here it could
  // self-enable audit mode. Root also writes the audit resolved-host snapshot
  // here for the server to read.
  clearTemporaryStateDirectory(path.dirname(auditMarkerPathFromEnv()));
  ensureOwnedDir(path.dirname(auditMarkerPathFromEnv()), 0, 0, 0o755);

  // Audit spool dir: the one intentional UID-1001 → root channel. The request
  // proxy appends observed hostnames; the root supervisor re-validates every
  // line before acting on it.
  clearTemporaryStateDirectory(path.dirname(auditSpoolPathFromEnv()));
  ensureOwnedDir(path.dirname(auditSpoolPathFromEnv()), serverUid, serverGid, 0o755);

  // Policy-generation status tmpfs (ownership split mirrors the audit paths):
  // the root dir holds the root-written firewall.json, which the UID-1001
  // request proxy must never be able to write — firewall convergence is the
  // claim that matters for policy removals. The request proxy gets its own
  // uid-1001 subdirectory for request-proxy.json.
  ensureOwnedDir(DEFAULT_PROXY_STATUS_DIR, 0, 0, 0o755);
  fs.rmSync(firewallStatusPath(), { force: true });
  ensureOwnedDir(requestProxyStatusDir(), serverUid, serverGid, 0o755);

  // Session admission is host/root authority: the untrusted agent and the
  // uid-1001 request proxy may read the session files, and neither may write
  // one.
  ensureOwnedDir(SESSION_ADMISSION_ROOT, 0, 0, 0o755);

  // Per-session heartbeat files. A proxy restart always begins with deny-all
  // dynamic admission, so a file left behind by a crash or a prior incarnation
  // must never survive into the new process: the directory is cleared, not
  // just recreated. eligibility.json — the host's per-project/per-generation
  // allowlist — is root-owned and removed the same way: the host republishes
  // it, and no session file is trusted without it.
  clearTemporaryStateDirectory(SESSION_FILES_DIR);
  ensureOwnedDir(SESSION_FILES_DIR, 0, 0, 0o755);
  // All TCP and process-local authority dies on proxy restart. Retire its IP
  // assignments at the same boundary; surviving sessions need fresh files.
  clearTemporaryStateDirectory(SESSION_IP_REUSE_DIR);
  ensureOwnedDir(SESSION_IP_REUSE_DIR, 0, 0, 0o755);
  for (const name of ["requests", "firewall"]) ensureOwnedDir(path.join(SESSION_IP_REUSE_DIR, name), 0, 0, 0o755);
  ensureOwnedDir(path.join(SESSION_IP_REUSE_DIR, "request-proxy"), serverUid, serverGid, 0o755);
  fs.rmSync(SESSION_ELIGIBILITY_PATH, { force: true });

  // Approve-on-write channel (ownership split mirrors the audit marker):
  // pending hold records are proxy-owned; decisions are root-owned so the
  // UID-1001 server reads but never writes them — a decision is a
  // boundary-widening authorization only the host CLI's root exec can mint.
  for (const dir of [approvalsPendingDirFromEnv(), approvalsDecisionsDirFromEnv()]) {
    clearTemporaryStateDirectory(dir);
  }
  ensureOwnedDir(approvalsPendingDirFromEnv(), serverUid, serverGid, 0o700);
  ensureOwnedDir(approvalsDecisionsDirFromEnv(), 0, 0, 0o755);
}

export async function waitForServerPrivilegeProofOrKill(
  child: ChildProcess,
  proof: (child: ChildProcess) => Promise<void> = waitForServerPrivilegeProof,
): Promise<void> {
  try {
    await proof(child);
  } catch (error) {
    killChild(child);
    throw error;
  }
}

export function createFirewallRefreshScheduler(input: FirewallRefreshSchedulerInput): FirewallRefreshScheduler {
  const nowMs = input.nowMs ?? (() => Date.now());
  const log = input.log ?? ((line: string) => console.error(line));
  let timer: ReturnType<typeof setInterval> | undefined;
  let inFlight = false;
  let lastDnsRefreshAtMs = nowMs();

  const tick = async () => {
    if (inFlight) {
      log("proxy-firewall: skipped refresh because the previous refresh is still running");
      return;
    }

    inFlight = true;
    const refreshDns = nowMs() - lastDnsRefreshAtMs >= input.dnsIntervalMs;
    try {
      await input.controller.refreshPolicyAndIps({ refreshDns });
      if (refreshDns) lastDnsRefreshAtMs = nowMs();
    } catch (error) {
      log(`proxy-firewall: refresh failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      inFlight = false;
    }
  };

  return {
    tick,
    start() {
      timer = setInterval(() => {
        void tick();
      }, input.policyIntervalMs);
      return timer;
    },
    stop() {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    },
  };
}

export function createSessionAdmissionScheduler(input: SessionAdmissionSchedulerInput): SessionAdmissionScheduler {
  const log = input.log ?? ((line: string) => console.error(line));
  const intervalMs = input.intervalMs ?? 100;
  let timer: ReturnType<typeof setInterval> | undefined;
  let inFlight = false;
  let pending = false;
  let stopped = false;

  const tick = async () => {
    if (inFlight) {
      pending = true;
      return;
    }

    inFlight = true;
    try {
      do {
        pending = false;
        try {
          await input.controller.reconcileSessionAdmission();
        } catch (error) {
          log(`proxy-firewall: session admission reconciliation failed: ${formatError(error)}`);
        }
      } while (pending && !stopped);
    } finally {
      inFlight = false;
    }
  };

  return {
    tick,
    start() {
      stopped = false;
      timer = setInterval(() => {
        void tick();
      }, intervalMs);
      return timer;
    },
    stop() {
      stopped = true;
      pending = false;
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    },
  };
}

export async function main(): Promise<number> {
  // Refuse before any side effect — no state-dir mutation, no nftables setup,
  // and the request-proxy child never starts — when the source-ip session
  // identity configuration is absent or wrong. There is no fallback mode.
  assertSourceIpSessionIdentityConfig();
  ensureProxyOwnedStateDirs();
  const effectiveProxyRoot = effectiveProxyRootFromEnv();
  const effectiveControl = effectiveProxyRoot ? loadEffectiveProxyControl(effectiveProxyRoot) : undefined;
  const policy = effectiveControl?.networkPolicy ?? loadProxyPolicy();
  const plan = buildFirewallPlan({
    allowedHosts: policy.allowedHosts,
    ...(effectiveControl ? {
      controlGeneration: effectiveControl.active.controlGeneration,
      effectiveProxyRoot,
      policyPath: effectiveControl.networkPolicyPath,
    } : {}),
    env: process.env,
    policyGeneration: policy.generation,
  });
  const controller = createFirewallController();
  await controller.initialize(plan);
  fs.writeFileSync(FIREWALL_READY_PATH, "");

  const child = startServer();
  try {
    await waitForServerPrivilegeProofOrKill(child);
  } catch (error) {
    await controller.stop();
    throw error;
  }

  const refreshIntervalMs = Math.max(1, plan.refresh.policyCheckIntervalSeconds) * 1000;
  const dnsIntervalMs = Math.max(1, plan.refresh.dnsRefreshIntervalSeconds) * 1000;
  const refreshScheduler = createFirewallRefreshScheduler({
    controller,
    policyIntervalMs: refreshIntervalMs,
    dnsIntervalMs,
  });
  const sessionAdmissionScheduler = createSessionAdmissionScheduler({ controller });
  refreshScheduler.start();
  sessionAdmissionScheduler.start();

  const forwardSignal = (signal: NodeJS.Signals) => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill(signal);
    }
  };
  process.once("SIGINT", () => forwardSignal("SIGINT"));
  process.once("SIGTERM", () => forwardSignal("SIGTERM"));

  const exit = await childExit(child);
  refreshScheduler.stop();
  sessionAdmissionScheduler.stop();
  await controller.stop();

  if (exit.signal) {
    return 128 + signalNumber(exit.signal);
  }
  return exit.code ?? 1;
}

function formatError(error: unknown): string {
  const value = error instanceof Error ? error.message : `non-Error ${typeof error}`;
  return value.length <= 2_048 ? value : `${value.slice(0, 2_047)}…`;
}

function killChild(child: ChildProcess): void {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
  }
}

function startServer(): ChildProcess {
  const launch = serverLaunchCommand();
  const child = spawn(launch.command, launch.args, {
    ...launch.options,
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
  });
  console.log(`proxy-firewall: launched proxy server pid=${child.pid ?? "<unknown>"}`);
  return child;
}

async function waitForServerPrivilegeProof(child: ChildProcess): Promise<void> {
  if (!child.pid) throw new Error("server child did not expose a process id");
  const started = Date.now();
  while (Date.now() - started < 5_000) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`server child exited before privilege verification: code=${child.exitCode} signal=${child.signalCode}`);
    }
    try {
      verifyServerProcessStatus(child.pid);
      return;
    } catch (error) {
      if (Date.now() - started >= 5_000) throw error;
      await delay(50);
    }
  }
}

function verifyServerProcessStatus(pid: number): void {
  const status = parseProcStatus(fs.readFileSync(`/proc/${pid}/status`, "utf8"));
  assertEveryValue(status.Uid, SERVER_UID, "Uid");
  assertEveryValue(status.Gid, SERVER_GID, "Gid");
  const groups = (status.Groups ?? "").trim().split(/\s+/).filter(Boolean);
  if (groups.length > 0 && groups.some((group) => group !== SERVER_GID)) {
    throw new Error(`proxy server has unexpected supplementary groups: ${groups.join(",")}`);
  }
  if (status.NoNewPrivs !== "1") throw new Error(`proxy server NoNewPrivs is ${status.NoNewPrivs ?? "<missing>"}`);
  for (const field of ["CapAmb", "CapInh"] as const) {
    if (capValue(status[field]) !== 0n) throw new Error(`proxy server ${field} is not empty`);
  }
  for (const field of ["CapPrm", "CapEff", "CapBnd"] as const) {
    const value = capValue(status[field]);
    if (hasCapability(value, NET_ADMIN_BIT) || hasCapability(value, NET_RAW_BIT)) {
      throw new Error(`proxy server ${field} retains network administration capabilities`);
    }
  }
  verifyServerDeniedCommands();
  console.log("proxy-firewall: proxy server privilege proof uid=1001 gid=1001 no_new_privs=1 net_admin=absent net_raw=absent");
}

export function verifyServerDeniedCommands(run: ServerDeniedCommandRunner = runServerDeniedCommand): void {
  for (const probe of serverDeniedCommandProbes()) {
    const result = run(probe);
    if (result.status === 0) {
      if (probe.cleanup) {
        spawnSync(probe.cleanup[0], probe.cleanup.slice(1), { encoding: "utf8", shell: false });
      }
      throw new Error(`proxy server privilege probe unexpectedly succeeded: ${probe.command} ${probe.args.join(" ")}`);
    }
    if (result.status === null || result.error) {
      throw new Error(`proxy server privilege probe could not execute: ${probe.command} ${probe.args.join(" ")}${formatProbeDetail(result)}`);
    }
    if (result.status === 127) {
      throw new Error(`proxy server privilege probe command was unavailable: ${probe.command} ${probe.args.join(" ")}${formatProbeDetail(result)}`);
    }
  }
}

function serverDeniedCommandProbes(): ServerDeniedCommandProbe[] {
  return [
    { command: "nft", args: ["list", "ruleset"] },
    { command: "nft", args: ["list", "set", "inet", "runfree_proxy", "allowed_ipv4"] },
    {
      command: "ip",
      args: ["route", "add", "blackhole", "203.0.113.254/32"],
      cleanup: ["ip", "route", "del", "blackhole", "203.0.113.254/32"],
    },
  ];
}

function runServerDeniedCommand(probe: ServerDeniedCommandProbe): ServerDeniedCommandResult {
  return spawnSync("setpriv", [...serverPrivilegeDropArgs(), probe.command, ...probe.args], {
    encoding: "utf8",
    shell: false,
  });
}

function formatProbeDetail(result: ServerDeniedCommandResult): string {
  const detail = `${result.error instanceof Error ? result.error.message : ""}\n${result.stderr}\n${result.stdout}`
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .join("; ");
  return detail ? `: ${detail}` : "";
}

function parseProcStatus(raw: string): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const match = /^([^:]+):\s*(.*)$/.exec(line);
    if (match) parsed[match[1]] = match[2].trim();
  }
  return parsed;
}

function assertEveryValue(value: string | undefined, expected: string, label: string): void {
  const values = (value ?? "").split(/\s+/).filter(Boolean);
  if (values.length !== 4 || values.some((entry) => entry !== expected)) {
    throw new Error(`proxy server ${label} expected ${expected} ${expected} ${expected} ${expected}, got ${value ?? "<missing>"}`);
  }
}

function capValue(value: string | undefined): bigint {
  return BigInt(`0x${value ?? "0"}`);
}

function hasCapability(value: bigint, bit: bigint): boolean {
  return (value & (1n << bit)) !== 0n;
}

function childExit(child: ChildProcess): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function signalNumber(signal: NodeJS.Signals): number {
  const numbers: Partial<Record<NodeJS.Signals, number>> = {
    SIGHUP: 1,
    SIGINT: 2,
    SIGTERM: 15,
  };
  return numbers[signal] ?? 1;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isMainModule(): boolean {
  if (!process.argv[1]) return false;
  return import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  main().then((code) => {
    process.exitCode = code;
  }).catch((error) => {
    console.error(`proxy-firewall: startup failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
