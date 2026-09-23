import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import type { ChildProcess } from "node:child_process";

import {
  approvalsDecisionsDirFromEnv,
  approvalsPendingDirFromEnv,
} from "@runfree/runtime-contracts/write-approvals";
import {
  SESSION_ELIGIBILITY_PATH,
  SESSION_FILES_DIR,
} from "@runfree/runtime-contracts/session-file";
import { auditMarkerPathFromEnv } from "./audit.ts";
import {
  createFirewallRefreshScheduler,
  createSessionAdmissionScheduler,
  ensureProxyOwnedStateDirs,
  main,
  serverLaunchCommand,
  verifyServerDeniedCommands,
  waitForServerPrivilegeProofOrKill,
} from "./entrypoint.ts";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("proxy entrypoint", () => {
  // Negative-before-side-effect proof for the mandatory source-ip identity
  // mode: `main()` must refuse before its FIRST side effect (the proxy-owned
  // state dirs), which in program order precedes firewall plan construction,
  // nftables setup, and the request-proxy child. The observable evidence is
  // the injectable OAuth state dir: refusal leaves it uncreated.
  test.each([
    [
      "identity mode absent",
      { RUNFREE_PROJECT_ID: "0123456789ab" },
      /RUNFREE_SESSION_IDENTITY_MODE must be "source-ip-v1"/,
    ],
    [
      "identity mode is the retired runtime-wide mode",
      { RUNFREE_SESSION_IDENTITY_MODE: "runtime-v1", RUNFREE_PROJECT_ID: "0123456789ab" },
      /RUNFREE_SESSION_IDENTITY_MODE must be "source-ip-v1"/,
    ],
    [
      "session registry dir configured empty",
      {
        RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1",
        RUNFREE_SESSION_REGISTRY_DIR: "  ",
        RUNFREE_PROJECT_ID: "0123456789ab",
      },
      /session registry directory/,
    ],
    [
      "project id absent",
      { RUNFREE_SESSION_IDENTITY_MODE: "source-ip-v1" },
      /RUNFREE_PROJECT_ID is required/,
    ],
  ])("refuses startup with no state or firewall side effect when %s", async (_label, env, message) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-entrypoint-refusal-"));
    const oauthDir = path.join(tmp, "oauth-state");
    const savedKeys = [
      "RUNFREE_OAUTH_STATE_DIR",
      "RUNFREE_SESSION_IDENTITY_MODE",
      "RUNFREE_SESSION_REGISTRY_DIR",
      "RUNFREE_PROJECT_ID",
    ] as const;
    const saved = Object.fromEntries(savedKeys.map((key) => [key, process.env[key]]));
    try {
      for (const key of savedKeys) delete process.env[key];
      process.env.RUNFREE_OAUTH_STATE_DIR = oauthDir;
      Object.assign(process.env, env);
      await expect(main()).rejects.toThrow(message);
      expect(fs.existsSync(oauthDir)).toBe(false);
    } finally {
      for (const key of savedKeys) {
        if (saved[key] === undefined) delete process.env[key];
        else process.env[key] = saved[key];
      }
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test("server launcher uses setpriv fixed argv and no shell", () => {
    expect(serverLaunchCommand()).toEqual({
      command: "setpriv",
      args: [
        "--reuid=1001",
        "--regid=1001",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-net_admin,-net_raw",
        "--no-new-privs",
        "node",
        "/app/proxy/server.js",
      ],
      options: { shell: false },
    });
  });

  test("prepares proxy-owned OAuth state before dropping privileges", () => {
    const mkdir = vi.spyOn(fs, "mkdirSync").mockImplementation(() => undefined as never);
    const chown = vi.spyOn(fs, "chownSync").mockImplementation(() => undefined);
    const chmod = vi.spyOn(fs, "chmodSync").mockImplementation(() => undefined);

    ensureProxyOwnedStateDirs();

    expect(mkdir).toHaveBeenCalledWith("/run/runfree-oauth", { recursive: true, mode: 0o700 });
    expect(chown).toHaveBeenCalledWith("/run/runfree-oauth", 1001, 1001);
    expect(chmod).toHaveBeenCalledWith("/run/runfree-oauth", 0o700);
  });

  test("audit marker dir is root-owned and never handed to the proxy server UID; the spool dir is", () => {
    const mkdir = vi.spyOn(fs, "mkdirSync").mockImplementation(() => undefined as never);
    const chown = vi.spyOn(fs, "chownSync").mockImplementation(() => undefined);
    const chmod = vi.spyOn(fs, "chmodSync").mockImplementation(() => undefined);

    ensureProxyOwnedStateDirs();

    // Host-only enablement linchpin: the marker dir is root-owned (0:0) with
    // a non-group/world-writable mode, so the UID-1001 proxy server — the
    // process most exposed to agent-controlled bytes — cannot create or
    // mutate the audit marker. Only the host CLI's root docker-exec path can.
    expect(mkdir).toHaveBeenCalledWith("/run/runfree-proxy-audit", { recursive: true, mode: 0o755 });
    expect(chown).toHaveBeenCalledWith("/run/runfree-proxy-audit", 0, 0);
    expect(chmod).toHaveBeenCalledWith("/run/runfree-proxy-audit", 0o755);
    expect(chown).not.toHaveBeenCalledWith("/run/runfree-proxy-audit", 1001, 1001);

    // The spool dir is the one intentional UID-1001 → root channel.
    expect(mkdir).toHaveBeenCalledWith("/run/runfree-proxy-audit-spool", { recursive: true, mode: 0o755 });
    expect(chown).toHaveBeenCalledWith("/run/runfree-proxy-audit-spool", 1001, 1001);
    expect(chmod).toHaveBeenCalledWith("/run/runfree-proxy-audit-spool", 0o755);
  });

  test("policy-generation status paths re-assert the audit-style ownership split at startup", () => {
    const mkdir = vi.spyOn(fs, "mkdirSync").mockImplementation(() => undefined as never);
    const chown = vi.spyOn(fs, "chownSync").mockImplementation(() => undefined);
    const chmod = vi.spyOn(fs, "chmodSync").mockImplementation(() => undefined);
    vi.spyOn(fs, "rmSync").mockImplementation(() => undefined);

    ensureProxyOwnedStateDirs();

    // firewall.json lives in the root-owned status root: the UID-1001 request
    // proxy must never be able to fabricate firewall convergence.
    expect(mkdir).toHaveBeenCalledWith("/run/runfree-proxy-status", { recursive: true, mode: 0o755 });
    expect(chown).toHaveBeenCalledWith("/run/runfree-proxy-status", 0, 0);
    expect(chmod).toHaveBeenCalledWith("/run/runfree-proxy-status", 0o755);
    expect(chown).not.toHaveBeenCalledWith("/run/runfree-proxy-status", 1001, 1001);

    // request-proxy.json lives in a uid-1001 subdirectory pre-created here.
    expect(mkdir).toHaveBeenCalledWith("/run/runfree-proxy-status/request-proxy", { recursive: true, mode: 0o755 });
    expect(chown).toHaveBeenCalledWith("/run/runfree-proxy-status/request-proxy", 1001, 1001);
    expect(chmod).toHaveBeenCalledWith("/run/runfree-proxy-status/request-proxy", 0o755);
  });

  test("clears a stale session file and recreates the session-files dir root-owned, and removes eligibility.json, at startup", () => {
    const mkdir = vi.spyOn(fs, "mkdirSync").mockImplementation(() => undefined as never);
    const chown = vi.spyOn(fs, "chownSync").mockImplementation(() => undefined);
    const chmod = vi.spyOn(fs, "chmodSync").mockImplementation(() => undefined);
    const remove = vi.spyOn(fs, "rmSync").mockImplementation(() => undefined);
    vi.spyOn(fs, "existsSync").mockImplementation((target) => target === SESSION_FILES_DIR);
    vi.spyOn(fs, "readdirSync").mockImplementation(
      (target) => (target === SESSION_FILES_DIR ? ["stale-session.json"] : []) as never,
    );

    ensureProxyOwnedStateDirs();

    // A restart always begins deny-all: a session file left behind by a
    // crash or a prior incarnation must never survive into the new process,
    // even though the directory itself is not torn down.
    expect(remove).toHaveBeenCalledWith(
      path.join(SESSION_FILES_DIR, "stale-session.json"),
      { recursive: true, force: true },
    );
    expect(mkdir).toHaveBeenCalledWith(SESSION_FILES_DIR, { recursive: true, mode: 0o755 });
    expect(chown).toHaveBeenCalledWith(SESSION_FILES_DIR, 0, 0);
    expect(chmod).toHaveBeenCalledWith(SESSION_FILES_DIR, 0o755);

    // The host heartbeat republishes eligibility.json; a stale copy must not
    // outlive the process that authorized it.
    expect(remove).toHaveBeenCalledWith(SESSION_ELIGIBILITY_PATH, { force: true });
  });

  test("no approval authorization survives the process that minted it", () => {
    // The approvals and audit directories are per-container tmpfs, so a
    // replacement proxy starts them empty on its own. The path that needs this
    // clear is the in-place `docker restart <proxyId>` the admin reload takes:
    // the tmpfs survives it and the entrypoint re-runs. A decision record is a
    // boundary-widening authorization minted by one host CLI root exec against
    // one proxy process; carrying it into the next incarnation would let a
    // widened write approval outlive the process and the operator that granted
    // it. Same reasoning retires the pending holds and the root-owned audit
    // marker (the host-only enablement switch for audit mode).
    const cleared = [approvalsPendingDirFromEnv(), approvalsDecisionsDirFromEnv(), path.dirname(auditMarkerPathFromEnv())];
    vi.spyOn(fs, "mkdirSync").mockImplementation(() => undefined as never);
    vi.spyOn(fs, "chownSync").mockImplementation(() => undefined);
    vi.spyOn(fs, "chmodSync").mockImplementation(() => undefined);
    const remove = vi.spyOn(fs, "rmSync").mockImplementation(() => undefined);
    vi.spyOn(fs, "existsSync").mockImplementation((target) => cleared.includes(target as string));
    vi.spyOn(fs, "readdirSync").mockImplementation(
      (target) => (cleared.includes(target as string) ? ["left-behind"] : []) as never,
    );

    ensureProxyOwnedStateDirs();

    for (const dir of cleared) {
      expect(remove).toHaveBeenCalledWith(path.join(dir, "left-behind"), { recursive: true, force: true });
    }
  });

  test("kills the proxy server child when privilege proof fails", async () => {
    const kill = vi.fn();
    const child = {
      pid: 123,
      exitCode: null,
      signalCode: null,
      kill,
    } as unknown as ChildProcess;
    const proof = async () => {
      throw new Error("bad privilege state");
    };

    await expect(waitForServerPrivilegeProofOrKill(child, proof)).rejects.toThrow("bad privilege state");

    expect(kill).toHaveBeenCalledWith("SIGTERM");
  });

  test("server privilege proof denies firewall and route administration commands", () => {
    const probes: string[] = [];

    verifyServerDeniedCommands((probe) => {
      probes.push([probe.command, ...probe.args].join(" "));
      return { status: 1, signal: null, stdout: "", stderr: "Operation not permitted" };
    });

    expect(probes).toEqual([
      "nft list ruleset",
      "nft list set inet runfree_proxy allowed_ipv4",
      "ip route add blackhole 203.0.113.254/32",
    ]);
  });

  test("server privilege proof rejects successful firewall or route probes", () => {
    expect(() => verifyServerDeniedCommands(() => ({ status: 0, signal: null, stdout: "unexpected", stderr: "" })))
      .toThrow(/unexpectedly succeeded/);
  });

  test("serializes firewall refresh ticks and honors the DNS interval", async () => {
    let now = 1_000;
    let releaseFirstRefresh!: () => void;
    const refreshPolicyAndIps = vi.fn((options: { refreshDns: boolean }) => {
      if (refreshPolicyAndIps.mock.calls.length === 1) {
        return new Promise<void>((resolve) => {
          releaseFirstRefresh = resolve;
        });
      }
      return Promise.resolve();
    });
    const scheduler = createFirewallRefreshScheduler({
      controller: { refreshPolicyAndIps },
      policyIntervalMs: 2_000,
      dnsIntervalMs: 300_000,
      nowMs: () => now,
      log: () => {},
    });

    const first = scheduler.tick();
    await scheduler.tick();
    expect(refreshPolicyAndIps).toHaveBeenCalledTimes(1);
    expect(refreshPolicyAndIps).toHaveBeenNthCalledWith(1, { refreshDns: false });

    releaseFirstRefresh();
    await first;
    now += 299_000;
    await scheduler.tick();
    expect(refreshPolicyAndIps).toHaveBeenNthCalledWith(2, { refreshDns: false });

    now += 1_000;
    await scheduler.tick();
    expect(refreshPolicyAndIps).toHaveBeenNthCalledWith(3, { refreshDns: true });
  });

  test("runs admission independently while maintenance is blocked", async () => {
    let releaseMaintenance!: () => void;
    const refreshPolicyAndIps = vi.fn(() => new Promise<void>((resolve) => {
      releaseMaintenance = resolve;
    }));
    const reconcileSessionAdmission = vi.fn(async () => {});
    const maintenance = createFirewallRefreshScheduler({
      controller: { refreshPolicyAndIps },
      policyIntervalMs: 2_000,
      dnsIntervalMs: 300_000,
      log: () => {},
    });
    const admission = createSessionAdmissionScheduler({
      controller: { reconcileSessionAdmission },
      log: () => {},
    });

    const blockedMaintenance = maintenance.tick();
    await admission.tick();

    expect(refreshPolicyAndIps).toHaveBeenCalledTimes(1);
    expect(reconcileSessionAdmission).toHaveBeenCalledTimes(1);
    releaseMaintenance();
    await blockedMaintenance;
  });

  test("coalesces busy admission ticks into one pass over the latest state", async () => {
    let selected = "generation-a";
    let releaseFirst!: () => void;
    const observed: string[] = [];
    const reconcileSessionAdmission = vi.fn(async () => {
      observed.push(selected);
      if (observed.length === 1) {
        await new Promise<void>((resolve) => {
          releaseFirst = resolve;
        });
      }
    });
    const logs: string[] = [];
    const scheduler = createSessionAdmissionScheduler({
      controller: { reconcileSessionAdmission },
      log: (line) => logs.push(line),
    });

    const first = scheduler.tick();
    selected = "generation-b";
    await scheduler.tick();
    selected = "generation-c";
    await scheduler.tick();
    releaseFirst();
    await first;

    expect(observed).toEqual(["generation-a", "generation-c"]);

    reconcileSessionAdmission.mockRejectedValueOnce(new Error("local reconciliation failed"));
    await scheduler.tick();
    await scheduler.tick();
    expect(logs).toContainEqual(expect.stringContaining("local reconciliation failed"));
    expect(reconcileSessionAdmission).toHaveBeenCalledTimes(4);
  });
});
