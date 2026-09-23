// Shared harness for the installable-cli test files. Importing this module
// registers the per-test temp-project hooks, so it must only be imported from
// Vitest test files. The tests are split across several files so their CLI
// subprocess spawns run on parallel worker threads.
//
// `runCli`/`runTsCli`/`runCliInProject` spawn the prebuilt CLI bundle when the
// globalSetup produced one (tests/support/prebuilt-entry.ts), replicating the
// exact env/cwd contract of the `bin/runfree.js` wrapper where the wrapper was
// previously in the loop. The wrapper itself keeps subprocess coverage in
// `scripts/installable-cli-wrapper.test.ts` via `runBinWrapperCli`.
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach } from "vitest";

import { projectInfo, type ProjectInfo } from "../packages/cli/src/config.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
} from "../packages/cli/src/control/approvals.ts";
import { captureDesiredPolicyCandidate } from "../packages/cli/src/control/candidates.ts";
import {
  publishEffectivePolicyGeneration,
  readActiveControlSelection,
} from "../packages/cli/src/control/effective.ts";
import { activeRuntimePlanFromContext, type ActiveRuntimePlan } from "../packages/cli/src/runtime/plan.ts";
import { createRuntimeSecurityContract } from "../packages/cli/src/runtime/security-contract.ts";
import { cliEntryArgv } from "../tests/support/prebuilt-entry.ts";

export const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
export const cliPath = path.join(repoRoot, "bin/runfree.js");

export let tmp: string;
export let tmpBase: string;
export let hostHome: string;
let defaultFakeBin: string;

function testPath(extraEnv: NodeJS.ProcessEnv = {}): string {
  const requestedPath = extraEnv.PATH ?? process.env.PATH ?? "";
  return `${requestedPath}${path.delimiter}${defaultFakeBin}`;
}

export function runCli(args: string[]): childProcess.SpawnSyncReturns<string> {
  // The bin wrapper would run the CLI with cwd=repoRoot and both wrapper env
  // vars set to its own invocation cwd (also repoRoot here); replicate that
  // contract exactly around the prebuilt entry.
  return childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", tmp, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: hostHome,
      PATH: testPath(),
      RUNFREE_INVOCATION_CWD: repoRoot,
      RUNFREE_PROJECT_ROOT: repoRoot,
      XDG_CONFIG_HOME: path.join(tmpBase, "xdg-config"),
      XDG_DATA_HOME: path.join(tmpBase, "xdg-data"),
      XDG_STATE_HOME: path.join(tmpBase, "xdg-state"),
    },
  });
}

export function runTsCli(args: string[], extraEnv: NodeJS.ProcessEnv = {}): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync(process.execPath, [...cliEntryArgv(), "--workspace", tmp, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: hostHome,
      XDG_CONFIG_HOME: path.join(tmpBase, "xdg-config"),
      XDG_DATA_HOME: path.join(tmpBase, "xdg-data"),
      XDG_STATE_HOME: path.join(tmpBase, "xdg-state"),
      ...extraEnv,
      PATH: testPath(extraEnv),
    },
  });
}

export function runCliInProject(args: string[]): childProcess.SpawnSyncReturns<string> {
  // Exactly what bin/runfree.js does when invoked from the project directory:
  // the child runs with cwd=repoRoot while both wrapper env vars carry the
  // invocation directory.
  return childProcess.spawnSync(process.execPath, [...cliEntryArgv(), ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: hostHome,
      PATH: testPath(),
      RUNFREE_INVOCATION_CWD: tmp,
      RUNFREE_PROJECT_ROOT: tmp,
      XDG_CONFIG_HOME: path.join(tmpBase, "xdg-config"),
      XDG_DATA_HOME: path.join(tmpBase, "xdg-data"),
      XDG_STATE_HOME: path.join(tmpBase, "xdg-state"),
    },
  });
}

/**
 * Runs the real `bin/runfree.js` wrapper as a subprocess from the project
 * directory, tsx and all. Slow (~1.5s per spawn); only
 * `scripts/installable-cli-wrapper.test.ts` uses it, to keep the wrapper's
 * argv/env/exit-status wiring under subprocess coverage now that the other
 * harness helpers spawn the prebuilt bundle.
 */
export function runBinWrapperCli(args: string[]): childProcess.SpawnSyncReturns<string> {
  return childProcess.spawnSync(process.execPath, [cliPath, ...args], {
    cwd: tmp,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: hostHome,
      PATH: testPath(),
      XDG_CONFIG_HOME: path.join(tmpBase, "xdg-config"),
      XDG_DATA_HOME: path.join(tmpBase, "xdg-data"),
      XDG_STATE_HOME: path.join(tmpBase, "xdg-state"),
    },
  });
}

export function tsCliEnv(): NodeJS.ProcessEnv {
  return {
    XDG_CONFIG_HOME: path.join(tmpBase, "xdg-config"),
    XDG_DATA_HOME: path.join(tmpBase, "xdg-data"),
    XDG_STATE_HOME: path.join(tmpBase, "xdg-state"),
  };
}

export function runtimeTargetForTsCliProject(project: ProjectInfo): {
  contract: ReturnType<typeof createRuntimeSecurityContract>;
  plan: ActiveRuntimePlan;
} {
  if (project.config.version >= 4 && !readActiveControlSelection(project)) {
    const candidate = captureDesiredPolicyCandidate(tmp, project.paths.controlCandidatesDir);
    approveNetworkCandidate(tmp, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(tmp, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(tmp, project, "interactive");
    publishEffectivePolicyGeneration(tmp, project);
  }
  fs.mkdirSync(path.dirname(project.paths.claudeMcpConfigPath), { recursive: true });
  if (!fs.existsSync(project.paths.claudeMcpConfigPath)) {
    fs.writeFileSync(project.paths.claudeMcpConfigPath, '{\n  "mcpServers": {}\n}\n');
  }
  const plan = activeRuntimePlanFromContext({
    projectRoot: tmp,
    project,
    runtimeRoot: path.join(tmpBase, "xdg-data/runfree/current/runtime"),
    env: tsCliEnv(),
  });
  return { contract: createRuntimeSecurityContract(plan), plan };
}

export function selectCurrentDesiredControlsForTsCliProject(): void {
  const project = projectInfo(tmp, tsCliEnv());
  const candidate = captureDesiredPolicyCandidate(tmp, project.paths.controlCandidatesDir);
  approveNetworkCandidate(tmp, project, candidate, "network-project", "interactive");
  approveNetworkCandidate(tmp, project, candidate, "network-local", "interactive");
  approveRuntimeIsolationControl(tmp, project, "interactive");
  publishEffectivePolicyGeneration(tmp, project);
}

export function runtimeContractHashForTsCliProject(project: ProjectInfo): string {
  return runtimeTargetForTsCliProject(project).contract.contractHash ?? "";
}

export function dockerInspectSecurityEvidence(project: ProjectInfo): string {
  const bind = (Destination: string, Source: string, mode: "ro" | "rw") => ({
    Destination,
    Mode: mode,
    RW: mode === "rw",
    Source,
    Type: "bind",
  });
  return JSON.stringify([
    {
      Id: "agent-id",
      HostConfig: {},
      Mounts: [
        bind("/runfree/inbox", project.paths.inboxDir, "ro"),
        bind("/runfree/mcp/claude.json", project.paths.claudeMcpConfigPath, "ro"),
        bind("/workspace/.codex", project.paths.projectCodexDirMaskPath, "ro"),
        bind("/etc/proxy-ca", project.paths.proxyCaCertDir, "ro"),
      ],
    },
    {
      Id: "proxy-id",
      HostConfig: {
        Tmpfs: {
          "/run/runfree-proxy-audit": "",
          "/run/runfree-proxy-audit-spool": "",
          "/run/runfree-proxy-secrets": "",
          "/run/runfree-proxy-status": "",
          "/run/runfree-approvals/pending": "",
          "/run/runfree-approvals/decisions": "",
        },
      },
      Mounts: [
        bind("/ca/private", project.paths.proxyCaKeyDir, "rw"),
        bind("/ca/public", project.paths.proxyCaCertDir, "rw"),
        bind("/app/runfree-effective", project.paths.controlProxyDir, "ro"),
        bind(
          "/app/proxy/mcp-operation-policy.json",
          project.paths.mcpOperationPolicyPath ?? path.join(project.paths.stateDir, "mcp-operation-policy.json"),
          "ro",
        ),
      ],
    },
  ]);
}

export function dockerSecurityContractProbeShell(): string {
  return `
  case "$*" in
    *runfree_security_contract_probe*)
      case "$*" in
        *agent-id*)
          printf '%s\\n' \\
            'mount\t/workspace\t0\t/workspace\text4\trw,relatime' \\
            'mount\t/runfree/inbox\t0\t/runfree/inbox\text4\tro,relatime' \\
            'mount\t/runfree/mcp/claude.json\t0\t/runfree/mcp/claude.json\text4\tro,relatime' \\
            'mount\t/workspace/.codex\t0\t/workspace/.codex\text4\tro,relatime' \\
            'mount\t/etc/proxy-ca\t0\t/etc/proxy-ca\text4\tro,relatime' \\
            'content\t/runfree/mcp/claude.json\t0\td8e397af03b5b032f21d0aa967086f0c78b33c87b76f2e9898ae0a144df7de02' \\
            'directory\t/workspace/.codex\t0\t1' \\
            'absence\t/ca/private/proxy-ca.key\t0'
          exit 0
          ;;
        *proxy-id*)
          printf '%s\\n' \\
            'mount\t/ca/private\t0\t/ca/private\text4\trw,relatime' \\
            'mount\t/ca/public\t0\t/ca/public\text4\trw,relatime' \\
            'mount\t/app/runfree-effective\t0\t/app/runfree-effective\text4\tro,relatime' \\
            'mount\t/app/proxy/mcp-operation-policy.json\t0\t/app/proxy/mcp-operation-policy.json\text4\tro,relatime' \\
            'mount\t/run/runfree-proxy-secrets\t0\t/run/runfree-proxy-secrets\ttmpfs\trw,nosuid,nodev,noexec,relatime' \\
            'mount\t/run/runfree-proxy-audit\t0\t/run/runfree-proxy-audit\ttmpfs\trw,nosuid,nodev,noexec,relatime' \\
            'mount\t/run/runfree-proxy-audit-spool\t0\t/run/runfree-proxy-audit-spool\ttmpfs\trw,nosuid,nodev,noexec,relatime' \\
            'mount\t/run/runfree-proxy-status\t0\t/run/runfree-proxy-status\ttmpfs\trw,nosuid,nodev,noexec,relatime' \\
            'mount\t/run/runfree-approvals/pending\t0\t/run/runfree-approvals/pending\ttmpfs\trw,nosuid,nodev,noexec,relatime' \\
            'mount\t/run/runfree-approvals/decisions\t0\t/run/runfree-approvals/decisions\ttmpfs\trw,nosuid,nodev,noexec,relatime' \\
            'stat\t/run/runfree-proxy-secrets\t0\t1001:1001:700' \\
            'stat\t/run/runfree-proxy-audit\t0\t0:0:755' \\
            'stat\t/run/runfree-proxy-audit-spool\t0\t1001:1001:755' \\
            'stat\t/run/runfree-proxy-status\t0\t0:0:755' \\
            'stat\t/run/runfree-proxy-status/request-proxy\t0\t1001:1001:755' \\
            'stat\t/run/runfree-approvals/pending\t0\t1001:1001:700' \\
            'stat\t/run/runfree-approvals/decisions\t0\t0:0:755'
          exit 0
          ;;
      esac
      ;;
  esac
`;
}

beforeEach(() => {
  tmpBase = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-cli-tests-")));
  tmp = path.join(tmpBase, "project");
  hostHome = path.join(tmpBase, "home");
  defaultFakeBin = path.join(tmpBase, "runfree-default-bin");
  fs.mkdirSync(tmp, { recursive: true });
  fs.mkdirSync(hostHome, { recursive: true });
  fs.mkdirSync(defaultFakeBin, { recursive: true });
  const dockerPath = path.join(defaultFakeBin, "docker");
  fs.writeFileSync(dockerPath, [
    "#!/bin/sh",
    "case \"$1\" in",
    "  info|ps) exit 0 ;;",
    "esac",
    "exit 1",
    "",
  ].join("\n"));
  fs.chmodSync(dockerPath, 0o755);
});

afterEach(() => {
  fs.rmSync(tmpBase, { recursive: true, force: true });
});
