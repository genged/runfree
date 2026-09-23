import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { projectInfo } from "../packages/cli/src/config.ts";
import { projectHash } from "../packages/cli/src/project-identity.ts";
import { mcpOAuthCallbackPort } from "../packages/cli/src/runtime/mcp.ts";
import {
  dockerInspectSecurityEvidence,
  dockerSecurityContractProbeShell,
  runTsCli,
  runtimeTargetForTsCliProject,
  selectCurrentDesiredControlsForTsCliProject,
  tmp,
  tmpBase,
  tsCliEnv,
} from "./installable-cli.test-harness.ts";

describe("installable runfree CLI: sources and intent wiring", () => {
  test("typescript cli reports command source validation failures without stacks", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    const fakeBin = path.join(tmpBase, "fake-bin");
    fs.mkdirSync(fakeBin, { recursive: true });
    fs.writeFileSync(path.join(fakeBin, "bad-gh"), [
      "#!/bin/sh",
      "echo 'not logged in sk-abcdefghijklmnopqrstuvwxyz1234567890TOKEN' >&2",
      "exit 7",
      "",
    ].join("\n"));
    fs.chmodSync(path.join(fakeBin, "bad-gh"), 0o755);

    const result = runTsCli(["credential", "source", "add", "github-cli", "--", "bad-gh", "auth", "token"], {
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("runfree error: command source exited nonzero: bad-gh status 7: not logged in [redacted]");
    expect(result.stderr).not.toContain("sk-abcdefghijklmnopqrstuvwxyz1234567890TOKEN");
    expect(result.stderr).not.toContain("at runCommandSource");
  });

  test("credential source add rejects an unknown pre-separator option before running the host command", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    const fakeBin = path.join(tmpBase, "fake-bin");
    const marker = path.join(tmpBase, "host-command-ran");
    fs.mkdirSync(fakeBin, { recursive: true });
    fs.writeFileSync(path.join(fakeBin, "marker-gh"), `#!/bin/sh\ntouch '${marker}'\necho tok\n`);
    fs.chmodSync(path.join(fakeBin, "marker-gh"), 0o755);

    // The typed `credential source add` keeps pre-`--` options strict: a bad pre-separator
    // option must fail (now via the yargs grammar) before the host command after
    // `--` is resolved or executed.
    const result = runTsCli(["credential", "source", "add", "github-cli", "--bogus", "--", "marker-gh", "auth", "token"], {
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Unknown argument: bogus");
    expect(fs.existsSync(marker)).toBe(false);
    expect(fs.existsSync(path.join(tmpBase, "xdg-state/runfree/sources.json"))).toBe(false);
  });

  // The admin enforcement is unit-tested directly via typed intents; these
  // smoke tests cover the public CLI argv -> intent wiring for representative
  // flag families so a broken/renamed yargs option is caught end-to-end.
  describe("typed CLI parser -> intent wiring", () => {
    function readPolicy(): { hosts: string[]; requests?: Record<string, { methods?: string[] }> } {
      return JSON.parse(fs.readFileSync(path.join(tmp, ".runfree/network-policy.json"), "utf8"));
    }

    test("host add --read-only wires a GET/HEAD/OPTIONS request rule", () => {
      expect(runTsCli(["init"]).status).toBe(0);
      const result = runTsCli(["host", "add", "pypi.org", "--read-only", "--no-reload"]);
      expect(result.status, result.stderr).toBe(0);
      const policy = readPolicy();
      expect(policy.hosts).toContain("pypi.org");
      expect(policy.requests?.["pypi.org"]?.methods?.slice().sort()).toEqual(["GET", "HEAD", "OPTIONS"]);
    });

    test("service enable --skip-broad reaches the intent and skips broad hosts", () => {
      expect(runTsCli(["init"]).status).toBe(0);
      const result = runTsCli(["service", "enable", "github", "--skip-broad", "--no-reload"]);
      expect(result.status, result.stderr).toBe(0);
      const policy = readPolicy() as ReturnType<typeof readPolicy> & {
        services?: Record<string, { selection?: { skippedHosts?: string[] } }>;
      };
      expect(policy.services?.github?.selection?.skippedHosts).toContain("objects.githubusercontent.com");
    });

    test("credential set-source wires a named source after explicit host authorization", () => {
      expect(runTsCli(["init"]).status).toBe(0);
      expect(runTsCli(["credential", "source", "add", "api-cli", "--", "node", "-e", "process.stdout.write('tok')"]).status).toBe(0);
      expect(runTsCli(["host", "add", "api.example.com", "--no-reload"]).status).toBe(0);
      const add = runTsCli(["credential", "add", "myapi", "--host", "api.example.com", "--no-reload"]);
      expect(add.status, add.stderr).toBe(0);
      selectCurrentDesiredControlsForTsCliProject();
      const set = runTsCli(["credential", "set-source", "myapi", "--from-source", "api-cli", "--no-sync"]);
      expect(set.status, set.stderr).toBe(0);
      const show = runTsCli(["credential", "source", "show", "api-cli"]);
      expect(show.stdout).toContain("used by: myapi");
    });
  });

  test("typescript cli keeps runtime path env out of admin policy reloads", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    selectCurrentDesiredControlsForTsCliProject();

    const fakeBin = path.join(tmp, "fake-bin");
    const envLog = path.join(tmp, "docker-env.log");
    const project = projectInfo(tmp, tsCliEnv());
    const target = runtimeTargetForTsCliProject(project);
    const validationMarkerJson = JSON.stringify({
      agentId: "agent-id",
      components: target.contract.components,
      contractHash: target.contract.contractHash,
      mcpOAuthCallbackPort: mcpOAuthCallbackPort(tmp),
      mcpOAuthCallbackTopologyVersion: 2,
      proofVersion: 4,
      projectId: projectHash(tmp),
      proxyId: "proxy-id",
    });
    const componentRows = [
      [
        "agent-id",
        "agent",
        "1",
        target.plan.components.selectedAgentImageInputDigest,
        "<no value>",
        target.plan.components.topologyDigest,
        "<no value>",
        target.plan.activeRuntime.agentImage,
        "true",
        target.plan.projectId,
        target.plan.composeProjectName,
      ].join("\\t"),
      [
        "proxy-id",
        "proxy",
        "1",
        "<no value>",
        target.plan.components.proxyImageInputDigest,
        target.plan.components.topologyDigest,
        "<no value>",
        target.plan.activeRuntime.proxyImage,
        "true",
        target.plan.projectId,
        target.plan.composeProjectName,
      ].join("\\t"),
    ].join("\\n");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s|%s|%s|%s\\n' "$1" "$RUNFREE_CLAUDE_DIR" "$RUNFREE_CLAUDE_JSON" "$DOCKER_CLI_HINTS" >> "${envLog}"
case "$1" in
  info) exit 0 ;;
  ps)
    if [ "$2" = "-q" ]; then
      case "$*" in
        *com.docker.compose.service=proxy*) ;;
      esac
    elif [ "$2" = "-aq" ]; then
      case "$*" in
        *com.docker.compose.service=proxy*) echo proxy-id ;;
        *com.docker.compose.service=mcp_callback*) ;;
        *) echo agent-id ;;
      esac
    fi
    exit 0
    ;;
  inspect)
    case "$*" in
      *io.runfree.agent-image-input-digest*) printf '%b\n' '${componentRows}' ;;
      *"inspect agent-id proxy-id"*) printf '%s' '${dockerInspectSecurityEvidence(project)}' ;;
      *State.Running*) echo true ;;
      *State.StartedAt*) echo '2026-06-18T00:00:00.000000000Z' ;;
      *com.docker.compose.project*) echo fake-project ;;
    esac
    exit 0
    ;;
  restart) exit 1 ;;
  start) exit 1 ;;
  exec)
${dockerSecurityContractProbeShell()}
    case "$*" in
      *request-proxy.json*)
        control_generation="$(node -e 'const value=require(process.argv[1]);process.stdout.write(value.controlGeneration)' ${JSON.stringify(project.paths.controlProxyActivePath)})"
        policy_generation="$(node -e 'const value=require(process.argv[1]);process.stdout.write(value.policyGeneration)' ${JSON.stringify(project.paths.controlProxyActivePath)})"
        printf '{"controlGeneration":"%s","generation":"%s","policyGeneration":"%s","rulesetVerified":true,"appliedAt":"2026-06-18T00:00:00.000Z"}\\n' "$control_generation" "$policy_generation" "$policy_generation"
        printf '{"controlGeneration":"%s","generation":"%s","policyGeneration":"%s","appliedAt":"2026-06-18T00:00:00.000Z"}\\n' "$control_generation" "$policy_generation" "$policy_generation"
        exit 0
        ;;
    esac
    printf '%s' '${validationMarkerJson}'
    exit 0
    ;;
esac
exit 0
`);
    fs.chmodSync(path.join(fakeBin, "docker"), 0o755);

    const result = runTsCli(["host", "add", "registry.npmjs.org"], {
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("effective policy: saved; applies when the runtime starts (effective policy generation sha256:");
    const log = fs.readFileSync(envLog, "utf8");
    expect(log).toContain("|false\n");
    expect(log).not.toContain("restart|");
    expect(log).not.toContain("/xdg-state/runfree/projects/");
    expect(log).not.toContain("compose|");
  });

  test("typescript cli toggles proxy verbose markers while following proxy logs", () => {
    const init = runTsCli(["init"]);
    expect(init.status, init.stderr).toBe(0);
    selectCurrentDesiredControlsForTsCliProject();

    const fakeBin = path.join(tmp, "fake-bin");
    const dockerLog = path.join(tmp, "docker.log");
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
printf '%s\\n' "$*" >> "${dockerLog}"
case "$1" in
  info) exit 0 ;;
  ps)
    if [ "$2" = "-aq" ]; then
      case "$*" in
        *io.runfree.project-id*) echo agent-id ;;
        *com.docker.compose.service=proxy*) echo proxy-id ;;
      esac
    fi
    exit 0
    ;;
  inspect)
    case "$*" in
      *com.docker.compose.project*) echo fake-project ;;
    esac
    exit 0
    ;;
  exec) exit 0 ;;
  compose) exit 0 ;;
esac
exit 0
`);
    fs.chmodSync(path.join(fakeBin, "docker"), 0o755);

    const result = runTsCli(["logs", "proxy", "--verbose"], {
      PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
    });

    expect(result.status, result.stderr).toBe(0);
    const log = fs.readFileSync(dockerLog, "utf8");
    expect(log).toMatch(/exec --user 0:0 proxy-id sh -c mkdir -p '\/run\/runfree-proxy-verbose' && : > '\/run\/runfree-proxy-verbose\/[a-z0-9-]+'/);
    expect(log).toContain("compose --project-directory");
    expect(log).toContain("-p fake-project");
    expect(log).toContain("logs -f proxy");
    expect(log).toMatch(/exec --user 0:0 proxy-id sh -c rm -f '\/run\/runfree-proxy-verbose\/[a-z0-9-]+'/);
  });

});
