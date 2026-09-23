import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  BUILTIN_AGENT_DESCRIPTORS,
  MCP_AGENT_IDS,
  agentChoiceLabel,
  agentStateEnvironment,
  agentStateHostPath,
  composeAgentEnvironment,
  composeAgentStateMounts,
  defaultBuiltinAgentCommands,
  validateBuiltinAgentDescriptors,
  type BuiltinAgentDescriptor,
} from "./agents.ts";

const [claudeDescriptor] = BUILTIN_AGENT_DESCRIPTORS;

function cloneDescriptor(overrides: Partial<BuiltinAgentDescriptor>): BuiltinAgentDescriptor {
  if (!claudeDescriptor) throw new Error("missing Claude descriptor");
  return {
    ...claudeDescriptor,
    stateMounts: claudeDescriptor.stateMounts.map((mount) => ({
      ...mount,
      bootstrap: { ...mount.bootstrap },
    })),
    ...overrides,
  };
}

describe("built-in agent descriptors", () => {
  test("defines the current built-in commands as trusted descriptors", () => {
    expect(defaultBuiltinAgentCommands()).toEqual({
      claude: { command: "claude --dangerously-skip-permissions --add-dir /runfree/inbox" },
      codex: {
        command: "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
      },
      pi: { command: "pi" },
    });
    expect(BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => descriptor.id)).toEqual(["claude", "codex", "pi"]);
    expect(BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => descriptor.directLaunch)).toEqual([
      {
        path: "/usr/local/bin/claude",
        args: ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
      },
      {
        path: "/usr/local/bin/codex",
        args: ["-c", "check_for_update_on_startup=false", "--dangerously-bypass-approvals-and-sandbox"],
      },
      { path: "/usr/local/bin/pi", args: [] },
    ]);
    expect(BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => descriptor.label)).toEqual(["Claude Code", "Codex CLI", "Pi"]);
    expect(MCP_AGENT_IDS).toEqual(["claude", "codex"]);
    expect(BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => agentChoiceLabel(descriptor.id)))
      .toEqual(["Claude Code (claude)", "Codex CLI (codex)", "Pi (pi)"]);
    expect(agentChoiceLabel("custom-agent")).toBe("custom-agent");
    expect(BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => descriptor.requiredServices)).toEqual([
      ["agent-claude"],
      ["agent-codex"],
      [],
    ]);
  });

  test("derives state host paths and compose inputs from descriptors", () => {
    const project = { paths: { stateDir: path.join("/tmp", "runfree-state") } };

    expect(agentStateHostPath(project, BUILTIN_AGENT_DESCRIPTORS[0].stateMounts[0]))
      .toBe(path.join("/tmp", "runfree-state", "claude"));
    expect(agentStateEnvironment(project)).toEqual({
      RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR: path.join("/tmp", "runfree-state", "claude"),
      RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON: path.join("/tmp", "runfree-state", "claude.json"),
      RUNFREE_AGENT_STATE_CODEX_HOME: path.join("/tmp", "runfree-state", "codex"),
      RUNFREE_AGENT_STATE_PI_AGENT_DIR: path.join("/tmp", "runfree-state", "pi"),
    });
    expect(composeAgentStateMounts()).toEqual([
      {
        sourceEnv: "RUNFREE_AGENT_STATE_CLAUDE_CONFIG_DIR",
        target: "/home/agent/.claude",
      },
      {
        sourceEnv: "RUNFREE_AGENT_STATE_CLAUDE_CONFIG_JSON",
        target: "/home/agent/.claude.json",
      },
      {
        sourceEnv: "RUNFREE_AGENT_STATE_CODEX_HOME",
        target: "/home/agent/.codex",
      },
      {
        sourceEnv: "RUNFREE_AGENT_STATE_PI_AGENT_DIR",
        target: "/home/agent/.pi/agent",
      },
    ]);
    expect(composeAgentEnvironment()).toEqual({
      CODEX_CA_CERTIFICATE: "/etc/proxy-ca/proxy-ca.crt",
      CODEX_HOME: "/home/agent/.codex",
      DISABLE_AUTOUPDATER: "1",
      PI_CODING_AGENT_DIR: "/home/agent/.pi/agent",
      PI_SKIP_VERSION_CHECK: "1",
      PI_TELEMETRY: "0",
    });
  });

  test("rejects unsafe descriptor definitions", () => {
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({ id: "Bad" }),
    ])).toThrow("invalid built-in agent id");
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({ stateMounts: [{ ...claudeDescriptor.stateMounts[0], hostSubdir: "/host/.claude" }] }),
    ])).toThrow("hostSubdir must be relative");
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({ stateMounts: [{ ...claudeDescriptor.stateMounts[0], containerPath: "/workspace/.claude" }] }),
    ])).toThrow("containerPath must be under /home/agent");
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({ env: { RUNFREE_SECRET: "/tmp/nope" } }),
    ])).toThrow("uses reserved RUNFREE_ env");
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({ directLaunch: { path: "/bin/claude", args: [] } }),
    ])).toThrow("direct launch must use bounded canonical argv");
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({ directLaunch: { path: "/usr/local/bin/claude", args: ["--different"] } }),
    ])).toThrow("direct launch must match its default command");
    expect(() => validateBuiltinAgentDescriptors([
      cloneDescriptor({
        stateMounts: [
          claudeDescriptor.stateMounts[0],
          { ...claudeDescriptor.stateMounts[0] },
        ],
      }),
    ])).toThrow("duplicate agent state env");
  });
});
