import path from "node:path";

import { AGENT_HOME_TARGETS } from "./runtime/mount-target-policy.ts";

export type AgentStateBootstrap =
  | { type: "empty-directory" }
  | { type: "empty-json-file" }
  | { type: "codex-file-credential-store" };

export type AgentStateMount = {
  bootstrap: AgentStateBootstrap;
  containerPath: string;
  hostSubdir: string;
  id: string;
  kind: "directory" | "file";
  mode: number;
};

export type BuiltinAgentDescriptor = {
  directLaunch: {
    args: string[];
    path: string;
  };
  defaultCommand: string;
  legacyDefaultCommands?: string[];
  env: Record<string, string>;
  id: string;
  label: string;
  processNames: string[];
  resume?: {
    exactArgvPrefix?: string[];
    pickerArgv?: string[];
  };
  requiredServices: string[];
  stateMounts: AgentStateMount[];
};

type AgentProject = {
  paths: {
    stateDir: string;
  };
};

const AGENT_ID_RE = /^[a-z][a-z0-9-]*$/;
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]*$/;

const DESCRIPTORS: BuiltinAgentDescriptor[] = [
  {
    id: "claude",
    label: "Claude Code",
    directLaunch: {
      path: "/usr/local/bin/claude",
      args: ["--dangerously-skip-permissions", "--add-dir", "/runfree/inbox"],
    },
    defaultCommand: "claude --dangerously-skip-permissions --add-dir /runfree/inbox",
    legacyDefaultCommands: ["claude --dangerously-skip-permissions"],
    env: {
      DISABLE_AUTOUPDATER: "1",
    },
    stateMounts: [
      {
        id: "config-dir",
        hostSubdir: "claude",
        containerPath: AGENT_HOME_TARGETS.claudeDir,
        kind: "directory",
        mode: 0o700,
        bootstrap: { type: "empty-directory" },
      },
      {
        id: "config-json",
        hostSubdir: "claude.json",
        containerPath: AGENT_HOME_TARGETS.claudeJson,
        kind: "file",
        mode: 0o600,
        bootstrap: { type: "empty-json-file" },
      },
    ],
    requiredServices: ["agent-claude"],
    processNames: ["claude"],
    resume: {
      exactArgvPrefix: [
        "claude",
        "--dangerously-skip-permissions",
        "--add-dir",
        "/runfree/inbox",
        "--resume",
      ],
      pickerArgv: [
        "claude",
        "--dangerously-skip-permissions",
        "--add-dir",
        "/runfree/inbox",
        "--resume",
      ],
    },
  },
  {
    id: "codex",
    label: "Codex CLI",
    directLaunch: {
      path: "/usr/local/bin/codex",
      args: ["-c", "check_for_update_on_startup=false", "--dangerously-bypass-approvals-and-sandbox"],
    },
    defaultCommand: "codex -c check_for_update_on_startup=false --dangerously-bypass-approvals-and-sandbox",
    legacyDefaultCommands: ["codex --dangerously-bypass-approvals-and-sandbox"],
    env: {
      CODEX_HOME: AGENT_HOME_TARGETS.codexHome,
      CODEX_CA_CERTIFICATE: "/etc/proxy-ca/proxy-ca.crt",
    },
    stateMounts: [
      {
        id: "home",
        hostSubdir: "codex",
        containerPath: AGENT_HOME_TARGETS.codexHome,
        kind: "directory",
        mode: 0o700,
        bootstrap: { type: "codex-file-credential-store" },
      },
    ],
    requiredServices: ["agent-codex"],
    processNames: ["codex"],
    resume: {
      pickerArgv: [
        "codex",
        "-c",
        "check_for_update_on_startup=false",
        "resume",
        "--dangerously-bypass-approvals-and-sandbox",
      ],
    },
  },
  {
    id: "pi",
    label: "Pi",
    directLaunch: {
      path: "/usr/local/bin/pi",
      args: [],
    },
    defaultCommand: "pi",
    env: {
      PI_CODING_AGENT_DIR: AGENT_HOME_TARGETS.piAgentDir,
      PI_SKIP_VERSION_CHECK: "1",
      PI_TELEMETRY: "0",
    },
    stateMounts: [
      {
        id: "agent-dir",
        hostSubdir: "pi",
        containerPath: AGENT_HOME_TARGETS.piAgentDir,
        kind: "directory",
        mode: 0o700,
        bootstrap: { type: "empty-directory" },
      },
    ],
    requiredServices: [],
    processNames: ["pi"],
  },
];

function assertIdentifier(value: string, label: string): void {
  if (!AGENT_ID_RE.test(value)) {
    throw new Error(`invalid built-in agent ${label}: ${value || "<empty>"}`);
  }
}

function assertRelativeStatePath(value: string, label: string): void {
  if (value.trim() === "" || path.isAbsolute(value)) {
    throw new Error(`${label}.hostSubdir must be relative`);
  }
  const normalized = path.normalize(value);
  if (normalized === ".." || normalized.startsWith(`..${path.sep}`)) {
    throw new Error(`${label}.hostSubdir must stay under the project state directory`);
  }
}

function assertContainerPath(value: string, label: string): void {
  const relative = path.posix.relative("/home/agent", value);
  if (!value.startsWith("/") || relative === "" || relative.startsWith("..") || path.posix.isAbsolute(relative)) {
    throw new Error(`${label}.containerPath must be under /home/agent`);
  }
}

function assertAgentEnv(name: string, value: string, label: string): void {
  if (!ENV_NAME_RE.test(name)) {
    throw new Error(`${label}.${name || "<empty>"} is not a valid environment name`);
  }
  if (name.startsWith("RUNFREE_")) {
    throw new Error(`${label}.${name} uses reserved RUNFREE_ env`);
  }
  if (/[\r\n]/.test(value)) {
    throw new Error(`${label}.${name} must not contain newlines`);
  }
  if (value.startsWith("/") && !(value.startsWith("/home/agent/") || value.startsWith("/etc/proxy-ca/"))) {
    throw new Error(`${label}.${name} must reference an approved container path`);
  }
}

function toEnvPart(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

export function agentStateEnvName(agentId: string, mountId: string): string {
  return `RUNFREE_AGENT_STATE_${toEnvPart(agentId)}_${toEnvPart(mountId)}`;
}

export function validateBuiltinAgentDescriptors(descriptors: readonly BuiltinAgentDescriptor[]): void {
  const ids = new Set<string>();
  const stateEnvNames = new Set<string>();
  for (const descriptor of descriptors) {
    assertIdentifier(descriptor.id, "id");
    if (ids.has(descriptor.id)) throw new Error(`duplicate built-in agent id: ${descriptor.id}`);
    ids.add(descriptor.id);
    if (descriptor.label.trim() === "") throw new Error(`built-in agent ${descriptor.id} label must be non-empty`);
    if (descriptor.defaultCommand.trim() === "") throw new Error(`built-in agent ${descriptor.id} command must be non-empty`);
    if (!descriptor.directLaunch.path.startsWith("/usr/local/bin/")
      || path.posix.normalize(descriptor.directLaunch.path) !== descriptor.directLaunch.path
      || descriptor.directLaunch.path.endsWith("/")
      || descriptor.directLaunch.args.some((entry) => entry === "" || /[\r\n\0]/.test(entry))) {
      throw new Error(`built-in agent ${descriptor.id} direct launch must use bounded canonical argv`);
    }
    const directLaunchCommand = [path.posix.basename(descriptor.directLaunch.path), ...descriptor.directLaunch.args].join(" ");
    if (directLaunchCommand !== descriptor.defaultCommand) {
      throw new Error(`built-in agent ${descriptor.id} direct launch must match its default command`);
    }
    for (const command of descriptor.legacyDefaultCommands ?? []) {
      if (command.trim() === "" || command === descriptor.defaultCommand) {
        throw new Error(`built-in agent ${descriptor.id} legacy command must be non-empty and distinct`);
      }
    }
    for (const [name, value] of Object.entries(descriptor.env)) {
      assertAgentEnv(name, value, `built-in agent ${descriptor.id} env`);
    }
    for (const processName of descriptor.processNames) {
      if (processName.trim() === "" || /[\s/]/.test(processName)) {
        throw new Error(`built-in agent ${descriptor.id} process names must be simple names`);
      }
    }
    for (const serviceId of descriptor.requiredServices) {
      assertIdentifier(serviceId, `required service for ${descriptor.id}`);
    }
    for (const argv of [descriptor.resume?.exactArgvPrefix, descriptor.resume?.pickerArgv]) {
      if (argv === undefined) continue;
      if (argv.length === 0 || argv.some((entry) => entry.trim() === "" || /[\r\n\0]/.test(entry))) {
        throw new Error(`built-in agent ${descriptor.id} resume argv must contain safe non-empty elements`);
      }
    }
    for (const mount of descriptor.stateMounts) {
      const label = `built-in agent ${descriptor.id} state mount ${mount.id}`;
      assertIdentifier(mount.id, "state mount id");
      assertRelativeStatePath(mount.hostSubdir, label);
      assertContainerPath(mount.containerPath, label);
      if (!Number.isInteger(mount.mode) || mount.mode < 0 || mount.mode > 0o777) {
        throw new Error(`${label}.mode must be a file mode`);
      }
      if (mount.kind === "file" && mount.bootstrap.type === "empty-directory") {
        throw new Error(`${label} cannot use directory bootstrap for a file`);
      }
      const stateEnvName = agentStateEnvName(descriptor.id, mount.id);
      if (stateEnvNames.has(stateEnvName)) throw new Error(`duplicate agent state env: ${stateEnvName}`);
      stateEnvNames.add(stateEnvName);
    }
  }
}

validateBuiltinAgentDescriptors(DESCRIPTORS);

export const BUILTIN_AGENT_DESCRIPTORS: readonly BuiltinAgentDescriptor[] = DESCRIPTORS;
export const MCP_AGENT_IDS = ["claude", "codex"] as const;

export function builtinAgent(id: string): BuiltinAgentDescriptor | undefined {
  return BUILTIN_AGENT_DESCRIPTORS.find((descriptor) => descriptor.id === id);
}

export function agentChoiceLabel(id: string): string {
  const descriptor = builtinAgent(id);
  return descriptor ? `${descriptor.label} (${descriptor.id})` : id;
}

export function isMcpAgentId(value: string | undefined): value is (typeof MCP_AGENT_IDS)[number] {
  return value !== undefined && MCP_AGENT_IDS.some((id) => id === value);
}

export function defaultBuiltinAgentCommands(): Record<string, { command: string }> {
  return Object.fromEntries(BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => [
    descriptor.id,
    { command: descriptor.defaultCommand },
  ]));
}

export function agentStateHostPath(project: AgentProject, mount: AgentStateMount): string {
  return path.join(project.paths.stateDir, mount.hostSubdir);
}

export function agentStateEnvironment(project: AgentProject): Record<string, string> {
  return Object.fromEntries(BUILTIN_AGENT_DESCRIPTORS.flatMap((descriptor) => descriptor.stateMounts.map((mount) => [
    agentStateEnvName(descriptor.id, mount.id),
    agentStateHostPath(project, mount),
  ])));
}

export function composeAgentStateMounts(): Array<{ sourceEnv: string; target: string; readOnly?: boolean }> {
  return BUILTIN_AGENT_DESCRIPTORS.flatMap((descriptor) => descriptor.stateMounts.map((mount) => ({
    sourceEnv: agentStateEnvName(descriptor.id, mount.id),
    target: mount.containerPath,
  })));
}

export function composeAgentEnvironment(): Record<string, string> {
  return Object.assign({}, ...BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => descriptor.env)) as Record<string, string>;
}

function sortedRecord(record: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(record).sort(([left], [right]) => left.localeCompare(right)));
}

export function agentDescriptorRuntimeInputs(): object[] {
  return BUILTIN_AGENT_DESCRIPTORS.map((descriptor) => ({
    defaultCommand: descriptor.defaultCommand,
    legacyDefaultCommands: descriptor.legacyDefaultCommands,
    env: sortedRecord(descriptor.env),
    id: descriptor.id,
    label: descriptor.label,
    processNames: [...descriptor.processNames].sort(),
    ...(descriptor.resume ? { resume: descriptor.resume } : {}),
    requiredServices: [...descriptor.requiredServices].sort(),
    stateMounts: descriptor.stateMounts.map((mount) => ({
      bootstrap: mount.bootstrap,
      containerPath: mount.containerPath,
      hostSubdir: mount.hostSubdir,
      id: mount.id,
      kind: mount.kind,
      mode: mount.mode,
    })),
  }));
}
