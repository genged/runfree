import { normalizeContainerPath } from "./mount-target-policy.ts";

export type RuntimeComposeMount = {
  type: "bind" | "volume";
  source: string;
  target: string;
  readOnly?: boolean;
  noCopy?: boolean;
};

export type RuntimeComposeAgentStateMount = {
  sourceEnv: string;
  target: string;
  readOnly?: boolean;
};

export type RuntimeComposeRenderOptions = {
  agentStateMounts?: RuntimeComposeAgentStateMount[];
  agentVolumes?: RuntimeComposeMount[];
  namedVolumes?: string[];
  proxyEnvironment?: Readonly<Record<string, string>>;
};

function validateEnvName(name: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`invalid runtime compose environment name: ${name || "<empty>"}`);
  }
}

function validateEnvValue(value: string): void {
  if (!/^[A-Za-z0-9._:/-]+$/.test(value)) {
    throw new Error(`invalid runtime compose environment value: ${value || "<empty>"}`);
  }
}

function validateNamedVolume(name: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(name)) {
    throw new Error(`invalid runtime compose volume name: ${name || "<empty>"}`);
  }
}

function validateNoDuplicateMountTargets(mounts: RuntimeComposeMount[]): void {
  const seen: string[] = [];
  for (const mount of mounts) {
    const target = normalizeContainerPath(mount.target);
    if (seen.includes(target)) throw new Error(`duplicate runtime compose mount target: ${target}`);
    const overlap = seen.find((existing) => target.startsWith(`${existing}/`) || existing.startsWith(`${target}/`));
    if (overlap) throw new Error(`overlapping runtime compose mount targets: ${overlap} and ${target}`);
    seen.push(target);
  }
}

function isTopLevelBlock(line: string): boolean {
  return /^[a-zA-Z0-9_-]+:\s*$/.test(line);
}

function findBlockEnd(lines: string[], start: number, predicate: (line: string) => boolean): number {
  for (let index = start + 1; index < lines.length; index += 1) {
    if (predicate(lines[index])) return index;
  }
  return lines.length;
}

function beforeTrailingBlank(lines: string[], index: number): number {
  let insertion = index;
  while (insertion > 0 && lines[insertion - 1] === "") insertion -= 1;
  return insertion;
}

// True once a line dedents to `indent` spaces or fewer (a sibling key or an
// enclosing block's next entry); blank lines never end a block on their own.
function isDedentedAtOrBelow(line: string, indent: number): boolean {
  const match = /^( *)\S/.exec(line);
  return match !== null && match[1].length <= indent;
}

function insertLines(lines: string[], index: number, rendered: string): string[] {
  return [
    ...lines.slice(0, index),
    ...rendered.split("\n"),
    ...lines.slice(index),
  ];
}

function stateMountToVolume(mount: RuntimeComposeAgentStateMount): RuntimeComposeMount {
  validateEnvName(mount.sourceEnv);
  return {
    type: "bind",
    source: `\${${mount.sourceEnv}:?${mount.sourceEnv} is required}`,
    target: mount.target,
    readOnly: mount.readOnly,
  };
}

function insertNamedVolumes(compose: string, volumes: string[] | undefined): string {
  const names = Array.from(new Set(volumes ?? [])).sort();
  if (names.length === 0) return compose;
  const lines = compose.split("\n");
  const volumesStart = lines.findIndex((line) => line === "volumes:");
  if (volumesStart === -1) {
    throw new Error("embedded runtime compose.yaml no longer has the expected top-level volumes block");
  }
  const volumesEnd = findBlockEnd(lines, volumesStart, isTopLevelBlock);
  const rendered = names.map((name) => {
    validateNamedVolume(name);
    return `  ${name}:`;
  }).join("\n");
  return insertLines(lines, beforeTrailingBlank(lines, volumesEnd), rendered).join("\n");
}

// Inserts entries into the proxy service's `environment:` mapping, sorted and
// appended at the end of the block. Confined to that one mapping: a template
// key with the same name refuses rather than shadowing it, so this can only
// ever add to the fixed template environment, never override it.
function insertProxyEnvironment(compose: string, entries: Readonly<Record<string, string>> | undefined): string {
  const values = entries ?? {};
  const names = Object.keys(values).sort();
  if (names.length === 0) return compose;
  const lines = compose.split("\n");
  const servicesStart = lines.findIndex((line) => line === "services:");
  if (servicesStart === -1) {
    throw new Error("embedded runtime compose.yaml no longer has the expected top-level services block");
  }
  const servicesEnd = findBlockEnd(lines, servicesStart, isTopLevelBlock);
  const proxyStart = lines.findIndex(
    (line, index) => index > servicesStart && index < servicesEnd && line === "  proxy:",
  );
  if (proxyStart === -1) {
    throw new Error("embedded runtime compose.yaml no longer has the expected proxy service block");
  }
  const environmentStart = lines.findIndex(
    (line, index) => index > proxyStart && index < servicesEnd && line === "    environment:",
  );
  if (environmentStart === -1) {
    throw new Error("embedded runtime compose.yaml no longer has the expected proxy environment block");
  }
  const environmentEnd = findBlockEnd(lines, environmentStart, (line) => isDedentedAtOrBelow(line, 4));
  const existingNames = new Set(
    lines
      .slice(environmentStart + 1, environmentEnd)
      .map((line) => /^ {6}([A-Za-z_][A-Za-z0-9_]*):/.exec(line)?.[1])
      .filter((name): name is string => name !== undefined),
  );
  const rendered = names.map((name) => {
    validateEnvName(name);
    const value = values[name];
    validateEnvValue(value);
    if (existingNames.has(name)) {
      throw new Error(`runtime compose proxy environment already defines ${name}`);
    }
    return `      ${name}: ${value}`;
  }).join("\n");
  return insertLines(lines, beforeTrailingBlank(lines, environmentEnd), rendered).join("\n");
}

// The runtime template ships the per-session shape: proxy plus the
// agent_internal network, no shared `agent` service, and no legacy proxy
// agent-IP env. Sessions are created by the admission driver and carry their
// own mounts and environment through the session container template, and the
// MCP OAuth callback is the per-session mcp-callback ingress forwarder rather
// than a Compose sidecar. Rendering is therefore the named-volume insertion,
// plus the proxy environment insertion that mints
// `RUNFREE_SESSION_ADMISSION_SOURCE`, on top of the duplicate-target
// validation the session state mounts need.
export function renderRuntimeCompose(compose: string, options: RuntimeComposeRenderOptions): string {
  validateNoDuplicateMountTargets([
    ...(options.agentStateMounts ?? []).map(stateMountToVolume),
    ...(options.agentVolumes ?? []),
  ]);
  const withVolumes = insertNamedVolumes(compose, options.namedVolumes);
  return insertProxyEnvironment(withVolumes, options.proxyEnvironment);
}
