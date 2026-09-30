import { expect, test } from "vitest";

import {
  UTILITY_ROLE_LABEL,
  UTILITY_VERSION_LABEL,
  validateIngressForwarderTeardownCandidate,
  validateInternalNetworkParticipants,
} from "./utility-containers.ts";
import { PROJECT_ID_LABEL } from "./constants.ts";
import {
  INGRESS_FORWARDER_COMMAND,
  INGRESS_FORWARDER_ENTRYPOINT,
  INGRESS_FORWARDER_IMAGE,
  ingressHostNetworkName,
} from "./ingress-forwarder.ts";
import type { DockerContainerInspect } from "./types.ts";

const projectId = "abc123def456";
const project = `runfree-${projectId}`;
const internalNetwork = `${project}_agent_internal`;
const hostNetwork = `runfree-vnc-host-${projectId}`;
const agentName = `${project}-agent-1`;
const proxyName = `${project}-proxy-1`;
const sidecarName = `runfree-vnc-forward-${projectId}-5901`;
const ingressImageId = `sha256:${"a".repeat(64)}`;

function container(name: string, networks: string[]): DockerContainerInspect {
  return {
    Config: {
      Labels: { [PROJECT_ID_LABEL]: projectId },
      User: "1000:1000",
    },
    Id: `${name}-id`,
    Name: `/${name}`,
    State: { Running: true },
    HostConfig: {
      NetworkMode: networks[0],
      PortBindings: {},
      SecurityOpt: ["no-new-privileges:true"],
    },
    NetworkSettings: {
      Networks: Object.fromEntries(networks.map((network) => [network, { IPAddress: "172.30.0.20" }])),
      Ports: {},
    },
  };
}

// The retired pre-facility VNC sidecar shape. No recognizer exists for it any
// more; it exists only to prove the fail-closed unapproved-container refusal.
function legacyVncSidecar(overrides: Partial<DockerContainerInspect> = {}): DockerContainerInspect {
  const base: DockerContainerInspect = {
    Config: {
      Cmd: ["-c", "exec socat \"TCP-LISTEN:${VNC_HOST_PORT},bind=$(hostname -i),fork,reuseaddr\" \"TCP:${VNC_TARGET}:${VNC_AGENT_PORT}\""],
      Entrypoint: ["sh"],
      Env: [
        "VNC_HOST_PORT=5901",
        `VNC_TARGET=${agentName}`,
        "VNC_AGENT_PORT=5901",
      ],
      Labels: {
        [PROJECT_ID_LABEL]: projectId,
        [UTILITY_ROLE_LABEL]: "vnc-forwarder",
        [UTILITY_VERSION_LABEL]: "1",
      },
      User: "65534:65534",
    },
    HostConfig: {
      CapAdd: [],
      CapDrop: ["ALL"],
      NetworkMode: hostNetwork,
      PidsLimit: 64,
      PortBindings: { "5901/tcp": [{ HostIp: "127.0.0.1", HostPort: "5901" }] },
      Privileged: false,
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges:true"],
    },
    Id: "vnc-id",
    Mounts: [],
    Name: `/${sidecarName}`,
    State: { Running: true },
    NetworkSettings: {
      Networks: {
        [hostNetwork]: { IPAddress: "172.31.0.2" },
        [internalNetwork]: { IPAddress: "172.30.0.30" },
      },
      Ports: { "5901/tcp": [{ HostIp: "127.0.0.1", HostPort: "5901" }] },
    },
  };
  return {
    ...base,
    ...overrides,
    Config: { ...base.Config, ...overrides.Config },
    HostConfig: { ...base.HostConfig, ...overrides.HostConfig },
    NetworkSettings: { ...base.NetworkSettings, ...overrides.NetworkSettings },
  };
}

function validate(attached: DockerContainerInspect[]) {
  return validateInternalNetworkParticipants({
    attached,
    internalNetwork,
    projectId,
    proxy: container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
  });
}

test("rejects unknown sidecars on agent_internal", () => {
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    container("unexpected", [internalNetwork]),
  ]);

  expect(issues.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
});

test("refuses a retired Compose relay-shaped container as unapproved without any mutation", () => {
  // The retired mcp_callback relay generation has no recognizer left: a
  // container carrying its old role label and command falls through to the
  // fail-closed unapproved-container refusal. Validation only inspects the
  // supplied records — no Docker call, no mutation.
  const base = container("retired-relay", [internalNetwork]);
  const relayShaped: DockerContainerInspect = {
    ...base,
    Config: {
      ...base.Config,
      Cmd: ["node", "/app/proxy/mcp-callback-relay.js"],
      Labels: {
        [PROJECT_ID_LABEL]: projectId,
        [UTILITY_ROLE_LABEL]: "mcp-callback-relay",
        [UTILITY_VERSION_LABEL]: "1",
      },
      User: "1001:1001",
    },
  };
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    relayShaped,
  ]);
  expect(issues.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
  expect(issues.some((issue) => issue.message.includes("retired-relay"))).toBe(true);
});

test("refuses a legacy-VNC-shaped sidecar as unapproved without any mutation", () => {
  // The retired VNC sidecar generation has no recognizer left: even with this
  // project's labels and the historical socat shape it falls through to the
  // fail-closed unapproved-container refusal. Validation only inspects the
  // supplied records — no Docker call, no mutation.
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    legacyVncSidecar(),
  ]);

  expect(issues.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
  expect(issues.some((issue) => issue.message.includes(sidecarName))).toBe(true);
});

const CONTAINER_ROLE_LABEL = "io.runfree.container-role";
const INGRESS_PURPOSE_LABEL = "io.runfree.ingress-purpose";
const ingressHostNetwork = ingressHostNetworkName(projectId);

function ingressForwarder(
  purpose: string,
  hostPort: string,
  overrides: Partial<DockerContainerInspect> = {},
): DockerContainerInspect {
  const base: DockerContainerInspect = {
    Config: {
      Cmd: [...INGRESS_FORWARDER_COMMAND],
      Entrypoint: [INGRESS_FORWARDER_ENTRYPOINT],
      Env: [
        `INGRESS_HOST_PORT=${hostPort}`,
        `INGRESS_TARGET=${agentName}`,
        `INGRESS_TARGET_PORT=${hostPort}`,
      ],
      Labels: {
        [PROJECT_ID_LABEL]: projectId,
        [CONTAINER_ROLE_LABEL]: "ingress-forwarder",
        [INGRESS_PURPOSE_LABEL]: purpose,
      },
      Image: INGRESS_FORWARDER_IMAGE,
      User: "65534:65534",
    },
    HostConfig: {
      AutoRemove: true,
      CapAdd: [],
      CapDrop: ["ALL"],
      NetworkMode: ingressHostNetwork,
      PidsLimit: 64,
      PortBindings: { [`${hostPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: hostPort }] },
      Privileged: false,
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges:true"],
    },
    Id: `ingress-${purpose}-id`,
    Image: ingressImageId,
    Mounts: [],
    Name: `/runfree-ingress-${purpose}-${projectId}-${hostPort}`,
    State: { Running: true },
    NetworkSettings: {
      Networks: {
        [ingressHostNetwork]: { IPAddress: "172.31.0.3" },
        [internalNetwork]: { IPAddress: "172.30.0.31" },
      },
      Ports: { [`${hostPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: hostPort }] },
    },
  };
  return {
    ...base,
    ...overrides,
    Config: { ...base.Config, ...overrides.Config },
    HostConfig: { ...base.HostConfig, ...overrides.HostConfig },
    NetworkSettings: { ...base.NetworkSettings, ...overrides.NetworkSettings },
  };
}

test("accepts a valid new-style ingress forwarder (port purpose) on agent_internal", () => {
  expect(validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000"),
  ])).toEqual([]);
});

test("proves one exact ingress forwarder for teardown", () => {
  expect(validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000"),
    expectedImageId: ingressImageId,
    projectId,
  })).toEqual([]);
});

test("proves exact stopped ingress residue for teardown", () => {
  expect(validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", { State: { Running: false } }),
    expectedImageId: ingressImageId,
    projectId,
  })).toEqual([]);
});

test("teardown proof ignores the mutable creation tag when the immutable image ID matches", () => {
  // The creation tag (Config.Image) is writable after the fact; only the
  // immutable resolved image ID participates in the four-fact teardown proof.
  expect(validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", { Config: { Image: "foreign/image:latest" } }),
    expectedImageId: ingressImageId,
    projectId,
  })).toEqual([]);
});

test("does not authorize teardown when Docker resolved different image bytes", () => {
  const issues = validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", { Image: `sha256:${"b".repeat(64)}` }),
    expectedImageId: ingressImageId,
    projectId,
  });

  expect(issues.map((entry) => entry.code)).toContain("utility-ingress-forwarder-shape");
});

test("does not authorize teardown when the pinned image cannot be resolved", () => {
  const issues = validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000"),
    projectId,
  });

  expect(issues.map((entry) => entry.code)).toContain("utility-ingress-forwarder-shape");
});

test("teardown proof accepts runtime-shape drift on a labeled pinned-image container", () => {
  // Accepted narrowing: runtime shape (auto-remove, caps, mounts, publication)
  // is creation authority, not deletion authority. A labeled container running
  // the pinned image bytes is provably ours to remove.
  expect(validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", { HostConfig: { AutoRemove: false } }),
    expectedImageId: ingressImageId,
    projectId,
  })).toEqual([]);
});

test("does not authorize teardown with a project label but a missing role label", () => {
  const issues = validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", {
      Config: { Labels: { [PROJECT_ID_LABEL]: projectId } },
    }),
    expectedImageId: ingressImageId,
    projectId,
  });

  expect(issues.map((entry) => entry.code)).toContain("utility-ingress-forwarder-shape");
});

test("does not authorize teardown with a role label but a foreign project label", () => {
  const issues = validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", {
      Config: { Labels: { [PROJECT_ID_LABEL]: "another-project", [CONTAINER_ROLE_LABEL]: "ingress-forwarder" } },
    }),
    expectedImageId: ingressImageId,
    projectId,
  });

  expect(issues.map((entry) => entry.code)).toContain("utility-ingress-forwarder-shape");
});

test("does not authorize teardown for another utility's role label", () => {
  const issues = validateIngressForwarderTeardownCandidate({
    container: ingressForwarder("port", "3000", {
      Config: { Labels: { [PROJECT_ID_LABEL]: projectId, [CONTAINER_ROLE_LABEL]: "session-agent" } },
    }),
    expectedImageId: ingressImageId,
    projectId,
  });

  expect(issues.map((entry) => entry.code)).toContain("utility-ingress-forwarder-shape");
});

test("accepts a valid ingress forwarder (vnc purpose)", () => {
  expect(validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("vnc", "5901"),
  ])).toEqual([]);
});

test("rejects an ingress forwarder that publishes a non-loopback port", () => {
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", {
      HostConfig: { PortBindings: { "3000/tcp": [{ HostIp: "0.0.0.0", HostPort: "3000" }] } },
      NetworkSettings: { Ports: { "3000/tcp": [{ HostIp: "0.0.0.0", HostPort: "3000" }] } },
    }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
});

test("rejects an ingress forwarder on a host network other than the derived one", () => {
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", {
      NetworkSettings: {
        Networks: {
          "some-other-bridge": { IPAddress: "172.99.0.2" },
          [internalNetwork]: { IPAddress: "172.30.0.31" },
        },
      },
    }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
});

test("rejects an ingress forwarder with a shell-significant INGRESS_TARGET", () => {
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", {
      Config: { Env: ["INGRESS_HOST_PORT=3000", "INGRESS_TARGET=evil,fork", "INGRESS_TARGET_PORT=3000"] },
    }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
});

test("rejects an ingress forwarder whose command only mentions the socat markers in a comment", () => {
  // An exact command match, not substring markers: a payload that merely names
  // the markers in a shell comment must not pass as the hardened forwarder.
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", {
      Config: { Cmd: ["-c", "sleep infinity # socat TCP-LISTEN:${INGRESS_HOST_PORT} TCP:${INGRESS_TARGET}:${INGRESS_TARGET_PORT}"] },
    }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
});

test("rejects an ingress forwarder that makes agent_internal its primary network mode", () => {
  // Both networks are attached, but agent_internal is primary — hostname -i
  // would resolve the internal-facing address first, defeating the one-way bind.
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", { HostConfig: { NetworkMode: internalNetwork } }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
});

test("rejects an ingress forwarder that does not drop all capabilities", () => {
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", { HostConfig: { CapDrop: [] } }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
});

test("rejects an ingress forwarder whose purpose label and name disagree as an unapproved container", () => {
  // The recognizer refuses to validate a role-labelled forwarder it cannot
  // read legibly; it then fails closed as unapproved rather than being checked
  // against a purpose it does not claim in its name.
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", {
      Config: { Labels: { [PROJECT_ID_LABEL]: projectId, [CONTAINER_ROLE_LABEL]: "ingress-forwarder", [INGRESS_PURPOSE_LABEL]: "vnc" } },
    }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
});

test("rejects an ingress forwarder from a different Runfree project id", () => {
  const issues = validate([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000", {
      Config: { Labels: { [PROJECT_ID_LABEL]: "other-project", [CONTAINER_ROLE_LABEL]: "ingress-forwarder", [INGRESS_PURPOSE_LABEL]: "port" } },
    }),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
});

test("per-session shape accepts a valid ingress forwarder", () => {
  expect(validatePerSession([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    ingressForwarder("port", "3000"),
  ])).toEqual([]);
});

// The mcp-callback forwarder (hop 1 of a session's callback) is bound to
// exactly one live session (session MCP OAuth callback decisions, 2026-09-30):
// env RUNFREE_CALLBACK_SESSION_ID/_CONTAINER name the owner, and the owner must
// be a running session container of this project carrying that session id and
// holding the forwarder's target address. sessionAgent below is that owner.
const SESSION_ID = "rf-20260930-abcdef";
const SESSION_CONTAINER_ID = "c".repeat(64);
const SESSION_IP = "172.30.0.30";

function sessionAgent(overrides: { id?: string; sessionId?: string; ip?: string; running?: boolean } = {}): DockerContainerInspect {
  const id = overrides.id ?? SESSION_CONTAINER_ID;
  return {
    Config: {
      Labels: {
        [PROJECT_ID_LABEL]: projectId,
        [CONTAINER_ROLE_LABEL]: "session-agent",
        "io.runfree.session-id": overrides.sessionId ?? SESSION_ID,
      },
      User: "1000:1000",
    },
    Id: id,
    Name: `/session-${id.slice(0, 8)}`,
    State: { Running: overrides.running ?? true },
    HostConfig: { NetworkMode: internalNetwork, PortBindings: {}, SecurityOpt: ["no-new-privileges:true"] },
    NetworkSettings: { Networks: { [internalNetwork]: { IPAddress: overrides.ip ?? SESSION_IP } }, Ports: {} },
  };
}

function mcpCallbackForwarder(options: {
  target?: string;
  hostPort?: string;
  targetPort?: string;
  sessionId?: string | null;
  containerId?: string | null;
  extraEnv?: readonly string[];
  id?: string;
} = {}): DockerContainerInspect {
  const hostPort = options.hostPort ?? "47123";
  const env = [
    `INGRESS_HOST_PORT=${hostPort}`,
    `INGRESS_TARGET=${options.target ?? SESSION_IP}`,
    `INGRESS_TARGET_PORT=${options.targetPort ?? hostPort}`,
    ...(options.sessionId === null ? [] : [`RUNFREE_CALLBACK_SESSION_ID=${options.sessionId ?? SESSION_ID}`]),
    ...(options.containerId === null ? [] : [`RUNFREE_CALLBACK_SESSION_CONTAINER=${options.containerId ?? SESSION_CONTAINER_ID}`]),
    ...(options.extraEnv ?? []),
  ];
  return ingressForwarder("mcp-callback", hostPort, {
    ...(options.id ? { Id: options.id } : {}),
    Config: { Env: env },
  });
}

const proxyParticipant = () => container(proxyName, [internalNetwork, `${project}_proxy_egress`]);

test("accepts an mcp-callback forwarder bound to the live session it targets", () => {
  expect(validatePerSession([proxyParticipant(), sessionAgent(), mcpCallbackForwarder()])).toEqual([]);
});

test("accepts two sessions' forwarders on different ports", () => {
  const otherContainer = "d".repeat(64);
  expect(validatePerSession([
    proxyParticipant(),
    sessionAgent(),
    sessionAgent({ id: otherContainer, sessionId: "rf-20260930-ghijkl", ip: "172.30.0.32" }),
    mcpCallbackForwarder(),
    mcpCallbackForwarder({
      hostPort: "47555",
      target: "172.30.0.32",
      sessionId: "rf-20260930-ghijkl",
      containerId: otherContainer,
      id: "second-forwarder",
    }),
  ])).toEqual([]);
});

test.each([
  ["an unbound (pre-session-owned) forwarder, even targeting a live session", { sessionId: null, containerId: null }, /must be bound to its owning session/u],
  ["a hardwired non-session target (the legacy bug)", { target: "172.30.0.20" }, /its own live session's internal IP/u],
  ["a container name target", { target: agentName }, /IPv4 address, not a name/u],
  ["a binding to another container", { containerId: "e".repeat(64) }, /its own live session's internal IP/u],
  ["a binding to another session id", { sessionId: "rf-20260930-zzzzzz" }, /its own live session's internal IP/u],
  ["a malformed session binding", { sessionId: "../../x" }, /malformed session binding/u],
  ["different ports on the two hops", { targetPort: "47124" }, /forward to the port it publishes/u],
  ["a port outside the callback block", { hostPort: "5000" }, /callback port in 47100-48099/u],
  ["a duplicated binding entry", { extraEnv: ["RUNFREE_CALLBACK_SESSION_ID=rf-20260930-zzzzzz"] }, /must set RUNFREE_CALLBACK_SESSION_ID once/u],
] as const)("rejects an mcp-callback forwarder with %s", (_label, options, message) => {
  const issues = validatePerSession([proxyParticipant(), sessionAgent(), mcpCallbackForwarder(options)]);
  expect(issues.map((issue) => issue.code)).toContain("utility-ingress-forwarder-shape");
  expect(issues.some((issue) => message.test(issue.message))).toBe(true);
});

test("rejects an mcp-callback forwarder whose bound session container has stopped", () => {
  const issues = validatePerSession([proxyParticipant(), sessionAgent({ running: false }), mcpCallbackForwarder()]);
  expect(issues.some((issue) => /its own live session's internal IP/u.test(issue.message))).toBe(true);
});

test("rejects a second mcp-callback forwarder for the same session", () => {
  const issues = validatePerSession([
    proxyParticipant(),
    sessionAgent(),
    mcpCallbackForwarder(),
    mcpCallbackForwarder({ hostPort: "47555", id: "second-forwarder" }),
  ]);
  expect(issues.some((issue) => /must own at most one mcp-callback forwarder/u.test(issue.message))).toBe(true);
});

function roleContainer(role: string, id: string, project = projectId): DockerContainerInspect {
  return {
    Config: { Labels: { [PROJECT_ID_LABEL]: project, [CONTAINER_ROLE_LABEL]: role }, User: "1000:1000" },
    Id: id,
    Name: `/${id}`,
    State: { Running: true },
    HostConfig: { NetworkMode: internalNetwork, PortBindings: {}, SecurityOpt: ["no-new-privileges:true"] },
    NetworkSettings: { Networks: { [internalNetwork]: { IPAddress: "172.30.0.30" } }, Ports: {} },
  };
}

function validatePerSession(attached: DockerContainerInspect[]) {
  return validateInternalNetworkParticipants({
    // No agent/agentName: the per-session runtime shape.
    attached,
    internalNetwork,
    projectId,
    proxy: container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
  });
}

test("per-session shape requires only the proxy, not a standing agent", () => {
  expect(validatePerSession([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
  ])).toEqual([]);
});

test("per-session shape accepts admitted session containers and ephemeral helpers by role", () => {
  expect(validatePerSession([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    roleContainer("session-agent", "session-1"),
    roleContainer("ephemeral-helper", "helper-1"),
  ])).toEqual([]);
});

test("refuses a container carrying the proxy's name but a different ID", () => {
  // Proxy identity is the exact inspected container ID; a same-named impostor
  // must fall through to the fail-closed unapproved-container refusal.
  const impostor = { ...container(proxyName, [internalNetwork]), Id: "impostor-id" };
  const issues = validatePerSession([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    impostor,
  ]);
  expect(issues.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
});

test("per-session shape still refuses an unlabelled or foreign transient container", () => {
  const unlabelled = validatePerSession([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    container("interloper", [internalNetwork]),
  ]);
  expect(unlabelled.map((issue) => issue.code)).toContain("agent-network-unapproved-container");

  const foreignRole = validatePerSession([
    container(proxyName, [internalNetwork, `${project}_proxy_egress`]),
    roleContainer("session-agent", "foreign-1", "other-project"),
  ]);
  expect(foreignRole.map((issue) => issue.code)).toContain("agent-network-unapproved-container");
});

test("per-session shape still requires the proxy participant", () => {
  const issues = validatePerSession([
    roleContainer("session-agent", "session-1"),
  ]);
  expect(issues.map((issue) => issue.code)).toContain("agent-network-count");
});
