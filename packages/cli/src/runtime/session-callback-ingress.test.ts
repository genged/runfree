import { describe, expect, test } from "vitest";

import { projectHash } from "./env.ts";
import {
  mcpCallbackForwarderRoutesToLiveOwner,
  reclaimStaleSessionMcpCallbackForwarders,
  removeSessionMcpCallbackIngress,
} from "./session-callback-ingress.ts";
import {
  boundCallbackForwarder,
  createFakeDocker,
  sessionAgentInspect,
  TEST_SESSION_CONTAINER_ID,
  TEST_SESSION_ID,
  TEST_SESSION_IP,
  type FakeDockerOptions,
} from "./session-callback-ingress.test-harness.ts";
import type { DockerContainerInspect } from "./types.ts";

const PROJECT_ROOT = "/workspace/project";
const PROJECT_ID = projectHash(PROJECT_ROOT);
const COMPOSE_PROJECT = `runfree-${PROJECT_ID}`;
const INTERNAL_NETWORK = `${COMPOSE_PROJECT}_agent_internal`;
const PEER_SESSION_ID = "rf-20260930-peer01";
const PEER_CONTAINER_ID = "9".repeat(64);
const PEER_IP = "172.30.0.41";

const own = (overrides: Partial<Parameters<typeof boundCallbackForwarder>[0]> = {}) => boundCallbackForwarder({
  composeProject: COMPOSE_PROJECT,
  projectId: PROJECT_ID,
  hostPort: "47200",
  containerId: "1".repeat(64),
  ...overrides,
});
const peer = (overrides: Partial<Parameters<typeof boundCallbackForwarder>[0]> = {}) => boundCallbackForwarder({
  composeProject: COMPOSE_PROJECT,
  projectId: PROJECT_ID,
  hostPort: "47300",
  containerId: "2".repeat(64),
  sessionId: PEER_SESSION_ID,
  sessionContainerId: PEER_CONTAINER_ID,
  target: PEER_IP,
  ...overrides,
});
const ownSession = (overrides: Partial<Parameters<typeof sessionAgentInspect>[0]> = {}) => sessionAgentInspect({
  composeProject: COMPOSE_PROJECT,
  projectId: PROJECT_ID,
  ...overrides,
});
const peerSession = () => sessionAgentInspect({
  composeProject: COMPOSE_PROJECT,
  projectId: PROJECT_ID,
  containerId: PEER_CONTAINER_ID,
  sessionId: PEER_SESSION_ID,
  ip: PEER_IP,
});

function fake(containers: DockerContainerInspect[], options: FakeDockerOptions = {}) {
  return createFakeDocker({ projectId: PROJECT_ID, composeProject: COMPOSE_PROJECT, containers, options });
}

function removeOwn(docker: ReturnType<typeof fake>): number {
  return removeSessionMcpCallbackIngress({
    io: docker.io,
    projectId: PROJECT_ID,
    sessionId: TEST_SESSION_ID,
    sourceIp: TEST_SESSION_IP,
  });
}

describe("removeSessionMcpCallbackIngress", () => {
  test("removes this session's forwarder by exact id and leaves a peer's route alone", () => {
    const docker = fake([own(), peer()]);
    expect(removeOwn(docker)).toBe(1);
    expect(docker.removed()).toEqual(["1".repeat(64)]);
    expect(docker.containers.map((container) => container.Id)).toEqual(["2".repeat(64)]);
  });

  test("also removes an unbound legacy forwarder that routes to this session's address", () => {
    const docker = fake([own({ sessionId: null, containerId: "3".repeat(64) }), peer()]);
    expect(removeOwn(docker)).toBe(1);
    expect(docker.removed()).toEqual(["3".repeat(64)]);
  });

  test("is idempotent: nothing routed to the session means nothing removed", () => {
    const docker = fake([peer()]);
    expect(removeOwn(docker)).toBe(0);
    expect(docker.removed()).toEqual([]);
  });

  test("an unreadable inventory is never read as absence", () => {
    const docker = fake([own()], { listFailure: true });
    expect(() => removeOwn(docker)).toThrow("could not list MCP OAuth callback forwarders");
    expect(docker.removed()).toEqual([]);
  });

  test("a removal Docker refuses fails the call, so the caller keeps the record", () => {
    const docker = fake([own()], { removeFailure: true });
    expect(() => removeOwn(docker)).toThrow("Docker failed to remove MCP OAuth callback forwarder");
  });

  test("refuses to remove a lookalike that is not the pinned ingress image", () => {
    const docker = fake([{ ...own(), Image: `sha256:${"0".repeat(64)}` }]);
    expect(() => removeOwn(docker)).toThrow("refusing to remove unverified MCP OAuth callback forwarder");
    expect(docker.removed()).toEqual([]);
  });
});

describe("mcpCallbackForwarderRoutesToLiveOwner", () => {
  const network = { projectId: PROJECT_ID, internalNetwork: INTERNAL_NETWORK };

  test("accepts a running, attached, bound forwarder whose session is live at its target", () => {
    expect(mcpCallbackForwarderRoutesToLiveOwner(own(), [ownSession()], network)).toBe(true);
  });

  test.each([
    ["the forwarder is not running", () => own({ running: false }), () => [ownSession()]],
    ["the forwarder is unbound", () => own({ sessionId: null }), () => [ownSession()]],
    ["its session container is not running", () => own(), () => [ownSession({ running: false })]],
    ["its session container is gone", () => own(), () => []],
    ["its session container carries another session id", () => own(), () => [ownSession({ sessionId: "rf-20260930-other1" })]],
    ["its session container holds another address", () => own(), () => [ownSession({ ip: "172.30.0.77" })]],
    ["it targets another address than its session's", () => own({ target: "172.30.0.77" }), () => [ownSession()]],
  ])("refuses when %s", (_label, forwarder, sessions) => {
    expect(mcpCallbackForwarderRoutesToLiveOwner(forwarder(), sessions(), network)).toBe(false);
  });

  test("refuses a forwarder that is not attached to agent_internal", () => {
    const detached = own();
    const networks = { ...(detached.NetworkSettings?.Networks ?? {}) };
    delete networks[INTERNAL_NETWORK];
    expect(mcpCallbackForwarderRoutesToLiveOwner(
      { ...detached, NetworkSettings: { ...detached.NetworkSettings, Networks: networks } },
      [ownSession()],
      network,
    )).toBe(false);
  });
});

describe("reclaimStaleSessionMcpCallbackForwarders", () => {
  function reclaim(docker: ReturnType<typeof fake>): number {
    return reclaimStaleSessionMcpCallbackForwarders({ io: docker.io, projectId: PROJECT_ID, internalNetwork: INTERNAL_NETWORK });
  }

  test("removes dead and unbound routes, keeping every live session's forwarder", () => {
    const docker = fake([
      ownSession({ running: false }),
      peerSession(),
      own(),
      peer(),
      own({ containerId: "4".repeat(64), hostPort: "47400", sessionId: null, target: PEER_IP }),
    ]);
    expect(reclaim(docker)).toBe(2);
    expect(docker.removed().sort()).toEqual(["1".repeat(64), "4".repeat(64)]);
    expect(docker.containers.some((container) => container.Id === "2".repeat(64))).toBe(true);
  });

  test("keeps everything when every forwarder routes to its live owner", () => {
    const docker = fake([ownSession(), peerSession(), own(), peer()]);
    expect(reclaim(docker)).toBe(0);
    expect(docker.removed()).toEqual([]);
  });

  test("spends no session inspection when there is no callback forwarder", () => {
    const docker = fake([ownSession()]);
    expect(reclaim(docker)).toBe(0);
    expect(docker.captures).toHaveLength(1);
  });

  test("an inventory it cannot read reclaims nothing", () => {
    const docker = fake([own()], { listFailure: true });
    expect(() => reclaim(docker)).toThrow();
    expect(docker.removed()).toEqual([]);
  });

  test("binds ownership to the exact container id, not the session id alone", () => {
    const impostor = sessionAgentInspect({
      composeProject: COMPOSE_PROJECT,
      projectId: PROJECT_ID,
      containerId: "7".repeat(64),
    });
    const docker = fake([impostor, own({ sessionContainerId: TEST_SESSION_CONTAINER_ID })]);
    expect(reclaim(docker)).toBe(1);
  });
});
