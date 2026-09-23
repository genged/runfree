import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test } from "vitest";

import {
  REQUIRED_TOPOLOGY_ASSERTIONS,
  formatTopologyIssues,
  validateRuntimeTopology,
} from "./topology.ts";
import { NON_RESOLVING_CONNECT_PROBE_HOST } from "./probes.ts";
import { PROJECT_ID_LABEL } from "./constants.ts";
import type { ActiveRuntimePlan } from "./plan.ts";
import {
  UTILITY_ROLE_LABEL,
  UTILITY_VERSION_LABEL,
} from "./utility-containers.ts";
import { projectHash } from "./env.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

function captureResult(status: number, stdout = "", stderr = ""): CaptureResult {
  return { status, stdout, stderr };
}

test("topology assertion inventory covers the current security checks", () => {
  expect(REQUIRED_TOPOLOGY_ASSERTIONS.map((entry) => entry.code).sort()).toEqual([
    "agent-container-exists",
    "agent-default-route-denied",
    "agent-direct-dns-denied",
    "agent-direct-tcp-denied",
    "agent-gateway-reachability-denied",
    "agent-host-gateway-denied",
    "agent-host-ports-denied",
    "agent-ip-matches-plan",
    "agent-net-admin-dropped",
    "agent-net-raw-dropped",
    "agent-network-unapproved-container",
    "agent-network-count",
    "agent-no-new-privileges",
    "agent-pid1-identity",
    "agent-proxy-reachability",
    "git-layout-container-proof",
    "internal-network-gateway-free",
    "internal-network-internal",
    "internal-network-ipv6-disabled",
    "proxy-container-exists",
    "proxy-dns-root-only",
    "proxy-egress-ip-matches-plan",
    "proxy-egress-network-subnet",
    "proxy-egress-route",
    "proxy-fixed-agent-ingress",
    "proxy-net-admin-shape",
    "proxy-net-raw-dropped",
    "proxy-nftables-shape",
    "proxy-privileged-command-denied",
    "raw-connect-disallowed-host-denied",
    "raw-connect-non-443-denied",
    "utility-ingress-forwarder-shape",
    "utility-mcp-callback-relay-shape",
    "utility-vnc-forwarder-shape",
  ].sort());
});

test("formatTopologyIssues renders structured codes", () => {
  expect(formatTopologyIssues([
    { code: "agent-container-exists", severity: "error", message: "agent missing" },
  ])).toEqual(["[agent-container-exists] agent missing"]);
});

test("topology accepts a validated VNC utility on agent_internal", () => {
  const projectRoot = "/workspace/project";
  const projectId = projectHash(projectRoot);
  const project = `runfree-${projectId}`;
  const internalNetwork = `${project}_agent_internal`;
  const egressNetwork = `${project}_proxy_egress`;
  const agentName = `${project}-agent-1`;
  const proxyName = `${project}-proxy-1`;
  const sidecarName = `runfree-vnc-forward-${projectId}-5901`;
  const context = {
    env: { RUNFREE_PROJECT_ID: projectId },
    network: {
      agentIp: "172.30.0.11",
      callbackSidecarIp: "172.30.0.12",
      proxyEgressGateway: "172.30.1.1",
      proxyEgressIp: "172.30.1.10",
      proxyEgressSubnet: "172.30.1.0/24",
      proxyIp: "172.30.0.10",
      subnet: "172.30.0.0/24",
    },
    project: {
      config: {},
      paths: { policyPath: "/tmp/policy.json" },
    },
    projectRoot,
    runtimeRoot: "/runtime",
  } as unknown as RuntimeContext;
  const agent = {
    Config: { User: "1000:1000" },
    HostConfig: {
      CapAdd: null,
      CapDrop: ["NET_ADMIN", "NET_RAW"],
      NetworkMode: internalNetwork,
      PortBindings: {},
      SecurityOpt: ["no-new-privileges:true"],
    },
    Id: "agent-id",
    Name: `/${agentName}`,
    NetworkSettings: { Ports: {}, Networks: { [internalNetwork]: { IPAddress: "172.30.0.11" } } },
    State: { Running: true },
  };
  const proxy = {
    HostConfig: { NetworkMode: internalNetwork, PortBindings: {} },
    Id: "proxy-id",
    Name: `/${proxyName}`,
    NetworkSettings: {
      Ports: {},
      Networks: {
        [internalNetwork]: { IPAddress: "172.30.0.10" },
        [egressNetwork]: { IPAddress: "172.30.1.10" },
      },
    },
    // Stop before expensive probe validation; this test targets network participants.
    State: { ExitCode: 1, Running: false, Status: "exited" },
  };
  const vnc = {
    Config: {
      Cmd: ["-c", "exec socat \"TCP-LISTEN:${VNC_HOST_PORT},bind=$(hostname -i),fork,reuseaddr\" \"TCP:${VNC_TARGET}:${VNC_AGENT_PORT}\""],
      Entrypoint: ["sh"],
      Env: ["VNC_HOST_PORT=5901", `VNC_TARGET=${agentName}`, "VNC_AGENT_PORT=5901"],
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
      NetworkMode: `runfree-vnc-host-${projectId}`,
      PidsLimit: 64,
      PortBindings: { "5901/tcp": [{ HostIp: "127.0.0.1", HostPort: "5901" }] },
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges:true"],
    },
    Id: "vnc-id",
    Mounts: [],
    Name: `/${sidecarName}`,
    NetworkSettings: {
      Networks: {
        [internalNetwork]: { IPAddress: "172.30.0.30" },
        [`runfree-vnc-host-${projectId}`]: { IPAddress: "172.31.0.2" },
      },
      Ports: { "5901/tcp": [{ HostIp: "127.0.0.1", HostPort: "5901" }] },
    },
    State: { Running: true },
  };
  const io: RuntimeIO = {
    admin: () => Promise.resolve(0),
    capture(command, args) {
      if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=agent"))) {
        return captureResult(0, "agent-id\n");
      }
      if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=proxy"))) {
        return captureResult(0, "proxy-id\n");
      }
      if (command === "docker" && args[0] === "inspect" && args.includes("agent-id") && args.includes("proxy-id")) {
        return captureResult(0, JSON.stringify([agent, proxy]));
      }
      if (command === "docker" && args[0] === "inspect" && args.includes("vnc-id")) {
        return captureResult(0, JSON.stringify([vnc]));
      }
      if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes(internalNetwork)) {
        return captureResult(0, JSON.stringify([{
          Containers: {
            "agent-id": { Name: agentName },
            "proxy-id": { Name: proxyName },
            "vnc-id": { Name: sidecarName },
          },
          EnableIPv6: false,
          Internal: true,
          Name: internalNetwork,
          Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
        }]));
      }
      if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes(egressNetwork)) {
        return captureResult(0, JSON.stringify([{
          EnableIPv6: false,
          IPAM: { Config: [{ Gateway: "172.30.1.1", Subnet: "172.30.1.0/24" }] },
          Name: egressNetwork,
        }]));
      }
      return captureResult(0);
    },
    commandExists: () => true,
    confirm: () => true,
    run: () => 0,
  };

  expect(validateRuntimeTopology(context, io).map((issue) => issue.code)).not.toContain("agent-network-count");
});

test("topology validation accepts an ActiveRuntimePlan", () => {
  const projectRoot = "/workspace/project";
  const projectId = projectHash(projectRoot);
  const project = `runfree-${projectId}`;
  const internalNetwork = `${project}_agent_internal`;
  const egressNetwork = `${project}_proxy_egress`;
  const agentName = `${project}-agent-1`;
  const proxyName = `${project}-proxy-1`;
  const plan = {
    activeRuntime: {
      activeRuntimeRoot: "/runtime-active",
      agentImage: "runfree/agent-runtime:test",
      composeDirectory: "/runtime-active/agent",
      composeFile: "/runtime-active/agent/compose.yaml",
      materialized: true,
      proxyImage: "runfree/proxy-runtime:test",
      runtimeDigest: "sha256:test",
    },
    agentImage: undefined,
    baseRuntimeRoot: "/runtime-base",
    composeProjectName: project,
    dependencyOverlays: { mounts: [], namedVolumes: [] },
    execution: {
      adminEnvProvider: { dockerClient: {}, resolveChildEnv: () => ({}) },
      composeEnv: {},
      dockerClientEnv: {},
      runtimeInputBuildEnv: {},
    },
    gitLayout: { kind: "direct", mounts: [] },
    gitRepositoryShape: { kind: "plain" },
    mcpOAuth: { callbackPort: 0, callbackUrl: "" },
    network: {
      agentIp: "172.30.0.11",
      callbackSidecarIp: "172.30.0.12",
      proxyEgressGateway: "172.30.1.1",
      proxyEgressIp: "172.30.1.10",
      proxyEgressSubnet: "172.30.1.0/24",
      proxyIp: "172.30.0.10",
      subnet: "172.30.0.0/24",
    },
    paths: { policyPath: "/tmp/policy.json" },
    project: { config: {}, paths: { policyPath: "/tmp/policy.json" } },
    projectId,
    projectRoot,
    projectRuntimeRoot: "/project-runtime",
    runfreeVersion: "test",
    runtimeDigest: "sha256:test",
  } as unknown as ActiveRuntimePlan;
  const agent = {
    Config: { User: "1000:1000" },
    HostConfig: {
      CapAdd: null,
      CapDrop: ["NET_ADMIN", "NET_RAW"],
      NetworkMode: internalNetwork,
      PortBindings: {},
      SecurityOpt: ["no-new-privileges:true"],
    },
    Id: "agent-id",
    Name: `/${agentName}`,
    NetworkSettings: { Ports: {}, Networks: { [internalNetwork]: { IPAddress: "172.30.0.11" } } },
    State: { Running: true },
  };
  const proxy = {
    HostConfig: { NetworkMode: internalNetwork, PortBindings: {} },
    Id: "proxy-id",
    Name: `/${proxyName}`,
    NetworkSettings: {
      Ports: {},
      Networks: {
        [internalNetwork]: { IPAddress: "172.30.0.10" },
        [egressNetwork]: { IPAddress: "172.30.1.10" },
      },
    },
    State: { ExitCode: 1, Running: false, Status: "exited" },
  };
  const io: RuntimeIO = {
    admin: () => Promise.resolve(0),
    capture(command, args) {
      if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=agent"))) {
        return captureResult(0, "agent-id\n");
      }
      if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=proxy"))) {
        return captureResult(0, "proxy-id\n");
      }
      if (command === "docker" && args[0] === "inspect") {
        return captureResult(0, JSON.stringify([agent, proxy]));
      }
      if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes(internalNetwork)) {
        return captureResult(0, JSON.stringify([{
          Containers: {
            "agent-id": { Name: agentName },
            "proxy-id": { Name: proxyName },
          },
          EnableIPv6: false,
          Internal: true,
          Name: internalNetwork,
          Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
        }]));
      }
      if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes(egressNetwork)) {
        return captureResult(0, JSON.stringify([{
          EnableIPv6: false,
          IPAM: { Config: [{ Gateway: "172.30.1.1", Subnet: "172.30.1.0/24" }] },
          Name: egressNetwork,
        }]));
      }
      return captureResult(0);
    },
    commandExists: () => true,
    confirm: () => true,
    run: () => 0,
  };

  expect(validateRuntimeTopology(plan, io).map((issue) => issue.code)).not.toContain("agent-ip-matches-plan");
});

// The non-443 CONNECT probe proves that the proxy rejects the port before DNS
// and before any upstream connection. That claim must not vary with project
// policy content — a deny-all policy has no host to borrow — and runtime
// validation must never make a third-party service a hidden dependency.
test("the non-443 CONNECT probe targets a reserved non-resolving host, never a policy host", () => {
  // Pinned, not just shape-checked: tests/runtime/sandbox.sh runs the same
  // probe against a live runtime and derives this exact literal out of
  // probes.ts. Asserting only `.endsWith(".invalid")` would let a rename leave
  // the two probes silently disagreeing — both still valid, just different,
  // which only surfaces when someone debugs a live failure.
  expect(NON_RESOLVING_CONNECT_PROBE_HOST).toBe("deny-all.runfree.invalid");
  expect(NON_RESOLVING_CONNECT_PROBE_HOST.endsWith(".invalid")).toBe(true);

  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "runfree-topology-probe-")));
  try {
    const policyPath = path.join(tmp, "network-policy.json");
    // A valid, non-empty policy: if the probe target were still derived from
    // policy content, this host would show up in the probe command.
    fs.writeFileSync(policyPath, JSON.stringify({ hosts: ["policy-host.example"] }));

    const projectRoot = path.join(tmp, "project");
    const projectId = projectHash(projectRoot);
    const project = `runfree-${projectId}`;
    const internalNetwork = `${project}_agent_internal`;
    const egressNetwork = `${project}_proxy_egress`;
    const context = {
      env: { RUNFREE_PROJECT_ID: projectId },
      network: {
        agentIp: "172.30.0.11",
        callbackSidecarIp: "172.30.0.12",
        proxyEgressGateway: "172.30.1.1",
        proxyEgressIp: "172.30.1.10",
        proxyEgressSubnet: "172.30.1.0/24",
        proxyIp: "172.30.0.10",
        subnet: "172.30.0.0/24",
      },
      project: { config: {}, paths: { policyPath } },
      projectRoot,
      runtimeRoot: "/runtime",
    } as unknown as RuntimeContext;
    const agent = {
      Config: { User: "1000:1000" },
      HostConfig: {
        CapAdd: null,
        CapDrop: ["NET_ADMIN", "NET_RAW"],
        NetworkMode: internalNetwork,
        PortBindings: {},
        SecurityOpt: ["no-new-privileges:true"],
      },
      Id: "agent-id",
      Name: `/${project}-agent-1`,
      NetworkSettings: { Ports: {}, Networks: { [internalNetwork]: { IPAddress: "172.30.0.11" } } },
      State: { Running: true },
    };
    const proxy = {
      HostConfig: { CapAdd: ["NET_ADMIN"], CapDrop: ["NET_RAW"], NetworkMode: internalNetwork, PortBindings: {} },
      Id: "proxy-id",
      Name: `/${project}-proxy-1`,
      NetworkSettings: {
        Ports: {},
        Networks: {
          [internalNetwork]: { IPAddress: "172.30.0.10" },
          [egressNetwork]: { IPAddress: "172.30.1.10" },
        },
      },
      State: { Running: true },
    };
    // Both containers run, so validation proceeds all the way through the
    // proxy denial probes instead of short-circuiting on container state.
    const execCommands: string[] = [];
    const io: RuntimeIO = {
      admin: () => Promise.resolve(0),
      capture(command, args) {
        if (command === "docker" && args[0] === "exec") execCommands.push(args.join(" "));
        if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=agent"))) {
          return captureResult(0, "agent-id\n");
        }
        if (command === "docker" && args[0] === "ps" && args.some((arg) => arg.includes("com.docker.compose.service=proxy"))) {
          return captureResult(0, "proxy-id\n");
        }
        if (command === "docker" && args[0] === "inspect" && args.includes("agent-id") && args.includes("proxy-id")) {
          return captureResult(0, JSON.stringify([agent, proxy]));
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes(internalNetwork)) {
          return captureResult(0, JSON.stringify([{
            Containers: { "agent-id": { Name: `${project}-agent-1` }, "proxy-id": { Name: `${project}-proxy-1` } },
            EnableIPv6: false,
            Internal: true,
            Name: internalNetwork,
            Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
          }]));
        }
        if (command === "docker" && args[0] === "network" && args[1] === "inspect" && args.includes(egressNetwork)) {
          return captureResult(0, JSON.stringify([{
            EnableIPv6: false,
            IPAM: { Config: [{ Gateway: "172.30.1.1", Subnet: "172.30.1.0/24" }] },
            Name: egressNetwork,
          }]));
        }
        return captureResult(0);
      },
      commandExists: () => true,
      confirm: () => true,
      run: () => 0,
    };

    validateRuntimeTopology(context, io);

    // Post-cutover plain validation has no shared agent to run the agent-position
    // CONNECT probe from; the non-443 denial is proven from an admitted session
    // / ephemeral helper (the live admission tranches, and sandbox.sh against a
    // real runtime). The unit-level guarantee preserved here is that no probe
    // this path does emit borrows a policy host or a third-party service — a
    // deny-all policy has no host to borrow, so the probe target must not vary
    // with policy content. The reserved probe host is pinned above.
    const nonHttpsProbes = execCommands.filter((entry) => entry.includes("CONNECT") && entry.includes(":22"));
    expect(nonHttpsProbes).toHaveLength(0);
    expect(execCommands.some((entry) => entry.includes("policy-host.example"))).toBe(false);
    expect(execCommands.some((entry) => entry.includes("api.github.com"))).toBe(false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// L3: the agent-position deny probes run as ONE ephemeral helper batch.
function denyProbeBatchPlanFixture(batch: (script: string) => CaptureResult) {
  const projectRoot = "/workspace/project";
  const projectId = projectHash(projectRoot);
  const project = `runfree-${projectId}`;
  const internalNetwork = `${project}_agent_internal`;
  const egressNetwork = `${project}_proxy_egress`;
  const proxyName = `${project}-proxy-1`;
  const networkId = "d".repeat(64);
  const plan = {
    activeRuntime: {
      activeRuntimeRoot: "/runtime-active",
      agentImage: "runfree/agent-runtime:test",
      composeDirectory: "/runtime-active/agent",
      composeFile: "/runtime-active/agent/compose.yaml",
      materialized: true,
      proxyImage: "runfree/proxy-runtime:test",
      runtimeDigest: "sha256:test",
    },
    agentImage: undefined,
    baseRuntimeRoot: "/runtime-base",
    composeProjectName: project,
    dependencyOverlays: { mounts: [], namedVolumes: [] },
    execution: {
      adminEnvProvider: { dockerClient: {}, resolveChildEnv: () => ({}) },
      composeEnv: {},
      dockerClientEnv: {},
      runtimeInputBuildEnv: {},
    },
    generationV2: { controlPlane: { controlPlaneGenerationDigest: `sha256:${"e".repeat(64)}` } },
    gitLayout: { kind: "direct", mounts: [] },
    gitRepositoryShape: { kind: "plain" },
    mcpOAuth: { callbackPort: 0, callbackUrl: "" },
    network: {
      agentIp: "172.30.0.11",
      callbackSidecarIp: "172.30.0.12",
      proxyEgressGateway: "172.30.1.1",
      proxyEgressIp: "172.30.1.10",
      proxyEgressSubnet: "172.30.1.0/24",
      proxyIp: "172.30.0.10",
      subnet: "172.30.0.0/24",
    },
    paths: { policyPath: "/tmp/policy.json" },
    project: { config: {}, paths: { policyPath: "/tmp/policy.json" } },
    projectId,
    projectRoot,
    projectRuntimeRoot: "/project-runtime",
    runfreeVersion: "test",
    runtimeDigest: "sha256:test",
  } as unknown as ActiveRuntimePlan;
  const proxy = {
    HostConfig: { CapAdd: ["NET_ADMIN"], CapDrop: ["NET_RAW"], NetworkMode: internalNetwork, PortBindings: {} },
    Id: "proxy-id",
    Name: `/${proxyName}`,
    NetworkSettings: {
      Ports: {},
      Networks: {
        [internalNetwork]: { IPAddress: "172.30.0.10" },
        [egressNetwork]: { IPAddress: "172.30.1.10" },
      },
    },
    State: { Running: true },
  };
  const helperRuns: string[][] = [];
  const io: RuntimeIO = {
    admin: () => Promise.resolve(0),
    capture(command, args) {
      if (command !== "docker") return captureResult(0);
      const text = args.join(" ");
      if (args[0] === "run") {
        helperRuns.push([...args]);
        return batch(args[args.length - 1] ?? "");
      }
      if (args[0] === "ps" && text.includes("com.docker.compose.service=proxy")) {
        return captureResult(0, "proxy-id\n");
      }
      if (args[0] === "inspect" && args.includes("proxy-id")) {
        return captureResult(0, JSON.stringify([proxy]));
      }
      if (args[0] === "network" && args[1] === "inspect" && args.includes(internalNetwork)) {
        return captureResult(0, JSON.stringify([{
          Containers: { "proxy-id": { Name: proxyName } },
          EnableIPv6: false,
          Id: networkId,
          Internal: true,
          Name: internalNetwork,
          Options: { "com.docker.network.bridge.inhibit_ipv4": "true" },
        }]));
      }
      if (args[0] === "network" && args[1] === "inspect" && args.includes(egressNetwork)) {
        return captureResult(0, JSON.stringify([{
          EnableIPv6: false,
          IPAM: { Config: [{ Gateway: "172.30.1.1", Subnet: "172.30.1.0/24" }] },
          Name: egressNetwork,
        }]));
      }
      if (text.includes("CapBnd")) return captureResult(0, "0000000000001000\n");
      return captureResult(0);
    },
    commandExists: () => true,
    confirm: () => true,
    run: () => 0,
  };
  // `boundaryViolated` is the escalation side channel `startup.ts` routes on: a
  // probe that observed a real confinement hole contains the validation proxy
  // and fails as `boundary-violation`, while a probe that could not run fails
  // as `observation-unavailable` and leaves it alone. Exposed here because the
  // deny-probe batch is the only place that draws the distinction from a
  // helper's own exit codes.
  const observed = { boundaryViolated: false };
  return {
    helperRuns,
    observed,
    run: () => validateRuntimeTopology(plan, io, {
      onBoundaryViolation: () => { observed.boundaryViolated = true; },
    }).map((issue) => issue.code),
  };
}

test("agent-position deny probes run as one hardened helper batch", () => {
  const fixture = denyProbeBatchPlanFixture((script) => {
    const probes = [...script.matchAll(/runfree_pid_(\d+)=\$!/g)].length;
    return captureResult(0, `${Array.from({ length: probes }, (_, index) => `RUNFREE_DENY_PROBE ${index} exit=1`).join("\n")}\n`);
  });
  const codes = fixture.run();

  expect(fixture.helperRuns).toHaveLength(1);
  const [helper] = fixture.helperRuns;
  expect(helper).toEqual(expect.arrayContaining([
    "--user", "1000:1000", "--cap-drop", "ALL", "--network", "d".repeat(64),
  ]));
  expect(helper).not.toContain("--cap-add");
  expect(helper.join(" ")).toContain("io.runfree.helper-purpose=deny-probe");
  expect(helper.join(" ")).toContain("RUNFREE_DENY_PROBE");
  for (const code of [
    "agent-direct-tcp-denied",
    "agent-direct-dns-denied",
    "agent-default-route-denied",
    "agent-host-gateway-denied",
  ]) {
    expect(codes).not.toContain(code);
  }
});

test("a broken deny-probe batch fails validation for every probe, never denial-proven", () => {
  // The inverted run-level contract: a batch that exits nonzero — even with
  // plausible records — proves nothing, and every probe's own issue code
  // surfaces so operators see exactly which denials are unproven.
  const fixture = denyProbeBatchPlanFixture(() => captureResult(96, "", "missing probe binary: dig"));
  const codes = fixture.run();

  expect(fixture.helperRuns).toHaveLength(1);
  for (const code of [
    "agent-direct-tcp-denied",
    "agent-direct-dns-denied",
    "agent-default-route-denied",
    "agent-host-gateway-denied",
  ]) {
    expect(codes).toContain(code);
  }
  // Unproven, not breached: the batch observed nothing, so containment must
  // not run off it.
  expect(fixture.observed.boundaryViolated).toBe(false);
});

test("a deny probe that could not run is unproven rather than a boundary violation", () => {
  // Exit 126/127 is the helper failing to execute the probe at all. It fails
  // validation like any unproven denial, but reporting it as a breach would
  // contain the proxy over a missing binary.
  const fixture = denyProbeBatchPlanFixture((script) => {
    const probes = [...script.matchAll(/runfree_pid_(\d+)=\$!/g)].length;
    return captureResult(0, `${Array.from({ length: probes }, (_, index) =>
      `RUNFREE_DENY_PROBE ${index} exit=${index === 1 ? 127 : 1}`).join("\n")}\n`);
  });
  const codes = fixture.run();

  expect(codes).toContain("agent-direct-dns-denied");
  expect(codes).not.toContain("agent-direct-tcp-denied");
  expect(fixture.observed.boundaryViolated).toBe(false);
});

test("a deny probe observed succeeding fails validation with that probe's code", () => {
  const fixture = denyProbeBatchPlanFixture((script) => {
    const probes = [...script.matchAll(/runfree_pid_(\d+)=\$!/g)].length;
    // Probe 0 (direct TCP egress) escapes: a real confinement hole must be
    // reported as exactly that probe's failure.
    return captureResult(0, `${Array.from({ length: probes }, (_, index) => `RUNFREE_DENY_PROBE ${index} exit=${index === 0 ? 0 : 1}`).join("\n")}\n`);
  });
  const codes = fixture.run();

  expect(codes).toContain("agent-direct-tcp-denied");
  expect(codes).not.toContain("agent-direct-dns-denied");
  // A live escape is the one deny-probe outcome that contains the proxy.
  expect(fixture.observed.boundaryViolated).toBe(true);
});
