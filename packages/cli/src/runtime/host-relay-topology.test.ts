import { describe, expect, test } from "vitest";

import {
  expectedHostRelayEnvironment,
  hostRelayProofIssues,
  hostRelayTopologyIssues,
  lookupHostRelayContainerIds,
  type HostRelayExpectation,
} from "./host-relay-topology.ts";
import { PROXY_EXTRA_HOSTS } from "./topology.ts";
import type { CaptureResult, DockerContainerInspect } from "./types.ts";

const PROXY_IMAGE = `sha256:${"a".repeat(64)}`;
const RELAY_ID = "b".repeat(64);
const EFFECTIVE = "/home/me/.local/state/runfree/projects/abc/control/effective/proxy";
const NETWORK = {
  proxyIp: "172.30.120.2",
  subnet: "172.30.120.0/26",
  proxyEgressIp: "172.30.120.66",
  proxyEgressSubnet: "172.30.120.64/26",
  proxyEgressGateway: "172.30.120.65",
};
const GENERATION_LABELS = {
  "io.runfree.proxy-image-input-digest": `sha256:${"d".repeat(64)}`,
  "io.runfree.topology-digest": `sha256:${"e".repeat(64)}`,
  "io.runfree.version": "0.7.0",
};
const PROXY: DockerContainerInspect = {
  Image: PROXY_IMAGE,
  Config: { Entrypoint: ["dumb-init", "--"], Labels: { ...GENERATION_LABELS, "io.runfree.container-role": "proxy" } },
};

const expectation = (mode: HostRelayExpectation["mode"]): HostRelayExpectation => ({
  mode,
  projectId: "0123456789ab",
  composeProject: "runfree-0123456789ab",
  proxy: PROXY,
  effectiveProxyDir: EFFECTIVE,
  extraHosts: PROXY_EXTRA_HOSTS,
  network: NETWORK,
});

const LABELS = {
  "io.runfree.managed": "true",
  "io.runfree.container-role": "host-relay",
  "io.runfree.project-id": "0123456789ab",
  "io.runfree.compose-project": "runfree-0123456789ab",
  "io.runfree.lifecycle-owner": "compose",
  "io.runfree.label-schema": "1",
  "io.runfree.digest-schema": "1",
  ...GENERATION_LABELS,
  "com.docker.compose.project": "runfree-0123456789ab",
  "com.docker.compose.service": "host_relay",
};

const ENV = [
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "NODE_VERSION=22.12.0",
  ...Object.entries(expectedHostRelayEnvironment(NETWORK)).map(([name, value]) => `${name}=${value}`),
];

function relay(overrides: { host?: Record<string, unknown>; config?: Record<string, unknown>; top?: Record<string, unknown> } = {}): DockerContainerInspect {
  return {
    Id: RELAY_ID,
    Name: "/runfree-0123456789ab-host-relay",
    Image: PROXY_IMAGE,
    State: { Running: true, Status: "running" },
    Config: {
      User: "65534:65534",
      Entrypoint: ["dumb-init", "--"],
      Cmd: ["node", "/app/proxy/host-relay.js"],
      Env: ENV,
      Labels: LABELS,
      ...overrides.config,
    },
    HostConfig: {
      NetworkMode: "host",
      Privileged: false,
      CapAdd: null,
      CapDrop: ["ALL"],
      ReadonlyRootfs: true,
      SecurityOpt: ["no-new-privileges:true"],
      PidsLimit: 64,
      PortBindings: {},
      ExtraHosts: ["gateway.runfree.internal:host-gateway"],
      ...overrides.host,
    },
    Mounts: [{ Type: "bind", Source: EFFECTIVE, Destination: "/app/runfree-effective", RW: false }],
    ...overrides.top,
  } as DockerContainerInspect;
}

const withEnv = (transform: (env: string[]) => string[]) => ({ config: { Env: transform([...ENV]) } });
const withLabels = (labels: Record<string, string | undefined>) => {
  const merged: Record<string, string> = {};
  for (const [key, value] of Object.entries({ ...LABELS, ...labels })) if (value !== undefined) merged[key] = value;
  return { config: { Labels: merged } };
};

describe("host relay topology proof (C6)", () => {
  test("Engine accepts exactly the hardened relay, with every managed label and the plan's addresses", () => {
    expect(hostRelayTopologyIssues(relay(), expectation("engine-relay"))).toEqual([]);
  });

  test("Engine requires the relay to exist", () => {
    expect(hostRelayTopologyIssues(undefined, expectation("engine-relay"))).toEqual([
      "host relay container is missing on Docker Engine; run `runfree rebuild` to recreate the runtime",
    ]);
  });

  test("Desktop (no relay mode) requires it absent, and accepts its absence", () => {
    expect(hostRelayTopologyIssues(undefined, expectation("none"))).toEqual([]);
    expect(hostRelayTopologyIssues(relay(), expectation("none"))).toEqual([
      "host relay container must not exist where Docker Desktop's host gateway serves host services; run `runfree rebuild` to recreate the runtime",
    ]);
  });

  test.each([
    ["root user", { config: { User: "" } }, "must run as 65534:65534"],
    ["uid 0", { config: { User: "0:0" } }, "must run as 65534:65534"],
    ["bridge networking", { host: { NetworkMode: "bridge" } }, "host network namespace"],
    ["privileged", { host: { Privileged: true } }, "must not be privileged"],
    ["an added capability", { host: { CapAdd: ["NET_BIND_SERVICE"] } }, "add no capability"],
    ["capabilities kept", { host: { CapDrop: ["NET_RAW"] } }, "drop ALL capabilities"],
    ["a writable rootfs", { host: { ReadonlyRootfs: false } }, "read-only root filesystem"],
    ["no no-new-privileges", { host: { SecurityOpt: [] } }, "no-new-privileges"],
    ["unbounded pids", { host: { PidsLimit: 0 } }, "pids must be bounded"],
    ["too many pids", { host: { PidsLimit: 4096 } }, "pids must be bounded"],
    ["a published port", { host: { PortBindings: { "8080/tcp": [{ HostIp: "0.0.0.0", HostPort: "8080" }] } } }, "must not publish host ports"],
    ["different ExtraHosts", { host: { ExtraHosts: ["gateway.runfree.internal:10.0.0.1"] } }, "ExtraHosts must be exactly"],
    ["another image", { top: { Image: `sha256:${"c".repeat(64)}` } }, "proxy image"],
    ["another entrypoint", { config: { Entrypoint: ["sh", "-c"] } }, "entrypoint must be the proxy image's"],
    ["another command", { config: { Cmd: ["sh"] } }, "command must be"],
    ["another project's labels", withLabels({ "io.runfree.project-id": "ffffffffffff", "com.docker.compose.project": "x" }), "labels"],
    ["a writable effective mount", { top: { Mounts: [{ Type: "bind", Source: EFFECTIVE, Destination: "/app/runfree-effective", RW: true }] } }, "read-only"],
    ["an extra mount", { top: { Mounts: [{ Type: "bind", Source: EFFECTIVE, Destination: "/app/runfree-effective", RW: false }, { Type: "bind", Source: "/", Destination: "/host", RW: false }] } }, "mount only the effective policy directory"],
    ["a stopped relay", { top: { State: { Running: false, Status: "exited" } } }, "is exited"],
  ])("Engine refuses %s", (_label, overrides, detail) => {
    const issues = hostRelayTopologyIssues(relay(overrides), expectation("engine-relay"));
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.join("\n")).toContain(detail);
    expect(issues.every((issue) => issue.startsWith("host relay"))).toBe(true);
  });

  // The relay admits exactly RUNFREE_PROXY_EGRESS_IP and reads its gateway
  // checks from the other addresses (packages/proxy/src/host-relay.ts), so a
  // relay configured with any other value is not this runtime's relay.
  describe("environment: the allowed source and every runtime address match the plan", () => {
    test.each([
      "RUNFREE_EFFECTIVE_PROXY_ROOT",
      "RUNFREE_PROXY_IP",
      "RUNFREE_SUBNET",
      "RUNFREE_PROXY_EGRESS_IP",
      "RUNFREE_PROXY_EGRESS_SUBNET",
      "RUNFREE_PROXY_EGRESS_GATEWAY",
    ])("missing %s is refused", (name) => {
      const issues = hostRelayTopologyIssues(relay(withEnv((env) => env.filter((entry) => !entry.startsWith(`${name}=`)))), expectation("engine-relay"));
      expect(issues).toEqual([`host relay environment is missing ${name}`]);
    });

    test.each([
      ["RUNFREE_PROXY_EGRESS_IP", "172.30.120.67"],
      ["RUNFREE_PROXY_EGRESS_IP", "0.0.0.0"],
      ["RUNFREE_PROXY_EGRESS_GATEWAY", "172.17.0.1"],
      ["RUNFREE_PROXY_IP", "172.30.120.3"],
      ["RUNFREE_SUBNET", "172.30.0.0/16"],
      ["RUNFREE_PROXY_EGRESS_SUBNET", "0.0.0.0/0"],
      ["RUNFREE_EFFECTIVE_PROXY_ROOT", "/tmp"],
    ])("a changed %s (%s) is refused", (name, value) => {
      const issues = hostRelayTopologyIssues(relay(withEnv((env) => env.map((entry) => entry.startsWith(`${name}=`) ? `${name}=${value}` : entry))), expectation("engine-relay"));
      expect(issues).toHaveLength(1);
      expect(issues[0]).toMatch(new RegExp(`^host relay environment ${name} must be `));
    });

    test("a conflicting duplicate of the allowed source is refused, whichever value comes first", () => {
      for (const env of [[...ENV, "RUNFREE_PROXY_EGRESS_IP=10.0.0.9"], ["RUNFREE_PROXY_EGRESS_IP=10.0.0.9", ...ENV]]) {
        expect(hostRelayTopologyIssues(relay({ config: { Env: env } }), expectation("engine-relay")))
          .toEqual(["host relay environment sets RUNFREE_PROXY_EGRESS_IP more than once"]);
      }
    });

    test("even an identical duplicate is refused (the proof is on exact entries)", () => {
      expect(hostRelayTopologyIssues(relay({ config: { Env: [...ENV, `RUNFREE_PROXY_EGRESS_IP=${NETWORK.proxyEgressIp}`] } }), expectation("engine-relay")))
        .toEqual(["host relay environment sets RUNFREE_PROXY_EGRESS_IP more than once"]);
    });

    test.each(["RUNFREE_EXTRA=1", "NODE_OPTIONS=--require /tmp/x.js", "LD_PRELOAD=/tmp/x.so", "NODE_PATH=/tmp"])("an unexpected %s is refused", (entry) => {
      const issues = hostRelayTopologyIssues(relay(withEnv((env) => [...env, entry])), expectation("engine-relay"));
      expect(issues).toEqual([`host relay environment must not set ${entry.slice(0, entry.indexOf("="))}`]);
    });

    test("a missing or malformed environment is refused", () => {
      expect(hostRelayTopologyIssues(relay({ config: { Env: null } }), expectation("engine-relay"))).toHaveLength(6);
      expect(hostRelayTopologyIssues(relay(withEnv((env) => [...env, "=x"])), expectation("engine-relay")))
        .toEqual(["host relay environment has a malformed entry"]);
    });
  });

  describe("labels: every managed label the compose contract stamps", () => {
    test.each([
      "io.runfree.managed",
      "io.runfree.container-role",
      "io.runfree.project-id",
      "io.runfree.compose-project",
      "io.runfree.lifecycle-owner",
      "io.runfree.label-schema",
      "io.runfree.digest-schema",
      "com.docker.compose.project",
      "com.docker.compose.service",
    ])("missing %s is refused", (key) => {
      expect(hostRelayTopologyIssues(relay(withLabels({ [key]: undefined })), expectation("engine-relay")))
        .toEqual(["host relay labels do not name this project's managed host-relay service"]);
    });

    test.each([
      ["io.runfree.lifecycle-owner", "utility"],
      ["io.runfree.label-schema", "2"],
      ["io.runfree.compose-project", "runfree-ffffffffffff"],
    ])("a changed %s is refused", (key, value) => {
      expect(hostRelayTopologyIssues(relay(withLabels({ [key]: value })), expectation("engine-relay")))
        .toEqual(["host relay labels do not name this project's managed host-relay service"]);
    });

    test.each(Object.keys(GENERATION_LABELS))("%s must match the proxy of the same generation", (key) => {
      expect(hostRelayTopologyIssues(relay(withLabels({ [key]: "sha256:other" })), expectation("engine-relay")))
        .toEqual([`host relay label ${key} must match the proxy's`]);
      expect(hostRelayTopologyIssues(relay(withLabels({ [key]: undefined })), expectation("engine-relay")))
        .toEqual([`host relay label ${key} must match the proxy's`]);
      // A proxy without the label never vouches for an empty relay label.
      const bare = { ...expectation("engine-relay"), proxy: { ...PROXY, Config: { ...PROXY.Config, Labels: {} } } };
      expect(hostRelayTopologyIssues(relay(withLabels({ [key]: undefined })), bare)).toContain(`host relay label ${key} must match the proxy's`);
    });
  });
});

describe("host relay lookup and proof (cold and warm alike)", () => {
  const client = (result: CaptureResult) => {
    const calls: unknown[] = [];
    return {
      calls,
      listContainers: (query: unknown) => {
        calls.push(query);
        return result;
      },
    };
  };
  const answer = (status: number, stdout: string): CaptureResult => ({ status, stdout, stderr: "" });

  test("lists this project's host_relay service containers, stopped ones too, by exact id", () => {
    const fake = client(answer(0, `${RELAY_ID}\n`));
    expect(lookupHostRelayContainerIds(fake, "runfree-0123456789ab")).toEqual([RELAY_ID]);
    expect(fake.calls).toEqual([{
      all: true,
      quiet: true,
      noTrunc: true,
      filters: ["label=com.docker.compose.project=runfree-0123456789ab", "label=com.docker.compose.service=host_relay"],
    }]);
    expect(lookupHostRelayContainerIds(client(answer(0, "")), "runfree-0123456789ab")).toEqual([]);
  });

  test("a failed or non-exact lookup is undefined, never absent", () => {
    expect(lookupHostRelayContainerIds(client(answer(1, "")), "runfree-0123456789ab")).toBeUndefined();
    expect(lookupHostRelayContainerIds(client(answer(0, "bbbb\n")), "runfree-0123456789ab")).toBeUndefined();
  });

  test("Desktop: a present relay fails the proof, a failed lookup fails it, only proven absence passes", () => {
    expect(hostRelayProofIssues({ ids: [], relay: undefined }, expectation("none"))).toEqual([]);
    expect(hostRelayProofIssues({ ids: [RELAY_ID], relay: undefined }, expectation("none"))[0]).toMatch(/^host relay container must not exist/u);
    expect(hostRelayProofIssues({ ids: undefined, relay: undefined }, expectation("none")))
      .toEqual(["host relay lookup failed; the relay's presence or absence is unproven"]);
  });

  test("Engine: exactly one relay, inspected as the looked-up container", () => {
    expect(hostRelayProofIssues({ ids: [RELAY_ID], relay: relay() }, expectation("engine-relay"))).toEqual([]);
    expect(hostRelayProofIssues({ ids: [], relay: undefined }, expectation("engine-relay"))[0]).toMatch(/is missing on Docker Engine/u);
    expect(hostRelayProofIssues({ ids: [RELAY_ID, "c".repeat(64)], relay: relay() }, expectation("engine-relay")))
      .toEqual(["host relay containers must be at most one, found 2"]);
    expect(hostRelayProofIssues({ ids: ["c".repeat(64)], relay: relay() }, expectation("engine-relay")))
      .toEqual(["host relay inspection is not the looked-up container"]);
    expect(hostRelayProofIssues({ ids: [RELAY_ID], relay: undefined }, expectation("engine-relay")))
      .toEqual(["host relay container could not be inspected"]);
  });
});
