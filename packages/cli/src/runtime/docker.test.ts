import { expect, test } from "vitest";

import { applyComposeTeardownDefaults, createRuntimeDocker, containerMissingNetwork, serviceContainerId } from "./docker.ts";
import { inspectReusableManagedImage } from "./image-identity.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "./types.ts";

function context(): RuntimeContext {
  return {
    projectRoot: "/workspace/project",
    project: {
      config: {},
      paths: {
        stateDir: "/workspace/project/.runfree/state",
      },
    },
    runtimeRoot: "/runtime",
    env: { PATH: "/bin", SECRET: "hidden", DOCKER_HOST: "unix:///docker.sock" },
  } as unknown as RuntimeContext;
}

test("containerMissingNetwork reports absent compose network", () => {
  expect(containerMissingNetwork({ id: "abc", networks: ["other"] }, "agent_internal")).toBe(true);
  expect(containerMissingNetwork({ id: "abc", networks: ["agent_internal", "proxy_egress"] }, "agent_internal")).toBe(false);
});

function networkInventoryIO(responses: Array<{ args: string[]; result: CaptureResult }>): RuntimeIO {
  return {
    capture(command, args) {
      const response = responses.shift();
      expect(command).toBe("docker");
      expect(args).toEqual(response?.args);
      if (!response) throw new Error("unexpected Docker call");
      return response.result;
    },
    run: () => { throw new Error("network discovery must not mutate Docker state"); },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => { throw new Error("network discovery must not sync credentials"); },
  };
}

test("network discovery discards partial inspection and includes newly discovered subnets after removal", () => {
  const responses = [
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "1395a4232aaa\n36404f88457b\naaaaaaaaaaaa\n", stderr: "" } },
    {
      args: ["network", "inspect", "1395a4232aaa", "36404f88457b", "aaaaaaaaaaaa"],
      result: {
        status: 1,
        stdout: JSON.stringify([{ Name: "survivor", IPAM: { Config: [{ Subnet: "172.30.1.0/24" }] } }]),
        stderr: "Error response from daemon: network 1395a4232aaa not found\nError response from daemon: network 36404f88457b not found\n",
      },
    },
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "aaaaaaaaaaaa\nbbbbbbbbbbbb\n", stderr: "" } },
    {
      args: ["network", "inspect", "aaaaaaaaaaaa", "bbbbbbbbbbbb"],
      result: {
        status: 0,
        stdout: JSON.stringify([
          { Name: "survivor", IPAM: { Config: [{ Subnet: "172.30.1.0/24" }] } },
          { Name: "new-network", IPAM: { Config: [{ Subnet: "172.30.2.0/24" }] } },
        ]),
        stderr: "",
      },
    },
  ];
  const docker = createRuntimeDocker(context(), networkInventoryIO(responses));
  expect(docker.networkSubnets()).toEqual(["172.30.1.0/24", "172.30.2.0/24"]);
  expect(responses).toHaveLength(0);
});

test.each(["1395a4232aaa", "xbtm0v4f1lfh"])("network discovery can recover to an empty fresh list after network %s disappears", (id) => {
  const responses = [
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: `${id}\n`, stderr: "" } },
    { args: ["network", "inspect", id], result: { status: 1, stdout: "[]", stderr: `Error response from daemon: network ${id} not found` } },
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "", stderr: "" } },
  ];
  expect(createRuntimeDocker(context(), networkInventoryIO(responses)).networkSubnets()).toEqual([]);
  expect(responses).toHaveLength(0);
});

test.each([
  "permission denied",
  "Error response from daemon: network 1395a4232aaa not found\npermission denied",
  "Error response from daemon: network bbbbbbbbbbbb not found",
  "",
])("network discovery refuses unrelated inspection failures without retry: %s", (stderr) => {
  const responses = [
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "1395a4232aaa\n", stderr: "" } },
    { args: ["network", "inspect", "1395a4232aaa"], result: { status: 1, stdout: "[]", stderr } },
  ];
  expect(() => createRuntimeDocker(context(), networkInventoryIO(responses)).networkSubnets())
    .toThrow("could not inspect Docker networks");
  expect(responses).toHaveLength(0);
});

test.each(["invalid JSON", "{}"])("network discovery refuses malformed successful inspection: %s", (stdout) => {
  const responses = [
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "1395a4232aaa\n", stderr: "" } },
    { args: ["network", "inspect", "1395a4232aaa"], result: { status: 0, stdout, stderr: "" } },
  ];
  expect(() => createRuntimeDocker(context(), networkInventoryIO(responses)).networkSubnets())
    .toThrow("could not parse Docker network inspection");
  expect(responses).toHaveLength(0);
});

test("network discovery bounds repeated removals and permits a later retry after churn settles", () => {
  const responses = Array.from({ length: 3 }, () => [
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "1395a4232aaa\n", stderr: "" } },
    { args: ["network", "inspect", "1395a4232aaa"], result: { status: 1, stdout: "[]", stderr: "Error response from daemon: network 1395a4232aaa not found" } },
  ]).flat();
  const docker = createRuntimeDocker(context(), networkInventoryIO(responses));
  expect(() => docker.networkSubnets()).toThrow("retry startup after Docker network changes settle");
  expect(responses).toHaveLength(0);
  responses.push(
    { args: ["network", "ls", "-q"], result: { status: 0, stdout: "aaaaaaaaaaaa\n", stderr: "" } },
    {
      args: ["network", "inspect", "aaaaaaaaaaaa"],
      result: { status: 0, stdout: JSON.stringify([{ Name: "stable", IPAM: { Config: [{ Subnet: "172.30.1.0/24" }] } }]), stderr: "" },
    },
  );
  expect(docker.networkSubnets()).toEqual(["172.30.1.0/24"]);
  expect(responses).toHaveLength(0);
});

function composeVolumeInspect(
  name: string,
  overrides: Partial<{ Driver: unknown; Scope: unknown; Options: unknown; Labels: unknown; Mountpoint: unknown }> = {},
): string {
  return JSON.stringify([{
    Name: name,
    Driver: "local",
    Scope: "local",
    Mountpoint: `/var/lib/docker/volumes/${name}/_data`,
    Options: null,
    Labels: {
      "com.docker.compose.project": "runfree-abc123def456",
      "com.docker.compose.volume": "runfree-commandhistory",
    },
    ...overrides,
  }]);
}

test("createComposeManagedVolume creates a local volume with the exact compose ownership labels", () => {
  const calls: Array<{ command: string; args: string[] }> = [];
  const io: RuntimeIO = {
    run: () => 0,
    capture(command, args) {
      calls.push({ command, args });
      if (args[0] === "volume" && args[1] === "inspect") {
        return { status: 0, stdout: composeVolumeInspect("runfree-abc123def456_runfree-commandhistory"), stderr: "" };
      }
      return { status: 0, stdout: "", stderr: "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  };

  const status = createRuntimeDocker(context(), io).createComposeManagedVolume("runfree-abc123def456", "runfree-commandhistory");

  expect(status).toBe(0);
  // Exactly the two labels the session named-volume proof checks, on the
  // <project>_<logical> name, with the local driver (no --driver, no --opt).
  expect(calls[0]?.args).toEqual([
    "volume", "create",
    "--label", "com.docker.compose.project=runfree-abc123def456",
    "--label", "com.docker.compose.volume=runfree-commandhistory",
    "runfree-abc123def456_runfree-commandhistory",
  ]);
  // The created volume is inspected and validated before any caller mounts it.
  expect(calls[1]?.args).toEqual(["volume", "inspect", "runfree-abc123def456_runfree-commandhistory"]);
});

test("createComposeManagedVolume fails closed when the daemon rejects the volume", () => {
  const io: RuntimeIO = {
    run: () => 0,
    capture: () => ({ status: 3, stdout: "", stderr: "existing volume uses a different driver" }),
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  };
  expect(createRuntimeDocker(context(), io).createComposeManagedVolume("runfree-x", "runfree-commandhistory")).toBe(3);
});

test("createComposeManagedVolume fails closed when a reused volume is a bind mount", () => {
  const io: RuntimeIO = {
    run: () => 0,
    capture(_command, args) {
      // `docker volume create` reuses an attacker-placed local-driver volume and
      // returns 0 without applying our labels; inspection reveals bind options.
      if (args[0] === "volume" && args[1] === "inspect") {
        return {
          status: 0,
          stdout: composeVolumeInspect("runfree-abc123def456_runfree-commandhistory", {
            Mountpoint: "/etc",
            Options: { type: "none", o: "bind", device: "/etc" },
          }),
          stderr: "",
        };
      }
      return { status: 0, stdout: "", stderr: "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  };
  // Must refuse before the dependency-ownership chown can target the bind path.
  expect(createRuntimeDocker(context(), io).createComposeManagedVolume("runfree-abc123def456", "runfree-commandhistory")).not.toBe(0);
});

test("applyComposeTeardownDefaults fills only the missing required compose vars", () => {
  const source = [
    "labels:",
    "  a: ${RUNFREE_TOPOLOGY_DIGEST:?RUNFREE_TOPOLOGY_DIGEST is required}",
    "  b: ${RUNFREE_PROXY_IMAGE:?RUNFREE_PROXY_IMAGE is required}",
    "  c: ${RUNFREE_OPTIONAL:-fallback}",
    "  d: ${RUNFREE_TOPOLOGY_DIGEST:?RUNFREE_TOPOLOGY_DIGEST is required}",
  ].join("\n");
  const env = applyComposeTeardownDefaults(source, { RUNFREE_PROXY_IMAGE: "runfree/proxy:real" });
  // Missing required var gets a placeholder so `down` can parse the file...
  expect(env.RUNFREE_TOPOLOGY_DIGEST).toBe("runfree-teardown");
  // ...a present one is never overwritten...
  expect(env.RUNFREE_PROXY_IMAGE).toBe("runfree/proxy:real");
  // ...and a `:-` (has-default) var is left for compose to default, not touched.
  expect(env.RUNFREE_OPTIONAL).toBeUndefined();
});

test("docker adapter uses sanitized docker client environment", () => {
  const calls: Array<{ command: string; args: string[]; env?: NodeJS.ProcessEnv }> = [];
  const io: RuntimeIO = {
    run(command, args, options) {
      calls.push({ command, args, env: options?.env as NodeJS.ProcessEnv | undefined });
      return 0;
    },
    capture(command, args, options) {
      calls.push({ command, args, env: options?.env as NodeJS.ProcessEnv | undefined });
      return { status: 0, stdout: "[]", stderr: "" };
    },
    commandExists() {
      return true;
    },
    confirm() {
      return true;
    },
    admin() {
      return Promise.resolve(0);
    },
  };

  createRuntimeDocker(context(), io).assertAvailable();

  expect(calls[0]?.env?.DOCKER_HOST).toBe("unix:///docker.sock");
  expect(calls[0]?.env?.SECRET).toBeUndefined();
  expect(calls[0]?.env?.DOCKER_CLI_HINTS).toBe("false");
});

// `docker ps -q` prints a 12-character prefix. Runtime validation markers, the
// deny-by-default base observation, and effective control-plane selection all
// compare exact 64-hex container identities, so this lookup must ask Docker for
// the untruncated ID.
test.each([
  [undefined, "-aq"],
  [{ runningOnly: true }, "-q"],
] as const)("service container lookup requests exact Docker container identity (%o)", (options, listFlag) => {
  const containerId = "1".repeat(64);
  const calls: string[][] = [];
  const io: RuntimeIO = {
    run: () => 0,
    capture(_command, args) {
      calls.push(args);
      return { status: 0, stdout: `${containerId}\n`, stderr: "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  };

  expect(serviceContainerId("runfree-test", "agent", context(), io, options)).toBe(containerId);
  expect(calls).toEqual([[
    "ps",
    listFlag,
    "--no-trunc",
    "--filter",
    "label=com.docker.compose.project=runfree-test",
    "--filter",
    "label=com.docker.compose.service=agent",
  ]]);
});

test("docker adapter reads paired effective-control receipts in one proxy exec", () => {
  const calls: string[][] = [];
  const io: RuntimeIO = {
    run: () => 0,
    capture(_command, args) {
      calls.push(args);
      if (args[0] === "ps") return { status: 0, stdout: "proxy-id\n", stderr: "" };
      if (args[0] === "exec") {
        return {
          status: 0,
          stdout: [
            JSON.stringify({
              generation: `sha256:${"a".repeat(64)}`,
              controlGeneration: `sha256:${"b".repeat(64)}`,
              policyGeneration: `sha256:${"a".repeat(64)}`,
              rulesetVerified: true,
              appliedAt: "2026-08-05T00:00:00.000Z",
            }),
            JSON.stringify({
              generation: `sha256:${"a".repeat(64)}`,
              controlGeneration: `sha256:${"b".repeat(64)}`,
              policyGeneration: `sha256:${"a".repeat(64)}`,
              appliedAt: "2026-08-05T00:00:00.000Z",
            }),
          ].join("\n"),
          stderr: "",
        };
      }
      throw new Error(`unexpected Docker call: ${args.join(" ")}`);
    },
    commandExists: () => true,
    confirm: () => true,
    admin: async () => 0,
  };

  expect(createRuntimeDocker(context(), io).proxyControlReceipts("runfree-test")).toMatchObject({
    firewall: { controlGeneration: `sha256:${"b".repeat(64)}`, rulesetVerified: true },
    requestProxy: { controlGeneration: `sha256:${"b".repeat(64)}` },
  });
  expect(calls).toHaveLength(2);
  expect(calls[1]?.slice(0, 3)).toEqual(["exec", "proxy-id", "sh"]);
});

test("docker adapter inspects image identity and labels", () => {
  const calls: Array<{ command: string; args: string[]; env?: NodeJS.ProcessEnv }> = [];
  const io: RuntimeIO = {
    run() {
      return 0;
    },
    capture(command, args, options) {
      calls.push({ command, args, env: options?.env as NodeJS.ProcessEnv | undefined });
      return {
        status: 0,
        stdout: JSON.stringify([{
          Architecture: "amd64",
          Id: "sha256:image",
          Os: "linux",
          Config: {
            Labels: { "io.runfree.managed": "true" },
            Env: ["PATH=/usr/bin", "LANG=C.UTF-8"],
            OnBuild: ["RUN project-trigger"],
            Volumes: { "/cache": {}, "/workspace": null },
          },
        }]),
        stderr: "",
      };
    },
    commandExists() {
      return true;
    },
    confirm() {
      return true;
    },
    admin() {
      return Promise.resolve(0);
    },
  };

  expect(createRuntimeDocker(context(), io).inspectImage("runfree:test")).toEqual({
    architecture: "amd64",
    environment: { PATH: "/usr/bin", LANG: "C.UTF-8" },
    id: "sha256:image",
    labels: { "io.runfree.managed": "true" },
    os: "linux",
    onBuild: ["RUN project-trigger"],
    volumes: ["/cache", "/workspace"],
  });
  expect(calls).toEqual([{
    command: "docker",
    args: ["image", "inspect", "runfree:test"],
    env: expect.objectContaining({ DOCKER_HOST: "unix:///docker.sock", DOCKER_CLI_HINTS: "false" }),
  }]);
});

test.each([
  "not json",
  "{}",
  "[]",
  '[{"Id":""}]',
  '[{"Id":"sha256:image","Config":[]}]',
  '[{"Id":"sha256:image","Config":{"Labels":[]}}]',
  '[{"Id":"sha256:image","Config":{"Labels":{"bad":false}}}]',
  '[{"Id":"sha256:image","Config":{"OnBuild":"RUN false"}}]',
  '[{"Id":"sha256:image","Config":{"OnBuild":["RUN true",false]}}]',
  '[{"Id":"sha256:image","Config":{"Volumes":[]}}]',
  '[{"Id":"sha256:image","Config":{"Volumes":{"relative":{}}}}]',
  '[{"Id":"sha256:image","Config":{"Volumes":{"/workspace/../escape":{}}}}]',
  '[{"Id":"sha256:image","Config":{"Volumes":{"/workspace":{"unexpected":true}}}}]',
  '[{"Id":"sha256:image","Config":{"Env":"PATH=/bin"}}]',
  '[{"Id":"sha256:image","Config":{"Env":["bad"]}}]',
  '[{"Id":"sha256:image","Config":{"Env":["PATH=/bin","PATH=/usr/bin"]}}]',
  '[{"Id":"sha256:image","Os":1,"Architecture":"amd64","Config":{}}]',
  '[{"Id":"sha256:image","Os":"linux","Architecture":[],"Config":{}}]',
])("docker adapter rejects malformed image inspection output: %s", (stdout) => {
  const io: RuntimeIO = {
    run() {
      return 0;
    },
    capture() {
      return { status: 0, stdout, stderr: "" };
    },
    commandExists() {
      return true;
    },
    confirm() {
      return true;
    },
    admin() {
      return Promise.resolve(0);
    },
  };

  expect(createRuntimeDocker(context(), io).inspectImage("runfree:test")).toBeUndefined();
});

test("docker adapter preserves unusual inherited image environment without rejecting image identity", () => {
  const stdout = JSON.stringify([{
    Architecture: "arm64",
    Id: "sha256:image",
    Os: "linux",
    Config: { Labels: {}, Env: ["BAD-NAME=value", "MULTILINE=line one\nline two"] },
  }]);
  const io: RuntimeIO = {
    run: () => 0,
    capture: () => ({ status: 0, stdout, stderr: "" }),
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  };

  expect(createRuntimeDocker(context(), io).inspectImage("runfree:test")).toEqual({
    architecture: "arm64",
    environment: { "BAD-NAME": "value", MULTILINE: "line one\nline two" },
    id: "sha256:image",
    labels: {},
    os: "linux",
  });
});

test("docker adapter returns no image inspection when Docker reports failure", () => {
  const io: RuntimeIO = {
    run() {
      return 0;
    },
    capture() {
      return { status: 1, stdout: "", stderr: "not found" };
    },
    commandExists() {
      return true;
    },
    confirm() {
      return true;
    },
    admin() {
      return Promise.resolve(0);
    },
  };

  expect(createRuntimeDocker(context(), io).inspectImage("runfree:missing")).toBeUndefined();
});

test("docker adapter tags an existing image through the Docker client boundary", () => {
  const calls: Array<{ command: string; args: string[]; env?: NodeJS.ProcessEnv }> = [];
  const io: RuntimeIO = {
    run(command, args, options) {
      calls.push({ command, args, env: options?.env as NodeJS.ProcessEnv | undefined });
      return 0;
    },
    capture() {
      return { status: 0, stdout: "", stderr: "" };
    },
    commandExists() {
      return true;
    },
    confirm() {
      return true;
    },
    admin() {
      return Promise.resolve(0);
    },
  };

  expect(createRuntimeDocker(context(), io).tagImage("runfree:source", "runfree:target")).toBe(0);
  expect(calls).toEqual([{
    command: "docker",
    args: ["image", "tag", "runfree:source", "runfree:target"],
    env: expect.objectContaining({ DOCKER_HOST: "unix:///docker.sock", DOCKER_CLI_HINTS: "false" }),
  }]);
});

// --- L5a: partitioned image-inspect memoization ---

function imageJson(id: string): string {
  return JSON.stringify([{
    Architecture: "amd64",
    Id: id,
    Os: "linux",
    Config: { Labels: {
      "io.runfree.managed": "true",
      "io.runfree.digest-schema": "1",
      "io.runfree.image-input-digest": `sha256:${"a".repeat(64)}`,
      "io.runfree.image-role": "agent-runtime",
    } },
  }]);
}

function memoFixture() {
  const byTag = new Map<string, string>();
  let inspects = 0;
  const io: RuntimeIO = {
    run: () => 0,
    capture(_command, args) {
      if (args[0] === "image" && args[1] === "inspect") {
        inspects += 1;
        const stdout = byTag.get(args[2]);
        return stdout ? { status: 0, stdout, stderr: "" } : { status: 1, stdout: "", stderr: "No such image" };
      }
      return { status: 0, stdout: "", stderr: "" };
    },
    commandExists: () => true,
    confirm: () => true,
    admin: () => Promise.resolve(0),
  };
  return { byTag, io, docker: createRuntimeDocker(context(), io), inspectCount: () => inspects };
}

test("inspectImage memoizes by exact argument and a fresh read always hits the daemon", () => {
  const { byTag, docker, inspectCount } = memoFixture();
  byTag.set("runfree:test", imageJson(`sha256:${"1".repeat(64)}`));

  expect(docker.inspectImage("runfree:test")?.id).toBe(`sha256:${"1".repeat(64)}`);
  expect(docker.inspectImage("runfree:test")?.id).toBe(`sha256:${"1".repeat(64)}`);
  expect(inspectCount()).toBe(1);

  // Freshness is explicit in the API: a fresh read bypasses the memo and does
  // not populate it, so must-bypass call sites always observe the daemon.
  expect(docker.inspectImage("runfree:test", { fresh: true })?.id).toBe(`sha256:${"1".repeat(64)}`);
  expect(inspectCount()).toBe(2);
  expect(docker.inspectImage("runfree:test")?.id).toBe(`sha256:${"1".repeat(64)}`);
  expect(inspectCount()).toBe(2);

  // A missing image is memoized too; image-mutating operations invalidate.
  expect(docker.inspectImage("runfree:absent")).toBeUndefined();
  expect(docker.inspectImage("runfree:absent")).toBeUndefined();
  expect(inspectCount()).toBe(3);
});

test("a retag after the memo is warmed cannot satisfy a fresh ref-then-id cross-check", () => {
  const { byTag, docker, inspectCount } = memoFixture();
  const recordedId = `sha256:${"2".repeat(64)}`;
  const retaggedId = `sha256:${"3".repeat(64)}`;
  byTag.set("runfree:selected", imageJson(recordedId));

  // Discovery warms the memo with the recorded binding.
  expect(docker.inspectImage("runfree:selected")?.id).toBe(recordedId);

  // Someone retags the reference between the build phase and preflight.
  byTag.set("runfree:selected", imageJson(retaggedId));

  // The memoized read still answers the stale binding — which is exactly why
  // the temporal cross-checks must bypass it: the fresh read observes the
  // retag, so the caller's "ref still resolves to the durable id" check throws.
  expect(docker.inspectImage("runfree:selected")?.id).toBe(recordedId);
  const fresh = inspectReusableManagedImage(docker, "runfree:selected", {
    inputDigest: `sha256:${"a".repeat(64)}`,
    roles: ["agent-runtime"],
  }, { fresh: true });
  expect(fresh?.id).toBe(retaggedId);
  expect(fresh?.id).not.toBe(recordedId);
  expect(inspectCount()).toBe(2);
});

test("image-mutating adapter operations invalidate the inspect memo", () => {
  const { byTag, docker, inspectCount } = memoFixture();
  byTag.set("runfree:test", imageJson(`sha256:${"4".repeat(64)}`));
  expect(docker.inspectImage("runfree:test")?.id).toBe(`sha256:${"4".repeat(64)}`);
  expect(inspectCount()).toBe(1);

  byTag.set("runfree:test", imageJson(`sha256:${"5".repeat(64)}`));
  docker.tagImage("runfree:other", "runfree:test");
  expect(docker.inspectImage("runfree:test")?.id).toBe(`sha256:${"5".repeat(64)}`);
  expect(inspectCount()).toBe(2);

  byTag.delete("runfree:test");
  docker.removeImages(["runfree:test"]);
  expect(docker.inspectImage("runfree:test")).toBeUndefined();
  expect(inspectCount()).toBe(3);
});
