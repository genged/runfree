import { afterEach, describe, expect, it } from "vitest";

import {
  cliVersionJson,
  DAEMON_VERSION,
  DOCKER_PING,
  type FakeEngine,
  type FakeEngineScript,
  frame,
  startFakeEngine,
  versionReply,
} from "./fake-engine.test-harness.ts";
import { createSyncBridge } from "./sync-bridge.ts";
import { type DockerApiCaptureDeps, createDockerApiCapture } from "./transport.ts";
import { DOCKER_API_WORKER_SOURCE } from "./worker.ts";

const ID = "a".repeat(64);
const ID2 = "b".repeat(64);
const EXEC_ID = "e".repeat(64);
const V = "/v1.47";

let engine: FakeEngine | undefined;

afterEach(async () => {
  await engine?.close();
  engine = undefined;
});

async function start(replies: FakeEngineScript["replies"], execStarts?: FakeEngineScript["execStarts"]): Promise<FakeEngine> {
  engine = await startFakeEngine({ replies: { "GET /_ping": DOCKER_PING, ...versionReply(), ...replies }, ...(execStarts ? { execStarts } : {}) });
  return engine;
}

function transportFor(fake: FakeEngine, deps: DockerApiCaptureDeps = {}) {
  return createDockerApiCapture({
    controlEnv: {},
    resolveEndpoint: () => ({ kind: "unix", socketPath: fake.socketPath, context: "default" }),
    dockerCliProbe: () => "docker-cli",
    runCli: () => ({ status: 0, stdout: `${cliVersionJson()}\n` }),
    socketIdentity: () => "socket",
    ...deps,
  });
}

const json = (value: unknown) => ({ status: 200, headers: { "Content-Type": "application/json" }, body: `${JSON.stringify(value)}\n` });

async function apiRequests(fake: FakeEngine) {
  return (await fake.requests()).filter((request) => request.url !== "/_ping" && !request.url.endsWith("/version"));
}

describe("docker API transport: inspect routes", () => {
  it("formats container inspect byte-for-byte like the CLI's indented raw inspector", async () => {
    const fake = await start({
      [`GET ${V}/containers/${ID}/json`]: { status: 200, body: `{"Id":"${ID}","State":{"Running":true,"Health":null},"Mounts":[],"Config":{"Labels":{"a":"x\\u003cy"}}}\n` },
      [`GET ${V}/containers/proxy/json`]: { status: 200, body: `{"Id":"${ID2}","Args":[]}\n` },
    });
    const outcome = transportFor(fake)("docker", ["container", "inspect", ID, "proxy"], { env: {} });
    const expected = [
      "[",
      "    {",
      `        "Id": "${ID}",`,
      '        "State": {',
      '            "Running": true,',
      '            "Health": null',
      "        },",
      '        "Mounts": [],',
      '        "Config": {',
      '            "Labels": {',
      '                "a": "x\\u003cy"',
      "            }",
      "        }",
      "    },",
      "    {",
      `        "Id": "${ID2}",`,
      '        "Args": []',
      "    }",
      "]",
      "",
    ].join("\n");
    expect(outcome).toEqual({ routed: true, result: { status: 0, stdout: expected, stderr: "" } });
    expect((await apiRequests(fake)).map((request) => `${request.method} ${request.url}`)).toEqual([
      `GET ${V}/containers/${ID}/json`,
      `GET ${V}/containers/proxy/json`,
    ]);
  });

  it("answers type-less inspect from the container lookup", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    const outcome = transportFor(fake)("docker", ["inspect", ID], {});
    expect(outcome).toEqual({ routed: true, result: { status: 0, stdout: `[\n    {\n        "Id": "${ID}"\n    }\n]\n`, stderr: "" } });
  });

  it("formats {{.Id}} and {{.State.Running}} one line per object", async () => {
    const fake = await start({
      [`GET ${V}/images/runfree/agent:1/json`]: json({ Id: `sha256:${ID}` }),
      [`GET ${V}/containers/${ID}/json`]: json({ Id: ID, State: { Running: false } }),
      [`GET ${V}/containers/${ID2}/json`]: json({ Id: ID2, State: { Running: true } }),
    });
    const capture = transportFor(fake);
    expect(capture("docker", ["image", "inspect", "--format", "{{.Id}}", "runfree/agent:1"])).toEqual({ routed: true, result: { status: 0, stdout: `sha256:${ID}\n`, stderr: "" } });
    expect(capture("docker", ["container", "inspect", "--format", "{{.State.Running}}", ID, ID2])).toEqual({ routed: true, result: { status: 0, stdout: "false\ntrue\n", stderr: "" } });
  });

  it("reads networks and volumes at their own endpoints", async () => {
    const fake = await start({
      [`GET ${V}/networks/runfree_net`]: json({ Name: "runfree_net", Containers: {} }),
      [`GET ${V}/volumes/vol1`]: json({ Name: "vol1", Labels: null }),
    });
    const capture = transportFor(fake);
    expect(capture("docker", ["network", "inspect", "runfree_net"])).toMatchObject({ routed: true, result: { status: 0, stdout: '[\n    {\n        "Name": "runfree_net",\n        "Containers": {}\n    }\n]\n' } });
    expect(capture("docker", ["volume", "inspect", "vol1"])).toMatchObject({ routed: true, result: { status: 0, stdout: '[\n    {\n        "Name": "vol1",\n        "Labels": null\n    }\n]\n' } });
  });

  it("hands a missing object to the CLI, which prints the exact not-found text and searches other types", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: { status: 404, body: '{"message":"No such container: x"}' } });
    expect(transportFor(fake)("docker", ["inspect", ID], { timeout: 5_000 })).toEqual({ routed: false, timeout: expect.any(Number) });
  });

  it("hands a body that is not a JSON object, or lacks the templated field, to the CLI", async () => {
    const fake = await start({
      [`GET ${V}/containers/${ID}/json`]: { status: 200, body: "[1]" },
      [`GET ${V}/containers/${ID2}/json`]: json({ Id: ID2, State: { Running: "yes" } }),
    });
    const capture = transportFor(fake);
    expect(capture("docker", ["container", "inspect", ID]).routed).toBe(false);
    expect(capture("docker", ["container", "inspect", "--format", "{{.State.Running}}", ID2]).routed).toBe(false);
  });

  it("returns a large answer whole when it fits maxBuffer, and 125 when it does not", async () => {
    const big = "x".repeat(3 * 1024 * 1024);
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID, Big: big }) });
    const capture = transportFor(fake);
    const fits = capture("docker", ["container", "inspect", ID], { maxBuffer: 8 * 1024 * 1024 });
    expect(fits.routed && fits.result.status).toBe(0);
    expect(fits.routed && JSON.parse(fits.result.stdout)[0].Big).toBe(big);
    const over = capture("docker", ["container", "inspect", ID]);
    expect(over).toMatchObject({ routed: true, result: { status: 125, stdout: "" } });
    // Indentation alone can push a fitting body over the limit.
    const edge = capture("docker", ["container", "inspect", ID], { maxBuffer: Buffer.byteLength(JSON.stringify({ Id: ID, Big: big })) + 2 });
    expect(edge).toMatchObject({ routed: true, result: { status: 125 } });
  });
});

describe("docker API transport: container listing", () => {
  it("sends the CLI's list query and prints full or truncated ids in daemon order", async () => {
    const fake = await start({ [`GET ${V}/containers/json`]: json([{ Id: ID }, { Id: ID2 }]) });
    const capture = transportFor(fake);
    expect(capture("docker", ["ps", "-aq", "--no-trunc", "--filter", "label=com.example=1", "--filter", "label=k", "--filter", `id=${ID}`]))
      .toEqual({ routed: true, result: { status: 0, stdout: `${ID}\n${ID2}\n`, stderr: "" } });
    expect(capture("docker", ["container", "ls", "-q"])).toEqual({ routed: true, result: { status: 0, stdout: `${"a".repeat(12)}\n${"b".repeat(12)}\n`, stderr: "" } });
    const [first, second] = await apiRequests(fake);
    const query = new URL(first.url, "http://x").searchParams;
    expect(query.get("all")).toBe("1");
    expect(JSON.parse(query.get("filters") ?? "")).toEqual({ id: { [ID]: true }, label: { "com.example=1": true, k: true } });
    expect(second.url).toBe(`${V}/containers/json`);
  });

  it("prints nothing for an empty listing", async () => {
    const fake = await start({ [`GET ${V}/containers/json`]: json([]) });
    expect(transportFor(fake)("docker", ["ps", "-q"])).toEqual({ routed: true, result: { status: 0, stdout: "", stderr: "" } });
  });

  it("hands a daemon refusal of the filter to the CLI", async () => {
    const fake = await start({ [`GET ${V}/containers/json`]: { status: 400, body: '{"message":"invalid filter"}' } });
    expect(transportFor(fake)("docker", ["ps", "-q", "--filter", "network=x"]).routed).toBe(false);
  });
});

describe("docker API transport: exec", () => {
  const execReplies = (exitReplies: FakeEngineScript["replies"][string]) => ({
    [`POST ${V}/containers/${ID}/exec`]: { status: 201, body: JSON.stringify({ Id: EXEC_ID }) },
    [`GET ${V}/exec/${EXEC_ID}/json`]: exitReplies,
  });

  it("delivers stdin exactly, half-closes, demuxes split frames, and takes the exit code from exec inspect", async () => {
    const stream = Buffer.concat([frame(1, "hello "), frame(2, "warn\n"), frame(1, Buffer.from("wörld\n"))]);
    const fake = await start(execReplies(json({ Running: false, ExitCode: 3 })), {
      // Split mid-header and mid-payload.
      [EXEC_ID]: { chunks: [stream.subarray(0, 5), stream.subarray(5, 17), stream.subarray(17)].map((chunk) => chunk.toString("base64")) },
    });
    const input = "{\"payload\":\"é\"}\n".repeat(3);
    const outcome = transportFor(fake)("docker", ["exec", "--user", "0:0", "-i", ID, "node", "-e", "script", "arg1"], { input, maxBuffer: 4096, timeout: 5_000 });
    expect(outcome).toEqual({ routed: true, result: { status: 3, stdout: "hello wörld\n", stderr: "warn\n" } });
    const requests = await apiRequests(fake);
    expect(requests.map((request) => `${request.method} ${request.url}`)).toEqual([
      `POST ${V}/containers/${ID}/exec`,
      `POST ${V}/exec/${EXEC_ID}/start`,
      `GET ${V}/exec/${EXEC_ID}/json`,
    ]);
    expect(JSON.parse(requests[0].body)).toEqual({ User: "0:0", AttachStdin: true, AttachStdout: true, AttachStderr: true, Tty: false, Cmd: ["node", "-e", "script", "arg1"] });
    expect(JSON.parse(requests[1].body)).toEqual({ Detach: false, Tty: false });
    expect(requests[1].headers.upgrade).toBe("tcp");
    expect(Buffer.from(requests[1].stdinBase64 ?? "", "base64").toString("utf8")).toBe(input);
    expect(requests[1].halfClosed).toBe(true);
  });

  it("does not attach stdin without -i and still half-closes", async () => {
    const fake = await start(execReplies(json({ Running: false, ExitCode: 0 })), { [EXEC_ID]: { chunks: [frame(1, "ok").toString("base64")] } });
    expect(transportFor(fake)("docker", ["exec", ID, "cat", "/x"])).toEqual({ routed: true, result: { status: 0, stdout: "ok", stderr: "" } });
    const requests = await apiRequests(fake);
    expect(JSON.parse(requests[0].body)).toMatchObject({ AttachStdin: false });
    expect(requests[0].body).not.toContain("User");
    expect(requests[1].stdinBase64).toBe("");
  });

  it("waits for the daemon to record the exit within the budget; a stopped exec without an exit code is 125, a never-stopping one 124", async () => {
    const fake = await start(execReplies([{ ...json({ Running: true, ExitCode: null }), times: 30 }, json({ Running: false, ExitCode: 0 })]), {
      [EXEC_ID]: { chunks: [frame(1, "x").toString("base64")] },
    });
    expect(transportFor(fake)("docker", ["exec", ID, "true"])).toEqual({ routed: true, result: { status: 0, stdout: "x", stderr: "" } });
    await fake.setScript({ replies: { "GET /_ping": DOCKER_PING, ...versionReply(), ...execReplies(json({ Running: false, ExitCode: null })) }, execStarts: { [EXEC_ID]: { chunks: [] } } });
    expect(transportFor(fake)("docker", ["exec", ID, "true"])).toMatchObject({ routed: true, result: { status: 125, stdout: "" } });
    await fake.setScript({ replies: { "GET /_ping": DOCKER_PING, ...versionReply(), ...execReplies(json({ Running: true, ExitCode: null })) }, execStarts: { [EXEC_ID]: { chunks: [] } } });
    const started = performance.now();
    expect(transportFor(fake)("docker", ["exec", ID, "true"], { timeout: 300 })).toMatchObject({ routed: true, result: { status: 124, timedOut: true } });
    expect(performance.now() - started).toBeLessThan(1_500);
  });

  it("a stream cut short whose exec the daemon no longer knows is 125, never a clean exit", async () => {
    const fake = await start(execReplies({ status: 404, body: '{"message":"No such exec instance"}' }), { [EXEC_ID]: { behavior: "reset-after-head" } });
    expect(transportFor(fake)("docker", ["exec", ID, "true"], { timeout: 5_000 }))
      .toEqual({ routed: true, result: { status: 125, stdout: "", stderr: "runfree: Docker Engine API call failed: exec inspect failed\n" } });
  });

  it("hands an exec the daemon refuses to create to the CLI (nothing ran)", async () => {
    const fake = await start({ [`POST ${V}/containers/${ID}/exec`]: { status: 409, body: '{"message":"container is not running"}' } });
    expect(transportFor(fake)("docker", ["exec", ID, "true"]).routed).toBe(false);
  });

  it("never re-runs a started exec: a refused start is the CLI's status 1; a cut stream, a system-error frame, or an overrun is 125", async () => {
    const cases: Array<[FakeEngineScript["execStarts"], string, number]> = [
      [{ [EXEC_ID]: { status: 500, body: '{"message":"boom"}' } }, "Error response from daemon: boom\n", 1],
      [{ [EXEC_ID]: { chunks: [frame(1, "abcdef").subarray(0, 10).toString("base64")] } }, "runfree: Docker Engine API call failed: truncated exec stream frame\n", 125],
      [{ [EXEC_ID]: { chunks: [frame(3, "oci failure").toString("base64")] } }, "runfree: Docker Engine API call failed: error from daemon in stream: oci failure\n", 125],
      [{ [EXEC_ID]: { chunks: [frame(1, "y".repeat(2048)).toString("base64")] } }, "runfree: Docker Engine API call failed: output exceeds maxBuffer\n", 125],
    ];
    for (const [execStarts, stderr, status] of cases) {
      const fake = await start(execReplies(json({ Running: false, ExitCode: 0 })), execStarts);
      expect(transportFor(fake)("docker", ["exec", ID, "true"], { maxBuffer: 1024, timeout: 5_000 })).toEqual({ routed: true, result: { status, stdout: "", stderr } });
      expect((await apiRequests(fake)).filter((request) => request.url.endsWith("/exec")).length).toBe(1);
      await fake.close();
      engine = undefined;
    }
  });
});

describe("docker API transport: bounded waits and failures", () => {
  it("a request that never answers returns 124 within the budget and leaves the lock span bounded", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: { behavior: "hang" } });
    const started = performance.now();
    const outcome = transportFor(fake)("docker", ["container", "inspect", ID], { timeout: 300 });
    const elapsed = performance.now() - started;
    expect(outcome).toEqual({ routed: true, result: { status: 124, stdout: "", stderr: "", timedOut: true } });
    expect(elapsed).toBeGreaterThanOrEqual(290);
    expect(elapsed).toBeLessThan(1_500);
  });

  it("an exec whose stream never ends returns 124 within the budget", async () => {
    const fake = await start({ [`POST ${V}/containers/${ID}/exec`]: { status: 201, body: JSON.stringify({ Id: EXEC_ID }) } }, { [EXEC_ID]: { behavior: "hang" } });
    const started = performance.now();
    expect(transportFor(fake)("docker", ["exec", ID, "sleep", "1000"], { timeout: 300 })).toMatchObject({ routed: true, result: { status: 124, timedOut: true } });
    expect(performance.now() - started).toBeLessThan(1_500);
  });

  it("the transport keeps working after a timed-out call", async () => {
    const fake = await start({
      [`GET ${V}/containers/${ID}/json`]: [{ behavior: "hang", times: 1 }, json({ Id: ID })],
    });
    const capture = transportFor(fake);
    expect(capture("docker", ["container", "inspect", "--format", "{{.Id}}", ID], { timeout: 200 })).toMatchObject({ result: { status: 124 } });
    expect(capture("docker", ["container", "inspect", "--format", "{{.Id}}", ID], { timeout: 2_000 })).toEqual({ routed: true, result: { status: 0, stdout: `${ID}\n`, stderr: "" } });
  });

  it("a socket error after connecting maps to 125", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: { behavior: "reset" } });
    expect(transportFor(fake)("docker", ["container", "inspect", ID])).toMatchObject({ routed: true, result: { status: 125, stdout: "" } });
  });

  it("a daemon that refuses the connection is the CLI's to report, with the remaining budget", async () => {
    const fake = await start({});
    const capture = transportFor(fake, { resolveEndpoint: () => ({ kind: "unix", socketPath: `${fake.dir}/absent.sock`, context: "default" }) });
    const outcome = capture("docker", ["container", "inspect", ID], { timeout: 5_000 });
    expect(outcome.routed).toBe(false);
    expect(!outcome.routed && outcome.timeout).toBeGreaterThan(4_000);
    expect(!outcome.routed && outcome.timeout).toBeLessThanOrEqual(5_000);
  });

  it("a worker crash returns 125 and later calls fall back to the CLI for the rest of the process", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    const crashing = DOCKER_API_WORKER_SOURCE.replace('if (message.type === "request") start(message);', 'if (message.type === "request") { if (message.req.path !== "/_ping" && !message.req.path.endsWith("/version")) throw new Error("crash"); start(message); }');
    expect(crashing).not.toBe(DOCKER_API_WORKER_SOURCE);
    const capture = transportFor(fake, { bridge: createSyncBridge({ workerSource: crashing }) });
    expect(capture("docker", ["container", "inspect", ID], { timeout: 5_000 })).toMatchObject({ routed: true, result: { status: 125 } });
    expect(capture("docker", ["container", "inspect", ID], { timeout: 5_000 })).toEqual({ routed: false });
  });
});

describe("docker API transport: what stays on the CLI", () => {
  it.each([
    ["the kill switch", { controlEnv: { RUNFREE_DOCKER_TRANSPORT: "cli" } }, {}],
    ["an unknown transport mode", { controlEnv: { RUNFREE_DOCKER_TRANSPORT: "fast" } }, {}],
    ["fake-docker test mode in the process env", { controlEnv: { RUNFREE_TEST_FAKE_DOCKER: "1" } }, {}],
    ["fake-docker test mode in the call env", {}, { env: { RUNFREE_TEST_FAKE_DOCKER: "1" } }],
    ["a docker on PATH that is not a native binary", { dockerCliProbe: () => undefined }, {}],
    ["an endpoint that is not a socket", { socketIdentity: () => undefined }, {}],
    ["a non-unix endpoint", { resolveEndpoint: () => ({ kind: "cli" as const, reason: "tcp" }) }, {}],
    ["an unexpected spawn option", {}, { cwd: "/" }],
    ["a non-utf8 encoding", {}, { encoding: "buffer" as const }],
  ])("%s sends nothing to the socket", async (_label, deps, options) => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    expect(transportFor(fake, deps)("docker", ["container", "inspect", ID], options)).toEqual({ routed: false });
    expect(await fake.requests()).toEqual([]);
  });

  it("RUNFREE_DOCKER_TRANSPORT=api keeps the transport on", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    expect(transportFor(fake, { controlEnv: { RUNFREE_DOCKER_TRANSPORT: "api" } })("docker", ["container", "inspect", "--format", "{{.Id}}", ID]).routed).toBe(true);
  });

  it("an unrouted argv or a non-docker command sends nothing to the socket", async () => {
    const fake = await start({});
    const capture = transportFor(fake);
    for (const args of [["run", "--rm", "x"], ["container", "inspect", "../images/x"], ["compose", "up"], ["exec", "-t", ID, "sh"]]) {
      expect(capture("docker", args)).toEqual({ routed: false });
    }
    expect(capture("git", ["status"])).toEqual({ routed: false });
    expect(await fake.requests()).toEqual([]);
  });

  it.each([
    ["a Podman daemon", { ...DOCKER_PING, headers: { "Api-Version": "1.41", "Libpod-Api-Version": "4.9.0", Server: "Docker/4.9 (linux)" } }],
    ["a non-Docker server header", { ...DOCKER_PING, headers: { "Api-Version": "1.47", Server: "nginx" } }],
    ["an API older than 1.41", { ...DOCKER_PING, headers: { "Api-Version": "1.40", Server: "Docker/19.03 (linux)" } }],
    ["a malformed API version", { ...DOCKER_PING, headers: { "Api-Version": "2", Server: "Docker/99 (linux)" } }],
    ["a failed ping", { status: 500, body: "" }],
  ])("%s stays on the CLI and is pinged only once per process", async (_label, pingReply) => {
    engine = await startFakeEngine({ replies: { "GET /_ping": pingReply, ...versionReply(), [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) } });
    let cliRuns = 0;
    const capture = transportFor(engine, { runCli: () => {
      cliRuns += 1;
      return { status: 0, stdout: cliVersionJson() };
    } });
    expect(capture("docker", ["container", "inspect", ID]).routed).toBe(false);
    expect(capture("docker", ["container", "inspect", ID]).routed).toBe(false);
    expect((await engine.requests()).map((request) => request.url)).toEqual(["/_ping"]);
    expect(cliRuns).toBe(0);
  });

  it("speaks the API version the CLI negotiated, not the daemon's newest", async () => {
    engine = await startFakeEngine({ replies: { "GET /_ping": DOCKER_PING, ...versionReply("1.43"), "GET /v1.43/volumes/v1": json({ Name: "v1" }) } });
    const capture = transportFor(engine, { runCli: () => ({ status: 0, stdout: cliVersionJson({ clientApiVersion: "1.43" }) }) });
    expect(capture("docker", ["volume", "inspect", "v1"]).routed).toBe(true);
    expect((await engine.requests()).map((request) => request.url)).toEqual(["/_ping", "/v1.43/version", "/v1.43/volumes/v1"]);
  });

});

describe("docker API transport: binding to the CLI's daemon", () => {
  it.each([
    ["the CLI resolved another context", cliVersionJson({ context: "orbstack" })],
    ["the CLI's server has another kernel", cliVersionJson({ server: { ...DAEMON_VERSION, KernelVersion: "6.1.0" } })],
    ["the CLI's server has another commit", cliVersionJson({ server: { ...DAEMON_VERSION, GitCommit: "abc1234" } })],
    ["the CLI reports no server", JSON.stringify({ Client: { ApiVersion: "1.47", Context: "default" } })],
    ["the CLI negotiated above the daemon", cliVersionJson({ clientApiVersion: "1.48" })],
    ["the CLI negotiated below 1.41", cliVersionJson({ clientApiVersion: "1.40" })],
    ["the CLI printed something else", "Client: Docker Engine\n"],
  ])("%s: every call stays on the CLI and the binding runs once", async (_label, stdout) => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    let cliRuns = 0;
    const capture = transportFor(fake, { runCli: () => {
      cliRuns += 1;
      return { status: 0, stdout };
    } });
    expect(capture("docker", ["container", "inspect", ID]).routed).toBe(false);
    expect(capture("docker", ["container", "inspect", ID]).routed).toBe(false);
    expect(cliRuns).toBe(1);
    expect(await apiRequests(fake)).toEqual([]);
  });

  it("a failed docker version keeps the process on the CLI", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    expect(transportFor(fake, { runCli: () => ({ status: 1, stdout: "" }) })("docker", ["container", "inspect", ID]).routed).toBe(false);
  });

  it("passes the call's environment to docker version", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    const seen: NodeJS.ProcessEnv[] = [];
    const capture = transportFor(fake, { runCli: (_args, env) => {
      seen.push(env);
      return { status: 0, stdout: cliVersionJson() };
    } });
    capture("docker", ["container", "inspect", ID], { env: { PATH: "/x", DOCKER_CONTEXT: "desktop" } });
    expect(seen).toEqual([{ PATH: "/x", DOCKER_CONTEXT: "desktop" }]);
  });

  it("binds again when the socket file or the CLI binary changes", async () => {
    const fake = await start({ [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }) });
    let socket = "socket-1";
    let cliBinary = "cli-1";
    let cliRuns = 0;
    const capture = transportFor(fake, {
      socketIdentity: () => socket,
      dockerCliProbe: () => cliBinary,
      runCli: () => {
        cliRuns += 1;
        return { status: 0, stdout: cliVersionJson() };
      },
    });
    const inspect = () => capture("docker", ["container", "inspect", "--format", "{{.Id}}", ID]).routed;
    expect(inspect()).toBe(true);
    expect(inspect()).toBe(true);
    expect(cliRuns).toBe(1);
    socket = "socket-2";
    expect(inspect()).toBe(true);
    cliBinary = "cli-2";
    expect(inspect()).toBe(true);
    expect(cliRuns).toBe(3);
  });

  it("answers type-less inspect only while swarm is inactive", async () => {
    engine = await startFakeEngine({ replies: {
      "GET /_ping": { ...DOCKER_PING, headers: { ...DOCKER_PING.headers, Swarm: "active/manager" } },
      ...versionReply(),
      [`GET ${V}/containers/${ID}/json`]: json({ Id: ID }),
    } });
    const capture = transportFor(engine);
    expect(capture("docker", ["inspect", ID]).routed).toBe(false);
    expect(capture("docker", ["container", "inspect", ID]).routed).toBe(true);
  });
});
