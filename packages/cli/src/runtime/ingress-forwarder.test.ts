import { describe, expect, test, vi } from "vitest";

import { CliError } from "../errors.ts";
import {
  INGRESS_FORWARDER_TEST_IMAGE_ID,
  INGRESS_HOST_NETWORK_TEST_ID,
  ingressForwarderInspectFixture,
  ingressHostNetworkInspectFixture,
  missingContainerResult,
  missingNetworkResult,
} from "./ingress-forwarder.test-harness.ts";
import {
  INGRESS_FORWARDER_IMAGE,
  ingressForwarderName,
  ingressForwarderRunArguments,
  ingressHostNetworkName,
  inspectIngressHostNetwork,
  listIngressForwarders,
  removeAllIngressForwarders,
  removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep,
  startIngressForwarder,
  stopIngressForwarders,
  type IngressForwarderInput,
} from "./ingress-forwarder.ts";
import { replaceValidatedIngressForwarder } from "./ingress-forwarder-ownership.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const FORWARDER_ID = "f".repeat(64);

function input(overrides: Partial<IngressForwarderInput> = {}): IngressForwarderInput {
  return {
    purpose: "port",
    projectId: PROJECT_ID,
    hostPort: "3000",
    target: "172.30.0.21",
    targetPort: "3000",
    internalNetwork: "runfree-0123456789ab_agent_internal",
    ...overrides,
  };
}

const context = { env: {}, projectRoot: "/p" } as unknown as RuntimeContext;

describe("ingress forwarder run arguments", () => {
  test("mints the exact hardened, loopback-only argv with the generic socat shape", () => {
    const args = ingressForwarderRunArguments(input({ purpose: "vnc", hostPort: "5901", targetPort: "5901", target: "runfree-x-agent-1" }));

    expect(args.slice(0, 5)).toEqual([
      "run",
      "--rm",
      "-d",
      "--name",
      "runfree-ingress-vnc-0123456789ab-5901",
    ]);
    expect(args).toEqual(expect.arrayContaining([
      "--label",
      "io.runfree.container-role=ingress-forwarder",
      "--label",
      "io.runfree.lifecycle-owner=utility",
      "--label",
      "io.runfree.ingress-purpose=vnc",
      "--cap-drop",
      "ALL",
      "--read-only",
      "--user",
      "65534:65534",
      "-p",
      "127.0.0.1:5901:5901",
      "-e",
      "INGRESS_TARGET=runfree-x-agent-1",
    ]));
    // Loopback-only publication, never 0.0.0.0.
    expect(args.join(" ")).not.toContain("0.0.0.0:");
    // The socat shape is the last argument and binds the host-facing interface.
    expect(args.at(-1)).toContain("bind=$(hostname -i)");
    expect(args.at(-1)).toContain("TCP:${INGRESS_TARGET}:${INGRESS_TARGET_PORT}");
  });

  test("threads a purpose's extra env after the generic INGRESS_* vars", () => {
    const args = ingressForwarderRunArguments(input({ extraEnv: { INGRESS_SESSION_ID: "rf-1" } }));
    expect(args).toEqual(expect.arrayContaining(["-e", "INGRESS_SESSION_ID=rf-1"]));
  });
});

describe("startIngressForwarder", () => {
  function fakeIo(
    fail?: { network?: boolean; run?: boolean; connect?: boolean; exec?: boolean },
    networkOptions: Record<string, string> = {},
  ) {
    const calls: string[][] = [];
    let networkCreated = false;
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([{ ...ingressHostNetworkInspectFixture(PROJECT_ID), Options: networkOptions }]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "container" && args[1] === "inspect") {
        return { status: 1, stdout: "", stderr: `Error: No such container: ${args[2]}` };
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = !fail?.network;
        return { status: fail?.network ? 1 : 0, stdout: networkCreated ? INGRESS_HOST_NETWORK_TEST_ID : "", stderr: "boom" };
      }
      if (args[0] === "run") return { status: fail?.run ? 1 : 0, stdout: `${FORWARDER_ID}\n`, stderr: "boom" };
      // socat readiness probe: listening unless the test forces it to fail.
      if (args[0] === "exec") return { status: fail?.exec ? 1 : 0, stdout: "", stderr: "" };
      if (args[0] === "network" && args[1] === "connect") return { status: fail?.connect ? 1 : 0, stdout: "", stderr: "boom" };
      if (args[0] === "rm") return { status: 0, stdout: "", stderr: "" };
      return { status: 0, stdout: "", stderr: "" };
    });
    return { io: { capture } as unknown as RuntimeIO, calls };
  }

  test("creates the host network, runs the sidecar, then dual-homes it — in that order", () => {
    const { io, calls } = fakeIo();
    const name = startIngressForwarder(context, io, input());

    expect(name).toBe(ingressForwarderName(PROJECT_ID, "port", "3000"));
    const verbs = calls.map((args) => `${args[0]} ${args[1] ?? ""}`.trim());
    const createIdx = verbs.indexOf("network create");
    const runIdx = verbs.indexOf("run --rm");
    const readinessIdx = calls.findIndex((args) => args[0] === "exec");
    const connectIdx = verbs.indexOf("network connect");
    expect(createIdx).toBeLessThan(runIdx);
    const postCreateInspectIdx = calls.findIndex((args, index) => index > createIdx && args[0] === "network" && args[1] === "inspect");
    expect(createIdx).toBeLessThan(postCreateInspectIdx);
    expect(postCreateInspectIdx).toBeLessThan(runIdx);
    // The readiness probe sits between the run and the attach: socat must be
    // observed LISTENing on the host-facing interface before agent_internal
    // exists on the container. That is the one-way invariant made real, not
    // merely likely.
    expect(runIdx).toBeLessThan(readinessIdx);
    expect(readinessIdx).toBeLessThan(connectIdx);
  });

  test.each<Record<string, string>>([
    {},
    { "com.docker.network.enable_ipv4": "true" },
    { "com.docker.network.enable_ipv6": "false" },
    { "com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false" },
  ])("starts a forwarder with compatible daemon address-family options %j", (options) => {
    const { io, calls } = fakeIo(undefined, options);
    expect(startIngressForwarder(context, io, input())).toBe(ingressForwarderName(PROJECT_ID, "port", "3000"));
    expect(calls).toContainEqual(["network", "connect", input().internalNetwork, FORWARDER_ID]);
  });

  test.each([{ EnableIPv4: false }, { EnableIPv6: true }])(
    "compatible driver options cannot mask conflicting network flags %j",
    (flags) => {
      const network = {
        ...ingressHostNetworkInspectFixture(PROJECT_ID),
        ...flags,
        Options: { "com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false" },
      };
      const capture = vi.fn((_cmd: string, args: string[]) => {
        if (args[0] === "container" && args[1] === "inspect") return missingContainerResult(args[2]);
        if (args[0] === "network" && args[1] === "inspect") {
          return { status: 0, stdout: JSON.stringify([network]), stderr: "" };
        }
        throw new Error(`unexpected Docker mutation: ${args.join(" ")}`);
      });
      expect(() => startIngressForwarder(context, { capture } as unknown as RuntimeIO, input()))
        .toThrow("network address-family shape does not match");
      expect(capture.mock.calls.every(([, args]) => args[1] === "inspect")).toBe(true);
    },
  );

  test.each([
    { "com.docker.network.driver.mtu": "1400" },
    { "com.docker.network.enable_ipv4": "false" },
    { "com.docker.network.enable_ipv6": "true" },
    { "com.docker.network.enable_ipv4": "TRUE" },
    { "com.docker.network.enable_ipv4": "true", "com.docker.network.bridge.trusted_host_interfaces": "eth0" },
  ])("reclaims a bridge with unsupported daemon options %j before starting a listener", (options) => {
    const invalidNetwork = ingressHostNetworkInspectFixture(PROJECT_ID);
    invalidNetwork.Options = options;
    let networkCreated = false;
    const calls: string[][] = [];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "container" && args[1] === "inspect") return missingContainerResult(args[2] as string);
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([invalidNetwork]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      if (args[0] === "network" && args[1] === "rm") {
        networkCreated = false;
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });

    // The refusal names the offending option, so the operator does not have to
    // re-inspect the network to learn which key the daemon populated.
    expect(() => startIngressForwarder(context, { capture } as unknown as RuntimeIO, input()))
      .toThrow(`network driver options do not match: ${JSON.stringify(options)}`);
    expect(calls).toContainEqual(["network", "rm", INGRESS_HOST_NETWORK_TEST_ID]);
    expect(calls.some((args) => args[0] === "run")).toBe(false);
    expect(networkCreated).toBe(false);
  });

  test("refuses an existing same-name container before any Docker mutation", () => {
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "container" && args[1] === "inspect") return { status: 0, stdout: "[]", stderr: "" };
      throw new Error(`unexpected mutation after name collision: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => startIngressForwarder(context, io, input())).toThrow(/already exists/u);
    const calls = capture.mock.calls.map((call) => (call as unknown as [string, string[]])[1]);
    expect(calls).toEqual([["container", "inspect", ingressForwarderName(PROJECT_ID, "port", "3000")]]);
  });

  test("removes the exact started container when Docker run returns malformed stdout", () => {
    const name = ingressForwarderName(PROJECT_ID, "port", "3000");
    let started = false;
    let networkCreated = false;
    const calls: string[][] = [];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "container" && args[1] === "inspect") {
        if (!started) return missingContainerResult(args[2] as string);
        return {
          status: 0,
          stdout: JSON.stringify([{
            Config: {
              Image: INGRESS_FORWARDER_IMAGE,
              Labels: {
                "io.runfree.container-role": "ingress-forwarder",
                "io.runfree.ingress-purpose": "port",
                "io.runfree.project-id": PROJECT_ID,
              },
            },
            Id: FORWARDER_ID,
            Name: `/${name}`,
          }]),
          stderr: "",
        };
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      if (args[0] === "run") {
        started = true;
        return { status: 0, stdout: "unexpected output\n", stderr: "" };
      }
      if (args[0] === "rm") {
        started = false;
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => startIngressForwarder(context, io, input())).toThrow(/returned no exact container ID/u);
    expect(calls).toContainEqual(["rm", "-f", FORWARDER_ID]);
    expect(started).toBe(false);
  });

  test("refuses a same-name host network without ownership proof before any Docker mutation", () => {
    const lookalike = ingressHostNetworkInspectFixture(PROJECT_ID);
    lookalike.Labels = { "io.runfree.project-id": PROJECT_ID };
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "container" && args[1] === "inspect") return missingContainerResult(args[2] as string);
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([lookalike]), stderr: "" };
      }
      throw new Error(`unexpected mutation after network ownership refusal: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => startIngressForwarder(context, io, input())).toThrow(/refusing unverified ingress host network/u);
    const calls = capture.mock.calls.map((call) => (call as unknown as [string, string[]])[1]);
    expect(calls.some((args) => args[0] === "network" && args[1] === "create")).toBe(false);
    expect(calls.some((args) => args[0] === "run")).toBe(false);
  });

  test("creates the versioned managed bridge and never inspects a non-v2 bridge name", () => {
    const currentNetwork = ingressHostNetworkName(PROJECT_ID);
    // The retired pre-v2 bridge spelling: a predictable public name a foreign
    // network could reproduce, never ownership evidence.
    const legacyNetwork = `runfree-ingress-host-${PROJECT_ID}`;
    const calls: string[][] = [];
    let networkCreated = false;
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "container" && args[1] === "inspect") {
        return missingContainerResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "inspect") {
        if (args[2] === legacyNetwork) throw new Error("retired bridge name must not be inspected as ownership evidence");
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      if (args[0] === "ps") return { status: 0, stdout: "", stderr: "" };
      if (args[0] === "run") return { status: 0, stdout: `${FORWARDER_ID}\n`, stderr: "" };
      if (args[0] === "exec" || (args[0] === "network" && args[1] === "connect")) {
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(replaceValidatedIngressForwarder(
      context,
      io,
      PROJECT_ID,
      input(),
    )).toBe(ingressForwarderName(PROJECT_ID, "port", "3000"));

    expect(calls).toContainEqual(expect.arrayContaining(["network", "create", currentNetwork]));
    expect(calls.some((args) => args.includes(legacyNetwork))).toBe(false);
    expect(calls.some((args) => args[0] === "run")).toBe(true);
    expect(calls.some((args) => args[0] === "rm")).toBe(false);
  });

  test("refuses an unexpected current-network endpoint before removing the target", () => {
    const target = ingressForwarderInspectFixture({
      composeProject: "runfree-0123456789ab",
      containerId: "b".repeat(64),
      hostPort: "3000",
      projectId: PROJECT_ID,
      purpose: "port",
    });
    const foreign = ingressForwarderInspectFixture({
      composeProject: "runfree-0123456789ab",
      containerId: "c".repeat(64),
      hostPort: "5901",
      projectId: PROJECT_ID,
      purpose: "vnc",
    });
    foreign.Config = {
      ...foreign.Config,
      Labels: {
        ...foreign.Config?.Labels,
        "io.runfree.project-id": "abcdef012345",
      },
    };
    const targetName = target.Name?.replace(/^\//, "") as string;
    const network = ingressHostNetworkInspectFixture(PROJECT_ID);
    network.Containers = {
      [target.Id as string]: { Name: targetName },
      [foreign.Id as string]: { Name: foreign.Name?.replace(/^\//, "") },
    };
    const calls: string[][] = [];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "container" && args[1] === "inspect") {
        const candidate = args[2] === targetName || args[2] === target.Id
          ? target
          : args[2] === foreign.Id
            ? foreign
            : undefined;
        return candidate
          ? { status: 0, stdout: JSON.stringify([candidate]), stderr: "" }
          : missingContainerResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([network]), stderr: "" };
      }
      if (args[0] === "image" && args[1] === "inspect") {
        return { status: 0, stdout: INGRESS_FORWARDER_TEST_IMAGE_ID, stderr: "" };
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => replaceValidatedIngressForwarder(
      context,
      io,
      PROJECT_ID,
      input(),
    )).toThrow(/does not carry this project's exact ingress-forwarder labels/u);

    expect(calls.some((args) => args[0] === "rm")).toBe(false);
    expect(calls.some((args) => args[0] === "run")).toBe(false);
  });

  test("removes the sidecar when the agent_internal attach fails, leaving no half-homed forwarder", () => {
    const { io, calls } = fakeIo({ connect: true });
    expect(() => startIngressForwarder(context, io, input())).toThrow(CliError);
    expect(calls.some((args) => args[0] === "rm" && args.includes("-f"))).toBe(true);
  });

  test("does not attach agent_internal — and removes the sidecar — when socat never binds", () => {
    const { io, calls } = fakeIo({ exec: true });
    expect(() => startIngressForwarder(context, io, input())).toThrow(/did not begin listening/u);
    // The attach must never happen without a confirmed host-facing listener.
    expect(calls.some((args) => args[0] === "network" && args[1] === "connect")).toBe(false);
    expect(calls.some((args) => args[0] === "rm" && args.includes("-f"))).toBe(true);
  });

  test("surfaces a cleanup failure when the sidecar cannot be removed after a failed start", () => {
    // socat never binds, and rm -f fails while the container is still present:
    // the error must say the sidecar is still running, not imply a clean roll back.
    let started = false;
    let networkCreated = false;
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      // Absent before `run` (so the pre-run stale check is a no-op), present
      // after — and it stays present because `rm -f` keeps failing.
      if (args[0] === "container" && args[1] === "inspect") {
        return started ? { status: 0, stdout: "", stderr: "" } : { status: 1, stdout: "", stderr: `Error: No such container: ${args[2]}` };
      }
      if (args[0] === "run") { started = true; return { status: 0, stdout: `${FORWARDER_ID}\n`, stderr: "" }; }
      if (args[0] === "exec") return { status: 1, stdout: "", stderr: "" };
      if (args[0] === "rm") return { status: 1, stdout: "", stderr: "device busy" };
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;
    // container inspect returns 0, so waitForSocatBind sees a live container and
    // exhausts its attempts rather than short-circuiting on a vanished --rm.
    expect(() => startIngressForwarder(context, io, input())).toThrow(/cleanup failed, .* is still running/u);
    const calls = capture.mock.calls.map((c) => (c as unknown as [string, string[]])[1]);
    expect(calls.some((args) => args[0] === "network" && args[1] === "connect")).toBe(false);
  });

  test("reports only the startup error when the sidecar was already gone", () => {
    // rm -f fails, but Docker's own 'No such container' is definitive proof the
    // --rm sidecar is gone: the error must not imply a surviving container.
    let started = false;
    let networkCreated = false;
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      if (args[0] === "container" && args[1] === "inspect") {
        return started ? { status: 0, stdout: "", stderr: "" } : { status: 1, stdout: "", stderr: `Error: No such container: ${args[2]}` };
      }
      if (args[0] === "run") { started = true; return { status: 0, stdout: `${FORWARDER_ID}\n`, stderr: "" }; }
      if (args[0] === "exec") return { status: 1, stdout: "", stderr: "" };
      if (args[0] === "rm") return { status: 1, stdout: "", stderr: `Error: No such container: ${FORWARDER_ID}` };
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;
    let message = "";
    try {
      startIngressForwarder(context, io, input());
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/did not begin listening/u);
    expect(message).not.toMatch(/still running/u);
  });

  test("does not accept a nested no-such-container from a failed force-kill as cleanup", () => {
    // The 'No such container' here names a runtime id, not our sidecar, which
    // Docker may still be retaining — this must NOT read as a clean removal.
    let started = false;
    let networkCreated = false;
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      if (args[0] === "container" && args[1] === "inspect") {
        return started ? { status: 0, stdout: "", stderr: "" } : { status: 1, stdout: "", stderr: `Error: No such container: ${args[2]}` };
      }
      if (args[0] === "run") { started = true; return { status: 0, stdout: `${FORWARDER_ID}\n`, stderr: "" }; }
      if (args[0] === "exec") return { status: 1, stdout: "", stderr: "" };
      if (args[0] === "rm") {
        return { status: 1, stdout: "", stderr: "cannot remove - Cannot kill container abc123: No such container: abc123def456" };
      }
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;
    expect(() => startIngressForwarder(context, io, input())).toThrow(/still running/u);
  });

  test("does not accept a same-prefixed but different container name as cleanup", () => {
    // `<name>-stale` names a different container; the trailing digit/'-' word
    // boundary must not let it read as our sidecar's definitive removal.
    let started = false;
    let networkCreated = false;
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "network" && args[1] === "inspect") {
        return networkCreated
          ? { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" }
          : missingNetworkResult(args[2] as string);
      }
      if (args[0] === "network" && args[1] === "create") {
        networkCreated = true;
        return { status: 0, stdout: INGRESS_HOST_NETWORK_TEST_ID, stderr: "" };
      }
      if (args[0] === "container" && args[1] === "inspect") {
        return started ? { status: 0, stdout: "", stderr: "" } : { status: 1, stdout: "", stderr: `Error: No such container: ${args[2]}` };
      }
      if (args[0] === "run") { started = true; return { status: 0, stdout: `${FORWARDER_ID}\n`, stderr: "" }; }
      if (args[0] === "exec") return { status: 1, stdout: "", stderr: "" };
      if (args[0] === "rm") {
        return { status: 1, stdout: "", stderr: `Error: No such container: ${FORWARDER_ID}-stale` };
      }
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;
    expect(() => startIngressForwarder(context, io, input())).toThrow(/still running/u);
  });

  test.each([
    [{ hostPort: "70000" }, /host port is invalid/u],
    [{ targetPort: "0" }, /target port is invalid/u],
    [{ target: "evil; rm -rf" }, /target is invalid/u],
    [{ internalNetwork: "bad name" }, /internal network is invalid/u],
    [{ internalNetwork: ingressHostNetworkName(PROJECT_ID) }, /must not be the host-facing network/u],
    [{ extraEnv: { INGRESS_TARGET: "elsewhere" } }, /reserved ingress var/u],
    [{ extraEnv: { "BAD-NAME": "x" } }, /env name is invalid/u],
    [{ extraEnv: { OK: "line\nbreak" } }, /control character/u],
    [{ purpose: "exfiltrate" as never }, /unknown ingress purpose/u],
  ])("refuses invalid input %#", (overrides, message) => {
    const { io } = fakeIo();
    expect(() => startIngressForwarder(context, io, input(overrides))).toThrow(message);
  });
});

describe("teardown", () => {
  test("forced cleanup removes an exact empty managed network by full id", () => {
    const network = ingressHostNetworkInspectFixture(PROJECT_ID);
    const calls: string[][] = [];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([network]), stderr: "" };
      }
      if (args[0] === "network" && args[1] === "rm") {
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep(context, io, PROJECT_ID))
      .toEqual({ kind: "removed" });
    expect(calls).toContainEqual(["network", "rm", INGRESS_HOST_NETWORK_TEST_ID]);
  });

  test("forced cleanup retains a foreign-labeled managed-name network without mutation", () => {
    const network = ingressHostNetworkInspectFixture(PROJECT_ID);
    network.Labels = { ...network.Labels, "io.runfree.project-id": "abcdef012345" };
    const calls: string[][] = [];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([network]), stderr: "" };
      }
      throw new Error(`unexpected Docker mutation: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep(context, io, PROJECT_ID).kind)
      .toBe("retained");
    expect(calls.some((args) => args[0] === "network" && args[1] === "rm")).toBe(false);
  });

  test("forced cleanup removes a fully-labeled empty bridge even when its deep shape drifted", () => {
    // Accepted narrowing: deep bridge shape (driver options, address family,
    // IPAM) is creation authority. Teardown proof is identity only — exact ID,
    // versioned name, minted labels, exact endpoints.
    const network = ingressHostNetworkInspectFixture(PROJECT_ID);
    network.Options = { "com.docker.network.bridge.name": "foreign0" };
    const calls: string[][] = [];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      calls.push(args);
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([network]), stderr: "" };
      }
      if (args[0] === "network" && args[1] === "rm") {
        return { status: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(removeValidatedEmptyManagedIngressHostNetworkAfterForcedSweep(context, io, PROJECT_ID))
      .toEqual({ kind: "removed" });
    expect(calls).toContainEqual(["network", "rm", INGRESS_HOST_NETWORK_TEST_ID]);
  });

  test("unlabeled current-name lookalikes are retained for every bridge shape", () => {
    const mutations: Array<(network: ReturnType<typeof ingressHostNetworkInspectFixture>) => void> = [
      (network) => { network.EnableIPv6 = true; },
      (network) => { network.IPAM = { ...network.IPAM, Options: { custom: "true" } }; },
      (network) => { network.Options = { "com.docker.network.bridge.name": "foreign0" }; },
    ];
    for (const mutate of mutations) {
      const network = ingressHostNetworkInspectFixture(PROJECT_ID);
      network.Labels = {};
      mutate(network);
      const capture = vi.fn((_cmd: string, args: string[]) => {
        if (args[0] === "network" && args[1] === "inspect") {
          return { status: 0, stdout: JSON.stringify([network]), stderr: "" };
        }
        throw new Error(`unexpected Docker mutation: ${args.join(" ")}`);
      });
      const io = { capture } as unknown as RuntimeIO;

      expect(() => inspectIngressHostNetwork(context, io, PROJECT_ID, "teardown"))
        .toThrow(/refusing unverified ingress host network/u);
      expect(capture.mock.calls.some((call) => {
        const args = (call as unknown as [string, string[]])[1];
        return args[0] === "network" && args[1] === "rm";
      })).toBe(false);
    }
  });

  test("removeAllIngressForwarders removes each forwarder then the host network when none remain", () => {
    let forwarders = ["runfree-ingress-port-0123456789ab-3000"];
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "ps") return { status: 0, stdout: `${forwarders.join("\n")}\n`, stderr: "" };
      if (args[0] === "container" && args[1] === "inspect") {
        return { status: forwarders.includes(args[2]) ? 0 : 1, stdout: "", stderr: "" };
      }
      if (args[0] === "rm") {
        forwarders = forwarders.filter((name) => !args.includes(name));
        return { status: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "network" && args[1] === "inspect") {
        return { status: 0, stdout: JSON.stringify([ingressHostNetworkInspectFixture(PROJECT_ID)]), stderr: "" };
      }
      if (args[0] === "network" && args[1] === "rm") return { status: 0, stdout: "", stderr: "" };
      return { status: 0, stdout: "", stderr: "" };
    });
    const io = { capture } as unknown as RuntimeIO;

    removeAllIngressForwarders(context, io, PROJECT_ID);

    const calls = capture.mock.calls.map((c) => (c as unknown as [string, string[]])[1]);
    expect(calls.some((args) => args[0] === "rm" && args.includes("runfree-ingress-port-0123456789ab-3000"))).toBe(true);
    expect(calls.some((args) => args[0] === "network" && args[1] === "rm" && args[2] === INGRESS_HOST_NETWORK_TEST_ID)).toBe(true);
  });

  test("listIngressForwarders filters by project id and role", () => {
    const capture = vi.fn(() => ({ status: 0, stdout: "runfree-ingress-vnc-0123456789ab-5901\n", stderr: "" }));
    const io = { capture } as unknown as RuntimeIO;

    expect(listIngressForwarders(context, io, PROJECT_ID)).toEqual(["runfree-ingress-vnc-0123456789ab-5901"]);
    const args = (capture.mock.calls[0] as unknown as [string, string[]])[1];
    expect(args).toEqual(expect.arrayContaining([
      "--filter",
      "label=io.runfree.project-id=0123456789ab",
      "--filter",
      "label=io.runfree.container-role=ingress-forwarder",
    ]));
  });

  test("treats a validated --rm forwarder that disappears before removal as gone", () => {
    const id = "f".repeat(64);
    const capture = vi.fn((_cmd: string, args: string[]) => {
      if (args[0] === "rm") {
        return { status: 1, stdout: "", stderr: `Error: No such container: ${id}` };
      }
      if (args[0] === "ps") return { status: 0, stdout: "", stderr: "" };
      if (args[0] === "network" && args[1] === "inspect") {
        return missingNetworkResult(args[2] as string);
      }
      throw new Error(`unexpected Docker arguments: ${args.join(" ")}`);
    });
    const io = { capture } as unknown as RuntimeIO;

    expect(() => stopIngressForwarders(context, io, PROJECT_ID, [id])).not.toThrow();
  });
});
