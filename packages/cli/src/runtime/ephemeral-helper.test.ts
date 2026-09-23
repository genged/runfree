import { describe, expect, test, vi } from "vitest";

import { ephemeralHelperRunArguments, runEphemeralHelper } from "./ephemeral-helper.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const NETWORK_ID = "c".repeat(64);

describe("ephemeral helper run arguments", () => {
  test("mints the exact hardened argv with no network by default", () => {
    const args = ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      capabilities: ["CHOWN"],
      volumes: [{ name: "runfree-x_deps", target: "/workspace/node_modules" }],
      command: ["sh", "-c", "script", "name", "arg"],
    });

    expect(args).toEqual([
      "run",
      "--rm",
      "--label",
      "io.runfree.managed=true",
      "--label",
      "io.runfree.container-role=ephemeral-helper",
      "--label",
      "io.runfree.lifecycle-owner=utility",
      "--label",
      "io.runfree.label-schema=1",
      "--label",
      `io.runfree.project-id=${PROJECT_ID}`,
      "--label",
      "io.runfree.helper-purpose=dependency-prep",
      "--user",
      "0:0",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "CHOWN",
      "--security-opt",
      "no-new-privileges:true",
      "--read-only",
      "--pids-limit",
      "64",
      "--network",
      "none",
      "-v",
      "runfree-x_deps:/workspace/node_modules",
      "runfree-agent:abc",
      "sh",
      "-c",
      "script",
      "name",
      "arg",
    ]);
  });

  test("batched dependency-prep inputs mount every volume in declared order under the same hardening", () => {
    // The L2 batch mounts every volume in ONE run; the hardening argv must be
    // byte-identical to the single-volume shape with only the -v pairs added.
    const args = ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      capabilities: ["CHOWN"],
      volumes: [
        { name: "runfree-x_deps-a", target: "/mnt/runfree-dep-prep/0" },
        { name: "runfree-x_deps-b", target: "/mnt/runfree-dep-prep/1" },
        { name: "runfree-x_store", target: "/mnt/runfree-dep-prep/2" },
      ],
      command: ["sh", "-c", "script"],
    });

    const volumeSpecs = args
      .map((arg, index) => (arg === "-v" ? args[index + 1] : undefined))
      .filter((spec): spec is string => spec !== undefined);
    expect(volumeSpecs).toEqual([
      "runfree-x_deps-a:/mnt/runfree-dep-prep/0",
      "runfree-x_deps-b:/mnt/runfree-dep-prep/1",
      "runfree-x_store:/mnt/runfree-dep-prep/2",
    ]);
    expect(args).toEqual(expect.arrayContaining([
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only", "--pids-limit", "64",
      "--network", "none",
    ]));
  });

  test("places a probe on an exact network with a static address", () => {
    const args = ephemeralHelperRunArguments({
      purpose: "deny-probe",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "1000:1000",
      networkId: NETWORK_ID,
      ip: "172.30.0.99",
      command: ["true"],
    });

    expect(args).toContain(NETWORK_ID);
    expect(args.slice(args.indexOf("--network"))).toEqual(
      expect.arrayContaining(["--network", NETWORK_ID, "--ip", "172.30.0.99"]),
    );
    // No capability sneaks in without being asked for.
    expect(args).not.toContain("--cap-add");
  });

  test.each([
    [{ image: "" }, /exact image reference/u],
    [{ image: "img with space" }, /exact image reference/u],
    [{ networkId: "abc" }, /exact 64-hex network id/u],
    [{ ip: "172.30.0.99" }, /static address requires a network/u],
    [{ networkId: NETWORK_ID, ip: "not-an-ip" }, /not IPv4/u],
    [{ volumes: [{ name: "", target: "/x" }] }, /volume name is invalid/u],
    [{ volumes: [{ name: "ok", target: "relative" }] }, /volume target is invalid/u],
    [{ volumes: [{ name: "ok", target: "/x:ro" }] }, /volume target is invalid/u],
    [{ command: [] }, /requires a command/u],
    [{ capabilities: ["SYS_ADMIN" as never] }, /not in the closed set/u],
    [{ projectId: "short" }, /exact project id/u],
    [{ purpose: "exfiltrate" as never }, /unknown ephemeral helper purpose/u],
  ])("refuses invalid input %#", (overrides, message) => {
    expect(() => ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      command: ["true"],
      ...overrides,
    })).toThrow(message);
  });
});

describe("runEphemeralHelper", () => {
  test("pipes stdin, bounds the run, and threads the docker client environment", () => {
    const capture = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));
    const io = { capture } as unknown as RuntimeIO;
    const context = { env: { PATH: "/usr/bin" }, projectRoot: "/p" } as unknown as RuntimeContext;

    runEphemeralHelper(context, io, {
      purpose: "deny-probe",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "1000:1000",
      command: ["sh", "-s"],
      stdin: "echo probe",
      timeoutMs: 5_000,
    });

    expect(capture).toHaveBeenCalledTimes(1);
    const [command, args, options] = capture.mock.calls[0] as unknown as [string, string[], Record<string, unknown>];
    expect(command).toBe("docker");
    expect(args.slice(0, 3)).toEqual(["run", "--rm", "-i"]);
    expect(options.input).toBe("echo probe");
    expect(options.timeout).toBe(5_000);
    expect(options.env).toBeDefined();
  });
});
