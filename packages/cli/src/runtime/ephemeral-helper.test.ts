import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test, vi } from "vitest";

import { ephemeralHelperRunArguments, runEphemeralHelper } from "./ephemeral-helper.ts";
import type { RuntimeContext, RuntimeIO } from "./types.ts";

const PROJECT_ID = "0123456789ab";
const NETWORK_ID = "c".repeat(64);
const RUN_NONCE = "d".repeat(32);
const CID_FILE = "/state/projects/0123456789ab/helper-runs/run-AbC123/cid";
// What runEphemeralHelper adds to a caller's request: the run's own cidfile
// and nonce, both minted under the host-owned helper-runs directory.
const RUN = { cidFile: CID_FILE, runNonce: RUN_NONCE } as const;

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
      ...RUN,
    });

    expect(args).toEqual([
      "run",
      "--rm",
      "--pull",
      "never",
      "--cidfile",
      CID_FILE,
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
      "--label",
      `io.runfree.helper-run=${RUN_NONCE}`,
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
      ...RUN,
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
      ip: "172.30.0.19",
      command: ["true"],
      ...RUN,
    });

    expect(args).toContain(NETWORK_ID);
    expect(args.slice(args.indexOf("--network"))).toEqual(
      expect.arrayContaining(["--network", NETWORK_ID, "--ip", "172.30.0.19"]),
    );
    // No capability sneaks in without being asked for.
    expect(args).not.toContain("--cap-add");
  });

  test.each([
    [{ image: "" }, /exact image reference/u],
    [{ image: "img with space" }, /exact image reference/u],
    [{ networkId: "abc" }, /exact 64-hex network id/u],
    [{ ip: "172.30.0.19" }, /static address requires a network/u],
    [{ networkId: NETWORK_ID, ip: "not-an-ip" }, /not IPv4/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.019" }, /not IPv4/u],
    // A helper address is only ever one of the reserved block's hosts: never a
    // session-pool address, a fixed role, or the gateway.
    [{ networkId: NETWORK_ID, ip: "172.30.0.20" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.83" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.99" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.10" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.1" }, /reserved ephemeral-helper block/u],
    [{ networkId: NETWORK_ID, ip: "172.30.0.12" }, /reserved ephemeral-helper block/u],
    [{ volumes: [{ name: "", target: "/x" }] }, /volume name is invalid/u],
    [{ volumes: [{ name: "ok", target: "relative" }] }, /volume target is invalid/u],
    [{ volumes: [{ name: "ok", target: "/x:ro" }] }, /volume target is invalid/u],
    [{ command: [] }, /requires a command/u],
    [{ capabilities: ["SYS_ADMIN" as never] }, /not in the closed set/u],
    // The cidfile is the run's exact-id evidence, so it must be the host-owned
    // run directory's own `cid`, never a caller-chosen path.
    [{ cidFile: "relative/helper-runs/run-AbC123/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/run-AbC123/other" }, /cidfile/u],
    [{ cidFile: "/state/not-helper-runs/run-AbC123/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/run-AbC123/../run-XyZ789/cid" }, /cidfile/u],
    [{ cidFile: "/state/helper-runs/nope-AbC123/cid" }, /cidfile/u],
    [{ runNonce: "" }, /run nonce/u],
    [{ runNonce: "D".repeat(32) }, /run nonce/u],
    [{ runNonce: "d".repeat(31) }, /run nonce/u],
    [{ projectId: "short" }, /exact project id/u],
    [{ purpose: "exfiltrate" as never }, /unknown ephemeral helper purpose/u],
  ])("refuses invalid input %#", (overrides, message) => {
    expect(() => ephemeralHelperRunArguments({
      purpose: "dependency-prep",
      projectId: PROJECT_ID,
      image: "runfree-agent:abc",
      user: "0:0",
      command: ["true"],
      ...RUN,
      ...overrides,
    })).toThrow(message);
  });

  test("never pulls: a helper runs only an image that is already local", () => {
    const args = ephemeralHelperRunArguments({
      purpose: "trust-bundle",
      projectId: PROJECT_ID,
      image: `sha256:${"e".repeat(64)}`,
      user: "1000:1000",
      command: ["true"],
      ...RUN,
    });
    const image = args.indexOf(`sha256:${"e".repeat(64)}`);
    expect(args.slice(0, image)).toEqual(expect.arrayContaining(["--pull", "never", "--cidfile", CID_FILE]));
    expect(args.indexOf("--cidfile")).toBeLessThan(image);
    expect(args.indexOf("--pull")).toBeLessThan(image);
  });
});

describe("runEphemeralHelper", () => {
  test("pipes stdin, bounds the run, and threads the docker client environment", () => {
    const capture = vi.fn(() => ({ status: 0, stdout: "", stderr: "" }));
    const io = { capture } as unknown as RuntimeIO;
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-helper-"));
    const context = { env: { PATH: "/usr/bin" }, projectRoot: "/p", project: { paths: { stateDir } } } as unknown as RuntimeContext;

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
    expect(args.slice(0, 2)).toEqual(["run", "--rm"]);
    expect(args).toContain("-i");
    const cidFile = args[args.indexOf("--cidfile") + 1];
    expect(path.dirname(path.dirname(cidFile))).toBe(path.join(stateDir, "helper-runs"));
    expect(options.input).toBe("echo probe");
    expect(options.timeout).toBe(5_000);
    expect(options.env).toBeDefined();
  });
});
