import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { approveNetworkCandidate, readApprovedNetworkPolicy, readControlApprovalSelection } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { LOCAL_POLICY_EXCLUDE_PATTERN } from "./git-exclude.ts";
import { mutateDesiredHostService } from "./host-service-mutation.ts";

const writes = vi.hoisted(() => ({ replaced: [] as string[] }));

vi.mock("../safe-fs.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../safe-fs.ts")>();
  return {
    ...actual,
    safeReplaceProjectFile: (...args: Parameters<typeof actual.safeReplaceProjectFile>) => {
      writes.replaced.push(args[1]);
      return actual.safeReplaceProjectFile(...args);
    },
  };
});

function command(commandName: string, args: string[]): CaptureResult {
  const result = childProcess.spawnSync(commandName, args, { encoding: "utf8" });
  return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

const ADMIT_IDB = () => ({ ok: true as const, owner: { command: "idb_companion", pid: 4242 } });

describe("typed host-service mutations", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  let projectPolicyPath: string;
  let localPolicyPath: string;

  beforeEach(() => {
    writes.replaced = [];
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-host-service-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-host-service-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    projectPolicyPath = path.join(root, ".runfree", "network-policy.json");
    localPolicyPath = path.join(root, ".runfree", "network-policy.local.json");
    fs.writeFileSync(projectPolicyPath, '{"version":2,"hosts":["project.example.com"]}\n');
    const env = {
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env };
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive", new Date("2026-10-04T00:00:00.000Z"));
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive", new Date("2026-10-04T00:00:00.000Z"));
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  // The transaction never touches a container; only git (local scope) may run.
  function io(): RuntimeIO {
    return {
      capture: (commandName, args) => {
        if (commandName === "git") return command(commandName, args);
        throw new Error(`unexpected command: ${commandName} ${args.join(" ")}`);
      },
      run: () => 0,
      commandExists: () => true,
      confirm: () => false,
      admin: async () => 0,
    };
  }

  function approvedDigest(layer: "network-project" | "network-local"): string | undefined {
    return readControlApprovalSelection(root, context.project)?.subjects[layer]?.digest;
  }

  test("add writes hostServices to the project policy and approves exactly it", async () => {
    const result = await mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, {
      admit: ADMIT_IDB,
    });

    expect(result).toMatchObject({ changed: true, owner: { command: "idb_companion", pid: 4242 } });
    expect(JSON.parse(fs.readFileSync(projectPolicyPath, "utf8"))).toMatchObject({
      hostServices: { idb: { target: "host-loopback", port: 10882 } },
    });
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).toMatchObject({
      hostServices: { idb: { target: "host-loopback", port: 10882 } },
    });
    expect(fs.existsSync(localPolicyPath)).toBe(false);
  });

  test("an admission refusal happens before any policy write or approval", async () => {
    const before = fs.readFileSync(projectPolicyPath, "utf8");
    const approvedBefore = approvedDigest("network-project");
    const admit = vi.fn(() => ({ ok: false as const, reason: "no process listens on 127.0.0.1:10882" }));

    await expect(mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, { admit }))
      .rejects.toThrow("no process listens on 127.0.0.1:10882\nstart the service on the host's 127.0.0.1:10882 (not a Docker-published port), then run: runfree host-service add idb --port 10882");

    expect(admit).toHaveBeenCalledOnce();
    expect(writes.replaced).toEqual([]);
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(before);
    expect(approvedDigest("network-project")).toBe(approvedBefore);
  });

  test("an invalid name or statically refused port is refused before admission and write", async () => {
    const admit = vi.fn(ADMIT_IDB);
    await expect(mutateDesiredHostService(context, io(), "project", { kind: "add", name: "Bad_Name", port: 10882 }, { admit }))
      .rejects.toThrow(/host-service name/u);
    await expect(mutateDesiredHostService(context, io(), "project", { kind: "add", name: "docker", port: 2375 }, { admit }))
      .rejects.toThrow(/2375/u);
    expect(admit).not.toHaveBeenCalled();
    expect(writes.replaced).toEqual([]);
  });

  test("a duplicate port under a different name is refused before admission and write", async () => {
    await mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, { admit: ADMIT_IDB });
    writes.replaced = [];
    const before = fs.readFileSync(projectPolicyPath, "utf8");
    const admit = vi.fn(ADMIT_IDB);

    await expect(mutateDesiredHostService(context, io(), "project", { kind: "add", name: "other", port: 10882 }, { admit }))
      .rejects.toThrow("port 10882 is already used by host service idb");
    // Across layers too: the compiler would refuse the pair, the mutation says so first.
    await expect(mutateDesiredHostService(context, io(), "local", { kind: "add", name: "other", port: 10882 }, { admit }))
      .rejects.toThrow("port 10882 is already used by host service idb");

    expect(admit).not.toHaveBeenCalled();
    expect(writes.replaced).toEqual([]);
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(before);
    expect(fs.existsSync(localPolicyPath)).toBe(false);
  });

  test("a name the other layer already approves is refused before the write (SR9)", async () => {
    await mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, { admit: ADMIT_IDB });
    writes.replaced = [];

    await expect(mutateDesiredHostService(context, io(), "local", { kind: "add", name: "idb", port: 10883 }, { admit: ADMIT_IDB }))
      .rejects.toThrow("host service idb is already approved in the project layer");
    expect(writes.replaced).toEqual([]);
  });

  test("remove deletes the entry; an unknown name is unchanged", async () => {
    await mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, { admit: ADMIT_IDB });

    const removed = await mutateDesiredHostService(context, io(), "project", { kind: "remove", name: "idb" });
    expect(removed.changed).toBe(true);
    expect(JSON.parse(fs.readFileSync(projectPolicyPath, "utf8"))).not.toHaveProperty("hostServices");
    expect(readApprovedNetworkPolicy(root, context.project, "network-project")).not.toHaveProperty("hostServices");

    writes.replaced = [];
    const unknown = await mutateDesiredHostService(context, io(), "project", { kind: "remove", name: "nothere" });
    expect(unknown.changed).toBe(false);
    expect(writes.replaced).toEqual([]);
  });

  test("remove never runs the port admission", async () => {
    await mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, { admit: ADMIT_IDB });
    const admit = vi.fn(ADMIT_IDB);

    await mutateDesiredHostService(context, io(), "project", { kind: "remove", name: "idb" }, { admit });
    expect(admit).not.toHaveBeenCalled();
  });

  test("--local writes the checkout-local policy and git-excludes it first", async () => {
    expect(command("git", ["init", "-q", root]).status).toBe(0);
    const originalProject = fs.readFileSync(projectPolicyPath, "utf8");

    const result = await mutateDesiredHostService(context, io(), "local", { kind: "add", name: "idb", port: 10882 }, {
      admit: ADMIT_IDB,
    });

    expect(result.changed).toBe(true);
    expect(JSON.parse(fs.readFileSync(localPolicyPath, "utf8"))).toMatchObject({
      hostServices: { idb: { target: "host-loopback", port: 10882 } },
    });
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(originalProject);
    const exclude = fs.readFileSync(path.join(root, ".git", "info", "exclude"), "utf8");
    expect(exclude.split(/\r?\n/u)).toContain(LOCAL_POLICY_EXCLUDE_PATTERN);
    expect(readApprovedNetworkPolicy(root, context.project, "network-local")).toMatchObject({
      hostServices: { idb: { port: 10882 } },
    });
  });

  test("agent-authored drift is refused before admission runs", async () => {
    fs.writeFileSync(projectPolicyPath, '{"version":2,"hosts":[],"hostServices":{"evil":{"target":"host-loopback","port":2222}}}\n');
    const admit = vi.fn(ADMIT_IDB);

    await expect(mutateDesiredHostService(context, io(), "project", { kind: "add", name: "idb", port: 10882 }, { admit }))
      .rejects.toThrow("project desired policy changed outside a trusted Runfree transaction");
    expect(admit).not.toHaveBeenCalled();
    expect(writes.replaced).toEqual([]);
  });
});
