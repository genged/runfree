import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  readHostServicePortRegistry,
  recordProjectHostServicePorts,
  registeredHostServicePortRefusal,
  removeProjectHostServicePorts,
  repairHostServicePortRegistry,
} from "./host-service-registry.ts";
import { runfreeStateRoot } from "./paths.ts";
import { projectHash } from "./project-identity.ts";

// A pid far past any plausible live process, so `processAlive` reads it as
// dead on every platform without depending on what happens to be running.
const DEAD_PID = 4_194_305;

const PROJECT_A_ROOT = "/workspace/project-a";
const PROJECT_B_ROOT = "/workspace/project-b";
const PROJECT_A_ID = projectHash(PROJECT_A_ROOT);
const PROJECT_B_ID = projectHash(PROJECT_B_ROOT);

let stateHome: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-host-service-registry-"));
  env = { XDG_STATE_HOME: stateHome };
});

afterEach(() => {
  fs.rmSync(stateHome, { recursive: true, force: true });
});

function stateRoot(): string {
  return runfreeStateRoot(env);
}

function registryFile(): string {
  return path.join(stateRoot(), "host-service-ports.json");
}

function writeProjectPointer(id: string, root: string): void {
  const dir = path.join(stateRoot(), "projects", id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "project.json"), `${JSON.stringify({ projectRoot: root, updatedAt: new Date().toISOString() })}\n`);
}

describe("recordProjectHostServicePorts / readHostServicePortRegistry", () => {
  test("round trips: record then read finds the exact owner", () => {
    recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882, 10883], { 10882: "idb_companion" });

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toEqual({ projectId: PROJECT_A_ID, projectRoot: PROJECT_A_ROOT, command: "idb_companion" });
    expect(read.owners.get(10883)).toEqual({ projectId: PROJECT_A_ID, projectRoot: PROJECT_A_ROOT });
    expect(read.owners.get(10884)).toBeUndefined();
  });

  test("an empty port list removes the project's row", () => {
    recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);

    recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, []);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toBeUndefined();
    expect(read.owners.get(10883)?.projectId).toBe(PROJECT_B_ID);
  });

  test("a symlinked registry file is refused rather than followed for a write", () => {
    fs.mkdirSync(stateRoot(), { recursive: true });
    const decoyTarget = path.join(stateRoot(), "decoy-target.json");
    fs.writeFileSync(decoyTarget, "{}\n");
    fs.symlinkSync(decoyTarget, registryFile());

    expect(() => recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]))
      .toThrow(/symlink/);
    expect(fs.readFileSync(decoyTarget, "utf8")).toBe("{}\n");
  });

  test("corrupt JSON reads as ok:false, and the refusal names the --repair remedy", () => {
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), "{ not json");

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(false);

    const refusal = registeredHostServicePortRefusal(env, 10882);
    expect(refusal).toBeDefined();
    expect(refusal).toContain("runfree host-service list --repair");
  });
});

describe("repairHostServicePortRegistry", () => {
  test("rebuilds the registry from each known project's own answer, recovering from corruption", () => {
    writeProjectPointer(PROJECT_A_ID, PROJECT_A_ROOT);
    writeProjectPointer(PROJECT_B_ID, PROJECT_B_ROOT);
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), "{ not json");

    const result = repairHostServicePortRegistry(env, (_root, id) => (id === PROJECT_A_ID ? [10882] : undefined));
    expect(result).toEqual({ projects: 1, ports: 1 });

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.projectId).toBe(PROJECT_A_ID);
    expect(read.owners.size).toBe(1);
  });
});

describe("removeProjectHostServicePorts", () => {
  test("removes one project's row and leaves another's intact", () => {
    recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);

    removeProjectHostServicePorts(env, PROJECT_A_ID);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toBeUndefined();
    expect(read.owners.get(10883)?.projectId).toBe(PROJECT_B_ID);
  });

  test("is a no-op when the project has no row", () => {
    recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);
    expect(() => removeProjectHostServicePorts(env, PROJECT_A_ID)).not.toThrow();
    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
  });
});

describe("registeredHostServicePortRefusal", () => {
  test("refuses a port registered by another project, naming its root", () => {
    recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10882]);
    const refusal = registeredHostServicePortRefusal(env, 10882, PROJECT_A_ID);
    expect(refusal).toContain(PROJECT_B_ROOT);
  });

  test("admits the registering project's own port", () => {
    recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    expect(registeredHostServicePortRefusal(env, 10882, PROJECT_A_ID)).toBeUndefined();
  });

  test("admits an unregistered port", () => {
    expect(registeredHostServicePortRefusal(env, 19999, PROJECT_A_ID)).toBeUndefined();
  });
});

describe("lock mechanics", () => {
  test("a stale lock whose owner process no longer runs is reclaimed", () => {
    const lockDir = path.join(stateRoot(), "host-service-ports.lock");
    fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(lockDir, "owner.json"), `${JSON.stringify({
      schemaVersion: 1,
      pid: DEAD_PID,
      nonce: "old-owner",
      createdAt: "2026-01-01T00:00:00.000Z",
    })}\n`);

    expect(() => recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882])).not.toThrow();
    // The reclaim replaced the stale holder and the write released cleanly;
    // nothing is left behind under the old owner's claim.
    expect(fs.existsSync(lockDir)).toBe(false);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.projectId).toBe(PROJECT_A_ID);
  });

  test("contention: a lock held by a live owner is retried until an outside release, and both projects' writes land", async () => {
    const lockDir = path.join(stateRoot(), "host-service-ports.lock");
    fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 });
    // Our own pid: always alive, and with no boot/process-start stamp the
    // staleness check reads "unknown" rather than proving a mismatch, so this
    // lock is live until something actually removes the directory.
    fs.writeFileSync(path.join(lockDir, "owner.json"), `${JSON.stringify({
      schemaVersion: 1,
      pid: process.pid,
      nonce: "external-holder",
      createdAt: new Date().toISOString(),
    })}\n`);

    // A separate OS process releases the lock shortly after; the retrying
    // acquire in this process is a synchronous busy-wait, so only another
    // process's filesystem change can unblock it.
    const releaseScript = "setTimeout(() => { try { require('fs').rmSync(process.argv[1], "
      + "{ recursive: true, force: true }); } catch (error) {} }, 150);";
    const release = spawn(process.execPath, ["-e", releaseScript, lockDir], { stdio: "ignore" });

    try {
      recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
      recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);
    } finally {
      await new Promise<void>((resolve) => release.once("exit", () => resolve()));
    }

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.projectId).toBe(PROJECT_A_ID);
    expect(read.owners.get(10883)?.projectId).toBe(PROJECT_B_ID);
  }, 10_000);
});
