import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  projectHasRegisteredHostServicePorts,
  readHostServicePortRegistry,
  recordedHostServiceOwners,
  recordProjectHostServicePorts,
  registeredHostServicePortRefusal,
  removeProjectHostServicePorts,
  repairHostServicePortRegistry,
} from "./host-service-registry.ts";
import { runfreeStateRoot } from "./paths.ts";
import { projectHash } from "./project-identity.ts";
import { setOutputWriterForTest } from "./warnings.ts";

// A pid far past any plausible live process, so `processAlive` reads it as
// dead on every platform without depending on what happens to be running.
const DEAD_PID = 4_194_305;

const PROJECT_A_ROOT = "/workspace/project-a";
const PROJECT_B_ROOT = "/workspace/project-b";
const PROJECT_A_ID = projectHash(PROJECT_A_ROOT);
const PROJECT_B_ID = projectHash(PROJECT_B_ROOT);
const PROJECT_C_ROOT = "/workspace/project-c";
const PROJECT_C_ID = projectHash(PROJECT_C_ROOT);

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

function lockDir(): string {
  return path.join(stateRoot(), "host-service-ports.lock");
}

function writeProjectPointer(id: string, root: string): string {
  const dir = path.join(stateRoot(), "projects", id);
  fs.mkdirSync(dir, { recursive: true });
  const pointerPath = path.join(dir, "project.json");
  fs.writeFileSync(pointerPath, `${JSON.stringify({ projectRoot: root, updatedAt: new Date().toISOString() })}\n`);
  return pointerPath;
}

// A lock directory with a live (never dying, in this test) owner: our own
// pid, which `processAlive` always reports as alive, and no boot/process-start
// stamp, which `lockIsStale` reads as "unknown" rather than a provable
// mismatch. The only way this lock goes away is something actually removing
// the directory.
function holdLockLive(nonce = "external-holder"): void {
  fs.mkdirSync(lockDir(), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockDir(), "owner.json"), `${JSON.stringify({
    schemaVersion: 1,
    pid: process.pid,
    nonce,
    createdAt: new Date().toISOString(),
  })}\n`);
}

describe("recordProjectHostServicePorts / readHostServicePortRegistry", () => {
  test("round trips: record then read finds the exact owner", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882, 10883], { 10882: "idb_companion" });

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toEqual([{ projectId: PROJECT_A_ID, projectRoot: PROJECT_A_ROOT, command: "idb_companion" }]);
    expect(read.owners.get(10883)).toEqual([{ projectId: PROJECT_A_ID, projectRoot: PROJECT_A_ROOT }]);
    expect(read.owners.get(10884)).toBeUndefined();
  });

  test("an empty port list removes the project's row", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);

    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, []);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toBeUndefined();
    expect(read.owners.get(10883)?.[0]?.projectId).toBe(PROJECT_B_ID);
  });

  test("a symlinked registry file is refused rather than followed for a write", async () => {
    fs.mkdirSync(stateRoot(), { recursive: true });
    const decoyTarget = path.join(stateRoot(), "decoy-target.json");
    fs.writeFileSync(decoyTarget, "{}\n");
    fs.symlinkSync(decoyTarget, registryFile());

    await expect(recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]))
      .rejects.toThrow(/symlink/);
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

describe("several projects owning one port (R18)", () => {
  test("two projects record 10882 and every read stays ok, listing both owners", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882], { 10882: "idb_companion" });
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10882, 10883]);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.map((owner) => owner.projectId).sort()).toEqual([PROJECT_A_ID, PROJECT_B_ID].sort());
    expect(recordedHostServiceOwners(env, PROJECT_A_ID)).toEqual(new Map([[10882, "idb_companion"]]));
    expect(recordedHostServiceOwners(env, PROJECT_B_ID)).toEqual(new Map());
    expect(projectHasRegisteredHostServicePorts(env, PROJECT_B_ID)).toBe(true);
    // A third write still reads and rewrites the shared state.
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882, 10884]);
    expect(readHostServicePortRegistry(env).ok).toBe(true);
  });

  test("a third project is refused on the shared port naming both owners, admitted on an unrelated port", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10882]);

    const refusal = registeredHostServicePortRefusal(env, 10882, PROJECT_C_ID);
    expect(refusal).toContain(PROJECT_A_ROOT);
    expect(refusal).toContain(PROJECT_B_ROOT);
    expect(registeredHostServicePortRefusal(env, 19999, PROJECT_C_ID)).toBeUndefined();
  });

  test("an owner is still refused when another project also owns the port", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10882]);

    const refusal = registeredHostServicePortRefusal(env, 10882, PROJECT_A_ID);
    expect(refusal).toContain(PROJECT_B_ROOT);
    expect(refusal).not.toContain(PROJECT_A_ROOT);
  });

  test("a duplicate port inside one project's row is still refused on read", () => {
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), `${JSON.stringify({
      schemaVersion: 1,
      projects: { [PROJECT_A_ID]: { projectRoot: PROJECT_A_ROOT, ports: [10882, 10882], updatedAt: new Date().toISOString() } },
    })}\n`);
    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(false);
    if (read.ok) throw new Error("unreachable");
    expect(read.reason).toMatch(/duplicate ports/);
  });

  test("repair over two projects approving the same port succeeds and reads back both", async () => {
    writeProjectPointer(PROJECT_A_ID, PROJECT_A_ROOT);
    writeProjectPointer(PROJECT_B_ID, PROJECT_B_ROOT);

    const result = await repairHostServicePortRegistry(env, () => [10882]);
    expect(result).toEqual({ projects: 2, ports: 2 });
    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toHaveLength(2);
  });
});

describe("repairHostServicePortRegistry", () => {
  test("rebuilds the registry from each known project's own answer, recovering from corruption", async () => {
    writeProjectPointer(PROJECT_A_ID, PROJECT_A_ROOT);
    writeProjectPointer(PROJECT_B_ID, PROJECT_B_ROOT);
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), "{ not json");

    const result = await repairHostServicePortRegistry(env, (_root, id) => (id === PROJECT_A_ID ? [10882] : undefined));
    expect(result).toEqual({ projects: 1, ports: 1 });

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.[0]?.projectId).toBe(PROJECT_A_ID);
    expect(read.owners.size).toBe(1);
  });

  test("a project whose ports cannot be read fails the repair closed: nothing written, every such project named; a later readable pass reclaims", async () => {
    writeProjectPointer(PROJECT_A_ID, PROJECT_A_ROOT);
    writeProjectPointer(PROJECT_B_ID, PROJECT_B_ROOT);
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), "{ not json");

    await expect(repairHostServicePortRegistry(env, (_root, id) => {
      if (id === PROJECT_B_ID) throw new Error("active control selection is malformed");
      return [10882];
    })).rejects.toThrow(new RegExp(`${PROJECT_B_ROOT.replace(/\//g, "\\/")}[^\n]*active control selection is malformed`, "u"));
    expect(fs.readFileSync(registryFile(), "utf8")).toBe("{ not json");
    expect(fs.existsSync(lockDir())).toBe(false);

    const result = await repairHostServicePortRegistry(env, (_root, id) => (id === PROJECT_A_ID ? [10882] : undefined));
    expect(result).toEqual({ projects: 1, ports: 1 });
    expect(readHostServicePortRegistry(env).ok).toBe(true);
  });

  test("skips a hard-linked project.json pointer without aborting repair for the other known project", async () => {
    writeProjectPointer(PROJECT_A_ID, PROJECT_A_ROOT);
    const pointerB = writeProjectPointer(PROJECT_B_ID, PROJECT_B_ROOT);
    // A second directory entry for the same inode: the same hard-link shape
    // `readBoundedRegularFile` refuses for the registry file itself.
    fs.linkSync(pointerB, `${pointerB}.extra-link`);

    const result = await repairHostServicePortRegistry(env, (_root, id) => {
      if (id === PROJECT_A_ID) return [10882];
      if (id === PROJECT_B_ID) return [10883];
      return undefined;
    });

    expect(result).toEqual({ projects: 1, ports: 1 });
    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.[0]?.projectId).toBe(PROJECT_A_ID);
    expect(read.owners.get(10883)).toBeUndefined();
  });

  test("skips an oversized project.json pointer without aborting repair for the other known project", async () => {
    const pointerA = writeProjectPointer(PROJECT_A_ID, PROJECT_A_ROOT);
    fs.writeFileSync(pointerA, `${JSON.stringify({ projectRoot: PROJECT_A_ROOT, updatedAt: new Date().toISOString(), pad: "x".repeat(128 * 1024) })}\n`);
    writeProjectPointer(PROJECT_B_ID, PROJECT_B_ROOT);

    const result = await repairHostServicePortRegistry(env, (_root, id) => {
      if (id === PROJECT_A_ID) return [10882];
      if (id === PROJECT_B_ID) return [10883];
      return undefined;
    });

    expect(result).toEqual({ projects: 1, ports: 1 });
    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10883)?.[0]?.projectId).toBe(PROJECT_B_ID);
    expect(read.owners.get(10882)).toBeUndefined();
  });
});

describe("removeProjectHostServicePorts", () => {
  test("removes one project's row and leaves another's intact", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);

    await removeProjectHostServicePorts(env, PROJECT_A_ID);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)).toBeUndefined();
    expect(read.owners.get(10883)?.[0]?.projectId).toBe(PROJECT_B_ID);
  });

  test("is a no-op when the project has no row", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);
    await removeProjectHostServicePorts(env, PROJECT_A_ID);
    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
  });
});

describe("recordedHostServiceOwners", () => {
  test("collects only this project's ports that have a recorded command", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882, 10883], { 10882: "idb_companion" });
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10884], { 10884: "other_service" });

    const recorded = recordedHostServiceOwners(env, PROJECT_A_ID);
    expect(recorded).toEqual(new Map([[10882, "idb_companion"]]));
  });

  test("is empty for a project with no row", () => {
    expect(recordedHostServiceOwners(env, PROJECT_A_ID)).toEqual(new Map());
  });

  test("is empty, never throws, when the registry is unreadable", () => {
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), "not json");
    expect(recordedHostServiceOwners(env, PROJECT_A_ID)).toEqual(new Map());
  });
});

describe("projectHasRegisteredHostServicePorts", () => {
  test("true for a project with a registered port, even with no recorded command", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    expect(projectHasRegisteredHostServicePorts(env, PROJECT_A_ID)).toBe(true);
  });

  test("false for a project with no row", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);
    expect(projectHasRegisteredHostServicePorts(env, PROJECT_A_ID)).toBe(false);
  });

  test("false for an empty registry", () => {
    expect(projectHasRegisteredHostServicePorts(env, PROJECT_A_ID)).toBe(false);
  });

  test("false, never throws, when the registry is unreadable", () => {
    fs.mkdirSync(stateRoot(), { recursive: true });
    fs.writeFileSync(registryFile(), "not json");
    expect(projectHasRegisteredHostServicePorts(env, PROJECT_A_ID)).toBe(false);
  });
});

describe("registeredHostServicePortRefusal", () => {
  test("refuses a port registered by another project, naming its root", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10882]);
    const refusal = registeredHostServicePortRefusal(env, 10882, PROJECT_A_ID);
    expect(refusal).toContain(PROJECT_B_ROOT);
  });

  test("admits the registering project's own port", async () => {
    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    expect(registeredHostServicePortRefusal(env, 10882, PROJECT_A_ID)).toBeUndefined();
  });

  test("admits an unregistered port", () => {
    expect(registeredHostServicePortRefusal(env, 19999, PROJECT_A_ID)).toBeUndefined();
  });
});

describe("lock mechanics: reclaim and contention", () => {
  test("a stale lock whose owner process no longer runs is reclaimed", async () => {
    fs.mkdirSync(lockDir(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(lockDir(), "owner.json"), `${JSON.stringify({
      schemaVersion: 1,
      pid: DEAD_PID,
      nonce: "old-owner",
      createdAt: "2026-01-01T00:00:00.000Z",
    })}\n`);

    await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    // The reclaim replaced the stale holder and the write released cleanly;
    // nothing is left behind under the old owner's claim.
    expect(fs.existsSync(lockDir())).toBe(false);

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.[0]?.projectId).toBe(PROJECT_A_ID);
  });

  test("contention: a lock held by a live owner is retried through the event loop until an outside release, and both projects' writes land", async () => {
    holdLockLive();

    // A separate OS process releases the lock shortly after. The retrying
    // acquire in this process now awaits a real `setTimeout` between
    // attempts rather than blocking the event loop, so this process keeps
    // running while it waits; only another process's filesystem change can
    // unblock it (there is no injected release path).
    const releaseScript = "setTimeout(() => { try { require('fs').rmSync(process.argv[1], "
      + "{ recursive: true, force: true }); } catch (error) {} }, 150);";
    const release = spawn(process.execPath, ["-e", releaseScript, lockDir()], { stdio: "ignore" });
    // Attached immediately, before anything is awaited: the release can
    // complete (and "exit" can fire) while this process is inside its own
    // retry `await`s, now that acquisition no longer blocks the event loop.
    // A listener attached only in `finally`, after those awaits, could miss
    // an "exit" that already fired and hang forever.
    const released = new Promise<void>((resolve) => release.once("exit", () => resolve()));

    try {
      await recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
      await recordProjectHostServicePorts(env, { id: PROJECT_B_ID, root: PROJECT_B_ROOT }, [10883]);
    } finally {
      await released;
    }

    const read = readHostServicePortRegistry(env);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error("unreachable");
    expect(read.owners.get(10882)?.[0]?.projectId).toBe(PROJECT_A_ID);
    expect(read.owners.get(10883)?.[0]?.projectId).toBe(PROJECT_B_ID);
  }, 10_000);
});

describe("lock mechanics: progress line and exhaustion", () => {
  let lines: string[];

  beforeEach(() => {
    lines = [];
    setOutputWriterForTest((line) => lines.push(line));
    vi.useFakeTimers();
  });

  afterEach(() => {
    setOutputWriterForTest(undefined);
    vi.useRealTimers();
  });

  function progressLines(): string[] {
    return lines.filter((line) => line.includes("waiting for the host-service port registry lock"));
  }

  test("prints one progress line once the wait passes 2s, never repeats it, and fails closed after 5s total", async () => {
    holdLockLive();
    const pending = recordProjectHostServicePorts(env, { id: PROJECT_A_ID, root: PROJECT_A_ROOT }, [10882]);
    // Attach a listener for the eventual rejection now, so advancing fake
    // timers to exhaustion later cannot surface it as unhandled.
    const settled = expect(pending).rejects.toThrow(/another host-service port registry operation is in progress/);

    await vi.advanceTimersByTimeAsync(1_800);
    expect(progressLines()).toEqual([]);

    await vi.advanceTimersByTimeAsync(400); // crosses the 2s mark (one retry lands at 2_000ms exactly)
    expect(progressLines()).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(progressLines()).toHaveLength(1); // still just the one line

    await vi.advanceTimersByTimeAsync(3_000); // exhausts the remaining budget (5s total)
    await settled;
    expect(fs.existsSync(lockDir())).toBe(true); // the external holder's lock is untouched
  });
});
