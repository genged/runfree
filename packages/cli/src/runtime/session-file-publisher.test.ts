import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  createSessionAdmissionEligibility,
  serializeSessionAdmissionEligibility,
  type SessionAdmissionEligibility,
} from "@runfree/runtime-contracts/session-admission";
import {
  isSessionFileEligible,
  parseSessionFileV1,
  serializeSessionFileV1,
  sessionFilePath,
  SESSION_ELIGIBILITY_PATH,
  SESSION_FILES_DIR,
  SESSION_FILE_MAX_BYTES,
  type SessionFileV1,
} from "@runfree/runtime-contracts/session-file";

import { sha256Digest } from "../strict-primitives.ts";
import { RuntimeObservationError } from "./observation-failure.ts";
import { readProxySessionFiles } from "./session-reconcile.ts";
import {
  eligibilityPublishCommand,
  executeSessionFileCommand,
  sealCommand,
  servedSetReadCommand,
  sessionFileDeleteCommand,
  sessionFileWriteCommand,
  type SessionAdmissionDockerCommand,
  type SessionAdmissionDockerExecutor,
} from "./session-file-publisher.ts";
import type { CaptureResult } from "./types.ts";

const PROXY_ID = "a".repeat(64);
const SESSION_KEY = "5".repeat(64);
const OTHER_KEY = "6".repeat(64);
const THIRD_KEY = "7".repeat(64);
const LEASE_MS = 5 * 60 * 1000;

function fileAt(aliveUntilEpochMs: number, overrides: Partial<SessionFileV1> = {}): SessionFileV1 {
  return {
    v: 1,
    projectId: "abcdef012345",
    sessionKey: SESSION_KEY,
    sessionId: "rf-20260907-abc123",
    sessionIncarnation: "1".repeat(64),
    sourceIp: "172.30.194.20",
    containerId: "c".repeat(64),
    networkId: "e".repeat(64),
    selectedAgentImageId: `sha256:${"a".repeat(64)}`,
    sessionAgentGenerationDigest: `sha256:${"b".repeat(64)}`,
    controlPlaneGenerationDigest: `sha256:${"d".repeat(64)}`,
    admissionContractEpoch: 3,
    name: "claude",
    command: "claude",
    startedAt: new Date(aliveUntilEpochMs - LEASE_MS - 10_000).toISOString(),
    nonce: "0".repeat(32),
    inspectedAt: new Date(aliveUntilEpochMs - LEASE_MS).toISOString(),
    aliveUntil: new Date(aliveUntilEpochMs).toISOString(),
    ...overrides,
  };
}

const base = fileAt(Date.now() + LEASE_MS);

function eligibilityFor(file: SessionFileV1): SessionAdmissionEligibility {
  return createSessionAdmissionEligibility({
    projectId: file.projectId,
    controlPlaneGenerationDigest: file.controlPlaneGenerationDigest,
    admissionContractEpoch: file.admissionContractEpoch,
    agentInternalNetworkId: file.networkId,
    allowedSessionAgents: [{
      selectedAgentImageId: file.selectedAgentImageId,
      sessionAgentGenerationDigest: file.sessionAgentGenerationDigest,
    }],
  });
}

function scriptOf(command: SessionAdmissionDockerCommand): string {
  const index = command.args.indexOf("-e");
  expect(index).toBeGreaterThan(-1);
  return command.args[index + 1] as string;
}

const WRITE_SCRIPT = scriptOf(sessionFileWriteCommand(PROXY_ID, base));
const DELETE_SCRIPT = scriptOf(sessionFileDeleteCommand(PROXY_ID, SESSION_KEY));
const READ_SCRIPT = scriptOf(servedSetReadCommand(PROXY_ID));

type Sandbox = Readonly<{
  root: string;
  sessionsDir: string;
  eligibilityPath: string;
  localize(script: string): string;
  names(): string[];
}>;

// The scripts run inside the proxy container against the pinned
// `/run/runfree-sessions` tree owned by uid 0. Here they run in-process
// against a tmpdir owned by the test user, so the test rewrites exactly the
// three pinned constants (the two directories and the owner uid) and proves
// the rewrite hit every one of them — the rest of the shipped script bytes are
// what runs.
function createSandbox(): Sandbox {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "session-file-publisher-"));
  const sessionsDir = path.join(root, "sessions");
  fs.mkdirSync(sessionsDir);
  return {
    root,
    sessionsDir,
    eligibilityPath: path.join(root, "eligibility.json"),
    localize(script: string): string {
      expect(script.split("const ownerUid = 0;")).toHaveLength(2);
      const localized = script
        .split("const ownerUid = 0;").join(`const ownerUid = ${process.getuid?.() ?? 0};`)
        .split(JSON.stringify(SESSION_FILES_DIR)).join(JSON.stringify(sessionsDir))
        .split(JSON.stringify(SESSION_ELIGIBILITY_PATH)).join(JSON.stringify(path.join(root, "eligibility.json")));
      expect(localized).not.toContain("/run/runfree-sessions");
      return localized;
    },
    names(): string[] {
      return fs.readdirSync(sessionsDir).sort();
    },
  };
}

function withSandbox(body: (sandbox: Sandbox) => void): void {
  const sandbox = createSandbox();
  try {
    body(sandbox);
  } finally {
    fs.chmodSync(sandbox.root, 0o700);
    fs.rmSync(sandbox.root, { recursive: true, force: true });
  }
}

function runScript(script: string, args: readonly string[], input?: string): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, ["-e", script, ...args], {
    encoding: "utf8",
    ...(input === undefined ? {} : { input }),
  });
}

function runWrite(sandbox: Sandbox, target: string, payload: string, digest?: string): SpawnSyncReturns<string> {
  return runScript(sandbox.localize(WRITE_SCRIPT), [target, digest ?? sha256Digest(payload)], payload);
}

function runDelete(sandbox: Sandbox, target: string): SpawnSyncReturns<string> {
  return runScript(sandbox.localize(DELETE_SCRIPT), [target]);
}

type ServedEntry = Readonly<{
  sessionKey?: string;
  name?: string;
  sourceIp?: string;
  aliveUntil?: string;
  nonce?: string;
  eligible?: boolean;
  wallActive?: boolean;
  malformed?: boolean;
}>;

function runRead(sandbox: Sandbox): { result: SpawnSyncReturns<string>; entries: ServedEntry[] } {
  const result = runScript(sandbox.localize(READ_SCRIPT), []);
  let entries: ServedEntry[] = [];
  if (result.status === 0) entries = JSON.parse(result.stdout) as ServedEntry[];
  return { result, entries };
}

function seed(sandbox: Sandbox, name: string, contents: string): string {
  const target = path.join(sandbox.sessionsDir, name);
  fs.writeFileSync(target, contents);
  return target;
}

function capturing(result: Partial<CaptureResult>): {
  io: SessionAdmissionDockerExecutor;
  calls: Array<{ command: string; args: string[]; options: Record<string, unknown> }>;
} {
  const calls: Array<{ command: string; args: string[]; options: Record<string, unknown> }> = [];
  return {
    calls,
    io: {
      capture: (command, args, options) => {
        calls.push({ command, args: [...args], options: (options ?? {}) as Record<string, unknown> });
        return { status: 0, stdout: "", stderr: "", ...result };
      },
    },
  };
}

describe("host session-file Docker channel", () => {
  test("builds sealed root Node argv without a shell, pinned to the session-file paths", () => {
    const eligibility = eligibilityFor(base);
    const commands = [
      sessionFileWriteCommand(PROXY_ID, base),
      sessionFileDeleteCommand(PROXY_ID, SESSION_KEY),
      eligibilityPublishCommand(PROXY_ID, eligibility),
      servedSetReadCommand(PROXY_ID),
    ];
    for (const command of commands) {
      expect(command.executable).toBe("docker");
      expect(command.args.slice(0, 5)).toEqual(["exec", "--user", "0:0", "-i", PROXY_ID]);
      expect(command.args[5]).toBe("node");
      expect(command.args[6]).toBe("-e");
      expect(command.args).not.toContain("sh");
      expect(command.args).not.toContain("-c");
      expect(Object.isFrozen(command)).toBe(true);
      expect(Object.isFrozen(command.args)).toBe(true);
    }
    expect(commands.map((command) => command.effect)).toEqual([
      "write-session-file",
      "delete-session-file",
      "publish-eligibility",
      "read-served-set",
    ]);
    expect(commands[0]?.args.slice(8)).toEqual([sessionFilePath(SESSION_KEY), sha256Digest(serializeSessionFileV1(base))]);
    expect(commands[1]?.args.slice(8)).toEqual([sessionFilePath(SESSION_KEY)]);
    expect(commands[2]?.args.slice(8)).toEqual([
      SESSION_ELIGIBILITY_PATH,
      sha256Digest(serializeSessionAdmissionEligibility(eligibility)),
    ]);
    expect(commands[3]?.args.slice(8)).toEqual([]);
  });

  test("the write and publish commands carry exactly the bytes their digest argument names", () => {
    const write = sessionFileWriteCommand(PROXY_ID, base);
    expect(write.input).toBe(serializeSessionFileV1(base));
    expect(write.args[write.args.length - 1]).toBe(sha256Digest(write.input as string));
    expect(parseSessionFileV1(write.input as string, SESSION_KEY)).toEqual(base);

    const eligibility = eligibilityFor(base);
    const publish = eligibilityPublishCommand(PROXY_ID, eligibility);
    expect(publish.input).toBe(serializeSessionAdmissionEligibility(eligibility));
    expect(publish.args[publish.args.length - 1]).toBe(sha256Digest(publish.input as string));

    expect(sessionFileDeleteCommand(PROXY_ID, SESSION_KEY).input).toBeUndefined();
    expect(servedSetReadCommand(PROXY_ID).input).toBeUndefined();
  });

  test("refuses an unusable key, an invalid file, and a short proxy id before a command exists", () => {
    expect(() => sessionFileWriteCommand(PROXY_ID, { ...base, sessionKey: `../${"5".repeat(61)}` })).toThrow();
    expect(() => sessionFileDeleteCommand(PROXY_ID, `${SESSION_KEY.slice(0, 62)}/x`)).toThrow();
    expect(() => sessionFileDeleteCommand(PROXY_ID, "eligibility")).toThrow();
    // A file the proxy's reader would reject must never reach the proxy.
    expect(() => sessionFileWriteCommand(PROXY_ID, { ...base, nonce: "zz" })).toThrow();
    expect(() => sessionFileWriteCommand(PROXY_ID, { ...base, aliveUntil: base.inspectedAt })).toThrow();
    expect(() => sessionFileWriteCommand("a".repeat(12), base)).toThrow();
    expect(() => sessionFileDeleteCommand("a".repeat(12), SESSION_KEY)).toThrow();
    expect(() => eligibilityPublishCommand("a".repeat(12), eligibilityFor(base))).toThrow();
    expect(() => servedSetReadCommand("a".repeat(12))).toThrow();
  });

  test("a non-zero capture is an observation-unavailable RuntimeObservationError, never a plain Error", () => {
    const failing = capturing({ status: 2, stderr: "unsafe session file target\n" });
    let thrown: unknown;
    try {
      executeSessionFileCommand(failing.io, sessionFileWriteCommand(PROXY_ID, base));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(RuntimeObservationError);
    const evidence = (thrown as RuntimeObservationError).evidence;
    expect(evidence.kind).toBe("observation-unavailable");
    expect(evidence.subject).toBe("proxy");
    expect(evidence.expectedIdentity).toBe(PROXY_ID);
    expect(evidence.phase).toContain("write-session-file");
    expect(evidence.observation).toContain("unsafe session file target");
  });

  test("a command missing '-i' at index 3 cannot misreport 'node' as the proxy identity", () => {
    // `pinnedExec` always places `-i` at index 3 and the exact proxy id right
    // after it at index 4; this hand-built command omits `-i` so index 4
    // lands on "node" instead, the way a bug reading that index unconditionally
    // would misreport it.
    const forged = sealCommand({
      executable: "docker",
      effect: "write-session-file",
      args: ["exec", "--user", "0:0", PROXY_ID, "node", "-e", "process.exit(1)"],
    });
    const failing = capturing({ status: 1, stderr: "boom\n" });
    let thrown: unknown;
    try {
      executeSessionFileCommand(failing.io, forged);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(RuntimeObservationError);
    const evidence = (thrown as RuntimeObservationError).evidence;
    expect(evidence.expectedIdentity).not.toBe("node");
    expect(evidence.expectedIdentity).toBe("");
  });

  test("a successful capture returns the result and carries the stdin the command sealed", () => {
    const succeeding = capturing({ status: 0, stdout: "[]\n" });
    const write = sessionFileWriteCommand(PROXY_ID, base);
    expect(executeSessionFileCommand(succeeding.io, write)).toEqual({ status: 0, stdout: "[]\n", stderr: "" });
    expect(succeeding.calls[0]?.command).toBe("docker");
    expect(succeeding.calls[0]?.args).toEqual([...write.args]);
    expect(succeeding.calls[0]?.options.input).toBe(write.input);
    expect(succeeding.calls[0]?.options.maxBuffer).toBeGreaterThanOrEqual(64 * 1024);

    const read = capturing({ status: 0, stdout: "[]\n" });
    executeSessionFileCommand(read.io, servedSetReadCommand(PROXY_ID), { timeout: 5_000 });
    expect(read.calls[0]?.options.input).toBeUndefined();
    expect(read.calls[0]?.options.timeout).toBe(5_000);
  });

  test("refuses a forged command before Docker runs", () => {
    const forged = capturing({ status: 0 });
    const command = {
      executable: "docker",
      effect: "write-session-file",
      args: ["exec", "--user", "0:0", "-i", PROXY_ID, "node", "-e", "process.exit(0)"],
    } as unknown as SessionAdmissionDockerCommand;
    expect(() => executeSessionFileCommand(forged.io, command)).toThrow(/unsealed/);
    expect(forged.calls).toHaveLength(0);
  });
});

describe("sealed session-file write script", () => {
  test("writes, fsyncs, renames, and reads back a root-owned 0644 file, leaving no temp behind", () => {
    withSandbox((sandbox) => {
      const payload = serializeSessionFileV1(base);
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      const result = runWrite(sandbox, target, payload);
      expect(result.status).toBe(0);
      expect(fs.readFileSync(target, "utf8")).toBe(payload);
      expect(fs.statSync(target).mode & 0o777).toBe(0o644);
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);

      const renewed = serializeSessionFileV1({ ...base, nonce: "f".repeat(32) });
      expect(runWrite(sandbox, target, renewed).status).toBe(0);
      expect(fs.readFileSync(target, "utf8")).toBe(renewed);
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);
    });
  });

  test("publishes the eligibility file next to the sessions directory", () => {
    withSandbox((sandbox) => {
      const payload = serializeSessionAdmissionEligibility(eligibilityFor(base));
      const result = runWrite(sandbox, sandbox.eligibilityPath, payload);
      expect(result.status).toBe(0);
      expect(fs.readFileSync(sandbox.eligibilityPath, "utf8")).toBe(payload);
      expect(fs.readdirSync(sandbox.root).sort()).toEqual(["eligibility.json", "sessions"]);
    });
  });

  test("refuses an eligibility payload over 64 KiB and leaves no temp file behind", () => {
    withSandbox((sandbox) => {
      const payload = " ".repeat(64 * 1024 + 1);
      const result = runWrite(sandbox, sandbox.eligibilityPath, payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr.trim()).toBe("session file payload too large");
      expect(fs.existsSync(sandbox.eligibilityPath)).toBe(false);
      expect(fs.readdirSync(sandbox.root).sort()).toEqual(["sessions"]);
    });
  });

  test("reports non-zero on a post-rename read-back fault", () => {
    withSandbox((sandbox) => {
      const localized = sandbox.localize(WRITE_SCRIPT);
      const readBack = 'fs.readFileSync(finalPath, "utf8")';
      expect(localized.split(readBack)).toHaveLength(2);
      const faulted = localized.split(readBack)
        .join('(function () { throw new Error("injected read-back failure"); })()');
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      const payload = serializeSessionFileV1(base);
      const result = spawnSync(process.execPath, ["-e", faulted, target, sha256Digest(payload)], {
        encoding: "utf8",
        input: payload,
      });
      expect(result.status).not.toBe(0);
      expect(result.stderr.trim()).toBe("injected read-back failure");
      // The rename already landed the real payload; only the post-rename
      // check faulted, so the file on disk is unaffected.
      expect(fs.readFileSync(target, "utf8")).toBe(payload);
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);
    });
  });

  test("refuses every path outside the two pinned destinations without writing anything", () => {
    const payload = serializeSessionFileV1(base);
    const cases: Array<{ target: (sandbox: Sandbox) => string; reason: string }> = [
      { target: (sandbox) => path.join(sandbox.sessionsDir, "session.json"), reason: "invalid session file name" },
      { target: (sandbox) => path.join(sandbox.sessionsDir, `${"ABCDEF0123456789".repeat(4)}.json`), reason: "invalid session file name" },
      { target: (sandbox) => path.join(sandbox.sessionsDir, `${SESSION_KEY}.json.tmp`), reason: "invalid session file name" },
      { target: (sandbox) => path.join(sandbox.sessionsDir, "nested", `${SESSION_KEY}.json`), reason: "invalid session file path" },
      { target: (sandbox) => `${sandbox.sessionsDir}/../${SESSION_KEY}.json`, reason: "invalid session file path" },
      { target: (sandbox) => `${sandbox.sessionsDir}/./${SESSION_KEY}.json`, reason: "invalid session file path" },
      { target: (sandbox) => path.join(sandbox.root, `${SESSION_KEY}.json`), reason: "invalid session file path" },
      { target: (sandbox) => path.join(sandbox.root, "other.json"), reason: "invalid session file path" },
      { target: () => "/tmp/session-file-publisher-escape.json", reason: "invalid session file path" },
    ];
    for (const scenario of cases) {
      withSandbox((sandbox) => {
        const resolved = scenario.target(sandbox);
        const result = runWrite(sandbox, resolved, payload);
        expect([resolved, result.status === 0, result.stderr.trim()]).toEqual([resolved, false, scenario.reason]);
        expect(sandbox.names()).toEqual([]);
        expect(fs.readdirSync(sandbox.root).sort()).toEqual(["sessions"]);
        expect(fs.existsSync(path.resolve(resolved))).toBe(false);
      });
    }
  });

  test("refuses a payload that is oversize, undigested, unparseable, or names another session", () => {
    const valid = serializeSessionFileV1(base);
    const cases: Array<{ label: string; payload: string; digest?: string; reason: string }> = [
      { label: "oversize", payload: " ".repeat(SESSION_FILE_MAX_BYTES + 1), reason: "session file payload too large" },
      { label: "digest of other bytes", payload: valid, digest: sha256Digest(`${valid} `), reason: "session file input digest mismatch" },
      { label: "unshaped digest", payload: valid, digest: "sha256:not-a-digest", reason: "session file input digest mismatch" },
      { label: "not json", payload: "{not json}\n", reason: "malformed session file input" },
      { label: "array", payload: "[]\n", reason: "session file input is not an object" },
      { label: "null", payload: "null\n", reason: "session file input is not an object" },
      { label: "string", payload: '"session"\n', reason: "session file input is not an object" },
      {
        label: "another session",
        payload: serializeSessionFileV1({ ...base, sessionKey: OTHER_KEY }),
        reason: "session file input names another session",
      },
      { label: "no key", payload: '{"sessionKey":null}\n', reason: "session file input names another session" },
    ];
    for (const scenario of cases) {
      withSandbox((sandbox) => {
        const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
        const result = runWrite(sandbox, target, scenario.payload, scenario.digest);
        expect([scenario.label, result.status === 0, result.stderr.trim()]).toEqual([scenario.label, false, scenario.reason]);
        expect(sandbox.names()).toEqual([]);
      });
    }
  });

  test("refuses an existing target that is a symlink, a directory, or hard-linked, leaving it untouched", () => {
    const payload = serializeSessionFileV1(base);

    withSandbox((sandbox) => {
      const outside = path.join(sandbox.root, "outside.json");
      fs.writeFileSync(outside, "outside\n");
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      fs.symlinkSync(outside, target);
      const result = runWrite(sandbox, target, payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr.trim()).toBe("unsafe session file target");
      expect(fs.lstatSync(target).isSymbolicLink()).toBe(true);
      expect(fs.readFileSync(outside, "utf8")).toBe("outside\n");
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);
    });

    withSandbox((sandbox) => {
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      fs.mkdirSync(target);
      const result = runWrite(sandbox, target, payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr.trim()).toBe("unsafe session file target");
      expect(fs.lstatSync(target).isDirectory()).toBe(true);
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);
    });

    withSandbox((sandbox) => {
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      const alias = path.join(sandbox.root, "alias.json");
      fs.writeFileSync(target, "linked\n");
      fs.linkSync(target, alias);
      const result = runWrite(sandbox, target, payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr.trim()).toBe("unsafe session file target");
      expect(fs.readFileSync(target, "utf8")).toBe("linked\n");
      expect(fs.readFileSync(alias, "utf8")).toBe("linked\n");
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);
    });
  });

  test("refuses an unsafe parent directory before opening anything", () => {
    const payload = serializeSessionFileV1(base);

    withSandbox((sandbox) => {
      fs.chmodSync(sandbox.sessionsDir, 0o777);
      const result = runWrite(sandbox, path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`), payload);
      expect(result.stderr.trim()).toBe("unsafe session file directory");
      expect(sandbox.names()).toEqual([]);
    });

    withSandbox((sandbox) => {
      const elsewhere = path.join(sandbox.root, "elsewhere");
      fs.mkdirSync(elsewhere);
      fs.rmdirSync(sandbox.sessionsDir);
      fs.symlinkSync(elsewhere, sandbox.sessionsDir);
      const result = runWrite(sandbox, path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`), payload);
      expect(result.stderr.trim()).toBe("unsafe session file directory");
      expect(fs.readdirSync(elsewhere)).toEqual([]);
    });
  });

  test("removes its temp file when the rename fails (injected fault after the temp exists)", () => {
    withSandbox((sandbox) => {
      const localized = sandbox.localize(WRITE_SCRIPT);
      const rename = "fs.renameSync(temporaryPath, finalPath);";
      expect(localized.split(rename)).toHaveLength(2);
      const faulted = localized.split(rename).join('throw new Error("injected rename failure");');
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      fs.writeFileSync(target, "existing\n");
      const payload = serializeSessionFileV1(base);
      const result = spawnSync(process.execPath, ["-e", faulted, target, sha256Digest(payload)], {
        encoding: "utf8",
        input: payload,
      });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("injected rename failure");
      expect(fs.readFileSync(target, "utf8")).toBe("existing\n");
      expect(sandbox.names()).toEqual([`${SESSION_KEY}.json`]);
    });
  });
});

describe("sealed session-file delete script", () => {
  test("unlinks a regular session file and is idempotent when it is already gone", () => {
    withSandbox((sandbox) => {
      const target = seed(sandbox, `${SESSION_KEY}.json`, serializeSessionFileV1(base));
      expect(runDelete(sandbox, target).status).toBe(0);
      expect(sandbox.names()).toEqual([]);
      expect(runDelete(sandbox, target).status).toBe(0);

      fs.rmdirSync(sandbox.sessionsDir);
      expect(runDelete(sandbox, target).status).toBe(0);
      fs.mkdirSync(sandbox.sessionsDir);
    });
  });

  test("refuses to unlink a symlink, a hard-linked file, a directory, or anything outside the sessions directory", () => {
    withSandbox((sandbox) => {
      const outside = path.join(sandbox.root, "outside.json");
      fs.writeFileSync(outside, "outside\n");
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      fs.symlinkSync(outside, target);
      expect(runDelete(sandbox, target).stderr.trim()).toBe("unsafe session file");
      expect(fs.lstatSync(target).isSymbolicLink()).toBe(true);
      expect(fs.existsSync(outside)).toBe(true);
    });

    withSandbox((sandbox) => {
      const target = seed(sandbox, `${SESSION_KEY}.json`, "linked\n");
      const alias = path.join(sandbox.root, "alias.json");
      fs.linkSync(target, alias);
      expect(runDelete(sandbox, target).stderr.trim()).toBe("unsafe session file");
      expect(fs.existsSync(target)).toBe(true);
      expect(fs.existsSync(alias)).toBe(true);
    });

    withSandbox((sandbox) => {
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      fs.mkdirSync(target);
      expect(runDelete(sandbox, target).stderr.trim()).toBe("unsafe session file");
      expect(fs.lstatSync(target).isDirectory()).toBe(true);
    });

    withSandbox((sandbox) => {
      const outside = path.join(sandbox.root, `${SESSION_KEY}.json`);
      fs.writeFileSync(outside, "outside\n");
      expect(runDelete(sandbox, outside).stderr.trim()).toBe("invalid session file path");
      expect(fs.existsSync(outside)).toBe(true);

      const misnamed = seed(sandbox, "session.json", "misnamed\n");
      expect(runDelete(sandbox, misnamed).stderr.trim()).toBe("invalid session file name");
      expect(fs.existsSync(misnamed)).toBe(true);

      const traversal = `${sandbox.sessionsDir}/../${SESSION_KEY}.json`;
      expect(runDelete(sandbox, traversal).stderr.trim()).toBe("invalid session file path");
      expect(fs.existsSync(outside)).toBe(true);
    });
  });

  test("refuses to unlink through an unsafe sessions directory", () => {
    withSandbox((sandbox) => {
      const target = seed(sandbox, `${SESSION_KEY}.json`, "kept\n");
      fs.chmodSync(sandbox.sessionsDir, 0o777);
      expect(runDelete(sandbox, target).stderr.trim()).toBe("unsafe session file directory");
      fs.chmodSync(sandbox.sessionsDir, 0o755);
      expect(fs.existsSync(target)).toBe(true);
    });

    withSandbox((sandbox) => {
      const elsewhere = path.join(sandbox.root, "elsewhere");
      fs.mkdirSync(elsewhere);
      const decoy = path.join(elsewhere, `${SESSION_KEY}.json`);
      fs.writeFileSync(decoy, "decoy\n");
      fs.rmdirSync(sandbox.sessionsDir);
      fs.symlinkSync(elsewhere, sandbox.sessionsDir);
      const target = path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`);
      expect(runDelete(sandbox, target).stderr.trim()).toBe("unsafe session file directory");
      expect(fs.existsSync(decoy)).toBe(true);
    });
  });
});

describe("sealed served-set read script", () => {
  test("reports an empty array for an empty and for an absent sessions directory", () => {
    withSandbox((sandbox) => {
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibilityFor(base)));
      const empty = runRead(sandbox);
      expect(empty.result.status).toBe(0);
      expect(empty.entries).toEqual([]);
      fs.rmdirSync(sandbox.sessionsDir);
      const absent = runRead(sandbox);
      expect(absent.result.status).toBe(0);
      expect(absent.entries).toEqual([]);
      fs.mkdirSync(sandbox.sessionsDir);
    });
  });

  test("emits identity, eligibility, and wall-clock liveness per well-formed file", () => {
    withSandbox((sandbox) => {
      const active = fileAt(Date.now() + LEASE_MS);
      const expired = fileAt(Date.now() - 1_000, { sessionKey: OTHER_KEY, sourceIp: "172.30.194.21", nonce: "1".repeat(32) });
      const eligibility = eligibilityFor(active);
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibility));
      seed(sandbox, `${SESSION_KEY}.json`, serializeSessionFileV1(active));
      seed(sandbox, `${OTHER_KEY}.json`, serializeSessionFileV1(expired));

      const { result, entries } = runRead(sandbox);
      expect(result.status).toBe(0);
      expect(entries).toEqual([
        {
          sessionKey: SESSION_KEY,
          sourceIp: active.sourceIp,
          aliveUntil: active.aliveUntil,
          nonce: active.nonce,
          eligible: true,
          wallActive: true,
        },
        {
          sessionKey: OTHER_KEY,
          sourceIp: expired.sourceIp,
          aliveUntil: expired.aliveUntil,
          nonce: expired.nonce,
          eligible: true,
          wallActive: false,
        },
      ]);
      expect(isSessionFileEligible(active, eligibility)).toBe(true);
      expect(isSessionFileEligible(expired, eligibility)).toBe(true);
    });
  });

  test("agrees with isSessionFileEligible on every eligibility dimension", () => {
    const dimensions: Array<Partial<SessionFileV1>> = [
      {},
      { projectId: "otherproject" },
      { controlPlaneGenerationDigest: `sha256:${"9".repeat(64)}` },
      { admissionContractEpoch: 4 },
      { networkId: "f".repeat(64) },
      { sessionAgentGenerationDigest: `sha256:${"8".repeat(64)}` },
      { selectedAgentImageId: `sha256:${"7".repeat(64)}` },
    ];
    withSandbox((sandbox) => {
      const eligibility = eligibilityFor(base);
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibility));
      const expected: boolean[] = [];
      for (const [index, overrides] of dimensions.entries()) {
        const key = `${index}`.repeat(64).slice(0, 64);
        const file = fileAt(Date.now() + LEASE_MS, { ...overrides, sessionKey: key });
        seed(sandbox, `${key}.json`, serializeSessionFileV1(file));
        expected.push(isSessionFileEligible(file, eligibility));
      }
      const { entries } = runRead(sandbox);
      expect(entries).toHaveLength(dimensions.length);
      const byKey = new Map(entries.map((entry) => [entry.sessionKey, entry.eligible]));
      for (const [index] of dimensions.entries()) {
        const key = `${index}`.repeat(64).slice(0, 64);
        expect(byKey.get(key)).toBe(expected[index]);
      }
      expect(expected).toEqual([true, false, false, false, false, false, false]);
    });
  });

  test("reports eligible false when the eligibility file is missing or unparseable", () => {
    withSandbox((sandbox) => {
      seed(sandbox, `${SESSION_KEY}.json`, serializeSessionFileV1(base));
      expect(runRead(sandbox).entries).toEqual([expect.objectContaining({ sessionKey: SESSION_KEY, eligible: false })]);

      fs.writeFileSync(sandbox.eligibilityPath, "{not json}\n");
      expect(runRead(sandbox).entries).toEqual([expect.objectContaining({ sessionKey: SESSION_KEY, eligible: false })]);

      fs.writeFileSync(sandbox.eligibilityPath, JSON.stringify({ v: 2, projectId: base.projectId }));
      expect(runRead(sandbox).entries).toEqual([expect.objectContaining({ sessionKey: SESSION_KEY, eligible: false })]);
    });
  });

  test("marks malformed and mis-named files without claiming their fields", () => {
    withSandbox((sandbox) => {
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibilityFor(base)));
      const misnamed = serializeSessionFileV1({ ...base, sessionKey: OTHER_KEY });
      seed(sandbox, `${SESSION_KEY}.json`, misnamed);
      seed(sandbox, `${OTHER_KEY}.json`, "{not json}\n");
      seed(sandbox, "session.json", serializeSessionFileV1(base));
      seed(sandbox, ".runfree-1234-abcdef01.tmp", serializeSessionFileV1(base));
      seed(sandbox, "notes.txt", "ignored\n");

      const { entries } = runRead(sandbox);
      expect(entries).toEqual([
        { sessionKey: SESSION_KEY, name: `${SESSION_KEY}.json`, malformed: true },
        { sessionKey: OTHER_KEY, name: `${OTHER_KEY}.json`, malformed: true },
        { name: "session.json", malformed: true },
      ]);
      // The name/key mismatch is the contract's verdict too.
      expect(parseSessionFileV1(misnamed, SESSION_KEY)).toBeUndefined();
    });
  });

  test("agrees with parseSessionFileV1 on the field shapes it emits", () => {
    const valid = serializeSessionFileV1(base);
    const shapes: Array<{ label: string; raw: string }> = [
      { label: "valid", raw: valid },
      { label: "empty", raw: "" },
      { label: "array", raw: "[]\n" },
      { label: "bad version", raw: valid.replace('"v":1', '"v":2') },
      { label: "bad nonce", raw: serializeSessionFileV1({ ...base, nonce: "zz" }) },
      { label: "bad sourceIp", raw: serializeSessionFileV1({ ...base, sourceIp: "172.030.194.20" }) },
      { label: "bad aliveUntil", raw: serializeSessionFileV1({ ...base, aliveUntil: "not a date" }) },
      { label: "bad networkId", raw: serializeSessionFileV1({ ...base, networkId: "e".repeat(63) }) },
      { label: "bad image digest", raw: serializeSessionFileV1({ ...base, selectedAgentImageId: "sha256:zz" }) },
      { label: "bad epoch", raw: serializeSessionFileV1({ ...base, admissionContractEpoch: 0 }) },
      { label: "oversize", raw: " ".repeat(SESSION_FILE_MAX_BYTES + 1) },
    ];
    // One file per shape, each renamed to its own key so the name/key rule is
    // not what decides the verdict.
    const cases = shapes.map((shape, index) => {
      const key = index.toString(16).repeat(64).slice(0, 64);
      return { ...shape, key, raw: shape.raw.split(base.sessionKey).join(key) };
    });
    withSandbox((sandbox) => {
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibilityFor(base)));
      for (const scenario of cases) seed(sandbox, `${scenario.key}.json`, scenario.raw);
      const { entries } = runRead(sandbox);
      const byKey = new Map(entries.map((entry) => [entry.sessionKey, entry]));
      const script = cases.map((scenario) => `${scenario.label}:${byKey.get(scenario.key)?.malformed === true}`);
      const contract = cases.map((scenario) => `${scenario.label}:${parseSessionFileV1(scenario.raw, scenario.key) === undefined}`);
      expect(script).toEqual(contract);
      expect(contract[0]).toBe("valid:false");
      expect(contract.slice(1).every((entry) => entry.endsWith(":true"))).toBe(true);
    });
  });

  // The seam every reconcile pass, GC gate, destroy teardown, and `runfree
  // sessions` report reads the proxy through: the sealed script's stdout on one
  // side, `readProxySessionFiles`'s host shapes on the other. Both halves ship
  // in different modules and neither test covered the join, so a field renamed
  // on one side would have been caught by nothing. Here the real script runs
  // against the tmpdir and its exact bytes are handed to the real host parser.
  test("the host parser reads exactly what the sealed script emits", () => {
    withSandbox((sandbox) => {
      const active = fileAt(Date.now() + LEASE_MS);
      const stale = fileAt(Date.now() - 1_000, {
        sessionKey: THIRD_KEY,
        sourceIp: "172.30.194.22",
        nonce: "2".repeat(32),
        controlPlaneGenerationDigest: `sha256:${"c".repeat(64)}`,
      });
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibilityFor(active)));
      seed(sandbox, `${SESSION_KEY}.json`, serializeSessionFileV1(active));
      seed(sandbox, `${OTHER_KEY}.json`, "{not json}\n");
      seed(sandbox, `${THIRD_KEY}.json`, serializeSessionFileV1(stale));
      seed(sandbox, "session.json", serializeSessionFileV1(active));

      const read = runRead(sandbox);
      expect(read.result.status).toBe(0);
      const { io, calls } = capturing({ stdout: read.result.stdout });
      const files = readProxySessionFiles({ io, proxyId: PROXY_ID });

      // The parser is fed through the one pinned served-set read argv, not a
      // hand-rolled command that happens to produce similar text.
      expect(calls).toHaveLength(1);
      expect(calls[0]?.args).toEqual([...servedSetReadCommand(PROXY_ID).args]);
      expect(files).toEqual([
        {
          sessionKey: SESSION_KEY,
          name: `${SESSION_KEY}.json`,
          sourceIp: active.sourceIp,
          malformed: false,
          aliveUntil: active.aliveUntil,
          eligible: true,
          wallActive: true,
        },
        { sessionKey: OTHER_KEY, name: `${OTHER_KEY}.json`, malformed: true },
        {
          sessionKey: THIRD_KEY,
          name: `${THIRD_KEY}.json`,
          sourceIp: stale.sourceIp,
          malformed: false,
          aliveUntil: stale.aliveUntil,
          eligible: false,
          wallActive: false,
        },
        // A `.json` whose stem is not a session key: no key to delete by, so
        // the host shape carries the name alone.
        { name: "session.json", malformed: true },
      ]);

      // The script emits a nonce the host shape deliberately does not carry:
      // renewal identity is the proxy's business, and a host consumer that
      // started reading it would be reading an unpinned field.
      expect(read.entries.map((entry) => entry.nonce))
        .toEqual([active.nonce, undefined, stale.nonce, undefined]);
      for (const file of files) expect(file).not.toHaveProperty("nonce");
    });
  });

  test("never follows a symlinked entry and refuses an unsafe sessions directory", () => {
    withSandbox((sandbox) => {
      fs.writeFileSync(sandbox.eligibilityPath, serializeSessionAdmissionEligibility(eligibilityFor(base)));
      const outside = path.join(sandbox.root, "outside.json");
      fs.writeFileSync(outside, serializeSessionFileV1(base));
      fs.symlinkSync(outside, path.join(sandbox.sessionsDir, `${SESSION_KEY}.json`));
      expect(runRead(sandbox).entries).toEqual([
        { sessionKey: SESSION_KEY, name: `${SESSION_KEY}.json`, malformed: true },
      ]);

      fs.chmodSync(sandbox.sessionsDir, 0o777);
      expect(runRead(sandbox).result.status).not.toBe(0);
      fs.chmodSync(sandbox.sessionsDir, 0o755);
    });
  });
});

describe("session-file command sealing stays private", () => {
  test("only the publisher references sealCommand", () => {
    const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const entryPath = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(entryPath);
        else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.includes(".test.")) files.push(entryPath);
      }
    };
    walk(sourceRoot);
    const referencing = files
      .filter((file) => /\bsealCommand\b/.test(fs.readFileSync(file, "utf8")))
      .map((file) => path.relative(sourceRoot, file))
      .sort();
    expect(referencing).toEqual(["runtime/session-file-publisher.ts"]);
  });
});
