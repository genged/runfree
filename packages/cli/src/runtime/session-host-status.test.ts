import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import {
  readSessionHostStatus,
  removeSessionHostStatus,
  sessionHostStatusPath,
  writeSessionHostStatus,
  type SessionHostStatusV1,
} from "./session-host-status.ts";

const SESSION_ID = "rf-20260907-abc123";

const roots: string[] = [];

function stateRoot(): string {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-session-host-status-"));
  roots.push(value);
  return value;
}

afterEach(() => {
  for (const directory of roots.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

function status(overrides: Partial<SessionHostStatusV1> = {}): SessionHostStatusV1 {
  return {
    v: 1,
    sessionId: SESSION_ID,
    lastHeartbeatAt: "2026-09-07T12:00:00.000Z",
    aliveUntil: "2026-09-07T12:01:00.000Z",
    served: "served",
    ...overrides,
  };
}

describe("session host status stamp", () => {
  test("round-trips a stamp at the per-session state path and removes it", () => {
    const stateDir = stateRoot();
    const file = sessionHostStatusPath(stateDir, SESSION_ID);
    expect(file).toBe(path.join(stateDir, "runtime", "v2", "session-status", `${SESSION_ID}.json`));
    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();

    writeSessionHostStatus(stateDir, status());
    expect(readSessionHostStatus(stateDir, SESSION_ID)).toEqual(status());
    const stat = fs.lstatSync(file);
    expect(stat.isFile()).toBe(true);
    expect(stat.mode & 0o777).toBe(0o600);

    // The optional terminal marker is carried, and its absence is not invented.
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).not.toHaveProperty("terminal");
    writeSessionHostStatus(stateDir, status({ served: "retrying", terminal: "revoking" }));
    expect(readSessionHostStatus(stateDir, SESSION_ID))
      .toEqual(status({ served: "retrying", terminal: "revoking" }));

    removeSessionHostStatus(stateDir, SESSION_ID);
    expect(fs.existsSync(file)).toBe(false);
    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
    // Removal is idempotent: a stamp that a crash already cleared must not
    // throw on the next teardown.
    expect(() => removeSessionHostStatus(stateDir, SESSION_ID)).not.toThrow();
  });

  test("refuses a symlinked status path on write and reads it as absent", () => {
    const stateDir = stateRoot();
    const outside = path.join(stateRoot(), "outside.json");
    fs.writeFileSync(outside, "untouched\n");
    const file = sessionHostStatusPath(stateDir, SESSION_ID);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.symlinkSync(outside, file);

    expect(() => writeSessionHostStatus(stateDir, status())).toThrow();
    expect(fs.readFileSync(outside, "utf8")).toBe("untouched\n");
    expect(fs.lstatSync(file).isSymbolicLink()).toBe(true);
    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
  });

  test("refuses a symlinked status directory on write and reads it as absent", () => {
    const stateDir = stateRoot();
    const elsewhere = stateRoot();
    const statusDir = path.join(stateDir, "runtime", "v2", "session-status");
    fs.mkdirSync(path.dirname(statusDir), { recursive: true, mode: 0o700 });
    fs.symlinkSync(elsewhere, statusDir);
    fs.writeFileSync(path.join(elsewhere, `${SESSION_ID}.json`), `${JSON.stringify(status())}\n`);

    expect(() => writeSessionHostStatus(stateDir, status())).toThrow();
    expect(fs.readdirSync(elsewhere)).toEqual([`${SESSION_ID}.json`]);
    // The planted stamp is inside a directory this host did not create; it is
    // never adopted as this project's state.
    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
  });

  test("a symlinked state-dir root reads as absent (the symlink is planted at the root itself, not two levels down)", () => {
    // A valid, well-formed stamp really is sitting where `stateDir` would
    // resolve it — proving that only the root's own symlink status (not
    // anything about the stamp) is why this reads as absent.
    const elsewhere = stateRoot();
    const statusDir = path.join(elsewhere, "runtime", "v2", "session-status");
    fs.mkdirSync(statusDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(statusDir, `${SESSION_ID}.json`), `${JSON.stringify(status())}\n`);

    const parent = stateRoot();
    const stateDir = path.join(parent, "state");
    fs.symlinkSync(elsewhere, stateDir);
    expect(fs.lstatSync(stateDir).isSymbolicLink()).toBe(true);

    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
  });

  test("a state-dir root that is a regular file, not a directory, reads as absent", () => {
    const parent = stateRoot();
    const stateDir = path.join(parent, "state");
    fs.writeFileSync(stateDir, "not a directory\n");

    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
  });

  test("rejects a session id that is not an exact session id", () => {
    const stateDir = stateRoot();
    for (const sessionId of ["../escape", "rf-2026", "", "rf-20260907-ABC123/../x"]) {
      expect(() => sessionHostStatusPath(stateDir, sessionId)).toThrow(/invalid session id/);
      expect(() => writeSessionHostStatus(stateDir, status({ sessionId }))).toThrow();
      expect(readSessionHostStatus(stateDir, sessionId)).toBeUndefined();
    }
  });

  test("refuses to write a stamp that could not be read back", () => {
    const stateDir = stateRoot();
    const file = sessionHostStatusPath(stateDir, SESSION_ID);
    for (const invalid of [
      status({ v: 2 as unknown as 1 }),
      status({ served: "sometimes" as unknown as "served" }),
      status({ aliveUntil: "2026-09-07 12:01:00" }),
      status({ lastHeartbeatAt: "not-a-timestamp" }),
      status({ terminal: "done" as unknown as "revoking" }),
      { ...status(), extra: "field" } as unknown as SessionHostStatusV1,
    ]) {
      expect(() => writeSessionHostStatus(stateDir, invalid)).toThrow();
      expect(fs.existsSync(file)).toBe(false);
    }
  });

  test("reads an unparseable, mistyped, or over-size stamp as absent without throwing", () => {
    const stateDir = stateRoot();
    const file = sessionHostStatusPath(stateDir, SESSION_ID);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });

    const cases: string[] = [
      "not json",
      "[]",
      "null",
      JSON.stringify({ ...status(), extra: "field" }),
      JSON.stringify({ ...status(), v: 2 }),
      JSON.stringify({ ...status(), served: "sometimes" }),
      JSON.stringify({ ...status(), terminal: "done" }),
      JSON.stringify({ ...status(), aliveUntil: "2026-09-07 12:01:00" }),
      JSON.stringify({ ...status(), lastHeartbeatAt: 1_757_246_400_000 }),
      // A stamp naming another session is not this session's evidence.
      JSON.stringify({ ...status(), sessionId: "rf-20260907-zzz999" }),
      // Bounded read: an over-size file is refused rather than parsed.
      `${JSON.stringify({ ...status(), sessionId: `${SESSION_ID}${"0".repeat(64 * 1024)}` })}`,
    ];
    for (const contents of cases) {
      fs.writeFileSync(file, contents);
      expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
    }

    // A missing key is missing evidence, not a defaulted stamp.
    for (const key of ["v", "sessionId", "lastHeartbeatAt", "aliveUntil", "served"] as const) {
      const { [key]: _dropped, ...partial } = status();
      fs.writeFileSync(file, JSON.stringify(partial));
      expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
    }

    // The directory being replaced by a file is not a state this host wrote.
    fs.rmSync(file);
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
    fs.writeFileSync(path.dirname(file), "");
    expect(readSessionHostStatus(stateDir, SESSION_ID)).toBeUndefined();
  });
});
