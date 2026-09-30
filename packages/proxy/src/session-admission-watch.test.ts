// Launch plan Task 7 (cadence change): the session-admission consumers
// rescan on inotify events. These cases pin what the watcher may and may not
// do; it never decides admission, only when the existing reconcile runs.

import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  createSessionAdmissionWatch,
  SESSION_ADMISSION_WATCH_ENV,
  sessionAdmissionWatchEnabled,
  sessionAdmissionWatchTargets,
  type SessionAdmissionWatchFunction,
} from "./session-admission-watch.ts";

type FakeWatcher = EventEmitter & {
  dir: string;
  closed: boolean;
  listener: (eventType: string, filename: string | null) => void;
  close(): void;
};

function fakeWatchFunction(options: { failWith?: (dir: string) => Error | undefined } = {}) {
  const watchers: FakeWatcher[] = [];
  const watch: SessionAdmissionWatchFunction = (dir, listener) => {
    const failure = options.failWith?.(dir);
    if (failure) throw failure;
    const watcher = Object.assign(new EventEmitter(), {
      dir,
      closed: false,
      listener,
      close() {
        watcher.closed = true;
      },
    }) as FakeWatcher;
    watchers.push(watcher);
    return watcher;
  };
  return { watch, watchers, live: () => watchers.filter((watcher) => !watcher.closed) };
}

const ROOT = "/run/runfree-sessions";
const targets = sessionAdmissionWatchTargets(ROOT);

function identities(initial: Record<string, string | undefined>) {
  const table = { ...initial };
  return { table, identity: (dir: string) => table[dir] };
}

const allPresent = () => identities(Object.fromEntries(targets.map((target, index) => [target.dir, `1:${index + 10}`])));

describe("session admission watch targets", () => {
  test("watches the inputs, never a consumer's own acknowledgement directory", () => {
    expect(targets.map((target) => target.dir)).toEqual([
      ROOT,
      `${ROOT}/sessions`,
      `${ROOT}/ip-reuse/requests`,
    ]);
    for (const dir of ["firewall", "request-proxy"]) {
      expect(targets.some((target) => target.dir.endsWith(`/ip-reuse/${dir}`))).toBe(false);
    }
  });

  test("a temp name never schedules a reconcile; the renamed-in name and a deletion do", () => {
    const [root, sessions, requests] = targets;
    // The host's atomic write creates `.runfree-<pid>-<rand>.tmp` (session
    // files, eligibility) or `<ip>.json.<hex>.tmp` (IP assignments) first.
    expect(sessions.relevant(".runfree-12-abcdef0123456789.tmp")).toBe(false);
    expect(requests.relevant("172.30.194.20.json.0123456789abcdef.tmp")).toBe(false);
    expect(root.relevant(".runfree-12-abcdef0123456789.tmp")).toBe(false);
    expect(sessions.relevant(`${"a".repeat(64)}.json`)).toBe(true);
    expect(requests.relevant("172.30.194.20.json")).toBe(true);
    expect(root.relevant("eligibility.json")).toBe(true);
    // Only eligibility lives at the root; the subdirectories have their own
    // watchers.
    expect(root.relevant("sessions")).toBe(false);
    // No name (an overflowed or unnamed event) is always relevant.
    for (const target of targets) expect(target.relevant(null)).toBe(true);
  });

  test("is on unless the host-controlled test switch says off", () => {
    expect(sessionAdmissionWatchEnabled({})).toBe(true);
    expect(sessionAdmissionWatchEnabled({ [SESSION_ADMISSION_WATCH_ENV]: "on" })).toBe(true);
    expect(sessionAdmissionWatchEnabled({ [SESSION_ADMISSION_WATCH_ENV]: "off" })).toBe(false);
  });
});

describe("session admission watch", () => {
  test("an input event schedules a reconcile; a temp-file event does not", () => {
    const fake = fakeWatchFunction();
    const onChange = vi.fn();
    const watch = createSessionAdmissionWatch({ targets, onChange, watch: fake.watch, identity: allPresent().identity, log: () => {} });
    watch.rearm();
    expect(fake.live()).toHaveLength(3);

    const sessions = fake.live().find((watcher) => watcher.dir.endsWith("/sessions"));
    sessions?.listener("rename", ".runfree-1-0011223344556677.tmp");
    expect(onChange).not.toHaveBeenCalled();
    sessions?.listener("rename", `${"b".repeat(64)}.json`);
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  test("re-arming an unchanged directory keeps its one watcher", () => {
    const fake = fakeWatchFunction();
    const watch = createSessionAdmissionWatch({ targets, onChange: () => {}, watch: fake.watch, identity: allPresent().identity, log: () => {} });
    watch.rearm();
    watch.rearm();
    watch.rearm();
    expect(fake.watchers).toHaveLength(3);
    expect(watch.armedCount()).toBe(3);
  });

  test("a directory that was replaced is re-armed on the new directory (I5)", () => {
    const fake = fakeWatchFunction();
    const ids = allPresent();
    const watch = createSessionAdmissionWatch({ targets, onChange: () => {}, watch: fake.watch, identity: ids.identity, log: () => {} });
    watch.rearm();
    const first = fake.live().find((watcher) => watcher.dir.endsWith("/sessions"));
    ids.table[`${ROOT}/sessions`] = "1:999";
    watch.rearm();
    expect(first?.closed).toBe(true);
    expect(fake.live().filter((watcher) => watcher.dir.endsWith("/sessions"))).toHaveLength(1);
  });

  test("a failed watcher is closed, logged once, and re-armed by the next backstop tick (I5)", () => {
    const fake = fakeWatchFunction();
    const logs: string[] = [];
    const watch = createSessionAdmissionWatch({ targets, onChange: () => {}, watch: fake.watch, identity: allPresent().identity, log: (line) => logs.push(line) });
    watch.rearm();
    const sessions = fake.live().find((watcher) => watcher.dir.endsWith("/sessions"));
    sessions?.emit("error", new Error("inotify queue gone"));
    sessions?.emit("error", new Error("inotify queue gone"));
    expect(sessions?.closed).toBe(true);
    expect(watch.armedCount()).toBe(2);
    expect(logs.filter((line) => line.includes("inotify queue gone"))).toHaveLength(1);

    watch.rearm();
    expect(watch.armedCount()).toBe(3);
  });

  test.each([
    ["ENOSPC (inotify watch limit)", "ENOSPC"],
    ["EMFILE (inotify instance limit)", "EMFILE"],
  ])("arming that fails with %s leaves the backstop in charge and retries on each tick (I5)", (_label, code) => {
    let failing = true;
    const fake = fakeWatchFunction({
      failWith: () => (failing ? Object.assign(new Error(`${code}: limit reached`), { code }) : undefined),
    });
    const logs: string[] = [];
    const watch = createSessionAdmissionWatch({ targets, onChange: () => {}, watch: fake.watch, identity: allPresent().identity, log: (line) => logs.push(line) });
    expect(() => watch.rearm()).not.toThrow();
    watch.rearm();
    expect(watch.armedCount()).toBe(0);
    // One line per directory, not one per tick.
    expect(logs.filter((line) => line.includes(code))).toHaveLength(3);

    failing = false;
    watch.rearm();
    expect(watch.armedCount()).toBe(3);
  });

  test("a missing directory is not watched until it exists", () => {
    const fake = fakeWatchFunction();
    const ids = allPresent();
    ids.table[`${ROOT}/ip-reuse/requests`] = undefined;
    const watch = createSessionAdmissionWatch({ targets, onChange: () => {}, watch: fake.watch, identity: ids.identity, log: () => {} });
    watch.rearm();
    expect(watch.armedCount()).toBe(2);
    ids.table[`${ROOT}/ip-reuse/requests`] = "1:77";
    watch.rearm();
    expect(watch.armedCount()).toBe(3);
  });

  test("a throwing change handler never escapes into the watcher", () => {
    const fake = fakeWatchFunction();
    const logs: string[] = [];
    const watch = createSessionAdmissionWatch({
      targets,
      onChange: () => {
        throw new Error("reconcile blew up");
      },
      watch: fake.watch,
      identity: allPresent().identity,
      log: (line) => logs.push(line),
    });
    watch.rearm();
    expect(() => fake.live()[1].listener("rename", `${"c".repeat(64)}.json`)).not.toThrow();
    expect(logs.some((line) => line.includes("reconcile blew up"))).toBe(true);
  });

  test("after close no event schedules a reconcile and nothing re-arms (I9)", () => {
    const fake = fakeWatchFunction();
    const onChange = vi.fn();
    const watch = createSessionAdmissionWatch({ targets, onChange, watch: fake.watch, identity: allPresent().identity, log: () => {} });
    watch.rearm();
    const listeners = fake.live().map((watcher) => watcher.listener);
    watch.close();
    expect(fake.live()).toHaveLength(0);
    for (const listener of listeners) listener("rename", "eligibility.json");
    watch.rearm();
    expect(onChange).not.toHaveBeenCalled();
    expect(fake.live()).toHaveLength(0);
  });
});

describe("session admission watch on a real directory", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });

  test("an atomic rename into sessions/ reaches the change handler through inotify", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-admission-watch-"));
    roots.push(root);
    fs.mkdirSync(path.join(root, "sessions"));
    fs.mkdirSync(path.join(root, "ip-reuse", "requests"), { recursive: true });
    let changes = 0;
    const changed = new Promise<void>((resolve) => {
      const watch = createSessionAdmissionWatch({
        targets: sessionAdmissionWatchTargets(root),
        onChange: () => {
          changes += 1;
          watch.close();
          resolve();
        },
        log: () => {},
      });
      watch.rearm();
      expect(watch.armedCount()).toBe(3);
      const temporary = path.join(root, "sessions", ".runfree-1-0011223344556677.tmp");
      fs.writeFileSync(temporary, "{}\n");
      fs.renameSync(temporary, path.join(root, "sessions", `${"d".repeat(64)}.json`));
    });
    await changed;
    expect(changes).toBe(1);
  });
});
