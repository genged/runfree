import fs from "node:fs";
import path from "node:path";

import { SESSION_ADMISSION_ROOT } from "@runfree/runtime-contracts/session-admission";
import { SESSION_FILES_DIR, SESSION_IP_REUSE_DIR } from "@runfree/runtime-contracts/session-file";

// Event-driven session admission (launch plan Task 7).
//
// Both proxy-side consumers — the root firewall supervisor and the uid-1001
// request proxy — rebuild their view from the same host-written files. Each
// keeps its 100 ms interval; this module only adds an earlier trigger: an
// inotify event on an admission input schedules the same reconcile the
// interval runs. It grants nothing. What a reconcile admits, revokes, or
// acknowledges is unchanged code, and the interval stays the backstop for
// everything an event cannot report:
//   - lease expiry, where time passes and no file changes;
//   - a lost or overflowed event, or a watcher that failed or never armed
//     (inotify instance and watch limits are per user and shared host-wide);
//   - a watched directory that was replaced (re-armed on its new identity).
//
// Watched: the admission root (for `eligibility.json`), `sessions/`, and
// `ip-reuse/requests/`. Never a directory a consumer writes (its own
// `ip-reuse/<consumer>/` acknowledgements), so a reconcile cannot trigger
// itself. Only host root execs write the watched directories, and the agent
// has no mount of them, so the event volume is the host's own writes.

/** Host-controlled test switch: `off` leaves only the interval, to prove the backstop alone. */
export const SESSION_ADMISSION_WATCH_ENV = "RUNFREE_SESSION_ADMISSION_WATCH";

export function sessionAdmissionWatchEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[SESSION_ADMISSION_WATCH_ENV] !== "off";
}

export type SessionAdmissionWatchTarget = Readonly<{
  dir: string;
  /**
   * Whether an event naming `filename` can change what a reconcile decides.
   * The host's atomic writes create a `.tmp` name first; that event would
   * only schedule a scan of the unchanged state, so it is ignored and the
   * rename's own event (which names the final `.json`) triggers the scan.
   * A missing name is always relevant.
   */
  relevant: (filename: string | null) => boolean;
}>;

const ELIGIBILITY_NAME = "eligibility.json";

export function sessionAdmissionWatchTargets(root: string = SESSION_ADMISSION_ROOT): readonly SessionAdmissionWatchTarget[] {
  const relative = (dir: string) => path.join(root, path.relative(SESSION_ADMISSION_ROOT, dir));
  const jsonName = (filename: string | null) => filename === null || filename.endsWith(".json");
  return Object.freeze([
    Object.freeze({ dir: root, relevant: (filename: string | null) => filename === null || filename === ELIGIBILITY_NAME }),
    Object.freeze({ dir: relative(SESSION_FILES_DIR), relevant: jsonName }),
    Object.freeze({ dir: path.join(relative(SESSION_IP_REUSE_DIR), "requests"), relevant: jsonName }),
  ]);
}

export type SessionAdmissionWatcher = Readonly<{
  close(): void;
  on(event: "error", listener: (error: Error) => void): unknown;
}>;

export type SessionAdmissionWatchFunction = (
  dir: string,
  listener: (eventType: string, filename: string | null) => void,
) => SessionAdmissionWatcher;

export type SessionAdmissionWatch = Readonly<{
  /** Arms every target not armed on its current directory. The backstop tick calls this. */
  rearm(): void;
  close(): void;
  armedCount(): number;
}>;

type TargetState = {
  watcher?: SessionAdmissionWatcher;
  identity?: string;
  lastLog?: string;
};

const defaultWatch: SessionAdmissionWatchFunction = (dir, listener) =>
  // `persistent: false`: like the interval's `unref()`, a watcher never keeps
  // a stopping consumer alive.
  fs.watch(dir, { persistent: false }, (eventType, filename) => listener(eventType, filename === null ? null : String(filename)));

function directoryIdentity(dir: string): string | undefined {
  try {
    const stat = fs.lstatSync(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return undefined;
    return `${stat.dev}:${stat.ino}`;
  } catch {
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : `non-Error ${typeof error}`;
  return value.length <= 512 ? value : `${value.slice(0, 511)}…`;
}

export function createSessionAdmissionWatch(input: Readonly<{
  targets: readonly SessionAdmissionWatchTarget[];
  onChange: () => void;
  watch?: SessionAdmissionWatchFunction;
  identity?: (dir: string) => string | undefined;
  log?: (line: string) => void;
  /** Log prefix naming the consumer (`proxy-firewall`, `proxy`). */
  label?: string;
}>): SessionAdmissionWatch {
  const watch = input.watch ?? defaultWatch;
  const identity = input.identity ?? directoryIdentity;
  const log = input.log ?? ((line: string) => console.error(line));
  const label = input.label ?? "proxy";
  const states = input.targets.map((): TargetState => ({}));
  let closed = false;

  // One line per distinct state per directory, so a failing arm on every
  // 100 ms tick does not flood the log.
  const note = (state: TargetState, line: string) => {
    if (state.lastLog === line) return;
    state.lastLog = line;
    log(line);
  };

  const disarm = (state: TargetState) => {
    const watcher = state.watcher;
    state.watcher = undefined;
    state.identity = undefined;
    try {
      watcher?.close();
    } catch {
      // Already closed; nothing else holds it.
    }
  };

  const arm = (target: SessionAdmissionWatchTarget, state: TargetState) => {
    const current = identity(target.dir);
    if (state.watcher && state.identity === current) return;
    disarm(state);
    if (current === undefined) {
      note(state, `${label}: session admission watch: ${target.dir} is not a directory; interval only until it is`);
      return;
    }
    let watcher: SessionAdmissionWatcher;
    try {
      watcher = watch(target.dir, (_eventType, filename) => {
        if (closed || state.watcher !== watcher || !target.relevant(filename)) return;
        try {
          input.onChange();
        } catch (error) {
          log(`${label}: session admission watch: reconcile trigger failed: ${errorMessage(error)}`);
        }
      });
    } catch (error) {
      note(state, `${label}: session admission watch: could not watch ${target.dir}; interval only: ${errorMessage(error)}`);
      return;
    }
    watcher.on("error", (error) => {
      if (state.watcher !== watcher) return;
      disarm(state);
      note(state, `${label}: session admission watch: watcher for ${target.dir} failed; interval only until re-armed: ${errorMessage(error)}`);
    });
    state.watcher = watcher;
    state.identity = current;
    note(state, `${label}: session admission watch: watching ${target.dir}`);
  };

  return Object.freeze({
    rearm() {
      if (closed) return;
      for (const [index, target] of input.targets.entries()) arm(target, states[index]);
    },
    close() {
      closed = true;
      for (const state of states) disarm(state);
    },
    armedCount() {
      return states.filter((state) => state.watcher !== undefined).length;
    },
  });
}
