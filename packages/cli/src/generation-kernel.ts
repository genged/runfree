// The generation/convergence kernel (evolution-strategy A5, step 1).
//
// Every generation family — effective policy generations, approved subject
// snapshots, desired-policy candidates, session-admission snapshots — shares
// one protocol: publish content-addressed immutable state (write-if-absent
// with O_EXCL, fsync, rename, verify-or-accept-existing), select it for a
// consumer, then poll each consumer for an exact-generation acknowledgement
// under repeated authority fences. Before this module the host-side store
// existed four times and the ack loop twice; a new family is meant to be a
// CLIENT of these functions with its formats as data, not a fifth mirror.
//
// The contract, stated once because every per-caller knob here has to answer
// to it: THE PUBLISHING PATH IS STRICTLY UNIFORM; THE NON-PUBLISHING PATH
// KEEPS PER-CALLER FIDELITY. Publishing an entry that does not yet exist runs
// one order for everyone — O_EXCL payload writes, payload fsyncs, temp-dir
// fsync, rename, parent fsync, verify — and nothing parameterizes it. What a
// caller does when the entry ALREADY exists is a different question, because
// there the four originals genuinely differed in what they touched, and a
// reuse path that starts touching more is doing something its caller never
// did.
//
// That single line settles both live knobs and the one that was rejected.
// `parentSetup` and `fsyncParentWhenPresent` are reuse-path fidelity: whether
// the already-published case normalizes the parent's mode, and whether it
// fsyncs the parent. The rejected review finding wanted per-caller fsync
// ORDERING inside the publishing path, which is exactly the divergence this
// module exists to remove — the four copies each fsynced a different subset,
// and reintroducing that as three knobs would restore the mirror in
// configuration form. The two positions are consistent, not opposed: fidelity
// is granted where callers observably differed and refused where they only
// differed by accident.
//
// Deliberately NOT extracted here: the session-admission publication and
// selection effectors are sealed `node -e` scripts executed inside the proxy
// container against root-owned tmpfs (`runtime/session-admission-publisher.ts`)
// — a different medium with its own uid/nlink proofs — and the verified-empty
// base-state checks are single-user and media-specific. Those stay with their
// owners; only the shared protocol shapes live here.

import fs from "node:fs";
import path from "node:path";

import { fsyncDirectory } from "./safe-fs.ts";

export type ImmutableDirectoryPublication<T> = {
  /** Directory that holds the content-addressed entries. */
  parent: string;
  /** Content-addressed entry name (digest-derived by the caller). */
  name: string;
  /** Relative path → exact contents; nested paths are created. */
  files: Record<string, string>;
  directoryMode: number;
  fileMode: number;
  /** Applied to `parent` via mkdir and chmod before any write. */
  parentMode: number;
  /** mkdtemp prefix inside `parent`; must be unambiguous per store. */
  tempPrefix: string;
  /**
   * When the parent directory is created, validated, and normalized.
   *
   * "always" matches the generation and candidate stores, which normalize the
   * parent before looking for the entry. "when-creating" matches the approved
   * subject store, whose reuse path is a pure read: it verifies an existing
   * approval without touching the parent, so normalizing there could mutate
   * the store's mode — or fail on a parent this process cannot chmod — on a
   * path that previously only read.
   *
   * This is the contract's reuse-path fidelity, not an exception to it: the
   * two settings differ only in what the already-published case touches.
   */
  parentSetup?: "always" | "when-creating";
  /**
   * Runs after the entry exists (freshly renamed or already present) and is
   * the caller's digest recompute: an existing entry that fails verification
   * must throw rather than be replaced — immutable state is never rewritten.
   */
  verify: () => T;
  /**
   * Also fsync `parent` when the entry already existed (publishers whose fast
   * path must still order against a concurrent creator).
   *
   * The contract's other reuse-path knob: the publishing path always fsyncs the
   * parent, so this only says whether the already-published case does too.
   */
  fsyncParentWhenPresent?: boolean;
};

/**
 * Publishes one immutable content-addressed directory entry: all payloads are
 * written O_EXCL into a same-parent temp directory, fsynced, renamed into
 * place, and verified; an existing entry is verified instead of rewritten.
 * The rename is the only publication step, so a reader can never observe a
 * partially written entry.
 *
 * Durability on the publishing path is deliberately uniform and is the one
 * accepted behavioral delta of the A5 extraction: every publication fsyncs each
 * payload, then the temp directory before the rename, then the parent after it.
 * At HEAD the four copies each did a different subset — the generation
 * publisher skipped the temp fsync, the approval publishers skipped both
 * directory fsyncs, the candidate publisher skipped the parent fsync. Per the
 * module contract this is the path that does not get knobs: the four subsets
 * were accident, not caller semantics, and the strictly more durable order
 * costs nothing real. Directory
 * fsync is already load-bearing at HEAD (the generation publisher fsyncs its
 * parent on every startup publication), so a filesystem that cannot fsync a
 * directory is already broken for Runfree rather than newly broken by this.
 * A failure here still fails closed — the desired write is left as pending
 * unapproved policy that the next transaction refuses and `policy approve`
 * reclaims.
 */
export function publishImmutableDirectory<T>(input: ImmutableDirectoryPublication<T>): T {
  // `mkdirSync` with `recursive` applies `mode` only to directories it creates
  // and returns undefined when the path already existed. "always" normalizes
  // an existing parent on top of that; "when-creating" deliberately does not,
  // because its callers' originals used bare recursive mkdir and must not
  // start rewriting an existing store's permissions.
  const setUpParent = (normalizeExisting: boolean): void => {
    const created = fs.mkdirSync(input.parent, { recursive: true, mode: input.parentMode });
    if (!normalizeExisting && created === undefined) return;
    const parentStat = fs.lstatSync(input.parent);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
      throw new Error(`immutable publication parent is not a normal directory: ${input.parent}`);
    }
    fs.chmodSync(input.parent, input.parentMode);
  };
  const parentSetup = input.parentSetup ?? "always";
  if (parentSetup === "always") setUpParent(true);
  const target = path.join(input.parent, input.name);
  if (fs.existsSync(target)) {
    if (input.fsyncParentWhenPresent) fsyncDirectory(input.parent);
    return input.verify();
  }
  if (parentSetup === "when-creating") setUpParent(false);
  const temporary = fs.mkdtempSync(path.join(input.parent, input.tempPrefix));
  try {
    fs.chmodSync(temporary, input.directoryMode);
    for (const [relativePath, contents] of Object.entries(input.files)) {
      const filePath = path.join(temporary, relativePath);
      fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: input.directoryMode });
      // Creation modes are filtered by umask; every nested directory must
      // remain traversable by the intended consumer before publication.
      for (let directory = path.dirname(filePath); directory.startsWith(`${temporary}${path.sep}`); directory = path.dirname(directory)) {
        fs.chmodSync(directory, input.directoryMode);
      }
      const descriptor = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, input.fileMode);
      try {
        fs.writeFileSync(descriptor, contents);
        fs.fchmodSync(descriptor, input.fileMode);
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
    }
    fsyncDirectory(temporary);
    fs.renameSync(temporary, target);
    fsyncDirectory(input.parent);
    return input.verify();
  } catch (error) {
    fs.rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
}

export type ExactAckPoll<T> = {
  /** One acknowledgement read; a defined value is convergence. The exact
   * generation/record predicate is the caller's and lives inside the probe. */
  probe: () => Promise<T | undefined> | T | undefined;
  /** Authority/stability fence before every probe; must throw to abort. */
  beforeProbe?: () => void;
  /** Authority fence after every probe (spent-authority families re-assert). */
  afterProbe?: () => void;
  timeoutMs: number;
  pollIntervalMs: number;
  /**
   * Where the deadline cuts: "after-probe" always probes at least once and
   * times out only after an unconverged probe; "before-probe" refuses to
   * start a probe past the deadline.
   */
  deadline: "after-probe" | "before-probe";
  nowMs?: () => number;
  delay?: (milliseconds: number) => Promise<void>;
};

/**
 * The bounded exact-acknowledgement convergence loop shared by every
 * generation family. Returns the converged probe value, or undefined when the
 * deadline passes without convergence — the caller owns what a timeout means
 * (rollback, teardown, or a family-specific error).
 */
export async function pollForExactAck<T>(input: ExactAckPoll<T>): Promise<T | undefined> {
  const nowMs = input.nowMs ?? (() => Date.now());
  const delay = input.delay ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const startedAt = nowMs();
  const expired = (): boolean => nowMs() - startedAt >= input.timeoutMs;
  for (;;) {
    if (input.deadline === "before-probe" && expired()) return undefined;
    input.beforeProbe?.();
    const result = await input.probe();
    input.afterProbe?.();
    if (result !== undefined) return result;
    if (input.deadline === "after-probe" && expired()) return undefined;
    await delay(input.pollIntervalMs);
  }
}
