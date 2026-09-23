// The checkout's persistent identity, as stored observations.
//
// This is a scope key, not an authorization. The approved subjects are content
// digests of the policy bytes, the isolation fields, and the image build
// inputs, so any change to what was approved already forces a review. Path
// scope is separately established by the record's own location under
// `projects/<projectHash(projectRoot)>`. What the inode adds on top is exactly
// one thing: a tripwire for a directory replaced at the same path.
//
// Three limits bound what that tripwire is worth, and they are accepted by
// design rather than worked around:
//
//  1. It does not cover the asset most often cited to justify it. A replacement
//     checkout at the same path inherits the per-project Claude, Codex, and Pi
//     state, which is keyed on the path alone.
//  2. It sees the container, not the contents. An in-place branch checkout, a
//     `git pull`, or an agent edit keeps the same root inode.
//  3. It is void whenever the project root is itself a filesystem mount root. A
//     newly created filesystem assigns its root directory a deterministic inode
//     (ext4 fixes it at 2), and `fs.realpathSync.native` resolves through
//     neither bind mounts nor firmlinks — so a dedicated source volume, a CI
//     workspace volume at a fixed path, a loopback image, or a bind-mounted
//     checkout presents the same observation for every volume mounted there.
//     For those layouts the binding degenerates to path alone.
//
// Inode persistence is a filesystem property this design does not claim for
// every filesystem, and it adds no filesystem-detection subsystem. Where an
// inode is unstable the cost is one review per change, never a wedge.

import fs from "node:fs";
import path from "node:path";

import { assertAllowedKeys as exactKeys, isRecord } from "../strict-primitives.ts";

export type CheckoutBinding = {
  resolvedRoot: string;
  rootDevice: string;
  rootInode: string;
};

export type CheckoutBindingField = "resolved-root" | "root-inode";

const MAX_RESOLVED_ROOT = 4096;
const DECIMAL = /^\d{1,20}$/;

/**
 * Observe the checkout's persistent identity.
 *
 * `rootDevice` is recorded and never compared. Storing it is what makes a
 * mismatch attributable — "the directory was replaced **and** the volume was
 * renumbered" is a different diagnosis from "the directory was replaced" — and
 * it costs no authority, because nothing tests it. Comparing it is precisely
 * what a reboot breaks, which is the incident this binding exists to fix.
 *
 * Stat is read with `bigint: true`: inode and device numbers exceed the safe
 * integer range on real filesystems, so they are carried as decimal strings and
 * never as JavaScript numbers.
 */
export function observeCheckoutBinding(projectRoot: string): CheckoutBinding {
  const resolvedRoot = fs.realpathSync.native(projectRoot);
  const stat = fs.statSync(resolvedRoot, { bigint: true });
  return {
    resolvedRoot,
    rootDevice: stat.dev.toString(),
    rootInode: stat.ino.toString(),
  };
}

export function validateCheckoutBinding(raw: unknown): CheckoutBinding {
  if (!isRecord(raw)) throw new Error("control approval checkoutBinding must be an object");
  exactKeys(raw, ["resolvedRoot", "rootDevice", "rootInode"], "control approval checkoutBinding");
  const resolvedRoot = raw.resolvedRoot;
  if (typeof resolvedRoot !== "string" || resolvedRoot.length === 0
    || resolvedRoot.length > MAX_RESOLVED_ROOT
    || !path.isAbsolute(resolvedRoot)
    || path.normalize(resolvedRoot) !== resolvedRoot) {
    throw new Error("control approval checkoutBinding resolvedRoot is malformed");
  }
  for (const name of ["rootDevice", "rootInode"] as const) {
    const value = raw[name];
    if (typeof value !== "string" || !DECIMAL.test(value)) {
      throw new Error(`control approval checkoutBinding ${name} is malformed`);
    }
  }
  return {
    resolvedRoot,
    rootDevice: raw.rootDevice as string,
    rootInode: raw.rootInode as string,
  };
}

/**
 * The first compared field that differs, or `undefined` when the binding holds.
 * `rootDevice` is deliberately absent from this comparison.
 */
export function compareCheckoutBinding(
  stored: CheckoutBinding,
  observed: CheckoutBinding,
): CheckoutBindingField | undefined {
  if (stored.resolvedRoot !== observed.resolvedRoot) return "resolved-root";
  if (stored.rootInode !== observed.rootInode) return "root-inode";
  return undefined;
}
