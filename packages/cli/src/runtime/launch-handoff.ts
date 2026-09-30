// Shared facts of a held-lock launch handoff (sub-second launch plan Task 3).
//
// The handoff itself lives in `prepared-runtime.ts`, bound to the prepared
// runtime that carries it. This module holds what both ends compute the same
// way: startup when it mints, admission when it decides whether it may skip
// repeating startup's reconcile.

import { sha256Digest, stableJson } from "../strict-primitives.ts";
import {
  listSessionContainerRecordsV2,
  type SessionContainerProjectIdentity,
} from "./session-containers.ts";

/**
 * The digest of the project's lifecycle registry as it is on disk. Admission
 * with a handoff re-reads it and compares: any record added, removed, or
 * changed since startup's reconcile means the full preflight runs.
 */
export function sessionRegistryDigest(stateDir: string, expectedProject: SessionContainerProjectIdentity): string {
  return sha256Digest(stableJson(listSessionContainerRecordsV2(stateDir, expectedProject)
    .map((record) => stableJson(record))
    .sort()));
}
