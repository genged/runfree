// The image-cleanup stamp: the digest of the host-side inputs the last
// completed cleanup pass saw (fast-launch spec Phase 2, sub-second launch plan
// Task 4).
//
// Cleanup only deletes. So the stamp can only ever *skip* deletion: a warm
// launch whose inputs digest equals the stamp does not run the cleanup pass,
// and a stale, forged, or unreadable stamp costs at most retained garbage until
// the next `runfree up`, `rebuild`, or `destroy` (which always clean up) or the
// next input change. It never authorizes an effect.

import { launchHostRecordPath, readLaunchHostRecord, removeLaunchHostRecord, writeLaunchHostRecord } from "./launch-host-record.ts";
import { exactKeySet, isRecord } from "../strict-primitives.ts";

export const IMAGE_CLEANUP_STAMP_NAME = "image-cleanup-stamp.json";
const MAX_BYTES = 4 * 1024;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const PROJECT_ID = /^[a-f0-9]{12}$/;

export type ImageCleanupStampV1 = Readonly<{
  version: 1;
  projectId: string;
  inputsDigest: string;
  writtenAt: string;
}>;

function parseImageCleanupStamp(value: unknown): ImageCleanupStampV1 | undefined {
  if (!isRecord(value) || !exactKeySet(value, ["version", "projectId", "inputsDigest", "writtenAt"])) return undefined;
  if (value.version !== 1) return undefined;
  if (typeof value.projectId !== "string" || !PROJECT_ID.test(value.projectId)) return undefined;
  if (typeof value.inputsDigest !== "string" || !DIGEST.test(value.inputsDigest)) return undefined;
  if (typeof value.writtenAt !== "string" || !Number.isFinite(Date.parse(value.writtenAt))) return undefined;
  return Object.freeze({
    version: 1,
    projectId: value.projectId,
    inputsDigest: value.inputsDigest,
    writtenAt: value.writtenAt,
  });
}

export function imageCleanupStampPath(stateDir: string): string {
  return launchHostRecordPath(stateDir, IMAGE_CLEANUP_STAMP_NAME);
}

export function readImageCleanupStamp(stateDir: string, projectId: string): ImageCleanupStampV1 | undefined {
  const stamp = readLaunchHostRecord(stateDir, IMAGE_CLEANUP_STAMP_NAME, MAX_BYTES, parseImageCleanupStamp);
  return stamp?.projectId === projectId ? stamp : undefined;
}

/** Whether a warm launch may skip cleanup: only an exact, current-project digest match. */
export function imageCleanupStampMatches(stateDir: string, projectId: string, inputsDigest: string): boolean {
  if (!DIGEST.test(inputsDigest)) return false;
  return readImageCleanupStamp(stateDir, projectId)?.inputsDigest === inputsDigest;
}

export function writeImageCleanupStamp(
  stateDir: string,
  projectId: string,
  inputsDigest: string,
  now: Date = new Date(),
): void {
  const stamp = parseImageCleanupStamp({ version: 1, projectId, inputsDigest, writtenAt: now.toISOString() });
  if (!stamp) throw new Error("invalid image cleanup stamp");
  writeLaunchHostRecord(stateDir, IMAGE_CLEANUP_STAMP_NAME, `${JSON.stringify(stamp)}\n`);
}

export function removeImageCleanupStamp(stateDir: string): void {
  removeLaunchHostRecord(stateDir, IMAGE_CLEANUP_STAMP_NAME);
}
