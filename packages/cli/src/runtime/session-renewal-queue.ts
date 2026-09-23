import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { hostBootId, hostProcessStart } from "./host-identity.ts";
import { sessionRecordOwnerLiveness } from "./session-record-liveness.ts";
import { readBoundedRegularFile } from "../strict-primitives.ts";

/** Scheduling only: a ticket never grants a lease or lifecycle-lock ownership. */
export const SESSION_RENEWAL_WAIT_BUDGET_MS = 120_000;
const ticketPattern = /^([0-9]{13})-[a-f0-9]{32}\.json$/u;
const ticketReadOptions = { maxBytes: 512, sizeRecheck: "exact" as const,
  notFileMessage: () => "session renewal ticket is unsafe; repair its host queue entry",
  changedMessage: () => "session renewal ticket changed during read; retry acquisition" };

function queueRoot(stateDir: string): string { return path.join(stateDir, "session-renewal-queue"); }

type RenewalTicket = { ticket: string; hostPid: number; hostBootId?: string; hostProcessStart?: string };

function readTicket(file: string, ticket: string): RenewalTicket | undefined {
  const source = readBoundedRegularFile(file, ticketReadOptions)?.source;
  if (source === undefined) return undefined;
  let record: RenewalTicket;
  try { record = JSON.parse(source) as RenewalTicket; }
  catch { throw new Error(`invalid renewal ticket; repair the host scheduling entry: ${file}`); }
  if (!record || record.ticket !== ticket || !Number.isSafeInteger(record.hostPid) || record.hostPid <= 0
    || Object.keys(record).some((key) => !["ticket", "hostPid", "hostBootId", "hostProcessStart"].includes(key))
    || record.hostBootId !== undefined && typeof record.hostBootId !== "string"
    || record.hostProcessStart !== undefined && typeof record.hostProcessStart !== "string") {
    throw new Error(`invalid renewal ticket identity; repair the host scheduling entry: ${file}`);
  }
  return record;
}

export function sessionRenewalQueueHead(stateDir: string, nowMs = Date.now(), env?: NodeJS.ProcessEnv): string | undefined {
  const root = queueRoot(stateDir);
  const entries: string[] = [];
  try {
    const stat = fs.lstatSync(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("session renewal queue is unsafe; repair its host state directory");
    const directory = fs.opendirSync(root);
    try {
      for (let count = 0; ; count += 1) {
        const entry = directory.readSync();
        if (!entry) break;
        if (count >= 1024) throw new Error("session renewal queue exceeds its inspection bound; remove obsolete host queue entries before retrying");
        entries.push(entry.name);
      }
    } finally { directory.closeSync(); }
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  for (const entry of entries.filter((name) => ticketPattern.test(name)).sort()) {
    const file = path.join(root, entry);
    const record = readTicket(file, entry);
    if (!record) continue;
    const issuedAt = Number(ticketPattern.exec(entry)?.[1]);
    // Wall time schedules a stale-owner check; it never expires a live request.
    // The requester releases on acquisition, cancellation, or its bounded wait.
    // A clock step cannot erase its priority. Unknown owners retain the ticket
    // until cancellation or explicit repair of the host scheduling entry.
    if ((nowMs < issuedAt || nowMs - issuedAt >= SESSION_RENEWAL_WAIT_BUDGET_MS)
      && sessionRecordOwnerLiveness(record, env) === "dead") {
      try { fs.unlinkSync(file); }
      catch (error) { if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error; }
      continue;
    }
    return entry;
  }
  return undefined;
}

export function enqueueSessionRenewal(stateDir: string, nowMs = Date.now(), env?: NodeJS.ProcessEnv): { ticket: string; release(): void } {
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const root = queueRoot(stateDir);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("session renewal queue is unsafe; repair its host state directory");
  const ticket = `${nowMs.toString().padStart(13, "0")}-${crypto.randomBytes(16).toString("hex")}.json`;
  const file = path.join(root, ticket);
  const source = JSON.stringify({ ticket, hostPid: process.pid, hostBootId: hostBootId(env), hostProcessStart: hostProcessStart(process.pid, env) });
  fs.writeFileSync(file, source, { mode: 0o600, flag: "wx" });
  return { ticket, release() {
    const current = readBoundedRegularFile(file, ticketReadOptions)?.source;
    if (current === source) fs.unlinkSync(file);
  } };
}
