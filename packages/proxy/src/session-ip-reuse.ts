import fs from "node:fs";
import path from "node:path";
import { SESSION_ADMISSION_ROOT } from "@runfree/runtime-contracts/session-admission";
import { SESSION_IP_REUSE_DIR, type SessionIpAssignment } from "@runfree/runtime-contracts/session-file";
import { isExactSessionSourceIpv4 } from "@runfree/runtime-contracts/session-registry";
import { isSafeDirectory, readOwnedRegularFile } from "./session-files.js";

/** Host-owned IP assignments fence reuse; neither consumer can grant one. */
export class SessionIpAssignments {
  readonly directory: string;
  readonly #ownerUid: number;
  readonly #acknowledged = new Map<string, string>();

  constructor(root: string, ownerUid = 0) {
    this.directory = path.join(root, path.relative(SESSION_ADMISSION_ROOT, SESSION_IP_REUSE_DIR));
    this.#ownerUid = ownerUid;
  }

  read(): Map<string, SessionIpAssignment> | undefined {
    const requests = path.join(this.directory, "requests");
    if (!isSafeDirectory(this.directory, this.#ownerUid) || !isSafeDirectory(requests, this.#ownerUid)) return undefined;
    const assignments = new Map<string, SessionIpAssignment>();
    try {
      for (const name of fs.readdirSync(requests)) {
        if (!name.endsWith(".json")) continue;
        const sourceIp = name.slice(0, -5);
        if (!isExactSessionSourceIpv4(sourceIp)) return undefined;
        const read = readOwnedRegularFile(path.join(requests, name), this.#ownerUid, 512);
        if (read.kind === "missing") continue;
        if (read.kind !== "ok") return undefined;
        const value = JSON.parse(read.content) as SessionIpAssignment;
        if (value === null || typeof value !== "object" || Array.isArray(value)
          || Object.keys(value).sort().join(",") !== "nonce,sessionKey,sourceIp,state,v"
          || value.v !== 1 || value.sourceIp !== sourceIp
          || typeof value.sessionKey !== "string" || !/^[a-f0-9]{64}$/.test(value.sessionKey)
          || typeof value.nonce !== "string" || !/^[a-f0-9]{32}$/.test(value.nonce)
          || (value.state !== "draining" && value.state !== "ready")) return undefined;
        assignments.set(sourceIp, value);
      }
      for (const address of this.#acknowledged.keys()) {
        if (!assignments.has(address)) this.#acknowledged.delete(address);
      }
      return assignments;
    } catch {
      return undefined;
    }
  }

  /** Caller has already removed the address and all authority it owned. */
  acknowledge(consumer: "firewall" | "request-proxy", assignment: SessionIpAssignment): void {
    if (assignment.state !== "draining" || this.#acknowledged.get(assignment.sourceIp) === assignment.nonce) return;
    const target = path.join(this.directory, consumer, `${assignment.sourceIp}.json`);
    const temporary = `${target}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(temporary, `${assignment.nonce}\n`, { mode: 0o644 });
      fs.renameSync(temporary, target);
      this.#acknowledged.set(assignment.sourceIp, assignment.nonce);
    } finally {
      fs.rmSync(temporary, { force: true });
    }
  }
}
