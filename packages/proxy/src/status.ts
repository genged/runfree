// Filesystem writer for the proxy policy-generation status files. Paths,
// shapes, and the single-line JSON framing live in the shared
// @runfree/runtime-contracts/proxy-status contract (also consumed by the host
// CLI's convergence-ack reader). Ownership split mirrors the audit
// marker/spool pattern: the root firewall supervisor writes firewall.json in
// the root-owned status root, the uid-1001 request proxy writes
// request-proxy.json inside a uid-1001-owned subdirectory pre-created by the
// entrypoint. Log lines are human diagnostics only — no control decision may
// read the log stream.

import fs from "node:fs";
import {
  parseHostServiceGatewayStatus,
  serializeGenerationStatus,
  type FirewallGenerationStatus,
  type HostServiceGatewayStatus,
  type RequestProxyGenerationStatus,
} from "@runfree/runtime-contracts/proxy-status";

import { readOwnedRegularFile } from "./session-files.js";

export type { FirewallGenerationStatus, RequestProxyGenerationStatus };

export const HOST_SERVICE_GATEWAY_MAX_BYTES = 4096;

// Atomic replace within the same tmpfs directory so a poll never observes a
// torn write; the shared serializer guarantees the one-JSON-line framing the
// CLI's exec-split reader depends on. Unique tmp name plus failure cleanup,
// matching writeResolvedHostsFile. The root supervisor also writes the
// host-service gateway hand-off through here (root-owned, 0644, atomic).
export function writeGenerationStatusFile(
  filePath: string,
  status: FirewallGenerationStatus | RequestProxyGenerationStatus | HostServiceGatewayStatus,
): void {
  const tmpPath = `${filePath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  try {
    fs.writeFileSync(tmpPath, serializeGenerationStatus(status), { mode: 0o644 });
    // The umask masks the create mode; readers under another uid need 0644.
    fs.chmodSync(tmpPath, 0o644);
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    fs.rmSync(tmpPath, { force: true });
    throw error;
  }
}

// The uid-1001 request proxy's reader of the gateway hand-off. The root
// firewall supervisor is its only writer, in the root-owned status root. Read
// it the same defended way as the session files (owner, regular file, no
// symlink, single link, bounded size) and also refuse a group- or
// other-writable file. Any failure reads as unavailable (`undefined`).
export function readHostServiceGatewayStatusFile(filePath: string, ownerUid: number): HostServiceGatewayStatus | undefined {
  try {
    const stat = fs.lstatSync(filePath);
    if ((stat.mode & 0o022) !== 0) return undefined;
    const read = readOwnedRegularFile(filePath, ownerUid, HOST_SERVICE_GATEWAY_MAX_BYTES);
    if (read.kind !== "ok") return undefined;
    return parseHostServiceGatewayStatus(read.content);
  } catch {
    return undefined;
  }
}
