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
  serializeGenerationStatus,
  type FirewallGenerationStatus,
  type RequestProxyGenerationStatus,
} from "@runfree/runtime-contracts/proxy-status";

export type { FirewallGenerationStatus, RequestProxyGenerationStatus };

// Atomic replace within the same tmpfs directory so a poll never observes a
// torn write; the shared serializer guarantees the one-JSON-line framing the
// CLI's exec-split reader depends on. Unique tmp name plus failure cleanup,
// matching writeResolvedHostsFile.
export function writeGenerationStatusFile(
  filePath: string,
  status: FirewallGenerationStatus | RequestProxyGenerationStatus,
): void {
  const tmpPath = `${filePath}.${process.pid}.${Date.now().toString(36)}.tmp`;
  try {
    fs.writeFileSync(tmpPath, serializeGenerationStatus(status), { mode: 0o644 });
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    fs.rmSync(tmpPath, { force: true });
    throw error;
  }
}
