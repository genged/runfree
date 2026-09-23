// Consolidated agent-position deny probes (design item L3).
//
// The five (plus per-gateway) direct-egress denial probes prove per-netns
// POSITION properties — internal network, no default route, no host gateway —
// so co-locating them in ONE ephemeral helper container does not change what
// any probe proves. What the consolidation must not do is fail open: the old
// shape ran one container per probe where a container-level failure was that
// probe's failure, while a naive batch would let one broken harness read as
// five proven denials. The contract here inverts that:
//
//   1. The batch script exits 0 iff it launched every probe and printed every
//      record. A nonzero batch exit, a timeout, oversized output, or any
//      missing, duplicated, reordered, or garbled record fails the WHOLE
//      validation — never "denial proven".
//   2. Every probe binary is `command -v` preflighted; a missing binary aborts
//      the batch. A per-probe exit of 126/127 is judged could-not-run, a
//      validation failure — not a denial. (This strengthens the old per-exec
//      shape, where could-not-run was indistinguishable from denied.)
//   3. Probes run once, concurrently — they are independent and the
//      failure-expected ones burn their in-probe timeouts by design. There is
//      no retry: observing a SUCCESS from any failure-expected probe is a
//      validation failure, and retrying could only mask it.
//
// Records are host-keyed by declaration index; the helper never emits
// content-derived names. The helper still runs the untrusted agent image's
// shell — exactly like the per-probe helpers it replaces — so its stdout is
// framing evidence for the host to judge, never authority.

import type { CaptureResult } from "./types.ts";

export type DenyProbeSpec = Readonly<{
  /** Issue label; must keep the `agent-position …` prefix the topology code map keys on. */
  label: string;
  /** The probe body, run via `bash -lc` exactly like the per-probe helpers did. */
  command: string;
}>;

const DENY_PROBE_MARKER = "RUNFREE_DENY_PROBE";
const DENY_PROBE_RECORD_PATTERN = /^RUNFREE_DENY_PROBE (\d+) exit=(\d+)$/u;
const DENY_PROBE_OUTPUT_MAX_BYTES = 16 * 1024;
// Every binary any probe body needs. Preflighted up front so a stripped-down
// agent image aborts the batch instead of minting fake denials.
const DENY_PROBE_REQUIRED_BINARIES = ["bash", "dig", "getent", "grep", "ip", "timeout"] as const;

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * Builds the one bash script that runs every probe as a background job and
 * prints one `RUNFREE_DENY_PROBE <index> exit=<code>` record per probe, in
 * host-declared index order. Probe output is discarded in-container; only the
 * index-keyed exit codes come back.
 */
export function denyProbeBatchScript(specs: readonly DenyProbeSpec[]): string {
  if (specs.length === 0) throw new Error("deny probe batch requires at least one probe");
  const lines: string[] = [
    "set -u",
    `for runfree_tool in ${DENY_PROBE_REQUIRED_BINARIES.join(" ")}; do`,
    "  if ! command -v \"$runfree_tool\" >/dev/null 2>&1; then",
    "    printf 'missing probe binary: %s\\n' \"$runfree_tool\" >&2",
    "    exit 96",
    "  fi",
    "done",
  ];
  specs.forEach((spec, index) => {
    lines.push(`bash -lc ${shellSingleQuote(spec.command)} >/dev/null 2>&1 & runfree_pid_${index}=$!`);
  });
  specs.forEach((_, index) => {
    lines.push(`wait "$runfree_pid_${index}"; runfree_status_${index}=$?`);
  });
  specs.forEach((_, index) => {
    lines.push(`printf '${DENY_PROBE_MARKER} %s exit=%s\\n' ${index} "$runfree_status_${index}"`);
  });
  lines.push("exit 0");
  return lines.join("\n");
}

function compactDiagnostic(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 500) return compact;
  return `${compact.slice(0, 497)}...`;
}

/**
 * Judges one batch run. Batch-harness failures push one did-not-run issue PER
 * probe — every denial in the batch is unproven, and each issue keeps its
 * probe's label so the topology issue codes stay per-probe.
 */
export function applyDenyProbeBatchResult(
  issues: string[],
  specs: readonly DenyProbeSpec[],
  result: CaptureResult,
  onBoundaryViolation?: () => void,
): void {
  const batchFailure = (detail: string): void => {
    for (const spec of specs) {
      issues.push(`${spec.label} denial probe did not run${detail ? `: ${detail}` : ""}`);
    }
  };
  if (result.status !== 0) {
    batchFailure(compactDiagnostic(`${result.stderr}\n${result.stdout}`) || `deny probe batch exited ${result.status}`);
    return;
  }
  if (Buffer.byteLength(result.stdout) > DENY_PROBE_OUTPUT_MAX_BYTES) {
    batchFailure("deny probe batch output exceeded its bound");
    return;
  }
  const records = result.stdout.split(/\r?\n/u).filter((line) => line.trim() !== "");
  if (records.length !== specs.length) {
    batchFailure(`deny probe batch printed ${records.length} of ${specs.length} records`);
    return;
  }
  const outcomes: number[] = [];
  for (let index = 0; index < records.length; index += 1) {
    const match = DENY_PROBE_RECORD_PATTERN.exec(records[index]);
    if (!match || Number(match[1]) !== index) {
      batchFailure(`deny probe record ${index} is missing or garbled`);
      return;
    }
    outcomes.push(Number(match[2]));
  }
  outcomes.forEach((exit, index) => {
    const label = specs[index].label;
    if (exit === 0) {
      onBoundaryViolation?.();
      issues.push(`${label} unexpectedly succeeded`);
    } else if (exit === 126 || exit === 127) {
      issues.push(`${label} denial probe could not run (exit ${exit})`);
    }
  });
}
