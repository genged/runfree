import { expect, test } from "vitest";

import {
  applyDenyProbeBatchResult,
  denyProbeBatchScript,
  type DenyProbeSpec,
  failDenyProbeBatch,
} from "./deny-probe-batch.ts";
import type { CaptureResult } from "./types.ts";

const SPECS: DenyProbeSpec[] = [
  { label: "agent-position direct TCP egress", command: "timeout 3 bash -c '</dev/tcp/1.1.1.1/443'" },
  { label: "agent-position direct external DNS", command: "dig +time=2 +tries=1 @1.1.1.1 example.com" },
  { label: "agent-position default IPv4 route", command: "ip -4 route show default | grep -q ." },
];

function result(status: number, stdout = "", stderr = ""): CaptureResult {
  return { status, stdout, stderr };
}

function records(exits: number[]): string {
  return `${exits.map((exit, index) => `RUNFREE_DENY_PROBE ${index} exit=${exit}`).join("\n")}\n`;
}

test("the batch script preflights binaries, launches every probe concurrently, and records in index order", () => {
  const script = denyProbeBatchScript(SPECS);
  // Preflight before any probe: a stripped image aborts instead of minting
  // fake denials (constraint 2).
  for (const binary of ["bash", "dig", "getent", "grep", "ip", "timeout"]) {
    expect(script).toContain(`for runfree_tool in`);
    expect(script.split("for runfree_tool in")[1]).toContain(binary);
  }
  expect(script.indexOf("command -v")).toBeLessThan(script.indexOf("runfree_pid_0"));
  // Every probe body is single-quoted through `bash -lc`, backgrounded, then
  // waited and printed in host-declared index order.
  for (let index = 0; index < SPECS.length; index += 1) {
    expect(script).toContain(`runfree_pid_${index}=$!`);
    expect(script).toContain(`wait "$runfree_pid_${index}"; runfree_status_${index}=$?`);
    expect(script).toContain(`printf 'RUNFREE_DENY_PROBE %s exit=%s\\n' ${index} "$runfree_status_${index}"`);
  }
  expect(script).toContain("bash -lc 'timeout 3 bash -c '\\''</dev/tcp/1.1.1.1/443'\\'''");
  // The harness exits 0 regardless of probe outcomes; per-probe exit codes
  // are the host's to judge.
  expect(script.trimEnd().endsWith("exit 0")).toBe(true);
  expect(() => denyProbeBatchScript([])).toThrow("at least one probe");
});

test("all-denied records prove every denial and add no issues", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, records([1, 9, 1])));
  expect(issues).toEqual([]);
});

test("a probe exit of 0 is an enforcement gap, named per probe", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, records([1, 0, 1])));
  expect(issues).toEqual(["agent-position direct external DNS unexpectedly succeeded"]);
});

test("exit 126/127 is could-not-run — a validation failure, never a denial", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, records([127, 1, 126])));
  expect(issues).toEqual([
    "agent-position direct TCP egress denial probe could not run (exit 127)",
    "agent-position default IPv4 route denial probe could not run (exit 126)",
  ]);
});

test("a nonzero batch exit fails validation for EVERY probe even when records read denied", () => {
  // The inverted run-level contract (constraint 1): without it, a broken batch
  // harness that still printed plausible records would read as denial-proven.
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(96, records([1, 1, 1]), "missing probe binary: dig"));
  expect(issues).toHaveLength(SPECS.length);
  for (const [index, spec] of SPECS.entries()) {
    expect(issues[index]).toContain(`${spec.label} denial probe did not run`);
  }
});

test("a missing record fails validation naming the batch, not success", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, records([1, 1])));
  expect(issues).toHaveLength(SPECS.length);
  expect(issues[0]).toContain("printed 2 of 3 records");
});

test.each([
  ["duplicate", "RUNFREE_DENY_PROBE 0 exit=1\nRUNFREE_DENY_PROBE 0 exit=1\nRUNFREE_DENY_PROBE 2 exit=1\n"],
  ["reordered", "RUNFREE_DENY_PROBE 1 exit=1\nRUNFREE_DENY_PROBE 0 exit=1\nRUNFREE_DENY_PROBE 2 exit=1\n"],
  ["garbled", "RUNFREE_DENY_PROBE 0 exit=1\nchatter\nRUNFREE_DENY_PROBE 2 exit=1\n"],
])("a %s record fails the whole validation", (_kind, stdout) => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, stdout));
  expect(issues.length).toBeGreaterThanOrEqual(SPECS.length);
  expect(issues.every((issue) => issue.includes("did not run"))).toBe(true);
});

test("extra records beyond the declared set fail the whole validation", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, records([1, 1, 1, 1])));
  expect(issues).toHaveLength(SPECS.length);
  expect(issues[0]).toContain("printed 4 of 3 records");
});

test("oversized batch output fails closed", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(0, `${records([1, 1, 1])}${"x".repeat(20_000)}`));
  expect(issues).toHaveLength(SPECS.length);
  expect(issues[0]).toContain("exceeded its bound");
});

test("a start refused for an address in use fails every probe and names the address and the remedy", () => {
  const issues: string[] = [];
  let violated = false;
  applyDenyProbeBatchResult(issues, SPECS, result(
    125,
    "",
    "docker: Error response from daemon: failed to set up container networking: Address already in use.",
  ), () => { violated = true; }, "172.30.0.19");

  expect(issues).toHaveLength(SPECS.length);
  for (const [index, spec] of SPECS.entries()) {
    const issue = issues[index] as string;
    expect(issue.startsWith(`${spec.label} denial probe did not run: `)).toBe(true);
    expect(issue).toContain("172.30.0.19");
    expect(issue).toContain("agent_internal");
    expect(issue).toContain("runfree up");
    expect(issue).toContain("runfree destroy --force");
  }
  // Nothing was observed: the helper never ran, so containment must not fire.
  expect(violated).toBe(false);
});

test("an unrelated nonzero exit keeps the raw diagnostic, not the address remedy", () => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, result(96, "", "missing probe binary: dig"), undefined, "172.30.0.19");
  expect(issues[0]).toBe(`${SPECS[0]?.label} denial probe did not run: missing probe binary: dig`);
});

// The address diagnostic is the daemon's refusal, read from stderr only: the
// helper's own stdout is untrusted-image output and must never pick the
// message, and a helper that merely prints the phrase and exits is not a
// refused start.
test.each([
  ["the phrase on the helper's stdout", result(125, "docker: Error response from daemon: Address already in use", "")],
  ["the phrase on stderr from a helper that exited 1", result(1, "", "docker: Error response from daemon: Address already in use")],
  ["the phrase on stderr without the daemon's framing", result(125, "", "bind: address already in use")],
])("%s is not the address-in-use diagnostic", (_name, batch) => {
  const issues: string[] = [];
  applyDenyProbeBatchResult(issues, SPECS, batch, undefined, "172.30.0.19");
  expect(issues).toHaveLength(SPECS.length);
  for (const issue of issues) {
    expect(issue).toContain("denial probe did not run");
    expect(issue).not.toContain("ephemeral-helper address 172.30.0.19");
  }
});

test("a timed-out batch fails every probe as did-not-run even with status 0 and well-formed records", () => {
  for (const unclean of [{ timedOut: true }, { signal: "SIGKILL" as const }]) {
    const issues: string[] = [];
    let violated = false;
    applyDenyProbeBatchResult(issues, SPECS, { ...result(0, records([0, 1, 1])), ...unclean }, () => { violated = true; });
    expect(issues).toHaveLength(SPECS.length);
    for (const issue of issues) expect(issue).toContain("denial probe did not run");
    expect(violated).toBe(false);
  }
});

test("a batch refused before docker run fails every probe as did-not-run with the reason", () => {
  const issues: string[] = [];
  failDenyProbeBatch(issues, SPECS, "no free ephemeral-helper address");
  expect(issues).toEqual(SPECS.map((spec) => `${spec.label} denial probe did not run: no free ephemeral-helper address`));
});
