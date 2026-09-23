// Shared runner for the internal session-admission matrix subprocess.
//
// The matrix keeps its own supervision: it re-execs itself as a detached
// process-group leader and bounds a hung probe with TERM, a grace period, and a
// process-group SIGKILL. Vitest cannot provide that — a blocked synchronous
// `docker` call in a worker is not interruptible by `testTimeout` — so the
// subprocess boundary stays and this module owns invoking it.
//
// The expected outcome is an explicit input rather than an implicit throw: a
// helper that always throws on non-zero cannot express "this must be refused",
// which is what the negative tranche needs from the same slice.
//
// A successful slice is validated here, not by the caller. The retired nominal
// tranche owned those assertions and ran them once per built-in agent; folding
// them in means every `expect: "success"` probe in the suite checks them, so a
// slice that exits 0 while reporting no completed runs, a non-empty lifecycle
// registry, residual session containers, or the other backend now fails.

import childProcess from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { SessionAdmissionProbeAgent } from "../../../packages/cli/src/runtime/session-admission-probe.ts";
import type { SessionAdmissionMatrixResult } from "../session-admission-matrix.ts";
import { describeOutput, type LiveFixture, type LiveRuntimeBackend } from "./fixture.ts";
import { sessionAdmissionMatrixEntryArgv } from "../../support/prebuilt-entry.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RESULT_PREFIX = '{"v":1,"kind":"runfree-internal-session-admission-matrix"';
const CAPTURE_MAX_BYTES = 8 * 1024 * 1024;

export type NominalAdmissionSliceInput = Readonly<{
  fixture: LiveFixture;
  backend: LiveRuntimeBackend;
  agent: SessionAdmissionProbeAgent;
  /** Whether the slice is required to pass or required to fail closed. */
  expect: "success" | "failure";
  repetitions?: number;
}>;

export type NominalAdmissionSliceOutcome = Readonly<{
  status: number;
  output: string;
  /** Present only for a slice that succeeded and emitted its labelled result. */
  result?: SessionAdmissionMatrixResult;
}>;

function repetitionsFromEnv(): number {
  const configured = process.env.TEST_RUNTIME_SESSION_ADMISSION_REPEAT;
  if (configured === undefined) return 1;
  if (!/^[1-9][0-9]*$/u.test(configured)) {
    throw new Error("TEST_RUNTIME_SESSION_ADMISSION_REPEAT must be a positive integer");
  }
  return Number(configured);
}

export function runNominalAdmissionSlice(input: NominalAdmissionSliceInput): NominalAdmissionSliceOutcome {
  const result = childProcess.spawnSync(
    process.execPath,
    [
      ...sessionAdmissionMatrixEntryArgv(),
      "--workspace",
      input.fixture.projectRoot,
      "--backend",
      input.backend,
      "--agent",
      input.agent,
      "--repeat",
      String(input.repetitions ?? repetitionsFromEnv()),
    ],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: input.fixture.env,
      maxBuffer: CAPTURE_MAX_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  if (result.error) throw result.error;
  const stdout = typeof result.stdout === "string" ? result.stdout : "";
  const stderr = typeof result.stderr === "string" ? result.stderr : "";
  const output = `${stdout}${stderr}`;
  const status = result.status ?? 1;

  if (input.expect === "failure") {
    if (status === 0) {
      throw new Error(
        `session admission slice for ${input.agent} was expected to fail closed and passed instead: ${describeOutput(output, 4000)}`,
      );
    }
    return Object.freeze({ status, output });
  }

  if (status !== 0) {
    // The causal failure is in the tranche's own output; a cleanup success
    // afterwards must not be what the maintainer reads first.
    throw new Error(
      `session admission slice failed closed for ${input.agent} (exit ${status}): ${describeOutput(output, 4000)}`,
    );
  }
  const line = stdout.split("\n").find((candidate) => candidate.startsWith(RESULT_PREFIX));
  if (!line) {
    throw new Error(`session admission slice emitted no labelled result for ${input.agent}: ${describeOutput(stdout)}`);
  }
  const matrixResult = JSON.parse(line) as SessionAdmissionMatrixResult;
  assertNominalSliceResult(input, matrixResult);
  return Object.freeze({ status, output, result: matrixResult });
}

/**
 * What a successful slice must report, beyond exiting zero.
 *
 * Every check here failed the retired nominal tranche and would otherwise be
 * unasserted anywhere: an exit code alone cannot distinguish "admitted, proved
 * and revoked one session" from "did nothing and said so politely".
 */
function assertNominalSliceResult(input: NominalAdmissionSliceInput, result: SessionAdmissionMatrixResult): void {
  const expectedRuns = input.repetitions ?? repetitionsFromEnv();
  const failures: string[] = [];
  const check = (condition: boolean, detail: string): void => { if (!condition) failures.push(detail); };

  // The label is load-bearing documentation, not decoration: it records that
  // this is the nominal tranche and not the full Item 4 gate.
  check(result.gateScope === "nominal-paired-provisioning-tranche", `gateScope was ${result.gateScope}`);
  // Attribution: a result that silently ran on the other backend is not
  // evidence for this one.
  check(result.backend.detected === input.backend, `ran on backend ${result.backend.detected}, not ${input.backend}`);
  check(
    result.configuration.agents.length === 1 && result.configuration.agents[0] === input.agent,
    `configured agents were ${JSON.stringify(result.configuration.agents)}, not [${input.agent}]`,
  );
  check(
    result.observedProbeOutcomes.completedProbeRuns === expectedRuns,
    `completed ${result.observedProbeOutcomes.completedProbeRuns} probe runs, expected ${expectedRuns}`,
  );
  check(result.observedProbeOutcomes.lifecycleRegistryEmpty, "the lifecycle registry was left non-empty");
  check(result.observedProbeOutcomes.sessionContainersAbsent, "session containers were left behind");

  const aggregate = result.aggregates.length === 1 ? result.aggregates[0] : undefined;
  if (!aggregate) {
    failures.push(`reported ${result.aggregates.length} aggregates, expected exactly 1`);
  } else {
    check(aggregate.agent === input.agent, `aggregate names agent ${aggregate.agent}, not ${input.agent}`);
    check(aggregate.samples === expectedRuns, `aggregate has ${aggregate.samples} samples, expected ${expectedRuns}`);
    // Zero would mean the phase was never measured, not that it was instant.
    check(aggregate.provisioningToSequenceMs.p50 > 0, "provisioning-to-sequence p50 was not measured");
    check(aggregate.dockerOperations.p50 > 0, "docker-operation p50 was not measured");
  }

  if (failures.length) {
    throw new Error(`session admission slice for ${input.agent} exited 0 but reported: ${failures.join("; ")}`);
  }
}
