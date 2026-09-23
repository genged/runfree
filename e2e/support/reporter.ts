import fs from "node:fs";
import path from "node:path";

import type { Reporter } from "vitest/reporters";

import {
  SCENARIO_META_KEY,
  validateScenarioMetadata,
  type ScenarioMetadata,
} from "./evidence-contract.ts";
import { BLOCKED_WORK, PROGRAM_SCENARIOS, validateProgramScenarios } from "./scenario-program.ts";

type ReporterTestCase = Parameters<NonNullable<Reporter["onTestCaseResult"]>>[0];

export type EvidenceRecord = Readonly<{
  test: string;
  file: string;
  status: string;
  durationMs?: number;
  scenario: ScenarioMetadata;
}>;

export function buildEvidenceReport(records: readonly EvidenceRecord[]): object {
  const scenarioTests = Object.fromEntries(PROGRAM_SCENARIOS.map(({ id }) => [
    id,
    records
      .filter((record) => record.scenario.scenarioIds.includes(id))
      .map(({ file, test, status }) => ({ file, test, result: status })),
  ]));
  return {
    version: 2,
    scenarios: PROGRAM_SCENARIOS.map((scenario) => ({ ...scenario, tests: scenarioTests[scenario.id] })),
    blockedWork: BLOCKED_WORK,
    tests: records,
  };
}

export default class E2EEvidenceReporter implements Reporter {
  private records: EvidenceRecord[] = [];

  onTestRunStart(): void {
    this.records = [];
    validateProgramScenarios();
  }

  onTestCaseResult(testCase: ReporterTestCase): void {
    const file = path.relative(process.cwd(), testCase.module.moduleId);
    if (!file.startsWith(`e2e${path.sep}`)) return;
    const scenario = validateScenarioMetadata(testCase.meta().runfreeScenario ?? testCase.meta()[SCENARIO_META_KEY]);
    const status = testCase.result().state;
    const record = Object.freeze({
      test: testCase.fullName,
      file,
      status,
      durationMs: testCase.diagnostic()?.duration,
      scenario,
    });
    this.records.push(record);
    process.stdout.write(
      `evidence: ${scenario.scenarioIds.join(",")} | ${scenario.layer} | ${scenario.implementationStatus} | `
      + `${scenario.evidence.kind} | ${status} | ${testCase.fullName}\n`,
    );
  }

  onTestRunEnd(): void {
    const reportPath = process.env.RUNFREE_E2E_REPORT;
    if (!reportPath) return;
    const absolute = path.resolve(reportPath);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    const temporary = `${absolute}.tmp-${process.pid}`;
    fs.writeFileSync(temporary, `${JSON.stringify(buildEvidenceReport(this.records), null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, absolute);
  }
}
