import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { defaultConfig, projectInfo } from "../config.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { migrateControlApprovalRecord } from "./approval-migration.ts";
import {
  approveNarrowImageBuildCandidate,
  captureNarrowImageBuildCandidate,
} from "./image-approval.ts";
import { mutateDesiredCredential } from "./credential-mutation.ts";
import { mutateDesiredHost } from "./local-host-mutation.ts";
import { mutateDesiredService } from "./service-mutation.ts";
import { approveNetworkControl, approveRuntimeIsolation } from "./workflow.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
  readControlApprovalSelection,
  readOrApproveAuthorityFreeNetworkBase,
  type ControlApprovalSelection,
  type ControlApprovalSelectionV1,
} from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { observeCheckoutBinding } from "./checkout-binding.ts";
import { checkoutFingerprint } from "./subjects.ts";

let root: string;
let stateHome: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-migration-project-"));
  stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-migration-state-"));
  fs.mkdirSync(path.join(root, ".runfree"));
  fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
});
afterEach(() => {
  fs.rmSync(root, { recursive: true });
  fs.rmSync(stateHome, { recursive: true });
});

function info() {
  return projectInfo(root, { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") });
}

function testEnv(): Record<string, string> {
  return {
    XDG_STATE_HOME: stateHome,
    XDG_CONFIG_HOME: path.join(stateHome, "config"),
    RUNFREE_TEST_FAKE_DOCKER: "1",
    RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
    RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
  };
}

function runtimeContext(): RuntimeContext {
  const env = testEnv();
  return { projectRoot: root, project: projectInfo(root, env), runtimeRoot: path.join(root, "runtime"), env } as RuntimeContext;
}

const io = {
  capture: (_command: string, args: string[]) => args[0] === "ps"
    ? { status: 0, stdout: "", stderr: "" }
    : { status: 1, stdout: "", stderr: "unexpected" },
  run: () => 0,
  commandExists: () => true,
  confirm: () => false,
  admin: async () => 0,
} as unknown as RuntimeIO;

function approveProjectLayer(): ReturnType<typeof info> {
  const project = info();
  const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
  approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
  return project;
}

test("an absent record reports absent and writes nothing", () => {
  const project = info();
  expect(migrateControlApprovalRecord(root, project)).toBe("absent");
  expect(fs.existsSync(project.paths.controlApprovalsPath)).toBe(false);
});

test("a current record is left byte-identical", () => {
  const project = approveProjectLayer();
  const before = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");

  expect(migrateControlApprovalRecord(root, project)).toBe("current");
  expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

test("a mismatched record is not migrated: consent belongs to the recovery gate", () => {
  const project = approveProjectLayer();
  const stored = JSON.parse(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")) as { checkoutBinding: { rootInode: string } };
  stored.checkoutBinding.rootInode = "999999999";
  const mismatched = `${JSON.stringify(stored, null, 2)}\n`;
  fs.writeFileSync(project.paths.controlApprovalsPath, mismatched);

  // Migrating it would silently rebind approvals granted against a different
  // checkout to this one.
  expect(migrateControlApprovalRecord(root, project)).toBe("current");
  expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(mismatched);
});

/**
 * Rewrite the current record as the v1 schema it would have had before the
 * binding change, optionally with a different fingerprint or an extra subject.
 */
function writeV1Record(
  project: ReturnType<typeof info>,
  options: { checkoutFingerprint?: string; withImageSubject?: boolean } = {},
): ControlApprovalSelectionV1 {
  const current = JSON.parse(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")) as ControlApprovalSelection;
  const subjects: Record<string, unknown> = { ...current.subjects };
  if (options.withImageSubject) {
    subjects["image-build"] = {
      approvedAt: "2026-09-01T00:00:00.000Z",
      digest: `sha256:${"e".repeat(64)}`,
      mechanism: "typed-host-command",
    };
  }
  const v1 = {
    schemaVersion: 1,
    projectId: current.projectId,
    checkoutFingerprint: options.checkoutFingerprint ?? checkoutFingerprint(root),
    configVersion: current.configVersion,
    subjects,
  } as ControlApprovalSelectionV1;
  fs.writeFileSync(project.paths.controlApprovalsPath, `${JSON.stringify(v1, null, 2)}\n`);
  return v1;
}

test("a matching v1 record migrates silently, preserving digests, mechanisms and timestamps", () => {
  const project = approveProjectLayer();
  const v1 = writeV1Record(project);

  expect(migrateControlApprovalRecord(root, project)).toBe("migrated");

  const after = JSON.parse(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")) as ControlApprovalSelection;
  expect(after.schemaVersion).toBe(2);
  expect(after.checkoutBinding).toEqual(observeCheckoutBinding(root));
  // The old binding proves continuity under its own contract, so no prompt and
  // no re-approval: the same consent, re-expressed.
  expect(after.subjects).toEqual(v1.subjects);
  expect(readControlApprovalSelection(root, project)?.subjects["network-project"]?.digest)
    .toBe(v1.subjects["network-project"]?.digest);
});

// A nonmatching v1 record is reported `superseded`, not `unmigratable`: it is
// well-formed and carries no authority, which is the recovery gate's case, not
// a refusal. Reporting it as unmigratable is what left rebooted projects with
// no command that could clear the state.
test("migration never enumerates device numbers: a nonmatching v1 record stays put for recovery", () => {
  const project = approveProjectLayer();
  writeV1Record(project, { checkoutFingerprint: `sha256:${"e".repeat(64)}` });
  const before = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");

  expect(migrateControlApprovalRecord(root, project)).toBe("superseded");
  expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

test("a v1 record whose project scope moved is superseded, never migrated into this scope", () => {
  const project = approveProjectLayer();
  const v1 = writeV1Record(project);
  fs.writeFileSync(
    project.paths.controlApprovalsPath,
    `${JSON.stringify({ ...v1, projectId: "ffffffffffff" }, null, 2)}\n`,
  );

  expect(migrateControlApprovalRecord(root, project)).toBe("superseded");
});

test("a corrupt subject snapshot blocks whole-selection migration and is never dropped", () => {
  const project = approveProjectLayer();
  // An image subject whose snapshot was never published: verification fails,
  // and migration must not quietly drop it while reporting success.
  writeV1Record(project, { withImageSubject: true });
  const before = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");

  expect(migrateControlApprovalRecord(root, project)).toBe("unmigratable");
  expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(before);
});

test("a v1 record reached outside the funnel refuses in the writer and keeps every subject", () => {
  const project = approveProjectLayer();
  writeV1Record(project, { withImageSubject: true });

  expect(() => approveRuntimeIsolationControl(root, project, "interactive"))
    .toThrow("predate this version of runfree");

  const after = JSON.parse(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")) as { subjects: Record<string, unknown> };
  expect(after.subjects["image-build"]).toBeDefined();
  expect(after.subjects["network-project"]).toBeDefined();
});

test("a corrupt record is reported unmigratable and never overwritten", () => {
  const project = approveProjectLayer();
  const garbage = `{"schemaVersion":1,"subjects":\n`;
  fs.writeFileSync(project.paths.controlApprovalsPath, garbage);

  expect(migrateControlApprovalRecord(root, project)).toBe("unmigratable");
  expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(garbage);
});

// Every approvals writer reached without crossing the launch path. Each either
// migrates the v1 record first or refuses; none may discard another subject's
// approval on the way. The families below share one transaction, so the point
// of listing them is that each family's entry really does reach it.
describe("writers reached outside the launch path", () => {
  /** A v1 record carrying two subjects, so a discard is visible. */
  function v1ProjectWithTwoSubjects(): ReturnType<typeof info> {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    approveRuntimeIsolationControl(root, project, "interactive");
    writeV1Record(project);
    return project;
  }

  function storedSubjects(project: ReturnType<typeof info>): ControlApprovalSelection {
    return JSON.parse(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")) as ControlApprovalSelection;
  }

  const families: Array<{ name: string; run: (context: RuntimeContext) => Promise<unknown> }> = [
    {
      name: "host add",
      run: (context) => mutateDesiredHost(context, io, "project", { kind: "add", host: "added.example.com" }),
    },
    {
      name: "credential add",
      run: (context) => mutateDesiredCredential(context, io, {
        kind: "add",
        name: "example",
        credential: { host: "example.com", header: "Authorization", scheme: "bearer" },
      }),
    },
    {
      name: "control approve runtime-isolation",
      run: (context) => approveRuntimeIsolation(context, io, { mechanism: "digest-command" }),
    },
    {
      // `policy approve`'s writer. Its handler also crosses the recovery gate
      // first, which is what renders the review under a mismatch; that wiring
      // is covered in `runtime/launch-approval-gate.test.ts` and
      // `control/approval-recovery.test.ts`. What this family asserts is the
      // T11 claim about the writer itself.
      name: "policy approve --project",
      run: (context) => approveNetworkControl(context, io, "network-project", { mechanism: "digest-command" }),
    },
  ];

  for (const family of families) {
    test(`${family.name} migrates the v1 record and keeps every other subject`, async () => {
      const project = v1ProjectWithTwoSubjects();
      const before = storedSubjects(project);

      await family.run(runtimeContext());

      const after = storedSubjects(project);
      expect(after.schemaVersion).toBe(2);
      expect(after.subjects["runtime-isolation"]?.digest).toBe(before.subjects["runtime-isolation"]?.digest);
      expect(after.subjects["network-project"]).toBeDefined();
    });
  }

  // `runfree image approve-context` writes the record without crossing either
  // the funnel or the gate, so it is the writer refusal's real caller.
  test("image approve-context refuses a v1 record rather than overwriting it", () => {
    const project = v1ProjectWithTwoSubjects();
    const before = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");
    const imageDir = path.join(root, ".runfree", "image");
    fs.mkdirSync(imageDir);
    fs.writeFileSync(path.join(imageDir, "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
    const build = { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" };
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);

    expect(() => approveNarrowImageBuildCandidate(root, project, candidate, "typed-host-command"))
      .toThrow("migrate them with: runfree up");
    expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(before);
  });

  // The other empty substitution: a service mutation falls back to an empty
  // approved policy when a layer is genuinely absent. A record that carries no
  // authority is not absent, and planning against an empty baseline under one
  // would not say so.
  test("a service mutation on a record that carries no authority refuses the empty baseline", async () => {
    const project = v1ProjectWithTwoSubjects();
    writeV1Record(project, { checkoutFingerprint: `sha256:${"e".repeat(64)}` });

    await expect(mutateDesiredService(runtimeContext(), io, "project", {
      kind: "enable",
      id: "api",
      entry: { revision: 1, definitionDigest: `sha256:${"a".repeat(64)}`, resolved: { hosts: ["api.example.com"] } },
    })).rejects.toThrow("predate this version of runfree");
  });

  // The auto-reduction path substitutes an approval for an authority-free
  // layer. On a record that carries no authority it must refuse instead, or a
  // v1 project with an empty layer would be silently auto-approved into a fresh
  // record that no longer carries the subjects the old one did.
  for (const fingerprint of [undefined, `sha256:${"e".repeat(64)}`]) {
    test(`an empty layer is not auto-approved over a ${fingerprint ? "superseded" : "v1"} record`, () => {
      const project = v1ProjectWithTwoSubjects();
      if (fingerprint) writeV1Record(project, { checkoutFingerprint: fingerprint });
      const before = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");
      const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);

      expect(() => readOrApproveAuthorityFreeNetworkBase(root, project, candidate, "network-local"))
        .toThrow("predate this version of runfree");
      expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(before);
    });
  }
});

// The funnel, end to end. `runfree service enable` never reaches startup, so if
// migration lived on the launch path this mutation would meet a v1 record and
// either refuse or drop the other subjects.
test("a typed mutation on a v1 project migrates first and keeps every other subject", async () => {
  const env = testEnv();
  const imageDir = path.join(root, ".runfree", "image");
  fs.mkdirSync(imageDir);
  fs.writeFileSync(path.join(imageDir, "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\n");
  fs.writeFileSync(
    path.join(root, ".runfree", "runfree.json"),
    `${JSON.stringify({
      ...defaultConfig(),
      runtime: {
        ...defaultConfig().runtime,
        agent: { build: { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" } },
      },
    }, null, 2)}\n`,
  );
  const project = projectInfo(root, env);
  const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
  approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
  approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
  const build = { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" };
  const imageCandidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
  approveNarrowImageBuildCandidate(root, project, imageCandidate, "typed-host-command");

  const imageDigest = readControlApprovalSelection(root, project)?.subjects["image-build"]?.digest;
  expect(imageDigest).toBeDefined();
  writeV1Record(project);

  await mutateDesiredService(runtimeContext(), io, "project", {
    kind: "enable",
    id: "api",
    entry: {
      revision: 1,
      definitionDigest: `sha256:${"a".repeat(64)}`,
      resolved: { hosts: ["api.example.com"] },
    },
  });

  const after = JSON.parse(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")) as ControlApprovalSelection;
  expect(after.schemaVersion).toBe(2);
  expect(after.subjects["image-build"]?.digest).toBe(imageDigest);
  // The mutation's own layer moved; nothing else did.
  expect(after.subjects["network-local"]?.digest).toBe(candidate.localSubject.digest);
});
