// Behavior-preservation pins for the extracted typed desired-policy
// transaction (2026-09-02 consolidation, S1/S2). Before the extraction the
// host, service, and credential families each owned a byte-identical copy of
// the transaction and its refusals; they now share one implementation and
// supply their refusal nouns as data. The nouns are read by operators, so this
// file asserts the WHOLE refusal text per family and per layer rather than a
// substring, which is the "error strings unchanged" proof the spec asked for
// explicitly instead of trusting the diff.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import type { DesiredServiceEntry } from "@runfree/runtime-contracts/desired-network-policy";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { projectInfo } from "../config.ts";
import type { CaptureResult, RuntimeContext, RuntimeIO } from "../runtime/types.ts";
import { approveNetworkCandidate } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { mutateDesiredCredential } from "./credential-mutation.ts";
import { mutateDesiredHost, readDesiredHostRules } from "./local-host-mutation.ts";
import { mutateDesiredService } from "./service-mutation.ts";

// One seam per capture: slot 0 is the first capture (T1), slot 1 the re-read
// (T4). Arming slot 1 is how the two post-write refusals are reached.
const seams = vi.hoisted(() => ({
  beforeCapture: [] as (undefined | (() => void))[],
  checkoutFingerprintSuffix: "",
}));

vi.mock("./candidates.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./candidates.ts")>();
  return {
    ...actual,
    captureDesiredPolicyCandidate: (...args: Parameters<typeof actual.captureDesiredPolicyCandidate>) => {
      seams.beforeCapture.shift()?.();
      return actual.captureDesiredPolicyCandidate(...args);
    },
  };
});

vi.mock("./subjects.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./subjects.ts")>();
  return {
    ...actual,
    checkoutFingerprint: (...args: Parameters<typeof actual.checkoutFingerprint>) =>
      `${actual.checkoutFingerprint(...args)}${seams.checkoutFingerprintSuffix}`,
  };
});

const SERVICE_ENTRY: DesiredServiceEntry = {
  revision: 1,
  definitionDigest: `sha256:${"a".repeat(64)}`,
  resolved: { hosts: ["service.example.com"] },
};
const CREDENTIAL = { host: "project.example.com", header: "Authorization", scheme: "bearer" as const };

const PROJECT_POLICY = '{"version":2,"hosts":["project.example.com"]}\n';
const LOCAL_POLICY = '{"version":2,"hosts":["local.example.com"]}\n';
const DRIFT = '{"version":2,"hosts":["agent-drift.example.com"]}\n';

// Both refusals say "review it with", but they point at different commands:
// the missing-base one at `policy review`, the drift one at `policy diff`.
function refusal(subject: string, tail: string, reviewCommand: "diff" | "review", flag: string): string {
  return [
    `${subject} ${tail}`,
    `review it with: runfree policy ${reviewCommand} --${flag}`,
    `approve it with: runfree policy approve --${flag}`,
  ].join("\n");
}

const noApprovedBase = (subject: string, flag: string): string =>
  refusal(subject, "has no approved base", "review", flag);
const outOfTransactionDrift = (subject: string, flag: string): string =>
  refusal(subject, "changed outside a trusted Runfree transaction", "diff", flag);

describe("typed desired-policy transaction refusals", () => {
  let root: string;
  let stateHome: string;
  let context: RuntimeContext;
  let projectPolicyPath: string;
  let localPolicyPath: string;

  const io: RuntimeIO = {
    capture: (): CaptureResult => ({ status: 0, stdout: "", stderr: "" }),
    run: () => 0,
    commandExists: () => true,
    confirm: () => false,
    admin: async () => 0,
  };

  beforeEach(() => {
    seams.beforeCapture = [];
    seams.checkoutFingerprintSuffix = "";
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-transaction-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-desired-transaction-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
    projectPolicyPath = path.join(root, ".runfree", "network-policy.json");
    localPolicyPath = path.join(root, ".runfree", "network-policy.local.json");
    fs.writeFileSync(projectPolicyPath, PROJECT_POLICY);
    fs.writeFileSync(localPolicyPath, LOCAL_POLICY);
    const env = {
      XDG_STATE_HOME: stateHome,
      XDG_CONFIG_HOME: path.join(stateHome, "config"),
      RUNFREE_TEST_FAKE_DOCKER: "1",
      RUNFREE_TEST_HOST_BOOT_ID: "linux:11111111-2222-3333-4444-555555555555",
      RUNFREE_TEST_HOST_PROCESS_START: "linux:12345",
    };
    const project = projectInfo(root, env);
    context = { projectRoot: root, project, runtimeRoot: path.join(root, "runtime"), env };
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  test("refuses agent drift during host binding without overwriting it", async () => {
    await expect(mutateDesiredService(context, io, "project", {
      kind: "enable", id: "example", entry: SERVICE_ENTRY,
    }, { beforeWrite: () => { fs.writeFileSync(projectPolicyPath, DRIFT); return undefined; } }))
      .rejects.toThrow("changed outside a trusted Runfree transaction");
    expect(fs.readFileSync(projectPolicyPath, "utf8")).toBe(DRIFT);
  });

  test("restores host bindings inside the lock when policy verification fails", async () => {
    let values = { OLD_ACCOUNT: "old" } as Record<string, string>;
    await expect(mutateDesiredService(context, io, "project", {
      kind: "enable", id: "example", entry: SERVICE_ENTRY,
    }, {
      beforeWrite: () => {
        const before = { ...values };
        values.NEW_ACCOUNT = "new";
        fs.writeFileSync(projectPolicyPath, DRIFT);
        return () => { values = before; };
      },
    })).rejects.toThrow("changed outside a trusted Runfree transaction");
    expect(values).toEqual({ OLD_ACCOUNT: "old" });
  });

  test("host binding and cleanup see approved snapshots despite opposite-layer drift", async () => {
    const snapshots: unknown[] = [];
    await mutateDesiredService(context, io, "project", {
      kind: "enable", id: "example", entry: SERVICE_ENTRY,
    }, {
      beforeWrite: (before, next) => {
        snapshots.push(before.local, next.local);
        fs.writeFileSync(localPolicyPath, DRIFT);
        return undefined;
      },
    });
    expect(snapshots).toEqual([JSON.parse(LOCAL_POLICY), JSON.parse(LOCAL_POLICY)]);
    expect(fs.readFileSync(localPolicyPath, "utf8")).toBe(DRIFT);
  });

  // Both layers already carry authority, so `readOrApproveAuthorityFreeNetworkBase`
  // cannot auto-approve a scaffold: dropping the selection leaves a real
  // missing-base refusal rather than a silent re-approval.
  function dropApprovals(): void {
    fs.rmSync(context.project.paths.controlApprovalsPath, { force: true });
  }

  function driftProject(): void {
    fs.writeFileSync(projectPolicyPath, DRIFT);
  }

  function driftLocal(): void {
    fs.writeFileSync(localPolicyPath, DRIFT);
  }

  const families: Array<{
    drift: () => void;
    driftSubject: string;
    flag: "local" | "project";
    missingBaseSubject: string;
    name: string;
    run: () => Promise<unknown>;
    writeSubject: string;
  }> = [
    {
      name: "host project",
      flag: "project",
      missingBaseSubject: "project policy",
      driftSubject: "project desired policy",
      writeSubject: "project policy write",
      drift: driftProject,
      run: () => mutateDesiredHost(context, io, "project", { kind: "add", host: "new.example.com" }),
    },
    {
      name: "host local",
      flag: "local",
      missingBaseSubject: "checkout-local policy",
      driftSubject: "local desired policy",
      writeSubject: "local policy write",
      drift: driftLocal,
      run: () => mutateDesiredHost(context, io, "local", { kind: "add", host: "new.example.com" }),
    },
    {
      name: "service project",
      flag: "project",
      missingBaseSubject: "project desired policy",
      driftSubject: "project desired policy",
      writeSubject: "desired service write",
      drift: driftProject,
      run: () => mutateDesiredService(context, io, "project", { kind: "enable", id: "api", entry: SERVICE_ENTRY }),
    },
    {
      name: "service local",
      flag: "local",
      missingBaseSubject: "local desired policy",
      driftSubject: "local desired policy",
      writeSubject: "desired service write",
      drift: driftLocal,
      run: () => mutateDesiredService(context, io, "local", { kind: "enable", id: "api", entry: SERVICE_ENTRY }),
    },
    {
      name: "credential",
      flag: "project",
      missingBaseSubject: "project desired policy",
      driftSubject: "project desired policy",
      writeSubject: "desired credential write",
      drift: driftProject,
      run: () => mutateDesiredCredential(context, io, { kind: "add", name: "example", credential: CREDENTIAL }),
    },
  ];

  for (const family of families) {
    describe(family.name, () => {
      test("refuses a missing approved base with this family's exact text", async () => {
        dropApprovals();

        await expect(family.run()).rejects.toThrow(noApprovedBase(family.missingBaseSubject, family.flag));
      });

      test("refuses out-of-transaction drift with this family's exact text", async () => {
        family.drift();

        await expect(family.run()).rejects.toThrow(outOfTransactionDrift(family.driftSubject, family.flag));
      });

      test("names this family when the write did not produce the exact planned candidate", async () => {
        // Slot 1 is the re-read: the drift lands after the atomic write.
        seams.beforeCapture = [undefined, family.drift];

        await expect(family.run())
          .rejects.toThrow(`${family.writeSubject} did not produce the exact planned candidate`);
      });
    });
  }

  const transactionNouns = [
    { name: "host", run: () => mutateDesiredHost(context, io, "project", { kind: "add", host: "new.example.com" }) },
    {
      name: "service",
      run: () => mutateDesiredService(context, io, "project", { kind: "enable", id: "api", entry: SERVICE_ENTRY }),
    },
    {
      name: "credential",
      run: () => mutateDesiredCredential(context, io, { kind: "add", name: "example", credential: CREDENTIAL }),
    },
  ];

  for (const family of transactionNouns) {
    test(`names the ${family.name} family when the checkout identity changes mid-transaction`, async () => {
      // Flip after the re-read so the exact-match check still passes and the
      // checkout re-check is the refusal actually reached.
      seams.beforeCapture = [undefined, () => { seams.checkoutFingerprintSuffix = "-moved"; }];

      await expect(family.run()).rejects.toThrow(
        `project checkout identity changed during the typed ${family.name} transaction; desired changes remain pending approval`,
      );
    });
  }

  test("the show-only rules query refuses a missing base without approving a scaffold", async () => {
    // S2's opt-in polarity: only the mutation paths auto-approve an
    // authority-free scaffold, so a lookup can never persist authority.
    dropApprovals();
    fs.writeFileSync(projectPolicyPath, '{"version":2,"hosts":[]}\n');

    await expect(readDesiredHostRules(context, io, "project", "absent.example.com"))
      .rejects.toThrow(noApprovedBase("project policy", "project"));

    expect(fs.existsSync(context.project.paths.controlApprovalsPath)).toBe(false);
  });
});
