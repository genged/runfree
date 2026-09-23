import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { projectInfo } from "../config.ts";
import { captureDesiredPolicyCandidate, verifyDesiredPolicyCandidate } from "./candidates.ts";
import {
  approveNetworkCandidate,
  approveRuntimeIsolationControl,
  approvalSetDigest,
  publishNetworkSnapshot,
  publishRuntimeSnapshot,
  readApprovedNetworkPolicy,
  readControlApprovalRecord,
  readControlApprovalSelection,
  readApprovedRuntimeIsolation,
  selectSubjectApprovals,
} from "./approvals.ts";
import { runtimeIsolationControlSubject } from "./subjects.ts";

describe("control approvals", () => {
  let root: string;
  let stateHome: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approval-project-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-approval-state-"));
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

  test("selects only an exact, verified approved subject snapshot", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const selection = approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    expect(readApprovedNetworkPolicy(root, project, "network-project")?.hosts).toEqual(["example.com"]);
    expect(readApprovedNetworkPolicy(root, project, "network-local")).toBeUndefined();
    expect(approvalSetDigest(selection)).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  test("stores runtime isolation independently of network authority", () => {
    const project = info();
    const selection = approveRuntimeIsolationControl(root, project, "digest-command");
    expect(selection.subjects["network-project"]).toBeUndefined();
    expect(readApprovedRuntimeIsolation(root, project)).toEqual({
      subnet: "generated",
      proxyIp: "generated",
      agentIp: "generated",
      dependencyOverlays: "auto",
      writeApprovalHoldSeconds: 120,
    });
  });

  test("rejects approved snapshot corruption", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const selection = approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    const digest = selection.subjects["network-project"]?.digest.slice("sha256:".length) ?? "";
    const policyPath = path.join(project.paths.controlApprovedDir, "network-project", digest, "network-policy.json");
    fs.chmodSync(policyPath, 0o600);
    fs.writeFileSync(policyPath, `{"version":2,"hosts":[]}\n`);
    expect(() => readApprovedNetworkPolicy(root, project, "network-project")).toThrow("wrong subject digest");
  });

  test("tampered approved policy bytes fail the digest recompute", () => {
    // The stored subject/manifest copies are gone; the surviving proof is the
    // digest recompute over the canonical policy bytes. A byte-level tamper
    // that still parses to the same policy set must be refused too.
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const selection = approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    const digest = selection.subjects["network-project"]?.digest.slice("sha256:".length) ?? "";
    const policyPath = path.join(project.paths.controlApprovedDir, "network-project", digest, "network-policy.json");
    fs.chmodSync(policyPath, 0o600);
    // Same parsed content, different bytes (extra trailing newline): the exact
    // canonical-bytes check refuses it even though the subject digest matches.
    fs.appendFileSync(policyPath, "\n");
    expect(() => readApprovedNetworkPolicy(root, project, "network-project")).toThrow("payload hash is corrupt");
  });

  test("approval directories written by older releases (extra subject/manifest files) still verify", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const selection = approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    const digest = selection.subjects["network-project"]?.digest.slice("sha256:".length) ?? "";
    const directory = path.join(project.paths.controlApprovedDir, "network-project", digest);
    // Simulate the pre-slim store: older releases also wrote subject.json and
    // manifest.json beside the policy. The verifier must ignore them.
    fs.writeFileSync(path.join(directory, "subject.json"), "{}\n", { mode: 0o400 });
    fs.writeFileSync(path.join(directory, "manifest.json"), "{}\n", { mode: 0o400 });
    expect(readApprovedNetworkPolicy(root, project, "network-project")?.hosts).toEqual(["example.com"]);

    const isolation = approveRuntimeIsolationControl(root, project, "digest-command");
    const isolationDigest = isolation.subjects["runtime-isolation"]?.digest.slice("sha256:".length) ?? "";
    fs.writeFileSync(
      path.join(project.paths.controlApprovedDir, "runtime-isolation", isolationDigest, "manifest.json"),
      "{}\n",
      { mode: 0o400 },
    );
    expect(readApprovedRuntimeIsolation(root, project)).toBeDefined();
  });

  // The old root is kept alive throughout, so inode reuse cannot make this pass
  // by accident, and the fixture root is inside the temp filesystem rather than
  // being a mount root, so it cannot pass through the layout exemption either.
  test("a replaced root inode copies the record aside and never merges its subjects", () => {
    let project = info();
    const first = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, first, "network-project", "interactive");
    approveRuntimeIsolationControl(root, project, "interactive");
    const superseded = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");

    const moved = `${root}-old`;
    fs.renameSync(root, moved);
    fs.mkdirSync(root);
    fs.mkdirSync(path.join(root, ".runfree"));
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    project = info();
    const replacement = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const selection = approveNetworkCandidate(root, project, replacement, "network-project", "interactive");

    // The new selection starts from an empty subject set: the runtime-isolation
    // approval was granted against a different binding and is not carried over.
    expect(Object.keys(selection.subjects)).toEqual(["network-project"]);
    expect(selection.subjects["runtime-isolation"]).toBeUndefined();
    expect(readControlApprovalSelection(root, project)?.subjects["network-project"]?.digest)
      .toBe(replacement.projectSubject.digest);

    // The evidence is copied, not renamed: the live selector still exists and
    // the superseded bytes are recoverable.
    expect(fs.readdirSync(project.paths.controlDir).some((name) => name.startsWith("approvals.json.quarantined-"))).toBe(false);
    const copies = fs.readdirSync(project.paths.controlDir)
      .filter((name) => name.startsWith("approvals.json.superseded-"));
    expect(copies).toHaveLength(1);
    expect(fs.readFileSync(path.join(project.paths.controlDir, copies[0]), "utf8")).toBe(superseded);

    fs.rmSync(moved, { recursive: true });
  });

  // The other half of the replacement tripwire: the directory is untouched and
  // the path is untouched, but the path resolves somewhere else. Both targets
  // stay alive for the whole test, so neither inode reuse nor a vanished target
  // can make it pass by accident.
  test("a retargeted project-root symlink refuses the old authority at the same path", () => {
    const targets = ["checkout-a", "checkout-b"].map((name) => {
      const target = path.join(root, name);
      fs.mkdirSync(path.join(target, ".runfree"), { recursive: true });
      fs.writeFileSync(path.join(target, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
      return target;
    });
    const link = path.join(root, "checkout");
    fs.symlinkSync(targets[0], link);
    const linked = () => projectInfo(link, { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") });

    let project = linked();
    const first = captureDesiredPolicyCandidate(link, project.paths.controlCandidatesDir);
    approveNetworkCandidate(link, project, first, "network-project", "interactive");
    approveRuntimeIsolationControl(link, project, "interactive");
    expect(readControlApprovalRecord(link, project).kind).toBe("valid");

    fs.unlinkSync(link);
    fs.symlinkSync(targets[1], link);
    project = linked();

    // The record is still the same file — `projectHash` hashes the path, which
    // did not move — so this is a read of the old authority, not a fresh one.
    expect(readControlApprovalRecord(link, project))
      .toMatchObject({ kind: "mismatch", reason: "resolved-root" });
    const replacement = captureDesiredPolicyCandidate(link, project.paths.controlCandidatesDir);
    const selection = approveNetworkCandidate(link, project, replacement, "network-project", "interactive");
    expect(Object.keys(selection.subjects)).toEqual(["network-project"]);

    expect(fs.existsSync(path.join(targets[0], ".runfree"))).toBe(true);
    expect(fs.readdirSync(project.paths.controlDir)
      .filter((name) => name.startsWith("approvals.json.superseded-"))).toHaveLength(1);
  });

  test("a corrupt record refuses in the writer and is left byte-identical", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");

    const garbage = `{"schemaVersion":1,"subjects":\n`;
    fs.writeFileSync(project.paths.controlApprovalsPath, garbage);

    expect(() => approveNetworkCandidate(root, project, candidate, "network-local", "interactive"))
      .toThrow("could not be read");
    expect(fs.readFileSync(project.paths.controlApprovalsPath, "utf8")).toBe(garbage);
    expect(fs.readdirSync(project.paths.controlDir).some((name) => name.includes(".superseded-"))).toBe(false);
  });

  test("one consent writes every configuration subject in a single replacement", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const runtimeSubject = runtimeIsolationControlSubject(project.config);
    const now = new Date("2026-09-16T00:00:00.000Z");

    verifyDesiredPolicyCandidate(candidate);
    publishNetworkSnapshot(project, candidate.projectSubject, candidate.project);
    publishNetworkSnapshot(project, candidate.localSubject, candidate.local);
    publishRuntimeSnapshot(project, runtimeSubject);
    const selection = selectSubjectApprovals(
      root,
      project,
      [candidate.projectSubject, candidate.localSubject, runtimeSubject],
      "interactive",
      now,
    );

    expect(Object.keys(selection.subjects).sort())
      .toEqual(["network-local", "network-project", "runtime-isolation"]);
    for (const record of Object.values(selection.subjects)) {
      expect(record?.approvedAt).toBe(now.toISOString());
    }
    expect(readApprovedNetworkPolicy(root, project, "network-project")?.hosts).toEqual(["example.com"]);
    expect(readApprovedRuntimeIsolation(root, project)).toBeDefined();
  });

  test("a write whose on-disk bytes changed since the read refuses", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    const original = fs.readFileSync(project.paths.controlApprovalsPath, "utf8");

    expect(() => selectSubjectApprovals(
      root,
      project,
      [candidate.localSubject],
      "interactive",
      new Date(),
      // A concurrent writer landing between the read and the replacement. The
      // lost update it would otherwise cause is a record built from a subject
      // set this caller never saw.
      { afterRead: () => fs.writeFileSync(project.paths.controlApprovalsPath, original.replace("interactive", "digest-command")) },
    )).toThrow("changed while it was being approved");

    expect(readControlApprovalSelection(root, project)?.subjects["network-project"]?.mechanism).toBe("digest-command");
    expect(readControlApprovalSelection(root, project)?.subjects["network-local"]).toBeUndefined();
  });

  test("the reclamation path for a corrupt record is removing it and re-approving", () => {
    const project = info();
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    fs.writeFileSync(project.paths.controlApprovalsPath, `{"schemaVersion":1,\n`);

    fs.rmSync(project.paths.controlApprovalsPath);
    const selection = approveNetworkCandidate(root, project, candidate, "network-project", "interactive");

    expect(selection.subjects["network-project"]?.digest).toBe(candidate.projectSubject.digest);
  });
});
