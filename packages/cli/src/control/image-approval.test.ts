import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { selectedProjectAgentImageInput } from "../agent-image.ts";
import type { AgentBuildConfig } from "../config.ts";
import { projectInfo } from "../config.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import {
  approveNarrowImageBuildCandidate,
  describeNarrowImageBuildCandidate,
  narrowImageBuildApprovalPrompt,
  approvedNarrowImageBuildForManifest,
  captureNarrowImageBuildCandidate,
  readApprovedNarrowImageBuild,
} from "./image-approval.ts";
import {
  approveNetworkCandidate,
  approvedSubjectDirectory,
  readControlApprovalSelection,
  selectSubjectApproval,
} from "./approvals.ts";
import { controlDigest } from "./subjects.ts";

describe("narrow project image approval", () => {
  let root: string;
  let stateHome: string;
  let build: AgentBuildConfig;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-image-approval-project-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-image-approval-state-"));
    const imageDir = path.join(root, ".runfree", "image");
    fs.mkdirSync(path.join(imageDir, "scripts"), { recursive: true });
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    fs.writeFileSync(path.join(imageDir, "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\nRUN scripts/setup.sh\n");
    fs.writeFileSync(path.join(imageDir, "scripts", "setup.sh"), "#!/bin/sh\necho setup\n", { mode: 0o755 });
    fs.chmodSync(path.join(imageDir, "scripts", "setup.sh"), 0o755);
    build = { context: ".runfree/image", dockerfile: ".runfree/image/Dockerfile" };
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(stateHome, { recursive: true, force: true });
  });

  function info() {
    return projectInfo(root, { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") });
  }

  test("the approval prompt shows the content of the decision: files, Dockerfile, first-approval marker", () => {
    const project = info();
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);

    const prompt = narrowImageBuildApprovalPrompt(candidate, undefined, { projectRoot: root });

    expect(prompt).toContain("First image-build approval for this project.");
    expect(prompt).toContain("Docker build runs before the Runfree sandbox and can execute files or send them over the network.");
    expect(prompt).toMatch(/Staged files \(2, 1 directories\):/);
    expect(prompt).toMatch(/  Dockerfile  \d+ B  sha256:[0-9a-f]{12}/);
    expect(prompt).toMatch(/  scripts\/setup\.sh  \d+ B  sha256:[0-9a-f]{12}/);
    expect(prompt).toContain("Dockerfile (.runfree/image/Dockerfile):");
    expect(prompt).toContain("  RUN scripts/setup.sh");
    // The digest prints once, as the record id, after the content.
    expect(prompt.split(candidate.subject.digest)).toHaveLength(2);
    expect(prompt).toContain(`approval record id: ${candidate.subject.digest}`);
    expect(prompt.trimEnd().endsWith("Approve this build input for this checkout? [y/N]")).toBe(true);
  });

  test("a changed candidate prompts with the diff against the approved snapshot", () => {
    const project = info();
    const first = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    approveNarrowImageBuildCandidate(root, project, first, "typed-host-command");
    const previous = readApprovedNarrowImageBuild(root, project);
    expect(previous).toBeDefined();

    fs.writeFileSync(path.join(root, ".runfree", "image", "Dockerfile"), "ARG RUNFREE_BASE_IMAGE\nFROM ${RUNFREE_BASE_IMAGE}\nRUN scripts/setup.sh\nRUN apt-get install -y jq\n");
    fs.writeFileSync(path.join(root, ".runfree", "image", "scripts", "extra.sh"), "#!/bin/sh\n", { mode: 0o755 });
    fs.rmSync(path.join(root, ".runfree", "image", "scripts", "setup.sh"));
    const changed = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);

    const lines = describeNarrowImageBuildCandidate(changed, previous, { projectRoot: root });
    const text = lines.join("\n");
    expect(text).toContain("Changed since the approved build (sha256:");
    expect(text).toContain("  + scripts/extra.sh");
    expect(text).toContain("  - scripts/setup.sh");
    expect(text).toContain("  ~ Dockerfile");
    expect(text).toContain("Dockerfile diff (.runfree/image/Dockerfile):");
    expect(text).toContain("  + RUN apt-get install -y jq");
    expect(text).not.toContain("First image-build approval");
    expect(narrowImageBuildApprovalPrompt(changed, previous)).toContain("Approve this changed build input for this checkout? [y/N]");
  });

  test("a long Dockerfile is truncated with an explicit marker and the full-file path", () => {
    const project = info();
    const long = Array.from({ length: 60 }, (_, index) => `RUN echo line-${index}`).join("\n");
    fs.writeFileSync(path.join(root, ".runfree", "image", "Dockerfile"), `ARG RUNFREE_BASE_IMAGE\nFROM \${RUNFREE_BASE_IMAGE}\n${long}\n`);
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);

    const text = describeNarrowImageBuildCandidate(candidate, undefined, { projectRoot: root }).join("\n");
    expect(text).toContain("  RUN echo line-37");
    expect(text).not.toContain("RUN echo line-38");
    expect(text).toMatch(/… truncated \(\d+ more lines\) — full file: \.runfree\/image\/Dockerfile/);
  });

  test("persists and selects the exact staged manifest outside the project", () => {
    const project = info();
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    const originalScript = fs.readFileSync(path.join(candidate.contextPath, "scripts", "setup.sh"), "utf8");

    const { approved, selection } = approveNarrowImageBuildCandidate(
      root,
      project,
      candidate,
      "typed-host-command",
      new Date("2026-08-05T12:00:00.000Z"),
    );
    fs.writeFileSync(path.join(root, ".runfree", "image", "scripts", "setup.sh"), "#!/bin/sh\necho drifted\n");

    expect(selection.subjects["image-build"]?.digest).toBe(candidate.subject.digest);
    expect(approved.directory.startsWith(project.paths.controlApprovedDir)).toBe(true);
    expect(approved.directory.startsWith(root)).toBe(false);
    expect(fs.readFileSync(path.join(approved.contextPath, "scripts", "setup.sh"), "utf8")).toBe(originalScript);
    expect(readApprovedNarrowImageBuild(root, project)?.inputDigest).toBe(candidate.inputDigest);
  });

  test("invalidates approval for file bytes, mode, added input, and normalized build config", () => {
    const project = info();
    const first = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    approveNarrowImageBuildCandidate(root, project, first, "interactive");

    const script = path.join(root, ".runfree", "image", "scripts", "setup.sh");
    fs.appendFileSync(script, "echo changed\n");
    const changedBytes = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    expect(changedBytes.subject.digest).not.toBe(first.subject.digest);
    expect(approvedNarrowImageBuildForManifest(root, project, { build: changedBytes.build, contextManifest: changedBytes.manifest })).toBeUndefined();

    fs.chmodSync(script, 0o700);
    const changedMode = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    expect(changedMode.subject.digest).not.toBe(changedBytes.subject.digest);

    fs.writeFileSync(path.join(root, ".runfree", "image", "new-input.txt"), "copied input\n");
    const addedInput = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    expect(addedInput.subject.digest).not.toBe(changedMode.subject.digest);

    const changedBuild = captureNarrowImageBuildCandidate(root, { ...build, target: "release" }, project.paths.controlCandidatesDir);
    expect(changedBuild.subject.digest).not.toBe(addedInput.subject.digest);
  });

  test("rejects candidate tampering before publishing approval state", () => {
    const project = info();
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    fs.writeFileSync(path.join(candidate.contextPath, "scripts", "setup.sh"), "#!/bin/sh\nleak source\n");

    expect(() => approveNarrowImageBuildCandidate(root, project, candidate, "interactive"))
      .toThrow("staged context does not match");
    expect(fs.existsSync(project.paths.controlApprovalsPath)).toBe(false);
    expect(fs.existsSync(path.join(project.paths.controlApprovedDir, "image-build"))).toBe(false);
  });

  test("rejects approved context corruption instead of rebuilding from desired bytes", () => {
    const project = info();
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    const { approved } = approveNarrowImageBuildCandidate(root, project, candidate, "interactive");
    fs.writeFileSync(path.join(approved.contextPath, "scripts", "setup.sh"), "#!/bin/sh\nchanged after approval\n");

    expect(() => readApprovedNarrowImageBuild(root, project)).toThrow("staged context does not match");
  });

  test("approval subject covers only project-controlled inputs; runtime identity moves the input digest alone", () => {
    const project = info();
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    expect(Object.keys(candidate.subject.payload).sort()).toEqual([
      "build",
      "contextKind",
      "contextManifest",
      "schemaVersion",
      "subjectType",
    ]);

    const dockerfile = fs.readFileSync(path.join(candidate.contextPath, "Dockerfile"));
    const before = selectedProjectAgentImageInput(candidate.build, "narrow", candidate.manifest, dockerfile, {
      embeddedAgentImageInputDigest: `sha256:${"1".repeat(64)}`,
    });
    const after = selectedProjectAgentImageInput(candidate.build, "narrow", candidate.manifest, dockerfile, {
      embeddedAgentImageInputDigest: `sha256:${"2".repeat(64)}`,
    });
    expect(before.digest).not.toBe(after.digest);
  });

  test("stale pre-split approval record reads as unapproved instead of failing verification", () => {
    const project = info();
    const candidate = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    const legacyPayload = {
      schemaVersion: 1,
      subjectType: "image-build" as const,
      runtimeDigest: `sha256:${"c".repeat(64)}`,
      build: candidate.build,
      contextKind: "narrow",
      contextManifest: candidate.manifest,
    };
    const legacySubject = {
      digest: controlDigest(legacyPayload),
      payload: legacyPayload as Record<string, unknown>,
      subjectType: "image-build" as const,
    };
    const legacyDirectory = approvedSubjectDirectory(project, "image-build", legacySubject.digest);
    fs.mkdirSync(legacyDirectory, { recursive: true });
    fs.cpSync(candidate.contextPath, path.join(legacyDirectory, "context"), { recursive: true });
    fs.writeFileSync(path.join(legacyDirectory, "subject.json"), `${JSON.stringify(legacyPayload, null, 2)}\n`);
    selectSubjectApproval(root, project, legacySubject, "typed-host-command", new Date());

    expect(approvedNarrowImageBuildForManifest(root, project, { build: candidate.build, contextManifest: candidate.manifest })).toBeUndefined();

    const { selection } = approveNarrowImageBuildCandidate(root, project, candidate, "interactive");
    expect(selection.subjects["image-build"]?.digest).toBe(candidate.subject.digest);
    expect(approvedNarrowImageBuildForManifest(root, project, { build: candidate.build, contextManifest: candidate.manifest })?.inputDigest).toBe(candidate.inputDigest);
  });

  test("same-digest snapshot corruption refuses the launch lookup and is reclaimed by explicit re-approval", () => {
    const project = info();
    const first = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    const { approved } = approveNarrowImageBuildCandidate(root, project, first, "interactive");
    const originalScript = fs.readFileSync(path.join(approved.contextPath, "scripts", "setup.sh"), "utf8");
    const fresh = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    fs.writeFileSync(path.join(approved.contextPath, "scripts", "setup.sh"), "#!/bin/sh\ncorrupted\n");

    expect(() => approvedNarrowImageBuildForManifest(root, project, { build: fresh.build, contextManifest: fresh.manifest })).toThrow("staged context does not match");

    const { approved: republished } = approveNarrowImageBuildCandidate(root, project, fresh, "interactive");
    expect(republished.subject.digest).toBe(fresh.subject.digest);
    expect(fs.readFileSync(path.join(republished.contextPath, "scripts", "setup.sh"), "utf8")).toBe(originalScript);
    expect(readApprovedNarrowImageBuild(root, project)?.inputDigest).toBe(fresh.inputDigest);
  });

  test("image approval preserves but does not update independent network approval", () => {
    const project = info();
    const network = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    const networkSelection = approveNetworkCandidate(root, project, network, "network-project", "interactive");
    const image = captureNarrowImageBuildCandidate(root, build, project.paths.controlCandidatesDir);
    approveNarrowImageBuildCandidate(root, project, image, "interactive");
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["drift.example"]}`);

    const selection = readControlApprovalSelection(root, project);
    expect(selection?.subjects["network-project"]?.digest).toBe(networkSelection.subjects["network-project"]?.digest);
    expect(selection?.subjects["image-build"]?.digest).toBe(image.subject.digest);
  });
});
