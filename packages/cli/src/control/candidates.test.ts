import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { captureDesiredPolicyCandidate } from "./candidates.ts";

describe("desired policy candidates", () => {
  let root: string;
  let candidates: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-candidate-project-"));
    candidates = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-candidates-"));
    fs.mkdirSync(path.join(root, ".runfree"));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(candidates, { recursive: true });
  });

  test("publishes one immutable candidate and treats an absent local layer as empty", () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":["example.com"]}`);
    const candidate = captureDesiredPolicyCandidate(root, candidates);
    expect(candidate.local).toEqual({ version: 2, hosts: [] });
    expect(fs.statSync(path.join(candidate.directory, "network-project.json")).mode & 0o777).toBe(0o400);
    expect(candidate.manifest.candidateDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  test("canonical-equivalent desired bytes select the same candidate", () => {
    const policyPath = path.join(root, ".runfree", "network-policy.json");
    fs.writeFileSync(policyPath, `{"version":2,"hosts":["example.com"]}`);
    const first = captureDesiredPolicyCandidate(root, candidates);
    fs.writeFileSync(policyPath, `{\n  "hosts": ["example.com"],\n  "version": 2\n}\n`);
    const second = captureDesiredPolicyCandidate(root, candidates);
    expect(second.directory).toBe(first.directory);
  });

  test("rejects corruption instead of trusting an existing digest directory", () => {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `{"version":2,"hosts":[]}`);
    const first = captureDesiredPolicyCandidate(root, candidates);
    fs.chmodSync(path.join(first.directory, "network-project.json"), 0o600);
    fs.writeFileSync(path.join(first.directory, "network-project.json"), `{"version":2,"hosts":["evil.example"]}\n`);
    expect(() => captureDesiredPolicyCandidate(root, candidates)).toThrow("does not match its manifest");
  });
});
