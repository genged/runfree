import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test } from "vitest";

import { defaultConfig } from "../config.ts";
import {
  checkoutFingerprint,
  checkoutFingerprintOf,
  networkControlSubject,
  runtimeIsolationControlSubject,
  sandboxLocalDigest,
} from "./subjects.ts";

test("control subjects are domain separated and runtime isolation excludes agent selection", () => {
  const policy = { version: 2 as const, hosts: [] };
  const project = networkControlSubject("network-project", policy);
  const local = networkControlSubject("network-local", policy);
  expect(project.digest).not.toBe(local.digest);

  const first = defaultConfig();
  const changedAgent = { ...first, agents: { ...first.agents, default: "codex" } };
  expect(runtimeIsolationControlSubject(first).digest).toBe(runtimeIsolationControlSubject(changedAgent).digest);
  expect(sandboxLocalDigest(first)).not.toBe(sandboxLocalDigest(changedAgent));
});

test("dependency isolation changes only the runtime-isolation subject", () => {
  const first = defaultConfig();
  const changed = { ...first, runtime: { ...first.runtime, dependencyOverlays: "off" as const } };
  expect(runtimeIsolationControlSubject(first).digest).not.toBe(runtimeIsolationControlSubject(changed).digest);
});

test("checkout fingerprints bind the resolved root inode", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-checkout-fingerprint-"));
  try {
    const root = path.join(parent, "project");
    fs.mkdirSync(root);
    const first = checkoutFingerprint(root);
    fs.renameSync(root, path.join(parent, "old-project"));
    fs.mkdirSync(root);
    expect(checkoutFingerprint(root)).not.toBe(first);
  } finally {
    fs.rmSync(parent, { recursive: true });
  }
});

/**
 * A golden vector for the v1 approval record's stored hash.
 *
 * Every other test computes the expected value with the same function it is
 * testing, so the whole suite would stay green if this algorithm changed —
 * while every v1 record still on disk silently stopped describing its own
 * checkout and became `superseded`. The cost of that is one review per affected
 * project, and nothing would report it. This digest was captured from the
 * pre-`checkoutFingerprintOf` implementation (`448367b`) and must not be
 * updated to match a new one: a deliberate change to the v1 algorithm is a
 * change to how records written by older releases are read.
 */
test("the v1 checkout fingerprint algorithm is pinned to what older releases wrote", () => {
  expect(checkoutFingerprintOf({
    resolvedRoot: "/Users/mg/code/capshelf",
    rootDevice: "16777229",
    rootInode: "166957006",
  })).toBe("sha256:4779ee3ded16279d31c49cdd7ae4cf2ddc98cc9e63e13001ba704353e50193ae");
});

// The recorded-never-compared device number is inside the v1 hash, which is why
// a reboot invalidated every approval and why only the v2 binding drops it.
test("the v1 fingerprint still moves with the device number the v2 binding ignores", () => {
  const binding = { resolvedRoot: "/Users/mg/code/capshelf", rootDevice: "16777229", rootInode: "166957006" };

  expect(checkoutFingerprintOf({ ...binding, rootDevice: "16777230" }))
    .not.toBe(checkoutFingerprintOf(binding));
});
