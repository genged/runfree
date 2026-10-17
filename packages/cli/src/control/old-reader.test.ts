import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { validateDesiredNetworkPolicy } from "@runfree/runtime-contracts/desired-network-policy";
import { loadEffectiveProxyControl } from "@runfree/runtime-contracts/effective-control";

import { validateDesiredNetworkPolicy as validateDesiredV052 } from "../../../../tests/fixtures/release-v0.5.2/runtime-contracts/desired-network-policy.ts";
import { loadEffectiveProxyControl as loadEffectiveProxyControlV052 } from "../../../../tests/fixtures/release-v0.5.2/runtime-contracts/effective-control.ts";
import { validateNetworkPolicy as validateNetworkPolicyV052 } from "../../../../tests/fixtures/release-v0.5.2/runtime-contracts/network-policy.ts";
import { projectInfo } from "../config.ts";
import { approveNetworkCandidate, approveRuntimeIsolationControl } from "./approvals.ts";
import { captureDesiredPolicyCandidate } from "./candidates.ts";
import { publishEffectivePolicyGeneration } from "./effective.ts";

// T13 (spec §4.6): the readers of the last release, frozen as fixtures, must
// refuse what this release writes when it uses `basic`, `username` or
// `protocol`. `protocol` with `bearer` is the case that matters: the old enum
// already refuses `basic`, so `basic` alone would hide a silent drop.

const BEARER_GIT_HTTP = { host: "gitlab.com", header: "Authorization", scheme: "bearer", protocol: "git-http" };
const BASIC_GIT_HTTP = { host: "gitlab.com", header: "Authorization", scheme: "basic", username: "oauth2", protocol: "git-http" };

function desiredWith(credential: Record<string, string>, version: 2 | 3 = 3) {
  return {
    version,
    hosts: ["gitlab.com"],
    tokens: { gitlab: { description: "GitLab token", credentials: [credential] } },
  };
}

describe("v0.5.2 readers against this release's policy", () => {
  test("the v0.5.2 desired validator refuses a v3 file", () => {
    for (const credential of [BEARER_GIT_HTTP, BASIC_GIT_HTTP]) {
      const current = desiredWith(credential);
      expect(validateDesiredNetworkPolicy(current).version).toBe(3);
      expect(() => validateDesiredV052(current)).toThrow("version must be 2");
    }
  });

  test("recorded fact: the v0.5.2 effective validator accepts protocol on bearer and drops it", () => {
    // This is the misread that makes the same-build fence and the generation
    // check necessary: an old proxy would inject on every path of the host.
    const loaded = validateNetworkPolicyV052({ hosts: ["gitlab.com"], tokens: desiredWith(BEARER_GIT_HTTP).tokens });
    expect(loaded.credentialMappings).toHaveLength(1);
    expect(loaded.credentialMappings[0]).not.toHaveProperty("protocol");
    expect(loaded.raw.tokens?.gitlab.credentials).toEqual([{ host: "gitlab.com", header: "Authorization", scheme: "bearer" }]);
    // basic is refused by the old closed scheme enum.
    expect(() => validateNetworkPolicyV052({ hosts: ["gitlab.com"], tokens: desiredWith(BASIC_GIT_HTTP).tokens }))
      .toThrow("scheme must be one of: bearer, raw");
  });

  test("this release refuses a v2 file that uses basic, username or protocol", () => {
    for (const credential of [BEARER_GIT_HTTP, BASIC_GIT_HTTP, { ...BASIC_GIT_HTTP, protocol: undefined }]) {
      expect(() => validateDesiredNetworkPolicy(desiredWith(credential as Record<string, string>, 2)))
        .toThrow("version 2 cannot use these fields; declare version 3");
    }
  });
});

describe("v0.5.2 proxy control loader over a generation this release publishes", () => {
  let root: string;
  let stateHome: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-old-reader-project-"));
    stateHome = fs.mkdtempSync(path.join(os.tmpdir(), "runfree-old-reader-state-"));
    fs.mkdirSync(path.join(root, ".runfree"));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true });
    fs.rmSync(stateHome, { recursive: true });
  });

  // The real publication path: approve the desired policy, then publish and
  // select the effective generation the proxy polls.
  function publish(desired: unknown): string {
    fs.writeFileSync(path.join(root, ".runfree", "network-policy.json"), `${JSON.stringify(desired)}\n`);
    const project = projectInfo(root, { XDG_STATE_HOME: stateHome, XDG_CONFIG_HOME: path.join(stateHome, "config") });
    const candidate = captureDesiredPolicyCandidate(root, project.paths.controlCandidatesDir);
    approveNetworkCandidate(root, project, candidate, "network-project", "interactive");
    approveNetworkCandidate(root, project, candidate, "network-local", "interactive");
    approveRuntimeIsolationControl(root, project, "interactive");
    publishEffectivePolicyGeneration(root, project);
    return project.paths.controlProxyDir;
  }

  test("control: a generation without the new fields loads in both readers", () => {
    const proxyRoot = publish(desiredWith({ host: "gitlab.com", header: "Authorization", scheme: "bearer" }, 2));
    const current = loadEffectiveProxyControl(proxyRoot);
    const old = loadEffectiveProxyControlV052(proxyRoot);
    expect(old.networkPolicy.generation).toBe(current.networkPolicy.generation);
  });

  test("a protocol-scoped bearer mapping fails the old generation/manifest check", () => {
    const proxyRoot = publish(desiredWith(BEARER_GIT_HTTP));
    expect(loadEffectiveProxyControl(proxyRoot).networkPolicy.credentialMappings[0]?.protocol).toBe("git-http");
    expect(() => loadEffectiveProxyControlV052(proxyRoot))
      .toThrow("selected network policy generation does not match its manifest");
  });

  test("a basic mapping is refused by the old scheme enum", () => {
    const proxyRoot = publish(desiredWith(BASIC_GIT_HTTP));
    expect(loadEffectiveProxyControl(proxyRoot).networkPolicy.credentialMappings[0]?.username).toBe("oauth2");
    expect(() => loadEffectiveProxyControlV052(proxyRoot)).toThrow("scheme must be one of: bearer, raw");
  });
});
