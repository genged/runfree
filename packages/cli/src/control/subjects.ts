
import {
  canonicalDesiredNetworkPolicy,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import {
  normalizedAgentBuildConfig,
  type AgentBuildContextKind,
  type BuildContextManifestEntry,
} from "../agent-image.ts";
import type { AgentBuildConfig, RunfreeConfig } from "../config.ts";
import { stableJson, sha256Digest } from "../strict-primitives.ts";
import { observeCheckoutBinding, type CheckoutBinding } from "./checkout-binding.ts";

export const CONTROL_APPROVAL_SCHEMA_VERSION = 1 as const;
export const CONTROL_COMPILER_VERSION = "desired-policy-v2-1" as const;

export type ControlSubjectType = "network-project" | "network-local" | "runtime-isolation" | "image-build";
export type ControlSubject = {
  digest: string;
  payload: Record<string, unknown>;
  subjectType: ControlSubjectType;
};


export function controlDigest(value: unknown): string {
  return sha256Digest(stableJson(value));
}

export function networkControlSubject(
  subjectType: "network-project" | "network-local",
  policy: DesiredNetworkPolicyJson,
): ControlSubject {
  const validated = validateDesiredNetworkPolicy(policy);
  const payload = {
    schemaVersion: CONTROL_APPROVAL_SCHEMA_VERSION,
    subjectType,
    compilerVersion: CONTROL_COMPILER_VERSION,
    networkPolicy: JSON.parse(canonicalDesiredNetworkPolicy(validated)) as unknown,
  };
  return { digest: controlDigest(payload), payload, subjectType };
}

export function runtimeIsolationControlSubject(config: RunfreeConfig): ControlSubject {
  const payload = {
    schemaVersion: CONTROL_APPROVAL_SCHEMA_VERSION,
    subjectType: "runtime-isolation" as const,
    compilerVersion: CONTROL_COMPILER_VERSION,
    runtime: {
      subnet: config.runtime.subnet ?? "generated",
      proxyIp: config.runtime.proxyIp ?? "generated",
      agentIp: config.runtime.agentIp ?? "generated",
      dependencyOverlays: config.runtime.dependencyOverlays ?? "auto",
      writeApprovalHoldSeconds: config.runtime.writeApprovalHoldSeconds ?? 120,
    },
  };
  return { digest: controlDigest(payload), payload, subjectType: "runtime-isolation" };
}

export function imageBuildControlSubject(input: {
  build: AgentBuildConfig;
  contextKind: AgentBuildContextKind;
  contextManifest: readonly BuildContextManifestEntry[];
}): ControlSubject {
  if (input.contextKind !== "narrow") throw new Error("image-build control subjects require a staged narrow context");
  // The subject covers only project-controlled build inputs. Embedded runtime
  // identity (base image, injected version args) belongs to the image input
  // digest that drives rebuilds, not to the human approval: a runfree upgrade
  // must rebuild the image without invalidating the approval of these bytes.
  const payload = {
    schemaVersion: CONTROL_APPROVAL_SCHEMA_VERSION,
    subjectType: "image-build" as const,
    build: normalizedAgentBuildConfig(input.build),
    contextKind: input.contextKind,
    contextManifest: input.contextManifest,
  };
  return { digest: controlDigest(payload), payload, subjectType: "image-build" };
}

export function sandboxLocalDigest(config: RunfreeConfig): string {
  return controlDigest({
    schemaVersion: CONTROL_APPROVAL_SCHEMA_VERSION,
    subjectType: "sandbox-local",
    project: config.project,
    agents: config.agents,
  });
}

/**
 * The checkout fingerprint over an already-observed binding.
 *
 * The algorithm is unchanged, and it has exactly one definition: the v1
 * approval record stores this value, and classification has to recompute it to
 * tell a v1 record that still describes this checkout from one that no longer
 * does. Deriving it from the same observation the v2 binding is built from also
 * removes a race — two separate `stat` calls could otherwise disagree about
 * which checkout a single read was classified against.
 */
export function checkoutFingerprintOf(binding: CheckoutBinding): string {
  return controlDigest({
    subjectType: "checkout-fingerprint",
    resolvedRootDigest: controlDigest(binding.resolvedRoot),
    rootIdentityDigest: controlDigest({ dev: binding.rootDevice, ino: binding.rootInode }),
  });
}

export function checkoutFingerprint(projectRoot: string): string {
  return checkoutFingerprintOf(observeCheckoutBinding(projectRoot));
}
