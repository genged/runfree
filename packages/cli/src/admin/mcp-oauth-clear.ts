// What `runfree mcp revoke` may say about the proxy's OAuth state for the
// server. Revoke writes a new state epoch (see runtime/mcp-oauth-epochs.ts);
// the proxy deletes older state when it activates a policy that carries it.
// "cleared" is printed only with proof that the running proxy did exactly
// that: its request-proxy status names the effective policy generation this
// revoke converged on, carries the state-epoch capability marker (published
// only after the prune succeeded), and that generation publishes the new
// epoch for the server or no longer names the server at all.

import fs from "node:fs";

import { validateOAuthMediationPolicy } from "@runfree/runtime-contracts/oauth-mediation-policy";
import type { ParsedGenerationStatus } from "@runfree/runtime-contracts/proxy-status";
import { discoverLiveProxyId, type ControlActivationResult } from "../control/activation.ts";
import { verifyEffectivePolicyGeneration } from "../control/effective.ts";
import { parseStrictJson } from "../control/strict-json.ts";
import { readProxyControlReceipts } from "../runtime/docker.ts";
import type { RuntimeContext, RuntimeIO } from "../runtime/types.ts";

export type OAuthStateClearEvidence = {
  activation: ControlActivationResult;
  // The live request proxy's status, read after the activation converged.
  requestProxy?: ParsedGenerationStatus;
  // The provider's epoch in the converged generation's OAuth policy;
  // "absent" when that generation does not name the provider.
  publishedEpoch?: string;
};

export const PROVIDER_ABSENT = "absent";

export function oauthStateClearProven(evidence: OAuthStateClearEvidence, expectedEpoch: string): boolean {
  const { activation, requestProxy, publishedEpoch } = evidence;
  return activation.kind === "converged"
    && requestProxy?.controlGeneration === activation.controlGeneration
    && requestProxy.oauthStateEpochs === true
    && (publishedEpoch === PROVIDER_ABSENT || publishedEpoch === expectedEpoch);
}

export function oauthStateClearLine(input: {
  agent: string;
  evidence: OAuthStateClearEvidence;
  expectedEpoch: string;
  server: string;
}): string {
  const subject = `proxy OAuth state for ${input.agent} ${input.server}`;
  const { activation } = input.evidence;
  if (activation.kind === "converged" && oauthStateClearProven(input.evidence, input.expectedEpoch)) {
    return `${subject}: cleared (the proxy applied effective policy generation ${activation.controlGeneration}); the next login starts fresh`;
  }
  if (activation.kind !== "converged") {
    return `${subject}: not cleared yet; the proxy clears it when it next starts with this project's policy`;
  }
  return `${subject}: not proven cleared; the running proxy did not confirm it (it may predate this Runfree version); it is cleared when the proxy next starts on this version`;
}

/** Collect the evidence; any read failure leaves it unproven, never proven. */
export function gatherOAuthStateClearEvidence(
  context: RuntimeContext,
  io: RuntimeIO,
  activation: ControlActivationResult,
  providerId: string,
): OAuthStateClearEvidence {
  if (activation.kind !== "converged") return { activation };
  let publishedEpoch: string | undefined;
  try {
    const generation = verifyEffectivePolicyGeneration(context.project, activation.controlGeneration);
    const policy = validateOAuthMediationPolicy(parseStrictJson(fs.readFileSync(generation.oauthPolicyPath, "utf8")));
    const provider = policy.providers.find((candidate) => candidate.providerId === providerId);
    publishedEpoch = provider ? provider.stateEpoch : PROVIDER_ABSENT;
  } catch {
    return { activation };
  }
  let requestProxy: ParsedGenerationStatus | undefined;
  try {
    const proxyId = discoverLiveProxyId(context, io);
    requestProxy = proxyId ? readProxyControlReceipts(context, io, proxyId)?.requestProxy : undefined;
  } catch {
    requestProxy = undefined;
  }
  return {
    activation,
    ...(requestProxy ? { requestProxy } : {}),
    ...(publishedEpoch !== undefined ? { publishedEpoch } : {}),
  };
}
