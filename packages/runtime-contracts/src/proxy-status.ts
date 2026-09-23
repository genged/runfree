// Proxy policy-generation status contract (see the convergent proxy token
// store design spec). Both halves of the host↔proxy convergence ack import
// this module: the proxy-side writers (root firewall supervisor →
// firewall.json; uid-1001 request proxy → request-proxy/request-proxy.json)
// and the CLI-side reader that polls the files over docker exec. Keeping the
// paths, shapes, and single-line JSON framing here means a proxy-side change
// cannot silently diverge from the CLI parser.


// Fixed by contract, like the .runfree/network-policy.json path: an env knob
// honored by only one side of the host↔proxy ack protocol would silently
// break convergence.
export const DEFAULT_PROXY_STATUS_DIR = "/run/runfree-proxy-status";

export function firewallStatusPath(statusDir: string = DEFAULT_PROXY_STATUS_DIR): string {
  return `${statusDir}/firewall.json`;
}

// request-proxy.json lives in a uid-1001-owned subdirectory pre-created by the
// entrypoint; the status root stays root-owned so the uid-1001 request proxy
// can never write firewall.json (the convergence claim that matters for
// policy removals).
export function requestProxyStatusDir(statusDir: string = DEFAULT_PROXY_STATUS_DIR): string {
  return `${statusDir}/request-proxy`;
}

export function requestProxyStatusPath(statusDir: string = DEFAULT_PROXY_STATUS_DIR): string {
  return `${requestProxyStatusDir(statusDir)}/request-proxy.json`;
}

type GenerationStatusIdentity = {
  generation: string;
  controlGeneration?: string;
  policyGeneration?: string;
};

export type FirewallGenerationStatus = GenerationStatusIdentity & {
  rulesetVerified: boolean;
  appliedAt: string;
};

export type RequestProxyGenerationStatus = GenerationStatusIdentity & {
  appliedAt: string;
};

export type ParsedGenerationStatus = {
  controlGeneration?: string;
  generation: string;
  policyGeneration?: string;
  rulesetVerified?: boolean;
};

// The CLI reads both files in one exec and splits on lines, so each status
// file must serialize to exactly one JSON line. This serializer is the only
// sanctioned writer framing; JSON.stringify never emits raw newlines, so the
// invariant holds by construction.
export function serializeGenerationStatus(
  status: FirewallGenerationStatus | RequestProxyGenerationStatus,
): string {
  return `${JSON.stringify(status)}\n`;
}

export function parseGenerationStatusLine(raw: string): ParsedGenerationStatus | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
  const record = parsed as Record<string, unknown>;
  if (typeof record.generation !== "string" || record.generation === "") return undefined;
  const hasControlGeneration = typeof record.controlGeneration === "string" && record.controlGeneration !== "";
  const hasPolicyGeneration = typeof record.policyGeneration === "string" && record.policyGeneration !== "";
  if (hasControlGeneration !== hasPolicyGeneration) return undefined;
  if (hasPolicyGeneration && record.policyGeneration !== record.generation) return undefined;
  return {
    generation: record.generation,
    ...(hasControlGeneration ? {
      controlGeneration: record.controlGeneration as string,
      policyGeneration: record.policyGeneration as string,
    } : {}),
    ...(typeof record.rulesetVerified === "boolean" ? { rulesetVerified: record.rulesetVerified } : {}),
  };
}


