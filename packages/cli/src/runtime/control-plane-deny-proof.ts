

import { validateProxyNftablesTableJson, type ProxyNftablesProofInput } from "../proxy-nftables-proof.ts";
import { sha256Digest as sha256 } from "../strict-primitives.ts";

export const DENY_BY_DEFAULT_BASE_PROOF_SCHEMA_VERSION = 1 as const;

const PROJECT_ID = /^[a-f0-9]{12}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const DOCKER_ID = /^[a-f0-9]{64}$/;

/**
 * The deny-by-default observation minted from the LIVE proxy firewall.
 *
 * The per-session INPUT chain is `policy drop` and accepts agent->proxy
 * traffic only from `@session_ipv4` on the internal interface — so an
 * unadmitted source is dropped at L3, before the proxy application, host
 * policy, DNS, or upstream paths are ever reachable. That is the
 * deny-by-default base claim: a container in the agent position with no
 * admission reaches nothing at all. The kernel `nft` ruleset IS the
 * enforcement, so validating its exact shape proves the property for ALL
 * unadmitted sources without any of the false-pass hazards of a single live
 * traffic probe (a dropped SYN, dead proxy, or broken toolchain would each
 * read as "denied"). The port-first non-443 claim remains proven from
 * admitted positions by the live tranches.
 */
export type DenyByDefaultFirewallObservationV1 = Readonly<{
  schemaVersion: typeof DENY_BY_DEFAULT_BASE_PROOF_SCHEMA_VERSION;
  origin: "proxy-firewall";
  projectId: string;
  controlPlaneGenerationDigest: string;
  proxyContainerId: string;
  /** sha256 over the exact live `nft -j list table` JSON string that was validated. */
  nftablesTableSha256: string;
}>;

export type DenyByDefaultObservationV1 = DenyByDefaultFirewallObservationV1;

const sealedFirewallObservations = new WeakSet<object>();


/**
 * Mints the post-cutover deny-by-default observation from the live proxy
 * nftables table that topology already fetched for the firewall proof. The
 * caller passes the exact same `ProxyNftablesProofInput` the firewall proof
 * validated (raw live nft JSON plus the interface/port/uid expectations); this
 * function re-runs `validateProxyNftablesTableJson` and mints only when the
 * ruleset proves deny-by-default: INPUT `policy drop` with `@session_ipv4` the
 * sole agent->proxy accept path.
 *
 * FAIL CLOSED: any validation issue — a malformed table, an unexpected accept
 * rule, the wrong INPUT policy, a missing session gate — throws and mints
 * nothing. The session-only ruleset shape is the only shape the proof
 * validator can express.
 */
export function observeDenyByDefaultViaFirewallV1(input: {
  projectId: string;
  controlPlaneGenerationDigest: string;
  proxyContainerId: string;
  /**
   * The exact input the firewall proof validated: the raw live nft table JSON
   * plus the interface/port/uid expectations.
   */
  nftables: ProxyNftablesProofInput;
}): DenyByDefaultFirewallObservationV1 {
  if (!PROJECT_ID.test(input.projectId)) throw new Error("deny-by-default firewall proof has invalid project identity");
  if (!SHA256.test(input.controlPlaneGenerationDigest)) {
    throw new Error("deny-by-default firewall proof has invalid control-plane generation");
  }
  if (!DOCKER_ID.test(input.proxyContainerId)) {
    throw new Error("deny-by-default firewall proof has invalid container identity");
  }
  const issues = validateProxyNftablesTableJson(input.nftables);
  if (issues.length > 0) {
    throw new Error(`deny-by-default firewall proof rejected the live ruleset: ${issues.join("; ")}`);
  }
  const observation = Object.freeze({
    schemaVersion: DENY_BY_DEFAULT_BASE_PROOF_SCHEMA_VERSION,
    origin: "proxy-firewall" as const,
    projectId: input.projectId,
    controlPlaneGenerationDigest: input.controlPlaneGenerationDigest,
    proxyContainerId: input.proxyContainerId,
    nftablesTableSha256: sha256(input.nftables.rawJson),
  });
  sealedFirewallObservations.add(observation);
  return observation;
}

export function assertDenyByDefaultFirewallObservationV1(
  observation: DenyByDefaultFirewallObservationV1,
): void {
  if (!sealedFirewallObservations.has(observation)) {
    throw new Error("deny-by-default firewall observation was not minted by the exact live ruleset proof");
  }
}
