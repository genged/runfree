
import {
  assertSpendableSessionContainerProof,
  type SessionContainerProof,
} from "./session-container-proof.ts";
import {
  assertSessionContainerForegroundAttachReceipt,
  type SessionContainerForegroundAttachReceipt,
} from "./session-container-start.ts";
import {
  assertSessionContainerRecordProject,
  parseSessionContainerRecordV2,
  serializeSessionContainerRecordV2,
  type SessionContainerProjectIdentity,
  type SessionContainerRecordV2,
} from "./session-containers.ts";

declare const sessionContainerProvisioningRunningAuthorizationBrand: unique symbol;

export type SessionContainerProvisioningRunningAuthorization = Readonly<{
  readonly [sessionContainerProvisioningRunningAuthorizationBrand]: true;
  record: SessionContainerRecordV2;
}>;

function exactRecordSnapshot(record: SessionContainerRecordV2): SessionContainerRecordV2 {
  const parsed = parseSessionContainerRecordV2(JSON.parse(serializeSessionContainerRecordV2(record)));
  if (!parsed) throw new Error("could not seal the provisioning-running lifecycle authority");
  return Object.freeze(parsed);
}

/**
 * Binds the single post-start inspection to the exact durable
 * provisioning-running record it proved. The proof is the one shape proof of
 * the whole admission: byte-exact against the create plan, including the
 * network endpoint at exactly the allocated address. Activation spends it once;
 * nothing else re-inspects static Docker configuration.
 */
export function authorizeProvisioningRunningSessionContainer(
  record: SessionContainerRecordV2,
  expectedProject: SessionContainerProjectIdentity,
  networkId: string,
  foregroundReceipt: SessionContainerForegroundAttachReceipt,
  liveProof: SessionContainerProof,
): SessionContainerProvisioningRunningAuthorization {
  assertSessionContainerRecordProject(record, expectedProject);
  const provisioningRecord = exactRecordSnapshot(record);
  if (provisioningRecord.state !== "provisioning-running") {
    throw new Error("provisioning-running authority requires a provisioning-running lifecycle record");
  }
  assertSessionContainerForegroundAttachReceipt(foregroundReceipt, provisioningRecord, expectedProject);
  assertSpendableSessionContainerProof(liveProof, provisioningRecord, "provisioning-running", networkId);
  return Object.freeze({
    record: provisioningRecord,
  }) as SessionContainerProvisioningRunningAuthorization;
}
