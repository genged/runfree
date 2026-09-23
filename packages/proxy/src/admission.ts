import { normalizeHostname } from "@runfree/runtime-contracts/network-policy";
import type { ApprovalRequestPrincipal } from "@runfree/runtime-contracts/session-registry";

export type AdmissionStage = "connect" | "sni" | "request";

export type AdmissionRecord = Readonly<{
  v: 1;
  host: string;
  port: 443;
  policyGeneration: string;
  admittedAtMs: number;
  connectionSerial: number;
  stage: AdmissionStage;
  sourceIp?: string;
  principal?: ApprovalRequestPrincipal;
  sessionBinding?: Readonly<{
    sessionKey: string;
    sessionIncarnation: string;
    containerId: string;
    sourceIp: string;
    networkId: string;
    selectedAgentImageId: string;
    sessionAgentGenerationDigest: string;
    controlPlaneGenerationDigest: string;
    admissionContractEpoch: number;
  }>;
}>;

export type AdmissionObservation =
  | { kind: "admitted"; record: AdmissionRecord }
  | { kind: "host-mismatch"; record: AdmissionRecord; observedHost: string }
  | { kind: "missing" };

type AdmissionBinding = {
  record: AdmissionRecord;
  observedSerial?: number;
};

function atStage(record: AdmissionRecord, stage: AdmissionStage): AdmissionRecord {
  return { ...record, stage };
}

export class AdmissionRegistry {
  readonly #bindings = new Map<number, AdmissionBinding>();
  #nextSerial = 1;

  mint(
    host: string,
    policyGeneration: string,
    identity: Pick<AdmissionRecord, "sourceIp" | "principal" | "sessionBinding"> = {},
  ): AdmissionRecord {
    return Object.freeze({
      v: 1,
      host: normalizeHostname(host),
      port: 443,
      policyGeneration,
      admittedAtMs: Date.now(),
      connectionSerial: this.#nextSerial++,
      stage: "connect",
      ...identity,
    });
  }

  bind(port: number, record: AdmissionRecord): void {
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new Error(`invalid admission connection port: ${port}`);
    }
    this.#bindings.set(port, { record });
  }

  observeTls(port: number | undefined, sniHostname: string | undefined): AdmissionObservation {
    if (port === undefined) return { kind: "missing" };
    const binding = this.#bindings.get(port);
    if (!binding) return { kind: "missing" };
    const { record } = binding;

    if (sniHostname !== undefined) {
      let observedHost: string;
      try {
        observedHost = normalizeHostname(sniHostname);
      } catch {
        return { kind: "host-mismatch", record, observedHost: "<unparseable>" };
      }
      if (observedHost !== record.host) {
        return { kind: "host-mismatch", record, observedHost };
      }
    }

    binding.observedSerial = record.connectionSerial;
    return { kind: "admitted", record: atStage(record, "sni") };
  }

  resolveRequest(port: number | undefined, observedSerial: number | undefined): AdmissionRecord | undefined {
    if (port === undefined || observedSerial === undefined) return undefined;
    const binding = this.#bindings.get(port);
    if (!binding
      || binding.observedSerial !== binding.record.connectionSerial
      || observedSerial !== binding.record.connectionSerial) return undefined;
    return atStage(binding.record, "request");
  }

  release(port: number, connectionSerial: number): void {
    const binding = this.#bindings.get(port);
    if (binding?.record.connectionSerial === connectionSerial) {
      this.#bindings.delete(port);
    }
  }

  revokeSession(sessionKey: string): number {
    let revoked = 0;
    for (const [port, binding] of this.#bindings) {
      if (binding.record.sessionBinding?.sessionKey !== sessionKey) continue;
      this.#bindings.delete(port);
      revoked += 1;
    }
    return revoked;
  }

  size(): number {
    return this.#bindings.size;
  }
}
