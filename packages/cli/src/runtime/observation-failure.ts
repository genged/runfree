/** Evidence categories shared by admission, renewal, and replacement recovery. */
export type RuntimeFailureKind =
  | "observation-unavailable"
  | "subject-absent"
  | "identity-contradiction"
  | "boundary-violation"
  | "lease-expired"
  | "owner-completed"
  | "fence-lost"
  | "partial-convergence"
  | "unclassified";

export type RuntimeFailureEvidence = Readonly<{
  kind: RuntimeFailureKind;
  subject: "owner" | "session" | "proxy" | "registry" | "fence";
  expectedIdentity: string;
  phase: string;
  observation: string;
}>;

export class RuntimeObservationError extends Error {
  readonly evidence: RuntimeFailureEvidence;

  constructor(evidence: RuntimeFailureEvidence, cause?: unknown) {
    super(`${evidence.subject} ${evidence.expectedIdentity}: ${evidence.kind} during ${evidence.phase}: ${evidence.observation}`, { cause });
    this.name = "RuntimeObservationError";
    this.evidence = Object.freeze({ ...evidence });
  }
}
