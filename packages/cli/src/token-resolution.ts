export type TokenResolutionReceipt = {
  tokenName: string;
  sourceFingerprint: string;
  proxyStoreGeneration: string;
  resolvedAt: number;
};

export type TokenResolutionLedger = {
  importedStartupReceipts: Set<string>;
  lastResolvedAt: Map<string, number>;
  retryAfterFailureAt: Map<string, number>;
  startupReceipts: TokenResolutionReceipt[];
};

// Typed source-resolution failure classification. Keep-last-good is only safe
// when "transient" and "definitive" cannot drift with free-form message text:
// provider adapters map raw failures into this type at the source boundary and
// the central syncTokens catch block consumes only the classification.
//
// - "transient": carries no revocation information (timeouts, locked vault,
//   not signed in, transport failures). Keep-eligible under a receipt.
// - "definitive": exactly how a host-side revocation gesture manifests
//   (item/field not found, env unset, source removed, auth denied, empty
//   value). Always fail-closed (delete).
export type TokenResolutionErrorClassification = "transient" | "definitive";

export type TokenResolutionSourceKind = "env" | "1password" | "named" | "command" | "jwt";

export class TokenResolutionError extends Error {
  readonly classification: TokenResolutionErrorClassification;
  readonly sourceKind: TokenResolutionSourceKind;
  readonly code: string;
  readonly safeMessage: string;

  constructor(input: {
    classification: TokenResolutionErrorClassification;
    sourceKind: TokenResolutionSourceKind;
    code: string;
    safeMessage: string;
  }) {
    super(input.safeMessage);
    this.name = "TokenResolutionError";
    this.classification = input.classification;
    this.sourceKind = input.sourceKind;
    this.code = input.code;
    this.safeMessage = input.safeMessage;
  }
}

export function isTransientTokenResolutionError(error: unknown): boolean {
  return error instanceof TokenResolutionError && error.classification === "transient";
}
