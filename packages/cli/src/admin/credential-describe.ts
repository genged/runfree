import type { CredentialPolicyJson } from "@runfree/runtime-contracts/network-policy";

// `(scheme[:username][, path P][, protocol=X])`: everything that decides what is
// sent and where, so two mappings on one host and header read apart.
export function describeCredentialScope(credential: CredentialPolicyJson): string {
  const scheme = credential.username !== undefined ? `${credential.scheme}:${credential.username}` : credential.scheme;
  const pathScope = credential.pathPrefix ? `, path ${credential.pathPrefix}` : "";
  const protocolScope = credential.protocol !== undefined ? `, protocol=${credential.protocol}` : "";
  return `(${scheme}${pathScope}${protocolScope})`;
}

export function describeCredential(credential: CredentialPolicyJson): string {
  return `${credential.host} -> ${credential.header} ${describeCredentialScope(credential)}`;
}
